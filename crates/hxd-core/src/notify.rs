//! Where push notifications attach.
//!
//! `docs/push-notifications.md` §9 stages the gateway itself — the device
//! registry, the payload shaping, the uniqush HTTP client — as later work
//! in its own crate. What belongs here, and only here, is the *decision*:
//! that §11 of that document names the hazard exactly, "the notify
//! decision must live in the domain rather than in `hxd-ng-session`, or
//! the legacy path silently skips it." A private message arriving for
//! someone who is not attentive is one rule, computed in one place, and
//! both wires reach it by calling the same function. A news article that
//! answers someone is the second rule, and it lives in `crate::news` for
//! the same reason.
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

use crate::inbox::{Mailbox, MessageId};
use crate::news::{ArticleId, NodeId, NotifyReason, SubScope};

/// Something happened that someone who is not watching should hear about.
///
/// A sum rather than one struct because a gateway builds a different
/// payload for each — a private message is a conversation to open, an
/// article is a thread to open — and a struct with half its fields
/// meaningless per kind is a payload builder waiting to read the wrong
/// half (`docs/news.md` §10.10).
#[derive(Debug, Clone, Copy)]
pub enum Notification<'a> {
    Message(MessageNotice<'a>),
    News(NewsNotice<'a>),
}

impl<'a> Notification<'a> {
    /// Whose it is: the address the gateway maps to a subscriber id,
    /// whichever kind it is.
    pub fn to(&self) -> &'a Mailbox {
        match self {
            Notification::Message(m) => m.to,
            Notification::News(n) => n.to,
        }
    }
}

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
pub struct MessageNotice<'a> {
    /// Whose mailbox this arrived in — the address the gateway maps to a
    /// subscriber id.
    ///
    /// **A gateway keys its device registry on the fingerprint where
    /// there is one**, not on the login beside it. uids recycle in
    /// minutes and logins recycle on a rename, and a push addressed by
    /// either is a stranger's private message on the wrong person's
    /// phone — the failure push-notifications.md §5 calls the worst bug
    /// this subsystem can have. The login is there for the log.
    pub to: &'a Mailbox,
    /// The sender, when the sender has a mailbox to be replied to.
    pub from: Option<&'a Mailbox>,
    /// The sender's nickname as displayed when it was sent.
    pub from_nick: &'a str,
    pub text: &'a str,
    /// The stored message, so a client woken by this can name it.
    pub id: MessageId,
    /// The recipient's unread count *after* this message — a badge number
    /// the gateway can pass through without asking us again.
    pub unread: usize,
}

/// An article that is someone's business: a reply to theirs, a citation
/// of theirs, or news in something they follow (`docs/news.md` §10.5).
///
/// There is no stored notification behind it. The article is the durable
/// thing, and a client woken by this opens the thread, where the article
/// will be next year too (§10.4).
#[derive(Debug, Clone, Copy)]
pub struct NewsNotice<'a> {
    /// Keyed as [`MessageNotice::to`] is, and for the same reason.
    pub to: &'a Mailbox,
    /// Why this mailbox is in the audience — the highest-precedence reason
    /// that applied, which is what the notification's text should say.
    pub reason: NotifyReason,
    /// The poster's nickname as it was when they posted.
    pub from_nick: &'a str,
    pub subject: &'a str,
    /// The opening of the body, capped. Whether it is sent is the
    /// gateway's call, not ours — the same content-policy split
    /// [`MessageNotice::text`] documents.
    pub excerpt: &'a str,
    pub article: ArticleId,
    pub root: ArticleId,
    pub category: NodeId,
    /// The subscription this counts against. Its [`SubScope::key`] is the
    /// collapse key — `thread:398` — so two pushes for one scope that are
    /// somehow both in flight collapse on the device (§10.7).
    pub scope: SubScope,
    /// Unread in `scope` after this article: a number a gateway can put on
    /// the notification without asking us again.
    pub unread: usize,
}

/// The seam `hxd-push-uniqush` (or any other gateway) implements.
pub trait NotificationGateway: Send + Sync + 'static {
    /// Someone who is not attentive has something to hear about.
    ///
    /// **Best effort, and must not block.** It is called on the private
    /// message and news paths with no lock held, and a slow provider must
    /// not become this server's latency: an implementation spawns and
    /// returns. A push that never arrives is a degraded notification, not
    /// a lost message — the message is in the inbox, and the article is in
    /// its thread, either way.
    fn notify(&self, n: &Notification<'_>);
}
