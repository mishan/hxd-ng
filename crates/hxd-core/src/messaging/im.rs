//! Instant messages between friends, their receipts and typing
//! (`docs/instant-messaging.md` §5), on the inbox.
//!
//! An instant message is an inbox row carrying the friendship it was
//! sent on, so the store's gate holds it once that friendship ends. It is
//! handed live to the recipient's messenger sessions, which acknowledge
//! it (812), and again at their next roster read until one does; a
//! session that does not speak the friend family is handed it as a
//! private message instead, which counts as its delivery.
//!
//! What was sent under an approval (§4.6) goes only to the sessions that
//! understand requests, since a client that does not know approvals
//! has nowhere to show it, or as private messages to a party whose account
//! never took requests; it never says when it arrived, and nor does a
//! delivery receipt for it.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use tracing::warn;

use super::{is_messenger, store_failed, Key, Me, MessagingError, Presence};
use crate::chat::{sessions_of, SignedMsg};
use crate::inbox::{
    Delivery, Mailbox, MessageGuid, MessageId, MessageKind, MessageStore, NewMessage, Pending,
    Pushed, StoredMessage,
};
use crate::relationships::{RelationId, SentOn};
use crate::roster::{is_live, Event, RosterInner, Uid, UserSession};
use crate::Core;

/// An instant message as it reaches a messenger session (IM Deliver,
/// 811).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Im {
    pub from_login: String,
    pub from_fingerprint: Option<[u8; 32]>,
    pub from_nick: String,
    pub text: String,
    /// The inbox row, which a client marks read by; `None` for one
    /// handed over live past the sender's quota, with no row.
    pub id: Option<MessageId>,
    pub guid: MessageGuid,
    pub sent_at: SystemTime,
    /// It waited rather than arriving in the moment.
    pub queued: bool,
    /// A signed message's detached form (`docs/e2e-messages.md` §4.9).
    pub signed: Option<Vec<u8>>,
    /// Sent under an approval rather than a friendship.
    pub approval: bool,
}

/// What became of an instant message: `OK` where a messenger session
/// took it, or a private message was handed over, and `OfflineQueued`
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImSent {
    /// `None` where nothing was stored.
    pub id: Option<MessageId>,
    pub guid: MessageGuid,
    pub delivered: bool,
}

/// A fresh guid for a message sent without one, since 811 requires
/// `DATA_MESSAGE_GUID`: a random (version 4) UUID.
pub(super) fn new_guid() -> Result<MessageGuid, MessagingError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| MessagingError::ServerError)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    MessageGuid::parse(&hex).ok_or(MessagingError::ServerError)
}

fn im_of(m: StoredMessage, queued: bool, approval: bool) -> Option<Event> {
    let sender = m.sender?;
    Some(Event::Im(Box::new(Im {
        from_login: sender.login,
        from_fingerprint: sender.fingerprint,
        from_nick: m.sender_nick,
        text: m.body,
        id: Some(m.id),
        guid: m.guid?,
        sent_at: m.sent_at,
        queued,
        signed: m.signed.map(|s| s.form),
        approval,
    })))
}

fn relation_of(m: &StoredMessage) -> Option<RelationId> {
    match m.friendship {
        Some(SentOn::Relation(id)) => Some(id),
        _ => None,
    }
}

/// A messenger session that understands requests, so it is shown what
/// an approval carries.
pub(crate) fn understands_requests(s: &UserSession) -> bool {
    s.messaging
        .as_ref()
        .is_some_and(|m| m.messenger && m.understands_requests)
}

impl Core {
    pub(crate) fn inbox_store(&self) -> Result<&Arc<dyn MessageStore>, MessagingError> {
        self.inbox.as_ref().ok_or(MessagingError::NotEnabled)
    }

    /// The live friendship between `me` and `them`, if neither has
    /// blocked the other.
    pub(crate) fn friendship(
        &self,
        me: &Mailbox,
        them: &Mailbox,
    ) -> Result<Option<RelationId>, MessagingError> {
        let store = self.friends_store()?;
        let now = self.clock.wall();
        let mine = store.relationship(me, them, now).map_err(store_failed)?;
        let blocked = store.is_blocked(them, me).map_err(store_failed)?;
        Ok(mine
            .filter(|m| m.blocked_at.is_none() && !blocked)
            .and_then(|m| m.friendship))
    }

    /// The live approval between `a` and `b`, given by either.
    pub(crate) fn approval(
        &self,
        a: &Mailbox,
        b: &Mailbox,
    ) -> Result<Option<RelationId>, MessagingError> {
        let store = self.friends_store()?;
        let now = self.clock.wall();
        for (owner, other) in [(a, b), (b, a)] {
            if let Some(id) = store
                .relationship(owner, other, now)
                .map_err(store_failed)?
                .and_then(|r| r.approval)
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The approvals among what `rows` were sent on to `to`.
    pub(crate) fn approval_ids(&self, to: &Mailbox, rows: &[StoredMessage]) -> HashSet<RelationId> {
        let mut senders: Vec<&Mailbox> = Vec::new();
        for m in rows.iter().filter(|m| relation_of(m).is_some()) {
            if let Some(s) = m.sender.as_ref().filter(|s| !senders.contains(s)) {
                senders.push(s);
            }
        }
        senders
            .into_iter()
            .filter_map(|s| self.approval(to, s).ok().flatten())
            .collect()
    }

    /// No session of `of` has ever turned its account's switch on: it
    /// can be sent an approval's traffic only as private messages. A
    /// switch turned off since stops new requests and nothing else.
    pub(crate) fn never_took_requests(&self, of: &Mailbox) -> bool {
        self.relationships
            .as_ref()
            .and_then(|s| s.account(of).ok())
            .is_none_or(|a| a.requests_opted_at.is_none())
    }

    /// IM Send (810): a message to a friend, onto the inbox. A
    /// stranger is answered `NotFriends`.
    pub fn im_send(
        &self,
        uid: Uid,
        to: &str,
        text: String,
        guid: Option<MessageGuid>,
        signed: Option<SignedMsg>,
    ) -> Result<ImSent, MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, to)?;
        let id = self
            .friendship(&me.mailbox, &them)?
            .ok_or(MessagingError::NotFriends)?;
        self.im_store(uid, &me, &them, (id, false), text, guid, signed)
    }

    /// Store a message on the friendship or approval `on` (`true` for an
    /// approval) and hand it over. An approval's is answered as queued
    /// whoever took it.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn im_store(
        &self,
        uid: Uid,
        me: &Me,
        them: &Mailbox,
        on: (RelationId, bool),
        text: String,
        guid: Option<MessageGuid>,
        signed: Option<SignedMsg>,
    ) -> Result<ImSent, MessagingError> {
        let (on, approval) = on;
        if text.len() > self.messaging_policy.max_message_bytes {
            return Err(MessagingError::MessageTooLong);
        }
        let signed = match signed {
            None => None,
            Some(s) if them.fingerprint == Some(s.to) => Some(s.signature),
            Some(_) => return Err(MessagingError::SignedElsewhere),
        };
        let content = signed.as_ref().map(|s| s.content);
        let store = self.inbox_store()?;
        let now = self.clock.wall();
        if let (Some(_), Some(g)) = (&signed, &guid) {
            if self
                .signed_elsewhere(&me.mailbox, them, g)
                .map_err(store_failed)?
            {
                return Err(MessagingError::Equivocation);
            }
        }
        // A retry stores nothing and is not the quota's to refuse.
        let spent = self
            .send_quota_spent(&**store, &me.mailbox, text.len(), now)
            .map_err(|_| MessagingError::ServerError)?
            && match &guid {
                Some(g) => store
                    .find_guid(them, Some(&me.mailbox), g)
                    .map_err(store_failed)?
                    .is_none(),
                None => true,
            };
        let guid = match guid {
            Some(g) => g,
            None => new_guid()?,
        };
        let nick = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .map(|s| s.info.nick.clone())
                .unwrap_or_default()
        };
        if spent {
            // The sender's daily quota (`docs/private-messages.md` §9)
            // bounds storage and never conversation: past it, a friend's
            // message reaches an attached session live with no row, as
            // mail does, and is refused only with none there. An
            // approval's is answered as queued whoever takes it, which
            // only a row can be.
            if approval {
                return Err(MessagingError::RateLimited);
            }
            // Behind any hand-over under way, so it overtakes nothing older.
            let _flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());
            let mut r = self.roster.lock().unwrap();
            let (messengers, plain): (Vec<Uid>, Vec<Uid>) = sessions_of(&r, them)
                .into_iter()
                .filter(|u| r.users.get(u).is_some_and(is_live))
                .partition(|u| r.users.get(u).is_some_and(is_messenger));
            if messengers.is_empty() && plain.is_empty() {
                return Err(MessagingError::RateLimited);
            }
            // No row, so a plain session beside a messenger has nothing
            // to be handed later: it hears it now, as mail.
            let form = signed.map(|s| s.form);
            let mail = Event::Msg {
                from: uid,
                from_nick: nick.clone(),
                from_login: Some(me.mailbox.login.clone()),
                text: text.clone(),
                id: None,
                sent_at: now,
                queued: false,
                media: None,
                signed: form.clone(),
            };
            let im = Event::Im(Box::new(Im {
                from_login: me.mailbox.login.clone(),
                from_fingerprint: me.mailbox.fingerprint,
                from_nick: nick,
                text,
                id: None,
                guid: guid.clone(),
                sent_at: now,
                queued: false,
                signed: form,
                approval: false,
            }));
            for u in messengers {
                r.send_to(u, im.clone());
            }
            for u in plain {
                r.send_to(u, mail.clone());
            }
            return Ok(ImSent {
                id: None,
                guid,
                delivered: true,
            });
        }
        let pushed = store
            .push(
                &NewMessage {
                    recipient: them.clone(),
                    sender: Some(me.mailbox.clone()),
                    sender_nick: nick.clone(),
                    body: text.clone(),
                    sent_at: now,
                    guid: Some(guid.clone()),
                    kind: MessageKind::Message,
                    media: None,
                    signed,
                    friendship: Some(SentOn::Relation(on)),
                },
                self.inbox_policy.max_queued,
            )
            .map_err(store_failed)?;
        let (id, fresh) = match pushed {
            Pushed::Stored(id) => (id, true),
            // A signed message whose id was used for other words.
            Pushed::Existing(m)
                if content.is_some() && m.signed.as_ref().map(|was| was.content) != content =>
            {
                return Err(MessagingError::Equivocation)
            }
            // A retry is that message, answered as of now, and an
            // approval's as queued whatever became of it.
            Pushed::Existing(m) if m.delivered_at.is_some() => {
                return Ok(ImSent {
                    id: Some(m.id),
                    guid,
                    delivered: !approval,
                })
            }
            Pushed::Existing(m) => (m.id, false),
            Pushed::Full => return Err(MessagingError::QueueFull),
        };
        let delivered = self
            .im_deliver(them, fresh.then_some(id), uid, approval)
            .contains(&id)
            && !approval;
        if fresh {
            self.im_notify(them, &me.mailbox, &nick, &text, id);
        }
        Ok(ImSent {
            id: Some(id),
            guid,
            delivered,
        })
    }

    /// Hand `to`'s waiting instant messages over live: to every attached
    /// messenger session, what an approval carries to those that
    /// understand requests alone, or, where it has none, to every attached
    /// session as private messages. `under_approval` says an approval's
    /// rows may be among them. Returns the ids handed over.
    pub(crate) fn im_deliver(
        &self,
        to: &Mailbox,
        fresh: Option<MessageId>,
        sender: Uid,
        under_approval: bool,
    ) -> Vec<MessageId> {
        let Some(store) = self.inbox.as_ref() else {
            return Vec::new();
        };
        let flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());
        let (messengers, plain, understood) = {
            let r = self.roster.lock().unwrap();
            let attached: Vec<Uid> = sessions_of(&r, to)
                .into_iter()
                .filter(|u| *u != sender && r.users.get(u).is_some_and(is_live))
                .collect();
            let (m, p): (Vec<Uid>, Vec<Uid>) = attached
                .into_iter()
                .partition(|u| r.users.get(u).is_some_and(is_messenger));
            let understood = m
                .iter()
                .any(|u| r.users.get(u).is_some_and(understands_requests));
            (m, p, understood)
        };
        if messengers.is_empty() {
            drop(flushing);
            return self.flush_each(plain, to, fresh, sender);
        }
        let batch = match store.pending_of(
            to,
            self.inbox_policy.deliver_at_flush,
            Pending::Instant {
                again: false,
                approvals: understood,
            },
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!("inbox: reading {}'s instant messages: {e}", to.login);
                return Vec::new();
            }
        };
        let approvals = self.approval_ids(to, &batch);
        let mut handed = Vec::new();
        {
            let mut r = self.roster.lock().unwrap();
            for m in batch {
                let (id, queued) = (m.id, Some(m.id) != fresh);
                let approval = relation_of(&m).is_some_and(|id| approvals.contains(&id));
                // Still attached, since the roster lock was let go for
                // the read.
                let to: Vec<Uid> = messengers
                    .iter()
                    .copied()
                    .filter(|u| {
                        r.users
                            .get(u)
                            .is_some_and(|s| is_live(s) && (!approval || understands_requests(s)))
                    })
                    .collect();
                if to.is_empty() {
                    continue;
                }
                let Some(ev) = im_of(m, queued, approval) else {
                    continue;
                };
                for uid in to {
                    r.send_to(uid, ev.clone());
                }
                handed.push(id);
            }
        }
        if let Err(e) = store.mark_handed(&handed, self.clock.wall()) {
            warn!("inbox: marking {} messages handed over: {e}", handed.len());
        }
        // An approval's rows, which no session here can be handed as IMs,
        // go as private messages to a party that never took requests.
        if under_approval && !understood && self.never_took_requests(to) {
            drop(flushing);
            handed.extend(self.flush_each(messengers, to, fresh, sender));
        }
        handed
    }

    /// What a roster read drains (`docs/instant-messaging.md` §5): the
    /// caller's instant messages not yet acknowledged, and the read
    /// receipts waiting for it, each up to `deliver_at_flush`.
    pub(crate) fn im_drain(&self, uid: Uid, me: &Mailbox) {
        let Some(store) = self.inbox.as_ref() else {
            return;
        };
        let _flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());
        let understands_of = |r: &RosterInner| {
            r.users
                .get(&uid)
                .filter(|s| is_live(s))
                .map(understands_requests)
        };
        // The read itself leaves out what an approval carries for a
        // session that does not understand requests, so that never takes
        // the places of what it can be shown.
        let Some(understood) = understands_of(&self.roster.lock().unwrap()) else {
            return;
        };
        let limit = self.inbox_policy.deliver_at_flush;
        let read = |which| {
            store.pending_of(me, limit, which).unwrap_or_else(|e| {
                warn!("inbox: draining {}'s: {e}", me.login);
                Vec::new()
            })
        };
        let ims = read(Pending::Instant {
            again: true,
            approvals: understood,
        });
        let receipts = read(Pending::Receipts {
            approvals: understood,
        });
        let approvals = self.approval_ids(me, &ims);
        {
            let mut r = self.roster.lock().unwrap();
            if understands_of(&r).is_none() {
                return;
            }
            for m in &ims {
                let approval = relation_of(m).is_some_and(|id| approvals.contains(&id));
                if let Some(ev) = im_of(m.clone(), true, approval) {
                    r.send_to(uid, ev);
                }
            }
            for m in &receipts {
                let (Some(from), Some(guid)) = (&m.sender, MessageGuid::parse(&m.body)) else {
                    continue;
                };
                r.send_to(
                    uid,
                    Event::Receipt {
                        login: from.login.clone(),
                        fingerprint: from.fingerprint,
                        guid,
                        read: true,
                    },
                );
            }
        }
        let now = self.clock.wall();
        let ids = |v: &[StoredMessage]| v.iter().map(|m| m.id).collect::<Vec<_>>();
        if let Err(e) = store.mark_handed(&ids(&ims), now) {
            warn!("inbox: marking messages handed over: {e}");
        }
        if let Err(e) = store.mark_delivered(&ids(&receipts), now, Delivery::Delivered) {
            warn!("inbox: marking receipts delivered: {e}");
        }
    }

    /// IM Acknowledge (812): the caller received, or read, the message
    /// `from` sent it under `guid`. Stamps it, and tells the sender while
    /// the two are friends, or of a read under an approval; a read is
    /// kept for a sender that is not there to hear it. Dropped silently
    /// between two accounts with no live friendship or approval, so a
    /// stranger learns nothing from one.
    pub fn im_ack(
        &self,
        uid: Uid,
        from: &str,
        guid: &MessageGuid,
        read: bool,
    ) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let store = self.inbox_store()?;
        let Some(sender) = self.any_account(from) else {
            return Ok(());
        };
        let Some(m) = store
            .find_guid(&me.mailbox, Some(&sender), guid)
            .map_err(store_failed)?
        else {
            return Ok(());
        };
        let (id, approval) = match self.friendship(&me.mailbox, &sender)? {
            Some(id) => (id, false),
            None => match self.approval(&me.mailbox, &sender)? {
                Some(id) => (id, true),
                None => return Ok(()),
            },
        };
        if m.friendship != Some(SentOn::Relation(id)) {
            return Ok(());
        }
        let what = if read {
            Delivery::Read
        } else {
            Delivery::Delivered
        };
        store
            .mark_delivered(&[m.id], self.clock.wall(), what)
            .map_err(store_failed)?;
        let receipt = Event::Receipt {
            login: me.mailbox.login.clone(),
            fingerprint: me.mailbox.fingerprint,
            guid: guid.clone(),
            read,
        };
        // What an approval shows is a read, to the party's sessions that
        // understand requests, whether or not its account takes them.
        if approval && !read {
            return Ok(());
        }
        // A read is told once, however often it is acknowledged.
        if read
            && !store
                .receipt_told(m.id, self.clock.wall())
                .map_err(store_failed)?
        {
            return Ok(());
        }
        // To attached sessions alone: a detached one is handed what is
        // kept for it at its next roster read, and only once.
        let told = {
            let mut r = self.roster.lock().unwrap();
            let to: Vec<Uid> = r
                .messengers(&Key::of(&sender))
                .into_iter()
                .filter(|u| {
                    r.users
                        .get(u)
                        .is_some_and(|s| is_live(s) && (!approval || understands_requests(s)))
                })
                .collect();
            for uid in &to {
                r.send_to(*uid, receipt.clone());
            }
            !to.is_empty()
        };
        // A delivery receipt may be dropped; a read one is a person's
        // act, and waits for the sender's next roster read.
        if read && !told {
            let nick = {
                let r = self.roster.lock().unwrap();
                r.users
                    .get(&uid)
                    .map(|s| s.info.nick.clone())
                    .unwrap_or_default()
            };
            store
                .push(
                    &NewMessage {
                        recipient: sender,
                        sender: Some(me.mailbox),
                        sender_nick: nick,
                        body: guid.to_string(),
                        sent_at: self.clock.wall(),
                        guid: None,
                        kind: MessageKind::ReadReceipt,
                        media: None,
                        signed: None,
                        friendship: Some(SentOn::Relation(id)),
                    },
                    self.inbox_policy.max_queued,
                )
                .map_err(store_failed)?;
        }
        Ok(())
    }

    /// IM Typing (813): to the friend's messenger sessions alone, never
    /// stored, and dropped silently for anyone else.
    pub fn im_typing(&self, uid: Uid, to: &str, typing: bool) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let Ok(them) = self.other(&me, to) else {
            return Ok(());
        };
        if self.friendship(&me.mailbox, &them)?.is_none() {
            return Ok(());
        }
        self.roster.lock().unwrap().tell_mailbox(
            &them,
            Event::Typing {
                login: me.mailbox.login,
                fingerprint: me.mailbox.fingerprint,
                typing,
            },
        );
        Ok(())
    }

    /// The notify decision for an instant message, as a private
    /// message's is made (`docs/push-notifications.md` §6): a recipient
    /// with no attentive session hears of it, unless it is busy, which
    /// is what do-not-disturb means. Invisible still pushes: it hides the
    /// user from others, not from their own devices.
    fn im_notify(&self, to: &Mailbox, from: &Mailbox, nick: &str, text: &str, id: MessageId) {
        let Some(gateway) = self.gateway.as_ref() else {
            return;
        };
        let (attentive, busy) = {
            let r = self.roster.lock().unwrap();
            let sessions: Vec<_> = sessions_of(&r, to)
                .into_iter()
                .filter_map(|u| r.users.get(&u))
                .collect();
            let attentive = sessions
                .iter()
                .any(|s| s.info.status == crate::SessionStatus::Active && is_live(s));
            let best = sessions
                .iter()
                .map(|s| super::session_presence(s))
                .max_by_key(|p| p.rank());
            (attentive, best == Some(Presence::Busy))
        };
        if attentive || busy {
            return;
        }
        let unread = self
            .inbox
            .as_ref()
            .and_then(|s| s.counts(to).ok())
            .map_or(0, |c| c.unread);
        gateway.notify(&crate::notify::Notification::Message(
            crate::notify::MessageNotice {
                to,
                from: Some(from),
                from_nick: nick,
                text,
                id,
                unread,
            },
        ));
    }
}
