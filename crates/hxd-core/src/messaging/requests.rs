//! Message requests and approvals (`docs/instant-messaging.md` §4): a
//! message by login from someone with an account who is not a friend,
//! held until its recipient approves the conversation, makes the sender
//! a friend or deletes it.
//!
//! **One answer for the sender.** A request is answered `Requested`
//! whether it was stored, held or dropped, and every bound counts what
//! the ledger says was sent, so nothing the recipient did shows in what
//! the sender is told (§4.2, §4.4).

use std::collections::HashSet;
use std::time::SystemTime;

use super::im::understands_requests;
use super::{store_failed, Key, Me, MessagingError};
use crate::chat::{ChatError, MsgOutcome, SignedMsg};
use crate::inbox::{Mailbox, MessageGuid, MessageKind, NewMessage, Pushed, StoredMessage};
use crate::relationships::{LedgerEntry, Recorded, RequestKind, Requester, SentOn};
use crate::roster::{Event, Uid};
use crate::Core;

/// What an answer to a message request does (§7's
/// `DATA_REQUEST_ACTION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAction {
    /// Let the conversation through (§4.6).
    Approve,
    /// Delete the request, telling the sender nothing and holding it.
    Delete,
    /// End an approval, holding its sender as a delete does.
    End,
}

/// One sender's waiting requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestGroup {
    pub from: Mailbox,
    /// Oldest first, each with its inbox id so it can be reported.
    pub messages: Vec<StoredMessage>,
}

/// What a listing of requests answers (§4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestsListing {
    /// By sender, oldest first.
    pub requests: Vec<RequestGroup>,
    /// Who the caller has approved.
    pub approvals: Vec<Mailbox>,
    /// Requests dropped since the listing before.
    pub dropped: u64,
}

/// What clearing requests in bulk did (§4.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cleared {
    pub declined: usize,
    pub deleted: usize,
}

/// The sender of a message by login, as routing it asks.
struct Sending {
    mailbox: Mailbox,
    /// Its session takes part in messaging.
    takes_part: bool,
    /// It understands requests.
    understands: bool,
    /// It is on the classic wire, which need not understand requests,
    /// nor hold `AccessMessaging`, to send one (§4.1).
    classic: bool,
}

impl Core {
    /// Every request waiting for one recipient fits a listing.
    fn requests_bound(&self) -> usize {
        let p = self.messaging_policy;
        p.max_requests.saturating_mul(p.request_messages).max(1)
    }

    /// What is older lapsed, as a request not acted on does (§4.4).
    fn requests_since(&self) -> SystemTime {
        self.clock
            .wall()
            .checked_sub(self.messaging_policy.request_retention)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    /// The account `login` names, whether or not it takes part.
    pub(crate) fn any_account(&self, login: &str) -> Option<Mailbox> {
        self.directory.as_ref()?.account(login).map(|(m, _)| m)
    }

    /// Who is waiting with a request for `of`, oldest first.
    fn requesters(&self, of: &Mailbox) -> Vec<Mailbox> {
        let Some(store) = self.inbox.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<Mailbox> = Vec::new();
        for m in store
            .requests(of, self.requests_since(), self.requests_bound())
            .unwrap_or_default()
        {
            if let Some(s) = m
                .sender
                .filter(|s| !out.iter().any(|o| Key::of(o) == Key::of(s)))
            {
                out.push(s);
            }
        }
        out
    }

    /// Tell `of`'s sessions that understand requests how many senders
    /// wait.
    fn requests_changed(&self, of: &Mailbox) {
        let count = self.requesters(of).len();
        let mut r = self.roster.lock().unwrap();
        let to: Vec<Uid> = r
            .messengers(&Key::of(of))
            .into_iter()
            .filter(|u| r.users.get(u).is_some_and(understands_requests))
            .collect();
        for uid in to {
            r.send_to(uid, Event::RequestsChanged { count });
        }
    }

    /// A message by login to an account taking part
    /// (`docs/instant-messaging.md` §4.1): to a friend an instant
    /// message, under an approval one answered as queued, and to anyone
    /// else a request or a refusal; to a classic sender outside messaging
    /// whose request waits, or that is approved, a message under the
    /// approval. `None` where it is none of these and goes as a private
    /// message always has: messaging off, any other account outside it,
    /// a guest, or mail to oneself.
    pub(crate) fn messaging_route(
        &self,
        uid: Uid,
        to: &str,
        text: &str,
        guid: &Option<MessageGuid>,
        media: bool,
        signed: &Option<SignedMsg>,
    ) -> Option<Result<MsgOutcome, ChatError>> {
        if !self.messaging_enabled() {
            return None;
        }
        let (them, takes_part) = match self.messaging_account(to) {
            Ok(them) => (them, true),
            Err(_) => (self.any_account(to)?, false),
        };
        let sending = {
            let r = self.roster.lock().unwrap();
            let s = r.users.get(&uid)?;
            if !s.has_inbox || s.login == "guest" {
                return None;
            }
            Sending {
                mailbox: s.mailbox(),
                takes_part: s.messaging.is_some(),
                understands: s.messaging.as_ref().is_some_and(|m| m.understands_requests),
                classic: s.reads_on_delivery,
            }
        };
        if Key::of(&sending.mailbox) == Key::of(&them) {
            return None;
        }
        if !takes_part {
            let me = &sending.mailbox;
            let asked = sending.understands
                && self
                    .requesters(me)
                    .iter()
                    .any(|s| Key::of(s) == Key::of(&them));
            let approved = sending.takes_part && self.approval(me, &them).ok().flatten().is_some();
            if media || !(asked || approved) {
                return None;
            }
        }
        let friend = if sending.takes_part {
            match self.friendship(&sending.mailbox, &them) {
                Ok(f) => f,
                Err(_) => return Some(Err(ChatError::ServerError)),
            }
        } else {
            None
        };
        // A block reads as no account at all, whatever is sent.
        if takes_part {
            match self
                .friends_store()
                .ok()?
                .is_blocked(&them, &sending.mailbox)
            {
                Ok(true) => return Some(Err(ChatError::NoSuchUser)),
                Ok(false) => {}
                Err(e) => return Some(Err(chat_error(store_failed(e)))),
            }
        }
        // An image, or text too long for an instant message, goes to a
        // friend as a private message, as it always has, and is no
        // stranger's first contact.
        if media || text.len() > self.messaging_policy.max_message_bytes {
            return friend.is_none().then_some(Err(ChatError::NotFriends));
        }
        Some(self.route(uid, sending, them, friend, text, guid, signed))
    }

    #[allow(clippy::too_many_arguments)]
    fn route(
        &self,
        uid: Uid,
        sending: Sending,
        them: Mailbox,
        friend: Option<crate::RelationId>,
        text: &str,
        guid: &Option<MessageGuid>,
        signed: &Option<SignedMsg>,
    ) -> Result<MsgOutcome, ChatError> {
        let rel = self.friends_store().map_err(chat_error)?;
        let me = Me {
            mailbox: sending.mailbox.clone(),
            understands: sending.understands,
        };
        // A block reads as no account at all, before any bound.
        if rel
            .is_blocked(&them, &me.mailbox)
            .map_err(|e| chat_error(store_failed(e)))?
        {
            return Err(ChatError::NoSuchUser);
        }
        if signed
            .as_ref()
            .is_some_and(|s| them.fingerprint != Some(s.to))
        {
            return Err(ChatError::SignedElsewhere);
        }
        // A retry of a request is answered as the request was, whatever
        // the two have become since (§4.4).
        if let Some(g) = guid {
            let sender = Requester::Account(me.mailbox.clone());
            if rel
                .find_request(&sender, Some(&them), g)
                .map_err(|e| chat_error(store_failed(e)))?
                .is_some()
            {
                return Ok(MsgOutcome::Requested);
            }
        }
        let store = |on| {
            self.im_store(
                uid,
                &me,
                &them,
                on,
                text.to_string(),
                guid.clone(),
                signed.clone(),
            )
            .map(|sent| match (sent.delivered, sent.id) {
                (false, Some(id)) => MsgOutcome::Queued(id),
                _ => MsgOutcome::Delivered,
            })
            .map_err(chat_error)
        };
        if let Some(id) = friend {
            return store((id, false));
        }
        if rel
            .is_blocked(&me.mailbox, &them)
            .map_err(|e| chat_error(store_failed(e)))?
        {
            return Err(ChatError::NotFriends);
        }
        if let Some(id) = self.approval(&me.mailbox, &them).map_err(chat_error)? {
            return store((id, true));
        }
        // Writing back is consent to the conversation (§4.3), from a
        // session that understands requests.
        if sending.understands
            && self
                .requesters(&me.mailbox)
                .iter()
                .any(|s| Key::of(s) == Key::of(&them))
        {
            let id = self
                .approve_requests(&me.mailbox, &them)
                .map_err(chat_error)?;
            return store((id, true));
        }
        // The sender understands requests, a classic sender aside, which
        // is exempt (§4.1), whether or not its own account takes them;
        // the recipient's account takes them.
        let may_ask = sending.classic || (sending.takes_part && sending.understands);
        let account = rel
            .account(&them)
            .map_err(|e| chat_error(store_failed(e)))?;
        if !may_ask || !account.takes_requests {
            return Err(ChatError::NotFriends);
        }
        self.request(
            uid,
            &me.mailbox,
            &them,
            text,
            guid,
            signed,
            account.requests_opted_at,
        )
        .map_err(chat_error)?;
        Ok(MsgOutcome::Requested)
    }

    /// Ask `them` for a conversation (§4.4): bounded, written to the
    /// ledger, then stored, held or dropped, answered the same.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        uid: Uid,
        me: &Mailbox,
        them: &Mailbox,
        text: &str,
        guid: &Option<MessageGuid>,
        signed: &Option<SignedMsg>,
        opted_at: Option<SystemTime>,
    ) -> Result<(), MessagingError> {
        let rel = self.friends_store()?;
        let inbox = self.inbox_store()?;
        let p = self.messaging_policy;
        let now = self.clock.wall();
        let sender = Requester::Account(me.clone());
        // What an approval later hands over as 811 needs one.
        let stored_guid = match guid {
            Some(g) => g.clone(),
            None => super::im::new_guid()?,
        };
        // Under the lock a block's cleanup takes, so a block made since
        // `route` looked is seen here or deletes what this stores, and
        // the bounds are read and the ledger written as one.
        let _writing = self.friend_writes();
        if rel.is_blocked(them, me).map_err(store_failed)? {
            return Err(MessagingError::AccountNotFound);
        }
        if let (Some(_), Some(g)) = (signed, guid) {
            if self.signed_elsewhere(me, them, g).map_err(store_failed)? {
                return Err(MessagingError::Equivocation);
            }
        }
        let retained = now
            .checked_sub(p.request_retention)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if rel
            .requests_to(&sender, them, RequestKind::Message, retained)
            .map_err(store_failed)?
            >= p.request_messages
        {
            return Err(MessagingError::RequestFull);
        }
        let addr = self.request_address(uid);
        self.request_bounds(rel, &sender, addr.as_deref(), them, now)?;
        if self
            .send_quota_spent(&**inbox, me, text.len(), now)
            .map_err(|_| MessagingError::ServerError)?
        {
            return Err(MessagingError::RateLimited);
        }
        let signed = signed.as_ref().map(|s| s.signature.clone());
        if let Recorded::Retry(_) = rel
            .record_request(&LedgerEntry {
                kind: RequestKind::Message,
                sender: Some(me.clone()),
                address: addr,
                recipient: them.clone(),
                guid: guid.clone(),
                bytes: text.len() as u64,
                at: now,
            })
            .map_err(store_failed)?
        {
            return Ok(());
        }
        if rel.is_held(them, &sender, now).map_err(store_failed)? {
            return Ok(());
        }
        // A recipient none of whose sessions has opted in for a while,
        // and none of whose sessions that understand requests is there
        // now, is answered as one taking requests, so a stranger cannot
        // tell when one last did.
        let lapsed = opted_at.is_some_and(|at| at < retained) && {
            let r = self.roster.lock().unwrap();
            !r.taking_part(them)
                .iter()
                .any(|u| r.users.get(u).is_some_and(understands_requests))
        };
        let waiting = self.requesters(them);
        let new = !waiting.iter().any(|s| Key::of(s) == Key::of(me));
        if lapsed || (new && waiting.len() >= p.max_requests) {
            rel.request_dropped(them).map_err(store_failed)?;
            return Ok(());
        }
        let nick = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .map(|s| s.info.nick.clone())
                .unwrap_or_default()
        };
        let pushed = inbox
            .push(
                &NewMessage {
                    recipient: them.clone(),
                    sender: Some(me.clone()),
                    sender_nick: nick,
                    body: text.to_string(),
                    sent_at: now,
                    guid: Some(stored_guid),
                    kind: MessageKind::Message,
                    media: None,
                    signed,
                    friendship: Some(SentOn::Request),
                },
                self.inbox_policy.max_queued,
            )
            .map_err(store_failed)?;
        if pushed == Pushed::Full {
            rel.request_dropped(them).map_err(store_failed)?;
            return Ok(());
        }
        self.requests_changed(them);
        Ok(())
    }

    /// `me` approves `them`, whose waiting requests become the
    /// approval's and are handed over (§4.6).
    fn approve_requests(
        &self,
        me: &Mailbox,
        them: &Mailbox,
    ) -> Result<crate::RelationId, MessagingError> {
        let rel = self.friends_store()?;
        let inbox = self.inbox_store()?;
        let now = self.clock.wall();
        // Under the lock a block's cleanup takes, as a request is stored.
        let _writing = self.friend_writes();
        if rel.is_blocked(them, me).map_err(store_failed)?
            || rel.is_blocked(me, them).map_err(store_failed)?
        {
            return Err(MessagingError::NoSuchRequest);
        }
        if rel.roster_size(me, now).map_err(store_failed)? >= self.messaging_policy.max_roster {
            return Err(MessagingError::RosterFull);
        }
        let id = rel.approve(me, them, now).map_err(store_failed)?;
        inbox
            .release_requests(me, them, id, self.requests_since())
            .map_err(store_failed)?;
        self.requests_changed(me);
        self.im_deliver(me, None, 0, true);
        Ok(id)
    }

    /// `me`'s requests from `them`, and its pending friend request,
    /// become `friendship`'s, which takes over its approvals' queued
    /// messages too (§4.3, §4.6). Called once the friendship is made.
    pub(crate) fn friendship_releases(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        friendship: crate::RelationId,
        approvals: &[crate::RelationId],
    ) {
        let Some(inbox) = self.inbox.as_ref() else {
            return;
        };
        let merged: Vec<_> = approvals.iter().map(|id| (*id, friendship)).collect();
        let since = self.requests_since();
        let released = inbox.restamp(&merged).and_then(|_| {
            Ok(inbox.release_requests(a, b, friendship, since)?
                + inbox.release_requests(b, a, friendship, since)?)
        });
        match released {
            Ok(0) => {}
            Ok(_) => {
                self.requests_changed(a);
                self.requests_changed(b);
            }
            Err(e) => tracing::warn!("inbox: releasing onto a friendship: {e}"),
        }
        self.im_deliver(a, None, 0, false);
        self.im_deliver(b, None, 0, false);
    }

    /// The caller's message requests and approvals (§4.5). Listing makes
    /// the session one that understands requests, and leaves whether its
    /// account takes them as it was (§4.1).
    pub fn requests_list(&self, uid: Uid) -> Result<RequestsListing, MessagingError> {
        let me = self.messenger(uid)?;
        let rel = self.friends_store()?;
        let inbox = self.inbox_store()?;
        if let Some(m) = self
            .roster
            .lock()
            .unwrap()
            .users
            .get_mut(&uid)
            .and_then(|s| s.messaging.as_mut())
        {
            m.understands_requests = true;
        }
        let now = self.clock.wall();
        let dropped = rel.requests_listed(&me.mailbox).map_err(store_failed)?;
        let mut requests: Vec<RequestGroup> = Vec::new();
        for m in inbox
            .requests(&me.mailbox, self.requests_since(), self.requests_bound())
            .map_err(store_failed)?
        {
            let Some(from) = m.sender.clone() else {
                continue;
            };
            match requests
                .iter_mut()
                .find(|g| Key::of(&g.from) == Key::of(&from))
            {
                Some(g) => g.messages.push(m),
                None => requests.push(RequestGroup {
                    from,
                    messages: vec![m],
                }),
            }
        }
        let approvals = rel
            .relationships(&me.mailbox, now)
            .map_err(store_failed)?
            .into_iter()
            .filter(|r| r.approval.is_some())
            .map(|r| r.other)
            .collect();
        Ok(RequestsListing {
            requests,
            approvals,
            dropped,
        })
    }

    /// Answer the request `login` sent the caller, or end its approval.
    pub fn request_answer(
        &self,
        uid: Uid,
        login: &str,
        action: RequestAction,
    ) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let them = self
            .any_account(login)
            .ok_or(MessagingError::NoSuchRequest)?;
        let rel = self.friends_store()?;
        let inbox = self.inbox_store()?;
        let waiting = self
            .requesters(&me.mailbox)
            .iter()
            .any(|s| Key::of(s) == Key::of(&them));
        match action {
            RequestAction::Approve if waiting => {
                self.approve_requests(&me.mailbox, &them)?;
            }
            RequestAction::Delete if waiting => {
                inbox
                    .delete_requests(&me.mailbox, &them)
                    .map_err(store_failed)?;
                self.hold_sender(&me.mailbox, &them)?;
                self.requests_changed(&me.mailbox);
            }
            RequestAction::End => {
                rel.end_approval(&me.mailbox, &them)
                    .map_err(store_failed)?
                    .ok_or(MessagingError::NoSuchRequest)?;
                self.hold_sender(&me.mailbox, &them)?;
            }
            RequestAction::Approve | RequestAction::Delete => {
                return Err(MessagingError::NoSuchRequest)
            }
        }
        Ok(())
    }

    fn hold_sender(&self, me: &Mailbox, them: &Mailbox) -> Result<(), MessagingError> {
        let until = self.clock.wall() + self.messaging_policy.request_retention;
        self.friends_store()?
            .hold(me, &Requester::Account(them.clone()), until)
            .map_err(store_failed)
    }

    /// Decline every friend request and delete every message request
    /// received in `since`..`before`, each optional (§4.3): a message
    /// request by its first waiting message. Each sender is held, and
    /// told, as one decline or delete would hold and tell it, and the
    /// caller's sessions hear once that the requests changed.
    pub fn requests_clear(
        &self,
        uid: Uid,
        since: Option<SystemTime>,
        before: Option<SystemTime>,
    ) -> Result<Cleared, MessagingError> {
        let me = self.messenger(uid)?;
        let rel = self.friends_store()?;
        let inbox = self.inbox_store()?;
        let now = self.clock.wall();
        let within = |t: SystemTime| since.is_none_or(|s| t >= s) && before.is_none_or(|b| t < b);
        let mut cleared = Cleared::default();
        let mut seen: HashSet<Key> = HashSet::new();
        for m in inbox
            .requests(&me.mailbox, self.requests_since(), self.requests_bound())
            .map_err(store_failed)?
        {
            let Some(from) = m.sender else {
                continue;
            };
            if !seen.insert(Key::of(&from)) || !within(m.sent_at) {
                continue;
            }
            inbox
                .delete_requests(&me.mailbox, &from)
                .map_err(store_failed)?;
            self.hold_sender(&me.mailbox, &from)?;
            cleared.deleted += 1;
        }
        let _writing = self.friend_writes();
        for theirs in rel.pending_in(&me.mailbox, now).map_err(store_failed)? {
            if theirs
                .pending_out
                .as_ref()
                .is_some_and(|p| within(p.sent_at))
            {
                self.decline(rel, &me.mailbox, &theirs.owner, now)?;
                cleared.declined += 1;
            }
        }
        self.requests_changed(&me.mailbox);
        Ok(cleared)
    }

    /// A block deletes what the blocker and the blocked asked each other
    /// (§4.1, §4.3).
    pub(crate) fn block_deletes_requests(&self, blocker: &Mailbox, blocked: &Mailbox) {
        let Some(inbox) = self.inbox.as_ref() else {
            return;
        };
        let deleted = inbox
            .delete_requests(blocker, blocked)
            .and_then(|n| Ok(n + inbox.delete_requests(blocked, blocker)?));
        match deleted {
            Ok(0) => {}
            Ok(_) => {
                self.requests_changed(blocker);
                self.requests_changed(blocked);
            }
            Err(e) => tracing::warn!("inbox: deleting what a block ends: {e}"),
        }
    }
}

/// A messaging refusal on the private-message path, by the names that
/// path answers with.
fn chat_error(e: MessagingError) -> ChatError {
    match e {
        MessagingError::NotFriends | MessagingError::NotEnabled => ChatError::NotFriends,
        MessagingError::RequestFull => ChatError::RequestFull,
        MessagingError::RosterFull => ChatError::RosterFull,
        MessagingError::RateLimited => ChatError::SendQuota,
        MessagingError::QueueFull => ChatError::MailboxFull,
        MessagingError::SignedElsewhere => ChatError::SignedElsewhere,
        MessagingError::Equivocation => ChatError::Equivocation,
        // A request a block has just deleted reads as no account, as the
        // block does.
        MessagingError::AccountNotFound
        | MessagingError::Blocked
        | MessagingError::NoSuchRequest => ChatError::NoSuchUser,
        MessagingError::MessageTooLong
        | MessagingError::AlreadyFriends
        | MessagingError::RequestPending
        | MessagingError::NotDeviceProved
        | MessagingError::BadSignature
        | MessagingError::Withdrawn
        | MessagingError::Stale
        | MessagingError::TooMany
        | MessagingError::ServerError => ChatError::ServerError,
    }
}
