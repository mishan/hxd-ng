//! Chat rooms, messaging, and moderation — further `impl Core` blocks over
//! the roster state.
//!
//! Structural rules (membership, invitations, chat lifecycle) are enforced
//! here; *policy* (the access bitmap) is enforced by the frontend before it
//! calls in, because policy wording belongs with the wire ("You are not
//! allowed to send chat") and future frontends may gate differently. The
//! one exception is delivery-side filtering: public chat only reaches
//! sessions whose account can read chat, mirroring the reference server.
//!
//! Private chat semantics mirror mhxd's `chat.c`: numeric refs (0 is the
//! public chat and is never in the registry), invitation is optional — any
//! member can invite, joining an un-passworded chat needs no invitation,
//! an invitation bypasses the password, the last part deletes the chat.
//! One deliberate departure from the reference: chat ids come from the OS
//! CSPRNG rather than a counter, because the id is also a voice room's
//! whole address — see `RosterInner::next_chat_id`.
//!
//! All text is UTF-8 (`String`) — see the roster module docs for the
//! conversion rules at the legacy edge.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tracing::warn;

use crate::history::{HistoryPage, HistoryQuery, LineFlags, NewLine};
use crate::inbox::{
    Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageStore, NewMessage,
    StoreError, StoredMessage,
};
use crate::roster::{is_buffering, reads_public_chat, Event, RosterInner, Uid, UserInfo};
use crate::Core;

/// Who a private message is from, resolved once under the roster lock.
struct Sender {
    uid: Uid,
    nick: String,
    /// The sender's mailbox, when the sender is durable enough to be
    /// named later — held to reply to, and held to block.
    ///
    /// An account with an inbox qualifies. So does a session carrying an
    /// identity but no inbox: under `new_accounts = guest` an identity
    /// user is a *guest session with a fingerprint*, and a fingerprint is
    /// exactly what a block can be held against. What does not qualify is
    /// a plain guest, because `guest` is a login several people share
    /// rather than an address, and there is nothing there to block that
    /// would not also block everyone else who walks through that door.
    mailbox: Option<Mailbox>,
    /// The login a recipient can *reply* to, which is not the same
    /// question as the one above. An identity user admitted as a guest
    /// has a mailbox — a fingerprint is something a block can be held
    /// against — but its login is `guest`, and `msg_login` to `guest`
    /// answers `no_such_user`. Handing that login to a client as the
    /// sender is handing it a reply button that cannot work.
    reply_login: Option<String>,
    /// What this sender's uploads are held under, and half of the set a
    /// message with an image captures: the sender's mailbox where there
    /// is one, and the session itself for a plain guest
    /// (`docs/inline-media.md` §5.1).
    principal: crate::media::Principal,
}

impl Sender {
    fn resolve(r: &RosterInner, uid: Uid) -> Result<Sender, ChatError> {
        let sess = r.users.get(&uid).ok_or(ChatError::NoSuchUser)?;
        let durable = sess.has_inbox || sess.identity.is_some();
        let mailbox = durable.then(|| sess.mailbox());
        Ok(Sender {
            uid,
            nick: sess.info.nick.clone(),
            // A sender with a mailbox keeps its images across a
            // reconnect; a plain guest's are its session's, and go when
            // the session does.
            principal: match mailbox.clone() {
                Some(m) => crate::media::Principal::Mailbox(m),
                None => crate::media::Principal::Session {
                    uid,
                    serial: sess.serial,
                },
            },
            mailbox,
            reply_login: sess.has_inbox.then(|| sess.login.clone()),
        })
    }
}

/// A stored message's image as it stands at delivery: the live handle
/// where the store still has one, and the row's own metadata with no
/// handle where it does not. Never `None` for a row that had an image —
/// "[an image was here]" is worth rendering and an empty message is not.
fn media_now(
    handles: &HashMap<Vec<u8>, crate::media::MediaRef>,
    meta: &crate::history::MediaMeta,
) -> Option<crate::media::MediaRef> {
    handles.get(&meta.id).cloned().or_else(|| {
        crate::media::MediaRef::from_meta(meta).map(|r| crate::media::MediaRef { id: None, ..r })
    })
}

/// Who it is for: a mailbox, and its session if it has one.
struct Recipient {
    uid: Option<Uid>,
    mailbox: Mailbox,
    has_inbox: bool,
    /// The other half of a media set: this account's mailbox, or the
    /// session where there is no mailbox to hold a grant.
    principal: crate::media::Principal,
}

/// Which of a mailbox's sessions a flush should hand its mail to.
enum Target {
    /// This session or nobody: a session that has just attached asking
    /// for its own mail. If it is gone again, the mail stays pending.
    Only(Uid),
    /// The session the sender named, if it is attached, and otherwise
    /// whichever is (lowest uid). A legacy user clicking a name in the
    /// user list is naming a *device*: an account with a phone on uid 2
    /// and a laptop on uid 3, both live, should hear it on the one that
    /// was clicked. §15's multi-device question, answered: prefer the
    /// named session, else the lowest attached.
    Named(Option<Uid>),
}

/// Every visible session owning `mailbox`, lowest uid first.
///
/// Matching is [`Mailbox`]'s rule, not a login comparison: a session
/// logged in as `alice` with identity B must not be handed mail addressed
/// to the `alice` who held that login before, and that is exactly what
/// comparing logins would do.
fn sessions_of(r: &RosterInner, mailbox: &Mailbox) -> Vec<Uid> {
    let mut uids: Vec<Uid> = r
        .users
        .iter()
        .filter(|(_, s)| s.visible && mailbox.matches(&s.login, s.identity.as_ref()))
        .map(|(uid, _)| *uid)
        .collect();
    uids.sort_unstable();
    uids
}

/// The uid of a visible session owning `mailbox`, if one is on the roster.
/// Lowest uid wins, so the answer is stable when an account holds more
/// than one (docs/private-messages.md §14 — the multi-device question this
/// design defers). Used to name a *sender*, where any of their sessions
/// will do.
fn session_of(r: &RosterInner, mailbox: &Mailbox) -> Option<Uid> {
    sessions_of(r, mailbox).into_iter().next()
}

/// The session to hand `mailbox`'s mail to: an *attached* one, lowest uid
/// first, or none at all.
///
/// Lowest-uid-wins over every session was wrong, and quietly. An account
/// with a detached phone on uid 5 and an attached laptop on uid 9 had
/// every message aimed at the phone, which is buffering — so nothing was
/// delivered live and the laptop learned about it at its next sync.
///
/// And no fallback to a detached session: its outbox buffer is bounded
/// and dies with the grace window, so a message put there is a message
/// stamped delivered and then lost. Mail stays pending until somebody is
/// actually holding a socket.
fn attached_session_of(r: &RosterInner, mailbox: &Mailbox) -> Option<Uid> {
    sessions_of(r, mailbox)
        .into_iter()
        .find(|uid| r.users.get(uid).is_some_and(|s| !is_buffering(s)))
}

/// A store that would not answer is a server-side failure, not the
/// client's fault. The detail goes to the log; the client gets the
/// generic error, like every other backend failure here.
fn store_failed(e: StoreError) -> ChatError {
    warn!("inbox: {e}");
    ChatError::ServerError
}

fn history_store_failed(e: StoreError) -> ChatError {
    warn!("history: {e}");
    ChatError::ServerError
}

/// A private chat room. (`cid` 0 — the public chat — is represented by the
/// roster itself, not an entry here.)
#[derive(Default)]
pub(crate) struct PrivateChat {
    pub(crate) members: Vec<Uid>,
    pub(crate) invited: Vec<Uid>,
    pub(crate) subject: String,
    pub(crate) password: String,
}

/// A ban-list entry. Matching is by address (the reference server also
/// wildcards name/login in practice, so address is the discriminating key;
/// per-login bans can join it when the account admin work lands).
pub(crate) struct Ban {
    pub(crate) addr: Option<IpAddr>,
    pub(crate) expires: Instant,
}

/// Why a chat operation was refused. The frontend maps these to task-error
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    NoSuchUser,
    NoSuchChat,
    NotAMember,
    AlreadyThere,
    WrongPassword,
    /// The recipient has as many messages waiting as the server allows. Refusing is deliberate: a message the sender was told was
    /// delivered and which then quietly disappeared is the failure mode
    /// that destroys trust in a messaging system.
    MailboxFull,
    /// The recipient has blocked the sender. Named rather than hidden,
    /// matching fogWraith's `Blocked` (reason 3) so the two subsystems
    /// answer alike — see docs/private-messages.md §14 for the argument
    /// against, which is real and which interoperability outweighs.
    Blocked,
    /// This session has no mailbox of its own, so there is nowhere to
    /// keep a block or a read mark. Distinct from `NoSuchUser`, which is
    /// about whoever was named: telling a guest "no such user" when the
    /// answer is "you have no inbox" sends them looking for a typo.
    NoInbox,
    /// The handle a sender attached is not theirs, has expired, or was
    /// revoked. One answer for all three, so a sender cannot use a chat
    /// send to test whether someone else's handle exists.
    NoSuchMedia,
    /// The server couldn't complete the operation — a chat id the OS
    /// CSPRNG refused to produce, or an inbox that would not write. Not
    /// the client's fault and not something it can retry usefully.
    ServerError,
}

/// What became of a private message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgOutcome {
    /// Handed to a live connection.
    Delivered,
    /// Stored for a recipient who wasn't there to take it.
    Queued(MessageId),
}

impl Core {
    // --- Chat lines -----------------------------------------------------

    /// A public chat line. Delivered (sender included) to every visible
    /// session allowed to read chat.
    pub fn chat_public(
        &self,
        from: Uid,
        text: String,
        style: u16,
        media: Option<crate::media::Handle>,
    ) -> Result<Option<crate::history::LineId>, ChatError> {
        let _serial = self.log_serial.lock().unwrap();
        let (info, login, fingerprint, principal) = {
            let r = self.roster.lock().unwrap();
            let Some(sess) = r.users.get(&from) else {
                return Err(ChatError::NoSuchUser);
            };
            (
                sess.info.clone(),
                (sess.login != "guest").then(|| sess.login.clone()),
                sess.identity,
                crate::media::Principal::Session {
                    uid: from,
                    serial: sess.serial,
                },
            )
        };
        // Before the line is logged: a handle that is not this sender's,
        // or whose bytes have gone, means no line at all rather than a
        // line whose reference resolves for nobody.
        let media = match media {
            Some(handle) => Some((
                handle,
                self.media_for_send(from, &handle)
                    .map_err(|_| ChatError::NoSuchMedia)?,
            )),
            None => None,
        };
        let at = SystemTime::now();
        let id = match self.history.as_ref() {
            Some(log) => Some(
                log.append(&NewLine {
                    channel: 0,
                    from_nick: info.nick.clone(),
                    from_login: login,
                    from_fingerprint: fingerprint,
                    icon: info.icon,
                    text: text.clone(),
                    flags: if style == 1 {
                        LineFlags::ACTION
                    } else {
                        LineFlags::default()
                    },
                    at,
                })
                .map_err(history_store_failed)?,
            ),
            None => None,
        };
        // The log keeps the canonical metadata beside the line, so a
        // history entry can still render a placeholder once the bytes
        // are gone (docs/inline-media.md §9, chat-history.md §8).
        if let (Some(log), Some(id), Some((_, reference))) = (self.history.as_ref(), id, &media) {
            if let Err(e) = log.attach_media(id, &reference.to_meta()) {
                warn!("chat log would not record media: {e}");
            }
        }
        let ev = Event::Chat {
            cid: 0,
            from: info,
            text,
            style,
            id,
            at,
            media: media.as_ref().map(|(_, r)| r.clone()),
        };
        let mut r = self.roster.lock().unwrap();
        r.broadcast_where(&ev, None, reads_public_chat);
        // The authorization set, fixed at relay time: the sender, and
        // every session this line just went to whose wire can carry the
        // reference. Captured under the roster's lock and stored under
        // the media store's, which is the one order those two are ever
        // taken in.
        if let Some((handle, _)) = &media {
            let audience = r.media_audience(None, reads_public_chat);
            self.media_capture(handle, audience.into_iter().chain([principal]));
        }
        Ok(id)
    }

    /// A private chat line; membership is the only gate.
    pub fn chat_private(
        &self,
        cid: u32,
        from: Uid,
        text: String,
        style: u16,
        media: Option<crate::media::Handle>,
    ) -> Result<(), ChatError> {
        // Membership is checked before the handle is resolved, and the
        // handle before anything is sent: a non-member learns nothing
        // about a room from the order of these refusals.
        let principal = {
            let r = self.roster.lock().unwrap();
            let Some(chat) = r.chats.get(&cid) else {
                return Err(ChatError::NoSuchChat);
            };
            if !chat.members.contains(&from) {
                return Err(ChatError::NotAMember);
            }
            let Some(sess) = r.users.get(&from) else {
                return Err(ChatError::NoSuchUser);
            };
            crate::media::Principal::Session {
                uid: from,
                serial: sess.serial,
            }
        };
        let media = match media {
            Some(handle) => Some((
                handle,
                self.media_for_send(from, &handle)
                    .map_err(|_| ChatError::NoSuchMedia)?,
            )),
            None => None,
        };
        let mut r = self.roster.lock().unwrap();
        let Some(chat) = r.chats.get(&cid) else {
            return Err(ChatError::NoSuchChat);
        };
        if !chat.members.contains(&from) {
            return Err(ChatError::NotAMember);
        }
        let members = chat.members.clone();
        let Some(info) = r.users.get(&from).map(|s| s.info.clone()) else {
            return Err(ChatError::NoSuchUser);
        };
        let ev = Event::Chat {
            cid,
            from: info,
            text,
            style,
            id: None,
            at: SystemTime::now(),
            media: media.as_ref().map(|(_, r)| r.clone()),
        };
        for uid in &members {
            r.send_to(*uid, ev.clone());
        }
        // A room's set is its membership at this moment, media-capable
        // members only, and nothing is added to it afterwards — someone
        // who joins the room later did not receive this line.
        if let Some((handle, _)) = &media {
            let audience = r.media_audience_of(&members);
            self.media_capture(handle, audience.into_iter().chain([principal]));
        }
        Ok(())
    }

    /// Page the durable public log. Policy is checked by the frontend; the
    /// uid check prevents a stale transport from reading after teardown.
    pub fn history(&self, uid: Uid, query: HistoryQuery) -> Result<HistoryPage, ChatError> {
        if !self.roster.lock().unwrap().users.contains_key(&uid) {
            return Err(ChatError::NoSuchUser);
        }
        self.history
            .as_ref()
            .ok_or(ChatError::ServerError)?
            .query(&query)
            .map_err(history_store_failed)
    }

    /// Ten history pages per second, scoped to the logical user session.
    /// Keeping this beside the roster means an ng reconnect cannot reset it.
    pub fn allow_history_request(&self, uid: Uid) -> Result<bool, ChatError> {
        let mut roster = self.roster.lock().unwrap();
        let session = roster.users.get_mut(&uid).ok_or(ChatError::NoSuchUser)?;
        let now = Instant::now();
        session.history_tokens = (session.history_tokens
            + now.duration_since(session.history_refill).as_secs_f64() * 10.0)
            .min(10.0);
        session.history_refill = now;
        if session.history_tokens < 1.0 {
            return Ok(false);
        }
        session.history_tokens -= 1.0;
        Ok(true)
    }

    /// Each stored reference in a batch, as the media store has it now.
    /// Keyed by the stored handle bytes, which is what the row carries.
    fn media_states(
        &self,
        batch: &[crate::inbox::StoredMessage],
    ) -> HashMap<Vec<u8>, crate::media::MediaRef> {
        let mut out = HashMap::new();
        for m in batch {
            let Some(meta) = m.media.as_ref() else {
                continue;
            };
            let Ok(handle) = <crate::media::Handle>::try_from(meta.id.as_slice()) else {
                continue;
            };
            if let Some(reference) = self.media_meta(&handle) {
                out.insert(meta.id.clone(), reference);
            }
        }
        out
    }

    /// Retention work for the binary's hourly sweeper.
    pub fn prune_history(&self, max_lines: usize, max_age: Option<Duration>) -> usize {
        self.history
            .as_ref()
            .and_then(
                |log| match log.prune(max_lines, max_age, SystemTime::now()) {
                    Ok(gone) => Some(gone),
                    Err(e) => {
                        warn!("history retention: {e}");
                        None
                    }
                },
            )
            .unwrap_or(0)
    }

    /// A server notice into a chat (kick announcements and the like).
    /// Semantic text — each frontend formats it. Public delivery honors the
    /// read-chat filter.
    pub fn chat_notice(&self, cid: u32, from: Uid, text: String) {
        let mut r = self.roster.lock().unwrap();
        let ev = Event::Notice { cid, from, text };
        if cid == 0 {
            r.broadcast_where(&ev, None, reads_public_chat);
        } else if let Some(members) = r.chats.get(&cid).map(|c| c.members.clone()) {
            for uid in members {
                r.send_to(uid, ev.clone());
            }
        }
    }

    // --- Private chat lifecycle ----------------------------------------

    /// Create a private chat with `creator` as its first member, inviting
    /// `invitee` (unless it's the creator). Returns the new chat id and the
    /// creator's row (the reply carries it).
    pub fn chat_create(&self, creator: Uid, invitee: Uid) -> Result<(u32, UserInfo), ChatError> {
        let mut r = self.roster.lock().unwrap();
        if !r.users.contains_key(&invitee) {
            return Err(ChatError::NoSuchUser);
        }
        let me = r
            .users
            .get(&creator)
            .map(|s| s.info.clone())
            .ok_or(ChatError::NoSuchUser)?;
        let cid = r.next_chat_id().ok_or(ChatError::ServerError)?;
        let mut chat = PrivateChat {
            members: vec![creator],
            ..Default::default()
        };
        if invitee != creator {
            chat.invited.push(invitee);
        }
        r.chats.insert(cid, chat);
        if invitee != creator {
            let ev = Event::ChatInvite {
                cid,
                from: creator,
                from_nick: me.nick.clone(),
            };
            r.send_to(invitee, ev);
        }
        Ok((cid, me))
    }

    /// Invite `target` to a chat the inviter is in.
    pub fn chat_invite(&self, cid: u32, by: Uid, target: Uid) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let by_nick = r
            .users
            .get(&by)
            .map(|s| s.info.nick.clone())
            .ok_or(ChatError::NoSuchUser)?;
        if !r.users.contains_key(&target) {
            return Err(ChatError::NoSuchUser);
        }
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&by) {
            return Err(ChatError::NotAMember);
        }
        if chat.members.contains(&target) {
            return Err(ChatError::AlreadyThere);
        }
        if !chat.invited.contains(&target) {
            chat.invited.push(target);
        }
        let ev = Event::ChatInvite {
            cid,
            from: by,
            from_nick: by_nick,
        };
        r.send_to(target, ev);
        Ok(())
    }

    /// Decline an invitation (or quietly drop a stale one).
    pub fn chat_decline(&self, cid: u32, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        if let Some(chat) = r.chats.get_mut(&cid) {
            chat.invited.retain(|u| *u != uid);
        }
    }

    /// Join a chat. An invitation bypasses the password; without one, a
    /// passworded chat requires the password. Returns the member rows
    /// (joiner included) and the subject, for the reply; other members get
    /// the join push.
    pub fn chat_join(
        &self,
        cid: u32,
        uid: Uid,
        password: &str,
    ) -> Result<(Vec<UserInfo>, String), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let me = r
            .users
            .get(&uid)
            .map(|s| s.info.clone())
            .ok_or(ChatError::NoSuchUser)?;
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if chat.members.contains(&uid) {
            return Err(ChatError::AlreadyThere);
        }
        if let Some(pos) = chat.invited.iter().position(|u| *u == uid) {
            chat.invited.remove(pos);
        } else if !chat.password.is_empty() && chat.password != password {
            return Err(ChatError::WrongPassword);
        }
        chat.members.push(uid);
        let members = chat.members.clone();
        let subject = chat.subject.clone();
        let ev = Event::ChatUserJoined { cid, user: me };
        let mut rows = Vec::with_capacity(members.len());
        for m in &members {
            if *m != uid {
                r.send_to(*m, ev.clone());
            }
            if let Some(s) = r.users.get(m) {
                rows.push(s.info.clone());
            }
        }
        Ok((rows, subject))
    }

    /// Leave a chat; the last member out deletes it.
    pub fn chat_part(&self, cid: u32, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        Self::part_one(&mut r, cid, uid);
    }

    /// Set a chat's subject. cid 0 is the public subject (policy-gated by
    /// the caller); private chats require membership.
    pub fn chat_subject(&self, cid: u32, uid: Uid, subject: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let ev = Event::ChatSubject {
            cid,
            subject: subject.clone(),
        };
        if cid == 0 {
            r.public_subject = subject;
            r.broadcast_where(&ev, None, |_| true);
            return Ok(());
        }
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&uid) {
            return Err(ChatError::NotAMember);
        }
        chat.subject = subject;
        for m in chat.members.clone() {
            r.send_to(m, ev.clone());
        }
        Ok(())
    }

    /// Set a private chat's password (members only; announced to members,
    /// mirroring the reference server).
    pub fn chat_password(&self, cid: u32, uid: Uid, password: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&uid) {
            return Err(ChatError::NotAMember);
        }
        chat.password = password.clone();
        let ev = Event::ChatPassword { cid, password };
        for m in chat.members.clone() {
            r.send_to(m, ev.clone());
        }
        Ok(())
    }

    /// The private chats `uid` is currently in (used by tests and, later,
    /// the info views).
    pub fn chats_of(&self, uid: Uid) -> Vec<u32> {
        let r = self.roster.lock().unwrap();
        let mut v: Vec<u32> = r
            .chats
            .iter()
            .filter(|(_, c)| c.members.contains(&uid))
            .map(|(cid, _)| *cid)
            .collect();
        v.sort_unstable();
        v
    }

    pub(crate) fn leave_all_chats(r: &mut RosterInner, uid: Uid) {
        let cids: Vec<u32> = r
            .chats
            .iter()
            .filter(|(_, c)| c.members.contains(&uid) || c.invited.contains(&uid))
            .map(|(cid, _)| *cid)
            .collect();
        for cid in cids {
            Self::part_one(r, cid, uid);
        }
    }

    fn part_one(r: &mut RosterInner, cid: u32, uid: Uid) {
        // Leaving a chat leaves its voice room — the spec's "if a user is
        // kicked from a chat room, their voice session MUST also be
        // terminated", and the same is true of walking out voluntarily.
        // Ahead of the early returns below: voice outlives a chat whose
        // membership has already been torn up.
        r.voice_part_room(uid, cid);
        let Some(chat) = r.chats.get_mut(&cid) else {
            return;
        };
        chat.invited.retain(|u| *u != uid);
        let Some(pos) = chat.members.iter().position(|u| *u == uid) else {
            return;
        };
        chat.members.remove(pos);
        if chat.members.is_empty() {
            r.chats.remove(&cid);
            return;
        }
        let members = chat.members.clone();
        let ev = Event::ChatUserParted { cid, uid };
        for m in members {
            r.send_to(m, ev.clone());
        }
    }

    // --- Messaging ------------------------------------------------------
    //
    // The rule, from docs/private-messages.md §5: a private message to an
    // account that has an inbox is persisted *before* the sender is acked,
    // and live delivery is a state change on the stored row rather than an
    // alternative to storing it. A recipient with no inbox (a guest), or a
    // server with no store configured, takes the path this module had
    // before the inbox existed — straight to the outbox, nothing
    // persisted.

    /// A private message to a session on the roster. The sender's ack is
    /// the frontend's task reply.
    pub fn msg(
        &self,
        from: Uid,
        to: Uid,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
    ) -> Result<MsgOutcome, ChatError> {
        let (sender, recipient) = {
            let r = self.roster.lock().unwrap();
            let sender = Sender::resolve(&r, from)?;
            let sess = r
                .users
                .get(&to)
                .filter(|s| s.visible)
                .ok_or(ChatError::NoSuchUser)?;
            (
                sender,
                Recipient {
                    uid: Some(to),
                    mailbox: sess.mailbox(),
                    has_inbox: sess.has_inbox,
                    // A guest has no mailbox to hold the grant, so the
                    // session it is sitting in is the address.
                    principal: match (sess.has_inbox, sess.mailbox()) {
                        (true, mailbox) => crate::media::Principal::Mailbox(mailbox),
                        (false, _) => crate::media::Principal::Session {
                            uid: to,
                            serial: sess.serial,
                        },
                    },
                },
            )
        };
        self.deliver(sender, recipient, text, guid, media)
    }

    /// A private message to an *account*, whether or not it holds a
    /// session. This is what the ng wire's `to_login` calls; the legacy
    /// wire has no way to name a user who isn't on its list, and does not
    /// call it.
    pub fn msg_login(
        &self,
        from: Uid,
        to: &str,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
    ) -> Result<MsgOutcome, ChatError> {
        let directory = self.directory.as_ref().ok_or(ChatError::NoSuchUser)?;
        // One `None` for "no such account" and "that account takes no
        // offline messages", so this path cannot be used to tell them
        // apart — see AccountDirectory::inbox_account.
        let mailbox = directory.inbox_account(to).ok_or(ChatError::NoSuchUser)?;
        let (sender, uid) = {
            let r = self.roster.lock().unwrap();
            // An attached session, or none: this uid is only used by the
            // non-durable path, which cannot store what it fails to
            // deliver, so aiming it at a detached session would lose the
            // message rather than queue it.
            (
                Sender::resolve(&r, from)?,
                attached_session_of(&r, &mailbox),
            )
        };
        self.deliver(
            sender,
            Recipient {
                principal: crate::media::Principal::Mailbox(mailbox.clone()),
                uid,
                mailbox,
                has_inbox: true,
            },
            text,
            guid,
            media,
        )
    }

    fn deliver(
        &self,
        sender: Sender,
        to: Recipient,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
    ) -> Result<MsgOutcome, ChatError> {
        let now = SystemTime::now();

        // The handle resolves before anything is delivered or stored: a
        // message carrying an image this sender may not attach is
        // refused outright rather than sent without it.
        //
        // The *audience* is a separate act, and it happens at each point
        // below where the message actually goes out — never here. The
        // set is what a relay showed someone, and a send that comes back
        // `Blocked`, `MailboxFull` or `NoSuchUser` relayed nothing;
        // capturing up here would leave the refused recipient a
        // permanent grant on an image they were never sent, and the set
        // is only ever extended. Both principals are taken now because
        // `sender` is consumed on the way down.
        let image = media;
        let audience = [sender.principal.clone(), to.principal.clone()];
        let media = match image.as_ref() {
            Some(handle) => Some(
                self.media_for_send(sender.uid, handle)
                    .map_err(|_| ChatError::NoSuchMedia)?,
            ),
            None => None,
        };

        // Two reasons not to touch the store, and the same consequence.
        //
        // The recipient may simply have no inbox. Or the *sender* may
        // have no mailbox — a plain guest — and §9's "anyone with an
        // account can put mail in anyone's mailbox" does not cover it:
        // a guest has no account, cannot be blocked (there is nothing
        // durable to hold a block against, and `guest` is a login several
        // people share), and could therefore fill any mailbox on the
        // server to its cap and stay unstoppable. So a guest may reach a
        // session, live, and may not queue anything.
        let durable = to.has_inbox && sender.mailbox.is_some();
        let Some(store) = self.inbox.as_ref().filter(|_| durable) else {
            // A recipient with no session cannot be reached this way.
            let mut r = self.roster.lock().unwrap();
            // The same resolution the durable path does, for the same
            // reasons and in the same order: the session the sender named
            // if it is attached (§15 — clicking a name in a user list is
            // naming a *device*, and an account with a phone on uid 2 and
            // a laptop on uid 3 should hear it on the one that was
            // clicked), else whichever session is attached. Preferring
            // the lowest attached uid over a named one that is *also*
            // attached was the durable path's old bug, still living here:
            // this is the path for every plain-guest sender, and for
            // every sender at all on a server with no `[inbox]`.
            //
            // Falling back to a detached uid is still right here and
            // wrong there: this path stores nothing, so the outbox buffer
            // is the only copy there can be.
            //
            // Only where the mailbox is a real address, though. A guest's
            // mailbox is `guest`, a login several people share, and
            // resolving *that* would hand the message to whichever guest
            // answered first. There the uid is the address.
            let attached = |uid: &Uid| {
                r.users
                    .get(uid)
                    .is_some_and(|s| s.mailbox() == to.mailbox && !is_buffering(s))
            };
            // Every candidate is checked against the mailbox as it
            // stands *now*: `msg` resolved this uid under an earlier
            // hold of the roster lock, and a uid is reused once the
            // counter wraps, so a session that ended in between must not
            // inherit the message. `attached` covers the first two; the
            // last resort is the same check without the attached part,
            // since a detached session is still the right addressee here.
            let owns = |uid: &Uid| r.users.get(uid).is_some_and(|s| s.mailbox() == to.mailbox);
            let uid = if to.has_inbox {
                to.uid
                    .filter(attached)
                    .or_else(|| attached_session_of(&r, &to.mailbox))
                    .or_else(|| to.uid.filter(owns))
            } else {
                to.uid
            }
            .ok_or(ChatError::NoSuchUser)?;
            // There is a recipient and the event is about to go out, so
            // now the image has been shown. Under the roster lock, which
            // is why `media_capture` takes principals rather than
            // looking them up.
            if let Some(handle) = &image {
                self.media_capture(handle, audience.clone());
            }
            r.send_to(
                uid,
                Event::Msg {
                    from: sender.uid,
                    from_nick: sender.nick,
                    from_login: sender.reply_login,
                    text,
                    id: None,
                    sent_at: now,
                    queued: false,
                    media,
                },
            );
            return Ok(MsgOutcome::Delivered);
        };

        // Blocking, before anything is written. It applies to a message
        // named by uid exactly as to one named by login: a block a
        // recipient can sidestep by clicking a name in the user list is
        // not a block.
        let from_mailbox = sender.mailbox.clone().expect("checked by `durable`");
        if store
            .is_blocked(&to.mailbox, &from_mailbox)
            .map_err(store_failed)?
        {
            return Err(ChatError::Blocked);
        }

        // The store decides both of the questions that used to be asked
        // here and answered a moment later: whether this guid is already
        // stored, and whether the mailbox is at its cap. Both were
        // check-then-insert, and both are racy in exactly the case they
        // exist for — a client retrying a send, and a sender sending in
        // parallel.
        //
        // A retry of a message we already have is that message, not a
        // second one. Answering it what the first send was answered is
        // what makes a client safe to retry after a socket died mid-ack.
        let (sender_nick, body) = (sender.nick.clone(), text);
        let id = match store
            .push(
                &NewMessage {
                    recipient: to.mailbox.clone(),
                    sender: sender.mailbox,
                    sender_nick: sender.nick,
                    body: body.clone(),
                    sent_at: now,
                    guid,
                    kind: MessageKind::Message,
                    media: media.as_ref().map(|m| m.to_meta()),
                },
                self.inbox_policy.max_queued,
            )
            .map_err(store_failed)?
        {
            // Stored: the row is durable and carries the image's
            // metadata, so whoever eventually reads it must be able to
            // fetch the bytes. A retry (`Existing`) captured on its
            // original send, and re-capturing here would grant the
            // recipient a *different* handle if the retry named one.
            crate::inbox::Pushed::Stored(id) => {
                if let Some(handle) = &image {
                    self.media_capture(handle, audience.clone());
                }
                id
            }
            crate::inbox::Pushed::Existing(m) => {
                // A retry is that same message, and it gets the answer
                // the first send would get *now* rather than the one it
                // got then. The recipient may have attached in between:
                // flushing here is what hands it over, instead of
                // leaving it for their next login or sync while they are
                // sitting right there. No notification — the original
                // send already decided that question.
                if m.delivered_at.is_some() {
                    return Ok(MsgOutcome::Delivered);
                }
                // `fresh` is `None`: this row has been in the inbox
                // since the original send, however short a time that
                // was, so it carries `queued` like anything else that
                // waited. Naming it fresh would tell the recipient a
                // message that sat there arrived just now.
                let delivered = self
                    .flush_to(Target::Named(to.uid), &to.mailbox, None)
                    .contains(&m.id)
                    || !store
                        .is_pending(&to.mailbox, m.id)
                        .map_err(store_failed)
                        .unwrap_or(true);
                return Ok(if delivered {
                    MsgOutcome::Delivered
                } else {
                    MsgOutcome::Queued(m.id)
                });
            }
            crate::inbox::Pushed::Full => return Err(ChatError::MailboxFull),
        };

        // **Store, then resolve.** The roster lock was dropped for the
        // write, so who should receive this — and whether anyone should —
        // is decided now rather than before. Resolving it earlier meant a
        // recipient who attached in between was never handed the message
        // live, and, worse, that a recipient with a detached session and
        // an attached one had the message aimed at whichever had the
        // lower uid.
        //
        // Flushing (rather than sending this one row) is what keeps
        // delivery in id order when two senders race.
        let delivered = self
            .flush_to(Target::Named(to.uid), &to.mailbox, Some(id))
            .contains(&id);
        // A concurrent flush may have been the one that carried it — in
        // which case ours came back without it, and telling the sender
        // "queued" for a message the recipient is reading would be wrong.
        // The same question answers the case where a backlog past
        // `deliver_at_flush` pushed this row out of the batch.
        let delivered = delivered
            || !store
                .is_pending(&to.mailbox, id)
                .map_err(store_failed)
                .unwrap_or(true);

        // The notify decision (docs/push-notifications.md §6), computed
        // here so that both wires reach it — the legacy path skipping it
        // by being written somewhere else is the failure that document
        // calls out by name.
        //
        // Anything but an *attentive* session earns a notification:
        // detached, or no session at all, plainly; and `idle` too, even
        // though a connection is attached and got the event, because the
        // app is backgrounded and the OS is the one that decides whether
        // to make noise. (Nothing sets `idle` yet — hotline-ng.md §12
        // still owes it a definition — but the rule is the rule.)
        //
        // Across *every* session that owns the mailbox, not one chosen
        // uid: an account reading on its laptop with a sleeping phone is
        // attentive, and the phone should not buzz.
        let attentive = {
            let r = self.roster.lock().unwrap();
            sessions_of(&r, &to.mailbox).into_iter().any(|uid| {
                r.users.get(&uid).map(|s| s.info.status) == Some(crate::SessionStatus::Active)
            })
        };
        // A message to yourself from your own other session is not news.
        let to_self = from_mailbox == to.mailbox;
        if !attentive && !to_self {
            if let Some(gateway) = &self.gateway {
                let unread = store.counts(&to.mailbox).map(|c| c.unread).unwrap_or(0);
                gateway.notify(&crate::notify::Notification {
                    to: &to.mailbox,
                    from: Some(&from_mailbox),
                    from_nick: &sender_nick,
                    text: &body,
                    id,
                    unread,
                });
            }
        }

        if delivered {
            return Ok(MsgOutcome::Delivered);
        }
        Ok(MsgOutcome::Queued(id))
    }

    /// Hand a session its waiting mail. Called at login completion (after
    /// `announce`, so the roster is coherent first), at resume, and after
    /// a `sync`. Idempotent, and safe to call on a server with no inbox.
    ///
    /// Whether the flush also stamps the rows read is the *receiving
    /// session's* business, not the caller's — see
    /// [`crate::AttachInfo::reads_on_delivery`]. A live delivery is as
    /// much a read as a queued one on a wire that cannot say otherwise,
    /// so the decision belongs where the session is resolved.
    ///
    /// Returns how many messages went out.
    pub fn flush_inbox(&self, uid: Uid) -> usize {
        let mailbox = {
            let r = self.roster.lock().unwrap();
            match r.users.get(&uid).filter(|s| s.has_inbox) {
                Some(sess) => sess.mailbox(),
                None => return 0,
            }
        };
        self.flush_to(Target::Only(uid), &mailbox, None).len()
    }

    /// The flush itself.
    ///
    /// `uid` names the session to flush to, or `None` for "whichever
    /// session of this mailbox is in a state to receive" — the send path
    /// passes `None`, because who should get a message is a question for
    /// after the write, not before it.
    ///
    /// The login a reply may name, per distinct sender in a batch.
    ///
    /// Not simply the stored login: an identity guest's mailbox is keyed
    /// by fingerprint and named `guest`, and a reply to `guest` answers
    /// `no_such_user`. Asking the directory also catches a sender whose
    /// account has since been deleted or renamed — the login is free,
    /// and it is not theirs. One lookup per sender, since a batch is
    /// usually one conversation, and each one is a file read.
    ///
    /// **What this costs, and where.** It runs inside the `flushing`
    /// lock — it has to, because the batch it is about is the one
    /// `pending` just read under that lock — so up to
    /// `deliver_at_flush` (default 25) file reads are on the critical
    /// path of every other flush on the server. Off the reactor, on a
    /// lock no roster operation waits behind, and one read in the usual
    /// case of a message from one sender; but it is the ceiling to look
    /// at first if flushes ever start queueing. `inbox_list` does the
    /// same lookups for up to 200 rows, outside this lock.
    fn reply_addresses(&self, batch: &[StoredMessage]) -> HashMap<Mailbox, Option<String>> {
        let mut out: HashMap<Mailbox, Option<String>> = HashMap::new();
        for m in batch {
            let Some(sender) = m.sender.as_ref() else {
                continue;
            };
            if out.contains_key(sender) {
                continue;
            }
            let named = self
                .directory
                .as_ref()
                .and_then(|d| d.inbox_account(&sender.login))
                .filter(|named| named == sender)
                .map(|_| sender.login.clone());
            out.insert(sender.clone(), named);
        }
        out
    }

    /// `target` says which of the mailbox's sessions receives; see
    /// [`Target`].
    ///
    /// `fresh` names the message this same call has just stored, if any.
    /// It is the one message in the batch that did *not* wait for
    /// anything, so it is the one that does not carry `queued` — a
    /// recipient who was there the whole time should not be told their
    /// message is old news. Everything else in the batch genuinely sat in
    /// the inbox, however briefly.
    ///
    /// Returns the ids delivered.
    fn flush_to(
        &self,
        target: Target,
        mailbox: &Mailbox,
        fresh: Option<MessageId>,
    ) -> Vec<MessageId> {
        let Some(store) = self.inbox.as_ref() else {
            return Vec::new();
        };
        // One flush per server at a time.
        //
        // `pending` reads rows, the send happens under the roster lock,
        // and `mark_delivered` runs after that lock is released — so two
        // flushes for one mailbox (a sender's post-store flush against
        // the recipient's login flush, or two senders racing) both read
        // the same rows and both push them, and the recipient gets every
        // message twice. Not the roster lock, which would put disk I/O
        // under it; a lock of its own, taken *before* the roster lock and
        // never the other way round.
        let _flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());

        let limit = self.inbox_policy.deliver_at_flush;
        let batch = match store.pending(mailbox, limit) {
            Ok(b) => b,
            Err(e) => {
                warn!("inbox: reading pending mail for {}: {e}", mailbox.login);
                return Vec::new();
            }
        };
        if batch.is_empty() {
            return Vec::new();
        }

        // The reply address for each row, resolved *before* the roster
        // lock: `inbox_account` reads and parses an account file, and
        // the roster mutex is the one every chat, join, part and voice
        // operation on the server waits behind (roster.rs, §6.2). A
        // 25-message login flush was 25 file reads under it.
        let from_logins = self.reply_addresses(&batch);
        // And which of the batch's images are still fetchable, resolved
        // in the same breath and for the same reason: a handle from
        // yesterday may have expired, and the answer belongs to the
        // event this flush is about to build.
        let handles = self.media_states(&batch);

        let mut delivered = Vec::with_capacity(batch.len());
        let (uid, what) = {
            let mut r = self.roster.lock().unwrap();
            // Only an attached session receives. A detached one leaves its
            // mail pending rather than filling an outbox buffer that is
            // bounded and dies with the grace window — the durable copy is
            // the copy.
            let attached = |uid: &Uid| {
                r.users
                    .get(uid)
                    .is_some_and(|s| s.mailbox() == *mailbox && !is_buffering(s))
            };
            let uid = match target {
                Target::Only(uid) => Some(uid).filter(attached),
                Target::Named(named) => named
                    .filter(attached)
                    .or_else(|| attached_session_of(&r, mailbox)),
            };
            let Some(uid) = uid else {
                return Vec::new();
            };
            // Whose wire this is decides whether handing a message over
            // counts as reading it. Read here, where the session is
            // finally known, rather than passed in: `deliver` reaches
            // this for a live send too, and a legacy user reading a
            // message the instant it arrives has read it just as much as
            // one who read it at login.
            let what = if r.users.get(&uid).is_some_and(|s| s.reads_on_delivery) {
                Delivery::Read
            } else {
                Delivery::Delivered
            };
            for m in batch {
                // The sender's uid, resolved now and by mailbox: the
                // sending session is long gone and its uid may belong to
                // someone else by now. Same identity, same person; nobody
                // there, no uid.
                let from = m
                    .sender
                    .as_ref()
                    .and_then(|s| session_of(&r, s))
                    .unwrap_or(0);
                let from_login = m
                    .sender
                    .as_ref()
                    .and_then(|s| from_logins.get(s).cloned().flatten());
                r.send_to(
                    uid,
                    Event::Msg {
                        from,
                        from_nick: m.sender_nick,
                        from_login,
                        text: m.body,
                        id: Some(m.id),
                        sent_at: m.sent_at,
                        queued: Some(m.id) != fresh,
                        media: m.media.as_ref().and_then(|meta| media_now(&handles, meta)),
                    },
                );
                delivered.push(m.id);
            }
            (uid, what)
        };

        // Stamped after the events are in the outbox: if this fails, the
        // message is delivered twice on the next flush, which is the right
        // way round to be wrong. (On the legacy wire it is the *only* way
        // round available: `delivered` there means "handed to the writer
        // task", and a socket that dies before the bytes go out loses
        // them for good — there is no resume on that wire. See
        // `docs/private-messages.md` §11.)
        if let Err(e) = store.mark_delivered(&delivered, SystemTime::now(), what) {
            warn!("inbox: marking {} messages delivered: {e}", delivered.len());
        }

        // The cap is for the legacy wire, where each private message opens
        // a window. What it leaves behind is still there — say so, in the
        // one place a client of either wire will see it, rather than
        // inventing a digest format.
        match store.pending_count(mailbox) {
            Ok(0) => {}
            Ok(n) => {
                let mut r = self.roster.lock().unwrap();
                r.send_to(
                    uid,
                    Event::Notice {
                        cid: 0,
                        from: 0,
                        text: format!("{n} more queued messages are waiting."),
                    },
                );
            }
            Err(e) => warn!("inbox: counting what is left for {}: {e}", mailbox.login),
        }

        delivered
    }

    /// One session's inbox, newest first — what a client that woke to a
    /// push calls to find out what it was woken for.
    pub fn inbox_list(
        &self,
        uid: Uid,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        let mut rows = store.list(&mailbox, before, limit).map_err(store_failed)?;
        // The same reply-address rule the delivered event carries: a row
        // whose sender no longer names an account a reply can reach
        // keeps its nick and loses its address, rather than offering a
        // `guest` login that answers `no_such_user`.
        let addresses = self.reply_addresses(&rows);
        for m in &mut rows {
            let reachable = m
                .sender
                .as_ref()
                .is_some_and(|s| addresses.get(s).is_some_and(Option::is_some));
            if !reachable {
                m.sender = None;
            }
        }
        Ok(rows)
    }

    /// Unread and total for a mailbox named directly, rather than by a
    /// session holding it. For operator tooling and for tests that need
    /// to look at a mailbox nobody is logged in to.
    pub fn inbox_counts_of(&self, mailbox: &Mailbox) -> InboxCounts {
        self.inbox
            .as_ref()
            .and_then(|s| s.counts(mailbox).ok())
            .unwrap_or_default()
    }

    /// Unread and total for one session's mailbox.
    pub fn inbox_counts(&self, uid: Uid) -> Result<InboxCounts, ChatError> {
        let Ok((store, mailbox)) = self.inbox_of(uid) else {
            return Ok(InboxCounts::default());
        };
        store.counts(&mailbox).map_err(store_failed)
    }

    /// Mark one session's mail read up to and including `up_to`, and
    /// answer with what is left.
    ///
    /// `up_to` is a cursor in this mailbox, not a key: ids are
    /// server-wide, so one the caller never received still marks
    /// everything of *theirs* below it. What the store scopes is the
    /// mailbox — no call here can mark another account's mail read.
    pub fn inbox_mark_read(&self, uid: Uid, up_to: MessageId) -> Result<InboxCounts, ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        store
            .mark_read(&mailbox, up_to, SystemTime::now())
            .map_err(store_failed)?;
        store.counts(&mailbox).map_err(store_failed)
    }

    /// Block or unblock an account, by login.
    ///
    /// Blocking works between accounts that have inboxes, because that is
    /// what a durable block can be about: an account with no inbox cannot
    /// queue anything for you and has no identity to hold the block
    /// against. Naming anything else answers `NoSuchUser`, the same one
    /// answer `msg_login` gives.
    pub fn inbox_block(&self, uid: Uid, other: &str, blocked: bool) -> Result<(), ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        let directory = self.directory.as_ref().ok_or(ChatError::NoSuchUser)?;
        let other = directory
            .inbox_account(other)
            .ok_or(ChatError::NoSuchUser)?;
        if other == mailbox {
            // Blocking yourself is not a thing worth storing, and a
            // mailbox that cannot receive its own mail is a support
            // question waiting to happen.
            return Err(ChatError::NoSuchUser);
        }
        store
            .set_blocked(&mailbox, &other, blocked, SystemTime::now())
            .map_err(store_failed)
    }

    /// Block or unblock whoever holds `uid` on the roster.
    ///
    /// The uid form exists for the sender a login cannot name: an
    /// identity user admitted as a guest has a fingerprint to hold a
    /// block against but no account of its own, and a recipient who just
    /// received a message from one can only point at the roster row.
    pub fn inbox_block_uid(&self, uid: Uid, other: Uid, blocked: bool) -> Result<(), ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        let other = {
            let r = self.roster.lock().unwrap();
            let sess = r
                .users
                .get(&other)
                .filter(|s| s.visible && (s.has_inbox || s.identity.is_some()))
                .ok_or(ChatError::NoSuchUser)?;
            sess.mailbox()
        };
        if other == mailbox {
            return Err(ChatError::NoSuchUser);
        }
        store
            .set_blocked(&mailbox, &other, blocked, SystemTime::now())
            .map_err(store_failed)
    }

    /// Who this session has blocked.
    ///
    /// Mailboxes, not logins: an identity guest is blocked as
    /// `{guest, fingerprint}`, and a list of logins showed `guest` — a
    /// name `unblock` then couldn't resolve and the roster couldn't
    /// answer for once they left. The fingerprint is what identifies
    /// that block, so it is what the list carries.
    pub fn inbox_blocked(&self, uid: Uid) -> Result<Vec<Mailbox>, ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        store.blocked(&mailbox).map_err(store_failed)
    }

    /// Unblock by fingerprint: the form that works for a sender who has
    /// left and has no account to name — the identity guest of
    /// `inbox_block_uid`. Blocking still needs a login or a roster row;
    /// you cannot block someone you have never seen.
    pub fn inbox_unblock_fingerprint(
        &self,
        uid: Uid,
        fingerprint: &[u8; 32],
    ) -> Result<(), ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        let other = store
            .blocked(&mailbox)
            .map_err(store_failed)?
            .into_iter()
            .find(|m| m.fingerprint.as_ref() == Some(fingerprint))
            .ok_or(ChatError::NoSuchUser)?;
        store
            .set_blocked(&mailbox, &other, false, SystemTime::now())
            .map_err(store_failed)
    }

    /// An account has linked an identity: move its mail onto the
    /// fingerprint. The account-linking path owes this call — see
    /// [`crate::inbox::MessageStore::claim`].
    pub fn inbox_claim(&self, login: &str, fingerprint: &[u8; 32]) -> usize {
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.claim(login, fingerprint) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: claiming {login}'s mail: {e}");
                0
            }
        }
    }

    /// An identity rotated to a successor key: move its mailbox and its
    /// blocks — see [`crate::inbox::MessageStore::rotate`].
    ///
    /// **Nothing calls this yet, because nothing rotates yet**: §8.5 of
    /// the identity spec describes rotation and the registrar spec owns
    /// it. This exists so that landing rotation is a call rather than a
    /// design question — and so that the obligation is written down
    /// somewhere the compiler will show whoever lands it.
    ///
    /// **Unlinking owes nothing**, deliberately. Mail is addressed to a
    /// person, and under the strict mailbox rule the fingerprint *is* the
    /// person; an account that gives up its link gives up the mailbox
    /// that link addressed, and that mail goes wherever the identity
    /// links next. The alternative — mail follows the account — would
    /// hand an account's history to whoever links to it afterwards.
    pub fn inbox_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> usize {
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.rotate(from, to) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: rotating an identity's mail: {e}");
                0
            }
        }
    }

    /// An account has been deleted: take its mail with it, so a later
    /// holder of the freed login inherits nothing.
    pub fn inbox_purge(&self, of: &Mailbox) -> usize {
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.purge(of) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: purging {}: {e}", of.login);
                0
            }
        }
    }

    /// Retention. The binary runs this on an interval, next to the
    /// detached-session sweeper. Returns how many messages went.
    pub fn prune_inbox(&self, unread: Duration, read: Duration) -> usize {
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.prune(SystemTime::now(), unread, read) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: pruning: {e}");
                0
            }
        }
    }

    /// The store and the mailbox behind a session, when both exist.
    fn inbox_of(&self, uid: Uid) -> Result<(&Arc<dyn MessageStore>, Mailbox), ChatError> {
        let store = self.inbox.as_ref().ok_or(ChatError::NoInbox)?;
        let r = self.roster.lock().unwrap();
        let sess = r
            .users
            .get(&uid)
            .filter(|s| s.has_inbox)
            .ok_or(ChatError::NoInbox)?;
        Ok((store, sess.mailbox()))
    }

    /// An administrator broadcast, to everyone (sender included).
    pub fn broadcast(&self, from: Uid, text: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let from_nick = r
            .users
            .get(&from)
            .map(|s| s.info.nick.clone())
            .ok_or(ChatError::NoSuchUser)?;
        r.broadcast_where(
            &Event::Broadcast {
                from,
                from_nick,
                text,
            },
            None,
            |_| true,
        );
        Ok(())
    }

    // --- Moderation -----------------------------------------------------

    /// Kick `target`, optionally banning for `ban_for`. The target session
    /// receives [`Event::Kicked`] and its transport closes; the public-chat
    /// announcement is the caller's job (it owns the wording). Returns the
    /// target's nick. The cant-be-disconnected check is policy and lives in
    /// the caller, which has the target's access via [`Core::access_of`].
    pub fn kick(&self, target: Uid, ban_for: Option<Duration>) -> Result<String, ChatError> {
        let mut r = self.roster.lock().unwrap();
        let sess = r.users.get(&target).ok_or(ChatError::NoSuchUser)?;
        let nick = sess.info.nick.clone();
        if let Some(dur) = ban_for {
            let ban = Ban {
                addr: sess.addr,
                expires: Instant::now() + dur,
            };
            r.bans.push(ban);
        }
        r.send_to(target, Event::Kicked);
        // A detached session has no connection to observe the event; the
        // kick must end it here or it would linger on the roster.
        if r.users
            .get(&target)
            .is_some_and(crate::roster::is_buffering)
        {
            r.end_session(target);
        }
        Ok(nick)
    }

    /// A user's access bits (for policy checks against a *target*, e.g.
    /// cant-be-disconnected).
    pub fn access_of(&self, uid: Uid) -> Option<crate::AccessBits> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.access)
    }

    /// Is this address currently banned? Expired entries are pruned on the
    /// way through.
    pub fn is_banned(&self, addr: IpAddr) -> bool {
        let mut r = self.roster.lock().unwrap();
        let now = Instant::now();
        r.bans.retain(|b| b.expires > now);
        r.bans.iter().any(|b| b.addr == Some(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::bit;
    use crate::roster::drain;
    use crate::roster::test_attach;
    use crate::AccessBits;

    fn chatter() -> AccessBits {
        AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT)
    }

    #[test]
    fn public_chat_reaches_readers_only_including_sender() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (_b, mut rx_b) = test_attach(&core, "bob", chatter());
        let (_m, mut rx_m) = test_attach(&core, "mute", AccessBits::empty());
        drain(&mut rx_a);
        drain(&mut rx_b);

        core.chat_public(a, "hi".into(), 0, None).unwrap();
        assert!(
            matches!(&drain(&mut rx_a)[..], [Event::Chat { cid: 0, text, .. }] if text == "hi")
        );
        assert_eq!(drain(&mut rx_b).len(), 1);
        assert!(drain(&mut rx_m).is_empty());
    }

    #[test]
    fn private_chat_lifecycle_create_invite_join_part() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", chatter());
        drain(&mut rx_a);

        let (cid, me) = core.chat_create(a, b).unwrap();
        assert_eq!(me.uid, a);
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::ChatInvite { cid: c, from, .. }] if *c == cid && *from == a)
        );

        // Chatting before joining is refused; joining via invite skips the
        // password.
        assert_eq!(
            core.chat_private(cid, b, "early".into(), 0, None),
            Err(ChatError::NotAMember)
        );
        let (rows, _subject) = core.chat_join(cid, b, "").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            matches!(&drain(&mut rx_a)[..], [Event::ChatUserJoined { user, .. }] if user.uid == b)
        );

        core.chat_private(cid, b, "hello".into(), 0, None).unwrap();
        assert_eq!(drain(&mut rx_a).len(), 1);
        assert_eq!(drain(&mut rx_b).len(), 1);

        // Parting announces to the survivor; last one out deletes the chat.
        core.chat_part(cid, b);
        assert!(matches!(&drain(&mut rx_a)[..], [Event::ChatUserParted { uid, .. }] if *uid == b));
        core.chat_part(cid, a);
        assert_eq!(core.chat_join(cid, a, ""), Err(ChatError::NoSuchChat));
    }

    #[test]
    fn chat_ids_are_unguessable_and_never_zero() {
        let core = Core::new();
        let (a, _rx_a) = test_attach(&core, "alice", chatter());
        let cids: Vec<u32> = (0..16).map(|_| core.chat_create(a, a).unwrap().0).collect();

        assert!(cids.iter().all(|c| *c != 0), "0 is the public chat");
        let unique: std::collections::HashSet<_> = cids.iter().collect();
        assert_eq!(unique.len(), cids.len(), "ids collide");
        // The property that matters: knowing one id tells you nothing
        // about the next. A counter would fail this on every pair.
        assert!(
            cids.windows(2).all(|w| w[1] != w[0].wrapping_add(1)),
            "ids look sequential: {cids:?}"
        );
        // And they're spread across the space rather than clustered
        // low. With sixteen draws a false failure is one run in 65536;
        // the two checks above carry the claim, so this one only has to
        // be cheap and honest about what it's asserting.
        let high = cids.iter().filter(|c| **c > u32::MAX / 2).count();
        assert!(high > 0 && high < cids.len(), "not spread: {cids:?}");
    }

    #[test]
    fn passworded_chat_gates_uninvited_joiners() {
        let core = Core::new();
        let (a, _rx_a) = test_attach(&core, "alice", chatter());
        let (b, _rx_b) = test_attach(&core, "bob", chatter());
        let (cid, _) = core.chat_create(a, a).unwrap();
        core.chat_password(cid, a, "sesame".into()).unwrap();

        assert_eq!(
            core.chat_join(cid, b, "wrong"),
            Err(ChatError::WrongPassword)
        );
        assert!(core.chat_join(cid, b, "sesame").is_ok());
    }

    #[test]
    fn detach_parts_every_chat() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, _rx_b) = test_attach(&core, "bob", chatter());
        let (cid, _) = core.chat_create(b, a).unwrap();
        core.chat_join(cid, a, "").unwrap();
        drain(&mut rx_a);

        core.end_session(b);
        let evs = drain(&mut rx_a);
        assert!(evs.contains(&Event::ChatUserParted { cid, uid: b }));
        assert!(evs.contains(&Event::Parted(b)));
        // Alice is now alone in the chat; it survives until she leaves.
        assert_eq!(core.chats_of(a), vec![cid]);
    }

    #[test]
    fn subjects_public_and_private() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", AccessBits::empty());
        drain(&mut rx_a);

        core.chat_subject(0, a, "welcome!".into()).unwrap();
        // Public subject reaches everyone, even non-chat-readers.
        assert_eq!(drain(&mut rx_b).len(), 1);
        assert_eq!(core.public_subject(), "welcome!");

        let (cid, _) = core.chat_create(a, a).unwrap();
        assert_eq!(
            core.chat_subject(cid, b, "x".into()),
            Err(ChatError::NotAMember)
        );
        core.chat_subject(cid, a, "private".into()).unwrap();
        let (_rows, subject) = {
            core.chat_invite(cid, a, b).unwrap();
            core.chat_join(cid, b, "").unwrap()
        };
        assert_eq!(subject, "private");
    }

    #[test]
    fn msg_broadcast_notice_and_kick_ban() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", chatter());
        drain(&mut rx_a);

        core.msg(a, b, "psst".into(), None, None).unwrap();
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::Msg { from, text, .. }] if *from == a && text == "psst")
        );
        assert_eq!(
            core.msg(a, 999, "x".into(), None, None),
            Err(ChatError::NoSuchUser)
        );

        core.broadcast(a, "attention".into()).unwrap();
        assert_eq!(drain(&mut rx_a).len(), 1);
        assert_eq!(drain(&mut rx_b).len(), 1);

        core.chat_notice(0, a, "bob has been warned".into());
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::Notice { cid: 0, text, .. }] if text == "bob has been warned")
        );

        let nick = core.kick(b, Some(Duration::from_secs(60))).unwrap();
        assert_eq!(nick, "bob");
        assert!(drain(&mut rx_b).contains(&Event::Kicked));
        // No address on test sessions, so nothing bannable by IP — but the
        // expiry path shouldn't panic.
        assert!(!core.is_banned("127.0.0.1".parse().unwrap()));
    }
}

#[cfg(test)]
mod inbox_tests {
    //! The private-message inbox, at the domain level: which messages get
    //! stored, who gets them and when, and what a queued one looks like
    //! when it finally arrives. See docs/private-messages.md §5.

    use std::sync::{Arc, Mutex, Weak};

    use tokio::sync::mpsc::UnboundedReceiver;

    use super::*;
    use crate::access::bit;
    use crate::inbox::MemoryStore;
    use crate::roster::{drain, AttachInfo, InboxPolicy, SeqEvent};
    use crate::{AccessBits, AccountDirectory, Resume};

    /// The accounts that exist and take mail, and the identity each is
    /// linked to. Anything else is the one `None` that covers both "no
    /// such account" and "takes no mail".
    struct Directory(Vec<Mailbox>);

    impl Directory {
        fn of(logins: &[&str]) -> Directory {
            Directory(logins.iter().map(|l| Mailbox::login(*l)).collect())
        }
    }

    impl AccountDirectory for Directory {
        fn inbox_account(&self, login: &str) -> Option<Mailbox> {
            let l = login.to_ascii_lowercase();
            self.0.iter().find(|m| m.login == l).cloned()
        }
    }

    /// A core with an inbox, and optionally somewhere to send
    /// notifications. Shared with `super::notify_tests`.
    pub(super) fn server_arc(
        policy: InboxPolicy,
        logins: &[&str],
        gateway: Option<Arc<dyn crate::NotificationGateway>>,
    ) -> (Arc<Core>, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let dir = Arc::new(Directory::of(logins));
        let mut core = Core::new().with_inbox(store.clone(), dir, policy);
        if let Some(gw) = gateway {
            core = core.with_notifications(gw);
        }
        (Arc::new(core), store)
    }

    fn server_with(policy: InboxPolicy, logins: &[&str]) -> (Arc<Core>, Arc<MemoryStore>) {
        server_arc(policy, logins, None)
    }

    fn server(logins: &[&str]) -> (Arc<Core>, Arc<MemoryStore>) {
        server_with(InboxPolicy::default(), logins)
    }

    /// Attach a session whose account is linked to an identity.
    pub(super) fn attach_identified(
        core: &Core,
        login: &str,
        fingerprint: [u8; 32],
    ) -> (Uid, UnboundedReceiver<SeqEvent>) {
        let (uid, rx) = core
            .attach(AttachInfo {
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_MSGS),
                login: login.to_string(),
                addr: Some("10.0.0.1".parse().unwrap()),
                can_detach: true,
                transport: crate::Transport::default(),
                has_inbox: true,
                is_person: true,
                reads_on_delivery: false,
                identity: Some(fingerprint),
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    pub(super) fn attach(
        core: &Core,
        login: &str,
        has_inbox: bool,
    ) -> (Uid, UnboundedReceiver<SeqEvent>) {
        let (uid, rx) = core
            .attach(AttachInfo {
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_MSGS),
                login: login.to_string(),
                addr: Some("10.0.0.1".parse().unwrap()),
                can_detach: true,
                transport: crate::Transport::default(),
                has_inbox,
                is_person: has_inbox,
                reads_on_delivery: false,
                identity: None,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    /// A distinguishable identity fingerprint.
    fn fp(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn msgs(evs: Vec<Event>) -> Vec<Event> {
        evs.into_iter()
            .filter(|e| matches!(e, Event::Msg { .. }))
            .collect()
    }

    #[test]
    fn a_message_to_someone_present_is_stored_and_handed_over_at_once() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        assert_eq!(
            core.msg(a, m, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered,
            "a recipient who is there gets it now"
        );
        match &msgs(drain(&mut rm))[..] {
            [Event::Msg {
                from,
                from_login,
                text,
                id,
                queued,
                ..
            }] => {
                assert_eq!(*from, a);
                assert_eq!(from_login.as_deref(), Some("alice"));
                assert_eq!(text, "hi");
                assert!(id.is_some(), "stored, so it has a handle to mark read");
                assert!(!queued, "it did not wait for anything");
            }
            other => panic!("expected one message, got {other:?}"),
        }
        // Persisted anyway: the durable copy is what a dropped socket or a
        // second device asks for later.
        let stored = store.all();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].delivered_at.is_some(), "and marked delivered");
        assert!(stored[0].read_at.is_none(), "delivered is not read");
    }

    #[test]
    fn a_detached_session_gets_no_outbox_copy_and_finds_it_on_resume() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        let last_seq = std::iter::from_fn(|| rm.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(m, 8));

        assert!(matches!(
            core.msg(a, m, "you there?".into(), None, None).unwrap(),
            MsgOutcome::Queued(_)
        ));
        assert_eq!(store.all().len(), 1);
        assert!(
            store.all()[0].delivered_at.is_none(),
            "a detached session is not a live connection"
        );

        let Resume::Replayed(mut rm2, replay) = core.resume(m, last_seq) else {
            panic!("resume should replay");
        };
        assert!(
            !replay
                .iter()
                .any(|se| matches!(se.event, Event::Msg { .. })),
            "the outbox must not carry a second copy — one message, one place"
        );

        assert_eq!(core.flush_inbox(m), 1);
        match &msgs(drain(&mut rm2))[..] {
            [Event::Msg { text, queued, .. }] => {
                assert_eq!(text, "you there?");
                assert!(queued, "this one waited");
            }
            other => panic!("expected the queued message, got {other:?}"),
        }
    }

    #[test]
    fn a_message_outlives_the_session_it_was_addressed_to() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        // The grace window lapses and the session is gone entirely.
        core.end_session(m);
        assert!(core.user(m).is_none());

        assert!(matches!(
            core.msg_login(a, "dave", "call me".into(), None, None)
                .unwrap(),
            MsgOutcome::Queued(_)
        ));

        // A fresh session, a different uid, the same account.
        let (m2, mut rm2) = attach(&core, "dave", true);
        assert_ne!(m2, m);
        assert_eq!(core.flush_inbox(m2), 1);
        assert!(matches!(
            &msgs(drain(&mut rm2))[..],
            [Event::Msg { text, queued: true, .. }] if text == "call me"
        ));
        // And only once.
        assert_eq!(core.flush_inbox(m2), 0);
    }

    #[test]
    fn a_recipient_without_an_inbox_is_live_only() {
        let (core, store) = server(&["alice"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (g, mut rg) = attach(&core, "guest", false);
        drain(&mut rg);

        assert_eq!(
            core.msg(a, g, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered
        );
        assert!(
            matches!(&msgs(drain(&mut rg))[..], [Event::Msg { id: None, .. }]),
            "nothing stored means no handle to mark read"
        );
        assert!(store.all().is_empty());
    }

    #[test]
    fn a_guest_may_reach_a_session_and_may_not_fill_a_mailbox() {
        // §9's "anyone with an account can put mail in anyone's mailbox"
        // does not cover a guest, which has no account. A guest cannot be
        // blocked — `guest` is a login several people share, so there is
        // nothing durable to hold a block against — so a guest that could
        // queue mail could fill any mailbox on the server to its cap and
        // stay unstoppable. Every other sender is then refused
        // `mailbox_full` until the owner clears it by hand.
        let (core, store) = server(&["dave"]);
        let (g, _rg) = attach(&core, "guest", false);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        // Live delivery to a session that is right there: fine, and the
        // nick shows, as it always did.
        assert_eq!(
            core.msg(g, m, "hello".into(), None, None).unwrap(),
            MsgOutcome::Delivered
        );
        match &msgs(drain(&mut rm))[..] {
            [Event::Msg {
                id: None,
                from_nick,
                from_login,
                ..
            }] => {
                assert_eq!(from_nick, "guest");
                assert_eq!(*from_login, None, "nowhere to reply");
            }
            other => panic!("{other:?}"),
        }
        assert!(store.all().is_empty(), "nothing durable was written");

        // With nobody there, there is nothing a guest can do.
        core.end_session(m);
        assert_eq!(
            core.msg_login(g, "dave", "still here?".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert!(store.all().is_empty());
    }

    #[test]
    fn a_guest_cannot_fill_a_mailbox_against_everyone_else() {
        let (core, store) = server(&["dave", "alice"]);
        let policy = core.inbox_policy;
        let (g, _rg) = attach(&core, "guest", false);
        let (a, _ra) = attach(&core, "alice", true);
        // Dave is offline. The guest tries the whole cap and more.
        for i in 0..policy.max_queued + 5 {
            assert_eq!(
                core.msg_login(g, "dave", format!("flood {i}"), None, None),
                Err(ChatError::NoSuchUser)
            );
        }
        assert!(store.all().is_empty());
        // An account can still reach him, which is the point.
        assert!(matches!(
            core.msg_login(a, "dave", "dinner?".into(), None, None),
            Ok(MsgOutcome::Queued(_))
        ));
        assert_eq!(store.all().len(), 1);
    }

    #[test]
    fn concurrent_flushes_do_not_deliver_a_message_twice() {
        // Two senders storing for one recipient, both flushing. Without a
        // lock across pending -> send -> mark, both read the same rows
        // and both push them, and the recipient sees every message twice
        // — an ng client gets two `msg` events with the same id, a 1.5
        // client gets two windows.
        use std::sync::Arc;
        let (core, _store) = server(&["dave", "a1", "a2", "a3", "a4"]);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        let senders: Vec<Uid> = (1..=4)
            .map(|n| attach(&core, &format!("a{n}"), true).0)
            .collect();

        let handles: Vec<_> = senders
            .iter()
            .enumerate()
            .map(|(i, &from)| {
                let core: Arc<Core> = core.clone();
                std::thread::spawn(move || {
                    for j in 0..10 {
                        core.msg(from, m, format!("s{i}-{j}"), None, None).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // And a flush racing them from the recipient's own side.
        core.flush_inbox(m);

        let mut ids = Vec::new();
        let mut bodies = Vec::new();
        for e in msgs(drain(&mut rm)) {
            if let Event::Msg { id, text, .. } = e {
                ids.push(id.expect("stored mail carries an id"));
                bodies.push(text);
            }
        }
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "every message exactly once; got {} events for {} ids",
            ids.len(),
            unique.len()
        );
        assert_eq!(bodies.len(), 40, "and all of them arrived");
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "in id order");
    }

    #[test]
    fn a_retry_hands_over_a_message_the_recipient_can_now_receive() {
        // A client retries after a socket died mid-ack. The store
        // answers "that is the message you already sent" — and the
        // answer to give the sender is the one the first send would get
        // *now*: the recipient may have arrived in between, and leaving
        // the mail pending until their next login while they are sitting
        // there is a message that waits for no reason.
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let g = crate::inbox::MessageGuid::parse("00000001-0000-4000-8000-000000000000").unwrap();

        assert!(matches!(
            core.msg_login(a, "dave", "you there?".into(), Some(g.clone()), None)
                .unwrap(),
            MsgOutcome::Queued(_)
        ));

        // Dave logs in. The retry finds him.
        let (_m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        assert_eq!(
            core.msg_login(a, "dave", "you there?".into(), Some(g), None)
                .unwrap(),
            MsgOutcome::Delivered,
            "the retry is answered as of now, not as of the first send"
        );
        assert!(
            matches!(
                &msgs(drain(&mut rm))[..],
                [Event::Msg { text, queued: true, .. }] if text == "you there?"
            ),
            "the message went with the answer, and it waited: a retry is \
             not a fresh send however briefly the row sat there"
        );
    }

    #[test]
    fn a_message_reaches_the_attached_session_not_the_lowest_uid() {
        // Two sessions on one account: a detached phone and an attached
        // laptop. Resolving the recipient by lowest uid aimed everything
        // at the phone, which is buffering — so nothing was delivered
        // live and the laptop learned about it at its next sync.
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (phone, _rp) = attach(&core, "dave", true);
        let (laptop, mut rl) = attach(&core, "dave", true);
        assert!(phone < laptop, "the detached one has the lower uid");
        drain(&mut rl);
        assert!(core.connection_lost(phone, 8));

        assert_eq!(
            core.msg_login(a, "dave", "dinner?".into(), None, None)
                .unwrap(),
            MsgOutcome::Delivered,
            "the laptop is right there"
        );
        assert!(
            matches!(&msgs(drain(&mut rl))[..], [Event::Msg { text, .. }] if text == "dinner?"),
            "and it is the laptop that got it"
        );
    }

    #[test]
    fn a_send_that_stores_nothing_still_goes_to_the_session_that_was_named() {
        // The non-durable path — every plain-guest sender on a server
        // with `[inbox]`, and *every* sender on a server without one.
        // It resolved by lowest attached uid, which overrode the uid the
        // sender named even when that session was attached too: the
        // phone got what was clicked on the laptop (§15).
        for (what, core) in [
            ("no store at all", Arc::new(Core::new())),
            ("a guest sender", server(&["dave"]).0),
        ] {
            // A guest has no mailbox, so nothing it sends is stored;
            // with no store nothing is stored either way.
            let (guest, _rg) = attach(&core, "guest", false);
            let (phone, mut rp) = attach(&core, "dave", true);
            let (laptop, mut rl) = attach(&core, "dave", true);
            assert!(phone < laptop, "{what}: the named one has the higher uid");
            drain(&mut rp);
            drain(&mut rl);

            assert_eq!(
                core.msg(guest, laptop, "over here".into(), None, None)
                    .unwrap(),
                MsgOutcome::Delivered,
                "{what}"
            );
            assert!(
                matches!(&msgs(drain(&mut rl))[..], [Event::Msg { text, .. }] if text == "over here"),
                "{what}: the session the sender clicked is the one that hears it"
            );
            assert!(msgs(drain(&mut rp)).is_empty(), "{what}: not the other one");

            // And naming the phone still reaches the phone.
            core.msg(guest, phone, "and here".into(), None, None)
                .unwrap();
            assert!(
                matches!(&msgs(drain(&mut rp))[..], [Event::Msg { text, .. }] if text == "and here"),
                "{what}"
            );
            assert!(msgs(drain(&mut rl)).is_empty(), "{what}");

            // A named session that is *detached* still falls back to one
            // that can hear it: this path has nowhere to queue.
            assert!(core.connection_lost(laptop, 8));
            core.msg(guest, laptop, "anyone".into(), None, None)
                .unwrap();
            assert!(
                matches!(&msgs(drain(&mut rp))[..], [Event::Msg { text, .. }] if text == "anyone"),
                "{what}: a detached named session is not an address"
            );
        }
    }

    #[test]
    fn addressing_an_account_that_takes_no_mail_is_the_same_answer_as_a_typo() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        assert_eq!(
            core.msg_login(a, "nobody", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(
            core.msg_login(a, "guest", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        // And the canonical form is the directory's, not the client's.
        assert!(core.msg_login(a, "DaVe", "hi".into(), None, None).is_ok());
    }

    #[test]
    fn addressing_a_login_that_is_online_delivers_rather_than_queues() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        assert_eq!(
            core.msg_login(a, "dave", "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered
        );
        assert!(matches!(
            &msgs(drain(&mut rm))[..],
            [Event::Msg { queued: false, .. }]
        ));
        assert_eq!(
            core.inbox_counts(m).unwrap(),
            InboxCounts {
                unread: 1,
                total: 1
            },
            "delivered, and still waiting to be read"
        );
    }

    #[test]
    fn a_queued_messages_sender_uid_is_resolved_at_delivery_by_login() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        core.end_session(m);

        core.msg_login(a, "dave", "first".into(), None, None)
            .unwrap();
        core.end_session(a); // the sender leaves before it is delivered

        let (m2, mut rm2) = attach(&core, "dave", true);
        core.flush_inbox(m2);
        assert!(
            matches!(
                &msgs(drain(&mut rm2))[..],
                [Event::Msg { from: 0, from_login, .. }]
                    if from_login.as_deref() == Some("alice")
            ),
            "no session, no uid — the login carries the identity"
        );
        core.end_session(m2);

        // Again, but this time the sender is back by the time it is
        // delivered — on a *different* uid, which is the one a reply
        // should reach, because it is the same account.
        let (a2, _ra2) = attach(&core, "alice", true);
        core.msg_login(a2, "dave", "second".into(), None, None)
            .unwrap();
        core.end_session(a2);
        let (a3, _ra3) = attach(&core, "alice", true);
        assert_ne!(a3, a2, "a fresh session, a fresh uid");

        let (m3, mut rm3) = attach(&core, "dave", true);
        core.flush_inbox(m3);
        assert!(
            matches!(&msgs(drain(&mut rm3))[..], [Event::Msg { from, .. }] if *from == a3),
            "resolved now and by login, never by the uid that sent it"
        );
    }

    #[test]
    fn a_full_mailbox_refuses_rather_than_dropping_the_oldest() {
        let (core, store) = server_with(
            InboxPolicy {
                max_queued: 2,
                ..InboxPolicy::default()
            },
            &["alice", "dave"],
        );
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "one".into(), None, None).unwrap();
        core.msg_login(a, "dave", "two".into(), None, None).unwrap();
        assert_eq!(
            core.msg_login(a, "dave", "three".into(), None, None),
            Err(ChatError::MailboxFull),
            "the sender is told, rather than the message vanishing"
        );
        assert_eq!(store.all().len(), 2, "and nothing was evicted to fit it");

        // Collecting the mail is what makes room — not reading it. A
        // client that never marks anything read must not be able to lock
        // its own mailbox against every sender.
        let (m, _rm) = attach(&core, "dave", true);
        assert_eq!(core.flush_inbox(m), 2);
        assert_eq!(
            core.inbox_counts(m).unwrap().unread,
            2,
            "still unread, and no longer in the way"
        );
        assert!(core
            .msg_login(a, "dave", "three".into(), None, None)
            .is_ok());
    }

    #[test]
    fn the_flush_cap_leaves_the_rest_pending_and_says_how_many() {
        let (core, _store) = server_with(
            InboxPolicy {
                deliver_at_flush: 2,
                ..InboxPolicy::default()
            },
            &["alice", "dave"],
        );
        let (a, _ra) = attach(&core, "alice", true);
        for i in 0..5 {
            core.msg_login(a, "dave", format!("m{i}"), None, None)
                .unwrap();
        }

        let (m, mut rm) = attach(&core, "dave", true);
        assert_eq!(core.flush_inbox(m), 2, "one window at a time");
        let evs = drain(&mut rm);
        assert_eq!(msgs(evs.clone()).len(), 2);
        assert!(
            matches!(evs.last(), Some(Event::Notice { text, .. }) if text.starts_with("3 more")),
            "what is left is still there, and says so: {evs:?}"
        );
        // The next login picks up where this one stopped.
        assert_eq!(core.flush_inbox(m), 2);
        assert_eq!(core.flush_inbox(m), 1);
        assert_eq!(core.flush_inbox(m), 0);
    }

    #[test]
    fn counts_and_marking_read_are_scoped_to_the_callers_own_account() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "one".into(), None, None).unwrap();
        core.msg_login(a, "alice", "to myself".into(), None, None)
            .unwrap();
        let dave_msg = store.all()[0].id;
        let alice_msg = store.all()[1].id;
        assert!(alice_msg > dave_msg);

        // Alice naming an id that is not hers marks only her own mail.
        let left = core.inbox_mark_read(a, alice_msg).unwrap();
        assert_eq!(left.unread, 0, "alice's own is read");
        let (m, _rm) = attach(&core, "dave", true);
        assert_eq!(
            core.inbox_counts(m).unwrap().unread,
            1,
            "dave's is untouched"
        );
    }

    #[test]
    fn a_server_with_no_inbox_behaves_exactly_as_it_did_before_there_was_one() {
        let core = Core::new();
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        assert_eq!(
            core.msg(a, m, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered
        );
        assert!(matches!(
            &msgs(drain(&mut rm))[..],
            [Event::Msg {
                id: None,
                queued: false,
                ..
            }]
        ));
        // Addressing an account is an inbox feature and is simply absent.
        assert_eq!(
            core.msg_login(a, "dave", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(core.flush_inbox(m), 0);
        assert_eq!(core.inbox_counts(m).unwrap(), InboxCounts::default());

        // And a detached session still buffers in its outbox, as before.
        let last_seq = core.current_seq(m).unwrap();
        assert!(core.connection_lost(m, 8));
        core.msg(a, m, "still there?".into(), None, None).unwrap();
        let Resume::Replayed(_rm2, replay) = core.resume(m, last_seq) else {
            panic!("resume should replay");
        };
        assert!(replay.iter().any(|se| matches!(&se.event,
            Event::Msg { text, .. } if text == "still there?")));
    }

    // --- The mailbox key (docs/private-messages.md §5.4) -----------------

    #[test]
    fn a_rename_takes_the_mailbox_and_the_freed_login_inherits_nothing() {
        let store = Arc::new(MemoryStore::new());
        // The directory knows alice by her identity, not just her login.
        let dir = Arc::new(Directory(vec![
            Mailbox::identified("alice", fp(10)),
            Mailbox::login("sender"),
        ]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));
        let (s, _rs) = attach(&core, "sender", true);
        core.msg_login(s, "alice", "private".into(), None, None)
            .unwrap();

        // She renames. Same identity, new login, same mail.
        let (alicia, mut r_alicia) = attach_identified(&core, "alicia", fp(10));
        assert_eq!(core.flush_inbox(alicia), 1);
        assert!(matches!(
            &msgs(drain(&mut r_alicia))[..],
            [Event::Msg { text, .. }] if text == "private"
        ));
        core.end_session(alicia);

        // Someone else takes the freed login — with an identity of their
        // own, and without one. Neither inherits a word of it.
        let (b, mut rb) = attach_identified(&core, "alice", fp(11));
        assert_eq!(core.flush_inbox(b), 0, "a different identity, same login");
        assert!(msgs(drain(&mut rb)).is_empty());
        core.end_session(b);

        let (bare, _rbare) = attach(&core, "alice", true);
        assert_eq!(core.flush_inbox(bare), 0, "nor a bare login");
    }

    #[test]
    fn a_queued_senders_uid_resolves_to_the_identity_not_the_login() {
        let store = Arc::new(MemoryStore::new());
        let dir = Arc::new(Directory(vec![
            Mailbox::login("dave"),
            Mailbox::identified("alice", fp(10)),
        ]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));

        // Alice, identity A, sends while dave is away, then leaves.
        let (a, _ra) = attach_identified(&core, "alice", fp(10));
        core.msg_login(a, "dave", "from the real alice".into(), None, None)
            .unwrap();
        core.end_session(a);

        // An impostor takes the freed login with no identity, and is on
        // the roster when the mail is delivered.
        let (impostor, _ri) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        core.flush_inbox(m);
        assert!(
            matches!(&msgs(drain(&mut rm))[..], [Event::Msg { from: 0, .. }]),
            "a reply must not be addressed to whoever holds the name now"
        );
        let _ = impostor;
    }

    // --- Blocking (docs/private-messages.md §9) --------------------------

    #[test]
    fn a_block_refuses_the_message_however_it_is_addressed() {
        let (core, store) = server(&["dave", "spammer"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (sp, _rsp) = attach(&core, "spammer", true);
        core.inbox_block(m, "spammer", true).unwrap();

        assert_eq!(
            core.msg_login(sp, "dave", "buy this".into(), None, None),
            Err(ChatError::Blocked)
        );
        // And naming the roster row instead does not get round it: a
        // block a recipient can sidestep by clicking a name is no block.
        assert_eq!(
            core.msg(sp, m, "buy this".into(), None, None),
            Err(ChatError::Blocked)
        );
        assert!(store.all().is_empty(), "and nothing was stored either way");

        core.inbox_block(m, "spammer", false).unwrap();
        assert!(core.msg(sp, m, "sorry".into(), None, None).is_ok());
    }

    #[test]
    fn mail_from_an_identity_guest_is_listed_with_no_one_to_reply_to() {
        // Their mailbox is keyed by fingerprint and named `guest`, which
        // is a login several people share and one a reply would answer
        // `no_such_user` for. The delivered event has applied that rule
        // since the flush learned it; the stored list used to print the
        // login verbatim, so `inbox` offered a reply address that
        // couldn't be used.
        let (core, _store) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (g, _rg) = core
            .attach(AttachInfo {
                nick: "drifter".into(),
                icon: 1,
                admin: false,
                access: AccessBits::empty().with(bit::SEND_MSGS),
                login: "guest".into(),
                addr: Some("10.0.0.9".parse().unwrap()),
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: false,
                is_person: false,
                reads_on_delivery: false,
                identity: Some(fp(3)),
            })
            .unwrap();
        core.announce(g);

        core.msg(g, m, "from a passer-by".into(), None, None)
            .unwrap();
        let listed = core.inbox_list(m, None, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sender_nick, "drifter", "the nick still shows");
        assert!(
            listed[0].sender.is_none(),
            "and there is no login to reply to"
        );
    }

    #[test]
    fn a_block_on_an_identity_guest_outlives_them_and_can_still_be_lifted() {
        // An identity user admitted as a guest has a fingerprint to hold
        // a block against and no account of its own. The list used to
        // report the login — `guest` — which `unblock` could not resolve
        // and which the roster could not answer for once they left, so
        // the block was permanent.
        let (core, _store) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (g, _rg) = core
            .attach(AttachInfo {
                nick: "drifter".into(),
                icon: 1,
                admin: false,
                access: AccessBits::empty().with(bit::SEND_MSGS),
                login: "guest".into(),
                addr: Some("10.0.0.9".parse().unwrap()),
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: false,
                is_person: false,
                reads_on_delivery: false,
                identity: Some(fp(7)),
            })
            .unwrap();
        core.announce(g);

        core.inbox_block_uid(m, g, true).unwrap();
        let blocked = core.inbox_blocked(m).unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].login, "guest");
        assert_eq!(blocked[0].fingerprint, Some(fp(7)), "keyed by the key");

        // They leave. There is no roster row to name, and `guest` names
        // no mailbox — the fingerprint is all that is left.
        core.end_session(g);
        assert!(core.inbox_block(m, "guest", false).is_err());
        core.inbox_unblock_fingerprint(m, &fp(7)).unwrap();
        assert!(core.inbox_blocked(m).unwrap().is_empty());
        assert_eq!(
            core.inbox_unblock_fingerprint(m, &fp(7)),
            Err(ChatError::NoSuchUser),
            "and a fingerprint that holds no block is not a block"
        );
    }

    #[test]
    fn a_block_is_one_way_and_listed_and_says_nothing_about_who_exists() {
        let (core, _store) = server(&["dave", "spammer"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (sp, _rsp) = attach(&core, "spammer", true);

        core.inbox_block(m, "spammer", true).unwrap();
        assert_eq!(
            core.inbox_blocked(m).unwrap(),
            vec![Mailbox::login("spammer")]
        );
        assert!(
            core.inbox_blocked(sp).unwrap().is_empty(),
            "blocking is one-way, and the blocked account is not told"
        );
        assert!(core
            .msg(m, sp, "you are blocked".into(), None, None)
            .is_ok());

        // Blocking a name that names no mailbox is the same one answer
        // msg_login gives, so this cannot enumerate accounts either.
        assert_eq!(
            core.inbox_block(m, "nobody", true),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(
            core.inbox_block(m, "dave", true),
            Err(ChatError::NoSuchUser),
            "and blocking yourself is not a thing"
        );
    }

    #[test]
    fn a_guest_cannot_be_blocked_because_there_is_nothing_to_block() {
        let (core, _store) = server(&["dave"]);
        let (m, mut rm) = attach(&core, "dave", true);
        let (g, _rg) = attach(&core, "guest", false);
        drain(&mut rm);

        assert_eq!(
            core.inbox_block(m, "guest", true),
            Err(ChatError::NoSuchUser)
        );
        // A guest reaches the mailbox as before; what bounds it is the
        // roster, where it can be kicked and banned.
        assert!(core.msg(g, m, "hello".into(), None, None).is_ok());
        assert_eq!(msgs(drain(&mut rm)).len(), 1);
    }

    // --- The store-then-re-check window (docs/private-messages.md §5.2) --

    /// A store that lets a test run something *during* `push` — inside the
    /// window where the domain has dropped the roster lock to write and
    /// has not taken it back to deliver.
    struct RacyStore {
        inner: MemoryStore,
        during_push: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl RacyStore {
        fn new() -> Self {
            RacyStore {
                inner: MemoryStore::new(),
                during_push: Mutex::new(None),
            }
        }
    }

    impl MessageStore for RacyStore {
        fn push(&self, m: &NewMessage, cap: usize) -> Result<crate::inbox::Pushed, StoreError> {
            let out = self.inner.push(m, cap)?;
            if let Some(f) = self.during_push.lock().unwrap().take() {
                f();
            }
            Ok(out)
        }
        fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError> {
            self.inner.is_pending(to, id)
        }
        fn pending(&self, to: &Mailbox, limit: usize) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.pending(to, limit)
        }
        fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError> {
            self.inner.pending_count(to)
        }
        fn mark_delivered(
            &self,
            ids: &[MessageId],
            at: std::time::SystemTime,
            what: Delivery,
        ) -> Result<(), StoreError> {
            self.inner.mark_delivered(ids, at, what)
        }
        fn mark_read(
            &self,
            to: &Mailbox,
            up_to: MessageId,
            at: std::time::SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.mark_read(to, up_to, at)
        }
        fn list(
            &self,
            to: &Mailbox,
            before: Option<MessageId>,
            limit: usize,
        ) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.list(to, before, limit)
        }
        fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError> {
            self.inner.counts(to)
        }
        fn find_guid(
            &self,
            to: &Mailbox,
            from: Option<&Mailbox>,
            guid: &MessageGuid,
        ) -> Result<Option<StoredMessage>, StoreError> {
            self.inner.find_guid(to, from, guid)
        }
        fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
            self.inner.claim(login, fingerprint)
        }
        fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
            self.inner.rotate(from, to)
        }
        fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
            self.inner.purge(of)
        }
        fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
            self.inner.purge_count(of)
        }
        fn prune(
            &self,
            now: std::time::SystemTime,
            unread: Duration,
            read: Duration,
        ) -> Result<usize, StoreError> {
            self.inner.prune(now, unread, read)
        }
        fn set_blocked(
            &self,
            owner: &Mailbox,
            other: &Mailbox,
            blocked: bool,
            at: SystemTime,
        ) -> Result<(), StoreError> {
            self.inner.set_blocked(owner, other, blocked, at)
        }
        fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError> {
            self.inner.is_blocked(owner, other)
        }
        fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError> {
            self.inner.blocked(owner)
        }
    }

    #[test]
    fn a_recipient_who_reattaches_mid_write_still_gets_it_now() {
        let store = Arc::new(RacyStore::new());
        let dir = Arc::new(Directory::of(&["alice", "dave"]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));

        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        let last_seq = std::iter::from_fn(|| rm.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(m, 8));

        // Dave's phone comes back exactly while the message is being
        // written — after the decision to store, before delivery.
        let resumed: Arc<Mutex<Option<UnboundedReceiver<SeqEvent>>>> = Arc::new(Mutex::new(None));
        let weak: Weak<Core> = Arc::downgrade(&core);
        let slot = resumed.clone();
        *store.during_push.lock().unwrap() = Some(Box::new(move || {
            let core = weak.upgrade().expect("core outlives the store call");
            if let Resume::Replayed(rx, _) | Resume::ResyncRequired(rx) = core.resume(m, last_seq) {
                *slot.lock().unwrap() = Some(rx);
            }
        }));

        assert_eq!(
            core.msg(a, m, "are you there".into(), None, None).unwrap(),
            MsgOutcome::Delivered,
            "the re-check after the write is what catches this"
        );
        let mut rx = resumed.lock().unwrap().take().expect("resumed");
        assert!(
            matches!(
                &msgs(drain(&mut rx))[..],
                [Event::Msg { text, .. }] if text == "are you there"
            ),
            "otherwise it sits unread until the next login — while they watch"
        );
    }

    #[test]
    fn a_recipient_with_no_session_at_all_who_attaches_mid_write_gets_it_now() {
        // The `to_login` half of the same race, and the half the re-check
        // could not close: with no session at store time there was no uid
        // to re-check *against*, so a recipient who logged in while the
        // row was being written waited until their next login for a
        // message sent while they were watching the screen.
        let store = Arc::new(RacyStore::new());
        let dir = Arc::new(Directory::of(&["alice", "dave"]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));
        let (a, _ra) = attach(&core, "alice", true);

        let arrived: Arc<Mutex<Option<UnboundedReceiver<SeqEvent>>>> = Arc::new(Mutex::new(None));
        let weak: Weak<Core> = Arc::downgrade(&core);
        let slot = arrived.clone();
        *store.during_push.lock().unwrap() = Some(Box::new(move || {
            let core = weak.upgrade().expect("core outlives the store call");
            let (_uid, rx) = attach(&core, "dave", true);
            *slot.lock().unwrap() = Some(rx);
        }));

        assert_eq!(
            core.msg_login(a, "dave", "still up?".into(), None, None)
                .unwrap(),
            MsgOutcome::Delivered,
            "they were there by the time the row existed"
        );
        let mut rx = arrived.lock().unwrap().take().expect("attached");
        assert!(
            matches!(&msgs(drain(&mut rx))[..], [Event::Msg { text, .. }] if text == "still up?")
        );
    }
}

#[cfg(test)]
mod notify_tests {
    //! The notify decision — which arriving message earns a push, and
    //! which does not. See docs/push-notifications.md §6 and §11: the rule
    //! lives here rather than in a frontend precisely so that neither wire
    //! can skip it, and these are the cases that would go quietly wrong.

    use std::sync::{Arc, Mutex};

    use super::inbox_tests::{attach, server_arc};
    use super::*;
    use crate::notify::{Notification, NotificationGateway};
    use crate::{Core, InboxPolicy};

    /// A gateway that records what it was asked to send. No network, no
    /// runtime, nothing to wait for — the decision is the whole subject.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, String, usize)>>,
    }

    impl Recorder {
        /// `(recipient login, text, unread)`, in order.
        fn sent(&self) -> Vec<(String, String, usize)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl NotificationGateway for Recorder {
        fn notify(&self, n: &Notification<'_>) {
            self.sent
                .lock()
                .unwrap()
                .push((n.to.login.clone(), n.text.to_string(), n.unread));
        }
    }

    fn server(logins: &[&str]) -> (Arc<Core>, Arc<Recorder>) {
        let gw = Arc::new(Recorder::default());
        let (core, _store) = server_arc(InboxPolicy::default(), logins, Some(gw.clone()));
        (core, gw)
    }

    #[test]
    fn nobody_there_earns_a_notification() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "wake up".into(), None, None)
            .unwrap();
        assert_eq!(
            gw.sent(),
            vec![("dave".to_string(), "wake up".to_string(), 1)]
        );
    }

    #[test]
    fn a_detached_session_earns_one_too() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        assert!(core.connection_lost(m, 8));

        core.msg(a, m, "still asleep?".into(), None, None).unwrap();
        assert_eq!(gw.sent().len(), 1, "the phone is what the push is for");
        assert_eq!(gw.sent()[0].2, 1, "and it carries the badge number");
    }

    #[test]
    fn someone_watching_the_screen_earns_nothing() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);

        assert_eq!(
            core.msg(a, m, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered
        );
        assert!(
            gw.sent().is_empty(),
            "a connection is attached and it got the event"
        );
    }

    #[test]
    fn a_message_to_your_own_account_is_not_news() {
        let (core, gw) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        core.msg_login(m, "dave", "note to self".into(), None, None)
            .unwrap();
        // Stored, so a second device finds it; not pushed, because the
        // person who wrote it does not need telling.
        assert_eq!(core.inbox_counts(m).unwrap().unread, 1);
        assert!(gw.sent().is_empty());
    }

    #[test]
    fn a_recipient_with_no_inbox_earns_nothing() {
        let (core, gw) = server(&["alice"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (g, _rg) = attach(&core, "guest", false);
        core.msg(a, g, "hi".into(), None, None).unwrap();
        assert!(
            gw.sent().is_empty(),
            "a push about a message that was never stored is a doorbell for nothing"
        );
    }

    #[test]
    fn the_badge_counts_everything_unread_not_just_this_one() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        for i in 0..3 {
            core.msg_login(a, "dave", format!("m{i}"), None, None)
                .unwrap();
        }
        assert_eq!(
            gw.sent().iter().map(|s| s.2).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn no_gateway_means_no_calls_and_no_difference() {
        let (core, _store) =
            super::inbox_tests::server_arc(InboxPolicy::default(), &["alice", "dave"], None);
        let (a, _ra) = attach(&core, "alice", true);
        // The only assertion available is that nothing panics and the
        // message still lands — which is the point: push is optional.
        assert!(matches!(
            core.msg_login(a, "dave", "hi".into(), None, None).unwrap(),
            MsgOutcome::Queued(_)
        ));
    }
}
