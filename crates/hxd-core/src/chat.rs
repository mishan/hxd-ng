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
//!
//! All text is UTF-8 (`String`) — see the roster module docs for the
//! conversion rules at the legacy edge.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::roster::{reads_public_chat, Event, RosterInner, Uid, UserInfo};
use crate::Core;

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
}

impl Core {
    // --- Chat lines -----------------------------------------------------

    /// A public chat line. Delivered (sender included) to every visible
    /// session allowed to read chat.
    pub fn chat_public(&self, from: Uid, text: String, style: u16) {
        let r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get(&from) else {
            return;
        };
        let ev = Event::Chat {
            cid: 0,
            from: sess.info.clone(),
            text,
            style,
        };
        r.broadcast_where(&ev, None, reads_public_chat);
    }

    /// A private chat line; membership is the only gate.
    pub fn chat_private(
        &self,
        cid: u32,
        from: Uid,
        text: String,
        style: u16,
    ) -> Result<(), ChatError> {
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
        let ev = Event::Chat {
            cid,
            from: sess.info.clone(),
            text,
            style,
        };
        for uid in &chat.members {
            r.send_to(*uid, ev.clone());
        }
        Ok(())
    }

    /// A server notice into a chat (kick announcements and the like).
    /// Semantic text — each frontend formats it. Public delivery honors the
    /// read-chat filter.
    pub fn chat_notice(&self, cid: u32, from: Uid, text: String) {
        let r = self.roster.lock().unwrap();
        let ev = Event::Notice { cid, from, text };
        if cid == 0 {
            r.broadcast_where(&ev, None, reads_public_chat);
        } else if let Some(chat) = r.chats.get(&cid) {
            for uid in &chat.members {
                r.send_to(*uid, ev.clone());
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
        r.last_chat_ref += 1;
        let cid = r.last_chat_ref;
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

    /// A private message. The sender's ack is the frontend's task reply.
    pub fn msg(&self, from: Uid, to: Uid, text: String) -> Result<(), ChatError> {
        let r = self.roster.lock().unwrap();
        let from_nick = r
            .users
            .get(&from)
            .map(|s| s.info.nick.clone())
            .ok_or(ChatError::NoSuchUser)?;
        if !r.users.get(&to).is_some_and(|s| s.visible) {
            return Err(ChatError::NoSuchUser);
        }
        r.send_to(
            to,
            Event::Msg {
                from,
                from_nick,
                text,
            },
        );
        Ok(())
    }

    /// An administrator broadcast, to everyone (sender included).
    pub fn broadcast(&self, from: Uid, text: String) -> Result<(), ChatError> {
        let r = self.roster.lock().unwrap();
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
    use crate::roster::test_attach;
    use crate::AccessBits;
    use tokio::sync::mpsc::UnboundedReceiver;

    fn drain(rx: &mut UnboundedReceiver<Event>) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

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

        core.chat_public(a, "hi".into(), 0);
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
            core.chat_private(cid, b, "early".into(), 0),
            Err(ChatError::NotAMember)
        );
        let (rows, _subject) = core.chat_join(cid, b, "").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            matches!(&drain(&mut rx_a)[..], [Event::ChatUserJoined { user, .. }] if user.uid == b)
        );

        core.chat_private(cid, b, "hello".into(), 0).unwrap();
        assert_eq!(drain(&mut rx_a).len(), 1);
        assert_eq!(drain(&mut rx_b).len(), 1);

        // Parting announces to the survivor; last one out deletes the chat.
        core.chat_part(cid, b);
        assert!(matches!(&drain(&mut rx_a)[..], [Event::ChatUserParted { uid, .. }] if *uid == b));
        core.chat_part(cid, a);
        assert_eq!(core.chat_join(cid, a, ""), Err(ChatError::NoSuchChat));
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

        core.detach(b);
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

        core.msg(a, b, "psst".into()).unwrap();
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::Msg { from, text, .. }] if *from == a && text == "psst")
        );
        assert_eq!(core.msg(a, 999, "x".into()), Err(ChatError::NoSuchUser));

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
