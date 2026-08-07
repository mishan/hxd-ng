//! The presence roster: who is on the server, and the event fan-out.
//!
//! **Presence is user-scoped, not connection-scoped** (a roadmap
//! commitment). A [`UserSession`] is a user's presence on the server; a
//! transport attaches to it. On the legacy frontend the mapping is
//! degenerate — one TCP connection is one session, and detaching ends it —
//! but the Hotline-ng phase adds sessions that outlive their connections,
//! and it does that here, not in a rewrite.
//!
//! Fan-out is a per-session unbounded channel of [`Event`]s. In-process
//! today; the clustering phase puts a bus behind the same shape. Events are
//! domain-typed — the session layer encodes them to wire pushes.
//!
//! Chat rooms, messaging and moderation live in [`crate::chat`], as further
//! `impl Core` blocks over the same state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::access::{bit, AccessBits};
use crate::chat::{Ban, PrivateChat};

/// A user id, as seen on the wire (16-bit, never 0 for a real user).
pub type Uid = u16;

/// The visible-to-others part of a session: what a user-list row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub uid: Uid,
    /// Nickname, raw wire bytes (Mac Roman). The domain layer relays these
    /// untouched; only configured strings get converted at the edges.
    pub nick: Vec<u8>,
    pub icon: u16,
    /// 0 = normal, 2 = admin (the legacy color/status field).
    pub color: u16,
}

/// The fuller view one session may request of another (the user-info op).
#[derive(Debug, Clone)]
pub struct UserDetails {
    pub info: UserInfo,
    pub login: String,
    pub addr: Option<IpAddr>,
    pub connected_at: Instant,
}

/// A domain event, delivered on session channels. The session layer encodes
/// these to wire pushes; a future frontend encodes them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A session became visible. Not delivered to the joiner itself.
    Joined(UserInfo),
    /// A visible session changed nick/icon/color. Delivered to everyone,
    /// including the changer (matching the reference server, whose clients
    /// rely on the echo).
    Changed(UserInfo),
    /// A visible session left. Not delivered to the leaver.
    Parted(Uid),
    /// A chat line (semantic: unformatted). `cid` 0 is the public chat.
    /// `style` 1 is an action (`/me`). Delivered to the sender too.
    Chat {
        cid: u32,
        from: UserInfo,
        text: Vec<u8>,
        style: u16,
    },
    /// A pre-formatted chat line (server notices: kicks, etc.). The legacy
    /// frontend emits it verbatim.
    ChatLine { cid: u32, from: Uid, line: Vec<u8> },
    /// A chat (or, for cid 0, server) subject change.
    ChatSubject { cid: u32, subject: Vec<u8> },
    /// A private chat's password change, announced to its members
    /// (reference-server behavior).
    ChatPassword { cid: u32, password: Vec<u8> },
    /// An invitation to a private chat.
    ChatInvite {
        cid: u32,
        from: Uid,
        from_nick: Vec<u8>,
    },
    /// Someone joined a private chat the recipient is in.
    ChatUserJoined { cid: u32, user: UserInfo },
    /// Someone left a private chat the recipient is in.
    ChatUserParted { cid: u32, uid: Uid },
    /// A private message to the recipient.
    Msg {
        from: Uid,
        from_nick: Vec<u8>,
        text: Vec<u8>,
    },
    /// An administrator broadcast. Delivered to everyone, sender included
    /// (the wire push carries the sender, matching the reference server).
    Broadcast {
        from: Uid,
        from_nick: Vec<u8>,
        text: Vec<u8>,
    },
    /// The recipient has been kicked; its transport should close.
    Kicked,
}

/// One user's presence. Today: exactly one attached connection, whose
/// death detaches the session. (See the module comment for where this
/// grows.)
pub(crate) struct UserSession {
    pub(crate) info: UserInfo,
    pub(crate) access: AccessBits,
    pub(crate) login: String,
    pub(crate) addr: Option<IpAddr>,
    pub(crate) connected_at: Instant,
    /// Whether this session has been announced (shows on the user list,
    /// generates events). False between login and login-completion.
    pub(crate) visible: bool,
    pub(crate) events: UnboundedSender<Event>,
}

/// What a transport hands the roster at login.
#[derive(Debug, Clone)]
pub struct AttachInfo {
    pub nick: Vec<u8>,
    pub icon: u16,
    pub color: u16,
    pub access: AccessBits,
    pub login: String,
    pub addr: Option<IpAddr>,
}

#[derive(Default)]
pub(crate) struct RosterInner {
    pub(crate) users: HashMap<Uid, UserSession>,
    last_uid: Uid,
    pub(crate) public_subject: Vec<u8>,
    pub(crate) chats: HashMap<u32, PrivateChat>,
    pub(crate) last_chat_ref: u32,
    pub(crate) bans: Vec<Ban>,
}

impl RosterInner {
    fn next_uid(&mut self) -> Option<Uid> {
        // Sequential with wrap, skipping 0 and in-use ids — stable ids for
        // the lifetime of a session, no reuse while alive.
        for _ in 0..=u16::MAX {
            self.last_uid = self.last_uid.wrapping_add(1);
            if self.last_uid == 0 {
                continue;
            }
            if !self.users.contains_key(&self.last_uid) {
                return Some(self.last_uid);
            }
        }
        None
    }

    pub(crate) fn send_to(&self, uid: Uid, ev: Event) {
        if let Some(sess) = self.users.get(&uid) {
            // A closed receiver just means that session is tearing down;
            // its detach will clean up.
            let _ = sess.events.send(ev);
        }
    }

    /// Deliver to every *visible* session matching `pred` (skipping `skip`).
    pub(crate) fn broadcast_where<F: Fn(&UserSession) -> bool>(
        &self,
        ev: &Event,
        skip: Option<Uid>,
        pred: F,
    ) {
        for (uid, sess) in &self.users {
            if Some(*uid) == skip || !sess.visible || !pred(sess) {
                continue;
            }
            let _ = sess.events.send(ev.clone());
        }
    }

    fn broadcast(&self, ev: &Event, skip: Option<Uid>) {
        self.broadcast_where(ev, skip, |_| true);
    }
}

/// The domain core. One per server; shared across sessions.
#[derive(Default)]
pub struct Core {
    pub(crate) roster: Mutex<RosterInner>,
}

impl Core {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new session and allocate its uid. The session is not yet
    /// visible (no join broadcast) — that's [`Core::announce`], after the
    /// login flow decides the final name/icon. The returned receiver is the
    /// session's event feed; events start arriving immediately, which is
    /// fine — a client merges user-change events it receives before its
    /// user-list fetch.
    ///
    /// Returns `None` only if all 65535 uids are in use.
    pub fn attach(&self, info: AttachInfo) -> Option<(Uid, UnboundedReceiver<Event>)> {
        let mut r = self.roster.lock().unwrap();
        let uid = r.next_uid()?;
        let (tx, rx) = mpsc::unbounded_channel();
        r.users.insert(
            uid,
            UserSession {
                info: UserInfo {
                    uid,
                    nick: info.nick,
                    icon: info.icon,
                    color: info.color,
                },
                access: info.access,
                login: info.login,
                addr: info.addr,
                connected_at: Instant::now(),
                visible: false,
                events: tx,
            },
        );
        Some((uid, rx))
    }

    /// Make an attached session visible and broadcast its join to everyone
    /// else. Idempotent.
    pub fn announce(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return;
        };
        if sess.visible {
            return;
        }
        sess.visible = true;
        let ev = Event::Joined(sess.info.clone());
        r.broadcast(&ev, Some(uid));
    }

    /// Update a session's nick and/or icon. Broadcasts a change event (to
    /// everyone, echo included) only if something actually changed and the
    /// session is visible. Returns whether anything changed.
    pub fn update(&self, uid: Uid, nick: Option<Vec<u8>>, icon: Option<u16>) -> bool {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return false;
        };
        let mut changed = false;
        if let Some(n) = nick {
            if sess.info.nick != n {
                sess.info.nick = n;
                changed = true;
            }
        }
        if let Some(i) = icon {
            if sess.info.icon != i {
                sess.info.icon = i;
                changed = true;
            }
        }
        if changed && sess.visible {
            let ev = Event::Changed(sess.info.clone());
            r.broadcast(&ev, None);
        }
        changed
    }

    /// Remove a session: leave every private chat (announcing the parts),
    /// then broadcast the part if it was visible.
    pub fn detach(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        Self::leave_all_chats(&mut r, uid);
        let Some(sess) = r.users.remove(&uid) else {
            return;
        };
        if sess.visible {
            r.broadcast(&Event::Parted(uid), Some(uid));
        }
    }

    /// The visible users, in uid order (stable output for lists and tests).
    pub fn snapshot(&self) -> Vec<UserInfo> {
        let r = self.roster.lock().unwrap();
        let mut v: Vec<_> = r
            .users
            .values()
            .filter(|s| s.visible)
            .map(|s| s.info.clone())
            .collect();
        v.sort_by_key(|u| u.uid);
        v
    }

    /// One attached user's info, announced or not — the login-completion
    /// path reads it *before* the session becomes visible. (Use
    /// [`Core::user_details`] when visibility must gate the answer.)
    pub fn user(&self, uid: Uid) -> Option<UserInfo> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.info.clone())
    }

    /// The fuller view of a *visible* user (the user-info op).
    pub fn user_details(&self, uid: Uid) -> Option<UserDetails> {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .filter(|s| s.visible)
            .map(|s| UserDetails {
                info: s.info.clone(),
                login: s.login.clone(),
                addr: s.addr,
                connected_at: s.connected_at,
            })
    }

    /// The public chat subject.
    pub fn public_subject(&self) -> Vec<u8> {
        self.roster.lock().unwrap().public_subject.clone()
    }
}

/// Convenience for chat delivery: does this session receive public chat?
pub(crate) fn reads_public_chat(sess: &UserSession) -> bool {
    sess.access.has(bit::READ_CHAT)
}

#[cfg(test)]
pub(crate) fn test_attach(
    core: &Core,
    nick: &[u8],
    access: AccessBits,
) -> (Uid, UnboundedReceiver<Event>) {
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: nick.to_vec(),
            icon: 1,
            color: 0,
            access,
            login: String::from_utf8_lossy(nick).into_owned(),
            addr: None,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn drain(rx: &mut UnboundedReceiver<Event>) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn join_is_broadcast_to_others_not_self() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, b"alice", AccessBits::empty());
        let (_b, mut rx_b) = test_attach(&core, b"bob", AccessBits::empty());

        let evs = drain(&mut rx_a);
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == b"bob"));
        assert!(drain(&mut rx_b).is_empty());
    }

    #[test]
    fn change_echoes_to_everyone_and_only_on_diff() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, b"alice", AccessBits::empty());

        assert!(!core.update(a, Some(b"alice".to_vec()), Some(1)));
        assert!(drain(&mut rx_a).is_empty());

        assert!(core.update(a, Some(b"al".to_vec()), None));
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Changed(u) if u.nick == b"al" && u.uid == a));
    }

    #[test]
    fn part_reaches_survivors_and_frees_the_uid_slot() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, b"alice", AccessBits::empty());
        let (b, _rx_b) = test_attach(&core, b"bob", AccessBits::empty());
        drain(&mut rx_a);

        core.detach(b);
        let evs = drain(&mut rx_a);
        assert_eq!(evs, vec![Event::Parted(b)]);
        assert_eq!(core.snapshot().len(), 1);
    }

    #[test]
    fn unannounced_sessions_are_invisible_and_part_silently() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, b"alice", AccessBits::empty());
        let (b, _rx_b) = core
            .attach(AttachInfo {
                nick: b"ghost".to_vec(),
                icon: 2,
                color: 0,
                access: AccessBits::empty(),
                login: "ghost".into(),
                addr: None,
            })
            .unwrap();

        assert_eq!(core.snapshot().len(), 1);
        core.detach(b);
        assert!(drain(&mut rx_a).is_empty());
    }

    #[test]
    fn uids_are_sequential_and_skip_zero_and_live_ids() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, b"a", AccessBits::empty());
        let (b, _rb) = test_attach(&core, b"b", AccessBits::empty());
        assert_eq!((a, b), (1, 2));
        core.detach(a);
        let (c, _rc) = test_attach(&core, b"c", AccessBits::empty());
        // Sequential, not first-free: c gets 3, not the freed 1.
        assert_eq!(c, 3);
    }

    #[test]
    fn user_details_carry_login_and_visibility_gate() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, b"alice", AccessBits::empty());
        let d = core.user_details(a).unwrap();
        assert_eq!(d.login, "alice");
        let (ghost, _rg) = core
            .attach(AttachInfo {
                nick: b"g".to_vec(),
                icon: 0,
                color: 0,
                access: AccessBits::empty(),
                login: "g".into(),
                addr: None,
            })
            .unwrap();
        assert!(core.user_details(ghost).is_none());
    }
}
