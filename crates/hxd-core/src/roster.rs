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

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::access::AccessBits;

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

/// A presence event, delivered to every attached session's channel.
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
}

/// One user's presence. Today: exactly one attached connection, whose
/// death detaches the session. (See the module comment for where this
/// grows.)
struct UserSession {
    info: UserInfo,
    /// Access bits, kept here so later phases can enforce per-operation
    /// permissions without a second lookup.
    #[allow(dead_code)]
    access: AccessBits,
    /// Whether this session has been announced (shows on the user list,
    /// generates events). False between login and login-completion.
    visible: bool,
    events: UnboundedSender<Event>,
}

#[derive(Default)]
struct RosterInner {
    users: HashMap<Uid, UserSession>,
    last_uid: Uid,
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

    fn broadcast(&self, ev: &Event, skip: Option<Uid>) {
        for (uid, sess) in &self.users {
            if Some(*uid) == skip {
                continue;
            }
            // A closed receiver just means that session is tearing down;
            // its detach will clean up.
            let _ = sess.events.send(ev.clone());
        }
    }
}

/// The domain core. One per server; shared across sessions.
#[derive(Default)]
pub struct Core {
    roster: Mutex<RosterInner>,
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
    pub fn attach(
        &self,
        nick: Vec<u8>,
        icon: u16,
        color: u16,
        access: AccessBits,
    ) -> Option<(Uid, UnboundedReceiver<Event>)> {
        let mut r = self.roster.lock().unwrap();
        let uid = r.next_uid()?;
        let (tx, rx) = mpsc::unbounded_channel();
        r.users.insert(
            uid,
            UserSession {
                info: UserInfo {
                    uid,
                    nick,
                    icon,
                    color,
                },
                access,
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

    /// Remove a session. Broadcasts the part if it was visible.
    pub fn detach(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
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

    /// One visible user's info.
    pub fn user(&self, uid: Uid) -> Option<UserInfo> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.info.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(rx: &mut UnboundedReceiver<Event>) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn join_is_broadcast_to_others_not_self() {
        let core = Core::new();
        let (a, mut rx_a) = core
            .attach(b"alice".to_vec(), 1, 0, AccessBits::empty())
            .unwrap();
        core.announce(a);
        let (b, mut rx_b) = core
            .attach(b"bob".to_vec(), 2, 0, AccessBits::empty())
            .unwrap();
        core.announce(b);

        let evs = drain(&mut rx_a);
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == b"bob"));
        assert!(drain(&mut rx_b).is_empty());
    }

    #[test]
    fn change_echoes_to_everyone_and_only_on_diff() {
        let core = Core::new();
        let (a, mut rx_a) = core
            .attach(b"alice".to_vec(), 1, 0, AccessBits::empty())
            .unwrap();
        core.announce(a);

        assert!(!core.update(a, Some(b"alice".to_vec()), Some(1)));
        assert!(drain(&mut rx_a).is_empty());

        assert!(core.update(a, Some(b"al".to_vec()), None));
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Changed(u) if u.nick == b"al" && u.uid == a));
    }

    #[test]
    fn part_reaches_survivors_and_frees_the_uid_slot() {
        let core = Core::new();
        let (a, mut rx_a) = core
            .attach(b"alice".to_vec(), 1, 0, AccessBits::empty())
            .unwrap();
        core.announce(a);
        let (b, _rx_b) = core
            .attach(b"bob".to_vec(), 2, 0, AccessBits::empty())
            .unwrap();
        core.announce(b);
        drain(&mut rx_a);

        core.detach(b);
        let evs = drain(&mut rx_a);
        assert_eq!(evs, vec![Event::Parted(b)]);
        assert_eq!(core.snapshot().len(), 1);
    }

    #[test]
    fn unannounced_sessions_are_invisible_and_part_silently() {
        let core = Core::new();
        let (a, mut rx_a) = core
            .attach(b"alice".to_vec(), 1, 0, AccessBits::empty())
            .unwrap();
        core.announce(a);
        let (b, _rx_b) = core
            .attach(b"ghost".to_vec(), 2, 0, AccessBits::empty())
            .unwrap();

        assert_eq!(core.snapshot().len(), 1);
        core.detach(b);
        assert!(drain(&mut rx_a).is_empty());
    }

    #[test]
    fn uids_are_sequential_and_skip_zero_and_live_ids() {
        let core = Core::new();
        let (a, _ra) = core
            .attach(b"a".to_vec(), 0, 0, AccessBits::empty())
            .unwrap();
        let (b, _rb) = core
            .attach(b"b".to_vec(), 0, 0, AccessBits::empty())
            .unwrap();
        assert_eq!((a, b), (1, 2));
        core.detach(a);
        let (c, _rc) = core
            .attach(b"c".to_vec(), 0, 0, AccessBits::empty())
            .unwrap();
        // Sequential, not first-free: c gets 3, not the freed 1.
        assert_eq!(c, 3);
    }
}
