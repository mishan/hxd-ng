//! The presence roster: who is on the server, and the event fan-out.
//!
//! **Presence is user-scoped, not connection-scoped** (a roadmap
//! commitment). A [`UserSession`] is a user's presence on the server; a
//! transport attaches to it. The legacy frontend keeps the degenerate
//! mapping — its connection's death calls [`Core::end_session`] — while the
//! Hotline-ng frontend calls [`Core::connection_lost`], which (permission
//! and caps allowing) parks the session `Detached` and buffers its events
//! for a later [`Core::resume`].
//!
//! **The outbox.** Every event a session should see is stamped with a
//! per-session monotonic sequence number. With a connection attached the
//! event goes straight out on a channel; detached, it buffers (bounded —
//! overflow marks the buffer broken and a resume then requires a fresh
//! sync). See `docs/hotline-ng.md` §4/§6.
//!
//! **The domain is UTF-8.** Nicks, chat text, subjects — everything textual
//! is a `String`. The legacy frontend converts Mac Roman ↔ UTF-8 at its
//! edges (lossless for legacy-origin text: Mac Roman → UTF-8 is injective
//! and round-trips exactly); the ng frontend is UTF-8 natively. The domain
//! also carries no wire presentation: `admin` is a bool and status an enum —
//! the legacy color bitfield (bit 1 away, bit 2 admin) is derived at the
//! legacy edge.
//!
//! Chat rooms, messaging and moderation live in [`crate::chat`], as further
//! `impl Core` blocks over the same state.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::access::{bit, AccessBits};
use crate::chat::{Ban, PrivateChat};

/// A user id, as seen on the wire (16-bit, never 0 for a real user).
pub type Uid = u16;

/// How many events a detached session's outbox holds before it gives up
/// and demands a resync.
pub const OUTBOX_BUFFER_CAP: usize = 512;

/// A session's presence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionStatus {
    /// A connection is attached.
    #[default]
    Active,
    /// Attached but quiet / away.
    Idle,
    /// No connection attached; grace window running.
    Detached,
}

/// The visible-to-others part of a session: what a user-list row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub uid: Uid,
    /// Nickname, UTF-8.
    pub nick: String,
    pub icon: u16,
    /// Administrator affordance (the legacy edge renders it as color
    /// bit 2).
    pub admin: bool,
    pub status: SessionStatus,
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
    /// A visible session changed nick/icon/status. Delivered to everyone,
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
        text: String,
        style: u16,
    },
    /// A server notice into a chat (kick announcements and the like).
    /// Semantic text; each frontend formats it (legacy: `\r<text>`).
    Notice { cid: u32, from: Uid, text: String },
    /// A chat (or, for cid 0, server) subject change.
    ChatSubject { cid: u32, subject: String },
    /// A private chat's password change, announced to its members
    /// (reference-server behavior).
    ChatPassword { cid: u32, password: String },
    /// An invitation to a private chat.
    ChatInvite {
        cid: u32,
        from: Uid,
        from_nick: String,
    },
    /// Someone joined a private chat the recipient is in.
    ChatUserJoined { cid: u32, user: UserInfo },
    /// Someone left a private chat the recipient is in.
    ChatUserParted { cid: u32, uid: Uid },
    /// A private message to the recipient.
    Msg {
        from: Uid,
        from_nick: String,
        text: String,
    },
    /// An administrator broadcast. Delivered to everyone, sender included
    /// (the wire push carries the sender, matching the reference server).
    Broadcast {
        from: Uid,
        from_nick: String,
        text: String,
    },
    /// The recipient has been kicked; its transport should close.
    Kicked,

    // --- Voice (see [`crate::voice`]) ---------------------------------
    /// An SDP offer for the recipient's own peer connection: the initial
    /// one answering a join, or a renegotiation. Opaque to the domain —
    /// both frontends carry the string verbatim.
    VoiceOffer { cid: u32, sdp: String },
    /// A server ICE candidate, or (empty candidate) end-of-candidates.
    VoiceIce {
        cid: u32,
        candidate: crate::voice::IceCandidate,
    },
    /// The voice room's participant list changed — someone joined, left,
    /// or changed mute state.
    VoiceStatus {
        cid: u32,
        participants: Vec<crate::voice::VoiceParticipant>,
    },

    // --- Video (see [`crate::video`]) ---------------------------------
    /// The room's video publications changed — a start, a stop, a pause,
    /// a resume, or a publisher leaving. **Always the complete list**,
    /// never a delta: a client replaces its whole view of the room's
    /// video state on each one, which is what makes the notification
    /// idempotent and a missed one self-healing.
    ///
    /// Delivered to every participant in the room, video-capable or not.
    /// A voice-only participant is entitled to know a camera is on in
    /// the room it is sitting in; whether its wire can say so is the
    /// frontend's business, not the domain's.
    VideoStatus {
        cid: u32,
        publications: Vec<crate::video::VideoPublication>,
    },
}

/// An event stamped with its position in the session's stream. `seq` is
/// per-session, monotonic from 1, gapless — the resume protocol's
/// substrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqEvent {
    pub seq: u64,
    pub event: Event,
}

/// Where a session's events currently go.
enum Sink {
    /// A connection is attached; events flow on the channel.
    Live(UnboundedSender<SeqEvent>),
    /// Detached: events buffer for replay.
    Buffering {
        /// When the connection was lost (grace accounting).
        since: Instant,
        /// The seq of the first event that went unbuffered-and-undelivered
        /// — i.e. `next_seq` at detach time. A resume with `last_seq + 1 <
        /// start_seq` predates the buffer and cannot be replayed.
        start_seq: u64,
        buf: VecDeque<SeqEvent>,
        /// The buffer overflowed; replay is impossible, a fresh sync is
        /// needed. The buffer is dropped when this trips.
        broken: bool,
    },
}

/// The seq-stamped per-session event stream.
pub(crate) struct Outbox {
    next_seq: u64,
    sink: Sink,
}

impl Outbox {
    fn live(tx: UnboundedSender<SeqEvent>) -> Self {
        Outbox {
            next_seq: 1,
            sink: Sink::Live(tx),
        }
    }

    fn push(&mut self, event: Event) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let se = SeqEvent { seq, event };
        match &mut self.sink {
            Sink::Live(tx) => {
                let _ = tx.send(se);
            }
            Sink::Buffering { buf, broken, .. } => {
                if *broken {
                    return;
                }
                if buf.len() >= OUTBOX_BUFFER_CAP {
                    *broken = true;
                    buf.clear(); // Nothing partial is replayable; free it.
                    return;
                }
                buf.push_back(se);
            }
        }
    }
}

/// One user's presence and its outbox.
pub(crate) struct UserSession {
    /// Distinguishes this session from any other that ever held the same
    /// uid (uids recycle after 65k sessions; serials never). External
    /// registries key trust decisions on (uid, serial).
    pub(crate) serial: u64,
    pub(crate) info: UserInfo,
    pub(crate) access: AccessBits,
    pub(crate) login: String,
    pub(crate) addr: Option<IpAddr>,
    pub(crate) connected_at: Instant,
    /// Account policy: may this session survive its connection? (The
    /// `[extra] can_detach` flag; guests default to no.)
    pub(crate) can_detach: bool,
    /// Whether this session has been announced (shows on the user list,
    /// generates events). False between login and login-completion.
    pub(crate) visible: bool,
    pub(crate) outbox: Outbox,
}

/// What a transport hands the roster at login.
#[derive(Debug, Clone)]
pub struct AttachInfo {
    pub nick: String,
    pub icon: u16,
    pub admin: bool,
    pub access: AccessBits,
    pub login: String,
    pub addr: Option<IpAddr>,
    pub can_detach: bool,
}

/// The outcome of a [`Core::resume`].
pub enum Resume {
    /// The buffer covered the gap: replay these, then live events follow
    /// on the channel.
    Replayed(UnboundedReceiver<SeqEvent>, Vec<SeqEvent>),
    /// The session is alive and the channel is attached, but the gap can't
    /// be replayed (overflow, or `last_seq` predates the buffer). The
    /// client must do a fresh sync; events flow from the session's current
    /// seq onward.
    ResyncRequired(UnboundedReceiver<SeqEvent>),
    /// No such session (grace lapsed, ended, or never existed).
    Gone,
}

#[derive(Default)]
pub(crate) struct RosterInner {
    pub(crate) users: HashMap<Uid, UserSession>,
    last_uid: Uid,
    last_serial: u64,
    pub(crate) public_subject: String,
    pub(crate) chats: HashMap<u32, PrivateChat>,
    pub(crate) bans: Vec<Ban>,
    pub(crate) voice: crate::voice::VoiceState,
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

    /// Allocate a private chat's id: nonzero, unused, and from the OS
    /// CSPRNG. `None` if the CSPRNG refuses (or, absurdly, if the id
    /// space is so full that a hundred draws all collide).
    ///
    /// **Random rather than sequential, and unconditionally.** A chat id
    /// is opaque to every client — nothing on either wire derives meaning
    /// from its value — but it is also the whole address of a voice room
    /// (fogWraith Capabilities-Voice.md, "Room Membership"), which a
    /// voice-capable client can name directly. Sequential ids are
    /// guessable, so they would let such a client name a private chat's
    /// voice room it was never invited to. Membership checks are the real
    /// defence and live where the joins are; this is the cheap layer
    /// underneath, and doing it always is one less mode than doing it
    /// only when voice is enabled.
    pub(crate) fn next_chat_id(&mut self) -> Option<u32> {
        for _ in 0..100 {
            let mut raw = [0u8; 4];
            getrandom::getrandom(&mut raw).ok()?;
            let cid = u32::from_be_bytes(raw);
            // 0 is the public chat and never appears in the registry.
            if cid != 0 && !self.chats.contains_key(&cid) {
                return Some(cid);
            }
        }
        None
    }

    pub(crate) fn send_to(&mut self, uid: Uid, ev: Event) {
        if let Some(sess) = self.users.get_mut(&uid) {
            sess.outbox.push(ev);
        }
    }

    /// Deliver to every *visible* session matching `pred` (skipping `skip`).
    pub(crate) fn broadcast_where<F: Fn(&UserSession) -> bool>(
        &mut self,
        ev: &Event,
        skip: Option<Uid>,
        pred: F,
    ) {
        for (uid, sess) in self.users.iter_mut() {
            if Some(*uid) == skip || !sess.visible || !pred(sess) {
                continue;
            }
            sess.outbox.push(ev.clone());
        }
    }

    fn broadcast(&mut self, ev: &Event, skip: Option<Uid>) {
        self.broadcast_where(ev, skip, |_| true);
    }

    /// Full teardown: leave voice and chats, remove, announce the part.
    pub(crate) fn end_session(&mut self, uid: Uid) {
        // Voice first, while the session is still on the roster: the
        // room it leaves has to be renegotiated and re-announced, and
        // that has nothing to do with the chat rooms below.
        self.voice_part(uid);
        crate::Core::leave_all_chats(self, uid);
        let Some(sess) = self.users.remove(&uid) else {
            return;
        };
        if sess.visible {
            self.broadcast(&Event::Parted(uid), Some(uid));
        }
    }

    /// Flip status and tell the roster (a status change is a user change).
    fn set_status(&mut self, uid: Uid, status: SessionStatus) {
        let Some(sess) = self.users.get_mut(&uid) else {
            return;
        };
        if sess.info.status == status {
            return;
        }
        sess.info.status = status;
        if sess.visible {
            let ev = Event::Changed(sess.info.clone());
            self.broadcast(&ev, None);
        }
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
    pub fn attach(&self, info: AttachInfo) -> Option<(Uid, UnboundedReceiver<SeqEvent>)> {
        let mut r = self.roster.lock().unwrap();
        let uid = r.next_uid()?;
        r.last_serial += 1;
        let serial = r.last_serial;
        let (tx, rx) = mpsc::unbounded_channel();
        r.users.insert(
            uid,
            UserSession {
                serial,
                info: UserInfo {
                    uid,
                    nick: info.nick,
                    icon: info.icon,
                    admin: info.admin,
                    status: SessionStatus::Active,
                },
                access: info.access,
                login: info.login,
                addr: info.addr,
                connected_at: Instant::now(),
                can_detach: info.can_detach,
                visible: false,
                outbox: Outbox::live(tx),
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
    pub fn update(&self, uid: Uid, nick: Option<String>, icon: Option<u16>) -> bool {
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

    /// End a session outright: leave every private chat (announcing the
    /// parts), remove from the roster, broadcast the part. The legacy
    /// frontend calls this when its socket dies; `logout` and moderation
    /// use it too.
    pub fn end_session(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        r.end_session(uid);
    }

    /// The attached transport died. If the account may detach (and the
    /// per-address cap allows), the session parks `Detached`, buffering
    /// events for a resume, and everyone sees the status change; otherwise
    /// the session ends as if [`Core::end_session`] were called.
    ///
    /// Returns `true` when the session survives detached.
    pub fn connection_lost(&self, uid: Uid, max_detached_per_addr: usize) -> bool {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return false;
        };
        if !sess.can_detach {
            r.end_session(uid);
            return false;
        }
        // Buffer first, *then* leave voice. A detached session's media
        // path is dead or about to be — the UDP flow went with the
        // control connection, and a client that resumes re-joins voice
        // explicitly — so the departure has to happen here. But the
        // status announcing it is the one event of this whole teardown
        // the resuming client must see: without it (docs/voice.md §8)
        // the client comes back to a voice UI that is live with nothing
        // behind it. Sent while the sink is still `Live` it would go to
        // the socket that just died. So the order is load-bearing, and
        // it is also what makes the buffer's voice content exactly the
        // tail of this departure and nothing else.
        sess.outbox.sink = Sink::Buffering {
            since: Instant::now(),
            start_seq: sess.outbox.next_seq,
            buf: VecDeque::new(),
            broken: false,
        };
        let addr = sess.addr;
        r.voice_part(uid);
        if !r.users.contains_key(&uid) {
            return false;
        }
        r.set_status(uid, SessionStatus::Detached);

        // Per-address backstop: a spammer with detach permission still
        // can't park an unbounded crowd. Oldest detached at this address
        // goes first (docs/hotline-ng.md §2).
        if let Some(addr) = addr {
            loop {
                let mut detached: Vec<(Uid, Instant)> = r
                    .users
                    .iter()
                    .filter(|(_, s)| s.addr == Some(addr))
                    .filter_map(|(u, s)| match s.outbox.sink {
                        Sink::Buffering { since, .. } => Some((*u, since)),
                        Sink::Live(_) => None,
                    })
                    .collect();
                if detached.len() <= max_detached_per_addr {
                    break;
                }
                detached.sort_by_key(|(_, since)| *since);
                let (oldest, _) = detached[0];
                r.end_session(oldest);
            }
        }
        true
    }

    /// Re-attach a connection to a detached (or live — takeover) session.
    pub fn resume(&self, uid: Uid, last_seq: u64) -> Resume {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return Resume::Gone;
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let old = std::mem::replace(&mut sess.outbox.sink, Sink::Live(tx));
        let next_seq = sess.outbox.next_seq;
        let outcome = match old {
            Sink::Buffering {
                start_seq,
                buf,
                broken,
                ..
            } => {
                if broken || last_seq + 1 < start_seq || last_seq + 1 > next_seq {
                    Resume::ResyncRequired(rx)
                } else {
                    let replay: Vec<SeqEvent> =
                        buf.into_iter().filter(|se| se.seq > last_seq).collect();
                    Resume::Replayed(rx, replay)
                }
            }
            // Takeover of a live session: the old channel's sender is gone,
            // so the old connection sees a closed event stream and shuts
            // down ("last device wins"). Events already sent to the old
            // channel can't be replayed.
            Sink::Live(_) => {
                if last_seq + 1 == next_seq {
                    Resume::Replayed(rx, Vec::new())
                } else {
                    Resume::ResyncRequired(rx)
                }
            }
        };
        r.set_status(uid, SessionStatus::Active);
        outcome
    }

    /// End every detached session whose grace has lapsed. The binary runs
    /// this on an interval. Returns how many ended.
    pub fn sweep_detached(&self, grace: Duration) -> usize {
        let mut r = self.roster.lock().unwrap();
        let now = Instant::now();
        let lapsed: Vec<Uid> = r
            .users
            .iter()
            .filter_map(|(u, s)| match s.outbox.sink {
                Sink::Buffering { since, .. } if now.duration_since(since) >= grace => Some(*u),
                _ => None,
            })
            .collect();
        let n = lapsed.len();
        for uid in lapsed {
            r.end_session(uid);
        }
        n
    }

    /// Is this session currently detached? (Moderation and tests.)
    pub fn is_detached(&self, uid: Uid) -> bool {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .is_some_and(|s| matches!(s.outbox.sink, Sink::Buffering { .. }))
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

    /// The session's serial — the anti-uid-recycling token for external
    /// registries. `None` when no session holds the uid.
    pub fn session_serial(&self, uid: Uid) -> Option<u64> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.serial)
    }

    /// The last event seq this session has emitted (0 if none yet) — what
    /// a fresh sync reports so the client can resume from there.
    pub fn current_seq(&self, uid: Uid) -> Option<u64> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.outbox.next_seq - 1)
    }

    /// The public chat subject.
    pub fn public_subject(&self) -> String {
        self.roster.lock().unwrap().public_subject.clone()
    }
}

/// Convenience for chat delivery: does this session receive public chat?
pub(crate) fn reads_public_chat(sess: &UserSession) -> bool {
    sess.access.has(bit::READ_CHAT)
}

/// Is this session's outbox buffering (i.e. detached)? For moderation
/// paths inside the lock.
pub(crate) fn is_buffering(sess: &UserSession) -> bool {
    matches!(sess.outbox.sink, Sink::Buffering { .. })
}

#[cfg(test)]
pub(crate) fn test_attach(
    core: &Core,
    nick: &str,
    access: AccessBits,
) -> (Uid, UnboundedReceiver<SeqEvent>) {
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: nick.to_string(),
            icon: 1,
            admin: false,
            access,
            login: nick.to_string(),
            addr: None,
            can_detach: false,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

#[cfg(test)]
pub(crate) fn drain(rx: &mut UnboundedReceiver<SeqEvent>) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(se) = rx.try_recv() {
        out.push(se.event);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ng_attach(core: &Core, nick: &str, addr: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
        let (uid, rx) = core
            .attach(AttachInfo {
                nick: nick.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_CHAT),
                login: nick.to_string(),
                addr: Some(addr.parse().unwrap()),
                can_detach: true,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    #[test]
    fn join_is_broadcast_to_others_not_self() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (_b, mut rx_b) = test_attach(&core, "bob", AccessBits::empty());

        let evs = drain(&mut rx_a);
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == "bob"));
        assert!(drain(&mut rx_b).is_empty());
    }

    #[test]
    fn seq_numbers_are_monotonic_and_gapless_from_one() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        for _ in 0..3 {
            let (b, _rb) = test_attach(&core, "x", AccessBits::empty());
            core.end_session(b);
        }
        let seqs: Vec<u64> = std::iter::from_fn(|| rx_a.try_recv().ok())
            .map(|se| se.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn change_echoes_to_everyone_and_only_on_diff() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());

        assert!(!core.update(a, Some("alice".into()), Some(1)));
        assert!(drain(&mut rx_a).is_empty());

        assert!(core.update(a, Some("al".into()), None));
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Changed(u) if u.nick == "al" && u.uid == a));
    }

    #[test]
    fn part_reaches_survivors_and_frees_the_uid_slot() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (b, _rx_b) = test_attach(&core, "bob", AccessBits::empty());
        drain(&mut rx_a);

        core.end_session(b);
        let evs = drain(&mut rx_a);
        assert_eq!(evs, vec![Event::Parted(b)]);
        assert_eq!(core.snapshot().len(), 1);
    }

    #[test]
    fn unannounced_sessions_are_invisible_and_part_silently() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (b, _rx_b) = core
            .attach(AttachInfo {
                nick: "ghost".into(),
                icon: 2,
                admin: false,
                access: AccessBits::empty(),
                login: "ghost".into(),
                addr: None,
                can_detach: false,
            })
            .unwrap();

        assert_eq!(core.snapshot().len(), 1);
        core.end_session(b);
        assert!(drain(&mut rx_a).is_empty());
    }

    #[test]
    fn uids_are_sequential_and_skip_zero_and_live_ids() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, "a", AccessBits::empty());
        let (b, _rb) = test_attach(&core, "b", AccessBits::empty());
        assert_eq!((a, b), (1, 2));
        core.end_session(a);
        let (c, _rc) = test_attach(&core, "c", AccessBits::empty());
        // Sequential, not first-free: c gets 3, not the freed 1.
        assert_eq!(c, 3);
    }

    #[test]
    fn user_details_carry_login_and_visibility_gate() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, "alice", AccessBits::empty());
        let d = core.user_details(a).unwrap();
        assert_eq!(d.login, "alice");
        assert_eq!(d.info.status, SessionStatus::Active);
    }

    #[test]
    fn non_ascii_nicks_are_preserved_verbatim() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (_b, _rx_b) = test_attach(&core, "Мишенька 🎈", AccessBits::empty());
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == "Мишенька 🎈"));
    }

    // --- Detach / resume ------------------------------------------------

    #[test]
    fn detach_buffers_and_resume_replays_the_gap() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (b, mut rx_b) = ng_attach(&core, "buddy", "10.0.0.2");
        // Read what a has seen so far (buddy's join) to learn its last_seq
        // — the client-side bookkeeping the resume protocol relies on.
        let seen: Vec<SeqEvent> = std::iter::from_fn(|| rx_a.try_recv().ok()).collect();
        let last_seq = seen.last().map_or(0, |se| se.seq);
        assert_eq!(last_seq, 1);

        assert!(core.connection_lost(a, 8));
        assert!(core.is_detached(a));
        // Others see the status flip to detached.
        assert!(matches!(
            drain(&mut rx_b).as_slice(),
            [Event::Changed(u)] if u.uid == a && u.status == SessionStatus::Detached
        ));

        // Traffic while detached buffers.
        core.chat_public(b, "you there?".into(), 0);
        core.chat_public(b, "hello?".into(), 0);

        let Resume::Replayed(mut rx_a2, replay) = core.resume(a, last_seq) else {
            panic!("resume should replay");
        };
        // The replay: the status-change echo + both chat lines, gapless.
        let texts: Vec<String> = replay
            .iter()
            .filter_map(|se| match &se.event {
                Event::Chat { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["you there?", "hello?"]);
        let seqs: Vec<u64> = replay.iter().map(|se| se.seq).collect();
        assert_eq!(
            seqs,
            (last_seq + 1..=last_seq + replay.len() as u64).collect::<Vec<_>>()
        );

        // Live again: buddy sees Active (after its own two chat echoes),
        // and new traffic flows on the channel.
        let evs = drain(&mut rx_b);
        assert!(matches!(
            evs.last(),
            Some(Event::Changed(u)) if u.status == SessionStatus::Active
        ));
        core.chat_public(b, "welcome back".into(), 0);
        assert!(drain(&mut rx_a2)
            .iter()
            .any(|e| matches!(e, Event::Chat { text, .. } if text == "welcome back")));
    }

    #[test]
    fn no_permission_means_connection_loss_ends_the_session() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (g, _rx_g) = test_attach(&core, "guest", AccessBits::empty());
        drain(&mut rx_a);

        assert!(!core.connection_lost(g, 8)); // can_detach = false
        assert_eq!(drain(&mut rx_a), vec![Event::Parted(g)]);
        assert!(matches!(core.resume(g, 0), Resume::Gone));
    }

    #[test]
    fn overflow_breaks_the_buffer_and_forces_resync() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (b, _rx_b) = ng_attach(&core, "chatty", "10.0.0.2");
        let last_seq = std::iter::from_fn(|| rx_a.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(a, 8));

        for i in 0..(OUTBOX_BUFFER_CAP + 10) {
            core.chat_public(b, format!("spam {i}"), 0);
        }
        match core.resume(a, last_seq) {
            Resume::ResyncRequired(_rx) => {}
            _ => panic!("overflowed buffer must demand resync"),
        }
    }

    #[test]
    fn stale_last_seq_predating_the_buffer_forces_resync() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (_b, _rx_b) = ng_attach(&core, "buddy", "10.0.0.2");
        // a has seen events but claims last_seq 0 — those live deliveries
        // predate the buffer and cannot be replayed.
        assert!(rx_a.try_recv().is_ok());
        assert!(core.connection_lost(a, 8));
        match core.resume(a, 0) {
            Resume::ResyncRequired(_rx) => {}
            _ => panic!("pre-buffer last_seq must demand resync"),
        }
    }

    #[test]
    fn per_address_cap_ends_the_oldest_detached() {
        let core = Core::new();
        let (a1, _r1) = ng_attach(&core, "one", "10.0.0.9");
        let (a2, _r2) = ng_attach(&core, "two", "10.0.0.9");
        let (a3, _r3) = ng_attach(&core, "three", "10.0.0.9");

        assert!(core.connection_lost(a1, 2));
        assert!(core.connection_lost(a2, 2));
        // Third detach at the same address exceeds the cap of 2 → the
        // oldest (a1) is ended.
        assert!(core.connection_lost(a3, 2));
        assert!(matches!(core.resume(a1, 0), Resume::Gone));
        assert!(core.is_detached(a2));
        assert!(core.is_detached(a3));
    }

    #[test]
    fn sweep_ends_lapsed_sessions() {
        let core = Core::new();
        let (a, _ra) = ng_attach(&core, "app", "10.0.0.1");
        assert!(core.connection_lost(a, 8));
        assert_eq!(core.sweep_detached(Duration::from_secs(3600)), 0);
        assert_eq!(core.sweep_detached(Duration::ZERO), 1);
        assert!(matches!(core.resume(a, 0), Resume::Gone));
        assert!(core.snapshot().is_empty());
    }

    #[test]
    fn takeover_replaces_the_live_channel() {
        let core = Core::new();
        let (a, mut rx_old) = ng_attach(&core, "app", "10.0.0.1");
        let (b, _rb) = ng_attach(&core, "buddy", "10.0.0.2");
        let last_seq = std::iter::from_fn(|| rx_old.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);

        let Resume::Replayed(mut rx_new, replay) = core.resume(a, last_seq) else {
            panic!("up-to-date takeover should attach cleanly");
        };
        assert!(replay.is_empty());
        // The old channel is dead; the new one gets traffic.
        core.chat_public(b, "hi".into(), 0);
        assert!(rx_old.try_recv().is_err());
        assert_eq!(drain(&mut rx_new).len(), 1);
    }
}
