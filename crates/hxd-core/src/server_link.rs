//! Users of linked servers, and this server's users as a link sees them
//! (`docs/server-link.md` §3, §4).
//!
//! A *ghost* is another server's user shown here. Ghosts live in a map of
//! their own beside the sessions, never among them, so every lookup that
//! acts on a session finds nothing for a ghost's uid and fails as it would
//! for a user who has left: a feature added later is safe by default. Only
//! user lists (`roster_rows`) and the acts a link translates look at
//! ghosts.
//!
//! The other direction is the export feed: every change to a local user a
//! link would pass on, numbered in the order the roster made it, so a link
//! that takes a snapshot can skip what the snapshot already holds.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, oneshot};

use crate::roster::{Event, RosterInner, SessionStatus, Uid, UserInfo, UserSession};
use crate::Core;

/// Where a ghost is from, for the frontends that show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    pub home_tag: String,
    pub home_name: String,
    /// Show the home server's tag in the ghost's name (`[link]
    /// show_tags`).
    pub tagged: bool,
    /// The ghost refuses private messages: its own flag, or because its
    /// path cannot carry them.
    pub refuses_msgs: bool,
}

/// A ghost as a link describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostInfo {
    /// Its own name, never a display name.
    pub nick: String,
    pub icon: u16,
    pub away: bool,
    /// Its home server's color, which a ghost always shows.
    pub color: u32,
    pub remote: RemoteRef,
    /// False for a ghost excluded here: kept, so it can be relayed, never
    /// shown.
    pub visible: bool,
}

pub(crate) struct Ghost {
    pub(crate) info: UserInfo,
    pub(crate) visible: bool,
    /// Held to local users' chat limit, for what is shown here only.
    flood: crate::limits::Flood,
}

/// A ghost's chat line, staged when it arrives so that the ghost leaving
/// before it is logged does not lose it ([`Core::ghost_chat`]).
pub struct GhostLine(pub(crate) crate::chat::Staged);

/// Why an act on a ghost, or a ghost's act here, was refused: the
/// extension's reply reasons, and what this server refuses before
/// anything crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRefusal {
    UnknownUser,
    RefusesMessages,
    Excluded,
    RateLimited,
    FeatureNotNegotiated,
    Unreachable,
    /// The ghost's server refused it, for a reason this server has no
    /// better word for.
    Refused,
    /// Refused here: the sender has no ghost over that link to send as.
    NotExported,
    /// Refused here: what a link cannot carry, an image or a text over
    /// [`MAX_LINK_TEXT`].
    CannotCross,
}

/// How long an act on a ghost waits for its answer before the client is
/// told the ghost's server did not answer (the extension's per-hop wait).
pub const PEER_WAIT: Duration = Duration::from_secs(10);

impl PeerRefusal {
    /// What a client is told, on either wire.
    pub fn text(self) -> &'static str {
        match self {
            PeerRefusal::UnknownUser => "That user is not connected.",
            PeerRefusal::RefusesMessages => "That user does not accept private messages.",
            PeerRefusal::Excluded => "That user cannot be reached from here.",
            PeerRefusal::RateLimited => {
                "Too much at once for that user's server; try again shortly."
            }
            PeerRefusal::FeatureNotNegotiated => {
                "That user's server does not take this from this one."
            }
            PeerRefusal::Unreachable => "That user's server did not answer.",
            PeerRefusal::Refused => "That user's server refused it.",
            PeerRefusal::NotExported => {
                "Users on other servers cannot see you, so you cannot message them."
            }
            PeerRefusal::CannotCross => "That cannot be sent to a user on another server.",
        }
    }
}

/// The acts that cross a link to a ghost's home server, answered when the
/// answer comes: the frontends await it on a task of their own, never in
/// their session loops.
pub trait PeerRouter: Send + Sync {
    fn msg(&self, from: Uid, to: Uid, text: String) -> oneshot::Receiver<Result<(), PeerRefusal>>;
    fn user_info(&self, of: Uid) -> oneshot::Receiver<Result<String, PeerRefusal>>;
}

/// An answer already known.
fn answered<T>(result: Result<T, PeerRefusal>) -> oneshot::Receiver<Result<T, PeerRefusal>> {
    let (tx, rx) = oneshot::channel();
    let _ = tx.send(result);
    rx
}

/// A user info request for a ghost, on its way.
pub struct PeerInfo {
    pub nick: String,
    /// The home server's name, which the reply names whatever comes back.
    pub home: String,
    pub answer: oneshot::Receiver<Result<String, PeerRefusal>>,
}

/// The most a chat line or private message may carry over a link, in
/// bytes of UTF-8 (the extension's Text on a Link).
pub const MAX_LINK_TEXT: usize = 8192;

/// Cut a local line to what a link can carry, at a character boundary,
/// before it is shown anywhere, so every copy of it is the same. Only a
/// classic client's line can be this long once converted: Mac Roman, or
/// UTF-8 whose invalid bytes became replacement characters.
pub(crate) fn cut_to_link_bound(text: &mut String) {
    if text.len() > MAX_LINK_TEXT {
        let mut end = MAX_LINK_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

/// A local user as it may cross a link: nothing else about a session does.
/// No login, address or access bits, so no later change can leak them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUser {
    pub uid: Uid,
    pub nick: String,
    pub icon: u16,
    pub away: bool,
    pub color: Option<u32>,
}

impl LocalUser {
    fn of(sess: &UserSession) -> LocalUser {
        LocalUser {
            uid: sess.info.uid,
            nick: sess.info.nick.clone(),
            icon: sess.info.icon,
            away: sess.info.status != SessionStatus::Active,
            color: sess.info.color,
        }
    }
}

/// Why a local user stopped being exported (Link User Gone's reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneReason {
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Shown(LocalUser),
    Changed(LocalUser),
    Gone(Uid, GoneReason),
    /// A public chat line, with text: `line` counts the lines this server
    /// has originated since it started, for the line's network-wide ID.
    Chat {
        from: Uid,
        /// Shared, as each link's channel holds a copy of the event.
        text: std::sync::Arc<str>,
        style: u16,
        line: u32,
    },
}

/// The export feed's end in the roster.
#[derive(Default)]
pub(crate) struct Feed {
    tx: Option<mpsc::Sender<(u64, PeerEvent)>>,
    seq: u64,
    lines: u32,
    /// A feed was ever installed, so a link is configured: kept while a
    /// feed that fell behind is replaced.
    linked: bool,
}

/// Whether a session is one a link may show elsewhere: announced, and not
/// the server's own account, which a private message turns into commands
/// that no other server's user has any business sending.
fn exported(sess: &UserSession) -> bool {
    sess.visible && !sess.system
}

impl RosterInner {
    /// Tell the feed about a local user, under the roster lock, so the
    /// feed's order is the roster's. A feed that cannot keep up is closed:
    /// the hub sees the end of it and starts its links over.
    fn export(&mut self, event: PeerEvent) {
        let Some(tx) = &self.feed.tx else { return };
        self.feed.seq += 1;
        if tx.try_send((self.feed.seq, event)).is_err() {
            self.feed.tx = None;
        }
    }

    pub(crate) fn export_shown(&mut self, uid: Uid) {
        if let Some(user) = self
            .users
            .get(&uid)
            .filter(|s| exported(s))
            .map(LocalUser::of)
        {
            self.export(PeerEvent::Shown(user));
        }
    }

    pub(crate) fn export_changed(&mut self, uid: Uid) {
        if let Some(user) = self
            .users
            .get(&uid)
            .filter(|s| exported(s))
            .map(LocalUser::of)
        {
            self.export(PeerEvent::Changed(user));
        }
    }

    pub(crate) fn linked(&self) -> bool {
        self.feed.linked
    }

    pub(crate) fn export_chat(&mut self, uid: Uid, text: &str, style: u16) {
        if self.users.get(&uid).is_some_and(exported) {
            self.feed.lines = self.feed.lines.wrapping_add(1);
            let line = self.feed.lines;
            self.export(PeerEvent::Chat {
                from: uid,
                text: text.into(),
                style,
                line,
            });
        }
    }

    /// Before the session leaves the roster: whether it was exported is
    /// asked of the session itself.
    pub(crate) fn export_gone(&mut self, sess: &UserSession) {
        if exported(sess) {
            self.export(PeerEvent::Gone(sess.info.uid, GoneReason::Disconnected));
        }
    }

    fn ghost_row(g: &GhostInfo, uid: Uid) -> UserInfo {
        UserInfo {
            uid,
            transport: Default::default(),
            nick: g.nick.clone(),
            icon: g.icon,
            admin: false,
            system: false,
            status: if g.away {
                SessionStatus::Idle
            } else {
                SessionStatus::Active
            },
            avatar: None,
            color: Some(g.color),
            remote: Some(g.remote.clone()),
        }
    }
}

impl Core {
    /// Start the export feed, replacing any before it, with room for `cap`
    /// events the hub has not yet taken.
    pub fn peer_feed(&self, cap: usize) -> mpsc::Receiver<(u64, PeerEvent)> {
        let (tx, rx) = mpsc::channel(cap);
        let mut r = self.roster.lock().unwrap();
        r.feed.tx = Some(tx);
        r.feed.linked = true;
        drop(r);
        rx
    }

    /// Every local user a link may show, and the feed's number at that
    /// moment: events numbered up to it are already in the snapshot.
    pub fn peer_snapshot(&self) -> (u64, Vec<LocalUser>) {
        let r = self.roster.lock().unwrap();
        let mut users: Vec<LocalUser> = r
            .users
            .values()
            .filter(|s| exported(s))
            .map(LocalUser::of)
            .collect();
        users.sort_by_key(|u| u.uid);
        (r.feed.seq, users)
    }

    /// Show a ghost, telling the room if it is visible. `None` when there
    /// is no uid to give it.
    pub fn ghost_attach(&self, g: GhostInfo) -> Option<Uid> {
        let mut r = self.roster.lock().unwrap();
        let uid = r.next_uid()?;
        let info = RosterInner::ghost_row(&g, uid);
        if g.visible {
            r.broadcast(&Event::Joined(info.clone()), None);
        }
        r.ghosts.insert(
            uid,
            Ghost {
                info,
                visible: g.visible,
                flood: Default::default(),
            },
        );
        Some(uid)
    }

    /// A ghost changed: shown, hidden or changed for the room as it must
    /// be. False if there is no such ghost.
    pub fn ghost_update(&self, uid: Uid, g: GhostInfo) -> bool {
        let mut r = self.roster.lock().unwrap();
        let Some(ghost) = r.ghosts.get_mut(&uid) else {
            return false;
        };
        let info = RosterInner::ghost_row(&g, uid);
        let (was, now) = (ghost.visible, g.visible);
        let changed = ghost.info != info;
        ghost.info = info.clone();
        ghost.visible = now;
        match (was, now) {
            (false, true) => r.broadcast(&Event::Joined(info), None),
            (true, false) => r.broadcast(&Event::Parted(uid), None),
            (true, true) if changed => r.broadcast(&Event::Changed(info), None),
            _ => {}
        }
        true
    }

    pub fn ghost_part(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        let Some(ghost) = r.ghosts.remove(&uid) else {
            return;
        };
        r.freed_uids.hold(uid, Instant::now());
        if ghost.visible {
            r.broadcast(&Event::Parted(uid), None);
        }
    }

    /// A line a ghost said, staged to be logged and shown by
    /// [`Core::ghost_chat`]; `None` when it is not shown here: no such
    /// ghost, one excluded here, or one past local users' chat limit. The
    /// hub relays a line whatever this answers.
    pub fn ghost_line(&self, uid: Uid, text: String, style: u16) -> Option<GhostLine> {
        let limits = self.flood_limits;
        let mut r = self.roster.lock().unwrap();
        let g = r.ghosts.get_mut(&uid).filter(|g| g.visible)?;
        if !g.flood.chat(
            crate::limits::chat_lines(&text),
            &limits,
            std::time::Instant::now(),
        ) {
            return None;
        }
        Some(GhostLine(crate::chat::Staged::ghost(
            g.info.clone(),
            text,
            style,
        )))
    }

    /// Where acts on ghosts go. Set once, by the hub when it starts.
    pub fn set_peer_router(&self, router: Arc<dyn PeerRouter>) {
        let _ = self.peer_router.set(router);
    }

    /// A private message to `to`: `None` when `to` is not a ghost shown
    /// here, so the message is a local one; otherwise its answer, refused
    /// at once for what could never be delivered.
    pub fn peer_msg(
        &self,
        from: Uid,
        to: Uid,
        text: &str,
        media: bool,
    ) -> Option<oneshot::Receiver<Result<(), PeerRefusal>>> {
        let r = self.roster.lock().unwrap();
        let g = r.ghosts.get(&to).filter(|g| g.visible)?;
        let refused = if g.info.remote.as_ref().is_some_and(|r| r.refuses_msgs) {
            Some(PeerRefusal::RefusesMessages)
        } else if !r.users.get(&from).is_some_and(exported) {
            Some(PeerRefusal::NotExported)
        } else if media || text.len() > MAX_LINK_TEXT {
            Some(PeerRefusal::CannotCross)
        } else {
            None
        };
        drop(r);
        Some(match (refused, self.peer_router.get()) {
            (Some(why), _) => answered(Err(why)),
            (None, Some(router)) => router.msg(from, to, text.to_owned()),
            (None, None) => answered(Err(PeerRefusal::Unreachable)),
        })
    }

    /// User info for `uid`: `None` when it is not a ghost shown here.
    pub fn peer_user_info(&self, uid: Uid) -> Option<PeerInfo> {
        let r = self.roster.lock().unwrap();
        let g = r.ghosts.get(&uid).filter(|g| g.visible)?;
        let nick = g.info.nick.clone();
        let home = g
            .info
            .remote
            .as_ref()
            .map_or_else(String::new, |r| r.home_name.clone());
        drop(r);
        let answer = match self.peer_router.get() {
            Some(router) => router.user_info(uid),
            None => answered(Err(PeerRefusal::Unreachable)),
        };
        Some(PeerInfo { nick, home, answer })
    }

    /// A private message from ghost `from` to `to`, a local user a link
    /// showed the ghost's server. Delivered live, as from the ghost: a
    /// ghost has no mailbox, so nothing waits and nothing is blocked.
    pub fn ghost_msg(&self, from: Uid, to: Uid, text: String) -> Result<(), PeerRefusal> {
        let limits = self.flood_limits;
        let mut r = self.roster.lock().unwrap();
        if !r.users.get(&to).is_some_and(exported) {
            return Err(PeerRefusal::UnknownUser);
        }
        let g = r.ghosts.get_mut(&from).ok_or(PeerRefusal::UnknownUser)?;
        if !g.visible {
            return Err(PeerRefusal::Excluded);
        }
        // A message spends a line of the ghost's chat allowance: local
        // users' limit, which is all the extension asks.
        if !g.flood.chat(1, &limits, Instant::now()) {
            return Err(PeerRefusal::RateLimited);
        }
        let from_nick = g.info.nick.clone();
        r.send_to(
            to,
            Event::Msg {
                from,
                from_nick,
                from_login: None,
                text,
                id: None,
                sent_at: SystemTime::now(),
                queued: false,
                media: None,
            },
        );
        Ok(())
    }

    /// What a linked server's clients may read about a local user: what
    /// an unprivileged client here may, never a login or an address.
    pub fn info_text_for_peer(&self, uid: Uid) -> Result<String, PeerRefusal> {
        let r = self.roster.lock().unwrap();
        let sess = r
            .users
            .get(&uid)
            .filter(|s| exported(s))
            .ok_or(PeerRefusal::UnknownUser)?;
        let secs = sess.connected_at.elapsed().as_secs();
        Ok(format!(
            "    name: {}\r    icon: {}\r  online: {}h {}m {}s\r",
            sess.info.nick,
            sess.info.icon,
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60,
        ))
    }

    pub fn ghost_count(&self) -> usize {
        self.roster.lock().unwrap().ghosts.len()
    }

    /// The user list: visible sessions and visible ghosts, in uid order.
    /// For the lists a client is shown (300, the ng roster) and nothing
    /// else; counts and every act on a user stay with the sessions.
    pub fn roster_rows(&self) -> Vec<UserInfo> {
        let r = self.roster.lock().unwrap();
        let mut rows: Vec<UserInfo> = r
            .users
            .values()
            .filter(|s| s.visible)
            .map(|s| s.info.clone())
            .chain(
                r.ghosts
                    .values()
                    .filter(|g| g.visible)
                    .map(|g| g.info.clone()),
            )
            .collect();
        rows.sort_by_key(|u| u.uid);
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AccessBits;
    use crate::roster::{drain, test_attach};

    fn chatter() -> AccessBits {
        AccessBits::empty()
            .with(crate::access::bit::READ_CHAT)
            .with(crate::access::bit::SEND_CHAT)
    }

    fn ghost(nick: &str, visible: bool) -> GhostInfo {
        GhostInfo {
            nick: nick.into(),
            icon: 7,
            away: false,
            color: 0x3a7bd5,
            remote: RemoteRef {
                home_tag: "hl2".into(),
                home_name: "Elsewhere".into(),
                tagged: false,
                refuses_msgs: true,
            },
            visible,
        }
    }

    #[test]
    fn a_ghost_is_listed_but_no_act_on_a_session_finds_it() {
        let core = Core::new();
        let (_me, mut rx) = test_attach(&core, "me", AccessBits::empty());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        assert!(
            matches!(&drain(&mut rx)[..], [Event::Joined(u)] if u.uid == g && u.remote.is_some())
        );
        assert!(core.roster_rows().iter().any(|u| u.uid == g));
        // Everything that acts on a session, and every count.
        assert!(core.user(g).is_none() && core.user_details(g).is_none());
        assert!(core.snapshot().iter().all(|u| u.uid != g));
        assert_eq!(core.census().attached, 1);
    }

    #[test]
    fn a_ghost_shown_hidden_and_gone_is_announced_each_time() {
        let core = Core::new();
        let (_me, mut rx) = test_attach(&core, "me", AccessBits::empty());
        let g = core.ghost_attach(ghost("bob", false)).unwrap();
        assert!(
            drain(&mut rx).is_empty(),
            "an excluded ghost is never shown"
        );
        core.ghost_update(g, ghost("bob", true));
        core.ghost_update(g, ghost("robert", true));
        core.ghost_update(g, ghost("robert", false));
        core.ghost_update(g, ghost("robert", true));
        core.ghost_part(g);
        let kinds: Vec<&str> = drain(&mut rx).iter().map(Event::kind).collect();
        assert_eq!(kinds, ["joined", "changed", "parted", "joined", "parted"]);
    }

    #[test]
    fn the_feed_numbers_what_the_snapshot_already_holds() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, "a", AccessBits::empty());
        let mut feed = core.peer_feed(16);
        let (b, _rb) = test_attach(&core, "b", AccessBits::empty());
        let (seq, users) = core.peer_snapshot();
        assert_eq!(users.iter().map(|u| u.uid).collect::<Vec<_>>(), [a, b]);
        core.update(a, Some("ann".into()), None);
        core.end_session(b);
        let mut events = vec![];
        while let Ok(e) = feed.try_recv() {
            events.push(e);
        }
        // b's join is numbered within the snapshot; what came after is not.
        let after: Vec<&PeerEvent> = events
            .iter()
            .filter(|(n, _)| *n > seq)
            .map(|(_, e)| e)
            .collect();
        assert!(
            matches!(after[..], [PeerEvent::Changed(LocalUser { uid, .. }), PeerEvent::Gone(gone, _)] if *uid == a && *gone == b)
        );
        assert!(events
            .iter()
            .any(|(n, e)| *n <= seq && matches!(e, PeerEvent::Shown(u) if u.uid == b)));
    }

    #[test]
    fn local_lines_with_text_are_exported_numbered() {
        let core = Core::new();
        let mut feed = core.peer_feed(16);
        let (a, _ra) = test_attach(&core, "a", chatter());
        core.chat_public(a, "one".into(), 0, None).unwrap();
        core.chat_public(a, String::new(), 0, None).unwrap();
        core.chat_public(a, "two".into(), 1, None).unwrap();
        let mut lines = vec![];
        while let Ok((_, e)) = feed.try_recv() {
            if let PeerEvent::Chat {
                text, style, line, ..
            } = e
            {
                lines.push((text, style, line));
            }
        }
        assert_eq!(lines, [("one".into(), 0, 1), ("two".into(), 1, 2)]);
    }

    #[test]
    fn a_ghosts_line_is_heard_unless_hidden_or_flooding_and_outlives_it() {
        let core = Core::new().with_flood_limits(crate::FloodLimits::MHXD);
        let (_me, mut rx) = test_attach(&core, "me", chatter());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        let line = core.ghost_line(g, "bye".into(), 0).unwrap();
        core.ghost_part(g);
        core.ghost_chat(line);
        let heard = drain(&mut rx);
        assert!(
            matches!(&heard[..], [Event::Joined(_), Event::Parted(_), Event::Chat { from, text, .. }] if from.uid == g && text == "bye"),
            "{heard:?}"
        );

        let hidden = core.ghost_attach(ghost("eve", false)).unwrap();
        assert!(core.ghost_line(hidden, "hi".into(), 0).is_none());
        let shown = core.ghost_attach(ghost("bob", true)).unwrap();
        let line = core.ghost_line(shown, "hi".into(), 0).unwrap();
        core.ghost_update(shown, ghost("bob", false));
        core.ghost_chat(line);
        assert!(!drain(&mut rx)
            .iter()
            .any(|e| matches!(e, Event::Chat { .. })));

        let loud = core.ghost_attach(ghost("loud", true)).unwrap();
        let limit = core.flood_limits.chat_lines as usize;
        let shown = (0..limit + 5)
            .filter(|_| core.ghost_line(loud, "x".into(), 0).is_some())
            .count();
        assert_eq!(shown, limit);
        assert!(
            core.roster_rows().iter().any(|u| u.uid == loud),
            "a ghost is never kicked here"
        );
    }

    #[test]
    fn a_long_line_is_cut_at_a_character_boundary() {
        let mut text = "a".repeat(MAX_LINK_TEXT - 1) + "\u{e9}b";
        cut_to_link_bound(&mut text);
        assert_eq!(text, "a".repeat(MAX_LINK_TEXT - 1));
    }

    #[test]
    fn what_cannot_reach_a_ghost_is_refused_before_anything_crosses() {
        let core = Core::new();
        let (me, _rx) = test_attach(&core, "me", chatter());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        let refused = |text: &str, media| {
            core.peer_msg(me, g, text, media)
                .unwrap()
                .try_recv()
                .unwrap()
        };
        // `ghost` refuses messages, as a link without them does.
        assert_eq!(refused("hi", false), Err(PeerRefusal::RefusesMessages));
        let mut open = ghost("bob", true);
        open.remote.refuses_msgs = false;
        core.ghost_update(g, open);
        assert_eq!(refused("hi", true), Err(PeerRefusal::CannotCross));
        let long = "x".repeat(MAX_LINK_TEXT + 1);
        assert_eq!(refused(&long, false), Err(PeerRefusal::CannotCross));
        assert_eq!(
            refused("hi", false),
            Err(PeerRefusal::Unreachable),
            "no router"
        );
        // A ghost hidden here is nobody: the message is a local one.
        let hidden = core.ghost_attach(ghost("eve", false)).unwrap();
        assert!(core.peer_msg(me, hidden, "hi", false).is_none());
    }

    #[test]
    fn a_ghosts_message_reaches_an_exported_user_only() {
        let core = Core::new().with_flood_limits(crate::FloodLimits::MHXD);
        let (me, mut rx) = test_attach(&core, "me", chatter());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        drain(&mut rx);
        assert_eq!(core.ghost_msg(g, me, "hi".into()), Ok(()));
        assert!(matches!(
            &drain(&mut rx)[..],
            [Event::Msg { from, from_login: None, text, .. }] if *from == g && text == "hi"
        ));
        assert_eq!(
            core.ghost_msg(g, 0x7ff0, "hi".into()),
            Err(PeerRefusal::UnknownUser)
        );
        assert_eq!(
            core.ghost_msg(0x7ff1, me, "hi".into()),
            Err(PeerRefusal::UnknownUser)
        );
        let text = core.info_text_for_peer(me).unwrap();
        assert!(text.starts_with("    name: me\r"), "{text:?}");
    }

    #[test]
    fn a_feed_that_falls_behind_is_closed() {
        let core = Core::new();
        let mut feed = core.peer_feed(1);
        let (_a, _ra) = test_attach(&core, "a", AccessBits::empty());
        let (_b, _rb) = test_attach(&core, "b", AccessBits::empty());
        assert!(feed.try_recv().is_ok());
        assert!(matches!(
            feed.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
