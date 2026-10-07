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
    /// Shown here: as the link says, and not hidden by a moderator here.
    pub(crate) visible: bool,
    /// Hidden by a moderator here, for as long as the ghost is shown.
    hidden_here: bool,
    /// What its lines are logged under, for a purge to name it by: a
    /// ghost has no login, and its name may be anyone's.
    pub(crate) key: [u8; 16],
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
    /// No ban by that handle was made by that server.
    UnknownBan,
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
            // Told apart from a local "not connected": over a link it can
            // also mean the far server does not know the sender.
            PeerRefusal::UnknownUser => "That user's server does not know them, or you.",
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
            PeerRefusal::UnknownBan => "No such ban.",
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
    /// Ask a ghost's home server to kick it from this one, or with `ban`
    /// to ban it from the network for a time (`None`, until lifted) and a
    /// reason. Answers whether the home server did it.
    /// `by` is the moderator's login, for this server's record of a ban.
    fn kick(
        &self,
        of: Uid,
        ban: Option<GhostBan>,
        by: String,
    ) -> oneshot::Receiver<Result<(), PeerRefusal>>;
}

/// A ban asked of a ghost's home server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostBan {
    pub for_: Option<Duration>,
    pub reason: String,
}

/// A ban this server asked a linked server to place on one of its users:
/// what this server's operator lists, and lifts by asking that server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkBan {
    /// Its number here; 0 until the store records it.
    pub id: u64,
    /// This server's ID when it asked: only under it can it be lifted.
    pub requester: [u8; 8],
    pub home: [u8; 8],
    pub home_tag: String,
    /// What the home server gave this server to lift it by.
    pub handle: [u8; 16],
    pub nick: String,
    pub reason: String,
    pub actor: String,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    /// When this server's operator asked for it lifted.
    pub lift_asked: Option<SystemTime>,
    /// When its home server lifted it, or answered that it had no such
    /// ban (lifted there by its own operator, or run out).
    pub lifted_at: Option<SystemTime>,
}

impl NetworkBan {
    pub fn standing(&self, now: SystemTime) -> bool {
        self.lifted_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }
}

/// A ghost as a purge names it: the key its lines were logged under, and
/// how the audit trail calls it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostRef {
    pub key: [u8; 16],
    pub label: String,
}

/// A moderator's kick of a ghost, carried out here at once and asked of
/// its home server.
pub struct GhostKick {
    pub nick: String,
    pub answer: oneshot::Receiver<Result<(), PeerRefusal>>,
}

/// The linked server a moderation request is made for, as the link that
/// carried it knows that server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    pub id: [u8; 8],
    pub tag: String,
    pub name: String,
}

impl Requester {
    /// Acts for it as this server's operator would, as the extension
    /// has a home server act on a network moderator's request, under a
    /// name its operator can read in the audit trail and the bans.
    fn acting(&self) -> crate::moderation::Acting {
        crate::moderation::Acting {
            name: format!("link {} ({})", self.tag, self.name),
            fingerprint: None,
            overrides: true,
            uid: None,
            person: None,
        }
    }
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
    /// Linked servers that kicked this user, which must not show it.
    pub exclude: Vec<[u8; 8]>,
}

impl LocalUser {
    fn of(sess: &UserSession) -> LocalUser {
        LocalUser {
            uid: sess.info.uid,
            nick: sess.info.nick.clone(),
            icon: sess.info.icon,
            away: sess.info.status != SessionStatus::Active,
            color: sess.info.color,
            exclude: sess.excluded_at.clone(),
        }
    }
}

/// Why a local user stopped being exported (Link User Gone's reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneReason {
    Disconnected,
    Banned,
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
        if let Err(e) = tx.try_send((self.feed.seq, event)) {
            if matches!(e, mpsc::error::TrySendError::Full(_)) {
                crate::instrument::link_lagged("feed");
            }
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
            let why = if sess.banned {
                GoneReason::Banned
            } else {
                GoneReason::Disconnected
            };
            self.export(PeerEvent::Gone(sess.info.uid, why));
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
        let mut key = [0u8; 16];
        getrandom::getrandom(&mut key).ok()?;
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
                hidden_here: false,
                key,
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
        let (was, now) = (ghost.visible, g.visible && !ghost.hidden_here);
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

    /// A moderator's kick of ghost `uid`, or with `ban` its ban: hidden
    /// here at once, as the extension has a requesting server do, and
    /// for as long as it is shown whatever its home server answers; and
    /// asked of that server, whose answer comes in [`GhostKick::answer`].
    /// `None` when `uid` is no ghost shown here.
    pub fn ghost_kick(&self, by: Uid, uid: Uid, ban: Option<GhostBan>) -> Option<GhostKick> {
        let nick = self.ghost_hide(uid)?;
        let moderator = self
            .roster
            .lock()
            .unwrap()
            .users
            .get(&by)
            .map(|s| s.login.clone());
        let answer = match self.peer_router.get() {
            Some(router) => router.kick(uid, ban, moderator.unwrap_or_default()),
            None => answered(Err(PeerRefusal::Unreachable)),
        };
        Some(GhostKick { nick, answer })
    }

    /// Hide ghost `uid` here; one hidden already, kicked again, stays so
    /// and is asked of its home server again.
    fn ghost_hide(&self, uid: Uid) -> Option<String> {
        let mut r = self.roster.lock().unwrap();
        let g = r.ghosts.get_mut(&uid)?;
        let was = std::mem::replace(&mut g.visible, false);
        g.hidden_here = true;
        let nick = g.info.nick.clone();
        if was {
            r.broadcast(&Event::Parted(uid), None);
        }
        Some(nick)
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
            g.key,
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

    /// A linked server's kick of local user `uid`: it is not shown there
    /// for the rest of its session, and stays here and everywhere else.
    pub fn peer_kick(&self, uid: Uid, by: &Requester) -> Result<(), PeerRefusal> {
        let mut r = self.roster.lock().unwrap();
        let sess = r
            .users
            .get_mut(&uid)
            .filter(|s| exported(s))
            .ok_or(PeerRefusal::UnknownUser)?;
        if !sess.excluded_at.contains(&by.id) {
            sess.excluded_at.push(by.id);
        }
        // So its users vanishing is not a mystery.
        let text = format!(
            "{} ({}) has removed you: its users no longer see you.",
            by.name, by.tag
        );
        r.send_to(
            uid,
            Event::Broadcast {
                from: 0,
                from_nick: String::new(),
                text,
            },
        );
        r.export_changed(uid);
        Ok(())
    }

    /// A linked server's ban of local user `uid`, placed as this server's
    /// operator would place it and ending the session; for `None`, until
    /// lifted. The handle the requester may lift it by, when there is one
    /// to give: none when the ban only extended another act's. A store
    /// write: call it off the reactor.
    pub fn peer_ban(
        &self,
        uid: Uid,
        by: &Requester,
        for_: Option<Duration>,
        reason: &str,
    ) -> Result<Option<[u8; 16]>, PeerRefusal> {
        let (targets, serial) = {
            let mut r = self.roster.lock().unwrap();
            let sess = r
                .users
                .get_mut(&uid)
                .filter(|s| exported(s))
                .ok_or(PeerRefusal::UnknownUser)?;
            // Before the ban, which may end the session itself.
            sess.banned = true;
            let serial = sess.serial;
            let targets = self.kick_ban_targets(sess);
            // Told first, while there is a session to tell: the ban may end
            // it, and `Kicked` says nothing.
            let text = format!(
                "You have been banned from the network by {} ({}).",
                by.name, by.tag
            );
            r.send_to(
                uid,
                Event::Broadcast {
                    from: 0,
                    from_nick: String::new(),
                    text,
                },
            );
            (targets, serial)
        };
        // The person, where there is one, so their every session ends and
        // nobody else's; the address only for a shared login such as
        // guest, as the extension asks a home server to judge.
        let targets = match targets.first() {
            Some(
                person @ (crate::ban::BanTarget::Login(_) | crate::ban::BanTarget::Identity(_)),
            ) => {
                vec![person.clone()]
            }
            _ => targets,
        };
        let unmark = |core: &Core| {
            let mut r = core.roster.lock().unwrap();
            if let Some(sess) = r.users.get_mut(&uid).filter(|s| s.serial == serial) {
                sess.banned = false;
            }
        };
        let mut handle = [0u8; 16];
        if getrandom::getrandom(&mut handle).is_err() {
            unmark(self);
            return Err(PeerRefusal::Unreachable);
        }
        let reason = match reason.trim() {
            "" => format!("banned from the network by {}", by.tag),
            why => format!("banned from the network by {}: {why}", by.tag),
        };
        let kept;
        // A guest on an address nobody may ban: thrown off, but nothing
        // holds them, so the requester is told no ban was placed.
        let Some((first, rest)) = targets.split_first() else {
            unmark(self);
            let mut r = self.roster.lock().unwrap();
            if r.users.get(&uid).is_some_and(|s| s.serial == serial) {
                let _ = crate::chat::kick_in(&mut r, uid);
            }
            return Err(PeerRefusal::UnknownUser);
        };
        {
            let ban = crate::ban::NewBan {
                target: first.clone(),
                reason,
                note: Some(format!("asked for by {} ({})", by.name, by.tag)),
                expires_at: for_.and_then(|d| SystemTime::now().checked_add(d)),
                // As a moderator's ban: every session it refuses ends.
                source: crate::ban::BanSource::Moderator,
            };
            let (act, placed) = match self.place_bans_act(&by.acting(), ban, rest.to_vec()) {
                Ok(placed) => placed,
                Err(e) => {
                    tracing::warn!(target = uid, "network ban not placed: {e:?}");
                    unmark(self);
                    return Err(PeerRefusal::Unreachable);
                }
            };
            // Only a row this ban created: one it extended is another act's,
            // which the requester has no business lifting, so the handle
            // then names nothing and its unban answers `UnknownBan`.
            let own = placed.iter().find(|row| act.is_some() && row.act == act);
            kept = match (self.moderation.as_ref(), own) {
                // The ban stands either way; only lifting it from there is
                // lost.
                (Some(store), Some(row)) => match store.note_link_ban(row.id, by.id, handle) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(target = uid, "network ban's handle not kept: {e}");
                        false
                    }
                },
                _ => false,
            };
        }
        let mut r = self.roster.lock().unwrap();
        // Ended already, by the ban, or gone; and its uid, if given out
        // again, somebody else's.
        if r.users.get(&uid).is_some_and(|s| s.serial == serial) {
            let _ = crate::chat::kick_in(&mut r, uid);
        }
        Ok(kept.then_some(handle))
    }

    /// A linked server lifting the ban it placed under `handle`.
    pub fn peer_unban(&self, handle: [u8; 16], by: &Requester) -> Result<(), PeerRefusal> {
        let store = self.moderation.as_ref().ok_or(PeerRefusal::UnknownBan)?;
        // A store that would not answer is not "no such ban": the
        // requester would take it for lifted and stop asking.
        let id = store
            .link_ban(by.id, handle)
            .map_err(|_| PeerRefusal::Unreachable)?
            .ok_or(PeerRefusal::UnknownBan)?;
        match self.lift_ban_as(&by.acting(), id) {
            Ok(_) => Ok(()),
            Err(crate::moderation::ModError::NoSuchBan) => Err(PeerRefusal::UnknownBan),
            Err(_) => Err(PeerRefusal::Unreachable),
        }
    }

    /// Keep a ban this server asked for, so its operator can list and
    /// lift it. A store write: off the reactor. Logged when it cannot be
    /// kept, as the ban stands at its home server either way.
    pub fn record_network_ban(&self, ban: NetworkBan) {
        let Some(store) = self.moderation.as_ref() else {
            return;
        };
        if let Err(e) = store.record_network_ban(&ban) {
            tracing::warn!(nick = %ban.nick, home = %ban.home_tag, "network ban not recorded: {e}");
        }
    }

    /// The bans this server asked of others, newest first.
    pub fn network_bans(&self) -> Result<Vec<NetworkBan>, crate::moderation::ModError> {
        let store = self
            .moderation
            .as_ref()
            .ok_or(crate::moderation::ModError::Disabled)?;
        Ok(store.network_bans()?)
    }

    /// Ask for ban `id` lifted: sent to its home server by the running
    /// server, on its next reload ([`Core::network_unbans_asked`]).
    pub fn ask_network_unban(&self, id: u64) -> Result<NetworkBan, crate::moderation::ModError> {
        use crate::moderation::ModError;
        let store = self.moderation.as_ref().ok_or(ModError::Disabled)?;
        store
            .ask_network_unban(id, SystemTime::now())?
            .ok_or(ModError::NoSuchBan)
    }

    /// The bans asked for lifted and not yet lifted, still standing.
    pub fn network_unbans_asked(&self) -> Vec<NetworkBan> {
        let now = SystemTime::now();
        self.network_bans()
            .unwrap_or_default()
            .into_iter()
            .filter(|b| b.lift_asked.is_some() && b.standing(now))
            .collect()
    }

    /// Ban `id` is lifted at its home server.
    pub fn network_unbanned(&self, id: u64) {
        if let Some(store) = self.moderation.as_ref() {
            if let Err(e) = store.network_unbanned(id, SystemTime::now()) {
                tracing::warn!(id, "network unban not recorded: {e}");
            }
        }
    }

    /// What a purge of ghost `uid` needs, shown here or hidden: taken
    /// before it is kicked, as its home server's answer may take it away.
    pub fn ghost_ref(&self, uid: Uid) -> Option<GhostRef> {
        let r = self.roster.lock().unwrap();
        r.ghosts.get(&uid).map(|g| GhostRef {
            key: g.key,
            label: match &g.info.remote {
                Some(remote) => format!("{}@{}", g.info.nick, remote.home_tag),
                None => g.info.nick.clone(),
            },
        })
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
    fn a_ghost_hidden_here_stays_hidden_whatever_its_link_says() {
        let core = Core::new();
        let (_me, mut rx) = test_attach(&core, "me", chatter());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        assert_eq!(
            core.ghost_kick(0, g, None).map(|k| k.nick).as_deref(),
            Some("bob")
        );
        assert!(core.ghost_kick(0, g, None).is_some(), "kicked again");
        core.ghost_update(g, ghost("robert", true));
        assert!(core.roster_rows().iter().all(|u| u.uid != g));
        assert!(core.ghost_line(g, "hi".into(), 0).is_none());
        let kinds: Vec<&str> = drain(&mut rx).iter().map(Event::kind).collect();
        assert_eq!(kinds, ["joined", "parted"]);
    }

    fn hub_server() -> Requester {
        Requester {
            id: [4; 8],
            tag: "hch".into(),
            name: "Hub".into(),
        }
    }

    #[test]
    fn a_network_kick_hides_the_user_at_its_requester_only() {
        let core = Core::new();
        let mut feed = core.peer_feed(16);
        let (ann, mut rx) = test_attach(&core, "ann", chatter());
        assert_eq!(core.peer_kick(ann, &hub_server()), Ok(()));
        assert!(drain(&mut rx)
            .iter()
            .any(|e| matches!(e, Event::Broadcast { text, .. } if text.contains("Hub (hch)"))));
        let mut changed = vec![];
        while let Ok((_, e)) = feed.try_recv() {
            if let PeerEvent::Changed(u) = e {
                changed.push(u.exclude);
            }
        }
        assert_eq!(changed, [vec![[4; 8]]]);
        assert!(core.user(ann).is_some(), "still here");
        assert_eq!(
            core.peer_kick(0x7ff0, &hub_server()),
            Err(PeerRefusal::UnknownUser)
        );
    }

    #[test]
    fn a_network_ban_is_placed_as_the_operator_would_and_lifted_only_by_its_requester() {
        use crate::moderation::{MemoryModeration, ModerationPolicy};
        let core = Core::new().with_moderation(
            Arc::new(MemoryModeration::default()),
            ModerationPolicy::default(),
        );
        let mut feed = core.peer_feed(16);
        let (ann, mut rx) = core
            .attach(crate::roster::AttachInfo {
                nick: "ann".into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: "ann".into(),
                addr: None,
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(ann);
        let handle = core
            .peer_ban(ann, &hub_server(), None, "spam")
            .unwrap()
            .expect("a ban of its own to lift");
        // Told who banned them before the ban ends the session.
        let kinds: Vec<&str> = drain(&mut rx).iter().map(Event::kind).collect();
        let told = kinds.iter().position(|k| *k == "broadcast").unwrap();
        assert!(
            told < kinds.iter().position(|k| *k == "kicked").unwrap(),
            "{kinds:?}"
        );
        let bans = core.list_bans(true, None, 10).unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].actor, "link hch (Hub)");
        assert!(bans[0].reason.contains("hch"), "{}", bans[0].reason);
        // The frontend ends the kicked session; its leaving is a ban.
        core.end_session(ann);
        let mut gone = None;
        while let Ok((_, e)) = feed.try_recv() {
            if let PeerEvent::Gone(uid, why) = e {
                gone = Some((uid, why));
            }
        }
        assert_eq!(gone, Some((ann, GoneReason::Banned)));

        let other = Requester {
            id: [5; 8],
            ..hub_server()
        };
        assert_eq!(
            core.peer_unban(handle, &other),
            Err(PeerRefusal::UnknownBan)
        );
        assert_eq!(core.peer_unban(handle, &hub_server()), Ok(()));
        assert!(core.list_bans(true, None, 10).unwrap().is_empty());
        assert_eq!(
            core.peer_unban(handle, &hub_server()),
            Err(PeerRefusal::UnknownBan),
            "lifted already"
        );
    }

    #[test]
    fn a_network_ban_cannot_lift_a_ban_it_only_extended() {
        use crate::moderation::{Actor, MemoryModeration, ModerationPolicy};
        let core = Core::new().with_moderation(
            Arc::new(MemoryModeration::default()),
            ModerationPolicy::default(),
        );
        let (ann, _rx) = core
            .attach(crate::roster::AttachInfo {
                nick: "ann".into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: "ann".into(),
                addr: None,
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(ann);
        // The operator's ban first, standing when the network's arrives.
        core.place_ban(
            Actor::Operator,
            crate::ban::NewBan {
                target: crate::ban::BanTarget::Login("ann".into()),
                reason: "ours".into(),
                note: None,
                expires_at: None,
                source: crate::ban::BanSource::Cli,
            },
        )
        .unwrap();
        let handle = core.peer_ban(ann, &hub_server(), None, "theirs").unwrap();
        assert_eq!(handle, None, "nothing of its own to lift");
        assert_eq!(
            core.list_bans(true, None, 10).unwrap().len(),
            1,
            "ours stands"
        );
    }

    #[test]
    fn a_purge_of_a_ghost_takes_its_lines_and_spares_a_namesake() {
        use crate::moderation::{Actor, MemoryModeration, ModerationPolicy};
        let core = Core::new()
            .with_history(
                Arc::new(crate::history::MemoryLog::default()),
                Default::default(),
            )
            .with_moderation(
                Arc::new(MemoryModeration::default()),
                ModerationPolicy::default(),
            );
        let (bob, _rx) = test_attach(&core, "bob", chatter());
        let g = core.ghost_attach(ghost("bob", true)).unwrap();
        core.chat_public(bob, "mine".into(), 0, None).unwrap();
        for text in ["spam", "more spam"] {
            core.ghost_chat(core.ghost_line(g, text.into(), 0).unwrap());
        }
        // Another ghost of the same name, from the same server.
        let twin = core.ghost_attach(ghost("bob", true)).unwrap();
        core.ghost_chat(core.ghost_line(twin, "hi".into(), 0).unwrap());
        let target = core.ghost_ref(g).unwrap();
        // Kicked, so hidden, before the purge, as the frontends do.
        core.ghost_kick(0, g, None).unwrap();
        let purged = core
            .purge_ghost(Actor::Operator, &target, Duration::from_secs(3600), "spam")
            .unwrap();
        assert_eq!(purged.lines, [2, 3]);
        let log = core.history.as_ref().unwrap();
        let text = |id| log.line(id).unwrap().unwrap().text;
        assert_eq!(text(1), "mine", "the local bob's line stands");
        assert_eq!(text(4), "hi", "and the other bob's");
        assert!(text(2).is_empty() && text(3).is_empty(), "tombstoned");
        let act = &core.moderation_log(Actor::Operator, None, 1).unwrap().0[0];
        assert!(
            act.evidence
                .as_deref()
                .unwrap()
                .starts_with("linked user bob@hl2"),
            "{act:?}"
        );
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
