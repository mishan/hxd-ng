//! Curated rooms (`docs/chat-rooms.md`): named, persistent, logged
//! conversations the operator keeps in a file, beside the lobby (public
//! chat, room 0) and the private chats.
//!
//! A room's id is its chat id, its log channel and its voice room at
//! once (§2.2), so ids come from the private chats' allocator and are
//! never drawn again once a room has held one. The file is behind
//! [`RoomStore`]; the rooms themselves are held in the roster beside the
//! private chats, with their members. Membership is a session's: a
//! detach keeps it, the end of a session parts every room.
//!
//! Who may do what is §5's, decided here for every wire: a room a
//! session may not see is answered exactly as a room that does not exist.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tracing::warn;

use crate::access::bit;
use crate::chat::ChatCommit;
use crate::history::LineId;
use crate::inbox::StoreError;
use crate::instrument::TimedMutex;
use crate::roster::{Core, Event, LogSerial, RosterInner, Uid, UserInfo, UserSession};

/// The longest room name, in characters.
pub const NAME_MAX: usize = 32;
/// The longest topic, in characters: a private chat's subject's cap.
pub const TOPIC_MAX: usize = 255;

/// A room's topic, or the lobby's subject, with who set it and when.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Topic {
    pub text: String,
    pub by: String,
    pub at: Option<SystemTime>,
}

/// One entry of the rooms file (§2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Room {
    /// Assigned by the running server and never reused; 0 in an entry
    /// written beside it, by `hxd room create` or by hand, until the
    /// server loads it.
    pub id: u32,
    pub name: String,
    pub topic: Topic,
    pub position: i64,
    /// Who may see, join and read it: logins, or none for everyone the
    /// access bits let in. `@role` entries name nobody until roles exist.
    pub read: Vec<String>,
    /// Who may send in it, the same way.
    pub post: Vec<String>,
    /// This room's retention, over `[history]`'s.
    pub max_lines: Option<u32>,
    pub max_days: Option<u32>,
    pub archived_at: Option<SystemTime>,
    /// A tombstone: the id stays taken, and nothing else is kept.
    pub deleted: bool,
}

impl Room {
    /// The tombstone a deleted room leaves.
    pub fn tombstone(id: u32) -> Room {
        Room {
            id,
            deleted: true,
            ..Room::default()
        }
    }
}

/// The rooms file as a whole: the lobby's subject, and every entry,
/// archived rooms and tombstones included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomFile {
    pub lobby: Topic,
    pub rooms: Vec<Room>,
}

/// Where the rooms are kept (§4). Every write is of one entry, so an
/// entry nobody touched is left as it was, comments and all.
pub trait RoomStore: Send + Sync + 'static {
    /// The whole file; an error when it cannot be read or does not parse.
    fn load(&self) -> Result<RoomFile, StoreError>;
    /// Write `room` over the entry holding its id, or else over the entry
    /// with no id and its name (the id the server just gave it), or else
    /// as a new entry.
    fn put(&self, room: &Room) -> Result<(), StoreError>;
    /// Write the topic alone of the entry holding `id`, or of the lobby
    /// for 0, so a topic flushed later does not undo an edit made
    /// meanwhile to the rest of the entry.
    fn put_topic(&self, id: u32, topic: &Topic) -> Result<(), StoreError>;
}

/// The rooms in memory, for tests and for a server with no file.
#[derive(Default)]
pub struct MemoryRooms(Mutex<RoomFile>);

impl MemoryRooms {
    pub fn new(file: RoomFile) -> MemoryRooms {
        MemoryRooms(Mutex::new(file))
    }
}

impl RoomStore for MemoryRooms {
    fn load(&self) -> Result<RoomFile, StoreError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn put(&self, room: &Room) -> Result<(), StoreError> {
        let mut file = self.0.lock().unwrap();
        let at = file
            .rooms
            .iter()
            .position(|r| room.id != 0 && r.id == room.id)
            .or_else(|| {
                file.rooms
                    .iter()
                    .position(|r| r.id == 0 && !r.deleted && r.name == room.name)
            });
        match at {
            Some(i) => file.rooms[i] = room.clone(),
            None => file.rooms.push(room.clone()),
        }
        Ok(())
    }

    fn put_topic(&self, id: u32, topic: &Topic) -> Result<(), StoreError> {
        let mut file = self.0.lock().unwrap();
        if id == 0 {
            file.lobby = topic.clone();
        } else if let Some(r) = file.rooms.iter_mut().find(|r| r.id == id) {
            r.topic = topic.clone();
        }
        Ok(())
    }
}

/// Why a room operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    /// No such room, or one this session may not see: one answer for
    /// both (§5).
    NoSuchRoom,
    NotAMember,
    /// The session is in `[rooms] max_joined` rooms already.
    TooManyRooms,
    /// The file holds `[rooms] max_rooms` entries.
    RoomsFull,
    NameTaken,
    /// A field no room may have; says which rule it broke.
    Invalid(&'static str),
    AccessDenied,
    /// This server keeps no rooms.
    Disabled,
    ServerError,
}

impl std::fmt::Display for RoomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RoomError::NoSuchRoom => "no such room",
            RoomError::NotAMember => "not in that room",
            RoomError::TooManyRooms => "in as many rooms as a session may be",
            RoomError::RoomsFull => "the server has as many rooms as it may",
            RoomError::NameTaken => "a room has that name already",
            RoomError::Invalid(why) => why,
            RoomError::AccessDenied => "not allowed",
            RoomError::Disabled => "this server keeps no rooms",
            RoomError::ServerError => "server error",
        })
    }
}

/// `[rooms]`'s limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPolicy {
    /// Rooms one session may be in at once.
    pub max_joined: usize,
    /// Entries the file may hold, archived rooms and tombstones included,
    /// so rooms cannot be made, filled and archived without end.
    pub max_rooms: usize,
    /// The lobby's name in listings.
    pub lobby: String,
    /// Tell a classic session at login that rooms exist (§6.5).
    pub announce: bool,
    /// Rooms that notice names before "and n more".
    pub announce_names: usize,
    /// The server reports a version below 151, to which a period client
    /// set to refuse private chat or to answer automatically declines an
    /// invite by itself (§6.2), so `/join` says what to turn off.
    pub invites_declined: bool,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        RoomPolicy {
            max_joined: 32,
            max_rooms: 256,
            lobby: "lobby".into(),
            announce: true,
            announce_names: 3,
            invites_declined: false,
        }
    }
}

/// Why the server parted a member (`Event::RoomParted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartReason {
    /// It may no longer be in the room.
    Access,
    /// The room was archived or deleted.
    Archived,
}

impl PartReason {
    pub fn name(self) -> &'static str {
        match self {
            PartReason::Access => "access",
            PartReason::Archived => "archived",
        }
    }
}

/// 1 to 32 lowercase ASCII letters, digits, `-` and `_`: easy to type into a
/// period client, and the same in Mac Roman and UTF-8.
pub fn valid_name(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// A gate entry is a login, or `@role`, which names nobody until roles
/// exist and cannot be written before then.
fn valid_entry(entry: &str, writing: bool) -> bool {
    match entry.strip_prefix('@') {
        Some(role) => !writing && valid_name(role),
        None => {
            (1..=31).contains(&entry.len())
                && !entry.starts_with('.')
                && entry
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
        }
    }
}

/// A change to a room, field by field: `None` leaves a field as it is,
/// and `Some(vec![])` clears a gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomEdit {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub position: Option<i64>,
    pub read: Option<Vec<String>>,
    pub post: Option<Vec<String>>,
    pub max_lines: Option<Option<u32>>,
    pub max_days: Option<Option<u32>>,
}

impl RoomEdit {
    /// Make the change to `room`, refusing a field no room may have; a
    /// topic is set as `by`'s, now.
    pub fn apply(self, room: &mut Room, by: &str, now: SystemTime) -> Result<(), RoomError> {
        if let Some(name) = self.name {
            if !valid_name(&name) {
                return Err(RoomError::Invalid(
                    "a room's name is 1 to 32 lowercase letters, digits, - and _",
                ));
            }
            room.name = name;
        }
        if let Some(text) = self.topic {
            if text.chars().count() > TOPIC_MAX {
                return Err(RoomError::Invalid("a topic is at most 255 characters"));
            }
            room.topic = Topic {
                text,
                by: by.into(),
                at: Some(now),
            };
        }
        for (list, gate) in [(self.read, &mut room.read), (self.post, &mut room.post)] {
            if let Some(list) = list {
                if !list.iter().all(|e| valid_entry(e, true)) {
                    return Err(RoomError::Invalid(
                        "a gate names logins; @roles arrive with roles",
                    ));
                }
                *gate = list;
            }
        }
        if let Some(position) = self.position {
            room.position = position;
        }
        if let Some(n) = self.max_lines {
            room.max_lines = n;
        }
        if let Some(n) = self.max_days {
            room.max_days = n;
        }
        Ok(())
    }
}

/// A room as the roster holds it.
pub(crate) struct RoomEntry {
    pub(crate) room: Room,
    pub(crate) members: Vec<Uid>,
}

/// One room's commit queue and the serial it holds from append to
/// fan-out: the lobby's (`Core::chat_commit`, `Core::log_serial`), per
/// room, because ids need only ascend in the order the room hears them
/// (§3), and one room's lines should not wait on another's fan-out.
pub(crate) struct RoomChannel {
    pub(crate) commit: ChatCommit,
    pub(crate) serial: TimedMutex<LogSerial>,
}

/// What `Core` keeps for rooms beside the roster.
#[derive(Default)]
pub(crate) struct RoomState {
    pub(crate) store: Option<Arc<dyn RoomStore>>,
    pub(crate) policy: RoomPolicy,
    /// Held by a write to the file across it and the roster change it
    /// makes, so no two land in the other order (§4). Taken after the
    /// account-write lock, never with the roster's held.
    pub(crate) writes: Mutex<()>,
    /// Topics changed since the file was last written, by room id, 0 for
    /// the lobby: a stream of topic changes is not a stream of writes.
    /// May be taken with the roster's lock held, never the other way.
    pub(crate) dirty: Mutex<BTreeSet<u32>>,
    /// Topics whose write failed: tried again by a reload and at
    /// shutdown, not every few seconds, and newer than the file's until
    /// then. Taken as `dirty` is.
    pub(crate) unwritten: Mutex<BTreeSet<u32>>,
    pub(crate) channels: Mutex<HashMap<u32, Arc<RoomChannel>>>,
    /// Who was told at login that rooms exist, and when (§6.5): memory,
    /// because forgetting costs one more notice and nothing else.
    pub(crate) announced: Mutex<HashMap<Announced, Instant>>,
}

/// Whom the lobby notice was sent: an account, or a guest by its
/// identity and else its address, since every guest shares one login.
pub(crate) type Announced = (String, Option<[u8; 32]>, Option<std::net::IpAddr>);

/// How many [`RoomState::announced`] entries are kept: past it those
/// older than a day are let go, and then the oldest.
const ANNOUNCED_KEPT: usize = 4096;

/// Does `list` name this session's account? `@role` names nobody yet.
fn named(list: &[String], sess: &UserSession) -> bool {
    list.iter()
        .any(|e| !e.starts_with('@') && e.eq_ignore_ascii_case(&sess.login))
}

/// May `sess` read `room` by its bits and the room's `read` gate?
fn reads(sess: &UserSession, room: &Room) -> bool {
    sess.access.has(bit::READ_CHAT) && (room.read.is_empty() || named(&room.read, sess))
}

/// Does `room` exist for `sess` (§5)? A manager or a moderator sees every
/// room, archived ones too.
pub(crate) fn sees(sess: &UserSession, room: &Room) -> bool {
    !room.deleted
        && (sess.manage_rooms || sess.moderate || (room.archived_at.is_none() && reads(sess, room)))
}

/// Is `room` in `sess`'s listing? What it sees, less the archive.
fn listed(sess: &UserSession, room: &Room) -> bool {
    sees(sess, room) && room.archived_at.is_none()
}

/// What a session's listing says of a room, to tell what changed: the
/// gates only to a manager, who alone is told them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    name: String,
    topic: String,
    position: i64,
    max_lines: Option<u32>,
    max_days: Option<u32>,
    may_post: bool,
    gates: Option<(Vec<String>, Vec<String>)>,
}

fn listed_as(sess: &UserSession, room: &Room) -> Listed {
    Listed {
        name: room.name.clone(),
        topic: room.topic.text.clone(),
        position: room.position,
        max_lines: room.max_lines,
        max_days: room.max_days,
        may_post: may_post(sess, room),
        gates: sess
            .manage_rooms
            .then(|| (room.read.clone(), room.post.clone())),
    }
}

/// What each rooms-aware session was shown of each room it lists,
/// [`RosterInner::room_shown`]'s, to compare with afterwards.
pub(crate) type Shown = BTreeMap<(Uid, u32), Listed>;

fn view(r: &RosterInner, sess: &UserSession, entry: &RoomEntry) -> RoomView {
    RoomView {
        room: entry.room.clone(),
        members: entry.members.len(),
        last_id: r.last_ids.get(&entry.room.id).copied(),
        may_post: may_post(sess, &entry.room),
        manages: sess.manage_rooms,
    }
}

/// May `sess` be in `room`, joining or staying?
fn admits(sess: &UserSession, room: &Room) -> bool {
    !room.deleted
        && room.archived_at.is_none()
        && (sess.manage_rooms || sess.moderate || reads(sess, room))
}

/// May `sess` send in `room`, given that it is in it?
fn may_post(sess: &UserSession, room: &Room) -> bool {
    admits(sess, room)
        && (sess.manage_rooms
            || (sess.access.has(bit::SEND_CHAT)
                && (room.post.is_empty() || named(&room.post, sess))))
}

impl RosterInner {
    /// Send `event` about `room` to its members that `pred` admits.
    pub(crate) fn room_send_where(
        &mut self,
        room: u32,
        event: Event,
        pred: impl Fn(&UserSession) -> bool,
    ) {
        let Some(members) = self.rooms.get(&room).map(|e| e.members.clone()) else {
            return;
        };
        let ev = Event::InRoom {
            room,
            event: Box::new(event),
        };
        for uid in members {
            if self.users.get(&uid).is_some_and(&pred) {
                self.send_to(uid, ev.clone());
            }
        }
    }

    /// Part `uid` from `room` and its voice room, telling the members
    /// left.
    pub(crate) fn room_part(&mut self, room: u32, uid: Uid) -> bool {
        self.room_part_where(room, uid, |_| true)
    }

    /// [`RosterInner::room_part`], telling the members `pred` admits.
    fn room_part_where(
        &mut self,
        room: u32,
        uid: Uid,
        pred: impl Fn(&UserSession) -> bool,
    ) -> bool {
        self.voice_part_room(uid, room);
        let Some(entry) = self.rooms.get_mut(&room) else {
            return false;
        };
        let Some(pos) = entry.members.iter().position(|u| *u == uid) else {
            return false;
        };
        entry.members.remove(pos);
        self.room_send_where(room, Event::ChatUserParted { cid: room, uid }, pred);
        true
    }

    /// Part every member a room no longer admits: a gate narrowed, an
    /// account changed, a room archived or gone (§5). Each parted session
    /// is told once, and the members who stay hear one part for each, so
    /// a room emptied at once costs each of its members one event.
    pub(crate) fn room_reconcile(&mut self) {
        let rooms: Vec<u32> = self.rooms.keys().copied().collect();
        for room in rooms {
            let entry = &self.rooms[&room];
            let (stay, lost): (Vec<Uid>, Vec<Uid>) = entry
                .members
                .iter()
                .partition(|uid| self.users.get(uid).is_some_and(|s| admits(s, &entry.room)));
            if lost.is_empty() {
                continue;
            }
            let reason = if entry.room.archived_at.is_some() || entry.room.deleted {
                PartReason::Archived
            } else {
                PartReason::Access
            };
            self.rooms.get_mut(&room).expect("listed above").members = stay.clone();
            let about = |event| Event::InRoom {
                room,
                event: Box::new(event),
            };
            for &uid in &lost {
                self.voice_part_room(uid, room);
                // Why is the parted session's business alone.
                self.send_to(uid, about(Event::RoomParted { uid, reason }));
                for &member in &stay {
                    self.send_to(member, about(Event::ChatUserParted { cid: room, uid }));
                }
            }
        }
    }

    /// Whether `sess`, as `uid`, may send in `room` now: in it, and let
    /// post. A room it may not see is a chat that does not exist.
    pub(crate) fn room_send_check(
        &self,
        room: u32,
        uid: Uid,
        sess: &UserSession,
    ) -> Result<(), crate::ChatError> {
        let entry = self
            .rooms
            .get(&room)
            .filter(|e| sees(sess, &e.room))
            .ok_or(crate::ChatError::NoSuchChat)?;
        if !entry.members.contains(&uid) {
            return Err(crate::ChatError::NotAMember);
        }
        if !may_post(sess, &entry.room) {
            return Err(crate::ChatError::ReadOnly);
        }
        Ok(())
    }

    /// A member of `room` invites `target` (§6.3), refused in a private
    /// chat's order; a room either of them may not see is a chat that
    /// does not exist.
    pub(crate) fn room_invite(
        &mut self,
        room: u32,
        by: Uid,
        target: Uid,
    ) -> Result<(), crate::ChatError> {
        use crate::ChatError;
        let (Some(inviter), Some(invitee)) = (self.users.get(&by), self.users.get(&target)) else {
            return Err(ChatError::NoSuchUser);
        };
        let entry = self.rooms.get(&room).ok_or(ChatError::NoSuchChat)?;
        if !sees(inviter, &entry.room) {
            return Err(ChatError::NoSuchChat);
        }
        if !entry.members.contains(&by) {
            return Err(ChatError::NotAMember);
        }
        if !sees(invitee, &entry.room) {
            return Err(ChatError::NoSuchChat);
        }
        if entry.members.contains(&target) {
            return Err(ChatError::AlreadyThere);
        }
        let ev = Event::ChatInvite {
            cid: room,
            from: by,
            from_nick: inviter.info.nick.clone(),
        };
        self.send_to(target, ev);
        Ok(())
    }

    /// Every room `uid` is in, parted, as its session ends. A rooms-aware
    /// session is not told: the session's own departure says it, and a
    /// part as well would be the same news twice (§7.3).
    pub(crate) fn room_leave_all(&mut self, uid: Uid) {
        let rooms: Vec<u32> = self
            .rooms
            .iter()
            .filter(|(_, e)| e.members.contains(&uid))
            .map(|(id, _)| *id)
            .collect();
        for room in rooms {
            self.room_part_where(room, uid, |s| !s.rooms_aware);
        }
    }

    /// Send `event` about `room`'s lines to every session that may read
    /// them, member or not, since one that paged them holds them too: a
    /// rooms-aware one, or a member, whose wire shows redactions.
    pub(crate) fn room_readers_send(&mut self, room: u32, event: Event) {
        let Some(entry) = self.rooms.get(&room) else {
            return;
        };
        let readers: Vec<Uid> = self
            .users
            .iter()
            .filter(|(uid, s)| {
                s.info.transport.redactions
                    && sees(s, &entry.room)
                    && (s.rooms_aware || entry.members.contains(uid))
            })
            .map(|(uid, _)| *uid)
            .collect();
        let ev = Event::InRoom {
            room,
            event: Box::new(event),
        };
        for uid in readers {
            self.send_to(uid, ev.clone());
        }
    }

    /// What the rooms-aware sessions are shown of the rooms, of `rooms`
    /// and to `uids` where given, for [`RosterInner::room_announce`] to
    /// compare with after a change.
    pub(crate) fn room_shown(&self, rooms: Option<&[u32]>, uids: Option<&[Uid]>) -> Shown {
        let entries: Vec<&RoomEntry> = match rooms {
            Some(ids) => ids.iter().filter_map(|id| self.rooms.get(id)).collect(),
            None => self.rooms.values().collect(),
        };
        let mut shown = Shown::new();
        let sessions: Vec<(&Uid, &UserSession)> = match uids {
            Some(uids) => uids
                .iter()
                .filter_map(|uid| self.users.get_key_value(uid))
                .collect(),
            None => self.users.iter().collect(),
        };
        for (uid, sess) in sessions.into_iter().filter(|(_, s)| s.rooms_aware) {
            for entry in entries.iter().filter(|e| listed(sess, &e.room)) {
                shown.insert((*uid, entry.room.id), listed_as(sess, &entry.room));
            }
        }
        shown
    }

    /// Tell each rooms-aware session how its listing changed since
    /// `before`, taken with the same `rooms` and `uids`: a room gone from
    /// it, one new to it, and one that changed, except a topic to a
    /// member, which heard it as the room's subject.
    pub(crate) fn room_announce(
        &mut self,
        before: Shown,
        rooms: Option<&[u32]>,
        uids: Option<&[Uid]>,
    ) {
        let after = self.room_shown(rooms, uids);
        let members: HashSet<(u32, Uid)> = self
            .rooms
            .iter()
            .filter(|(id, _)| rooms.is_none_or(|ids| ids.contains(id)))
            .flat_map(|(id, e)| e.members.iter().map(move |uid| (*id, *uid)))
            .collect();
        let mut sends = Vec::new();
        for &(uid, room) in before.keys().filter(|k| !after.contains_key(k)) {
            sends.push((uid, Event::RoomRemoved { room }));
        }
        for (&(uid, room), now) in &after {
            let (Some(sess), Some(entry)) = (self.users.get(&uid), self.rooms.get(&room)) else {
                continue;
            };
            let added = match before.get(&(uid, room)) {
                None => true,
                Some(was) if was == now => continue,
                Some(was) => {
                    let topic_only = Listed {
                        topic: now.topic.clone(),
                        ..was.clone()
                    } == *now;
                    if topic_only && members.contains(&(room, uid)) {
                        continue;
                    }
                    false
                }
            };
            let view = Box::new(view(self, sess, entry));
            let ev = if added {
                Event::RoomAdded(view)
            } else {
                Event::RoomChanged(view)
            };
            sends.push((uid, ev));
        }
        for (uid, ev) in sends {
            self.send_to(uid, ev);
        }
    }

    /// The live rooms, for a census.
    pub(crate) fn room_count(&self) -> usize {
        self.rooms
            .values()
            .filter(|e| !e.room.deleted && e.room.archived_at.is_none())
            .count()
    }
}

/// A room as one session may see it listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomView {
    pub room: Room,
    pub members: usize,
    /// The newest line in it, where there is a log.
    pub last_id: Option<LineId>,
    pub may_post: bool,
    /// Whether the viewer manages rooms, and so may be told the gates.
    pub manages: bool,
}

impl Core {
    /// Keep rooms in `store`, held to `policy`: the file is read now, an
    /// entry without an id is given one and written back, and a file that
    /// cannot be read is an error, because a server that came up without
    /// its rooms would also have lost their gates (§4). After
    /// [`Core::with_history`], whose channels no room id may be.
    pub fn with_rooms(
        mut self,
        store: Arc<dyn RoomStore>,
        policy: RoomPolicy,
    ) -> Result<Self, String> {
        self.room_state.store = Some(store);
        self.room_state.policy = policy;
        if let Some(log) = self.history.as_ref() {
            let channels = log.channels().map_err(|e| format!("chat history: {e}"))?;
            let mut r = self.roster.lock().unwrap();
            for (channel, id) in channels {
                r.taken_ids.insert(channel);
                r.last_ids.insert(channel, id);
            }
        }
        let file = self.reload_rooms()?;
        // The lobby's subject is the server's to write; the file keeps it
        // across a restart.
        self.roster.lock().unwrap().lobby_topic = file.lobby;
        Ok(self)
    }

    /// Does this server keep rooms?
    pub fn rooms_enabled(&self) -> bool {
        self.room_state.store.is_some()
    }

    /// `[rooms]`'s limits and the lobby's name, where there are rooms.
    pub fn room_policy(&self) -> Option<&RoomPolicy> {
        self.rooms_enabled().then_some(&self.room_state.policy)
    }

    /// `uid` has asked about rooms on a wire that shows them (§7): from
    /// now on it is told of the rooms it may see changing, and of a
    /// redaction in one it may read. Kept with the session, so a resume
    /// keeps it.
    pub fn rooms_aware(&self, uid: Uid) {
        if self.rooms_enabled() {
            if let Some(sess) = self.roster.lock().unwrap().users.get_mut(&uid) {
                sess.rooms_aware = true;
            }
        }
    }

    /// May this session manage rooms?
    pub fn manages_rooms(&self, uid: Uid) -> bool {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).is_some_and(|s| s.manage_rooms)
    }

    /// The newest line logged in `room`, 0 the lobby, where there is a log.
    pub fn last_line_id(&self, room: u32) -> Option<LineId> {
        self.roster.lock().unwrap().last_ids.get(&room).copied()
    }

    /// Read the rooms file again (SIGHUP), give entries without an id one
    /// and write them back, and apply the difference: a room archived or
    /// gone parts its members, a narrowed gate parts whoever it no longer
    /// admits. A file that cannot be read leaves the rooms as they were.
    /// Answers the file as applied.
    pub fn reload_rooms(&self) -> Result<RoomFile, String> {
        let Some(store) = self.room_state.store.as_ref() else {
            return Ok(RoomFile::default());
        };
        let _writes = self.room_state.writes.lock().unwrap();
        // Topics set since the last write go to the file first, so that
        // what is read back is current.
        self.flush_topics(store.as_ref(), true);
        let mut file = store.load().map_err(|e| e.to_string())?;
        check_file(&file)?;
        // As one that does not parse: a reload may then announce at most
        // so many rooms to each session at once.
        let max = self.room_state.policy.max_rooms;
        if file.rooms.len() > max {
            return Err(format!(
                "{} entries, past [rooms] max_rooms {max}",
                file.rooms.len()
            ));
        }
        let mut drawn = Vec::new();
        let purge: Vec<u32>;
        {
            let mut r = self.roster.lock().unwrap();
            if let Some(room) = file
                .rooms
                .iter()
                .find(|room| r.chats.contains_key(&room.id) && !r.rooms.contains_key(&room.id))
            {
                return Err(format!("room id {} is a private chat's", room.id));
            }
            // A tombstone this server has not yet seen is a room deleted
            // since: its lines go once its members are parted, below.
            purge = file
                .rooms
                .iter()
                .filter(|room| {
                    room.deleted && !r.rooms.get(&room.id).is_some_and(|e| e.room.deleted)
                })
                .map(|room| room.id)
                .collect();
            for room in &file.rooms {
                r.taken_ids.insert(room.id);
            }
            for room in file.rooms.iter_mut().filter(|r| r.id == 0 && !r.deleted) {
                room.id = r.next_chat_id().ok_or("no room id could be drawn")?;
                r.taken_ids.insert(room.id);
                drawn.push(room.clone());
            }
        }
        for room in &drawn {
            store
                .put(room)
                .map_err(|e| format!("writing room {}'s id: {e}", room.name))?;
        }
        let mut r = self.roster.lock().unwrap();
        // A topic set since the flush above, or not written by it, is
        // newer than the file's.
        let mut dirty = self.room_state.dirty.lock().unwrap().clone();
        dirty.extend(self.room_state.unwritten.lock().unwrap().iter());
        // Only the entries that changed: a reload changes no session.
        let changed: Vec<u32> = file
            .rooms
            .iter()
            .filter(|room| r.rooms.get(&room.id).is_none_or(|e| e.room != **room))
            .map(|room| room.id)
            .chain(
                r.rooms
                    .keys()
                    .copied()
                    .filter(|id| !file.rooms.iter().any(|room| room.id == *id)),
            )
            .collect();
        let before = r.room_shown(Some(&changed), None);
        let mut old = std::mem::take(&mut r.rooms);
        for room in file.rooms.iter().filter(|r| r.id != 0) {
            let mut room = room.clone();
            let members = match old.remove(&room.id) {
                Some(was) => {
                    if dirty.contains(&room.id) {
                        room.topic = was.room.topic;
                    }
                    was.members
                }
                None => Vec::new(),
            };
            r.rooms.insert(room.id, RoomEntry { room, members });
        }
        // A room taken out of the file by hand is a room deleted: its
        // members are parted, and its id stays taken.
        for (id, mut entry) in old {
            entry.room.deleted = true;
            r.rooms.insert(id, entry);
        }
        r.room_reconcile();
        r.rooms
            .retain(|id, _| file.rooms.iter().any(|room| room.id == *id));
        r.room_announce(before, Some(&changed), None);
        drop(r);
        if let Some(log) = self.history.as_ref() {
            for id in purge {
                // Under the room's serial, so no line committed meanwhile
                // outlives the purge.
                let channel = self.room_channel(id);
                let _serial = channel.serial.lock().unwrap();
                if let Err(e) = log.delete_channel(id) {
                    warn!("rooms: deleted room {id}'s lines would not go: {e}");
                }
            }
        }
        Ok(file)
    }

    /// Write the topics changed since the last write (§4), and with
    /// `retry` the ones whose write failed. The binary calls this every
    /// few seconds without `retry`, so a file that cannot be written is
    /// not complained about every few seconds, and at shutdown with it.
    pub fn flush_room_topics(&self, retry: bool) {
        if let Some(store) = self.room_state.store.as_ref() {
            let _writes = self.room_state.writes.lock().unwrap();
            self.flush_topics(store.as_ref(), retry);
        }
    }

    /// Under the rooms-write lock.
    fn flush_topics(&self, store: &dyn RoomStore, retry: bool) {
        let mut ids = std::mem::take(&mut *self.room_state.dirty.lock().unwrap());
        if retry {
            ids.append(&mut self.room_state.unwritten.lock().unwrap());
        }
        for id in ids {
            let topic = {
                let r = self.roster.lock().unwrap();
                match id {
                    0 => Some(r.lobby_topic.clone()),
                    id => r.rooms.get(&id).map(|e| e.room.topic.clone()),
                }
            };
            let Some(topic) = topic else { continue };
            match store.put_topic(id, &topic) {
                Ok(()) => {
                    self.room_state.unwritten.lock().unwrap().remove(&id);
                }
                Err(e) => {
                    warn!("rooms: a topic would not write: {e}");
                    self.room_state.unwritten.lock().unwrap().insert(id);
                }
            }
        }
    }

    /// A topic changed in memory, for the file to catch up with.
    pub(crate) fn topic_changed(&self, id: u32) {
        if self.room_state.store.is_some() {
            self.room_state.dirty.lock().unwrap().insert(id);
        }
    }

    /// This room's commit queue and serial.
    pub(crate) fn room_channel(&self, room: u32) -> Arc<RoomChannel> {
        self.room_state
            .channels
            .lock()
            .unwrap()
            .entry(room)
            .or_insert_with(|| {
                Arc::new(RoomChannel {
                    commit: ChatCommit::for_room(room),
                    serial: TimedMutex::default(),
                })
            })
            .clone()
    }

    /// Make a room, for a session that may manage rooms.
    pub fn room_create(&self, uid: Uid, edit: RoomEdit) -> Result<Room, RoomError> {
        if edit.name.is_none() {
            return Err(RoomError::Invalid("a room needs a name"));
        }
        self.room_write(uid, None, |room, by, now| edit.apply(room, by, now))
    }

    /// Change a room, for a session that may manage rooms. A narrowed
    /// gate parts whoever it no longer admits.
    pub fn room_edit(&self, uid: Uid, id: u32, edit: RoomEdit) -> Result<Room, RoomError> {
        self.room_write(uid, Some(id), |room, by, now| edit.apply(room, by, now))
    }

    /// Archive a room, parting its members, or bring one back.
    pub fn room_archive(&self, uid: Uid, id: u32, archive: bool) -> Result<Room, RoomError> {
        self.room_write(uid, Some(id), |room, _, now| {
            room.archived_at = archive.then_some(now);
            Ok(())
        })
    }

    /// The manage path: the change made to a copy, the copy written to
    /// the file, and only then to the roster, all under the rooms-write
    /// lock. A new room's id is drawn and taken before the write, so a
    /// private chat cannot draw it meanwhile.
    fn room_write(
        &self,
        uid: Uid,
        id: Option<u32>,
        change: impl FnOnce(&mut Room, &str, SystemTime) -> Result<(), RoomError>,
    ) -> Result<Room, RoomError> {
        let store = self.room_state.store.as_ref().ok_or(RoomError::Disabled)?;
        let _writes = self.room_state.writes.lock().unwrap();
        let (mut room, by) = {
            let mut r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(RoomError::AccessDenied)?;
            if !sess.manage_rooms {
                return Err(RoomError::AccessDenied);
            }
            let by = sess.info.nick.clone();
            let room = match id {
                Some(id) => r
                    .rooms
                    .get(&id)
                    .filter(|e| !e.room.deleted)
                    .map(|e| e.room.clone())
                    .ok_or(RoomError::NoSuchRoom)?,
                None => {
                    if r.rooms.len() >= self.room_state.policy.max_rooms {
                        return Err(RoomError::RoomsFull);
                    }
                    let id = r.next_chat_id().ok_or(RoomError::ServerError)?;
                    r.taken_ids.insert(id);
                    Room {
                        id,
                        ..Room::default()
                    }
                }
            };
            (room, by)
        };
        let topic = room.topic.clone();
        change(&mut room, &by, SystemTime::now())?;
        let topic_set = room.topic != topic;
        if self
            .roster
            .lock()
            .unwrap()
            .rooms
            .values()
            .any(|e| e.room.id != room.id && !e.room.deleted && e.room.name == room.name)
        {
            return Err(RoomError::NameTaken);
        }
        store.put(&room).map_err(|e| {
            warn!("rooms: {e}");
            RoomError::ServerError
        })?;
        let mut r = self.roster.lock().unwrap();
        let before = r.room_shown(Some(&[room.id]), None);
        let entry = r.rooms.entry(room.id).or_insert_with(|| RoomEntry {
            room: room.clone(),
            members: Vec::new(),
        });
        // A topic set meanwhile is newer than the one this edit read.
        if !topic_set {
            room.topic = entry.room.topic.clone();
        }
        entry.room = room.clone();
        r.room_reconcile();
        if topic_set {
            let subject = Event::ChatSubject {
                cid: room.id,
                subject: room.topic.text.clone(),
            };
            r.room_send_where(room.id, subject, |_| true);
        }
        r.room_announce(before, Some(&[room.id]), None);
        Ok(room)
    }

    /// Join a room: who is in it, the joiner included, and its topic. A
    /// join of a room the session is already in is answered as the first
    /// was, and tells nobody again.
    pub fn room_join(&self, uid: Uid, id: u32) -> Result<(Vec<UserInfo>, Topic), RoomError> {
        let mut r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid).ok_or(RoomError::NoSuchRoom)?;
        let entry = r
            .rooms
            .get(&id)
            .filter(|e| admits(sess, &e.room))
            .ok_or(RoomError::NoSuchRoom)?;
        let me = sess.info.clone();
        let topic = entry.room.topic.clone();
        if !entry.members.contains(&uid) {
            let joined = r
                .rooms
                .values()
                .filter(|e| e.members.contains(&uid))
                .count();
            if joined >= self.room_state.policy.max_joined {
                return Err(RoomError::TooManyRooms);
            }
            r.room_send_where(id, Event::ChatUserJoined { cid: id, user: me }, |_| true);
            r.rooms.get_mut(&id).expect("found above").members.push(uid);
        }
        let members = r.rooms[&id]
            .members
            .iter()
            .filter_map(|m| r.users.get(m).map(|s| s.info.clone()))
            .collect();
        Ok((members, topic))
    }

    /// Leave a room, and its voice room.
    pub fn room_part(&self, uid: Uid, id: u32) -> Result<(), RoomError> {
        let mut r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid).ok_or(RoomError::NoSuchRoom)?;
        if !r.rooms.get(&id).is_some_and(|e| sees(sess, &e.room)) {
            return Err(RoomError::NoSuchRoom);
        }
        if !r.room_part(id, uid) {
            return Err(RoomError::NotAMember);
        }
        Ok(())
    }

    /// Set a room's topic: whoever may post in it and set the lobby's
    /// subject may (§5), member or not; its members hear it. The lobby's
    /// is [`Core::chat_subject`]'s.
    pub fn room_topic(&self, uid: Uid, id: u32, text: String) -> Result<(), RoomError> {
        {
            let mut r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(RoomError::NoSuchRoom)?;
            let entry = r
                .rooms
                .get(&id)
                .filter(|e| sees(sess, &e.room))
                .ok_or(RoomError::NoSuchRoom)?;
            if !(sess.set_subject && may_post(sess, &entry.room)) {
                return Err(RoomError::AccessDenied);
            }
            let text: String = text.chars().take(TOPIC_MAX).collect();
            let before = r.room_shown(Some(&[id]), None);
            let topic = Topic {
                text: text.clone(),
                by: sess.info.nick.clone(),
                at: Some(SystemTime::now()),
            };
            r.rooms.get_mut(&id).expect("found above").room.topic = topic;
            r.room_send_where(
                id,
                Event::ChatSubject {
                    cid: id,
                    subject: text,
                },
                |_| true,
            );
            r.room_announce(before, Some(&[id]), None);
            // Under the roster's lock, so a reload that holds it sees
            // the topic is newer than the file's.
            self.topic_changed(id);
        }
        Ok(())
    }

    /// The rooms `uid` is in, lowest id first.
    pub fn rooms_of(&self, uid: Uid) -> Vec<u32> {
        let r = self.roster.lock().unwrap();
        let mut ids: Vec<u32> = r
            .rooms
            .iter()
            .filter(|(_, e)| e.members.contains(&uid))
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The rooms `uid` may see and are not archived, by position and then
    /// name.
    pub fn room_list(&self, uid: Uid) -> Vec<RoomView> {
        let r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get(&uid) else {
            return Vec::new();
        };
        let mut list: Vec<RoomView> = r
            .rooms
            .values()
            .filter(|e| listed(sess, &e.room))
            .map(|e| view(&r, sess, e))
            .collect();
        list.sort_by(|a, b| (a.room.position, &a.room.name).cmp(&(b.room.position, &b.room.name)));
        list
    }

    /// `room` as `uid` sees it, if it may.
    pub fn room_view(&self, uid: Uid, room: u32) -> Option<RoomView> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid)?;
        let entry = r.rooms.get(&room).filter(|e| sees(sess, &e.room))?;
        Some(view(&r, sess, entry))
    }

    /// Is `id` a room's, rather than a private chat's or nobody's? Says
    /// nothing about who may see it: what a transaction naming it is
    /// answered decides that.
    pub fn is_room(&self, id: u32) -> bool {
        id != 0 && self.roster.lock().unwrap().rooms.contains_key(&id)
    }

    /// `room`'s name, while it has one.
    pub fn room_name(&self, room: u32) -> Option<String> {
        let r = self.roster.lock().unwrap();
        r.rooms
            .get(&room)
            .map(|e| e.room.name.clone())
            .filter(|n| !n.is_empty())
    }

    /// [`Core::room_list`], the rooms `uid` is in first.
    pub fn room_list_members_first(&self, uid: Uid) -> Vec<RoomView> {
        let joined = self.rooms_of(uid);
        let mut list = self.room_list(uid);
        list.sort_by_key(|v| !joined.contains(&v.room.id));
        list
    }

    /// The lobby notice a classic session is sent after its user list
    /// (§6.5), when it is to be sent: a room it may see, bit 9, commands
    /// to point at, and not already told today.
    pub fn rooms_announcement(&self, uid: Uid) -> Option<String> {
        let policy = self.room_policy().filter(|p| p.announce)?;
        let system = self.system.as_ref().filter(|s| s.policy.commands)?;
        let key = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid)?;
            if !sess.access.has(bit::READ_CHAT) {
                return None;
            }
            let guest = sess.login == "guest" && sess.identity.is_none();
            (
                sess.login.clone(),
                sess.identity,
                sess.addr.filter(|_| guest),
            )
        };
        let list = self.room_list_members_first(uid);
        if list.is_empty() {
            return None;
        }
        let now = self.clock.now();
        const DAY: Duration = Duration::from_secs(24 * 3600);
        {
            let mut told = self.room_state.announced.lock().unwrap();
            if told
                .get(&key)
                .is_some_and(|at| now.saturating_duration_since(*at) < DAY)
            {
                return None;
            }
            if told.len() >= ANNOUNCED_KEPT {
                told.retain(|_, at| now.saturating_duration_since(*at) < DAY);
            }
            // Past the bound with the day's own, the oldest is forgotten
            // first: the one most nearly due again anyway.
            if told.len() >= ANNOUNCED_KEPT {
                if let Some(oldest) = told
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| k.clone())
                {
                    told.remove(&oldest);
                }
            }
            told.insert(key, now);
        }
        let names: Vec<String> = list
            .iter()
            .take(policy.announce_names)
            .map(|v| format!("#{}", v.room.name))
            .collect();
        let more = list.len() - names.len();
        let rooms = match (names.is_empty(), more) {
            (true, n) => format!("{n}"),
            (false, 0) => names.join(", "),
            (false, n) => format!("{} and {n} more", names.join(", ")),
        };
        Some(format!(
            "Rooms: {rooms}. Send /rooms to {} to see them, /join <name> to join one.",
            system.policy.nick
        ))
    }

    /// Is `uid` in `room`, may it send there, and is the room one it can
    /// see at all? For a chat line: nothing about a room it may not see
    /// is told apart from a room that does not exist.
    pub(crate) fn room_may_send(&self, uid: Uid, room: u32) -> Result<(), crate::ChatError> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid).ok_or(crate::ChatError::NoSuchUser)?;
        r.room_send_check(room, uid, sess)
    }

    /// May `uid` read `room`'s lines, in history or a report?
    pub(crate) fn room_readable(&self, uid: Uid, room: u32) -> bool {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .zip(r.rooms.get(&room))
            .is_some_and(|(sess, e)| sees(sess, &e.room))
    }

    /// Each room with a retention of its own, as the log takes it:
    /// `(channel, max_lines, max_age)` over `max_lines` and `max_age`.
    pub(crate) fn room_retention(
        &self,
        max_lines: usize,
        max_age: Option<Duration>,
    ) -> Vec<(u32, usize, Option<Duration>)> {
        let r = self.roster.lock().unwrap();
        r.rooms
            .values()
            .filter(|e| e.room.max_lines.is_some() || e.room.max_days.is_some())
            .map(|e| {
                let days = |d: u32| Duration::from_secs(u64::from(d) * 24 * 3600);
                (
                    e.room.id,
                    e.room.max_lines.map_or(max_lines, |n| n as usize),
                    e.room
                        .max_days
                        .map_or(max_age, |d| (d != 0).then(|| days(d))),
                )
            })
            .collect()
    }
}

/// What a file must be to be loaded: ids and live names unique, names and
/// gates well formed. Anything else is a file that does not parse.
fn check_file(file: &RoomFile) -> Result<(), String> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for room in &file.rooms {
        if room.id != 0 && !ids.insert(room.id) {
            return Err(format!("room id {} is given twice", room.id));
        }
        if room.deleted {
            continue;
        }
        if !valid_name(&room.name) {
            return Err(format!(
                "{:?} is not a room name: 1 to 32 lowercase letters, digits, - and _",
                room.name
            ));
        }
        if !names.insert(room.name.as_str()) {
            return Err(format!("two rooms are named {:?}", room.name));
        }
        if let Some(bad) = room
            .read
            .iter()
            .chain(&room.post)
            .find(|e| !valid_entry(e, false))
        {
            return Err(format!(
                "room {}: {bad:?} is not a login or @role",
                room.name
            ));
        }
    }
    Ok(())
}

/// The suite every [`RoomStore`] passes.
pub mod conformance {
    use super::*;

    pub fn run(new_store: &dyn Fn() -> Box<dyn RoomStore>) {
        an_empty_store_holds_nothing(new_store());
        a_room_round_trips_whole(new_store());
        an_entry_written_without_an_id_is_given_one_in_place(new_store());
        a_put_replaces_by_id_and_keeps_the_rest(new_store());
        a_tombstone_keeps_its_id_alone(new_store());
        a_topic_is_written_alone(new_store());
    }

    fn room(id: u32, name: &str) -> Room {
        Room {
            id,
            name: name.into(),
            ..Room::default()
        }
    }

    fn an_empty_store_holds_nothing(store: Box<dyn RoomStore>) {
        assert_eq!(store.load().unwrap(), RoomFile::default());
    }

    fn a_room_round_trips_whole(store: Box<dyn RoomStore>) {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_500_000);
        let full = Room {
            id: 2_754_100_983,
            name: "staff".into(),
            topic: Topic {
                text: "the backroom".into(),
                by: "alice".into(),
                at: Some(at),
            },
            position: -3,
            read: vec!["carol".into(), "@moderators".into()],
            post: vec!["carol".into()],
            max_lines: Some(50_000),
            max_days: Some(30),
            archived_at: Some(at),
            deleted: false,
        };
        store.put(&full).unwrap();
        assert_eq!(store.load().unwrap().rooms, [full]);
    }

    fn an_entry_written_without_an_id_is_given_one_in_place(store: Box<dyn RoomStore>) {
        store.put(&room(0, "lounge")).unwrap();
        store.put(&room(0, "music")).unwrap();
        store.put(&room(17, "lounge")).unwrap();
        let rooms = store.load().unwrap().rooms;
        assert_eq!(rooms, [room(17, "lounge"), room(0, "music")]);
    }

    fn a_put_replaces_by_id_and_keeps_the_rest(store: Box<dyn RoomStore>) {
        store.put(&room(1, "lounge")).unwrap();
        store.put(&room(2, "music")).unwrap();
        let renamed = Room {
            position: 4,
            post: vec!["dj".into()],
            ..room(1, "hangout")
        };
        store.put(&renamed).unwrap();
        assert_eq!(store.load().unwrap().rooms, [renamed, room(2, "music")]);
    }

    fn a_tombstone_keeps_its_id_alone(store: Box<dyn RoomStore>) {
        store
            .put(&Room {
                topic: Topic {
                    text: "gone soon".into(),
                    ..Topic::default()
                },
                read: vec!["carol".into()],
                ..room(5, "old-news")
            })
            .unwrap();
        store.put(&Room::tombstone(5)).unwrap();
        assert_eq!(store.load().unwrap().rooms, [Room::tombstone(5)]);
    }

    fn a_topic_is_written_alone(store: Box<dyn RoomStore>) {
        let at = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000));
        let topic = |text: &str| Topic {
            text: text.into(),
            by: "bob".into(),
            at,
        };
        store
            .put(&Room {
                read: vec!["carol".into()],
                ..room(3, "lounge")
            })
            .unwrap();
        store.put_topic(3, &topic("hi")).unwrap();
        store.put_topic(0, &topic("welcome")).unwrap();
        let file = store.load().unwrap();
        assert_eq!(file.lobby, topic("welcome"));
        assert_eq!(
            file.rooms,
            [Room {
                topic: topic("hi"),
                read: vec!["carol".into()],
                ..room(3, "lounge")
            }]
        );
    }

    #[cfg(test)]
    #[test]
    fn memory_rooms_pass() {
        run(&|| Box::<MemoryRooms>::default());
    }
}

#[cfg(test)]
mod tests;
