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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomPolicy {
    /// Rooms one session may be in at once.
    pub max_joined: usize,
    /// Entries the file may hold, archived rooms and tombstones included,
    /// so rooms cannot be made, filled and archived without end.
    pub max_rooms: usize,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        RoomPolicy {
            max_joined: 32,
            max_rooms: 256,
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
}

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
        self.voice_part_room(uid, room);
        let Some(entry) = self.rooms.get_mut(&room) else {
            return false;
        };
        let Some(pos) = entry.members.iter().position(|u| *u == uid) else {
            return false;
        };
        entry.members.remove(pos);
        self.room_send_where(room, Event::ChatUserParted { cid: room, uid }, |_| true);
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
            self.rooms.get_mut(&room).expect("listed above").members = stay.clone();
            for &uid in &lost {
                self.voice_part_room(uid, room);
                let parted = |uid| Event::InRoom {
                    room,
                    event: Box::new(Event::ChatUserParted { cid: room, uid }),
                };
                self.send_to(uid, parted(uid));
                for &member in &stay {
                    self.send_to(member, parted(uid));
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

    /// Every room `uid` is in, parted, as its session ends.
    pub(crate) fn room_leave_all(&mut self, uid: Uid) {
        let rooms: Vec<u32> = self
            .rooms
            .iter()
            .filter(|(_, e)| e.members.contains(&uid))
            .map(|(id, _)| *id)
            .collect();
        for room in rooms {
            self.room_part(room, uid);
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

    /// The rooms `uid` may see, by position and then name.
    pub fn room_list(&self, uid: Uid) -> Vec<RoomView> {
        let r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get(&uid) else {
            return Vec::new();
        };
        let mut list: Vec<RoomView> = r
            .rooms
            .values()
            .filter(|e| sees(sess, &e.room))
            .map(|e| RoomView {
                room: e.room.clone(),
                members: e.members.len(),
                last_id: r.last_ids.get(&e.room.id).copied(),
                may_post: may_post(sess, &e.room),
            })
            .collect();
        list.sort_by(|a, b| (a.room.position, &a.room.name).cmp(&(b.room.position, &b.room.name)));
        list
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
