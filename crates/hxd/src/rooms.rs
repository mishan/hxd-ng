//! `[rooms]`, the rooms file (`docs/chat-rooms.md` §4) and `hxd room`.
//!
//! The file is the operator's to read and edit as well as the server's,
//! so every write goes through `toml_edit` and touches one entry: what
//! nobody changed, and every comment, stays as it was. A write replaces
//! the file whole. `hxd room` edits it beside a running server, which
//! applies the edit on SIGHUP and gives a new entry its id then: only the
//! running server knows which ids its private chats hold.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hxd_core::{Core, Room, RoomEdit, RoomFile, RoomPolicy, RoomStore, StoreError, Topic};
use serde::Deserialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

use crate::Config;

/// `[rooms]` (§12). Every key optional.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomsSection {
    #[serde(default = "crate::default_true")]
    pub enabled: bool,
    /// Relative to the working directory, as every path here is.
    #[serde(default = "default_file")]
    pub file: PathBuf,
    /// The lobby's name in listings.
    #[serde(default = "default_lobby")]
    pub lobby: String,
    #[serde(default = "default_max_joined")]
    pub max_joined: usize,
    /// Every entry, archived rooms and tombstones included.
    #[serde(default = "default_max_rooms")]
    pub max_rooms: usize,
    /// The lobby notice to classic sessions (§6.5).
    #[serde(default = "crate::default_true")]
    pub announce: bool,
    #[serde(default = "default_announce_names")]
    pub announce_names: usize,
}

fn default_file() -> PathBuf {
    "rooms.toml".into()
}
fn default_lobby() -> String {
    "lobby".into()
}
fn default_max_joined() -> usize {
    32
}
fn default_max_rooms() -> usize {
    256
}
fn default_announce_names() -> usize {
    3
}

impl Default for RoomsSection {
    fn default() -> Self {
        RoomsSection {
            enabled: true,
            file: default_file(),
            lobby: default_lobby(),
            max_joined: default_max_joined(),
            max_rooms: default_max_rooms(),
            announce: true,
            announce_names: default_announce_names(),
        }
    }
}

impl RoomsSection {
    pub fn policy(&self) -> RoomPolicy {
        RoomPolicy {
            max_joined: self.max_joined,
            max_rooms: self.max_rooms,
            lobby: self.lobby.clone(),
        }
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        if !hxd_core::rooms::valid_name(&self.lobby) {
            return Err(format!(
                "[rooms] lobby {:?} is not a room name: 1 to 32 lowercase letters, digits, - \
                 and _",
                self.lobby
            ));
        }
        if self.max_joined == 0 || self.max_rooms == 0 {
            return Err("[rooms] max_joined and max_rooms are at least 1".into());
        }
        Ok(())
    }
}

/// Keep the domain's rooms in `[rooms] file`, when rooms are on.
pub fn with_rooms(core: Core, config: &Config) -> Result<Core, String> {
    if !config.rooms.enabled {
        return Ok(core);
    }
    core.with_rooms(
        Arc::new(FileRooms::new(&config.rooms.file)),
        config.rooms.policy(),
    )
}

/// Topics changed in memory reach the file every few seconds (§4).
pub async fn topic_flusher(core: Arc<Core>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let core = core.clone();
        let _ = crate::spawn_blocking("rooms", move || core.flush_room_topics(false)).await;
    }
}

/// The file as `toml` reads it: strictly, so that a key misspelled is a
/// file that does not parse rather than a gate quietly not there.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    #[serde(default)]
    lobby: TopicDoc,
    #[serde(default)]
    room: Vec<RoomDoc>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TopicDoc {
    topic: Option<String>,
    topic_by: Option<String>,
    topic_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomDoc {
    id: Option<u32>,
    name: Option<String>,
    topic: Option<String>,
    topic_by: Option<String>,
    topic_at: Option<u64>,
    position: Option<i64>,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    post: Vec<String>,
    max_lines: Option<u32>,
    max_days: Option<u32>,
    archived_at: Option<u64>,
    #[serde(default)]
    deleted: bool,
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64)
}

fn topic(text: Option<String>, by: Option<String>, when: Option<u64>) -> Topic {
    Topic {
        text: text.unwrap_or_default(),
        by: by.unwrap_or_default(),
        at: when.map(at),
    }
}

const USAGE: &str = "usage:\n  \
hxd [--config …] room list [--archived]\n  \
hxd [--config …] room create <name> [--topic T] [--read LOGIN,…] [--post LOGIN,…] [--position N]\n    \
[--max-lines N|default] [--max-days N|default]\n  \
hxd [--config …] room edit <name> [--name NEW] [the same flags as create]\n  \
hxd [--config …] room archive|unarchive <name>\n  \
hxd [--config …] room delete <name> --purge";

const HEADER: &str = "# Rooms on this server (docs/chat-rooms.md). `hxd room` and room\n\
# managers edit this file; an entry without an id is given one by the\n\
# server when it loads.\n";

/// The rooms file.
pub struct FileRooms {
    path: PathBuf,
}

impl FileRooms {
    pub fn new(path: &Path) -> FileRooms {
        FileRooms { path: path.into() }
    }

    fn fail(&self, e: impl std::fmt::Display) -> StoreError {
        StoreError::new(format!("{}: {e}", self.path.display()))
    }

    fn text(&self) -> Result<String, StoreError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(self.fail(e)),
        }
    }

    /// Read, change and write the file whole.
    fn edit(
        &self,
        change: impl FnOnce(&mut DocumentMut) -> Result<(), String>,
    ) -> Result<(), StoreError> {
        let text = self.text()?;
        let mut doc: DocumentMut = match text.is_empty() {
            true => HEADER.parse(),
            false => text.parse(),
        }
        .map_err(|e| self.fail(e))?;
        change(&mut doc).map_err(|e| self.fail(e))?;
        crate::link::write_whole(&self.path, &doc.to_string()).map_err(StoreError::new)
    }
}

/// Set `key` to `value`, or take it out for `None`, keeping a comment
/// written beside the value.
fn set(t: &mut Table, key: &str, value: Option<Value>) {
    match (value, t.get_mut(key).and_then(Item::as_value_mut)) {
        (None, _) => {
            t.remove(key);
        }
        (Some(mut value), Some(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        (Some(value), None) => {
            t.insert(key, Item::Value(value));
        }
    }
}

fn set_topic(t: &mut Table, topic: &Topic) {
    set(
        t,
        "topic",
        (!topic.text.is_empty()).then(|| topic.text.as_str().into()),
    );
    set(
        t,
        "topic_by",
        (!topic.by.is_empty()).then(|| topic.by.as_str().into()),
    );
    set(t, "topic_at", topic.at.map(|t| secs(t).into()));
}

fn list(entries: &[String]) -> Option<Value> {
    (!entries.is_empty())
        .then(|| Value::Array(entries.iter().map(String::as_str).collect::<Array>()))
}

fn write_room(t: &mut Table, room: &Room) {
    set(t, "id", (room.id != 0).then(|| i64::from(room.id).into()));
    if room.deleted {
        let keep = ["id", "deleted"];
        let gone: Vec<String> = t
            .iter()
            .map(|(k, _)| k.to_string())
            .filter(|k| !keep.contains(&k.as_str()))
            .collect();
        for key in gone {
            t.remove(&key);
        }
        set(t, "deleted", Some(true.into()));
        return;
    }
    set(t, "name", Some(room.name.as_str().into()));
    set_topic(t, &room.topic);
    set(
        t,
        "position",
        (room.position != 0).then(|| room.position.into()),
    );
    set(t, "read", list(&room.read));
    set(t, "post", list(&room.post));
    set(t, "max_lines", room.max_lines.map(|n| i64::from(n).into()));
    set(t, "max_days", room.max_days.map(|n| i64::from(n).into()));
    set(t, "archived_at", room.archived_at.map(|t| secs(t).into()));
    set(t, "deleted", None);
}

fn rooms_of(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables, String> {
    doc.entry("room")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| "`room` is not a list of [[room]] tables".to_string())
}

fn id_of(t: &Table) -> Option<i64> {
    t.get("id").and_then(Item::as_integer)
}

impl RoomStore for FileRooms {
    fn load(&self) -> Result<RoomFile, StoreError> {
        let doc: FileDoc = toml::from_str(&self.text()?).map_err(|e| self.fail(e))?;
        Ok(RoomFile {
            lobby: topic(doc.lobby.topic, doc.lobby.topic_by, doc.lobby.topic_at),
            rooms: doc
                .room
                .into_iter()
                .map(|r| Room {
                    id: r.id.unwrap_or(0),
                    name: r.name.unwrap_or_default(),
                    topic: topic(r.topic, r.topic_by, r.topic_at),
                    position: r.position.unwrap_or(0),
                    read: r.read,
                    post: r.post,
                    max_lines: r.max_lines,
                    max_days: r.max_days,
                    archived_at: r.archived_at.map(at),
                    deleted: r.deleted,
                })
                .collect(),
        })
    }

    fn put(&self, room: &Room) -> Result<(), StoreError> {
        self.edit(|doc| {
            let rooms = rooms_of(doc)?;
            let id = i64::from(room.id);
            let at = rooms
                .iter()
                .position(|t| room.id != 0 && id_of(t) == Some(id))
                .or_else(|| {
                    rooms.iter().position(|t| {
                        id_of(t).is_none()
                            && t.get("deleted").and_then(Item::as_bool) != Some(true)
                            && t.get("name").and_then(Item::as_str) == Some(room.name.as_str())
                    })
                });
            let table = match at {
                Some(i) => rooms.get_mut(i).expect("found above"),
                None => {
                    rooms.push(Table::new());
                    rooms.iter_mut().last().expect("just pushed")
                }
            };
            write_room(table, room);
            Ok(())
        })
    }

    fn put_topic(&self, id: u32, topic: &Topic) -> Result<(), StoreError> {
        self.edit(|doc| {
            let table = if id == 0 {
                doc.entry("lobby")
                    .or_insert(Item::Table(Table::new()))
                    .as_table_mut()
                    .ok_or("`lobby` is not a table")?
            } else {
                match rooms_of(doc)?
                    .iter_mut()
                    .find(|t| id_of(t) == Some(i64::from(id)))
                {
                    Some(t) => t,
                    // Taken out of the file by hand meanwhile.
                    None => return Ok(()),
                }
            };
            set_topic(table, topic);
            Ok(())
        })
    }
}

/// `hxd room …`: `args` are the words after `room`.
pub fn command(config: &Config, args: &[String]) -> Result<String, String> {
    let store = FileRooms::new(&config.rooms.file);
    let mut words = Vec::new();
    let mut edit = RoomEdit::default();
    let (mut archived, mut purge) = (false, false);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or(format!("{arg} needs a value"));
        let entries = |v: &str| -> Vec<String> {
            v.split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(String::from)
                .collect()
        };
        let retention = |v: &str| -> Result<Option<u32>, String> {
            match v {
                "default" => Ok(None),
                n => n
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("{arg} takes a number or `default`")),
            }
        };
        match arg.as_str() {
            "--archived" => archived = true,
            "--purge" => purge = true,
            "--name" => edit.name = Some(value()?.clone()),
            "--topic" => edit.topic = Some(value()?.clone()),
            "--read" => edit.read = Some(entries(value()?)),
            "--post" => edit.post = Some(entries(value()?)),
            "--position" => {
                edit.position = Some(value()?.parse().map_err(|_| "--position takes a number")?)
            }
            "--max-lines" => edit.max_lines = Some(retention(value()?)?),
            "--max-days" => edit.max_days = Some(retention(value()?)?),
            other if other.starts_with('-') => return Err(format!("unknown argument {other:?}")),
            other => words.push(other),
        }
    }
    let editing = edit != RoomEdit::default();
    let file = store.load().map_err(|e| e.to_string())?;
    let find = |name: &str| {
        file.rooms
            .iter()
            .find(|r| !r.deleted && r.name == name.trim_start_matches('#'))
            .cloned()
            .ok_or_else(|| format!("there is no room {name:?}"))
    };
    let sighup = "a running server applies it on SIGHUP (`systemctl reload`)";
    let put = |room: &Room| store.put(room).map_err(|e| e.to_string());
    match words[..] {
        ["list"] if !editing && !purge => Ok(listing(&file, archived)),
        ["create", name] if !archived && !purge => {
            if file.rooms.len() >= config.rooms.max_rooms {
                return Err(format!("[rooms] max_rooms is {}", config.rooms.max_rooms));
            }
            if edit.name.is_some() {
                return Err("--name renames a room with `edit`".into());
            }
            let mut room = Room::default();
            RoomEdit {
                name: Some(name.into()),
                ..edit
            }
            .apply(&mut room, hxd_core::moderation::OPERATOR, SystemTime::now())
            .map_err(|e| e.to_string())?;
            if find(&room.name).is_ok() {
                return Err(format!("there is a room {:?} already", room.name));
            }
            put(&room)?;
            Ok(format!(
                "created #{}; {sighup}, which gives it its id",
                room.name
            ))
        }
        ["edit", name] if editing && !archived && !purge => {
            let mut room = find(name)?;
            if room.id == 0 && edit.name.is_some() {
                return Err(format!(
                    "#{name} has no id yet: send the server SIGHUP before renaming it"
                ));
            }
            edit.apply(&mut room, hxd_core::moderation::OPERATOR, SystemTime::now())
                .map_err(|e| e.to_string())?;
            if room.name != name.trim_start_matches('#') && find(&room.name).is_ok() {
                return Err(format!("there is a room {:?} already", room.name));
            }
            put(&room)?;
            Ok(format!("changed #{}; {sighup}", room.name))
        }
        [verb @ ("archive" | "unarchive"), name] if !editing && !archived && !purge => {
            let mut room = find(name)?;
            room.archived_at = (verb == "archive").then(SystemTime::now);
            put(&room)?;
            Ok(format!("{verb}d #{}; {sighup}", room.name))
        }
        ["delete", name] if !editing && !archived => {
            if !purge {
                return Err(
                    "`room delete` takes --purge: it deletes the room's lines too, and it \
                     cannot be undone; `room archive` keeps them"
                        .into(),
                );
            }
            let room = find(name)?;
            if room.id == 0 {
                return Err(format!(
                    "#{name} has no id yet, so nothing was said in it: take its entry out of {}",
                    config.rooms.file.display()
                ));
            }
            put(&Room::tombstone(room.id))?;
            Ok(format!(
                "deleted #{name} (id {}); {sighup}, parting its members and then \
                 deleting its lines",
                room.id
            ))
        }
        _ => Err(USAGE.into()),
    }
}

fn listing(file: &RoomFile, archived: bool) -> String {
    let mut rooms: Vec<&Room> = file
        .rooms
        .iter()
        .filter(|r| !r.deleted && (archived || r.archived_at.is_none()))
        .collect();
    rooms.sort_by(|a, b| (a.position, &a.name).cmp(&(b.position, &b.name)));
    rooms
        .iter()
        .map(|r| {
            let mut line = match r.id {
                0 => format!("{:<10} #{}", "(no id)", r.name),
                id => format!("{id:<10} #{}", r.name),
            };
            if r.archived_at.is_some() {
                line += " (archived)";
            }
            for (gate, list) in [("read", &r.read), ("post", &r.post)] {
                if !list.is_empty() {
                    line += &format!(" {gate}: {}", list.join(","));
                }
            }
            if !r.topic.text.is_empty() {
                line += &format!(": {}", r.topic.text);
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> (tempfile::TempDir, impl Fn() -> FileRooms) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        let n = std::sync::atomic::AtomicUsize::new(0);
        (dir, move || {
            let i = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            FileRooms::new(&base.join(format!("rooms-{i}.toml")))
        })
    }

    #[test]
    fn the_file_passes_the_suite() {
        let (_dir, file) = files();
        hxd_core::rooms::conformance::run(&|| Box::new(file()));
    }

    const WRITTEN: &str = "# Our rooms.\n\
        [lobby]\n\
        topic = \"Welcome!\"\n\
        \n\
        [[room]]\n\
        name = \"lounge\"   # new\n\
        topic = \"anything goes\"\n\
        \n\
        # staff only\n\
        [[room]]\n\
        id = 811937042           # written by the server; never reused\n\
        name = \"staff\"\n\
        read = [\"carol\"]\n";

    /// The server gives an entry its id and writes it back, and the next
    /// start finds it there, with every comment the operator wrote.
    #[test]
    fn an_entry_without_an_id_is_given_one_in_the_file_keeping_its_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rooms.toml");
        std::fs::write(&path, WRITTEN).unwrap();
        let start =
            || Core::new().with_rooms(Arc::new(FileRooms::new(&path)), RoomPolicy::default());
        let core = start().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for kept in [
            "# Our rooms.",
            "# new",
            "# staff only",
            "# written by the server",
        ] {
            assert!(text.contains(kept), "{kept:?} in\n{text}");
        }
        let file = FileRooms::new(&path).load().unwrap();
        let lounge = file.rooms[0].id;
        assert_ne!(lounge, 0);
        assert_eq!(file.rooms[1].id, 811_937_042);
        assert_eq!(core.public_subject(), "Welcome!");
        drop(core);
        start().unwrap();
        assert_eq!(FileRooms::new(&path).load().unwrap().rooms[0].id, lounge);
    }

    #[test]
    fn a_file_that_does_not_parse_refuses_startup() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "[[room]\nname = \"x\"\n",
            "[[room]]\nname = \"lounge\"\nreed = [\"carol\"]\n",
            "[[room]]\nname = \"Lounge\"\n",
            "[[room]]\nname = \"a\"\n[[room]]\nname = \"a\"\n",
        ] {
            let path = dir.path().join("rooms.toml");
            std::fs::write(&path, bad).unwrap();
            let refused =
                Core::new().with_rooms(Arc::new(FileRooms::new(&path)), RoomPolicy::default());
            assert!(refused.is_err(), "{bad:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
        }
    }

    /// `hxd room` beside a server: an entry without an id until the server
    /// reloads, then archived, then deleted down to its tombstone.
    #[test]
    fn the_command_edits_the_file_a_running_server_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.rooms.file = dir.path().join("rooms.toml");
        let run = |words: &str| {
            let args: Vec<String> = words.split(' ').map(String::from).collect();
            command(&config, &args)
        };
        run("create lounge --topic hi --post alice,bob").unwrap();
        assert!(run("create lounge").is_err());
        assert!(run("delete lounge --purge").is_err(), "no id yet");
        let core = Core::new()
            .with_rooms(
                Arc::new(FileRooms::new(&config.rooms.file)),
                RoomPolicy::default(),
            )
            .unwrap();
        let file = FileRooms::new(&config.rooms.file).load().unwrap();
        let id = file.rooms[0].id;
        assert_eq!(file.rooms[0].post, ["alice", "bob"]);
        assert_eq!(file.rooms[0].topic.text, "hi");
        run("edit lounge --name hangout --position 2").unwrap();
        run("archive hangout").unwrap();
        assert!(run("list").unwrap().is_empty());
        assert!(run("list --archived")
            .unwrap()
            .contains("#hangout (archived)"));
        assert!(run("delete hangout").is_err(), "without --purge");
        run("delete hangout --purge").unwrap();
        core.reload_rooms().unwrap();
        assert_eq!(
            FileRooms::new(&config.rooms.file).load().unwrap().rooms,
            [Room::tombstone(id)]
        );
    }
}
