//! Server-held chat history: the lobby's, channel 0, and each room's
//! under its id (`docs/chat-rooms.md` §3).
//!
//! The log is deliberately wire-free: both frontends page the same UTF-8
//! lines and do their own encoding. Private chats never reach this module.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::inbox::{Mailbox, MessageGuid, StoreError};
use crate::reaction::{reactor_key, ReactAct, Reacted, Reactions};

pub type LineId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryPolicy {
    pub max_lines: u32,
    pub max_days: u32,
    pub max_page: usize,
    pub replay: usize,
}

impl Default for HistoryPolicy {
    fn default() -> Self {
        Self {
            max_lines: 10_000,
            max_days: 0,
            max_page: 200,
            replay: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineFlags(u16);

impl LineFlags {
    pub const ACTION: Self = Self(1 << 0);
    pub const SERVER_MESSAGE: Self = Self(1 << 1);
    pub const DELETED: Self = Self(1 << 2);

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    #[must_use]
    pub const fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }
}

/// Canonical metadata retained after media bytes or their handle disappear.
/// The media implementation fills this seam when it lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaMeta {
    pub id: Vec<u8>,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLine {
    pub channel: u32,
    /// The key of the linked server's user who said it, which a purge of
    /// that ghost finds it by (`docs/server-link.md` §6.3).
    pub ghost: Option<[u8; 16]>,
    pub from_nick: String,
    pub from_login: Option<String>,
    pub from_fingerprint: Option<[u8; 32]>,
    pub icon: u16,
    pub text: String,
    pub flags: LineFlags,
    pub at: SystemTime,
    /// The client's own id for the line and who it is held under
    /// (`docs/hotline-ng.md` §7.3): one line per channel, sender and
    /// guid. Kept so a repeat after a restart finds its line; never read
    /// back into a [`LogLine`]. The sender is [`guid_sender_key`]'s.
    pub guid: Option<(String, MessageGuid)>,
    /// A signed line's detached form, and what it says. Its signer is
    /// `from_fingerprint` and its id `guid`'s, which the frontend that
    /// checked it made sure of.
    pub signed: Option<Signature>,
    /// For a linked server's user's signed line, its home server's key,
    /// which the line's scope names (`docs/e2e-messages.md` §5).
    pub home_key: Option<[u8; 32]>,
    /// For any linked server's user's line, where it was from when it was
    /// heard, so a replay does not pass it off as a local user's.
    pub home: Option<LineHome>,
    /// What the line answers, as its sender named it.
    pub re: Option<crate::reply::Reply>,
}

/// A linked server's user's home server, as its line was logged
/// (`docs/chat-history.md` §7.2): `tagged` is whether `from_nick` was
/// logged with the tag in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineHome {
    pub name: String,
    pub tag: String,
    pub tagged: bool,
}

/// A signed line's or message's detached form
/// (`docs/e2e-messages.md` §3.1), checked by the frontend that took it,
/// and kept and served exactly as it came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub form: Vec<u8>,
    /// SHA-256 of what it says, which signing it again does not change
    /// (§3.6): what tells the same line from an equivocation.
    pub content: [u8; 32],
}

/// Where a signed line is logged, as [`ChatLog::find_signed`] finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAt {
    pub channel: u32,
    pub id: LineId,
    pub content: [u8; 32],
}

/// How a line's guid sender is kept, the same in memory and in the log:
/// `login:<login>` for an account one person is behind, and
/// `fp:<hex>` for the identity a session proved where none is. Never a
/// uid or a session, which do not outlive a restart.
pub fn guid_sender_key(login: Option<&str>, fingerprint: Option<&[u8; 32]>) -> Option<String> {
    match (login, fingerprint) {
        (Some(login), _) => Some(format!("login:{login}")),
        (None, Some(fp)) => Some(format!(
            "fp:{}",
            fp.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )),
        (None, None) => None,
    }
}

/// What appending a line did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub id: LineId,
    /// False where the line's guid was logged already: nothing was
    /// appended, and `id` is that line's.
    pub new: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub id: LineId,
    pub channel: u32,
    pub from_nick: String,
    pub from_login: Option<String>,
    pub from_fingerprint: Option<[u8; 32]>,
    pub icon: u16,
    pub text: String,
    pub flags: LineFlags,
    pub at: SystemTime,
    pub media: Option<MediaMeta>,
    /// The detached form a signed line came with, until it is redacted.
    pub signed: Option<Vec<u8>>,
    /// [`NewLine::home_key`].
    pub home_key: Option<[u8; 32]>,
    /// [`NewLine::home`]; none on a line logged before it was kept.
    pub home: Option<LineHome>,
    /// [`NewLine::re`], until the line is redacted.
    pub re: Option<crate::reply::Reply>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryQuery {
    pub channel: u32,
    pub before: Option<LineId>,
    pub after: Option<LineId>,
    pub limit: usize,
}

impl HistoryQuery {
    pub fn check(self) -> Result<Self, StoreError> {
        if self.limit == 0 {
            return Err(StoreError::new("history query limit is zero"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPage {
    pub lines: Vec<LogLine>,
    pub has_more: bool,
}

/// What retention keeps of each channel: its newest `max_lines` (0 for
/// any number), none older than `max_age`, unless `channels` gives it a
/// rule of its own, `(channel, max_lines, max_age)`. Per channel, so a
/// busy lobby cannot evict a quiet room's history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Retention {
    pub max_lines: usize,
    pub max_age: Option<Duration>,
    pub channels: Vec<(u32, usize, Option<Duration>)>,
}

impl Retention {
    /// `channel`'s `(max_lines, max_age)`.
    pub fn of(&self, channel: u32) -> (usize, Option<Duration>) {
        self.channels
            .iter()
            .find(|(c, ..)| *c == channel)
            .map_or((self.max_lines, self.max_age), |&(_, n, age)| (n, age))
    }
}

/// Did `who` send this line? The mailbox rule over the line's two
/// columns. A line with neither — a plain guest's — is nobody's, because
/// `guest` is a login several people share.
pub fn sent_by(line: &LogLine, who: &Mailbox) -> bool {
    match (&line.from_login, &line.from_fingerprint) {
        (None, None) => false,
        (login, fp) => who.matches(login.as_deref().unwrap_or(""), fp.as_ref()),
    }
}

pub trait ChatLog: Send + Sync + 'static {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError> {
        self.append_all(std::slice::from_ref(line))
            .map(|done| done[0].id)
    }
    /// Several lines at once, in order, all or none: what public chat
    /// commits when lines arrive faster than one commit each can keep up
    /// with (`Core::chat_public`). A store that can make them one
    /// transaction should. A line whose guid is logged already is not
    /// appended again ([`Appended::new`]).
    fn append_all(&self, lines: &[NewLine]) -> Result<Vec<Appended>, StoreError>;
    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError>;
    /// One line by id, tombstone or not: what a redaction reads before it
    /// clears the line, and what a report names.
    fn line(&self, id: LineId) -> Result<Option<LogLine>, StoreError>;
    /// The lines of `channel` among `ids`, tombstones too, ascending: the
    /// quotes a page of replies draws, fetched at once. An id of another
    /// channel, or of no line, is left out.
    fn lines(&self, channel: u32, ids: &[LineId]) -> Result<Vec<LogLine>, StoreError>;
    /// Every live line `who` sent into `channel`, or into any channel
    /// for `None`, at or after `since`, oldest first ([`sent_by`]'s rule):
    /// what a purge selects (`docs/moderation.md` §3.3). By sender
    /// identity rather than by uid, because the sender may be gone and the
    /// uid someone else's.
    fn lines_by(
        &self,
        channel: Option<u32>,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError>;
    /// Clear a line down to its tombstone: id and time stay, nick, text,
    /// home server and what it answered go. `by` is who did it, the column's fast answer to what the
    /// moderation record says at length.
    fn tombstone(&self, id: LineId, by: &str, at: SystemTime) -> Result<bool, StoreError>;
    fn prune(&self, keep: &Retention, now: SystemTime) -> Result<usize, StoreError>;
    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError>;
    /// [`ChatLog::lines_by`] for a linked server's user, by the key its
    /// lines were logged with ([`NewLine::ghost`]): a ghost has no login to
    /// purge by, and its name may be anyone's.
    fn lines_by_ghost(
        &self,
        channel: Option<u32>,
        ghost: [u8; 16],
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError>;
    /// Every channel that has lines, with its newest line's id: what a
    /// room's id is drawn against, so a new room never inherits an old
    /// one's lines, and where a room's newest id starts.
    fn channels(&self) -> Result<Vec<(u32, LineId)>, StoreError>;
    /// Delete every line in `channel`, answering how many: a deleted
    /// room's (`hxd room delete --purge`).
    fn delete_channel(&self, channel: u32) -> Result<usize, StoreError>;
    /// The line `sender` sent into `channel` under `guid`, tombstone or
    /// not, while the log keeps it ([`NewLine::guid`]). Appending a second
    /// appends nothing and answers the first's id.
    fn find_guid(
        &self,
        channel: u32,
        sender: &str,
        guid: &MessageGuid,
    ) -> Result<Option<LineId>, StoreError>;
    /// The signed line `signer` logged under `guid`, in any channel,
    /// while the log keeps it: the index of signed lines by
    /// `(signer, id)` (`docs/e2e-messages.md` §4.7). A redacted line is
    /// not in it, since what it said goes with its words; its guid still
    /// answers a line sent again under that id ([`ChatLog::find_guid`]).
    fn find_signed(
        &self,
        signer: &[u8; 32],
        guid: &MessageGuid,
    ) -> Result<Option<SignedAt>, StoreError>;
    /// Each room's `signed` mark as kept beside its log
    /// (`docs/e2e-messages.md` §4.8), which a rooms file must agree with.
    fn room_marks(&self) -> Result<std::collections::HashMap<u32, bool>, StoreError>;
    fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError>;
    /// Does `channel` hold a line that is neither signed nor a tombstone?
    fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError>;
    /// Replace a signed line's form with `form`: a linked server's line
    /// logged in its link form, once its certificate is held. A
    /// tombstone keeps none.
    fn restore_signed(&self, id: LineId, form: &[u8]) -> Result<(), StoreError>;
    /// Does a line keep `key` as its home server's ([`NewLine::home_key`])?
    fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError>;
    /// Apply one reaction (`crate::reaction`): the line looked up in its
    /// channel and the caps held in the same step as the write, so two
    /// accounts cannot both take a line's last key. A tombstone, a
    /// retired line and a room's deletion take a line's reactions with
    /// it.
    fn react(&self, act: &ReactAct) -> Result<Reacted, StoreError>;
    /// The reactions on those of `ids` that have any, `mine` as
    /// `reader`'s account holds them.
    fn reactions(
        &self,
        ids: &[LineId],
        reader: Option<&Mailbox>,
    ) -> Result<std::collections::HashMap<LineId, Reactions>, StoreError>;
    /// Take every reaction `who` made at or after `since`, answering the
    /// lines they were on: a purge's (`docs/moderation.md` §3.3), and
    /// from the epoch an account's deletion.
    fn forget_reactions(&self, who: &Mailbox, since: SystemTime)
        -> Result<Vec<LineId>, StoreError>;
    /// `from`'s reactions become `to`'s, an identity linked or rotated,
    /// so the account still holds them; one `to` already holds goes.
    fn rekey_reactions(&self, from: &Mailbox, to: &Mailbox) -> Result<(), StoreError>;
}

#[derive(Default)]
pub struct MemoryLog {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    next_id: LineId,
    lines: Vec<LogLine>,
    ghosts: std::collections::HashMap<LineId, [u8; 16]>,
    guids: std::collections::HashMap<(u32, String, MessageGuid), LineId>,
    signed: std::collections::HashMap<([u8; 32], MessageGuid), SignedAt>,
    marks: std::collections::HashMap<u32, bool>,
    /// In the order they were made.
    reactions: Vec<ReactionRow>,
}

struct ReactionRow {
    line: LineId,
    key: Vec<u8>,
    reactor: String,
    at: SystemTime,
}

impl MemoryInner {
    fn append(&mut self, line: &NewLine) -> Result<Appended, StoreError> {
        let guid = line
            .guid
            .as_ref()
            .map(|(sender, guid)| (line.channel, sender.clone(), guid.clone()));
        if let Some(&id) = guid.as_ref().and_then(|k| self.guids.get(k)) {
            return Ok(Appended { id, new: false });
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| StoreError::new("chat line ids exhausted"))?;
        let id = self.next_id;
        self.lines.push(LogLine {
            id,
            channel: line.channel,
            from_nick: line.from_nick.clone(),
            from_login: line.from_login.clone(),
            from_fingerprint: line.from_fingerprint,
            icon: line.icon,
            text: line.text.clone(),
            flags: line.flags,
            at: line.at,
            media: None,
            signed: line.signed.as_ref().map(|s| s.form.clone()),
            home_key: line.home_key,
            home: line.home.clone(),
            re: line.re.clone(),
        });
        if let Some(key) = line.ghost {
            self.ghosts.insert(id, key);
        }
        if let (Some(s), Some(fp), Some((_, g))) = (&line.signed, line.from_fingerprint, &line.guid)
        {
            let at = SignedAt {
                channel: line.channel,
                id,
                content: s.content,
            };
            self.signed.insert((fp, g.clone()), at);
        }
        if let Some(key) = guid {
            self.guids.insert(key, id);
        }
        Ok(Appended { id, new: true })
    }
}

impl ChatLog for MemoryLog {
    fn append_all(&self, lines: &[NewLine]) -> Result<Vec<Appended>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        lines.iter().map(|line| inner.append(line)).collect()
    }

    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError> {
        let query = query.check()?;
        let inner = self.inner.lock().unwrap();
        let mut matching: Vec<_> = inner
            .lines
            .iter()
            .filter(|line| line.channel == query.channel)
            .filter(|line| query.before.is_none_or(|id| line.id < id))
            .filter(|line| query.after.is_none_or(|id| line.id > id))
            .cloned()
            .collect();

        let has_more = matching.len() > query.limit;
        if query.after.is_some() {
            matching.truncate(query.limit);
        } else if has_more {
            matching.drain(..matching.len() - query.limit);
        }
        Ok(HistoryPage {
            lines: matching,
            has_more,
        })
    }

    fn line(&self, id: LineId) -> Result<Option<LogLine>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.lines.iter().find(|line| line.id == id).cloned())
    }

    fn lines(&self, channel: u32, ids: &[LineId]) -> Result<Vec<LogLine>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .lines
            .iter()
            .filter(|line| line.channel == channel && ids.contains(&line.id))
            .cloned()
            .collect())
    }

    fn lines_by_ghost(
        &self,
        channel: Option<u32>,
        ghost: [u8; 16],
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .lines
            .iter()
            .filter(|l| {
                channel.is_none_or(|c| l.channel == c)
                    && l.at >= since
                    && !l.flags.contains(LineFlags::DELETED)
                    && inner.ghosts.get(&l.id) == Some(&ghost)
            })
            .cloned()
            .collect())
    }

    fn lines_by(
        &self,
        channel: Option<u32>,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .lines
            .iter()
            .filter(|line| {
                channel.is_none_or(|c| line.channel == c)
                    && line.at >= since
                    && !line.flags.contains(LineFlags::DELETED)
                    && sent_by(line, who)
            })
            .cloned()
            .collect())
    }

    fn tombstone(&self, id: LineId, by: &str, at: SystemTime) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(line) = inner.lines.iter_mut().find(|line| line.id == id) else {
            return Ok(false);
        };
        line.from_nick.clear();
        line.text.clear();
        line.signed = None;
        line.home = None;
        line.re = None;
        line.flags = line.flags.with(LineFlags::DELETED);
        inner.signed.retain(|_, at| at.id != id);
        inner.reactions.retain(|r| r.line != id);
        // The public timestamp is the original receive time; who and
        // when are the moderation record's, which this store has no
        // column for.
        let _ = (by, at);
        Ok(true)
    }

    fn prune(&self, keep: &Retention, now: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.lines.len();
        inner.lines.retain(|line| {
            keep.of(line.channel)
                .1
                .is_none_or(|age| line.at >= now.checked_sub(age).unwrap_or(SystemTime::UNIX_EPOCH))
        });
        // Newest first, so each channel's count is of the lines it keeps.
        let mut seen: std::collections::HashMap<u32, usize> = Default::default();
        let mut kept: Vec<LogLine> = inner
            .lines
            .drain(..)
            .rev()
            .filter(|line| {
                let n = seen.entry(line.channel).or_default();
                *n += 1;
                let max = keep.of(line.channel).0;
                max == 0 || *n <= max
            })
            .collect();
        kept.reverse();
        inner.lines = kept;
        let MemoryInner {
            lines,
            ghosts,
            guids,
            signed,
            reactions,
            ..
        } = &mut *inner;
        ghosts.retain(|id, _| lines.iter().any(|line| line.id == *id));
        guids.retain(|_, id| lines.iter().any(|line| line.id == *id));
        signed.retain(|_, at| lines.iter().any(|line| line.id == at.id));
        reactions.retain(|r| lines.iter().any(|line| line.id == r.line));
        Ok(before - inner.lines.len())
    }

    fn channels(&self) -> Result<Vec<(u32, LineId)>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut newest = std::collections::BTreeMap::new();
        for line in &inner.lines {
            newest.insert(line.channel, line.id);
        }
        Ok(newest.into_iter().collect())
    }

    fn delete_channel(&self, channel: u32) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.lines.len();
        inner.lines.retain(|line| line.channel != channel);
        let MemoryInner {
            lines,
            ghosts,
            guids,
            signed,
            reactions,
            ..
        } = &mut *inner;
        ghosts.retain(|id, _| lines.iter().any(|line| line.id == *id));
        guids.retain(|_, id| lines.iter().any(|line| line.id == *id));
        signed.retain(|_, at| lines.iter().any(|line| line.id == at.id));
        reactions.retain(|r| lines.iter().any(|line| line.id == r.line));
        Ok(before - inner.lines.len())
    }

    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let line = inner
            .lines
            .iter_mut()
            .find(|line| line.id == id)
            .ok_or_else(|| StoreError::new("no such chat line"))?;
        line.media = Some(media.clone());
        Ok(())
    }

    fn find_guid(
        &self,
        channel: u32,
        sender: &str,
        guid: &MessageGuid,
    ) -> Result<Option<LineId>, StoreError> {
        let key = (channel, sender.to_string(), guid.clone());
        Ok(self.inner.lock().unwrap().guids.get(&key).copied())
    }

    fn find_signed(
        &self,
        signer: &[u8; 32],
        guid: &MessageGuid,
    ) -> Result<Option<SignedAt>, StoreError> {
        let key = (*signer, guid.clone());
        Ok(self.inner.lock().unwrap().signed.get(&key).copied())
    }

    fn room_marks(&self) -> Result<std::collections::HashMap<u32, bool>, StoreError> {
        Ok(self.inner.lock().unwrap().marks.clone())
    }

    fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError> {
        self.inner.lock().unwrap().marks.insert(room, signed);
        Ok(())
    }

    fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError> {
        Ok(self.inner.lock().unwrap().lines.iter().any(|l| {
            l.channel == channel && l.signed.is_none() && !l.flags.contains(LineFlags::DELETED)
        }))
    }

    fn restore_signed(&self, id: LineId, form: &[u8]) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(signed) = inner
            .lines
            .iter_mut()
            .find(|l| l.id == id)
            .and_then(|l| l.signed.as_mut())
        {
            *signed = form.to_vec();
        }
        Ok(())
    }

    fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.lines.iter().any(|l| l.home_key == Some(*key)))
    }

    fn react(&self, act: &ReactAct) -> Result<Reacted, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.lines.iter().any(|l| {
            l.id == act.line && l.channel == act.channel && !l.flags.contains(LineFlags::DELETED)
        }) {
            return Ok(Reacted::NoSuchLine);
        }
        let (key, reactor) = (act.key.pack(), reactor_key(act.who));
        let (held, keyed, keys, yours) = {
            let on: Vec<&ReactionRow> = inner
                .reactions
                .iter()
                .filter(|r| r.line == act.line)
                .collect();
            let mut keys: Vec<&[u8]> = on.iter().map(|r| &r.key[..]).collect();
            keys.sort_unstable();
            keys.dedup();
            (
                on.iter().any(|r| r.key == key && r.reactor == reactor),
                on.iter().any(|r| r.key == key),
                keys.len(),
                on.iter().filter(|r| r.reactor == reactor).count(),
            )
        };
        if act.add && !held {
            if !keyed && keys >= act.max_keys {
                return Ok(Reacted::TooManyKeys);
            }
            if yours >= act.max_per_user {
                return Ok(Reacted::TooManyOfYours);
            }
            inner.reactions.push(ReactionRow {
                line: act.line,
                key: key.clone(),
                reactor,
                at: act.at,
            });
        } else if !act.add && held {
            inner
                .reactions
                .retain(|r| !(r.line == act.line && r.key == key && r.reactor == reactor));
        }
        let count = inner
            .reactions
            .iter()
            .filter(|r| r.line == act.line && r.key == key)
            .count();
        Ok(Reacted::Count(count as u32))
    }

    fn reactions(
        &self,
        ids: &[LineId],
        reader: Option<&Mailbox>,
    ) -> Result<std::collections::HashMap<LineId, Reactions>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let reader = reader.map(reactor_key);
        Ok(ids
            .iter()
            .filter_map(|&id| {
                let rows = inner
                    .reactions
                    .iter()
                    .filter(|r| r.line == id)
                    .map(|r| (&r.key[..], &r.reactor[..]));
                let shown = summarize(rows, reader.as_deref());
                (!shown.keys.is_empty()).then_some((id, shown))
            })
            .collect())
    }

    fn forget_reactions(
        &self,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LineId>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let reactor = reactor_key(who);
        let mut lines = Vec::new();
        inner.reactions.retain(|r| {
            let gone = r.reactor == reactor && r.at >= since;
            if gone && !lines.contains(&r.line) {
                lines.push(r.line);
            }
            !gone
        });
        Ok(lines)
    }

    fn rekey_reactions(&self, from: &Mailbox, to: &Mailbox) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let (from, to) = (reactor_key(from), reactor_key(to));
        let held: std::collections::HashSet<(LineId, Vec<u8>)> = inner
            .reactions
            .iter()
            .filter(|r| r.reactor == to)
            .map(|r| (r.line, r.key.clone()))
            .collect();
        inner
            .reactions
            .retain(|r| r.reactor != from || !held.contains(&(r.line, r.key.clone())));
        for r in inner.reactions.iter_mut().filter(|r| r.reactor == from) {
            r.reactor = to.clone();
        }
        Ok(())
    }
}

/// A line's rows, as `(key, reactor)` in the order they were made, read
/// into what a reader is shown.
fn summarize<'a>(
    rows: impl IntoIterator<Item = (&'a [u8], &'a str)>,
    reader: Option<&str>,
) -> Reactions {
    let mut out = Reactions::default();
    let mut at: std::collections::HashMap<&[u8], usize> = Default::default();
    for (packed, reactor) in rows {
        let Some(i) = at.get(packed).copied().or_else(|| {
            let key = crate::reaction::ReactionKey::unpack(packed)?;
            out.keys.push((key, 0));
            at.insert(packed, out.keys.len() - 1);
            Some(out.keys.len() - 1)
        }) else {
            continue;
        };
        out.keys[i].1 += 1;
        if reader == Some(reactor) {
            out.mine.extend(u8::try_from(i).ok());
        }
    }
    out.mine.sort_unstable();
    out
}

pub mod conformance {
    use super::*;

    fn line(n: u64) -> NewLine {
        NewLine {
            home_key: None,
            home: None,
            channel: 0,
            ghost: None,
            from_nick: format!("user-{n}"),
            from_login: Some(format!("login-{n}")),
            from_fingerprint: Some([n as u8; 32]),
            icon: n as u16,
            text: format!("line-{n}"),
            flags: if n % 2 == 0 {
                LineFlags::ACTION
            } else {
                LineFlags::default()
            },
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(100 + n),
            guid: None,
            signed: None,
            re: None,
        }
    }

    pub fn run(new_log: &dyn Fn() -> Box<dyn ChatLog>) {
        ids_and_fields_round_trip(new_log());
        pages_in_both_directions(new_log());
        channels_do_not_mix(new_log());
        tombstones_keep_the_cursor(new_log());
        pruning_combines_age_and_count(new_log());
        media_attaches_without_changing_the_line(new_log());
        a_line_is_found_by_id_tombstone_or_not(new_log());
        a_senders_lines_are_found_by_the_mailbox_rule(new_log());
        lines_appended_together_keep_their_order(new_log());
        a_ghosts_lines_are_found_by_its_key(new_log());
        retention_is_per_channel(new_log());
        a_senders_lines_are_found_in_every_channel(new_log());
        channels_are_listed_and_deleted_whole(new_log());
        a_line_is_found_by_its_guid_once(new_log());
        a_signed_line_is_found_by_its_signer_in_any_channel(new_log());
        a_rooms_mark_is_kept_and_its_unsigned_lines_are_found(new_log());
        a_linked_lines_signature_is_restored_beside_its_home_key(new_log());
        a_reply_is_kept_until_its_own_line_is_redacted(new_log());
        lines_are_fetched_by_id_in_their_channel_alone(new_log());
        reactions_are_counted_per_account_in_the_order_keys_came(new_log());
        reactions_are_held_to_their_caps_when_they_add(new_log());
        a_reaction_names_a_live_line_of_its_channel(new_log());
        a_lines_reactions_go_when_it_does(new_log());
        reactions_are_forgotten_by_reactor_and_time(new_log());
        reactions_follow_their_account_to_its_identity(new_log());
    }

    fn key(e: &str) -> crate::reaction::ReactionKey {
        crate::reaction::ReactionKey::emoji(e).unwrap()
    }

    /// `who` adding (or removing) `e` on `line` of the lobby at `at`
    /// seconds, under caps no case here reaches but its own.
    fn react(
        log: &dyn ChatLog,
        who: &Mailbox,
        line: LineId,
        e: &str,
        add: bool,
        at: u64,
    ) -> Reacted {
        react_capped(log, who, (0, line), e, add, at, (20, 5))
    }

    fn react_capped(
        log: &dyn ChatLog,
        who: &Mailbox,
        (channel, line): (u32, LineId),
        e: &str,
        add: bool,
        at: u64,
        (max_keys, max_per_user): (usize, usize),
    ) -> Reacted {
        log.react(&ReactAct {
            channel,
            line,
            who,
            nick: &who.login,
            key: &key(e),
            add,
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(at),
            max_keys,
            max_per_user,
        })
        .unwrap()
    }

    fn shown(log: &dyn ChatLog, ids: &[LineId], reader: &Mailbox) -> Vec<(LineId, Reactions)> {
        let mut out: Vec<_> = log
            .reactions(ids, Some(reader))
            .unwrap()
            .into_iter()
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }

    fn keys(pairs: &[(&str, u32)], mine: &[u8]) -> Reactions {
        Reactions {
            keys: pairs.iter().map(|(e, n)| (key(e), *n)).collect(),
            mine: mine.to_vec(),
        }
    }

    /// One account holds a key once however many times it adds it, and
    /// removing one it does not hold changes nothing; keys are listed in
    /// the order they were first added, and each reader is shown its own
    /// account's. An identified account is not its bare login.
    fn reactions_are_counted_per_account_in_the_order_keys_came(log: Box<dyn ChatLog>) {
        fill(&*log, 2);
        let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
        assert_eq!(react(&*log, &alice, 1, "👍", true, 1), Reacted::Count(1));
        assert_eq!(react(&*log, &bob, 1, "🎉", true, 2), Reacted::Count(1));
        assert_eq!(react(&*log, &bob, 1, "👍", true, 3), Reacted::Count(2));
        assert_eq!(react(&*log, &alice, 1, "👍", true, 4), Reacted::Count(2));
        assert_eq!(react(&*log, &alice, 1, "🎉", false, 5), Reacted::Count(1));
        assert_eq!(
            shown(&*log, &[1, 2], &alice),
            [(1, keys(&[("👍", 2), ("🎉", 1)], &[0]))]
        );
        assert_eq!(
            shown(&*log, &[1, 2], &bob),
            [(1, keys(&[("👍", 2), ("🎉", 1)], &[0, 1]))]
        );
        let linked = Mailbox::identified("alice", [9; 32]);
        assert_eq!(
            shown(&*log, &[1], &linked),
            [(1, keys(&[("👍", 2), ("🎉", 1)], &[]))]
        );
        assert_eq!(react(&*log, &alice, 1, "👍", false, 6), Reacted::Count(1));
        assert_eq!(react(&*log, &bob, 1, "👍", false, 7), Reacted::Count(0));
        assert_eq!(shown(&*log, &[1], &bob), [(1, keys(&[("🎉", 1)], &[0]))]);
    }

    /// A new key past the line's keys, or past what one account may hold
    /// on it, is refused; adding to a key already there never is.
    fn reactions_are_held_to_their_caps_when_they_add(log: Box<dyn ChatLog>) {
        fill(&*log, 1);
        let [alice, bob, carol] = ["alice", "bob", "carol"].map(Mailbox::login);
        let caps = (3, 2);
        let mut at = 0;
        let mut go = |who: &Mailbox, e: &str| {
            at += 1;
            react_capped(&*log, who, (0, 1), e, true, at, caps)
        };
        assert_eq!(go(&alice, "👍"), Reacted::Count(1));
        assert_eq!(go(&alice, "🎉"), Reacted::Count(1));
        assert_eq!(go(&alice, "🔥"), Reacted::TooManyOfYours);
        assert_eq!(go(&alice, "👍"), Reacted::Count(1));
        assert_eq!(go(&bob, "🔥"), Reacted::Count(1));
        assert_eq!(go(&carol, "😀"), Reacted::TooManyKeys);
        assert_eq!(go(&carol, "👍"), Reacted::Count(2));
    }

    fn a_reaction_names_a_live_line_of_its_channel(log: Box<dyn ChatLog>) {
        fill(&*log, 2);
        let alice = Mailbox::login("alice");
        let caps = (20, 5);
        assert_eq!(
            react_capped(&*log, &alice, (7, 1), "👍", true, 1, caps),
            Reacted::NoSuchLine
        );
        assert_eq!(react(&*log, &alice, 99, "👍", true, 1), Reacted::NoSuchLine);
        assert!(log.tombstone(2, "mod", SystemTime::UNIX_EPOCH).unwrap());
        assert_eq!(react(&*log, &alice, 2, "👍", true, 1), Reacted::NoSuchLine);
        assert!(shown(&*log, &[1, 2, 99], &alice).is_empty());
    }

    /// A redaction, retention and a room's deletion each take a line's
    /// reactions with it, and no other line's.
    fn a_lines_reactions_go_when_it_does(log: Box<dyn ChatLog>) {
        fill(&*log, 3);
        log.append(&in_channel(4, 9)).unwrap();
        let alice = Mailbox::login("alice");
        for id in 1..=3 {
            react(&*log, &alice, id, "👍", true, id);
        }
        react_capped(&*log, &alice, (9, 4), "👍", true, 4, (20, 5));
        log.tombstone(3, "mod", SystemTime::UNIX_EPOCH).unwrap();
        let keep = Retention {
            max_lines: 1,
            max_age: None,
            channels: Vec::new(),
        };
        log.prune(&keep, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(ids_in(&*log, 0), [3]);
        log.delete_channel(9).unwrap();
        assert!(shown(&*log, &[1, 2, 3, 4], &alice).is_empty());
        // Nothing of the old rows answers for a line logged since.
        let next = log.append(&line(5)).unwrap();
        assert!(shown(&*log, &[next], &alice).is_empty());
    }

    /// What a purge takes: one account's reactions from a time on,
    /// wherever they are, answered by line.
    fn reactions_are_forgotten_by_reactor_and_time(log: Box<dyn ChatLog>) {
        fill(&*log, 2);
        let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
        react(&*log, &alice, 1, "👍", true, 100);
        react(&*log, &alice, 2, "👍", true, 200);
        react(&*log, &alice, 2, "🎉", true, 300);
        react(&*log, &bob, 2, "👍", true, 400);
        let since = SystemTime::UNIX_EPOCH + Duration::from_secs(150);
        assert_eq!(log.forget_reactions(&alice, since).unwrap(), [2]);
        assert_eq!(
            shown(&*log, &[1, 2], &alice),
            [(1, keys(&[("👍", 1)], &[0])), (2, keys(&[("👍", 1)], &[]))]
        );
        assert!(log.forget_reactions(&alice, since).unwrap().is_empty());
    }

    /// A link or a rotation moves an account's reactions, and one the new
    /// key already holds is not counted twice.
    fn reactions_follow_their_account_to_its_identity(log: Box<dyn ChatLog>) {
        fill(&*log, 1);
        let (bare, linked) = (
            Mailbox::login("alice"),
            Mailbox::identified("alice", [4; 32]),
        );
        react(&*log, &bare, 1, "👍", true, 1);
        react(&*log, &bare, 1, "🎉", true, 2);
        react(&*log, &linked, 1, "👍", true, 3);
        log.rekey_reactions(&bare, &linked).unwrap();
        // The thumbs-up it already held stays, and the bare login's goes.
        assert_eq!(
            shown(&*log, &[1], &linked),
            [(1, keys(&[("🎉", 1), ("👍", 1)], &[0, 1]))]
        );
        let rotated = Mailbox::identified("alice", [5; 32]);
        log.rekey_reactions(&linked, &rotated).unwrap();
        assert_eq!(
            shown(&*log, &[1], &rotated),
            [(1, keys(&[("🎉", 1), ("👍", 1)], &[0, 1]))]
        );
        assert_eq!(react(&*log, &bare, 1, "🔥", true, 4), Reacted::Count(1));
        assert_eq!(
            shown(&*log, &[1], &bare),
            [(1, keys(&[("🎉", 1), ("👍", 1), ("🔥", 1)], &[2]))]
        );
    }

    /// What a line answers is kept as sent and goes with the line's
    /// words; a reply to a line redacted since keeps its own.
    fn a_reply_is_kept_until_its_own_line_is_redacted(log: Box<dyn ChatLog>) {
        use crate::reply::Reply;
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
        let replies = [
            Reply::Line { room: 0, id: 1 },
            Reply::im("alice".into(), guid).unwrap(),
            Reply::Signed {
                signer: [1; 32],
                id: [2; 16],
                hash: [3; 32],
            },
        ];
        log.append(&line(1)).unwrap();
        for (n, re) in (2..).zip(&replies) {
            log.append(&NewLine {
                re: Some(re.clone()),
                ..line(n)
            })
            .unwrap();
        }
        let kept = |id| log.line(id).unwrap().unwrap().re;
        for (id, re) in (2..).zip(&replies) {
            assert_eq!(kept(id).as_ref(), Some(re));
        }
        assert!(log.tombstone(1, "carol", SystemTime::now()).unwrap());
        assert!(log.tombstone(3, "carol", SystemTime::now()).unwrap());
        assert_eq!(kept(2).as_ref(), Some(&replies[0]));
        assert_eq!(kept(3), None);
    }

    fn lines_are_fetched_by_id_in_their_channel_alone(log: Box<dyn ChatLog>) {
        fill(&*log, 3);
        log.append(&in_channel(4, 7)).unwrap();
        assert!(log.tombstone(2, "carol", SystemTime::now()).unwrap());
        let got = log.lines(0, &[4, 3, 99, 2, 1]).unwrap();
        assert_eq!(got.iter().map(|l| l.id).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(got[1].flags.contains(LineFlags::DELETED));
        assert_eq!(
            log.lines(7, &[4, 1])
                .unwrap()
                .iter()
                .map(|l| l.id)
                .collect::<Vec<_>>(),
            [4]
        );
        assert!(log.lines(0, &[]).unwrap().is_empty());
    }

    /// A linked server's signed line, logged in its link form with its
    /// home server's key, takes its whole form once its certificate is
    /// held (`docs/e2e-messages.md` §5); a tombstone takes none.
    fn a_linked_lines_signature_is_restored_beside_its_home_key(log: Box<dyn ChatLog>) {
        let linked = |n| NewLine {
            ghost: Some([n as u8; 16]),
            from_login: None,
            from_fingerprint: None,
            signed: Some(Signature {
                form: vec![0xa5, n as u8],
                content: [n as u8; 32],
            }),
            home_key: Some([7; 32]),
            ..line(n)
        };
        let (kept, redacted) = (
            log.append(&linked(1)).unwrap(),
            log.append(&linked(2)).unwrap(),
        );
        assert!(log.holds_home_key(&[7; 32]).unwrap());
        assert!(!log.holds_home_key(&[8; 32]).unwrap());
        assert!(log
            .tombstone(redacted, "mod", SystemTime::UNIX_EPOCH)
            .unwrap());
        for id in [kept, redacted] {
            log.restore_signed(id, &[0xa5, 0xff]).unwrap();
        }
        let line = log.line(kept).unwrap().unwrap();
        assert_eq!(
            (line.signed, line.home_key),
            (Some(vec![0xa5, 0xff]), Some([7; 32]))
        );
        assert_eq!(log.line(redacted).unwrap().unwrap().signed, None);
    }

    /// What a room that requires signing is held to across restarts
    /// (`docs/e2e-messages.md` §4.8): its mark, and whether its log holds
    /// a line that is neither signed nor a tombstone.
    fn a_rooms_mark_is_kept_and_its_unsigned_lines_are_found(log: Box<dyn ChatLog>) {
        assert!(log.room_marks().unwrap().is_empty());
        log.set_room_mark(7, false).unwrap();
        log.set_room_mark(8, true).unwrap();
        log.set_room_mark(7, true).unwrap();
        let marks = log.room_marks().unwrap();
        assert_eq!(marks, [(7, true), (8, true)].into_iter().collect());
        let signed = Signature {
            form: vec![0xa5],
            content: [1; 32],
        };
        log.append(&NewLine {
            signed: Some(signed),
            ..in_channel(1, 7)
        })
        .unwrap();
        assert!(!log.holds_unsigned(7).unwrap(), "a signed line");
        let unsigned = log.append(&in_channel(2, 7)).unwrap();
        assert!(log.holds_unsigned(7).unwrap());
        assert!(!log.holds_unsigned(8).unwrap(), "another channel's");
        log.tombstone(unsigned, "mod", SystemTime::UNIX_EPOCH)
            .unwrap();
        assert!(!log.holds_unsigned(7).unwrap(), "a tombstone");
    }

    /// A signed line keeps its form and is found by its signer and guid,
    /// in whichever channel it was said, until it is redacted; another
    /// sender's unsigned line under the same guid is not.
    fn a_signed_line_is_found_by_its_signer_in_any_channel(log: Box<dyn ChatLog>) {
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000002").unwrap();
        let sender = guid_sender_key(Some("login-3"), None).unwrap();
        let signed = Signature {
            form: vec![0xa5, 1, 2, 3],
            content: [9; 32],
        };
        let id = log
            .append(&NewLine {
                guid: Some((sender.clone(), guid.clone())),
                signed: Some(signed.clone()),
                ..in_channel(3, 7)
            })
            .unwrap();
        log.append(&NewLine {
            guid: Some((sender, guid.clone())),
            ..line(4)
        })
        .unwrap();
        let found = SignedAt {
            channel: 7,
            id,
            content: signed.content,
        };
        assert_eq!(log.find_signed(&[3; 32], &guid).unwrap(), Some(found));
        assert_eq!(log.find_signed(&[4; 32], &guid).unwrap(), None);
        assert_eq!(log.line(id).unwrap().unwrap().signed, Some(signed.form));
        assert!(log.tombstone(id, "mod", SystemTime::UNIX_EPOCH).unwrap());
        assert_eq!(log.line(id).unwrap().unwrap().signed, None, "redacted");
        assert_eq!(log.find_signed(&[3; 32], &guid).unwrap(), None);
    }

    /// A line logged with a guid is found by its channel, sender and
    /// guid, tombstone or not, until it is pruned; a second with the same
    /// three is not logged and is answered the first's id, and one in
    /// another channel or from another sender, or with no guid, is a line
    /// like any other.
    fn a_line_is_found_by_its_guid_once(log: Box<dyn ChatLog>) {
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
        let alice = guid_sender_key(Some("alice"), None).unwrap();
        let keyed = guid_sender_key(None, Some(&[3; 32])).unwrap();
        let with = |n, channel, sender: &str| NewLine {
            guid: Some((sender.to_string(), guid.clone())),
            ..in_channel(n, channel)
        };
        let id = log.append(&with(1, 0, &alice)).unwrap();
        assert_eq!(log.find_guid(0, &alice, &guid).unwrap(), Some(id));
        let done = log.append_all(&[with(2, 0, &alice), line(8)]).unwrap();
        assert_eq!(done[0], Appended { id, new: false }, "one line a guid");
        assert!(
            done[1].new && done[1].id > id,
            "and the next is logged after it"
        );
        let elsewhere = log.append(&with(3, 9, &alice)).unwrap();
        let other = log.append(&with(4, 0, &keyed)).unwrap();
        assert_eq!(log.find_guid(9, &alice, &guid).unwrap(), Some(elsewhere));
        assert_eq!(log.find_guid(0, &keyed, &guid).unwrap(), Some(other));
        assert_eq!(log.find_guid(0, "login:bob", &guid).unwrap(), None);
        log.append(&line(5)).unwrap();
        log.append(&line(6)).unwrap();
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines.len(), 5, "the repeat was not logged");

        assert!(log.tombstone(id, "mod", SystemTime::UNIX_EPOCH).unwrap());
        assert_eq!(
            log.find_guid(0, &alice, &guid).unwrap(),
            Some(id),
            "redacted"
        );
        let keep = Retention {
            max_lines: 0,
            max_age: Some(Duration::from_secs(1)),
            channels: Vec::new(),
        };
        log.prune(&keep, SystemTime::UNIX_EPOCH + Duration::from_secs(1000))
            .unwrap();
        assert_eq!(log.find_guid(0, &alice, &guid).unwrap(), None, "pruned");
        let reused = log.append(&with(7, 0, &alice)).unwrap();
        assert_ne!(reused, id);
        assert_eq!(log.find_guid(0, &alice, &guid).unwrap(), Some(reused));
    }

    fn in_channel(n: u64, channel: u32) -> NewLine {
        NewLine { channel, ..line(n) }
    }

    fn ids_in(log: &dyn ChatLog, channel: u32) -> Vec<LineId> {
        log.query(&HistoryQuery {
            channel,
            before: None,
            after: None,
            limit: 100,
        })
        .unwrap()
        .lines
        .iter()
        .map(|l| l.id)
        .collect()
    }

    /// A busy channel keeps its newest lines and a quiet one all of its
    /// own, and a channel with a rule of its own is held to that rule.
    fn retention_is_per_channel(log: Box<dyn ChatLog>) {
        for n in 1..=12 {
            let channel = match n {
                3 | 7 => 7,
                5 | 9 | 11 => 9,
                _ => 0,
            };
            log.append(&in_channel(n, channel)).unwrap();
        }
        let keep = Retention {
            max_lines: 3,
            max_age: None,
            channels: vec![(9, 1, None)],
        };
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
        assert_eq!(log.prune(&keep, now).unwrap(), 6);
        assert_eq!(ids_in(&*log, 0), [8, 10, 12]);
        assert_eq!(ids_in(&*log, 7), [3, 7]);
        assert_eq!(ids_in(&*log, 9), [11]);
        // An age of its own reaches its channel only.
        let keep = Retention {
            channels: vec![(7, 0, Some(Duration::from_secs(95)))],
            ..Retention::default()
        };
        assert_eq!(log.prune(&keep, now).unwrap(), 1);
        assert_eq!(ids_in(&*log, 7), [7]);
        assert_eq!(ids_in(&*log, 0), [8, 10, 12]);
    }

    /// What a purge selects: one channel's lines, or every channel's.
    fn a_senders_lines_are_found_in_every_channel(log: Box<dyn ChatLog>) {
        log.append(&line(1)).unwrap();
        log.append(&in_channel(1, 7)).unwrap();
        log.append(&NewLine {
            ghost: Some([3; 16]),
            ..in_channel(2, 9)
        })
        .unwrap();
        let who = Mailbox::identified("login-1", [1; 32]);
        let ids = |channel| -> Vec<LineId> {
            log.lines_by(channel, &who, SystemTime::UNIX_EPOCH)
                .unwrap()
                .iter()
                .map(|l| l.id)
                .collect()
        };
        assert_eq!(ids(None), [1, 2]);
        assert_eq!(ids(Some(7)), [2]);
        let ghost = |channel| log.lines_by_ghost(channel, [3; 16], SystemTime::UNIX_EPOCH);
        assert_eq!(ghost(None).unwrap().len(), 1);
        assert!(ghost(Some(0)).unwrap().is_empty());
    }

    fn channels_are_listed_and_deleted_whole(log: Box<dyn ChatLog>) {
        assert!(log.channels().unwrap().is_empty());
        for (n, channel) in [(1, 0), (2, 7), (3, 0), (4, 7), (5, 9)] {
            log.append(&in_channel(n, channel)).unwrap();
        }
        assert_eq!(log.channels().unwrap(), [(0, 3), (7, 4), (9, 5)]);
        assert_eq!(log.delete_channel(7).unwrap(), 2);
        assert!(ids_in(&*log, 7).is_empty());
        assert_eq!(ids_in(&*log, 0), [1, 3]);
        assert_eq!(log.channels().unwrap(), [(0, 3), (9, 5)]);
    }

    /// A linked server's user's lines, by the key this server gave it, and
    /// never another's, whatever the name; each with its home server.
    fn a_ghosts_lines_are_found_by_its_key(log: Box<dyn ChatLog>) {
        for (n, ghost) in [
            (1, Some([7; 16])),
            (2, Some([8; 16])),
            (3, Some([7; 16])),
            (4, None),
        ] {
            let home = ghost.map(|g| LineHome {
                name: "Far Away".into(),
                tag: "far".into(),
                tagged: g == [7; 16],
            });
            log.append(&NewLine {
                ghost,
                home,
                ..line(n)
            })
            .unwrap();
        }
        let home = |id| log.line(id).unwrap().unwrap().home;
        assert_eq!(
            home(1),
            Some(LineHome {
                name: "Far Away".into(),
                tag: "far".into(),
                tagged: true
            })
        );
        assert!(!home(2).unwrap().tagged);
        assert_eq!(home(4), None);
        let since = SystemTime::UNIX_EPOCH;
        let ids = |key| -> Vec<LineId> {
            log.lines_by_ghost(Some(0), key, since)
                .unwrap()
                .iter()
                .map(|l| l.id)
                .collect()
        };
        assert_eq!(ids([7; 16]), [1, 3]);
        assert_eq!(ids([8; 16]), [2]);
        assert!(log.tombstone(3, "carol", SystemTime::now()).unwrap());
        assert_eq!(ids([7; 16]), [1], "a tombstone is purged already");
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(102);
        assert!(log
            .lines_by_ghost(Some(0), [7; 16], later)
            .unwrap()
            .is_empty());
    }

    /// Several lines at once are logged as a line at a time would log
    /// them: an id each, rising, and the lines in that order.
    fn lines_appended_together_keep_their_order(log: Box<dyn ChatLog>) {
        fill(&*log, 2);
        let lines: Vec<NewLine> = (3..=7).map(line).collect();
        let ids: Vec<LineId> = log
            .append_all(&lines)
            .unwrap()
            .iter()
            .map(|done| done.id)
            .collect();
        assert_eq!(ids, vec![3, 4, 5, 6, 7]);
        assert_eq!(log.append(&line(8)).unwrap(), 8);
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 50,
            })
            .unwrap();
        let texts: Vec<&str> = page.lines.iter().map(|l| l.text.as_str()).collect();
        let want: Vec<String> = (1..=8).map(|n| format!("line-{n}")).collect();
        assert_eq!(texts, want);
        assert!(log.append_all(&[]).unwrap().is_empty());
    }

    fn fill(log: &dyn ChatLog, count: u64) {
        for n in 1..=count {
            assert_eq!(log.append(&line(n)).unwrap(), n);
        }
    }

    fn ids_and_fields_round_trip(log: Box<dyn ChatLog>) {
        fill(&*log, 1);
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 50,
            })
            .unwrap();
        assert_eq!(page.lines[0].from_login.as_deref(), Some("login-1"));
        assert_eq!(page.lines[0].from_fingerprint, Some([1; 32]));
        assert_eq!(page.lines[0].text, "line-1");
        assert!(!page.has_more);
    }

    fn pages_in_both_directions(log: Box<dyn ChatLog>) {
        fill(&*log, 6);
        let latest = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 2,
            })
            .unwrap();
        assert_eq!(
            latest.lines.iter().map(|l| l.id).collect::<Vec<_>>(),
            [5, 6]
        );
        assert!(latest.has_more);

        let older = log
            .query(&HistoryQuery {
                channel: 0,
                before: Some(5),
                after: None,
                limit: 2,
            })
            .unwrap();
        assert_eq!(older.lines.iter().map(|l| l.id).collect::<Vec<_>>(), [3, 4]);
        assert!(older.has_more);

        let newer = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: Some(2),
                limit: 2,
            })
            .unwrap();
        assert_eq!(newer.lines.iter().map(|l| l.id).collect::<Vec<_>>(), [3, 4]);
        assert!(newer.has_more);

        let bounded = log
            .query(&HistoryQuery {
                channel: 0,
                before: Some(6),
                after: Some(2),
                limit: 2,
            })
            .unwrap();
        assert_eq!(
            bounded.lines.iter().map(|line| line.id).collect::<Vec<_>>(),
            [3, 4]
        );
        assert!(bounded.has_more);

        let bounded_tail = log
            .query(&HistoryQuery {
                channel: 0,
                before: Some(6),
                after: Some(2),
                limit: 3,
            })
            .unwrap();
        assert_eq!(
            bounded_tail
                .lines
                .iter()
                .map(|line| line.id)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert!(!bounded_tail.has_more);
    }

    fn channels_do_not_mix(log: Box<dyn ChatLog>) {
        fill(&*log, 1);
        let mut other = line(2);
        other.channel = 7;
        log.append(&other).unwrap();
        let page = log
            .query(&HistoryQuery {
                channel: 7,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines.len(), 1);
        assert_eq!(page.lines[0].channel, 7);
    }

    fn tombstones_keep_the_cursor(log: Box<dyn ChatLog>) {
        fill(&*log, 3);
        assert!(log.tombstone(2, "carol", SystemTime::now()).unwrap());
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: Some(1),
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines.iter().map(|l| l.id).collect::<Vec<_>>(), [2, 3]);
        assert!(page.lines[0].flags.contains(LineFlags::DELETED));
        assert!(page.lines[0].from_nick.is_empty());
        assert!(page.lines[0].text.is_empty());
    }

    fn pruning_combines_age_and_count(log: Box<dyn ChatLog>) {
        fill(&*log, 6);
        let keep = Retention {
            max_lines: 2,
            max_age: Some(Duration::from_secs(3)),
            channels: Vec::new(),
        };
        let gone = log
            .prune(&keep, SystemTime::UNIX_EPOCH + Duration::from_secs(106))
            .unwrap();
        assert_eq!(gone, 4);
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines.iter().map(|l| l.id).collect::<Vec<_>>(), [5, 6]);
    }

    fn media_attaches_without_changing_the_line(log: Box<dyn ChatLog>) {
        fill(&*log, 1);
        let media = MediaMeta {
            id: vec![7; 16],
            mime: "image/png".into(),
            width: 12,
            height: 34,
            bytes: 56,
        };
        log.attach_media(1, &media).unwrap();
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 1,
            })
            .unwrap();
        assert_eq!(page.lines[0].media.as_ref(), Some(&media));
    }

    fn a_line_is_found_by_id_tombstone_or_not(log: Box<dyn ChatLog>) {
        fill(&*log, 2);
        assert_eq!(log.line(1).unwrap().unwrap().text, "line-1");
        assert!(log.tombstone(2, "carol", SystemTime::now()).unwrap());
        let gone = log.line(2).unwrap().unwrap();
        assert!(gone.flags.contains(LineFlags::DELETED));
        assert!(gone.text.is_empty());
        assert!(log.line(3).unwrap().is_none());
    }

    fn a_senders_lines_are_found_by_the_mailbox_rule(log: Box<dyn ChatLog>) {
        // Lines 1..=4 from four different senders, then two more from
        // sender 3, one of which is redacted, and a guest's.
        fill(&*log, 4);
        let later = |n: u64| NewLine {
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(200 + n),
            ..line(3)
        };
        assert_eq!(log.append(&later(1)).unwrap(), 5);
        assert_eq!(log.append(&later(2)).unwrap(), 6);
        assert!(log.tombstone(6, "carol", SystemTime::now()).unwrap());
        let guest = NewLine {
            from_login: None,
            from_fingerprint: None,
            ..line(7)
        };
        assert_eq!(log.append(&guest).unwrap(), 7);
        let ids = |who: &Mailbox, since: u64| {
            log.lines_by(
                Some(0),
                who,
                SystemTime::UNIX_EPOCH + Duration::from_secs(since),
            )
            .unwrap()
            .iter()
            .map(|l| l.id)
            .collect::<Vec<_>>()
        };
        // By fingerprint whatever the login says, live lines only, oldest
        // first, and bounded by time.
        let three = Mailbox::identified("renamed", [3; 32]);
        assert_eq!(ids(&three, 0), [3, 5]);
        assert_eq!(ids(&three, 150), [5]);
        // A bare login does not claim an identified sender's lines, and
        // nobody claims a guest's.
        assert!(ids(&Mailbox::login("login-3"), 0).is_empty());
        assert!(ids(&Mailbox::login(""), 0).is_empty());
        assert!(ids(&Mailbox::login("guest"), 0).is_empty());
    }

    #[cfg(test)]
    #[test]
    fn memory_log_passes() {
        run(&|| Box::<MemoryLog>::default());
    }
}

#[cfg(test)]
mod core_tests {
    use std::sync::Arc;

    use super::*;
    use crate::access::bit;
    use crate::roster::{test_attach, Event};
    use crate::{AccessBits, Core};

    #[test]
    fn concurrent_live_order_is_the_persisted_order() {
        let log = Arc::new(MemoryLog::default());
        let core = Arc::new(Core::new().with_history(log.clone(), HistoryPolicy::default()));
        let access = AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT);
        let (uid, mut events) = test_attach(&core, "alice", access);
        let mut sends = Vec::new();
        for n in 0..32 {
            let core = core.clone();
            sends.push(std::thread::spawn(move || {
                core.chat_public(uid, format!("line-{n}"), 0, None).unwrap();
            }));
        }
        for send in sends {
            send.join().unwrap();
        }

        let live: Vec<_> = std::iter::from_fn(|| events.try_recv().ok())
            .filter_map(|event| match event.event {
                Event::Chat {
                    id: Some(id), text, ..
                } => Some((id, text)),
                _ => None,
            })
            .collect();
        let stored = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 100,
            })
            .unwrap()
            .lines
            .into_iter()
            .map(|line| (line.id, line.text))
            .collect::<Vec<_>>();
        assert_eq!(live, stored);
    }

    #[test]
    fn private_chat_never_enters_the_log() {
        let log = Arc::new(MemoryLog::default());
        let core = Core::new().with_history(log.clone(), HistoryPolicy::default());
        let access = AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT)
            .with(bit::CREATE_PCHATS);
        let (a, _) = test_attach(&core, "alice", access);
        let (b, _) = test_attach(&core, "bob", access);
        let (cid, _) = core.chat_create(a, b).unwrap();
        core.chat_join(cid, b, "").unwrap();
        core.chat_private(cid, a, "secret".into(), 0, None).unwrap();
        assert!(log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap()
            .lines
            .is_empty());
    }

    #[test]
    fn history_rate_limit_is_scoped_to_the_user_session() {
        let core = Core::new();
        let (uid, _) = test_attach(&core, "alice", AccessBits::empty());
        for _ in 0..10 {
            assert!(core.allow_history_request(uid).unwrap());
        }
        assert!(!core.allow_history_request(uid).unwrap());
        assert_eq!(
            core.allow_history_request(u16::MAX),
            Err(crate::ChatError::NoSuchUser)
        );
    }
}
