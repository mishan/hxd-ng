//! Server-held chat history: the lobby's, channel 0, and each room's
//! under its id (`docs/chat-rooms.md` §3).
//!
//! The log is deliberately wire-free: both frontends page the same UTF-8
//! lines and do their own encoding. Private chats never reach this module.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::inbox::{Mailbox, MessageGuid, StoreError};

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
    /// Clear a line down to its tombstone: id and time stay, nick and
    /// text go. `by` is who did it, the column's fast answer to what the
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
        line.flags = line.flags.with(LineFlags::DELETED);
        inner.signed.retain(|_, at| at.id != id);
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
            ..
        } = &mut *inner;
        ghosts.retain(|id, _| lines.iter().any(|line| line.id == *id));
        guids.retain(|_, id| lines.iter().any(|line| line.id == *id));
        signed.retain(|_, at| lines.iter().any(|line| line.id == at.id));
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
            ..
        } = &mut *inner;
        ghosts.retain(|id, _| lines.iter().any(|line| line.id == *id));
        guids.retain(|_, id| lines.iter().any(|line| line.id == *id));
        signed.retain(|_, at| lines.iter().any(|line| line.id == at.id));
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
}

pub mod conformance {
    use super::*;

    fn line(n: u64) -> NewLine {
        NewLine {
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
    /// never another's, whatever the name.
    fn a_ghosts_lines_are_found_by_its_key(log: Box<dyn ChatLog>) {
        for (n, ghost) in [
            (1, Some([7; 16])),
            (2, Some([8; 16])),
            (3, Some([7; 16])),
            (4, None),
        ] {
            log.append(&NewLine { ghost, ..line(n) }).unwrap();
        }
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
