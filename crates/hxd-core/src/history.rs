//! Server-held public-chat history.
//!
//! The log is deliberately wire-free: both frontends page the same UTF-8
//! lines and do their own encoding. Private chats never reach this module.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::inbox::{Mailbox, StoreError};

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
    pub from_nick: String,
    pub from_login: Option<String>,
    pub from_fingerprint: Option<[u8; 32]>,
    pub icon: u16,
    pub text: String,
    pub flags: LineFlags,
    pub at: SystemTime,
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
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError>;
    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError>;
    /// One line by id, tombstone or not: what a redaction reads before it
    /// clears the line, and what a report names.
    fn line(&self, id: LineId) -> Result<Option<LogLine>, StoreError>;
    /// Every live line `who` sent into `channel` at or after `since`,
    /// oldest first ([`sent_by`]'s rule): what a purge selects
    /// (`docs/moderation.md` §3.3). By sender identity rather than by
    /// uid, because the sender may be gone and the uid someone else's.
    fn lines_by(
        &self,
        channel: u32,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError>;
    /// Clear a line down to its tombstone: id and time stay, nick and
    /// text go. `by` is who did it, the column's fast answer to what the
    /// moderation record says at length.
    fn tombstone(&self, id: LineId, by: &str, at: SystemTime) -> Result<bool, StoreError>;
    fn prune(
        &self,
        max_lines: usize,
        max_age: Option<Duration>,
        now: SystemTime,
    ) -> Result<usize, StoreError>;
    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError>;
}

#[derive(Default)]
pub struct MemoryLog {
    inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    next_id: LineId,
    lines: Vec<LogLine>,
}

impl ChatLog for MemoryLog {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.next_id = inner
            .next_id
            .checked_add(1)
            .ok_or_else(|| StoreError::new("chat line ids exhausted"))?;
        let id = inner.next_id;
        inner.lines.push(LogLine {
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
        });
        Ok(id)
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

    fn lines_by(
        &self,
        channel: u32,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .lines
            .iter()
            .filter(|line| {
                line.channel == channel
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
        line.flags = line.flags.with(LineFlags::DELETED);
        // The public timestamp is the original receive time; who and
        // when are the moderation record's, which this store has no
        // column for.
        let _ = (by, at);
        Ok(true)
    }

    fn prune(
        &self,
        max_lines: usize,
        max_age: Option<Duration>,
        now: SystemTime,
    ) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.lines.len();
        if let Some(age) = max_age {
            let cutoff = now.checked_sub(age).unwrap_or(SystemTime::UNIX_EPOCH);
            inner.lines.retain(|line| line.at >= cutoff);
        }
        if max_lines > 0 && inner.lines.len() > max_lines {
            let excess = inner.lines.len() - max_lines;
            inner.lines.drain(..excess);
        }
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
}

pub mod conformance {
    use super::*;

    fn line(n: u64) -> NewLine {
        NewLine {
            channel: 0,
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
        let gone = log
            .prune(
                2,
                Some(Duration::from_secs(3)),
                SystemTime::UNIX_EPOCH + Duration::from_secs(106),
            )
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
            log.lines_by(0, who, SystemTime::UNIX_EPOCH + Duration::from_secs(since))
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
