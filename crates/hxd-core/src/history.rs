//! Server-held public-chat history.
//!
//! The log is deliberately wire-free: both frontends page the same UTF-8
//! lines and do their own encoding. Private chats never reach this module.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::inbox::StoreError;

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
        if self.before.is_some() && self.after.is_some() {
            return Err(StoreError::new("history query has both before and after"));
        }
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

pub trait ChatLog: Send + Sync + 'static {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError>;
    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError>;
    fn tombstone(&self, id: LineId, at: SystemTime) -> Result<bool, StoreError>;
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

    fn tombstone(&self, id: LineId, at: SystemTime) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(line) = inner.lines.iter_mut().find(|line| line.id == id) else {
            return Ok(false);
        };
        line.from_nick.clear();
        line.text.clear();
        line.flags = line.flags.with(LineFlags::DELETED);
        // The public timestamp is the original receive time. `at` is the
        // deletion time and will be persisted by the moderation store.
        let _ = at;
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
        assert!(log.tombstone(2, SystemTime::now()).unwrap());
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
                core.chat_public(uid, format!("line-{n}"), 0).unwrap();
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
        core.chat_private(cid, a, "secret".into(), 0).unwrap();
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
