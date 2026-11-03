//! A chat log that fails the methods a test names, or stops in one until
//! the test lets it go, and forwards everything to a real [`MemoryLog`]
//! otherwise: for the paths a store error or a race takes.

use std::collections::HashSet;
use std::sync::{Arc, Barrier, Mutex};

use super::*;

#[derive(Default)]
pub(crate) struct FaultyLog {
    pub(crate) inner: MemoryLog,
    failing: Mutex<HashSet<&'static str>>,
    parked: Mutex<Option<(&'static str, Arc<Barrier>)>>,
    /// How many reactions each `react_all` carried, in order.
    pub(crate) runs: Mutex<Vec<usize>>,
    /// A line any reaction to or tombstone of which panics, alone or in
    /// a run.
    panics_on: Mutex<Option<LineId>>,
}

impl FaultyLog {
    /// Fail `method` from now on, or with `on` false, stop.
    pub(crate) fn fail(&self, method: &'static str, on: bool) {
        let mut failing = self.failing.lock().unwrap();
        match on {
            true => failing.insert(method),
            false => failing.remove(method),
        };
    }

    /// The next call of `method` stops once it is done, meets the test
    /// at `at`, and waits there again for the test to let it go.
    pub(crate) fn park_after(&self, method: &'static str, at: Arc<Barrier>) {
        *self.parked.lock().unwrap() = Some((method, at));
    }

    fn park(&self, method: &str) {
        let at = {
            let mut parked = self.parked.lock().unwrap();
            match parked.as_ref() {
                Some((m, _)) if *m == method => parked.take().map(|(_, at)| at),
                _ => None,
            }
        };
        if let Some(at) = at {
            at.wait();
            at.wait();
        }
    }

    /// Panic under any reaction to `line`.
    pub(crate) fn panic_on(&self, line: LineId) {
        *self.panics_on.lock().unwrap() = Some(line);
    }

    fn panics(&self, acts: &[ReactAct]) {
        let on = *self.panics_on.lock().unwrap();
        if acts.iter().any(|a| Some(a.line) == on) {
            panic!("a reaction to line {on:?} panicked, as the test asked");
        }
    }

    fn fails(&self, method: &str) -> Result<(), StoreError> {
        match self.failing.lock().unwrap().contains(method) {
            true => Err(StoreError::new(format!(
                "{method} failed, as the test asked"
            ))),
            false => Ok(()),
        }
    }
}

impl ChatLog for FaultyLog {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError> {
        self.inner.append(line)
    }

    fn append_all(&self, lines: &[NewLine]) -> Result<Vec<Appended>, StoreError> {
        let out = self.inner.append_all(lines);
        self.park("append_all");
        out
    }

    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError> {
        self.inner.query(query)
    }

    fn line(&self, id: LineId) -> Result<Option<LogLine>, StoreError> {
        self.inner.line(id)
    }

    fn lines(&self, channel: u32, ids: &[LineId]) -> Result<Vec<LogLine>, StoreError> {
        self.inner.lines(channel, ids)
    }

    fn lines_by(
        &self,
        channel: Option<u32>,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError> {
        self.inner.lines_by(channel, who, since)
    }

    fn tombstone(&self, id: LineId, by: &str, at: SystemTime) -> Result<bool, StoreError> {
        self.inner.tombstone(id, by, at)
    }

    fn prune(&self, keep: &Retention, now: SystemTime) -> Result<usize, StoreError> {
        self.inner.prune(keep, now)
    }

    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError> {
        self.inner.attach_media(id, media)
    }

    fn lines_by_ghost(
        &self,
        channel: Option<u32>,
        ghost: [u8; 16],
        since: SystemTime,
    ) -> Result<Vec<LogLine>, StoreError> {
        self.inner.lines_by_ghost(channel, ghost, since)
    }

    fn channels(&self) -> Result<Vec<(u32, LineId)>, StoreError> {
        self.inner.channels()
    }

    fn delete_channel(&self, channel: u32) -> Result<usize, StoreError> {
        self.inner.delete_channel(channel)
    }

    fn find_guid(
        &self,
        channel: u32,
        sender: &str,
        guid: &MessageGuid,
    ) -> Result<Option<LineId>, StoreError> {
        self.inner.find_guid(channel, sender, guid)
    }

    fn find_signed(
        &self,
        signer: &[u8; 32],
        guid: &MessageGuid,
    ) -> Result<Option<SignedAt>, StoreError> {
        self.inner.find_signed(signer, guid)
    }

    fn room_marks(&self) -> Result<std::collections::HashMap<u32, bool>, StoreError> {
        self.inner.room_marks()
    }

    fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError> {
        self.inner.set_room_mark(room, signed)
    }

    fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError> {
        self.inner.holds_unsigned(channel)
    }

    fn restore_signed(&self, id: LineId, form: &[u8]) -> Result<(), StoreError> {
        self.inner.restore_signed(id, form)
    }

    fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.holds_home_key(key)
    }

    fn react(&self, act: &ReactAct) -> Result<Reacted, StoreError> {
        self.fails("react")?;
        self.panics(std::slice::from_ref(act));
        let out = self.inner.react(act);
        self.park("react");
        out
    }

    fn reactions(
        &self,
        ids: &[LineId],
        reader: Option<&Mailbox>,
    ) -> Result<std::collections::HashMap<LineId, Reactions>, StoreError> {
        self.fails("reactions")?;
        let out = self.inner.reactions(ids, reader);
        self.park("reactions");
        out
    }

    fn forget_reactions(
        &self,
        who: &Mailbox,
        since: SystemTime,
    ) -> Result<Vec<LineId>, StoreError> {
        self.inner.forget_reactions(who, since)
    }

    fn rekey_reactions(&self, from: &Mailbox, to: &Mailbox) -> Result<Vec<LineId>, StoreError> {
        self.inner.rekey_reactions(from, to)
    }

    fn reactors_on(
        &self,
        ids: &[LineId],
    ) -> Result<Vec<(LineId, String, ReactionKey)>, StoreError> {
        self.fails("reactors_on")?;
        self.inner.reactors_on(ids)
    }

    fn reactors(
        &self,
        line: LineId,
        key: &ReactionKey,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        self.fails("reactors")?;
        self.inner.reactors(line, key, limit)
    }

    fn clear_reactions(&self, channel: u32, line: LineId) -> Result<Option<usize>, StoreError> {
        self.fails("clear_reactions")?;
        let out = self.inner.clear_reactions(channel, line);
        self.park("clear_reactions");
        out
    }

    fn tombstone_all(
        &self,
        ids: &[LineId],
        by: &str,
        at: SystemTime,
    ) -> Result<Vec<LineId>, StoreError> {
        let on = *self.panics_on.lock().unwrap();
        if ids.iter().any(|id| Some(*id) == on) {
            panic!("a tombstone of line {on:?} panicked, as the test asked");
        }
        self.inner.tombstone_all(ids, by, at)
    }

    fn react_all(&self, acts: &[ReactAct]) -> Result<Vec<Reacted>, StoreError> {
        self.fails("react_all")?;
        self.runs.lock().unwrap().push(acts.len());
        self.panics(acts);
        let out = self.inner.react_all(acts);
        self.park("react_all");
        out
    }
}
