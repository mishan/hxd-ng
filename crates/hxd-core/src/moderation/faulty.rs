//! A moderation store that fails the methods a test names, and forwards
//! everything to a real [`MemoryModeration`] otherwise.

use std::collections::HashSet;
use std::sync::Mutex;

use super::*;

#[derive(Default)]
pub(crate) struct FaultyModeration {
    pub(crate) inner: MemoryModeration,
    failing: Mutex<HashSet<&'static str>>,
}

impl FaultyModeration {
    /// Fail `method` from now on.
    pub(crate) fn fail(&self, method: &'static str) {
        self.failing.lock().unwrap().insert(method);
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

impl ModerationStore for FaultyModeration {
    fn record(&self, act: &Act) -> Result<ActId, StoreError> {
        self.fails("record")?;
        self.inner.record(act)
    }

    fn acts(&self, before: Option<ActId>, limit: usize) -> Result<Vec<Act>, StoreError> {
        self.inner.acts(before, limit)
    }

    fn file(&self, report: &Report) -> Result<ReportId, StoreError> {
        self.inner.file(report)
    }

    fn report(&self, id: ReportId) -> Result<Option<Report>, StoreError> {
        self.inner.report(id)
    }

    fn reports(
        &self,
        filter: ReportFilter,
        before: Option<ReportId>,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError> {
        self.inner.reports(filter, before, limit)
    }

    fn open_count(&self) -> Result<usize, StoreError> {
        self.inner.open_count()
    }

    fn open_on(&self, target: &ReportTarget) -> Result<Vec<Report>, StoreError> {
        self.inner.open_on(target)
    }

    fn close(&self, id: ReportId, closed: &Closed) -> Result<bool, StoreError> {
        self.inner.close(id, closed)
    }

    fn holds_media(&self, handle: &Handle) -> Result<bool, StoreError> {
        self.inner.holds_media(handle)
    }

    fn block_hash(&self, hash: &[u8; 32], by: &str, at: SystemTime) -> Result<(), StoreError> {
        self.inner.block_hash(hash, by, at)
    }

    fn blocked_hashes(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        self.inner.blocked_hashes()
    }

    fn scrub_evidence(&self, before: SystemTime) -> Result<usize, StoreError> {
        self.inner.scrub_evidence(before)
    }

    fn prune_reports(&self, before: SystemTime) -> Result<usize, StoreError> {
        self.inner.prune_reports(before)
    }

    fn ban(&self, ban: &crate::ban::Ban) -> Result<crate::ban::Ban, StoreError> {
        self.inner.ban(ban)
    }

    fn lift_ban(
        &self,
        id: crate::ban::BanId,
        by: &str,
        at: SystemTime,
    ) -> Result<Option<crate::ban::Ban>, StoreError> {
        self.inner.lift_ban(id, by, at)
    }

    fn bans(
        &self,
        standing_at: Option<SystemTime>,
        before: Option<crate::ban::BanId>,
        limit: usize,
    ) -> Result<Vec<crate::ban::Ban>, StoreError> {
        self.inner.bans(standing_at, before, limit)
    }

    fn prune_bans(&self, before: SystemTime) -> Result<usize, StoreError> {
        self.inner.prune_bans(before)
    }

    fn note_link_ban(
        &self,
        id: crate::ban::BanId,
        requester: [u8; 8],
        handle: [u8; 16],
    ) -> Result<(), StoreError> {
        self.inner.note_link_ban(id, requester, handle)
    }

    fn link_ban(
        &self,
        requester: [u8; 8],
        handle: [u8; 16],
    ) -> Result<Option<crate::ban::BanId>, StoreError> {
        self.inner.link_ban(requester, handle)
    }

    fn record_network_ban(
        &self,
        ban: &crate::server_link::NetworkBan,
    ) -> Result<crate::server_link::NetworkBan, StoreError> {
        self.inner.record_network_ban(ban)
    }

    fn network_bans(&self) -> Result<Vec<crate::server_link::NetworkBan>, StoreError> {
        self.inner.network_bans()
    }

    fn ask_network_unban(
        &self,
        id: u64,
        at: SystemTime,
    ) -> Result<Option<crate::server_link::NetworkBan>, StoreError> {
        self.inner.ask_network_unban(id, at)
    }

    fn network_unbanned(&self, id: u64, at: SystemTime) -> Result<(), StoreError> {
        self.inner.network_unbanned(id, at)
    }
}
