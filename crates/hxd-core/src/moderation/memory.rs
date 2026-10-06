//! The moderation store in a few `Vec`s: what the domain tests use, and
//! what a server with no database keeps its reports in until it stops.

use std::sync::Mutex;
use std::time::SystemTime;

use super::{
    Act, ActId, ActKind, Closed, Handle, ModerationStore, Report, ReportFilter, ReportId,
    ReportTarget,
};
use crate::inbox::StoreError;

#[derive(Default)]
struct Inner {
    acts: Vec<Act>,
    reports: Vec<Report>,
    /// Ids are never reused, even once retention has taken rows: a
    /// moderator's "#17" names one report forever.
    last_report: ReportId,
    blocked: Vec<[u8; 32]>,
    bans: Vec<crate::ban::Ban>,
    last_ban: crate::ban::BanId,
    link_bans: std::collections::HashMap<[u8; 16], ([u8; 8], crate::ban::BanId)>,
    network_bans: Vec<crate::server_link::NetworkBan>,
    last_network_ban: u64,
    /// Bans still to write before every later one fails, for the tests
    /// of a store that fails partway.
    #[cfg(test)]
    bans_before_failing: Option<usize>,
}

/// A [`ModerationStore`] in memory.
#[derive(Default)]
pub struct MemoryModeration {
    inner: Mutex<Inner>,
}

/// Does an open report name `target`? For a person, every open report on
/// one; the caller narrows by whom.
fn names(r: &Report, target: &ReportTarget) -> bool {
    match (target, r.target) {
        (ReportTarget::User, ReportTarget::User) => true,
        (t, rt) => *t == rt,
    }
}

#[cfg(test)]
impl MemoryModeration {
    /// Write `n` more bans, then fail every one after.
    pub(crate) fn fail_bans_after(&self, n: usize) {
        self.inner.lock().unwrap().bans_before_failing = Some(n);
    }
}

impl ModerationStore for MemoryModeration {
    fn record(&self, act: &Act) -> Result<ActId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.acts.len() as ActId + 1;
        inner.acts.push(Act { id, ..act.clone() });
        Ok(id)
    }

    fn acts(&self, before: Option<ActId>, limit: usize) -> Result<Vec<Act>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .acts
            .iter()
            .rev()
            .filter(|a| before.is_none_or(|b| a.id < b))
            .take(limit)
            .cloned()
            .collect())
    }

    fn file(&self, report: &Report) -> Result<ReportId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.last_report += 1;
        let id = inner.last_report;
        inner.reports.push(Report {
            id,
            ..report.clone()
        });
        Ok(id)
    }

    fn report(&self, id: ReportId) -> Result<Option<Report>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.reports.iter().find(|r| r.id == id).cloned())
    }

    fn reports(
        &self,
        filter: ReportFilter,
        before: Option<ReportId>,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .reports
            .iter()
            .rev()
            .filter(|r| filter.admits(r) && before.is_none_or(|b| r.id < b))
            .take(limit)
            .cloned()
            .collect())
    }

    fn open_count(&self) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.reports.iter().filter(|r| r.closed.is_none()).count())
    }

    fn open_on(&self, target: &ReportTarget) -> Result<Vec<Report>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .reports
            .iter()
            .filter(|r| r.closed.is_none() && names(r, target))
            .cloned()
            .collect())
    }

    fn close(&self, id: ReportId, closed: &Closed) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        match inner
            .reports
            .iter_mut()
            .find(|r| r.id == id && r.closed.is_none())
        {
            Some(r) => {
                r.closed = Some(closed.clone());
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn holds_media(&self, handle: &Handle) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .reports
            .iter()
            .any(|r| r.closed.is_none() && r.media == Some(*handle)))
    }

    fn block_hash(&self, hash: &[u8; 32], _by: &str, _at: SystemTime) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.blocked.contains(hash) {
            inner.blocked.push(*hash);
        }
        Ok(())
    }

    fn blocked_hashes(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        Ok(self.inner.lock().unwrap().blocked.clone())
    }

    fn scrub_evidence(&self, before: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        for act in inner
            .acts
            .iter_mut()
            .filter(|a| a.at < before && a.kind != ActKind::Close)
        {
            if act.evidence.as_deref().is_some_and(|e| !e.is_empty()) {
                act.evidence = Some(String::new());
                n += 1;
            }
        }
        Ok(n)
    }

    fn prune_reports(&self, before: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let was = inner.reports.len();
        inner
            .reports
            .retain(|r| r.closed.as_ref().is_none_or(|c| c.at >= before));
        Ok(was - inner.reports.len())
    }

    fn ban(&self, ban: &crate::ban::Ban) -> Result<crate::ban::Ban, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(test)]
        if let Some(n) = inner.bans_before_failing.as_mut() {
            if *n == 0 {
                return Err(StoreError::new("the disk is full"));
            }
            *n -= 1;
        }
        if let Some(old) = inner
            .bans
            .iter_mut()
            .find(|b| b.lifted_at.is_none() && b.target == ban.target)
        {
            if old.standing(ban.created_at) {
                *old = super::extend_ban(old, ban);
                return Ok(old.clone());
            }
            old.lifted_at = old.expires_at;
        }
        inner.last_ban += 1;
        let ban = crate::ban::Ban {
            id: inner.last_ban,
            ..ban.clone()
        };
        inner.bans.push(ban.clone());
        Ok(ban)
    }

    fn lift_ban(
        &self,
        id: crate::ban::BanId,
        by: &str,
        at: SystemTime,
    ) -> Result<Option<crate::ban::Ban>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(inner
            .bans
            .iter_mut()
            .find(|b| b.id == id && b.lifted_at.is_none())
            .map(|b| {
                b.lifted_at = Some(at);
                b.lifted_by = Some(by.to_owned());
                b.clone()
            }))
    }

    fn bans(
        &self,
        standing_at: Option<SystemTime>,
        before: Option<crate::ban::BanId>,
        limit: usize,
    ) -> Result<Vec<crate::ban::Ban>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .bans
            .iter()
            .rev()
            .filter(|b| {
                before.is_none_or(|id| b.id < id) && standing_at.is_none_or(|now| b.standing(now))
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn prune_bans(&self, before: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let was = inner.bans.len();
        inner.bans.retain(|b| {
            b.lifted_at.is_none_or(|at| at >= before) && b.expires_at.is_none_or(|at| at >= before)
        });
        let Inner {
            bans, link_bans, ..
        } = &mut *inner;
        link_bans.retain(|_, (_, id)| bans.iter().any(|b| b.id == *id));
        inner.network_bans.retain(|b| {
            b.lifted_at.is_none_or(|at| at >= before) && b.expires_at.is_none_or(|at| at >= before)
        });
        Ok(was - inner.bans.len())
    }

    fn note_link_ban(
        &self,
        id: crate::ban::BanId,
        requester: [u8; 8],
        handle: [u8; 16],
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.link_bans.insert(handle, (requester, id));
        Ok(())
    }

    fn record_network_ban(
        &self,
        ban: &crate::server_link::NetworkBan,
    ) -> Result<crate::server_link::NetworkBan, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.last_network_ban += 1;
        let id = inner.last_network_ban;
        let row = crate::server_link::NetworkBan { id, ..ban.clone() };
        inner.network_bans.push(row.clone());
        Ok(row)
    }

    fn network_bans(&self) -> Result<Vec<crate::server_link::NetworkBan>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.network_bans.iter().rev().cloned().collect())
    }

    fn ask_network_unban(
        &self,
        id: u64,
        at: SystemTime,
    ) -> Result<Option<crate::server_link::NetworkBan>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(inner
            .network_bans
            .iter_mut()
            .find(|b| b.id == id && b.standing(at))
            .map(|b| {
                b.lift_asked = Some(at);
                b.clone()
            }))
    }

    fn network_unbanned(&self, id: u64, at: SystemTime) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(b) = inner.network_bans.iter_mut().find(|b| b.id == id) {
            b.lifted_at.get_or_insert(at);
        }
        Ok(())
    }

    fn link_ban(
        &self,
        requester: [u8; 8],
        handle: [u8; 16],
    ) -> Result<Option<crate::ban::BanId>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .link_bans
            .get(&handle)
            .filter(|(by, _)| *by == requester)
            .map(|(_, id)| *id))
    }
}
