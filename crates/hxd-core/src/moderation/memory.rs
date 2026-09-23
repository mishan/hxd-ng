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
}
