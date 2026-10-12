//! The record lists registrars publish against keys, as this server
//! fetched them (`docs/identity-records.md` §2). Kept so that a restart
//! while a registrar cannot be reached still has the last list to use.
//! A list is verified again as it is read back, under the keys kept
//! with it. Beside them, when each key was first seen here, which the
//! newcomer delay (`identity-registrar.md` §7.3) counts from.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::inbox::StoreError;

/// How long a first sighting is remembered: a reconnect within it does
/// not start the newcomer delay again, and one after it does.
pub const FIRST_SEEN_KEPT: u64 = 24 * 3600;

/// One registrar's signed list for one identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedList {
    pub registrar: String,
    /// The list as the registrar signed it: its pages, in order, each
    /// signed on its own.
    pub pages: Vec<Vec<u8>>,
    /// The registrar's keys it verified under, which it is verified
    /// under again: a restart while the registrar cannot be reached has
    /// no discovery document to read them from. Each with the `until`
    /// a retiring key was published with.
    pub keys: Vec<([u8; 32], Option<u64>)>,
    /// Unix seconds, when it was fetched.
    pub fetched: u64,
}

pub trait RecordCache: Send + Sync {
    /// Keep `list` for `identity`, replacing what its registrar's last
    /// one said.
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError>;
    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError>;
    /// When `identity` was first seen, in unix seconds: the sighting kept,
    /// if it is younger than [`FIRST_SEEN_KEPT`], or `now`, kept from here.
    fn first_seen(&self, identity: &[u8; 32], now: u64) -> Result<u64, StoreError>;
}

/// A [`RecordCache`] a restart forgets, for a server without a store.
#[derive(Default)]
pub struct MemoryRecordCache {
    lists: Mutex<HashMap<([u8; 32], String), CachedList>>,
    seen: Mutex<HashMap<[u8; 32], u64>>,
}

impl RecordCache for MemoryRecordCache {
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        self.lists
            .lock()
            .unwrap()
            .insert((*identity, list.registrar.clone()), list.clone());
        Ok(())
    }

    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        let lists = self.lists.lock().unwrap();
        Ok(lists
            .iter()
            .filter(|((id, _), _)| id == identity)
            .map(|(_, list)| list.clone())
            .collect())
    }

    fn first_seen(&self, identity: &[u8; 32], now: u64) -> Result<u64, StoreError> {
        let mut seen = self.seen.lock().unwrap();
        let fresh = |at: &u64| now.saturating_sub(*at) < FIRST_SEEN_KEPT;
        if let Some(at) = seen.get(identity).filter(|at| fresh(at)) {
            return Ok(*at);
        }
        seen.retain(|_, at| fresh(at));
        seen.insert(*identity, now);
        Ok(now)
    }
}

impl crate::Core {
    /// Keep the registrars' record lists in `cache`, which outlives a
    /// restart.
    pub fn with_record_cache(mut self, cache: std::sync::Arc<dyn RecordCache>) -> Self {
        self.record_cache = Some(cache);
        self
    }

    pub fn record_cache(&self) -> Option<std::sync::Arc<dyn RecordCache>> {
        self.record_cache.clone()
    }
}
