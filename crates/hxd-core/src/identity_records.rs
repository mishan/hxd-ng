//! The record lists registrars publish against keys, as this server
//! fetched them (`docs/identity-records.md` §2). Kept so that a restart
//! while a registrar cannot be reached still has the last list to use.
//! A list is verified again as it is read back, under the keys kept
//! with it.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::inbox::StoreError;

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
}

/// A [`RecordCache`] a restart forgets, for a server without a store.
#[derive(Default)]
pub struct MemoryRecordCache(Mutex<HashMap<([u8; 32], String), CachedList>>);

impl RecordCache for MemoryRecordCache {
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        self.0
            .lock()
            .unwrap()
            .insert((*identity, list.registrar.clone()), list.clone());
        Ok(())
    }

    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        let lists = self.0.lock().unwrap();
        Ok(lists
            .iter()
            .filter(|((id, _), _)| id == identity)
            .map(|(_, list)| list.clone())
            .collect())
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
