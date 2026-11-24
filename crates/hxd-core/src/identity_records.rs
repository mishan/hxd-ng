//! The record lists registrars publish against keys, as this server
//! fetched them (`docs/identity-records.md` §2). Kept so that a restart
//! while a registrar cannot be reached still has the last list to use.
//! A list is verified again as it is read back, under the keys kept
//! with it. Beside them, when each key was first seen here, which the
//! newcomer delay (`identity-registrar.md` §7.3) counts from, and the
//! device epoch records seen for each identity, kept apart from the
//! lists so that a list that no longer carries one lowers no floor
//! (`docs/identity-records.md` §3).

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

/// A device epoch record kept for an identity: for its `epoch`, the one
/// with the earliest `time` seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptEpoch {
    pub epoch: u64,
    /// The record's `time`.
    pub time: u64,
    /// The record as the identity signed it, which the reader verifies
    /// again: what is kept here is never taken on its word.
    pub record: Vec<u8>,
}

pub trait RecordCache: Send + Sync {
    /// Keep `list` for `identity`, replacing what its registrar's last
    /// one said.
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError>;
    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError>;
    /// Keep `list`, which a list fetched for `identity` replaced while the
    /// resets it carries could not be kept, until [`Self::release_superseded`],
    /// in place of the one held from its registrar.
    fn hold_superseded(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError>;
    fn superseded(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError>;
    /// Forget what is held for `identity`: its resets are kept.
    fn release_superseded(&self, identity: &[u8; 32]) -> Result<(), StoreError>;
    /// When `identity` was first seen, in unix seconds: the sighting kept,
    /// if it is younger than [`FIRST_SEEN_KEPT`], or `now`, kept from here.
    fn first_seen(&self, identity: &[u8; 32], now: u64) -> Result<u64, StoreError>;
    /// Keep `kept` for `identity`, unless what is kept for its epoch has
    /// an earlier `time`. Nothing kept is ever removed.
    fn keep_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError>;
    /// Keep `kept` for `identity` in place of whatever is kept for its
    /// epoch: for a reader that found what is kept did not verify.
    fn replace_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError>;
    /// The device epoch records kept for `identity`, unverified.
    fn epochs(&self, identity: &[u8; 32]) -> Result<Vec<KeptEpoch>, StoreError>;
    /// Every identity with a device epoch record kept, once each.
    fn identities_with_epochs(&self) -> Result<Vec<[u8; 32]>, StoreError>;
}

/// A [`RecordCache`] a restart forgets, for a server without a store.
#[derive(Default)]
pub struct MemoryRecordCache {
    lists: Mutex<HashMap<([u8; 32], String), CachedList>>,
    seen: Mutex<HashMap<[u8; 32], u64>>,
    epochs: Mutex<HashMap<([u8; 32], u64), KeptEpoch>>,
    superseded: Mutex<HashMap<[u8; 32], Vec<CachedList>>>,
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

    fn hold_superseded(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        let mut held = self.superseded.lock().unwrap();
        let lists = held.entry(*identity).or_default();
        lists.retain(|l| l.registrar != list.registrar);
        lists.push(list.clone());
        Ok(())
    }

    fn superseded(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        let held = self.superseded.lock().unwrap();
        Ok(held.get(identity).cloned().unwrap_or_default())
    }

    fn release_superseded(&self, identity: &[u8; 32]) -> Result<(), StoreError> {
        self.superseded.lock().unwrap().remove(identity);
        Ok(())
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

    fn keep_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let mut epochs = self.epochs.lock().unwrap();
        let held = epochs
            .entry((*identity, kept.epoch))
            .or_insert_with(|| kept.clone());
        if kept.time < held.time {
            *held = kept.clone();
        }
        Ok(())
    }

    fn replace_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let mut epochs = self.epochs.lock().unwrap();
        epochs.insert((*identity, kept.epoch), kept.clone());
        Ok(())
    }

    fn epochs(&self, identity: &[u8; 32]) -> Result<Vec<KeptEpoch>, StoreError> {
        let epochs = self.epochs.lock().unwrap();
        Ok(epochs
            .iter()
            .filter(|((id, _), _)| id == identity)
            .map(|(_, kept)| kept.clone())
            .collect())
    }

    fn identities_with_epochs(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let epochs = self.epochs.lock().unwrap();
        let ids: std::collections::BTreeSet<[u8; 32]> = epochs.keys().map(|(id, _)| *id).collect();
        Ok(ids.into_iter().collect())
    }
}

impl crate::Core {
    /// Keep the registrars' record lists in `cache`, which outlives a
    /// restart.
    pub fn with_record_cache(mut self, cache: std::sync::Arc<dyn RecordCache>) -> Self {
        let reconciled = self.reconciled.clone();
        self.record_cache = Some(std::sync::Arc::new(crate::messaging::Watched {
            inner: cache,
            reconciled,
        }));
        self
    }

    pub fn record_cache(&self) -> Option<std::sync::Arc<dyn RecordCache>> {
        self.record_cache.clone()
    }
}

/// A suite every [`RecordCache`] must pass: the in-memory one here and
/// the SQLite one a server keeps its records in.
pub mod conformance {
    use super::*;

    /// Run every case against a freshly built store.
    pub fn run(new_store: &dyn Fn() -> Box<dyn RecordCache>) {
        an_epoch_kept_is_replaced_by_an_earlier_time_or_in_place(&*new_store());
        a_superseded_list_is_held_one_a_registrar_until_released(&*new_store());
    }

    fn a_superseded_list_is_held_one_a_registrar_until_released(store: &dyn RecordCache) {
        let list = |registrar: &str, fetched| CachedList {
            registrar: registrar.into(),
            pages: vec![vec![fetched as u8]],
            keys: vec![([1; 32], None)],
            fetched,
        };
        let (alice, bob) = ([1; 32], [2; 32]);
        for l in [list("a", 1), list("b", 1), list("a", 2)] {
            store.hold_superseded(&alice, &l).unwrap();
        }
        store.hold_superseded(&bob, &list("a", 3)).unwrap();
        let mut held = store.superseded(&alice).unwrap();
        held.sort_by(|x, y| x.registrar.cmp(&y.registrar));
        assert_eq!(held, [list("a", 2), list("b", 1)], "one a registrar");
        assert!(
            store.lists(&alice).unwrap().is_empty(),
            "apart from the lists"
        );
        store.release_superseded(&alice).unwrap();
        assert!(store.superseded(&alice).unwrap().is_empty());
        assert_eq!(store.superseded(&bob).unwrap(), [list("a", 3)]);
    }

    fn an_epoch_kept_is_replaced_by_an_earlier_time_or_in_place(store: &dyn RecordCache) {
        let kept = |epoch, time| KeptEpoch {
            epoch,
            time,
            record: vec![epoch as u8, time as u8],
        };
        let (alice, bob) = ([1; 32], [2; 32]);
        assert!(store.epochs(&alice).unwrap().is_empty());
        for k in [
            kept(1, 20),
            kept(2, 30),
            kept(1, 10),
            kept(1, 15),
            kept(2, 40),
        ] {
            store.keep_epoch(&alice, &k).unwrap();
        }
        store.keep_epoch(&bob, &kept(5, 50)).unwrap();
        let mut held = store.epochs(&alice).unwrap();
        held.sort_by_key(|k| k.epoch);
        assert_eq!(held, [kept(1, 10), kept(2, 30)]);
        assert_eq!(store.epochs(&bob).unwrap(), [kept(5, 50)]);
        store.replace_epoch(&bob, &kept(5, 60)).unwrap();
        assert_eq!(store.epochs(&bob).unwrap(), [kept(5, 60)]);
        let mut ids = store.identities_with_epochs().unwrap();
        ids.sort_unstable();
        assert_eq!(ids, [alice, bob], "each once");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn passes_the_conformance_suite() {
        super::conformance::run(&|| Box::new(super::MemoryRecordCache::default()));
    }
}
