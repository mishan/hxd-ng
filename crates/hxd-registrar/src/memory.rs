//! The registrar store in memory: what the domain's tests run on, and
//! the semantics the SQLite store is held to. Everything the SQL says in
//! SQL this says in Rust, and [`crate::conformance`] holds the two to the
//! same answers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::store::{
    entry_cost, Counts, Effect, HandleRow, IdentityRow, Issue, Issued, Key, NewRecord, Page,
    Pending, Publish, RecordFilter, RecordKind, Recovery, RegistrarStore, StoreError,
};

#[derive(Debug, Clone)]
struct LogEntry {
    identity: Key,
    handle: String,
    issued: u64,
    expires: u64,
    first: bool,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct State {
    identities: HashMap<Key, IdentityRow>,
    handles: BTreeMap<String, HandleRow>,
    /// The log, by seq.
    log: BTreeMap<u64, LogEntry>,
    records: BTreeMap<u64, NewRecord>,
    digests: HashMap<[u8; 32], u64>,
    pending: HashMap<Key, Pending>,
    recoveries: HashMap<String, Recovery>,
    /// Invite hash → spent.
    invites: HashMap<[u8; 32], bool>,
    next_log: u64,
    next_record: u64,
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn fingerprint(key: &Key) -> [u8; 32] {
    Sha256::digest(key).into()
}

fn page<'a>(items: impl Iterator<Item = (u64, &'a [u8])>, budget: usize) -> Page {
    let mut out = Page::default();
    let mut used = 0;
    for (seq, bytes) in items {
        let cost = entry_cost(bytes);
        if !out.entries.is_empty() && used + cost > budget {
            out.more = true;
            break;
        }
        used += cost;
        out.entries.push((seq, bytes.to_vec()));
    }
    out
}

impl State {
    fn apply(&mut self, effect: &Effect) {
        match effect {
            Effect::SetFrozen(key, frozen) => {
                if let Some(row) = self.identities.get_mut(key) {
                    row.frozen = *frozen;
                }
            }
            Effect::Revoke(key) => {
                if let Some(row) = self.identities.get_mut(key) {
                    row.revoked = true;
                }
            }
            Effect::Rotate { from, to, at } => {
                if let Some(row) = self.identities.get_mut(from) {
                    row.rotated_to = Some(*to);
                }
                self.identities.entry(*to).or_insert(IdentityRow {
                    key: *to,
                    commitment: None,
                    frozen: false,
                    revoked: false,
                    rotated_to: None,
                    created: *at,
                });
                for h in self.handles.values_mut() {
                    if h.identity == *from {
                        h.identity = *to;
                    }
                }
            }
            Effect::LapseHandles { identity, at } => {
                for h in self.handles.values_mut() {
                    if h.identity == *identity && h.lapsed_at.is_none() {
                        h.lapsed_at = Some(*at);
                    }
                }
            }
            Effect::LapseHandle { name, at, barred } => {
                if let Some(h) = self.handles.get_mut(name) {
                    if h.lapsed_at.is_none() {
                        h.lapsed_at = Some(*at);
                    }
                    h.barred |= *barred;
                }
            }
            Effect::GrantRecovery(r) => {
                self.recoveries.insert(r.handle.clone(), r.clone());
            }
            Effect::SetPending(p) => {
                self.pending.insert(p.identity, p.clone());
            }
            Effect::DropPending(key) => {
                self.pending.remove(key);
            }
        }
    }
}

impl RegistrarStore for MemoryStore {
    fn identity(&self, key: &Key) -> Result<Option<IdentityRow>, StoreError> {
        Ok(self.state.lock().unwrap().identities.get(key).cloned())
    }

    fn identity_by_fingerprint(&self, fp: &[u8; 32]) -> Result<Option<IdentityRow>, StoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .identities
            .values()
            .find(|r| &fingerprint(&r.key) == fp)
            .cloned())
    }

    fn handle(&self, name: &str) -> Result<Option<HandleRow>, StoreError> {
        Ok(self.state.lock().unwrap().handles.get(name).cloned())
    }

    fn handles_of(&self, key: &Key) -> Result<Vec<HandleRow>, StoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .handles
            .values()
            .filter(|h| &h.identity == key)
            .cloned()
            .collect())
    }

    fn recovery(&self, handle: &str) -> Result<Option<Recovery>, StoreError> {
        Ok(self.state.lock().unwrap().recoveries.get(handle).cloned())
    }

    fn issue(&self, w: &Issue) -> Result<Issued, StoreError> {
        let mut s = self.state.lock().unwrap();
        if let Some(hash) = &w.invite {
            match s.invites.get_mut(hash) {
                Some(spent @ false) => *spent = true,
                _ => return Ok(Issued::InviteSpent),
            }
        }
        let row = s.identities.entry(w.identity).or_insert(IdentityRow {
            key: w.identity,
            commitment: None,
            frozen: false,
            revoked: false,
            rotated_to: None,
            created: w.issued,
        });
        if row.commitment.is_none() {
            row.commitment = w.commitment;
        }
        s.handles.insert(w.handle.name.clone(), w.handle.clone());
        if let Some(name) = &w.recovery {
            s.recoveries.remove(name);
        }
        s.next_log += 1;
        let seq = s.next_log;
        s.log.insert(
            seq,
            LogEntry {
                identity: w.identity,
                handle: w.handle.name.clone(),
                issued: w.issued,
                expires: w.handle.expires,
                first: w.first,
                bytes: w.attestation.clone(),
            },
        );
        Ok(Issued::Logged(seq))
    }

    fn attestations_expire(
        &self,
        identity: &Key,
        handle: &str,
        issued_up_to: u64,
    ) -> Result<Option<u64>, StoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .log
            .values()
            .filter(|e| &e.identity == identity && e.handle == handle && e.issued <= issued_up_to)
            .map(|e| e.expires)
            .max())
    }

    fn publish(&self, p: &Publish) -> Result<Vec<u64>, StoreError> {
        let mut s = self.state.lock().unwrap();
        let mut seqs = Vec::with_capacity(p.records.len());
        for r in &p.records {
            if let Some(seq) = s.digests.get(&r.digest) {
                seqs.push(*seq);
                continue;
            }
            s.next_record += 1;
            let seq = s.next_record;
            s.digests.insert(r.digest, seq);
            s.records.insert(seq, r.clone());
            seqs.push(seq);
        }
        for e in &p.effects {
            s.apply(e);
        }
        Ok(seqs)
    }

    fn record_seq(&self, digest: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        Ok(self.state.lock().unwrap().digests.get(digest).copied())
    }

    fn set_commitment(&self, key: &Key, commitment: &[u8; 32]) -> Result<bool, StoreError> {
        let mut s = self.state.lock().unwrap();
        match s.identities.get_mut(key) {
            Some(row) if row.commitment.is_none() => {
                row.commitment = Some(*commitment);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn pending(&self, key: &Key) -> Result<Option<Pending>, StoreError> {
        Ok(self.state.lock().unwrap().pending.get(key).cloned())
    }

    fn pending_due(&self, now: u64) -> Result<Vec<Pending>, StoreError> {
        let s = self.state.lock().unwrap();
        let mut due: Vec<Pending> = s
            .pending
            .values()
            .filter(|p| p.publish_at <= now)
            .cloned()
            .collect();
        due.sort_by_key(|p| (p.publish_at, p.identity));
        Ok(due)
    }

    fn records_page(
        &self,
        filter: RecordFilter,
        since: u64,
        budget: usize,
    ) -> Result<Page, StoreError> {
        let s = self.state.lock().unwrap();
        // For the full list: the device revocations each identity keeps
        // in it — its latest `device_cap` by `until`, ties to the later
        // seq.
        let kept: HashSet<u64> = match filter {
            RecordFilter::Identity(_) => HashSet::new(),
            RecordFilter::All { device_cap, .. } => {
                let mut by_identity: HashMap<Key, Vec<(u64, u64)>> = HashMap::new();
                for (seq, r) in &s.records {
                    if r.kind == RecordKind::RevokeDevice {
                        by_identity
                            .entry(r.identity)
                            .or_default()
                            .push((r.until.unwrap_or(u64::MAX), *seq));
                    }
                }
                let mut kept = HashSet::new();
                for mut v in by_identity.into_values() {
                    v.sort_by(|a, b| b.cmp(a));
                    kept.extend(v.into_iter().take(device_cap).map(|(_, seq)| seq));
                }
                kept
            }
        };
        let visible = |seq: u64, r: &NewRecord| match filter {
            RecordFilter::Identity(key) => r.identity == key || r.other == Some(key),
            RecordFilter::All { now, .. } => {
                let live = r.until.is_none_or(|u| u >= now);
                match r.kind {
                    RecordKind::RevokeDevice => live && kept.contains(&seq),
                    RecordKind::RevokeAttestation => live,
                    _ => true,
                }
            }
        };
        Ok(page(
            s.records
                .range(since.saturating_add(1)..)
                .filter(|(seq, r)| visible(**seq, r))
                .map(|(seq, r)| (*seq, r.bytes.as_slice())),
            budget,
        ))
    }

    fn log_page(&self, since: u64, budget: usize) -> Result<Page, StoreError> {
        let s = self.state.lock().unwrap();
        Ok(page(
            s.log
                .range(since.saturating_add(1)..)
                .map(|(seq, e)| (*seq, e.bytes.as_slice())),
            budget,
        ))
    }

    fn counts(&self, now: u64) -> Result<Counts, StoreError> {
        let s = self.state.lock().unwrap();
        let holders: HashSet<Key> = s
            .handles
            .values()
            .filter(|h| h.lapsed(now).is_none())
            .map(|h| h.identity)
            .collect();
        let first = |since: u64| {
            s.log
                .values()
                .filter(|e| e.first && e.issued > since)
                .count() as u64
        };
        Ok(Counts {
            identities: holders.len() as u64,
            issued_24h: first(now.saturating_sub(86_400)),
            issued_7d: first(now.saturating_sub(7 * 86_400)),
            issued_total: s.log.values().filter(|e| e.first).count() as u64,
            revoked_total: s
                .records
                .values()
                .filter(|r| r.kind == RecordKind::RevokeAttestation)
                .count() as u64,
            frozen: s.identities.values().filter(|r| r.frozen).count() as u64,
            log_seq: s.log.keys().next_back().copied().unwrap_or(0),
        })
    }

    fn invite_open(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.state.lock().unwrap().invites.get(hash) == Some(&false))
    }

    fn add_invites(&self, hashes: &[[u8; 32]]) -> Result<usize, StoreError> {
        let mut s = self.state.lock().unwrap();
        let mut added = 0;
        for h in hashes {
            if !s.invites.contains_key(h) {
                s.invites.insert(*h, false);
                added += 1;
            }
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        crate::conformance::run(&|| Box::new(MemoryStore::new()));
    }
}
