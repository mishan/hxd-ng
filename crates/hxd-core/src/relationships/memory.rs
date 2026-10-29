//! An in-memory [`RelationshipStore`], for the domain's tests and for a
//! server whose inbox is in memory too. [`super::conformance`] holds it
//! to the SQLite store's answers.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    AccountUpdate, Ignore, LedgerEntry, MessagingAccount, PendingOut, Recorded, Rekeyed,
    RelationId, Relationship, RelationshipStore, RequestKind, Requester, MAX_LANGUAGES,
};
use crate::inbox::{Mailbox, MessageGuid, Sent, StoreError};

struct Row {
    /// Creation order, which is the order rows are listed in.
    seq: u64,
    rel: Relationship,
}

/// One side of a hold: either key may be gone, never both.
struct HoldKey {
    login: Option<String>,
    fingerprint: Option<[u8; 32]>,
}

impl HoldKey {
    fn of(m: &Mailbox) -> Self {
        HoldKey {
            login: Some(m.login.clone()),
            fingerprint: m.fingerprint,
        }
    }

    /// A hold's match: either key.
    fn loosely(&self, m: &Mailbox) -> bool {
        self.login.as_deref() == Some(m.login.as_str())
            || (self.fingerprint.is_some() && self.fingerprint == m.fingerprint)
    }

    /// Whether a purge of `m` takes it: its fingerprint, or its login
    /// with no fingerprint beside it.
    fn purged_by(&self, m: &Mailbox) -> bool {
        let bare = self.fingerprint.is_none() && self.login.as_deref() == Some(m.login.as_str());
        bare || (m.fingerprint.is_some() && self.fingerprint == m.fingerprint)
    }

    /// What a purge of `m` leaves of it: the fingerprint alone.
    fn strip(&mut self, m: &Mailbox) {
        if self.login.as_deref() == Some(m.login.as_str()) {
            self.login = None;
        }
    }

    fn stamp(&mut self, moves: &impl Fn(&Mailbox) -> bool, to: &[u8; 32]) -> usize {
        let m = Mailbox {
            login: self.login.clone().unwrap_or_default(),
            fingerprint: self.fingerprint,
        };
        if moves(&m) {
            self.fingerprint = Some(*to);
            1
        } else {
            0
        }
    }
}

enum Held {
    Account(HoldKey),
    Address(String),
}

impl Held {
    fn of(r: &Requester) -> Self {
        match r {
            Requester::Account(m) => Held::Account(HoldKey::of(m)),
            Requester::Address(a) => Held::Address(a.clone()),
        }
    }

    fn matches(&self, r: &Requester) -> bool {
        match (self, r) {
            (Held::Account(h), Requester::Account(m)) => h.loosely(m),
            (Held::Address(h), Requester::Address(a)) => h == a,
            _ => false,
        }
    }

    fn purged_by(&self, m: &Mailbox) -> bool {
        matches!(self, Held::Account(h) if h.purged_by(m))
    }
}

struct Hold {
    owner: HoldKey,
    held: Held,
    until: SystemTime,
}

struct Account {
    owner: Mailbox,
    state: MessagingAccount,
    dropped: u64,
}

#[derive(Default)]
struct Inner {
    next_seq: u64,
    next_relation: RelationId,
    rows: Vec<Row>,
    /// The friendships and approvals that are live.
    relations: BTreeSet<RelationId>,
    holds: Vec<Hold>,
    ledger: Vec<LedgerEntry>,
    accounts: Vec<Account>,
}

#[derive(Default)]
pub struct MemoryRelationships {
    inner: Mutex<Inner>,
}

impl MemoryRelationships {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is this friendship or approval live? What the in-memory inbox's
    /// gate asks ([`crate::inbox::MemoryStore::gated`]).
    pub fn is_live(&self, id: RelationId) -> bool {
        self.inner.lock().unwrap().relations.contains(&id)
    }

    /// Is this an approval rather than a friendship?
    pub fn is_approval(&self, id: RelationId) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.rows.iter().any(|r| r.rel.approval == Some(id))
    }
}

fn is(m: &Mailbox, key: &Mailbox) -> bool {
    key.matches(&m.login, m.fingerprint.as_ref())
}

fn sent_by(e: &LedgerEntry, from: &Requester) -> bool {
    match (from, &e.sender) {
        (Requester::Account(m), Some(s)) => is(s, m),
        (Requester::Address(a), None) => e.address.as_deref() == Some(a),
        _ => false,
    }
}

/// The SQLite store's spelling of a mailbox key, `IFNULL(<col>_fp,
/// <col>)`, for counting distinct recipients alike.
fn key(m: &Mailbox) -> String {
    match m.fingerprint {
        Some(fp) => fp.iter().map(|b| format!("{b:02x}")).collect(),
        None => m.login.clone(),
    }
}

/// Times as SQLite keeps them, whole seconds, so ordering by one agrees.
fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A time to the second, as every time here is kept and compared.
fn floor(t: SystemTime) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs(t))
}

fn floor_row(r: &mut Relationship) {
    r.blocked_at = r.blocked_at.map(floor);
    if let Some(p) = r.pending_out.as_mut() {
        p.sent_at = floor(p.sent_at);
        p.lapses_at = floor(p.lapses_at);
    }
    if let Some(i) = r.ignore.as_mut() {
        i.until = i.until.map(floor);
    }
}

impl Inner {
    fn find(&self, owner: &Mailbox, other: &Mailbox) -> Option<usize> {
        self.rows
            .iter()
            .position(|r| is(&r.rel.owner, owner) && is(&r.rel.other, other))
    }

    /// Change one row, creating it if need be and dropping it if nothing
    /// is left in it.
    fn edit<T>(
        &mut self,
        owner: &Mailbox,
        other: &Mailbox,
        f: impl FnOnce(&mut Relationship) -> T,
    ) -> T {
        let i = match self.find(owner, other) {
            Some(i) => i,
            None => {
                self.next_seq += 1;
                self.rows.push(Row {
                    seq: self.next_seq,
                    rel: Relationship::new(owner, other),
                });
                self.rows.len() - 1
            }
        };
        let out = f(&mut self.rows[i].rel);
        floor_row(&mut self.rows[i].rel);
        self.rows[i].rel.settle();
        if self.rows[i].rel.is_empty() {
            self.rows.remove(i);
        }
        out
    }

    fn mint(&mut self) -> RelationId {
        self.next_relation += 1;
        self.relations.insert(self.next_relation);
        self.next_relation
    }

    /// Drop ids no row points at any more.
    fn forget(&mut self, ids: impl IntoIterator<Item = RelationId>) {
        for id in ids {
            let held = self
                .rows
                .iter()
                .any(|r| r.rel.friendship == Some(id) || r.rel.approval == Some(id));
            if !held {
                self.relations.remove(&id);
            }
        }
    }

    fn account_mut(&mut self, of: &Mailbox) -> &mut Account {
        let i = match self.accounts.iter().position(|a| is(&a.owner, of)) {
            Some(i) => i,
            None => {
                self.accounts.push(Account {
                    owner: of.clone(),
                    state: MessagingAccount::default(),
                    dropped: 0,
                });
                self.accounts.len() - 1
            }
        };
        &mut self.accounts[i]
    }

    /// Re-key every mailbox `moves` names with `to`, folding together
    /// what that makes duplicates of.
    fn rekey(&mut self, moves: impl Fn(&Mailbox) -> bool, to: &[u8; 32]) -> Rekeyed {
        let stamp = |m: &mut Mailbox| {
            if moves(m) {
                m.fingerprint = Some(*to);
                1
            } else {
                0
            }
        };
        let after = |m: &Mailbox| {
            if moves(m) {
                key(&Mailbox::identified("", *to))
            } else {
                key(m)
            }
        };
        // A row that moves onto a pair some row already holds is folded
        // into that row, which is kept, as the SQLite store's unique
        // index would have it.
        let mut merged = Vec::new();
        let mut n = 0;
        let mut i = 0;
        while i < self.rows.len() {
            let r = &self.rows[i].rel;
            if !(moves(&r.owner) || moves(&r.other)) {
                i += 1;
                continue;
            }
            let pair = (after(&r.owner), after(&r.other));
            let kept = self.rows.iter().position(|k| {
                !(moves(&k.rel.owner) || moves(&k.rel.other))
                    && (key(&k.rel.owner), key(&k.rel.other)) == pair
            });
            match kept {
                Some(k) => {
                    let dup = self.rows.remove(i).rel;
                    let k = if k > i { k - 1 } else { k };
                    merged.extend(self.rows[k].rel.absorb(dup));
                    n += 1;
                }
                None => i += 1,
            }
        }
        self.forget(merged.iter().map(|(lost, _)| *lost));
        for r in self.rows.iter_mut() {
            n += stamp(&mut r.rel.owner) + stamp(&mut r.rel.other);
        }
        for h in self.holds.iter_mut() {
            n += h.owner.stamp(&moves, to);
            if let Held::Account(k) = &mut h.held {
                n += k.stamp(&moves, to);
            }
        }
        for e in self.ledger.iter_mut() {
            n += stamp(&mut e.recipient);
            if let Some(s) = e.sender.as_mut() {
                n += stamp(s);
            }
        }
        let target = Mailbox::identified("", *to);
        let mut j = 0;
        while j < self.accounts.len() {
            let a = &self.accounts[j];
            if moves(&a.owner) && self.accounts.iter().any(|k| is(&k.owner, &target)) {
                self.accounts.remove(j);
            } else {
                j += 1;
            }
        }
        for a in self.accounts.iter_mut() {
            n += stamp(&mut a.owner);
        }
        merged.sort_unstable();
        merged.dedup();
        Rekeyed { moved: n, merged }
    }

    fn purge(&mut self, of: &Mailbox) -> usize {
        let doomed = |r: &Relationship| is(&r.owner, of) || is(&r.other, of);
        let ids: Vec<RelationId> = self
            .rows
            .iter()
            .filter(|r| doomed(&r.rel))
            .flat_map(|r| [r.rel.friendship, r.rel.approval])
            .flatten()
            .collect();
        let before = self.rows.len() + self.holds.len() + self.ledger.len() + self.accounts.len();
        self.rows.retain(|r| !doomed(&r.rel));
        self.holds
            .retain(|h| !h.owner.purged_by(of) && !h.held.purged_by(of));
        for h in self.holds.iter_mut() {
            h.owner.strip(of);
            if let Held::Account(k) = &mut h.held {
                k.strip(of);
            }
        }
        self.ledger
            .retain(|e| !is(&e.recipient, of) && !e.sender.as_ref().is_some_and(|s| is(s, of)));
        self.accounts.retain(|a| !is(&a.owner, of));
        self.forget(ids);
        before - (self.rows.len() + self.holds.len() + self.ledger.len() + self.accounts.len())
    }
}

impl RelationshipStore for MemoryRelationships {
    fn relationship(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        now: SystemTime,
    ) -> Result<Option<Relationship>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .find(owner, other)
            .and_then(|i| inner.rows[i].rel.clone().as_of(floor(now))))
    }

    fn relationships(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .rows
            .iter()
            .filter(|r| is(&r.rel.owner, owner))
            .filter_map(|r| r.rel.clone().as_of(floor(now)))
            .collect())
    }

    fn pending_in(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<(u64, u64, Relationship)> = inner
            .rows
            .iter()
            .filter(|r| is(&r.rel.other, owner))
            .filter_map(|r| Some((r.seq, r.rel.clone().as_of(floor(now))?)))
            .filter_map(|(seq, rel)| {
                let p = rel.pending_out.as_ref().filter(|p| p.delivered)?;
                Some((secs(p.sent_at), seq, rel))
            })
            .collect();
        rows.sort_by_key(|(at, seq, _)| (*at, *seq));
        Ok(rows.into_iter().map(|(_, _, r)| r).collect())
    }

    fn roster_size(&self, owner: &Mailbox, now: SystemTime) -> Result<usize, StoreError> {
        Ok(self.relationships(owner, now)?.len())
    }

    fn set_alias(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        alias: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.edit(owner, other, |r| r.alias = alias.map(str::to_owned));
        Ok(())
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.edit(owner, other, |r| {
            r.blocked_at = if blocked {
                r.blocked_at.or(Some(at))
            } else {
                None
            }
        });
        Ok(())
    }

    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .find(owner, other)
            .is_some_and(|i| inner.rows[i].rel.blocked_at.is_some()))
    }

    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<(u64, u64, Mailbox)> = inner
            .rows
            .iter()
            .filter(|r| is(&r.rel.owner, owner))
            .filter_map(|r| Some((secs(r.rel.blocked_at?), r.seq, r.rel.other.clone())))
            .collect();
        rows.sort_by_key(|(at, seq, _)| (*at, *seq));
        Ok(rows.into_iter().map(|(_, _, m)| m).collect())
    }

    fn set_pending_out(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        pending: Option<&PendingOut>,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.edit(owner, other, |r| r.pending_out = pending.cloned());
        Ok(())
    }

    fn set_ignore(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        ignore: Option<&Ignore>,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.edit(owner, other, |r| r.ignore = ignore.cloned());
        Ok(())
    }

    fn befriend(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        _at: SystemTime,
    ) -> Result<RelationId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let of = |inner: &Inner, x: &Mailbox, y: &Mailbox| {
            inner.find(x, y).and_then(|i| inner.rows[i].rel.friendship)
        };
        let (ab, ba) = (of(&inner, a, b), of(&inner, b, a));
        if let (Some(x), Some(y)) = (ab, ba) {
            if x == y {
                return Ok(x);
            }
        }
        let id = inner.mint();
        let mut ended: Vec<RelationId> = ab.into_iter().chain(ba).collect();
        for (x, y) in [(a, b), (b, a)] {
            ended.extend(inner.edit(x, y, |r| {
                r.friendship = Some(id);
                r.pending_out = None;
                r.approval.take()
            }));
        }
        inner.forget(ended);
        Ok(id)
    }

    fn unfriend(&self, a: &Mailbox, b: &Mailbox) -> Result<Option<RelationId>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut ended = Vec::new();
        for (x, y) in [(a, b), (b, a)] {
            if inner.find(x, y).is_some() {
                ended.extend(inner.edit(x, y, |r| r.friendship.take()));
            }
        }
        inner.forget(ended.iter().copied());
        Ok(ended.first().copied())
    }

    fn approve(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        _at: SystemTime,
    ) -> Result<RelationId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = inner
            .find(owner, other)
            .and_then(|i| inner.rows[i].rel.approval)
        {
            return Ok(id);
        }
        let id = inner.mint();
        inner.edit(owner, other, |r| r.approval = Some(id));
        Ok(id)
    }

    fn end_approval(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
    ) -> Result<Option<RelationId>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.find(owner, other).is_none() {
            return Ok(None);
        }
        let id = inner.edit(owner, other, |r| r.approval.take());
        inner.forget(id);
        Ok(id)
    }

    fn hold(&self, owner: &Mailbox, held: &Requester, until: SystemTime) -> Result<(), StoreError> {
        self.inner.lock().unwrap().holds.push(Hold {
            owner: HoldKey::of(owner),
            held: Held::of(held),
            until: floor(until),
        });
        Ok(())
    }

    fn is_held(
        &self,
        owner: &Mailbox,
        sender: &Requester,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .holds
            .iter()
            .any(|h| h.until > floor(now) && h.owner.loosely(owner) && h.held.matches(sender)))
    }

    fn record_request(&self, entry: &LedgerEntry) -> Result<Recorded, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(guid) = entry.guid.as_ref() {
            let from = match &entry.sender {
                Some(m) => Requester::Account(m.clone()),
                None => Requester::Address(entry.address.clone().unwrap_or_default()),
            };
            if let Some(e) = inner.ledger.iter().find(|e| {
                e.guid.as_ref() == Some(guid)
                    && is(&e.recipient, &entry.recipient)
                    && sent_by(e, &from)
            }) {
                return Ok(Recorded::Retry(Box::new(e.clone())));
            }
        }
        inner.ledger.push(LedgerEntry {
            at: floor(entry.at),
            ..entry.clone()
        });
        Ok(Recorded::New)
    }

    fn find_request(
        &self,
        from: &Requester,
        to: &Mailbox,
        guid: &MessageGuid,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .find(|e| e.guid.as_ref() == Some(guid) && is(&e.recipient, to) && sent_by(e, from))
            .cloned())
    }

    fn requests_to(
        &self,
        from: &Requester,
        to: &Mailbox,
        kind: RequestKind,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .filter(|e| {
                e.kind == kind && e.at >= floor(since) && is(&e.recipient, to) && sent_by(e, from)
            })
            .count())
    }

    fn recipients_since(&self, from: &Requester, since: SystemTime) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .filter(|e| e.at >= floor(since) && sent_by(e, from))
            .map(|e| key(&e.recipient))
            .collect::<BTreeSet<_>>()
            .len())
    }

    fn recipients_from_address(
        &self,
        address: &str,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .filter(|e| e.at >= floor(since) && e.address.as_deref() == Some(address))
            .map(|e| key(&e.recipient))
            .collect::<BTreeSet<_>>()
            .len())
    }

    fn requested_since(&self, from: &Requester, since: SystemTime) -> Result<Sent, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .filter(|e| e.kind == RequestKind::Message && e.at >= floor(since) && sent_by(e, from))
            .fold(Sent::default(), |s, e| Sent {
                messages: s.messages + 1,
                bytes: s.bytes + e.bytes,
            }))
    }

    fn request_dropped(&self, owner: &Mailbox) -> Result<(), StoreError> {
        self.inner.lock().unwrap().account_mut(owner).dropped += 1;
        Ok(())
    }

    fn requests_listed(&self, owner: &Mailbox, at: SystemTime) -> Result<u64, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let account = inner.account_mut(owner);
        account.state.requests_listed_at = Some(floor(at));
        Ok(std::mem::take(&mut account.dropped))
    }

    fn account(&self, of: &Mailbox) -> Result<MessagingAccount, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .accounts
            .iter()
            .find(|a| is(&a.owner, of))
            .map(|a| a.state.clone())
            .unwrap_or_default())
    }

    fn update_account(&self, of: &Mailbox, update: &AccountUpdate) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let state = &mut inner.account_mut(of).state;
        if let Some(text) = &update.status_text {
            state.status_text = text.clone();
        }
        if let Some(on) = update.discoverable {
            state.discoverable = on;
        }
        if let Some(on) = update.takes_requests {
            state.takes_requests = on;
        }
        if let Some(profile) = &update.profile {
            state.profile = profile.clone();
            state.profile.languages.truncate(MAX_LANGUAGES);
        }
        Ok(())
    }

    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<Rekeyed, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(inner.rekey(|m| m.fingerprint.is_none() && m.login == login, fingerprint))
    }

    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Rekeyed, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(inner.rekey(|m| m.fingerprint.as_ref() == Some(from), to))
    }

    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        Ok(self.inner.lock().unwrap().purge(of))
    }

    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        let rows = inner
            .rows
            .iter()
            .filter(|r| is(&r.rel.owner, of) || is(&r.rel.other, of))
            .count();
        let holds = inner
            .holds
            .iter()
            .filter(|h| h.owner.purged_by(of) || h.held.purged_by(of))
            .count();
        let ledger = inner
            .ledger
            .iter()
            .filter(|e| is(&e.recipient, of) || e.sender.as_ref().is_some_and(|s| is(s, of)))
            .count();
        let accounts = inner.accounts.iter().filter(|a| is(&a.owner, of)).count();
        Ok(rows + holds + ledger + accounts)
    }

    fn cleanup(
        &self,
        lapsed_before: SystemTime,
        ledger_before: SystemTime,
        batch: usize,
    ) -> Result<usize, StoreError> {
        let (lapsed_before, ledger_before) = (floor(lapsed_before), floor(ledger_before));
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        let mut held = 0;
        inner.holds.retain(|h| {
            let go = h.until <= lapsed_before && held < batch;
            held += usize::from(go);
            !go
        });
        n += held;
        let lapsing: Vec<usize> = inner
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rel.clone().as_of(lapsed_before).as_ref() != Some(&r.rel))
            .map(|(i, _)| i)
            .take(batch)
            .collect();
        for &i in lapsing.iter().rev() {
            match inner.rows[i].rel.clone().as_of(lapsed_before) {
                Some(rel) => inner.rows[i].rel = rel,
                None => {
                    inner.rows.remove(i);
                }
            }
        }
        n += lapsing.len();
        let mut old = 0;
        inner.ledger.retain(|e| {
            let go = e.at < ledger_before && old < batch;
            old += usize::from(go);
            !go
        });
        Ok(n + old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        super::super::conformance::run(&|| Box::new(MemoryRelationships::new()));
    }
}
