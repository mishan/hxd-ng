//! An in-memory [`RelationshipStore`], for the domain's tests and for a
//! server whose inbox is in memory too. [`super::conformance`] holds it
//! to the SQLite store's answers.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    AccountUpdate, Cause, Charge, Did, Ended, EndedEdge, Ending, FpPair, HeldWithdrawal, Ignore,
    LedgerEntry, Left, MessagingAccount, Owed, OwedId, PairDrop, Part, PendingOut, Presentation,
    Recorded, Rekeyed, RelationId, Relationship, RelationshipStore, Report, RequestKind, Requester,
    RotationRecord, StoredOffer, Work, MAX_LANGUAGES,
};
use crate::inbox::{Mailbox, MessageGuid, Sent, StoreError};

#[derive(Debug, Clone)]
struct Row {
    /// Creation order, which is the order rows are listed in.
    seq: u64,
    rel: Relationship,
}

/// One side of a hold: either key may be gone, never both.
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
enum Held {
    Account(HoldKey),
    Address(String),
}

impl Held {
    fn of(r: &Requester) -> Self {
        match r {
            Requester::Account(m) => Held::Account(HoldKey::of(m)),
            Requester::Address(a) => Held::Address(a.clone()),
            Requester::Identity(fp) => Held::Account(HoldKey {
                login: None,
                fingerprint: Some(*fp),
            }),
        }
    }

    fn matches(&self, r: &Requester) -> bool {
        match (self, r) {
            (Held::Account(h), Requester::Account(m)) => h.loosely(m),
            (Held::Account(h), Requester::Identity(fp)) => h.fingerprint == Some(*fp),
            (Held::Address(h), Requester::Address(a)) => h == a,
            _ => false,
        }
    }

    fn purged_by(&self, m: &Mailbox) -> bool {
        matches!(self, Held::Account(h) if h.purged_by(m))
    }
}

#[derive(Debug, Clone)]
struct Hold {
    owner: HoldKey,
    held: Held,
    until: SystemTime,
}

#[derive(Debug, Clone)]
struct Account {
    owner: Mailbox,
    state: MessagingAccount,
    dropped: u64,
}

#[derive(Default, Clone)]
struct Inner {
    next_seq: u64,
    next_relation: RelationId,
    rows: Vec<Row>,
    /// The friendships and approvals that are live.
    relations: BTreeSet<RelationId>,
    /// When each live one was made.
    made: std::collections::HashMap<RelationId, SystemTime>,
    holds: Vec<Hold>,
    ledger: Vec<LedgerEntry>,
    accounts: Vec<Account>,
    /// In the order they were made, which is the order they are listed in.
    presentations: Vec<Presentation>,
    withdrawals: Vec<HeldWithdrawal>,
    /// `(owner, other, offer)`.
    offers: Vec<([u8; 32], [u8; 32], StoredOffer)>,
    /// `(from, to, record)`.
    rotations: Vec<([u8; 32], [u8; 32], Vec<u8>)>,
    /// In id order.
    owed: Vec<Owed>,
    last_owed: OwedId,
    /// The latest move from each key, `(from, to)`.
    moved: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Default)]
pub struct MemoryRelationships {
    inner: Mutex<Inner>,
}

impl MemoryRelationships {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything the store holds, for a test to tell whether an act
    /// changed any of it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dump(&self) -> String {
        let i = self.inner.lock().unwrap();
        let made: std::collections::BTreeMap<_, _> = i.made.iter().collect();
        format!(
            "{} {} {:?} {:?} {made:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {} {:?}",
            i.next_seq,
            i.next_relation,
            i.rows,
            i.relations,
            i.holds,
            i.ledger,
            i.accounts,
            i.presentations,
            i.withdrawals,
            i.offers,
            i.rotations,
            i.owed,
            i.last_owed,
            i.moved
        )
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
        (Requester::Identity(fp), Some(s)) => s.fingerprint == Some(*fp),
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
        if let Some(o) = p.offer.as_mut() {
            o.lapses_at = floor(o.lapses_at);
        }
    }
    if let Some(i) = r.ignore.as_mut() {
        i.until = i.until.map(floor);
    }
}

impl Inner {
    /// [`RelationshipStore::drop_offers`]'s one pair.
    fn drop_offer(&mut self, x: &[u8; 32], y: &[u8; 32]) {
        self.offers.retain(|(o, t, _)| (o, t) != (x, y));
        for r in self.rows.iter_mut() {
            let rel = &mut r.rel;
            if rel.owner.fingerprint.as_ref() != Some(x)
                || rel.other.fingerprint.as_ref() != Some(y)
            {
                continue;
            }
            if rel.pending_out.as_ref().is_some_and(|p| p.upgrade) {
                rel.pending_out = None;
            } else if let Some(p) = rel.pending_out.as_mut() {
                p.offer = None;
            }
        }
        self.rows.retain(|r| {
            let rel = &r.rel;
            let pair = rel.owner.fingerprint.as_ref() == Some(x)
                && rel.other.fingerprint.as_ref() == Some(y);
            !pair || !rel.is_empty()
        });
    }

    /// Every pair, by fingerprint, an offer waits on that names `fp`.
    fn offers_naming(&self, fp: &[u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
        let upgrades = self.offers.iter().map(|(o, t, _)| (*o, *t));
        let asked = self.rows.iter().filter_map(|r| {
            let p = r.rel.pending_out.as_ref()?;
            p.offer.as_ref()?;
            r.rel.owner.fingerprint.zip(r.rel.other.fingerprint)
        });
        upgrades
            .chain(asked)
            .filter(|(o, t)| o == fp || t == fp)
            .collect()
    }

    /// The friendships a pair's `Reset` records kept, gone, their hashes
    /// left.
    fn forget_resets(&mut self, x: &[u8; 32], y: &[u8; 32]) {
        for p in self.presentations.iter_mut() {
            if (p.presenter, p.other) == (*x, *y) || (p.presenter, p.other) == (*y, *x) {
                p.reset = None;
            }
        }
    }

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
                self.made.remove(&id);
            }
        }
    }

    fn owe(&mut self, work: &Work, cause: &Cause) -> OwedId {
        let work = &rekeyed(work, |k| self.tail(k));
        if let Some(o) = (self.owed.iter()).find(|o| o.work == *work && o.cause == *cause) {
            return o.id;
        }
        self.last_owed += 1;
        self.owed.push(Owed {
            id: self.last_owed,
            work: work.clone(),
            cause: cause.clone(),
        });
        self.last_owed
    }

    /// Where `key`'s rows are now, by the moves rotations made.
    fn tail(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut key = *key;
        for _ in 0..MAX_MOVES {
            match self.moved.iter().find(|(from, _)| *from == key) {
                Some((_, to)) => key = *to,
                None => break,
            }
        }
        key
    }

    /// A rotation's re-stamp of owed work, in id order: a piece that
    /// becomes one already owed is folded into it.
    fn restamp_owed(&mut self, from: &[u8; 32], to: &[u8; 32]) -> Vec<(OwedId, OwedId)> {
        let mut merged = Vec::new();
        let mut i = 0;
        while i < self.owed.len() {
            let o = &self.owed[i];
            let work = rekeyed(&o.work, |k| if k == from { *to } else { *k });
            if work == o.work {
                i += 1;
                continue;
            }
            match (self.owed.iter()).find(|k| k.work == work && k.cause == o.cause) {
                Some(kept) => {
                    merged.push((o.id, kept.id));
                    self.owed.remove(i);
                }
                None => {
                    self.owed[i].work = work;
                    i += 1;
                }
            }
        }
        merged
    }

    /// One part of a write, as its method does it.
    fn part(&mut self, part: &Part) -> Did {
        match part {
            Part::DropPresentations(a, b, presenters) => {
                Did::Ended(self.drop_presentations(a, b, presenters))
            }
            Part::EndFriendship(a, b, end) => Did::Ended(self.end_friendship(a, b, end)),
            Part::Present(p) => Did::Replaced(self.present(p)),
            Part::PresentBefriending {
                a,
                b,
                rows,
                befriend,
                at,
            } => {
                let (replaced, id) = self.present_befriending(a, b, rows, *befriend, *at);
                Did::Befriended(replaced, id)
            }
            Part::AnswerReset {
                drops,
                record,
                upgrade,
            } => {
                let upgrade = upgrade.as_ref().map(|(o, t)| (o, t));
                let (ended, replaced) = self.answer_reset(drops, record.as_ref(), upgrade);
                Did::Reset(ended, replaced)
            }
            Part::SetOffer(owner, other, offer) => {
                self.set_offer(owner, other, offer.as_ref());
                Did::Nothing
            }
            Part::DropOffers(pairs) => {
                for (x, y) in pairs {
                    self.drop_offer(x, y);
                }
                Did::Nothing
            }
            Part::DropOffersNaming(fp) => Did::Named(self.drop_offers_naming(fp)),
            Part::BefriendDropping { a, b, at, id, drop } => {
                Did::Friends(self.befriend_dropping(a, b, *at, *id, drop))
            }
            Part::KeepWithdrawal(w, cap) => {
                self.keep_withdrawal(w, *cap);
                Did::Nothing
            }
            Part::DropWithdrawal(owner, pair, party, w) => {
                self.drop_withdrawal(owner, pair, party, w);
                Did::Nothing
            }
            Part::SetAlias(owner, other, alias) => {
                self.edit(owner, other, |r| r.alias = alias.clone());
                Did::Nothing
            }
            Part::SetBlocked(owner, other, blocked, at) => {
                self.edit(owner, other, |r| {
                    r.blocked_at = if *blocked {
                        r.blocked_at.or(Some(*at))
                    } else {
                        None
                    }
                });
                Did::Nothing
            }
            Part::SetPendingOut(owner, other, pending) => {
                self.edit(owner, other, |r| r.pending_out = pending.clone());
                Did::Nothing
            }
            Part::Owe(work, cause) => Did::Owed(self.owe(work, cause)),
            Part::Settle(id) => {
                self.owed.retain(|o| o.id != *id);
                Did::Nothing
            }
            #[cfg(any(test, feature = "test-support"))]
            Part::Fail => unreachable!("failed before it is applied"),
        }
    }

    fn present_befriending(
        &mut self,
        a: &Mailbox,
        b: &Mailbox,
        rows: &[Presentation],
        befriend: Option<Option<RelationId>>,
        at: SystemTime,
    ) -> (Vec<Option<Presentation>>, Option<RelationId>) {
        let replaced = rows.iter().map(|p| self.present(p)).collect();
        if let Some((x, y)) = a.fingerprint.zip(b.fingerprint) {
            self.offers
                .retain(|(o, t, _)| !((*o == x && *t == y) || (*o == y && *t == x)));
        }
        let id = befriend.map(|id| match id {
            Some(id) => {
                self.refriend(a, b, id, at);
                id
            }
            None => self.befriend(a, b, at),
        });
        (replaced, id)
    }

    fn befriend_dropping(
        &mut self,
        a: &Mailbox,
        b: &Mailbox,
        at: SystemTime,
        id: Option<RelationId>,
        drop: &[[u8; 32]],
    ) -> RelationId {
        if let Some((x, y)) = a.fingerprint.zip(b.fingerprint) {
            self.unpresent_pair(&x, &y, drop);
            self.forget_resets(&x, &y);
        }
        match id {
            Some(id) => {
                self.refriend(a, b, id, at);
                id
            }
            None => self.befriend(a, b, at),
        }
    }

    fn drop_withdrawal(&mut self, owner: &[u8; 32], pair: &[u8; 32], party: &[u8; 32], w: &[u8]) {
        self.withdrawals.retain(|h| {
            !(h.owner == *owner
                && h.pair == *pair
                && h.party == *party
                && h.withdrawal.as_deref() == Some(w))
        });
    }

    fn set_offer(&mut self, owner: &[u8; 32], other: &[u8; 32], offer: Option<&StoredOffer>) {
        self.offers.retain(|(a, b, _)| !(a == owner && b == other));
        if let Some(o) = offer {
            let o = StoredOffer {
                lapses_at: floor(o.lapses_at),
                ..o.clone()
            };
            self.offers.push((*owner, *other, o));
        }
    }

    fn answer_reset(
        &mut self,
        drops: &[PairDrop],
        record: Option<&Presentation>,
        upgrade: Option<(&Mailbox, &Mailbox)>,
    ) -> (Vec<Ended>, Option<Presentation>) {
        let ended = drops
            .iter()
            .map(|(a, b, presenters)| self.drop_presentations(a, b, presenters))
            .collect();
        let replaced = record.and_then(|p| self.present(p));
        if let Some((owner, other)) = upgrade {
            let fps = owner.fingerprint.zip(other.fingerprint);
            let offer = self.find(owner, other).and_then(|i| {
                let p = self.rows[i].rel.pending_out.as_mut()?;
                let o = p.offer.take()?;
                p.upgrade = true;
                Some(StoredOffer {
                    lapses_at: o.lapses_at.min(p.lapses_at),
                    ..o
                })
            });
            if let (Some(o), Some((x, y))) = (offer, fps) {
                self.offers.retain(|(a, b, _)| (*a, *b) != (x, y));
                self.offers.push((x, y, o));
            }
        }
        (ended, replaced)
    }

    fn drop_offers_naming(&mut self, fp: &[u8; 32]) -> Vec<FpPair> {
        let mut pairs = self.offers_naming(fp);
        pairs.extend(
            self.rows
                .iter()
                .filter_map(|r| {
                    r.rel.pending_out.as_ref().filter(|p| p.upgrade)?;
                    r.rel.owner.fingerprint.zip(r.rel.other.fingerprint)
                })
                .filter(|(o, t)| o == fp || t == fp),
        );
        pairs.sort();
        pairs.dedup();
        for (x, y) in &pairs {
            self.drop_offer(x, y);
        }
        pairs
    }

    /// What `report` asks of, as it stands.
    fn left(&self, report: &Report) -> Vec<Left> {
        let now = floor(report.now);
        report
            .pairs
            .iter()
            .map(|(a, b)| {
                let row = |x: &Mailbox, y: &Mailbox| {
                    self.find(x, y)
                        .and_then(|i| self.rows[i].rel.clone().as_of(now))
                };
                let fps = a.fingerprint.zip(b.fingerprint);
                let presentation = |x: &[u8; 32], y: &[u8; 32]| {
                    self.presentations
                        .iter()
                        .find(|p| p.presenter == *x && p.other == *y)
                        .cloned()
                };
                let offer = |x: &[u8; 32], y: &[u8; 32]| {
                    self.offers
                        .iter()
                        .find(|(o, t, s)| o == x && t == y && s.lapses_at > now)
                        .map(|(_, _, s)| s.clone())
                };
                let shown = |m: &Mailbox| {
                    self.accounts
                        .iter()
                        .find(|c| is(&c.owner, m))
                        .and_then(|c| c.state.shown_text.clone())
                };
                Left {
                    pair: [a.clone(), b.clone()],
                    rows: [row(a, b), row(b, a)],
                    presentations: [
                        fps.and_then(|(x, y)| presentation(&x, &y)),
                        fps.and_then(|(x, y)| presentation(&y, &x)),
                    ],
                    offers: [
                        fps.and_then(|(x, y)| offer(&x, &y)),
                        fps.and_then(|(x, y)| offer(&y, &x)),
                    ],
                    shown: [shown(a), shown(b)],
                }
            })
            .collect()
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
        for p in self.presentations.iter_mut() {
            if let Some((_, kept)) = merged.iter().find(|(lost, _)| p.edge == Some(*lost)) {
                p.edge = Some(*kept);
            }
        }
        Rekeyed {
            moved: n,
            merged,
            ..Rekeyed::default()
        }
    }

    /// The portable part of a rotation: presentations and offers by or
    /// naming `from`, and withdrawals counted toward it, re-stamped, where
    /// the successor holds none of its own for the same other party; and
    /// the edge of each pair that loses its evidence both ways so, ended.
    fn rotate_portable(&mut self, from: &[u8; 32], to: &[u8; 32], rekeyed: &mut Rekeyed) {
        let mut n = 0;
        let swap = |k: &mut [u8; 32]| {
            if k == from {
                *k = *to;
            }
        };
        let had: Vec<[u8; 32]> = self
            .presentations
            .iter()
            .filter_map(|p| match (p.presenter == *from, p.other == *from) {
                (true, false) => Some(p.other),
                (false, true) => Some(p.presenter),
                _ => None,
            })
            .filter(|o| self.evidence_both_ways(from, o) || self.evidence_both_ways(to, o))
            .collect();
        let mut held: Vec<([u8; 32], [u8; 32])> = self
            .presentations
            .iter()
            .filter(|p| p.presenter != *from && p.other != *from)
            .map(|p| (p.presenter, p.other))
            .collect();
        let mut kept = Vec::new();
        for mut p in std::mem::take(&mut self.presentations) {
            if p.presenter == *from || p.other == *from {
                swap(&mut p.presenter);
                swap(&mut p.other);
                n += 1;
                if held.contains(&(p.presenter, p.other)) {
                    rekeyed.dropped.push(p);
                    continue;
                }
                held.push((p.presenter, p.other));
            }
            kept.push(p);
        }
        self.presentations = kept;
        let mut ended: Vec<[u8; 32]> = Vec::new();
        for p in &rekeyed.dropped {
            let o = if p.presenter == *to {
                p.other
            } else {
                p.presenter
            };
            if ended.contains(&o) || !had.contains(&o) || self.evidence_both_ways(to, &o) {
                continue;
            }
            ended.push(o);
            let (a, b) = (Mailbox::identified("", *to), Mailbox::identified("", o));
            if let Some(e) = self.end_edge(&a, &b) {
                self.set_edge(to, &o, Some(e.id));
                rekeyed.ended.push(e);
            }
        }
        let mut held: Vec<([u8; 32], [u8; 32])> = self
            .offers
            .iter()
            .filter(|(a, b, _)| a != from && b != from)
            .map(|(a, b, _)| (*a, *b))
            .collect();
        let mut kept = Vec::new();
        for (mut a, mut b, o) in std::mem::take(&mut self.offers) {
            if a == *from || b == *from {
                swap(&mut a);
                swap(&mut b);
                n += 1;
                if held.contains(&(a, b)) {
                    continue;
                }
                held.push((a, b));
            }
            kept.push((a, b, o));
        }
        self.offers = kept;
        // Of a successor's withdrawal and a moved one for the same pair,
        // party and kind, the later cutoff stands, the moved one on a tie.
        let key = |w: &HeldWithdrawal| (w.pair, w.party, w.withdrawal.is_none());
        let of = |owner: &[u8; 32]| -> Vec<_> {
            self.withdrawals
                .iter()
                .filter(|w| w.owner == *owner)
                .map(|w| (key(w), w.before))
                .collect()
        };
        let (moved, theirs) = (of(from), of(to));
        self.withdrawals.retain(|w| {
            if w.owner == *to {
                !moved.iter().any(|(k, b)| *k == key(w) && *b >= w.before)
            } else if w.owner == *from {
                !theirs.iter().any(|(k, b)| *k == key(w) && *b > w.before)
            } else {
                true
            }
        });
        for w in self.withdrawals.iter_mut() {
            if w.owner == *from {
                w.owner = *to;
                n += 1;
            }
        }
        rekeyed.moved += n;
    }

    fn keep_withdrawal(&mut self, w: &HeldWithdrawal, cap: usize) {
        let same = |k: &HeldWithdrawal| {
            k.owner == w.owner
                && k.pair == w.pair
                && k.party == w.party
                && k.withdrawal.is_none() == w.withdrawal.is_none()
        };
        // One whose cutoff is older replaces nothing, and the cap holds
        // all the same.
        let older = self
            .withdrawals
            .iter()
            .any(|k| same(k) && k.before > w.before);
        if !older {
            self.withdrawals.retain(|k| !same(k));
            self.withdrawals.push(HeldWithdrawal {
                at: floor(w.at),
                ..w.clone()
            });
        }
        loop {
            let owned: Vec<usize> = (0..self.withdrawals.len())
                .filter(|&i| self.withdrawals[i].owner == w.owner)
                .collect();
            if owned.len() <= cap {
                break;
            }
            // The oldest, signed ones first, by the order they were kept.
            let victim = owned
                .iter()
                .copied()
                .min_by_key(|&i| {
                    let k = &self.withdrawals[i];
                    (k.withdrawal.is_none(), secs(k.at), i)
                })
                .expect("past its cap, so it holds some");
            self.withdrawals.remove(victim);
        }
    }

    /// Whether each of `a` and `b` holds a presentation of the other with
    /// evidence.
    fn evidence_both_ways(&self, a: &[u8; 32], b: &[u8; 32]) -> bool {
        [(a, b), (b, a)].into_iter().all(|(p, q)| {
            self.presentations
                .iter()
                .any(|x| x.presenter == *p && x.other == *q && x.evidence())
        })
    }

    fn befriend(&mut self, a: &Mailbox, b: &Mailbox, at: SystemTime) -> RelationId {
        let of = |inner: &Inner, x: &Mailbox, y: &Mailbox| {
            inner.find(x, y).and_then(|i| inner.rows[i].rel.friendship)
        };
        let (ab, ba) = (of(self, a, b), of(self, b, a));
        if let (Some(x), Some(y)) = (ab, ba) {
            if x == y {
                return x;
            }
        }
        let id = self.mint();
        self.made.insert(id, floor(at));
        let mut ended: Vec<RelationId> = ab.into_iter().chain(ba).collect();
        for (x, y) in [(a, b), (b, a)] {
            ended.extend(self.edit(x, y, |r| {
                r.friendship = Some(id);
                r.pending_out = None;
                r.approval.take()
            }));
        }
        self.forget(ended);
        id
    }

    fn refriend(&mut self, a: &Mailbox, b: &Mailbox, id: RelationId, at: SystemTime) {
        self.relations.insert(id);
        self.made.entry(id).or_insert(floor(at));
        let mut ended = Vec::new();
        for (x, y) in [(a, b), (b, a)] {
            ended.extend(self.edit(x, y, |r| {
                let old = r.friendship.replace(id);
                r.pending_out = None;
                [old, r.approval.take()]
            }));
        }
        self.forget(ended.into_iter().flatten().filter(|e| *e != id));
    }

    fn present(&mut self, p: &Presentation) -> Option<Presentation> {
        let p = floor_presentation(p);
        let old = self
            .presentations
            .iter()
            .position(|k| k.presenter == p.presenter && k.other == p.other)
            .map(|i| self.presentations.remove(i));
        if old
            .as_ref()
            .is_some_and(|o| o.reset.is_some() && o.reset != p.reset)
        {
            self.drop_upgrade(&p.other, &p.presenter);
        }
        self.presentations.push(p);
        old
    }

    /// What a rotation merged onto `fp`, made one state a direction again:
    /// an upgrade offer off a friendship stands only as its sender's
    /// pending out shows it and while the record it was taken on does, and
    /// never beside a request.
    fn settle_upgrades(&mut self, fp: &[u8; 32]) {
        let names = |rel: &Relationship| {
            rel.owner.fingerprint.as_ref() == Some(fp) || rel.other.fingerprint.as_ref() == Some(fp)
        };
        // A pending out shown for an upgrade offer, without its record.
        let presentations = &self.presentations;
        for r in self.rows.iter_mut().filter(|r| names(&r.rel)) {
            let shown = r.rel.pending_out.as_ref().is_some_and(|p| p.upgrade);
            let recorded = r
                .rel
                .owner
                .fingerprint
                .zip(r.rel.other.fingerprint)
                .is_some_and(|(x, y)| {
                    presentations
                        .iter()
                        .any(|p| p.presenter == y && p.other == x && p.reset.is_some())
                });
            // Nor any pending out beside the friendship a merge left.
            if shown && !recorded || r.rel.friendship.is_some() {
                r.rel.pending_out = None;
            }
        }
        // An upgrade offer with neither a friendship nor that pending out.
        let standing: Vec<([u8; 32], [u8; 32])> = self
            .rows
            .iter()
            .filter(|r| {
                r.rel.friendship.is_some() || r.rel.pending_out.as_ref().is_some_and(|p| p.upgrade)
            })
            .filter_map(|r| r.rel.owner.fingerprint.zip(r.rel.other.fingerprint))
            .collect();
        self.offers
            .retain(|(o, t, _)| (o != fp && t != fp) || standing.contains(&(*o, *t)));
        self.reclaim();
    }

    /// Rows left holding nothing, gone.
    fn reclaim(&mut self) {
        self.rows.retain(|r| !r.rel.is_empty());
    }

    /// The upgrade offer `x` has waiting for `y` on an edge a reset left
    /// inactive, gone with the record `y` kept for it, and the pending out
    /// it showed `x` with it.
    fn drop_upgrade(&mut self, x: &[u8; 32], y: &[u8; 32]) {
        let shown = |rel: &Relationship| {
            rel.owner.fingerprint.as_ref() == Some(x)
                && rel.other.fingerprint.as_ref() == Some(y)
                && rel.pending_out.as_ref().is_some_and(|p| p.upgrade)
        };
        if !self.rows.iter().any(|r| shown(&r.rel)) {
            return;
        }
        self.offers.retain(|(o, t, _)| (o, t) != (x, y));
        for r in self.rows.iter_mut().filter(|r| shown(&r.rel)) {
            r.rel.pending_out = None;
        }
        self.reclaim();
    }

    fn unpresent_pair(
        &mut self,
        a: &[u8; 32],
        b: &[u8; 32],
        presenters: &[[u8; 32]],
    ) -> Vec<Presentation> {
        let mut gone = Vec::new();
        self.presentations.retain(|p| {
            let go = presenters.contains(&p.presenter)
                && ((p.presenter == *a && p.other == *b) || (p.presenter == *b && p.other == *a));
            if go {
                gone.push(p.clone());
            }
            !go
        });
        for g in gone.iter().filter(|g| g.reset.is_some()) {
            self.drop_upgrade(&g.other, &g.presenter);
        }
        gone
    }

    fn set_edge(&mut self, a: &[u8; 32], b: &[u8; 32], edge: Option<RelationId>) {
        for p in self.presentations.iter_mut().filter(|p| {
            (p.presenter == *a && p.other == *b) || (p.presenter == *b && p.other == *a)
        }) {
            p.edge = edge;
        }
    }

    /// The friendship on the pair's rows, ended.
    fn end_edge(&mut self, a: &Mailbox, b: &Mailbox) -> Option<EndedEdge> {
        let (ab, ba) = (self.find(a, b), self.find(b, a));
        let id = [ab, ba]
            .into_iter()
            .flatten()
            .find_map(|i| self.rows[i].rel.friendship)?;
        let row = |i: usize| &self.rows[i].rel;
        let parties = match (ab, ba) {
            (Some(i), _) => [row(i).owner.clone(), row(i).other.clone()],
            (None, i) => [row(i?).other.clone(), row(i?).owner.clone()],
        };
        let mut ended = Vec::new();
        for (x, y) in [(a, b), (b, a)] {
            if self.find(x, y).is_some() {
                ended.extend(self.edit(x, y, |r| r.friendship.take()));
            }
        }
        self.forget(ended);
        // An upgrade offer stood beside the friendship, and goes with it.
        if let Some((x, y)) = parties[0].fingerprint.zip(parties[1].fingerprint) {
            self.offers
                .retain(|(o, t, _)| (*o, *t) != (x, y) && (*o, *t) != (y, x));
        }
        Some(EndedEdge { id, parties })
    }

    fn drop_presentations(&mut self, a: &[u8; 32], b: &[u8; 32], presenters: &[[u8; 32]]) -> Ended {
        let had = self.evidence_both_ways(a, b);
        let gone = self.unpresent_pair(a, b, presenters);
        let mut ended = None;
        if had && !self.evidence_both_ways(a, b) {
            ended = self.end_edge(&Mailbox::identified("", *a), &Mailbox::identified("", *b));
            if let Some(e) = &ended {
                self.set_edge(a, b, Some(e.id));
            }
        }
        Ended { gone, ended }
    }

    fn end_friendship(&mut self, a: &Mailbox, b: &Mailbox, end: &Ending) -> Ended {
        assert!(
            end.withdrawals.is_empty() || end.cap > 0,
            "a cap to keep under"
        );
        for w in &end.withdrawals {
            self.keep_withdrawal(w, end.cap);
        }
        let fps = a.fingerprint.zip(b.fingerprint);
        let mut gone = Vec::new();
        if let Some((x, y)) = fps {
            gone = self.unpresent_pair(&x, &y, &end.presentations);
            for (o, t) in [(x, y), (y, x)] {
                if end.offers.contains(&o) || end.block.is_some() {
                    self.drop_offer(&o, &t);
                }
            }
            if end.block.is_some() {
                self.forget_resets(&x, &y);
            }
        }
        if end.pending && self.find(b, a).is_some() {
            let offer = b.fingerprint.zip(a.fingerprint);
            self.edit(b, a, |r| r.pending_out = None);
            if let Some((x, y)) = offer {
                self.drop_offer(&x, &y);
            }
        }
        if let Some(at) = end.block {
            self.edit(a, b, |r| r.blocked_at = r.blocked_at.or(Some(at)));
            let mut lost = Vec::new();
            for (x, y) in [(a, b), (b, a)] {
                if self.find(x, y).is_some() {
                    lost.extend(self.edit(x, y, |r| {
                        r.pending_out = None;
                        r.approval.take()
                    }));
                }
            }
            self.forget(lost);
        }
        let ended = if end.friendship {
            self.end_edge(a, b)
        } else {
            None
        };
        let mut held: Vec<(&Mailbox, &Mailbox, SystemTime)> = Vec::new();
        if let Some(e) = &ended {
            if let Some((x, y)) = fps {
                self.set_edge(&x, &y, None);
            }
            held.extend(end.hold.map(|until| (&e.parties[0], &e.parties[1], until)));
        }
        held.extend(end.declined.map(|until| (a, b, until)));
        for (owner, them, until) in held {
            self.holds.push(Hold {
                owner: HoldKey::of(owner),
                held: Held::of(&Requester::Account(them.clone())),
                until: floor(until),
            });
        }
        Ended { gone, ended }
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
        let mut n =
            before - (self.rows.len() + self.holds.len() + self.ledger.len() + self.accounts.len());
        if let Some(fp) = of.fingerprint {
            let had = self.presentations.len() + self.offers.len();
            self.presentations.retain(|p| p.presenter != fp);
            self.offers.retain(|(a, b, _)| *a != fp && *b != fp);
            n += had - (self.presentations.len() + self.offers.len());
        }
        n
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

    fn upgrades_to(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .rows
            .iter()
            .filter(|r| is(&r.rel.other, owner))
            .filter_map(|r| r.rel.clone().as_of(floor(now)))
            .filter(|r| r.pending_out.as_ref().is_some_and(|p| p.upgrade))
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
                let p = rel
                    .pending_out
                    .as_ref()
                    .filter(|p| p.delivered && !p.upgrade)?;
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
        let alias = alias.map(str::to_owned);
        let part = Part::SetAlias(owner.clone(), other.clone(), alias);
        self.write(&[part], &Report::none()).map(drop)
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        let part = Part::SetBlocked(owner.clone(), other.clone(), blocked, at);
        self.write(&[part], &Report::none()).map(drop)
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
        let part = Part::SetPendingOut(owner.clone(), other.clone(), pending.cloned());
        self.write(&[part], &Report::none()).map(drop)
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

    fn befriend(&self, a: &Mailbox, b: &Mailbox, at: SystemTime) -> Result<RelationId, StoreError> {
        Ok(self.inner.lock().unwrap().befriend(a, b, at))
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
        at: SystemTime,
    ) -> Result<RelationId, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = inner
            .find(owner, other)
            .and_then(|i| inner.rows[i].rel.approval)
        {
            return Ok(id);
        }
        let id = inner.mint();
        inner.made.insert(id, floor(at));
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

    fn refriend(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        id: RelationId,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        self.inner.lock().unwrap().refriend(a, b, id, at);
        Ok(())
    }

    fn befriend_dropping(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        at: SystemTime,
        id: Option<RelationId>,
        drop: &[[u8; 32]],
    ) -> Result<RelationId, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .befriend_dropping(a, b, at, id, drop))
    }

    fn made_at(&self, id: RelationId) -> Result<Option<SystemTime>, StoreError> {
        Ok(self.inner.lock().unwrap().made.get(&id).copied())
    }

    fn present(&self, p: &Presentation) -> Result<Option<Presentation>, StoreError> {
        Ok(self.inner.lock().unwrap().present(p))
    }

    fn present_befriending(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        rows: &[Presentation],
        befriend: Option<Option<RelationId>>,
        at: SystemTime,
    ) -> Result<(Vec<Option<Presentation>>, Option<RelationId>), StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .present_befriending(a, b, rows, befriend, at))
    }

    fn lapse_resets(&self, before: SystemTime, now: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        // An upgrade offer waiting, or the pending out it shows its sender,
        // which lapses as a request would.
        let shown = inner.rows.iter().filter_map(|r| {
            let rel = r.rel.clone().as_of(floor(now))?;
            rel.pending_out.filter(|p| p.upgrade)?;
            rel.owner.fingerprint.zip(rel.other.fingerprint)
        });
        let waiting: Vec<([u8; 32], [u8; 32])> = inner
            .offers
            .iter()
            .filter(|(_, _, o)| o.lapses_at > floor(now))
            .map(|(o, t, _)| (*o, *t))
            .chain(shown)
            .collect();
        let mut n = 0;
        for p in inner.presentations.iter_mut() {
            if p.reset.is_some() && p.at <= before && !waiting.contains(&(p.other, p.presenter)) {
                p.reset = None;
                n += 1;
            }
        }
        Ok(n)
    }

    fn presentation(
        &self,
        presenter: &[u8; 32],
        other: &[u8; 32],
    ) -> Result<Option<Presentation>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .presentations
            .iter()
            .find(|p| p.presenter == *presenter && p.other == *other)
            .cloned())
    }

    fn presentations(&self, of: &[u8; 32]) -> Result<Vec<Presentation>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .presentations
            .iter()
            .filter(|p| p.presenter == *of || p.other == *of)
            .cloned()
            .collect())
    }

    fn unpresent(
        &self,
        presenter: &[u8; 32],
        other: &[u8; 32],
    ) -> Result<Option<Presentation>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .unpresent_pair(presenter, other, &[*presenter])
            .pop())
    }

    fn drop_presentations(
        &self,
        a: &[u8; 32],
        b: &[u8; 32],
        presenters: &[[u8; 32]],
    ) -> Result<Ended, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .drop_presentations(a, b, presenters))
    }

    fn end_friendship(&self, a: &Mailbox, b: &Mailbox, end: &Ending) -> Result<Ended, StoreError> {
        Ok(self.inner.lock().unwrap().end_friendship(a, b, end))
    }

    fn presented_by(&self, device: &[u8; 32]) -> Result<Vec<Presentation>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .presentations
            .iter()
            .filter(|p| p.device == *device)
            .cloned()
            .collect())
    }

    fn keep_withdrawal(&self, w: &HeldWithdrawal, cap: usize) -> Result<(), StoreError> {
        self.inner.lock().unwrap().keep_withdrawal(w, cap);
        Ok(())
    }

    fn withdrawals(&self, pair: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .withdrawals
            .iter()
            .filter(|w| w.pair == *pair)
            .cloned()
            .collect())
    }

    fn withdrawals_by(&self, owner: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .withdrawals
            .iter()
            .filter(|w| w.owner == *owner)
            .cloned()
            .collect())
    }

    fn drop_withdrawal(
        &self,
        owner: &[u8; 32],
        pair: &[u8; 32],
        party: &[u8; 32],
        withdrawal: &[u8],
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.drop_withdrawal(owner, pair, party, withdrawal);
        Ok(())
    }

    fn set_offer(
        &self,
        owner: &[u8; 32],
        other: &[u8; 32],
        offer: Option<&StoredOffer>,
    ) -> Result<(), StoreError> {
        self.inner.lock().unwrap().set_offer(owner, other, offer);
        Ok(())
    }

    fn ask(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        pending: &PendingOut,
        upgrade: Option<&StoredOffer>,
        charge: Option<&Charge>,
        report: &Report,
    ) -> Result<Vec<Left>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(c) = charge {
            inner.ledger.push(LedgerEntry {
                at: floor(c.entry.at),
                ..c.entry.clone()
            });
            if c.dropped {
                inner.account_mut(other).dropped += 1;
            }
        }
        inner.edit(owner, other, |r| r.pending_out = Some(pending.clone()));
        if let Some((x, y)) = owner.fingerprint.zip(other.fingerprint) {
            inner.offers.retain(|(o, t, _)| (*o, *t) != (x, y));
            if let Some(o) = upgrade {
                let o = StoredOffer {
                    lapses_at: floor(o.lapses_at),
                    ..o.clone()
                };
                inner.offers.push((x, y, o));
            }
        }
        Ok(inner.left(report))
    }

    fn answer_reset(
        &self,
        drops: &[([u8; 32], [u8; 32], Vec<[u8; 32]>)],
        record: Option<&Presentation>,
        upgrade: Option<(&Mailbox, &Mailbox)>,
    ) -> Result<(Vec<Ended>, Option<Presentation>), StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .answer_reset(drops, record, upgrade))
    }

    fn write(&self, parts: &[Part], report: &Report) -> Result<(Vec<Did>, Vec<Left>), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        // All or nothing: a part that fails leaves the store as it was.
        let before = parts.iter().any(Part::fails).then(|| inner.clone());
        let mut did = Vec::new();
        for p in parts {
            if p.fails() {
                *inner = before.expect("kept for a part that fails");
                return Err(StoreError("a part of the write failed".into()));
            }
            did.push(inner.part(p));
        }
        Ok((did, inner.left(report)))
    }

    fn drop_offers(&self, pairs: &[FpPair]) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        for (x, y) in pairs {
            inner.drop_offer(x, y);
        }
        Ok(())
    }

    fn drop_offers_naming(&self, fp: &[u8; 32]) -> Result<Vec<FpPair>, StoreError> {
        Ok(self.inner.lock().unwrap().drop_offers_naming(fp))
    }

    fn offer(
        &self,
        owner: &[u8; 32],
        other: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<StoredOffer>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .offers
            .iter()
            .find(|(a, b, o)| a == owner && b == other && o.lapses_at > floor(now))
            .map(|(_, _, o)| o.clone()))
    }

    fn offerers(&self, now: SystemTime) -> Result<Vec<[u8; 32]>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let asked = inner.rows.iter().filter_map(|r| {
            let rel = r.rel.clone().as_of(floor(now))?;
            rel.pending_out?.offer?;
            rel.owner.fingerprint
        });
        let mut out: Vec<[u8; 32]> = inner
            .offers
            .iter()
            .filter(|(_, _, o)| o.lapses_at > floor(now))
            .map(|(a, _, _)| *a)
            .chain(asked)
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    fn offers_from(
        &self,
        owner: &[u8; 32],
        now: SystemTime,
    ) -> Result<Vec<([u8; 32], StoredOffer)>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let asked = inner.rows.iter().filter_map(|r| {
            if r.rel.owner.fingerprint.as_ref() != Some(owner) {
                return None;
            }
            let rel = r.rel.clone().as_of(floor(now))?;
            let o = rel.pending_out?.offer?;
            (rel.owner.fingerprint.as_ref() == Some(owner)).then_some((rel.other.fingerprint?, o))
        });
        let mut out: Vec<_> = inner
            .offers
            .iter()
            .filter(|(a, _, o)| a == owner && o.lapses_at > floor(now))
            .map(|(_, b, o)| (*b, o.clone()))
            .chain(asked)
            .collect();
        out.sort_by_key(|(b, _)| *b);
        Ok(out)
    }

    fn keep_rotation(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        record: &[u8],
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.rotations.iter().any(|(f, _, _)| f == from) {
            inner.rotations.push((*from, *to, record.to_vec()));
        }
        Ok(())
    }

    fn rotation_from(&self, from: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .rotations
            .iter()
            .find(|(f, _, _)| f == from)
            .map(|(_, t, r)| (*t, r.clone())))
    }

    fn owe(&self, owed: &[(Work, Cause)]) -> Result<Vec<OwedId>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(owed.iter().map(|(w, c)| inner.owe(w, c)).collect())
    }

    fn owed(&self) -> Result<Vec<Owed>, StoreError> {
        Ok(self.inner.lock().unwrap().owed.clone())
    }

    fn settle(&self, ids: &[OwedId]) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.owed.retain(|o| !ids.contains(&o.id));
        Ok(())
    }

    fn moved(&self, key: &[u8; 32]) -> Result<[u8; 32], StoreError> {
        Ok(self.inner.lock().unwrap().tail(key))
    }

    fn rotation_to(&self, to: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .rotations
            .iter()
            .find(|(_, t, _)| t == to)
            .map(|(f, _, r)| (*f, r.clone())))
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
        to: Option<&Mailbox>,
        guid: &MessageGuid,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .find(|e| {
                e.guid.as_ref() == Some(guid)
                    && to.is_none_or(|to| is(&e.recipient, to))
                    && sent_by(e, from)
            })
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

    fn request_addresses(
        &self,
        to: &Mailbox,
        since: SystemTime,
        before: Option<SystemTime>,
    ) -> Result<Vec<String>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<String> = Vec::new();
        for e in &inner.ledger {
            if let Some(a) = e.address.as_ref().filter(|a| {
                e.sender.is_none()
                    && e.at >= floor(since)
                    && before.is_none_or(|b| e.at < floor(b))
                    && is(&e.recipient, to)
                    && !out.contains(a)
            }) {
                out.push(a.clone());
            }
        }
        Ok(out)
    }

    fn guest_requests_to(
        &self,
        address: &str,
        to: &Mailbox,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .ledger
            .iter()
            .filter(|e| {
                e.kind == RequestKind::Message
                    && e.address.as_deref() == Some(address)
                    && e.sender.as_ref().is_none_or(|s| s.login == "guest")
                    && e.at >= floor(since)
                    && is(&e.recipient, to)
            })
            .count())
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

    fn requests_listed(&self, owner: &Mailbox) -> Result<u64, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        Ok(std::mem::take(&mut inner.account_mut(owner).dropped))
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
        if let Some(text) = &update.shown_text {
            state.shown_text = text.clone();
        }
        if let Some(on) = update.discoverable {
            state.discoverable = on;
        }
        if let Some(at) = update.takes_requests {
            state.takes_requests = at.is_some();
            if let Some(at) = at {
                state.requests_opted_at = Some(floor(at));
            }
        }
        if let Some(profile) = &update.profile {
            state.profile = profile.clone();
            state.profile.languages.truncate(MAX_LANGUAGES);
        }
        Ok(())
    }

    fn claim(
        &self,
        login: &str,
        fingerprint: &[u8; 32],
        owe: &[(Work, Cause)],
    ) -> Result<Rekeyed, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut rekeyed = inner.rekey(|m| m.fingerprint.is_none() && m.login == login, fingerprint);
        rekeyed.owed = owe.iter().map(|(w, c)| inner.owe(w, c)).collect();
        Ok(rekeyed)
    }

    fn claimable(&self, login: &str) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        let bare = |m: &Mailbox| m.fingerprint.is_none() && m.login == login;
        let held = |k: &HoldKey| k.fingerprint.is_none() && k.login.as_deref() == Some(login);
        Ok(inner
            .rows
            .iter()
            .any(|r| bare(&r.rel.owner) || bare(&r.rel.other))
            || inner
                .holds
                .iter()
                .any(|h| held(&h.owner) || matches!(&h.held, Held::Account(k) if held(k)))
            || inner
                .ledger
                .iter()
                .any(|e| bare(&e.recipient) || e.sender.as_ref().is_some_and(bare))
            || inner.accounts.iter().any(|a| bare(&a.owner)))
    }

    fn rotate_reporting(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        report: &Report,
        owe: &[(Work, Cause)],
    ) -> Result<(Rekeyed, Vec<Left>), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        // What waits for the key that retires goes, an upgrade's pending
        // out with its offer.
        let incoming: Vec<[u8; 32]> = inner
            .offers_naming(from)
            .into_iter()
            .filter(|(_, y)| y == from)
            .map(|(x, _)| x)
            .chain(inner.rows.iter().filter_map(|r| {
                r.rel.pending_out.as_ref().filter(|p| p.upgrade)?;
                (r.rel.other.fingerprint.as_ref() == Some(from)).then_some(r.rel.owner.fingerprint?)
            }))
            .collect();
        for x in incoming {
            inner.drop_upgrade(&x, from);
            inner.drop_offer(&x, from);
        }
        // Each upgrade the key that moves has waiting, with the record it
        // was taken on, where the successor has nothing pending for the
        // same party to keep in its place: once moved, it stands only on
        // that record.
        let moving: Vec<([u8; 32], Vec<u8>)> = inner
            .rows
            .iter()
            .filter(|r| r.rel.pending_out.as_ref().is_some_and(|p| p.upgrade))
            .filter(|r| r.rel.owner.fingerprint.as_ref() == Some(from))
            .filter_map(|r| r.rel.other.fingerprint)
            .filter(|t| {
                let theirs = Mailbox::identified("", *t);
                let succ = Mailbox::identified("", *to);
                inner
                    .find(&succ, &theirs)
                    .is_none_or(|i| inner.rows[i].rel.pending_out.is_none())
            })
            .filter_map(|t| {
                let p = inner
                    .presentations
                    .iter()
                    .find(|p| p.presenter == t && p.other == *from)?;
                Some((t, p.reset.clone()?))
            })
            .collect();
        let mut rekeyed = inner.rekey(|m| m.fingerprint.as_ref() == Some(from), to);
        inner.rotate_portable(from, to, &mut rekeyed);
        rekeyed.owed_merged = inner.restamp_owed(from, to);
        inner.moved.retain(|(f, _)| f != from && f != to);
        inner.moved.push((*from, *to));
        rekeyed.owed = owe.iter().map(|(w, c)| inner.owe(w, c)).collect();
        inner.settle_upgrades(to);
        for (other, record) in moving {
            let kept = inner
                .presentations
                .iter()
                .find(|p| p.presenter == other && p.other == *to)
                .and_then(|p| p.reset.clone());
            if kept.as_ref() != Some(&record) {
                inner.drop_upgrade(to, &other);
            }
        }
        let left = inner.left(&report.and_ended(&rekeyed.ended));
        Ok((rekeyed, left))
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
        let portable = of.fingerprint.map_or(0, |fp| {
            inner
                .presentations
                .iter()
                .filter(|p| p.presenter == fp)
                .count()
                + inner
                    .offers
                    .iter()
                    .filter(|(a, b, _)| *a == fp || *b == fp)
                    .count()
        });
        Ok(rows + holds + ledger + accounts + portable)
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
        let mut offers = 0;
        inner.offers.retain(|(_, _, o)| {
            let go = o.lapses_at <= lapsed_before && offers < batch;
            offers += usize::from(go);
            !go
        });
        Ok(n + old + offers)
    }
}

/// `work` with each identity key mapped by `m`, never its device.
fn rekeyed(work: &Work, m: impl Fn(&[u8; 32]) -> [u8; 32]) -> Work {
    match work {
        Work::DropOffersBy { under, device } => Work::DropOffersBy {
            under: under.as_ref().map(m),
            device: *device,
        },
        Work::DropPresentedBy { under, device } => Work::DropPresentedBy {
            under: under.as_ref().map(m),
            device: *device,
        },
        Work::DropOffersNaming(k) => Work::DropOffersNaming(m(k)),
        Work::DropPresentationsOf(k) => Work::DropPresentationsOf(m(k)),
        Work::Judge(a, b) => Work::Judge(m(a), m(b)),
        Work::Settle(k) => Work::Settle(m(k)),
    }
}

/// So many moves followed from a key, past which a chain is taken to end,
/// as a guard: recording a move forgets any from the key moved to, which
/// holds rows again, so no chain loops.
const MAX_MOVES: usize = 64;

fn floor_presentation(p: &Presentation) -> Presentation {
    Presentation {
        at: floor(p.at),
        taken: floor(p.taken),
        ..p.clone()
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
