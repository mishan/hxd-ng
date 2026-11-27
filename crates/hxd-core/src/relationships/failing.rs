//! A [`RelationshipStore`] that fails a call when asked to, for what a
//! failed read or write leaves, or holds one, for what lands beside it:
//! the domain's tests and [`crate::messaging::sequence`] wrap either store
//! in it.

use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

use super::{
    AccountUpdate, Cause, Charge, Did, Ended, Ending, FpPair, HeldWithdrawal, Ignore, LedgerEntry,
    Left, MessagingAccount, Owed, OwedId, Part, PendingOut, Presentation, Recorded, Rekeyed,
    RelationId, Relationship, RelationshipStore, Report, RequestKind, Requester, RotationRecord,
    StoredOffer, Work,
};
use crate::inbox::{Mailbox, MessageGuid, Sent, StoreError};

/// The methods that change nothing.
pub(crate) const READS: &[&str] = &[
    "relationship",
    "relationships",
    "pending_in",
    "upgrades_to",
    "roster_size",
    "is_blocked",
    "blocked",
    "is_held",
    "find_request",
    "requests_to",
    "recipients_since",
    "request_addresses",
    "guest_requests_to",
    "recipients_from_address",
    "requested_since",
    "made_at",
    "presentation",
    "presentations",
    "presented_by",
    "withdrawals",
    "withdrawals_by",
    "offer",
    "offers_from",
    "offerers",
    "rotation_from",
    "rotation_to",
    "owed",
    "moved",
    "account",
    "claimable",
    "purge_count",
];

enum Plan {
    Off,
    /// This many calls from now, the last fails.
    Nth(usize),
    /// This many calls from now, the last and every one after it fail,
    /// until the plan is set again.
    #[cfg(test)]
    From(usize),
    /// The call of this method this many calls of it from now fails.
    #[cfg(test)]
    Next(&'static str, usize),
    /// This many writes from now, the last fails.
    NthWrite(usize),
    /// The next `write` fails after this many of its parts, all or
    /// nothing.
    Part(usize),
    /// Every read fails once a write whose name starts with this has been
    /// called: whether one was.
    #[cfg(test)]
    ReadsAfter(&'static str, bool),
}

pub(crate) struct Failing {
    inner: Arc<dyn RelationshipStore>,
    plan: Mutex<Plan>,
    failed: Mutex<Option<&'static str>>,
    /// The methods called since the plan was last set, in order.
    calls: Mutex<Vec<&'static str>>,
    /// Held once its call is made, at the method's name.
    pub(crate) park: Park,
}

/// A named point the next call to reach it waits at, until the test lets
/// it go: for what another thread does while it waits.
#[derive(Default)]
pub(crate) struct Park(Mutex<Option<Waiting>>);

/// The point, how the call says it arrived, and what it waits on.
type Waiting = (&'static str, mpsc::Sender<()>, mpsc::Receiver<()>);

/// The test's side of a held call.
#[cfg(test)]
pub(crate) struct Parked {
    arrived: mpsc::Receiver<()>,
    go: mpsc::Sender<()>,
}

impl Park {
    /// The next call to reach `point` waits there until what this
    /// answers is released or dropped.
    #[cfg(test)]
    pub(crate) fn arm(&self, point: &'static str) -> Parked {
        let (arrive, arrived) = mpsc::channel();
        let (go, wait) = mpsc::channel();
        *self.0.lock().unwrap() = Some((point, arrive, wait));
        Parked { arrived, go }
    }

    pub(crate) fn at(&self, point: &'static str) {
        let held = {
            let mut armed = self.0.lock().unwrap();
            match armed.as_ref() {
                Some((p, ..)) if *p == point => armed.take(),
                _ => None,
            }
        };
        if let Some((_, arrive, wait)) = held {
            let _ = arrive.send(());
            let _ = wait.recv();
        }
    }
}

#[cfg(test)]
impl Parked {
    /// Wait for the call to arrive.
    pub(crate) fn arrived(&self) {
        self.arrived
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the call arrives at its point");
    }

    pub(crate) fn release(self) {
        let _ = self.go.send(());
    }
}

impl Failing {
    pub(crate) fn new(inner: Arc<dyn RelationshipStore>) -> Self {
        Failing {
            inner,
            plan: Mutex::new(Plan::Off),
            failed: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
            park: Park::default(),
        }
    }

    /// The `n`-th call from now fails, whichever method it is; 1 is the
    /// next.
    pub(crate) fn fail_nth(&self, n: usize) {
        self.calls.lock().unwrap().clear();
        *self.plan.lock().unwrap() = if n == 0 { Plan::Off } else { Plan::Nth(n) };
    }

    /// The `n`-th call from now and every one after it fail, until the
    /// plan is set again; 1 is the next.
    #[cfg(test)]
    pub(crate) fn fail_from(&self, n: usize) {
        self.calls.lock().unwrap().clear();
        *self.plan.lock().unwrap() = Plan::From(n.max(1));
    }

    /// The next call of `method` fails.
    #[cfg(test)]
    pub(crate) fn fail_next(&self, method: &'static str) {
        self.fail_nth_of(method, 1);
    }

    /// The `n`-th call of `method` from now fails; 1 is the next.
    #[cfg(test)]
    pub(crate) fn fail_nth_of(&self, method: &'static str, n: usize) {
        *self.plan.lock().unwrap() = Plan::Next(method, n);
    }

    /// The `n`-th write from now fails, whichever method it is.
    pub(crate) fn fail_nth_write(&self, n: usize) {
        *self.plan.lock().unwrap() = if n == 0 { Plan::Off } else { Plan::NthWrite(n) };
    }

    /// Every read from the first write named `write`, or a longer name
    /// starting with it, on fails, until the plan is set again: what a
    /// tell made from a read after its step depends on.
    #[cfg(test)]
    pub(crate) fn fail_reads_after(&self, write: &'static str) {
        *self.plan.lock().unwrap() = Plan::ReadsAfter(write, false);
    }

    /// The next `write` fails after `k` of its parts, if it has as many.
    pub(crate) fn fail_write_part(&self, k: usize) {
        self.calls.lock().unwrap().clear();
        *self.plan.lock().unwrap() = Plan::Part(k);
    }

    /// The writes called since the plan was last set, in order.
    pub(crate) fn writes(&self) -> Vec<&'static str> {
        let calls = self.calls.lock().unwrap();
        calls
            .iter()
            .filter(|m| !READS.contains(m))
            .copied()
            .collect()
    }

    /// The method whose call failed since this was last asked.
    pub(crate) fn failed(&self) -> Option<&'static str> {
        self.failed.lock().unwrap().take()
    }

    fn call(&self, method: &'static str) -> Result<(), StoreError> {
        self.calls.lock().unwrap().push(method);
        let mut plan = self.plan.lock().unwrap();
        let fails = match &mut *plan {
            Plan::Off => false,
            Plan::Nth(n) => {
                *n -= 1;
                *n == 0
            }
            #[cfg(test)]
            Plan::From(n) if *n > 1 => {
                *n -= 1;
                false
            }
            #[cfg(test)]
            Plan::From(_) => {
                *self.failed.lock().unwrap() = Some(method);
                return Err(StoreError(format!("{method} failed")));
            }
            #[cfg(test)]
            Plan::Next(m, n) if *m == method => {
                *n -= 1;
                *n == 0
            }
            #[cfg(test)]
            Plan::Next(..) => false,
            Plan::NthWrite(n) if !READS.contains(&method) => {
                *n -= 1;
                *n == 0
            }
            Plan::NthWrite(_) => false,
            Plan::Part(_) => false,
            #[cfg(test)]
            Plan::ReadsAfter(write, written) => {
                let read = READS.contains(&method);
                *written |= !read && method.starts_with(*write);
                if read && *written {
                    *self.failed.lock().unwrap() = Some(method);
                    return Err(StoreError(format!("{method} failed")));
                }
                false
            }
        };
        if fails {
            *plan = Plan::Off;
            *self.failed.lock().unwrap() = Some(method);
            return Err(StoreError(format!("{method} failed")));
        }
        Ok(())
    }
}

macro_rules! through {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        impl RelationshipStore for Failing {
            fn write(&self, parts: &[Part], report: &Report) -> Result<(Vec<Did>, Vec<Left>), StoreError> {
                self.call("write")?;
                let mut plan = self.plan.lock().unwrap();
                let parts = match *plan {
                    Plan::Part(k) if k <= parts.len() => {
                        *plan = Plan::Off;
                        *self.failed.lock().unwrap() = Some("write");
                        let mut failing = parts.to_vec();
                        failing.insert(k, Part::Fail);
                        failing
                    }
                    _ => parts.to_vec(),
                };
                drop(plan);
                let out = self.inner.write(&parts, report);
                self.park.at("write");
                out
            }
            $(fn $name(&self, $($arg: $ty),*) -> $ret {
                self.call(stringify!($name))?;
                let out = self.inner.$name($($arg),*);
                self.park.at(stringify!($name));
                out
            })*
        }
    };
}

through! {
    fn relationship(owner: &Mailbox, other: &Mailbox, now: SystemTime) -> Result<Option<Relationship>, StoreError>;
    fn relationships(owner: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
    fn naming(other: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
    fn pending_in(owner: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
    fn upgrades_to(owner: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
    fn roster_size(owner: &Mailbox, now: SystemTime) -> Result<usize, StoreError>;
    fn set_alias(owner: &Mailbox, other: &Mailbox, alias: Option<&str>) -> Result<(), StoreError>;
    fn set_blocked(owner: &Mailbox, other: &Mailbox, blocked: bool, at: SystemTime) -> Result<(), StoreError>;
    fn is_blocked(owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError>;
    fn blocked(owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError>;
    fn set_pending_out(owner: &Mailbox, other: &Mailbox, pending: Option<&PendingOut>) -> Result<(), StoreError>;
    fn set_ignore(owner: &Mailbox, other: &Mailbox, ignore: Option<&Ignore>) -> Result<(), StoreError>;
    fn befriend(a: &Mailbox, b: &Mailbox, at: SystemTime) -> Result<RelationId, StoreError>;
    fn unfriend(a: &Mailbox, b: &Mailbox) -> Result<Option<RelationId>, StoreError>;
    fn approve(owner: &Mailbox, other: &Mailbox, at: SystemTime) -> Result<RelationId, StoreError>;
    fn end_approval(owner: &Mailbox, other: &Mailbox) -> Result<Option<RelationId>, StoreError>;
    fn hold(owner: &Mailbox, held: &Requester, until: SystemTime) -> Result<(), StoreError>;
    fn is_held(owner: &Mailbox, sender: &Requester, now: SystemTime) -> Result<bool, StoreError>;
    fn record_request(entry: &LedgerEntry) -> Result<Recorded, StoreError>;
    fn find_request(from: &Requester, to: Option<&Mailbox>, guid: &MessageGuid) -> Result<Option<LedgerEntry>, StoreError>;
    fn requests_to(from: &Requester, to: &Mailbox, kind: RequestKind, since: SystemTime) -> Result<usize, StoreError>;
    fn recipients_since(from: &Requester, since: SystemTime) -> Result<usize, StoreError>;
    fn request_addresses(to: &Mailbox, since: SystemTime, before: Option<SystemTime>) -> Result<Vec<String>, StoreError>;
    fn guest_requests_to(address: &str, to: &Mailbox, since: SystemTime) -> Result<usize, StoreError>;
    fn recipients_from_address(address: &str, since: SystemTime) -> Result<usize, StoreError>;
    fn requested_since(from: &Requester, since: SystemTime) -> Result<Sent, StoreError>;
    fn request_dropped(owner: &Mailbox) -> Result<(), StoreError>;
    fn requests_listed(owner: &Mailbox) -> Result<u64, StoreError>;
    fn refriend(a: &Mailbox, b: &Mailbox, id: RelationId, at: SystemTime) -> Result<(), StoreError>;
    fn befriend_dropping(a: &Mailbox, b: &Mailbox, at: SystemTime, id: Option<RelationId>, drop: &[[u8; 32]]) -> Result<RelationId, StoreError>;
    fn made_at(id: RelationId) -> Result<Option<SystemTime>, StoreError>;
    fn present(p: &Presentation) -> Result<Option<Presentation>, StoreError>;
    fn present_befriending(a: &Mailbox, b: &Mailbox, rows: &[Presentation], befriend: Option<Option<RelationId>>, at: SystemTime) -> Result<(Vec<Option<Presentation>>, Option<RelationId>), StoreError>;
    fn lapse_resets(before: SystemTime, now: SystemTime) -> Result<usize, StoreError>;
    fn presentation(presenter: &[u8; 32], other: &[u8; 32]) -> Result<Option<Presentation>, StoreError>;
    fn presentations(of: &[u8; 32]) -> Result<Vec<Presentation>, StoreError>;
    fn unpresent(presenter: &[u8; 32], other: &[u8; 32]) -> Result<Option<Presentation>, StoreError>;
    fn drop_presentations(a: &[u8; 32], b: &[u8; 32], presenters: &[[u8; 32]]) -> Result<Ended, StoreError>;
    fn end_friendship(a: &Mailbox, b: &Mailbox, end: &Ending) -> Result<Ended, StoreError>;
    fn presented_by(device: &[u8; 32]) -> Result<Vec<Presentation>, StoreError>;
    fn keep_withdrawal(w: &HeldWithdrawal, cap: usize) -> Result<(), StoreError>;
    fn withdrawals(pair: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError>;
    fn withdrawals_by(owner: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError>;
    fn drop_withdrawal(owner: &[u8; 32], pair: &[u8; 32], party: &[u8; 32], withdrawal: &[u8]) -> Result<(), StoreError>;
    fn set_offer(owner: &[u8; 32], other: &[u8; 32], offer: Option<&StoredOffer>) -> Result<(), StoreError>;
    fn ask(owner: &Mailbox, other: &Mailbox, pending: &PendingOut, upgrade: Option<&StoredOffer>, charge: Option<&Charge>, report: &Report) -> Result<Vec<Left>, StoreError>;
    fn answer_reset(drops: &[([u8; 32], [u8; 32], Vec<[u8; 32]>)], record: Option<&Presentation>, upgrade: Option<(&Mailbox, &Mailbox)>) -> Result<(Vec<Ended>, Option<Presentation>), StoreError>;
    fn drop_offers(pairs: &[FpPair]) -> Result<(), StoreError>;
    fn drop_offers_naming(fp: &[u8; 32]) -> Result<Vec<FpPair>, StoreError>;
    fn offer(owner: &[u8; 32], other: &[u8; 32], now: SystemTime) -> Result<Option<StoredOffer>, StoreError>;
    fn offers_from(owner: &[u8; 32], now: SystemTime) -> Result<Vec<([u8; 32], StoredOffer)>, StoreError>;
    fn offerers(now: SystemTime) -> Result<Vec<[u8; 32]>, StoreError>;
    fn keep_rotation(from: &[u8; 32], to: &[u8; 32], record: &[u8]) -> Result<(), StoreError>;
    fn rotation_from(from: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError>;
    fn rotation_to(to: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError>;
    fn owe(owed: &[(Work, Cause)]) -> Result<Vec<OwedId>, StoreError>;
    fn owed() -> Result<Vec<Owed>, StoreError>;
    fn settle(ids: &[OwedId]) -> Result<(), StoreError>;
    fn moved(key: &[u8; 32]) -> Result<[u8; 32], StoreError>;
    fn account(of: &Mailbox) -> Result<MessagingAccount, StoreError>;
    fn update_account(of: &Mailbox, update: &AccountUpdate) -> Result<(), StoreError>;
    fn claim(login: &str, fingerprint: &[u8; 32], owe: &[(Work, Cause)]) -> Result<Rekeyed, StoreError>;
    fn claimable(login: &str) -> Result<bool, StoreError>;
    fn rotate_reporting(from: &[u8; 32], to: &[u8; 32], report: &Report, owe: &[(Work, Cause)]) -> Result<(Rekeyed, Vec<Left>), StoreError>;
    fn purge(of: &Mailbox) -> Result<usize, StoreError>;
    fn purge_count(of: &Mailbox) -> Result<usize, StoreError>;
    fn cleanup(lapsed_before: SystemTime, ledger_before: SystemTime, batch: usize) -> Result<usize, StoreError>;
}
