//! A [`RelationshipStore`] that fails a call when asked to, for what a
//! failed read or write leaves: the domain's tests and
//! [`crate::messaging::sequence`] wrap either store in it.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::{
    AccountUpdate, Ended, Ending, HeldWithdrawal, Ignore, LedgerEntry, MessagingAccount,
    PendingOut, Presentation, Recorded, Rekeyed, RelationId, Relationship, RelationshipStore,
    RequestKind, Requester, RotationRecord, StoredOffer,
};
use crate::inbox::{Mailbox, MessageGuid, Sent, StoreError};

/// The methods that change nothing.
pub(crate) const READS: &[&str] = &[
    "relationship",
    "relationships",
    "pending_in",
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
    "offer",
    "rotation_from",
    "rotation_to",
    "account",
    "purge_count",
];

enum Plan {
    Off,
    /// This many calls from now, the last fails.
    Nth(usize),
    /// The next call of this method fails.
    #[cfg(test)]
    Next(&'static str),
    /// This many writes from now, the last fails.
    NthWrite(usize),
}

pub(crate) struct Failing {
    inner: Arc<dyn RelationshipStore>,
    plan: Mutex<Plan>,
    failed: Mutex<Option<&'static str>>,
}

impl Failing {
    pub(crate) fn new(inner: Arc<dyn RelationshipStore>) -> Self {
        Failing {
            inner,
            plan: Mutex::new(Plan::Off),
            failed: Mutex::new(None),
        }
    }

    /// The `n`-th call from now fails, whichever method it is; 1 is the
    /// next.
    pub(crate) fn fail_nth(&self, n: usize) {
        *self.plan.lock().unwrap() = if n == 0 { Plan::Off } else { Plan::Nth(n) };
    }

    /// The next call of `method` fails.
    #[cfg(test)]
    pub(crate) fn fail_next(&self, method: &'static str) {
        *self.plan.lock().unwrap() = Plan::Next(method);
    }

    /// The `n`-th write from now fails, whichever method it is.
    pub(crate) fn fail_nth_write(&self, n: usize) {
        *self.plan.lock().unwrap() = if n == 0 { Plan::Off } else { Plan::NthWrite(n) };
    }

    /// The method whose call failed since this was last asked.
    pub(crate) fn failed(&self) -> Option<&'static str> {
        self.failed.lock().unwrap().take()
    }

    fn call(&self, method: &'static str) -> Result<(), StoreError> {
        let mut plan = self.plan.lock().unwrap();
        let fails = match &mut *plan {
            Plan::Off => false,
            Plan::Nth(n) => {
                *n -= 1;
                *n == 0
            }
            #[cfg(test)]
            Plan::Next(m) => *m == method,
            Plan::NthWrite(n) if !READS.contains(&method) => {
                *n -= 1;
                *n == 0
            }
            Plan::NthWrite(_) => false,
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
            $(fn $name(&self, $($arg: $ty),*) -> $ret {
                self.call(stringify!($name))?;
                self.inner.$name($($arg),*)
            })*
        }
    };
}

through! {
    fn relationship(owner: &Mailbox, other: &Mailbox, now: SystemTime) -> Result<Option<Relationship>, StoreError>;
    fn relationships(owner: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
    fn pending_in(owner: &Mailbox, now: SystemTime) -> Result<Vec<Relationship>, StoreError>;
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
    fn made_at(id: RelationId) -> Result<Option<SystemTime>, StoreError>;
    fn present(p: &Presentation) -> Result<Option<Presentation>, StoreError>;
    fn presentation(presenter: &[u8; 32], other: &[u8; 32]) -> Result<Option<Presentation>, StoreError>;
    fn presentations(of: &[u8; 32]) -> Result<Vec<Presentation>, StoreError>;
    fn unpresent(presenter: &[u8; 32], other: &[u8; 32]) -> Result<Option<Presentation>, StoreError>;
    fn drop_presentations(a: &[u8; 32], b: &[u8; 32], presenters: &[[u8; 32]]) -> Result<Ended, StoreError>;
    fn end_friendship(a: &Mailbox, b: &Mailbox, end: &Ending) -> Result<Ended, StoreError>;
    fn presented_by(device: &[u8; 32]) -> Result<Vec<Presentation>, StoreError>;
    fn keep_withdrawal(w: &HeldWithdrawal, cap: usize) -> Result<(), StoreError>;
    fn withdrawals(pair: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError>;
    fn drop_withdrawal(owner: &[u8; 32], pair: &[u8; 32], party: &[u8; 32]) -> Result<(), StoreError>;
    fn set_offer(owner: &[u8; 32], other: &[u8; 32], offer: Option<&StoredOffer>) -> Result<(), StoreError>;
    fn offer(owner: &[u8; 32], other: &[u8; 32], now: SystemTime) -> Result<Option<StoredOffer>, StoreError>;
    fn keep_rotation(from: &[u8; 32], to: &[u8; 32], record: &[u8]) -> Result<(), StoreError>;
    fn rotation_from(from: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError>;
    fn rotation_to(to: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError>;
    fn account(of: &Mailbox) -> Result<MessagingAccount, StoreError>;
    fn update_account(of: &Mailbox, update: &AccountUpdate) -> Result<(), StoreError>;
    fn claim(login: &str, fingerprint: &[u8; 32]) -> Result<Rekeyed, StoreError>;
    fn rotate(from: &[u8; 32], to: &[u8; 32]) -> Result<Rekeyed, StoreError>;
    fn purge(of: &Mailbox) -> Result<usize, StoreError>;
    fn purge_count(of: &Mailbox) -> Result<usize, StoreError>;
    fn cleanup(lapsed_before: SystemTime, ledger_before: SystemTime, batch: usize) -> Result<usize, StoreError>;
}
