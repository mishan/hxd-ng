//! An in-memory [`MessageStore`]: the domain's unit tests, and any server
//! that wants offline messages within one run of the process and nothing
//! more.
//!
//! It is public rather than `#[cfg(test)]` for the same reason
//! [`crate::voice::fake`] is: the end-to-end suites want a real server
//! whose inbox needs no file on disk.
//!
//! Where the SQLite store expresses a rule in SQL, this expresses it in
//! Rust, and [`super::conformance`] holds them to the same answer.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::relationships::{MemoryRelationships, RelationId, SentOn};

use super::{
    Cursor, Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageRef,
    MessageStore, NewMessage, Pending, Pushed, Sent, StoreError, StoredMessage,
};

#[derive(Default)]
struct Inner {
    next_id: MessageId,
    msgs: Vec<StoredMessage>,
    /// Each mailbox's last cursor, by [`index_key`]: kept apart from the
    /// rows so pruning the newest never hands its cursor out again.
    cursors: HashMap<String, Cursor>,
    /// Instant messages handed over and not yet acknowledged.
    handed: HashSet<MessageId>,
    /// Messages whose read receipt was told.
    receipted: HashSet<MessageId>,
    /// Messages stored as requests, released since or not, which the
    /// request ledger counts toward the sender's quota instead.
    requested: HashSet<MessageId>,
    /// The address keys guests' requests were sent from.
    addresses: HashMap<MessageId, String>,
}

impl Inner {
    /// After rows are removed, so a long-lived store does not keep marks
    /// for rows it no longer holds.
    fn forget_removed(&mut self) {
        let held: HashSet<MessageId> = self.msgs.iter().map(|m| m.id).collect();
        for marks in [&mut self.handed, &mut self.receipted, &mut self.requested] {
            marks.retain(|id| held.contains(id));
        }
        self.addresses.retain(|id, _| held.contains(id));
    }
}

/// A [`MessageStore`] in a `Vec`. Ordered by id, which is insertion order.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
    /// Whose friendships and approvals are live, for the gate; with none,
    /// nothing sent on one is.
    gate: Option<Arc<MemoryRelationships>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store whose gate asks `relationships` what is live, as SQLite's
    /// asks the relationship tables in its own file.
    pub fn gated(relationships: Arc<MemoryRelationships>) -> Self {
        MemoryStore {
            gate: Some(relationships),
            ..Self::default()
        }
    }

    /// Does the gate let `m` through? Its own lock is taken under this
    /// store's, and never the other way round.
    fn live(&self, m: &StoredMessage) -> bool {
        match m.friendship {
            None => true,
            Some(SentOn::Request) => false,
            Some(SentOn::Relation(id)) => self.gate.as_ref().is_some_and(|g| g.is_live(id)),
        }
    }

    /// Was `m` sent under an approval?
    fn on_approval(&self, m: &StoredMessage) -> bool {
        matches!(m.friendship, Some(SentOn::Relation(id))
            if self.gate.as_ref().is_some_and(|g| g.is_approval(id)))
    }

    /// Mail waiting to be handed over, through the gate.
    /// Is `m` one of `to`'s rows that `which` reads?
    fn pends(&self, inner: &Inner, m: &StoredMessage, to: &Mailbox, which: Pending) -> bool {
        let instant = matches!(m.friendship, Some(SentOn::Relation(_)));
        is(&m.recipient, to)
            && m.delivered_at.is_none()
            && match which {
                Pending::All => self.waiting(inner, m),
                Pending::Unapproved => self.waiting(inner, m) && !self.on_approval(m),
                Pending::Mail => self.waiting(inner, m) && m.friendship.is_none(),
                Pending::MailApproved => {
                    self.waiting(inner, m) && (m.friendship.is_none() || self.on_approval(m))
                }
                Pending::Instant { again, approvals } => {
                    is_mail(m)
                        && instant
                        && self.live(m)
                        && (again || !inner.handed.contains(&m.id))
                        && (approvals || !self.on_approval(m))
                }
                Pending::Receipts { approvals } => {
                    m.kind == MessageKind::ReadReceipt
                        && self.live(m)
                        && (approvals || !self.on_approval(m))
                }
            }
    }

    fn waiting(&self, inner: &Inner, m: &StoredMessage) -> bool {
        is_mail(m) && m.delivered_at.is_none() && !inner.handed.contains(&m.id) && self.live(m)
    }

    /// Every message held, oldest first — for tests that want to look at
    /// the whole store rather than one mailbox's view of it.
    pub fn all(&self) -> Vec<StoredMessage> {
        self.inner.lock().unwrap().msgs.clone()
    }
}

/// Stamp a mailbox's bare login with a fingerprint, if that is what it is
/// still keyed by. The claim rule, in one place.
fn claim_one(m: &mut Mailbox, login: &str, fingerprint: &[u8; 32]) -> bool {
    if m.fingerprint.is_none() && m.login == login {
        m.fingerprint = Some(*fingerprint);
        return true;
    }
    false
}

/// Move a mailbox from one fingerprint to its successor.
fn rotate_one(m: &mut Mailbox, from: &[u8; 32], to: &[u8; 32]) -> bool {
    if m.fingerprint.as_ref() == Some(from) {
        m.fingerprint = Some(*to);
        return true;
    }
    false
}

/// How the guid index keys a mailbox: its fingerprint if it has one,
/// else its login — the SQL store's `IFNULL(<col>_fp, <col>)`, spelled
/// out. An absent sender keys as the empty string, its `IFNULL(…, '')`.
fn index_key(m: &Mailbox) -> String {
    match m.fingerprint {
        Some(fp) => fp.iter().map(|b| format!("{b:02x}")).collect(),
        None => m.login.clone(),
    }
}

/// The key the guid index will hold for this row once the merge has
/// moved everything it moves — `after` is the merge, applied to one
/// mailbox.
fn merged_key(
    m: &StoredMessage,
    after: &impl Fn(&Mailbox) -> String,
) -> (String, String, Option<MessageGuid>) {
    (
        after(&m.recipient),
        m.sender.as_ref().map(after).unwrap_or_default(),
        m.guid.clone(),
    )
}

/// The cursors of a merge of the mailbox keyed `from` into the one keyed
/// `into`. Into one that never issued a cursor — a first link, a fresh
/// key — the moved mail keeps its cursors and `from`'s count carries
/// over, so no client's go stale. Into one that did, the moved mail is
/// numbered after the last cursor of either, in the order it had, so no
/// cursor its owner saw in either is handed out again. Runs before the
/// rows are re-stamped, while `moves` still knows them.
fn renumber(inner: &mut Inner, moves: impl Fn(&Mailbox) -> bool, from: &str, into: &str) {
    let last = |k: &str| inner.cursors.get(k).copied().unwrap_or(0);
    let (from_last, into_last) = (last(from), last(into));
    if into_last == 0 {
        if from_last > 0 {
            inner.cursors.insert(into.to_string(), from_last);
        }
        return;
    }
    let mut moving: Vec<&mut StoredMessage> = inner
        .msgs
        .iter_mut()
        .filter(|m| is_mail(m) && moves(&m.recipient))
        .collect();
    moving.sort_by_key(|m| m.cursor);
    // Raised even when nothing moves: `from` issued its cursors whether
    // or not its rows are still here.
    let mut last = from_last.max(into_last);
    for m in moving {
        last += 1;
        m.cursor = last;
    }
    inner.cursors.insert(into.to_string(), last);
}

/// Merge duplicate guids when two mailboxes become one, keeping the row
/// that is already at the destination.
///
/// A guid is unique *per pair of mailboxes*, and `claim` and `rotate`
/// merge two mailboxes — so the same guid can legitimately exist on both
/// sides: unlink, retry the send with the same guid, relink. Afterwards
/// those two rows are one message by the guid rule, and the one already
/// at the destination is the older claim on the name. The SQL store has
/// no choice about this (its unique index would refuse the update, which
/// is a `claim` that fails outright and strands everything else in the
/// transaction); this one has to be told, or the two disagree — which is
/// what the shared conformance suite is for.
///
/// Both halves of the key move, so this runs twice: a row that keeps its
/// recipient can still collide because its *sender* is the one being
/// merged. Each pass deletes a row the merge moves and keeps one already
/// at the destination — which are exclusive — so no pair loses both.
///
/// What the duplicate knew comes with it: the two rows are one message,
/// so a duplicate that was delivered or read makes the survivor
/// delivered or read. Otherwise the obvious sequence — mail arrives
/// while linked, the account unlinks, the sender retries, the reader
/// reads the retry, the account relinks — deletes the row that was read
/// and hands the survivor over again as unread.
fn collapse(
    msgs: &mut Vec<StoredMessage>,
    at_destination: impl Fn(&Mailbox) -> bool,
    moves: impl Fn(&Mailbox) -> bool,
    after: impl Fn(&Mailbox) -> String,
) {
    for sender_side in [false, true] {
        let side = |m: &StoredMessage, f: &dyn Fn(&Mailbox) -> bool| {
            if sender_side {
                m.sender.as_ref().is_some_and(f)
            } else {
                f(&m.recipient)
            }
        };
        // Each moving row against the row it will collide with, by
        // index, so the survivor can be updated before the other goes.
        let doomed: Vec<(usize, usize)> = msgs
            .iter()
            .enumerate()
            .filter(|(_, m)| m.guid.is_some() && side(m, &moves))
            .filter_map(|(i, m)| {
                let key = merged_key(m, &after);
                let kept = msgs.iter().position(|k| {
                    k.guid.is_some() && side(k, &at_destination) && merged_key(k, &after) == key
                })?;
                Some((i, kept))
            })
            .collect();
        for (dup, kept) in &doomed {
            let (delivered, read) = (msgs[*dup].delivered_at, msgs[*dup].read_at);
            let kept = &mut msgs[*kept];
            kept.delivered_at = kept.delivered_at.or(delivered);
            kept.read_at = kept.read_at.or(read);
        }
        let mut i = 0;
        msgs.retain(|_| {
            let keep = !doomed.iter().any(|(dup, _)| *dup == i);
            i += 1;
            keep
        });
    }
}

fn is_request(m: &StoredMessage) -> bool {
    m.friendship == Some(SentOn::Request)
}

/// Every read path the inbox exposes is mail only.
fn is_mail(m: &StoredMessage) -> bool {
    m.kind == MessageKind::Message
}

fn is(m: &Mailbox, key: &Mailbox) -> bool {
    key.matches(&m.login, m.fingerprint.as_ref())
}

impl MessageStore for MemoryStore {
    fn push(&self, m: &NewMessage, cap: usize) -> Result<Pushed, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        // Dedup and cap under the one lock the SQLite store does them
        // under too — see the trait docs for why neither can be the
        // caller's job.
        if let Some(guid) = m.guid.as_ref() {
            let existing = inner.msgs.iter().find(|x| {
                x.guid.as_ref() == Some(guid)
                    && is(&x.recipient, &m.recipient)
                    && match (&x.sender, &m.sender) {
                        (Some(a), Some(b)) => is(a, b),
                        (None, None) => true,
                        _ => false,
                    }
            });
            if let Some(existing) = existing {
                return Ok(Pushed::Existing(Box::new(existing.clone())));
            }
        }
        // The cap is about mail. A receipt is not something the recipient
        // reads, and a chatty reader's acks must not fill the mailbox they
        // are acking into.
        if m.kind == MessageKind::Message {
            let waiting = inner
                .msgs
                .iter()
                .filter(|x| is(&x.recipient, &m.recipient) && self.waiting(&inner, x))
                .count();
            if waiting >= cap {
                return Ok(Pushed::Full);
            }
        }
        let mut reference: MessageRef = [0; 16];
        getrandom::getrandom(&mut reference).map_err(StoreError::new)?;
        let cursor = if m.kind == MessageKind::Message {
            let last = inner.cursors.entry(index_key(&m.recipient)).or_default();
            *last += 1;
            *last
        } else {
            0
        };
        inner.next_id += 1;
        let id = inner.next_id;
        inner.msgs.push(StoredMessage {
            id,
            reference,
            cursor,
            recipient: m.recipient.clone(),
            sender: m.sender.clone(),
            sender_nick: m.sender_nick.clone(),
            body: m.body.clone(),
            sent_at: m.sent_at,
            guid: m.guid.clone(),
            kind: m.kind,
            media: m.media.clone(),
            signed: m.signed.clone(),
            friendship: m.friendship,
            delivered_at: None,
            // A receipt is not something anyone reads; stamping it here
            // keeps it out of unread counts and ages it on the read clock
            // without prune needing to know what kinds exist.
            read_at: (m.kind != MessageKind::Message).then_some(m.sent_at),
        });
        if m.friendship == Some(SentOn::Request) {
            inner.requested.insert(id);
        }
        if let Some(a) = &m.sender_address {
            inner.addresses.insert(id, a.clone());
        }
        Ok(Pushed::Stored {
            id,
            reference,
            cursor,
        })
    }

    fn find_guid(
        &self,
        to: &Mailbox,
        from: Option<&Mailbox>,
        guid: &MessageGuid,
    ) -> Result<Option<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .find(|m| {
                m.guid.as_ref() == Some(guid)
                    && is(&m.recipient, to)
                    && match (&m.sender, from) {
                        (Some(s), Some(f)) => is(s, f),
                        (None, None) => true,
                        _ => false,
                    }
            })
            .cloned())
    }

    fn find_sent(
        &self,
        from: &Mailbox,
        guid: &MessageGuid,
    ) -> Result<Option<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .find(|m| {
                m.guid.as_ref() == Some(guid) && m.sender.as_ref().is_some_and(|s| is(s, from))
            })
            .cloned())
    }

    fn pending_of(
        &self,
        to: &Mailbox,
        limit: usize,
        which: Pending,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| self.pends(&inner, m, to, which))
            .take(limit)
            .cloned()
            .collect())
    }

    fn pending_count_of(&self, to: &Mailbox, which: Pending) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| self.pends(&inner, m, to, which))
            .count())
    }

    fn mark_handed(&self, ids: &[MessageId], _at: SystemTime) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.handed.extend(ids.iter().copied());
        Ok(())
    }

    fn receipt_told(&self, id: MessageId, _at: SystemTime) -> Result<bool, StoreError> {
        Ok(self.inner.lock().unwrap().receipted.insert(id))
    }

    fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| is(&m.recipient, to) && self.waiting(&inner, m))
            .count())
    }

    fn mark_delivered(
        &self,
        ids: &[MessageId],
        at: SystemTime,
        what: Delivery,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        for m in inner.msgs.iter_mut() {
            if !ids.contains(&m.id) {
                continue;
            }
            if m.delivered_at.is_none() {
                m.delivered_at = Some(at);
            }
            if what == Delivery::Read && m.read_at.is_none() {
                m.read_at = Some(at);
            }
        }
        Ok(())
    }

    fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .any(|m| m.id == id && is(&m.recipient, to) && self.waiting(&inner, m)))
    }

    fn mark_read(&self, to: &Mailbox, up_to: Cursor, at: SystemTime) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if is_mail(m)
                && is(&m.recipient, to)
                && m.cursor <= up_to
                && m.read_at.is_none()
                && self.live(m)
            {
                m.read_at = Some(at);
                // A message read straight out of `list` was never flushed;
                // stamping it delivered here is what keeps `pending` from
                // handing it to the client a second time.
                m.delivered_at.get_or_insert(at);
                n += 1;
            }
        }
        Ok(n)
    }

    fn list(
        &self,
        to: &Mailbox,
        before: Option<Cursor>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut mine: Vec<StoredMessage> = inner
            .msgs
            .iter()
            .filter(|m| {
                is_mail(m)
                    && is(&m.recipient, to)
                    && before.is_none_or(|b| m.cursor < b)
                    && self.live(m)
            })
            .cloned()
            .collect();
        // Not insertion order: a claim or a rotation numbers what it
        // moves after what was already there.
        mine.sort_by_key(|m| std::cmp::Reverse(m.cursor));
        mine.truncate(limit);
        Ok(mine)
    }

    fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut counts = InboxCounts::default();
        for m in inner
            .msgs
            .iter()
            .filter(|m| is_mail(m) && is(&m.recipient, to) && self.live(m))
        {
            counts.total += 1;
            if m.read_at.is_none() {
                counts.unread += 1;
            }
        }
        Ok(counts)
    }

    fn last_cursor(&self, of: &Mailbox) -> Result<Cursor, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.cursors.get(&index_key(of)).copied().unwrap_or(0))
    }

    fn unlinked(&self, login: &str, fingerprint: &[u8; 32]) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let identity = index_key(&Mailbox::identified(login, *fingerprint));
        if let Some(&past) = inner.cursors.get(&identity) {
            let bare = inner.cursors.entry(login.to_string()).or_default();
            *bare = (*bare).max(past);
        }
        Ok(())
    }

    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
        let moves = |m: &Mailbox| m.fingerprint.is_none() && m.login == login;
        collapse(
            &mut inner.msgs,
            |m: &Mailbox| m.fingerprint.as_ref() == Some(fingerprint),
            moves,
            |m: &Mailbox| {
                if moves(m) {
                    hex.clone()
                } else {
                    index_key(m)
                }
            },
        );
        inner.forget_removed();
        renumber(&mut inner, moves, login, &hex);
        // Its count went with its mail: a later holder of the login
        // must not count on from it. An unlink raises it again.
        inner.cursors.remove(login);
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if claim_one(&mut m.recipient, login, fingerprint) {
                n += 1;
            }
            if let Some(s) = m.sender.as_mut() {
                if claim_one(s, login, fingerprint) {
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let hex: String = to.iter().map(|b| format!("{b:02x}")).collect();
        let moves = |m: &Mailbox| m.fingerprint.as_ref() == Some(from);
        collapse(
            &mut inner.msgs,
            |m: &Mailbox| m.fingerprint.as_ref() == Some(to),
            moves,
            |m: &Mailbox| {
                if moves(m) {
                    hex.clone()
                } else {
                    index_key(m)
                }
            },
        );
        inner.forget_removed();
        renumber(
            &mut inner,
            moves,
            &index_key(&Mailbox::identified("", *from)),
            &hex,
        );
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if rotate_one(&mut m.recipient, from, to) {
                n += 1;
            }
            if let Some(s) = m.sender.as_mut() {
                if rotate_one(s, from, to) {
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.msgs.len();
        inner
            .msgs
            .retain(|m| !is(&m.recipient, of) && !m.sender.as_ref().is_some_and(|s| is(s, of)));
        inner.cursors.remove(&index_key(of));
        inner.forget_removed();
        Ok(before - inner.msgs.len())
    }

    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| is(&m.recipient, of) || m.sender.as_ref().is_some_and(|s| is(s, of)))
            .count())
    }

    fn prune(
        &self,
        now: SystemTime,
        unread: Duration,
        read: Duration,
    ) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.msgs.len();
        inner.msgs.retain(|m| match m.read_at {
            Some(read_at) => elapsed(now, read_at) < read,
            None => elapsed(now, m.sent_at) < unread,
        });
        inner.forget_removed();
        Ok(before - inner.msgs.len())
    }

    fn restamp(&self, merged: &[(RelationId, RelationId)]) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        for (lost, kept) in merged {
            for m in inner.msgs.iter_mut() {
                if m.friendship == Some(SentOn::Relation(*lost)) {
                    m.friendship = Some(SentOn::Relation(*kept));
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    fn requests(
        &self,
        to: &Mailbox,
        since: SystemTime,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| is_mail(m) && is_request(m) && is(&m.recipient, to) && m.sent_at >= since)
            .take(limit)
            .cloned()
            .collect())
    }

    fn release_requests(
        &self,
        to: &Mailbox,
        from: &Mailbox,
        on: RelationId,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if is_request(m)
                && is(&m.recipient, to)
                && m.sent_at >= since
                && m.sender.as_ref().is_some_and(|s| is(s, from))
            {
                m.friendship = Some(SentOn::Relation(on));
                n += 1;
            }
        }
        Ok(n)
    }

    fn requests_to_mail(
        &self,
        to: &Mailbox,
        from: &Mailbox,
        address: Option<&str>,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if is_request(m)
                && is(&m.recipient, to)
                && m.sent_at >= since
                && m.sender.as_ref().is_some_and(|s| is(s, from))
                && address.is_none_or(|a| inner.addresses.get(&m.id).is_some_and(|k| k == a))
            {
                m.friendship = None;
                inner.addresses.remove(&m.id);
                n += 1;
            }
        }
        Ok(n)
    }

    fn delete_requests_from(
        &self,
        to: &Mailbox,
        from: &Mailbox,
        address: &str,
    ) -> Result<usize, StoreError> {
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        let before = inner.msgs.len();
        let addresses = &inner.addresses;
        inner.msgs.retain(|m| {
            !(is_request(m)
                && is(&m.recipient, to)
                && m.sender.as_ref().is_some_and(|s| is(s, from))
                && addresses.get(&m.id).is_some_and(|a| a == address))
        });
        inner.forget_removed();
        Ok(before - inner.msgs.len())
    }

    fn delete_requests(&self, to: &Mailbox, from: &Mailbox) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.msgs.len();
        inner.msgs.retain(|m| {
            !(is_request(m)
                && is(&m.recipient, to)
                && m.sender.as_ref().is_some_and(|s| is(s, from)))
        });
        inner.forget_removed();
        Ok(before - inner.msgs.len())
    }

    fn sent_since(&self, from: &Mailbox, since: SystemTime) -> Result<Sent, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|x| {
                x.kind == MessageKind::Message
                    && x.sent_at >= since
                    && !inner.requested.contains(&x.id)
            })
            .filter(|x| x.sender.as_ref().is_some_and(|s| is(s, from)))
            .fold(Sent::default(), |sent, x| Sent {
                messages: sent.messages + 1,
                bytes: sent.bytes + x.body.len() as u64,
            }))
    }
}

/// `now - then`, floored at zero. A clock that went backwards (NTP, a
/// suspended laptop) must not make an old message look brand new *or*
/// panic; treating it as "no time has passed" keeps the message.
fn elapsed(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::conformance;

    #[test]
    fn passes_the_conformance_suite() {
        conformance::run(&|| {
            let relationships = Arc::new(MemoryRelationships::new());
            conformance::Gated {
                inbox: Arc::new(MemoryStore::gated(relationships.clone())),
                relationships,
            }
        });
    }

    #[test]
    fn all_is_insertion_order() {
        let s = MemoryStore::new();
        for i in 0..3 {
            s.push(
                &NewMessage {
                    recipient: Mailbox::login("bob"),
                    sender: None,
                    sender_nick: "a".into(),
                    body: format!("m{i}"),
                    sent_at: SystemTime::UNIX_EPOCH,
                    guid: None,
                    kind: MessageKind::Message,
                    media: None,
                    signed: None,
                    friendship: None,
                    sender_address: None,
                },
                usize::MAX,
            )
            .unwrap();
        }
        let ids: Vec<MessageId> = s.all().iter().map(|m| m.id).collect();
        assert_eq!(ids, [1, 2, 3]);
    }
}
