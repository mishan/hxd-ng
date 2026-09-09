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

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::{
    Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageStore, NewMessage,
    Pushed, StoreError, StoredMessage,
};

struct Block {
    owner: Mailbox,
    other: Mailbox,
}

#[derive(Default)]
struct Inner {
    next_id: MessageId,
    msgs: Vec<StoredMessage>,
    blocks: Vec<Block>,
}

/// A [`MessageStore`] in a `Vec`. Ordered by id, which is insertion order.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
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

/// One block per pair of mailboxes, keeping the oldest — the SQL store's
/// `MERGE_BLOCKS`. A merge is the only thing that can make two: block
/// while linked, unlink, block again, relink.
fn merge_blocks(blocks: &mut Vec<Block>) {
    let mut seen: Vec<(String, String)> = Vec::new();
    blocks.retain(|b| {
        let key = (index_key(&b.owner), index_key(&b.other));
        let first = !seen.contains(&key);
        if first {
            seen.push(key);
        }
        first
    });
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
                .filter(|x| {
                    is_mail(x) && is(&x.recipient, &m.recipient) && x.delivered_at.is_none()
                })
                .count();
            if waiting >= cap {
                return Ok(Pushed::Full);
            }
        }
        inner.next_id += 1;
        let id = inner.next_id;
        inner.msgs.push(StoredMessage {
            id,
            recipient: m.recipient.clone(),
            sender: m.sender.clone(),
            sender_nick: m.sender_nick.clone(),
            body: m.body.clone(),
            sent_at: m.sent_at,
            guid: m.guid.clone(),
            kind: m.kind,
            media: m.media.clone(),
            delivered_at: None,
            // A receipt is not something anyone reads; stamping it here
            // keeps it out of unread counts and ages it on the read clock
            // without prune needing to know what kinds exist.
            read_at: (m.kind != MessageKind::Message).then_some(m.sent_at),
        });
        Ok(Pushed::Stored(id))
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

    fn pending(&self, to: &Mailbox, limit: usize) -> Result<Vec<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| is_mail(m) && is(&m.recipient, to) && m.delivered_at.is_none())
            .take(limit)
            .cloned()
            .collect())
    }

    fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .filter(|m| is_mail(m) && is(&m.recipient, to) && m.delivered_at.is_none())
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
            .any(|m| m.id == id && is_mail(m) && is(&m.recipient, to) && m.delivered_at.is_none()))
    }

    fn mark_read(
        &self,
        to: &Mailbox,
        up_to: MessageId,
        at: SystemTime,
    ) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let mut n = 0;
        for m in inner.msgs.iter_mut() {
            if is_mail(m) && is(&m.recipient, to) && m.id <= up_to && m.read_at.is_none() {
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
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .msgs
            .iter()
            .rev()
            .filter(|m| is_mail(m) && is(&m.recipient, to) && before.is_none_or(|b| m.id < b))
            .take(limit)
            .cloned()
            .collect())
    }

    fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut counts = InboxCounts::default();
        for m in inner
            .msgs
            .iter()
            .filter(|m| is_mail(m) && is(&m.recipient, to))
        {
            counts.total += 1;
            if m.read_at.is_none() {
                counts.unread += 1;
            }
        }
        Ok(counts)
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
        for b in inner.blocks.iter_mut() {
            if claim_one(&mut b.owner, login, fingerprint) {
                n += 1;
            }
            if claim_one(&mut b.other, login, fingerprint) {
                n += 1;
            }
        }
        merge_blocks(&mut inner.blocks);
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
        for b in inner.blocks.iter_mut() {
            if rotate_one(&mut b.owner, from, to) {
                n += 1;
            }
            if rotate_one(&mut b.other, from, to) {
                n += 1;
            }
        }
        merge_blocks(&mut inner.blocks);
        Ok(n)
    }

    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.msgs.len() + inner.blocks.len();
        inner
            .msgs
            .retain(|m| !is(&m.recipient, of) && !m.sender.as_ref().is_some_and(|s| is(s, of)));
        inner
            .blocks
            .retain(|b| !is(&b.owner, of) && !is(&b.other, of));
        Ok(before - (inner.msgs.len() + inner.blocks.len()))
    }

    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        let messages = inner
            .msgs
            .iter()
            .filter(|m| is(&m.recipient, of) || m.sender.as_ref().is_some_and(|s| is(s, of)))
            .count();
        let blocks = inner
            .blocks
            .iter()
            .filter(|b| is(&b.owner, of) || is(&b.other, of))
            .count();
        Ok(messages + blocks)
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
        Ok(before - inner.msgs.len())
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        _at: SystemTime,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let held = inner
            .blocks
            .iter()
            .any(|b| is(&b.owner, owner) && is(&b.other, other));
        match (blocked, held) {
            (true, false) => inner.blocks.push(Block {
                owner: owner.clone(),
                other: other.clone(),
            }),
            // *Every* match, as the SQL store's `DELETE` does. Removing
            // one left the pair still blocked after an unblock said it
            // wasn't, if anything had ever managed to store two.
            (false, true) => inner
                .blocks
                .retain(|b| !(is(&b.owner, owner) && is(&b.other, other))),
            _ => {}
        }
        Ok(())
    }

    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .blocks
            .iter()
            .any(|b| is(&b.owner, owner) && is(&b.other, other)))
    }

    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .blocks
            .iter()
            .filter(|b| is(&b.owner, owner))
            .map(|b| b.other.clone())
            .collect())
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
        conformance::run(&|| Box::new(MemoryStore::new()));
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
                },
                usize::MAX,
            )
            .unwrap();
        }
        let ids: Vec<MessageId> = s.all().iter().map(|m| m.id).collect();
        assert_eq!(ids, [1, 2, 3]);
    }
}
