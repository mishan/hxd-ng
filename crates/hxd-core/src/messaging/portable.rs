//! Portable friendships (`docs/proposals/portable-friends.md`): offers on
//! friend requests, friendships made here or presented from elsewhere,
//! and the withdrawals that end them, every object checked by
//! hl-identity's friendship API against what this server holds.
//!
//! **An edge is portable once each party has presented** a friendship
//! for the pair here (§2): the friendship of the two rows, made by the
//! second presentation, and ended when a party's last one goes. One
//! dropped without a withdrawal, by a device's revocation, leaves the
//! friendship's id on the other party's presentation, so the messages
//! queued on it are released when it is active again (§4.3, §6); one
//! ended by a withdrawal does not, since whatever makes it active again
//! is a friendship made after it.
//!
//! **Every act is a device act** (§3): an offer, an acceptance or a
//! withdrawal the session gives is signed with the certificate it
//! proved, while that certificate is unexpired and not revoked here.
//!
//! hxd-ng shows every account's link to anyone, so there are no hidden
//! links (§3), and every refusal that names the other party is one
//! answer, `AccountNotFound`, for no account, one outside messaging and
//! a block either way.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hl_identity::friendship::{chain_end, Cutoff, Pair};
use hl_identity::message::SKEW;
use hl_identity::{
    DeviceCert, Error as IdError, Fingerprint, Friendship, Offer, Rotation, Withdrawal,
};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::{store_failed, takes_part, FriendEntry, MessagingError, RosterState};
use crate::inbox::Mailbox;
use crate::relationships::{
    HeldWithdrawal, Presentation, RelationshipStore, Requester, StoredOffer,
};
use crate::roster::{Event, Uid};
use crate::Core;

#[cfg(test)]
mod tests;

/// A request carries at most this many objects (§4.3, §7).
pub const MAX_OBJECTS: usize = 32;

/// How far a chain of rotations is followed: further than any person
/// rotates, and short of a loop's cost.
const MAX_CHAIN: usize = 16;

/// What one object of a presentation came to (§4.3's reply).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    Ok,
    AccountNotFound,
    RosterFull,
    BadSignature,
    /// With the withdrawal that ends it, where it is not the server's own.
    Withdrawn(Option<Vec<u8>>),
    Stale,
}

/// One object's answer, by the friendship hash, or a withdrawal's pair
/// hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentResult {
    pub hash: [u8; 32],
    pub outcome: Presented,
}

/// What Get Friendships answers (§4.2): each hash with its friendship
/// where the caller may have it, and each fingerprint with the rotation
/// records that end at it, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fetched {
    pub friendships: Vec<([u8; 32], Option<Vec<u8>>)>,
    pub rotations: Vec<([u8; 32], Vec<Vec<u8>>)>,
}

/// What a withdrawal held here ends, and its object where it has one.
type HeldCutoff = (Cutoff, Option<Vec<u8>>);

/// The device a friendships session proved, as the gate admitted it.
pub(super) struct Device {
    /// The SHA-256 of its key.
    key: [u8; 32],
    cert: Arc<Vec<u8>>,
}

/// An object's `time` within `S` of the server's clock, either way (§4.1,
/// §4.3).
fn fresh(time: u64, now: u64) -> Result<(), MessagingError> {
    if time.abs_diff(now) > SKEW {
        return Err(MessagingError::Stale);
    }
    Ok(())
}

/// Signed by the session's own identity, with the certificate it proved.
fn own(device: &Device, me: &Mailbox, from: &[u8; 32], cert: &[u8]) -> Result<(), MessagingError> {
    if me.fingerprint != Some(Fingerprint::of(from).0) || cert != device.cert.as_slice() {
        return Err(MessagingError::BadSignature);
    }
    Ok(())
}

fn whole(p: &Option<Presentation>) -> bool {
    p.as_ref().is_some_and(|p| p.friendship.is_some())
}

fn unix_time(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

impl Core {
    /// The caller, if it may make a friendship act now (§3): a
    /// friendships session whose proved certificate is of the identity
    /// its account links now, not only at login, unexpired, and not
    /// revoked here.
    pub(super) fn device_act(&self, uid: Uid) -> Result<(super::Me, Device), MessagingError> {
        let me = self.messenger(uid)?;
        let now = self.clock.unix();
        let (identity, key, cert) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(MessagingError::NotEnabled)?;
            let tag = sess
                .info
                .transport
                .identity
                .as_ref()
                .filter(|_| sess.info.transport.friendships)
                .filter(|t| Some(t.fingerprint) == me.mailbox.fingerprint)
                .filter(|t| t.device_expires > now)
                .ok_or(MessagingError::NotDeviceProved)?;
            let cert = tag
                .device_cert
                .clone()
                .ok_or(MessagingError::NotDeviceProved)?;
            (tag.fingerprint, tag.device, cert)
        };
        let linked = self
            .directory
            .as_ref()
            .and_then(|d| d.account(&me.mailbox.login))
            .and_then(|(m, _)| m.fingerprint);
        if linked != Some(identity) || self.is_revoked(&identity, &key) {
            return Err(MessagingError::NotDeviceProved);
        }
        Ok((me, Device { key, cert }))
    }

    /// The account linked to `fp` that takes part, if there is one.
    fn mailbox_of(&self, fp: &[u8; 32]) -> Option<Mailbox> {
        let (m, access) = self.directory.as_ref()?.account_by_key(fp)?;
        takes_part(&m.login, access).then_some(m)
    }

    /// The rotations this server applied from `fp` on, in chain order,
    /// each verified again as it is read.
    fn chain_from(&self, store: &Arc<dyn RelationshipStore>, fp: [u8; 32]) -> Vec<Rotation> {
        let mut out = Vec::new();
        let mut key = fp;
        for _ in 0..MAX_CHAIN {
            let Ok(Some((to, record))) = store.rotation_from(&key) else {
                break;
            };
            match Rotation::parse(&record) {
                Ok(r) => out.push(r),
                Err(e) => {
                    warn!("relationships: a kept rotation record does not verify: {e}");
                    break;
                }
            }
            key = to;
        }
        out
    }

    fn rotations_for(&self, store: &Arc<dyn RelationshipStore>, pair: &Pair) -> Vec<Rotation> {
        let (lo, hi) = pair.fingerprints();
        let mut out = self.chain_from(store, lo.0);
        out.extend(self.chain_from(store, hi.0));
        out
    }

    /// What the withdrawals held for `pair` end, each with its object to
    /// hand on: one kept unchecked is checked against the pair now, kept
    /// checked if it passes and dropped if not (§4.3).
    fn cutoffs(
        &self,
        store: &Arc<dyn RelationshipStore>,
        pair: &Pair,
        rotations: &[Rotation],
    ) -> Result<Vec<HeldCutoff>, MessagingError> {
        let now = self.clock.unix();
        let mut out = Vec::new();
        for w in store.withdrawals(&pair.hash()).map_err(store_failed)? {
            if !w.checked {
                let passes = w
                    .withdrawal
                    .as_deref()
                    .and_then(|b| Withdrawal::parse(b, now).ok())
                    .is_some_and(|k| k.check_pair(pair, rotations).is_ok());
                if !passes {
                    store
                        .drop_withdrawal(&w.owner, &w.pair, &w.party)
                        .map_err(store_failed)?;
                    continue;
                }
                let checked = HeldWithdrawal {
                    checked: true,
                    ..w.clone()
                };
                store
                    .keep_withdrawal(&checked, self.messaging_policy.max_roster)
                    .map_err(store_failed)?;
            }
            let cut = Cutoff {
                pair: w.pair,
                party: Fingerprint(w.party),
                before: w.before,
            };
            out.push((cut, w.withdrawal));
        }
        Ok(out)
    }

    /// The offer `from` has waiting for `to`, as it reads now.
    pub(super) fn offer_between(
        &self,
        store: &Arc<dyn RelationshipStore>,
        from: &Mailbox,
        to: &Mailbox,
        now: SystemTime,
    ) -> Option<StoredOffer> {
        let (a, b) = (from.fingerprint?, to.fingerprint?);
        store.offer(&a, &b, now).unwrap_or_else(|e| {
            warn!("relationships: reading an offer: {e}");
            None
        })
    }

    /// Drop the offers either of two accounts has waiting for the other.
    pub(super) fn drop_offers(&self, store: &Arc<dyn RelationshipStore>, a: &Mailbox, b: &Mailbox) {
        let (Some(x), Some(y)) = (a.fingerprint, b.fingerprint) else {
            return;
        };
        for (p, q) in [(x, y), (y, x)] {
            if let Err(e) = store.set_offer(&p, &q, None) {
                warn!("relationships: dropping an offer: {e}");
            }
        }
    }

    /// An 802's offer, checked as §4.1 has it: the caller's own act, in
    /// time, to the fingerprint `them` links, and ended by no withdrawal
    /// held here.
    pub(super) fn check_offer(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        them: &Mailbox,
        bytes: Vec<u8>,
    ) -> Result<StoredOffer, MessagingError> {
        let now = self.clock.unix();
        let offer = Offer::check(&bytes, now, &[]).map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        own(device, me, &offer.from, &offer.cert)?;
        fresh(offer.time, now)?;
        if them.fingerprint != Some(offer.to.0) {
            return Err(MessagingError::AccountNotFound);
        }
        let pair = offer.pair();
        let rotations = self.rotations_for(store, &pair);
        if self
            .cutoffs(store, &pair, &rotations)?
            .iter()
            .any(|(c, _)| offer.cut_by(c))
        {
            return Err(MessagingError::Withdrawn);
        }
        Ok(StoredOffer {
            offer: bytes,
            lapses_at: unix_time(offer.expires),
        })
    }

    /// An upgrade offer on a friendship already standing (§4.1): kept,
    /// and told to the friend's friendships sessions alone.
    pub(super) fn upgrade_offer(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        note: Option<String>,
        offer: StoredOffer,
    ) -> Result<RosterState, MessagingError> {
        let (Some(a), Some(b)) = (me.fingerprint, them.fingerprint) else {
            return Err(MessagingError::AlreadyFriends);
        };
        store
            .set_offer(&a, &b, Some(&offer))
            .map_err(store_failed)?;
        self.roster.lock().unwrap().tell_friendships(
            them,
            Event::FriendRequest {
                login: me.login.clone(),
                fingerprint: me.fingerprint,
                note,
                offer: Some(offer.offer),
            },
        );
        Ok(RosterState::Accepted)
    }

    /// An 805 that accepts with a friendship (§4.1): checked against the
    /// offer stored, the acceptance the caller's own act, then recorded as
    /// presented by both, each by the device that signed its half, and the
    /// edge made portable, keeping its id where there was one.
    pub(super) fn made_here(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        them: &Mailbox,
        offered: &StoredOffer,
        bytes: Vec<u8>,
    ) -> Result<(), MessagingError> {
        let now = self.clock.unix();
        let f = Friendship::check(&bytes, now, &[]).map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        if f.acceptance.offer != <[u8; 32]>::from(Sha256::digest(&offered.offer)) {
            return Err(MessagingError::BadSignature);
        }
        own(device, me, &f.acceptance.from, &f.acceptance.cert)?;
        fresh(f.acceptance.time, now)?;
        let pair = f.pair();
        let rotations = self.rotations_for(store, &pair);
        if self
            .cutoffs(store, &pair, &rotations)?
            .iter()
            .any(|(c, _)| f.cut_by(c))
        {
            return Err(MessagingError::Withdrawn);
        }
        let (Some(mine), Some(theirs)) = (me.fingerprint, them.fingerprint) else {
            return Err(MessagingError::BadSignature);
        };
        let offerer = DeviceCert::parse(&f.offer.cert)
            .map(|c| Fingerprint::of(&c.device).0)
            .map_err(|_| MessagingError::BadSignature)?;
        let at = self.clock.wall();
        for (presenter, other, dev) in [(mine, theirs, device.key), (theirs, mine, offerer)] {
            let edge = store
                .presentation(&presenter, &other)
                .map_err(store_failed)?
                .and_then(|p| p.edge);
            store
                .present(&Presentation {
                    presenter,
                    other,
                    names: [presenter, other],
                    pair: pair.hash(),
                    hash: f.hash,
                    friendship: Some(bytes.clone()),
                    device: dev,
                    edge,
                    at,
                })
                .map_err(store_failed)?;
        }
        let friends = store
            .relationship(me, them, at)
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some());
        if friends {
            self.drop_offers(store, me, them);
            self.tell_entry(me, them);
            self.tell_entry(them, me);
        } else {
            self.befriend(store, me, them, at)?;
        }
        Ok(())
    }

    /// The pairs two accounts' friendships name: their own fingerprints,
    /// and those of the friendships they presented, which a rotation may
    /// have left behind the accounts' keys.
    fn pairs_between(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &[u8; 32],
        b: &[u8; 32],
    ) -> Result<Vec<Pair>, MessagingError> {
        let mut out = vec![Pair::new(Fingerprint(*a), Fingerprint(*b))];
        for (p, q) in [(a, b), (b, a)] {
            if let Some(pres) = store.presentation(p, q).map_err(store_failed)? {
                out.push(Pair::new(
                    Fingerprint(pres.names[0]),
                    Fingerprint(pres.names[1]),
                ));
            }
        }
        Ok(out)
    }

    /// A withdrawal `me` gives as its own act about `them`, at 803 or 806
    /// (§4.3): checked whole against the pair it names, kept, and applied.
    /// Answers its bytes, for the `Removed` it is told with.
    pub(super) fn take_withdrawal(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        them: &Mailbox,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MessagingError> {
        let now = self.clock.unix();
        let kept = Withdrawal::parse(&bytes, now).map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        let w = kept.withdrawal();
        own(device, me, &w.from, &w.cert)?;
        fresh(w.time, now)?;
        let (Some(mine), Some(theirs)) = (me.fingerprint, them.fingerprint) else {
            return Err(MessagingError::BadSignature);
        };
        let named = w.pair;
        let pair = self
            .pairs_between(store, &mine, &theirs)?
            .into_iter()
            .find(|p| p.hash() == named)
            .ok_or(MessagingError::BadSignature)?;
        let rotations = self.rotations_for(store, &pair);
        let held = kept
            .check_pair(&pair, &rotations)
            .map_err(|_| MessagingError::BadSignature)?;
        let cut = held.cutoff();
        self.keep_cutoff(store, &mine, &cut, Some(bytes.clone()))?;
        let party_mine = chain_end(cut.party, &rotations).map(|f| f.0) == Some(mine);
        let (party, other) = if party_mine { (me, them) } else { (them, me) };
        self.apply_cutoff(store, &cut, Some(&bytes), party, other)?;
        Ok(bytes)
    }

    fn keep_cutoff(
        &self,
        store: &Arc<dyn RelationshipStore>,
        owner: &[u8; 32],
        cut: &Cutoff,
        withdrawal: Option<Vec<u8>>,
    ) -> Result<(), MessagingError> {
        store
            .keep_withdrawal(
                &HeldWithdrawal {
                    owner: *owner,
                    pair: cut.pair,
                    party: cut.party.0,
                    before: cut.before,
                    withdrawal,
                    checked: true,
                    at: self.clock.wall(),
                },
                self.messaging_policy.max_roster,
            )
            .map_err(store_failed)
    }

    /// Apply a withdrawal held here to what `party`, whose side it
    /// measures, and `other` hold of each other: the presentations and
    /// offers it ends dropped, and the edge following what is left
    /// (§4.3). A friendship of this server alone ends where it was made
    /// before the cutoff (§2).
    fn apply_cutoff(
        &self,
        store: &Arc<dyn RelationshipStore>,
        cut: &Cutoff,
        withdraw: Option<&[u8]>,
        party: &Mailbox,
        other: &Mailbox,
    ) -> Result<(), MessagingError> {
        let (Some(x), Some(y)) = (party.fingerprint, other.fingerprint) else {
            return Ok(());
        };
        let now = self.clock.unix();
        let wall = self.clock.wall();
        let (mut had, mut ended) = (0, 0);
        for (p, q) in [(x, y), (y, x)] {
            let Some(bytes) = store
                .presentation(&p, &q)
                .map_err(store_failed)?
                .and_then(|pres| pres.friendship)
            else {
                continue;
            };
            had += 1;
            if Friendship::check(&bytes, now, &[]).is_ok_and(|f| f.cut_by(cut)) {
                store.unpresent(&p, &q).map_err(store_failed)?;
                ended += 1;
            }
        }
        for (p, q) in [(x, y), (y, x)] {
            let Some(o) = store.offer(&p, &q, wall).map_err(store_failed)? else {
                continue;
            };
            if Offer::check(&o.offer, now, &[]).is_ok_and(|o| o.cut_by(cut)) {
                store.set_offer(&p, &q, None).map_err(store_failed)?;
            }
        }
        let Some(id) = store
            .relationship(party, other, wall)
            .map_err(store_failed)?
            .and_then(|r| r.friendship)
        else {
            return Ok(());
        };
        let ends = if had == 2 {
            ended > 0
        } else {
            let made = store.made_at(id).map_err(store_failed)?;
            made.is_some_and(|t| t < unix_time(cut.before))
        };
        if !ends {
            return Ok(());
        }
        store.unfriend(party, other).map_err(store_failed)?;
        self.roster
            .lock()
            .unwrap()
            .friends_changed(party, other, false);
        // A friendship that makes it active again is made after the
        // withdrawal, and takes a new id.
        for (p, q) in [(x, y), (y, x)] {
            if let Some(pres) = store.presentation(&p, &q).map_err(store_failed)? {
                if pres.edge.is_some() {
                    store
                        .present(&Presentation { edge: None, ..pres })
                        .map_err(store_failed)?;
                }
            }
        }
        if had == ended {
            store
                .hold(
                    party,
                    &Requester::Account(other.clone()),
                    wall + self.messaging_policy.request_retention,
                )
                .map_err(store_failed)?;
        }
        self.tell_entry_with(party, other, withdraw);
        self.tell_entry_with(other, party, withdraw);
        Ok(())
    }

    /// `me` removes or blocks `them` without a withdrawal of its own,
    /// where they had presented friendships: the server keeps one of its
    /// own for `me`, dated now, that applies here alone, so that `me`'s
    /// other devices do not present the friendship straight back, and the
    /// presentations it ends go (§4.3). Ending the edge is the caller's.
    pub(super) fn end_here(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
    ) {
        let (Some(mine), Some(theirs)) = (me.fingerprint, them.fingerprint) else {
            return;
        };
        let before = self.clock.unix();
        for (p, q) in [(mine, theirs), (theirs, mine)] {
            let pres = match store.unpresent(&p, &q) {
                Ok(Some(pres)) => pres,
                Ok(None) => continue,
                Err(e) => {
                    warn!("relationships: ending a presentation: {e}");
                    continue;
                }
            };
            let named = if p == mine {
                pres.names[0]
            } else {
                pres.names[1]
            };
            let cut = Cutoff {
                pair: pres.pair,
                party: Fingerprint(named),
                before,
            };
            // Needless where a signed one the remover gave already cuts as
            // far; it stands beside one that does not.
            let signed = store.withdrawals(&pres.pair).is_ok_and(|held| {
                held.iter().any(|w| {
                    w.owner == mine
                        && w.party == named
                        && w.withdrawal.is_some()
                        && w.before >= before
                })
            });
            if signed {
                continue;
            }
            if let Err(e) = self.keep_cutoff(store, &mine, &cut, None) {
                warn!("relationships: keeping a removal's withdrawal: {e:?}");
            }
        }
        self.drop_offers(store, me, them);
    }

    /// A presentation went without a withdrawal: an edge it kept active
    /// goes inactive, its id kept on the other party's presentation, and
    /// both are told it is gone here (§6).
    fn presentation_dropped(&self, store: &Arc<dyn RelationshipStore>, gone: &Presentation) {
        if gone.friendship.is_none() {
            return;
        }
        let (Some(a), Some(b)) = (
            self.mailbox_of(&gone.presenter),
            self.mailbox_of(&gone.other),
        ) else {
            return;
        };
        let wall = self.clock.wall();
        let id = store
            .relationship(&a, &b, wall)
            .ok()
            .flatten()
            .and_then(|r| r.friendship);
        let theirs = store
            .presentation(&gone.other, &gone.presenter)
            .ok()
            .flatten()
            .filter(|p| p.friendship.is_some());
        let (Some(id), Some(theirs)) = (id, theirs) else {
            return;
        };
        let kept = store.unfriend(&a, &b).and_then(|_| {
            store.present(&Presentation {
                edge: Some(id),
                ..theirs
            })
        });
        if let Err(e) = kept {
            warn!("relationships: an edge going inactive: {e}");
            return;
        }
        self.roster.lock().unwrap().friends_changed(&a, &b, false);
        self.tell_entry(&a, &b);
        self.tell_entry(&b, &a);
    }

    /// Fill in what only a friendships session is shown of an entry
    /// (§4.2): the hashes a portable friend's entry carries, and the
    /// other's offer waiting for this owner.
    pub(super) fn portable_fields(
        &self,
        store: &Arc<dyn RelationshipStore>,
        of: &Mailbox,
        e: &mut FriendEntry,
        now: SystemTime,
    ) {
        let (Some(mine), Some(theirs)) = (of.fingerprint, e.fingerprint) else {
            return;
        };
        let read = |p: &[u8; 32], q: &[u8; 32]| store.presentation(p, q).ok().flatten();
        if e.state == RosterState::Accepted {
            let (a, b) = (read(&mine, &theirs), read(&theirs, &mine));
            if whole(&a) && whole(&b) {
                let mut hashes: Vec<[u8; 32]> =
                    [a, b].into_iter().flatten().map(|p| p.hash).collect();
                hashes.dedup();
                e.friendships = hashes;
            }
        }
        if matches!(e.state, RosterState::Accepted | RosterState::PendingIn) {
            e.offer = store
                .offer(&theirs, &mine, now)
                .ok()
                .flatten()
                .map(|o| o.offer);
        }
    }

    // --- Requests ------------------------------------------------------

    /// Find User (822) by `DATA_FRIEND_IDENTITY`: as by login, one answer
    /// for every account the caller may not find.
    pub fn find_user_by_key(
        &self,
        uid: Uid,
        fingerprint: &[u8; 32],
        profile: bool,
    ) -> Result<super::FoundUser, MessagingError> {
        let them = self
            .mailbox_of(fingerprint)
            .ok_or(MessagingError::AccountNotFound)?;
        self.found(uid, &them.login, profile)
    }

    /// Remove Friend (803) naming its party by fingerprint (§4.3): a
    /// friend is removed as by login; for anyone else, a presentation the
    /// caller made naming that fingerprint is dropped, whether or not
    /// there was one, so that the answer says nothing.
    pub fn friend_remove_by_key(
        &self,
        uid: Uid,
        fingerprint: &[u8; 32],
        withdraw: Option<Vec<u8>>,
    ) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let store = self.friends_store()?;
        if let Some(them) = self.mailbox_of(fingerprint) {
            let friends = store
                .relationship(&me.mailbox, &them, self.clock.wall())
                .map_err(store_failed)?
                .is_some_and(|r| r.friendship.is_some());
            if friends {
                return self.friend_unfriend(uid, &them.login, withdraw);
            }
        }
        if let Some(mine) = me.mailbox.fingerprint {
            let _writing = self.friend_writes();
            store.unpresent(&mine, fingerprint).map_err(store_failed)?;
        }
        Ok(())
    }

    /// Remove Friend (803) carrying the caller's own upgrade offer to
    /// `login`: that offer canceled, and nothing else (§4.1).
    pub fn friend_cancel_offer(
        &self,
        uid: Uid,
        login: &str,
        offer: &[u8],
    ) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, login)?;
        let store = self.friends_store()?;
        let _writing = self.friend_writes();
        let now = self.clock.wall();
        match self.offer_between(store, &me.mailbox, &them, now) {
            Some(o) if o.offer == offer => {
                let (a, b) = (me.mailbox.fingerprint, them.fingerprint);
                let (Some(a), Some(b)) = (a, b) else {
                    return Err(MessagingError::NotFriends);
                };
                store.set_offer(&a, &b, None).map_err(store_failed)
            }
            _ => Err(MessagingError::NotFriends),
        }
    }

    /// The withdrawal a Block User (806) carries, taken before the block
    /// is (§4.3), so the friend's other servers hear of a removal and
    /// never of a block. The block itself is the caller's to make next.
    pub fn block_withdrawing(
        &self,
        uid: Uid,
        login: &str,
        withdraw: Vec<u8>,
    ) -> Result<(), MessagingError> {
        // The gate is asked under the lock a revocation's or an unlink's
        // cleanup takes, so what it admits is recorded before that cleanup
        // runs, and dropped by it, or refused after.
        let _writing = self.friend_writes();
        let (me, device) = self.device_act(uid)?;
        // What can be said of the withdrawal alone is said before anyone
        // is looked up, so that its answer is the same whoever it names.
        let now = self.clock.unix();
        let kept = Withdrawal::parse(&withdraw, now).map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        let w = kept.withdrawal();
        own(&device, &me.mailbox, &w.from, &w.cert)?;
        fresh(w.time, now)?;
        // One the caller may not name, one linking no identity, and one
        // whose pair it does not name have no friendship here to withdraw,
        // and the block that follows answers for them as a plain one does,
        // so that the withdrawal tells nothing of a blocker or of a Login.
        let Ok(them) = self.other(&me, login) else {
            return Ok(());
        };
        let store = self.friends_store()?;
        let (Some(mine), Some(theirs)) = (me.mailbox.fingerprint, them.fingerprint) else {
            return Ok(());
        };
        let named = w.pair;
        if !self
            .pairs_between(store, &mine, &theirs)?
            .iter()
            .any(|p| p.hash() == named)
        {
            return Ok(());
        }
        self.take_withdrawal(store, &me.mailbox, &device, &them, withdraw)
            .map(|_| ())
    }

    /// Present Friendships (§4.3): its withdrawals taken, then its
    /// friendships checked in §4.3's order, each answered.
    pub fn friendships_present(
        &self,
        uid: Uid,
        withdrawals: Vec<Vec<u8>>,
        friendships: Vec<Vec<u8>>,
    ) -> Result<(Vec<PresentResult>, Vec<PresentResult>), MessagingError> {
        let store = self.friends_store()?;
        if withdrawals.len() + friendships.len() > MAX_OBJECTS {
            return Err(MessagingError::TooMany);
        }
        // The reply names a withdrawal by its pair hash.
        let now = self.clock.unix();
        let mut pairs: Vec<[u8; 32]> = withdrawals
            .iter()
            .filter_map(|b| Withdrawal::parse(b, now).ok())
            .map(|k| k.withdrawal().pair)
            .collect();
        let named = pairs.len();
        pairs.sort_unstable();
        pairs.dedup();
        if pairs.len() != named {
            return Err(MessagingError::TooMany);
        }
        // The gate is asked under the lock a revocation's or an unlink's
        // cleanup takes, so what it admits is recorded before that cleanup
        // runs, and dropped by it, or refused after.
        let _writing = self.friend_writes();
        let (me, device) = self.device_act(uid)?;
        let mine = me
            .mailbox
            .fingerprint
            .ok_or(MessagingError::NotDeviceProved)?;
        let taken = withdrawals
            .into_iter()
            .map(|b| self.present_withdrawal(store, &me.mailbox, &device, b))
            .collect::<Result<_, _>>()?;
        let presented = friendships
            .into_iter()
            .map(|b| self.present_friendship(store, &me.mailbox, mine, &device, b))
            .collect::<Result<_, _>>()?;
        Ok((taken, presented))
    }

    fn present_withdrawal(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        bytes: Vec<u8>,
    ) -> Result<PresentResult, MessagingError> {
        let now = self.clock.unix();
        let refused = |hash, outcome| Ok(PresentResult { hash, outcome });
        let kept = match Withdrawal::parse(&bytes, now) {
            Ok(k) => k,
            Err(r) => {
                let outcome = match r.error {
                    IdError::ClockSkew => Presented::Stale,
                    _ => Presented::BadSignature,
                };
                // Named by the pair it names where that can be read.
                let pair =
                    Withdrawal::parse(&bytes, u64::MAX).map_or([0; 32], |k| k.withdrawal().pair);
                return refused(pair, outcome);
            }
        };
        let w = kept.withdrawal().clone();
        if let Err(e) = own(device, me, &w.from, &w.cert).and_then(|()| fresh(w.time, now)) {
            let outcome = match e {
                MessagingError::Stale => Presented::Stale,
                _ => Presented::BadSignature,
            };
            return refused(w.pair, outcome);
        }
        let mine = me.fingerprint.expect("a device act's account is linked");
        // The pair is one this server holds where a presentation by either
        // account names it, or where the two have rows, a friendship, a
        // request or an offer, between them; until then the withdrawal is
        // kept unchecked.
        let held = store.presentations(&mine).map_err(store_failed)?;
        let found = match held.iter().find(|p| p.pair == w.pair) {
            Some(p) => Some((p.names, p.presenter, p.other)),
            None => self
                .counterparts(store, me)?
                .into_iter()
                .find(|o| Pair::new(Fingerprint(mine), Fingerprint(*o)).hash() == w.pair)
                .map(|o| ([mine, o], mine, o)),
        };
        let Some((names, presenter, other)) = found else {
            let cut = HeldWithdrawal {
                owner: mine,
                pair: w.pair,
                party: w.effective_party().0,
                before: w.before,
                withdrawal: Some(bytes),
                checked: false,
                at: self.clock.wall(),
            };
            store
                .keep_withdrawal(&cut, self.messaging_policy.max_roster)
                .map_err(store_failed)?;
            return refused(w.pair, Presented::Ok);
        };
        let pair = Pair::new(Fingerprint(names[0]), Fingerprint(names[1]));
        let rotations = self.rotations_for(store, &pair);
        let Ok(held) = kept.check_pair(&pair, &rotations) else {
            return refused(w.pair, Presented::BadSignature);
        };
        let cut = held.cutoff();
        self.keep_cutoff(store, &mine, &cut, Some(bytes.clone()))?;
        let party_key = chain_end(cut.party, &rotations).map(|f| f.0);
        let accounts = (self.mailbox_of(&presenter), self.mailbox_of(&other));
        if let (Some(a), Some(b)) = accounts {
            let (party, other) = if a.fingerprint == party_key {
                (a, b)
            } else {
                (b, a)
            };
            self.apply_cutoff(store, &cut, Some(&bytes), &party, &other)?;
        }
        refused(w.pair, Presented::Ok)
    }

    /// The fingerprints of the accounts `me` has a row about, or that
    /// have a request waiting for it.
    fn counterparts(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
    ) -> Result<Vec<[u8; 32]>, MessagingError> {
        let now = self.clock.wall();
        let mine = store.relationships(me, now).map_err(store_failed)?;
        let asking = store.pending_in(me, now).map_err(store_failed)?;
        Ok(mine
            .iter()
            .filter_map(|r| r.other.fingerprint)
            .chain(asking.iter().filter_map(|r| r.owner.fingerprint))
            .collect())
    }

    fn present_friendship(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        mine: [u8; 32],
        device: &Device,
        bytes: Vec<u8>,
    ) -> Result<PresentResult, MessagingError> {
        let now = self.clock.unix();
        let wall = self.clock.wall();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let answer = |outcome| Ok(PresentResult { hash, outcome });
        // Step 1: the friendship, and that it names the presenter's key or
        // one that rotated to it.
        let Ok(f) = Friendship::check(&bytes, now, &[]) else {
            return answer(Presented::BadSignature);
        };
        let pair = f.pair();
        let rotations = self.rotations_for(store, &pair);
        let names = [f.offer.offerer(), f.offer.to];
        let at = |k: Fingerprint| chain_end(k, &rotations).map(|e| e.0);
        let (my_name, their_name) = match (at(names[0]) == Some(mine), at(names[1]) == Some(mine)) {
            (true, false) => (names[0], names[1]),
            (false, true) => (names[1], names[0]),
            _ => return answer(Presented::BadSignature),
        };
        let theirs = at(their_name).unwrap_or(their_name.0);
        let held = store.presentations(&mine).map_err(store_failed)?;
        let presented = |p: &[u8; 32], q: &[u8; 32]| {
            held.iter()
                .find(|x| x.presenter == *p && x.other == *q)
                .cloned()
        };
        // The bound counts this account's presentations whose edge is not
        // active, read from its own rows alone.
        let friends: Vec<[u8; 32]> = store
            .relationships(me, wall)
            .map_err(store_failed)?
            .into_iter()
            .filter(|r| r.friendship.is_some())
            .filter_map(|r| r.other.fingerprint)
            .collect();
        if !friends.contains(&theirs) {
            let waiting = held
                .iter()
                .filter(|p| p.presenter == mine && p.other != theirs)
                .filter(|p| !friends.contains(&p.other))
                .count();
            if waiting >= self.messaging_policy.max_roster {
                return answer(Presented::RosterFull);
            }
        }
        let record = |friendship: Option<Vec<u8>>| {
            let edge = presented(&mine, &theirs).and_then(|p| p.edge);
            store
                .present(&Presentation {
                    presenter: mine,
                    other: theirs,
                    names: [my_name.0, their_name.0],
                    pair: pair.hash(),
                    hash,
                    friendship,
                    device: device.key,
                    edge,
                    at: wall,
                })
                .map(|_| ())
                .map_err(store_failed)
        };
        // Step 2's refusal keeps the hash alone toward the bound, as the
        // identity draft has it, and changes nothing already held.
        let keep_hash = || match presented(&mine, &theirs) {
            Some(_) => Ok(()),
            None => record(None),
        };
        // Step 2: the other party.
        let them = match self.mailbox_of(&theirs) {
            Some(them)
                if !store.is_blocked(&them, me).map_err(store_failed)?
                    && !store.is_blocked(me, &them).map_err(store_failed)? =>
            {
                them
            }
            _ => {
                keep_hash()?;
                return answer(Presented::AccountNotFound);
            }
        };
        // Step 3: withdrawals.
        if let Some((_, w)) = self
            .cutoffs(store, &pair, &rotations)?
            .into_iter()
            .find(|(c, _)| f.cut_by(c))
        {
            return answer(Presented::Withdrawn(w));
        }
        // Step 5, there being no hidden links for step 4.
        record(Some(bytes))?;
        match self.activate(store, me, &them, wall) {
            Ok(()) => answer(Presented::Ok),
            Err(MessagingError::RosterFull) => answer(Presented::RosterFull),
            Err(e) => Err(e),
        }
    }

    /// Make the edge between `me` and `them` active where each has
    /// presented a friendship for it (§4.3), under the id it had where a
    /// dropped presentation kept one; or tell both its entry again where
    /// it is active already. `RosterFull` where `me`'s roster has no room
    /// for it; where `them`'s has none it stays inactive, unanswered.
    fn activate(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        now: SystemTime,
    ) -> Result<(), MessagingError> {
        let (Some(a), Some(b)) = (me.fingerprint, them.fingerprint) else {
            return Ok(());
        };
        let pa = store.presentation(&a, &b).map_err(store_failed)?;
        let pb = store.presentation(&b, &a).map_err(store_failed)?;
        if !(whole(&pa) && whole(&pb)) {
            return Ok(());
        }
        let friends = store
            .relationship(me, them, now)
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some());
        if friends {
            self.tell_entry(me, them);
            self.tell_entry(them, me);
            return Ok(());
        }
        let max = self.messaging_policy.max_roster;
        let room = |x: &Mailbox, y: &Mailbox| -> Result<bool, MessagingError> {
            Ok(store
                .relationship(x, y, now)
                .map_err(store_failed)?
                .is_some()
                || store.roster_size(x, now).map_err(store_failed)? < max)
        };
        if !room(me, them)? {
            return Err(MessagingError::RosterFull);
        }
        if !room(them, me)? {
            return Ok(());
        }
        let edge = pa.and_then(|p| p.edge).or(pb.and_then(|p| p.edge));
        self.befriend_as(store, me, them, now, edge)?;
        Ok(())
    }

    /// Get Friendships (§4.2), open to the sessions Present Friendships
    /// is.
    pub fn friendships_fetch(
        &self,
        uid: Uid,
        hashes: &[[u8; 32]],
        fingerprints: &[[u8; 32]],
    ) -> Result<Fetched, MessagingError> {
        let (me, _) = self.device_act(uid)?;
        let store = self.friends_store()?;
        let mine = me
            .mailbox
            .fingerprint
            .ok_or(MessagingError::NotDeviceProved)?;
        if hashes.len() + fingerprints.len() > MAX_OBJECTS {
            return Err(MessagingError::TooMany);
        }
        let wall = self.clock.wall();
        let held = store.presentations(&mine).map_err(store_failed)?;
        let read = |p: &[u8; 32], q: &[u8; 32]| {
            held.iter()
                .find(|x| x.presenter == *p && x.other == *q)
                .cloned()
        };
        // The friends whose entries carry hashes: both presented, and
        // friends here.
        let mut friends: Vec<[u8; 32]> = Vec::new();
        for p in &held {
            let other = if p.presenter == mine {
                p.other
            } else {
                p.presenter
            };
            if friends.contains(&other)
                || !(whole(&read(&mine, &other)) && whole(&read(&other, &mine)))
            {
                continue;
            }
            let Some(them) = self.mailbox_of(&other) else {
                continue;
            };
            if store
                .relationship(&me.mailbox, &them, wall)
                .map_err(store_failed)?
                .is_some_and(|r| r.friendship.is_some())
            {
                friends.push(other);
            }
        }
        let mut out = Fetched::default();
        for h in hashes {
            let found = held
                .iter()
                .filter(|p| {
                    friends.contains(if p.presenter == mine {
                        &p.other
                    } else {
                        &p.presenter
                    })
                })
                .find(|p| p.hash == *h)
                .and_then(|p| p.friendship.clone());
            out.friendships.push((*h, found));
        }
        for fp in fingerprints {
            let mut records = Vec::new();
            if friends.contains(fp) {
                let mut key = *fp;
                for _ in 0..MAX_CHAIN {
                    match store.rotation_to(&key).map_err(store_failed)? {
                        Some((from, record)) => {
                            records.push(record);
                            key = from;
                        }
                        None => break,
                    }
                }
                records.reverse();
            }
            out.rotations.push((*fp, records));
        }
        Ok(out)
    }

    // --- Keys ----------------------------------------------------------

    /// Keep the record of a rotation this server applied, so that its
    /// successor takes its predecessor's place in every check here, and a
    /// friend's client can fetch it (§4.4, §10). One that does not verify
    /// is not kept.
    pub fn keep_rotation_record(&self, record: &[u8]) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        let r = match Rotation::parse(record) {
            Ok(r) => r,
            Err(e) => {
                warn!("relationships: a rotation record that does not verify: {e}");
                return;
            }
        };
        let (from, to) = (
            Fingerprint::of(&r.identity).0,
            Fingerprint::of(&r.successor).0,
        );
        if let Err(e) = store.keep_rotation(&from, &to, record) {
            warn!("relationships: keeping a rotation record: {e}");
        }
    }

    /// Drop what the devices now revoked here presented (§6): the
    /// operator's by device, the registrars' by device and identity.
    pub(crate) fn drop_revoked_presentations(&self, devices: &[(Option<[u8; 32]>, [u8; 32])]) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        let _writing = self.friend_writes();
        for (identity, device) in devices {
            let made = match store.presented_by(device) {
                Ok(made) => made,
                Err(e) => {
                    warn!("relationships: reading a revoked device's presentations: {e}");
                    continue;
                }
            };
            for p in made
                .into_iter()
                .filter(|p| identity.is_none_or(|i| p.presenter == i))
            {
                match store.unpresent(&p.presenter, &p.other) {
                    Ok(_) => self.presentation_dropped(store, &p),
                    Err(e) => warn!("relationships: dropping a revoked device's presentation: {e}"),
                }
            }
        }
    }

    /// An account gave up its link to `fingerprint`: what it presented
    /// under it goes (§4.4). A link made again starts from the
    /// presentations its clients make then.
    pub fn friendships_unlinked(&self, fingerprint: &[u8; 32]) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        // Its sessions that proved the identity make friendship acts no
        // more: the account no longer links it.
        for s in self.roster.lock().unwrap().users.values_mut() {
            if s.info
                .transport
                .identity
                .as_ref()
                .is_some_and(|t| t.fingerprint == *fingerprint)
            {
                s.info.transport.friendships = false;
            }
        }
        let _writing = self.friend_writes();
        let made = store.presentations(fingerprint).unwrap_or_default();
        for p in made.iter().filter(|p| p.presenter == *fingerprint) {
            if let Err(e) = store.unpresent(&p.presenter, &p.other) {
                warn!("relationships: dropping an unlinked account's presentation: {e}");
            }
        }
    }
}
