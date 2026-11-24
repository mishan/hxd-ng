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

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hl_identity::friendship::{chain_end, Cutoff, Pair, Refused};
use hl_identity::message::SKEW;
use hl_identity::{
    DeviceCert, DeviceEpoch, Error as IdError, Fingerprint, Friendship, Offer, PublicKey, Rotation,
    Withdrawal,
};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use super::{store_failed, takes_part, FriendEntry, MessagingError, RosterState};
use crate::identity_records::{CachedList, KeptEpoch, RecordCache};
use crate::inbox::{Mailbox, StoreError};
use crate::relationships::{
    Ended, EndedEdge, Ending, HeldWithdrawal, Presentation, RelationId, RelationshipStore,
    StoredOffer,
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

/// The `now` an object stored here is checked at: its `time` was checked
/// against the clock when it was taken, and a clock set back since must
/// not refuse it.
const STORED: u64 = u64::MAX;

/// Every floor taken as 0: for an object whose signatures must verify
/// whatever the floors, which are tested after them (§4.3 step 1, §6),
/// or one stored here and read only for what it says.
fn zero_floor(_: &PublicKey) -> u64 {
    0
}

/// What this server holds of an identity's device epochs (§6): its
/// floor, and for each epoch the earliest `time` of a record of it seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Epochs {
    floor: u64,
    /// `(epoch, time)`, by epoch.
    times: Vec<(u64, u64)>,
}

impl Epochs {
    /// `fp`'s records kept, as far as they verify, and the floor
    /// installed, whichever is higher.
    fn of(fp: &[u8; 32], installed: Option<u64>, rows: &[KeptEpoch]) -> Self {
        let mut times: Vec<(u64, u64)> = rows
            .iter()
            .filter_map(|row| {
                DeviceEpoch::parse(&row.record)
                    .ok()
                    .filter(|e| e.epoch == row.epoch && Fingerprint::of(&e.identity).0 == *fp)
                    .map(|e| (e.epoch, e.time))
            })
            .collect();
        times.sort_unstable();
        let kept = times.last().map_or(0, |(e, _)| *e);
        let floor = kept.max(installed.unwrap_or(0));
        Epochs { floor, times }
    }

    /// For a certificate of `epoch` below the floor, when it was reset:
    /// the earliest `time` of a record above it, or `None` where no such
    /// record is kept, as where the floor came from a list whose records
    /// could not be kept.
    fn reset_at(&self, epoch: u64) -> Option<Option<u64>> {
        (epoch < self.floor).then(|| {
            self.times
                .iter()
                .filter(|(e, _)| *e > epoch)
                .map(|(_, t)| *t)
                .min()
        })
    }

    /// The floor the records kept here alone show, which never falls, as
    /// one installed from a list can.
    fn kept(&self) -> u64 {
        self.times.iter().map(|(e, _)| *e).max().unwrap_or(0)
    }
}

/// Identities, each with the floor the records kept here showed for it.
pub(crate) type KeptFloors = Vec<([u8; 32], u64)>;

/// An identity's device epochs as stored, unverified: its kept records,
/// each as `(epoch, time, hash)`, and the floor installed. Two reads that
/// match held the same epochs, so a pass compares them without verifying
/// a record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EpochKey {
    installed: Option<u64>,
    rows: Vec<(u64, u64, [u8; 32])>,
}

impl EpochKey {
    fn of(installed: Option<u64>, rows: &[KeptEpoch]) -> Self {
        let mut key: Vec<_> = rows
            .iter()
            .map(|r| (r.epoch, r.time, Sha256::digest(&r.record).into()))
            .collect();
        key.sort_unstable();
        EpochKey {
            installed,
            rows: key,
        }
    }
}

/// So many generations kept, past which every identity's is forgotten
/// at once rather than the map growing with every key ever changed.
const GENERATIONS: usize = 1 << 16;

/// So many identities [`Core::reconcile_due`] judges a tick beside those
/// the tick names: each that no pass recorded costs a pass, and one whose
/// passes keep failing would otherwise cost one every tick however many
/// there are.
const UNRECORDED_PER_TICK: usize = 256;

/// What [`Core::judge_floors`] reconciled: each identity whose stored
/// friendships and offers were all judged at its epochs, with the
/// generation of each key of its chain then, and a generation for each
/// key, which every change that can leave a row under it no longer held
/// without moving an epoch bumps, so a pass that read the key before the
/// change records nothing and one recorded before it is passed over no
/// more.
#[derive(Default)]
pub(crate) struct Reconciled {
    at: HashMap<[u8; 32], (EpochKey, Generations)>,
    generation: HashMap<[u8; 32], u64>,
    /// Bumped where every identity's is forgotten at once.
    cleared: u64,
    /// Where [`Core::reconcile_due`]'s last tick stopped.
    next: [u8; 32],
}

/// The keys of a chain, each with its generation.
type Generations = Vec<([u8; 32], u64)>;

impl Reconciled {
    fn of(&self, keys: &[[u8; 32]]) -> Generations {
        let generation = |k| self.generation.get(k).copied().unwrap_or(0);
        keys.iter().map(|k| (*k, generation(k))).collect()
    }

    /// Whether `fp` was recorded at `key`, nothing under its chain changed
    /// since.
    fn holds(&self, fp: &[u8; 32], key: &EpochKey) -> bool {
        self.at.get(fp).is_some_and(|(at, _)| at == key) && self.current(fp)
    }

    /// Whether `fp` was recorded, nothing under its chain changed since.
    fn current(&self, fp: &[u8; 32]) -> bool {
        self.at.get(fp).is_some_and(|(_, gens)| {
            gens.iter()
                .all(|(k, g)| self.generation.get(k).copied().unwrap_or(0) == *g)
        })
    }

    /// Every pass whose chain holds one of `keys` is due again.
    fn bump(&mut self, keys: impl IntoIterator<Item = [u8; 32]>) {
        for k in keys {
            *self.generation.entry(k).or_default() += 1;
        }
        if self.generation.len() > GENERATIONS {
            self.forget();
        }
    }

    fn forget(&mut self) {
        self.at.clear();
        self.generation.clear();
        self.cleared += 1;
    }
}

/// The record cache as the core holds it: a device epoch kept bumps its
/// identity, so a tick that passes over identities recorded and not named
/// finds it due whichever caller kept it.
pub(crate) struct Watched {
    pub(crate) inner: Arc<dyn RecordCache>,
    pub(crate) reconciled: Arc<std::sync::Mutex<Reconciled>>,
}

impl RecordCache for Watched {
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        self.inner.put(identity, list)
    }
    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        self.inner.lists(identity)
    }
    fn hold_superseded(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        self.inner.hold_superseded(identity, list)
    }
    fn superseded(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        self.inner.superseded(identity)
    }
    fn release_superseded(&self, identity: &[u8; 32]) -> Result<(), StoreError> {
        self.inner.release_superseded(identity)
    }
    fn first_seen(&self, identity: &[u8; 32], now: u64) -> Result<u64, StoreError> {
        self.inner.first_seen(identity, now)
    }
    // Bumped after the write, so a pass that read before it records
    // nothing and one recorded before it is due.
    fn keep_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let kept = self.inner.keep_epoch(identity, kept);
        self.reconciled.lock().unwrap().bump([*identity]);
        kept
    }
    fn replace_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let kept = self.inner.replace_epoch(identity, kept);
        self.reconciled.lock().unwrap().bump([*identity]);
        kept
    }
    fn epochs(&self, identity: &[u8; 32]) -> Result<Vec<KeptEpoch>, StoreError> {
        self.inner.epochs(identity)
    }
    fn identities_with_epochs(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        self.inner.identities_with_epochs()
    }
}

/// What a friendship comes to against the floors (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judged {
    /// No half below its floor, or each one reset after it was taken.
    Stands,
    /// A half below its floor, reset at or before it was taken.
    Reset,
    /// A half below its floor whose reset time no record kept here shows:
    /// refused when presented, since nothing shows it held, and kept
    /// when judged again, since nothing shows it is not.
    Unknown,
}

/// An identity's epochs, and the rows they were read from where the read
/// succeeded.
type Read = (Option<EpochKey>, Epochs);

/// The device epochs one act reads, each identity's read once.
struct Floors<'a> {
    core: &'a Core,
    read: RefCell<HashMap<[u8; 32], Read>>,
    /// Epochs verified by an earlier read, taken again where the rows
    /// read the same.
    known: Option<&'a HashMap<[u8; 32], Read>>,
    failed: RefCell<Option<StoreError>>,
}

impl<'a> Floors<'a> {
    fn new(core: &'a Core) -> Self {
        Floors {
            core,
            read: RefCell::default(),
            known: None,
            failed: RefCell::default(),
        }
    }

    /// A fresh read, verifying again only the epochs whose rows have
    /// changed since an earlier read, `known`.
    fn after(core: &'a Core, known: &'a HashMap<[u8; 32], Read>) -> Self {
        Floors {
            known: Some(known),
            ..Floors::new(core)
        }
    }

    /// `fp`'s epochs: its records kept by fingerprint, as far as they
    /// verify, and the floor the lists installed publish, whichever is
    /// higher; on a store's failure, the floor installed alone.
    fn of(&self, fp: &[u8; 32]) -> Epochs {
        if let Some((_, e)) = self.read.borrow().get(fp) {
            return e.clone();
        }
        let (installed, rows) = self.core.epoch_rows(fp);
        let (key, e) = match rows {
            Ok(rows) => {
                let key = EpochKey::of(installed, &rows);
                let e = match self.known.and_then(|k| k.get(fp)) {
                    Some((Some(k), e)) if *k == key => e.clone(),
                    _ => Epochs::of(fp, installed, &rows),
                };
                (Some(key), e)
            }
            Err(err) => {
                *self.failed.borrow_mut() = Some(err);
                let floor = installed.unwrap_or(0);
                (
                    None,
                    Epochs {
                        floor,
                        times: Vec::new(),
                    },
                )
            }
        };
        self.read.borrow_mut().insert(*fp, (key, e.clone()));
        e
    }

    /// The floor held for an identity key, as hl-identity's checks take
    /// it.
    fn floor(&self, key: &PublicKey) -> u64 {
        self.of(&Fingerprint::of(key).0).floor
    }

    /// Whether the friendship `hash`, `bytes`, is held (§6): each half
    /// below its floor reset after this server first took the friendship,
    /// the earliest taking of a presentation in `stored` of these bytes, or
    /// `now` for one not stored yet. What every grant and every judging of what is
    /// stored asks. One stored that no longer checks is not held.
    fn held(&self, hash: &[u8; 32], bytes: &[u8], stored: &[Presentation], now: u64) -> Judged {
        let f = Friendship::check(bytes, STORED, &[], zero_floor);
        self.judged(hash, bytes, f.as_ref(), stored, now)
    }

    /// [`Self::held`], for a friendship already checked.
    fn judged(
        &self,
        hash: &[u8; 32],
        bytes: &[u8],
        f: Result<&Friendship, &Refused>,
        stored: &[Presentation],
        now: u64,
    ) -> Judged {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                let hash: String = hash.iter().map(|b| format!("{b:02x}")).collect();
                error!("relationships: the friendship {hash} held here does not check: {e}");
                return Judged::Reset;
            }
        };
        let taken = taken_of(stored, bytes).unwrap_or(now);
        let mut out = Judged::Stands;
        for (from, cert) in [
            (&f.offer.from, &f.offer.cert),
            (&f.acceptance.from, &f.acceptance.cert),
        ] {
            let epoch = DeviceCert::parse(cert).map_or(0, |c| c.epoch);
            match self.of(&Fingerprint::of(from).0).reset_at(epoch) {
                Some(Some(at)) if taken >= at => return Judged::Reset,
                Some(None) => out = Judged::Unknown,
                _ => {}
            }
        }
        out
    }

    /// Whether `o` was signed by a certificate below its signer's floor.
    fn below(&self, o: &Offer) -> bool {
        DeviceCert::parse(&o.cert).is_ok_and(|c| c.check_floor(self.floor(&o.from)).is_err())
    }

    /// Whether a withdrawal held here, by its object, still stands: its
    /// certificate not below its signer's floor now, whenever it was
    /// taken. A server's own, with none, always does. Read from the
    /// certificate rather than `Held::stands`, since a `Held` is made
    /// again only by a pair check a rotation applied since can refuse.
    fn stands(&self, withdrawal: Option<&[u8]>) -> bool {
        let Some(bytes) = withdrawal else {
            return true;
        };
        Withdrawal::parse(bytes, STORED, zero_floor).is_ok_and(|k| {
            let w = k.withdrawal();
            DeviceCert::parse(&w.cert).is_ok_and(|c| c.check_floor(self.floor(&w.from)).is_ok())
        })
    }

    /// The floor the records kept here show for an identity, which a
    /// withdrawal held here is dropped below, since it will never stand
    /// again (§6). Never a floor installed alone, which can fall: a
    /// withdrawal dropped cannot come back.
    fn kept(&self, fp: &[u8; 32]) -> u64 {
        self.of(fp).kept()
    }

    /// A withdrawal held here's signer and its certificate.
    fn signed_by(&self, withdrawal: &[u8]) -> Option<([u8; 32], DeviceCert)> {
        let k = Withdrawal::parse(withdrawal, STORED, zero_floor).ok()?;
        let w = k.withdrawal();
        let cert = DeviceCert::parse(&w.cert).ok()?;
        Some((Fingerprint::of(&w.from).0, cert))
    }

    /// A read of the epochs that failed, for an act that must not go on
    /// without them.
    fn failed(&self) -> Result<(), StoreError> {
        self.failed.borrow_mut().take().map_or(Ok(()), Err)
    }
}

/// When this server first took the friendship `bytes`: the earliest
/// taking of the presentations among `held` that stored those bytes (§6),
/// so that a copy of its hash that does not check dates nothing.
fn taken_of(held: &[Presentation], bytes: &[u8]) -> Option<u64> {
    held.iter()
        .filter(|p| p.friendship.as_deref() == Some(bytes))
        .map(|p| secs(p.taken))
        .min()
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

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

/// A pair, and those of its parties whose presentations go.
type Going = ([u8; 32], [u8; 32], Vec<[u8; 32]>);

/// What applying a withdrawal left of the pair's friendship.
pub(super) enum Applied {
    /// Ended, and told.
    Ended,
    /// Active, each party's presentation standing, under the mailboxes
    /// its rows keep.
    Standing([Mailbox; 2]),
    /// Neither: there was none, or it is this server's alone and made
    /// after the cutoff.
    Untouched,
}

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
    p.as_ref().is_some_and(Presentation::evidence)
}

fn logged(what: &str, r: Result<(), StoreError>) {
    if let Err(e) = r {
        warn!("relationships: {what}: {e}");
    }
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
        let me = self.caller(uid, true)?;
        let now = self.clock.unix();
        let (identity, key, cert, refused) = {
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
            (tag.fingerprint, tag.device, cert, tag.cert())
        };
        let linked = self
            .directory
            .as_ref()
            .and_then(|d| d.account(&me.mailbox.login))
            .and_then(|(m, _)| m.fingerprint);
        if linked != Some(identity) || self.refuses(&refused) {
            return Err(MessagingError::NotDeviceProved);
        }
        self.staying(uid)?;
        Ok((me, Device { key, cert }))
    }

    fn epoch_rows(&self, fp: &[u8; 32]) -> (Option<u64>, Result<Vec<KeptEpoch>, StoreError>) {
        let installed = self
            .revoked
            .read()
            .unwrap()
            .published
            .floors
            .get(fp)
            .copied();
        let rows = self
            .record_cache
            .as_ref()
            .map_or(Ok(Vec::new()), |c| c.epochs(fp));
        (installed, rows)
    }

    /// `fp`'s epochs as stored, and the rows they were read from.
    fn epoch_key(&self, fp: &[u8; 32]) -> Result<(EpochKey, Vec<KeptEpoch>), StoreError> {
        let (installed, rows) = self.epoch_rows(fp);
        let rows = rows?;
        Ok((EpochKey::of(installed, &rows), rows))
    }

    /// Judge again what is stored of friendships with a half by any of
    /// `identities`, by their device epochs as held now (§6): the
    /// presentations of each friendship no longer held go, as a revoked
    /// device's do, and the offers its devices below the floor signed,
    /// which no acceptance could now make a friendship of. For when a
    /// floor is installed or rises, or a reset's earliest `time` moves
    /// earlier: an identity reconciled whole at the epochs it reads now is
    /// passed over. Store work, so called off the reactor.
    pub(crate) fn judge_floors(&self, identities: impl IntoIterator<Item = [u8; 32]>) {
        for fp in identities {
            self.reconcile_logged(fp, false);
        }
    }

    /// A sweep's tick: [`Self::judge_floors`] for the identities `listed`,
    /// whose floors it installs, and for those with epochs kept here that
    /// no pass recorded as they stand, as after a restart or a pass
    /// something else changed under, so many a tick. One recorded and not
    /// listed is passed over without reading its rows: a keep of them
    /// marks it due ([`Watched`]).
    pub(crate) fn reconcile_due(&self, listed: impl IntoIterator<Item = [u8; 32]>) {
        let (Some(_), Some(cache)) = (&self.relationships, &self.record_cache) else {
            return;
        };
        let mut due: Vec<[u8; 32]> = listed.into_iter().collect();
        match cache.identities_with_epochs() {
            Ok(mut kept) => {
                let named: std::collections::HashSet<[u8; 32]> = due.iter().copied().collect();
                let next = {
                    let r = self.reconciled.lock().unwrap();
                    kept.retain(|fp| !named.contains(fp) && !r.current(fp));
                    r.next
                };
                kept.sort_unstable();
                // On from where the last tick stopped, so that none waits
                // behind ones whose passes never record.
                let from = kept.partition_point(|fp| *fp <= next);
                kept.rotate_left(from);
                kept.truncate(UNRECORDED_PER_TICK);
                if let Some(last) = kept.last() {
                    self.reconciled.lock().unwrap().next = *last;
                }
                due.extend(kept);
            }
            Err(e) => warn!("relationships: reading the identities with device epochs: {e}"),
        }
        self.judge_floors(due);
    }

    /// [`Self::judge_floors`] for every identity with epochs kept here, as
    /// a start does, since what was recorded is not kept across one.
    /// Store work, so called off the reactor.
    pub fn reconcile_kept(&self) {
        let (Some(_), Some(cache)) = (&self.relationships, &self.record_cache) else {
            return;
        };
        match cache.identities_with_epochs() {
            Ok(kept) => self.judge_floors(kept),
            Err(e) => warn!("relationships: reading the identities with device epochs: {e}"),
        }
    }

    /// [`Self::judge_floors`] for `fp` once it has rotated, whatever its
    /// own floor: its chain now holds the rows moved to its successor,
    /// whose halves the other parties' floors judge.
    pub(crate) fn reconcile_predecessor(&self, fp: [u8; 32]) {
        self.reconcile_logged(fp, true);
    }

    fn reconcile_logged(&self, fp: [u8; 32], any_floor: bool) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        if let Err(e) = self.reconcile(store, fp, any_floor) {
            // A pass under way may have read before what this one could
            // not judge.
            let _writing = self.friend_writes();
            self.unjudge(store, [fp]);
            warn!("relationships: judging presentations by a device floor: {e}");
        }
    }

    /// [`Self::judge_floors`] for one identity, its key and each key it
    /// rotated to. What is stored is read under the hold, so a grant
    /// judged at the epochs before an install is read as committed; every
    /// object is checked outside it, so a pass costs messaging the reads
    /// alone; and each pair that may end is judged again at the epochs as
    /// they are and ended under a hold of its own. The pass is recorded
    /// only where it judged at the epochs read now and nothing has changed
    /// what it read but its own ends.
    fn reconcile(
        &self,
        store: &Arc<dyn RelationshipStore>,
        fp: [u8; 32],
        any_floor: bool,
    ) -> Result<(), StoreError> {
        // Before the read, so a keep landing after it is not recorded over.
        let alone = self.reconciled.lock().unwrap().of(&[fp]);
        let (seen, rows) = self.epoch_key(&fp)?;
        // A pass of no floor recorded says nothing of the chain's rows.
        if !any_floor && self.reconciled.lock().unwrap().holds(&fp, &seen) {
            return Ok(());
        }
        let epochs = Epochs::of(&fp, seen.installed, &rows);
        if epochs.floor == 0 && !any_floor {
            // Nothing of its own below a floor: judged again only once
            // its rows change, which bumps it.
            let mut r = self.reconciled.lock().unwrap();
            if r.of(&[fp]) == alone {
                r.at.insert(fp, (seen, alone));
            }
            return Ok(());
        }
        let wall = self.clock.wall();
        let (key, rows, keys, stamp, cleared, held, offers) = {
            let _writing = self.friend_writes();
            let (key, rows) = self.epoch_key(&fp)?;
            let successors = self.chain_from(store, fp)?;
            let keys: Vec<[u8; 32]> = std::iter::once(fp)
                .chain(successors.iter().map(|r| Fingerprint::of(&r.successor).0))
                .collect();
            let (stamp, cleared) = {
                let r = self.reconciled.lock().unwrap();
                (r.of(&keys), r.cleared)
            };
            // Every presentation of the chain's keys, each pair's once.
            let mut held: Vec<Presentation> = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for key in &keys {
                for p in store.presentations(key)? {
                    if seen.insert((p.presenter, p.other)) {
                        held.push(p);
                    }
                }
            }
            let mut offers = Vec::new();
            for key in &keys {
                for (other, o) in store.offers_from(key, wall)? {
                    offers.push((*key, other, o));
                }
            }
            (key, rows, keys, stamp, cleared, held, offers)
        };
        #[cfg(test)]
        self.reconciling.at("read");

        let floors = Floors::new(self);
        let epochs = if key == seen {
            epochs
        } else {
            Epochs::of(&fp, key.installed, &rows)
        };
        floors
            .read
            .borrow_mut()
            .insert(fp, (Some(key.clone()), epochs));
        // Each stored copy checked once.
        let mut checked: Vec<(&[u8], Result<Friendship, Refused>)> = Vec::new();
        for p in &held {
            if let Some(bytes) = p.friendship.as_deref() {
                if !checked.iter().any(|(b, _)| *b == bytes) {
                    checked.push((bytes, Friendship::check(bytes, STORED, &[], zero_floor)));
                }
            }
        }
        let judge = |floors: &Floors, p: &Presentation, stored: &[Presentation]| {
            let bytes = p.friendship.as_deref()?;
            let (_, f) = checked.iter().find(|(b, _)| *b == bytes)?;
            Some(floors.judged(&p.hash, bytes, f.as_ref(), stored, STORED))
        };
        let mut ending: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for p in &held {
            let pair = |(a, b): &([u8; 32], [u8; 32])| {
                (*a, *b) == (p.presenter, p.other) || (*a, *b) == (p.other, p.presenter)
            };
            if judge(&floors, p, &held) == Some(Judged::Reset) && !ending.iter().any(pair) {
                ending.push((p.presenter, p.other));
            }
        }
        let dropping: Vec<_> = offers
            .into_iter()
            .filter_map(|(owner, other, stored)| {
                let o = Offer::check(&stored.offer, STORED, &[], zero_floor).ok()?;
                floors.below(&o).then_some((owner, other, stored, o))
            })
            .collect();
        floors.failed()?;
        let known = floors.read.into_inner();

        let mut whole = true;
        // Offers first, so the entry each tells is the one before an end.
        for (owner, other, stored, o) in dropping {
            let _writing = self.friend_writes();
            if store
                .offer(&owner, &other, wall)?
                .is_none_or(|now| now.offer != stored.offer)
            {
                // Moved or replaced since: judged by a pass that reads it
                // where it is now.
                whole = false;
                continue;
            }
            let floors = Floors::after(self, &known);
            let below = floors.below(&o);
            floors.failed()?;
            if below {
                store.set_offer(&owner, &other, None)?;
                if let (Some(me), Some(them)) = (self.mailbox_of(&owner), self.mailbox_of(&other)) {
                    self.tell_entry(&them, &me);
                }
            }
        }

        let mut own = vec![0; keys.len()];
        for (a, b) in ending {
            let _writing = self.friend_writes();
            let before = self.reconciled.lock().unwrap().of(&keys);
            let pair = [store.presentation(&a, &b)?, store.presentation(&b, &a)?];
            // Moved or changed since: judged by a pass that reads it where
            // it is now.
            let read = |q: &[u8; 32], r: &[u8; 32]| {
                held.iter().find(|p| (&p.presenter, &p.other) == (q, r))
            };
            if pair[0].as_ref() != read(&a, &b) || pair[1].as_ref() != read(&b, &a) {
                whole = false;
            }
            let floors = Floors::after(self, &known);
            let mut gone = Vec::new();
            for p in pair.iter().flatten() {
                let Some(bytes) = p.friendship.as_deref() else {
                    continue;
                };
                let Some((_, f)) = checked.iter().find(|(b, _)| *b == bytes) else {
                    continue;
                };
                // Its copies under every key of both chains date it.
                let copies = match f {
                    Ok(f) => self.copies(store, f, bytes)?,
                    Err(_) => Vec::new(),
                };
                if floors.judged(&p.hash, bytes, f.as_ref(), &copies, STORED) == Judged::Reset {
                    gone.push(p);
                }
            }
            floors.failed()?;
            self.drop_pairs(store, gone)?;
            // Under the hold every bump is this pass's own, unless the
            // generations were forgotten meanwhile.
            let r = self.reconciled.lock().unwrap();
            if r.cleared != cleared {
                whole = false;
                continue;
            }
            for (own, (b, a)) in own.iter_mut().zip(before.iter().zip(&r.of(&keys))) {
                *own += a.1 - b.1;
            }
        }
        #[cfg(test)]
        self.reconciling.at("ended");
        let _writing = self.friend_writes();
        let (now, _) = self.epoch_key(&fp)?;
        let mut reconciled = self.reconciled.lock().unwrap();
        let gens = reconciled.of(&keys);
        let moved = gens.iter().zip(&stamp).zip(&own);
        let ours = moved
            .into_iter()
            .all(|((g, s), own)| g.1 == s.1.wrapping_add(*own));
        if whole && now == key && reconciled.cleared == cleared && ours {
            reconciled.at.insert(fp, (key, gens));
        } else if !reconciled.holds(&fp, &now) {
            // Due again at the next tick, which passes over a recording.
            reconciled.at.remove(&fp);
        }
        Ok(())
    }

    /// Forget every pass recorded, as a restart does.
    pub(crate) fn unjudge_all(&self) {
        self.reconciled.lock().unwrap().forget();
    }

    /// Forget what was reconciled of the friendships under `fps`, and
    /// under each key they rotated to, whose copies they date, in every
    /// identity's pass whose chain holds one of them: for a change that
    /// can leave a row no longer held without moving an epoch, such as an
    /// evidence drop or replacement. Under the hold the change was made
    /// in. Where a chain cannot be read, every identity's is forgotten.
    pub(crate) fn unjudge(
        &self,
        store: &Arc<dyn RelationshipStore>,
        fps: impl IntoIterator<Item = [u8; 32]>,
    ) {
        let mut keys = Vec::new();
        for fp in fps {
            keys.push(fp);
            match self.chain_from(store, fp) {
                Ok(chain) => keys.extend(chain.iter().map(|r| Fingerprint::of(&r.successor).0)),
                Err(e) => {
                    warn!("relationships: reading a rotation to forget its judging: {e}");
                    self.unjudge_all();
                    return;
                }
            }
        }
        self.reconciled.lock().unwrap().bump(keys);
    }

    /// The account linked to `fp` that takes part, if there is one.
    fn mailbox_of(&self, fp: &[u8; 32]) -> Option<Mailbox> {
        let (m, access) = self.directory.as_ref()?.account_by_key(fp)?;
        takes_part(&m.login, access).then_some(m)
    }

    /// The rotations this server applied from `fp` on, in chain order,
    /// each verified again as it is read.
    fn chain_from(
        &self,
        store: &Arc<dyn RelationshipStore>,
        fp: [u8; 32],
    ) -> Result<Vec<Rotation>, StoreError> {
        let mut out = Vec::new();
        let mut key = fp;
        for _ in 0..MAX_CHAIN {
            let Some((to, record)) = store.rotation_from(&key)? else {
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
        Ok(out)
    }

    fn rotations_for(
        &self,
        store: &Arc<dyn RelationshipStore>,
        pair: &Pair,
    ) -> Result<Vec<Rotation>, MessagingError> {
        let (lo, hi) = pair.fingerprints();
        let mut out = self.chain_from(store, lo.0).map_err(store_failed)?;
        out.extend(self.chain_from(store, hi.0).map_err(store_failed)?);
        Ok(out)
    }

    /// Drop the withdrawals counted toward the owners of `keeping` that
    /// will never stand again where they would cost what is kept next: a
    /// signed one of a signed keep's key, whose later cutoff would refuse
    /// it, and, where the keep passes its owner's cap, any, so that the
    /// cap takes them before one that stands. Dropping them changes no
    /// answer, so the keep need not be the same step.
    fn make_room(
        &self,
        store: &Arc<dyn RelationshipStore>,
        floors: &Floors,
        keeping: &[HeldWithdrawal],
    ) -> Result<(), StoreError> {
        let same = |a: &HeldWithdrawal, b: &HeldWithdrawal| {
            (a.owner, a.pair, a.party, a.withdrawal.is_none())
                == (b.owner, b.pair, b.party, b.withdrawal.is_none())
        };
        let mut owners: Vec<[u8; 32]> = keeping.iter().map(|w| w.owner).collect();
        owners.sort_unstable();
        owners.dedup();
        for owner in owners {
            let held = store.withdrawals_by(&owner)?;
            let new = keeping
                .iter()
                .filter(|k| k.owner == owner && !held.iter().any(|h| same(h, k)))
                .count();
            // A withdrawal is kept only at or above its signer's floor, its
            // owner's own key, so none falls below the kept floors an
            // owner's were last judged whole at until one of them rises.
            let judged = self.withdrawals_judged.lock().unwrap().get(&owner).cloned();
            let whole = judged.is_some_and(|j| j.iter().all(|(fp, kept)| floors.kept(fp) == *kept));
            if held.len() + new > self.messaging_policy.max_roster && !whole {
                #[cfg(test)]
                self.withdrawal_scans
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut signers = self.drop_dead(store, floors, &held)?;
                signers.push((owner, floors.kept(&owner)));
                floors.failed()?;
                self.withdrawals_judged
                    .lock()
                    .unwrap()
                    .insert(owner, signers);
            } else {
                let shadowed = |h: &&HeldWithdrawal| {
                    keeping.iter().any(|k| k.withdrawal.is_some() && same(h, k))
                };
                self.drop_dead(store, floors, held.iter().filter(shadowed))?;
            }
        }
        floors.failed()
    }

    /// Drop those of `held` signed below their signer's kept floor,
    /// answering each signer's kept floor as read.
    fn drop_dead<'w>(
        &self,
        store: &Arc<dyn RelationshipStore>,
        floors: &Floors,
        held: impl IntoIterator<Item = &'w HeldWithdrawal>,
    ) -> Result<KeptFloors, StoreError> {
        let mut signers = KeptFloors::new();
        for w in held {
            let Some(bytes) = w.withdrawal.as_deref() else {
                continue;
            };
            let Some((signer, cert)) = floors.signed_by(bytes) else {
                continue;
            };
            let kept = floors.kept(&signer);
            if !signers.iter().any(|(fp, _)| *fp == signer) {
                signers.push((signer, kept));
            }
            if cert.check_floor(kept).is_err() {
                store.drop_withdrawal(&w.owner, &w.pair, &w.party, bytes)?;
            }
        }
        Ok(signers)
    }

    /// Drop every withdrawal counted toward `owners` that will never
    /// stand again, and forget their judging: before a rotation's merge,
    /// which keeps the later cutoff of two for one key without asking
    /// which stands, and moves in withdrawals other keys signed.
    pub(crate) fn drop_dead_withdrawals(&self, owners: &[[u8; 32]]) -> Result<(), StoreError> {
        let Some(store) = self.relationships.as_ref() else {
            return Ok(());
        };
        let floors = Floors::new(self);
        for owner in owners {
            self.withdrawals_judged.lock().unwrap().remove(owner);
            self.drop_dead(store, &floors, &store.withdrawals_by(owner)?)?;
        }
        floors.failed()
    }

    /// End what `end` names between `a` and `b`, as one step, room made
    /// first for the withdrawals it keeps.
    pub(super) fn end_friendship(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &Mailbox,
        b: &Mailbox,
        end: &Ending,
    ) -> Result<Ended, StoreError> {
        self.make_room(store, &Floors::new(self), &end.withdrawals)?;
        let ended = store.end_friendship(a, b, end)?;
        self.unjudge(store, [a.fingerprint, b.fingerprint].into_iter().flatten());
        Ok(ended)
    }

    /// What the withdrawals held for `pair` that stand at the current
    /// floors end, each with its object to hand on: one kept unchecked is
    /// checked against the pair now, kept checked if it passes and
    /// dropped if not (§4.3, §6).
    fn cutoffs(
        &self,
        store: &Arc<dyn RelationshipStore>,
        pair: &Pair,
        rotations: &[Rotation],
        floors: &Floors,
    ) -> Result<Vec<HeldCutoff>, MessagingError> {
        let mut out = Vec::new();
        for w in store.withdrawals(&pair.hash()).map_err(store_failed)? {
            if !w.checked {
                let passes = w
                    .withdrawal
                    .as_deref()
                    .and_then(|b| Withdrawal::parse(b, STORED, zero_floor).ok())
                    .is_some_and(|k| k.check_pair(pair, rotations).is_ok());
                if !passes {
                    if let Some(bytes) = &w.withdrawal {
                        store
                            .drop_withdrawal(&w.owner, &w.pair, &w.party, bytes)
                            .map_err(store_failed)?;
                    }
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
            // One a device now below its floor signed ends nothing.
            if !floors.stands(w.withdrawal.as_deref()) {
                continue;
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
        let floors = Floors::new(self);
        let checked = Offer::check(&bytes, now, &[], |k| floors.floor(k));
        floors.failed().map_err(store_failed)?;
        let offer = checked.map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        own(device, me, &offer.from, &offer.cert)?;
        fresh(offer.time, now)?;
        if them.fingerprint != Some(offer.to.0) {
            return Err(MessagingError::AccountNotFound);
        }
        let pair = offer.pair();
        let rotations = self.rotations_for(store, &pair)?;
        let cuts = self.cutoffs(store, &pair, &rotations, &floors)?;
        floors.failed().map_err(store_failed)?;
        if cuts.iter().any(|(c, _)| offer.cut_by(c)) {
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
        // One reading of the clock, so the evidence is stamped with the time
        // it was judged at.
        let at = self.clock.wall();
        let now = secs(at);
        let floors = Floors::new(self);
        let f = Friendship::check(&bytes, now, &[], zero_floor).map_err(|r| match r.error {
            IdError::ClockSkew => MessagingError::Stale,
            _ => MessagingError::BadSignature,
        })?;
        if f.acceptance.offer != <[u8; 32]>::from(Sha256::digest(&offered.offer)) {
            return Err(MessagingError::BadSignature);
        }
        own(device, me, &f.acceptance.from, &f.acceptance.cert)?;
        fresh(f.acceptance.time, now)?;
        let pair = f.pair();
        let rotations = self.rotations_for(store, &pair)?;
        let cuts = self.cutoffs(store, &pair, &rotations, &floors)?;
        floors.failed().map_err(store_failed)?;
        if cuts.iter().any(|(c, _)| f.cut_by(c)) {
            return Err(MessagingError::Withdrawn);
        }
        let (Some(mine), Some(theirs)) = (me.fingerprint, them.fingerprint) else {
            return Err(MessagingError::BadSignature);
        };
        let offerer = DeviceCert::parse(&f.offer.cert)
            .map(|c| Fingerprint::of(&c.device).0)
            .map_err(|_| MessagingError::BadSignature)?;
        let rows = [(mine, theirs, device.key), (theirs, mine, offerer)];
        let mut olds = Vec::new();
        for (presenter, other, _) in rows {
            olds.push(
                store
                    .presentation(&presenter, &other)
                    .map_err(store_failed)?,
            );
        }
        // Judged before anything is recorded, so that one not held leaves
        // nothing stored.
        let stored: Vec<Presentation> = olds.iter().flatten().cloned().collect();
        let judged = floors.held(&f.hash, &bytes, &stored, now);
        floors.failed().map_err(store_failed)?;
        if judged != Judged::Stands {
            return Err(MessagingError::BadSignature);
        }
        for ((presenter, other, dev), old) in rows.into_iter().zip(olds) {
            let edge = old.as_ref().and_then(|p| p.edge);
            let taken = old
                .filter(|p| p.friendship.as_deref() == Some(&bytes[..]))
                .map_or(at, |p| p.taken);
            let replaced = store
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
                    taken,
                })
                .map_err(store_failed)?;
            self.replaced(store, replaced, Some(&bytes));
        }
        let friends = store
            .relationship(me, them, at)
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some());
        if friends {
            self.drop_offers(store, me, them);
            self.tell_entry(me, them);
            self.tell_entry(them, me);
            Ok(())
        } else {
            self.activate(store, me, them, &floors, at)
        }
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
    /// Answers its bytes, for the `Removed` it is told with, and what it
    /// left of the friendship. With `block`, `me` blocks `them` in the
    /// same step, as Block User (806) carrying it does.
    pub(super) fn take_withdrawal(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        them: &Mailbox,
        bytes: Vec<u8>,
        block: bool,
    ) -> Result<(Vec<u8>, Applied), MessagingError> {
        let now = self.clock.unix();
        let floors = Floors::new(self);
        let parsed = Withdrawal::parse(&bytes, now, |k| floors.floor(k));
        floors.failed().map_err(store_failed)?;
        let kept = parsed.map_err(|r| match r.error {
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
        let rotations = self.rotations_for(store, &pair)?;
        let held = kept
            .check_pair(&pair, &rotations)
            .map_err(|_| MessagingError::BadSignature)?;
        let cut = held.cutoff();
        let keep = self.cutoff_held(&mine, &cut, Some(bytes.clone()));
        let party_mine = chain_end(cut.party, &rotations).map(|f| f.0) == Some(mine);
        let (party, other) = if party_mine {
            (mine, theirs)
        } else {
            (theirs, mine)
        };
        let blocking = block.then_some((me, them));
        let applied = self.apply_cutoff(store, &floors, keep, party, other, blocking)?;
        Ok((bytes, applied))
    }

    fn cutoff_held(
        &self,
        owner: &[u8; 32],
        cut: &Cutoff,
        withdrawal: Option<Vec<u8>>,
    ) -> HeldWithdrawal {
        HeldWithdrawal {
            owner: *owner,
            pair: cut.pair,
            party: cut.party.0,
            before: cut.before,
            withdrawal,
            checked: true,
            at: self.clock.wall(),
        }
    }

    /// Apply a withdrawal held here, `keep`, to what `party`, whose side
    /// it measures, and `other` hold of each other, as one step: the
    /// withdrawal kept, the presentations and offers it ends dropped, and
    /// the edge following what is left (§4.3). A friendship of this
    /// server alone ends where it was made before the cutoff (§2).
    fn apply_cutoff(
        &self,
        store: &Arc<dyn RelationshipStore>,
        floors: &Floors,
        keep: HeldWithdrawal,
        party: [u8; 32],
        other: [u8; 32],
        block: Option<(&Mailbox, &Mailbox)>,
    ) -> Result<Applied, MessagingError> {
        let cut = Cutoff {
            pair: keep.pair,
            party: Fingerprint(keep.party),
            before: keep.before,
        };
        let wall = self.clock.wall();
        let mut end = Ending {
            cap: self.messaging_policy.max_roster,
            ..Ending::default()
        };
        let mut had = 0;
        for (p, q) in [(party, other), (other, party)] {
            if let Some(bytes) = store
                .presentation(&p, &q)
                .map_err(store_failed)?
                .filter(Presentation::evidence)
                .and_then(|pres| pres.friendship)
            {
                had += 1;
                if Friendship::check(&bytes, STORED, &[], zero_floor).is_ok_and(|f| f.cut_by(&cut))
                {
                    end.presentations.push(p);
                }
            }
            if let Some(o) = store.offer(&p, &q, wall).map_err(store_failed)? {
                if Offer::check(&o.offer, STORED, &[], zero_floor).is_ok_and(|o| o.cut_by(&cut)) {
                    end.offers.push(p);
                }
            }
        }
        let (x, y) = (
            Mailbox::identified("", party),
            Mailbox::identified("", other),
        );
        let row = store.relationship(&x, &y, wall).map_err(store_failed)?;
        if let Some(id) = row.as_ref().and_then(|r| r.friendship) {
            end.friendship = if had == 2 {
                !end.presentations.is_empty()
            } else {
                let made = store.made_at(id).map_err(store_failed)?;
                made.is_some_and(|t| t < unix_time(cut.before))
            };
            if had == end.presentations.len() {
                end.hold = Some(wall + self.messaging_policy.request_retention);
            }
        }
        let withdraw = keep.withdrawal.clone();
        end.withdrawals.push(keep);
        // A block takes what a removal here takes besides, and is written
        // with it: what the withdrawal ends never stands without it.
        let mut shown = false;
        if let Some((blocker, blocked)) = block {
            let here = self
                .end_here(store, blocker, blocked, &end.presentations)
                .map_err(store_failed)?;
            for p in here.presentations {
                if !end.presentations.contains(&p) {
                    end.presentations.push(p);
                }
            }
            for o in here.offers {
                if !end.offers.contains(&o) {
                    end.offers.push(o);
                }
            }
            end.withdrawals.extend(here.withdrawals);
            end.block = Some(wall);
            end.friendship = true;
            shown = store
                .relationship(blocker, blocked, wall)
                .map_err(store_failed)?
                .and_then(|r| r.pending_out)
                .is_some_and(|p| p.delivered);
        }
        let (a, b) = block.unwrap_or((&x, &y));
        self.make_room(store, floors, &end.withdrawals)
            .map_err(store_failed)?;
        let ended = store.end_friendship(a, b, &end).map_err(store_failed)?;
        self.unjudge(store, [party, other]);
        if let Some(e) = ended.ended {
            self.edge_ended(&e, withdraw.as_deref());
            return Ok(Applied::Ended);
        }
        if shown {
            self.tell_entry(b, a);
        }
        Ok(match row.filter(|r| r.friendship.is_some()) {
            Some(r) if had == 2 => Applied::Standing([r.owner, r.other]),
            _ => Applied::Untouched,
        })
    }

    /// What `me` removing or blocking `them` without a withdrawal of its
    /// own ends of what they presented: the presentations either way and
    /// the offers, and a withdrawal of the server's own for `me`, dated
    /// now, that applies here alone, so that `me`'s other devices do not
    /// present the friendship straight back (§4.3), but for the parties
    /// whose presentations a withdrawal in the same step ends, `withdrawn`.
    /// The caller adds what else it ends, and applies it as one step.
    pub(super) fn end_here(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        withdrawn: &[[u8; 32]],
    ) -> Result<Ending, StoreError> {
        let mut end = Ending {
            cap: self.messaging_policy.max_roster,
            ..Ending::default()
        };
        let (Some(mine), Some(theirs)) = (me.fingerprint, them.fingerprint) else {
            return Ok(end);
        };
        end.offers = vec![mine, theirs];
        let before = self.clock.unix();
        for (p, q) in [(mine, theirs), (theirs, mine)] {
            let Some(pres) = store.presentation(&p, &q)? else {
                continue;
            };
            end.presentations.push(p);
            if withdrawn.contains(&p) {
                continue;
            }
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
            // Needless where a signed one the remover gave, checked and
            // standing at the floors, already cuts as far; kept beside any
            // other.
            let floors = Floors::new(self);
            let signed = store.withdrawals(&pres.pair).is_ok_and(|held| {
                held.iter().any(|w| {
                    w.owner == mine
                        && w.party == named
                        && w.checked
                        && w.withdrawal.is_some()
                        && w.before >= before
                        && floors.stands(w.withdrawal.as_deref())
                })
            });
            if signed && floors.failed().is_ok() {
                continue;
            }
            end.withdrawals.push(self.cutoff_held(&mine, &cut, None));
        }
        Ok(end)
    }

    /// Drop the presentations of the pair `a`, `b` that `presenters` made,
    /// with no withdrawal, as one step, and tell the edge where that ended
    /// it: its id stays on what is left, so the messages queued on it are
    /// released when it is active again (§6).
    fn drop_presented(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &[u8; 32],
        b: &[u8; 32],
        presenters: &[[u8; 32]],
    ) -> Result<Vec<Presentation>, StoreError> {
        let dropped = store.drop_presentations(a, b, presenters)?;
        if !dropped.gone.is_empty() {
            self.unjudge(store, [*a, *b]);
        }
        if let Some(e) = &dropped.ended {
            self.edge_ended(e, None);
        }
        Ok(dropped.gone)
    }

    /// A presentation `present` answered as replaced, where its evidence
    /// was other than `now`'s: what it held is judged again.
    fn replaced(
        &self,
        store: &Arc<dyn RelationshipStore>,
        old: Option<Presentation>,
        now: Option<&[u8]>,
    ) {
        if let Some(old) = old.filter(|o| o.friendship.is_some() && o.friendship.as_deref() != now)
        {
            self.unjudge(store, [old.presenter, old.other]);
        }
    }

    /// Drop `gone`, presentations made with no withdrawal, as one step
    /// for each pair, so that one pair's both are never half dropped.
    fn drop_pairs<'p>(
        &self,
        store: &Arc<dyn RelationshipStore>,
        gone: impl IntoIterator<Item = &'p Presentation>,
    ) -> Result<(), StoreError> {
        let mut pairs: Vec<Going> = Vec::new();
        for p in gone {
            let pair = pairs.iter_mut().find(|(a, b, _)| {
                (*a, *b) == (p.presenter, p.other) || (*a, *b) == (p.other, p.presenter)
            });
            match pair {
                Some((_, _, presenters)) => presenters.push(p.presenter),
                None => pairs.push((p.presenter, p.other, vec![p.presenter])),
            }
        }
        for (a, b, presenters) in pairs {
            self.drop_presented(store, &a, &b, &presenters)?;
        }
        Ok(())
    }

    /// An edge's ending, told once it is committed: the roster, then both
    /// parties' entries, by the mailboxes their rows keep, so a party the
    /// directory no longer names is told too.
    pub(super) fn edge_ended(&self, e: &EndedEdge, withdraw: Option<&[u8]>) {
        let [a, b] = &e.parties;
        self.roster.lock().unwrap().friends_changed(a, b, false);
        self.tell_entry_with(a, b, withdraw);
        self.tell_entry_with(b, a, withdraw);
    }

    /// What a rotation's merge dropped, told and judged as any drop is:
    /// each edge it ended, then the other party's presentation each
    /// dropped one leaves held by its own taking alone. Under the hold the
    /// merge was made in, once the roster has followed it.
    pub(crate) fn merge_dropped(
        &self,
        _writing: &super::FriendWrites<'_>,
        store: &Arc<dyn RelationshipStore>,
        rekeyed: &crate::relationships::Rekeyed,
    ) {
        for e in &rekeyed.ended {
            self.edge_ended(e, None);
        }
        for gone in &rekeyed.dropped {
            logged("judging an orphan", self.orphan_judged(store, gone));
        }
    }

    /// The other party's presentation of the friendship `gone` was of,
    /// dropped where only `gone` held it, taken itself after a half's
    /// reset (§6). A withdrawal or a removal ends the edge, and whatever
    /// would make it active again is judged at its own presentation.
    fn orphan_judged(
        &self,
        store: &Arc<dyn RelationshipStore>,
        gone: &Presentation,
    ) -> Result<(), StoreError> {
        if !gone.evidence() {
            return Ok(());
        }
        match store
            .presentation(&gone.other, &gone.presenter)?
            .filter(|p| p.hash == gone.hash)
        {
            Some(theirs) => self.judged_alone(store, &theirs),
            None => Ok(()),
        }
    }

    /// The presentations of `f`, `bytes`, under any key of its parties'
    /// chains: what dates its taking here, read pair by pair rather than
    /// every row naming a key.
    fn copies(
        &self,
        store: &Arc<dyn RelationshipStore>,
        f: &Friendship,
        bytes: &[u8],
    ) -> Result<Vec<Presentation>, StoreError> {
        let chain = |fp: Fingerprint| -> Result<Vec<[u8; 32]>, StoreError> {
            let successors = self.chain_from(store, fp.0)?;
            let keys = successors.iter().map(|r| Fingerprint::of(&r.successor).0);
            Ok(std::iter::once(fp.0).chain(keys).collect())
        };
        let (lo, hi) = f.pair().fingerprints();
        let (xs, ys) = (chain(lo)?, chain(hi)?);
        let mut out = Vec::new();
        for x in &xs {
            for y in &ys {
                for (p, q) in [(x, y), (y, x)] {
                    out.extend(
                        store
                            .presentation(p, q)?
                            .filter(|c| c.friendship.as_deref() == Some(bytes)),
                    );
                }
            }
        }
        Ok(out)
    }

    /// `p`, held by its own taking and those of its bytes under the other
    /// keys of its parties' chains alone, dropped where that came after a
    /// half's reset.
    fn judged_alone(
        &self,
        store: &Arc<dyn RelationshipStore>,
        p: &Presentation,
    ) -> Result<(), StoreError> {
        let Some(bytes) = p.friendship.as_deref() else {
            return Ok(());
        };
        let f = Friendship::check(bytes, STORED, &[], zero_floor);
        let copies = match &f {
            Ok(f) => self.copies(store, f, bytes)?,
            Err(_) => Vec::new(),
        };
        let floors = Floors::new(self);
        let judged = floors.judged(&p.hash, bytes, f.as_ref(), &copies, STORED);
        floors.failed()?;
        if judged == Judged::Reset {
            self.drop_presented(store, &p.presenter, &p.other, &[p.presenter])?;
        }
        Ok(())
    }

    /// Judge what `a` and `b` have presented of each other, for a
    /// friendship by request or a local one made portable (§6): the
    /// presenters of what is not held, to drop first, and the id a
    /// presentation left keeps, to make the friendship under. One no
    /// record shows held goes too: beside the friendship it would count as
    /// evidence never shown held, and judging it again keeps it.
    pub(super) fn unheld_between(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &Mailbox,
        b: &Mailbox,
    ) -> Result<(Vec<[u8; 32]>, Option<RelationId>), StoreError> {
        let (Some(x), Some(y)) = (a.fingerprint, b.fingerprint) else {
            return Ok((Vec::new(), None));
        };
        let mut stored = Vec::new();
        for (p, q) in [(x, y), (y, x)] {
            stored.extend(store.presentation(&p, &q)?);
        }
        let floors = Floors::new(self);
        let now = self.clock.unix();
        let gone: Vec<[u8; 32]> = stored
            .iter()
            .filter(|p| {
                p.friendship
                    .as_deref()
                    .is_some_and(|b| floors.held(&p.hash, b, &stored, now) != Judged::Stands)
            })
            .map(|p| p.presenter)
            .collect();
        floors.failed()?;
        let kept = stored
            .iter()
            .filter(|p| !gone.contains(&p.presenter))
            .find_map(|p| p.edge);
        Ok((gone, kept))
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
            let _writing = self.friend_act(uid)?;
            // A friend the directory no longer names is removed as one
            // it does, so its other devices do not present it back.
            let them = Mailbox::identified("", *fingerprint);
            let wall = self.clock.wall();
            let friends = store
                .relationship(&me.mailbox, &them, wall)
                .map_err(store_failed)?
                .is_some_and(|r| r.friendship.is_some());
            if friends {
                let mut end = self
                    .end_here(store, &me.mailbox, &them, &[])
                    .map_err(store_failed)?;
                end.friendship = true;
                end.hold = Some(wall + self.messaging_policy.request_retention);
                let ended = self
                    .end_friendship(store, &me.mailbox, &them, &end)
                    .map_err(store_failed)?;
                if let Some(e) = ended.ended {
                    self.edge_ended(&e, None);
                }
                return Ok(());
            }
            let gone = self
                .drop_presented(store, &mine, fingerprint, &[mine])
                .map_err(store_failed)?;
            for gone in &gone {
                logged("judging an orphan", self.orphan_judged(store, gone));
            }
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
        let _writing = self.friend_act(uid)?;
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

    /// The withdrawal a Block User (806) carries, taken with the block
    /// in one step, and handed on as a removal (§4.3), so the friend's
    /// other servers hear of a removal and never of a block. Where it
    /// names no friendship here, the block is the caller's to make next,
    /// as it makes one again after this.
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
        let floors = Floors::new(self);
        let parsed = Withdrawal::parse(&withdraw, now, |k| floors.floor(k));
        floors.failed().map_err(store_failed)?;
        let kept = parsed.map_err(|r| match r.error {
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
        self.take_withdrawal(store, &me.mailbox, &device, &them, withdraw, true)
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
            .filter_map(|b| Withdrawal::parse(b, now, zero_floor).ok())
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
        let floors = Floors::new(self);
        let taken = withdrawals
            .into_iter()
            .map(|b| self.present_withdrawal(store, &me.mailbox, &device, &floors, b))
            .collect::<Result<_, _>>()?;
        let presented = friendships
            .into_iter()
            .map(|b| self.present_friendship(store, &me.mailbox, mine, &device, &floors, b))
            .collect::<Result<_, _>>()?;
        Ok((taken, presented))
    }

    fn present_withdrawal(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        floors: &Floors,
        bytes: Vec<u8>,
    ) -> Result<PresentResult, MessagingError> {
        let now = self.clock.unix();
        let refused = |hash, outcome| Ok(PresentResult { hash, outcome });
        let parsed = Withdrawal::parse(&bytes, now, |k| floors.floor(k));
        floors.failed().map_err(store_failed)?;
        let kept = match parsed {
            Ok(k) => k,
            Err(r) => {
                let outcome = match r.error {
                    IdError::ClockSkew => Presented::Stale,
                    _ => Presented::BadSignature,
                };
                // Named by the pair it names where that can be read.
                let pair = Withdrawal::parse(&bytes, u64::MAX, zero_floor)
                    .map_or([0; 32], |k| k.withdrawal().pair);
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
            self.make_room(store, floors, std::slice::from_ref(&cut))
                .map_err(store_failed)?;
            store
                .keep_withdrawal(&cut, self.messaging_policy.max_roster)
                .map_err(store_failed)?;
            return refused(w.pair, Presented::Ok);
        };
        let pair = Pair::new(Fingerprint(names[0]), Fingerprint(names[1]));
        let rotations = self.rotations_for(store, &pair)?;
        let Ok(held) = kept.check_pair(&pair, &rotations) else {
            return refused(w.pair, Presented::BadSignature);
        };
        let cut = held.cutoff();
        let keep = self.cutoff_held(&mine, &cut, Some(bytes));
        let (party, other) = if chain_end(cut.party, &rotations).map(|f| f.0) == Some(presenter) {
            (presenter, other)
        } else {
            (other, presenter)
        };
        // An edge that stays active is told to both again (§4.3).
        if let Applied::Standing([x, y]) =
            self.apply_cutoff(store, floors, keep, party, other, None)?
        {
            self.tell_entry(&x, &y);
            self.tell_entry(&y, &x);
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
        floors: &Floors,
        bytes: Vec<u8>,
    ) -> Result<PresentResult, MessagingError> {
        let now = self.clock.unix();
        let wall = self.clock.wall();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let answer = |outcome| Ok(PresentResult { hash, outcome });
        // Step 1: the friendship, and that it names the presenter's key or
        // one that rotated to it, whatever the floors.
        let Ok(f) = Friendship::check(&bytes, now, &[], zero_floor) else {
            return answer(Presented::BadSignature);
        };
        let pair = f.pair();
        let rotations = self.rotations_for(store, &pair)?;
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
        // The row as stored now, which a reset's drop may have taken
        // since `held` was read.
        let record = |friendship: Option<Vec<u8>>| {
            let old = store.presentation(&mine, &theirs).map_err(store_failed)?;
            let edge = old.as_ref().and_then(|p| p.edge);
            let taken = old
                .filter(|p| friendship.is_some() && p.friendship == friendship)
                .map_or(wall, |p| p.taken);
            store
                .present(&Presentation {
                    presenter: mine,
                    other: theirs,
                    names: [my_name.0, their_name.0],
                    pair: pair.hash(),
                    hash,
                    friendship: friendship.clone(),
                    device: device.key,
                    edge,
                    at: wall,
                    taken,
                })
                .map(|old| self.replaced(store, old, friendship.as_deref()))
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
        // Step 3: withdrawals, those a device below its floor signed
        // ending nothing.
        let cuts = self.cutoffs(store, &pair, &rotations, floors)?;
        floors.failed().map_err(store_failed)?;
        if let Some((_, w)) = cuts.into_iter().find(|(c, _)| f.cut_by(c)) {
            return answer(Presented::Withdrawn(w));
        }
        // Step 4: a half below its signer's floor, where this server did
        // not take the friendship, by either party, before that half was
        // reset. Until `Reset` has a code, it is answered as the classic
        // wire answers it meanwhile (§7), keeping the hash as step 2 does.
        let judged = floors.held(&hash, &bytes, &held, now);
        floors.failed().map_err(store_failed)?;
        match judged {
            Judged::Stands => {}
            Judged::Unknown => {
                keep_hash()?;
                return answer(Presented::AccountNotFound);
            }
            Judged::Reset => {
                // What is stored of it is not held either, and goes now
                // rather than at the next judging.
                self.drop_pairs(
                    store,
                    held.iter().filter(|p| p.hash == hash && p.evidence()),
                )
                .map_err(store_failed)?;
                if presented(&mine, &theirs).is_none_or(|p| p.hash == hash) {
                    record(None)?;
                }
                return answer(Presented::AccountNotFound);
            }
        }
        // Step 6, there being no hidden links for step 5. A local edge this
        // makes portable stands on held evidence alone; on any other, the
        // other party's presentation of other bytes is held by its own
        // taking alone.
        let both = [(mine, theirs), (theirs, mine)]
            .iter()
            .all(|(p, q)| presented(p, q).is_some_and(|x| x.evidence()));
        if friends.contains(&theirs) && !both {
            let (gone, _) = self
                .unheld_between(store, me, &them)
                .map_err(store_failed)?;
            if !gone.is_empty() {
                self.drop_presented(store, &mine, &theirs, &gone)
                    .map_err(store_failed)?;
            }
        }
        record(Some(bytes.clone()))?;
        if let Some(p) = store
            .presentation(&theirs, &mine)
            .map_err(store_failed)?
            .filter(|p| p.friendship.as_ref() != Some(&bytes))
        {
            self.judged_alone(store, &p).map_err(store_failed)?;
        }
        match self.activate(store, me, &them, floors, wall) {
            Ok(()) => answer(Presented::Ok),
            Err(MessagingError::RosterFull) => answer(Presented::RosterFull),
            Err(e) => Err(e),
        }
    }

    /// Make the edge between `me` and `them` active where each has
    /// presented a friendship for it (§4.3), under the id it had where a
    /// dropped presentation kept one; or tell both its entry again where
    /// it is active already. `RosterFull` where `me`'s roster has no room
    /// for it; where `them`'s has none it stays inactive, unanswered. A
    /// presentation stored here counts only where its friendship stands at
    /// the floors, as it must where presented now (§6).
    fn activate(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        floors: &Floors,
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
        let rows: Vec<Presentation> = pa.iter().chain(&pb).cloned().collect();
        let stands = rows.iter().all(|p| {
            p.friendship
                .as_deref()
                .is_some_and(|b| floors.held(&p.hash, b, &rows, STORED) == Judged::Stands)
        });
        floors.failed().map_err(store_failed)?;
        if !stands {
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
        self.befriend_as(store, me, them, now, edge, &[])?;
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
        // A new link in a chain changes which rows an act judges as the
        // identity's, so it lands between acts.
        let _writing = self.friend_writes();
        match store.keep_rotation(&from, &to, record) {
            Ok(()) => self.unjudge(store, [from, to]),
            Err(e) => warn!("relationships: keeping a rotation record: {e}"),
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
                match self.drop_presented(store, &p.presenter, &p.other, &[p.presenter]) {
                    Ok(gone) => {
                        for gone in &gone {
                            logged("judging an orphan", self.orphan_judged(store, gone));
                        }
                    }
                    Err(e) => warn!("relationships: dropping a revoked device's presentation: {e}"),
                }
            }
        }
    }

    /// An account gave up its link to `fingerprint`: what it presented
    /// under it goes, and with it each edge that was its evidence (§4.3,
    /// §4.4). A link made again starts from the presentations its clients
    /// make then.
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
            match self.drop_presented(store, &p.presenter, &p.other, &[p.presenter]) {
                Ok(gone) => {
                    for gone in &gone {
                        logged("judging an orphan", self.orphan_judged(store, gone));
                    }
                }
                Err(e) => warn!("relationships: dropping an unlinked account's presentation: {e}"),
            }
        }
    }
}
