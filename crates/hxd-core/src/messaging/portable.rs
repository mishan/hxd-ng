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
    Charge, Did, Ended, EndedEdge, Ending, FpPair, HeldWithdrawal, Left, Part, PendingOut,
    Presentation, RelationId, Relationship, RelationshipStore, Report, StoredOffer,
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

/// What one object of a presentation weighs against the classic wire's
/// friendship pacing (`Core::friendships_spend`), as the frontends weigh
/// it.
const PRESENTING: u32 = 4;

/// How long a `Reset` record outlasts the last presentation answered
/// `Reset` that kept it, while no upgrade offer waits on it (§4.3 step 4).
const RESET_KEPT: Duration = Duration::from_secs(30 * 24 * 3600);

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

/// How long a revoked device's offers wait to be swept again after a
/// sweep of them fails, doubling with each failure up to
/// [`SWEEP_BACKOFF_MAX`], so a store that keeps failing costs a try and a
/// log line that often rather than every tick.
const SWEEP_BACKOFF: u64 = 60;
const SWEEP_BACKOFF_MAX: u64 = 3600;

/// Offers owed a drop: a revoked device's, by the operator or by a
/// registrar, under the identity it signed for; a revoked identity's,
/// from or to it; or an unlinked one's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sweep {
    /// A deleted account's relationships, purged under the mailbox it
    /// held, so that whoever is given the login next inherits none.
    Purge(Mailbox),
    /// The offers a device signed: under the identity a registrar names
    /// it for, or, the operator's naming none, under whichever.
    Device {
        identity: Option<[u8; 32]>,
        device: [u8; 32],
        operator: bool,
    },
    Identity {
        identity: [u8; 32],
        operator: bool,
    },
    Unlinked([u8; 32]),
    /// The presentations an unlinked identity made.
    Unpresented([u8; 32]),
    /// What two keys hold of each other judged again, after a drop that
    /// left one held by its own taking alone could not be judged.
    Judge([u8; 32], [u8; 32]),
    /// A revoked device's presentations, the operator's by device alone.
    Presented {
        identity: Option<[u8; 32]>,
        device: [u8; 32],
    },
}

/// A sweep that could not read or drop what it owes, until its
/// backoff is over or what owed it is lifted.
pub(crate) struct OwedSweep {
    sweep: Sweep,
    failures: u32,
    due: u64,
}

impl OwedSweep {
    pub(super) fn failed(sweep: Sweep, failures: u32, now: u64) -> Self {
        let failures = failures + 1;
        let wait = SWEEP_BACKOFF.saturating_mul(1 << (failures - 1).min(6));
        OwedSweep {
            sweep,
            failures,
            due: now + wait.min(SWEEP_BACKOFF_MAX),
        }
    }
}

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

    /// Whether `who`'s own half of `f`, signed by `who` or a key that
    /// rotated to it along `rotations`, was signed by a certificate below
    /// its signer's floor.
    fn own_half_below(&self, f: &Friendship, who: &[u8; 32], rotations: &[Rotation]) -> bool {
        [
            (&f.offer.from, &f.offer.cert),
            (&f.acceptance.from, &f.acceptance.cert),
        ]
        .into_iter()
        .any(|(from, cert)| {
            chain_end(Fingerprint::of(from), rotations).is_some_and(|k| k.0 == *who)
                && DeviceCert::parse(cert).is_ok_and(|c| c.check_floor(self.floor(from)).is_err())
        })
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
    /// A half below its signer's floor that this server did not hold
    /// before the reset (§6).
    Reset,
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
    /// Active, each party's presentation standing, told to both again.
    Standing,
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

/// [`Core::portable_fields`] for `left.pair[i]`'s entry, from what the
/// step left.
pub(super) fn fields_left(left: &Left, i: usize, e: &mut FriendEntry) {
    if left.pair[i].fingerprint.is_none() || e.fingerprint.is_none() {
        return;
    }
    let (mine, theirs) = (&left.presentations[i], &left.presentations[1 - i]);
    if e.state == RosterState::Accepted && whole(mine) && whole(theirs) {
        let mut hashes: Vec<[u8; 32]> = [mine, theirs]
            .into_iter()
            .flatten()
            .map(|p| p.hash)
            .collect();
        hashes.dedup();
        e.friendships = hashes;
    }
    e.offer = match e.state {
        RosterState::Accepted => left.offers[1 - i].clone(),
        RosterState::PendingIn => left.rows[1 - i]
            .as_ref()
            .and_then(|r| r.pending_out.clone())
            .filter(|p| !p.upgrade)
            .and_then(|p| p.offer),
        _ => None,
    }
    .map(|o| o.offer);
}

/// The drops that make room for the withdrawals a write keeps, and each
/// owner's withdrawals judged whole by them, to record once it commits.
struct Room {
    parts: Vec<Part>,
    judged: Vec<([u8; 32], KeptFloors)>,
}

/// What presenting does to the edge, as [`Core::activation`] reads it.
enum Activation {
    None,
    Already,
    RosterFull,
    Befriend(Option<RelationId>, Vec<RelationId>),
}

/// The parts that make `a` and `b` friends, under `id` where there is
/// one, dropping the pair's presentations `drop` names and the offers
/// between them: the first acceptance answers them all.
pub(super) fn befriend_parts(
    a: &Mailbox,
    b: &Mailbox,
    at: SystemTime,
    id: Option<RelationId>,
    drop: &[[u8; 32]],
) -> Vec<Part> {
    let mut parts = vec![Part::BefriendDropping {
        a: a.clone(),
        b: b.clone(),
        at,
        id,
        drop: drop.to_vec(),
    }];
    if let Some((x, y)) = a.fingerprint.zip(b.fingerprint) {
        parts.push(Part::SetOffer(x, y, None));
        parts.push(Part::SetOffer(y, x, None));
    }
    parts
}

fn whole(p: &Option<Presentation>) -> bool {
    p.as_ref().is_some_and(Presentation::evidence)
}

impl Core {
    /// [`Core`]'s `upgrades_off`, false outside the sequence harness.
    fn upgrades_off(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        return self.upgrades_off.load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(any(test, feature = "test-support")))]
        false
    }
}

/// Whether the friendship `bytes` was built from an offer that has lapsed
/// by `now` (§4.1), which its acceptance is answered `Stale` for.
pub(super) fn lapsed_offer(bytes: &[u8], now: SystemTime) -> bool {
    Friendship::check(bytes, STORED, &[], zero_floor).is_ok_and(|f| f.offer.expires <= secs(now))
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
        let now = self.clock.unix();
        if self
            .offer_sweeps
            .lock()
            .unwrap()
            .iter()
            .any(|o| o.due <= now)
        {
            self.sweep_offers(Vec::new());
        }
        if let Some(store) = &self.relationships {
            // Under the hold an 802 judges a record under, so that none
            // lapses between the judging and the offer it keeps waiting.
            let _writing = self.friend_writes();
            let now = self.clock.wall();
            let lapsed = store.lapse_resets(now - RESET_KEPT, now);
            logged("lapsing `Reset` records", lapsed.map(drop));
        }
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
        let (alone, cleared) = {
            let r = self.reconciled.lock().unwrap();
            (r.of(&[fp]), r.cleared)
        };
        let (seen, rows) = self.epoch_key(&fp)?;
        // A pass of no floor recorded says nothing of the chain's rows.
        if !any_floor && self.reconciled.lock().unwrap().holds(&fp, &seen) {
            return Ok(());
        }
        let epochs = Epochs::of(&fp, seen.installed, &rows);
        if epochs.floor == 0 && !any_floor {
            // Nothing of its own below a floor: judged again only once
            // its rows change, which bumps it.
            #[cfg(test)]
            self.reconciling.at("no floor");
            let mut r = self.reconciled.lock().unwrap();
            if r.of(&[fp]) == alone && r.cleared == cleared {
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
            // The pair's own offer, read alone: an upgrade, or the one its
            // request carries.
            let asked = store
                .relationship(
                    &Mailbox::identified("", owner),
                    &Mailbox::identified("", other),
                    wall,
                )?
                .and_then(|r| r.pending_out)
                .and_then(|p| p.offer);
            let now = store.offer(&owner, &other, wall)?.or(asked);
            if now.is_none_or(|now| now.offer != stored.offer) {
                // Moved or replaced since: judged by a pass that reads it
                // where it is now.
                whole = false;
                continue;
            }
            let floors = Floors::after(self, &known);
            let below = floors.below(&o);
            floors.failed()?;
            if below {
                store.drop_offers(&[(owner, other)])?;
                if let (Some(me), Some(them)) = (self.mailbox_of(&owner), self.mailbox_of(&other)) {
                    self.tell_entry("an offer below a floor", &them, &me);
                    self.tell_entry("an offer below a floor", &me, &them);
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
    ) -> Result<Room, StoreError> {
        let mut parts = Vec::new();
        let mut judged = Vec::new();
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
            let last = self.withdrawals_judged.lock().unwrap().get(&owner).cloned();
            let whole = last.is_some_and(|j| j.iter().all(|(fp, kept)| floors.kept(fp) == *kept));
            if held.len() + new > self.messaging_policy.max_roster && !whole {
                #[cfg(test)]
                self.withdrawal_scans
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (mut signers, dead) = self.dead(floors, &held);
                parts.extend(dead);
                signers.push((owner, floors.kept(&owner)));
                floors.failed()?;
                judged.push((owner, signers));
            } else {
                let shadowed = |h: &&HeldWithdrawal| {
                    keeping.iter().any(|k| k.withdrawal.is_some() && same(h, k))
                };
                parts.extend(self.dead(floors, held.iter().filter(shadowed)).1);
            }
        }
        floors.failed()?;
        Ok(Room { parts, judged })
    }

    /// What a write `make_room` made room for judged, once that write
    /// committed: a cache that recorded a scan the write never kept would
    /// pass over the rows it left.
    fn room_made(&self, judged: Vec<([u8; 32], KeptFloors)>) {
        self.withdrawals_judged.lock().unwrap().extend(judged);
    }

    /// The drops of those of `held` signed below their signer's kept
    /// floor, with each signer's kept floor as read.
    fn dead<'w>(
        &self,
        floors: &Floors,
        held: impl IntoIterator<Item = &'w HeldWithdrawal>,
    ) -> (KeptFloors, Vec<Part>) {
        let mut signers = KeptFloors::new();
        let mut parts = Vec::new();
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
                parts.push(Part::DropWithdrawal(
                    w.owner,
                    w.pair,
                    w.party,
                    bytes.to_vec(),
                ));
            }
        }
        (signers, parts)
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
            let (_, dead) = self.dead(&floors, &store.withdrawals_by(owner)?);
            store.write(&dead, &Report::none())?;
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
    ) -> Result<(Ended, Left), StoreError> {
        let Room { mut parts, judged } =
            self.make_room(store, &Floors::new(self), &end.withdrawals)?;
        parts.push(Part::EndFriendship(a.clone(), b.clone(), end.clone()));
        let (mut did, left) = self.write_left(store, &parts, &[(a, b)], self.clock.wall())?;
        self.room_made(judged);
        let Some(Did::Ended(ended)) = did.pop() else {
            unreachable!("an ending answers what it ended");
        };
        self.unjudge(store, [a.fingerprint, b.fingerprint].into_iter().flatten());
        Ok((ended, left.into_iter().next().expect("the pair asked of")))
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
        tidy: &mut Vec<Part>,
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
                        tidy.push(Part::DropWithdrawal(
                            w.owner,
                            w.pair,
                            w.party,
                            bytes.clone(),
                        ));
                    }
                    continue;
                }
                let checked = HeldWithdrawal {
                    checked: true,
                    ..w.clone()
                };
                tidy.push(Part::KeepWithdrawal(
                    checked,
                    self.messaging_policy.max_roster,
                ));
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
        tidy: &mut Vec<Part>,
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
        let cuts = self.cutoffs(store, &pair, &rotations, &floors, tidy)?;
        floors.failed().map_err(store_failed)?;
        if cuts.iter().any(|(c, _)| offer.cut_by(c)) {
            return Err(MessagingError::Withdrawn);
        }
        Ok(StoredOffer {
            offer: bytes,
            lapses_at: unix_time(offer.expires),
        })
    }

    /// An upgrade offer (§4.1), told to `them`'s friendships sessions
    /// alone: on a friendship standing, kept beside it; on an edge a reset
    /// left inactive, kept with a pending out its sender is shown as of a
    /// request, which `them` never is. One that takes the place of another
    /// waiting is paced as presenting is, so that offers made again tell
    /// `them` no faster than presentations would.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn upgrade_offer(
        &self,
        store: &Arc<dyn RelationshipStore>,
        uid: Uid,
        me: &Mailbox,
        them: &Mailbox,
        note: Option<String>,
        offer: StoredOffer,
        charge: Option<&Charge>,
    ) -> Result<(), MessagingError> {
        let (Some(a), Some(b)) = (me.fingerprint, them.fingerprint) else {
            return Err(MessagingError::AlreadyFriends);
        };
        let now = self.clock.wall();
        if store.offer(&a, &b, now).map_err(store_failed)?.is_some()
            && self.friendships_spend(uid, PRESENTING).is_err()
        {
            return Err(MessagingError::RateLimited);
        }
        let friends = store
            .relationship(me, them, now)
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some());
        if friends {
            store
                .set_offer(&a, &b, Some(&offer))
                .map_err(store_failed)?;
        } else {
            // It lapses for its sender as a request would, and its offer
            // never after it.
            let lapses_at = now + self.messaging_policy.request_retention;
            let shown = PendingOut {
                sent_at: now,
                lapses_at,
                delivered: true,
                note: note.clone(),
                offer: None,
                upgrade: true,
            };
            let kept = StoredOffer {
                lapses_at: offer.lapses_at.min(lapses_at),
                ..offer.clone()
            };
            let left = store
                .ask(
                    me,
                    them,
                    &shown,
                    Some(&kept),
                    charge,
                    &Report::of(me, them, now),
                )
                .map_err(store_failed)?;
            self.tell_left(&left[0], [true, false]);
        }
        self.roster.lock().unwrap().tell_friendships(
            them,
            Event::FriendRequest {
                login: me.login.clone(),
                fingerprint: me.fingerprint,
                note,
                offer: Some(offer.offer),
            },
        );
        Ok(())
    }

    /// Whether an offer from `sender` to `target` is an upgrade offer on an
    /// edge a reset left inactive (§4.1): `target`'s own presentation for
    /// the pair answered `Reset` here, which is its consent, and `sender`'s
    /// half of the friendship it kept below its floor. `waiting`, for an
    /// offer already taken as one, which keeps the record past its time.
    pub(super) fn reset_edge(
        &self,
        store: &Arc<dyn RelationshipStore>,
        sender: &Mailbox,
        target: &Mailbox,
        now: SystemTime,
        waiting: bool,
    ) -> Result<bool, MessagingError> {
        let (Some(s), Some(t)) = (sender.fingerprint, target.fingerprint) else {
            return Ok(false);
        };
        if self.upgrades_off() {
            return Ok(false);
        }
        let Some(record) = store
            .presentation(&t, &s)
            .map_err(store_failed)?
            .filter(|p| waiting || p.at + RESET_KEPT > now)
            .and_then(|p| p.reset)
        else {
            return Ok(false);
        };
        let Ok(f) = Friendship::check(&record, STORED, &[], zero_floor) else {
            return Ok(false);
        };
        let rotations = self.rotations_for(store, &f.pair())?;
        let floors = Floors::new(self);
        let below = floors.own_half_below(&f, &s, &rotations);
        floors.failed().map_err(store_failed)?;
        Ok(below)
    }

    /// What a `Reset` answered `me` tells of `them`'s `offer` waiting
    /// (§4.1), told to `me`'s friendships sessions as an upgrade offer at
    /// every presentation answered so, which reaches one made while `me`
    /// was away. Where it came with `asked`, a request taken as an upgrade
    /// just now, `me`'s other sessions saw the request, which is gone for
    /// them; `them`'s sessions are told nothing, their request standing as
    /// far as they can tell.
    fn reset_offer(
        &self,
        me: &Mailbox,
        them: &Mailbox,
        offer: StoredOffer,
        asked: Option<PendingOut>,
    ) {
        let mut r = self.roster.lock().unwrap();
        if asked.is_some() {
            r.tell_plain(me, Event::FriendEntry(Box::new(FriendEntry::removed(them))));
        }
        r.tell_friendships(
            me,
            Event::FriendRequest {
                login: them.login.clone(),
                fingerprint: them.fingerprint,
                note: asked.and_then(|p| p.note),
                offer: Some(offer.offer),
            },
        );
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
        let mut tidy = Vec::new();
        let cuts = self.cutoffs(store, &pair, &rotations, &floors, &mut tidy)?;
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
        let kept = olds.iter().flatten().find_map(|p| p.edge);
        let presented: Vec<Presentation> = rows
            .into_iter()
            .zip(olds)
            .map(|((presenter, other, dev), old)| Presentation {
                presenter,
                other,
                names: [presenter, other],
                pair: pair.hash(),
                hash: f.hash,
                friendship: Some(bytes.clone()),
                reset: None,
                device: dev,
                edge: old.as_ref().and_then(|p| p.edge),
                at,
                taken: old
                    .filter(|p| p.friendship.as_deref() == Some(&bytes[..]))
                    .map_or(at, |p| p.taken),
            })
            .collect();
        let friends = store
            .relationship(me, them, at)
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some());
        // The caller's roster is asked before anything is written, so that
        // a refusal leaves what was there, a `Reset` record included. The
        // sender's always has room: its request, or the pending out its
        // upgrade offer shows it, is a row of it already.
        let mut approvals = Vec::new();
        if !friends {
            let max = self.messaging_policy.max_roster;
            for (x, y) in [(me, them), (them, me)] {
                let row = store.relationship(x, y, at).map_err(store_failed)?;
                if x == me
                    && row.is_none()
                    && store.roster_size(x, at).map_err(store_failed)? >= max
                {
                    return Err(MessagingError::RosterFull);
                }
                approvals.extend(row.and_then(|r| r.approval));
            }
        }
        let part = Part::PresentBefriending {
            a: me.clone(),
            b: them.clone(),
            rows: presented,
            befriend: (!friends).then_some(kept),
            at,
        };
        let (did, left) = self
            .write_left(store, &[tidy, vec![part]].concat(), &[(me, them)], at)
            .map_err(store_failed)?;
        let Some(Did::Befriended(replaced, id)) = did.into_iter().last() else {
            unreachable!("a presenting befriending answers what it replaced");
        };
        for old in replaced {
            self.replaced(store, old, Some(&bytes), false);
        }
        match id {
            Some(id) => self.befriended(&left[0], id, &approvals),
            None => self.tell_left(&left[0], [true, true]),
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
    /// Answers its bytes, for the `Removed` it is told with, and what it
    /// left of the friendship. With `block`, `me` blocks `them` in the
    /// same step, as Block User (806) carrying it does; with `removal`,
    /// what a removal ends here alone is written in the same step where
    /// the withdrawal does not end the friendship.
    pub(super) fn take_withdrawal(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        device: &Device,
        them: &Mailbox,
        bytes: Vec<u8>,
        removal: Option<Ending>,
    ) -> Result<(Vec<u8>, Applied), MessagingError> {
        let block = removal.is_none();
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
        let applied = self.apply_cutoff(store, &floors, keep, party, other, blocking, removal)?;
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
    #[allow(clippy::too_many_arguments)]
    fn apply_cutoff(
        &self,
        store: &Arc<dyn RelationshipStore>,
        floors: &Floors,
        keep: HeldWithdrawal,
        party: [u8; 32],
        other: [u8; 32],
        block: Option<(&Mailbox, &Mailbox)>,
        removal: Option<Ending>,
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
            // An upgrade offer, or the offer a request carries.
            let asked = store
                .relationship(
                    &Mailbox::identified("", p),
                    &Mailbox::identified("", q),
                    wall,
                )
                .map_err(store_failed)?
                .and_then(|r| r.pending_out)
                .and_then(|r| r.offer);
            let waiting = store.offer(&p, &q, wall).map_err(store_failed)?.or(asked);
            if let Some(o) = waiting {
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
        let standing = had == 2 && row.as_ref().is_some_and(|r| r.friendship.is_some());
        // A removal the withdrawal leaves undone ends the friendship here
        // alone, in the same step.
        if let Some(here) = removal.filter(|_| !end.friendship && !standing) {
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
            end.friendship = here.friendship;
            end.hold = here.hold;
        }
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
            // An upgrade the blocked had waiting goes too, told as a
            // decline is.
            shown |= store
                .relationship(blocked, blocker, wall)
                .map_err(store_failed)?
                .and_then(|r| r.pending_out)
                .is_some_and(|p| p.upgrade);
        }
        let (a, b) = block.unwrap_or((&x, &y));
        let Room { mut parts, judged } = self
            .make_room(store, floors, &end.withdrawals)
            .map_err(store_failed)?;
        let changes = standing || !end.presentations.is_empty() || !end.offers.is_empty();
        parts.push(Part::EndFriendship(a.clone(), b.clone(), end));
        // Told under the accounts' own mailboxes, read before the write.
        let told = match block {
            Some((blocker, blocked)) => Some((blocker.clone(), blocked.clone())),
            None => self
                .pair_mailboxes(store, &party, &other, wall)
                .map_err(store_failed)?,
        };
        let pairs: Vec<(&Mailbox, &Mailbox)> = told.iter().map(|(a, b)| (a, b)).collect();
        let (mut did, left) = self
            .write_left(store, &parts, &pairs, wall)
            .map_err(store_failed)?;
        self.room_made(judged);
        let Some(Did::Ended(ended)) = did.pop() else {
            unreachable!("an ending answers what it ended");
        };
        self.unjudge(store, [party, other]);
        let left = left.first();
        if let Some(e) = ended.ended {
            let [a, b] = &e.parties;
            self.roster.lock().unwrap().friends_changed(a, b, false);
            if let Some(left) = left {
                self.tell_left_with(left, [true, true], withdraw.as_deref());
            }
            return Ok(Applied::Ended);
        }
        // An edge that stays active is told to both again (§4.3), as is
        // what it cut of what waits; a block's own client knows what its
        // block ended.
        if let Some(left) = left {
            match block {
                Some(_) if shown => self.tell_left(left, [false, true]),
                Some(_) => {}
                None if changes => self.tell_left(left, [true, true]),
                None => {}
            }
        }
        Ok(if standing {
            Applied::Standing
        } else {
            Applied::Untouched
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
            let signed = store.withdrawals(&pres.pair)?.iter().any(|w| {
                w.owner == mine
                    && w.party == named
                    && w.checked
                    && w.withdrawal.is_some()
                    && w.before >= before
                    && floors.stands(w.withdrawal.as_deref())
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
        site: &'static str,
        store: &Arc<dyn RelationshipStore>,
        a: &[u8; 32],
        b: &[u8; 32],
        presenters: &[[u8; 32]],
    ) -> Result<Vec<Presentation>, StoreError> {
        let dropped = store.drop_presentations(a, b, presenters)?;
        if !dropped.gone.is_empty() {
            self.unjudge(store, [*a, *b]);
        }
        // An edge ended is told once, whatever record left with it.
        match &dropped.ended {
            Some(e) => self.edge_ended(site, e, None),
            None => {
                for gone in &dropped.gone {
                    self.record_left(site, gone);
                }
            }
        }
        Ok(dropped.gone)
    }

    /// A `Reset` record left its row, and with it any upgrade offer it
    /// qualified: both parties told their entries as they now stand.
    fn record_left(&self, site: &'static str, p: &Presentation) {
        if p.reset.is_none() {
            return;
        }
        if let (Some(a), Some(b)) = (self.mailbox_of(&p.presenter), self.mailbox_of(&p.other)) {
            self.tell_entry(site, &a, &b);
            self.tell_entry(site, &b, &a);
        }
    }

    /// A presentation `present` answered as replaced, where its evidence
    /// was other than `now`'s: what it held is judged again. A record it
    /// was is told, unless the caller tells both parties after.
    fn replaced(
        &self,
        store: &Arc<dyn RelationshipStore>,
        old: Option<Presentation>,
        now: Option<&[u8]>,
        tell: bool,
    ) {
        if let Some(old) = old.as_ref().filter(|_| tell) {
            self.record_left("a hash kept", old);
        }
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
            self.drop_presented("a floor's pass", store, &a, &b, &presenters)?;
        }
        Ok(())
    }

    /// An edge's ending, told once it is committed: the roster, then both
    /// parties' entries, by the mailboxes their rows keep, so a party the
    /// directory no longer names is told too.
    pub(super) fn edge_ended(&self, site: &'static str, e: &EndedEdge, withdraw: Option<&[u8]>) {
        let [a, b] = &e.parties;
        self.roster.lock().unwrap().friends_changed(a, b, false);
        self.tell_entry_with(site, a, b, withdraw);
        self.tell_entry_with(site, b, a, withdraw);
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
            self.edge_ended("a rotation's merge", e, None);
        }
        for gone in &rekeyed.dropped {
            self.orphan_judged_or_owed(store, gone);
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
        if self.judged_reset(store, p, &[])? {
            let site = "an orphan judged";
            self.drop_presented(site, store, &p.presenter, &p.other, &[p.presenter])?;
        }
        Ok(())
    }

    /// The mailboxes of the accounts holding `a` and `b`, `a`'s first: as
    /// the pair's rows keep them, whether or not the directory still names
    /// each key, or as the directory names them where there is no row.
    fn pair_mailboxes(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &[u8; 32],
        b: &[u8; 32],
        wall: SystemTime,
    ) -> Result<Option<(Mailbox, Mailbox)>, StoreError> {
        let (x, y) = (Mailbox::identified("", *a), Mailbox::identified("", *b));
        if let Some(r) = store.relationship(&x, &y, wall)? {
            return Ok(Some((r.owner, r.other)));
        }
        if let Some(r) = store.relationship(&y, &x, wall)? {
            return Ok(Some((r.other, r.owner)));
        }
        Ok(self.mailbox_of(a).zip(self.mailbox_of(b)))
    }

    /// Whether `p`, held by its own taking alone, no longer is, once the
    /// rows `replacing` names are replaced by others. Reads alone.
    fn judged_reset(
        &self,
        store: &Arc<dyn RelationshipStore>,
        p: &Presentation,
        replacing: &[([u8; 32], [u8; 32])],
    ) -> Result<bool, StoreError> {
        let Some(bytes) = p.friendship.as_deref() else {
            return Ok(false);
        };
        let f = Friendship::check(bytes, STORED, &[], zero_floor);
        let mut copies = match &f {
            Ok(f) => self.copies(store, f, bytes)?,
            Err(_) => Vec::new(),
        };
        copies.retain(|c| !replacing.contains(&(c.presenter, c.other)));
        let floors = Floors::new(self);
        let judged = floors.judged(&p.hash, bytes, f.as_ref(), &copies, STORED);
        floors.failed()?;
        Ok(judged == Judged::Reset)
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
        // An upgrade offer beside a friendship, or the offer a request
        // shown as pending in carries: each from where it is kept.
        e.offer = match e.state {
            RosterState::Accepted => store.offer(&theirs, &mine, now).ok().flatten(),
            RosterState::PendingIn => self.mailbox_of(&theirs).and_then(|them| {
                let row = store.relationship(&them, of, now).ok().flatten()?;
                row.pending_out.filter(|p| !p.upgrade)?.offer
            }),
            _ => None,
        }
        .map(|o| o.offer);
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
                let (ended, _) = self
                    .end_friendship(store, &me.mailbox, &them, &end)
                    .map_err(store_failed)?;
                if let Some(e) = ended.ended {
                    self.edge_ended("a removal by key", &e, None);
                }
                return Ok(());
            }
            let gone = self
                .drop_presented("a removal by key", store, &mine, fingerprint, &[mine])
                .map_err(store_failed)?;
            for gone in &gone {
                self.orphan_judged_or_owed(store, gone);
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
        let (Some(a), Some(b)) = (me.mailbox.fingerprint, them.fingerprint) else {
            return Err(MessagingError::NotFriends);
        };
        if store
            .offer(&a, &b, now)
            .map_err(store_failed)?
            .is_none_or(|o| o.offer != offer)
        {
            return Err(MessagingError::NotFriends);
        }
        // On an edge a reset left inactive, with the pending out it shows.
        let shown = store
            .relationship(&me.mailbox, &them, now)
            .map_err(store_failed)?
            .and_then(|r| r.pending_out)
            .is_some_and(|p| p.upgrade);
        // Beside a friendship the friend's entry loses the offer, and is
        // told so.
        let part = match shown {
            false => Part::SetOffer(a, b, None),
            true => Part::EndFriendship(
                them.clone(),
                me.mailbox.clone(),
                Ending {
                    offers: vec![a],
                    pending: true,
                    ..Ending::default()
                },
            ),
        };
        let (_, left) = self
            .write_left(store, &[part], &[(&me.mailbox, &them)], now)
            .map_err(store_failed)?;
        self.tell_left(&left[0], [shown, true]);
        Ok(())
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
        self.take_withdrawal(store, &me.mailbox, &device, &them, withdraw, None)
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
            .map(|b| {
                let mut tidy = Vec::new();
                let presented = self.present_friendship(
                    store,
                    &me.mailbox,
                    mine,
                    &device,
                    &floors,
                    b,
                    &mut tidy,
                );
                if presented.is_ok() {
                    self.tidy(store, tidy);
                }
                presented
            })
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
            let Room { mut parts, judged } = self
                .make_room(store, floors, std::slice::from_ref(&cut))
                .map_err(store_failed)?;
            parts.push(Part::KeepWithdrawal(cut, self.messaging_policy.max_roster));
            store.write(&parts, &Report::none()).map_err(store_failed)?;
            self.room_made(judged);
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
        self.apply_cutoff(store, floors, keep, party, other, None, None)?;
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

    #[allow(clippy::too_many_arguments)]
    fn present_friendship(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        mine: [u8; 32],
        device: &Device,
        floors: &Floors,
        bytes: Vec<u8>,
        tidy: &mut Vec<Part>,
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
        let row = |friendship: Option<Vec<u8>>, reset: Option<Vec<u8>>| {
            let old = store.presentation(&mine, &theirs).map_err(store_failed)?;
            let edge = old.as_ref().and_then(|p| p.edge);
            let taken = old
                .filter(|p| friendship.is_some() && p.friendship == friendship)
                .map_or(wall, |p| p.taken);
            Ok::<_, MessagingError>(Presentation {
                presenter: mine,
                other: theirs,
                names: [my_name.0, their_name.0],
                pair: pair.hash(),
                hash,
                friendship,
                reset,
                device: device.key,
                edge,
                at: wall,
                taken,
            })
        };
        let record = |friendship: Option<Vec<u8>>, reset: Option<Vec<u8>>| {
            let p = row(friendship, reset)?;
            store
                .present(&p)
                .map(|old| self.replaced(store, old, p.friendship.as_deref(), true))
                .map_err(store_failed)
        };
        // Step 2's refusal keeps the hash alone toward the bound, as the
        // identity draft has it, and changes nothing already held.
        let keep_hash = || match presented(&mine, &theirs) {
            Some(_) => Ok(()),
            None => record(None, None),
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
        let cuts = self.cutoffs(store, &pair, &rotations, floors, tidy)?;
        floors.failed().map_err(store_failed)?;
        if let Some((_, w)) = cuts.into_iter().find(|(c, _)| f.cut_by(c)) {
            return answer(Presented::Withdrawn(w));
        }
        // Step 4: a half below its signer's floor, where this server did
        // not take the friendship, by either party, before that half was
        // reset. Unknown keeps the hash as step 2 does; `Reset` keeps the
        // friendship as a record, for the upgrade offer that remakes it.
        let judged = floors.held(&hash, &bytes, &held, now);
        floors.failed().map_err(store_failed)?;
        match judged {
            Judged::Stands => {}
            Judged::Unknown => {
                keep_hash()?;
                return answer(Presented::AccountNotFound);
            }
            Judged::Reset => {
                // The other party's pending state toward the presenter, read
                // before anything is written.
                let pending = store
                    .relationship(&them, me, wall)
                    .map_err(store_failed)?
                    .and_then(|r| r.pending_out);
                let below = !self.upgrades_off() && floors.own_half_below(&f, &theirs, &rotations);
                floors.failed().map_err(store_failed)?;
                let upgrade = match &pending {
                    Some(p) if p.upgrade && below => {
                        store.offer(&theirs, &mine, wall).map_err(store_failed)?
                    }
                    Some(p) if below => p.offer.clone(),
                    _ => None,
                };
                // What is stored of it is not held either, and goes now
                // rather than at the next judging; the record takes the
                // place of a hash kept alone, or a record, but never of
                // another friendship presented that is evidence; and the
                // request it remakes is taken as an upgrade: one step.
                let mut drops: Vec<Going> = Vec::new();
                for p in held.iter().filter(|p| p.hash == hash && p.evidence()) {
                    let pair = drops.iter_mut().find(|(a, b, _)| {
                        (*a, *b) == (p.presenter, p.other) || (*a, *b) == (p.other, p.presenter)
                    });
                    match pair {
                        Some((_, _, presenters)) => presenters.push(p.presenter),
                        None => drops.push((p.presenter, p.other, vec![p.presenter])),
                    }
                }
                let recording =
                    presented(&mine, &theirs).is_none_or(|p| p.hash == hash || !p.evidence());
                let dropping_mine = drops.iter().any(|(a, b, ps)| {
                    (*a, *b) == (mine, theirs) && ps.contains(&mine)
                        || (*a, *b) == (theirs, mine) && ps.contains(&mine)
                });
                let record = recording
                    .then(|| row(None, Some(bytes.clone())))
                    .transpose()?
                    .map(|p| Presentation {
                        edge: p.edge.filter(|_| !dropping_mine),
                        ..p
                    });
                let converting = recording && pending.as_ref().is_some_and(|p| !p.upgrade);
                let part = Part::AnswerReset {
                    drops: drops.clone(),
                    record,
                    upgrade: converting
                        .then(|| (them.clone(), me.clone()))
                        .filter(|_| upgrade.is_some()),
                };
                // Each pair a drop names is told from what the step left
                // of it, under the mailboxes its rows keep, so a party the
                // directory no longer names is told too.
                let mut named: Vec<(Mailbox, Mailbox)> = Vec::new();
                for (a, b, _) in &drops {
                    named.extend(
                        self.pair_mailboxes(store, a, b, wall)
                            .map_err(store_failed)?,
                    );
                }
                let mut pairs = vec![(me, &them)];
                pairs.extend(named.iter().map(|(a, b)| (a, b)));
                let (did, left) = self
                    .write_left(store, &[part], &pairs, wall)
                    .map_err(store_failed)?;
                let Some(Did::Reset(ended, replaced)) = did.into_iter().next() else {
                    unreachable!("a reset answers what it dropped and replaced");
                };
                let mut said = false;
                for ((a, b, _), dropped) in drops.iter().zip(&ended) {
                    if !dropped.gone.is_empty() {
                        self.unjudge(store, [*a, *b]);
                    }
                    let Some(e) = &dropped.ended else {
                        continue;
                    };
                    let pair = left.iter().find(|l| {
                        let fps = [l.pair[0].fingerprint, l.pair[1].fingerprint];
                        let ends = [e.parties[0].fingerprint, e.parties[1].fingerprint];
                        fps == ends || fps == [ends[1], ends[0]]
                    });
                    if let Some(l) = pair {
                        said |= l.pair[0] == *me || l.pair[1] == *me;
                        self.edge_ended_left(l, None);
                    }
                }
                let left = &left[0];
                let record_left = replaced.as_ref().is_some_and(|o| o.reset.is_some());
                self.replaced(store, replaced, None, false);
                if record_left && !said {
                    self.tell_left(left, [true, true]);
                }
                // What is told is what the step left waiting: a record it
                // replaced may have taken the upgrade with it.
                if let (true, Some(_), Some(offer)) = (recording, upgrade, left.offers[1].clone()) {
                    self.reset_offer(me, &them, offer, pending.filter(|p| !p.upgrade));
                }
                return answer(Presented::Reset);
            }
        }
        // Step 6, there being no hidden links for step 5. A local edge this
        // makes portable stands on held evidence alone; on any other, the
        // other party's presentation of other bytes is held by its own
        // taking alone.
        let both = [(mine, theirs), (theirs, mine)]
            .iter()
            .all(|(p, q)| presented(p, q).is_some_and(|x| x.evidence()));
        // Everything read first, then written as one step: what is not
        // held of a local edge, this presentation, the other party's of
        // other bytes where its own taking no longer holds it, and the
        // friendship where both now stand.
        let gone = match friends.contains(&theirs) && !both {
            true => {
                self.unheld_between(store, me, &them)
                    .map_err(store_failed)?
                    .0
            }
            false => Vec::new(),
        };
        let p = row(Some(bytes.clone()), None)?;
        let other = presented(&theirs, &mine).filter(|t| !gone.contains(&t.presenter));
        let reset_theirs = match other
            .as_ref()
            .filter(|t| t.friendship.as_ref() != Some(&bytes))
        {
            Some(t) => self
                .judged_reset(store, t, &[(mine, theirs)])
                .map_err(store_failed)?,
            None => false,
        };
        let other = other.filter(|_| !reset_theirs);
        let plan = self.activation(store, me, &them, floors, &Some(p.clone()), &other, wall)?;
        let mut parts = Vec::new();
        if !gone.is_empty() {
            parts.push(Part::DropPresentations(mine, theirs, gone));
        }
        parts.push(Part::Present(p.clone()));
        if reset_theirs {
            parts.push(Part::DropPresentations(theirs, mine, vec![theirs]));
        }
        if let Activation::Befriend(edge, _) = &plan {
            parts.extend(befriend_parts(me, &them, wall, *edge, &[]));
        }
        let (did, left) = self
            .write_left(store, &parts, &[(me, &them)], wall)
            .map_err(store_failed)?;
        let left = &left[0];
        let (mut owed, mut said) = (false, false);
        for d in &did {
            match d {
                Did::Ended(dropped) => {
                    if !dropped.gone.is_empty() {
                        self.unjudge(store, [mine, theirs]);
                    }
                    if dropped.ended.is_some() && !said {
                        self.edge_ended_left(left, None);
                        said = true;
                    }
                }
                Did::Replaced(old) => {
                    owed |= old.as_ref().is_some_and(|o| o.reset.is_some());
                    self.replaced(store, old.clone(), p.friendship.as_deref(), false);
                }
                Did::Friends(id) => {
                    if let Activation::Befriend(_, approvals) = &plan {
                        self.unjudge(store, [mine, theirs]);
                        self.befriended(left, *id, approvals);
                        return answer(Presented::Ok);
                    }
                }
                _ => {}
            }
        }
        // An edge active already is told to both again; so is a record
        // this replaced, and the upgrade it took with it.
        if (owed || matches!(plan, Activation::Already)) && !said {
            self.tell_left(left, [true, true]);
        }
        match plan {
            Activation::RosterFull => answer(Presented::RosterFull),
            _ => answer(Presented::Ok),
        }
    }

    /// Whether the edge between `me` and `them` is made active, where
    /// each has presented a friendship for it (§4.3), with `mine` and
    /// `theirs` as they will stand: under the id a dropped presentation
    /// kept, with the approvals it ends. `RosterFull` where `me`'s roster
    /// has no room for it; where `them`'s has none it stays inactive,
    /// unanswered. A presentation stored here counts only where its
    /// friendship stands at the floors, as it must where presented now
    /// (§6). Reads alone.
    #[allow(clippy::too_many_arguments)]
    fn activation(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        floors: &Floors,
        mine: &Option<Presentation>,
        theirs: &Option<Presentation>,
        now: SystemTime,
    ) -> Result<Activation, MessagingError> {
        if me.fingerprint.zip(them.fingerprint).is_none() || !(whole(mine) && whole(theirs)) {
            return Ok(Activation::None);
        }
        let row = store.relationship(me, them, now).map_err(store_failed)?;
        if row.as_ref().is_some_and(|r| r.friendship.is_some()) {
            return Ok(Activation::Already);
        }
        let rows: Vec<Presentation> = mine.iter().chain(theirs).cloned().collect();
        let stands = rows.iter().all(|p| {
            p.friendship
                .as_deref()
                .is_some_and(|b| floors.held(&p.hash, b, &rows, STORED) == Judged::Stands)
        });
        floors.failed().map_err(store_failed)?;
        if !stands {
            return Ok(Activation::None);
        }
        let max = self.messaging_policy.max_roster;
        let back = store.relationship(them, me, now).map_err(store_failed)?;
        let room = |row: &Option<Relationship>, x: &Mailbox| -> Result<bool, MessagingError> {
            Ok(row.is_some() || store.roster_size(x, now).map_err(store_failed)? < max)
        };
        if !room(&row, me)? {
            return Ok(Activation::RosterFull);
        }
        if !room(&back, them)? {
            return Ok(Activation::None);
        }
        let approvals = [&row, &back]
            .into_iter()
            .filter_map(|r| r.as_ref().and_then(|r| r.approval))
            .collect();
        let edge = mine
            .as_ref()
            .and_then(|p| p.edge)
            .or(theirs.as_ref().and_then(|p| p.edge));
        Ok(Activation::Befriend(edge, approvals))
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
        let now = self.clock.unix();
        for (identity, device) in devices {
            if let Err(e) = self.drop_device_presentations(store, *identity, device) {
                warn!("relationships: dropping a revoked device's presentations: {e}");
                let sweep = Sweep::Presented {
                    identity: *identity,
                    device: *device,
                };
                self.offer_sweeps
                    .lock()
                    .unwrap()
                    .push(OwedSweep::failed(sweep, 0, now));
            }
        }
    }

    /// What `device` presented, for `identity` where one is named,
    /// dropped, each pair as one step.
    fn drop_device_presentations(
        &self,
        store: &Arc<dyn RelationshipStore>,
        identity: Option<[u8; 32]>,
        device: &[u8; 32],
    ) -> Result<(), StoreError> {
        let made = store.presented_by(device)?;
        for p in made
            .into_iter()
            .filter(|p| identity.is_none_or(|i| p.presenter == i))
        {
            let site = "a revoked device's presentation";
            let gone = self.drop_presented(site, store, &p.presenter, &p.other, &[p.presenter])?;
            for gone in &gone {
                self.orphan_judged_or_owed(store, gone);
            }
        }
        Ok(())
    }

    /// Drop what `sweeps` owe and what owed sweeps whose backoff is over
    /// owe, as one step, every pair it changes told to its parties from
    /// what the step left: one that cannot be read or written owed again,
    /// and one whose revocation was lifted, or whose identity was linked
    /// again, moot.
    pub(crate) fn sweep_offers(&self, sweeps: Vec<Sweep>) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        let _writing = self.friend_writes();
        let (wall, now) = (self.clock.wall(), self.clock.unix());
        // Fresh ones stand by what owes them; those owed again are
        // checked against it first.
        let due: Vec<(Sweep, u32, bool)> = {
            let mut owed = self.offer_sweeps.lock().unwrap();
            let (due, later): (Vec<_>, Vec<_>) = owed.drain(..).partition(|o| o.due <= now);
            *owed = later;
            sweeps
                .into_iter()
                .map(|s| (s, 0, true))
                .chain(
                    due.into_iter()
                        .map(|o| (o.sweep.clone(), o.failures, false)),
                )
                .collect()
        };
        let mut parts = Vec::new();
        let mut pairs: Vec<(Mailbox, Mailbox, [bool; 2])> = Vec::new();
        let mut read = Vec::new();
        let mut owe = Vec::new();
        for (sweep, failures, fresh) in due {
            if !fresh && !self.still_owed(&sweep) {
                continue;
            }
            if let Sweep::Purge(of) = &sweep {
                if !self.purge_relationships_held(&_writing, of) {
                    owe.push(OwedSweep::failed(sweep, failures, now));
                }
                continue;
            }
            if let Sweep::Presented { identity, device } = sweep {
                if let Err(e) = self.drop_device_presentations(store, identity, &device) {
                    warn!("relationships: dropping a revoked device's presentations: {e}");
                    owe.push(OwedSweep::failed(sweep, failures, now));
                }
                continue;
            }
            if let Sweep::Unpresented(fp) = sweep {
                if let Err(e) = self.drop_unlinked_presentations(store, &fp) {
                    warn!("relationships: dropping an unlinked account's presentations: {e}");
                    owe.push(OwedSweep::failed(sweep, failures, now));
                }
                continue;
            }
            if let Sweep::Judge(a, b) = sweep {
                if let Err(e) = self.judge_pair(store, &a, &b) {
                    warn!("relationships: judging what a drop left: {e}");
                    owe.push(OwedSweep::failed(sweep, failures, now));
                }
                continue;
            }
            match self.owed_by(store, &sweep, wall) {
                Ok((part, named)) => {
                    parts.push(part);
                    pairs.extend(named);
                    read.push((sweep, failures));
                }
                Err(e) => {
                    warn!("relationships: reading what a revocation or an unlink owes: {e}");
                    owe.push(OwedSweep::failed(sweep, failures, now));
                }
            }
        }
        // One tell a pair, whichever sweeps named it: an unlink's
        // recipients kept, each party told where any sweep would tell it.
        let mut coalesced: Vec<(Mailbox, Mailbox, [bool; 2])> = Vec::new();
        for (a, b, to) in pairs {
            let key = |m: &Mailbox| (m.login.clone(), m.fingerprint);
            match coalesced.iter_mut().find(|(x, y, _)| {
                (key(x), key(y)) == (key(&a), key(&b)) || (key(x), key(y)) == (key(&b), key(&a))
            }) {
                Some((x, _, seen)) => {
                    let same = key(x) == key(&a);
                    let to = if same { to } else { [to[1], to[0]] };
                    *seen = [seen[0] || to[0], seen[1] || to[1]];
                }
                None => coalesced.push((a, b, to)),
            }
        }
        let pairs = coalesced;
        if !parts.is_empty() {
            let asked: Vec<(&Mailbox, &Mailbox)> = pairs.iter().map(|(a, b, _)| (a, b)).collect();
            match self.write_left(store, &parts, &asked, wall) {
                Ok((did, left)) => {
                    // Told where an offer went, and nowhere else.
                    let mut gone: Vec<FpPair> = Vec::new();
                    for (part, did) in parts.iter().zip(did) {
                        match (part, did) {
                            (Part::DropOffers(signed), _) => gone.extend(signed),
                            (_, Did::Named(named)) => gone.extend(named),
                            _ => {}
                        }
                    }
                    for ((a, b, to), left) in pairs.iter().zip(&left) {
                        let dropped = a
                            .fingerprint
                            .zip(b.fingerprint)
                            .is_some_and(|(x, y)| gone.contains(&(x, y)) || gone.contains(&(y, x)));
                        if dropped {
                            self.tell_left(left, *to);
                        }
                    }
                }
                Err(e) => {
                    warn!("relationships: dropping what a revocation or an unlink owes: {e}");
                    owe.extend(read.into_iter().map(|(s, f)| OwedSweep::failed(s, f, now)));
                }
            }
        }
        self.offer_sweeps.lock().unwrap().extend(owe);
    }

    /// What judging the withdrawals tidied, written once the act it was
    /// judged for is done: a withdrawal found checked or dropped is found
    /// so again by the next that judges it, so one that cannot be written
    /// costs nothing but the work.
    pub(super) fn tidy(&self, store: &Arc<dyn RelationshipStore>, tidy: Vec<Part>) {
        if tidy.is_empty() {
            return;
        }
        if let Err(e) = store.write(&tidy, &Report::none()) {
            warn!("relationships: tidying the withdrawals judged: {e}");
        }
    }

    /// What `a` and `b` hold of each other, each presentation held by its
    /// own taking alone judged from the store as it stands.
    fn judge_pair(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &[u8; 32],
        b: &[u8; 32],
    ) -> Result<(), StoreError> {
        for (p, q) in [(a, b), (b, a)] {
            if let Some(held) = store.presentation(p, q)? {
                self.judged_alone(store, &held)?;
            }
        }
        Ok(())
    }

    /// `gone`'s orphan judged, or owed to a later tick where it cannot be.
    fn orphan_judged_or_owed(&self, store: &Arc<dyn RelationshipStore>, gone: &Presentation) {
        if let Err(e) = self.orphan_judged(store, gone) {
            warn!("relationships: judging an orphan: {e}");
            let sweep = Sweep::Judge(gone.presenter, gone.other);
            let now = self.clock.unix();
            let owed = OwedSweep::failed(sweep, 0, now);
            self.offer_sweeps.lock().unwrap().push(owed);
        }
    }

    /// The sweeps owed, for the sequence harness to hold each to ending
    /// only once done or lifted.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn owed_sweeps(&self) -> Vec<Sweep> {
        let owed = self.offer_sweeps.lock().unwrap();
        owed.iter().map(|o| o.sweep.clone()).collect()
    }

    /// What the core keeps of friendships beside the store, as text: the
    /// sweeps owed, the withdrawals judged, the revocations installed and
    /// what the passes recorded, for a test to tell whether an act changed
    /// any of it.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn friend_state(&self) -> String {
        use std::collections::{BTreeMap, BTreeSet};
        let mut sweeps: Vec<String> = self
            .offer_sweeps
            .lock()
            .unwrap()
            .iter()
            .map(|o| format!("{:?} {} {}", o.sweep, o.failures, o.due))
            .collect();
        sweeps.sort();
        let judged: BTreeMap<_, _> = self
            .withdrawals_judged
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let revoked = {
            let r = self.revoked.read().unwrap();
            let set = |s: &std::collections::HashSet<[u8; 32]>| {
                s.iter().copied().collect::<BTreeSet<_>>()
            };
            let devices: BTreeSet<_> = r.published.devices.iter().copied().collect();
            let floors: BTreeMap<_, _> = r.published.floors.iter().map(|(k, v)| (*k, *v)).collect();
            format!(
                "{:?} {:?} {:?} {devices:?} {:?} {floors:?} {:?}",
                set(&r.local.identities),
                set(&r.local.devices),
                set(&r.published.identities),
                set(&r.published.unrevoked),
                set(&r.rotated),
            )
        };
        let reconciled = {
            let r = self.reconciled.lock().unwrap();
            let at: BTreeMap<_, _> = r.at.iter().map(|(k, v)| (*k, format!("{v:?}"))).collect();
            let generation: BTreeMap<_, _> = r.generation.iter().map(|(k, v)| (*k, *v)).collect();
            format!("{at:?} {generation:?} {} {:?}", r.cleared, r.next)
        };
        format!("{sweeps:?} {judged:?} {revoked} {reconciled}")
    }

    /// Whether what owed `sweep` still stands.
    fn still_owed(&self, sweep: &Sweep) -> bool {
        match sweep {
            // Linked again is the evidence, whatever the account may do.
            Sweep::Unlinked(fp) | Sweep::Unpresented(fp) => {
                let dir = self.directory.as_ref();
                return dir.is_none_or(|d| d.account_by_key(fp).is_none());
            }
            Sweep::Judge(..) | Sweep::Purge(_) => return true,
            _ => {}
        }
        // A registrar's lift is one only where the lists read cover the
        // identity: a key missing from a list that covers nothing of it
        // says nothing.
        let r = self.revoked.read().unwrap();
        let published =
            |identity: &[u8; 32], listed: bool| listed || !r.published.covered.contains(identity);
        match *sweep {
            Sweep::Presented {
                identity: None,
                device,
            }
            | Sweep::Device {
                device,
                operator: true,
                ..
            } => r.local.devices.contains(&device),
            Sweep::Presented {
                identity: Some(identity),
                device,
            }
            | Sweep::Device {
                identity: Some(identity),
                device,
                ..
            } => published(&identity, r.published.devices.contains(&(identity, device))),
            Sweep::Device { identity: None, .. } => true,
            Sweep::Identity {
                identity,
                operator: true,
            } => r.local.identities.contains(&identity),
            Sweep::Identity { identity, .. } => {
                published(&identity, r.published.identities.contains(&identity))
            }
            Sweep::Unlinked(_) | Sweep::Unpresented(_) | Sweep::Judge(..) | Sweep::Purge(_) => {
                unreachable!("answered above")
            }
        }
    }

    /// What `sweep` drops, read first, and each pair it names with which
    /// of its parties to tell, the revoked or unlinked one first.
    #[allow(clippy::type_complexity)]
    fn owed_by(
        &self,
        store: &Arc<dyn RelationshipStore>,
        sweep: &Sweep,
        wall: SystemTime,
    ) -> Result<(Part, Vec<(Mailbox, Mailbox, [bool; 2])>), StoreError> {
        Ok(match *sweep {
            Sweep::Device {
                identity, device, ..
            } => {
                let mut signed = Vec::new();
                let mut named = Vec::new();
                // Under the named key and each it rotated to, which an
                // outgoing offer moves with; the operator's, under any.
                let identities = match identity {
                    Some(i) => {
                        let next = self.chain_from(store, i)?;
                        let next = next.iter().map(|r| Fingerprint::of(&r.successor).0);
                        std::iter::once(i).chain(next).collect()
                    }
                    None => store.offerers(wall)?,
                };
                let mut offers = Vec::new();
                for i in identities {
                    offers.extend(store.offers_from(&i, wall)?.into_iter().map(|o| (i, o)));
                }
                for (identity, (other, o)) in offers {
                    let by = Offer::check(&o.offer, STORED, &[], zero_floor)
                        .ok()
                        .and_then(|o| DeviceCert::parse(&o.cert).ok())
                        .map(|c| Fingerprint::of(&c.device).0);
                    if by != Some(device) {
                        continue;
                    }
                    signed.push((identity, other));
                    if let (Some(a), Some(b)) =
                        (self.mailbox_of(&identity), self.mailbox_of(&other))
                    {
                        named.push((a, b, [true, true]));
                    }
                }
                (Part::DropOffers(signed), named)
            }
            Sweep::Identity { identity, .. } => {
                let named = self.counterparts_of(store, &identity, wall)?;
                let named = named.into_iter().map(|(me, o)| (me, o, [true, true]));
                (Part::DropOffersNaming(identity), named.collect())
            }
            Sweep::Unlinked(fp) => {
                let to = [self.mailbox_of(&fp).is_some(), true];
                let named = self.counterparts_of(store, &fp, wall)?;
                let named = named.into_iter().map(|(me, o)| (me, o, to));
                (Part::DropOffersNaming(fp), named.collect())
            }
            Sweep::Presented { .. }
            | Sweep::Unpresented(_)
            | Sweep::Judge(..)
            | Sweep::Purge(_) => unreachable!("not offers"),
        })
    }

    /// Each pair `fp` has a row about, or that has a request or an upgrade
    /// waiting for it, `fp`'s mailbox as its rows keep it first: every
    /// party a change to what stands between them affects.
    pub(crate) fn counterparts_of(
        &self,
        store: &Arc<dyn RelationshipStore>,
        fp: &[u8; 32],
        wall: SystemTime,
    ) -> Result<Vec<(Mailbox, Mailbox)>, StoreError> {
        let m = Mailbox::identified("", *fp);
        let mut out: Vec<(Mailbox, Mailbox)> = store
            .relationships(&m, wall)?
            .into_iter()
            .map(|r| (r.owner, r.other))
            .chain(
                store
                    .pending_in(&m, wall)?
                    .into_iter()
                    .chain(store.upgrades_to(&m, wall)?)
                    .map(|r| (r.other, r.owner)),
            )
            .collect();
        let key = |(_, b): &(Mailbox, Mailbox)| (b.login.clone(), b.fingerprint);
        out.sort_by_key(key);
        out.dedup_by_key(|p| key(p));
        Ok(out)
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
        self.sweep_offers(vec![Sweep::Unlinked(*fingerprint)]);
        let _writing = self.friend_writes();
        if let Err(e) = self.drop_unlinked_presentations(store, fingerprint) {
            warn!("relationships: dropping an unlinked account's presentations: {e}");
            let owed = OwedSweep::failed(Sweep::Unpresented(*fingerprint), 0, self.clock.unix());
            self.offer_sweeps.lock().unwrap().push(owed);
        }
    }

    /// What `fingerprint` presented, dropped, each pair as one step.
    fn drop_unlinked_presentations(
        &self,
        store: &Arc<dyn RelationshipStore>,
        fingerprint: &[u8; 32],
    ) -> Result<(), StoreError> {
        let made = store.presentations(fingerprint)?;
        for p in made.iter().filter(|p| p.presenter == *fingerprint) {
            let site = "an unlinked identity's presentation";
            let gone = self.drop_presented(site, store, &p.presenter, &p.other, &[p.presenter])?;
            for gone in &gone {
                self.orphan_judged_or_owed(store, gone);
            }
        }
        Ok(())
    }
}
