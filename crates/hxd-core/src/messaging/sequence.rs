//! Sequences of friendship acts by two linked accounts, run against a
//! real core on a given relationship store, conformance-style: each
//! store's tests call [`run`] with the steps a property test draws, and
//! every step is held to what a store transition must keep, whatever
//! failed in it:
//!
//! - an edge made active by presentations has evidence both ways while it
//!   is active;
//! - an edge that went inactive was told to both parties, and nothing is
//!   told as removed while the store still holds the friendship;
//! - each party's friend set in the roster is the store's;
//! - a request hold exists exactly where a removal or a withdrawal that
//!   ended both sides' evidence placed one;
//! - an edge is made active only over evidence held at the floors, and an
//!   accepted friendship takes the id a dropped presentation kept;
//! - a withdrawal kept stands at the floors, and one taken stays held, or
//!   one of its key cutting as far, that its signer's kept floor has not
//!   passed, until that floor rises: one that no longer stands never
//!   costs one that does;
//! - with nothing failing, a pass over both parties leaves no evidence
//!   that a reset shows is not held, and a second, with nothing of the
//!   first remembered, changes and tells nothing;
//! - each direction's pending state is one the model allows: a request,
//!   with the offer it carries, or an upgrade offer, never both; none
//!   beside a friendship or a block; and an upgrade offer on an edge a
//!   reset left inactive only while the record it was taken on stands;
//! - a session that did not ask for portable friendships is never told an
//!   offer, and, with nothing failing, shows a request from the other
//!   party exactly while the store holds one it may see;
//! - an ask with an offer that is answered, by a party with no friendship
//!   and nothing pending, is answered and told to it alike whatever the
//!   other party holds;
//! - every ask, plain or with an offer, from whatever the asker can see,
//!   is answered and told to the asker alike in a twin run where no
//!   `Reset` record ever makes an upgrade offer: what the other party
//!   holds never shows. The request ledger may differ, the answer may not.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hl_identity::friendship::Pair;
use hl_identity::{
    Acceptance, DeviceCert, DeviceEpoch, DeviceKey, Fingerprint, Friendship, IdentityKey, Offer,
    Withdrawal,
};
use sha2::{Digest, Sha256};

use super::{Key, Presented, RosterState};
use crate::access::bit;
use crate::identity_records::{KeptEpoch, MemoryRecordCache, RecordCache};
use crate::inbox::{Mailbox, MemoryStore};
use crate::relationships::failing::{Failing, READS};
use crate::relationships::{Presentation, RelationId, RelationshipStore, Requester};
use crate::roster::{AttachInfo, Event, InboxPolicy, Uid};
use crate::{
    AccessBits, AccountDirectory, Core, Events, IdentityTag, MessagingPolicy, Published,
    Revocations,
};

const LOGINS: [&str; 2] = ["alice", "bob"];
const DAY: u64 = 24 * 3600;

struct Person {
    id: IdentityKey,
    devices: Vec<(DeviceKey, Vec<u8>)>,
}

impl Person {
    /// Its first device certified in epoch 0, which a reset ends, and its
    /// second in epoch 1, which stays.
    fn new(seed: u8, now: u64) -> Self {
        let id = IdentityKey::from_seed(&[seed; 32]);
        let devices = (0..2u8)
            .map(|n| {
                let dev = DeviceKey::from_seed(&[seed * 16 + n + 1; 32]);
                let mut cert = DeviceCert::for_device(&id, &dev, now - 3600, 90 * 24 * 3600)
                    .expect("a certificate");
                cert.epoch = n.into();
                (dev, cert.sign(&id))
            })
            .collect();
        Person { id, devices }
    }

    fn fp(&self) -> [u8; 32] {
        self.id.fingerprint().0
    }

    fn device(&self, d: usize) -> [u8; 32] {
        Fingerprint::of(&self.devices[d].0.public()).0
    }

    fn offer(&self, d: usize, to: &Person, time: u64) -> Vec<u8> {
        let (key, cert) = &self.devices[d];
        Offer {
            from: self.id.public(),
            to: Fingerprint(to.fp()),
            time,
            expires: time + 24 * 3600,
            id: Sha256::digest(time.to_be_bytes()).as_slice()[..16]
                .try_into()
                .unwrap(),
            cert: cert.clone(),
        }
        .sign(key)
        .expect("an offer")
    }

    fn accept(&self, d: usize, offer: &[u8], time: u64) -> Vec<u8> {
        let (key, cert) = &self.devices[d];
        let acceptance = Acceptance {
            offer: Sha256::digest(offer).into(),
            from: self.id.public(),
            time,
            cert: cert.clone(),
        }
        .sign(key)
        .expect("an acceptance");
        Friendship::encode(offer, &acceptance)
    }

    fn withdraw(&self, d: usize, other: &Person, before: u64, time: u64) -> Vec<u8> {
        let (key, cert) = &self.devices[d];
        Withdrawal {
            from: self.id.public(),
            pair: Pair::new(Fingerprint(self.fp()), Fingerprint(other.fp())).hash(),
            party: None,
            before,
            time,
            cert: cert.clone(),
        }
        .sign(key)
        .expect("a withdrawal")
    }
}

/// The accounts, each linked or not and taking part or not, as a step
/// left them.
struct Directory(Mutex<Vec<(Mailbox, AccessBits)>>);

impl AccountDirectory for Directory {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| m.login == login)
            .map(|(m, _)| m.clone())
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| who.matches(&m.login, m.fingerprint.as_ref()))
            .map(|(_, a)| *a)
    }

    fn account_by_key(&self, fp: &[u8; 32]) -> Option<(Mailbox, AccessBits)> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| m.fingerprint == Some(*fp))
            .cloned()
    }
}

fn messaging_bits() -> AccessBits {
    AccessBits::empty()
        .with(bit::SEND_MSGS)
        .with(bit::MESSAGING)
}

/// One step, read from a number so a property test can shrink a sequence
/// of them.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// A friend request, with an offer or without.
    Ask {
        offer: bool,
    },
    /// Accept the other's request, with a friendship where it offered one.
    Answer {
        friendship: bool,
    },
    /// Present a friendship this run has seen.
    Present {
        k: usize,
    },
    /// Remove Friend (803), plain or with a withdrawal. Each withdrawal
    /// cuts at its time, or `early`, before the friendships made in the
    /// run.
    Remove {
        withdraw: bool,
        early: bool,
    },
    /// Block User (806)'s withdrawal, which blocks with it.
    BlockWithdrawal,
    Block,
    Unblock,
    PresentWithdrawal {
        early: bool,
    },
    /// Unlink the identity and link it again.
    Link,
    RemoveByKey,
    /// The messaging bit lost, or given back.
    Messaging,
    Revoke,
    /// The party reset its first device: a floor of 1 installed with no
    /// record, a record from before the run kept and installed, or a
    /// record dated now kept with nothing installed, which nothing judges
    /// by until an act does.
    Floor {
        how: u32,
    },
    /// Decline the other's request or upgrade offer.
    Decline,
    /// Remove Friend (803) carrying the caller's own offer: cancel it.
    Cancel,
    /// A registrar's list revokes the device.
    PublishDevice,
    /// A registrar's list freezes the identity, refused but not revoked.
    Freeze,
    /// A registrar's list revokes the identity.
    RevokeIdentity,
    /// The identity rotates to its successor key, once; with `into`, the
    /// other party has first presented a friendship it made with that
    /// successor elsewhere, so the rotation lands on a pair it holds.
    Rotate {
        into: bool,
    },
    /// The clock moved on by this much: past a request's or an offer's
    /// lapse, or a `Reset` record's.
    Clock {
        secs: u64,
    },
}

/// What fails while a step runs.
#[derive(Debug, Clone, Copy)]
enum Failure {
    None,
    /// The `k`-th store call.
    Call(usize),
    /// The `k`-th write.
    Write(usize),
}

impl Step {
    fn of(n: u32) -> (Step, usize, usize, Failure) {
        let (p, d, arg) = ((n >> 5) as usize & 1, (n >> 6) as usize & 1, n >> 7);
        // Weighted toward the acts on pending state and the endings that
        // make room for it: Ask 5/32, Answer 3/32, Remove, Unblock,
        // Present, Decline, Cancel and Clock 2/32 each (each clock move
        // 1/48), every other kind 1/32 (each way of rotating 1/64).
        let step = match n % 32 {
            0..=3 | 30 => Step::Ask {
                offer: arg & 1 == 1,
            },
            4..=6 => Step::Answer {
                friendship: arg & 1 == 1,
            },
            7 | 31 => Step::Present { k: arg as usize },
            8 | 9 => Step::Remove {
                withdraw: arg & 1 == 1,
                early: arg & 2 == 2,
            },
            10 | 12 => Step::Unblock,
            11 => Step::Revoke,
            13 => Step::RemoveByKey,
            14 => Step::PresentWithdrawal {
                early: arg & 1 == 1,
            },
            15 | 21 => Step::Clock {
                secs: [120, DAY, 31 * DAY][arg as usize % 3],
            },
            16 => Step::Block,
            17 | 23 => Step::Decline,
            18 => Step::Link,
            19 => Step::Floor { how: arg % 3 },
            20 => Step::Messaging,
            22 => Step::BlockWithdrawal,
            24 | 25 => Step::Cancel,
            26 => Step::PublishDevice,
            27 => Step::Freeze,
            28 => Step::RevokeIdentity,
            _ => Step::Rotate { into: arg & 1 == 1 },
        };
        // A quarter of the steps meet a failure somewhere in them.
        let failure = match n >> 27 {
            f @ 0..=3 => Failure::Write(1 + f as usize),
            4..=7 => Failure::Call(1 + (n >> 22) as usize % 24),
            _ => Failure::None,
        };
        (step, p, d, failure)
    }
}

/// What the store holds of the pair.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pairing {
    friendship: Option<RelationId>,
    /// Whether each party holds a presentation of the other with
    /// evidence, alice's first.
    evidence: [bool; 2],
    /// Whether each holds the other's requests, alice's first.
    held: [bool; 2],
    /// Whether each has a request to the other waiting, delivered.
    asking: [bool; 2],
    /// The ids the pair's presentations keep.
    kept: Vec<RelationId>,
    /// Each presentation with evidence, as `(presenter, hash, taken)`.
    rows: Vec<Row>,
}

type Row = ([u8; 32], [u8; 32], u64);

/// A key's resets, as `(epoch, time)`.
type Resets = Vec<(u64, u64)>;

fn row_of(p: &Presentation) -> Row {
    (p.presenter, p.hash, secs(p.taken))
}

fn secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Run {
    core: Arc<Core>,
    store: Arc<dyn RelationshipStore>,
    fail: Arc<Failing>,
    dir: Arc<Directory>,
    records: Arc<MemoryRecordCache>,
    people: [Person; 2],
    /// Each party's two device sessions.
    sessions: [[(Uid, Events); 2]; 2],
    /// Each party's session that did not ask for portable friendships,
    /// and whether it shows a request from the other.
    plain: [(Uid, Events); 2],
    shows: [bool; 2],
    /// Whether each party's friendships sessions show a request or an
    /// upgrade offer from the other, and the entry each was last told.
    views: [[(bool, Option<RosterState>); 2]; 2],
    /// What the registrars' lists hold beside the floors.
    listed: Published,
    /// Each party's successor key, once it has rotated to it.
    rotated: [bool; 2],
    /// Each party's keys before its rotation, with the resets they kept.
    former: [Vec<(Person, Resets)>; 2],
    /// Sessions made this step, which read what is as they start rather
    /// than being told it.
    fresh: HashSet<Uid>,
    /// What an ask this step was answered.
    asked: Option<Result<RosterState, super::MessagingError>>,
    /// The last step as its actor saw it, for the twin to compare.
    seen: Option<Seen>,
    /// The sessions a floor ended.
    ended: HashSet<Uid>,
    /// The floors installed, and each party's reset records kept, as
    /// `(epoch, time)`.
    floors: HashMap<[u8; 32], u64>,
    resets: [Vec<(u64, u64)>; 2],
    base: u64,
    friendships: Vec<Vec<u8>>,
    offers: [Option<Vec<u8>>; 2],
    revoked: HashSet<[u8; 32]>,
    /// Ids that were active with evidence both ways.
    portable: HashSet<RelationId>,
    /// The withdrawals answered as taken, with their signer, while one
    /// that stands holds as far.
    withdrawn: Vec<(usize, Vec<u8>)>,
    /// The withdrawal a removal or a block carried this step.
    carried: Option<(usize, Vec<u8>)>,
    /// The holds this run expects, alice's first.
    holds: [bool; 2],
}

/// An ask's answer, and what its actor's sessions were told.
type Outcome = (
    Option<Result<RosterState, super::MessagingError>>,
    Vec<Vec<RosterState>>,
);

/// A step as its actor saw it: whether it was an ask, what the actor
/// could see of the pair before it (a friendship, its own request, one
/// from the other shown it), and, where nothing failed, the answer and
/// what its sessions were told.
#[derive(Debug, PartialEq)]
struct Seen {
    ask: bool,
    visible: (bool, bool, bool),
    outcome: Option<Outcome>,
}

fn mailbox(login: &str, p: &Person) -> Mailbox {
    Mailbox::identified(login, p.fp())
}

impl Run {
    fn new(store: Arc<dyn RelationshipStore>, start: u32) -> Self {
        let fail = Arc::new(Failing::new(store.clone()));
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let people = [Person::new(1, base), Person::new(2, base)];
        let records = Arc::new(MemoryRecordCache::default());
        let dir = Arc::new(Directory(Mutex::new(
            LOGINS
                .iter()
                .zip(&people)
                .map(|(l, p)| (mailbox(l, p), messaging_bits()))
                .collect(),
        )));
        let core = Arc::new(
            Core::new()
                .with_inbox(
                    Arc::new(MemoryStore::new()),
                    dir.clone(),
                    InboxPolicy::default(),
                )
                .with_relationships(fail.clone())
                .with_messaging(MessagingPolicy {
                    enabled: true,
                    presence_debounce: Duration::ZERO,
                    // Some runs, friends by presentations alone, at the
                    // daily bound from the start.
                    requests_per_day: if start % 6 == 0 { 0 } else { 20 },
                    ..MessagingPolicy::default()
                })
                .with_record_cache(records.clone()),
        );
        let sessions =
            [0, 1].map(|p| [0, 1].map(|d| attach(&core, LOGINS[p], &people[p], d, true)));
        let plain = [0, 1].map(|p| {
            let (uid, rx) = attach(&core, LOGINS[p], &people[p], 0, false);
            core.friends_roster(uid).expect("a roster");
            (uid, rx)
        });
        // Two friendships made elsewhere a minute before the run.
        let friendships: Vec<Vec<u8>> = (0..2)
            .map(|d| {
                let o = people[0].offer(d, &people[1], base - 60 - d as u64);
                people[1].accept(d, &o, base - 60)
            })
            .collect();
        // Friends from the start, so that every sequence has an edge to
        // end: by what each presented, or by a plain request with what
        // Alice alone presented, or with nothing presented.
        let (alice, bob) = (sessions[0][0].0, sessions[1][0].0);
        if start % 3 != 0 {
            assert!(core.friend_ask(alice, LOGINS[1], None, None).is_ok());
            assert!(core.friend_answer(bob, LOGINS[0], true, None).is_ok());
        }
        let presenting: &[Uid] = match start % 3 {
            0 => &[alice, bob],
            1 => &[alice],
            _ => &[],
        };
        for uid in presenting {
            let f = friendships[0].clone();
            assert!(core.friendships_present(*uid, vec![], vec![f]).is_ok());
        }
        Run {
            core,
            store,
            fail,
            dir,
            records,
            people,
            sessions,
            plain,
            shows: [false, false],
            views: Default::default(),
            listed: Published::default(),
            rotated: [false, false],
            former: Default::default(),
            fresh: HashSet::new(),
            asked: None,
            seen: None,
            ended: HashSet::new(),
            floors: HashMap::new(),
            resets: [Vec::new(), Vec::new()],
            base,
            friendships,
            offers: [None, None],
            revoked: HashSet::new(),
            portable: HashSet::new(),
            withdrawn: Vec::new(),
            carried: None,
            holds: [false, false],
        }
    }

    fn mailbox(&self, p: usize) -> Mailbox {
        mailbox(LOGINS[p], &self.people[p])
    }

    fn pairing(&self) -> Pairing {
        let now = self.core.clock.wall();
        let (a, b) = (self.mailbox(0), self.mailbox(1));
        let (fa, fb) = (self.people[0].fp(), self.people[1].fp());
        let row = |x: &Mailbox, y: &Mailbox| self.store.relationship(x, y, now).unwrap();
        let (ab, ba) = (row(&a, &b), row(&b, &a));
        let friendship = ab.as_ref().and_then(|r| r.friendship);
        assert_eq!(
            friendship,
            ba.as_ref().and_then(|r| r.friendship),
            "one id for the pair"
        );
        let evidence = |p: &[u8; 32], q: &[u8; 32]| {
            let pres = self.store.presentation(p, q).unwrap();
            pres.is_some_and(|p| p.evidence())
        };
        let held = |x: &Mailbox, y: &Mailbox| {
            self.store
                .is_held(x, &Requester::Account(y.clone()), now)
                .unwrap()
        };
        let asking = |r: &Option<crate::relationships::Relationship>| {
            r.as_ref()
                .and_then(|r| r.pending_out.as_ref())
                .is_some_and(|p| p.delivered)
        };
        Pairing {
            friendship,
            evidence: [evidence(&fa, &fb), evidence(&fb, &fa)],
            held: [held(&a, &b), held(&b, &a)],
            asking: [asking(&ab), asking(&ba)],
            kept: self.presentations().iter().filter_map(|p| p.edge).collect(),
            rows: self
                .presentations()
                .iter()
                .filter(|p| p.evidence())
                .map(row_of)
                .collect(),
        }
    }

    /// The pair's presentations, alice's first.
    fn presentations(&self) -> Vec<Presentation> {
        let (fa, fb) = (self.people[0].fp(), self.people[1].fp());
        [(fa, fb), (fb, fa)]
            .iter()
            .filter_map(|(p, q)| self.store.presentation(p, q).unwrap())
            .collect()
    }

    /// Whether `p`'s friendship is held at the floors and records this run
    /// installed and kept, judged from first principles: each half stands
    /// at or above its signer's floor, or was reset by a record kept after
    /// the friendship was first taken here, by either party.
    fn held(&self, p: &Presentation, all: &[Presentation]) -> bool {
        self.judged(p, all) == Some(true)
    }

    /// [`Self::held`], or `None` where a half is below its floor and no
    /// record kept shows when it was reset.
    fn judged(&self, p: &Presentation, all: &[Presentation]) -> Option<bool> {
        let Some(Ok(f)) = p
            .friendship
            .as_deref()
            .map(|b| Friendship::check(b, u64::MAX, &[], |_| 0))
        else {
            return Some(false);
        };
        let taken = all
            .iter()
            .filter(|x| x.hash == p.hash && x.evidence())
            .map(|x| secs(x.taken))
            .min()
            .expect("p is evidence");
        let halves: Vec<Option<bool>> = [&f.offer.cert, &f.acceptance.cert]
            .iter()
            .map(|cert| {
                let cert = DeviceCert::parse(cert).expect("a certificate");
                let (who, kept) = self.signer(&cert.identity).expect("one of the pair");
                let installed = self.floors.get(&who).copied();
                let floor = kept.iter().map(|(e, _)| *e).chain(installed).max();
                if floor.is_none_or(|floor| cert.epoch >= floor) {
                    return Some(true);
                }
                let reset = kept
                    .iter()
                    .filter(|(e, _)| *e > cert.epoch)
                    .map(|(_, t)| *t)
                    .min();
                reset.map(|at| taken < at)
            })
            .collect();
        match () {
            _ if halves.contains(&Some(false)) => Some(false),
            _ if halves.contains(&None) => None,
            _ => Some(true),
        }
    }

    /// What a pass can change: the pair, its withdrawals, and the offers
    /// either way.
    fn reconcilable(&self) -> impl PartialEq + std::fmt::Debug {
        let wall = self.core.clock.wall();
        let (fa, fb) = (self.people[0].fp(), self.people[1].fp());
        let offers: Vec<_> = [(fa, fb), (fb, fa)]
            .iter()
            .map(|(p, q)| self.store.offer(p, q, wall).unwrap().map(|o| o.offer))
            .collect();
        (self.pairing(), self.signed(), offers)
    }

    /// With nothing failing, a sweep's tick over the floors installed:
    /// what it leaves, and what a tick after a restart makes of that.
    fn quiescent(&mut self, what: &str) {
        let listed: Vec<[u8; 32]> = self.floors.keys().copied().collect();
        let before = self.pairing();
        self.core.reconcile_due(listed.iter().copied());
        let after = self.pairing();
        let told = self.told();
        let ended = before.friendship.is_some() && after.friendship != before.friendship;
        self.told_once(&format!("{what}, then a pass"), &after, ended, &told);
        let wall = self.core.clock.wall();
        for (q, login) in LOGINS.iter().enumerate() {
            let (me, them) = (self.people[q].fp(), self.people[1 - q].fp());
            let offers = self.store.offers_from(&me, wall).unwrap();
            let Some((_, o)) = offers.into_iter().find(|(to, _)| *to == them) else {
                continue;
            };
            let o = Offer::check(&o.offer, u64::MAX, &[], |_| 0).expect("an offer kept");
            let cert = DeviceCert::parse(&o.cert).expect("a certificate");
            // An offer kept through a rotation is its signer's, the key
            // rotated away from.
            let (signer, kept) = self.signer(&cert.identity).expect("one of the pair");
            let floor = self.floors.get(&signer).copied().unwrap_or(0);
            let kept = kept.iter().map(|(e, _)| *e).max().unwrap_or(0);
            assert!(
                cert.epoch >= floor.max(kept),
                "{what}: a pass left {login}'s offer below the floor"
            );
        }
        let all = self.presentations();
        for p in all.iter().filter(|p| p.evidence()) {
            assert!(
                self.judged(p, &all) != Some(false),
                "{what}: a pass left {:?}, which is not held",
                row_of(p)
            );
        }
        let before = self.reconcilable();
        self.core.unjudge_all();
        self.core.reconcile_due(listed);
        assert_eq!(self.reconcilable(), before, "{what}: a pass judged again");
        let told = self.told();
        assert!(
            told.iter().flatten().all(Vec::is_empty),
            "{what}: a pass judged again told {told:?}"
        );
    }

    /// Each session told of a removal at most once and only where the
    /// store holds none, and, where an ending was `owed`, told of it once.
    fn told_once(
        &self,
        what: &str,
        after: &Pairing,
        owed: bool,
        told: &[[Vec<RosterState>; 2]; 2],
    ) {
        for (q, sessions) in told.iter().enumerate() {
            for (d, told) in sessions.iter().enumerate() {
                let uid = self.sessions[q][d].0;
                if self.ended.contains(&uid) || self.fresh.contains(&uid) {
                    continue;
                }
                let removed = told.iter().filter(|s| **s == RosterState::Removed).count();
                assert!(removed <= 1, "{what}: {} told twice: {told:?}", LOGINS[q]);
                if removed > 0 {
                    assert_eq!(
                        after.friendship, None,
                        "{what}: {} told of a removal the store does not hold",
                        LOGINS[q]
                    );
                }
                if owed && self.takes_part(q) {
                    let ending = told.iter().filter(|s| **s != RosterState::Accepted);
                    assert_eq!(
                        ending.count(),
                        1,
                        "{what}: {} told of the ending: {told:?}",
                        LOGINS[q]
                    );
                }
            }
        }
    }

    /// Whether `p`'s account takes part now, and so can be told anything.
    fn takes_part(&self, p: usize) -> bool {
        let fp = self.people[p].fp();
        self.dir
            .account_by_key(&fp)
            .is_some_and(|(_, access)| access.has(bit::MESSAGING))
    }

    fn act(&mut self, step: Step, p: usize, d: usize) -> bool {
        let core = self.core.clone();
        let (uid, other) = (self.sessions[p][d].0, LOGINS[1 - p]);
        let (me, them) = (&self.people[p], &self.people[1 - p]);
        let now = core.clock.unix();
        let base = self.base;
        let cut = |early: bool| if early { base - 30 } else { now };
        match step {
            Step::Ask { offer } => {
                let o = offer.then(|| me.offer(d, them, now));
                let asked = core.friend_ask(uid, other, None, o.clone());
                if asked.is_ok() {
                    self.offers[p] = o;
                }
                let ok = asked.is_ok();
                self.asked = Some(asked);
                ok
            }
            Step::Answer { friendship } => {
                let f = self.offers[1 - p]
                    .as_ref()
                    .filter(|_| friendship)
                    .map(|o| me.accept(d, o, now));
                if let Some(f) = &f {
                    self.friendships.push(f.clone());
                }
                core.friend_answer(uid, other, true, f).is_ok()
            }
            Step::Decline => core.friend_answer(uid, other, false, None).is_ok(),
            // Inside the certificates' days, so that a device can still
            // sign.
            Step::Clock { secs } => {
                if now + secs < base + 80 * DAY {
                    core.clock.advance(Duration::from_secs(secs));
                }
                let wall = core.clock.wall();
                let _ = self
                    .store
                    .cleanup(wall, wall - Duration::from_secs(DAY), 1000);
                true
            }
            Step::Present { k } => {
                let f = self.friendships[k % self.friendships.len()].clone();
                core.friendships_present(uid, vec![], vec![f]).is_ok()
            }
            Step::Remove { withdraw, early } => {
                let w = withdraw.then(|| me.withdraw(d, them, cut(early), now));
                self.carried = w.clone().map(|w| (p, w));
                core.friend_unfriend(uid, other, w).is_ok()
            }
            Step::BlockWithdrawal => {
                let w = me.withdraw(d, them, now, now);
                self.carried = Some((p, w.clone()));
                core.block_withdrawing(uid, other, w).is_ok()
            }
            Step::Block => core.inbox_block(uid, other, true).is_ok(),
            Step::Unblock => core.inbox_block(uid, other, false).is_ok(),
            Step::PresentWithdrawal { early } => {
                let w = me.withdraw(d, them, cut(early), now);
                let taken = core.friendships_present(uid, vec![w.clone()], vec![]);
                if taken
                    .as_ref()
                    .is_ok_and(|(t, _)| t[0].outcome == Presented::Ok)
                {
                    self.withdrawn.push((p, w));
                }
                taken.is_ok()
            }
            Step::Link => {
                // Linked again at once, so no row is ever keyed by the
                // bare login, which a link would have to claim.
                let fp = me.fp();
                self.dir.0.lock().unwrap()[p].0.fingerprint = None;
                core.friendships_unlinked(&fp);
                self.dir.0.lock().unwrap()[p].0.fingerprint = Some(fp);
                true
            }
            Step::RemoveByKey => core.friend_remove_by_key(uid, &them.fp(), None).is_ok(),
            Step::Messaging => {
                let mut accounts = self.dir.0.lock().unwrap();
                let access = &mut accounts[p].1;
                *access = if access.has(bit::MESSAGING) {
                    AccessBits::empty().with(bit::SEND_MSGS)
                } else {
                    messaging_bits()
                };
                true
            }
            Step::Revoke => {
                self.revoked.insert(me.device(d));
                let ended = core.set_revocations(Revocations {
                    devices: self.revoked.clone(),
                    ..Default::default()
                });
                self.ended.extend(ended.into_iter().map(|(uid, _)| uid));
                true
            }
            Step::Cancel => match self.offers[p].clone() {
                Some(o) => core.friend_cancel_offer(uid, other, &o).is_ok(),
                None => false,
            },
            Step::PublishDevice => {
                self.listed.devices.insert((me.fp(), me.device(d)));
                self.publish();
                true
            }
            Step::Freeze => {
                self.listed.unrevoked.insert(me.fp());
                self.publish();
                true
            }
            Step::RevokeIdentity => {
                self.listed.identities.insert(me.fp());
                self.publish();
                true
            }
            Step::Rotate { into } => self.rotate(p, into),
            Step::Floor { how } => {
                let fp = me.fp();
                if how != 0 {
                    let time = if how == 1 { self.base - 120 } else { now };
                    let record = DeviceEpoch {
                        identity: me.id.public(),
                        epoch: 1,
                        time,
                    }
                    .sign(&me.id)
                    .expect("a record");
                    let kept = KeptEpoch {
                        epoch: 1,
                        time,
                        record,
                    };
                    self.records.keep_epoch(&fp, &kept).expect("kept");
                    self.resets[p].push((1, time));
                }
                if how != 2 {
                    self.floors.insert(fp, 1);
                    self.publish();
                }
                true
            }
        }
    }

    /// Install what the lists hold, the floors among it, and note the
    /// sessions it ended.
    fn publish(&mut self) {
        let mut list = self.listed.clone();
        list.floors = self.floors.clone();
        list.covered = self
            .floors
            .keys()
            .chain(&list.identities)
            .chain(&list.unrevoked)
            .chain(list.devices.iter().map(|(i, _)| i))
            .copied()
            .collect();
        let ended = self.core.set_published_revocations(list);
        self.ended.extend(ended.into_iter().map(|(uid, _)| uid));
    }

    /// `p` rotates to its successor key, its account linking it and its
    /// sessions made again under it; with `into`, after the other party
    /// presented a friendship it made with the successor elsewhere.
    fn rotate(&mut self, p: usize, into: bool) -> bool {
        if self.rotated[p] {
            return false;
        }
        let now = self.core.clock.unix();
        let next = Person::new(3 + p as u8, self.base);
        if into {
            let (q, them) = (1 - p, &self.people[1 - p]);
            let o = next.offer(1, them, now - 30);
            let f = them.accept(1, &o, now - 30);
            let uid = self.sessions[q][1].0;
            let _ = self.core.friendships_present(uid, vec![], vec![f]);
        }
        let me = &self.people[p];
        let record = hl_identity::Rotation {
            identity: me.id.public(),
            successor: next.id.public(),
            time: now,
            next: None,
        }
        .sign(&me.id, &next.id)
        .expect("a rotation");
        let (from, to) = (me.fp(), next.fp());
        self.dir.0.lock().unwrap()[p].0.fingerprint = Some(to);
        self.core.keep_rotation_record(&record);
        // One that fails, its record kept, is made again with nothing
        // failing, as the successor's next login would, so that what
        // follows has one key to judge by; what follows is that login.
        let made = self.core.rotate_identity(&from, &to);
        self.fail.fail_nth(0);
        if made.is_err() {
            self.core
                .rotate_identity(&from, &to)
                .expect("a rotation made again");
        }
        self.rotated[p] = true;
        for (uid, _) in self.sessions[p].iter().chain([&self.plain[p]]) {
            self.ended.insert(*uid);
            self.core.end_session(*uid);
        }
        let old = std::mem::replace(&mut self.people[p], next);
        let resets = std::mem::take(&mut self.resets[p]);
        self.former[p].push((old, resets));
        self.withdrawn.retain(|(q, _)| *q != p);
        self.offers[p] = None;
        let sessions = [0, 1].map(|d| attach(&self.core, LOGINS[p], &self.people[p], d, true));
        let plain = attach(&self.core, LOGINS[p], &self.people[p], 0, false);
        for (uid, _) in sessions.iter().chain([&plain]) {
            self.core.friends_roster(*uid).expect("a roster");
        }
        self.fresh
            .extend(sessions.iter().chain([&plain]).map(|(uid, _)| *uid));
        self.sessions[p] = sessions;
        self.plain[p] = plain;
        self.resync(p);
        true
    }

    /// What `q`'s sessions show taken from the store, for sessions made
    /// now or a step nothing could be judged by.
    fn resync(&mut self, q: usize) {
        let (shown, upgrade, friends) = self.expected(q);
        self.shows[q] = shown;
        for d in 0..2 {
            self.views[q][d] = (shown || upgrade, friends.then_some(RosterState::Accepted));
        }
    }

    /// For `q`: whether a request from the other is held that it may see,
    /// whether the other's upgrade offer waits for it off a friendship, and
    /// whether they are friends.
    fn expected(&self, q: usize) -> (bool, bool, bool) {
        let now = self.core.clock.wall();
        let (me, them) = (self.mailbox(q), self.mailbox(1 - q));
        let shown = self
            .store
            .pending_in(&me, now)
            .unwrap()
            .iter()
            .any(|r| r.owner.login == LOGINS[1 - q]);
        let friends = self
            .store
            .relationship(&me, &them, now)
            .unwrap()
            .is_some_and(|r| r.friendship.is_some());
        let (x, y) = (self.people[1 - q].fp(), self.people[q].fp());
        let upgrade = !friends && self.store.offer(&x, &y, now).unwrap().is_some();
        (shown, upgrade, friends)
    }

    /// What each session of each party was told of the other this step,
    /// alice's first.
    fn told(&mut self) -> [[Vec<RosterState>; 2]; 2] {
        for (q, (_, rx)) in self.plain.iter_mut().enumerate() {
            while let Ok(se) = rx.try_recv() {
                match se.event {
                    Event::FriendRequest { login, offer, .. } if login == LOGINS[1 - q] => {
                        assert!(offer.is_none(), "{} told an offer", LOGINS[q]);
                        self.shows[q] = true;
                    }
                    Event::FriendEntry(e) if e.login == LOGINS[1 - q] => {
                        assert!(e.offer.is_none(), "{} told an offer on an entry", LOGINS[q]);
                        self.shows[q] = e.state == RosterState::PendingIn;
                    }
                    _ => {}
                }
            }
        }
        let mut out: [[Vec<RosterState>; 2]; 2] = Default::default();
        for (p, sessions) in self.sessions.iter_mut().enumerate() {
            for (d, (_, rx)) in sessions.iter_mut().enumerate() {
                while let Ok(se) = rx.try_recv() {
                    match se.event {
                        Event::FriendEntry(e) if e.login == LOGINS[1 - p] => {
                            out[p][d].push(e.state);
                            self.views[p][d] = (e.state == RosterState::PendingIn, Some(e.state));
                        }
                        // An upgrade offer beside a friendship is shown on
                        // the friend's entry, never as a request.
                        Event::FriendRequest { login, .. }
                            if login == LOGINS[1 - p]
                                && self.views[p][d].1 != Some(RosterState::Accepted) =>
                        {
                            self.views[p][d].0 = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }

    fn step(&mut self, n: u32, p: usize) {
        self.fresh.clear();
        self.told();
        let (step, _, d, failure) = Step::of(n);
        let before = self.pairing();
        let signed_before = self.signed();
        // Whether a removal or a block would name the other party: one
        // that blocked it, or takes no part, is answered as no account.
        let (me, them) = (self.mailbox(p), self.mailbox(1 - p));
        let named = self.takes_part(1 - p) && !self.store.is_blocked(&them, &me).unwrap();
        match failure {
            Failure::None => {}
            Failure::Call(k) => self.fail.fail_nth(k),
            Failure::Write(k) => self.fail.fail_nth_write(k),
        }
        // Whether the party has nothing to the other that its own sessions
        // see: what an ask's answer may depend on.
        let wall = self.core.clock.wall();
        let mine = self
            .store
            .relationship(&me, &them, wall)
            .unwrap()
            .and_then(|r| r.pending_out)
            .is_some();
        let shown = self
            .store
            .pending_in(&me, wall)
            .unwrap()
            .iter()
            .any(|r| r.owner.login == LOGINS[1 - p]);
        let visible = (before.friendship.is_some(), mine, shown);
        let free = before.friendship.is_none() && !mine;
        let predecessor = self.names_a_predecessor();
        let ok = self.act(step, p, d);
        self.fail.fail_nth(0);
        self.core.clock.advance(Duration::from_secs(1));
        let after = self.pairing();
        let told = self.told();
        // A failed read can cost an ending its tell, never a tell its
        // ending.
        let failed = self.fail.failed();
        let read_failed = failed.is_some_and(|m| READS.contains(&m));
        let what = format!("{step:?} by {} on device {d}, {failure:?}", LOGINS[p]);

        // An ask with an offer, from a party with nothing to the other,
        // answered and told alike whether or not it was taken as an
        // upgrade offer; the request ledger and bounds aside, which differ
        // by design.
        let asked = self.asked.take();
        self.seen = Some(Seen {
            ask: matches!(step, Step::Ask { .. }),
            visible,
            outcome: failed.is_none().then(|| (asked, told[p].to_vec())),
        });
        if let (Step::Ask { offer: true }, Some(Ok(answer))) = (step, asked) {
            if free && failed.is_none() {
                assert_eq!(answer, RosterState::PendingOut, "{what}: answered");
                for (q, told) in told[p].iter().enumerate() {
                    if !self.ended.contains(&self.sessions[p][q].0) {
                        assert_eq!(
                            told,
                            &[RosterState::PendingOut],
                            "{what}: told {}",
                            LOGINS[p]
                        );
                    }
                }
            }
        }

        // An edge made active by presentations keeps its evidence both
        // ways while it is active; one a request made active again under
        // its id, beside one party's alone, is local.
        let accepted =
            matches!(step, Step::Answer { friendship: true }) && self.offers[1 - p].is_some();
        let requested = matches!(step, Step::Ask { .. } | Step::Answer { .. }) && !accepted;
        if let Some(id) = after.friendship {
            if requested && before.friendship.is_none() && after.evidence != [true, true] {
                self.portable.remove(&id);
            }
            if after.evidence == [true, true] {
                self.portable.insert(id);
            }
            assert!(
                !self.portable.contains(&id) || after.evidence == [true, true],
                "{what}: edge {id} active without its evidence: {before:?} -> {after:?}"
            );
        }

        // An ending is told to each session of both once, a removal only
        // once committed, and only what removes or withdraws, or a
        // presentation, which judges the other party's (§6), ends an edge
        // that was not its presentations' alone.
        let ended = before.friendship.is_some() && after.friendship != before.friendship;
        let ends = matches!(
            step,
            Step::Remove { .. }
                | Step::BlockWithdrawal
                | Step::Block
                | Step::PresentWithdrawal { .. }
                | Step::RemoveByKey
                | Step::Present { .. }
        ) || (matches!(
            step,
            Step::Link
                | Step::Revoke
                | Step::Floor { .. }
                | Step::PublishDevice
                | Step::RevokeIdentity
                | Step::Rotate { .. }
        ) && before.evidence == [true, true]);
        assert!(
            !ended || ends,
            "{what}: ended what it may not: {before:?} -> {after:?}"
        );
        self.told_once(&what, &after, ended && !read_failed, &told);

        // An active edge stands on held evidence wherever a step made it
        // active, made it portable or wrote evidence for it, and an
        // accepted friendship takes the id a dropped presentation kept.
        if let Some(id) = after.friendship {
            let granted = before.friendship.is_none()
                || (before.evidence != [true, true] && after.evidence == [true, true]);
            let all = self.presentations();
            // A rotation moves rows onto the successor's key: moved, not
            // written.
            let moving = matches!(step, Step::Rotate { .. });
            for pres in all.iter().filter(|p| p.evidence()) {
                let written = !moving && !before.rows.contains(&row_of(pres));
                assert!(
                    !(granted || written) || self.held(pres, &all),
                    "{what}: active over {pres:?}, which is not held"
                );
            }
            let reused = !accepted
                || before.friendship.is_some()
                || after.evidence != [true, true]
                || before.kept.is_empty()
                || before.kept.contains(&id);
            assert!(reused, "{what}: made {id} over kept {:?}", before.kept);
        }

        // The roster's friend sets are the store's.
        for (q, login) in LOGINS.iter().enumerate() {
            let m = self.mailbox(q);
            let stored: HashSet<Key> = self
                .store
                .relationships(&m, self.core.clock.wall())
                .unwrap()
                .into_iter()
                .filter(|r| r.friendship.is_some() && r.blocked_at.is_none())
                .map(|r| Key::of(&r.other))
                .collect();
            let roster = self.core.roster.lock().unwrap();
            let shown = roster.presences.by.get(&Key::of(&m)).map(|e| &e.friends);
            assert_eq!(
                shown.cloned().unwrap_or_default(),
                stored,
                "{what}: {login}'s friends in the roster"
            );
        }

        // A hold where a removal or a withdrawal that ended both sides'
        // evidence placed one, and nowhere else.
        let holding = matches!(
            step,
            Step::Remove { .. }
                | Step::BlockWithdrawal
                | Step::PresentWithdrawal { .. }
                | Step::RemoveByKey
        );
        let left = (0..2).any(|q| before.evidence[q] && after.evidence[q]);
        if holding && ended && !left {
            self.holds[p] = true;
        }
        let declined = matches!(step, Step::Remove { .. })
            && before.friendship.is_none()
            && !before.asking[p]
            && before.asking[1 - p];
        if declined && ok {
            self.holds[p] = true;
        }
        // A decline of a request or an upgrade offer holds its sender, in
        // the one step that ends it, whatever failed after.
        if matches!(step, Step::Decline) && ok && before.asking[1 - p] {
            self.holds[p] = true;
        }
        // A hold lapses with time, and only with it.
        if let Step::Clock { .. } = step {
            for q in 0..2 {
                self.holds[q] &= after.held[q];
            }
        }
        // A withdrawal by a successor's key names the successor's pair, and
        // what it cuts of a friendship naming a predecessor's is not
        // modeled here (a follow-up of its own): that hold alone is taken
        // as the store has it.
        let withdrawing = matches!(
            step,
            Step::Remove { withdraw: true, .. }
                | Step::BlockWithdrawal
                | Step::PresentWithdrawal { .. }
        );
        if withdrawing && predecessor {
            self.holds[p] = after.held[p];
        }
        assert_eq!(
            after.held, self.holds,
            "{what}: holds, {before:?} -> {after:?}"
        );

        // A withdrawal kept stands, and one that stands by its signer's
        // kept floor is never lost to one that does not.
        let signed = self.signed();
        for (q, epoch, ..) in signed.iter().filter(|w| !signed_before.contains(w)) {
            let floor = self.floors.get(&self.people[*q].fp()).copied();
            assert!(
                *epoch >= floor.unwrap_or(0).max(self.kept_floor(*q)),
                "{what}: kept {}'s withdrawal below the floor",
                LOGINS[*q]
            );
        }
        // One a removal of a friend or a block took, whatever it ended.
        let took = match step {
            Step::Remove { .. } => before.friendship.is_some(),
            _ => named,
        };
        if let Some(w) = self.carried.take() {
            if ok && took && failed.is_none() {
                self.withdrawn.push(w);
            }
        }
        let mut withdrawn = std::mem::take(&mut self.withdrawn);
        let covered = |rows: &[(usize, u64, u64, Vec<u8>)], (q, w): &(usize, Vec<u8>)| {
            let (_, epoch, cutoff, _) = self.signed_of(*q, w);
            let kept = self.kept_floor(*q);
            epoch >= kept
                && rows
                    .iter()
                    .any(|(r, e, b, _)| r == q && *e >= kept && *b >= cutoff)
        };
        // A floor rising forgives only what no row it left standing held.
        if matches!(step, Step::Floor { how } if how != 0) {
            withdrawn.retain(|w| covered(&signed, w) || covered(&signed_before, w));
        }
        for w in &withdrawn {
            assert!(
                covered(&signed, w),
                "{what}: {}'s withdrawal lost: {signed:?}",
                LOGINS[w.0]
            );
        }
        self.withdrawn = withdrawn;
        self.quiescent(&what);
        self.legal(&what);
        // A blocker's own client knows what its block ended, and a request
        // lapses without a notice (instant-messaging 3): neither is told.
        let blocking = matches!(step, Step::Block | Step::BlockWithdrawal).then_some(p);
        let lapsing = matches!(step, Step::Clock { .. });
        self.shown(&what, failed.is_none() && !lapsing, blocking);
    }

    /// Each direction's pending state one the model allows.
    fn legal(&self, what: &str) {
        let now = self.core.clock.wall();
        let blocked = (0..2).any(|q| {
            self.store
                .is_blocked(&self.mailbox(q), &self.mailbox(1 - q))
                .unwrap()
        });
        for (q, who) in LOGINS.iter().enumerate() {
            let (me, them) = (self.mailbox(q), self.mailbox(1 - q));
            let (x, y) = (self.people[q].fp(), self.people[1 - q].fp());
            let row = self.store.relationship(&me, &them, now).unwrap();
            let friends = row.as_ref().is_some_and(|r| r.friendship.is_some());
            let pending = row.and_then(|r| r.pending_out);
            let upgrade = self.store.offer(&x, &y, now).unwrap();
            let record = |a, b| {
                self.store
                    .presentation(a, b)
                    .unwrap()
                    .and_then(|p: Presentation| p.reset)
            };
            if friends || blocked {
                assert!(
                    pending.is_none(),
                    "{what}: {who}'s request beside a friendship or a block"
                );
            }
            if blocked {
                assert!(
                    upgrade.is_none(),
                    "{what}: {who}'s upgrade offer beside a block"
                );
            }
            if blocked {
                assert!(record(&y, &x).is_none(), "{what}: a record beside a block");
            }
            match &pending {
                // Its offer may lapse before its pending out, which lapses
                // as a request would; the record stays while either does.
                Some(p) if p.upgrade => {
                    assert!(
                        p.offer.is_none(),
                        "{what}: {who}'s upgrade with a request's offer"
                    );
                    assert!(
                        record(&y, &x).is_some(),
                        "{what}: {who}'s upgrade without the record it was taken on"
                    );
                }
                Some(_) => assert!(
                    upgrade.is_none(),
                    "{what}: {who}'s request beside an upgrade"
                ),
                None => assert!(
                    friends || upgrade.is_none(),
                    "{what}: {who}'s upgrade offer with no pending out"
                ),
            }
        }
    }

    /// Each session that did not ask for portable friendships shows a
    /// request from the other party exactly while the store holds one it
    /// may see: checked where nothing failed, and taken as the store has
    /// it where something did.
    fn shown(&mut self, what: &str, whole: bool, blocking: Option<usize>) {
        self.told();
        for q in 0..2 {
            let (held, upgrade, _) = self.expected(q);
            let judged =
                whole && blocking != Some(q) && self.takes_part(q) && self.takes_part(1 - q);
            if judged && !self.ended.contains(&self.plain[q].0) {
                assert_eq!(
                    self.shows[q],
                    held,
                    "{what}: {}'s plain session shows a request from {}",
                    LOGINS[q],
                    LOGINS[1 - q]
                );
            }
            for d in 0..2 {
                if judged && !self.ended.contains(&self.sessions[q][d].0) {
                    assert_eq!(
                        self.views[q][d].0,
                        held || upgrade,
                        "{what}: {}'s device {d} shows a request or an upgrade from {}",
                        LOGINS[q],
                        LOGINS[1 - q]
                    );
                }
            }
            if !judged {
                self.resync(q);
            }
        }
    }

    /// The floor `q`'s kept records show.
    fn kept_floor(&self, q: usize) -> u64 {
        self.resets[q].iter().map(|(e, _)| *e).max().unwrap_or(0)
    }

    /// The fingerprint and the resets of the key `identity` is among the
    /// pair's, now or before a rotation.
    fn signer(&self, identity: &hl_identity::PublicKey) -> Option<([u8; 32], &Resets)> {
        (0..2).find_map(|q| {
            if self.people[q].id.public() == *identity {
                return Some((self.people[q].fp(), &self.resets[q]));
            }
            self.former[q]
                .iter()
                .find(|(p, _)| p.id.public() == *identity)
                .map(|(p, r)| (p.fp(), r))
        })
    }

    /// A cancel or a decline is drawn for a party with something to cancel
    /// or decline, where either has.
    fn actor(&self, n: u32) -> usize {
        let (step, p, ..) = Step::of(n);
        let wall = self.core.clock.wall();
        let has = |q: usize| match step {
            Step::Cancel => self.offers[q].is_some(),
            Step::Decline => {
                self.offers[1 - q].is_some()
                    || self
                        .store
                        .pending_in(&self.mailbox(q), wall)
                        .unwrap()
                        .iter()
                        .any(|r| r.owner.login == LOGINS[1 - q])
            }
            _ => true,
        };
        if has(p) || !has(1 - p) {
            p
        } else {
            1 - p
        }
    }

    /// Whether a presentation of the pair names a key either party has
    /// rotated away from.
    fn names_a_predecessor(&self) -> bool {
        let former: Vec<[u8; 32]> = self.former.iter().flatten().map(|(p, _)| p.fp()).collect();
        self.presentations()
            .iter()
            .any(|p| p.names.iter().any(|n| former.contains(n)))
    }

    /// Every key of `q`'s, its current last.
    fn keys(&self, q: usize) -> Vec<[u8; 32]> {
        self.former[q]
            .iter()
            .map(|(p, _)| p.fp())
            .chain([self.people[q].fp()])
            .collect()
    }

    /// A signed withdrawal by `q`, as `(q, its certificate's epoch, its
    /// cutoff, its bytes)`.
    fn signed_of(&self, q: usize, bytes: &[u8]) -> (usize, u64, u64, Vec<u8>) {
        let k = Withdrawal::parse(bytes, u64::MAX, |_| 0).expect("a withdrawal kept");
        let w = k.withdrawal();
        let own = self.keys(q).contains(&Fingerprint::of(&w.from).0);
        assert!(own, "signed by its owner");
        let epoch = DeviceCert::parse(&w.cert).expect("a certificate").epoch;
        (q, epoch, w.before, bytes.to_vec())
    }

    /// The signed withdrawals held for the pair, each party's own.
    fn signed(&self) -> Vec<(usize, u64, u64, Vec<u8>)> {
        let mut out = Vec::new();
        let (xs, ys) = (self.keys(0), self.keys(1));
        let pairs = xs.iter().flat_map(|x| {
            ys.iter()
                .map(move |y| Pair::new(Fingerprint(*x), Fingerprint(*y)))
        });
        for w in pairs.flat_map(|pair| self.store.withdrawals(&pair.hash()).unwrap()) {
            let Some(bytes) = w.withdrawal else {
                continue;
            };
            let q = (0..2)
                .find(|&q| self.keys(q).contains(&w.owner))
                .expect("one of the pair's");
            assert!(self.keys(q).contains(&w.party), "its signer's own cutoff");
            // By the cutoff the row keeps, which is what it ends.
            let (q, epoch, _, bytes) = self.signed_of(q, &bytes);
            out.push((q, epoch, w.before, bytes));
        }
        out
    }
}

fn attach(core: &Core, login: &str, who: &Person, d: usize, friendships: bool) -> (Uid, Events) {
    let cert = &who.devices[d].1;
    let (uid, mut rx) = core
        .attach(AttachInfo {
            account: None,
            nick: login.into(),
            icon: 1,
            admin: false,
            access: messaging_bits(),
            login: login.into(),
            addr: Some("10.0.0.1".parse().unwrap()),
            can_detach: true,
            transport: crate::Transport {
                messaging: true,
                friendships,
                identity: Some(IdentityTag {
                    fingerprint: who.fp(),
                    device: who.device(d),
                    handle: None,
                    quiet_until: None,
                    signs: false,
                    can_sign: false,
                    device_expires: u64::MAX,
                    device_epoch: DeviceCert::parse(cert).unwrap().epoch,
                    sealed: None,
                    device_cert: Some(Arc::new(cert.clone())),
                }),
                ..Default::default()
            },
            has_inbox: true,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_rooms: false,
            set_subject: false,
            is_person: true,
            reads_on_delivery: false,
            identity: Some(who.fp()),
            system: false,
        })
        .expect("a session");
    core.announce(uid);
    while rx.try_recv().is_ok() {}
    (uid, rx)
}

/// Sequences run on every store: ones a property test once found
/// failing, and ones that reach what it rarely draws: an edge made active
/// beside a presentation no record shows held, a friendship accepted
/// where a dropped presentation kept the id, an upgrade offer a reset
/// device signed, accepted, a withdrawal cutting earlier than one a
/// reset device signed, one below a floor installed alone, an ask taken as
/// an upgrade offer on a friendship answered `Reset` and accepted, a
/// request with an offer taken as one, declined, then asked again, the
/// record an upgrade offer was taken on dropped under it, a request taken
/// as one then asked again with an offer, an ask that would be one at
/// the daily bound, a rotation failing past its store and one failing in
/// it, an upgrade offer kept through a rotation, then a floor, and a
/// record replaced by the presentation that makes the friendship active
/// again.
pub const FOUND: &[&[u32]] = &[
    &[1073741952, 1073741843, 1073741988],
    &[1073742219, 1073741971, 1073742023],
    &[1073742123, 1073742016, 1073742052],
    &[3653138221, 1083754464, 736438800, 2139438084],
    &[
        3489662961, 4651, 535972, 1755425298, 1160182336, 1648425267, 1769223588,
    ],
    &[1088533518, 3701201427, 2985964750],
    &[2586569774, 334638451, 3275716072],
    &[1073745039, 1073742099, 1073741863, 1073742016, 1073741988],
    &[
        1073745039, 1073742099, 1073742016, 1073741863, 1073742129, 1073741888,
    ],
    &[1073745039, 1073742099, 1073741863, 1073742016, 1073741869],
    &[1073745039, 1073742099, 1073742016, 1073741863, 1073742016],
    &[1073741964, 1073742099, 1073741863, 1073742016],
    &[1484404, 2287251147, 881412125],
    &[2817259648, 3125557727, 1520565341, 1356973523],
    &[
        69354185, 3394129704, 169593288, 949713781, 1869947303, 1134085939, 3446946862, 2183693831,
        4199419015,
    ],
    &[1369815304, 3160564558, 62, 142700573, 2788673504],
];

/// Run `steps` against a store from `new_store`, each step held to the
/// invariants above.
pub fn run(new_store: &dyn Fn() -> Arc<dyn RelationshipStore>, steps: &[u32]) {
    let first = steps.first().copied().unwrap_or(0);
    let (mut run, mut twin) = (Run::new(new_store(), first), Run::new(new_store(), first));
    twin.core
        .upgrades_off
        .store(true, std::sync::atomic::Ordering::Relaxed);
    for r in [&mut run, &mut twin] {
        let start = r.pairing();
        assert!(start.friendship.is_some(), "friends from the start");
        if start.evidence == [true, true] {
            r.portable.extend(start.friendship);
        }
        r.resync(0);
        r.resync(1);
    }
    for &n in steps {
        // Both runs act as the same party, whatever the twin holds.
        let p = run.actor(n);
        run.step(n, p);
        twin.step(n, p);
        // What the other party holds never shows to an asker: where it saw
        // the same before, it is answered and told the same.
        if let (Some(a), Some(b)) = (&run.seen, &twin.seen) {
            if a.ask && a.visible == b.visible && a.outcome.is_some() && b.outcome.is_some() {
                assert_eq!(
                    a,
                    b,
                    "{:?}: an ask told what the other party holds",
                    Step::of(n)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::relationships::MemoryRelationships;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn the_memory_store_keeps_every_step_whole(
            steps in proptest::collection::vec(any::<u32>(), 1..40)
        ) {
            super::run(&|| std::sync::Arc::new(MemoryRelationships::new()), &steps);
        }
    }

    #[test]
    fn the_memory_store_keeps_the_sequences_found_before() {
        for steps in super::FOUND {
            super::run(&|| std::sync::Arc::new(MemoryRelationships::new()), steps);
        }
    }
}
