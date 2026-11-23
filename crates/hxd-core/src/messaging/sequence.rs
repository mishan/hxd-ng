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
//!   first remembered, changes and tells nothing.

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
        // Weighted toward the acts that make friends, so that sequences
        // reach the endings often.
        let step = match n % 32 {
            0..=4 => Step::Ask {
                offer: arg & 1 == 1,
            },
            5..=9 => Step::Answer {
                friendship: arg & 1 == 1,
            },
            10..=15 => Step::Present { k: arg as usize },
            16 | 17 => Step::Remove {
                withdraw: arg & 1 == 1,
                early: arg & 2 == 2,
            },
            18 => Step::BlockWithdrawal,
            19 => Step::Block,
            20 | 21 => Step::Unblock,
            22 | 23 => Step::PresentWithdrawal {
                early: arg & 1 == 1,
            },
            24 => Step::Link,
            25 => Step::RemoveByKey,
            26 => Step::Messaging,
            27 => Step::Revoke,
            28 | 30 => Step::Floor { how: arg % 3 },
            29 => Step::Answer {
                friendship: arg & 1 == 1,
            },
            _ => Step::Present { k: arg as usize },
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
                    ..MessagingPolicy::default()
                })
                .with_record_cache(records.clone()),
        );
        let sessions = [0, 1].map(|p| [0, 1].map(|d| attach(&core, LOGINS[p], &people[p], d)));
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
                let q = (0..2)
                    .find(|&q| self.people[q].id.public() == cert.identity)
                    .expect("one of the pair");
                let kept = &self.resets[q];
                let installed = self.floors.get(&self.people[q].fp()).copied();
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

    /// With nothing failing, a pass over both parties, as the sweep makes
    /// over the identities it covers: what it leaves, and what a pass
    /// after a restart makes of that.
    fn quiescent(&mut self, what: &str) {
        let fps = [self.people[0].fp(), self.people[1].fp()];
        let before = self.pairing();
        self.core.judge_floors(fps);
        let after = self.pairing();
        let told = self.told();
        let ended = before.friendship.is_some() && after.friendship != before.friendship;
        self.told_once(&format!("{what}, then a pass"), &after, ended, &told);
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
        self.core.judge_floors(fps);
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
                if self.ended.contains(&self.sessions[q][d].0) {
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
                asked.is_ok()
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
                core.set_revocations(Revocations {
                    devices: self.revoked.clone(),
                    ..Default::default()
                });
                true
            }
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
                    let ended = core.set_published_revocations(Published {
                        floors: self.floors.clone(),
                        covered: self.floors.keys().copied().collect(),
                        ..Default::default()
                    });
                    self.ended.extend(ended.into_iter().map(|(uid, _)| uid));
                }
                true
            }
        }
    }

    /// What each session of each party was told of the other this step,
    /// alice's first.
    fn told(&mut self) -> [[Vec<RosterState>; 2]; 2] {
        let mut out: [[Vec<RosterState>; 2]; 2] = Default::default();
        for (p, sessions) in self.sessions.iter_mut().enumerate() {
            for (d, (_, rx)) in sessions.iter_mut().enumerate() {
                while let Ok(se) = rx.try_recv() {
                    if let Event::FriendEntry(e) = se.event {
                        if e.login == LOGINS[1 - p] {
                            out[p][d].push(e.state);
                        }
                    }
                }
            }
        }
        out
    }

    fn step(&mut self, n: u32) {
        self.told();
        let (step, p, d, failure) = Step::of(n);
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
        ) || (matches!(step, Step::Link | Step::Revoke | Step::Floor { .. })
            && before.evidence == [true, true]);
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
            for pres in all.iter().filter(|p| p.evidence()) {
                let written = !before.rows.contains(&row_of(pres));
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
    }

    /// The floor `q`'s kept records show.
    fn kept_floor(&self, q: usize) -> u64 {
        self.resets[q].iter().map(|(e, _)| *e).max().unwrap_or(0)
    }

    /// A signed withdrawal by `q`, as `(q, its certificate's epoch, its
    /// cutoff, its bytes)`.
    fn signed_of(&self, q: usize, bytes: &[u8]) -> (usize, u64, u64, Vec<u8>) {
        let k = Withdrawal::parse(bytes, u64::MAX, |_| 0).expect("a withdrawal kept");
        let w = k.withdrawal();
        assert_eq!(w.from, self.people[q].id.public(), "signed by its owner");
        let epoch = DeviceCert::parse(&w.cert).expect("a certificate").epoch;
        (q, epoch, w.before, bytes.to_vec())
    }

    /// The signed withdrawals held for the pair, each party's own.
    fn signed(&self) -> Vec<(usize, u64, u64, Vec<u8>)> {
        let pair = Pair::new(
            Fingerprint(self.people[0].fp()),
            Fingerprint(self.people[1].fp()),
        );
        let mut out = Vec::new();
        for w in self.store.withdrawals(&pair.hash()).unwrap() {
            let Some(bytes) = w.withdrawal else {
                continue;
            };
            let q = (0..2)
                .find(|&q| self.people[q].fp() == w.owner)
                .expect("one of the pair's");
            assert_eq!(w.party, w.owner, "its signer's own cutoff");
            // By the cutoff the row keeps, which is what it ends.
            let (q, epoch, _, bytes) = self.signed_of(q, &bytes);
            out.push((q, epoch, w.before, bytes));
        }
        out
    }
}

fn attach(core: &Core, login: &str, who: &Person, d: usize) -> (Uid, Events) {
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
                friendships: true,
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
/// reset device signed, and one below a floor installed alone.
pub const FOUND: &[&[u32]] = &[
    &[1073741952, 1073741852, 1073741989],
    &[1073741979, 1073741980, 1073742026],
    &[1073741883, 1073742016, 1073742053],
    &[3653138233, 1083754464, 736438803, 2139438085],
    &[
        3598185087, 4667, 535997, 1755425304, 1160182336, 1648425276, 1769223613,
    ],
    &[1088533014, 3701201436, 2985964758],
    &[2586569270, 334638460, 3275716080],
];

/// Run `steps` against a store from `new_store`, each step held to the
/// invariants above.
pub fn run(new_store: &dyn Fn() -> Arc<dyn RelationshipStore>, steps: &[u32]) {
    let mut run = Run::new(new_store(), steps.first().copied().unwrap_or(0));
    let start = run.pairing();
    assert!(start.friendship.is_some(), "friends from the start");
    if start.evidence == [true, true] {
        run.portable.extend(start.friendship);
    }
    for &n in steps {
        run.step(n);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::relationships::MemoryRelationships;

    proptest! {
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
