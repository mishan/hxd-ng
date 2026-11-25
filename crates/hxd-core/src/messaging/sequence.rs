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
//! - every live session of each party, plain ones included, shows what a
//!   fresh read of its roster would, offers and listed friendships
//!   included; a session that did not ask for portable friendships is
//!   never told an offer;
//! - an act reads what it tells from what its step left, never from a
//!   read after it, but where [`TELLS_BY_READING`] names;
//! - a pass drops an offer only where what is installed forbids it, and
//!   ticks with nothing failing leave none such, nor a revoked device's
//!   presentation;
//! - an answer to a request or an upgrade waiting is never refused as if
//!   there were none;
//! - an ask with an offer that is answered, by a party with no friendship
//!   and nothing pending, is answered and told to it alike whatever the
//!   other party holds;
//! - every ask, plain or with an offer, from whatever the asker can see,
//!   is answered and told to the asker alike in a twin run where no
//!   `Reset` record ever makes an upgrade offer: what the other party
//!   holds never shows. The request ledger may differ, the answer may not.
//!
//! [`run_failing_each_call`] replays sequences with each store call a step
//! makes failing in turn: a step answered with an error leaves the store as
//! it was and tells nothing.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

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
use crate::relationships::{
    PendingOut, Presentation, RelationId, RelationshipStore, Report, Requester, StoredOffer,
};
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
    /// The caller's alias for the other set or cleared.
    Alias {
        set: bool,
    },
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
    /// A registrar's list revokes the device; with `unread`, the lists are
    /// published again with this party's left unread, covering nothing of
    /// it.
    PublishDevice {
        unread: bool,
    },
    /// A registrar's list freezes the identity, refused but not revoked.
    Freeze,
    /// A registrar's list revokes the identity.
    RevokeIdentity,
    /// The identity rotates to its successor key, once; with `into`, the
    /// other party has first presented a friendship it made with that
    /// successor elsewhere, so the rotation lands on a pair it holds; with
    /// `crowded`, the successor brings state of its own toward the other
    /// party, and the other party has upgrades to both keys.
    Rotate {
        into: bool,
        crowded: bool,
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
        // make room for it: Ask 4/32, Answer 3/32, Remove, Unblock,
        // Present, Decline, Cancel and Clock 2/32 each (each clock move
        // 1/48), every other kind 1/32 (each way of rotating 1/128).
        let step = match n % 32 {
            0..=3 => Step::Ask {
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
            26 => Step::PublishDevice {
                unread: arg & 1 == 1,
            },
            27 => Step::Freeze,
            28 => Step::RevokeIdentity,
            30 => Step::Alias { set: arg & 1 == 1 },
            _ => Step::Rotate {
                into: arg & 1 == 1,
                crowded: arg & 2 == 2,
            },
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
    /// Each party's session that did not ask for portable friendships.
    plain: [(Uid, Events); 2],
    /// What each of each party's sessions shows of the other, from what
    /// it was told: its two device sessions, then its plain one.
    views: [[View; 3]; 2],
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
    /// The requests told since this was last cleared.
    requested: usize,
    /// Whether a rotation has brought state written to the store by hand,
    /// as a successor's account here would have left it.
    crowded: bool,
    /// Whether each party's pending out was an upgrade before the step.
    upgrading: [bool; 2],
    /// The keys the last list published covered.
    covered: HashSet<[u8; 32]>,
}

/// Where tells are still read after the step that changed what they
/// tell, so that a read failing there may cost one: what the follow-up to
/// #474 moves onto telling from what the step left. Every other tell is
/// made from that, and one read after its step fails the run.
const TELLS_BY_READING: &[&str] = &[
    "an unblock",
    "an alias",
    "a merge",
    "a rotation's merge",
    "a floor's pass",
    "an offer below a floor",
    "an orphan judged",
    "a removal by key",
    "a revoked device's presentation",
    "an unlinked identity's presentation",
];

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

/// What a session shows of the other party, as a client keeps it from
/// what it is told: the entry's state (none once removed), the offer on
/// it, and the friendships it lists.
#[derive(Debug, Clone, Default, PartialEq)]
struct View {
    state: Option<RosterState>,
    alias: Option<String>,
    offer: Option<Vec<u8>>,
    friendships: Vec<[u8; 32]>,
}

impl View {
    fn of(e: &super::FriendEntry) -> View {
        View {
            state: (e.state != RosterState::Removed).then_some(e.state),
            alias: e.alias.clone(),
            offer: e.offer.clone(),
            friendships: e.friendships.clone(),
        }
    }
}

/// Unix seconds, real time: where a run's clock starts.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

fn mailbox(login: &str, p: &Person) -> Mailbox {
    Mailbox::identified(login, p.fp())
}

impl Run {
    fn new(store: Arc<dyn RelationshipStore>, start: u32, base: u64) -> Self {
        let fail = Arc::new(Failing::new(store.clone()));
        let people = [Person::new(1, base), Person::new(2, base)];
        let records = Arc::new(MemoryRecordCache::default());
        let dir = Arc::new(Directory(Mutex::new(
            LOGINS
                .iter()
                .zip(&people)
                .map(|(l, p)| (mailbox(l, p), messaging_bits()))
                .collect(),
        )));
        let mut core = Core::new()
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
            .with_record_cache(records.clone());
        // Standing still but for what the run advances, as its twin's
        // does from the same time: a lapse at a second's edge lands
        // alike in both.
        core.clock = crate::clock::Clock::frozen(UNIX_EPOCH + Duration::from_secs(base));
        let core = Arc::new(core);
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
            requested: 0,
            crowded: false,
            upgrading: [false, false],
            covered: HashSet::new(),
        }
    }

    fn mailbox(&self, p: usize) -> Mailbox {
        mailbox(LOGINS[p], &self.people[p])
    }

    /// What the run starts from, as its sessions see it.
    fn start(&mut self) {
        let start = self.pairing();
        assert!(start.friendship.is_some(), "friends from the start");
        if start.evidence == [true, true] {
            self.portable.extend(start.friendship);
        }
        self.resync(0);
        self.resync(1);
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
        let offered = self.stored_offers();
        self.core.reconcile_due(listed.iter().copied());
        let after = self.pairing();
        // A pass drops an offer only for what forbids it, or with the
        // friendship it stood beside.
        if after.friendship == before.friendship {
            let left = self.stored_offers();
            for o in offered.iter().filter(|o| !left.contains(o)) {
                assert!(
                    self.forbidden(o),
                    "{what}: a pass dropped an offer nothing forbids"
                );
            }
        }
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
        told: &[[Vec<RosterState>; 3]; 2],
    ) {
        for (q, sessions) in told.iter().enumerate() {
            for (slot, told) in sessions.iter().enumerate() {
                let uid = self.uid(q, slot);
                if self.ended.contains(&uid) || self.fresh.contains(&uid) {
                    continue;
                }
                let removed = told.iter().filter(|s| **s == RosterState::Removed).count();
                assert!(
                    removed <= 1,
                    "{what}: {} told twice in session {slot}: {told:?}",
                    LOGINS[q]
                );
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
                let answered = core.friend_answer(uid, other, true, f);
                let ok = answered.is_ok();
                self.asked = Some(answered);
                ok
            }
            Step::Decline => core.friend_answer(uid, other, false, None).is_ok(),
            Step::Alias { set } => core.friend_alias(uid, other, set.then_some("pal")).is_ok(),
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
                // bare login, which a link would have to claim; its
                // sessions, which make friendship acts no more, sign in
                // again.
                let fp = me.fp();
                self.dir.0.lock().unwrap()[p].0.fingerprint = None;
                core.friendships_unlinked(&fp);
                self.dir.0.lock().unwrap()[p].0.fingerprint = Some(fp);
                self.sign_in_again(p);
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
            // Each revocation lifts when made again.
            Step::Revoke => {
                let lifted = self.revoked.remove(&me.device(d));
                if !lifted {
                    self.revoked.insert(me.device(d));
                }
                let ended = core.set_revocations(Revocations {
                    devices: self.revoked.clone(),
                    ..Default::default()
                });
                self.ended.extend(ended.into_iter().map(|(uid, _)| uid));
                if lifted {
                    self.sign_in_again(p);
                }
                true
            }
            Step::Cancel => match self.offers[p].clone() {
                Some(o) => core.friend_cancel_offer(uid, other, &o).is_ok(),
                None => false,
            },
            Step::PublishDevice { unread: true } => {
                self.publish_unread(Some(p));
                true
            }
            Step::PublishDevice { unread: false } => {
                let listed = (me.fp(), me.device(d));
                let lifted = self.listed.devices.remove(&listed);
                if !lifted {
                    self.listed.devices.insert(listed);
                }
                self.publish();
                if lifted {
                    self.sign_in_again(p);
                }
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
            Step::Rotate { into, crowded } => self.rotate(p, into, crowded),
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
        self.publish_unread(None);
    }

    /// [`Self::publish`], every key of both parties covered, but `unread`'s
    /// where its lists could not be read.
    fn publish_unread(&mut self, unread: Option<usize>) {
        let mut list = self.listed.clone();
        list.floors = self.floors.clone();
        let keys: Vec<[u8; 32]> = (0..2)
            .filter(|q| Some(*q) != unread)
            .flat_map(|q| {
                let former = self.former[q].iter().map(|(p, _)| p.fp());
                former.chain([self.people[q].fp()]).collect::<Vec<_>>()
            })
            .collect();
        // An unread party's entries are carried from before, as a sweep
        // carries what it found; its keys are covered by nothing read now.
        list.covered = keys.into_iter().collect();
        self.covered = list.covered.clone();
        let ended = self.core.set_published_revocations(list);
        self.ended.extend(ended.into_iter().map(|(uid, _)| uid));
    }

    /// `p` rotates to its successor key, its account linking it and its
    /// sessions made again under it; with `into`, after the other party
    /// presented a friendship it made with the successor elsewhere.
    fn rotate(&mut self, p: usize, into: bool, crowded: bool) -> bool {
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
        if crowded {
            self.crowd(p, &next);
            self.crowded = true;
        }
        let before = self.upgrades_of(p, &[from, to]);
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
        self.settled(p, from, to, &before);
        self.rotated[p] = true;
        let old = std::mem::replace(&mut self.people[p], next);
        let resets = std::mem::take(&mut self.resets[p]);
        self.former[p].push((old, resets));
        self.withdrawn.retain(|(q, _)| *q != p);
        self.offers[p] = None;
        self.sign_in_again(p);
        true
    }

    /// The successor `next` of `p` brought state of its own toward the
    /// other party, as an account it was linked to here left it: its
    /// upgrade to the other party on a record the other holds for it,
    /// the other's upgrade to it on a record it holds, and the other's
    /// upgrade to the key it retires, where nothing else stands between
    /// them. Written to the store as that account left it, and read by
    /// the parties' sessions afresh.
    fn crowd(&mut self, p: usize, next: &Person) {
        let (me, them) = (&self.people[p], &self.people[1 - p]);
        let (now, wall) = (self.core.clock.unix(), self.core.clock.wall());
        // Beside no friendship and no block, where such state could stand.
        let (mine, other) = (self.mailbox(p), self.mailbox(1 - p));
        let standing = |x: &Mailbox, y: &Mailbox| {
            self.store
                .relationship(x, y, wall)
                .unwrap()
                .is_some_and(|r| r.friendship.is_some() || r.blocked_at.is_some())
        };
        if standing(&mine, &other) || standing(&other, &mine) {
            return;
        }
        let record = |by: &Person, of: &Person, bytes: Vec<u8>| Presentation {
            presenter: by.fp(),
            other: of.fp(),
            names: [by.fp(), of.fp()],
            pair: Pair::new(Fingerprint(by.fp()), Fingerprint(of.fp())).hash(),
            hash: Sha256::digest(&bytes).into(),
            friendship: None,
            reset: Some(bytes),
            device: by.device(1),
            edge: None,
            at: wall,
            taken: wall,
        };
        let friendship = |a: &Person, b: &Person, t: u64| b.accept(1, &a.offer(1, b, t), t);
        let shown = PendingOut {
            sent_at: wall,
            lapses_at: wall + Duration::from_secs(30 * DAY),
            delivered: true,
            note: None,
            offer: None,
            upgrade: true,
        };
        let stored = |offer: Vec<u8>| StoredOffer {
            offer,
            lapses_at: wall + Duration::from_secs(DAY),
        };
        let (succ, other, mine) = (
            Mailbox::identified(LOGINS[p], next.fp()),
            self.mailbox(1 - p),
            self.mailbox(p),
        );
        let store = &self.store;
        let none = Report::none();
        // By no device what is installed refuses.
        let refused = |by: &Person| {
            let d = by.device(1);
            self.revoked.contains(&d) || self.listed.devices.contains(&(by.fp(), d))
        };
        if refused(them) || refused(next) || refused(me) {
            return;
        }
        store
            .present(&record(them, next, friendship(next, them, now - 40)))
            .unwrap();
        store
            .present(&record(next, them, friendship(them, next, now - 41)))
            .unwrap();
        // None that what is installed would have swept away.
        let ask = |a: &Mailbox, b: &Mailbox, o: Vec<u8>| {
            if self.forbidden(&o) {
                return;
            }
            store
                .ask(a, b, &shown, Some(&stored(o)), None, &none)
                .unwrap();
        };
        // Where the key that retires has something pending for the other
        // party, the successor has an upgrade of its own to it; otherwise
        // the other has upgrades to both keys, the one to the key that
        // retires where that key holds nothing toward it but the record it
        // is taken on. Never two upgrades crossing, which nothing makes.
        let pending = |x: &Mailbox, y: &Mailbox| {
            store
                .relationship(x, y, wall)
                .unwrap()
                .is_some_and(|r| r.pending_out.is_some())
        };
        if pending(&mine, &other) {
            ask(&succ, &other, next.offer(1, them, now));
        } else {
            ask(&other, &succ, them.offer(1, next, now));
            let free = store.relationship(&other, &mine, wall).unwrap().is_none()
                && store.relationship(&mine, &other, wall).unwrap().is_none()
                && store.presentation(&me.fp(), &them.fp()).unwrap().is_none();
            if free {
                store
                    .present(&record(me, them, friendship(them, me, now - 42)))
                    .unwrap();
                ask(&other, &mine, them.offer(1, me, now));
            }
        }
        self.resync(0);
        self.resync(1);
    }

    /// Each upgrade waiting between `p`'s keys `keys` and the other party,
    /// either way, as `(owner, other, offer)`, with the records each was
    /// taken on: those its pending out shows, with their offers.
    #[allow(clippy::type_complexity)]
    fn upgrades_of(
        &self,
        p: usize,
        keys: &[[u8; 32]],
    ) -> (
        Vec<([u8; 32], [u8; 32], Vec<u8>)>,
        HashMap<([u8; 32], [u8; 32]), Vec<u8>>,
    ) {
        let wall = self.core.clock.wall();
        let b = self.people[1 - p].fp();
        let mut upgrades = Vec::new();
        let mut records = HashMap::new();
        for k in keys {
            for (x, y) in [(*k, b), (b, *k)] {
                let (mx, my) = (Mailbox::identified("", x), Mailbox::identified("", y));
                let shown = self
                    .store
                    .relationship(&mx, &my, wall)
                    .unwrap()
                    .and_then(|r| r.pending_out)
                    .is_some_and(|p| p.upgrade);
                if let Some(o) = self.store.offer(&x, &y, wall).unwrap().filter(|_| shown) {
                    upgrades.push((x, y, o.offer));
                }
                if let Some(reset) = self
                    .store
                    .presentation(&y, &x)
                    .unwrap()
                    .and_then(|p| p.reset)
                {
                    records.insert((y, x), reset);
                }
            }
        }
        upgrades.sort();
        (upgrades, records)
    }

    /// What a rotation of `p` from `from` to `to` left of the upgrades
    /// between its keys and the other party, held to what should stand:
    /// the successor's own toward the other where it had one, else the
    /// retired key's, moved, while the record it was taken on is the one
    /// that survives; the other's to the successor, as it was; and none to
    /// or from the retired key.
    #[allow(clippy::type_complexity)]
    fn settled(
        &self,
        p: usize,
        from: [u8; 32],
        to: [u8; 32],
        before: &(
            Vec<([u8; 32], [u8; 32], Vec<u8>)>,
            HashMap<([u8; 32], [u8; 32]), Vec<u8>>,
        ),
    ) {
        let (pre, records) = before;
        let b = self.people[1 - p].fp();
        let had = |x: [u8; 32], y: [u8; 32]| {
            pre.iter()
                .find(|(o, t, _)| (*o, *t) == (x, y))
                .map(|(_, _, offer)| offer.clone())
        };
        let (after, kept) = self.upgrades_of(p, &[from, to]);
        let mut expected = Vec::new();
        // None stands as a pending out beside the friendship the merge
        // left.
        let wall = self.core.clock.wall();
        let (mine, theirs) = (Mailbox::identified("", to), Mailbox::identified("", b));
        let friends = self
            .store
            .relationship(&mine, &theirs, wall)
            .unwrap()
            .is_some_and(|r| r.friendship.is_some());
        let outgoing = had(to, b).filter(|_| !friends).or_else(|| {
            let moved = had(from, b).filter(|_| !friends)?;
            let qualified = records.get(&(b, from))?;
            (kept.get(&(b, to)) == Some(qualified)).then_some(moved)
        });
        if let Some(o) = outgoing {
            expected.push((to, b, o));
        }
        if let Some(o) = had(b, to).filter(|_| !friends) {
            expected.push((b, to, o));
        }
        expected.sort();
        assert_eq!(
            after, expected,
            "{}'s rotation settled the upgrades to and from its keys",
            LOGINS[p]
        );
    }

    /// `p`'s sessions ended and made again, each reading its roster.
    fn sign_in_again(&mut self, p: usize) {
        // The client's own reads, not the step's.
        self.fail.fail_nth(0);
        for (uid, _) in self.sessions[p].iter().chain([&self.plain[p]]) {
            self.ended.insert(*uid);
            self.core.end_session(*uid);
        }
        // A device still refused stays signed out.
        let who = &self.people[p];
        for d in 0..2 {
            if let Some(s) = try_attach(&self.core, LOGINS[p], who, d, true) {
                self.sessions[p][d] = s;
            }
        }
        if let Some(s) = try_attach(&self.core, LOGINS[p], who, 0, false) {
            self.plain[p] = s;
        }
        for slot in 0..3 {
            let uid = self.uid(p, slot);
            if !self.ended.contains(&uid) {
                self.core.friends_roster(uid).expect("a roster");
                self.fresh.insert(uid);
            }
        }
        self.resync(p);
    }

    /// Where entries were told from a read after their step, since last
    /// asked.
    /// Whether each party's pending out is an upgrade, which a block that
    /// takes it tells: read before a step acts.
    fn upgrading_now(&self) -> [bool; 2] {
        let wall = self.core.clock.wall();
        [0, 1].map(|q| {
            let (x, y) = (self.mailbox(q), self.mailbox(1 - q));
            self.store
                .relationship(&x, &y, wall)
                .unwrap()
                .and_then(|r| r.pending_out)
                .is_some_and(|p| p.upgrade)
        })
    }

    fn told_by_reading(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.core.told_by_reading.lock().unwrap())
    }

    fn uid(&self, q: usize, slot: usize) -> Uid {
        if slot < 2 {
            self.sessions[q][slot].0
        } else {
            self.plain[q].0
        }
    }

    /// What `q`'s sessions show taken from the store, for sessions made
    /// now or a step nothing could be judged by.
    fn resync(&mut self, q: usize) {
        for slot in 0..3 {
            if let Some(v) = self.derived(q, slot) {
                self.views[q][slot] = v;
            }
        }
    }

    /// What `q`'s session in `slot` shows of the other party read afresh:
    /// its roster's entry, or the upgrade offer a `Reset` edge's pending
    /// out shows the other, which only a friendships session is told.
    /// None for a session that cannot read its roster.
    fn derived(&self, q: usize, slot: usize) -> Option<View> {
        let uid = self.uid(q, slot);
        if self.ended.contains(&uid) {
            return None;
        }
        let roster = self.core.friends_roster(uid).ok()?;
        let mut view = roster
            .iter()
            .find(|e| e.login == LOGINS[1 - q])
            .map(View::of)
            .unwrap_or_default();
        if view.state.is_none() && slot < 2 {
            let now = self.core.clock.wall();
            let (me, them) = (self.mailbox(q), self.mailbox(1 - q));
            let upgrade = self
                .store
                .relationship(&them, &me, now)
                .unwrap()
                .and_then(|r| r.pending_out)
                .is_some_and(|p| p.upgrade);
            let (x, y) = (self.people[1 - q].fp(), self.people[q].fp());
            if let Some(o) = self.store.offer(&x, &y, now).unwrap().filter(|_| upgrade) {
                view = View {
                    state: Some(RosterState::PendingIn),
                    offer: Some(o.offer),
                    ..View::default()
                };
            }
        }
        Some(view)
    }

    /// What each session of each party was told of the other this step,
    /// alice's first.
    fn told(&mut self) -> [[Vec<RosterState>; 3]; 2] {
        let mut out: [[Vec<RosterState>; 3]; 2] = Default::default();
        for (p, told) in out.iter_mut().enumerate() {
            for (slot, out) in told.iter_mut().enumerate() {
                let rx = if slot < 2 {
                    &mut self.sessions[p][slot].1
                } else {
                    &mut self.plain[p].1
                };
                while let Ok(se) = rx.try_recv() {
                    let view = &mut self.views[p][slot];
                    match se.event {
                        Event::FriendEntry(e) if e.login == LOGINS[1 - p] => {
                            if slot == 2 {
                                assert!(
                                    e.offer.is_none(),
                                    "{} told an offer on an entry",
                                    LOGINS[p]
                                );
                            }
                            out.push(e.state);
                            *view = View::of(&e);
                        }
                        Event::FriendRequest { login, offer, .. } if login == LOGINS[1 - p] => {
                            self.requested += 1;
                            if slot == 2 {
                                assert!(offer.is_none(), "{} told an offer", LOGINS[p]);
                            }
                            // An upgrade offer beside a friendship is shown
                            // on the friend's entry.
                            if view.state != Some(RosterState::Accepted) {
                                *view = View {
                                    state: Some(RosterState::PendingIn),
                                    ..View::default()
                                };
                            }
                            view.offer = offer;
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
        // Whether the other has a request or an upgrade's pending out
        // waiting on this party.
        let asked_of = self
            .store
            .relationship(&them, &me, wall)
            .unwrap()
            .and_then(|r| r.pending_out)
            .filter(|p| p.delivered && !p.upgrade);
        let free = before.friendship.is_none() && !mine;
        let predecessor = self.names_a_predecessor();
        let owed = self.core.owed_sweeps();
        let upgrading = self.upgrading_now();
        self.told_by_reading();
        let ok = self.act(step, p, d);
        let by_reading = self.told_by_reading();
        self.fail.fail_nth(0);
        self.core.clock.advance(Duration::from_secs(1));
        let after = self.pairing();
        let told = self.told();
        // A failed read can cost an ending its tell, never a tell its
        // ending.
        let failed = self.fail.failed();
        let read_failed = failed.is_some_and(|m| READS.contains(&m));
        let what = format!("{step:?} by {} on device {d}, {failure:?}", LOGINS[p]);
        if let Some(site) = by_reading.iter().find(|s| !TELLS_BY_READING.contains(s)) {
            panic!("{what}: told from a read after its step, at {site}");
        }
        let unmigrated = !by_reading.is_empty();

        // An ask with an offer, from a party with nothing to the other,
        // answered and told alike whether or not it was taken as an
        // upgrade offer; the request ledger and bounds aside, which differ
        // by design.
        let asked = self.asked.take();
        // An answer to what waits is never told there is nothing to answer.
        if let (Step::Answer { .. }, Some(Err(super::MessagingError::NotFriends))) = (step, asked) {
            assert!(
                failed.is_some() || asked_of.is_none(),
                "{what}: an answer to {asked_of:?} refused NotFriends"
            );
        }
        self.seen = Some(Seen {
            ask: matches!(step, Step::Ask { .. }),
            visible,
            outcome: failed.is_none().then(|| (asked, told[p].to_vec())),
        });
        if let (Step::Ask { offer: true }, Some(Ok(answer))) = (step, asked) {
            if free && failed.is_none() {
                assert_eq!(answer, RosterState::PendingOut, "{what}: answered");
                for (q, told) in told[p].iter().enumerate() {
                    if !self.ended.contains(&self.uid(p, q)) {
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
                | Step::PublishDevice { .. }
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
            // A party with no session signed in has no entry.
            let roster = self.core.roster.lock().unwrap();
            if let Some(e) = roster.presences.by.get(&Key::of(&m)) {
                assert_eq!(e.friends, stored, "{what}: {login}'s friends in the roster");
            }
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
        self.ended_owed(&what, &owed);
        self.legal(&what);
        // A blocker's own client knows what its block ended, and a request
        // lapses without a notice (instant-messaging 3): neither is told.
        let blocking = matches!(step, Step::Block | Step::BlockWithdrawal).then_some(p);
        // An act on the list reads what it tells after its writes, so a
        // read that fails there costs a tell; losing the messaging bit is
        // read live.
        // What a merge of a successor's own state tells is a rotation's,
        // still read after its step, and the state was not one an act made.
        let lapsing = matches!(step, Step::Clock { .. } | Step::Messaging) || self.crowded;
        self.upgrading = upgrading;
        self.shown(&what, !(read_failed && unmigrated) && !lapsing, blocking);
    }

    /// Each sweep owed before a step and gone after it ended on positive
    /// evidence: its work done, or what owed it lifted by a list that
    /// covers it.
    fn ended_owed(&self, what: &str, before: &[crate::messaging::Sweep]) {
        use crate::messaging::Sweep;
        let now = self.core.owed_sweeps();
        let offers: Vec<(DeviceCert, [u8; 32])> = self
            .stored_offers()
            .iter()
            .map(|o| {
                let o = Offer::check(o, u64::MAX, &[], |_| 0).expect("an offer kept");
                (DeviceCert::parse(&o.cert).expect("a certificate"), o.to.0)
            })
            .collect();
        let names = |fp: &[u8; 32]| {
            offers
                .iter()
                .any(|(c, to)| Fingerprint::of(&c.identity).0 == *fp || to == fp)
        };
        for sweep in before.iter().filter(|s| !now.contains(s)) {
            let done = match sweep {
                Sweep::Device {
                    identity, device, ..
                } => !offers.iter().any(|(c, _)| {
                    identity.is_none_or(|i| Fingerprint::of(&c.identity).0 == i)
                        && Fingerprint::of(&c.device).0 == *device
                }),
                Sweep::Identity { identity, .. } => !names(identity),
                Sweep::Unlinked(fp) => !names(fp),
                Sweep::Presented { device, .. } => {
                    !self.presentations().iter().any(|p| p.device == *device)
                }
                Sweep::Unpresented(fp) => !self.presentations().iter().any(|p| p.presenter == *fp),
                // What it judged stands, or is gone.
                Sweep::Judge(a, b) => {
                    let all = self.presentations();
                    all.iter()
                        .filter(|p| {
                            [(p.presenter, p.other), (p.other, p.presenter)].contains(&(*a, *b))
                        })
                        .filter(|p| p.evidence())
                        .all(|p| self.judged(p, &all) != Some(false))
                }
                Sweep::Purge(of) => {
                    let wall = self.core.clock.wall();
                    self.store.relationships(of, wall).unwrap().is_empty()
                        && self.store.pending_in(of, wall).unwrap().is_empty()
                }
            };
            let lifted = match sweep.clone() {
                Sweep::Device {
                    device,
                    operator: true,
                    ..
                }
                | Sweep::Presented {
                    identity: None,
                    device,
                } => !self.revoked.contains(&device),
                Sweep::Device {
                    identity: Some(identity),
                    device,
                    ..
                }
                | Sweep::Presented {
                    identity: Some(identity),
                    device,
                } => {
                    self.covered.contains(&identity)
                        && !self.listed.devices.contains(&(identity, device))
                }
                Sweep::Device { identity: None, .. } => false,
                Sweep::Identity { identity, .. } => {
                    self.covered.contains(&identity) && !self.listed.identities.contains(&identity)
                }
                Sweep::Unlinked(_) | Sweep::Unpresented(_) => true,
                Sweep::Judge(..) | Sweep::Purge(_) => false,
            };
            assert!(
                done || lifted,
                "{what}: {sweep:?} ended undone and not lifted"
            );
        }
    }

    /// Every offer the store holds between the pair, on a request or as
    /// an upgrade, under any key either party has had.
    fn stored_offers(&self) -> Vec<Vec<u8>> {
        let now = self.core.clock.wall();
        let keys: Vec<[u8; 32]> = (0..2)
            .flat_map(|q| {
                let former = self.former[q].iter().map(|(p, _)| p.fp());
                former.chain([self.people[q].fp()]).collect::<Vec<_>>()
            })
            .collect();
        let mut out = Vec::new();
        for x in &keys {
            for (_, o) in self.store.offers_from(x, now).unwrap() {
                out.push(o.offer);
            }
        }
        for q in 0..2 {
            let (me, them) = (self.mailbox(q), self.mailbox(1 - q));
            let row = self.store.relationship(&me, &them, now).unwrap();
            out.extend(
                row.and_then(|r| r.pending_out)
                    .and_then(|p| p.offer)
                    .map(|o| o.offer),
            );
        }
        out
    }

    /// Whether what is installed now forbids an offer: its device revoked
    /// by the operator or a registrar, the identity it is from or to
    /// revoked, or its certificate below its signer's floor.
    fn forbidden(&self, offer: &[u8]) -> bool {
        let o = Offer::check(offer, u64::MAX, &[], |_| 0).expect("an offer kept");
        let cert = DeviceCert::parse(&o.cert).expect("a certificate");
        let (identity, device) = (
            Fingerprint::of(&cert.identity).0,
            Fingerprint::of(&cert.device).0,
        );
        let floor = self.signer(&cert.identity).map_or(0, |(signer, kept)| {
            let kept = kept.iter().map(|(e, _)| *e).max().unwrap_or(0);
            self.floors.get(&signer).copied().unwrap_or(0).max(kept)
        });
        self.revoked.contains(&device)
            || self.listed.devices.contains(&(identity, device))
            || self.listed.identities.contains(&identity)
            || self.listed.identities.contains(&o.to.0)
            || cert.epoch < floor
    }

    /// With nothing failing, ticks until the store is quiet, owed sweeps'
    /// backoffs past: then it holds no offer and no presentation that
    /// what is installed forbids.
    fn converged(&mut self) {
        let listed: Vec<[u8; 32]> = self.floors.keys().copied().collect();
        self.fail.fail_nth(0);
        for _ in 0..8 {
            self.core.clock.advance(Duration::from_secs(3700));
            self.core.reconcile_due(listed.iter().copied());
        }
        for o in self.stored_offers() {
            let detail = Offer::check(&o, u64::MAX, &[], |_| 0).map(|o| {
                let c = DeviceCert::parse(&o.cert).expect("a certificate");
                (Fingerprint::of(&c.identity).0[0], o.to.0[0], c.epoch)
            });
            assert!(
                !self.forbidden(&o),
                "converged on an offer that is forbidden: {detail:?}, {:?}",
                [self.people[0].fp()[0], self.people[1].fp()[0]]
            );
        }
        for p in self.presentations() {
            let revoked = self.revoked.contains(&p.device)
                || self.listed.devices.contains(&(p.presenter, p.device));
            assert!(
                !revoked,
                "converged on a revoked device's presentation: {:?} by {:?}, owing {:?}",
                (
                    p.presenter[0],
                    p.other[0],
                    p.friendship.is_some(),
                    p.reset.is_some()
                ),
                (p.device[0], self.revoked.contains(&p.device)),
                self.core.owed_sweeps()
            );
        }
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

    /// Every live session of each party shows what a fresh read of its
    /// roster would: checked where nothing could cost a tell, and taken
    /// as the store has it where something could.
    fn shown(&mut self, what: &str, whole: bool, blocking: Option<usize>) {
        self.told();
        for q in 0..2 {
            let judged = whole && blocking != Some(q) && self.takes_part(q);
            for slot in 0..3 {
                let Some(derived) = self.derived(q, slot) else {
                    continue;
                };
                // A block drops the blocked party's request unsaid, as a
                // missing account's would be.
                let unsaid = blocking == Some(1 - q)
                    && !self.upgrading[q]
                    && self.views[q][slot].state == Some(RosterState::PendingOut)
                    && derived.state.is_none();
                // What is shown of a party that takes no part is read live,
                // its state aside: an edge it ends is told.
                let (shows, read) = match self.takes_part(1 - q) {
                    true => (self.views[q][slot].clone(), derived.clone()),
                    false => (
                        View {
                            state: self.views[q][slot].state,
                            ..View::default()
                        },
                        View {
                            state: derived.state,
                            ..View::default()
                        },
                    ),
                };
                if judged && !unsaid {
                    assert_eq!(
                        shows,
                        read,
                        "{what}: {}'s session {slot} shows of {}",
                        LOGINS[q],
                        LOGINS[1 - q]
                    );
                }
                self.views[q][slot] = derived;
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
    try_attach(core, login, who, d, friendships).expect("a session")
}

fn try_attach(
    core: &Core,
    login: &str,
    who: &Person,
    d: usize,
    friendships: bool,
) -> Option<(Uid, Events)> {
    let cert = &who.devices[d].1;
    let (uid, mut rx) = core.attach(AttachInfo {
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
    })?;
    core.announce(uid);
    while rx.try_recv().is_ok() {}
    Some((uid, rx))
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
/// it, an upgrade offer kept through a rotation, then a floor, a record
/// replaced by the presentation that makes the friendship active again,
/// an upgrade beside a friendship canceled, an unlink, the offer a
/// device the operator revoked signed, one to an identity whose
/// revocation's sweep was owed, one asked of a revoked identity, and a
/// rotation whose successor's own upgrade wins the merge, and an unlink's
/// sweep owed for an account that lost messaging and was linked again,
/// and an ask its twin answered across a second's edge the run did not.
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
    &[1369815304, 3160564558, 32, 142700573, 2788673504],
    &[1268098574, 1865338562, 2686804959, 2851487448],
    &[2728864225, 3673178098, 783180557, 773610635],
    &[877930787, 259041713, 422970530, 2957443115],
    &[
        1162221802, 137516573, 362072657, 498996160, 115384252, 3433446927,
    ],
    &[199610076, 2956155360],
    &[35977725],
    &[
        299946571, 4253775924, 118200754, 1634629088, 36862, 2276450037,
    ],
    &[
        968273619, 3005749070, 3110229216, 2592843849, 3169815897, 2983732227, 4079285387,
        1781202850, 2551120605, 160697240, 1692976527, 992581572, 2048177643, 2784003648,
        785053516, 3582407074, 1096161089, 3001502511, 3351752313, 1353097061, 3296373531,
        857864333, 642791484, 3113031500, 3247857250, 1760733790, 1121327242, 716363323,
        1144741207, 3717504557, 1248828497, 1455716137,
    ],
];

/// Run `steps` against a store from `new_store`, each step held to the
/// invariants above.
pub fn run(new_store: &dyn Fn() -> Arc<dyn RelationshipStore>, steps: &[u32]) {
    let first = steps.first().copied().unwrap_or(0);
    let base = now();
    let (mut run, mut twin) = (
        Run::new(new_store(), first, base),
        Run::new(new_store(), first, base),
    );
    twin.core
        .upgrades_off
        .store(true, std::sync::atomic::Ordering::Relaxed);
    run.start();
    twin.start();
    for &n in steps {
        // Both runs act as the same party, whatever the twin holds.
        let p = run.actor(n);
        run.step(n, p);
        twin.step(n, p);
        // The state a crowded rotation wrote by hand ends the run: what
        // follows would judge acts on state no act made.
        if run.crowded {
            break;
        }
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
    run.converged();
}

/// Each step of `steps` with each store call it makes failing in turn,
/// the steps before it replayed on a fresh store from `new_store`, whose
/// second half dumps all it holds: a step answered with an error leaves
/// the store as it was and tells nothing.
pub fn run_failing_each_call(
    new_store: &dyn Fn() -> (Arc<dyn RelationshipStore>, Dump),
    steps: &[u32],
) {
    let first = steps.first().copied().unwrap_or(0);
    for (i, &n) in steps.iter().enumerate() {
        // Each call failing in turn, then each `write` failing after each
        // of its parts.
        for (inside, from) in [(false, 1), (true, 0)] {
            for k in from.. {
                let (store, dump) = new_store();
                let mut run = Run::new(store, first, now());
                run.start();
                for &m in &steps[..i] {
                    let p = run.actor(m);
                    run.step(m, p);
                }
                let p = run.actor(n);
                let (step, _, d, _) = Step::of(n);
                run.told();
                run.requested = 0;
                run.told_by_reading();
                run.upgrading = run.upgrading_now();
                let held = |run: &Run| format!("{}\n{}", dump(), run.core.friend_state());
                let before = held(&run);
                match inside {
                    false => run.fail.fail_nth(k),
                    true => run.fail.fail_write_part(k),
                }
                let ok = run.act(step, p, d);
                let writes = run.fail.writes();
                run.fail.fail_nth(0);
                let Some(failed) = run.fail.failed() else {
                    break;
                };
                let what = match inside {
                    false => format!("{step:?} by {}, call {k} ({failed}) failing", LOGINS[p]),
                    true => format!("{step:?} by {}, a write failing after part {k}", LOGINS[p]),
                };
                let what = format!("{what} after {writes:?}");
                let by_reading = run.told_by_reading();
                if !ok {
                    assert_eq!(held(&run), before, "{what}: an error left a change");
                    let told = run.told();
                    assert!(
                        told.iter().flatten().all(Vec::is_empty) && run.requested == 0,
                        "{what}: an error told {told:?}, and {} requests",
                        run.requested
                    );
                    continue;
                }
                // One answered as done past the failure leaves a state the
                // model allows, each session told what it changed, but where
                // a tell still read after its step could cost one.
                run.legal(&what);
                let blocking = matches!(step, Step::Block | Step::BlockWithdrawal).then_some(p);
                let lapsing = matches!(step, Step::Clock { .. } | Step::Messaging) || run.crowded;
                run.shown(&what, by_reading.is_empty() && !lapsing, blocking);
            }
        }
    }
}

/// Everything a store holds, as text.
pub type Dump = Box<dyn Fn() -> String>;

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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn the_memory_store_is_left_as_it_was_by_a_step_that_fails(
            steps in proptest::collection::vec(any::<u32>(), 1..7)
        ) {
            super::run_failing_each_call(&|| {
                let store = std::sync::Arc::new(MemoryRelationships::new());
                let dumped = store.clone();
                (store as _, Box::new(move || dumped.dump()) as super::Dump)
            }, &steps);
        }
    }

    #[test]
    fn the_memory_store_keeps_the_sequences_found_before() {
        for steps in super::FOUND {
            super::run(&|| std::sync::Arc::new(MemoryRelationships::new()), steps);
        }
    }
}
