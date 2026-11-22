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
//!   ended both sides' evidence placed one.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hl_identity::friendship::Pair;
use hl_identity::{
    Acceptance, DeviceCert, DeviceKey, Fingerprint, Friendship, IdentityKey, Offer, Withdrawal,
};
use sha2::{Digest, Sha256};

use super::{Key, RosterState};
use crate::access::bit;
use crate::inbox::{Mailbox, MemoryStore};
use crate::relationships::failing::{Failing, READS};
use crate::relationships::{RelationId, RelationshipStore, Requester};
use crate::roster::{AttachInfo, Event, InboxPolicy, Uid};
use crate::{
    AccessBits, AccountDirectory, Core, Events, IdentityTag, MessagingPolicy, Revocations,
};

const LOGINS: [&str; 2] = ["alice", "bob"];

struct Person {
    id: IdentityKey,
    devices: Vec<(DeviceKey, Vec<u8>)>,
}

impl Person {
    fn new(seed: u8, now: u64) -> Self {
        let id = IdentityKey::from_seed(&[seed; 32]);
        let devices = (0..2u8)
            .map(|n| {
                let dev = DeviceKey::from_seed(&[seed * 16 + n + 1; 32]);
                let cert = DeviceCert::for_device(&id, &dev, now - 3600, 90 * 24 * 3600)
                    .expect("a certificate")
                    .sign(&id);
                (dev, cert)
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

    fn withdraw(&self, d: usize, other: &Person, time: u64) -> Vec<u8> {
        let (key, cert) = &self.devices[d];
        Withdrawal {
            from: self.id.public(),
            pair: Pair::new(Fingerprint(self.fp()), Fingerprint(other.fp())).hash(),
            party: None,
            before: time,
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
    /// Remove Friend (803), plain or with a withdrawal.
    Remove {
        withdraw: bool,
    },
    /// Block User (806)'s withdrawal, which blocks with it.
    BlockWithdrawal,
    Block,
    Unblock,
    PresentWithdrawal,
    /// Unlink the identity and link it again.
    Link,
    RemoveByKey,
    /// The messaging bit lost, or given back.
    Messaging,
    Revoke,
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
            },
            18 => Step::BlockWithdrawal,
            19 => Step::Block,
            20 | 21 => Step::Unblock,
            22 | 23 => Step::PresentWithdrawal,
            24 => Step::Link,
            25 => Step::RemoveByKey,
            26 => Step::Messaging,
            27 => Step::Revoke,
            28 | 29 => Step::Answer {
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
}

struct Run {
    core: Arc<Core>,
    store: Arc<dyn RelationshipStore>,
    fail: Arc<Failing>,
    dir: Arc<Directory>,
    people: [Person; 2],
    /// Each party's two device sessions.
    sessions: [[(Uid, Events); 2]; 2],
    friendships: Vec<Vec<u8>>,
    offers: [Option<Vec<u8>>; 2],
    revoked: HashSet<[u8; 32]>,
    /// Ids that were active with evidence both ways.
    portable: HashSet<RelationId>,
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
                .with_record_cache(Arc::new(
                    crate::identity_records::MemoryRecordCache::default(),
                )),
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
            people,
            sessions,
            friendships,
            offers: [None, None],
            revoked: HashSet::new(),
            portable: HashSet::new(),
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
            Step::Remove { withdraw } => {
                let w = withdraw.then(|| me.withdraw(d, them, now));
                core.friend_unfriend(uid, other, w).is_ok()
            }
            Step::BlockWithdrawal => core
                .block_withdrawing(uid, other, me.withdraw(d, them, now))
                .is_ok(),
            Step::Block => core.inbox_block(uid, other, true).is_ok(),
            Step::Unblock => core.inbox_block(uid, other, false).is_ok(),
            Step::PresentWithdrawal => core
                .friendships_present(uid, vec![me.withdraw(d, them, now)], vec![])
                .is_ok(),
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
        let read_failed = self.fail.failed().is_some_and(|m| READS.contains(&m));
        let what = format!("{step:?} by {} on device {d}, {failure:?}", LOGINS[p]);

        // An edge made active by presentations keeps its evidence both
        // ways while it is active.
        if let Some(id) = after.friendship {
            if after.evidence == [true, true] {
                self.portable.insert(id);
            }
            assert!(
                !self.portable.contains(&id) || after.evidence == [true, true],
                "{what}: edge {id} active without its evidence: {before:?} -> {after:?}"
            );
        }

        // An ending is told to each session of both once, a removal only
        // once committed, and only what removes or withdraws ends an edge
        // that was not its presentations' alone.
        let ended = before.friendship.is_some() && after.friendship != before.friendship;
        let ends = matches!(
            step,
            Step::Remove { .. }
                | Step::BlockWithdrawal
                | Step::Block
                | Step::PresentWithdrawal
                | Step::RemoveByKey
        ) || (matches!(step, Step::Link | Step::Revoke)
            && before.evidence == [true, true]);
        assert!(
            !ended || ends,
            "{what}: ended what it may not: {before:?} -> {after:?}"
        );
        for (q, sessions) in told.iter().enumerate() {
            for told in sessions {
                let removed = told.iter().filter(|s| **s == RosterState::Removed).count();
                assert!(removed <= 1, "{what}: {} told twice: {told:?}", LOGINS[q]);
                if removed > 0 {
                    assert_eq!(
                        after.friendship, None,
                        "{what}: {} told of a removal the store does not hold",
                        LOGINS[q]
                    );
                }
                if ended && !read_failed && self.takes_part(q) {
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
                | Step::PresentWithdrawal
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

/// Sequences a property test once found failing, run on every store.
pub const FOUND: &[&[u32]] = &[&[3653138233, 1083754464, 736438803, 2139438085]];

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
