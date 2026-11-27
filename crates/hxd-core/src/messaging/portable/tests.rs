//! Portable friendships against the in-memory stores, with real device
//! keys: made on one server and presented on another, withdrawn, dropped
//! with a revoked device, followed through a rotation, judged against a
//! device epoch floor, and refused to any act the device-act gate does
//! not admit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hl_identity::friendship::Pair;
use hl_identity::{
    Acceptance, DeviceCert, DeviceEpoch, DeviceKey, Fingerprint, Friendship, IdentityKey, Offer,
    Rotation, Withdrawal,
};
use sha2::{Digest, Sha256};

use super::super::tests::{messaging_bits, policy, server_of, Directory, Server};
use super::super::*;
use crate::identity_records::{CachedList, KeptEpoch, MemoryRecordCache, RecordCache};
use crate::inbox::{Mailbox, StoreError};
use crate::relationships::{Cause, Presentation, RelationId, Work};
use crate::roster::{drain, AttachInfo};
use crate::{Events, IdentityTag, InboxPolicy, Published, Revocations};

const DAY: u64 = 24 * 3600;

struct Person {
    id: IdentityKey,
    devices: Vec<(DeviceKey, Vec<u8>)>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An identity with two devices, each certified.
fn person(seed: u8) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let devices = (0..2)
        .map(|n| {
            let dev = DeviceKey::from_seed(&[seed.wrapping_mul(16).wrapping_add(n + 1); 32]);
            let cert = DeviceCert::for_device(&id, &dev, now() - 3600, 90 * DAY)
                .unwrap()
                .sign(&id);
            (dev, cert)
        })
        .collect();
    Person { id, devices }
}

fn fp(p: &Person) -> [u8; 32] {
    p.id.fingerprint().0
}

/// A device of `who` certified in `epoch`, beside its others: its index.
fn enroll(who: &mut Person, epoch: u64) -> usize {
    let seed: [u8; 32] = Sha256::digest([&fp(who)[..], &[who.devices.len() as u8]].concat()).into();
    let dev = DeviceKey::from_seed(&seed);
    let mut cert = DeviceCert::for_device(&who.id, &dev, now() - 3600, 90 * DAY).unwrap();
    cert.epoch = epoch;
    let cert = cert.sign(&who.id);
    who.devices.push((dev, cert));
    who.devices.len() - 1
}

/// `who` reset its devices to `epoch` at `time`: the record kept here, and
/// the floor installed as the lists publish it.
fn reset(s: &Server, who: &Person, epoch: u64, time: u64) {
    keep(s, who, epoch, time);
    install(s, who, epoch);
}

/// The record of `who`'s reset to `epoch` at `time`, kept here.
fn keep(s: &Server, who: &Person, epoch: u64, time: u64) {
    let record = DeviceEpoch {
        identity: who.id.public(),
        epoch,
        time,
    }
    .sign(&who.id)
    .unwrap();
    s.core
        .record_cache()
        .unwrap()
        .keep_epoch(
            &fp(who),
            &KeptEpoch {
                epoch,
                time,
                record,
            },
        )
        .unwrap();
}

/// `who`'s floor at `epoch`, installed as the lists publish it.
fn install(s: &Server, who: &Person, epoch: u64) {
    s.core.set_published_revocations(Published {
        floors: [(fp(who), epoch)].into(),
        covered: [fp(who)].into(),
        ..Default::default()
    });
}

fn offer(from: &Person, dev: usize, to: &Person, time: u64) -> Vec<u8> {
    let (key, cert) = &from.devices[dev];
    Offer {
        from: from.id.public(),
        to: Fingerprint(fp(to)),
        time,
        expires: time + DAY,
        id: [time as u8; 16],
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn accept(offer: &[u8], by: &Person, dev: usize, time: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    let acceptance = Acceptance {
        offer: Sha256::digest(offer).into(),
        from: by.id.public(),
        time,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap();
    Friendship::encode(offer, &acceptance)
}

fn withdraw(by: &Person, dev: usize, other: &Person, before: u64) -> Vec<u8> {
    withdraw_at(by, dev, other, before, now().max(before))
}

fn withdraw_at(by: &Person, dev: usize, other: &Person, before: u64, time: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    Withdrawal {
        from: by.id.public(),
        pair: Pair::new(Fingerprint(fp(by)), Fingerprint(fp(other))).hash(),
        party: None,
        before,
        time,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn hash(friendship: &[u8]) -> [u8; 32] {
    Sha256::digest(friendship).into()
}

/// [`linked`], with the directory its unlinks are written to.
fn switched(policy: MessagingPolicy, accounts: &[(&str, &[u8; 32])]) -> (Server, Switch) {
    let dir = Switch(Arc::new(std::sync::Mutex::new(
        (accounts.iter())
            .map(|(l, fp)| (Mailbox::identified(*l, **fp), messaging_bits()))
            .collect(),
    )));
    let s = server_of(dir.clone(), policy, InboxPolicy::default(), None);
    (s, dir)
}

/// The account linking `fingerprint` gives the link up, as the identity
/// layer unlinks: written to the directory, then the unlink's work owed.
fn unlinked(s: &Server, dir: &Switch, fingerprint: &[u8; 32]) {
    s.core
        .friendships_unlinking(fingerprint, |owe| {
            owe()?;
            for (m, _) in dir.0.lock().unwrap().iter_mut() {
                if m.fingerprint == Some(*fingerprint) {
                    *m = Mailbox::login(&m.login);
                }
            }
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

/// A server whose accounts link these identities.
fn linked(accounts: &[(&str, &[u8; 32])]) -> Server {
    linked_with(policy(), accounts)
}

fn linked_with(policy: MessagingPolicy, accounts: &[(&str, &[u8; 32])]) -> Server {
    let dir = Directory(
        accounts
            .iter()
            .map(|(l, fp)| (Mailbox::identified(*l, **fp), messaging_bits()))
            .collect(),
    );
    server_of(dir, policy, InboxPolicy::default(), None)
}

/// A session of `login`'s account that proved `who`'s device `dev`, and asked for
/// portable friendships where `friendships` says so; `expires` is its
/// certificate's.
fn session(
    core: &Core,
    login: &str,
    who: &Person,
    dev: usize,
    friendships: bool,
    expires: u64,
) -> (Uid, Events) {
    let (key, cert) = &who.devices[dev];
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
                    fingerprint: fp(who),
                    device: Fingerprint::of(&key.public()).0,
                    handle: None,
                    quiet_until: None,
                    signs: false,
                    can_sign: false,
                    device_expires: expires,
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
            identity: core
                .directory
                .as_ref()
                .and_then(|d| d.account(login))
                .and_then(|(m, _)| m.fingerprint),
            system: false,
        })
        .unwrap();
    core.announce(uid);
    drain(&mut rx);
    (uid, rx)
}

fn device(core: &Core, login: &str, who: &Person, dev: usize) -> (Uid, Events) {
    session(core, login, who, dev, true, u64::MAX)
}

/// An entry told, as `(login, state, hashes, withdraw)`.
type Told = (String, RosterState, Vec<[u8; 32]>, Option<Vec<u8>>);

fn told(rx: &mut Events) -> Vec<Told> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) => Some((e.login, e.state, e.friendships, e.withdraw)),
            _ => None,
        })
        .collect()
}

fn ok_all(results: &[PresentResult]) -> bool {
    results.iter().all(|r| r.outcome == Presented::Ok)
}

/// Alice and Bob made friends on `s` a minute ago, from their first
/// devices.
fn made(s: &Server, alice: &Person, bob: &Person) -> (Uid, Events, Uid, Events, Vec<u8>) {
    let (a, mut ra) = device(&s.core, "alice", alice, 0);
    let (b, mut rb) = device(&s.core, "bob", bob, 0);
    let o = offer(alice, 0, bob, now() - 60);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let f = accept(&o, bob, 0, now() - 60);
    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(f.clone())),
        Ok(RosterState::Accepted)
    );
    drain(&mut ra);
    drain(&mut rb);
    (a, ra, b, rb, f)
}

#[test]
fn a_friendship_made_on_one_server_is_presented_on_another() {
    let (alice, bob) = (person(1), person(2));
    let s1 = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, mut ra) = device(&s1.core, "alice", &alice, 0);
    let (b, mut rb) = device(&s1.core, "bob", &bob, 0);
    let (plain, mut rp) = session(&s1.core, "bob", &bob, 1, false, u64::MAX);
    s1.core.friends_roster(plain).unwrap();
    drain(&mut rp);

    let o = offer(&alice, 0, &bob, now());
    assert_eq!(
        s1.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let offered = |rx: &mut Events| {
        drain(rx).into_iter().find_map(|e| match e {
            Event::FriendRequest { offer, .. } => Some(offer),
            _ => None,
        })
    };
    assert_eq!(
        offered(&mut rb),
        Some(Some(o.clone())),
        "the offer, to a device"
    );
    assert_eq!(offered(&mut rp), Some(None), "a plain request, to the rest");

    let f = accept(&o, &bob, 0, now());
    assert_eq!(
        s1.core.friend_answer(b, "alice", true, Some(f.clone())),
        Ok(RosterState::Accepted)
    );
    assert!(told(&mut ra).contains(&("bob".into(), RosterState::Accepted, vec![hash(&f)], None)));
    assert!(
        told(&mut rp).contains(&("alice".into(), RosterState::Accepted, vec![], None)),
        "a client that never asked sees the extension's entry"
    );

    // A second server, where neither has been: friends once both present,
    // with no request.
    let s2 = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a2, mut ra2) = device(&s2.core, "alice", &alice, 1);
    let (b2, mut rb2) = device(&s2.core, "bob", &bob, 1);
    let (_, alone) = s2
        .core
        .friendships_present(a2, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&alone));
    assert!(told(&mut ra2).is_empty(), "inactive until both present");
    let (_, both) = s2
        .core
        .friendships_present(b2, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&both));
    for rx in [&mut ra2, &mut rb2] {
        let entries = told(rx);
        assert!(
            entries
                .iter()
                .any(|(_, state, hashes, _)| *state == RosterState::Accepted
                    && *hashes == [hash(&f)]),
            "{entries:?}"
        );
    }
    let fetched = s2
        .core
        .friendships_fetch(a2, &[hash(&f), [9; 32]], &[])
        .unwrap();
    assert_eq!(fetched.friendships, [(hash(&f), Some(f)), ([9; 32], None)]);
}

#[test]
fn a_withdrawal_on_one_server_ends_the_friendship_on_another() {
    let (alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (a1, _, _, mut rb1, f) = made(&s1, &alice, &bob);
    let s2 = linked(&accounts);
    let (a2, _) = device(&s2.core, "alice", &alice, 1);
    let (b2, mut rb2) = device(&s2.core, "bob", &bob, 1);
    for uid in [a2, b2] {
        s2.core
            .friendships_present(uid, vec![], vec![f.clone()])
            .unwrap();
    }
    drain(&mut rb2);

    let before = now();
    let w = withdraw(&alice, 1, &bob, before);
    assert_eq!(s2.core.friend_unfriend(a2, "bob", Some(w.clone())), Ok(()));
    assert_eq!(
        told(&mut rb2),
        [("alice".into(), RosterState::Removed, vec![], Some(w))]
    );

    // Alice's other device brings the cutoff to the first server, signed
    // afresh, and Bob is told there too.
    let again = withdraw(&alice, 0, &bob, before);
    let (taken, _) = s1
        .core
        .friendships_present(a1, vec![again.clone()], vec![])
        .unwrap();
    assert!(ok_all(&taken));
    assert_eq!(
        told(&mut rb1),
        [(
            "alice".into(),
            RosterState::Removed,
            vec![],
            Some(again.clone())
        )]
    );
    // And the friendship cannot be presented there again.
    let (b1b, _) = device(&s1.core, "bob", &bob, 1);
    let (_, refused) = s1.core.friendships_present(b1b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Withdrawn(Some(again)));
}

#[test]
fn a_revoked_device_takes_its_presentations_with_it() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, mut rb, f) = made(&s, &alice, &bob);
    let mine = Mailbox::identified("alice", fp(&alice));
    let id = s
        .rel
        .relationship(
            &mine,
            &Mailbox::identified("bob", fp(&bob)),
            std::time::SystemTime::now(),
        )
        .unwrap()
        .unwrap()
        .friendship
        .unwrap();

    let revoked = Fingerprint::of(&alice.devices[0].0.public()).0;
    s.core.set_revocations(Revocations {
        devices: [revoked].into(),
        ..Default::default()
    });
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)],
        "removed here, with no withdrawal"
    );
    assert!(
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
            .is_err(),
        "the revoked device acts no more"
    );
    // The device that stays presents again, and the friendship is back
    // under the id it had, so what was queued on it is released.
    let (a2, _) = device(&s.core, "alice", &alice, 1);
    let (_, back) = s.core.friendships_present(a2, vec![], vec![f]).unwrap();
    assert!(ok_all(&back));
    assert!(s.rel.is_live(id));
}

#[test]
fn a_revocation_lifted_while_its_drop_is_read_drops_nothing() {
    let (alice, bob, s, _) = offered_by_alice();
    let revoked = Fingerprint::of(&alice.devices[0].0.public()).0;
    let parked = s.fail.park.arm("offers_from");
    std::thread::scope(|t| {
        let first = t.spawn(|| {
            s.core.set_revocations(Revocations {
                devices: [revoked].into(),
                ..Default::default()
            })
        });
        parked.arrived();
        s.core.set_revocations(Revocations::default());
        parked.release();
        first.join().unwrap();
    });
    assert!(offering(&s, &alice, &bob), "the lifted device's offer");
}

#[test]
fn a_revocation_lifted_before_its_sweep_runs_drops_nothing() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    made(&s, &alice, &bob);
    let revoked = Fingerprint::of(&alice.devices[0].0.public()).0;
    let installed = || {
        s.core
            .revoked
            .read()
            .unwrap()
            .local
            .devices
            .contains(&revoked)
    };
    // The first install's sweep waits on the hold while a second lifts it.
    std::thread::scope(|t| {
        let writing = s.core.friend_writes();
        let first = t.spawn(|| {
            s.core.set_revocations(Revocations {
                devices: [revoked].into(),
                ..Default::default()
            })
        });
        while !installed() {
            std::thread::yield_now();
        }
        s.core.set_revocations(Revocations::default());
        drop(writing);
        first.join().unwrap();
    });
    assert!(
        (s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap()).is_some(),
        "the lifted device's presentation"
    );
}

#[test]
fn a_removal_without_a_withdrawal_holds_here_against_the_removers_other_devices() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, mut ra, _, _, f) = made(&s, &alice, &bob);
    let (password, _) = session(&s.core, "bob", &bob, 1, false, u64::MAX);
    assert_eq!(s.core.friend_remove(password, "alice"), Ok(()));
    assert_eq!(
        told(&mut ra),
        [("bob".into(), RosterState::Removed, vec![], None)]
    );
    let (other, _) = device(&s.core, "bob", &bob, 1);
    let (_, refused) = s.core.friendships_present(other, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Withdrawn(None));
}

#[test]
fn the_gate_refuses_every_act_a_proved_device_of_the_account_did_not_make() {
    let (alice, bob, mallory) = (person(1), person(2), person(3));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = now();
    let cases = [
        (
            "a session that did not ask",
            (false, u64::MAX, &alice),
            offer(&alice, 0, &bob, t),
            MessagingError::NotDeviceProved,
        ),
        (
            "a certificate expired since login",
            (true, t - 1, &alice),
            offer(&alice, 0, &bob, t),
            MessagingError::NotDeviceProved,
        ),
        (
            "another identity's device",
            (true, u64::MAX, &mallory),
            offer(&mallory, 0, &bob, t),
            MessagingError::NotDeviceProved,
        ),
        (
            "signed by another of its devices",
            (true, u64::MAX, &alice),
            offer(&alice, 1, &bob, t),
            MessagingError::BadSignature,
        ),
        (
            "out of time",
            (true, u64::MAX, &alice),
            offer(&alice, 0, &bob, t - 3600),
            MessagingError::Stale,
        ),
    ];
    for (case, (asked, expires, proved), o, want) in cases {
        let (uid, _) = session(&s.core, "alice", proved, 0, asked, expires);
        assert_eq!(
            s.core.friend_ask(uid, "bob", None, Some(o)),
            Err(want),
            "{case}"
        );
        s.core.end_session(uid);
    }
}

#[test]
fn a_rotated_identity_presents_its_old_friendships_and_its_record_is_fetched() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    // The account links the successor already: the rotation has moved it.
    let s = linked(&[("alice", &fp(&successor)), ("bob", &fp(&bob))]);
    let record = Rotation {
        identity: alice.id.public(),
        successor: successor.id.public(),
        time: now(),
        next: None,
    }
    .sign(&alice.id, &successor.id)
    .unwrap();
    s.core.keep_rotation_record(&record);

    let o = offer(&alice, 0, &bob, now() - 60);
    let f = accept(&o, &bob, 0, now() - 60);
    let (a, _) = device(&s.core, "alice", &successor, 0);
    let (b, mut rb) = device(&s.core, "bob", &bob, 0);
    let (_, by_bob) = s
        .core
        .friendships_present(b, vec![], vec![f.clone()])
        .unwrap();
    assert!(
        ok_all(&by_bob),
        "the predecessor's party is the successor's account"
    );
    let (_, by_alice) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert!(
        ok_all(&by_alice),
        "the successor presents in the predecessor's place"
    );
    assert!(told(&mut rb)
        .iter()
        .any(|(login, state, _, _)| login == "alice" && *state == RosterState::Accepted));

    let fetched = s
        .core
        .friendships_fetch(b, &[], &[fp(&successor), fp(&alice)])
        .unwrap();
    assert_eq!(
        fetched.rotations,
        [(fp(&successor), vec![record]), (fp(&alice), vec![])],
        "the records behind a friend's key, and nothing for a key no friend has"
    );
}

fn requests_offered(rx: &mut Events) -> Vec<Option<Vec<u8>>> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendRequest { offer, .. } => Some(offer),
            _ => None,
        })
        .collect()
}

#[test]
fn every_friendship_act_is_refused_to_a_session_that_did_not_prove_a_device() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let o = offer(&alice, 0, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    let (plain, _) = session(&s.core, "bob", &bob, 0, false, u64::MAX);
    let f = accept(&o, &bob, 0, now());
    let denied: Result<(), _> = Err(MessagingError::NotDeviceProved);
    assert_eq!(
        s.core
            .friend_answer(plain, "alice", true, Some(f.clone()))
            .map(|_| ()),
        denied,
        "805"
    );
    assert_eq!(
        s.core
            .block_withdrawing(plain, "alice", withdraw(&bob, 0, &alice, now())),
        denied
    );
    assert_eq!(
        s.core
            .friendships_present(plain, vec![], vec![f.clone()])
            .map(|_| ()),
        denied,
        "present"
    );
    assert_eq!(
        s.core
            .friendships_fetch(plain, &[hash(&f)], &[])
            .map(|_| ()),
        denied
    );

    // A friendship, and a removal whose withdrawal the gate refuses: the
    // friend goes here all the same.
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core.friend_answer(b, "alice", true, Some(f)).unwrap();
    assert_eq!(
        s.core
            .friend_unfriend(plain, "alice", Some(withdraw(&bob, 0, &alice, now()))),
        denied,
        "803"
    );
    let row = s
        .rel
        .relationship(
            &Mailbox::identified("bob", fp(&bob)),
            &Mailbox::identified("alice", fp(&alice)),
            std::time::SystemTime::now(),
        )
        .unwrap();
    assert!(row.is_none_or(|r| r.friendship.is_none()), "removed here");
}

#[test]
fn a_withdrawal_presented_must_be_the_sessions_own() {
    let (alice, bob, mallory) = (person(1), person(2), person(3));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, _) = made(&s, &alice, &bob);
    let t = now();
    for (case, w, want) in [
        (
            "another of its devices",
            withdraw(&alice, 1, &bob, t),
            Presented::BadSignature,
        ),
        (
            "someone else's",
            withdraw(&mallory, 0, &bob, t),
            Presented::BadSignature,
        ),
        (
            "an hour old",
            withdraw_at(&alice, 0, &bob, t - 3600, t - 3600),
            Presented::Stale,
        ),
    ] {
        let (taken, _) = s
            .core
            .friendships_present(a, vec![w.clone()], vec![])
            .unwrap();
        let pair = Withdrawal::parse(&w, u64::MAX, |_| 0)
            .unwrap()
            .withdrawal()
            .pair;
        assert_eq!(
            taken[0],
            PresentResult {
                hash: pair,
                outcome: want
            },
            "{case}"
        );
    }
}

#[test]
fn a_withdrawal_ends_a_friendship_of_this_server_alone_only_where_it_predates_it() {
    let (alice, bob) = (person(1), person(2));
    let t = now();
    // A cutoff after the friendship was made ends it; one before leaves it.
    for (before, ends) in [(t + 5, true), (t - 100, false)] {
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let (b, mut rb) = device(&s.core, "bob", &bob, 0);
        s.core.friend_add(a, "bob", None).unwrap();
        s.core.friend_respond(b, "alice", true).unwrap();
        drain(&mut rb);
        let w = withdraw_at(&alice, 0, &bob, before, before.max(t));
        let (taken, _) = s.core.friendships_present(a, vec![w], vec![]).unwrap();
        assert!(ok_all(&taken));
        let removed = told(&mut rb)
            .iter()
            .any(|(_, state, _, _)| *state == RosterState::Removed);
        assert_eq!(removed, ends, "before {before}");
    }
}

#[test]
fn an_offer_crossing_a_request_waits_for_its_answer() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .set_presence(
            b,
            PresenceUpdate {
                takes_requests: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    s.core.friend_add(b, "alice", None).unwrap();
    assert_eq!(
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now()))),
        Err(MessagingError::RequestPending),
        "an offer meeting a request"
    );

    // A plain request meeting an offer, from a session that understands
    // requests, crosses as the extension's do: a friendship here, the
    // offer dropped.
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    s.core
        .set_presence(
            b,
            PresenceUpdate {
                takes_requests: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Ok(RosterState::Accepted)
    );
    assert_eq!(
        s.rel
            .offer(&fp(&alice), &fp(&bob), std::time::SystemTime::now())
            .unwrap(),
        None
    );
}

#[test]
fn an_upgrade_offer_reaches_the_friends_devices_alone_and_an_offer_lapses() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, mut rb) = device(&s.core, "bob", &bob, 0);
    let (plain, mut rp) = session(&s.core, "bob", &bob, 1, false, u64::MAX);
    s.core.friends_roster(plain).unwrap();
    s.core.friend_add(a, "bob", None).unwrap();
    s.core.friend_respond(b, "alice", true).unwrap();
    drain(&mut rb);
    drain(&mut rp);
    let o = offer(&alice, 0, &bob, now());
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::Accepted),
        "an upgrade offer"
    );
    assert_eq!(requests_offered(&mut rb), [Some(o)]);
    assert!(
        requests_offered(&mut rp).is_empty(),
        "a plain session hears nothing"
    );

    // An offer on a request lapses at its expiry, leaving the request.
    let carol = person(5);
    let s = linked(&[("alice", &fp(&alice)), ("carol", &fp(&carol))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (c, _) = device(&s.core, "carol", &carol, 0);
    let o = offer(&alice, 0, &carol, now());
    s.core
        .friend_ask(a, "carol", None, Some(o.clone()))
        .unwrap();
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(2 * DAY));
    let roster = s.core.friends_roster(c).unwrap();
    assert_eq!(
        (roster[0].state, roster[0].offer.clone()),
        (RosterState::PendingIn, None)
    );
    assert_eq!(
        s.core
            .friend_answer(c, "alice", true, Some(accept(&o, &carol, 0, now()))),
        Err(MessagingError::Stale),
        "its offer lapsed"
    );
    assert_eq!(
        s.core.friend_respond(c, "alice", true),
        Ok(RosterState::Accepted)
    );
}

#[test]
fn presenting_answers_one_way_for_an_absent_or_blocking_party_and_is_bounded() {
    let (alice, bob, mallory, carol) = (person(1), person(2), person(3), person(5));
    let tight = MessagingPolicy {
        max_roster: 1,
        ..policy()
    };
    let s = linked_with(tight, &[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let with = |other: &Person| accept(&offer(&alice, 0, other, now() - 60), other, 0, now() - 60);
    s.core.inbox_block(b, "alice", true).unwrap();
    let outcome = |f: Vec<u8>| {
        s.core.friendships_present(a, vec![], vec![f]).unwrap().1[0]
            .outcome
            .clone()
    };
    assert_eq!(outcome(with(&bob)), Presented::AccountNotFound, "blocked");
    // The refusal counts toward the bound on presentations not active, so
    // reaching it says nothing of which party was there.
    assert_eq!(outcome(with(&mallory)), Presented::RosterFull);
    s.core.friend_remove_by_key(a, &fp(&bob), None).unwrap();
    assert_eq!(
        outcome(with(&mallory)),
        Presented::AccountNotFound,
        "absent"
    );
    assert!(
        s.rel
            .presentation(&fp(&alice), &fp(&bob))
            .unwrap()
            .is_none(),
        "dropped by fingerprint"
    );
    assert_eq!(outcome(with(&carol)), Presented::RosterFull);
}

#[test]
fn too_many_objects_or_two_withdrawals_for_a_pair_are_malformed() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let w = withdraw(&alice, 0, &bob, now());
    for (case, ws) in [
        ("33 objects", vec![w.clone(); MAX_OBJECTS + 1]),
        ("one pair twice", vec![w.clone(), w]),
    ] {
        assert_eq!(
            s.core.friendships_present(a, ws, vec![]).map(|_| ()),
            Err(MessagingError::TooMany),
            "{case}"
        );
    }
    assert_eq!(
        s.core
            .friendships_fetch(a, &[[0; 32]; MAX_OBJECTS + 1], &[])
            .map(|_| ()),
        Err(MessagingError::TooMany)
    );
}

#[test]
fn an_unlinked_identitys_sessions_make_no_more_friendship_acts() {
    let (alice, bob) = (person(1), person(2));
    let (s, dir) = switched(policy(), &[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, f) = made(&s, &alice, &bob);
    unlinked(&s, &dir, &fp(&alice));
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_none());
    assert_eq!(
        s.core.friendships_present(a, vec![], vec![f]).map(|_| ()),
        Err(MessagingError::NotDeviceProved)
    );
}

#[test]
fn a_removal_without_a_withdrawal_holds_past_an_earlier_signed_one() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, _, b, _, f) = made(&s, &alice, &bob);
    // Bob withdrew before this friendship was made: it stands.
    let early = withdraw_at(&bob, 0, &alice, now() - 120, now());
    let (taken, _) = s.core.friendships_present(b, vec![early], vec![]).unwrap();
    assert!(ok_all(&taken));
    let (password, _) = session(&s.core, "bob", &bob, 1, false, u64::MAX);
    assert_eq!(s.core.friend_remove(password, "alice"), Ok(()));
    let (other, _) = device(&s.core, "bob", &bob, 1);
    let (_, refused) = s.core.friendships_present(other, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Withdrawn(None));
}

#[test]
fn a_blocks_withdrawal_tells_nothing_of_a_blocker() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core.inbox_block(b, "alice", true).unwrap();
    let w = withdraw(&alice, 0, &bob, now());
    assert_eq!(s.core.block_withdrawing(a, "bob", w.clone()), Ok(()));
    assert_eq!(s.core.block_withdrawing(a, "nobody", w), Ok(()));
}

#[test]
fn a_device_revoked_while_an_act_waits_for_the_lock_records_nothing() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, now() - 60);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let device = Fingerprint::of(&alice.devices[0].0.public()).0;
    let core = s.core.clone();
    let present = {
        // Held as a cleanup or another act would hold it, so the act
        // waits with its authorization not yet asked for.
        let writing = s.core.friend_writes();
        let presenting =
            std::thread::spawn(move || core.friendships_present(a, vec![], vec![f]).map(|_| ()));
        std::thread::sleep(std::time::Duration::from_millis(100));
        let core = s.core.clone();
        let revoking = std::thread::spawn(move || {
            core.set_revocations(Revocations {
                devices: [device].into(),
                ..Default::default()
            })
        });
        let cert = crate::CertRef {
            identity: fp(&alice),
            device,
            epoch: 0,
        };
        while !s.core.refuses(&cert) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        drop(writing);
        revoking.join().unwrap();
        presenting.join().unwrap()
    };
    assert_eq!(present, Err(MessagingError::NotDeviceProved));
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_none());
}

#[test]
fn a_reset_holds_what_was_taken_before_it_and_refuses_what_was_not() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let t = s1.core.clock().unix();
    let (_, _, b1, mut rb1, f) = made(&s1, &alice, &bob);
    reset(&s1, &alice, 1, t + 5);
    assert!(
        !told(&mut rb1).iter().any(|e| e.1 == RosterState::Removed),
        "held: taken before the reset"
    );
    let (_, again) = s1
        .core
        .friendships_present(b1, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&again), "presented again as before: {again:?}");

    // A server that never took it before the reset: refused whichever
    // party presents it, and never active.
    let s2 = linked(&accounts);
    reset(&s2, &alice, 1, s2.core.clock().unix() - 1);
    let renewed = enroll(&mut alice, 1);
    let (a2, mut ra2) = device(&s2.core, "alice", &alice, renewed);
    let (b2, _) = device(&s2.core, "bob", &bob, 0);
    for uid in [b2, a2] {
        let (_, refused) = s2
            .core
            .friendships_present(uid, vec![], vec![f.clone()])
            .unwrap();
        assert_eq!(refused[0].outcome, Presented::Reset);
    }
    assert!(told(&mut ra2).is_empty(), "never active");
}

/// Alice reset after making friends with Bob elsewhere, and enrolled a
/// device since; `s`, under `policy`, never took their friendship, and
/// has Carol's account too. Bob's first device, a session of his that
/// never asked for portable friendships, and Alice's new device, each
/// with its events.
fn reset_elsewhere(
    alice: &mut Person,
    bob: &Person,
    policy: MessagingPolicy,
) -> (Server, Vec<u8>, usize, [(Uid, Events); 3]) {
    let (s, _, f, renewed, sessions) = reset_elsewhere_switched(alice, bob, policy);
    (s, f, renewed, sessions)
}

/// [`reset_elsewhere`], with the directory its unlinks are written to.
fn reset_elsewhere_switched(
    alice: &mut Person,
    bob: &Person,
    policy: MessagingPolicy,
) -> (Server, Switch, Vec<u8>, usize, [(Uid, Events); 3]) {
    let carol = fp(&person(5));
    let accounts = [("alice", &fp(alice)), ("bob", &fp(bob)), ("carol", &carol)];
    let (_, _, _, _, f) = made(&linked(&accounts), alice, bob);
    let (s, dir) = switched(policy, &accounts);
    reset(&s, alice, 1, s.core.clock().unix() - 1);
    let renewed = enroll(alice, 1);
    let a = device(&s.core, "alice", alice, renewed);
    let b = device(&s.core, "bob", bob, 0);
    let plain = session(&s.core, "bob", bob, 1, false, u64::MAX);
    s.core.friends_roster(plain.0).unwrap();
    (s, dir, f, renewed, [a, b, plain])
}

/// Whether `target` is shown a request from `sender`.
fn requested(s: &Server, target: &Mailbox, sender: &Mailbox) -> bool {
    s.rel
        .pending_in(target, s.core.clock().wall())
        .unwrap()
        .iter()
        .any(|r| r.owner.login == sender.login)
}

fn mailboxes(alice: &Person, bob: &Person) -> (Mailbox, Mailbox) {
    (
        Mailbox::identified("alice", fp(alice)),
        Mailbox::identified("bob", fp(bob)),
    )
}

#[test]
fn an_upgrade_offer_on_a_friendship_answered_reset_is_its_friends_alone_and_a_decline_holds() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, mut ra), (b, mut rb), (_, mut rp)]) =
        reset_elsewhere(&mut alice, &bob, policy());
    let (_, refused) = s
        .core
        .friendships_present(b, vec![], vec![f.clone()])
        .unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let kept = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap().unwrap();
    assert_eq!(
        (kept.friendship, kept.reset),
        (None, Some(f.clone())),
        "a record, never evidence"
    );

    // Answered as a request is, told to Bob's friendships sessions alone
    // and asking nothing of the request bounds; declined, the offer goes
    // and Alice is held, as from a request.
    let o = offer(&alice, renewed, &bob, now() - 2);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(requests_offered(&mut rb), [Some(o)]);
    assert!(requests_offered(&mut rp).is_empty(), "a plain session");
    assert_eq!(
        told(&mut ra),
        [("bob".into(), RosterState::PendingOut, vec![], None)],
        "Alice told as of a request"
    );
    let (ma, mb) = mailboxes(&alice, &bob);
    let wall = s.core.clock().wall();
    assert!(!requested(&s, &mb, &ma));
    assert_eq!(
        s.core.friend_respond(b, "alice", false),
        Ok(RosterState::Removed)
    );
    assert!(s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap().is_none());
    let o = offer(&alice, renewed, &bob, now() - 1);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o)),
        Ok(RosterState::PendingOut)
    );
    assert!(requests_offered(&mut rb).is_empty(), "held");
    assert!(s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap().is_none());
}

#[test]
fn an_offer_is_an_upgrade_only_from_the_half_below_its_floor_and_within_the_record() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (ma, mb) = mailboxes(&alice, &bob);
    let asking = |x: &Mailbox, y: &Mailbox| requested(&s, y, x);
    // Alice's presentation answered `Reset`: Bob's half is not below its
    // floor, so his offer is a request.
    let (_, refused) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    s.core
        .friend_ask(b, "alice", None, Some(offer(&bob, 0, &alice, now())))
        .unwrap();
    assert!(asking(&mb, &ma));
    s.core.friend_remove(b, "alice").unwrap();

    // Bob's, thirty days on: the record has gone by then.
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(30 * DAY + 1));
    let o = offer(&alice, renewed, &bob, s.core.clock().unix());
    s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
    assert!(asking(&ma, &mb));
}

#[test]
fn an_offer_waiting_when_its_friendship_is_answered_reset_becomes_an_upgrade() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, mut ra), (b, mut rb), (_, mut rp)]) =
        reset_elsewhere(&mut alice, &bob, policy());
    let (plain_alice, mut rap) = session(&s.core, "alice", &alice, renewed, false, u64::MAX);
    s.core.friends_roster(plain_alice).unwrap();
    let (ma, mb) = mailboxes(&alice, &bob);
    let o = offer(&alice, renewed, &bob, now());
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    for rx in [&mut ra, &mut rb, &mut rp, &mut rap] {
        drain(rx);
    }
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let removed_of = |evs: &[Event], login: &str| {
        evs.iter().any(|e| {
            matches!(e, Event::FriendEntry(e) if e.login == login && e.state == RosterState::Removed)
        })
    };
    let removed = |evs: &[Event]| removed_of(evs, "alice");
    assert!(
        drain(&mut rap).is_empty(),
        "the sender's sessions told nothing"
    );
    assert!(drain(&mut ra).is_empty());
    let mine = s.core.friends_roster(plain_alice).unwrap();
    assert_eq!(
        mine.iter()
            .map(|e| (e.login.as_str(), e.state))
            .collect::<Vec<_>>(),
        [("bob", RosterState::PendingOut)],
        "nothing changed from Alice's side"
    );
    assert_eq!(
        s.core.friend_add(plain_alice, "bob", None),
        Err(MessagingError::RequestPending)
    );
    let offered = |evs: &[Event]| -> Vec<Option<Vec<u8>>> {
        evs.iter()
            .filter_map(|e| match e {
                Event::FriendRequest { offer, .. } => Some(offer.clone()),
                _ => None,
            })
            .collect()
    };
    let (upgrading, plain) = (drain(&mut rb), drain(&mut rp));
    assert_eq!(
        (offered(&upgrading), removed(&upgrading)),
        (vec![Some(o.clone())], false),
        "told again, as an upgrade"
    );
    assert_eq!(
        (offered(&plain), removed(&plain)),
        (vec![], true),
        "a session that never asked told the request is gone"
    );
    assert!(!requested(&s, &mb, &ma), "out of the request bounds");
    let remade = accept(&o, &bob, 0, now());
    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(remade.clone())),
        Ok(RosterState::Accepted)
    );
    assert!(friendship_of(&s, &alice, &bob).is_some());
    let p = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap().unwrap();
    assert_eq!(
        (p.friendship, p.reset),
        (Some(remade), None),
        "the record goes"
    );
}

/// An offer of Alice's device `dev` to Bob that lapses `days` on.
fn offer_for(from: &Person, dev: usize, to: &Person, time: u64, days: u64) -> Vec<u8> {
    let (key, cert) = &from.devices[dev];
    Offer {
        from: from.id.public(),
        to: Fingerprint(fp(to)),
        time,
        expires: time + days * DAY,
        id: [time as u8 ^ 0x55; 16],
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

#[test]
fn a_reset_record_lapses_thirty_days_after_its_last_answer() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, _, [_, (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let record = || {
        s.rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .unwrap()
            .reset
    };
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(30 * DAY - 2));
    s.core.owed_tick();
    assert!(record().is_some(), "kept into its thirtieth day");
    s.core.clock().advance(std::time::Duration::from_secs(2));
    s.core.owed_tick();
    assert_eq!(record(), None, "its bytes gone, its hash kept");
}

#[test]
fn an_upgrade_waiting_keeps_its_record_and_an_offer_made_again_past_thirty_days() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (ma, mb) = mailboxes(&alice, &bob);
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(29 * DAY));
    let first = offer_for(&alice, renewed, &bob, s.core.clock().unix(), 30);
    s.core
        .friend_ask(a, "bob", None, Some(first.clone()))
        .unwrap();
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(2 * DAY));
    s.core.owed_tick();
    let p = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap().unwrap();
    assert!(p.reset.is_some(), "kept while the upgrade waits");
    // Asked again, answered as a request asked again is; the one waiting
    // still taken.
    let t = s.core.clock().unix();
    let again = offer(&alice, renewed, &bob, t);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(again)),
        Err(MessagingError::RequestPending)
    );
    assert!(!requested(&s, &mb, &ma), "still an upgrade, no request");
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&first, &bob, 0, t))),
        Ok(RosterState::Accepted)
    );
}

#[test]
fn an_offer_beside_a_request_is_no_upgrade() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [_, (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (ma, mb) = mailboxes(&alice, &bob);
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(31 * DAY));
    // A request held, beside an offer waiting from before.
    let (t, wall) = (s.core.clock().unix(), s.core.clock().wall());
    let o = offer_for(&alice, renewed, &bob, t - 60, 30);
    let stored = crate::relationships::StoredOffer {
        offer: o.clone(),
        lapses_at: wall + std::time::Duration::from_secs(DAY),
    };
    s.rel
        .set_offer(&fp(&alice), &fp(&bob), Some(&stored))
        .unwrap();
    let held = crate::relationships::PendingOut {
        sent_at: wall,
        lapses_at: wall + std::time::Duration::from_secs(DAY),
        delivered: false,
        note: None,
        offer: None,
        upgrade: false,
    };
    s.rel.set_pending_out(&ma, &mb, Some(&held)).unwrap();
    assert_eq!(
        s.core.friend_respond(b, "alice", false),
        Err(MessagingError::NotFriends)
    );
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 0, t))),
        Err(MessagingError::NotFriends)
    );
}

#[test]
fn an_offer_its_request_lapsed_behind_is_no_upgrade() {
    let (mut alice, bob) = (person(1), person(2));
    let brief = MessagingPolicy {
        request_retention: std::time::Duration::from_secs(60),
        ..policy()
    };
    let (s, f, renewed, [(a, _), (b, mut rb), _]) = reset_elsewhere(&mut alice, &bob, brief);
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(120));
    drain(&mut rb);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    assert!(requests_offered(&mut rb).is_empty(), "told nothing");
    assert_eq!(
        s.core.friend_respond(b, "alice", false),
        Err(MessagingError::NotFriends)
    );
    let t = s.core.clock().unix();
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 0, t))),
        Err(MessagingError::NotFriends)
    );
    assert!(friendship_of(&s, &alice, &bob).is_none());
}

#[test]
fn a_tick_waits_for_an_upgrade_offer_judged_on_its_record() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    // An offer judged on the record a minute before it lapses, which a
    // tick lapses while the offer waits to be kept.
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(30 * DAY - 60));
    let again = offer(&alice, renewed, &bob, s.core.clock().unix());
    let parked = s.fail.park.arm("presentation");
    let asking = {
        let (core, again) = (s.core.clone(), again.clone());
        std::thread::spawn(move || core.friend_ask(a, "bob", None, Some(again)))
    };
    parked.arrived();
    let ticking = {
        let core = s.core.clone();
        std::thread::spawn(move || {
            core.clock().advance(std::time::Duration::from_secs(120));
            core.owed_tick();
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    parked.release();
    assert_eq!(asking.join().unwrap(), Ok(RosterState::PendingOut));
    ticking.join().unwrap();
    let t = s.core.clock().unix();
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&again, &bob, 0, t))),
        Ok(RosterState::Accepted),
        "the record the offer was taken on kept for it"
    );
}

#[test]
fn a_remade_friendship_is_recorded_whole_or_not_at_all() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    s.core
        .friendships_present(b, vec![], vec![f.clone()])
        .unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    let remade = accept(&o, &bob, 0, now());
    let wall = s.core.clock().wall();
    let row = |x: &Person, y: &Person| s.rel.presentation(&fp(x), &fp(y)).unwrap();

    s.fail.fail_next("write");
    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(remade.clone())),
        Err(MessagingError::ServerError)
    );
    let kept = row(&bob, &alice).unwrap();
    assert_eq!(
        (kept.friendship, kept.reset),
        (None, Some(f)),
        "the record as it was"
    );
    assert!(row(&alice, &bob).is_none_or(|p| !p.evidence()));
    assert!(
        s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap().is_some(),
        "the offer kept"
    );
    assert!(friendship_of(&s, &alice, &bob).is_none());

    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(remade)),
        Ok(RosterState::Accepted)
    );
    assert!(row(&bob, &alice).is_some_and(|p| p.evidence()));
    assert!(row(&alice, &bob).is_some_and(|p| p.evidence()));
    let (ma, mb) = mailboxes(&alice, &bob);
    for (x, y) in [(&ma, &mb), (&mb, &ma)] {
        assert!(s
            .rel
            .relationship(x, y, wall)
            .unwrap()
            .is_some_and(|r| r.friendship.is_some()));
    }
}

#[test]
fn a_new_request_takes_the_place_of_an_offer_a_lapsed_one_left() {
    let (mut alice, bob) = (person(1), person(2));
    let brief = MessagingPolicy {
        request_retention: std::time::Duration::from_secs(60),
        ..policy()
    };
    let (s, f, renewed, [(a, _), (b, mut rb), _]) = reset_elsewhere(&mut alice, &bob, brief);
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(120));
    s.core.friend_add(a, "bob", None).unwrap();
    drain(&mut rb);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    assert!(requests_offered(&mut rb).is_empty(), "no upgrade told");
    let wall = s.core.clock().wall();
    assert_eq!(
        s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap(),
        None,
        "the request carries none"
    );
}

#[test]
fn a_reset_record_takes_the_place_of_a_hash_alone() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, _, [_, (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let wall = s.core.clock().wall();
    let hash_only = Presentation {
        presenter: fp(&bob),
        other: fp(&alice),
        names: [fp(&bob), fp(&alice)],
        pair: Pair::new(Fingerprint(fp(&bob)), Fingerprint(fp(&alice))).hash(),
        hash: [9; 32],
        friendship: None,
        reset: None,
        device: [7; 32],
        edge: None,
        at: wall,
        taken: wall,
    };
    s.rel.present(&hash_only).unwrap();
    let (_, refused) = s
        .core
        .friendships_present(b, vec![], vec![f.clone()])
        .unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let p = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap().unwrap();
    assert_eq!((p.hash, p.reset), (hash(&f), Some(f)));
}

#[test]
fn a_successors_offer_remakes_a_friendship_its_predecessor_signed() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let (_, _, _, _, f) = made(
        &linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]),
        &alice,
        &bob,
    );
    let s = linked(&[("alice", &fp(&successor)), ("bob", &fp(&bob))]);
    let record = Rotation {
        identity: alice.id.public(),
        successor: successor.id.public(),
        time: now(),
        next: None,
    }
    .sign(&alice.id, &successor.id)
    .unwrap();
    s.core.keep_rotation_record(&record);
    reset(&s, &alice, 1, s.core.clock().unix() - 1);
    let (a, _) = device(&s.core, "alice", &successor, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let o = offer(&successor, 0, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    let (ms, mb) = (
        Mailbox::identified("alice", fp(&successor)),
        Mailbox::identified("bob", fp(&bob)),
    );
    assert!(!requested(&s, &mb, &ms), "an upgrade, no request");
    let t = s.core.clock().unix();
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 0, t))),
        Ok(RosterState::Accepted)
    );
    assert!(s
        .rel
        .relationship(&mb, &ms, s.core.clock().wall())
        .unwrap()
        .is_some_and(|r| r.friendship.is_some()));
}

#[test]
fn an_offer_that_cannot_be_read_writes_nothing() {
    // A request's offer, read as its friendship is answered `Reset`.
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
    s.fail.fail_next("relationship");
    assert_eq!(
        s.core.friendships_present(b, vec![], vec![f]).map(drop),
        Err(MessagingError::ServerError)
    );
    assert!(
        s.rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .is_none(),
        "no record"
    );
}

#[test]
fn an_upgrade_counts_toward_its_senders_roster_as_a_request_does() {
    // So its acceptance always finds the sender room.
    let (mut alice, bob) = (person(1), person(2));
    let tight = MessagingPolicy {
        max_roster: 1,
        ..policy()
    };
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, tight);
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    assert_eq!(
        s.core.friend_add(a, "carol", None),
        Err(MessagingError::RosterFull)
    );
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 0, now()))),
        Ok(RosterState::Accepted)
    );
}

#[test]
fn a_floor_learned_late_drops_what_was_taken_after_the_reset() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let reset_at = s.core.clock().unix() - 30;
    let (_, _, b, mut rb, f) = made(&s, &alice, &bob);
    reset(&s, &alice, 1, reset_at);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)],
        "removed with no withdrawal"
    );
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
}

#[test]
fn presenting_again_keeps_the_first_taking_and_an_earlier_reset_judges_again() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = s.core.clock().unix();
    let (a, _, b, mut rb, f) = made(&s, &alice, &bob);
    s.core.clock().advance(std::time::Duration::from_secs(10));
    for uid in [a, b] {
        let (_, again) = s
            .core
            .friendships_present(uid, vec![], vec![f.clone()])
            .unwrap();
        assert!(ok_all(&again));
    }
    drain(&mut rb);

    reset(&s, &alice, 1, t + 5);
    assert!(
        told(&mut rb).is_empty(),
        "held: first taken before the reset, whenever presented since"
    );
    // A record of the same epoch, signed earlier, as another registrar
    // may publish it.
    reset(&s, &alice, 1, t - 10);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
}

#[test]
fn a_withdrawal_a_reset_device_signed_ends_nothing() {
    let (mut alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (taken, _) = s
        .core
        .friendships_present(a, vec![withdraw(&alice, 0, &bob, now())], vec![])
        .unwrap();
    assert!(ok_all(&taken));
    reset(&s, &alice, 1, now());

    // A friendship made since by a device that stays, its halves dated
    // inside the cutoff the reset device signed.
    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let o = offer(&alice, renewed, &bob, now() - 30);
    assert_eq!(
        s.core.friend_ask(a2, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let f = accept(&o, &bob, 0, now() - 30);
    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(f)),
        Ok(RosterState::Accepted)
    );
}

#[test]
fn a_presentation_by_either_party_before_the_reset_holds_the_friendship() {
    let (alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (_, first) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&first));
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);

    // Bob's first presentation comes after the reset, Alice's before it.
    let (b, mut rb) = device(&s.core, "bob", &bob, 1);
    let (_, second) = s
        .core
        .friendships_present(b, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&second), "{second:?}");
    assert!(told(&mut rb).iter().any(|e| e.1 == RosterState::Accepted));
    // Judged again, it keeps both.
    reset(&s, &alice, 2, t + 8);
    assert!(told(&mut rb).is_empty());
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_some());

    // Alice's presentation goes with her device, and Bob's, which only
    // hers held, with it.
    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&alice.devices[1].0.public()).0].into(),
        ..Default::default()
    });
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
}

#[test]
fn a_floor_with_no_record_kept_drops_nothing_and_presenting_drops_what_is_not_held() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let taken = s.core.clock().unix();
    let (_, _, b, mut rb, f) = made(&s, &alice, &bob);
    install(&s, &alice, 1);
    assert!(
        !told(&mut rb).iter().any(|e| e.1 == RosterState::Removed),
        "no record shows it is not held"
    );

    // A record kept since, with nothing judged again: Bob's presenting
    // finds it not held, and what is stored of it goes then.
    keep(&s, &alice, 1, taken - 30);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_none());
}

#[test]
fn an_offer_a_reset_device_signed_goes_with_the_floor() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let o = offer(&alice, 0, &bob, now());
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o)),
        Ok(RosterState::PendingOut)
    );
    let wall = std::time::SystemTime::now();
    let offered = || !s.rel.offers_from(&fp(&alice), wall).unwrap().is_empty();
    assert!(offered());
    let (_, mut rb) = device(&s.core, "bob", &bob, 0);
    reset(&s, &alice, 1, now());
    assert!(!offered());
    let entries: Vec<_> = drain(&mut rb)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) if e.login == "alice" => Some((e.state, e.offer)),
            _ => None,
        })
        .collect();
    assert_eq!(
        entries,
        [(RosterState::PendingIn, None)],
        "told, a plain request"
    );
}

#[test]
fn a_presentation_refused_before_it_was_recorded_holds_nothing() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let t = s.core.clock().unix();
    let (b, _) = device(&s.core, "bob", &bob, 1);
    s.core.inbox_block(b, "alice", true).unwrap();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (_, hidden) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert_eq!(
        hidden[0].outcome,
        Presented::AccountNotFound,
        "its hash alone kept"
    );
    s.core.inbox_block(b, "alice", false).unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);

    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let (_, refused) = s.core.friendships_present(a2, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
}

#[test]
fn an_unlink_takes_the_presentation_only_it_held() {
    let (alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let (s, dir) = switched(policy(), &accounts);
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    s.core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));

    unlinked(&s, &dir, &fp(&alice));
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
}

#[test]
fn a_reset_whose_cleanup_fails_ends_the_friendship_when_judged_again() {
    for write in ["presentations", "write"] {
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let reset_at = s.core.clock().unix() - 30;
        let (_, _, _, mut rb, _) = made(&s, &alice, &bob);
        s.fail.fail_next(write);
        reset(&s, &alice, 1, reset_at);
        assert_eq!(s.fail.failed(), Some(write));
        install(&s, &alice, 1);
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], None)],
            "removed once judged again, {write} failing"
        );
        let wall = std::time::SystemTime::now();
        let (ma, mb) = (
            Mailbox::identified("alice", fp(&alice)),
            Mailbox::identified("bob", fp(&bob)),
        );
        assert!(s
            .rel
            .relationship(&ma, &mb, wall)
            .unwrap()
            .is_none_or(|r| r.friendship.is_none()));
    }
}

/// The in-memory record cache, its epochs unreadable while `fail` is set,
/// and whose epochs were asked for.
#[derive(Default)]
struct Flaky {
    inner: MemoryRecordCache,
    fail: AtomicBool,
    read: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl RecordCache for Flaky {
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
    fn keep_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        self.inner.keep_epoch(identity, kept)
    }
    fn replace_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        self.inner.replace_epoch(identity, kept)
    }
    fn epochs(&self, identity: &[u8; 32]) -> Result<Vec<KeptEpoch>, StoreError> {
        self.read.lock().unwrap().push(*identity);
        if self.fail.load(Ordering::Relaxed) {
            return Err(StoreError("unreadable".into()));
        }
        self.inner.epochs(identity)
    }
    fn identities_with_epochs(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        self.inner.identities_with_epochs()
    }
}

#[test]
fn a_withdrawal_whose_floor_cannot_be_read_is_a_server_error() {
    for block in [false, true] {
        let (mut alice, bob) = (person(1), person(2));
        let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let cache = Arc::new(Flaky::default());
        Arc::get_mut(&mut s.core).unwrap().record_cache = Some(cache.clone());
        install(&s, &alice, 1);
        let renewed = enroll(&mut alice, 1);
        let (a, _) = device(&s.core, "alice", &alice, renewed);
        let (b, mut rb) = device(&s.core, "bob", &bob, 0);
        let o = offer(&alice, renewed, &bob, now() - 60);
        assert_eq!(
            s.core.friend_ask(a, "bob", None, Some(o.clone())),
            Ok(RosterState::PendingOut)
        );
        let f = accept(&o, &bob, 0, now() - 60);
        assert_eq!(
            s.core.friend_answer(b, "alice", true, Some(f)),
            Ok(RosterState::Accepted)
        );
        drain(&mut rb);

        // Signed by a certificate below the floor installed, which alone
        // cannot say what the records would, and by one above it.
        cache.fail.store(true, Ordering::Relaxed);
        let w = withdraw(&alice, renewed, &bob, now());
        for w in [withdraw(&alice, 0, &bob, now()), w.clone()] {
            let got = if block {
                s.core.block_withdrawing(a, "bob", w)
            } else {
                s.core.friend_unfriend(a, "bob", Some(w))
            };
            assert_eq!(got, Err(MessagingError::ServerError), "block: {block}");
        }
        assert!(told(&mut rb).is_empty(), "nothing ended, block: {block}");

        // Once the records read, the same withdrawal ends it, and is told.
        cache.fail.store(false, Ordering::Relaxed);
        let got = if block {
            s.core.block_withdrawing(a, "bob", w.clone())
        } else {
            s.core.friend_unfriend(a, "bob", Some(w.clone()))
        };
        assert_eq!(got, Ok(()), "block: {block}");
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], Some(w))],
            "block: {block}"
        );
    }
}

#[test]
fn a_reset_judges_what_was_taken_while_the_clock_ran_ahead() {
    let (alice, bob) = (person(1), person(2));
    let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    s.core.clock().advance(std::time::Duration::from_secs(3600));
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, mut rb) = device(&s.core, "bob", &bob, 0);
    let o = offer(&alice, 0, &bob, t - 60);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let f = accept(&o, &bob, 0, t - 60);
    assert_eq!(
        s.core.friend_answer(b, "alice", true, Some(f)),
        Ok(RosterState::Accepted)
    );
    drain(&mut rb);

    // The clock set right, what it took is dated ahead of it.
    Arc::get_mut(&mut s.core).unwrap().clock = crate::clock::Clock::default();
    reset(&s, &alice, 1, now() - 30);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
}

#[test]
fn a_withdrawal_kept_while_the_clock_ran_ahead_still_refuses_the_friendship() {
    let (alice, bob) = (person(1), person(2));
    let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    s.core.clock().advance(std::time::Duration::from_secs(3600));
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 0);
    // Nothing here names the pair yet, so it is kept unchecked.
    let w = withdraw_at(&alice, 0, &bob, t, t);
    let (taken, _) = s
        .core
        .friendships_present(a, vec![w.clone()], vec![])
        .unwrap();
    assert!(ok_all(&taken));

    Arc::get_mut(&mut s.core).unwrap().clock = crate::clock::Clock::default();
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, now() - 60);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Withdrawn(Some(w)));
}

#[test]
fn a_withdrawal_ends_a_friendship_taken_while_the_clock_ran_ahead() {
    let (alice, bob) = (person(1), person(2));
    let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    s.core.clock().advance(std::time::Duration::from_secs(3600));
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, mut rb) = device(&s.core, "bob", &bob, 0);
    // Alice's half by the right time, Bob's by the clock ahead of it.
    let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, t - 60);
    for uid in [a, b] {
        let (_, presented) = s
            .core
            .friendships_present(uid, vec![], vec![f.clone()])
            .unwrap();
        assert!(ok_all(&presented));
    }
    assert!(told(&mut rb)
        .iter()
        .any(|(_, state, _, _)| *state == RosterState::Accepted));

    Arc::get_mut(&mut s.core).unwrap().clock = crate::clock::Clock::default();
    let w = withdraw(&alice, 1, &bob, now());
    let (a1, _) = device(&s.core, "alice", &alice, 1);
    let (taken, _) = s
        .core
        .friendships_present(a1, vec![w.clone()], vec![])
        .unwrap();
    assert!(ok_all(&taken));
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], Some(w))]
    );
}

#[test]
fn a_reset_whose_rotations_cannot_be_read_is_judged_again() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&successor)), ("bob", &fp(&bob))]);
    let record = Rotation {
        identity: alice.id.public(),
        successor: successor.id.public(),
        time: now(),
        next: None,
    }
    .sign(&alice.id, &successor.id)
    .unwrap();
    s.core.keep_rotation_record(&record);
    let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, now() - 60);
    let (a, _) = device(&s.core, "alice", &successor, 0);
    let (b, mut rb) = device(&s.core, "bob", &bob, 0);
    for uid in [b, a] {
        let (_, ok) = s
            .core
            .friendships_present(uid, vec![], vec![f.clone()])
            .unwrap();
        assert!(ok_all(&ok));
    }
    drain(&mut rb);

    s.fail.fail_next("rotation_from");
    reset(&s, &alice, 1, now() - 30);
    assert_eq!(s.fail.failed(), Some("rotation_from"));
    install(&s, &alice, 1);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
}

#[test]
fn a_removal_without_a_withdrawal_holds_past_one_a_reset_device_signed() {
    let (alice, mut bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let ahead = now() + 300;
    let early = withdraw_at(&bob, 0, &alice, ahead, ahead);
    let (taken, _) = s.core.friendships_present(b, vec![early], vec![]).unwrap();
    assert!(ok_all(&taken));
    reset(&s, &bob, 1, now());

    let renewed = enroll(&mut bob, 1);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b2, _) = device(&s.core, "bob", &bob, renewed);
    let o = offer(&alice, 0, &bob, now() - 30);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let f = accept(&o, &bob, renewed, now() - 30);
    assert_eq!(
        s.core.friend_answer(b2, "alice", true, Some(f.clone())),
        Ok(RosterState::Accepted)
    );
    let (password, _) = session(&s.core, "bob", &bob, renewed, false, u64::MAX);
    assert_eq!(s.core.friend_remove(password, "alice"), Ok(()));
    let (_, refused) = s.core.friendships_present(b2, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Withdrawn(None));
}

#[test]
fn a_presentation_no_record_shows_held_activates_no_edge() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (_, first) = s.core.friendships_present(a, vec![], vec![f]).unwrap();
    assert!(ok_all(&first));
    install(&s, &alice, 1);

    // A friendship made since, elsewhere, presented here by Bob alone.
    let renewed = enroll(&mut alice, 1);
    let o = offer(&alice, renewed, &bob, now() - 30);
    let f2 = accept(&o, &bob, 1, now() - 30);
    let (b, mut rb) = device(&s.core, "bob", &bob, 1);
    let (_, by_bob) = s
        .core
        .friendships_present(b, vec![], vec![f2.clone()])
        .unwrap();
    assert!(ok_all(&by_bob));
    assert!(told(&mut rb).is_empty(), "Alice's presentation is not held");

    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let (_, by_alice) = s.core.friendships_present(a2, vec![], vec![f2]).unwrap();
    assert!(ok_all(&by_alice));
    assert!(told(&mut rb).iter().any(|e| e.1 == RosterState::Accepted));
}

#[test]
fn a_presentation_replaced_takes_the_other_partys_only_it_held() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    s.core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);
    let (b, mut rb) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));
    drain(&mut rb);

    // Alice presents a friendship made since, from a device that stays.
    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let o = offer(&alice, renewed, &bob, now() - 30);
    let f2 = accept(&o, &bob, 0, now() - 30);
    s.fail.fail_next("write");
    assert_eq!(
        s.core.friendships_present(a2, vec![], vec![f2.clone()]),
        Err(MessagingError::ServerError)
    );
    assert_eq!(s.fail.failed(), Some("write"));
    let (_, replaced) = s.core.friendships_present(a2, vec![], vec![f2]).unwrap();
    assert!(ok_all(&replaced), "{replaced:?}");
    assert!(
        s.rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .is_none(),
        "Bob's was held by Alice's alone"
    );
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
}

#[test]
fn a_removal_by_fingerprint_takes_the_presentation_only_it_held() {
    let (mut alice, bob, carol) = (person(1), person(2), person(3));
    let accounts = [
        ("alice", &fp(&alice)),
        ("bob", &fp(&bob)),
        ("carol", &fp(&carol)),
    ];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked_with(
        MessagingPolicy {
            max_roster: 1,
            ..policy()
        },
        &accounts,
    );
    let t = s.core.clock().unix();
    // Alice's roster is full, so the friendship stays inactive here.
    let (a, _) = device(&s.core, "alice", &alice, 1);
    s.core.inbox_block(a, "carol", true).unwrap();
    s.core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_some());

    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    assert_eq!(s.core.friend_remove_by_key(a2, &fp(&bob), None), Ok(()));
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
}

fn friendship_of(s: &Server, alice: &Person, bob: &Person) -> Option<RelationId> {
    s.rel
        .relationship(
            &Mailbox::identified("alice", fp(alice)),
            &Mailbox::identified("bob", fp(bob)),
            std::time::SystemTime::now(),
        )
        .unwrap()
        .and_then(|r| r.friendship)
}

fn presented_both_ways(s: &Server, alice: &Person, bob: &Person) -> bool {
    [(fp(alice), fp(bob)), (fp(bob), fp(alice))]
        .iter()
        .all(|(p, q)| s.rel.presentation(p, q).unwrap().is_some())
}

#[test]
fn an_unlink_ends_the_friendship_its_presentations_held() {
    let (alice, bob) = (person(1), person(2));
    let (s, dir) = switched(policy(), &[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, _, _, mut rb, _) = made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob).unwrap();
    unlinked(&s, &dir, &fp(&alice));
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
    assert_eq!(
        s.rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .and_then(|p| p.edge),
        Some(id),
        "the id kept, so what was queued on it waits"
    );
}

#[test]
fn a_dropped_presentation_ends_its_edge_where_a_party_takes_no_part() {
    let (alice, bob) = (person(1), person(2));
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    let dir = Directory(vec![
        (ma.clone(), messaging_bits()),
        (mb.clone(), crate::AccessBits::empty()),
    ]);
    let s = server_of(dir, policy(), InboxPolicy::default(), None);
    let (_, mut ra) = device(&s.core, "alice", &alice, 0);
    let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, now() - 60);
    let at = std::time::SystemTime::now();
    s.rel.befriend(&ma, &mb, at).unwrap();
    for (p, q, who) in [(&alice, &bob, &alice), (&bob, &alice, &bob)] {
        s.rel
            .present(&Presentation {
                presenter: fp(p),
                other: fp(q),
                names: [fp(p), fp(q)],
                pair: Pair::new(Fingerprint(fp(p)), Fingerprint(fp(q))).hash(),
                hash: hash(&f),
                friendship: Some(f.clone()),
                reset: None,
                device: Fingerprint::of(&who.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
    }
    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&alice.devices[0].0.public()).0].into(),
        ..Default::default()
    });
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    assert!(told(&mut ra).contains(&("bob".into(), RosterState::Removed, vec![], None)));
}

#[test]
fn a_removal_that_fails_leaves_the_friendship_whole() {
    for method in ["presentation", "withdrawals", "write"] {
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (_, _, _, mut rb, _) = made(&s, &alice, &bob);
        let (password, _) = session(&s.core, "alice", &alice, 1, false, u64::MAX);
        s.fail.fail_next(method);
        let removed = s.core.friend_remove(password, "bob");
        assert_eq!(s.fail.failed(), Some(method));
        match removed {
            Ok(()) => {
                assert_eq!(friendship_of(&s, &alice, &bob), None, "{method}");
                assert!(s.rel.presentations(&fp(&alice)).unwrap().is_empty());
            }
            Err(e) => {
                assert_eq!(e, MessagingError::ServerError, "{method}");
                assert!(friendship_of(&s, &alice, &bob).is_some(), "{method}");
                assert!(presented_both_ways(&s, &alice, &bob), "{method}");
                assert!(told(&mut rb).is_empty(), "{method}: nothing told");
            }
        }
    }
}

#[test]
fn a_block_that_fails_blocks_nothing() {
    for method in ["presentation", "write"] {
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (a, _, _, _, _) = made(&s, &alice, &bob);
        let (ma, mb) = (
            Mailbox::identified("alice", fp(&alice)),
            Mailbox::identified("bob", fp(&bob)),
        );
        s.fail.fail_next(method);
        let blocked = s.core.inbox_block(a, "bob", true);
        assert_eq!(s.fail.failed(), Some(method));
        let is_blocked = s.rel.is_blocked(&ma, &mb).unwrap();
        let friends = friendship_of(&s, &alice, &bob).is_some();
        match blocked {
            Ok(()) => assert!(is_blocked && !friends, "{method}: blocked, so ended"),
            Err(_) => {
                assert!(!is_blocked && friends, "{method}: nothing written");
                assert!(presented_both_ways(&s, &alice, &bob), "{method}");
            }
        }
    }
}

#[test]
fn a_withdrawal_retried_after_a_failure_ends_a_friendship_made_while_the_clock_ran_ahead() {
    for method in ["presentation", "write"] {
        let (alice, bob) = (person(1), person(2));
        let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        s.core.clock().advance(std::time::Duration::from_secs(3600));
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let (b, _) = device(&s.core, "bob", &bob, 0);
        let f = accept(&offer(&alice, 0, &bob, now() - 60), &bob, 0, now() - 60);
        for uid in [a, b] {
            let (_, presented) = s
                .core
                .friendships_present(uid, vec![], vec![f.clone()])
                .unwrap();
            assert!(ok_all(&presented));
        }
        assert!(friendship_of(&s, &alice, &bob).is_some());

        // The edge was made later than the cutoff now reads.
        Arc::get_mut(&mut s.core).unwrap().clock = crate::clock::Clock::default();
        let w = withdraw(&alice, 0, &bob, now());
        s.fail.fail_next(method);
        let _ = s.core.friendships_present(a, vec![w.clone()], vec![]);
        assert_eq!(s.fail.failed(), Some(method));
        let (taken, _) = s.core.friendships_present(a, vec![w], vec![]).unwrap();
        assert!(ok_all(&taken), "{method}");
        assert_eq!(friendship_of(&s, &alice, &bob), None, "{method}: retried");
    }
}

#[test]
fn a_merge_whose_ending_fails_changes_and_tells_nothing() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, mut ra, _, mut rb, _) = made(&s, &alice, &bob);
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    // A fold left a block beside the friendship.
    s.rel
        .set_blocked(&ma, &mb, true, std::time::SystemTime::now())
        .unwrap();
    let befriended = |s: &Server| {
        let r = s.core.roster.lock().unwrap();
        let e = r.presences.by.get(&Key::of(&ma));
        e.is_some_and(|e| e.friends.contains(&Key::of(&mb)))
    };
    s.fail.fail_next("write");
    s.core.after_merge(&s.core.friend_writes(), &ma);
    assert!(s.fail.failed().is_some());
    assert!(friendship_of(&s, &alice, &bob).is_some());
    assert!(befriended(&s), "the roster as the store left it");
    assert_eq!(told(&mut ra), []);
    assert_eq!(told(&mut rb), []);

    s.core.after_merge(&s.core.friend_writes(), &ma);
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    assert!(!befriended(&s));
}

#[test]
fn a_merge_is_told_from_what_its_settling_left_whatever_is_read_after() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, mut ra, _, mut rb, _) = made(&s, &alice, &bob);
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    // A fold left a block beside the friendship.
    s.rel
        .set_blocked(&ma, &mb, true, std::time::SystemTime::now())
        .unwrap();
    s.fail.fail_reads_after("write");
    s.core.after_merge(&s.core.friend_writes(), &ma);
    s.fail.fail_nth(0);
    assert!(s.fail.failed().is_some(), "a read after the write failed");
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    assert_eq!(
        told(&mut ra),
        [("bob".into(), RosterState::Blocked, vec![], None)]
    );
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)]
    );
}

#[test]
fn a_pair_two_sweeps_name_by_two_spellings_is_told_once() {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (_, mut rb) = device(&s.core, "bob", &bob, 0);
    let o = offer(&alice, 0, &bob, now());
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o)),
        Ok(RosterState::PendingOut)
    );
    drain(&mut rb);
    // The directory renamed Alice under the rows that name her.
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alicia", fp(&alice));
    let device = Fingerprint::of(&alice.devices[0].0.public()).0;
    s.core.sweep_offers(vec![
        (
            Work::DropOffersBy {
                under: Some(fp(&alice)),
                device,
            },
            Cause::PublishedDevice {
                identity: fp(&alice),
                device,
            },
        ),
        (
            Work::DropOffersNaming(fp(&alice)),
            Cause::PublishedIdentity(fp(&alice)),
        ),
    ]);
    let told: Vec<_> = drain(&mut rb)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) => Some((e.login, e.state)),
            _ => None,
        })
        .collect();
    assert_eq!(
        told,
        [("alice".into(), RosterState::PendingIn)],
        "once, as the rows name her"
    );
}

/// Accounts whose bits a test changes as it goes.
#[derive(Clone)]
struct Switch(Arc<std::sync::Mutex<Vec<(Mailbox, crate::AccessBits)>>>);

impl crate::AccountDirectory for Switch {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        let accounts = self.0.lock().unwrap();
        let found = accounts.iter().find(|(m, _)| m.login == login);
        found.map(|(m, _)| m.clone())
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<crate::AccessBits> {
        let accounts = self.0.lock().unwrap();
        let found = accounts
            .iter()
            .find(|(m, _)| who.matches(&m.login, m.fingerprint.as_ref()));
        found.map(|(_, a)| *a)
    }

    fn account_by_key(
        &self,
        fp: &[u8; 32],
    ) -> Result<Option<(Mailbox, crate::AccessBits)>, StoreError> {
        let accounts = self.0.lock().unwrap();
        Ok(accounts
            .iter()
            .find(|(m, _)| m.fingerprint == Some(*fp))
            .cloned())
    }
}

#[test]
fn a_removal_by_fingerprint_of_one_outside_messaging_ends_the_friendship_here() {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _, _, _, f) = made(&s, &alice, &bob);
    let bits = |b| accounts.0.lock().unwrap()[1].1 = b;
    bits(crate::AccessBits::empty());
    assert_eq!(s.core.friend_remove_by_key(a, &fp(&bob), None), Ok(()));
    assert_eq!(friendship_of(&s, &alice, &bob), None);

    // Bob takes part again, and Alice's other device presents it back.
    bits(messaging_bits());
    let (a1, _) = device(&s.core, "alice", &alice, 1);
    let (_, again) = s.core.friendships_present(a1, vec![], vec![f]).unwrap();
    assert_eq!(again[0].outcome, Presented::Withdrawn(None));
    assert_eq!(friendship_of(&s, &alice, &bob), None);
}

#[test]
fn a_reset_of_both_presentations_ends_the_pair_in_one_step() {
    for on_presenting in [false, true] {
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let reset_at = s.core.clock().unix() - 30;
        let (_, _, _, _, f) = made(&s, &alice, &bob);
        s.fail.fail_nth_of("write", 2);
        if on_presenting {
            keep(&s, &alice, 1, reset_at);
            let (b1, _) = device(&s.core, "bob", &bob, 1);
            let _ = s.core.friendships_present(b1, vec![], vec![f]);
        } else {
            reset(&s, &alice, 1, reset_at);
        }
        let evidence = |p: &Person, q: &Person| {
            let pres = s.rel.presentation(&fp(p), &fp(q)).unwrap();
            pres.is_some_and(|p| p.evidence())
        };
        let pair = (
            evidence(&alice, &bob),
            evidence(&bob, &alice),
            friendship_of(&s, &alice, &bob).is_some(),
        );
        assert_eq!(pair, (false, false, false), "presenting {on_presenting}");
        assert_eq!(
            s.fail.failed(),
            None,
            "one write, presenting {on_presenting}"
        );
    }
}

/// A directory whose account for one key loses the messaging bit when
/// told to.
struct Unmessaging(Directory, [u8; 32], Arc<AtomicBool>);

impl Unmessaging {
    fn access(&self, who: &Mailbox, bits: crate::AccessBits) -> crate::AccessBits {
        match who.fingerprint == Some(self.1) && self.2.load(Ordering::Relaxed) {
            true => crate::AccessBits::empty(),
            false => bits,
        }
    }
}

impl crate::AccountDirectory for Unmessaging {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        self.0.inbox_account(login)
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<crate::AccessBits> {
        self.0.mailbox_access(who).map(|b| self.access(who, b))
    }

    fn account_by_key(
        &self,
        fp: &[u8; 32],
    ) -> Result<Option<(Mailbox, crate::AccessBits)>, StoreError> {
        let found = self.0.account_by_key(fp)?;
        Ok(found.map(|(m, b)| {
            let b = self.access(&m, b);
            (m, b)
        }))
    }
}

#[test]
fn a_withdrawal_that_ends_an_edge_tells_it_where_the_other_party_takes_no_part() {
    let (alice, bob) = (person(1), person(2));
    let lost = Arc::new(AtomicBool::new(false));
    let dir = Directory(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ]);
    let s = server_of(
        Unmessaging(dir, fp(&alice), lost.clone()),
        policy(),
        crate::InboxPolicy::default(),
        None,
    );
    let (_, _, b, mut rb, _) = made(&s, &alice, &bob);
    lost.store(true, Ordering::Relaxed);
    let w = withdraw(&bob, 0, &alice, now());
    let (taken, _) = s.core.friendships_present(b, vec![w], vec![]).unwrap();
    assert!(ok_all(&taken));
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    assert!(
        told(&mut rb)
            .iter()
            .any(|(login, state, ..)| login == "alice" && *state == RosterState::Removed),
        "the edge it ended told to the party that takes part"
    );
}

#[test]
fn a_withdrawal_that_ended_the_friendship_is_answered_by_what_it_committed() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, _) = made(&s, &alice, &bob);
    // A read after the ending's commit and its tells fails.
    s.fail.fail_nth_of("relationship", 7);
    let w = withdraw(&alice, 0, &bob, now());
    assert_eq!(s.core.friend_unfriend(a, "bob", Some(w)), Ok(()));
    assert_eq!(friendship_of(&s, &alice, &bob), None);
}

#[test]
fn a_withdrawal_that_cuts_nothing_tells_both_the_entry_again() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, mut ra, _, mut rb, f) = made(&s, &alice, &bob);
    let early = withdraw_at(&alice, 0, &bob, now() - 120, now());
    let (taken, _) = s.core.friendships_present(a, vec![early], vec![]).unwrap();
    assert!(ok_all(&taken));
    assert!(friendship_of(&s, &alice, &bob).is_some());
    assert_eq!(
        told(&mut ra),
        [("bob".into(), RosterState::Accepted, vec![hash(&f)], None)]
    );
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Accepted, vec![hash(&f)], None)]
    );
}

#[test]
fn a_reset_leaves_no_id_for_a_friendship_made_after_it() {
    let (mut alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let reset_at = s.core.clock().unix() - 30;
    let (_, _, _, _, f) = made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob).unwrap();
    // Alice's presentation goes with her device, leaving the id on Bob's
    // for what was queued on it.
    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&alice.devices[0].0.public()).0].into(),
        ..Default::default()
    });
    let edge = |s: &Server| {
        let pres = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap();
        pres.and_then(|p| p.edge)
    };
    assert_eq!(edge(&s), Some(id));

    // Alice reset before it was taken, and Bob presents it again.
    keep(&s, &alice, 1, reset_at);
    let (b1, _) = device(&s.core, "bob", &bob, 1);
    let (_, judged) = s.core.friendships_present(b1, vec![], vec![f]).unwrap();
    assert_eq!(judged[0].outcome, Presented::Reset);
    assert_eq!(
        edge(&s),
        None,
        "the reset took the id with the presentation"
    );

    // A friendship made since is a new one.
    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let f2 = accept(
        &offer(&alice, renewed, &bob, now() - 30),
        &bob,
        1,
        now() - 30,
    );
    for uid in [b1, a2] {
        let (_, presented) = s
            .core
            .friendships_present(uid, vec![], vec![f2.clone()])
            .unwrap();
        assert!(ok_all(&presented));
    }
    assert!(friendship_of(&s, &alice, &bob).is_some_and(|new| new != id));
    assert!(
        !s.rel.is_live(id),
        "what was queued before the reset stays held"
    );
}

#[test]
fn a_removal_whose_withdrawal_cuts_nothing_keeps_the_friendship() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, mut ra, _, mut rb, f) = made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob);
    let early = withdraw_at(&alice, 0, &bob, now() - 120, now());
    assert_eq!(s.core.friend_unfriend(a, "bob", Some(early)), Ok(()));
    assert_eq!(friendship_of(&s, &alice, &bob), id, "the edge stands");
    assert_eq!(
        told(&mut ra),
        [("bob".into(), RosterState::Accepted, vec![hash(&f)], None)]
    );
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Accepted, vec![hash(&f)], None)]
    );
}

#[test]
fn a_merge_ends_a_blocked_friendship_with_its_requests() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    made(&s, &alice, &bob);
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    // A fold left Alice's block beside the friendship and Bob's request.
    let at = std::time::SystemTime::now();
    s.rel.set_blocked(&ma, &mb, true, at).unwrap();
    let asked = crate::relationships::PendingOut {
        sent_at: at,
        lapses_at: at + std::time::Duration::from_secs(DAY),
        delivered: true,
        note: None,
        offer: None,
        upgrade: false,
    };
    s.rel.set_pending_out(&mb, &ma, Some(&asked)).unwrap();
    s.fail.fail_nth_write(2);
    s.core.after_merge(&s.core.friend_writes(), &ma);
    let asking = s.rel.relationship(&mb, &ma, at).unwrap();
    assert_eq!(
        friendship_of(&s, &alice, &bob).is_some(),
        asking.is_some_and(|r| r.pending_out.is_some()),
        "ended with the request, or neither"
    );
    assert!(s.rel.is_blocked(&ma, &mb).unwrap());
}

#[test]
fn a_block_withdrawing_is_blocked_with_what_it_ends() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, _) = made(&s, &alice, &bob);
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    s.fail.fail_nth_write(2);
    // As Block User (806) carrying a withdrawal does.
    let _ = s
        .core
        .block_withdrawing(a, "bob", withdraw(&alice, 0, &bob, now()));
    let _ = s.core.inbox_block(a, "bob", true);
    assert_eq!(
        s.rel.is_blocked(&ma, &mb).unwrap(),
        friendship_of(&s, &alice, &bob).is_none(),
        "the friendship ended with the block, or neither"
    );
}

#[test]
fn a_merges_block_ends_what_a_block_ends() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, f) = made(&s, &alice, &bob);
    let (ma, mb) = (
        Mailbox::identified("alice", fp(&alice)),
        Mailbox::identified("bob", fp(&bob)),
    );
    // A fold left Alice's block beside the friendship both presented.
    s.rel
        .set_blocked(&ma, &mb, true, std::time::SystemTime::now())
        .unwrap();
    s.core.after_merge(&s.core.friend_writes(), &ma);
    assert_eq!(friendship_of(&s, &alice, &bob), None);
    s.core.inbox_block(a, "bob", false).unwrap();

    let (a1, _) = device(&s.core, "alice", &alice, 1);
    let (_, again) = s.core.friendships_present(a1, vec![], vec![f]).unwrap();
    assert_eq!(again[0].outcome, Presented::Withdrawn(None));
    assert_eq!(friendship_of(&s, &alice, &bob), None, "not friends again");
}

/// How a reset of Alice's first devices reads against what was taken of
/// a friendship before it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Taking {
    Held,
    Reset,
    Unknown,
}

#[test]
fn a_plain_befriend_drops_what_is_not_held_before_the_friendship_is_made() {
    for crossing in [false, true] {
        for taking in [Taking::Held, Taking::Reset, Taking::Unknown] {
            let case = format!("{taking:?}, crossing {crossing}");
            let (alice, bob) = (person(1), person(2));
            let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
            let s1 = linked(&accounts);
            let (_, _, _, _, f) = made(&s1, &alice, &bob);
            let s = linked(&accounts);
            let t = s.core.clock().unix();
            let (a, _) = device(&s.core, "alice", &alice, 1);
            let (_, presented) = s.core.friendships_present(a, vec![], vec![f]).unwrap();
            assert!(ok_all(&presented), "{case}");
            let (b, _) = device(&s.core, "bob", &bob, 1);
            s.core
                .set_presence(
                    b,
                    PresenceUpdate {
                        takes_requests: Some(true),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(
                s.core.friend_add(a, "bob", None),
                Ok(RosterState::PendingOut),
                "{case}"
            );
            s.core.clock().advance(std::time::Duration::from_secs(10));
            // Kept, or installed, alone: nothing judges the presentation
            // again until the grant does.
            match taking {
                Taking::Held => keep(&s, &alice, 1, t + 5),
                Taking::Reset => keep(&s, &alice, 1, t - 5),
                Taking::Unknown => install(&s, &alice, 1),
            }
            let answered = if crossing {
                s.core.friend_add(b, "alice", None)
            } else {
                s.core.friend_respond(b, "alice", true)
            };
            assert_eq!(answered, Ok(RosterState::Accepted), "{case}");
            assert!(friendship_of(&s, &alice, &bob).is_some(), "{case}");
            assert_eq!(
                s.rel
                    .presentation(&fp(&alice), &fp(&bob))
                    .unwrap()
                    .is_some(),
                taking == Taking::Held,
                "{case}: only a held presentation stays beside the friendship"
            );
        }
    }
}

#[test]
fn a_friendship_accepted_here_takes_the_id_a_dropped_presentation_kept() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob).unwrap();
    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&bob.devices[0].0.public()).0].into(),
        ..Default::default()
    });
    assert_eq!(friendship_of(&s, &alice, &bob), None);

    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let o = offer(&alice, 1, &bob, now());
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 1, now()))),
        Ok(RosterState::Accepted)
    );
    assert_eq!(friendship_of(&s, &alice, &bob), Some(id));
    assert!(s.rel.is_live(id), "what was queued on it is released");
}

#[test]
fn a_stored_friendship_that_no_longer_checks_is_not_held() {
    // Which presentations' copies of the friendship are corrupted, Alice's
    // and Bob's.
    for corrupted in [[true, true], [true, false], [false, true]] {
        let case = format!("corrupted {corrupted:?}");
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let t = s.core.clock().unix();
        let (_, _, _, mut rb, _) = made(&s, &alice, &bob);
        let pairs = [(fp(&alice), fp(&bob)), (fp(&bob), fp(&alice))];
        for ((p, q), bad) in pairs.iter().zip(corrupted) {
            if bad {
                let mut pres = s.rel.presentation(p, q).unwrap().unwrap();
                pres.friendship = Some(b"not a friendship".to_vec());
                s.rel.present(&pres).unwrap();
            }
        }
        // A reset after it was taken, which holds a copy that checks.
        reset(&s, &alice, 1, t + 5);
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], None)],
            "{case}"
        );
        for ((p, q), bad) in pairs.iter().zip(corrupted) {
            assert_eq!(
                s.rel.presentation(p, q).unwrap().is_some(),
                !bad,
                "{case}: a copy is dropped where it does not check, and only there"
            );
        }
    }
}

#[test]
fn an_acceptance_whose_offer_a_reset_device_signed_changes_nothing() {
    for upgrade in [false, true] {
        let case = format!("upgrade {upgrade}");
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (a, b) = if upgrade {
            let (a, _, b, _, _) = made(&s, &alice, &bob);
            (a, b)
        } else {
            (
                device(&s.core, "alice", &alice, 0).0,
                device(&s.core, "bob", &bob, 0).0,
            )
        };
        let before = |p: &Person, q: &Person| s.rel.presentation(&fp(p), &fp(q)).unwrap();
        let held = [before(&alice, &bob), before(&bob, &alice)];
        let o = offer(&alice, 0, &bob, now());
        let asked = s.core.friend_ask(a, "bob", None, Some(o.clone()));
        assert!(asked.is_ok(), "{case}: {asked:?}");
        // A record of a reset kept since, with no floor installed, so
        // nothing has judged the offer.
        keep(&s, &alice, 1, now() - 5);
        let f = accept(&o, &bob, 0, now());
        assert_eq!(
            s.core.friend_answer(b, "alice", true, Some(f)),
            Err(MessagingError::BadSignature),
            "{case}"
        );
        assert_eq!(
            [before(&alice, &bob), before(&bob, &alice)],
            held,
            "{case}: the presentations as they were"
        );
        assert_eq!(friendship_of(&s, &alice, &bob).is_some(), upgrade, "{case}");
    }
}

#[test]
fn a_local_edge_is_made_portable_over_held_evidence_alone() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f1) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, by_bob) = s.core.friendships_present(b, vec![], vec![f1]).unwrap();
    assert!(ok_all(&by_bob));
    let (a, _) = device(&s.core, "alice", &alice, 1);
    assert_eq!(
        s.core.friend_add(a, "bob", None),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        s.core.friend_respond(b, "alice", true),
        Ok(RosterState::Accepted)
    );
    // Bob's presentation was held beside the local edge, and is no longer
    // shown held.
    install(&s, &alice, 1);
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_some());

    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let f2 = accept(
        &offer(&alice, renewed, &bob, now() - 30),
        &bob,
        1,
        now() - 30,
    );
    let (_, by_alice) = s.core.friendships_present(a2, vec![], vec![f2]).unwrap();
    assert!(ok_all(&by_alice));
    assert!(friendship_of(&s, &alice, &bob).is_some(), "still friends");
    assert!(
        s.rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .is_none(),
        "not portable over Bob's"
    );
}

#[test]
fn a_friendship_by_request_takes_the_id_a_dropped_presentation_kept() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob).unwrap();
    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&bob.devices[0].0.public()).0].into(),
        ..Default::default()
    });
    assert_eq!(friendship_of(&s, &alice, &bob), None);

    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    assert_eq!(
        s.core.friend_add(a, "bob", None),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        s.core.friend_respond(b, "alice", true),
        Ok(RosterState::Accepted)
    );
    assert_eq!(friendship_of(&s, &alice, &bob), Some(id));
    assert!(s.rel.is_live(id), "what was queued on it is released");
}

#[test]
fn a_friendship_is_dated_by_the_takings_of_its_own_bytes() {
    let (alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked(&accounts);
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    let (_, by_alice) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&by_alice));
    let mut corrupt = s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap().unwrap();
    corrupt.friendship = Some(b"not a friendship".to_vec());
    s.rel.present(&corrupt).unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, by_bob) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&by_bob));
    assert_eq!(friendship_of(&s, &alice, &bob), None, "not over Alice's");

    // Reset after Alice's copy was taken and before Bob's.
    keep(&s, &alice, 1, t + 5);
    assert_eq!(
        s.core.friend_add(a, "bob", None),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        s.core.friend_respond(b, "alice", true),
        Ok(RosterState::Accepted)
    );
    assert!(friendship_of(&s, &alice, &bob).is_some());
    for (who, p, q) in [
        ("alice", fp(&alice), fp(&bob)),
        ("bob", fp(&bob), fp(&alice)),
    ] {
        assert!(
            s.rel.presentation(&p, &q).unwrap().is_none(),
            "{who}'s not held: a copy that does not check dates nothing"
        );
    }
}

#[test]
fn a_taking_is_carried_only_to_the_bytes_it_dated() {
    for accepted in [false, true] {
        let case = format!("accepted {accepted}");
        let (alice, bob) = (person(1), person(2));
        let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
        let s = linked(&accounts);
        let t = s.core.clock().unix();
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let (b, _) = device(&s.core, "bob", &bob, 0);
        let o = offer(&alice, 0, &bob, t);
        let f = if accepted {
            assert_eq!(
                s.core.friend_ask(a, "bob", None, Some(o.clone())),
                Ok(RosterState::PendingOut),
                "{case}"
            );
            accept(&o, &bob, 0, t + 20)
        } else {
            let (_, _, _, _, f) = made(&linked(&accounts), &alice, &bob);
            f
        };
        // A copy of its hash whose bytes do not check, taken at t.
        let (p, q) = if accepted {
            (fp(&bob), fp(&alice))
        } else {
            (fp(&alice), fp(&bob))
        };
        s.rel
            .present(&Presentation {
                presenter: p,
                other: q,
                names: [p, q],
                pair: Pair::new(Fingerprint(p), Fingerprint(q)).hash(),
                hash: hash(&f),
                friendship: Some(b"not a friendship".to_vec()),
                reset: None,
                device: [0; 32],
                edge: None,
                at: super::unix_time(t),
                taken: super::unix_time(t),
            })
            .unwrap();
        s.core.clock().advance(std::time::Duration::from_secs(20));
        if accepted {
            assert_eq!(
                s.core.friend_answer(b, "alice", true, Some(f)),
                Ok(RosterState::Accepted),
                "{case}"
            );
        } else {
            let (_, again) = s.core.friendships_present(a, vec![], vec![f]).unwrap();
            assert!(ok_all(&again), "{case}");
        }
        assert!(s.rel.presentation(&p, &q).unwrap().is_some(), "{case}");

        // Reset after the copy that does not check was taken, and before
        // the one that does.
        reset(&s, &alice, 1, t + 10);
        assert!(
            s.rel.presentation(&p, &q).unwrap().is_none(),
            "{case}: not held"
        );
    }
}

#[test]
fn presenting_again_judges_the_other_partys_copy_that_does_not_check() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, mut rb, f) = made(&s, &alice, &bob);
    let mut theirs = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap().unwrap();
    theirs.friendship = Some(b"not a friendship".to_vec());
    s.rel.present(&theirs).unwrap();
    let (_, again) = s
        .core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    assert!(ok_all(&again));
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
    let mine = s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap();
    assert_eq!(mine.and_then(|p| p.friendship), Some(f), "Alice's stays");
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)],
        "an edge stands on no copy that does not check"
    );
}

fn pair_of(a: &Person, b: &Person) -> [u8; 32] {
    Pair::new(Fingerprint(fp(a)), Fingerprint(fp(b))).hash()
}

#[test]
fn a_withdrawal_a_reset_device_signed_shadows_no_earlier_one_that_stands() {
    // Kept unchecked, where nothing here names the pair, and applied,
    // where a presentation does.
    for named in [false, true] {
        let (mut alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let renewed = enroll(&mut alice, 1);
        let f = accept(
            &offer(&alice, renewed, &bob, now() - 60),
            &bob,
            0,
            now() - 60,
        );
        // A stolen device's, cutting later than the owner's will.
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let stolen = withdraw(&alice, 0, &bob, now() - 10);
        let (taken, _) = s.core.friendships_present(a, vec![stolen], vec![]).unwrap();
        assert!(ok_all(&taken));
        reset(&s, &alice, 1, now());
        let (b, _) = device(&s.core, "bob", &bob, 0);
        if named {
            let g = accept(&offer(&alice, renewed, &bob, now() - 5), &bob, 0, now() - 5);
            let (_, presented) = s.core.friendships_present(b, vec![], vec![g]).unwrap();
            assert!(ok_all(&presented));
        }
        let (a2, _) = device(&s.core, "alice", &alice, renewed);
        let w = withdraw(&alice, renewed, &bob, now() - 30);
        let (taken, _) = s
            .core
            .friendships_present(a2, vec![w.clone()], vec![])
            .unwrap();
        assert!(ok_all(&taken));
        let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
        assert_eq!(
            refused[0].outcome,
            Presented::Withdrawn(Some(w)),
            "named {named}"
        );
    }
}

#[test]
fn past_its_cap_an_owner_loses_a_withdrawal_that_no_longer_stands_first() {
    let (mut alice, carol, dave, erin) = (person(1), person(3), person(4), person(5));
    let cap = MessagingPolicy {
        max_roster: 2,
        ..policy()
    };
    let s = linked_with(cap, &[("alice", &fp(&alice))]);
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let keep = |uid, dev, other: &Person| {
        let w = withdraw(&alice, dev, other, now());
        let (taken, _) = s.core.friendships_present(uid, vec![w], vec![]).unwrap();
        assert!(ok_all(&taken));
    };
    keep(a2, renewed, &carol);
    keep(a, 0, &dave);
    reset(&s, &alice, 1, now());
    keep(a2, renewed, &erin);
    let held = |other: &Person| s.rel.withdrawals(&pair_of(&alice, other)).unwrap().len();
    assert_eq!(
        [held(&carol), held(&dave), held(&erin)],
        [1, 0, 1],
        "the reset device's goes, not the oldest"
    );
}

#[test]
fn a_rotation_keeps_the_successors_withdrawal_over_one_that_no_longer_stands() {
    // Where the records cannot be read, the rotation fails rather than
    // merge by cutoff alone, and a retry merges.
    for unreadable in [false, true] {
        let (alice, bob, successor) = (person(1), person(2), person(4));
        let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
            (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
            (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
        ])));
        let mut s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
        let cache = Arc::new(Flaky::default());
        Arc::get_mut(&mut s.core).unwrap().record_cache = Some(cache.clone());
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let dead = withdraw(&alice, 0, &bob, now() - 10);
        let (taken, _) = s.core.friendships_present(a, vec![dead], vec![]).unwrap();
        assert!(ok_all(&taken));
        reset(&s, &alice, 1, now());

        let record = Rotation {
            identity: alice.id.public(),
            successor: successor.id.public(),
            time: now(),
            next: None,
        }
        .sign(&alice.id, &successor.id)
        .unwrap();
        s.core.keep_rotation_record(&record);
        accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
        let (key, cert) = &successor.devices[0];
        let theirs = Withdrawal {
            from: successor.id.public(),
            pair: pair_of(&alice, &bob),
            party: Some(Fingerprint(fp(&alice))),
            before: now() - 30,
            time: now(),
            cert: cert.clone(),
        }
        .sign(key)
        .unwrap();
        let (t, _) = device(&s.core, "alice", &successor, 0);
        let (taken, _) = s
            .core
            .friendships_present(t, vec![theirs.clone()], vec![])
            .unwrap();
        assert!(ok_all(&taken));

        let held = || -> Vec<_> {
            s.rel
                .withdrawals(&pair_of(&alice, &bob))
                .unwrap()
                .into_iter()
                .map(|w| w.withdrawal)
                .collect()
        };
        if unreadable {
            cache.fail.store(true, Ordering::Relaxed);
            assert!(s
                .core
                .rotate_identity(&fp(&alice), &fp(&successor))
                .is_err());
            assert!(held().contains(&Some(theirs.clone())), "nothing merged");
            cache.fail.store(false, Ordering::Relaxed);
        }
        s.core
            .rotate_identity(&fp(&alice), &fp(&successor))
            .unwrap();
        assert_eq!(held(), [Some(theirs)], "unreadable {unreadable}");
    }
}

#[test]
fn a_presentation_a_rotation_merges_away_is_dropped_as_any_drop_is() {
    // The successor already holds a presentation of Bob, so Alice's moved
    // one goes. As a hash alone it leaves the edge evidence one way; whole,
    // it leaves Bob's held by his own taking alone, after Alice's reset.
    // Its tell is made from what the rotation left, whatever is read after.
    for (whole, unread) in [(false, false), (true, false), (false, true)] {
        let (alice, bob, successor) = (person(1), person(2), person(4));
        let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
        let (_, _, _, _, f) = made(&linked(&accounts), &alice, &bob);
        let s = linked(&accounts);
        let t = s.core.clock().unix();
        let (a, _) = device(&s.core, "alice", &alice, 1);
        let (_, first) = s
            .core
            .friendships_present(a, vec![], vec![f.clone()])
            .unwrap();
        assert!(ok_all(&first));
        s.core.clock().advance(std::time::Duration::from_secs(10));
        reset(&s, &alice, 1, t + 5);
        let (b, mut rb) = device(&s.core, "bob", &bob, 1);
        let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
        assert!(ok_all(&held));
        let id = friendship_of(&s, &alice, &bob).expect("friends");
        let theirs = accept(&offer(&successor, 0, &bob, now() - 30), &bob, 0, now() - 30);
        let at = super::unix_time(t);
        s.rel
            .present(&Presentation {
                presenter: fp(&successor),
                other: fp(&bob),
                names: [fp(&successor), fp(&bob)],
                pair: pair_of(&successor, &bob),
                hash: hash(&theirs),
                friendship: whole.then_some(theirs),
                reset: None,
                device: Fingerprint::of(&successor.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
        drain(&mut rb);

        if unread {
            s.fail.fail_reads_after("rotate");
        }
        s.core
            .rotate_identity(&fp(&alice), &fp(&successor))
            .unwrap();
        s.fail.fail_nth(0);
        assert_eq!(
            s.fail.failed().is_some(),
            unread,
            "whole {whole}, unread {unread}"
        );
        let rows = s
            .rel
            .relationship(
                &Mailbox::identified("bob", fp(&bob)),
                &Mailbox::identified("alice", fp(&successor)),
                std::time::SystemTime::now(),
            )
            .unwrap();
        assert_eq!(
            rows.and_then(|r| r.friendship),
            None,
            "whole {whole}, unread {unread}"
        );
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], None)],
            "whole {whole}, unread {unread}"
        );
        let kept: Vec<_> = s
            .rel
            .presentations(&fp(&successor))
            .unwrap()
            .into_iter()
            .map(|p| p.edge)
            .collect();
        assert!(kept.contains(&Some(id)), "whole {whole}: {kept:?}");
    }
}

#[test]
fn a_party_a_rotation_leaves_nothing_with_is_told_so_whatever_is_read_after() {
    // Alice's request is taken as an upgrade offer to Bob, on the edge his
    // presentation answered `Reset` left inactive: the only row of the
    // pair, which the rotation drops with the offer.
    for unread in [false, true] {
        let (mut alice, bob, successor) = (person(1), person(2), person(6));
        let accounts = [
            ("alice", &fp(&alice)),
            ("bob", &fp(&bob)),
            ("bob", &fp(&successor)),
        ];
        let (_, _, _, _, f) = made(&linked(&accounts), &alice, &bob);
        let s = linked(&accounts);
        reset(&s, &alice, 1, s.core.clock().unix() - 1);
        let renewed = enroll(&mut alice, 1);
        let (a, mut ra) = device(&s.core, "alice", &alice, renewed);
        let (b, _) = device(&s.core, "bob", &bob, 0);
        let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
        assert_eq!(refused[0].outcome, Presented::Reset);
        let o = offer(&alice, renewed, &bob, now() - 2);
        assert_eq!(
            s.core.friend_ask(a, "bob", None, Some(o)),
            Ok(RosterState::PendingOut)
        );
        drain(&mut ra);
        s.core.keep_rotation_record(&rotation(&bob, &successor));

        if unread {
            s.fail.fail_reads_after("rotate");
        }
        s.core.rotate_identity(&fp(&bob), &fp(&successor)).unwrap();
        s.fail.fail_nth(0);
        assert_eq!(s.fail.failed().is_some(), unread);
        assert_eq!(
            told(&mut ra),
            [("bob".into(), RosterState::Removed, vec![], None)],
            "unread {unread}"
        );
    }
}

#[test]
fn an_owner_past_its_cap_is_judged_whole_again_only_once_a_floor_rises() {
    let mut alice = person(1);
    let others: Vec<Person> = (3..8).map(person).collect();
    let cap = MessagingPolicy {
        max_roster: 2,
        ..policy()
    };
    let s = linked_with(cap, &[("alice", &fp(&alice))]);
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, renewed);
    let withdraw_from = |other: &Person| {
        let w = withdraw(&alice, renewed, other, now());
        let (taken, _) = s.core.friendships_present(a, vec![w], vec![]).unwrap();
        assert!(ok_all(&taken));
    };
    let scans = || s.core.withdrawal_scans.load(Ordering::Relaxed);
    for other in &others[..4] {
        withdraw_from(other);
    }
    assert_eq!(scans(), 1, "judged once past the cap");
    keep(&s, &alice, 1, now());
    withdraw_from(&others[4]);
    assert_eq!(scans(), 2, "and again once a kept floor rose");
}

#[test]
fn a_scan_past_the_cap_is_recorded_only_once_its_write_commits() {
    let mut alice = person(1);
    let others: Vec<Person> = (3..8).map(person).collect();
    let cap = MessagingPolicy {
        max_roster: 2,
        ..policy()
    };
    let s = linked_with(cap, &[("alice", &fp(&alice))]);
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, renewed);
    let present = |other: &Person| {
        let w = withdraw(&alice, renewed, other, now());
        s.core.friendships_present(a, vec![w], vec![])
    };
    for other in &others[..2] {
        assert!(ok_all(&present(other).unwrap().0));
    }
    let judged = || {
        s.core
            .withdrawals_judged
            .lock()
            .unwrap()
            .contains_key(&fp(&alice))
    };
    assert!(!judged(), "under the cap, no scan");
    s.fail.fail_next("write");
    assert!(present(&others[2]).is_err());
    assert_eq!(s.fail.failed(), Some("write"));
    assert!(!judged(), "a scan whose write failed is not recorded");
    assert!(ok_all(&present(&others[2]).unwrap().0));
    assert!(judged(), "and is once its write commits");
}

#[test]
fn a_withdrawal_below_a_floor_installed_alone_is_kept_past_the_cap() {
    // That floor can fall, and a withdrawal dropped cannot come back.
    let (mut alice, carol, dave, erin) = (person(1), person(3), person(4), person(5));
    let cap = MessagingPolicy {
        max_roster: 2,
        ..policy()
    };
    let s = linked_with(cap, &[("alice", &fp(&alice))]);
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    let keep = |uid, dev, other: &Person| {
        let w = withdraw(&alice, dev, other, now());
        let (taken, _) = s.core.friendships_present(uid, vec![w], vec![]).unwrap();
        assert!(ok_all(&taken));
    };
    keep(a2, renewed, &carol);
    keep(a, 0, &dave);
    install(&s, &alice, 1);
    keep(a2, renewed, &erin);
    let held = |other: &Person| s.rel.withdrawals(&pair_of(&alice, other)).unwrap().len();
    assert_eq!([held(&carol), held(&dave), held(&erin)], [0, 1, 1]);
}

#[test]
fn an_orphan_a_removal_by_fingerprint_left_goes_when_judged_again() {
    let (mut alice, bob, carol) = (person(1), person(2), person(3));
    let accounts = [
        ("alice", &fp(&alice)),
        ("bob", &fp(&bob)),
        ("carol", &fp(&carol)),
    ];
    let s1 = linked(&accounts);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = linked_with(
        MessagingPolicy {
            max_roster: 1,
            ..policy()
        },
        &accounts,
    );
    let t = s.core.clock().unix();
    // Alice's roster is full, so the friendship stays inactive here.
    let (a, _) = device(&s.core, "alice", &alice, 1);
    s.core.inbox_block(a, "carol", true).unwrap();
    s.core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));

    // Bob's, held by Alice's taking alone, outlives the removal's
    // judging of it.
    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    s.fail.fail_next("presentation");
    assert_eq!(s.core.friend_remove_by_key(a2, &fp(&bob), None), Ok(()));
    assert_eq!(s.fail.failed(), Some("presentation"));
    let bobs = || s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap();
    assert!(bobs().is_some());
    s.core.judge_floors([fp(&alice)]);
    assert!(bobs().is_none());
}

#[test]
fn an_offer_moved_to_a_successor_goes_with_its_predecessors_floor() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    assert_eq!(
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now()))),
        Ok(RosterState::PendingOut)
    );
    let (_, mut rb) = device(&s.core, "bob", &bob, 0);
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
    let record = Rotation {
        identity: alice.id.public(),
        successor: successor.id.public(),
        time: now(),
        next: None,
    }
    .sign(&alice.id, &successor.id)
    .unwrap();
    s.core.keep_rotation_record(&record);
    s.core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .unwrap();
    let wall = std::time::SystemTime::now();
    let moved = || {
        s.rel
            .offers_from(&fp(&successor), wall)
            .unwrap()
            .into_iter()
            .find(|(to, _)| *to == fp(&bob))
    };
    assert!(moved().is_some());
    drain(&mut rb);

    reset(&s, &alice, 1, now());
    assert!(moved().is_none());
    let entries: Vec<_> = drain(&mut rb)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) if e.login == "alice" => Some((e.state, e.offer)),
            _ => None,
        })
        .collect();
    assert_eq!(entries, [(RosterState::PendingIn, None)]);
}

#[test]
fn a_friendship_moved_by_a_rotation_whose_record_was_not_kept_goes_with_its_predecessors_floor() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    made(&s, &alice, &bob);
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
    s.fail.fail_next("keep_rotation");
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    assert_eq!(s.fail.failed(), Some("keep_rotation"));
    s.core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .unwrap();
    let moved = || s.rel.presentation(&fp(&successor), &fp(&bob)).unwrap();
    assert!(moved().is_some());

    reset(&s, &alice, 1, now() - 30);
    assert!(moved().is_none());
}

#[test]
fn a_grant_judged_before_an_install_is_judged_by_the_pass_after_it() {
    let (mut alice, bob) = (person(1), person(2));
    let accounts = [("alice", &fp(&alice)), ("bob", &fp(&bob))];
    let (_, _, _, _, f) = made(&linked(&accounts), &alice, &bob);
    let s = linked(&accounts);
    let t = s.core.clock().unix();
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, renewed);
    // Parked once it has judged the friendship at Alice's epochs before
    // the reset, holding the lock, before it records.
    let parked = s.fail.park.arm("presentation");
    let core = s.core.clone();
    let grant = std::thread::spawn(move || core.friendships_present(a, vec![], vec![f]));
    parked.arrived();
    keep(&s, &alice, 1, t - 60);
    let core = s.core.clone();
    let alice_fp = fp(&alice);
    let install = std::thread::spawn(move || core.raise_floor(alice_fp, 1));
    while s.core.published_floor(&fp(&alice)) != Some(1) {
        std::thread::yield_now();
    }
    // Room for a pass that read without the lock to read before the grant
    // records.
    std::thread::sleep(std::time::Duration::from_millis(200));
    parked.release();
    let (_, granted) = grant.join().unwrap().unwrap();
    assert!(ok_all(&granted), "{granted:?}");
    install.join().unwrap();
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_none_or(|p| !p.evidence()));
}

#[test]
fn a_pass_records_its_own_ends_and_not_a_change_beside_them() {
    for beside in [false, true] {
        let (alice, bob, successor) = (person(1), person(2), person(4));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let reset_at = s.core.clock().unix() - 30;
        made(&s, &alice, &bob);
        keep(&s, &alice, 1, reset_at);
        let parked = s.core.reconciling.arm("ended");
        let core = s.core.clone();
        let alice_fp = fp(&alice);
        let pass = std::thread::spawn(move || core.raise_floor(alice_fp, 1));
        parked.arrived();
        assert_eq!(friendship_of(&s, &alice, &bob), None, "ended by the pass");
        if beside {
            // A link in Alice's chain, which the pass did not read.
            let record = Rotation {
                identity: alice.id.public(),
                successor: successor.id.public(),
                time: now(),
                next: None,
            }
            .sign(&alice.id, &successor.id)
            .unwrap();
            s.core.keep_rotation_record(&record);
        }
        parked.release();
        pass.join().unwrap();
        let recorded = s
            .core
            .reconciled
            .lock()
            .unwrap()
            .at
            .contains_key(&fp(&alice));
        assert_eq!(recorded, !beside, "beside {beside}");
    }
}

fn rotation(from: &Person, to: &Person) -> Vec<u8> {
    Rotation {
        identity: from.id.public(),
        successor: to.id.public(),
        time: now(),
        next: None,
    }
    .sign(&from.id, &to.id)
    .unwrap()
}

#[test]
fn a_pass_records_nothing_after_a_change_under_a_key_it_rotated_to() {
    for beside in [false, true] {
        let (alice, bob, successor, next) = (person(1), person(2), person(4), person(5));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        // Two predecessors of one successor: the store answers one of them
        // first.
        s.core.keep_rotation_record(&rotation(&alice, &successor));
        s.core.keep_rotation_record(&rotation(&bob, &successor));
        keep(&s, &bob, 1, now());
        let parked = s.core.reconciling.arm("ended");
        let core = s.core.clone();
        let bob_fp = fp(&bob);
        let pass = std::thread::spawn(move || core.raise_floor(bob_fp, 1));
        parked.arrived();
        if beside {
            s.core.keep_rotation_record(&rotation(&successor, &next));
        }
        parked.release();
        pass.join().unwrap();
        let recorded = s.core.reconciled.lock().unwrap().at.contains_key(&fp(&bob));
        assert_eq!(recorded, !beside, "beside {beside}");
    }
}

#[test]
fn a_pass_dates_a_friendship_by_its_taking_under_every_key_of_the_chain() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = now();
    let f = accept(&offer(&alice, 0, &bob, t - 300), &bob, 0, t - 300);
    let g = accept(&offer(&alice, 0, &bob, t - 250), &bob, 0, t - 250);
    let row = |presenter: &Person, other: &Person, bytes: &Vec<u8>, taken: u64| {
        let at = super::unix_time(taken);
        s.rel
            .present(&Presentation {
                presenter: fp(presenter),
                other: fp(other),
                names: [fp(presenter), fp(other)],
                pair: pair_of(presenter, other),
                hash: hash(bytes),
                friendship: Some(bytes.clone()),
                reset: None,
                device: Fingerprint::of(&presenter.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
    };
    // `f` taken under Alice's key before her reset, and again under her
    // successor's after it; Bob's of the successor, `g`, only after.
    row(&alice, &bob, &f, t - 200);
    row(&successor, &bob, &f, t);
    row(&bob, &successor, &g, t);
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    reset(&s, &alice, 1, t - 100);
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&successor))
        .unwrap()
        .is_none());
    assert!(
        s.rel
            .presentation(&fp(&successor), &fp(&bob))
            .unwrap()
            .is_some(),
        "held by its taking under Alice's key"
    );
}

#[test]
fn an_orphan_is_dated_by_its_taking_under_every_key_of_the_chain() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&successor)), ("bob", &fp(&bob))]);
    let t = now();
    let f = accept(&offer(&alice, 0, &bob, t - 300), &bob, 0, t - 300);
    let row = |presenter: &Person, other: &Person, names: [&Person; 2], taken: u64| {
        let at = super::unix_time(taken);
        s.rel
            .present(&Presentation {
                presenter: fp(presenter),
                other: fp(other),
                names: [fp(names[0]), fp(names[1])],
                pair: pair_of(&alice, &bob),
                hash: hash(&f),
                friendship: Some(f.clone()),
                reset: None,
                device: Fingerprint::of(&presenter.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
    };
    // Taken under Alice's key before her reset, and under her successor's
    // and by Bob after it.
    row(&alice, &bob, [&alice, &bob], t - 200);
    row(&successor, &bob, [&alice, &bob], t);
    row(&bob, &successor, [&bob, &alice], t);
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    reset(&s, &alice, 1, t - 100);
    let bobs = || s.rel.presentation(&fp(&bob), &fp(&successor)).unwrap();
    assert!(bobs().is_some(), "held by the taking under Alice's key");

    let (a, _) = device(&s.core, "alice", &successor, 0);
    assert_eq!(s.core.friend_remove_by_key(a, &fp(&bob), None), Ok(()));
    assert!(s
        .rel
        .presentation(&fp(&successor), &fp(&bob))
        .unwrap()
        .is_none());
    assert!(
        bobs().is_some(),
        "still held by the taking under Alice's key"
    );
}

#[test]
fn a_pass_whose_ends_meet_the_generations_forgotten_records_nothing() {
    let (alice, bob, carol) = (person(1), person(2), person(3));
    let s = linked(&[
        ("alice", &fp(&alice)),
        ("bob", &fp(&bob)),
        ("carol", &fp(&carol)),
    ]);
    let t = now();
    for (other, at) in [(&bob, t - 300), (&carol, t - 250)] {
        let f = accept(&offer(&alice, 0, other, at), other, 0, at);
        for (presenter, to) in [(&alice, other), (other, &alice)] {
            let taken = super::unix_time(t);
            s.rel
                .present(&Presentation {
                    presenter: fp(presenter),
                    other: fp(to),
                    names: [fp(presenter), fp(to)],
                    pair: pair_of(presenter, to),
                    hash: hash(&f),
                    friendship: Some(f.clone()),
                    reset: None,
                    device: Fingerprint::of(&presenter.devices[0].0.public()).0,
                    edge: None,
                    at: taken,
                    taken,
                })
                .unwrap();
        }
    }
    // The first pair's end leaves the generations one short of their
    // bound, and the second's passes it.
    let filler = (0..super::GENERATIONS as u32 - 2).map(|i| {
        let mut k = [0xee; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    });
    s.core
        .unjudge(s.core.relationships.as_ref().unwrap(), filler);
    reset(&s, &alice, 1, t - 100);
    for other in [&bob, &carol] {
        assert!(s
            .rel
            .presentation(&fp(&alice), &fp(other))
            .unwrap()
            .is_none());
    }
    assert!(!s
        .core
        .reconciled
        .lock()
        .unwrap()
        .at
        .contains_key(&fp(&alice)));
}

#[test]
fn a_pass_that_fails_keeps_one_under_way_from_recording() {
    let alice = person(1);
    let s = linked(&[("alice", &fp(&alice))]);
    keep(&s, &alice, 1, now());
    let parked = s.core.reconciling.arm("ended");
    let core = s.core.clone();
    let alice_fp = fp(&alice);
    let pass = std::thread::spawn(move || core.raise_floor(alice_fp, 1));
    parked.arrived();
    s.fail.fail_next("presentations");
    s.core.judge_floors([fp(&alice)]);
    assert_eq!(s.fail.failed(), Some("presentations"));
    parked.release();
    pass.join().unwrap();
    assert!(!s
        .core
        .reconciled
        .lock()
        .unwrap()
        .at
        .contains_key(&fp(&alice)));
}

/// Presentations of `bytes` by each `(presenter, other)`, named by
/// `names` and taken at its time.
fn stored(s: &Server, bytes: &[u8], names: [&Person; 2], rows: &[(&Person, &Person, u64)]) {
    for (presenter, other, taken) in rows {
        let at = super::unix_time(*taken);
        s.rel
            .present(&Presentation {
                presenter: fp(presenter),
                other: fp(other),
                names: [fp(names[0]), fp(names[1])],
                pair: pair_of(names[0], names[1]),
                hash: hash(bytes),
                friendship: Some(bytes.to_vec()),
                reset: None,
                device: Fingerprint::of(&presenter.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
    }
}

#[test]
fn a_reset_dated_after_a_pass_kept_the_friendship_unknown_ends_it() {
    let (mut alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = now();
    let renewed = enroll(&mut alice, 1);
    let f = accept(&offer(&alice, renewed, &bob, t - 300), &bob, 0, t - 300);
    stored(
        &s,
        &f,
        [&alice, &bob],
        &[(&alice, &bob, t), (&bob, &alice, t)],
    );
    // Bob's floor with no record of when he reset: Unknown to both passes.
    install(&s, &bob, 1);
    keep(&s, &alice, 1, t - 1000);
    s.core.raise_floor(fp(&alice), 1);
    let theirs = || s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap();
    assert!(theirs().is_some());
    assert!(s
        .core
        .reconciled
        .lock()
        .unwrap()
        .at
        .contains_key(&fp(&alice)));

    // The record arrives as an admission fetches it.
    keep(&s, &bob, 1, t - 100);
    s.core.raise_floor(fp(&bob), 1);
    assert!(theirs().is_none());
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_none());
}

#[test]
fn an_offer_moved_while_a_pass_judged_it_is_judged_again() {
    let (mut alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    // Recorded once, at the reset before the one the offer goes with.
    reset(&s, &alice, 1, now() - 600);
    let renewed = enroll(&mut alice, 1);
    let (a, _) = device(&s.core, "alice", &alice, renewed);
    assert_eq!(
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, renewed, &bob, now()))),
        Ok(RosterState::PendingOut)
    );
    assert!(s
        .core
        .reconciled
        .lock()
        .unwrap()
        .at
        .contains_key(&fp(&alice)));
    keep(&s, &alice, 2, now());
    let parked = s.core.reconciling.arm("read");
    let core = s.core.clone();
    let alice_fp = fp(&alice);
    let pass = std::thread::spawn(move || core.raise_floor(alice_fp, 2));
    parked.arrived();
    s.core.keep_rotation_record(&rotation(&bob, &successor));
    s.core.rotate_identity(&fp(&bob), &fp(&successor)).unwrap();
    parked.release();
    pass.join().unwrap();
    // A tick that does not name her.
    s.core.reconcile_due([]);
    let wall = std::time::SystemTime::now();
    assert!(s
        .rel
        .offer(&fp(&alice), &fp(&successor), wall)
        .unwrap()
        .is_none());
}

#[test]
fn a_copy_dropped_under_a_predecessor_judges_its_successors_again() {
    let (old, new, bob) = (person(1), person(4), person(2));
    let s = linked(&[("bob", &fp(&bob))]);
    let t = now();
    let f = accept(&offer(&old, 0, &bob, t - 300), &bob, 0, t - 300);
    stored(
        &s,
        &f,
        [&old, &bob],
        &[(&old, &bob, t - 200), (&new, &bob, t)],
    );
    s.core.keep_rotation_record(&rotation(&old, &new));
    keep(&s, &old, 1, t - 100);
    keep(&s, &new, 1, t - 1000);
    s.core.judge_floors([fp(&new)]);
    let later = || s.rel.presentation(&fp(&new), &fp(&bob)).unwrap();
    assert!(later().is_some(), "dated by the copy under the old key");

    let device = Fingerprint::of(&old.devices[0].0.public()).0;
    let cause = Cause::PublishedDevice {
        identity: fp(&old),
        device,
    };
    let under = Some(fp(&old));
    s.core
        .sweep_offers(vec![(Work::DropPresentedBy { under, device }, cause)]);
    assert!(later().is_some(), "made by another device");
    s.core.judge_floors([fp(&new)]);
    assert!(later().is_none());
}

#[test]
fn a_pair_moved_while_a_pass_judged_it_is_judged_again() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = now();
    let f = accept(&offer(&alice, 0, &bob, t - 300), &bob, 0, t - 300);
    stored(
        &s,
        &f,
        [&alice, &bob],
        &[(&alice, &bob, t), (&bob, &alice, t)],
    );
    keep(&s, &alice, 1, t - 100);
    let parked = s.core.reconciling.arm("read");
    let core = s.core.clone();
    let alice_fp = fp(&alice);
    let pass = std::thread::spawn(move || core.raise_floor(alice_fp, 1));
    parked.arrived();
    s.core.keep_rotation_record(&rotation(&bob, &successor));
    s.core.rotate_identity(&fp(&bob), &fp(&successor)).unwrap();
    parked.release();
    pass.join().unwrap();
    // Bob, of no floor, judged with his successor's rows by the rotation.
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&successor))
        .unwrap()
        .is_none());
}

#[test]
fn a_tick_reads_the_epochs_only_of_identities_it_names_or_no_pass_recorded() {
    let (alice, bob) = (person(1), person(2));
    let mut s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let cache = Arc::new(Flaky::default());
    Arc::get_mut(&mut s.core).unwrap().record_cache = Some(cache.clone());
    keep(&s, &alice, 1, now());
    keep(&s, &bob, 1, now());
    s.core.raise_floor(fp(&alice), 1);
    let read = || std::mem::take(&mut *cache.read.lock().unwrap());
    read();
    s.core.reconcile_due([]);
    let first = read();
    assert!(first.contains(&fp(&bob)), "never recorded");
    assert!(!first.contains(&fp(&alice)), "recorded and not named");
    s.core.reconcile_due([]);
    assert!(read().is_empty(), "both recorded");
    s.core.reconcile_due([fp(&alice)]);
    assert!(read().contains(&fp(&alice)), "named");
}

#[test]
fn a_tick_reaches_every_identity_no_pass_recorded_so_many_at_a_time() {
    let mut s = linked(&[]);
    let cache = Arc::new(Flaky::default());
    Arc::get_mut(&mut s.core).unwrap().record_cache = Some(cache.clone());
    // Every pass fails, so that none is recorded.
    cache.fail.store(true, Ordering::Relaxed);
    let ids: Vec<[u8; 32]> = (0..=super::UNRECORDED_PER_TICK as u16)
        .map(|n| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&n.to_be_bytes());
            id
        })
        .collect();
    for id in &ids {
        let kept = KeptEpoch {
            epoch: 1,
            time: 1,
            record: Vec::new(),
        };
        cache.keep_epoch(id, &kept).unwrap();
    }
    let tick = || {
        s.core.reconcile_due([]);
        let read = std::mem::take(&mut *cache.read.lock().unwrap());
        read.into_iter().collect::<std::collections::BTreeSet<_>>()
    };
    let first = tick();
    assert_eq!(first.len(), super::UNRECORDED_PER_TICK);
    let reached: Vec<_> = first.union(&tick()).copied().collect();
    assert_eq!(reached, ids, "the next tick goes on from where it stopped");
}

#[test]
fn an_epoch_kept_with_no_floor_raised_is_judged_at_the_next_tick() {
    let (mut alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let t = now();
    let renewed = enroll(&mut alice, 1);
    let f = accept(&offer(&alice, renewed, &bob, t - 300), &bob, 0, t - 300);
    stored(
        &s,
        &f,
        [&alice, &bob],
        &[(&alice, &bob, t), (&bob, &alice, t)],
    );
    // Bob's floor with no record of when he reset: Unknown, and recorded.
    install(&s, &bob, 1);
    assert!(s.core.reconciled.lock().unwrap().at.contains_key(&fp(&bob)));
    // The record kept as an admission refused before its floor is raised.
    keep(&s, &bob, 1, t - 100);
    s.core.reconcile_due([]);
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
}

#[test]
fn a_pass_of_no_floor_is_recorded() {
    let mut s = linked(&[]);
    let cache = Arc::new(Flaky::default());
    Arc::get_mut(&mut s.core).unwrap().record_cache = Some(cache.clone());
    let kept = KeptEpoch {
        epoch: 1,
        time: 1,
        record: Vec::new(),
    };
    cache.keep_epoch(&[1; 32], &kept).unwrap();
    let read = || std::mem::take(&mut *cache.read.lock().unwrap());
    s.core.reconcile_due([]);
    assert!(read().contains(&[1; 32]));
    s.core.reconcile_due([]);
    assert!(
        read().is_empty(),
        "a record that does not verify, judged once"
    );
}

#[test]
fn a_pass_of_no_floor_records_nothing_past_a_keep_and_a_clear() {
    let mut s = linked(&[]);
    let kept = |time| KeptEpoch {
        epoch: 1,
        time,
        record: Vec::new(),
    };
    // Kept before a restart, so no generation is held for it.
    let stored = Arc::new(MemoryRecordCache::default());
    stored.keep_epoch(&[1; 32], &kept(2)).unwrap();
    let core = Arc::get_mut(&mut s.core).unwrap();
    core.record_cache = Some(Arc::new(super::Watched {
        inner: stored,
        reconciled: core.reconciled.clone(),
    }));
    let records = s.core.record_cache().unwrap();
    let parked = s.core.reconciling.arm("no floor");
    let core = s.core.clone();
    let pass = std::thread::spawn(move || core.judge_floors([[1; 32]]));
    parked.arrived();
    records.keep_epoch(&[1; 32], &kept(1)).unwrap();
    s.core.unjudge_all();
    parked.release();
    pass.join().unwrap();
    assert!(!s.core.reconciled.lock().unwrap().at.contains_key(&[1; 32]));
}

#[test]
fn an_ask_is_answered_and_told_alike_whatever_the_target_holds() {
    // Alice's roster is full, no friendship with Bob: refused whether or
    // not Bob's record would qualify her offer.
    for qualifying in [true, false] {
        let (mut alice, bob, carol) = (person(1), person(2), person(5));
        let tight = MessagingPolicy {
            max_roster: 1,
            ..policy()
        };
        let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, tight);
        if qualifying {
            s.core.friendships_present(b, vec![], vec![f]).unwrap();
        }
        let (c, _) = device(&s.core, "carol", &carol, 0);
        s.core.friend_add(a, "carol", None).unwrap();
        s.core.friend_respond(c, "alice", true).unwrap();
        let o = offer(&alice, renewed, &bob, now());
        assert_eq!(
            s.core.friend_ask(a, "bob", None, Some(o)),
            Err(MessagingError::RosterFull),
            "qualifying {qualifying}"
        );
    }
    // With room: the same answer, and Alice told the same entry.
    let mut seen = Vec::new();
    for qualifying in [true, false] {
        let (mut alice, bob) = (person(1), person(2));
        let (s, f, renewed, [(a, mut ra), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
        if qualifying {
            s.core.friendships_present(b, vec![], vec![f]).unwrap();
        }
        drain(&mut ra);
        let o = offer(&alice, renewed, &bob, now());
        let answer = s.core.friend_ask(a, "bob", None, Some(o));
        seen.push((
            answer,
            told(&mut ra),
            s.core.friends_roster(a).unwrap().len(),
        ));
    }
    assert_eq!(seen[0], seen[1]);
}

#[test]
fn an_upgrade_on_a_friendship_is_taken_at_a_full_roster() {
    let (alice, bob) = (person(1), person(2));
    let tight = MessagingPolicy {
        max_roster: 1,
        ..policy()
    };
    let s = linked_with(tight, &[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core.friend_add(a, "bob", None).unwrap();
    s.core.friend_respond(b, "alice", true).unwrap();
    assert_eq!(
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now()))),
        Ok(RosterState::Accepted)
    );
}

#[test]
fn an_upgrade_waiting_is_a_crossing_for_the_other_party() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Err(MessagingError::RequestPending)
    );
    assert_eq!(
        s.core
            .friend_ask(b, "alice", None, Some(offer(&bob, 0, &alice, now()))),
        Err(MessagingError::RequestPending)
    );
    assert!(friendship_of(&s, &alice, &bob).is_none());
}

#[test]
fn a_friendship_or_a_block_takes_the_reset_record_with_it() {
    for blocking in [false, true] {
        let (mut alice, bob) = (person(1), person(2));
        let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
        s.core.friendships_present(b, vec![], vec![f]).unwrap();
        if blocking {
            s.core.inbox_block(b, "alice", true).unwrap();
            s.core.inbox_block(b, "alice", false).unwrap();
        } else {
            s.core.friend_add(a, "bob", None).unwrap();
            s.core.friend_respond(b, "alice", true).unwrap();
            s.core.friend_remove(b, "alice").unwrap();
            s.core.clock().advance(std::time::Duration::from_secs(
                policy().request_retention.as_secs() + 1,
            ));
        }
        let record = s.rel.presentation(&fp(&bob), &fp(&alice)).unwrap();
        assert!(
            record.is_none_or(|p| p.reset.is_none()),
            "blocking {blocking}"
        );
        let (ma, mb) = mailboxes(&alice, &bob);
        let o = offer(&alice, renewed, &bob, s.core.clock().unix());
        s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
        assert!(requested(&s, &mb, &ma), "a request, blocking {blocking}");
    }
}

#[test]
fn an_offer_goes_with_its_device_its_identity_and_its_link() {
    // Bob's roster shows the offer on Alice's request until it goes.
    let shown = |s: &Server, b: Uid| {
        s.core
            .friends_roster(b)
            .unwrap()
            .iter()
            .find(|e| e.login == "alice")
            .and_then(|e| e.offer.clone())
    };
    for how in ["device", "identity", "unlink"] {
        let (alice, bob) = (person(1), person(2));
        let (s, dir) = switched(policy(), &[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (a, _) = device(&s.core, "alice", &alice, 0);
        let (b, _) = device(&s.core, "bob", &bob, 0);
        let o = offer(&alice, 0, &bob, now());
        s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
        assert_eq!(shown(&s, b), Some(o), "{how}");
        match how {
            "device" => drop(s.core.set_published_revocations(Published {
                devices: [(fp(&alice), Fingerprint::of(&alice.devices[0].0.public()).0)].into(),
                ..Default::default()
            })),
            "identity" => drop(s.core.set_published_revocations(Published {
                identities: [fp(&alice)].into(),
                ..Default::default()
            })),
            _ => unlinked(&s, &dir, &fp(&alice)),
        }
        assert_eq!(shown(&s, b), None, "{how}");
    }
}

#[test]
fn a_rotation_drops_an_offer_to_the_key_it_retires() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    accounts.0.lock().unwrap()[1].0 = Mailbox::identified("bob", fp(&successor));
    let record = Rotation {
        identity: bob.id.public(),
        successor: successor.id.public(),
        time: now(),
        next: None,
    }
    .sign(&bob.id, &successor.id)
    .unwrap();
    s.core.keep_rotation_record(&record);
    s.core.rotate_identity(&fp(&bob), &fp(&successor)).unwrap();
    let (b, _) = device(&s.core, "bob", &successor, 0);
    let roster = s.core.friends_roster(b).unwrap();
    let entry = roster.iter().find(|e| e.login == "alice").unwrap();
    assert_eq!(
        (entry.state, entry.offer.clone()),
        (RosterState::PendingIn, None)
    );
}

#[test]
fn a_reset_answer_is_recorded_whole_or_not_at_all() {
    for n in 1..=4 {
        let (mut alice, bob) = (person(1), person(2));
        let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
        let (ma, mb) = mailboxes(&alice, &bob);
        let o = offer(&alice, renewed, &bob, now());
        s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
        s.fail.fail_nth_write(n);
        let answered = s.core.friendships_present(b, vec![], vec![f.clone()]);
        let record = s
            .rel
            .presentation(&fp(&bob), &fp(&alice))
            .unwrap()
            .is_some_and(|p| p.reset.is_some());
        let request = requested(&s, &mb, &ma);
        match answered {
            Ok(_) => assert_eq!((record, request), (true, false), "write {n}"),
            Err(_) => assert_eq!((record, request), (false, true), "write {n}"),
        }
    }
}

#[test]
fn replacing_an_upgrade_beside_a_friendship_is_paced_as_presenting_is() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, _) = made(&s, &alice, &bob);
    let paced = (0..400u64).any(|n| {
        let o = offer(&alice, 0, &bob, now() - n % 200);
        s.core.friend_ask(a, "bob", None, Some(o)) == Err(MessagingError::RateLimited)
    });
    assert!(paced);
}

#[test]
fn an_upgrade_that_cannot_be_read_is_answered_as_a_failure() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, b, _, _) = made(&s, &alice, &bob);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    s.fail.fail_next("offer");
    assert_eq!(
        s.core.friend_respond(b, "alice", false),
        Err(MessagingError::ServerError)
    );
}

#[test]
fn an_upgrade_an_unlink_takes_is_told_to_the_friend() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, dir, f, renewed, [(a, mut ra), (b, mut rb), _]) =
        reset_elsewhere_switched(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
    drain(&mut ra);
    drain(&mut rb);
    unlinked(&s, &dir, &fp(&alice));
    // Her account no longer links the key the request was under, and her
    // sessions that proved it make friendship acts no more.
    assert_eq!(told(&mut ra), [], "the sender's account");
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::Removed, vec![], None)],
        "the friend's upgrade gone"
    );
}

#[test]
fn a_plain_session_asks_as_it_sees_beside_an_upgrade_it_cannot() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), (plain, _)]) = reset_elsewhere(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o)).unwrap();
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Err(MessagingError::RequestPending),
        "a session shown the upgrade answers it"
    );
    assert_eq!(
        s.core.friend_add(plain, "alice", None),
        Ok(RosterState::PendingOut),
        "one never shown it asks as ever"
    );
    let (ma, mb) = mailboxes(&alice, &bob);
    assert!(requested(&s, &ma, &mb));
}

#[test]
fn a_dismissed_upgrade_is_told_to_the_dismissers_sessions() {
    for accept in [false, true] {
        let (mut alice, bob) = (person(1), person(2));
        let (s, f, renewed, [(a, _), (b, mut rb), _]) = reset_elsewhere(&mut alice, &bob, policy());
        s.core.friendships_present(b, vec![], vec![f]).unwrap();
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, renewed, &bob, now())))
            .unwrap();
        drain(&mut rb);
        s.core.friend_respond(b, "alice", accept).unwrap();
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], None)],
            "accept {accept}"
        );
    }
}

#[test]
fn a_cancelled_upgrade_tells_the_friend_what_still_stands() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, mut rb), (plain, _)]) =
        reset_elsewhere(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    let o = offer(&alice, renewed, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    s.core.friend_add(plain, "alice", None).unwrap();
    drain(&mut rb);
    s.core.friend_cancel_offer(a, "bob", &o).unwrap();
    assert_eq!(
        told(&mut rb),
        [("alice".into(), RosterState::PendingOut, vec![], None)],
        "Bob's own request stands"
    );
}

#[test]
fn an_upgrade_its_record_was_replaced_under_is_not_told_again() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, mut rb), _]) = reset_elsewhere(&mut alice, &bob, policy());
    s.core.friendships_present(b, vec![], vec![f]).unwrap();
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, renewed, &bob, now())))
        .unwrap();
    // Another friendship the two made elsewhere before the reset.
    let o2 = offer(&alice, 0, &bob, now() - 1800);
    let f2 = accept(&o2, &bob, 0, now() - 1800);
    drain(&mut rb);
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f2]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    assert!(
        requests_offered(&mut rb).is_empty(),
        "the upgrade went with its record"
    );
}

/// What a records tick does with a sweep owed.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Owed {
    /// Its backoff is not over: not tried, whatever would fail.
    Waits,
    /// Tried, and failing again.
    Fails,
    /// Tried with nothing failing: the offer goes.
    Sweeps,
}

/// A revocation sweep of alice's device whose `failing` call failed, then
/// each tick after the clock moves so many seconds.
fn sweep_owed(failing: &'static str, ticks: &[(u64, Owed)]) {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    let offered = || {
        let roster = s.core.friends_roster(b).unwrap();
        roster
            .iter()
            .find(|e| e.login == "alice")
            .unwrap()
            .offer
            .is_some()
    };
    assert!(offered());
    s.fail.fail_next(failing);
    drop(s.core.set_published_revocations(Published {
        devices: [(fp(&alice), Fingerprint::of(&alice.devices[0].0.public()).0)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert_eq!(s.fail.failed(), Some(failing));
    for &(secs, owed) in ticks {
        s.core.clock.advance(std::time::Duration::from_secs(secs));
        if owed != Owed::Sweeps {
            s.fail.fail_next(failing);
        }
        s.core.owed_tick();
        s.fail.fail_nth(0);
        let tried = s.fail.failed() == Some(failing);
        assert_eq!(tried, owed == Owed::Fails, "{secs}s on: {owed:?}");
        assert_eq!(offered(), owed != Owed::Sweeps, "{secs}s on: {owed:?}");
    }
}

#[test]
fn offers_a_revocation_could_not_read_are_swept_after_a_backoff() {
    use Owed::*;
    sweep_owed(
        "offers_from",
        &[(0, Waits), (61, Fails), (61, Waits), (60, Sweeps)],
    );
}

#[test]
fn offers_a_revocation_could_not_drop_are_dropped_after_a_backoff() {
    sweep_owed("write", &[(0, Owed::Waits), (61, Owed::Sweeps)]);
}

#[test]
fn offers_an_identity_revocation_could_not_drop_are_dropped_after_a_backoff() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    let offered = || {
        let roster = s.core.friends_roster(b).unwrap();
        roster
            .iter()
            .find(|e| e.login == "alice")
            .unwrap()
            .offer
            .is_some()
    };
    s.fail.fail_next("write");
    drop(s.core.set_published_revocations(Published {
        identities: [fp(&alice)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert_eq!(s.fail.failed(), Some("write"));
    assert!(offered(), "kept, and owed");
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(!offered(), "dropped once its backoff is over");
}

#[test]
fn an_owed_sweep_whose_revocation_lifted_drops_nothing() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    let device_fp = Fingerprint::of(&alice.devices[0].0.public()).0;
    s.fail.fail_next("write");
    drop(s.core.set_published_revocations(Published {
        devices: [(fp(&alice), device_fp)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert_eq!(s.fail.failed(), Some("write"));
    // Lifted, and the device asks again: what the sweep owed is moot.
    drop(s.core.set_published_revocations(Published {
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    let (a, _) = device(&s.core, "alice", &alice, 0);
    s.core.friend_remove(a, "bob").unwrap();
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    let roster = s.core.friends_roster(b).unwrap();
    let e = roster.iter().find(|e| e.login == "alice").unwrap();
    assert!(e.offer.is_some(), "an offer signed after the lift kept");
}

/// Alice's upgrade waiting for Bob, on the record Bob holds: what each
/// test below takes from Bob's side.
fn upgrade_waiting() -> (Person, Person, Server, Events) {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, mut ra), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let o = offer(&alice, renewed, &bob, now() - 2);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o)),
        Ok(RosterState::PendingOut)
    );
    drain(&mut ra);
    (alice, bob, s, ra)
}

#[test]
fn every_party_an_upgrade_waits_from_is_told_when_it_goes() {
    let removed = |ra: &mut Events| {
        told(ra)
            .iter()
            .any(|(login, state, ..)| login == "bob" && *state == RosterState::Removed)
    };
    // Bob's identity revoked.
    let (_, bob, s, mut ra) = upgrade_waiting();
    drop(s.core.set_published_revocations(Published {
        identities: [fp(&bob)].into(),
        covered: [fp(&bob)].into(),
        ..Default::default()
    }));
    assert!(removed(&mut ra), "a revocation");
    // Bob blocking Alice, which says nothing of the block.
    let (_, _, s, mut ra) = upgrade_waiting();
    let (b, _) = device(&s.core, "bob", &person(2), 0);
    s.core.inbox_block(b, "alice", true).unwrap();
    assert!(removed(&mut ra), "a block");
    // Bob's account purged.
    let (_, bob, s, mut ra) = upgrade_waiting();
    s.core
        .purge_relationships(&Mailbox::identified("bob", fp(&bob)));
    assert!(removed(&mut ra), "a purge");
}

#[test]
fn a_block_whose_reads_fail_writes_nothing_and_one_that_takes_an_upgrade_tells_it() {
    // Each call the block makes failing in turn, then none: whatever it
    // takes of Alice's upgrade, she is told; whatever fails, nothing goes.
    for k in 1.. {
        let (alice, bob, s, mut ra) = upgrade_waiting();
        let (b, _) = device(&s.core, "bob", &bob, 0);
        let (ma, mb) = mailboxes(&alice, &bob);
        let waiting = || {
            let wall = s.core.clock().wall();
            let row = s.rel.relationship(&ma, &mb, wall).unwrap();
            row.and_then(|r| r.pending_out).is_some_and(|p| p.upgrade)
        };
        // Both rows and the offer apart, as they stood.
        let held = || {
            let wall = s.core.clock().wall();
            (
                s.rel.relationship(&ma, &mb, wall).unwrap(),
                s.rel.relationship(&mb, &ma, wall).unwrap(),
                s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap(),
            )
        };
        let before = held();
        s.fail.fail_nth(k);
        let blocked = s.core.inbox_block(b, "alice", true);
        s.fail.fail_nth(0);
        let failed = s.fail.failed();
        let told = told(&mut ra)
            .iter()
            .any(|(login, state, ..)| login == "bob" && *state == RosterState::Removed);
        match blocked {
            Ok(()) => assert!(!waiting() && told, "call {k}: taken, and told"),
            Err(_) => {
                assert!(!told, "call {k} ({failed:?}): nothing told");
                assert_eq!(held(), before, "call {k} ({failed:?}): nothing written");
            }
        }
        if failed.is_none() {
            break;
        }
    }
}

#[test]
fn a_deleted_accounts_purge_that_cannot_be_done_is_owed_until_it_is() {
    let (alice, bob, s, _) = upgrade_waiting();
    let (ma, mb) = mailboxes(&alice, &bob);
    let rows = || {
        s.rel
            .relationships(&ma, s.core.clock().wall())
            .unwrap()
            .len()
    };
    assert!(rows() > 0);
    s.fail.fail_next("relationships");
    s.core.inbox_purge(&ma);
    assert_eq!(s.fail.failed(), Some("relationships"));
    assert!(rows() > 0, "nothing purged yet");
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert_eq!(rows(), 0, "purged once owed");
    let _ = mb;
}

#[test]
fn a_registrar_device_sweep_follows_the_offers_its_identity_rotated() {
    // Whether or not the rotation's record was kept here: the move the
    // rotation made is.
    for kept in [true, false] {
        let (alice, bob, successor) = (person(1), person(2), person(4));
        let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
            (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
            (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
        ])));
        let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
        let (a, _) = device(&s.core, "alice", &alice, 0);
        s.core
            .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
            .unwrap();
        if kept {
            s.core.keep_rotation_record(&rotation(&alice, &successor));
        }
        accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
        s.core
            .rotate_identity(&fp(&alice), &fp(&successor))
            .unwrap();
        let carried = || {
            let ms = Mailbox::identified("alice", fp(&successor));
            let mb = Mailbox::identified("bob", fp(&bob));
            let row = s.rel.relationship(&ms, &mb, s.core.clock().wall()).unwrap();
            row.and_then(|r| r.pending_out).and_then(|p| p.offer)
        };
        assert!(carried().is_some(), "moved with the rotation, kept {kept}");
        drop(s.core.set_published_revocations(Published {
            devices: [(fp(&alice), Fingerprint::of(&alice.devices[0].0.public()).0)].into(),
            covered: [fp(&alice)].into(),
            ..Default::default()
        }));
        assert_eq!(carried(), None, "found under the successor, kept {kept}");
    }
}

#[test]
fn a_registrar_device_revocation_follows_the_presentations_its_identity_rotated() {
    let (alice, bob, successor) = (person(1), person(2), person(4));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    made(&s, &alice, &bob);
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    s.core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .unwrap();
    let revoked = Fingerprint::of(&alice.devices[0].0.public()).0;
    let presented = || s.rel.presented_by(&revoked).unwrap();
    assert!(
        presented().iter().any(|p| p.presenter == fp(&successor)),
        "moved with the rotation"
    );
    drop(s.core.set_published_revocations(Published {
        devices: [(fp(&alice), revoked)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert!(presented().is_empty(), "found under the successor");
}

#[test]
fn sweeps_that_overlap_in_one_install_tell_each_pair_once() {
    let (alice, bob, s, mut ra) = upgrade_waiting();
    let stored = s.rel.offer(&fp(&alice), &fp(&bob), s.core.clock().wall());
    let stored = stored.unwrap().expect("the upgrade's offer");
    let cert = Offer::check(&stored.offer, u64::MAX, &[], |_| 0)
        .unwrap()
        .cert;
    let renewed = Fingerprint::of(&DeviceCert::parse(&cert).unwrap().device).0;
    drop(s.core.set_published_revocations(Published {
        identities: [fp(&alice)].into(),
        devices: [(fp(&alice), renewed)].into(),
        covered: [fp(&alice), fp(&bob)].into(),
        ..Default::default()
    }));
    let entries = told(&mut ra)
        .iter()
        .filter(|(login, ..)| login == "bob")
        .count();
    assert_eq!(entries, 1, "one tell for one pair");
}

#[test]
fn a_signed_block_that_takes_an_upgrade_tells_its_sender() {
    let (alice, bob, s, mut ra) = upgrade_waiting();
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let w = withdraw(&bob, 0, &alice, now());
    s.core.block_withdrawing(b, "alice", w).unwrap();
    assert!(
        told(&mut ra)
            .iter()
            .any(|(login, state, ..)| login == "bob" && *state == RosterState::Removed),
        "told as a decline is"
    );
}

#[test]
fn an_owed_sweep_ends_only_on_a_list_that_covers_its_identity() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    let offered = || {
        let roster = s.core.friends_roster(b).unwrap();
        roster
            .iter()
            .find(|e| e.login == "alice")
            .unwrap()
            .offer
            .is_some()
    };
    s.fail.fail_next("write");
    drop(s.core.set_published_revocations(Published {
        identities: [fp(&alice)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert!(offered(), "owed");
    // Lists that could not read Alice's say nothing of her.
    drop(s.core.set_published_revocations(Published {
        covered: [fp(&bob)].into(),
        ..Default::default()
    }));
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(!offered(), "still owed, and dropped");
}

#[test]
fn an_operator_revoked_devices_offers_go_with_no_session_or_presentation_to_name_it() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    let o = offer(&alice, 0, &bob, now());
    s.core.friend_ask(a, "bob", None, Some(o.clone())).unwrap();
    let (ma, mb) = mailboxes(&alice, &bob);
    let row = s.rel.relationship(&ma, &mb, s.core.clock().wall()).unwrap();
    let carried = row.and_then(|r| r.pending_out).and_then(|p| p.offer);
    assert_eq!(
        carried.map(|o| o.offer),
        Some(o),
        "the request carries the offer signed"
    );
    s.core.end_session(a);
    drop(s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&alice.devices[0].0.public()).0].into(),
        ..Default::default()
    }));
    let roster = s.core.friends_roster(b).unwrap();
    let e = roster.iter().find(|e| e.login == "alice").unwrap();
    assert_eq!(e.offer, None, "found by what signed it");
}

#[test]
fn a_signed_acceptance_of_an_upgrade_whose_offer_lapsed_is_stale() {
    let (mut alice, bob) = (person(1), person(2));
    let (s, f, renewed, [(a, _), (b, _), _]) = reset_elsewhere(&mut alice, &bob, policy());
    let (_, refused) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert_eq!(refused[0].outcome, Presented::Reset);
    let o = offer(&alice, renewed, &bob, now() - 2);
    assert_eq!(
        s.core.friend_ask(a, "bob", None, Some(o.clone())),
        Ok(RosterState::PendingOut)
    );
    let (ma, mb) = mailboxes(&alice, &bob);
    let wall = s.core.clock().wall();
    let shown = s.rel.relationship(&ma, &mb, wall).unwrap();
    assert!(
        shown.and_then(|r| r.pending_out).is_some_and(|p| p.upgrade),
        "taken as an upgrade"
    );
    let kept = s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap();
    assert_eq!(
        kept.map(|k| k.offer),
        Some(o.clone()),
        "its offer kept apart"
    );
    s.core
        .clock()
        .advance(std::time::Duration::from_secs(2 * DAY));
    assert_eq!(
        s.core
            .friend_answer(b, "alice", true, Some(accept(&o, &bob, 0, now()))),
        Err(MessagingError::Stale),
        "its offer lapsed while its pending out stands"
    );
}

#[test]
fn a_frozen_identity_revoked_after_loses_its_offers() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    let shown = |s: &Server| {
        let roster = s.core.friends_roster(b).unwrap();
        roster
            .iter()
            .find(|e| e.login == "alice")
            .and_then(|e| e.offer.clone())
    };
    drop(s.core.set_published_revocations(Published {
        unrevoked: [fp(&alice)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert!(shown(&s).is_some(), "frozen alone keeps it");
    drop(s.core.set_published_revocations(Published {
        identities: [fp(&alice)].into(),
        covered: [fp(&alice)].into(),
        ..Default::default()
    }));
    assert_eq!(shown(&s), None, "revoked takes it");
}

#[test]
fn a_withdrawal_cutting_a_requests_offer_leaves_the_request_plain() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    let (b, _) = device(&s.core, "bob", &bob, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now() - 60)))
        .unwrap();
    let w = withdraw(&alice, 0, &bob, now());
    s.core.friendships_present(a, vec![w], vec![]).unwrap();
    let roster = s.core.friends_roster(b).unwrap();
    let e = roster.iter().find(|e| e.login == "alice").unwrap();
    assert_eq!((e.state, e.offer.clone()), (RosterState::PendingIn, None));
}

#[test]
fn a_dismissed_upgrade_beside_a_friendship_is_told_to_the_dismissers_sessions() {
    let (alice, bob) = (person(1), person(2));
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, b, mut rb, _) = made(&s, &alice, &bob);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    drain(&mut rb);
    s.core.friend_respond(b, "alice", false).unwrap();
    let entries: Vec<_> = drain(&mut rb)
        .into_iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) if e.login == "alice" => Some((e.state, e.offer)),
            _ => None,
        })
        .collect();
    assert_eq!(entries, [(RosterState::Accepted, None)], "the offer gone");
}

/// Alice and Bob friends by what each presented, her account then giving
/// up its link with the drop of her presentations failing: the server, its
/// directory, and Bob's presentation of her.
fn unlinked_owing() -> (Person, Person, Server, Switch) {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    made(&s, &alice, &bob);
    assert!(s
        .rel
        .presentation(&fp(&alice), &fp(&bob))
        .unwrap()
        .is_some());
    s.fail.fail_next("presentations");
    unlinked(&s, &accounts, &fp(&alice));
    assert_eq!(s.fail.failed(), Some("presentations"));
    (alice, bob, s, accounts)
}

/// A core on `s`'s stores, as a server started again on its database
/// builds one.
fn started_again(s: &Server, accounts: &Switch) -> Core {
    Core::new()
        .with_inbox(
            s.inbox.clone(),
            Arc::new(accounts.clone()),
            InboxPolicy::default(),
        )
        .with_relationships(s.fail.clone())
        .with_messaging(policy())
        .with_record_cache(Arc::new(MemoryRecordCache::default()))
}

#[test]
fn presentations_an_unlink_could_not_drop_are_dropped_by_the_server_started_after() {
    let (alice, bob, s, accounts) = unlinked_owing();
    let core = started_again(&s, &accounts);
    drop(s.core);
    core.owed_tick();
    assert!(
        (s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap()).is_none(),
        "the drop owed before the restart, done after it"
    );
}

#[test]
fn presentations_an_unlink_could_not_drop_are_dropped_where_a_rotation_moved_them() {
    let (alice, bob, s, _) = unlinked_owing();
    let successor = person(4);
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    s.core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .unwrap();
    assert!(s
        .rel
        .presentation(&fp(&successor), &fp(&bob))
        .unwrap()
        .is_some());
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(
        (s.rel.presentation(&fp(&successor), &fp(&bob)).unwrap()).is_none(),
        "dropped under the key the rows moved to"
    );
}

#[test]
fn an_orphan_whose_judging_was_owed_is_judged_where_a_rotation_moved_it() {
    let (mut alice, bob, carol, successor) = (person(1), person(2), person(3), person(4));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
        (Mailbox::identified("carol", fp(&carol)), messaging_bits()),
    ])));
    let s1 = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, _, _, _, f) = made(&s1, &alice, &bob);
    let s = server_of(
        accounts.clone(),
        MessagingPolicy {
            max_roster: 1,
            ..policy()
        },
        InboxPolicy::default(),
        None,
    );
    let t = s.core.clock().unix();
    let (a, _) = device(&s.core, "alice", &alice, 1);
    s.core.inbox_block(a, "carol", true).unwrap();
    s.core
        .friendships_present(a, vec![], vec![f.clone()])
        .unwrap();
    s.core.clock().advance(std::time::Duration::from_secs(10));
    reset(&s, &alice, 1, t + 5);
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));
    let renewed = enroll(&mut alice, 1);
    let (a2, _) = device(&s.core, "alice", &alice, renewed);
    s.fail.fail_next("presentation");
    assert_eq!(s.core.friend_remove_by_key(a2, &fp(&bob), None), Ok(()));
    assert_eq!(s.fail.failed(), Some("presentation"));

    // Bob's, held by Alice's taking alone, moves with her rotation, which
    // a start judges nothing of.
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
    s.core.keep_rotation_record(&rotation(&alice, &successor));
    s.core
        .rotate_identity_linking(&fp(&alice), &fp(&successor), true, |to| *to, |_| Ok(()))
        .unwrap();
    let bobs = || s.rel.presentation(&fp(&bob), &fp(&successor)).unwrap();
    assert!(bobs().is_some());
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(bobs().is_none(), "judged where the rotation moved it");
}

#[test]
fn a_claims_settling_that_cannot_be_written_is_owed_until_it_is() {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = session(&s.core, "alice", &alice, 0, false, u64::MAX);
    let (b, _) = session(&s.core, "bob", &bob, 0, false, u64::MAX);
    s.core.friend_add(a, "bob", None).unwrap();
    assert_eq!(
        s.core.friend_answer(b, "alice", true, None),
        Ok(RosterState::Accepted)
    );
    // Bob asks the account while it links nothing: a row by its login.
    accounts.0.lock().unwrap()[0].0 = Mailbox::login("alice");
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Ok(RosterState::PendingOut)
    );
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&alice));
    let asking = || {
        let (ma, mb) = mailboxes(&alice, &bob);
        let row = s.rel.relationship(&mb, &ma, s.core.clock().wall());
        let row = row.unwrap().unwrap();
        assert!(row.friendship.is_some());
        row.pending_out.is_some()
    };
    s.fail.fail_next("write");
    s.core.inbox_claim("alice", &fp(&alice));
    assert_eq!(s.fail.failed(), Some("write"));
    assert!(
        asking(),
        "the fold left Bob's request beside the friendship"
    );
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(!asking(), "settled by a tick");
}

/// Alice's offer to Bob, on a server whose directory a test changes.
fn offered_by_alice() -> (Person, Person, Server, Switch) {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let s = server_of(accounts.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    (alice, bob, s, accounts)
}

/// Whether `by`'s request to `to` carries its offer, under `by`'s key.
fn offering(s: &Server, by: &Person, to: &Person) -> bool {
    let (mb, mt) = (
        Mailbox::identified("", fp(by)),
        Mailbox::identified("", fp(to)),
    );
    let row = s.rel.relationship(&mb, &mt, s.core.clock().wall()).unwrap();
    row.and_then(|r| r.pending_out)
        .is_some_and(|p| p.offer.is_some())
}

fn revoked_device(who: &Person) -> Published {
    Published {
        devices: [(fp(who), Fingerprint::of(&who.devices[0].0.public()).0)].into(),
        covered: [fp(who)].into(),
        ..Default::default()
    }
}

#[test]
fn a_revocations_drop_owed_across_a_restart_is_done_before_any_list_is_read_again() {
    let (alice, bob, s, accounts) = offered_by_alice();
    s.fail.fail_next("write");
    drop(s.core.set_published_revocations(revoked_device(&alice)));
    assert_eq!(s.fail.failed(), Some("write"));
    assert!(offering(&s, &alice, &bob), "owed");
    let core = started_again(&s, &accounts);
    core.owed_tick();
    assert!(
        !offering(&s, &alice, &bob),
        "a key no list read covers is judged as revoked still"
    );
}

#[test]
fn a_rotation_waits_for_work_that_could_not_be_owed() {
    let (alice, bob, s, accounts) = offered_by_alice();
    let successor = person(4);
    s.fail.fail_from(1);
    drop(s.core.set_published_revocations(revoked_device(&alice)));
    s.fail.fail_nth(0);
    assert_eq!(s.core.owed_unwritten().len(), 2, "kept in memory alone");
    assert!(s.rel.owed().unwrap().is_empty());
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
    s.fail.fail_next("owe");
    assert!(s
        .core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .is_err());
    assert!(offering(&s, &alice, &bob), "nothing moved");
    assert_eq!(s.core.owed_unwritten().len(), 2);

    s.core
        .rotate_identity(&fp(&alice), &fp(&successor))
        .unwrap();
    assert!(
        offering(&s, &successor, &bob),
        "moved, once the work was written"
    );
    let owed = s.rel.owed().unwrap();
    let moved = Work::DropOffersBy {
        under: Some(fp(&successor)),
        device: Fingerprint::of(&alice.devices[0].0.public()).0,
    };
    assert!(
        owed.iter().any(|o| o.work == moved),
        "and moved with it: {owed:?}"
    );
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(!offering(&s, &successor, &bob), "dropped where it went");
}

/// The server dies inside `link`, before `friendships_linking` returns:
/// the core started again on its stores, its next tick run.
fn linking_cut_short(s: &Server, accounts: &Switch, fp: &[u8; 32], link: impl FnOnce()) {
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.core
            .friendships_linking(fp, || -> Result<(), StoreError> {
                link();
                panic!("the server dies");
            })
    }));
    assert!(crashed.is_err());
    started_again(s, accounts).owed_tick();
}

#[test]
fn an_unlinks_drops_outlive_a_link_cut_short_before_its_write() {
    let (alice, bob, s, accounts) = unlinked_owing();
    linking_cut_short(&s, &accounts, &fp(&alice), || {});
    assert!(
        (s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap()).is_none(),
        "dropped for the identity no account links"
    );
}

#[test]
fn an_unlinks_drops_are_moot_once_a_link_is_written_however_its_call_ends() {
    let (alice, bob, s, accounts) = unlinked_owing();
    let relink = || accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&alice));
    linking_cut_short(&s, &accounts, &fp(&alice), relink);
    let kept = || (s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap()).is_some();
    assert!(kept(), "the linked identity's presentation");
    assert_eq!(s.rel.owed().unwrap(), [], "settled unrun");

    // And where settling them fails, a tick finds them moot.
    let (alice, bob, s, accounts) = unlinked_owing();
    s.fail.fail_next("owed");
    let linked = s.core.friendships_linking(&fp(&alice), || {
        accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&alice));
        Ok::<_, StoreError>(())
    });
    assert!(linked.is_ok());
    assert_eq!(s.fail.failed(), Some("owed"));
    assert_ne!(s.rel.owed().unwrap(), [], "left owed");
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(
        (s.rel.presentation(&fp(&alice), &fp(&bob)).unwrap()).is_some(),
        "kept"
    );
    assert_eq!(s.rel.owed().unwrap(), [], "settled unrun");
}

/// A directory whose lookups by key can be made to fail, as a file
/// directory's scan can.
#[derive(Clone)]
struct Unreadable(Switch, Arc<AtomicBool>);

impl crate::AccountDirectory for Unreadable {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        self.0.inbox_account(login)
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<crate::AccessBits> {
        self.0.mailbox_access(who)
    }

    fn account_by_key(
        &self,
        fp: &[u8; 32],
    ) -> Result<Option<(Mailbox, crate::AccessBits)>, StoreError> {
        match self.1.load(Ordering::SeqCst) {
            true => Err(StoreError("the accounts directory".into())),
            false => self.0.account_by_key(fp),
        }
    }
}

#[test]
fn an_unlinks_drop_is_left_owed_while_the_link_cannot_be_read() {
    let (alice, bob) = (person(1), person(2));
    let accounts = Switch(Arc::new(std::sync::Mutex::new(vec![
        (Mailbox::identified("alice", fp(&alice)), messaging_bits()),
        (Mailbox::identified("bob", fp(&bob)), messaging_bits()),
    ])));
    let dir = Unreadable(accounts.clone(), Arc::new(AtomicBool::new(false)));
    let s = server_of(dir.clone(), policy(), InboxPolicy::default(), None);
    let (a, _) = device(&s.core, "alice", &alice, 0);
    s.core
        .friend_ask(a, "bob", None, Some(offer(&alice, 0, &bob, now())))
        .unwrap();
    // Unlinked with its drop failing, linked again with the settling after
    // the link failing: owed, and moot.
    s.fail.fail_next("write");
    unlinked(&s, &accounts, &fp(&alice));
    assert_eq!(s.fail.failed(), Some("write"));
    s.fail.fail_next("owed");
    let relinked = s.core.friendships_linking(&fp(&alice), || {
        accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&alice));
        Ok::<_, StoreError>(())
    });
    assert!(relinked.is_ok());
    let owed = || s.rel.owed().unwrap().len();
    assert_ne!(owed(), 0);

    dir.1.store(true, Ordering::SeqCst);
    s.core.clock().advance(std::time::Duration::from_secs(3700));
    s.core.owed_tick();
    assert!(offering(&s, &alice, &bob), "the linked identity's offer");
    assert_ne!(owed(), 0, "still owed");

    dir.1.store(false, Ordering::SeqCst);
    s.core.clock().advance(std::time::Duration::from_secs(3700));
    s.core.owed_tick();
    assert!(offering(&s, &alice, &bob), "kept");
    assert_eq!(owed(), 0, "settled unrun once it reads as linked");
}

#[test]
fn a_link_made_again_keeps_its_presentations_while_a_rotation_moves_its_link() {
    let (alice, bob, s, accounts) = unlinked_owing();
    let successor = person(4);
    let linked = s.core.friendships_linking(&fp(&alice), || {
        accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&alice));
        Ok::<_, StoreError>(())
    });
    assert!(linked.is_ok());
    // The link moves to the successor before the rows do, as a rotation's
    // `rotate_link` does ahead of `rotate_identity`; a tick between.
    accounts.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp(&successor));
    s.core.clock().advance(std::time::Duration::from_secs(61));
    s.core.owed_tick();
    assert!(
        s.rel
            .presentation(&fp(&alice), &fp(&bob))
            .unwrap()
            .is_some(),
        "the relinked account's presentation kept"
    );
}
