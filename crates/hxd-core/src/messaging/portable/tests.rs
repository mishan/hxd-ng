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
use crate::relationships::{Presentation, RelationId};
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
        Err(MessagingError::BadSignature),
        "no offer stored to accept"
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
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (a, _, _, _, f) = made(&s, &alice, &bob);
    s.core.friendships_unlinked(&fp(&alice));
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
        assert_eq!(refused[0].outcome, Presented::AccountNotFound);
    }
    assert!(told(&mut ra2).is_empty(), "never active");
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
    assert_eq!(refused[0].outcome, Presented::AccountNotFound);
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
    assert_eq!(refused[0].outcome, Presented::AccountNotFound);
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
    assert!(s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap().is_some());
    let (_, mut rb) = device(&s.core, "bob", &bob, 0);
    reset(&s, &alice, 1, now());
    assert!(s.rel.offer(&fp(&alice), &fp(&bob), wall).unwrap().is_none());
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
    assert_eq!(refused[0].outcome, Presented::AccountNotFound);
}

#[test]
fn an_unlink_takes_the_presentation_only_it_held() {
    let (alice, bob) = (person(1), person(2));
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
    let (b, _) = device(&s.core, "bob", &bob, 1);
    let (_, held) = s.core.friendships_present(b, vec![], vec![f]).unwrap();
    assert!(ok_all(&held));

    s.core.friendships_unlinked(&fp(&alice));
    assert!(s
        .rel
        .presentation(&fp(&bob), &fp(&alice))
        .unwrap()
        .is_none());
}

#[test]
fn a_reset_whose_cleanup_fails_ends_the_friendship_when_judged_again() {
    for write in ["presentations", "drop_presentations"] {
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

/// The in-memory record cache, its epochs unreadable while `fail` is set.
#[derive(Default)]
struct Flaky {
    inner: MemoryRecordCache,
    fail: AtomicBool,
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
        if self.fail.load(Ordering::Relaxed) {
            return Err(StoreError("unreadable".into()));
        }
        self.inner.epochs(identity)
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
    s.fail.fail_next("drop_presentations");
    assert_eq!(
        s.core.friendships_present(a2, vec![], vec![f2.clone()]),
        Err(MessagingError::ServerError)
    );
    assert_eq!(s.fail.failed(), Some("drop_presentations"));
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
    let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
    let (_, _, _, mut rb, _) = made(&s, &alice, &bob);
    let id = friendship_of(&s, &alice, &bob).unwrap();
    s.core.friendships_unlinked(&fp(&alice));
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
    for method in ["presentation", "withdrawals", "end_friendship"] {
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
    for method in ["presentation", "end_friendship"] {
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
fn an_entry_whose_read_fails_is_not_told() {
    for nth in [1, 2] {
        let (alice, bob) = (person(1), person(2));
        let s = linked(&[("alice", &fp(&alice)), ("bob", &fp(&bob))]);
        let (_, mut ra, _, _, _) = made(&s, &alice, &bob);
        s.fail.fail_nth(nth);
        s.core.tell_entry(
            &Mailbox::identified("alice", fp(&alice)),
            &Mailbox::identified("bob", fp(&bob)),
        );
        assert_eq!(s.fail.failed(), Some("relationship"));
        assert_eq!(told(&mut ra), [], "read {nth} failing");
    }
}

#[test]
fn a_withdrawal_retried_after_a_failure_ends_a_friendship_made_while_the_clock_ran_ahead() {
    for method in ["presentation", "end_friendship"] {
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
    s.fail.fail_next("end_friendship");
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

    fn account_by_key(&self, fp: &[u8; 32]) -> Option<(Mailbox, crate::AccessBits)> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| m.fingerprint == Some(*fp))
            .cloned()
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
        s.fail.fail_nth_of("drop_presentations", 2);
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
            "one drop, presenting {on_presenting}"
        );
    }
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
    assert_eq!(judged[0].outcome, Presented::AccountNotFound);
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
    for whole in [false, true] {
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
                device: Fingerprint::of(&successor.devices[0].0.public()).0,
                edge: None,
                at,
                taken: at,
            })
            .unwrap();
        drain(&mut rb);

        s.core
            .rotate_identity(&fp(&alice), &fp(&successor))
            .unwrap();
        let rows = s
            .rel
            .relationship(
                &Mailbox::identified("bob", fp(&bob)),
                &Mailbox::identified("alice", fp(&successor)),
                std::time::SystemTime::now(),
            )
            .unwrap();
        assert_eq!(rows.and_then(|r| r.friendship), None, "whole {whole}");
        assert_eq!(
            told(&mut rb),
            [("alice".into(), RosterState::Removed, vec![], None)],
            "whole {whole}"
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
    let moved = || s.rel.offer(&fp(&successor), &fp(&bob), wall).unwrap();
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
