//! Portable friendships against the in-memory stores, with real device
//! keys: made on one server and presented on another, withdrawn, dropped
//! with a revoked device, followed through a rotation, and refused to any
//! act the device-act gate does not admit.

use std::sync::Arc;

use hl_identity::friendship::Pair;
use hl_identity::{
    Acceptance, DeviceCert, DeviceKey, Fingerprint, Friendship, IdentityKey, Offer, Rotation,
    Withdrawal,
};
use sha2::{Digest, Sha256};

use super::super::tests::{messaging_bits, policy, server_of, Directory, Server};
use super::super::*;
use crate::inbox::Mailbox;
use crate::roster::{drain, AttachInfo};
use crate::{Events, IdentityTag, InboxPolicy, Revocations};

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
        let pair = Withdrawal::parse(&w, u64::MAX).unwrap().withdrawal().pair;
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
