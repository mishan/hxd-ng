//! A person across a link: one user under its row, shown at its first
//! device and gone at its last, kicked and banned whole, and never named
//! by a device's own uid.

use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use super::{session, ALICE};
use crate::roster::{drain, AttachInfo, Core, Event, Events, IdentityTag, Transport, Uid};
use crate::server_link::{
    GhostBan, GhostInfo, GoneReason, LinkForm, LocalUser, PeerEvent, PeerRefusal, PeerRouter,
    RemoteRef, Requester,
};

fn linked() -> (Core, mpsc::Receiver<(u64, PeerEvent)>) {
    let core = Core::new()
        .with_moderation(
            Arc::new(crate::moderation::MemoryModeration::default()),
            crate::moderation::ModerationPolicy::default(),
        )
        .with_coalesce(true);
    let feed = core.peer_feed(64);
    (core, feed)
}

fn device(core: &Core, transport: Transport) -> (Uid, Events) {
    device_with(core, transport, |_| ())
}

fn device_with(
    core: &Core,
    transport: Transport,
    f: impl FnOnce(&mut AttachInfo),
) -> (Uid, Events) {
    let mut info = session("alice", Some(ALICE), Some(ALICE), transport);
    f(&mut info);
    let (uid, rx) = core.attach(info).unwrap();
    core.announce(uid);
    (uid, rx)
}

fn proved(device: u8, signs: bool) -> Transport {
    Transport {
        identity: Some(IdentityTag {
            fingerprint: ALICE,
            device: [device; 32],
            handle: None,
            quiet_until: None,
            signs,
            can_sign: true,
            device_expires: u64::MAX,
            sealed: None,
            device_cert: None,
        }),
        ..Transport::default()
    }
}

fn hub() -> Requester {
    Requester {
        id: [4; 8],
        tag: "hch".into(),
        name: "Hub".into(),
    }
}

/// What the links were told, as (kind, uid).
fn crossed(feed: &mut mpsc::Receiver<(u64, PeerEvent)>) -> Vec<(&'static str, Uid)> {
    let mut told = vec![];
    while let Ok((_, e)) = feed.try_recv() {
        told.push(match e {
            PeerEvent::Shown(u) => ("shown", u.uid),
            PeerEvent::Changed(u) => ("changed", u.uid),
            PeerEvent::Gone(uid, GoneReason::Disconnected) => ("gone", uid),
            PeerEvent::Gone(uid, GoneReason::Banned) => ("banned", uid),
            PeerEvent::Chat { from, .. } => ("chat", from),
        });
    }
    told
}

/// The users the links were last told of, by uid.
fn users(feed: &mut mpsc::Receiver<(u64, PeerEvent)>) -> Vec<LocalUser> {
    let mut users = vec![];
    while let Ok((_, e)) = feed.try_recv() {
        if let PeerEvent::Shown(u) | PeerEvent::Changed(u) = e {
            users.retain(|v: &LocalUser| v.uid != u.uid);
            users.push(u);
        }
    }
    users
}

fn kicked(rx: &mut Events) -> bool {
    drain(rx).contains(&Event::Kicked)
}

#[test]
fn a_person_is_shown_once_by_its_first_device_and_gone_with_its_last() {
    let (core, mut feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    let (a3, _rx3) = device(&core, Transport::default());
    assert_eq!(crossed(&mut feed), [("shown", a1)]);
    // The device whose uid is the row's leaves: nothing to tell.
    core.end_session(a1);
    core.end_session(a3);
    assert_eq!(crossed(&mut feed), []);
    core.end_session(a2);
    assert_eq!(crossed(&mut feed), [("gone", a1)]);
}

#[test]
fn a_person_changes_to_the_links_only_when_what_crosses_changes() {
    let (core, mut feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    crossed(&mut feed);
    assert!(core.update(a2, Some("Ally".into()), None));
    assert_eq!(crossed(&mut feed), [("changed", a1)], "one rename, one row");
    // Away on one device, while another is here, is no change.
    core.roster
        .lock()
        .unwrap()
        .set_status(a2, crate::roster::SessionStatus::Idle);
    assert_eq!(crossed(&mut feed), []);
    core.roster
        .lock()
        .unwrap()
        .set_status(a1, crate::roster::SessionStatus::Idle);
    assert_eq!(
        crossed(&mut feed),
        [("changed", a1)],
        "away on every device"
    );
}

#[test]
fn a_line_from_any_device_crosses_as_its_row() {
    let (core, mut feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    crossed(&mut feed);
    core.chat_public(a2, "from the phone".into(), 0, None)
        .unwrap();
    core.end_session(a1);
    core.chat_public(a2, "and again".into(), 0, None).unwrap();
    assert_eq!(crossed(&mut feed), [("chat", a1), ("chat", a1)]);
}

#[test]
fn a_snapshot_shows_a_person_once_under_its_row() {
    let (core, _feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    let shown =
        |core: &Core| -> Vec<Uid> { core.peer_snapshot().1.iter().map(|u| u.uid).collect() };
    assert_eq!(shown(&core), [a1]);
    core.end_session(a1);
    assert_eq!(shown(&core), [a1], "the row outlives its own device");
    core.end_session(a2);
    assert_eq!(shown(&core), Vec::<Uid>::new());
}

#[test]
fn a_person_is_known_to_a_link_by_its_row_and_never_by_a_devices_uid() {
    let (core, _feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    for row_own_left in [false, true] {
        if row_own_left {
            core.end_session(a1);
        }
        assert!(
            core.is_exported(a1),
            "row, its own device left: {row_own_left}"
        );
        assert_eq!(core.peer_identity(a1), Some(ALICE));
        assert!(core.info_text_for_peer(a1).is_ok());
        assert!(!core.is_exported(a2), "a device's own uid");
        assert_eq!(core.peer_identity(a2), None);
        assert_eq!(core.info_text_for_peer(a2), Err(PeerRefusal::UnknownUser));
        assert_eq!(core.peer_kick(a2, &hub()), Err(PeerRefusal::UnknownUser));
        let gus = ghost(&core);
        assert_eq!(
            core.ghost_msg(gus, a2, "hi".into(), None),
            Err(PeerRefusal::UnknownUser)
        );
        assert_eq!(
            core.ghost_device_cert(gus, a2),
            Err(PeerRefusal::UnknownUser)
        );
        assert_eq!(
            core.ghost_sealed(gus, a2, vec![1], None),
            Err(PeerRefusal::UnknownUser)
        );
        assert_eq!(
            core.peer_ban(a2, &hub(), None, ""),
            Err(PeerRefusal::UnknownUser)
        );
        assert!(!core.answers_device_cert(a2, b"cert"));
    }
}

#[test]
fn a_person_has_been_online_since_its_device_here_longest_came() {
    let (core, _feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    // The device that has been here longest need not be the row's own: a
    // session resumed keeps when it came.
    {
        let mut r = core.roster.lock().unwrap();
        let s = r.users.get_mut(&a2).unwrap();
        s.connected_at -= std::time::Duration::from_secs(3 * 3600);
    }
    let text = core.info_text_for_peer(a1).unwrap();
    assert!(text.contains("online: 3h"), "{text}");
}

#[test]
fn a_network_kick_hides_every_device_and_any_that_comes_later() {
    let (core, mut feed) = linked();
    let (a1, mut rx1) = device(&core, Transport::default());
    let (_a2, mut rx2) = device(&core, Transport::default());
    users(&mut feed);
    assert_eq!(core.peer_kick(a1, &hub()), Ok(()));
    for rx in [&mut rx1, &mut rx2] {
        assert!(drain(rx)
            .iter()
            .any(|e| matches!(e, Event::Broadcast { text, .. } if text.contains("Hub (hch)"))));
    }
    let told = users(&mut feed);
    assert_eq!(told.len(), 1);
    assert_eq!((told[0].uid, told[0].exclude.clone()), (a1, vec![[4; 8]]));
    // A device that comes later, and the row's own leaving, keep it hidden.
    let (_a3, _rx3) = device(&core, Transport::default());
    core.end_session(a1);
    let snapshot = core.peer_snapshot().1;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].exclude, vec![[4; 8]]);
    // Kicked again by row, its own device gone, it changes nothing.
    assert_eq!(core.peer_kick(a1, &hub()), Ok(()));
    assert!(users(&mut feed).iter().all(|u| u.exclude == vec![[4; 8]]));
}

#[test]
fn a_network_ban_ends_every_device_and_its_leaving_crosses_as_a_ban() {
    for row_own_left in [false, true] {
        let (core, mut feed) = linked();
        let (a1, rx1) = device(&core, Transport::default());
        let (a2, mut rx2) = device(&core, Transport::default());
        let (a3, mut rx3) = device(&core, Transport::default());
        if row_own_left {
            core.end_session(a1);
        }
        drop(rx1);
        crossed(&mut feed);
        core.peer_ban(a1, &hub(), None, "spam").unwrap();
        for (uid, rx) in [(a2, &mut rx2), (a3, &mut rx3)] {
            assert!(
                kicked(rx),
                "{uid}, the row's own device left: {row_own_left}"
            );
            core.end_session(uid);
        }
        if !row_own_left {
            core.end_session(a1);
        }
        assert_eq!(
            crossed(&mut feed),
            [("banned", a1)],
            "the row's own device left: {row_own_left}"
        );
        assert!(!core.list_bans(true, None, 10).unwrap().is_empty());
    }
}

#[test]
fn a_person_is_shown_with_the_identity_its_first_device_proved_and_never_another() {
    // (first device, second device) -> (fingerprint, signs)
    let cases = [
        (proved(1, true), proved(2, true), Some(ALICE), true),
        (proved(1, true), proved(2, false), Some(ALICE), false),
        (proved(1, true), Transport::default(), Some(ALICE), false),
        // A password session of the linked account first: never said.
        (Transport::default(), proved(2, true), None, false),
    ];
    for (i, (first, second, fingerprint, signs)) in cases.into_iter().enumerate() {
        let (core, mut feed) = linked();
        device(&core, first);
        device(&core, second);
        let told = users(&mut feed);
        assert_eq!(told.len(), 1, "case {i}");
        assert_eq!(
            (told[0].fingerprint, told[0].signs, told[0].sealed),
            (fingerprint, signs, false),
            "case {i}"
        );
    }
}

#[test]
fn a_person_shown_with_no_identity_never_gains_one() {
    let (core, mut feed) = linked();
    // A password session of the linked account first, then a key.
    let (a1, _rx1) = device(&core, Transport::default());
    let (_a2, _rx2) = device(&core, proved(2, true));
    // The key's device is the front now, and still the person is said
    // to have no identity: a link was never told one.
    core.end_session(a1);
    let told = users(&mut feed);
    assert!(told.iter().all(|u| u.fingerprint.is_none()), "{told:?}");
    let snapshot = core.peer_snapshot().1;
    assert_eq!(snapshot[0].fingerprint, None);
}

fn ghost(core: &Core) -> Uid {
    core.ghost_attach(GhostInfo {
        nick: "gus".into(),
        icon: 7,
        away: false,
        color: 0,
        remote: RemoteRef {
            home_tag: "hl2".into(),
            home_name: "Elsewhere".into(),
            tagged: false,
            refuses_msgs: false,
            transport: None,
            fingerprint: Some([9; 32]),
            signs: false,
            server_key: None,
        },
        visible: true,
    })
    .unwrap()
}

#[test]
fn a_ghosts_message_to_a_person_reaches_every_device() {
    let (core, _feed) = linked();
    let (a1, mut rx1) = device(&core, Transport::default());
    let (a2, mut rx2) = device(&core, Transport::default());
    let gus = ghost(&core);
    assert_eq!(core.ghost_msg(gus, a1, "hi".into(), None), Ok(()));
    for rx in [&mut rx1, &mut rx2] {
        assert!(drain(rx)
            .iter()
            .any(|e| matches!(e, Event::Msg { from, .. } if *from == gus)));
    }
    assert_eq!(
        core.ghost_msg(gus, a2, "hi".into(), None),
        Err(PeerRefusal::UnknownUser),
        "a device's own uid"
    );
    // A block on one device is the person's.
    assert!(matches!(core.block_ghost(a2, gus, true), Some(Ok(()))));
    assert_eq!(
        core.ghost_msg(gus, a1, "hi".into(), None),
        Err(PeerRefusal::RefusesMessages)
    );
}

/// A router that keeps who each message is from.
#[derive(Default)]
struct Router(Mutex<Vec<Uid>>);

impl PeerRouter for Router {
    fn msg(
        &self,
        from: Uid,
        _: Uid,
        _: String,
        _: Option<LinkForm>,
    ) -> oneshot::Receiver<Result<(), PeerRefusal>> {
        self.0.lock().unwrap().push(from);
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(()));
        rx
    }
    fn msg_sealed(
        &self,
        from: Uid,
        _: Uid,
        _: Vec<u8>,
        _: [u8; 32],
    ) -> oneshot::Receiver<Result<(), PeerRefusal>> {
        self.0.lock().unwrap().push(from);
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(()));
        rx
    }
    fn device_cert(&self, asker: Uid, _: Uid) -> oneshot::Receiver<Result<Vec<u8>, PeerRefusal>> {
        self.0.lock().unwrap().push(asker);
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(vec![]));
        rx
    }
    fn knows_server_key(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn user_info(&self, _: Uid) -> oneshot::Receiver<Result<String, PeerRefusal>> {
        unreachable!()
    }
    fn kick(
        &self,
        _: Uid,
        _: Option<GhostBan>,
        _: String,
    ) -> oneshot::Receiver<Result<(), PeerRefusal>> {
        unreachable!()
    }
}

#[test]
fn a_message_from_any_device_crosses_as_its_row() {
    let (core, _feed) = linked();
    let router = Arc::new(Router::default());
    core.set_peer_router(router.clone());
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    let gus = ghost(&core);
    assert!(core.peer_msg(a2, gus, "hello", false, None).is_some());
    assert_eq!(*router.0.lock().unwrap(), [a1]);
}

#[test]
fn with_coalescing_off_each_device_is_a_user_of_its_own_to_the_links() {
    let core = Core::new();
    let mut feed = core.peer_feed(16);
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    core.chat_public(a2, "mine".into(), 0, None).unwrap();
    core.end_session(a1);
    assert_eq!(
        crossed(&mut feed),
        [("shown", a1), ("shown", a2), ("chat", a2), ("gone", a1)]
    );
    assert!(core.is_exported(a2));
}

fn holding(device: u8, cert: &[u8]) -> Transport {
    let mut t = proved(device, true);
    if let Some(id) = t.identity.as_mut() {
        id.device_cert = Some(Arc::new(cert.to_vec()));
    }
    t
}

#[test]
fn a_servers_own_request_is_answered_only_with_a_certificate_a_device_here_proves() {
    let (core, _feed) = linked();
    let (a1, _rx1) = device(&core, holding(1, b"phone"));
    let (a2, _rx2) = device(&core, holding(2, b"laptop"));
    assert!(core.answers_device_cert(a1, b"phone"));
    assert!(
        core.answers_device_cert(a1, b"laptop"),
        "the person's other device"
    );
    assert!(!core.answers_device_cert(a1, b"someone else's"));
    // A device gone takes its certificate with it, even the row's own.
    core.end_session(a1);
    assert!(!core.answers_device_cert(a1, b"phone"));
    assert!(core.answers_device_cert(a1, b"laptop"));
    core.end_session(a2);
    assert!(!core.answers_device_cert(a1, b"laptop"));
}

#[test]
fn a_person_shown_with_no_identity_says_none_by_its_keyed_devices() {
    let (core, mut feed) = linked();
    let router = Arc::new(Router::default());
    core.set_peer_router(router.clone());
    // A password session of the linked account first, then a key.
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, holding(2, b"laptop"));
    crossed(&mut feed);
    assert!(!core.answers_device_cert(a1, b"laptop"), "its certificate");
    // Its signed line stays here, as one never crosses without its
    // signature.
    let form = LinkForm {
        form: Arc::from(&b"form"[..]),
        cert: Arc::from(&b"laptop"[..]),
    };
    core.roster
        .lock()
        .unwrap()
        .export_chat(a2, "signed", 0, Some(form.clone()));
    core.roster
        .lock()
        .unwrap()
        .export_chat(a2, "plain", 0, None);
    assert_eq!(crossed(&mut feed), [("chat", a1)], "the plain line alone");
    // Nor does a signed message.
    let gus = ghost(&core);
    let sent = core.peer_msg(a2, gus, "hi", false, Some(form)).unwrap();
    assert_eq!(
        sent.blocking_recv().unwrap(),
        Err(PeerRefusal::SenderUnkeyed)
    );
    assert!(router.0.lock().unwrap().is_empty());
}

#[test]
fn an_unplaced_network_ban_of_a_person_crosses_as_a_leaving() {
    // A store that will not write the act.
    let store = Arc::new(crate::moderation::faulty::FaultyModeration::default());
    store.fail("record");
    let core = Core::new()
        .with_moderation(store, crate::moderation::ModerationPolicy::default())
        .with_coalesce(true);
    let mut feed = core.peer_feed(16);
    let (a1, mut rx1) = device(&core, Transport::default());
    let (a2, mut rx2) = device(&core, Transport::default());
    crossed(&mut feed);
    assert_eq!(
        core.peer_ban(a1, &hub(), None, "spam"),
        Err(PeerRefusal::Unreachable)
    );
    for (uid, rx) in [(a1, &mut rx1), (a2, &mut rx2)] {
        assert!(kicked(rx), "{uid}: its kick begun, it ends");
        core.end_session(uid);
    }
    assert_eq!(crossed(&mut feed), [("gone", a1)]);
}

#[test]
fn a_person_being_kicked_is_told_to_the_links_once_as_it_goes() {
    let (core, mut feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    // The row's own device away: its going would change the row.
    core.roster
        .lock()
        .unwrap()
        .set_status(a1, crate::roster::SessionStatus::Idle);
    core.roster
        .lock()
        .unwrap()
        .set_status(a2, crate::roster::SessionStatus::Idle);
    core.roster
        .lock()
        .unwrap()
        .set_status(a1, crate::roster::SessionStatus::Active);
    crossed(&mut feed);
    core.kick_by(a1, None).unwrap();
    core.end_session(a1);
    core.end_session(a2);
    assert_eq!(crossed(&mut feed), [("gone", a1)]);
}

#[test]
fn a_block_on_any_device_refuses_a_ghosts_sealed_message_to_its_person() {
    let (core, _feed) = linked();
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, Transport::default());
    let gus = ghost(&core);
    assert!(matches!(core.block_ghost(a2, gus, true), Some(Ok(()))));
    assert_eq!(
        core.ghost_sealed(gus, a1, vec![1], None),
        Err(PeerRefusal::RefusesMessages)
    );
}

/// A device of alice's that can open sealed messages until `expires`.
fn sealing_until(device: u8, expires: u64) -> Transport {
    let mut t = proved(device, false);
    if let Some(id) = t.identity.as_mut() {
        id.device_expires = expires;
        id.sealed = Some(
            crate::SealedDevice {
                cert: vec![device],
                enc: [device; 32],
                expires,
            }
            .into(),
        );
    }
    t
}

fn sealing(device: u8) -> Transport {
    sealing_until(device, u64::MAX)
}

/// The SHA-256 of the `device_enc` key `sealing` gives device `byte`.
fn key(byte: u8) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest([byte; 32]).into()
}

/// Whether the links were last told `row` can open sealed messages.
fn shown_sealed(feed: &mut mpsc::Receiver<(u64, PeerEvent)>, row: Uid) -> Option<bool> {
    users(feed)
        .into_iter()
        .find(|u| u.uid == row)
        .map(|u| u.sealed)
}

fn sealed_from(rx: &mut Events, ghost: Uid) -> bool {
    drain(rx)
        .iter()
        .any(|e| matches!(e, Event::Sealed { from, .. } if *from == ghost))
}

/// Which of the four go across a link, each tried: `from` sealing to
/// the ghost and asking its certificate, and the ghost sealing to
/// `row` by `device`'s key and asking `row`'s certificate.
fn four_ways(core: &Core, gus: Uid, from: Uid, row: Uid, device: u8) -> [bool; 4] {
    [
        matches!(core.peer_sealed(from, gus, vec![1], key(1)), Some(Ok(_))),
        matches!(core.peer_device_cert(from, gus), Some(Ok(_))),
        core.ghost_sealed(gus, row, vec![1], Some(key(device)))
            .is_ok(),
        core.ghost_device_cert(gus, row) == Ok(vec![device]),
    ]
}

#[test]
fn a_person_of_one_sealable_device_seals_across_a_link_both_ways_and_of_two_does_not() {
    let (core, mut feed) = linked();
    let router = Arc::new(Router::default());
    core.set_peer_router(router.clone());
    let gus = ghost(&core);
    let (a1, mut rx1) = device(&core, sealing(1));
    assert_eq!(shown_sealed(&mut feed, a1), Some(true), "one device");
    drain(&mut rx1);
    assert_eq!(four_ways(&core, gus, a1, a1, 1), [true; 4], "one device");
    assert!(sealed_from(&mut rx1, gus), "delivered to it");

    // A second device mid-conversation: neither way, and the links told.
    let (a2, mut rx2) = device(&core, sealing(2));
    assert_eq!(shown_sealed(&mut feed, a1), Some(false), "two: told");
    for from in [a1, a2] {
        assert_eq!(
            four_ways(&core, gus, from, a1, 1),
            [false; 4],
            "two, from {from}"
        );
    }

    // The first goes: the one left is sealed with, under the row.
    core.end_session(a1);
    assert_eq!(shown_sealed(&mut feed, a1), Some(true), "one again: told");
    drain(&mut rx2);
    assert_eq!(four_ways(&core, gus, a2, a1, 2), [true; 4], "one again");
    assert!(sealed_from(&mut rx2, gus), "delivered to the one left");

    // A session alone, its account linking no identity, as ever.
    let (bob, _rb) = core
        .attach(session("bob", Some(ALICE), None, sealing(3)))
        .unwrap();
    core.announce(bob);
    assert!(matches!(
        core.peer_sealed(bob, gus, vec![1], key(1)),
        Some(Ok(_))
    ));
    assert_eq!(
        *router.0.lock().unwrap(),
        [a1, a1, a1, a1, bob],
        "each allowed, under the row"
    );
}

#[test]
fn a_persons_one_sealable_device_is_the_one_sealed_with_not_its_front() {
    let (core, mut feed) = linked();
    core.set_peer_router(Arc::new(Router::default()));
    let gus = ghost(&core);
    let (a1, mut rx1) = device(&core, proved(1, false));
    let (a2, mut rx2) = device(&core, sealing(2));
    assert_eq!(shown_sealed(&mut feed, a1), Some(true));
    drain(&mut rx1);
    drain(&mut rx2);
    assert_eq!(core.ghost_device_cert(gus, a1), Ok(vec![2]));
    assert_eq!(core.ghost_sealed(gus, a1, vec![1], Some(key(2))), Ok(()));
    assert!(sealed_from(&mut rx2, gus), "to the device it was sealed to");
    assert!(!sealed_from(&mut rx1, gus), "not to the row's front");
    assert!(matches!(
        core.peer_sealed(a1, gus, vec![1], key(1)),
        Some(Err(crate::SealedError::SelfNotSealed))
    ));
    assert!(matches!(core.peer_device_cert(a1, gus), Some(Err(_))));
    assert!(matches!(
        core.peer_sealed(a2, gus, vec![1], key(1)),
        Some(Ok(_))
    ));
    assert!(matches!(core.peer_device_cert(a2, gus), Some(Ok(_))));
}

#[test]
fn a_person_sealed_with_across_a_link_is_told_so_as_its_devices_change() {
    // How its sole sealable device stops being one, its socket open.
    type End = fn(&Core, Uid);
    let ends: [(&str, End); 3] = [
        ("expired", |core, _| {
            core.clock().advance(std::time::Duration::from_secs(120));
            core.expire_device_keys();
        }),
        ("kicked", |core, a2| {
            let device = core.roster.lock().unwrap().users[&a2].device;
            core.kick_device(core.row_uid(a2), device).unwrap();
        }),
        ("revoked", |core, _| {
            core.set_revocations(crate::Revocations {
                devices: [[2; 32]].into(),
                ..Default::default()
            });
        }),
    ];
    for (case, end) in ends {
        let (core, mut feed) = linked();
        let (a1, _rx1) = device(&core, proved(1, false));
        let expires = core.clock().unix() + 60;
        let (a2, _rx2) = device(&core, sealing_until(2, expires));
        assert_eq!(shown_sealed(&mut feed, a1), Some(true), "{case}");
        end(&core, a2);
        assert_eq!(
            shown_sealed(&mut feed, a1),
            Some(false),
            "{case}: told at once, its socket still open"
        );
    }
}

#[test]
fn a_person_shown_with_no_identity_is_sealed_with_across_no_link() {
    let (core, mut feed) = linked();
    core.set_peer_router(Arc::new(Router::default()));
    let gus = ghost(&core);
    // Its first device logged in with the password.
    let (a1, _rx1) = device(&core, Transport::default());
    let (a2, _rx2) = device(&core, sealing(2));
    assert_eq!(shown_sealed(&mut feed, a1), Some(false));
    assert_eq!(four_ways(&core, gus, a2, a1, 2), [false; 4]);
}

#[test]
fn a_person_with_more_sealable_devices_than_its_account_may_connect_is_sealed_with_across_no_link()
{
    let (core, mut feed) = linked();
    let core = core.with_conn_limits(crate::ConnLimits {
        per_account: 1,
        ..crate::ConnLimits::default()
    });
    core.set_peer_router(Arc::new(Router::default()));
    let gus = ghost(&core);
    let (a1, _rx1) = device(&core, sealing(1));
    let (a2, _rx2) = device(&core, sealing(2));
    // Detached, it holds no connection, so the account is within its cap,
    // and only its newest device is sealed to here.
    assert!(core.connection_lost(a1, usize::MAX));
    assert_eq!(shown_sealed(&mut feed, a1), Some(false));
    assert_eq!(four_ways(&core, gus, a2, a1, 2), [false; 4]);
}

#[test]
fn a_box_from_a_ghost_its_device_cannot_hold_is_refused() {
    let (core, _feed) = linked();
    let gus = ghost(&core);
    let (a1, _rx1) = device(&core, sealing(1));
    assert!(core.connection_lost(a1, usize::MAX));
    {
        let mut r = core.roster.lock().unwrap();
        for _ in 0..=crate::roster::OUTBOX_BUFFER_CAP {
            r.send_to(a1, Event::RosterStale);
        }
    }
    assert_eq!(
        core.ghost_sealed(gus, a1, vec![1], Some(key(1))),
        Err(PeerRefusal::RateLimited)
    );
}
