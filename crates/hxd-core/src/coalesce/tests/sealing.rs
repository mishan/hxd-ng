//! Sealing to a person: a box for each device it can be sealed to, the
//! devices fetched on demand, one rule saying which those are, and a
//! client that knows nothing of devices sealing to a person with only
//! one.

use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{session, ALICE};
use crate::relationships::RelationshipStore;
use crate::roster::{drain, Core, Event, Events, IdentityTag, Transport, Uid};
use crate::{BoxesError, DeviceCerts, SealedBox, SealedDevice, SealedError, SealedHolds};

const BOB: [u8; 32] = [8; 32];

/// The ng wire, a device of `fingerprint` that said `sealed` with a
/// certificate expiring at `expires`, or did not say it.
fn sealing(fingerprint: [u8; 32], device: u8, persons: bool, expires: Option<u64>) -> Transport {
    Transport {
        ng: true,
        roles: true,
        persons,
        identity: Some(IdentityTag {
            fingerprint,
            device: [device; 32],
            handle: None,
            quiet_until: None,
            signs: false,
            can_sign: false,
            device_expires: u64::MAX,
            device_epoch: 0,
            sealed: expires.map(|expires| {
                SealedDevice {
                    cert: vec![device],
                    enc: [device; 32],
                    expires,
                }
                .into()
            }),
            device_cert: None,
        }),
        ..Transport::default()
    }
}

/// A session attached, announced and sent its user list, as an ng login
/// is.
fn on(core: &Core, login: &str, fingerprint: [u8; 32], t: Transport) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(session(login, Some(fingerprint), Some(fingerprint), t))
        .unwrap();
    core.announce(uid);
    core.roster_for(uid);
    (uid, rx)
}

/// One of alice's devices, sealed to until `expires` if at all.
fn alice(core: &Core, device: u8, persons: bool, expires: Option<u64>) -> (Uid, Events) {
    on(
        core,
        "alice",
        ALICE,
        sealing(ALICE, device, persons, expires),
    )
}

/// Bob, who can open sealed messages: a session alone, his account
/// linking no identity, so never a person.
fn bob(core: &Core, persons: bool) -> (Uid, Events) {
    let t = sealing(BOB, 50, persons, Some(u64::MAX));
    let (uid, rx) = core.attach(session("bob", Some(BOB), None, t)).unwrap();
    core.announce(uid);
    core.roster_for(uid);
    (uid, rx)
}

fn persons() -> Core {
    Core::new().with_coalesce(true)
}

fn device_of(core: &Core, uid: Uid) -> u64 {
    core.roster.lock().unwrap().users[&uid].device
}

/// The SHA-256 of the `device_enc` key `sealing` gives device `byte`.
fn key_of(byte: u8) -> [u8; 32] {
    Sha256::digest([byte; 32]).into()
}

/// A box for `uid`, device `byte` of `sealing`.
fn box_for(core: &Core, uid: Uid, byte: u8) -> SealedBox {
    SealedBox {
        device: device_of(core, uid),
        sealed: vec![byte; 5],
        sealed_to: key_of(byte),
    }
}

/// What `uid` was sealed to as (the box's sealer, its device, the box).
fn sealed_in(rx: &mut Events) -> Vec<(Uid, Option<u64>, Vec<u8>)> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::Sealed {
                from,
                from_device,
                sealed: Some(sealed),
                ..
            } => Some((from, from_device, sealed)),
            _ => None,
        })
        .collect()
}

/// The devices a list names, as (device, cert).
fn listed(core: &Core, uids: &[(Uid, u8)]) -> Vec<(u64, Vec<u8>)> {
    uids.iter()
        .map(|(uid, byte)| (device_of(core, *uid), vec![*byte]))
        .collect()
}

#[test]
fn one_rule_says_which_devices_a_person_is_sealed_to_in_its_entry_its_list_and_its_delivery() {
    for (case, expires_in, sealable) in [
        ("sealed", Some(u64::MAX), true),
        ("its certificate expired", Some(60), false),
        ("never said sealed", None, false),
        ("kicked", Some(u64::MAX), false),
        ("revoked", Some(u64::MAX), false),
    ] {
        let core = persons();
        let (bob, _rb) = bob(&core, true);
        let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
        let expires = expires_in.map(|s: u64| core.clock().unix().saturating_add(s));
        let (a2, mut r2) = alice(&core, 2, true, expires);
        core.clock().advance(Duration::from_secs(120));
        let d2 = device_of(&core, a2);
        match case {
            // Between its kick and its end.
            "kicked" => {
                core.roster
                    .lock()
                    .unwrap()
                    .users
                    .get_mut(&a2)
                    .unwrap()
                    .kicked = true
            }
            // Between the revocation landing and the kick it brings.
            "revoked" => {
                core.revoked.write().unwrap().local.devices.insert([2; 32]);
            }
            _ => {}
        }

        let entry = core.roster.lock().unwrap().devices_of(a1);
        let shown = entry.iter().find(|d| d.device == d2).unwrap().sealed;
        assert_eq!(shown, sealable, "{case}: the entry");

        let mut want = vec![(a1, 1)];
        if sealable {
            want.push((a2, 2));
        }
        assert_eq!(
            core.device_cert(bob, a1, None),
            Ok(DeviceCerts::Devices(listed(&core, &want))),
            "{case}: the list"
        );

        drain(&mut r1);
        let both = vec![box_for(&core, a1, 1), box_for(&core, a2, 2)];
        let sent = core.msg_boxes(bob, a1, both);
        if sealable {
            assert_eq!(sent, Ok(vec![]), "{case}");
            assert_eq!(sealed_in(&mut r2).len(), 1, "{case}: delivered");
        } else {
            assert_eq!(
                sent,
                Err(BoxesError::DevicesChanged(listed(&core, &want))),
                "{case}: the delivery"
            );
            assert_eq!(sealed_in(&mut r1), vec![], "{case}: nothing delivered");
        }
    }
}

#[test]
fn boxes_that_are_not_one_for_each_device_are_refused_with_the_devices_as_they_are() {
    for case in [
        "a box missing",
        "a box for no device",
        "a box for a device not sealed",
    ] {
        let core = persons();
        let (bob, _rb) = bob(&core, true);
        let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
        let (a2, mut r2) = alice(&core, 2, true, Some(u64::MAX));
        let (a3, _r3) = alice(&core, 3, true, None);
        let mut boxes = vec![box_for(&core, a1, 1)];
        match case {
            "a box missing" => {}
            "a box for no device" => {
                boxes.push(box_for(&core, a2, 2));
                boxes.push(SealedBox {
                    device: 99,
                    ..box_for(&core, a2, 2)
                });
            }
            _ => {
                boxes.push(box_for(&core, a2, 2));
                boxes.push(box_for(&core, a3, 3));
            }
        }
        drain(&mut r1);
        drain(&mut r2);
        assert_eq!(
            core.msg_boxes(bob, a1, boxes),
            Err(BoxesError::DevicesChanged(listed(
                &core,
                &[(a1, 1), (a2, 2)]
            ))),
            "{case}"
        );
        assert!(
            sealed_in(&mut r1).is_empty() && sealed_in(&mut r2).is_empty(),
            "{case}: no device sealed to"
        );
    }
}

#[test]
fn a_box_sealed_to_a_key_its_device_no_longer_has_is_named_and_nothing_is_delivered() {
    let core = persons();
    let (bob, _rb) = bob(&core, true);
    let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    let stale = SealedBox {
        sealed_to: key_of(9),
        ..box_for(&core, a2, 2)
    };
    drain(&mut r1);
    assert_eq!(
        core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1), stale]),
        Err(BoxesError::CertChanged(device_of(&core, a2)))
    );
    assert!(sealed_in(&mut r1).is_empty());
}

#[test]
fn a_device_holding_all_it_may_is_skipped_and_the_rest_delivered() {
    for (case, both_away) in [("one away", false), ("both away", true)] {
        let core = persons().with_sealed_holds(SealedHolds {
            per_sender: 4,
            all: 4,
        });
        let (bob, _rb) = bob(&core, true);
        let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
        let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
        assert!(core.connection_lost(a2, usize::MAX));
        if both_away {
            assert!(core.connection_lost(a1, usize::MAX));
        }
        drain(&mut r1);
        let sent = core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1), box_for(&core, a2, 2)]);
        if both_away {
            assert_eq!(
                sent,
                Err(BoxesError::Sealed(SealedError::HeldFull)),
                "{case}"
            );
        } else {
            assert_eq!(sent, Ok(vec![device_of(&core, a2)]), "{case}");
            assert_eq!(sealed_in(&mut r1).len(), 1, "{case}: the rest delivered");
            let held = core.roster.lock().unwrap().users[&a2]
                .outbox
                .sealed_held(&BOB);
            assert_eq!(
                held,
                Some((0, 0)),
                "{case}: the skipped device holds nothing"
            );
        }
    }
}

#[test]
fn a_device_whose_held_events_overflowed_is_skipped_as_one_holding_all_it_may() {
    for (case, both) in [("one", false), ("both", true)] {
        let core = persons();
        let (bob, _rb) = bob(&core, true);
        let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
        let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
        let broken: &[Uid] = if both { &[a1, a2] } else { &[a2] };
        for uid in broken {
            assert!(core.connection_lost(*uid, usize::MAX));
            let mut r = core.roster.lock().unwrap();
            for _ in 0..=crate::roster::OUTBOX_BUFFER_CAP {
                r.send_to(*uid, Event::RosterStale);
            }
        }
        drain(&mut r1);
        let sent = core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1), box_for(&core, a2, 2)]);
        if both {
            assert_eq!(
                sent,
                Err(BoxesError::Sealed(SealedError::HeldFull)),
                "{case}"
            );
        } else {
            assert_eq!(sent, Ok(vec![device_of(&core, a2)]), "{case}");
            assert_eq!(sealed_in(&mut r1).len(), 1, "{case}: the rest delivered");
        }
    }
}

#[test]
fn a_sealed_message_to_a_session_whose_held_events_overflowed_is_refused() {
    for (case, coalesce) in [("coalescing off", false), ("coalescing on", true)] {
        let core = Core::new().with_coalesce(coalesce);
        let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
        let (bob, _rb) = bob(&core, false);
        assert!(core.connection_lost(bob, usize::MAX));
        let mut r = core.roster.lock().unwrap();
        for _ in 0..=crate::roster::OUTBOX_BUFFER_CAP {
            r.send_to(bob, Event::RosterStale);
        }
        drop(r);
        assert_eq!(
            core.msg_sealed(a1, bob, vec![7; 5], key_of(50)),
            Err(SealedError::HeldFull),
            "{case}"
        );
    }
}

/// A server whose accounts may each hold `per_account` connections.
fn holding(per_account: usize) -> Core {
    persons().with_conn_limits(crate::ConnLimits {
        per_account,
        ..crate::ConnLimits::default()
    })
}

#[test]
fn a_person_with_more_devices_than_a_message_reaches_is_sealed_to_its_newest() {
    let core = holding(2);
    let (bob, _rb) = bob(&core, true);
    let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, mut r2) = alice(&core, 2, true, Some(u64::MAX));
    let (a3, mut r3) = alice(&core, 3, true, Some(u64::MAX));
    let newest = listed(&core, &[(a2, 2), (a3, 3)]);
    assert_eq!(
        core.device_cert(bob, a1, None),
        Ok(DeviceCerts::Devices(newest.clone()))
    );
    let entry = core.roster.lock().unwrap().devices_of(a1);
    let shown: Vec<bool> = entry.iter().map(|d| d.sealed).collect();
    assert_eq!(shown, [false, true, true], "the entry");
    drain(&mut r1);
    assert_eq!(
        core.msg_boxes(
            bob,
            a1,
            vec![
                box_for(&core, a1, 1),
                box_for(&core, a2, 2),
                box_for(&core, a3, 3)
            ]
        ),
        Err(BoxesError::DevicesChanged(newest)),
        "the oldest is no device to seal to"
    );
    assert_eq!(
        core.msg_boxes(bob, a1, vec![box_for(&core, a2, 2), box_for(&core, a3, 3)]),
        Ok(vec![])
    );
    assert!(sealed_in(&mut r1).is_empty(), "the oldest hears nothing");
    assert_eq!(sealed_in(&mut r2).len() + sealed_in(&mut r3).len(), 2);
}

#[test]
fn a_person_with_one_device_within_the_limit_is_sealed_to_by_any_client() {
    let core = holding(1);
    let (bob, _rb) = bob(&core, false);
    let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
    let (_a2, mut r2) = alice(&core, 2, true, Some(u64::MAX));
    let shown = core
        .snapshot()
        .into_iter()
        .find(|u| u.uid == a1)
        .and_then(|u| u.transport.identity)
        .and_then(|i| i.sealed)
        .map(|d| d.cert.clone());
    assert_eq!(shown, Some(vec![2]), "the row shows the newest");
    assert_eq!(
        core.device_cert(bob, a1, None),
        Ok(DeviceCerts::One(vec![2]))
    );
    drain(&mut r1);
    drain(&mut r2);
    assert_eq!(core.msg_sealed(bob, a1, vec![7; 5], key_of(2)), Ok(()));
    assert_eq!(sealed_in(&mut r2), vec![(bob, None, vec![7; 5])]);
    assert!(sealed_in(&mut r1).is_empty());
}

#[test]
fn a_message_reaches_as_many_devices_as_an_account_may_connect_up_to_one_requests_worth() {
    for (per_account, most) in [
        (2, 2),
        (0, crate::MAX_BOXES),
        (crate::MAX_BOXES + 5, crate::MAX_BOXES),
    ] {
        assert_eq!(holding(per_account).max_boxes(), most, "{per_account}");
    }
}

#[test]
fn a_core_built_by_default_seals_to_a_session_alone() {
    let core = Core::default();
    let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
    let (bob, _rb) = bob(&core, false);
    assert_eq!(
        core.device_cert(a1, bob, None),
        Ok(DeviceCerts::One(vec![50]))
    );
}

#[test]
fn a_device_not_cleared_for_takes_none_of_the_newest_places() {
    let core = holding(2);
    let (bob, _rb) = bob(&core, true);
    let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    // Logged in after the sender's blocks were checked, so not in the
    // row the hold delivers to.
    let (_a3, _r3) = alice(&core, 3, true, Some(u64::MAX));
    let r = core.roster.lock().unwrap();
    let set: Vec<Uid> = core
        .sealing_set(&r, a1, &[a1, a2], bob)
        .iter()
        .map(|d| d.uid)
        .collect();
    assert_eq!(set, [a1, a2]);
}

#[test]
fn a_device_sealing_to_its_own_person_past_the_limit_seals_to_the_rest_of_the_newest() {
    let core = holding(2);
    let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    let (a3, _r3) = alice(&core, 3, true, Some(u64::MAX));
    // The newest are shown sealed to everyone, the sender among them;
    // what it seals to is those, less itself.
    assert_eq!(
        core.msg_boxes(a3, a1, vec![box_for(&core, a1, 1), box_for(&core, a2, 2)]),
        Err(BoxesError::DevicesChanged(listed(&core, &[(a2, 2)])))
    );
}

#[test]
fn a_device_seals_to_its_own_person_as_its_row_and_by_its_device() {
    for (case, reader_persons) in [("persons", true), ("not persons", false)] {
        let core = persons();
        let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
        let (a2, mut r2) = alice(&core, 2, reader_persons, Some(u64::MAX));
        // Its own device is no device it seals to.
        assert_eq!(
            core.msg_boxes(a1, a1, vec![box_for(&core, a1, 1), box_for(&core, a2, 2)]),
            Err(BoxesError::DevicesChanged(listed(&core, &[(a2, 2)]))),
            "{case}"
        );
        drain(&mut r2);
        assert_eq!(
            core.msg_boxes(a2, a1, vec![box_for(&core, a1, 1)]),
            Ok(vec![]),
            "{case}: from the other way"
        );
        assert_eq!(
            core.msg_boxes(a1, a1, vec![box_for(&core, a2, 2)]),
            Ok(vec![])
        );
        let from_device = reader_persons.then(|| device_of(&core, a1));
        assert_eq!(
            sealed_in(&mut r2),
            vec![(a1, from_device, vec![2; 5])],
            "{case}: from the row, and by its device to a reader of devices"
        );
    }
}

#[test]
fn a_device_that_is_not_its_rows_seals_as_the_row() {
    let core = persons();
    let (bob, mut rb) = bob(&core, true);
    let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    drain(&mut r1);
    drain(&mut rb);
    let d2 = Some(device_of(&core, a2));
    assert_eq!(
        core.msg_boxes(a2, bob, vec![box_for(&core, bob, 50)]),
        Ok(vec![])
    );
    assert_eq!(
        sealed_in(&mut rb),
        vec![(a1, d2, vec![50; 5])],
        "to another"
    );
    assert_eq!(
        core.msg_boxes(a2, a1, vec![box_for(&core, a1, 1)]),
        Ok(vec![])
    );
    assert_eq!(sealed_in(&mut r1), vec![(a1, d2, vec![1; 5])], "to its own");
}

#[test]
fn a_session_alone_seals_to_itself() {
    for (case, coalesce) in [("coalescing off", false), ("coalescing on", true)] {
        let core = Core::new().with_coalesce(coalesce);
        let (bob, mut rb) = bob(&core, false);
        assert_eq!(
            core.device_cert(bob, bob, None),
            Ok(DeviceCerts::One(vec![50])),
            "{case}"
        );
        drain(&mut rb);
        assert_eq!(
            core.msg_sealed(bob, bob, vec![7; 5], key_of(50)),
            Ok(()),
            "{case}"
        );
        assert_eq!(sealed_in(&mut rb), vec![(bob, None, vec![7; 5])], "{case}");
    }
}

const CAROL: [u8; 32] = [6; 32];

/// One of carol's devices: her account is personal, so a password device
/// that proved no identity is one with her linked ones, under another
/// mailbox.
fn carol(core: &Core, linked: bool) -> (Uid, Events) {
    let fingerprint = linked.then_some(CAROL);
    let t = match linked {
        true => sealing(CAROL, 60, true, Some(u64::MAX)),
        false => Transport {
            ng: true,
            persons: true,
            ..Transport::default()
        },
    };
    let mut info = session("carol", fingerprint, fingerprint, t);
    let account = info.account.as_mut().unwrap();
    account.config.personal = true;
    account.has_password = true;
    info.is_person = account.is_person();
    let (uid, rx) = core.attach(info).unwrap();
    core.announce(uid);
    core.roster_for(uid);
    (uid, rx)
}

#[test]
fn a_block_from_any_of_a_persons_mailboxes_refuses_the_sealer() {
    for (case, linked_first, blocker) in [
        ("by the row's mailbox", true, Some(CAROL)),
        ("by its other device's", false, Some(CAROL)),
        ("by a password device's", true, None),
    ] {
        let store = std::sync::Arc::new(crate::MemoryRelationships::new());
        let core = persons().with_relationships(store.clone());
        let (bob, _rb) = bob(&core, true);
        let (c1, _r1) = carol(&core, linked_first);
        let (c2, mut r2) = carol(&core, !linked_first);
        let linked = if linked_first { c1 } else { c2 };
        assert_eq!(core.row_uid(c2), c1, "{case}: one person");
        let owner = crate::inbox::Mailbox {
            login: "carol".into(),
            fingerprint: blocker,
        };
        let sealer = crate::inbox::Mailbox {
            login: "bob".into(),
            fingerprint: Some(BOB),
        };
        store
            .set_blocked(&owner, &sealer, true, std::time::SystemTime::now())
            .unwrap();
        assert_eq!(
            core.device_cert(bob, c1, None),
            Err(SealedError::Blocked),
            "{case}: the list"
        );
        drain(&mut r2);
        assert_eq!(
            core.msg_boxes(bob, c1, vec![box_for(&core, linked, 60)]),
            Err(BoxesError::Sealed(SealedError::Blocked)),
            "{case}: the boxes"
        );
        assert!(sealed_in(&mut r2).is_empty(), "{case}: nothing delivered");
    }
}

#[test]
fn a_person_with_one_device_sealed_to_is_shown_so_to_the_ng_wire_and_sealed_to_by_any_client() {
    let core = persons();
    let (bob, _rb) = bob(&core, false);
    // Watchers on either wire, which know nothing of devices.
    let (_ng, mut seen_ng) = on(&core, "carol", [3; 32], sealing([3; 32], 30, false, None));
    let (_classic, mut seen_classic) = on(&core, "dave", [4; 32], Transport::default());
    let (a1, mut r1) = alice(&core, 1, true, Some(u64::MAX));
    let row_sealed = |core: &Core| {
        core.snapshot()
            .into_iter()
            .find(|u| u.uid == a1)
            .and_then(|u| u.transport.identity)
            .is_some_and(|i| i.sealed.is_some())
    };
    assert!(row_sealed(&core), "one device: the row says sealed");
    assert_eq!(
        core.device_cert(bob, a1, None),
        Ok(DeviceCerts::One(vec![1]))
    );
    drain(&mut r1);
    assert_eq!(core.msg_sealed(bob, a1, vec![7; 5], key_of(1)), Ok(()));
    assert_eq!(sealed_in(&mut r1), vec![(bob, None, vec![7; 5])]);

    let told = |rx: &mut Events| {
        drain(rx)
            .into_iter()
            .any(|e| matches!(e, Event::Changed(u) if u.uid == a1))
    };
    told(&mut seen_ng);
    told(&mut seen_classic);
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    assert!(!row_sealed(&core), "two: no longer");
    // A classic row cannot show it, so its viewers would be sent the
    // row they have, saying only that a device came.
    assert!(
        told(&mut seen_ng) && !told(&mut seen_classic),
        "told to the ng wire alone"
    );
    assert_eq!(core.device_cert(bob, a1, None), Err(SealedError::NotSealed));
    assert_eq!(
        core.msg_sealed(bob, a1, vec![7; 5], key_of(1)),
        Err(SealedError::NotSealed)
    );

    core.end_session(a2);
    assert!(row_sealed(&core), "one again");
    assert!(
        told(&mut seen_ng) && !told(&mut seen_classic),
        "told again, to the ng wire alone"
    );
}

#[test]
fn a_persons_devices_are_rationed_as_a_certificate_is() {
    for case in ["listed", "refused with the list", "refused with a key"] {
        let core = persons();
        let (bob, _rb) = bob(&core, true);
        let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
        let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
        let stale = SealedBox {
            sealed_to: key_of(9),
            ..box_for(&core, a2, 2)
        };
        // Two devices each time: a list costs one for each.
        let times = match case {
            "refused with a key" => crate::sealed::DEVICE_CERTS,
            _ => crate::sealed::DEVICE_CERTS / 2,
        };
        for _ in 0..times {
            match case {
                "listed" => assert!(core.device_cert(bob, a1, None).is_ok()),
                "refused with the list" => assert!(matches!(
                    core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1)]),
                    Err(BoxesError::DevicesChanged(_))
                )),
                _ => assert!(matches!(
                    core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1), stale.clone()]),
                    Err(BoxesError::CertChanged(_))
                )),
            }
        }
        assert!(
            matches!(
                core.device_cert(bob, a1, None),
                Err(SealedError::RateLimited(_))
            ),
            "{case}"
        );
    }
}

#[test]
fn a_person_with_no_device_to_seal_to_is_not_sealed_and_costs_no_ration() {
    let core = persons();
    let (bob, _rb) = bob(&core, true);
    let (a1, _r1) = alice(&core, 1, true, None);
    alice(&core, 2, true, None);
    for _ in 0..=crate::sealed::DEVICE_CERTS {
        assert_eq!(
            core.msg_boxes(bob, a1, vec![box_for(&core, a1, 1)]),
            Err(BoxesError::Sealed(SealedError::NotSealed))
        );
    }
}

#[test]
fn one_device_is_fetched_by_its_id_and_a_device_not_the_persons_is_none() {
    let core = persons();
    let (bob, _rb) = bob(&core, true);
    let (a1, _r1) = alice(&core, 1, true, Some(u64::MAX));
    let (a2, _r2) = alice(&core, 2, true, Some(u64::MAX));
    let (a3, _r3) = alice(&core, 3, true, None);
    let d = |uid| Some(device_of(&core, uid));
    assert_eq!(
        core.device_cert(bob, a1, d(a2)),
        Ok(DeviceCerts::One(vec![2]))
    );
    assert_eq!(
        core.device_cert(bob, a1, d(a3)),
        Err(SealedError::NotSealed)
    );
    assert_eq!(
        core.device_cert(bob, a1, d(bob)),
        Err(SealedError::NoSuchDevice)
    );
}
