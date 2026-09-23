//! The registrar's rules, on the in-memory store.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hl_identity::registrar::{attestation_reason, device_reason};
use hl_identity::{
    Attestation, Card, DeviceCert, DeviceKey, DeviceRevocation, IdentityKey, IdentityRevocation,
    ListKind, Record, RegisterRequest, RegistrarKeys, Rotation, ServerKey, SignedList, Stats,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::memory::MemoryStore;

const T: u64 = 1_750_000_000;
const HOST: &str = "hl.example";

fn addr(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn reg_key() -> ServerKey {
    ServerKey::from_seed(&[3; 32])
}

fn registrar_with(f: impl FnOnce(&mut Config)) -> Registrar {
    let mut cfg = Config::new(HOST);
    cfg.signup = Signup::Open;
    cfg.level = 0;
    f(&mut cfg);
    Registrar::new(cfg, reg_key(), Arc::new(MemoryStore::new()))
}

fn registrar() -> Registrar {
    registrar_with(|_| {})
}

fn id(n: u8) -> IdentityKey {
    IdentityKey::from_seed(&[n; 32])
}

fn request(who: &IdentityKey, handle: &str, time: u64) -> RegisterRequest {
    RegisterRequest {
        identity: who.public(),
        registrar: HOST.into(),
        handle: handle.into(),
        time,
        successor: None,
        proof: None,
    }
}

fn register(
    r: &Registrar,
    who: &IdentityKey,
    handle: &str,
    now: u64,
) -> Result<Registered, Refusal> {
    let bytes = request(who, handle, now).sign(who).unwrap();
    r.register(&bytes, addr(1), now)
}

fn commitment(k: &IdentityKey) -> [u8; 32] {
    Sha256::digest(k.public()).into()
}

fn keys(r: &Registrar) -> Vec<[u8; 32]> {
    vec![r.public_key()]
}

/// Every record in a per-identity list, each verified.
fn records_of(r: &Registrar, who: &IdentityKey, now: u64) -> Vec<Record> {
    let fp = who.fingerprint().0;
    let bytes = r.records_for(&fp, None, now).unwrap();
    let k = keys(r);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let list = SignedList::parse(&bytes, ListKind::Records, rk).unwrap();
    assert_eq!(list.fingerprint, Some(fp));
    list.entries
        .iter()
        .map(|(_, b)| Record::parse(b, Some(rk)).unwrap())
        .collect()
}

#[test]
fn a_first_registration_then_reissues_keep_the_age() {
    let r = registrar();
    let alice = id(1);
    let first = register(&r, &alice, "alice", T).unwrap();
    assert!(!first.reissued);
    assert_eq!(first.handle, "alice@hl.example");
    let a = Attestation::parse(&first.attestation).unwrap();
    a.verify_registrar(&r.public_key(), T, 0).unwrap();
    assert_eq!(a.registrar, HOST);
    assert_eq!((a.registered, a.issued), (T, T));
    assert_eq!(a.expires, T + 365 * DAY);
    assert_eq!(a.level, Some(0));

    let later = T + 200 * DAY;
    let again = register(&r, &alice, "alice", later).unwrap();
    assert!(again.reissued);
    let b = Attestation::parse(&again.attestation).unwrap();
    assert_eq!((b.registered, b.issued), (T, later));

    // Lapsed, but inside the hold: still a reissue, age intact.
    let lapsed = T + 200 * DAY + 400 * DAY;
    let c = register(&r, &alice, "alice", lapsed).unwrap();
    assert!(c.reissued);
    assert_eq!(c.registered, T);
}

#[test]
fn handles_are_checked_for_form_and_reservation() {
    let r = registrar_with(|c| {
        c.reserved.insert("misha".into());
    });
    let alice = id(1);
    for bad in ["Alice", "al", "a..b", "-ab", &"a".repeat(33)] {
        assert_eq!(
            register(&r, &alice, bad, T).unwrap_err(),
            Refusal::HandleInvalid,
            "{bad}"
        );
    }
    for reserved in ["admin", "guest", "misha"] {
        assert_eq!(
            register(&r, &alice, reserved, T).unwrap_err(),
            Refusal::HandleReserved
        );
    }
    // The server's logins arrive on reload.
    r.set_reserved(["alice".to_string()].into_iter().collect());
    assert_eq!(
        register(&r, &alice, "alice", T).unwrap_err(),
        Refusal::HandleReserved
    );
    assert!(register(&r, &alice, "misha", T).is_ok());
}

#[test]
fn a_taken_name_is_held_then_released() {
    let r = registrar();
    let alice = id(1);
    let bob = id(2);
    register(&r, &alice, "alice", T).unwrap();
    assert_eq!(
        register(&r, &bob, "alice", T + 1).unwrap_err(),
        Refusal::HandleTaken
    );
    // Expired: the hold keeps it for alice alone.
    let expired = T + 365 * DAY + 1;
    assert_eq!(
        register(&r, &bob, "alice", expired).unwrap_err(),
        Refusal::HandleHeld
    );
    // The hold passed: anyone, with a fresh age.
    let released = T + 730 * DAY + 1;
    let got = register(&r, &bob, "alice", released).unwrap();
    assert!(!got.reissued);
    assert_eq!(got.registered, released);
    // And alice lost it.
    assert_eq!(
        register(&r, &alice, "alice", released + 1).unwrap_err(),
        Refusal::HandleTaken
    );
}

#[test]
fn requests_are_bound_to_this_registrar_and_to_now() {
    let r = registrar();
    let alice = id(1);
    let mut req = request(&alice, "alice", T);
    req.registrar = "other.example".into();
    assert!(matches!(
        r.register(&req.sign(&alice).unwrap(), addr(1), T),
        Err(Refusal::BadRequest(_))
    ));
    assert_eq!(register(&r, &alice, "alice", T).map(|_| ()), Ok(()),);
    let stale = request(&alice, "alice", T).sign(&alice).unwrap();
    assert_eq!(
        r.register(&stale, addr(1), T + 301).unwrap_err(),
        Refusal::BadTime
    );
    // The same bytes again, inside the window: a replay, answered with
    // what it got the first time and issuing nothing new.
    let bytes = request(&alice, "alice", T + 10).sign(&alice).unwrap();
    let first = r.register(&bytes, addr(1), T + 10).unwrap();
    let logged = |r: &Registrar| {
        let k = keys(r);
        SignedList::parse(
            &r.log_since(None, T + 20).unwrap(),
            ListKind::Log,
            RegistrarKeys {
                host: HOST,
                keys: &k,
            },
        )
        .unwrap()
        .entries
        .len()
    };
    let before = logged(&r);
    assert_eq!(r.register(&bytes, addr(1), T + 11).unwrap(), first);
    assert_eq!(logged(&r), before);
    // Out of the window it is stale, whatever the seen-set says.
    assert_eq!(
        r.register(&bytes, addr(1), T + 10 + 301).unwrap_err(),
        Refusal::BadTime
    );
    // A forged signature is a signature failure.
    let mut forged = bytes.clone();
    let n = forged.len();
    forged[n - 1] ^= 1;
    assert_eq!(
        r.register(&forged, addr(1), T + 12).unwrap_err(),
        Refusal::BadSignature
    );
}

#[test]
fn invites_are_required_and_spent_once() {
    let r = registrar_with(|c| {
        c.signup = Signup::Invite;
        c.level = 2;
        c.proof_url = Some("https://hl.example/invite".into());
    });
    let alice = id(1);
    let bob = id(2);
    assert_eq!(
        register(&r, &alice, "alice", T).unwrap_err(),
        Refusal::ProofRequired {
            url: Some("https://hl.example/invite".into())
        }
    );
    let code = new_invite_code();
    assert_eq!(code.len(), 19);
    assert_eq!(r.add_invites(std::slice::from_ref(&code)).unwrap(), 1);

    let with = |who: &IdentityKey, handle: &str, proof: &str, at: u64| {
        let mut req = request(who, handle, at);
        req.proof = Some(proof.into());
        r.register(&req.sign(who).unwrap(), addr(1), at)
    };
    assert_eq!(
        with(&alice, "alice", "NOPE-NOPE", T).unwrap_err(),
        Refusal::ProofInvalid
    );
    // Typed back in lowercase and without the dashes, it still counts.
    let typed = code.replace('-', "").to_lowercase();
    let got = with(&alice, "alice", &typed, T).unwrap();
    assert_eq!(Attestation::parse(&got.attestation).unwrap().level, Some(2));
    assert_eq!(
        with(&bob, "bob", &code, T).unwrap_err(),
        Refusal::ProofInvalid
    );
    // A reissue needs no invite.
    assert!(register(&r, &alice, "alice", T + 10).unwrap().reissued);
}

#[test]
fn a_closed_registrar_still_renews() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let closed = Registrar::new(
        Config {
            signup: Signup::Closed,
            ..r.config().clone()
        },
        reg_key(),
        r.store.clone(),
    );
    assert_eq!(
        register(&closed, &id(2), "bob", T).unwrap_err(),
        Refusal::SignupClosed
    );
    assert!(register(&closed, &alice, "alice", T + 5).unwrap().reissued);
}

#[test]
fn registrations_are_rate_limited_and_reissues_are_not() {
    let r = registrar_with(|c| c.rates.registrations_per_address = 2);
    register(&r, &id(1), "aaa", T).unwrap();
    register(&r, &id(2), "bbb", T).unwrap();
    let err = register(&r, &id(3), "ccc", T + 10).unwrap_err();
    assert_eq!(err, Refusal::RateLimited { retry_after: 3590 });
    assert!(register(&r, &id(1), "aaa", T + 20).unwrap().reissued);
    // Another address has its own window, and the hour turns.
    let bytes = request(&id(3), "ccc", T + 30).sign(&id(3)).unwrap();
    assert!(r.register(&bytes, addr(9), T + 30).is_ok());
    assert!(register(&r, &id(4), "ddd", T + 3600).is_ok());

    // An IPv6 host is counted by its /64.
    let r = registrar_with(|c| c.rates.registrations_per_address = 1);
    let v6 = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, last));
    let one = request(&id(1), "aaa", T).sign(&id(1)).unwrap();
    let two = request(&id(2), "bbb", T).sign(&id(2)).unwrap();
    r.register(&one, v6(1), T).unwrap();
    assert!(matches!(
        r.register(&two, v6(2), T),
        Err(Refusal::RateLimited { .. })
    ));

    let r = registrar_with(|c| c.rates.registrations_total = 1);
    register(&r, &id(1), "aaa", T).unwrap();
    let two = request(&id(2), "bbb", T).sign(&id(2)).unwrap();
    assert!(matches!(
        r.register(&two, addr(7), T),
        Err(Refusal::RateLimited { .. })
    ));
}

#[test]
fn a_commitment_is_immutable_in_requests_and_cards() {
    let r = registrar();
    let alice = id(1);
    let next = id(9);
    let mut req = request(&alice, "alice", T);
    req.successor = Some(commitment(&next));
    r.register(&req.sign(&alice).unwrap(), addr(1), T).unwrap();

    // Dropping it is changing it.
    assert_eq!(
        register(&r, &alice, "alice", T + 5).unwrap_err(),
        Refusal::SuccessorMismatch
    );
    let mut other = request(&alice, "alice", T + 6);
    other.successor = Some([1; 32]);
    assert_eq!(
        r.register(&other.sign(&alice).unwrap(), addr(1), T + 6)
            .unwrap_err(),
        Refusal::SuccessorMismatch
    );
    let mut same = request(&alice, "alice", T + 7);
    same.successor = Some(commitment(&next));
    assert!(r
        .register(&same.sign(&alice).unwrap(), addr(1), T + 7)
        .is_ok());

    let mut card = Card::new(&alice, "Alice", T);
    assert_eq!(r.check_card(&card).unwrap_err(), Refusal::SuccessorMismatch);
    card.successor = Some(commitment(&next));
    assert!(r.check_card(&card).is_ok());

    // A card is where an identity that registered without one commits.
    let bob = id(2);
    register(&r, &bob, "bob", T).unwrap();
    let mut card = Card::new(&bob, "Bob", T);
    assert!(r.check_card(&card).is_ok());
    card.successor = Some([4; 32]);
    r.note_card(&card).unwrap();
    card.successor = Some([5; 32]);
    assert_eq!(r.check_card(&card).unwrap_err(), Refusal::SuccessorMismatch);
    // An identity this registrar never attested is not its to police.
    let stranger = Card::new(&id(3), "Carol", T);
    r.note_card(&Card {
        successor: Some([6; 32]),
        ..stranger.clone()
    })
    .unwrap();
    assert!(r.check_card(&stranger).is_ok());
}

#[test]
fn a_device_revocation_is_published_once_by_either_signer() {
    let r = registrar();
    let alice = id(1);
    let phone = DeviceKey::from_seed(&[2; 32]);
    let laptop = DeviceKey::from_seed(&[4; 32]);
    let rev = DeviceRevocation {
        identity: alice.public(),
        device: phone.public(),
        time: T,
        until: T + 90 * DAY,
        reason: Some(device_reason::STOLEN),
        signer: None,
        signer_cert: None,
    };
    let bytes = rev.sign(&alice).unwrap();
    assert_eq!(
        r.post_record(&bytes, T).unwrap_err(),
        Refusal::NotRegistered
    );

    register(&r, &alice, "alice", T).unwrap();
    let Posted::Published { seq } = r.post_record(&bytes, T).unwrap() else {
        panic!("a device revocation is never held back")
    };
    // Posting again after a lost reply is not a failure.
    assert_eq!(
        r.post_record(&bytes, T + 5).unwrap(),
        Posted::Published { seq }
    );

    let cert = DeviceCert::for_device(&alice, &laptop, T - 10, 30 * DAY)
        .unwrap()
        .sign(&alice);
    let by_device = DeviceRevocation {
        time: T + 1,
        ..rev.clone()
    }
    .sign_as_device(&laptop, cert)
    .unwrap();
    assert!(matches!(
        r.post_record(&by_device, T + 1).unwrap(),
        Posted::Published { .. }
    ));
    let held = records_of(&r, &alice, T + 2);
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|rec| rec.kind() == "revoke_device"));

    // A record from the future, and one only the registrar may sign.
    let future = DeviceRevocation {
        time: T + 10_000,
        until: T + 20_000,
        ..rev
    }
    .sign(&alice)
    .unwrap();
    assert_eq!(r.post_record(&future, T + 2).unwrap_err(), Refusal::BadTime);
    let freeze = Freeze {
        identity: alice.public(),
        registrar: HOST.into(),
        frozen: true,
        time: T,
    }
    .sign(&reg_key());
    assert!(matches!(
        r.post_record(&freeze, T + 2),
        Err(Refusal::BadRequest(_))
    ));
}

#[test]
fn records_are_rate_limited_per_identity() {
    let r = registrar_with(|c| c.rates.records_per_identity = 2);
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let post = |n: u8| {
        let rev = DeviceRevocation {
            identity: alice.public(),
            device: DeviceKey::from_seed(&[n; 32]).public(),
            time: T,
            until: T + DAY,
            reason: None,
            signer: None,
            signer_cert: None,
        };
        r.post_record(&rev.sign(&alice).unwrap(), T)
    };
    post(10).unwrap();
    post(11).unwrap();
    assert!(matches!(post(12), Err(Refusal::RateLimited { .. })));
    // A repeat of an accepted one is still answered.
    assert!(post(10).is_ok());
}

#[test]
fn an_identity_revocation_ends_everything_and_holds_the_names() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let bytes = IdentityRevocation {
        identity: alice.public(),
        time: T + 10,
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    r.post_record(&bytes, T + 10).unwrap();
    assert_eq!(
        register(&r, &alice, "alice", T + 20).unwrap_err(),
        Refusal::Revoked { successor: None }
    );
    assert_eq!(
        register(&r, &id(2), "alice", T + 20).unwrap_err(),
        Refusal::HandleHeld
    );
    assert_eq!(r.lookup_handle("alice", addr(1), T + 20).unwrap(), None);
    // The hold starts at the revocation, not at the old expiry.
    assert!(register(&r, &id(2), "alice", T + 10 + 365 * DAY).is_ok());
    // A revoked identity posts nothing more.
    let dev = DeviceRevocation {
        identity: alice.public(),
        device: [7; 32],
        time: T + 30,
        until: T + DAY,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    assert_eq!(
        r.post_record(&dev, T + 30).unwrap_err(),
        Refusal::Revoked { successor: None }
    );
}

#[test]
fn a_rotation_moves_the_names_to_the_committed_successor() {
    let r = registrar();
    let old = id(1);
    let new = id(2);
    let impostor = id(6);
    let mut req = request(&old, "alice", T);
    req.successor = Some(commitment(&new));
    r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
    let mut second = request(&old, "ally", T + 1);
    second.successor = Some(commitment(&new));
    r.register(&second.sign(&old).unwrap(), addr(1), T + 1)
        .unwrap();

    // Step 3: nothing but the committed key.
    let wrong = Rotation {
        identity: old.public(),
        successor: impostor.public(),
        time: T + 100,
    }
    .sign(&old, &impostor)
    .unwrap();
    assert_eq!(
        r.post_record(&wrong, T + 100).unwrap_err(),
        Refusal::SuccessorMismatch
    );

    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T + 100,
    }
    .sign(&old, &new)
    .unwrap();
    assert!(matches!(
        r.post_record(&rot, T + 100).unwrap(),
        Posted::Published { .. }
    ));

    // The predecessor is done, and is told where to go.
    assert_eq!(
        register(&r, &old, "alice", T + 110).unwrap_err(),
        Refusal::Revoked {
            successor: Some(new.public())
        }
    );
    // The successor's first request is a reissue, with the old age.
    let got = register(&r, &new, "alice", T + 120).unwrap();
    assert!(got.reissued);
    assert_eq!(got.registered, T);
    assert_eq!(
        r.lookup_identity(&new.fingerprint().0, addr(1), T + 120)
            .unwrap(),
        vec!["alice".to_string(), "ally".to_string()]
    );

    // Published under both keys, with the predecessor's attestations
    // revoked for every handle it held.
    let under_old = records_of(&r, &old, T + 130);
    let under_new = records_of(&r, &new, T + 130);
    assert!(matches!(&under_new[..], [Record::Rotate(_)]));
    let revoked: Vec<_> = under_old
        .iter()
        .filter_map(|rec| match rec {
            Record::RevokeAttestation(a) => Some((a.handle.clone(), a.reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        revoked,
        vec![
            ("alice".into(), Some(attestation_reason::ROTATED)),
            ("ally".into(), Some(attestation_reason::ROTATED))
        ]
    );
    assert!(under_old.iter().any(|rec| matches!(rec, Record::Rotate(_))));
    // And only one rotation, ever.
    let again = Rotation {
        identity: old.public(),
        successor: impostor.public(),
        time: T + 140,
    }
    .sign(&old, &impostor)
    .unwrap();
    assert_eq!(
        r.post_record(&again, T + 140).unwrap_err(),
        Refusal::Revoked {
            successor: Some(new.public())
        }
    );
}

#[test]
fn a_delayed_rotation_can_be_met_with_a_freeze() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let old = id(1);
    let thief = id(6);
    register(&r, &old, "alice", T).unwrap();
    let rot = Rotation {
        identity: old.public(),
        successor: thief.public(),
        time: T + 10,
    }
    .sign(&old, &thief)
    .unwrap();
    assert_eq!(
        r.post_record(&rot, T + 10).unwrap(),
        Posted::Pending {
            until: T + 10 + DAY
        }
    );
    assert_eq!(
        r.post_record(&rot, T + 11).unwrap(),
        Posted::Pending {
            until: T + 10 + DAY
        }
    );
    // Nothing published yet, and a second rotation is refused.
    assert!(records_of(&r, &old, T + 20).is_empty());
    let second = Rotation {
        identity: old.public(),
        successor: id(7).public(),
        time: T + 30,
    }
    .sign(&old, &id(7))
    .unwrap();
    assert!(matches!(
        r.post_record(&second, T + 30),
        Err(Refusal::BadRequest(_))
    ));

    r.freeze(&old.fingerprint().0, true, T + 40).unwrap();
    assert_eq!(
        register(&r, &old, "alice", T + 50).unwrap_err(),
        Refusal::Frozen
    );
    // Past the delay, the rotation is gone rather than published.
    let recs = records_of(&r, &old, T + 2 * DAY);
    assert!(matches!(&recs[..], [Record::Freeze(f)] if f.frozen));
    r.freeze(&old.fingerprint().0, false, T + 2 * DAY).unwrap();
    assert!(register(&r, &old, "alice", T + 2 * DAY).is_ok());
}

#[test]
fn a_delayed_rotation_publishes_itself_when_its_time_comes() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let old = id(1);
    let new = id(2);
    register(&r, &old, "alice", T).unwrap();
    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, T).unwrap();
    // The first thing to look after the delay publishes it.
    let recs = records_of(&r, &new, T + DAY);
    assert!(matches!(&recs[..], [Record::Rotate(_)]));
    assert!(matches!(
        r.post_record(&rot, T + DAY + 1).unwrap(),
        Posted::Published { .. }
    ));
}

#[test]
fn a_delayed_rotation_is_dropped_if_its_successor_moved_on() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let old = id(1);
    let new = id(2);
    let other = id(3);
    register(&r, &old, "alice", T).unwrap();
    register(&r, &new, "bobby", T).unwrap();
    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, T).unwrap();
    // While it waits, the successor revokes itself.
    let gone = IdentityRevocation {
        identity: new.public(),
        time: T + 10,
        reason: None,
    }
    .sign(&new)
    .unwrap();
    r.post_record(&gone, T + 10).unwrap();
    // Past the delay the rotation is dropped, and the name stays where
    // it can still be renewed.
    assert!(records_of(&r, &old, T + DAY).is_empty());
    let found = r.lookup_handle("alice", addr(1), T + DAY).unwrap().unwrap();
    assert_eq!(found.identity, old.public());
    assert!(register(&r, &old, "alice", T + DAY).unwrap().reissued);

    // Likewise a successor that rotated on to a key of its own, its
    // rotation due first.
    let r = registrar_with(|c| c.rotation_delay = DAY);
    register(&r, &old, "alice", T).unwrap();
    register(&r, &new, "bobby", T).unwrap();
    let on = Rotation {
        identity: new.public(),
        successor: other.public(),
        time: T,
    }
    .sign(&new, &other)
    .unwrap();
    r.post_record(&on, T).unwrap();
    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T + 10,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, T + 10).unwrap();
    assert!(records_of(&r, &old, T + DAY + 10).is_empty());
    let rotations: Vec<([u8; 32], [u8; 32])> = records_of(&r, &new, T + DAY + 10)
        .into_iter()
        .filter_map(|rec| match rec {
            Record::Rotate(x) => Some((x.identity, x.successor)),
            _ => None,
        })
        .collect();
    assert_eq!(rotations, vec![(new.public(), other.public())]);
    assert!(register(&r, &old, "alice", T + DAY + 10).is_ok());
}

#[test]
fn a_reissue_in_the_second_of_a_revocation_is_not_void() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    r.revoke_handle("alice", attestation_reason::LAPSED, false, T + 10)
        .unwrap();
    let got = register(&r, &alice, "alice", T + 10).unwrap();
    assert!(got.reissued);
    let att = Attestation::parse(&got.attestation).unwrap();
    assert_eq!(att.issued, T + 11);
    let recs = records_of(&r, &alice, T + 10);
    let [Record::RevokeAttestation(rev)] = &recs[..] else {
        panic!("{recs:?}")
    };
    assert!(!rev.voids(&att));
    // A second revocation in that same second must reach the reissue:
    // dated like the first, it would void nothing new, and with the same
    // reason it would not even be published.
    r.revoke_handle("alice", attestation_reason::LAPSED, false, T + 10)
        .unwrap();
    let recs = records_of(&r, &alice, T + 10);
    let revs: Vec<_> = recs
        .iter()
        .filter_map(|rec| match rec {
            Record::RevokeAttestation(rev) => Some(rev),
            _ => None,
        })
        .collect();
    assert_eq!(revs.len(), 2, "{recs:?}");
    assert!(revs.iter().any(|rev| rev.voids(&att)));
    // A second later, nothing is shifted.
    let later = register(&r, &alice, "alice", T + 12).unwrap();
    assert_eq!(
        Attestation::parse(&later.attestation).unwrap().issued,
        T + 12
    );
}

#[test]
fn freezes_are_ordered_even_within_a_second() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let fp = alice.fingerprint().0;
    r.freeze(&fp, true, T).unwrap();
    r.freeze(&fp, false, T).unwrap();
    r.freeze(&fp, true, T).unwrap();
    let times: Vec<(u64, bool)> = records_of(&r, &alice, T)
        .into_iter()
        .map(|rec| match rec {
            Record::Freeze(f) => (f.time, f.frozen),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(times, vec![(T, true), (T + 1, false), (T + 2, true)]);
    assert_eq!(
        r.freeze(&id(9).fingerprint().0, true, T),
        Err(OpError::UnknownIdentity)
    );
}

#[test]
fn an_abuse_revocation_bars_the_holder_for_the_hold() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    // An operator types the name as it is displayed.
    r.revoke_handle("Alice", attestation_reason::ABUSE, true, T + 10)
        .unwrap();
    assert_eq!(
        register(&r, &alice, "alice", T + 20).unwrap_err(),
        Refusal::HandleHeld
    );
    assert_eq!(
        register(&r, &id(2), "alice", T + 20).unwrap_err(),
        Refusal::HandleHeld
    );
    let recs = records_of(&r, &alice, T + 20);
    let [Record::RevokeAttestation(a)] = &recs[..] else {
        panic!("{recs:?}")
    };
    assert_eq!(a.reason, Some(attestation_reason::ABUSE));
    // Its `until` is the voided attestation's expiry, which is when the
    // full list stops carrying it.
    let k = keys(&r);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let full = |now| {
        SignedList::parse(&r.records_since(None, now).unwrap(), ListKind::Records, rk)
            .unwrap()
            .entries
            .len()
    };
    assert_eq!(full(T + 365 * DAY), 1);
    assert_eq!(full(T + 365 * DAY + 1), 0);
    assert_eq!(
        r.revoke_handle("nobody", 0, false, T),
        Err(OpError::UnknownHandle)
    );
}

#[test]
fn a_recovery_gives_the_name_to_the_new_key_alone() {
    let r = registrar();
    let lost = id(1);
    let found = id(2);
    register(&r, &lost, "alice", T).unwrap();
    assert_eq!(
        r.recover("alice", &lost.fingerprint().0, true, T + 5),
        Err(OpError::SameIdentity)
    );
    r.recover("alice", &found.fingerprint().0, true, T + 10)
        .unwrap();
    assert_eq!(
        register(&r, &lost, "alice", T + 20).unwrap_err(),
        Refusal::HandleHeld
    );
    assert_eq!(
        register(&r, &id(3), "alice", T + 20).unwrap_err(),
        Refusal::HandleHeld
    );
    let got = register(&r, &found, "alice", T + 30).unwrap();
    assert!(got.reissued);
    assert_eq!(got.registered, T, "--keep-age");
    assert!(matches!(
        &records_of(&r, &lost, T + 30)[..],
        [Record::RevokeAttestation(a)] if a.reason == Some(attestation_reason::RECOVERED)
    ));

    // Without --keep-age the new key is a stranger.
    register(&r, &id(4), "bob", T).unwrap();
    r.recover("bob", &id(5).fingerprint().0, false, T + 10)
        .unwrap();
    assert_eq!(
        register(&r, &id(5), "bob", T + 40).unwrap().registered,
        T + 40
    );
}

#[test]
fn lookups_show_held_names_only() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let found = r.lookup_handle("alice", addr(1), T + 1).unwrap().unwrap();
    assert_eq!(found.identity, alice.public());
    assert_eq!(found.registered, T);
    // Handles compare case-insensitively (§5.1).
    assert_eq!(
        r.lookup_handle("Alice", addr(1), T + 1).unwrap(),
        Some(found)
    );
    assert_eq!(r.lookup_handle("bob", addr(1), T + 1).unwrap(), None);
    assert_eq!(
        r.lookup_handle("alice", addr(1), T + 365 * DAY + 1)
            .unwrap(),
        None
    );
    assert!(r
        .lookup_identity(&id(9).fingerprint().0, addr(1), T)
        .unwrap()
        .is_empty());

    let r = registrar_with(|c| c.rates.lookups_per_address = 2);
    r.lookup_handle("a", addr(1), T).unwrap();
    r.lookup_identity(&[0; 32], addr(1), T).unwrap();
    assert!(matches!(
        r.lookup_handle("a", addr(1), T + 1),
        Err(Refusal::RateLimited { retry_after: 59 })
    ));
    assert!(r.lookup_handle("a", addr(1), T + 60).is_ok());
}

#[test]
fn an_unknown_key_gets_a_signed_empty_list() {
    let r = registrar();
    let k = keys(&r);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let fp = id(9).fingerprint().0;
    let list =
        SignedList::parse(&r.records_for(&fp, None, T).unwrap(), ListKind::Records, rk).unwrap();
    assert_eq!(list.fingerprint, Some(fp));
    assert!(list.entries.is_empty());
    assert_eq!((list.issued, list.expires), (T, T + 3600));
}

#[test]
fn the_log_carries_every_issuance_and_the_stats_count_them() {
    let r = registrar();
    register(&r, &id(1), "alice", T).unwrap();
    register(&r, &id(1), "alice", T + 10).unwrap();
    register(&r, &id(2), "bob", T + 20).unwrap();
    let k = keys(&r);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let log = SignedList::parse(&r.log_since(None, T + 30).unwrap(), ListKind::Log, rk).unwrap();
    let handles: Vec<(String, u64)> = log
        .entries
        .iter()
        .map(|(_, b)| {
            let a = Attestation::parse(b).unwrap();
            (a.handle, a.issued)
        })
        .collect();
    assert_eq!(
        handles,
        vec![
            ("alice".into(), T),
            ("alice".into(), T + 10),
            ("bob".into(), T + 20)
        ]
    );
    let tail = SignedList::parse(
        &r.log_since(Some(log.entries[1].0), T + 30).unwrap(),
        ListKind::Log,
        rk,
    )
    .unwrap();
    assert_eq!(tail.entries.len(), 1);
    assert_eq!(tail.since, Some(log.entries[1].0));

    let stats = Stats::parse(&r.stats(T + 30).unwrap(), rk).unwrap();
    assert_eq!(stats.identities, 2);
    assert_eq!(stats.issued_total, 2);
    assert_eq!(stats.log_seq, log.entries[2].0);
    // Cached for the hour.
    register(&r, &id(3), "carol", T + 40).unwrap();
    assert_eq!(
        Stats::parse(&r.stats(T + 50).unwrap(), rk)
            .unwrap()
            .issued_total,
        2
    );
    assert_eq!(
        Stats::parse(&r.stats(T + 30 + 3600).unwrap(), rk)
            .unwrap()
            .issued_total,
        3
    );
}

/// A memory store whose commit fails on demand, counting the issuances
/// that reach it.
#[derive(Default)]
struct FailingCommit {
    inner: MemoryStore,
    fail: std::sync::atomic::AtomicBool,
    issued: std::sync::atomic::AtomicUsize,
}

impl RegistrarStore for FailingCommit {
    fn commit(&self) -> Result<(), StoreError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError("disk full".into()));
        }
        Ok(())
    }
    fn identity(&self, key: &Key) -> Result<Option<IdentityRow>, StoreError> {
        self.inner.identity(key)
    }
    fn identity_by_fingerprint(&self, fp: &[u8; 32]) -> Result<Option<IdentityRow>, StoreError> {
        self.inner.identity_by_fingerprint(fp)
    }
    fn handle(&self, name: &str) -> Result<Option<HandleRow>, StoreError> {
        self.inner.handle(name)
    }
    fn handles_of(&self, key: &Key) -> Result<Vec<HandleRow>, StoreError> {
        self.inner.handles_of(key)
    }
    fn recovery(&self, handle: &str) -> Result<Option<Recovery>, StoreError> {
        self.inner.recovery(handle)
    }
    fn issue(&self, w: &Issue) -> Result<Issued, StoreError> {
        self.issued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.issue(w)
    }
    fn attestations_expire(
        &self,
        identity: &Key,
        handle: &str,
        issued_up_to: u64,
    ) -> Result<Option<u64>, StoreError> {
        self.inner
            .attestations_expire(identity, handle, issued_up_to)
    }
    fn publish(&self, p: &Publish) -> Result<Vec<u64>, StoreError> {
        self.inner.publish(p)
    }
    fn record_seq(&self, digest: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        self.inner.record_seq(digest)
    }
    fn set_commitment(&self, key: &Key, commitment: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.set_commitment(key, commitment)
    }
    fn pending(&self, key: &Key) -> Result<Option<Pending>, StoreError> {
        self.inner.pending(key)
    }
    fn pending_due(&self, now: u64) -> Result<Vec<Pending>, StoreError> {
        self.inner.pending_due(now)
    }
    fn records_page(
        &self,
        filter: RecordFilter,
        since: u64,
        budget: usize,
    ) -> Result<Page, StoreError> {
        self.inner.records_page(filter, since, budget)
    }
    fn log_page(&self, since: u64, budget: usize) -> Result<Page, StoreError> {
        self.inner.log_page(since, budget)
    }
    fn counts(&self, now: u64) -> Result<Counts, StoreError> {
        self.inner.counts(now)
    }
    fn invite_open(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.invite_open(hash)
    }
    fn add_invites(&self, hashes: &[[u8; 32]]) -> Result<usize, StoreError> {
        self.inner.add_invites(hashes)
    }
}

#[test]
fn a_registration_whose_commit_failed_is_not_replayed() {
    use std::sync::atomic::Ordering::SeqCst;
    let store = Arc::new(FailingCommit::default());
    let mut cfg = Config::new(HOST);
    cfg.signup = Signup::Open;
    let r = Registrar::new(cfg, reg_key(), store.clone());
    let alice = id(1);
    let bytes = request(&alice, "alice", T).sign(&alice).unwrap();

    store.fail.store(true, SeqCst);
    assert!(matches!(
        r.register(&bytes, addr(1), T),
        Err(Refusal::Store(_))
    ));
    // The client sends the same request again. It is decided again, not
    // answered with an attestation the failed commit may have lost.
    store.fail.store(false, SeqCst);
    r.register(&bytes, addr(1), T + 1).unwrap();
    assert_eq!(store.issued.load(SeqCst), 2);
    // Once committed, the same bytes are answered from the replay cache.
    r.register(&bytes, addr(1), T + 2).unwrap();
    assert_eq!(store.issued.load(SeqCst), 2);
}
