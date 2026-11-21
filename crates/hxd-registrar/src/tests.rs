//! The registrar's rules, on the in-memory store.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hl_identity::envelope::{Keys, Secret};
use hl_identity::registrar::{attestation_reason, device_reason};
use hl_identity::{
    Attestation, Card, DeviceCert, DeviceEpoch, DeviceKey, DeviceRevocation, IdentityKey,
    IdentityRevocation, ListKind, Record, RecoveryCode, RegisterRequest, RegistrarKeys, Rotation,
    ServerKey, SignedList, Stats,
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
    r.note_card(&card, b"", T).unwrap();
    card.successor = Some([5; 32]);
    assert_eq!(r.check_card(&card).unwrap_err(), Refusal::SuccessorMismatch);
    // An identity this registrar never attested is not its to police.
    let stranger = Card::new(&id(3), "Carol", T);
    r.note_card(
        &Card {
            successor: Some([6; 32]),
            ..stranger.clone()
        },
        b"",
        T,
    )
    .unwrap();
    assert!(r.check_card(&stranger).is_ok());
}

#[test]
fn a_card_is_kept_only_while_it_carries_the_commitment_held() {
    let r = registrar();
    let (alice, next) = (id(1), id(9));
    let mut req = request(&alice, "alice", T);
    req.successor = Some(commitment(&next));
    r.register(&req.sign(&alice).unwrap(), addr(1), T).unwrap();
    let kept = || r.kept_card(&alice.fingerprint().0, T).unwrap();
    let skew = Config::new(HOST).clock_skew;
    // In order, each a card noted and the card kept after it.
    for (successor, updated, want) in [
        (None, T + 1, None),
        (Some([4; 32]), T + 2, None),
        (Some(commitment(&next)), T + 3, Some(T + 3)),
        (Some(commitment(&next)), T + 2, Some(T + 3)),
        (Some(commitment(&next)), T + 4, Some(T + 4)),
        // Dated past the clock and its skew, it is not kept.
        (Some(commitment(&next)), T + skew + 1, Some(T + 4)),
        (Some(commitment(&next)), u64::MAX, Some(T + 4)),
    ] {
        let mut card = Card::new(&alice, "Alice", updated);
        card.successor = successor;
        let bytes = card.sign(&alice, vec![]).unwrap();
        r.note_card(&card, &bytes, T).unwrap();
        let got = kept();
        assert_eq!(
            got.as_ref().map(|k| k.0),
            want,
            "{successor:?} at {updated}"
        );
        if want == Some(updated) {
            assert_eq!(got.unwrap().1, bytes);
        }
    }

    // A card making the commitment is kept as one carrying it.
    let bob = id(2);
    register(&r, &bob, "bob", T).unwrap();
    let mut card = Card::new(&bob, "Bob", T);
    card.successor = Some([5; 32]);
    let bytes = card.sign(&bob, vec![]).unwrap();
    r.note_card(&card, &bytes, T).unwrap();
    assert_eq!(
        r.kept_card(&bob.fingerprint().0, T).unwrap(),
        Some((T, bytes))
    );
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
        r.post_record(&bytes, addr(1), T).unwrap_err(),
        Refusal::NotRegistered
    );

    register(&r, &alice, "alice", T).unwrap();
    let Posted::Published { seq } = r.post_record(&bytes, addr(1), T).unwrap() else {
        panic!("a device revocation is never held back")
    };
    // Posting again after a lost reply is not a failure.
    assert_eq!(
        r.post_record(&bytes, addr(1), T + 5).unwrap(),
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
        r.post_record(&by_device, addr(1), T + 1).unwrap(),
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
    assert_eq!(
        r.post_record(&future, addr(1), T + 2).unwrap_err(),
        Refusal::BadTime
    );
    let freeze = Freeze {
        identity: alice.public(),
        registrar: HOST.into(),
        frozen: true,
        time: T,
    }
    .sign(&reg_key());
    assert!(matches!(
        r.post_record(&freeze, addr(1), T + 2),
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
        r.post_record(&rev.sign(&alice).unwrap(), addr(1), T)
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
    r.post_record(&bytes, addr(1), T + 10).unwrap();
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
        r.post_record(&dev, addr(1), T + 30).unwrap_err(),
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
        next: None,
    }
    .sign(&old, &impostor)
    .unwrap();
    assert_eq!(
        r.post_record(&wrong, addr(1), T + 100).unwrap_err(),
        Refusal::SuccessorMismatch
    );

    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T + 100,
        next: None,
    }
    .sign(&old, &new)
    .unwrap();
    assert!(matches!(
        r.post_record(&rot, addr(1), T + 100).unwrap(),
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
        next: None,
    }
    .sign(&old, &impostor)
    .unwrap();
    assert_eq!(
        r.post_record(&again, addr(1), T + 140).unwrap_err(),
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
        next: None,
    }
    .sign(&old, &thief)
    .unwrap();
    assert_eq!(
        r.post_record(&rot, addr(1), T + 10).unwrap(),
        Posted::Pending {
            until: T + 10 + DAY
        }
    );
    assert_eq!(
        r.post_record(&rot, addr(1), T + 11).unwrap(),
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
        next: None,
    }
    .sign(&old, &id(7))
    .unwrap();
    assert_eq!(
        r.post_record(&second, addr(1), T + 30).unwrap_err(),
        Refusal::RotationPending {
            until: T + 10 + DAY
        }
    );

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
fn the_old_keys_revocation_takes_a_pending_rotation_whatever_it_committed() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let (old, new) = (id(1), id(2));
    let mut req = request(&old, "alice", T);
    req.successor = Some(commitment(&new));
    r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
    r.post_record(&rotation(&old, &new, None, T), addr(1), T)
        .unwrap();
    // Whoever holds the old key may destroy the identity, though not
    // take it.
    let revoke = IdentityRevocation {
        identity: old.public(),
        time: T + 10,
        reason: None,
    }
    .sign(&old)
    .unwrap();
    assert!(matches!(
        r.post_record(&revoke, addr(1), T + 10),
        Ok(Posted::Published { .. })
    ));
    assert!(records_of(&r, &new, T + DAY).is_empty());
    assert_eq!(r.store.pending(&old.public()).unwrap(), None);
}

/// `from`'s rotation to `to`, naming `to`'s own commitment as `next`.
fn rotation(
    from: &IdentityKey,
    to: &IdentityKey,
    next: Option<&IdentityKey>,
    time: u64,
) -> Vec<u8> {
    Rotation {
        identity: from.public(),
        successor: to.public(),
        time,
        next: next.map(commitment),
    }
    .sign(from, to)
    .unwrap()
}

#[test]
fn a_rotations_next_is_the_commitment_of_a_successor_that_has_none() {
    let (old, new, next) = (id(1), id(2), id(3));
    let rotated = |next: Option<&IdentityKey>, known: bool| {
        let r = registrar();
        let mut req = request(&old, "alice", T);
        req.successor = Some(commitment(&new));
        r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
        if known {
            register(&r, &new, "bobby", T).unwrap();
        }
        r.post_record(&rotation(&old, &new, next, T + 10), addr(1), T + 10)
            .unwrap();
        r.lookup_handle("alice", addr(1), T + 10)
            .unwrap()
            .unwrap()
            .successor
    };
    assert_eq!(rotated(Some(&next), false), Some(commitment(&next)));
    assert_eq!(rotated(None, false), None);
    assert_eq!(rotated(Some(&next), true), Some(commitment(&next)));
}

#[test]
fn a_rotation_posted_at_another_registrar_names_the_owners_next_there_too() {
    let (old, new, next, thief) = (id(1), id(2), id(3), id(6));
    let (a, b) = (registrar(), registrar());
    for r in [&a, &b] {
        let mut req = request(&old, "alice", T);
        req.successor = Some(commitment(&new));
        r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
    }
    // Published at one, the record is public, and a thief holding only
    // the successor's key posts it at the other, having made the
    // successor known there first: it brings the owner's commitment with
    // it, and nothing the thief can sign replaces it.
    let bytes = rotation(&old, &new, Some(&next), T);
    a.post_record(&bytes, addr(1), T).unwrap();
    register(&b, &new, "zzzz", T + 1).unwrap();
    b.post_record(&bytes, addr(1), T + 10).unwrap();
    let found = b.lookup_handle("alice", addr(1), T + 10).unwrap().unwrap();
    assert_eq!(
        (found.identity, found.successor),
        (new.public(), Some(commitment(&next)))
    );
    let mut req = request(&new, "alice", T + 20);
    req.successor = Some(commitment(&thief));
    assert_eq!(
        b.register(&req.sign(&new).unwrap(), addr(1), T + 20)
            .unwrap_err(),
        Refusal::SuccessorMismatch
    );
    assert_eq!(
        b.post_record(&rotation(&new, &thief, None, T + 20), addr(1), T + 20)
            .unwrap_err(),
        Refusal::SuccessorMismatch
    );
}

#[test]
fn a_rotation_is_refused_to_a_successor_that_could_not_take_it() {
    let (old, new, next, thief) = (id(1), id(2), id(3), id(6));
    let rotating = || {
        let r = registrar_with(|c| c.rotation_delay = DAY);
        let mut req = request(&old, "alice", T);
        req.successor = Some(commitment(&new));
        r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
        r
    };
    let commit_new = |r: &Registrar, to: &IdentityKey, at| {
        let mut req = request(&new, "bobby", at);
        req.successor = Some(commitment(to));
        r.register(&req.sign(&new).unwrap(), addr(1), at).unwrap();
    };
    let post = |r: &Registrar, next: Option<&IdentityKey>| {
        r.post_record(&rotation(&old, &new, next, T + 10), addr(1), T + 10)
    };
    let bad = |why: &str| Err(Refusal::BadRequest(why.into()));

    // A successor holding a commitment keeps it, so a rotation naming
    // another `next`, or none, is refused; the same one is taken.
    let r = rotating();
    commit_new(&r, &thief, T);
    assert_eq!(post(&r, Some(&next)), Err(Refusal::SuccessorMismatch));
    assert_eq!(post(&r, None), Err(Refusal::SuccessorMismatch));
    let r = rotating();
    commit_new(&r, &next, T);
    assert!(post(&r, Some(&next)).is_ok());

    // A frozen successor, or one with a rotation of its own pending.
    let r = rotating();
    register(&r, &new, "bobby", T).unwrap();
    r.freeze(&new.fingerprint().0, true, T + 1).unwrap();
    assert_eq!(post(&r, None), bad("the successor key is frozen"));
    let r = rotating();
    register(&r, &new, "bobby", T).unwrap();
    r.post_record(&rotation(&new, &next, None, T + 5), addr(1), T + 5)
        .unwrap();
    assert_eq!(
        post(&r, None),
        bad("the successor key has a rotation of its own pending")
    );
}

#[test]
fn the_successor_of_a_held_rotation_commits_to_its_next_or_to_nothing() {
    let (old, new, next, thief) = (id(1), id(2), id(3), id(6));
    let held = || {
        let r = registrar_with(|c| c.rotation_delay = DAY);
        let mut req = request(&old, "alice", T);
        req.successor = Some(commitment(&new));
        r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
        r.post_record(&rotation(&old, &new, Some(&next), T), addr(1), T)
            .unwrap();
        r
    };
    let commit_new = |r: &Registrar, to: &IdentityKey, at| {
        let mut req = request(&new, "bobby", at);
        req.successor = Some(commitment(to));
        r.register(&req.sign(&new).unwrap(), addr(1), at)
    };
    let committed = |r: &Registrar| r.store.identity(&new.public()).unwrap().unwrap().commitment;

    // Whoever holds the successor's key, while the rotation waits: a
    // commitment of its own would have the owner's rotation dropped,
    // whether the key is new here or known.
    let r = held();
    assert_eq!(
        commit_new(&r, &thief, T + 5).unwrap_err(),
        Refusal::RotationPending { until: T + DAY }
    );
    register(&r, &new, "bobby", T + 5).unwrap();
    assert_eq!(
        commit_new(&r, &thief, T + 10).unwrap_err(),
        Refusal::RotationPending { until: T + DAY }
    );
    let mut card = Card::new(&new, "Bob", T + 10);
    card.successor = Some(commitment(&thief));
    assert_eq!(
        r.check_card(&card).unwrap_err(),
        Refusal::RotationPending { until: T + DAY }
    );
    r.note_card(&card, b"", T).unwrap();
    assert_eq!(committed(&r), None);
    // A card naming the rotation's `next`, or none, is taken as ever.
    for successor in [Some(commitment(&next)), None] {
        card.successor = successor;
        assert!(r.check_card(&card).is_ok());
    }
    // Published when its time comes, it commits the successor to `next`.
    assert!(records_of(&r, &new, T + DAY)
        .iter()
        .any(|rec| matches!(rec, Record::Rotate(_))));
    assert_eq!(committed(&r), Some(commitment(&next)));

    // The rotation's own `next` may be committed to early.
    let r = held();
    commit_new(&r, &next, T + 20).unwrap();
    assert!(records_of(&r, &new, T + DAY)
        .iter()
        .any(|rec| matches!(rec, Record::Rotate(_))));
}

#[test]
fn a_held_rotation_that_no_longer_reads_is_dropped() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let (old, new) = (id(1), id(2));
    register(&r, &old, "alice", T).unwrap();
    r.store
        .publish(&Publish {
            records: vec![],
            effects: vec![Effect::SetPending(Pending {
                identity: old.public(),
                successor: new.public(),
                publish_at: T + DAY,
                digest: [1; 32],
                bytes: b"not a rotation".to_vec(),
            })],
        })
        .unwrap();
    assert!(records_of(&r, &old, T + DAY).is_empty());
    assert_eq!(r.store.pending(&old.public()).unwrap(), None);
    assert_eq!(
        r.lookup_handle("alice", addr(1), T + DAY)
            .unwrap()
            .unwrap()
            .identity,
        old.public()
    );
}

#[test]
fn a_rotation_whose_next_hands_nothing_over_is_refused_by_name() {
    use hl_identity::cbor::{self, Value};
    let r = registrar();
    let (old, new) = (id(1), id(2));
    register(&r, &old, "alice", T).unwrap();
    // `next` is read before either signature is checked, so a record
    // with it rewritten needs neither key.
    for to in [&old, &new] {
        let mut v = cbor::decode_canonical(&rotation(&old, &new, Some(&id(3)), T)).unwrap();
        if let Value::Map(entries) = &mut v {
            for (k, val) in entries.iter_mut() {
                if k == &Value::Text("next".into()) {
                    *val = Value::Bytes(commitment(to).to_vec());
                }
            }
        }
        assert!(matches!(
            r.post_record(&cbor::encode(&v), addr(1), T),
            Err(Refusal::BadRequest(why)) if why.contains("hands nothing over")
        ));
    }
}

#[test]
fn a_card_records_no_commitment_for_an_identity_that_may_not_write() {
    let alice = id(1);
    let fp = alice.fingerprint().0;
    let revocation = IdentityRevocation {
        identity: alice.public(),
        time: T + 1,
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    let rotation = Rotation {
        identity: alice.public(),
        successor: id(2).public(),
        time: T + 1,
        next: None,
    }
    .sign(&alice, &id(2))
    .unwrap();
    for case in ["frozen", "revoked", "rotated"] {
        let r = registrar();
        register(&r, &alice, "alice", T).unwrap();
        match case {
            "frozen" => assert!(r.freeze(&fp, true, T + 1).is_ok()),
            "revoked" => assert!(r.post_record(&revocation, addr(1), T + 1).is_ok()),
            _ => assert!(r.post_record(&rotation, addr(1), T + 1).is_ok()),
        }
        let mut card = Card::new(&alice, "Alice", T + 2);
        card.successor = Some([4; 32]);
        r.note_card(&card, b"", T).unwrap();
        let row = r.store.identity(&alice.public()).unwrap().unwrap();
        assert_eq!(row.commitment, None, "{case}");
        match (case, r.kept_card(&fp, T + 2)) {
            ("frozen", kept) => assert_eq!(kept, Ok(None), "{case}"),
            (_, kept) => assert!(matches!(kept, Err(Refusal::Revoked { .. })), "{case}"),
        }
    }
}

#[test]
fn an_operator_publishes_a_held_rotation_at_once() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let old = id(1);
    let new = id(2);
    let (fp, to) = (old.fingerprint().0, new.fingerprint().0);
    let mut req = request(&old, "alice", T);
    req.successor = Some(commitment(&new));
    r.register(&req.sign(&old).unwrap(), addr(1), T).unwrap();
    assert_eq!(
        r.publish_pending(&fp, &to, T + 1).unwrap_err(),
        OpError::NothingPending
    );
    assert_eq!(
        r.publish_pending(&id(9).fingerprint().0, &to, T + 1)
            .unwrap_err(),
        OpError::UnknownIdentity
    );
    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T + 10,
        next: None,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, addr(1), T + 10).unwrap();
    // The operator names the successor they confirmed with the holder,
    // and a rotation to any other is left waiting.
    assert_eq!(
        r.publish_pending(&fp, &id(6).fingerprint().0, T + 15)
            .unwrap_err(),
        OpError::PendingToAnother(to)
    );
    let seq = r.publish_pending(&fp, &to, T + 20).unwrap();
    assert_eq!(
        r.post_record(&rot, addr(1), T + 30).unwrap(),
        Posted::Published { seq }
    );
    assert_eq!(
        r.lookup_handle("alice", addr(1), T + 30)
            .unwrap()
            .unwrap()
            .identity,
        new.public()
    );
    assert_eq!(
        r.publish_pending(&fp, &to, T + 40).unwrap_err(),
        OpError::NothingPending
    );

    // One that no longer passes is dropped, not published: here its
    // successor revoked itself while it waited.
    let r = registrar_with(|c| c.rotation_delay = DAY);
    register(&r, &old, "alice", T).unwrap();
    register(&r, &new, "bobby", T).unwrap();
    r.post_record(&rot, addr(1), T + 10).unwrap();
    let gone = IdentityRevocation {
        identity: new.public(),
        time: T + 20,
        reason: None,
    }
    .sign(&new)
    .unwrap();
    r.post_record(&gone, addr(1), T + 20).unwrap();
    assert_eq!(
        r.publish_pending(&fp, &to, T + 30).unwrap_err(),
        OpError::PendingDropped
    );
    assert!(records_of(&r, &old, T + 40).is_empty());
    assert_eq!(
        r.publish_pending(&fp, &to, T + 40).unwrap_err(),
        OpError::NothingPending
    );
}

#[test]
fn a_waiting_rotations_identity_commits_to_nothing() {
    let r = registrar_with(|c| c.rotation_delay = DAY);
    let (old, owners, thiefs) = (id(1), id(2), id(6));
    let fp = old.fingerprint().0;
    register(&r, &old, "alice", T).unwrap();
    // A thief holding the old key of an uncommitted identity rotates it
    // to its own key, then tries to pin the commitment to that key, which
    // the registrar cannot tell from the owner doing the same.
    let stolen = rotation(&old, &thiefs, None, T + 10);
    r.post_record(&stolen, addr(1), T + 10).unwrap();
    let mut req = request(&old, "alice", T + 20);
    req.successor = Some(commitment(&thiefs));
    assert_eq!(
        r.register(&req.sign(&old).unwrap(), addr(1), T + 20)
            .unwrap_err(),
        Refusal::RotationPending {
            until: T + 10 + DAY
        }
    );
    let mut card = Card::new(&old, "Alice", T + 20);
    card.successor = Some(commitment(&thiefs));
    assert_eq!(
        r.check_card(&card).unwrap_err(),
        Refusal::RotationPending {
            until: T + 10 + DAY
        }
    );
    r.note_card(&card, b"", T).unwrap();
    assert_eq!(
        r.store.identity(&old.public()).unwrap().unwrap().commitment,
        None
    );
    // The owner's way out, §8.2: a freeze cancels the thief's rotation,
    // and once it is lifted the owner's rotation is the one that waits.
    r.freeze(&fp, true, T + 30).unwrap();
    r.freeze(&fp, false, T + 40).unwrap();
    assert!(matches!(
        r.post_record(&rotation(&old, &owners, None, T + 50), addr(1), T + 50),
        Ok(Posted::Pending { .. })
    ));
    assert!(matches!(
        r.post_record(&stolen, addr(1), T + 60),
        Err(Refusal::RotationPending { .. })
    ));
    let to = owners.fingerprint().0;
    r.publish_pending(&fp, &to, T + 70).unwrap();
    assert_eq!(
        r.lookup_handle("alice", addr(1), T + 70)
            .unwrap()
            .unwrap()
            .identity,
        owners.public()
    );
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
        next: None,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, addr(1), T).unwrap();
    // The first thing to look after the delay publishes it.
    let recs = records_of(&r, &new, T + DAY);
    assert!(matches!(&recs[..], [Record::Rotate(_)]));
    assert!(matches!(
        r.post_record(&rot, addr(1), T + DAY + 1).unwrap(),
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
        next: None,
    }
    .sign(&old, &new)
    .unwrap();
    r.post_record(&rot, addr(1), T).unwrap();
    // While it waits, the successor revokes itself.
    let gone = IdentityRevocation {
        identity: new.public(),
        time: T + 10,
        reason: None,
    }
    .sign(&new)
    .unwrap();
    r.post_record(&gone, addr(1), T + 10).unwrap();
    // Past the delay the rotation is dropped, and the name stays where
    // it can still be renewed.
    assert!(records_of(&r, &old, T + DAY).is_empty());
    let found = r.lookup_handle("alice", addr(1), T + DAY).unwrap().unwrap();
    assert_eq!(found.identity, old.public());
    assert!(register(&r, &old, "alice", T + DAY).unwrap().reissued);

    // Likewise a successor rotating on to a key of its own, refused
    // while that rotation waits.
    let r = registrar_with(|c| c.rotation_delay = DAY);
    register(&r, &old, "alice", T).unwrap();
    register(&r, &new, "bobby", T).unwrap();
    let on = Rotation {
        identity: new.public(),
        successor: other.public(),
        time: T,
        next: None,
    }
    .sign(&new, &other)
    .unwrap();
    r.post_record(&on, addr(1), T).unwrap();
    let rot = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: T + 10,
        next: None,
    }
    .sign(&old, &new)
    .unwrap();
    assert_eq!(
        r.post_record(&rot, addr(1), T + 10).unwrap_err(),
        Refusal::BadRequest("the successor key has a rotation of its own pending".into())
    );
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

    // And one the successor's holder rotates on after the owner's was
    // posted: the owner's is dropped when it comes due.
    let r = registrar_with(|c| c.rotation_delay = DAY);
    register(&r, &old, "alice", T).unwrap();
    r.post_record(&rotation(&old, &new, None, T), addr(1), T)
        .unwrap();
    register(&r, &new, "bobby", T + 5).unwrap();
    r.post_record(&rotation(&new, &other, None, T + 10), addr(1), T + 10)
        .unwrap();
    assert!(records_of(&r, &old, T + DAY).is_empty());
    assert_eq!(r.store.pending(&old.public()).unwrap(), None);
    assert_eq!(
        r.lookup_handle("alice", addr(1), T + DAY)
            .unwrap()
            .unwrap()
            .identity,
        old.public()
    );
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
    fn latest_record(
        &self,
        key: &Key,
        kind: RecordKind,
    ) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        self.inner.latest_record(key, kind)
    }
    fn set_commitment(&self, key: &Key, commitment: &[u8; 32]) -> Result<bool, StoreError> {
        self.inner.set_commitment(key, commitment)
    }
    fn card(&self, key: &Key) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        self.inner.card(key)
    }
    fn set_card(&self, key: &Key, updated: u64, bytes: &[u8]) -> Result<bool, StoreError> {
        self.inner.set_card(key, updated, bytes)
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
    fn envelope(&self, identity: &Key, kind: u8) -> Result<Option<EnvelopeRow>, StoreError> {
        self.inner.envelope(identity, kind)
    }
    fn last_put(&self, identity: &Key, kind: u8) -> Result<Option<u64>, StoreError> {
        self.inner.last_put(identity, kind)
    }
    fn put_envelope(&self, row: &EnvelopeRow) -> Result<(), StoreError> {
        self.inner.put_envelope(row)
    }
    fn delete_envelope(&self, identity: &Key, kind: u8, at: u64) -> Result<(), StoreError> {
        self.inner.delete_envelope(identity, kind, at)
    }
    fn envelope_guesses(&self, identity: &Key, kind: u8) -> Result<Lockout, StoreError> {
        self.inner.envelope_guesses(identity, kind)
    }
    fn set_envelope_guesses(
        &self,
        identity: &Key,
        kind: u8,
        l: &Lockout,
    ) -> Result<(), StoreError> {
        self.inner.set_envelope_guesses(identity, kind, l)
    }
    fn lockout_slot(&self, slot: u32) -> Result<Option<([u8; 32], Lockout)>, StoreError> {
        self.inner.lockout_slot(slot)
    }
    fn set_lockout_slot(&self, slot: u32, tag: &[u8; 32], l: &Lockout) -> Result<(), StoreError> {
        self.inner.set_lockout_slot(slot, tag, l)
    }
    fn unlock_epoch(&self, handle: &str, kind: u8) -> Result<u64, StoreError> {
        self.inner.unlock_epoch(handle, kind)
    }
    fn bump_unlock_epoch(&self, handle: &str, kind: u8) -> Result<(), StoreError> {
        self.inner.bump_unlock_epoch(handle, kind)
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

// --- §9 envelopes ------------------------------------------------------------

const SECRET: [u8; 32] = [9; 32];

fn backups_with(store: Arc<MemoryStore>, f: impl FnOnce(&mut Config)) -> Registrar {
    let mut cfg = Config::new(HOST);
    cfg.signup = Signup::Open;
    cfg.level = 0;
    f(&mut cfg);
    Registrar::new(cfg, reg_key(), store).with_envelopes(Envelopes {
        max: 1024,
        secret: SECRET,
    })
}

fn backups_on(store: Arc<MemoryStore>) -> Registrar {
    backups_with(store, |_| {})
}

fn backups() -> Registrar {
    backups_on(Arc::new(MemoryStore::new()))
}

fn put(r: &Registrar, who: &IdentityKey, secret: &Secret, now: u64) -> Keys {
    let (env, keys) = KeyEnvelope::seal(who, secret).unwrap();
    let bytes = EnvelopePut::store(who, HOST, now, &env, &keys).unwrap();
    assert_eq!(r.put_envelope(&bytes, now), Ok(Stored::Stored));
    keys
}

/// A fetch from `from`, opened as a device opens it.
fn restore_from(
    r: &Registrar,
    handle: &str,
    kind: u64,
    keys: &Keys,
    from: IpAddr,
    now: u64,
) -> Result<IdentityKey, Refusal> {
    let (identity, bytes) = r.fetch_envelope(handle, kind, keys.auth(), from, now)?;
    Ok(KeyEnvelope::parse(&bytes)
        .unwrap()
        .open(&identity, keys)
        .unwrap())
}

fn restore(
    r: &Registrar,
    handle: &str,
    kind: u64,
    keys: &Keys,
    now: u64,
) -> Result<IdentityKey, Refusal> {
    restore_from(r, handle, kind, keys, addr(1), now)
}

fn salt(r: &Registrar, handle: &str, kind: u64, now: u64) -> Kdf {
    Kdf::parse(&r.envelope_params(handle, kind, addr(1), now).unwrap()).unwrap()
}

#[test]
fn an_envelope_is_put_found_by_its_salt_fetched_replaced_and_deleted() {
    let r = backups();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let keys = put(&r, &alice, &Secret::Passphrase("correct horse"), T);
    let stored = r.store.envelope(&alice.public(), 1).unwrap().unwrap();
    assert_eq!(
        salt(&r, "Alice", 1, T),
        KeyEnvelope::parse(&stored.bytes).unwrap().kdf
    );
    assert_eq!(
        restore(&r, "Alice", 1, &keys, T).unwrap().public(),
        alice.public()
    );

    // A replacement is under a fresh salt, so the old key fetches nothing.
    let again = put(&r, &alice, &Secret::Passphrase("correct horse"), T + 1);
    assert_eq!(
        restore(&r, "alice", 1, &keys, T + 1).err(),
        Some(Refusal::NotFound)
    );
    assert!(restore(&r, "alice", 1, &again, T + 1).is_ok());

    let delete = EnvelopePut::delete(&alice, HOST, EnvelopeKind::Passphrase, T + 2).unwrap();
    assert_eq!(r.put_envelope(&delete, T + 2), Ok(Stored::Deleted));
    assert_eq!(
        restore(&r, "alice", 1, &again, T + 2).err(),
        Some(Refusal::NotFound)
    );
    assert_eq!(
        salt(&r, "alice", 1, T + 2),
        Kdf::decoy(&SECRET, "alice", EnvelopeKind::Passphrase)
    );
}

#[test]
fn every_miss_is_one_answer_and_every_salt_without_an_envelope_a_decoy() {
    let r = backups();
    let (alice, bob) = (id(1), id(2));
    register(&r, &alice, "alice", T).unwrap();
    register(&r, &bob, "bobby", T).unwrap();
    let keys = put(&r, &alice, &Secret::Passphrase("correct horse"), T);
    let bobs = put(&r, &bob, &Secret::Passphrase("battery staple"), T);
    r.freeze(&bob.fingerprint().0, true, T).unwrap();
    for (case, handle, kind, auth) in [
        ("no such handle", "carol", 1, *keys.auth()),
        ("no envelope of the kind", "alice", 2, *keys.auth()),
        ("the wrong key", "alice", 1, [0; 32]),
        ("frozen", "bobby", 1, *bobs.auth()),
    ] {
        assert_eq!(
            r.fetch_envelope(handle, kind, &auth, addr(1), T),
            Err(Refusal::NotFound),
            "{case}"
        );
    }
    for (handle, kind) in [("carol", 1), ("alice", 2), ("bobby", 1)] {
        let k = envelope_kind(kind).unwrap();
        assert_eq!(salt(&r, handle, kind, T), Kdf::decoy(&SECRET, handle, k));
    }
}

#[test]
fn an_envelope_is_fetched_for_a_handle_lapsed_within_its_hold() {
    let r = backups();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let keys = put(&r, &alice, &Secret::Passphrase("correct horse"), T);
    let lapsed = T + 400 * DAY;
    assert_eq!(
        r.store
            .handle("alice")
            .unwrap()
            .unwrap()
            .state(lapsed, 365 * DAY),
        HandleState::Lapsed
    );
    assert!(restore(&r, "alice", 1, &keys, lapsed).is_ok());
}

#[test]
fn a_put_is_this_registrars_from_an_attested_unfrozen_identity_and_newer() {
    let r = backups();
    let (alice, stranger) = (id(1), id(2));
    register(&r, &alice, "alice", T).unwrap();
    let (env, keys) = KeyEnvelope::seal(&alice, &Secret::Passphrase("p")).unwrap();
    let to = |who: &IdentityKey, host: &str, time: u64| {
        EnvelopePut::store(who, host, time, &env, &keys).unwrap()
    };
    assert!(matches!(
        r.put_envelope(&to(&alice, "elsewhere.example", T), T),
        Err(Refusal::BadRequest(_))
    ));
    assert_eq!(
        r.put_envelope(&to(&alice, HOST, T - 301), T),
        Err(Refusal::BadTime)
    );
    let (s_env, s_keys) = KeyEnvelope::seal(&stranger, &Secret::Passphrase("p")).unwrap();
    let theirs = EnvelopePut::store(&stranger, HOST, T, &s_env, &s_keys).unwrap();
    assert_eq!(r.put_envelope(&theirs, T), Err(Refusal::NotRegistered));
    let small = registrar().with_envelopes(Envelopes {
        max: 64,
        secret: SECRET,
    });
    register(&small, &alice, "alice", T).unwrap();
    assert_eq!(
        small.put_envelope(&to(&alice, HOST, T), T),
        Err(Refusal::TooLarge)
    );
    r.freeze(&alice.fingerprint().0, true, T).unwrap();
    assert_eq!(
        r.put_envelope(&to(&alice, HOST, T), T),
        Err(Refusal::Frozen)
    );
}

#[test]
fn a_put_no_newer_than_the_last_is_refused_even_after_a_restart() {
    let store = Arc::new(MemoryStore::new());
    let r = backups_on(store.clone());
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let (old, old_keys) = KeyEnvelope::seal(&alice, &Secret::Passphrase("old")).unwrap();
    let first = EnvelopePut::store(&alice, HOST, T, &old, &old_keys).unwrap();
    assert_eq!(r.put_envelope(&first, T), Ok(Stored::Stored));
    assert_eq!(r.put_envelope(&first, T), Err(Refusal::BadTime), "a replay");
    let new = put(&r, &alice, &Secret::Passphrase("new"), T + 2);
    let between = EnvelopePut::delete(&alice, HOST, EnvelopeKind::Passphrase, T + 1).unwrap();
    assert_eq!(r.put_envelope(&between, T + 3), Err(Refusal::BadTime));
    let restarted = backups_on(store);
    assert_eq!(restarted.put_envelope(&first, T + 3), Err(Refusal::BadTime));
    assert!(restore(&restarted, "alice", 1, &new, T + 3).is_ok());
}

#[test]
fn puts_are_limited_per_identity() {
    let r = backups();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let delete = |t| EnvelopePut::delete(&alice, HOST, EnvelopeKind::Passphrase, t).unwrap();
    for i in 0..20 {
        assert_eq!(r.put_envelope(&delete(T + i), T + i), Ok(Stored::Deleted));
    }
    assert!(matches!(
        r.put_envelope(&delete(T + 20), T + 20),
        Err(Refusal::RateLimited { .. })
    ));
}

#[test]
fn one_address_guessing_at_a_handle_is_locked_out_longer_each_time_and_its_owner_is_not() {
    let store = Arc::new(MemoryStore::new());
    let r = backups_on(store.clone());
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let keys = put(&r, &alice, &Secret::Passphrase("correct horse"), T);
    // A handle with an envelope and one without are locked out alike, and
    // a handle is one whatever its case.
    for (handle, guesser) in [("alice", addr(1)), ("nobody", addr(3))] {
        let mut now = T;
        for (round, lock) in [(0, 3600), (1, 7200)] {
            for i in 0..10 {
                let asked = if i % 2 == 0 {
                    handle.to_ascii_uppercase()
                } else {
                    handle.to_owned()
                };
                assert_eq!(
                    r.fetch_envelope(&asked, 1, &[0; 32], guesser, now),
                    Err(Refusal::NotFound),
                    "{handle} fetch {i} of round {round}"
                );
            }
            assert_eq!(
                r.fetch_envelope(handle, 1, keys.auth(), guesser, now),
                Err(Refusal::RateLimited { retry_after: lock }),
                "{handle} round {round}"
            );
            // A new process over the same store has not forgotten.
            let restarted = backups_on(store.clone());
            assert_eq!(
                restarted.fetch_envelope(handle, 1, keys.auth(), guesser, now + lock - 1),
                Err(Refusal::RateLimited { retry_after: 1 })
            );
            now += lock;
        }
    }
    // The owner, from anywhere else, and the other kind from the guesser,
    // are counted apart.
    assert!(restore_from(&r, "alice", 1, &keys, addr(2), T).is_ok());
    assert_eq!(
        r.fetch_envelope("alice", 2, &[0; 32], addr(1), T),
        Err(Refusal::NotFound)
    );
    // The operator's unlock forgets the guesser's lockout too.
    r.unlock("alice", &[1]).unwrap();
    assert!(restore_from(&r, "alice", 1, &keys, addr(1), T + 3600 + 1).is_ok());
}

#[test]
fn guesses_from_everywhere_stop_at_the_daily_ceiling_until_unlocked() {
    let r = backups_with(Arc::new(MemoryStore::new()), |c| {
        c.rates.envelope_fetches_per_handle_daily = 5
    });
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let keys = put(&r, &alice, &Secret::Passphrase("correct horse"), T);
    for handle in ["alice", "nobody"] {
        for i in 0..5 {
            assert_eq!(
                r.fetch_envelope(handle, 1, &[0; 32], addr(10 + i), T),
                Err(Refusal::NotFound),
                "{handle} from address {i}"
            );
        }
        assert_eq!(
            r.fetch_envelope(handle, 1, keys.auth(), addr(20), T + 10),
            Err(Refusal::RateLimited {
                retry_after: DAY - 10
            }),
            "{handle}"
        );
    }
    assert!(restore_from(&r, "alice", 1, &keys, addr(20), T + DAY).is_ok());
    for i in 0..4 {
        let _ = r.fetch_envelope("alice", 1, &[0; 32], addr(30 + i), T + DAY);
    }
    assert!(restore_from(&r, "alice", 1, &keys, addr(20), T + DAY).is_err());
    r.unlock("Alice", &[1, 2]).unwrap();
    assert!(restore_from(&r, "alice", 1, &keys, addr(20), T + DAY).is_ok());
}

#[test]
fn fetches_are_limited_per_address_its_ipv6_64_and_its_48() {
    let v6 = |net: u16, sub: u16, host: u16| {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, net, sub, 0, 0, 0, host))
    };
    let mapped = |n: u8| IpAddr::V6(Ipv4Addr::new(192, 0, 2, n).to_ipv6_mapped());
    // Thirty fetches from inside one counted prefix, and one from outside.
    let cases = [
        ("an IPv4 address", vec![addr(1); 30], addr(2)),
        // Within the /64, the host part changes nothing.
        (
            "an IPv6 /64",
            (0..30).map(|i| v6(1, 1, i)).collect(),
            v6(1, 2, 1),
        ),
        // One IPv4-mapped address is not every other's /64.
        ("an IPv4-mapped address", vec![mapped(1); 30], mapped(2)),
    ];
    for (case, inside, other) in cases {
        let r = backups();
        let same = inside[0];
        for (i, &from) in inside.iter().enumerate() {
            assert_eq!(
                r.fetch_envelope(&format!("user{i}"), 1, &[0; 32], from, T),
                Err(Refusal::NotFound),
                "{case} {i}"
            );
        }
        assert!(
            matches!(
                r.fetch_envelope("user99", 1, &[0; 32], same, T),
                Err(Refusal::RateLimited { .. })
            ),
            "{case}"
        );
        assert_eq!(
            r.fetch_envelope("user99", 1, &[0; 32], other, T),
            Err(Refusal::NotFound),
            "{case}"
        );
    }
    let r = backups();
    for i in 0..30 * FETCHES_PER_48 {
        assert_eq!(
            r.fetch_envelope(&format!("user{i}"), 1, &[0; 32], v6(1, i as u16, 1), T),
            Err(Refusal::NotFound)
        );
    }
    assert!(matches!(
        r.fetch_envelope("user", 1, &[0; 32], v6(1, 9999, 1), T),
        Err(Refusal::RateLimited { .. })
    ));
    assert_eq!(
        r.fetch_envelope("user", 1, &[0; 32], v6(2, 1, 1), T),
        Err(Refusal::NotFound)
    );
}

#[test]
fn a_flood_of_fetches_leaves_registrations_lookups_and_new_fetchers_their_room() {
    let r = backups();
    for i in 0..MAX_WINDOWS as u32 + 1 {
        let from = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        let _ = r.fetch_envelope(&format!("user{i}"), 1, &[0; 32], from, T);
    }
    let alice = id(1);
    let bytes = request(&alice, "alice", T).sign(&alice).unwrap();
    let fresh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    assert!(r.register(&bytes, fresh, T).is_ok());
    assert!(r.lookup_handle("alice", fresh, T).is_ok());
    // Nor are fetches refused to an address the flood never used.
    assert_eq!(
        r.fetch_envelope("alice", 1, &[0; 32], fresh, T),
        Err(Refusal::NotFound)
    );
}

#[test]
fn revocation_and_rotation_take_the_envelopes_with_them() {
    let r = backups();
    let (alice, bob, bob2) = (id(1), id(2), id(12));
    register(&r, &alice, "alice", T).unwrap();
    register(&r, &bob, "bobby", T).unwrap();
    put(&r, &alice, &Secret::Passphrase("p"), T);
    put(
        &r,
        &alice,
        &Secret::RecoveryCode(&RecoveryCode::generate()),
        T,
    );
    put(&r, &bob, &Secret::Passphrase("p"), T);
    let revoke = IdentityRevocation {
        identity: alice.public(),
        time: T + 1,
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    r.post_record(&revoke, addr(1), T + 1).unwrap();
    let rotate = Rotation {
        identity: bob.public(),
        successor: bob2.public(),
        time: T + 1,
        next: None,
    }
    .sign(&bob, &bob2)
    .unwrap();
    r.post_record(&rotate, addr(1), T + 1).unwrap();
    for (who, kind) in [(&alice, 1), (&alice, 2), (&bob, 1)] {
        assert_eq!(r.store.envelope(&who.public(), kind).unwrap(), None);
    }
}

#[test]
fn a_rotation_that_came_due_is_published_by_a_salt_lookup_or_a_fetch() {
    for by_fetch in [false, true] {
        let r = backups_with(Arc::new(MemoryStore::new()), |c| c.rotation_delay = DAY);
        let (bob, bob2) = (id(2), id(12));
        register(&r, &bob, "bobby", T).unwrap();
        let keys = put(&r, &bob, &Secret::Passphrase("p"), T);
        let rotate = Rotation {
            identity: bob.public(),
            successor: bob2.public(),
            time: T + 1,
            next: None,
        }
        .sign(&bob, &bob2)
        .unwrap();
        r.post_record(&rotate, addr(1), T + 1).unwrap();
        let due = T + 1 + DAY;
        if by_fetch {
            assert_eq!(
                r.fetch_envelope("bobby", 1, keys.auth(), addr(1), due),
                Err(Refusal::NotFound)
            );
        } else {
            assert_eq!(
                salt(&r, "bobby", 1, due),
                Kdf::decoy(&SECRET, "bobby", EnvelopeKind::Passphrase)
            );
        }
        assert_eq!(r.store.envelope(&bob.public(), 1).unwrap(), None);
    }
}

#[test]
fn a_registrar_without_envelopes_answers_as_if_the_endpoint_were_not_there() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let delete = EnvelopePut::delete(&alice, HOST, EnvelopeKind::Passphrase, T).unwrap();
    assert_eq!(r.put_envelope(&delete, T), Err(Refusal::NotFound));
    assert_eq!(
        r.envelope_params("alice", 1, addr(1), T),
        Err(Refusal::NotFound)
    );
    assert_eq!(
        r.fetch_envelope("alice", 1, &[0; 32], addr(1), T),
        Err(Refusal::NotFound)
    );
}

// --- device epochs (§4.10, §6.2) -------------------------------------------

fn reset(who: &IdentityKey, epoch: u64, time: u64) -> Vec<u8> {
    DeviceEpoch {
        identity: who.public(),
        epoch,
        time,
    }
    .sign(who)
    .unwrap()
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What an answer says of where the identity stands: `epoch` and `hash`.
fn stands(p: Posted) -> (u64, [u8; 32]) {
    match p {
        Posted::DeviceEpoch { epoch, hash, .. } => (epoch, hash),
        other => panic!("not a device epoch's answer: {other:?}"),
    }
}

/// The epochs of the device epoch records in the full list.
fn full_epochs(r: &Registrar, now: u64) -> Vec<u64> {
    let k = keys(r);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    SignedList::parse(&r.records_since(None, now).unwrap(), ListKind::Records, rk)
        .unwrap()
        .entries
        .iter()
        .filter_map(|(_, b)| match Record::parse(b, Some(rk)).unwrap() {
            Record::DeviceEpoch(e) => Some(e.epoch),
            _ => None,
        })
        .collect()
}

fn own_epochs(r: &Registrar, who: &IdentityKey, now: u64) -> Vec<u64> {
    records_of(r, who, now)
        .into_iter()
        .filter_map(|rec| match rec {
            Record::DeviceEpoch(e) => Some(e.epoch),
            _ => None,
        })
        .collect()
}

#[test]
fn a_reset_moves_the_floor_at_most_sixteen_at_a_time() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let one = reset(&alice, 1, T);
    let Posted::DeviceEpoch {
        seq,
        epoch,
        hash: h,
    } = r.post_record(&one, addr(1), T).unwrap()
    else {
        panic!("a device epoch is answered as one")
    };
    assert_eq!((epoch, h), (1, hash(&one)));
    assert_eq!(own_epochs(&r, &alice, T), vec![1]);
    assert!(seq > 0);

    let far = reset(&alice, 1 + EPOCH_STEP_MAX + 1, T + 1);
    assert!(matches!(
        r.post_record(&far, addr(1), T + 1),
        Err(Refusal::BadRequest(why)) if why.contains("at most 16")
    ));
    let jump = reset(&alice, 1 + EPOCH_STEP_MAX, T + 1);
    assert_eq!(
        stands(r.post_record(&jump, addr(1), T + 1).unwrap()),
        (17, hash(&jump))
    );
}

#[test]
fn a_retry_of_either_kind_is_answered_where_the_identity_stands() {
    let r = registrar_with(|c| c.rates.records_per_identity = 2);
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let two = reset(&alice, 2, T);
    let Posted::DeviceEpoch { seq, .. } = r.post_record(&two, addr(1), T).unwrap() else {
        panic!("published")
    };
    // A revocation spends the identity's last record post: what follows
    // is answered all the same, since it stores nothing.
    let rev = DeviceRevocation {
        identity: alice.public(),
        device: [9; 32],
        time: T,
        until: T + DAY,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    r.post_record(&rev, addr(1), T).unwrap();
    let done = Posted::DeviceEpoch {
        seq,
        epoch: 2,
        hash: hash(&two),
    };
    for (what, bytes) in [
        ("the exact bytes", two.clone()),
        ("signed afresh", reset(&alice, 2, T + 5)),
        ("a lower epoch", reset(&alice, 1, T + 6)),
    ] {
        assert_eq!(r.post_record(&bytes, addr(1), T + 10), Ok(done), "{what}");
    }
    assert!(matches!(
        r.post_record(&reset(&alice, 3, T + 10), addr(1), T + 10),
        Err(Refusal::RateLimited { .. })
    ));

    // A superseded record's bytes are answered with the current one.
    let r = registrar();
    register(&r, &alice, "alice", T).unwrap();
    let one = reset(&alice, 1, T);
    r.post_record(&one, addr(1), T).unwrap();
    let three = reset(&alice, 3, T + 1);
    let Posted::DeviceEpoch { seq: current, .. } = r.post_record(&three, addr(1), T + 1).unwrap()
    else {
        panic!("published")
    };
    assert_eq!(
        r.post_record(&one, addr(1), T + 2),
        Ok(Posted::DeviceEpoch {
            seq: current,
            epoch: 3,
            hash: hash(&three),
        })
    );
}

#[test]
fn the_answers_that_store_nothing_are_counted_as_lookups() {
    let alice = id(1);
    let revocation = DeviceRevocation {
        identity: alice.public(),
        device: [9; 32],
        time: T,
        until: T + DAY,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    // Each record published, then posted again: the first repeat is the
    // address's one lookup, and every answer after it is refused.
    for (what, record, again) in [
        (
            "a reset",
            reset(&alice, 1, T),
            vec![reset(&alice, 1, T + 1)],
        ),
        ("a device revocation", revocation, vec![]),
        ("a rotation", rotation(&alice, &id(2), None, T), vec![]),
    ] {
        let r = registrar_with(|c| c.rates.lookups_per_address = 1);
        register(&r, &alice, "alice", T).unwrap();
        r.post_record(&record, addr(1), T).unwrap();
        r.post_record(&record, addr(1), T).unwrap();
        for bytes in std::iter::once(record.clone()).chain(again) {
            assert!(
                matches!(
                    r.post_record(&bytes, addr(1), T + 1),
                    Err(Refusal::RateLimited { .. })
                ),
                "{what}"
            );
        }
        assert!(r.post_record(&record, addr(2), T + 1).is_ok(), "{what}");
    }
    // One that publishes is a record post, not a lookup.
    let r = registrar_with(|c| c.rates.lookups_per_address = 1);
    register(&r, &alice, "alice", T).unwrap();
    let one = reset(&alice, 1, T);
    r.post_record(&one, addr(1), T).unwrap();
    r.post_record(&one, addr(1), T).unwrap();
    assert!(r
        .post_record(&reset(&alice, 2, T + 1), addr(1), T + 1)
        .is_ok());
}

#[test]
fn held_bytes_are_answered_whatever_has_become_of_the_identity() {
    let alice = id(1);
    let revocation = DeviceRevocation {
        identity: alice.public(),
        device: [9; 32],
        time: T,
        until: T + DAY,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    let one = reset(&alice, 1, T);
    for what in ["frozen", "revoked"] {
        let r = registrar();
        register(&r, &alice, "alice", T).unwrap();
        let Posted::Published { seq } = r.post_record(&revocation, addr(1), T).unwrap() else {
            panic!("published")
        };
        let done = r.post_record(&one, addr(1), T).unwrap();
        match what {
            "frozen" => {
                r.freeze(&alice.fingerprint().0, true, T + 1).unwrap();
            }
            _ => {
                let gone = IdentityRevocation {
                    identity: alice.public(),
                    time: T + 1,
                    reason: None,
                }
                .sign(&alice)
                .unwrap();
                r.post_record(&gone, addr(1), T + 1).unwrap();
            }
        }
        assert_eq!(
            r.post_record(&revocation, addr(1), T + 2),
            Ok(Posted::Published { seq }),
            "{what}"
        );
        assert_eq!(r.post_record(&one, addr(1), T + 2), Ok(done), "{what}");
    }
}

#[test]
fn four_resets_publish_in_a_day() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    for epoch in 1..=EPOCHS_PER_DAY as u64 {
        r.post_record(&reset(&alice, epoch, T), addr(1), T).unwrap();
        // A retry between them spends none of the day's.
        r.post_record(&reset(&alice, epoch, T + 1), addr(1), T + 1)
            .unwrap();
    }
    let Err(Refusal::RateLimited { retry_after }) =
        r.post_record(&reset(&alice, 5, T + 2), addr(1), T + 2)
    else {
        panic!("a fifth reset in a day is refused")
    };
    assert_eq!(retry_after, DAY - 2);
    assert_eq!(
        stands(
            r.post_record(&reset(&alice, 5, T + DAY), addr(1), T + DAY)
                .unwrap()
        )
        .0,
        5
    );
}

#[test]
fn a_reset_dated_before_the_last_is_refused() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    r.post_record(&reset(&alice, 1, T + 100), addr(1), T + 100)
        .unwrap();
    assert!(matches!(
        r.post_record(&reset(&alice, 2, T + 99), addr(1), T + 200),
        Err(Refusal::BadRequest(why)) if why.contains("not dated before")
    ));
    // The same time is not earlier, and one long past the last is fine
    // so long as it is not before it.
    assert_eq!(
        stands(
            r.post_record(&reset(&alice, 2, T + 100), addr(1), T + 200)
                .unwrap()
        )
        .0,
        2
    );
}

#[test]
fn a_reset_is_refused_as_any_record_is() {
    let r = registrar();
    let alice = id(1);
    assert_eq!(
        r.post_record(&reset(&alice, 1, T), addr(1), T),
        Err(Refusal::NotRegistered)
    );
    register(&r, &alice, "alice", T).unwrap();
    assert_eq!(
        r.post_record(&reset(&alice, 1, T + 1000), addr(1), T),
        Err(Refusal::BadTime)
    );
    // Signed by any key but the identity's, as a device's would be.
    use hl_identity::cbor::{self, Value};
    let sig = |v: &Value| v.get("sig").cloned().unwrap();
    let theirs = sig(&cbor::decode_canonical(&reset(&id(7), 1, T)).unwrap());
    let mut forged = cbor::decode_canonical(&reset(&alice, 1, T)).unwrap();
    if let Value::Map(entries) = &mut forged {
        for (k, val) in entries.iter_mut() {
            if k == &Value::Text("sig".into()) {
                *val = theirs.clone();
            }
        }
    }
    let forged = cbor::encode(&forged);
    assert_eq!(
        r.post_record(&forged, addr(1), T),
        Err(Refusal::BadSignature)
    );
    r.freeze(&alice.fingerprint().0, true, T + 1).unwrap();
    assert_eq!(
        r.post_record(&reset(&alice, 1, T + 2), addr(1), T + 2),
        Err(Refusal::Frozen)
    );
    assert_eq!(own_epochs(&r, &alice, T + 2), Vec::<u64>::new());
}

#[test]
fn a_superseded_reset_leaves_the_full_list_and_stays_in_its_own() {
    let r = registrar();
    let (alice, bob) = (id(1), id(2));
    register(&r, &alice, "alice", T).unwrap();
    register(&r, &bob, "bob", T).unwrap();
    r.post_record(&reset(&alice, 1, T), addr(1), T).unwrap();
    r.post_record(&reset(&bob, 4, T), addr(1), T).unwrap();
    assert_eq!(full_epochs(&r, T), vec![1, 4]);
    r.post_record(&reset(&alice, 2, T + 1), addr(1), T + 1)
        .unwrap();
    assert_eq!(full_epochs(&r, T + 1), vec![4, 2]);
    assert_eq!(own_epochs(&r, &alice, T + 1), vec![1, 2]);
}

#[test]
fn a_registrar_behind_is_caught_up_by_the_next_reset() {
    let (a, b) = (registrar(), registrar());
    let alice = id(1);
    register(&a, &alice, "alice", T).unwrap();
    register(&b, &alice, "alice", T).unwrap();
    // The reset to 1 reached `a` alone.
    a.post_record(&reset(&alice, 1, T), addr(1), T).unwrap();
    for r in [&a, &b] {
        let two = reset(&alice, 2, T + 1);
        assert_eq!(
            stands(r.post_record(&two, addr(1), T + 1).unwrap()),
            (2, hash(&two))
        );
        assert_eq!(full_epochs(r, T + 1), vec![2]);
    }
}

#[test]
fn a_device_reset_away_signs_no_revocation() {
    let r = registrar();
    let alice = id(1);
    register(&r, &alice, "alice", T).unwrap();
    let old = DeviceKey::from_seed(&[2; 32]);
    let old_cert = DeviceCert::for_device(&alice, &old, T - 10, 30 * DAY)
        .unwrap()
        .sign(&alice);
    let revoke = |device: u8, time: u64, signer: &DeviceKey, cert: Vec<u8>| {
        DeviceRevocation {
            identity: alice.public(),
            device: [device; 32],
            time,
            until: time + DAY,
            reason: None,
            signer: None,
            signer_cert: None,
        }
        .sign_as_device(signer, cert)
        .unwrap()
    };
    let before = revoke(8, T, &old, old_cert.clone());
    r.post_record(&before, addr(1), T).unwrap();

    r.post_record(&reset(&alice, 1, T + 1), addr(1), T + 1)
        .unwrap();
    // Dated inside its certificate's window, and refused all the same.
    let after = revoke(9, T + 2, &old, old_cert);
    let refused = r.post_record(&after, addr(1), T + 2).unwrap_err();
    assert_eq!(refused, Refusal::SignerReset);
    assert_eq!(refused.code(), "bad_signature");
    // Its exact bytes, published before the reset, are no longer taken.
    assert_eq!(
        r.post_record(&before, addr(1), T + 2),
        Err(Refusal::SignerReset)
    );
    assert!(records_of(&r, &alice, T + 2)
        .iter()
        .any(|rec| matches!(rec, Record::RevokeDevice(d) if d.device == [8; 32])));

    // A device certified at the floor, and the identity itself, may.
    let new = DeviceKey::from_seed(&[3; 32]);
    let mut fresh = DeviceCert::for_device(&alice, &new, T, 30 * DAY).unwrap();
    fresh.epoch = 1;
    assert!(r
        .post_record(&revoke(9, T + 2, &new, fresh.sign(&alice)), addr(1), T + 2)
        .is_ok());
    let by_identity = DeviceRevocation {
        identity: alice.public(),
        device: old.public(),
        time: T + 3,
        until: T + DAY,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    assert!(r.post_record(&by_identity, addr(1), T + 3).is_ok());
}
