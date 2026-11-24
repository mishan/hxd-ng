//! A suite every [`RelationshipStore`] must pass, for the reason
//! [`crate::inbox::conformance`] gives: the in-memory store and SQLite's
//! must agree exactly, and above all about which mailbox a row is
//! keyed by, where a disagreement is a block that stopped applying.
//!
//! Clocks are fixed values, never `SystemTime::now()`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    AccountUpdate, Birthdate, Ending, HeldWithdrawal, Ignore, IgnoreMode, LedgerEntry,
    MessagingAccount, PendingOut, Presentation, Profile, Recorded, RelationshipStore, RequestKind,
    Requester, StoredOffer,
};
use crate::inbox::{Mailbox, MessageGuid, Sent};

/// Run every case against a freshly built store.
pub fn run(new_store: &dyn Fn() -> Box<dyn RelationshipStore>) {
    blocks_are_directional_and_idempotent(&*new_store());
    blocks_follow_an_identity_and_are_listed(&*new_store());
    a_merge_leaves_one_block_per_pair(&*new_store());
    a_claim_folds_two_rows_for_one_pair_into_the_older_claim(&*new_store());
    a_rename_keeps_an_identitys_rows_and_frees_the_login(&*new_store());
    rotation_moves_everything_to_the_successor_key(&*new_store());
    rotating_onto_a_key_with_rows_folds_them(&*new_store());
    purging_takes_everything_naming_the_account(&*new_store());
    a_friendship_is_one_id_for_the_pair_and_never_reused(&*new_store());
    an_approval_is_its_approvers_alone(&*new_store());
    a_friendship_ends_the_pairs_approvals(&*new_store());
    an_alias_lives_only_beside_a_friendship_or_a_block(&*new_store());
    what_lapses_reads_as_gone_and_counts_for_nothing(&*new_store());
    a_hold_matches_either_key_and_lapses(&*new_store());
    request_addresses_lists_each_guest_address_once_within_its_span(&*new_store());
    the_guests_behind_an_address_are_counted_together(&*new_store());
    the_ledger_counts_what_was_sent_and_answers_a_retry(&*new_store());
    a_listing_takes_the_dropped_count(&*new_store());
    an_account_keeps_what_it_was_told_and_nothing_else(&*new_store());
    the_cleanup_changes_no_answer(&*new_store());
    times_are_kept_to_the_second(&*new_store());
    a_presentation_is_one_per_party_and_is_dropped_by_its_device(&*new_store());
    a_withdrawal_keeps_the_latest_cutoff_and_its_owners_newest(&*new_store());
    an_offer_lapses_and_a_refriend_keeps_the_id(&*new_store());
    rotation_moves_the_portable_part_and_purging_keeps_withdrawals(&*new_store());
    a_rotation_ends_an_edge_its_merge_leaves_without_evidence_both_ways(&*new_store());
    a_merge_carries_a_kept_edge_id_to_the_friendship_kept(&*new_store());
    claimable_finds_whatever_a_claim_moves(&*new_store());
    a_drop_ends_an_edge_only_where_it_had_evidence_both_ways(&*new_store());
    a_friendship_by_request_drops_the_presentations_named(&*new_store());
    ending_a_friendship_is_one_step(&*new_store());
    a_declined_upgrade_drops_its_offer_and_holds_in_one_step(&*new_store());
    a_friendship_an_acceptance_makes_is_one_step(&*new_store());
    a_reset_record_lapses_unless_an_offer_waits_on_it(&*new_store());
    a_lapsed_request_takes_its_offer_and_an_upgrade_is_taken_whole(&*new_store());
    a_request_takes_the_place_of_an_offer_an_earlier_one_left(&*new_store());
    cleanup_counts_the_offers_lapsed_requests_take(&*new_store());
    an_older_cutoff_kept_by_an_ending_still_holds_the_owner_to_its_cap(&*new_store());
    a_block_ends_the_requests_and_approvals_either_way(&*new_store());
}

fn presentation(presenter: u8, other: u8, hash: u8, device: u8) -> Presentation {
    Presentation {
        presenter: fp(presenter),
        other: fp(other),
        names: [fp(presenter), fp(other)],
        pair: [presenter ^ other; 32],
        hash: [hash; 32],
        friendship: Some(vec![hash; 3]),
        reset: None,
        device: [device; 32],
        edge: None,
        at: at(100 + u64::from(hash)),
        taken: at(50 + u64::from(hash)),
    }
}

fn withdrawal(owner: u8, pair: u8, before: u64, signed: bool, secs: u64) -> HeldWithdrawal {
    HeldWithdrawal {
        owner: fp(owner),
        pair: [pair; 32],
        party: fp(owner),
        before,
        withdrawal: signed.then(|| vec![pair, before as u8]),
        checked: true,
        at: at(secs),
    }
}

fn a_presentation_is_one_per_party_and_is_dropped_by_its_device(s: &dyn RelationshipStore) {
    let case = "a_presentation_is_one_per_party_and_is_dropped_by_its_device";
    let first = presentation(1, 2, 10, 7);
    assert_eq!(s.present(&first).unwrap(), None, "{case}: new");
    let again = Presentation {
        edge: Some(4),
        ..presentation(1, 2, 11, 8)
    };
    assert_eq!(s.present(&again).unwrap(), Some(first), "{case}: replaced");
    let theirs = Presentation {
        friendship: None,
        reset: Some(vec![12; 3]),
        ..presentation(2, 1, 12, 7)
    };
    s.present(&theirs).unwrap();
    assert_eq!(
        s.presentation(&fp(2), &fp(1)).unwrap(),
        Some(theirs),
        "{case}: a `Reset` record read back whole"
    );
    s.present(&presentation(1, 3, 13, 7)).unwrap();
    assert_eq!(
        s.presentation(&fp(1), &fp(2)).unwrap(),
        Some(again.clone()),
        "{case}: read back whole"
    );
    let hashes = |v: Vec<Presentation>| v.iter().map(|p| p.hash[0]).collect::<Vec<_>>();
    assert_eq!(
        hashes(s.presentations(&fp(2)).unwrap()),
        [11, 12],
        "{case}: made and naming"
    );
    assert_eq!(
        hashes(s.presented_by(&[7; 32]).unwrap()),
        [12, 13],
        "{case}: by device"
    );
    assert_eq!(
        s.unpresent(&fp(1), &fp(2)).unwrap(),
        Some(again),
        "{case}: dropped"
    );
    assert_eq!(s.unpresent(&fp(1), &fp(2)).unwrap(), None, "{case}: gone");
}

fn a_withdrawal_keeps_the_latest_cutoff_and_its_owners_newest(s: &dyn RelationshipStore) {
    let case = "a_withdrawal_keeps_the_latest_cutoff_and_its_owners_newest";
    s.keep_withdrawal(&withdrawal(1, 9, 50, true, 1), 3)
        .unwrap();
    s.keep_withdrawal(&withdrawal(1, 9, 40, true, 2), 3)
        .unwrap();
    let befores = |pair: u8| -> Vec<u64> {
        s.withdrawals(&[pair; 32])
            .unwrap()
            .iter()
            .map(|w| w.before)
            .collect()
    };
    assert_eq!(befores(9), [50], "{case}: an earlier cutoff ends less");
    s.keep_withdrawal(&withdrawal(1, 9, 60, true, 3), 3)
        .unwrap();
    assert_eq!(befores(9), [60], "{case}: a later one ends more");
    // The server's own is the last to go, past the owner's cap.
    s.keep_withdrawal(&withdrawal(1, 8, 5, false, 0), 3)
        .unwrap();
    s.keep_withdrawal(&withdrawal(1, 7, 5, true, 4), 3).unwrap();
    s.keep_withdrawal(&withdrawal(1, 6, 5, true, 5), 3).unwrap();
    assert!(
        befores(9).is_empty(),
        "{case}: the oldest signed went first"
    );
    assert_eq!(befores(8), [5], "{case}: the server's own kept");
    s.keep_withdrawal(&withdrawal(2, 5, 5, true, 0), 3).unwrap();
    assert_eq!(befores(7), [5], "{case}: another owner's counts apart");
    s.keep_withdrawal(&withdrawal(4, 3, 10, true, 1), 3)
        .unwrap();
    s.keep_withdrawal(&withdrawal(4, 3, 20, false, 2), 3)
        .unwrap();
    assert_eq!(
        befores(3),
        [10, 20],
        "{case}: a server's own beside a signed one for the pair"
    );

    let unchecked = HeldWithdrawal {
        checked: false,
        party: fp(4),
        ..withdrawal(3, 4, 5, true, 6)
    };
    s.keep_withdrawal(&unchecked, 3).unwrap();
    let pairs = |owner: u8| -> Vec<u8> {
        s.withdrawals_by(&fp(owner))
            .unwrap()
            .iter()
            .map(|w| w.pair[0])
            .collect()
    };
    assert_eq!(pairs(1), [8, 7, 6], "{case}: an owner's, in the order kept");
    s.drop_withdrawal(&fp(4), &[3; 32], &fp(4), &[3, 9])
        .unwrap();
    assert_eq!(befores(3), [10, 20], "{case}: other bytes drop nothing");
    s.drop_withdrawal(&fp(4), &[3; 32], &fp(4), &[3, 10])
        .unwrap();
    assert_eq!(befores(3), [20], "{case}: checked, dropped by its bytes");
    s.drop_withdrawal(&fp(3), &[4; 32], &fp(4), &[4, 5])
        .unwrap();
    assert!(befores(4).is_empty(), "{case}: unchecked, dropped");

    s.keep_withdrawal(&withdrawal(5, 7, 5, true, 1), 3).unwrap();
    s.keep_withdrawal(&withdrawal(5, 8, 5, true, 1), 3).unwrap();
    s.keep_withdrawal(&withdrawal(5, 7, 6, true, 1), 3).unwrap();
    s.keep_withdrawal(&withdrawal(5, 8, 4, true, 1), 3).unwrap();
    assert_eq!(
        pairs(5),
        [8, 7],
        "{case}: a replacement kept as the newest, a refused one not"
    );
}

fn an_offer_lapses_and_a_refriend_keeps_the_id(s: &dyn RelationshipStore) {
    let case = "an_offer_lapses_and_a_refriend_keeps_the_id";
    let offer = StoredOffer {
        offer: vec![1, 2, 3],
        lapses_at: at(100),
        upgrade: false,
    };
    s.set_offer(&fp(1), &fp(2), Some(&offer)).unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(99)).unwrap(),
        Some(offer.clone()),
        "{case}"
    );
    assert_eq!(
        s.offer(&fp(2), &fp(1), at(99)).unwrap(),
        None,
        "{case}: directed"
    );
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(100)).unwrap(),
        None,
        "{case}: lapsed"
    );
    let later = StoredOffer {
        offer: vec![4],
        lapses_at: at(300),
        upgrade: false,
    };
    s.set_offer(&fp(1), &fp(3), Some(&later)).unwrap();
    s.set_offer(&fp(3), &fp(1), Some(&later)).unwrap();
    let mut from = s.offers_from(&fp(1), at(99)).unwrap();
    from.sort_by_key(|(other, _)| *other);
    assert_eq!(
        from,
        [(fp(2), offer.clone()), (fp(3), later.clone())],
        "{case}: an owner's, by the party each is to"
    );
    assert_eq!(
        s.offers_from(&fp(1), at(100)).unwrap(),
        [(fp(3), later)],
        "{case}: none lapsed"
    );
    s.set_offer(&fp(1), &fp(3), None).unwrap();
    s.set_offer(&fp(3), &fp(1), None).unwrap();
    s.cleanup(at(200), at(0), 10).unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(0)).unwrap(),
        None,
        "{case}: reclaimed"
    );

    let (a, b) = (
        Mailbox::identified("a", fp(1)),
        Mailbox::identified("b", fp(2)),
    );
    let id = s.befriend(&a, &b, at(1)).unwrap();
    assert_eq!(s.made_at(id).unwrap(), Some(at(1)), "{case}: made");
    s.unfriend(&a, &b).unwrap();
    assert_eq!(s.made_at(id).unwrap(), None, "{case}: ended");
    s.set_pending_out(&a, &b, Some(&pending(2, 1000, true)))
        .unwrap();
    s.refriend(&a, &b, id, at(3)).unwrap();
    assert_eq!(s.made_at(id).unwrap(), Some(at(3)), "{case}: made again");
    for (x, y) in [(&a, &b), (&b, &a)] {
        let row = s.relationship(x, y, at(3)).unwrap().unwrap();
        assert_eq!(row.friendship, Some(id), "{case}: the id it had");
        assert_eq!(row.pending_out, None, "{case}: a request answered");
    }
    assert!(
        s.befriend(&a, &b, at(4)).unwrap() == id,
        "{case}: the same friendship"
    );
}

fn rotation_moves_the_portable_part_and_purging_keeps_withdrawals(s: &dyn RelationshipStore) {
    let case = "rotation_moves_the_portable_part_and_purging_keeps_withdrawals";
    s.present(&presentation(1, 2, 10, 7)).unwrap();
    s.present(&presentation(2, 1, 11, 7)).unwrap();
    // The successor's own for party 3 wins over the predecessor's.
    s.present(&presentation(1, 3, 12, 7)).unwrap();
    s.present(&presentation(5, 3, 13, 7)).unwrap();
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade: false,
    };
    s.set_offer(&fp(1), &fp(2), Some(&offer)).unwrap();
    s.keep_withdrawal(&withdrawal(1, 9, 5, true, 1), 10)
        .unwrap();
    // The successor's own for two more pairs: a later cutoff than the
    // predecessor's for one, and an earlier one for the other.
    let held = |owner, pair, before| HeldWithdrawal {
        party: fp(9),
        ..withdrawal(owner, pair, before, true, 1)
    };
    for (owner, pair, before) in [(1, 7, 10), (5, 7, 20), (1, 6, 30), (5, 6, 15)] {
        s.keep_withdrawal(&held(owner, pair, before), 10).unwrap();
    }
    s.keep_rotation(&fp(1), &fp(5), b"record").unwrap();
    s.keep_rotation(&fp(1), &fp(6), b"other").unwrap();
    s.rotate(&fp(1), &fp(5)).unwrap();

    assert_eq!(
        s.rotation_from(&fp(1)).unwrap(),
        Some((fp(5), b"record".to_vec())),
        "{case}: the first record stands"
    );
    assert_eq!(
        s.rotation_to(&fp(5)).unwrap(),
        Some((fp(1), b"record".to_vec())),
        "{case}"
    );
    assert!(s.presentations(&fp(1)).unwrap().is_empty(), "{case}: moved");
    let mine = s.presentation(&fp(5), &fp(2)).unwrap().unwrap();
    assert_eq!(
        mine.names,
        [fp(1), fp(2)],
        "{case}: the names its friendship gave"
    );
    assert_eq!(
        s.presentation(&fp(2), &fp(5)).unwrap().map(|p| p.hash),
        Some([11; 32]),
        "{case}: naming it, moved"
    );
    assert_eq!(
        s.presentation(&fp(5), &fp(3)).unwrap().map(|p| p.hash),
        Some([13; 32]),
        "{case}: the successor's own kept"
    );
    assert_eq!(
        s.offer(&fp(5), &fp(2), at(1)).unwrap(),
        Some(offer),
        "{case}"
    );
    assert_eq!(
        s.withdrawals(&[9; 32]).unwrap()[0].owner,
        fp(5),
        "{case}: counted toward the successor"
    );
    for (pair, before) in [(7, 20), (6, 30)] {
        let kept: Vec<_> = s
            .withdrawals(&[pair; 32])
            .unwrap()
            .iter()
            .map(|w| (w.owner, w.before, w.withdrawal.clone()))
            .collect();
        assert_eq!(
            kept,
            [(fp(5), before, Some(vec![pair, before as u8]))],
            "{case}: the later cutoff stands, with its object"
        );
    }

    s.purge(&Mailbox::identified("x", fp(5))).unwrap();
    assert!(
        s.presentation(&fp(5), &fp(2)).unwrap().is_none(),
        "{case}: its own presentations go"
    );
    assert!(
        s.presentation(&fp(2), &fp(5)).unwrap().is_some(),
        "{case}: its friend's stay its friend's"
    );
    assert_eq!(s.offer(&fp(5), &fp(2), at(1)).unwrap(), None, "{case}");
    assert_eq!(
        s.withdrawals(&[9; 32]).unwrap().len(),
        1,
        "{case}: withdrawals stay"
    );
}

fn a_rotation_ends_an_edge_its_merge_leaves_without_evidence_both_ways(s: &dyn RelationshipStore) {
    let case = "a_rotation_ends_an_edge_its_merge_leaves_without_evidence_both_ways";
    // Party 1 rotates to 5, friends with 2 and 3 over presentations both
    // ways; 5 already holds a hash of 2's and the whole of 3's.
    let old = Mailbox::identified("old", fp(1));
    let mut ids = Vec::new();
    for other in [2, 3] {
        let them = Mailbox::identified(format!("p{other}"), fp(other));
        ids.push(s.befriend(&old, &them, at(1)).unwrap());
        s.present(&presentation(1, other, other, 7)).unwrap();
        s.present(&presentation(other, 1, other, 8)).unwrap();
    }
    s.present(&Presentation {
        friendship: None,
        ..presentation(5, 2, 20, 9)
    })
    .unwrap();
    s.present(&presentation(5, 3, 30, 9)).unwrap();

    let rotated = s.rotate(&fp(1), &fp(5)).unwrap();
    let dropped: Vec<_> = rotated
        .dropped
        .iter()
        .map(|p| (p.presenter, p.other, p.hash))
        .collect();
    assert_eq!(
        dropped,
        [(fp(5), fp(2), [2; 32]), (fp(5), fp(3), [3; 32])],
        "{case}: each moved one the successor held its own for, as it would have moved"
    );
    let ended: Vec<_> = rotated.ended.iter().map(|e| e.id).collect();
    assert_eq!(ended, [ids[0]], "{case}: only the pair left one way");
    let friendship = |other: u8| {
        s.relationship(
            &Mailbox::identified("new", fp(5)),
            &Mailbox::identified("x", fp(other)),
            at(2),
        )
        .unwrap()
        .and_then(|r| r.friendship)
    };
    assert_eq!(friendship(2), None, "{case}: ended");
    assert_eq!(friendship(3), Some(ids[1]), "{case}: kept");
    for (p, q) in [(5, 2), (2, 5)] {
        assert_eq!(
            s.presentation(&fp(p), &fp(q)).unwrap().and_then(|p| p.edge),
            Some(ids[0]),
            "{case}: the id kept on what is left"
        );
    }
}

fn a_merge_carries_a_kept_edge_id_to_the_friendship_kept(s: &dyn RelationshipStore) {
    let case = "a_merge_carries_a_kept_edge_id_to_the_friendship_kept";
    for (n, rotation) in [(1u8, false), (2, true)] {
        let bob = Mailbox::login(format!("bob{n}"));
        let (from, to) = match rotation {
            false => (
                Mailbox::login(format!("alice{n}")),
                Mailbox::identified(format!("alice{n}"), fp(10 + n)),
            ),
            true => (
                Mailbox::identified("dave", fp(20 + n)),
                Mailbox::identified("dave", fp(30 + n)),
            ),
        };
        let lost = s.befriend(&from, &bob, at(1)).unwrap();
        let kept = s.befriend(&to, &bob, at(2)).unwrap();
        s.present(&Presentation {
            edge: Some(lost),
            ..presentation(40 + n, 50 + n, n, 7)
        })
        .unwrap();
        let merged = match rotation {
            false => s.claim(&from.login, &fp(10 + n)),
            true => s.rotate(&fp(20 + n), &fp(30 + n)),
        }
        .unwrap()
        .merged;
        assert_eq!(merged, [(lost, kept)], "{case}: rotation {rotation}");
        assert_eq!(
            s.presentation(&fp(40 + n), &fp(50 + n))
                .unwrap()
                .and_then(|p| p.edge),
            Some(kept),
            "{case}: rotation {rotation}"
        );
    }
}

fn claimable_finds_whatever_a_claim_moves(s: &dyn RelationshipStore) {
    let case = "claimable_finds_whatever_a_claim_moves";
    let them = Mailbox::identified("them", fp(9));
    let held = |m: &Mailbox| Requester::Account(m.clone());
    type Keep<'a> = &'a dyn Fn(&Mailbox);
    let kinds: [(&str, Keep); 7] = [
        ("a row it owns", &|m| {
            s.set_blocked(m, &them, true, at(1)).unwrap()
        }),
        ("a row naming it", &|m| {
            s.set_blocked(&them, m, true, at(1)).unwrap()
        }),
        ("a hold it placed", &|m| {
            s.hold(m, &held(&them), at(100)).unwrap()
        }),
        ("a hold on it", &|m| {
            s.hold(&them, &held(m), at(100)).unwrap()
        }),
        ("a request it sent", &|m| {
            s.record_request(&entry(RequestKind::Message, Some(m), &them, 1))
                .map(|_| ())
                .unwrap()
        }),
        ("a request to it", &|m| {
            s.record_request(&entry(RequestKind::Message, Some(&them), m, 1))
                .map(|_| ())
                .unwrap()
        }),
        ("its account", &|m| {
            s.update_account(
                m,
                &AccountUpdate {
                    discoverable: Some(true),
                    ..Default::default()
                },
            )
            .unwrap()
        }),
    ];
    for (n, (kind, keep)) in kinds.iter().enumerate() {
        let login = format!("c{n}");
        assert!(!s.claimable(&login).unwrap(), "{case}: {kind}, before");
        keep(&Mailbox::login(login.clone()));
        assert!(s.claimable(&login).unwrap(), "{case}: {kind}");
        s.claim(&login, &fp(60 + n as u8)).unwrap();
        assert!(!s.claimable(&login).unwrap(), "{case}: {kind}, claimed");
    }
}

fn a_drop_ends_an_edge_only_where_it_had_evidence_both_ways(s: &dyn RelationshipStore) {
    let case = "a_drop_ends_an_edge_only_where_it_had_evidence_both_ways";
    let hash_only = |p: Presentation| Presentation {
        friendship: None,
        ..p
    };
    // Pairs (1, 2), (3, 4) and (5, 6), each friends, with presentations
    // both ways, one way, and one way beside a hash.
    let mut ids = Vec::new();
    for (x, y) in [(1, 2), (3, 4), (5, 6)] {
        let a = Mailbox::identified(format!("a{x}"), fp(x));
        let b = Mailbox::identified(format!("b{y}"), fp(y));
        ids.push(s.befriend(&a, &b, at(1)).unwrap());
        s.present(&presentation(x, y, x, 7)).unwrap();
    }
    s.present(&presentation(2, 1, 1, 8)).unwrap();
    s.present(&hash_only(presentation(6, 5, 5, 8))).unwrap();
    let friends = |x: u8, y: u8| {
        s.relationship(
            &Mailbox::identified("", fp(x)),
            &Mailbox::identified("", fp(y)),
            at(2),
        )
        .unwrap()
        .and_then(|r| r.friendship)
    };

    let ended = s
        .drop_presentations(&fp(1), &fp(2), &[fp(1), fp(9)])
        .unwrap();
    assert_eq!(
        ended.gone,
        [presentation(1, 2, 1, 7)],
        "{case}: the one named"
    );
    let e = ended.ended.expect("ended");
    assert_eq!(e.id, ids[0], "{case}");
    let logins = e.parties.map(|m| (m.login, m.fingerprint));
    assert_eq!(
        logins,
        [("a1".into(), Some(fp(1))), ("b2".into(), Some(fp(2)))],
        "{case}: the parties as their rows keep them"
    );
    assert_eq!(friends(1, 2), None, "{case}");
    assert_eq!(friends(2, 1), None, "{case}");
    assert_eq!(
        s.presentation(&fp(2), &fp(1)).unwrap().and_then(|p| p.edge),
        Some(ids[0]),
        "{case}: the id kept on what is left"
    );

    for (x, y) in [(3, 4), (5, 6)] {
        let ended = s.drop_presentations(&fp(x), &fp(y), &[fp(x)]).unwrap();
        assert_eq!(ended.gone.len(), 1, "{case}: ({x}, {y})");
        assert_eq!(ended.ended, None, "{case}: ({x}, {y}) never had both");
        assert!(friends(x, y).is_some(), "{case}: ({x}, {y}) left as it was");
    }
    let left = s.drop_presentations(&fp(6), &fp(5), &[fp(6)]).unwrap();
    assert_eq!(left.ended, None, "{case}: a hash is no evidence");
    assert!(friends(5, 6).is_some(), "{case}");
}

fn a_friendship_by_request_drops_the_presentations_named(s: &dyn RelationshipStore) {
    let case = "a_friendship_by_request_drops_the_presentations_named";
    let mailbox = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let friends = |x: u8, y: u8| {
        s.relationship(&mailbox(x), &mailbox(y), at(9))
            .unwrap()
            .and_then(|r| r.friendship)
    };
    for (x, y) in [(1, 2), (3, 4)] {
        s.present(&presentation(x, y, x, 7)).unwrap();
        s.present(&presentation(y, x, y, 8)).unwrap();
    }
    let made = s
        .befriend_dropping(&mailbox(1), &mailbox(2), at(2), None, &[fp(1)])
        .unwrap();
    assert_eq!(friends(1, 2), Some(made), "{case}");
    assert_eq!(friends(2, 1), Some(made), "{case}");
    assert_eq!(s.presentation(&fp(1), &fp(2)).unwrap(), None, "{case}");
    assert!(s.presentation(&fp(2), &fp(1)).unwrap().is_some(), "{case}");

    // Again under an id the pair had.
    let id = s.befriend(&mailbox(3), &mailbox(4), at(1)).unwrap();
    s.unfriend(&mailbox(3), &mailbox(4)).unwrap();
    let again = s
        .befriend_dropping(&mailbox(3), &mailbox(4), at(2), Some(id), &[fp(3), fp(4)])
        .unwrap();
    assert_eq!(again, id, "{case}");
    assert_eq!(friends(4, 3), Some(id), "{case}");
    for (p, q) in [(3, 4), (4, 3)] {
        assert_eq!(s.presentation(&fp(p), &fp(q)).unwrap(), None, "{case}");
    }
}

fn ending_a_friendship_is_one_step(s: &dyn RelationshipStore) {
    let case = "ending_a_friendship_is_one_step";
    let (a, b) = (
        Mailbox::identified("a", fp(1)),
        Mailbox::identified("b", fp(2)),
    );
    let id = s.befriend(&a, &b, at(1)).unwrap();
    s.present(&presentation(1, 2, 10, 7)).unwrap();
    s.present(&Presentation {
        edge: Some(id),
        ..presentation(2, 1, 11, 7)
    })
    .unwrap();
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade: false,
    };
    for (x, y) in [(1, 2), (2, 1), (1, 3)] {
        s.set_offer(&fp(x), &fp(y), Some(&offer)).unwrap();
    }
    let w = withdrawal(1, 12, 5, true, 1);
    let keep_edge = Ending {
        presentations: vec![fp(1)],
        ..Ending::default()
    };
    let kept = s.end_friendship(&a, &b, &keep_edge).unwrap();
    assert_eq!(kept.gone.len(), 1, "{case}");
    assert_eq!(kept.ended, None, "{case}: the edge not asked for");
    s.present(&presentation(1, 2, 10, 7)).unwrap();

    let end = Ending {
        withdrawals: vec![w.clone()],
        cap: 10,
        presentations: vec![fp(1)],
        offers: vec![fp(1), fp(2)],
        block: Some(at(3)),
        friendship: true,
        hold: Some(at(500)),
        declined: None,
    };
    let ended = s
        .end_friendship(
            &Mailbox::identified("", fp(1)),
            &Mailbox::identified("", fp(2)),
            &end,
        )
        .unwrap();
    assert_eq!(ended.ended.as_ref().map(|e| e.id), Some(id), "{case}");
    assert_eq!(ended.gone, [presentation(1, 2, 10, 7)], "{case}");
    assert_eq!(s.withdrawals(&[12; 32]).unwrap(), [w], "{case}: kept");
    assert_eq!(
        s.presentation(&fp(2), &fp(1)).unwrap().map(|p| p.edge),
        Some(None),
        "{case}: no id left for the edge"
    );
    assert_eq!(s.offer(&fp(1), &fp(2), at(4)).unwrap(), None, "{case}");
    assert_eq!(s.offer(&fp(2), &fp(1), at(4)).unwrap(), None, "{case}");
    assert!(
        s.offer(&fp(1), &fp(3), at(4)).unwrap().is_some(),
        "{case}: another pair's"
    );
    assert!(s.is_blocked(&a, &b).unwrap(), "{case}");
    assert_eq!(
        s.relationship(&b, &a, at(4)).unwrap(),
        None,
        "{case}: the friendship gone"
    );
    assert_eq!(
        s.relationship(&a, &b, at(4)).unwrap().map(|r| r.friendship),
        Some(None),
        "{case}: the block stays"
    );
    assert!(
        s.is_held(&a, &Requester::Account(b.clone()), at(499))
            .unwrap(),
        "{case}: held under the rows' mailboxes"
    );
    assert!(
        !s.is_held(&a, &Requester::Account(b), at(500)).unwrap(),
        "{case}"
    );

    // Without fingerprints, a friendship of logins alone; and no hold
    // where nothing ended.
    let (c, d) = (Mailbox::login("c"), Mailbox::login("d"));
    s.befriend(&c, &d, at(1)).unwrap();
    let plain = Ending {
        friendship: true,
        presentations: vec![fp(1)],
        hold: Some(at(500)),
        ..Ending::default()
    };
    assert!(s.end_friendship(&c, &d, &plain).unwrap().ended.is_some());
    assert_eq!(s.relationship(&c, &d, at(4)).unwrap(), None, "{case}");
    assert!(
        s.is_held(&c, &Requester::Account(d), at(4)).unwrap(),
        "{case}"
    );
    let (e, f) = (Mailbox::login("e"), Mailbox::login("f"));
    assert!(s.end_friendship(&e, &f, &plain).unwrap().ended.is_none());
    assert!(
        !s.is_held(&e, &Requester::Account(f), at(4)).unwrap(),
        "{case}: nothing ended"
    );
}

fn an_older_cutoff_kept_by_an_ending_still_holds_the_owner_to_its_cap(s: &dyn RelationshipStore) {
    let case = "an_older_cutoff_kept_by_an_ending_still_holds_the_owner_to_its_cap";
    s.keep_withdrawal(&withdrawal(1, 20, 50, true, 1), 2)
        .unwrap();
    s.keep_withdrawal(&withdrawal(1, 21, 50, true, 2), 2)
        .unwrap();
    let end = Ending {
        withdrawals: vec![withdrawal(1, 21, 40, true, 3)],
        cap: 1,
        ..Ending::default()
    };
    s.end_friendship(&Mailbox::login("a"), &Mailbox::login("b"), &end)
        .unwrap();
    assert_eq!(
        s.withdrawals(&[20; 32]).unwrap(),
        [],
        "{case}: the oldest past the cap"
    );
    assert_eq!(
        s.withdrawals(&[21; 32]).unwrap(),
        [withdrawal(1, 21, 50, true, 2)],
        "{case}: the later cutoff kept"
    );
}

fn a_block_ends_the_requests_and_approvals_either_way(s: &dyn RelationshipStore) {
    let case = "a_block_ends_the_requests_and_approvals_either_way";
    let (a, b) = (Mailbox::login("a"), Mailbox::login("b"));
    let ids = [
        s.approve(&a, &b, at(1)).unwrap(),
        s.approve(&b, &a, at(1)).unwrap(),
    ];
    for (x, y) in [(&a, &b), (&b, &a)] {
        s.set_pending_out(x, y, Some(&pending(2, 1000, true)))
            .unwrap();
    }
    let end = Ending {
        block: Some(at(3)),
        ..Ending::default()
    };
    s.end_friendship(&a, &b, &end).unwrap();
    let mine = s.relationship(&a, &b, at(4)).unwrap().unwrap();
    assert_eq!(mine.blocked_at, Some(at(3)), "{case}");
    assert_eq!((mine.approval, mine.pending_out), (None, None), "{case}");
    assert_eq!(s.relationship(&b, &a, at(4)).unwrap(), None, "{case}");
    for id in ids {
        assert_eq!(s.made_at(id).unwrap(), None, "{case}: {id} ended");
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn fp(n: u8) -> [u8; 32] {
    [n; 32]
}

fn guid(n: u8) -> MessageGuid {
    MessageGuid::parse(&format!("{n:08x}-0000-4000-8000-000000000000")).unwrap()
}

fn pending(sent: u64, lapses: u64, delivered: bool) -> PendingOut {
    PendingOut {
        sent_at: at(sent),
        lapses_at: at(lapses),
        delivered,
        note: Some("hi".into()),
    }
}

fn entry(kind: RequestKind, from: Option<&Mailbox>, to: &Mailbox, secs: u64) -> LedgerEntry {
    LedgerEntry {
        kind,
        sender: from.cloned(),
        address: Some("addr-1".into()),
        recipient: to.clone(),
        guid: None,
        bytes: 10,
        at: at(secs),
    }
}

fn logins(m: Vec<Mailbox>) -> Vec<String> {
    m.into_iter().map(|m| m.login).collect()
}

fn blocks_are_directional_and_idempotent(s: &dyn RelationshipStore) {
    let case = "blocks_are_directional_and_idempotent";
    let (dave, spammer) = (Mailbox::login("dave"), Mailbox::login("spammer"));
    assert!(!s.is_blocked(&dave, &spammer).unwrap(), "{case}: clean");
    s.set_blocked(&dave, &spammer, true, at(1)).unwrap();
    s.set_blocked(&dave, &spammer, true, at(2)).unwrap();
    assert!(s.is_blocked(&dave, &spammer).unwrap(), "{case}: blocked");
    assert!(
        !s.is_blocked(&spammer, &dave).unwrap(),
        "{case}: one-way — it says nothing about the reverse"
    );
    assert_eq!(s.blocked(&dave).unwrap().len(), 1, "{case}: listed once");
    assert_eq!(
        s.relationship(&dave, &spammer, at(3))
            .unwrap()
            .unwrap()
            .blocked_at,
        Some(at(1)),
        "{case}: blocking again keeps the first block"
    );
    s.set_blocked(&dave, &spammer, false, at(4)).unwrap();
    s.set_blocked(&dave, &spammer, false, at(4)).unwrap();
    assert!(!s.is_blocked(&dave, &spammer).unwrap(), "{case}: unblocked");
    assert!(s.blocked(&dave).unwrap().is_empty(), "{case}: and delisted");
    assert_eq!(
        s.relationship(&dave, &spammer, at(5)).unwrap(),
        None,
        "{case}: a row with nothing in it is not kept"
    );
}

fn blocks_follow_an_identity_and_are_listed(s: &dyn RelationshipStore) {
    let case = "blocks_follow_an_identity_and_are_listed";
    let dave = Mailbox::login("dave");
    // A friendship's row made first, blocked later, lists by its block.
    s.befriend(&dave, &Mailbox::login("two"), at(1)).unwrap();
    s.set_blocked(&dave, &Mailbox::login("one"), true, at(2))
        .unwrap();
    s.set_blocked(&dave, &Mailbox::login("two"), true, at(3))
        .unwrap();

    assert!(s.claim("dave", &fp(1)).unwrap().moved > 0, "{case}: moved");
    assert_eq!(
        s.claim("dave", &fp(1)).unwrap().moved,
        0,
        "{case}: idempotent"
    );
    let identified = Mailbox::identified("dave", fp(1));
    assert_eq!(
        logins(s.blocked(&identified).unwrap()),
        ["one", "two"],
        "{case}: the list follows the owner, oldest block first"
    );
    assert!(
        s.blocked(&dave).unwrap().is_empty(),
        "{case}: and the bare login no longer holds it"
    );
    s.claim("one", &fp(2)).unwrap();
    assert!(
        s.is_blocked(&identified, &Mailbox::identified("one", fp(2)))
            .unwrap(),
        "{case}: a block is not shaken off by linking an identity"
    );
    let friendship = |x: &Mailbox, y: &Mailbox| {
        s.relationship(x, y, at(4))
            .unwrap()
            .and_then(|r| r.friendship)
    };
    let two = Mailbox::login("two");
    assert!(
        friendship(&two, &identified).is_some()
            && friendship(&two, &identified) == friendship(&identified, &two),
        "{case}: the other side's row follows the identity too"
    );
}

/// Block while linked, unlink, block again, relink: two rows for one
/// pair, which must be one, or the stores disagree about what an
/// unblock means.
fn a_merge_leaves_one_block_per_pair(s: &dyn RelationshipStore) {
    let case = "a_merge_leaves_one_block_per_pair";
    let bob = Mailbox::login("bob");
    let alice_linked = Mailbox::identified("alice", fp(1));
    s.set_blocked(&alice_linked, &bob, true, at(1)).unwrap();
    s.set_blocked(&Mailbox::login("alice"), &bob, true, at(2))
        .unwrap();
    s.claim("alice", &fp(1)).unwrap();
    assert_eq!(s.blocked(&alice_linked).unwrap().len(), 1, "{case}: one");
    s.set_blocked(&alice_linked, &bob, false, at(3)).unwrap();
    assert!(
        !s.is_blocked(&alice_linked, &bob).unwrap(),
        "{case}: and unblocking means unblocked"
    );
}

fn a_claim_folds_two_rows_for_one_pair_into_the_older_claim(s: &dyn RelationshipStore) {
    let case = "a_claim_folds_two_rows_for_one_pair_into_the_older_claim";
    let bob = Mailbox::login("bob");
    let linked = Mailbox::identified("alice", fp(1));
    let bare = Mailbox::login("alice");
    // Friends while linked, friends again unlinked: two friendships.
    let first = s.befriend(&linked, &bob, at(1)).unwrap();
    s.set_alias(&linked, &bob, Some("Bobby")).unwrap();
    let second = s.befriend(&bare, &bob, at(2)).unwrap();
    assert_ne!(first, second, "{case}: two pairs, two ids");
    s.set_ignore(
        &bare,
        &bob,
        Some(&Ignore {
            mode: IgnoreMode::Chat,
            until: None,
        }),
    )
    .unwrap();
    s.set_blocked(&bare, &bob, true, at(2)).unwrap();
    let approval = s.approve(&bare, &bob, at(2)).unwrap();

    let claimed = s.claim("alice", &fp(1)).unwrap();
    assert_eq!(
        claimed.merged,
        [(second, first)],
        "{case}: the lost friendship, beside the one that stands for it"
    );
    assert!(
        claimed.moved >= 2,
        "{case}: each row folded counts, though none is left to re-key"
    );
    let mine = s.relationship(&linked, &bob, at(3)).unwrap().unwrap();
    assert_eq!(mine.friendship, Some(first), "{case}: the older claim's");
    assert_eq!(mine.alias.as_deref(), Some("Bobby"), "{case}: its alias");
    assert_eq!(
        mine.ignore.map(|i| i.mode),
        Some(IgnoreMode::Chat),
        "{case}: and what only the other row held"
    );
    // Folded without judging: the domain ends what no act would leave.
    assert_eq!(
        (mine.blocked_at, mine.approval),
        (Some(at(2)), Some(approval)),
        "{case}: a block and an approval beside a live friendship"
    );
    let theirs = s.relationship(&bob, &linked, at(3)).unwrap().unwrap();
    assert_eq!(
        theirs.friendship,
        Some(first),
        "{case}: both rows still point at one friendship"
    );
    assert_eq!(s.relationships(&bob, at(3)).unwrap().len(), 1, "{case}");
    assert_eq!(
        s.befriend(&linked, &bob, at(4)).unwrap(),
        first,
        "{case}: and it is the one they share"
    );
}

fn a_rename_keeps_an_identitys_rows_and_frees_the_login(s: &dyn RelationshipStore) {
    let case = "a_rename_keeps_an_identitys_rows_and_frees_the_login";
    let bob = Mailbox::login("bob");
    let alice = Mailbox::identified("alice", fp(10));
    let id = s.befriend(&alice, &bob, at(1)).unwrap();
    s.set_blocked(&alice, &Mailbox::login("spammer"), true, at(1))
        .unwrap();
    s.update_account(
        &alice,
        &AccountUpdate {
            status_text: Some(Some("here".into())),
            ..Default::default()
        },
    )
    .unwrap();
    let pest = Requester::Account(Mailbox::login("pest"));
    s.hold(&alice, &pest, at(100)).unwrap();
    s.hold(&bob, &Requester::Account(alice.clone()), at(100))
        .unwrap();

    let alicia = Mailbox::identified("alicia", fp(10));
    assert_eq!(
        s.relationship(&alicia, &bob, at(2))
            .unwrap()
            .and_then(|r| r.friendship),
        Some(id),
        "{case}: the friendship follows the identity through a rename"
    );
    assert!(
        s.is_blocked(&alicia, &Mailbox::login("spammer")).unwrap(),
        "{case}: and the block"
    );
    assert_eq!(
        s.account(&alicia).unwrap().status_text.as_deref(),
        Some("here"),
        "{case}: and the account's own record"
    );
    // The operator purges the old login, as a rename owes (§6).
    assert_eq!(s.purge(&Mailbox::login("alice")).unwrap(), 0, "{case}");
    assert!(
        s.is_held(&alicia, &pest, at(2)).unwrap()
            && s.is_held(&bob, &Requester::Account(alicia.clone()), at(2))
                .unwrap(),
        "{case}: the holds follow the identity, on both sides"
    );
    for stranger in [
        Mailbox::login("alice"),
        Mailbox::identified("alice", fp(11)),
    ] {
        assert!(
            !s.is_held(&stranger, &pest, at(2)).unwrap()
                && !s
                    .is_held(&bob, &Requester::Account(stranger.clone()), at(2))
                    .unwrap(),
            "{case}: and are not the freed login's"
        );
        assert!(
            s.relationships(&stranger, at(2)).unwrap().is_empty()
                && s.relationship(&bob, &stranger, at(2)).unwrap().is_none(),
            "{case}: a new holder of the freed login inherits nothing"
        );
        assert_eq!(s.account(&stranger).unwrap(), MessagingAccount::default());
    }
}

fn rotation_moves_everything_to_the_successor_key(s: &dyn RelationshipStore) {
    let case = "rotation_moves_everything_to_the_successor_key";
    let (old, new) = (
        Mailbox::identified("dave", fp(1)),
        Mailbox::identified("dave", fp(2)),
    );
    let (bob, spammer) = (Mailbox::login("bob"), Mailbox::login("spammer"));
    let id = s.befriend(&old, &bob, at(1)).unwrap();
    s.set_blocked(&old, &spammer, true, at(1)).unwrap();
    s.hold(&old, &Requester::Account(spammer.clone()), at(100))
        .unwrap();
    s.record_request(&entry(RequestKind::Message, Some(&old), &bob, 1))
        .unwrap();
    s.update_account(
        &old,
        &AccountUpdate {
            discoverable: Some(true),
            ..Default::default()
        },
    )
    .unwrap();

    assert!(s.rotate(&fp(1), &fp(2)).unwrap().moved > 0, "{case}: moved");
    assert_eq!(
        s.rotate(&fp(1), &fp(2)).unwrap().moved,
        0,
        "{case}: idempotent"
    );
    assert_eq!(
        s.relationship(&bob, &new, at(2))
            .unwrap()
            .and_then(|r| r.friendship),
        Some(id),
        "{case}: the friend's row names the successor"
    );
    assert!(
        s.is_blocked(&new, &spammer).unwrap(),
        "{case}: a block that quietly stopped applying is the worse half"
    );
    assert!(
        s.relationships(&old, at(2)).unwrap().is_empty(),
        "{case}: the retired key holds nothing"
    );
    assert!(
        s.is_held(
            &Mailbox::identified("x", fp(2)),
            &Requester::Account(spammer.clone()),
            at(2)
        )
        .unwrap(),
        "{case}: the hold"
    );
    assert_eq!(
        s.recipients_since(&Requester::Account(new.clone()), at(0))
            .unwrap(),
        1,
        "{case}: the ledger"
    );
    assert!(s.account(&new).unwrap().discoverable, "{case}: the account");
}

fn purging_takes_everything_naming_the_account(s: &dyn RelationshipStore) {
    let case = "purging_takes_everything_naming_the_account";
    let (dave, bob, carol) = (
        Mailbox::login("dave"),
        Mailbox::login("bob"),
        Mailbox::login("carol"),
    );
    s.befriend(&dave, &bob, at(1)).unwrap(); // two rows
    s.set_blocked(&carol, &dave, true, at(1)).unwrap(); // one
    s.approve(&bob, &carol, at(1)).unwrap(); // someone else's
    s.hold(&bob, &Requester::Account(dave.clone()), at(100))
        .unwrap(); // one
    s.record_request(&entry(RequestKind::Message, Some(&dave), &carol, 1))
        .unwrap(); // one
    s.request_dropped(&dave).unwrap(); // one

    assert_eq!(s.purge_count(&dave).unwrap(), 6, "{case}: counted");
    assert_eq!(s.purge(&dave).unwrap(), 6, "{case}: as purged");
    assert_eq!(s.purge_count(&dave).unwrap(), 0, "{case}: nothing left");
    assert!(
        s.relationship(&bob, &dave, at(2)).unwrap().is_none()
            && !s.is_blocked(&carol, &dave).unwrap(),
        "{case}: the rows naming it went too"
    );
    assert!(
        s.relationship(&bob, &carol, at(2)).unwrap().is_some(),
        "{case}: and nobody else's"
    );
    assert!(
        !s.is_held(&bob, &Requester::Account(dave.clone()), at(2))
            .unwrap(),
        "{case}: nor its holds"
    );
}

fn a_friendship_is_one_id_for_the_pair_and_never_reused(s: &dyn RelationshipStore) {
    let case = "a_friendship_is_one_id_for_the_pair_and_never_reused";
    let (a, b) = (Mailbox::login("a"), Mailbox::login("b"));
    s.set_pending_out(&a, &b, Some(&pending(1, 100, true)))
        .unwrap();
    s.set_pending_out(&b, &a, Some(&pending(1, 100, true)))
        .unwrap();
    let id = s.befriend(&a, &b, at(2)).unwrap();
    assert_eq!(s.befriend(&b, &a, at(3)).unwrap(), id, "{case}: one pair");
    for (x, y) in [(&a, &b), (&b, &a)] {
        let r = s.relationship(x, y, at(4)).unwrap().unwrap();
        assert_eq!(r.friendship, Some(id), "{case}: both rows point at it");
        assert_eq!(r.pending_out, None, "{case}: the requests are answered");
    }
    assert_eq!(s.unfriend(&b, &a).unwrap(), Some(id), "{case}: ended");
    assert_eq!(s.unfriend(&a, &b).unwrap(), None, "{case}: once");
    assert!(s.relationship(&a, &b, at(5)).unwrap().is_none(), "{case}");
    let again = s.befriend(&a, &b, at(6)).unwrap();
    assert_ne!(again, id, "{case}: made again, a new id");
    let approval = s.approve(&a, &Mailbox::login("c"), at(7)).unwrap();
    assert!(
        approval != id && approval != again,
        "{case}: approvals draw on the same ids"
    );
}

fn an_approval_is_its_approvers_alone(s: &dyn RelationshipStore) {
    let case = "an_approval_is_its_approvers_alone";
    let (me, stranger) = (Mailbox::login("me"), Mailbox::login("stranger"));
    let id = s.approve(&me, &stranger, at(1)).unwrap();
    assert_eq!(s.approve(&me, &stranger, at(2)).unwrap(), id, "{case}");
    assert_eq!(
        s.relationship(&me, &stranger, at(3))
            .unwrap()
            .and_then(|r| r.approval),
        Some(id),
        "{case}: on the approver's row"
    );
    assert!(
        s.relationship(&stranger, &me, at(3)).unwrap().is_none(),
        "{case}: and not on the other's"
    );
    assert_eq!(s.roster_size(&me, at(3)).unwrap(), 1, "{case}: it counts");
    assert_eq!(s.roster_size(&stranger, at(3)).unwrap(), 0, "{case}");
    assert_eq!(s.end_approval(&me, &stranger).unwrap(), Some(id));
    assert_eq!(s.end_approval(&me, &stranger).unwrap(), None);
    assert_ne!(s.approve(&me, &stranger, at(4)).unwrap(), id, "{case}");
}

fn an_alias_lives_only_beside_a_friendship_or_a_block(s: &dyn RelationshipStore) {
    let case = "an_alias_lives_only_beside_a_friendship_or_a_block";
    let (a, b, c) = (
        Mailbox::login("a"),
        Mailbox::login("b"),
        Mailbox::login("c"),
    );
    s.set_alias(&a, &c, Some("nobody")).unwrap();
    assert!(
        s.relationship(&a, &c, at(1)).unwrap().is_none(),
        "{case}: not on its own"
    );
    s.befriend(&a, &b, at(1)).unwrap();
    s.set_alias(&a, &b, Some("Bee")).unwrap();
    s.set_blocked(&a, &b, true, at(2)).unwrap();
    s.unfriend(&a, &b).unwrap();
    assert_eq!(
        s.relationship(&a, &b, at(3))
            .unwrap()
            .unwrap()
            .alias
            .as_deref(),
        Some("Bee"),
        "{case}: a block keeps it, so the blocked row is legible"
    );
    s.set_blocked(&a, &b, false, at(4)).unwrap();
    assert!(
        s.relationship(&a, &b, at(5)).unwrap().is_none(),
        "{case}: and goes with the last of them"
    );
}

fn what_lapses_reads_as_gone_and_counts_for_nothing(s: &dyn RelationshipStore) {
    let case = "what_lapses_reads_as_gone_and_counts_for_nothing";
    let me = Mailbox::login("me");
    let (x, y, z) = (
        Mailbox::login("x"),
        Mailbox::login("y"),
        Mailbox::login("z"),
    );
    s.set_pending_out(&me, &x, Some(&pending(1, 10, true)))
        .unwrap();
    s.set_pending_out(&y, &me, Some(&pending(2, 10, true)))
        .unwrap();
    s.set_pending_out(&z, &me, Some(&pending(1, 20, false)))
        .unwrap();
    s.set_ignore(
        &me,
        &y,
        Some(&Ignore {
            mode: IgnoreMode::Messages,
            until: Some(at(10)),
        }),
    )
    .unwrap();
    // Before, at and after the lapse.
    for (now, size, waiting) in [(9, 2, 1), (10, 0, 0), (11, 0, 0)] {
        assert_eq!(
            s.roster_size(&me, at(now)).unwrap(),
            size,
            "{case}: at {now}, a request sent and an ignore count"
        );
        assert_eq!(
            s.pending_in(&me, at(now)).unwrap().len(),
            waiting,
            "{case}: at {now}, only a delivered request waits"
        );
        assert_eq!(
            s.relationships(&me, at(now)).unwrap().len(),
            size,
            "{case}: at {now}, read as gone"
        );
    }
    assert_eq!(
        s.pending_in(&me, at(9)).unwrap()[0].owner.login,
        "y",
        "{case}: the waiting request is the other's row"
    );
}

fn a_hold_matches_either_key_and_lapses(s: &dyn RelationshipStore) {
    let case = "a_hold_matches_either_key_and_lapses";
    let dave = Mailbox::identified("dave", fp(1));
    let pest = Requester::Account(Mailbox::identified("pest", fp(2)));
    s.hold(&dave, &pest, at(100)).unwrap();
    s.hold(&dave, &Requester::Address("addr-9".into()), at(100))
        .unwrap();
    s.hold(&dave, &Requester::Identity(fp(4)), at(100)).unwrap();
    let account = Requester::Account;
    for (what, owner, sender, now, held) in [
        ("as placed", dave.clone(), pest.clone(), 50, true),
        (
            "the sender unlinked",
            dave.clone(),
            account(Mailbox::login("pest")),
            50,
            true,
        ),
        (
            "the sender renamed",
            dave.clone(),
            account(Mailbox::identified("pester", fp(2))),
            50,
            true,
        ),
        (
            "the owner unlinked",
            Mailbox::login("dave"),
            pest.clone(),
            50,
            true,
        ),
        (
            "someone else",
            dave.clone(),
            account(Mailbox::login("friend")),
            50,
            false,
        ),
        (
            "the guest's address",
            dave.clone(),
            Requester::Address("addr-9".into()),
            50,
            true,
        ),
        (
            "another address",
            dave.clone(),
            Requester::Address("addr-8".into()),
            50,
            false,
        ),
        (
            "another owner",
            Mailbox::login("erin"),
            pest.clone(),
            50,
            false,
        ),
        (
            "an identity guest",
            dave.clone(),
            Requester::Identity(fp(4)),
            50,
            true,
        ),
        (
            "another identity guest",
            dave.clone(),
            Requester::Identity(fp(5)),
            50,
            false,
        ),
        (
            "a plain guest's mailbox",
            dave.clone(),
            account(Mailbox::login("guest")),
            50,
            false,
        ),
        ("lapsed", dave.clone(), pest.clone(), 100, false),
    ] {
        assert_eq!(
            s.is_held(&owner, &sender, at(now)).unwrap(),
            held,
            "{case}: {what}"
        );
    }
    s.claim("pest", &fp(3)).unwrap();
    assert!(
        s.is_held(&dave, &Requester::Account(Mailbox::login("pest")), at(50))
            .unwrap(),
        "{case}: linking does not shed it"
    );
}

fn request_addresses_lists_each_guest_address_once_within_its_span(s: &dyn RelationshipStore) {
    let case = "request_addresses_lists_each_guest_address_once_within_its_span";
    let (dave, erin) = (Mailbox::login("dave"), Mailbox::login("erin"));
    let from = |sender: Option<&Mailbox>, addr: &str, to: &Mailbox, secs| LedgerEntry {
        address: Some(addr.into()),
        ..entry(RequestKind::Message, sender, to, secs)
    };
    for e in [
        from(None, "before", &dave, 5),
        from(None, "a1", &dave, 10),
        from(None, "a2", &dave, 20),
        from(None, "a1", &dave, 30),
        from(None, "to erin", &erin, 30),
        from(Some(&Mailbox::login("alice")), "an account's", &dave, 30),
        from(None, "after", &dave, 40),
    ] {
        s.record_request(&e).unwrap();
    }
    assert_eq!(
        s.request_addresses(&dave, at(10), None).unwrap(),
        ["a1", "a2", "after"],
        "{case}"
    );
    assert_eq!(
        s.request_addresses(&dave, at(10), Some(at(40))).unwrap(),
        ["a1", "a2"],
        "{case}: what was sent from `before` on is outside it"
    );
}

fn the_guests_behind_an_address_are_counted_together(s: &dyn RelationshipStore) {
    let case = "the_guests_behind_an_address_are_counted_together";
    let (dave, erin) = (Mailbox::login("dave"), Mailbox::login("erin"));
    let (seven, eight) = (
        Mailbox::identified("guest", fp(7)),
        Mailbox::identified("guest", fp(8)),
    );
    let from = |sender: Option<&Mailbox>, addr: &str, to: &Mailbox, secs| LedgerEntry {
        address: Some(addr.into()),
        ..entry(RequestKind::Message, sender, to, secs)
    };
    for e in [
        from(None, "k1", &dave, 5),
        from(None, "k1", &dave, 10),
        from(Some(&seven), "k1", &dave, 10),
        from(Some(&eight), "k1", &dave, 10),
        from(Some(&seven), "k2", &dave, 10),
        from(None, "k2", &dave, 10),
        from(None, "k1", &erin, 10),
        from(Some(&Mailbox::login("alice")), "k1", &dave, 10),
    ] {
        s.record_request(&e).unwrap();
    }
    for (what, n, expected) in [
        (
            "every guest behind k1, and no account",
            s.guest_requests_to("k1", &dave, at(10)),
            3,
        ),
        (
            "an identity guest from any address",
            s.requests_to(
                &Requester::Identity(fp(7)),
                &dave,
                RequestKind::Message,
                at(0),
            ),
            2,
        ),
        (
            "the plain guests behind k1 alone",
            s.requests_to(
                &Requester::Address("k1".into()),
                &dave,
                RequestKind::Message,
                at(0),
            ),
            2,
        ),
    ] {
        assert_eq!(n.unwrap(), expected, "{case}: {what}");
    }
}

fn the_ledger_counts_what_was_sent_and_answers_a_retry(s: &dyn RelationshipStore) {
    let case = "the_ledger_counts_what_was_sent_and_answers_a_retry";
    let me = Mailbox::login("me");
    let (x, y) = (Mailbox::login("x"), Mailbox::login("y"));
    let mut first = entry(RequestKind::Message, Some(&me), &x, 10);
    first.guid = Some(guid(1));
    assert_eq!(s.record_request(&first).unwrap(), Recorded::New, "{case}");
    let mut retry = first.clone();
    retry.at = at(11);
    assert_eq!(
        s.record_request(&retry).unwrap(),
        Recorded::Retry(Box::new(first.clone())),
        "{case}: a retry is answered from the original"
    );
    s.record_request(&entry(RequestKind::Message, Some(&me), &x, 20))
        .unwrap();
    s.record_request(&entry(RequestKind::Friend, Some(&me), &y, 30))
        .unwrap();
    // A guest, counted by its address alone.
    let mut guest = entry(RequestKind::Message, None, &y, 30);
    guest.guid = Some(guid(1));
    assert_eq!(
        s.record_request(&guest).unwrap(),
        Recorded::New,
        "{case}: a guid is scoped to its sender"
    );
    let me_ = Requester::Account(me.clone());
    let addr = Requester::Address("addr-1".into());
    assert_eq!(
        s.find_request(&me_, Some(&x), &guid(1)).unwrap(),
        Some(first.clone()),
        "{case}: found before it is asked again"
    );
    assert_eq!(
        s.find_request(&me_, None, &guid(1)).unwrap(),
        Some(first.clone()),
        "{case}: and toward anyone"
    );
    for (from, to) in [(&me_, &y), (&addr, &x)] {
        assert_eq!(
            s.find_request(from, Some(to), &guid(1)).unwrap(),
            None,
            "{case}: another pair's"
        );
    }
    assert_eq!(
        s.requests_to(&me_, &x, RequestKind::Message, at(0))
            .unwrap(),
        2,
        "{case}: the retry was not counted again"
    );
    assert_eq!(
        s.requests_to(&me_, &x, RequestKind::Message, at(15))
            .unwrap(),
        1,
        "{case}: a window is a range"
    );
    assert_eq!(
        s.requests_to(&me_, &y, RequestKind::Message, at(0))
            .unwrap(),
        0
    );
    assert_eq!(
        s.requests_to(&me_, &y, RequestKind::Friend, at(0)).unwrap(),
        1
    );
    assert_eq!(
        s.recipients_since(&me_, at(0)).unwrap(),
        2,
        "{case}: both kinds"
    );
    assert_eq!(
        s.recipients_since(&addr, at(0)).unwrap(),
        1,
        "{case}: the guest"
    );
    assert_eq!(
        s.recipients_from_address("addr-1", at(0)).unwrap(),
        2,
        "{case}: everyone at the address"
    );
    assert_eq!(
        s.requested_since(&me_, at(0)).unwrap(),
        Sent {
            messages: 2,
            bytes: 20
        },
        "{case}: message requests toward the daily quota"
    );
    s.claim("x", &fp(5)).unwrap();
    assert_eq!(
        s.recipients_since(&me_, at(0)).unwrap(),
        2,
        "{case}: a recipient that linked is one recipient still"
    );
    assert_eq!(
        s.requests_to(
            &me_,
            &Mailbox::identified("x", fp(5)),
            RequestKind::Message,
            at(0)
        )
        .unwrap(),
        2,
        "{case}: and its rows followed it"
    );
}

fn a_listing_takes_the_dropped_count(s: &dyn RelationshipStore) {
    let case = "a_listing_takes_the_dropped_count";
    let me = Mailbox::login("me");
    s.request_dropped(&me).unwrap();
    s.request_dropped(&me).unwrap();
    assert_eq!(s.requests_listed(&me).unwrap(), 2, "{case}");
    assert_eq!(s.requests_listed(&me).unwrap(), 0, "{case}: since");
    assert!(
        !s.account(&me).unwrap().takes_requests,
        "{case}: listing is no opt-in"
    );
}

fn an_account_keeps_what_it_was_told_and_nothing_else(s: &dyn RelationshipStore) {
    let case = "an_account_keeps_what_it_was_told_and_nothing_else";
    let me = Mailbox::identified("me", fp(1));
    let fresh = s.account(&me).unwrap();
    assert!(!fresh.discoverable, "{case}: unlisted until asked");
    assert!(
        !fresh.takes_requests && fresh.requests_opted_at.is_none(),
        "{case}: off until a session opts in"
    );
    s.update_account(
        &me,
        &AccountUpdate {
            takes_requests: Some(Some(at(5))),
            ..Default::default()
        },
    )
    .unwrap();
    let opted = s.account(&me).unwrap();
    assert_eq!(
        (opted.takes_requests, opted.requests_opted_at),
        (true, Some(at(5))),
        "{case}: and when"
    );
    let profile = Profile {
        nickname: Some("Misha".into()),
        first_name: Some("A".into()),
        last_name: None,
        email: Some("a@example.com".into()),
        gender: 1,
        birthdate: Birthdate {
            year: 0,
            month: 7,
            day: 4,
        },
        country: Some("US".into()),
        postcode: None,
        languages: vec!["en".into(), "ru".into(), "fr".into(), "de".into()],
    };
    s.update_account(
        &me,
        &AccountUpdate {
            status_text: Some(Some("out".into())),
            shown_text: Some(Some("in".into())),
            discoverable: Some(true),
            takes_requests: Some(None),
            profile: Some(profile.clone()),
        },
    )
    .unwrap();
    // A partial update leaves the rest as it was.
    s.update_account(
        &me,
        &AccountUpdate {
            status_text: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    let got = s.account(&me).unwrap();
    assert_eq!(got.status_text, None, "{case}: cleared");
    assert_eq!(got.shown_text.as_deref(), Some("in"), "{case}: kept apart");
    assert!(got.discoverable && !got.takes_requests, "{case}: kept");
    assert_eq!(
        got.requests_opted_at,
        Some(at(5)),
        "{case}: opting out keeps when it was on"
    );
    assert_eq!(
        got.profile,
        Profile {
            languages: vec!["en".into(), "ru".into(), "fr".into()],
            ..profile
        },
        "{case}: the profile whole, with at most three languages"
    );
    s.update_account(
        &me,
        &AccountUpdate {
            shown_text: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    let cleared = s.account(&me).unwrap();
    assert_eq!(
        (cleared.shown_text, cleared.discoverable),
        (None, true),
        "{case}: the shown text cleared alone"
    );
}

fn the_cleanup_changes_no_answer(s: &dyn RelationshipStore) {
    let case = "the_cleanup_changes_no_answer";
    let me = Mailbox::login("me");
    let (x, y) = (Mailbox::login("x"), Mailbox::login("y"));
    s.set_pending_out(&me, &x, Some(&pending(1, 10, true)))
        .unwrap();
    s.set_blocked(&me, &y, true, at(1)).unwrap();
    s.set_pending_out(&me, &y, Some(&pending(1, 10, true)))
        .unwrap();
    s.hold(&me, &Requester::Account(x.clone()), at(10)).unwrap();
    s.record_request(&entry(RequestKind::Message, Some(&me), &x, 5))
        .unwrap();
    s.record_request(&entry(RequestKind::Message, Some(&me), &x, 50))
        .unwrap();
    let before = s.relationships(&me, at(60)).unwrap();
    let mut changed = 0;
    loop {
        let n = s.cleanup(at(20), at(40), 1).unwrap();
        if n == 0 {
            break;
        }
        changed += n;
    }
    assert_eq!(
        changed, 4,
        "{case}: a lapsed request, the one beside a block, a hold and an old entry"
    );
    assert_eq!(s.relationships(&me, at(60)).unwrap(), before, "{case}");
    assert_eq!(
        s.requests_to(
            &Requester::Account(me.clone()),
            &x,
            RequestKind::Message,
            at(0)
        )
        .unwrap(),
        1,
        "{case}: the entry inside the window is kept"
    );
    assert_eq!(s.purge_count(&x).unwrap(), 1, "{case}: what is left");
}

fn rotating_onto_a_key_with_rows_folds_them(s: &dyn RelationshipStore) {
    let case = "rotating_onto_a_key_with_rows_folds_them";
    let (old, new) = (
        Mailbox::identified("dave", fp(1)),
        Mailbox::identified("dave", fp(2)),
    );
    let (bob, carol, erin) = (
        Mailbox::login("bob"),
        Mailbox::login("carol"),
        Mailbox::login("erin"),
    );
    let kept = s.befriend(&new, &bob, at(1)).unwrap();
    let lost = s.befriend(&old, &bob, at(2)).unwrap();
    s.set_blocked(&old, &carol, true, at(3)).unwrap();
    s.set_blocked(&new, &carol, true, at(4)).unwrap();
    s.set_blocked(&old, &erin, true, at(5)).unwrap();
    assert_eq!(
        s.rotate(&fp(1), &fp(2)).unwrap().merged,
        [(lost, kept)],
        "{case}: the successor's friendship stands"
    );
    for (x, y) in [(&new, &bob), (&bob, &new)] {
        assert_eq!(
            s.relationship(x, y, at(6))
                .unwrap()
                .and_then(|r| r.friendship),
            Some(kept),
            "{case}: on both rows"
        );
    }
    assert_eq!(
        s.relationship(&new, &carol, at(6))
            .unwrap()
            .and_then(|r| r.blocked_at),
        Some(at(3)),
        "{case}: one block, the earlier"
    );
    assert_eq!(
        logins(s.blocked(&new).unwrap()),
        ["carol", "erin"],
        "{case}: and the rows only the old key had come across"
    );
    assert_eq!(s.relationships(&bob, at(6)).unwrap().len(), 1, "{case}");
}

fn a_friendship_ends_the_pairs_approvals(s: &dyn RelationshipStore) {
    let case = "a_friendship_ends_the_pairs_approvals";
    let (a, b) = (Mailbox::login("a"), Mailbox::login("b"));
    s.approve(&a, &b, at(1)).unwrap();
    s.approve(&b, &a, at(1)).unwrap();
    let id = s.befriend(&a, &b, at(2)).unwrap();
    for (x, y) in [(&a, &b), (&b, &a)] {
        let r = s.relationship(x, y, at(3)).unwrap().unwrap();
        assert_eq!(
            (r.friendship, r.approval),
            (Some(id), None),
            "{case}: the friendship takes the approval's place"
        );
    }
}

/// Every time is kept to the second, as SQLite keeps it, so a time
/// within a second reads the same from either store.
fn times_are_kept_to_the_second(s: &dyn RelationshipStore) {
    let case = "times_are_kept_to_the_second";
    let ms = |secs: u64, millis: u64| at(secs) + Duration::from_millis(millis);
    let (me, x) = (Mailbox::login("me"), Mailbox::login("x"));
    s.set_pending_out(
        &me,
        &x,
        Some(&PendingOut {
            sent_at: ms(1, 500),
            lapses_at: ms(10, 900),
            delivered: true,
            note: None,
        }),
    )
    .unwrap();
    s.hold(&me, &Requester::Account(x.clone()), ms(10, 900))
        .unwrap();
    let mut e = entry(RequestKind::Message, Some(&me), &x, 0);
    e.at = ms(20, 700);
    s.record_request(&e).unwrap();
    let from = Requester::Account(me.clone());
    for (now, lapsed) in [(ms(9, 999), false), (ms(10, 100), true)] {
        assert_eq!(
            s.relationship(&me, &x, now).unwrap().is_none(),
            lapsed,
            "{case}: a request lapsing in its second"
        );
        assert_eq!(
            s.is_held(&me, &Requester::Account(x.clone()), now).unwrap(),
            !lapsed,
            "{case}: a hold lapsing in its second"
        );
    }
    assert_eq!(
        s.requests_to(&from, &x, RequestKind::Message, ms(20, 900))
            .unwrap(),
        1,
        "{case}: an entry is in a window that opens within its second"
    );
    assert_eq!(
        s.relationship(&me, &x, at(5))
            .unwrap()
            .and_then(|r| r.pending_out)
            .map(|p| (p.sent_at, p.lapses_at)),
        Some((at(1), at(10))),
        "{case}: and is read back as its second"
    );
}

fn a_declined_upgrade_drops_its_offer_and_holds_in_one_step(s: &dyn RelationshipStore) {
    let case = "a_declined_upgrade_drops_its_offer_and_holds_in_one_step";
    let (a, b) = (
        Mailbox::identified("a", fp(1)),
        Mailbox::identified("b", fp(2)),
    );
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade: false,
    };
    s.set_offer(&fp(2), &fp(1), Some(&offer)).unwrap();
    let decline = Ending {
        offers: vec![fp(2)],
        declined: Some(at(500)),
        ..Ending::default()
    };
    s.end_friendship(&a, &b, &decline).unwrap();
    assert_eq!(s.offer(&fp(2), &fp(1), at(4)).unwrap(), None, "{case}");
    let them = Requester::Account(b.clone());
    assert!(s.is_held(&a, &them, at(10)).unwrap(), "{case}: held");
    assert!(
        !s.is_held(&a, &them, at(600)).unwrap(),
        "{case}: until then"
    );
}

fn a_friendship_an_acceptance_makes_is_one_step(s: &dyn RelationshipStore) {
    let case = "a_friendship_an_acceptance_makes_is_one_step";
    let (a, b) = (
        Mailbox::identified("a", fp(1)),
        Mailbox::identified("b", fp(2)),
    );
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade: false,
    };
    for (x, y) in [(1, 2), (2, 1), (1, 3)] {
        s.set_offer(&fp(x), &fp(y), Some(&offer)).unwrap();
    }
    let kept = s.befriend(&a, &b, at(1)).unwrap();
    s.unfriend(&a, &b).unwrap();
    let record = Presentation {
        friendship: None,
        reset: Some(vec![9; 3]),
        ..presentation(2, 1, 9, 7)
    };
    s.present(&record).unwrap();
    let rows = [presentation(1, 2, 10, 7), presentation(2, 1, 10, 8)];
    let (replaced, id) = s
        .present_befriending(&a, &b, &rows, Some(Some(kept)), at(5))
        .unwrap();
    assert_eq!(replaced, [None, Some(record)], "{case}: what was replaced");
    assert_eq!(id, Some(kept), "{case}: under the id kept");
    let made = s.relationship(&a, &b, at(6)).unwrap();
    assert_eq!(made.and_then(|r| r.friendship), Some(kept), "{case}");
    assert_eq!(
        s.presentation(&fp(1), &fp(2)).unwrap(),
        Some(rows[0].clone()),
        "{case}"
    );
    assert_eq!(
        s.presentation(&fp(2), &fp(1)).unwrap(),
        Some(rows[1].clone()),
        "{case}"
    );
    assert_eq!(s.offer(&fp(1), &fp(2), at(4)).unwrap(), None, "{case}");
    assert_eq!(s.offer(&fp(2), &fp(1), at(4)).unwrap(), None, "{case}");
    assert!(
        s.offer(&fp(1), &fp(3), at(4)).unwrap().is_some(),
        "{case}: another pair's"
    );

    // Between friends already, the rows alone, and a fresh id where none
    // was kept.
    let (c, d) = (
        Mailbox::identified("c", fp(5)),
        Mailbox::identified("d", fp(6)),
    );
    let row = presentation(5, 6, 11, 7);
    let (_, none) = s
        .present_befriending(&c, &d, std::slice::from_ref(&row), None, at(5))
        .unwrap();
    assert_eq!(none, None, "{case}");
    assert!(s.relationship(&c, &d, at(6)).unwrap().is_none(), "{case}");
    assert_eq!(s.presentation(&fp(5), &fp(6)).unwrap(), Some(row), "{case}");
    let (_, fresh) = s
        .present_befriending(&c, &d, &[], Some(None), at(5))
        .unwrap();
    let made = s.relationship(&c, &d, at(6)).unwrap();
    assert_eq!(made.and_then(|r| r.friendship), fresh, "{case}: made");
    assert!(fresh.is_some(), "{case}");
}

fn a_reset_record_lapses_unless_an_offer_waits_on_it(s: &dyn RelationshipStore) {
    let case = "a_reset_record_lapses_unless_an_offer_waits_on_it";
    let record = |p: u8, o: u8, secs: u64| Presentation {
        friendship: None,
        reset: Some(vec![p; 3]),
        at: at(secs),
        ..presentation(p, o, p, 7)
    };
    s.present(&record(1, 2, 10)).unwrap();
    s.present(&record(3, 4, 10)).unwrap();
    s.present(&record(5, 6, 20)).unwrap();
    s.present(&record(9, 10, 21)).unwrap();
    s.present(&presentation(7, 8, 7, 7)).unwrap();
    let waiting = |secs, upgrade| StoredOffer {
        offer: vec![1],
        lapses_at: at(secs),
        upgrade,
    };
    s.set_offer(&fp(4), &fp(3), Some(&waiting(1000, true)))
        .unwrap();
    s.set_offer(&fp(2), &fp(1), Some(&waiting(1000, false)))
        .unwrap();
    s.set_offer(&fp(6), &fp(5), Some(&waiting(25, true)))
        .unwrap();
    assert_eq!(s.lapse_resets(at(20), at(30)).unwrap(), 2, "{case}");
    let reset = |p, o| s.presentation(&fp(p), &fp(o)).unwrap().map(|p| p.reset);
    assert_eq!(
        reset(1, 2),
        Some(None),
        "{case}: a request's offer keeps none"
    );
    assert_eq!(reset(5, 6), Some(None), "{case}: at the time given");
    assert_eq!(
        reset(3, 4),
        Some(Some(vec![3; 3])),
        "{case}: an upgrade waits"
    );
    assert_eq!(reset(9, 10), Some(Some(vec![9; 3])), "{case}: later");
    assert_eq!(
        s.presentation(&fp(7), &fp(8)).unwrap(),
        Some(presentation(7, 8, 7, 7)),
        "{case}: evidence untouched"
    );
}

fn a_lapsed_request_takes_its_offer_and_an_upgrade_is_taken_whole(s: &dyn RelationshipStore) {
    let case = "a_lapsed_request_takes_its_offer_and_an_upgrade_is_taken_whole";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let asked = |lapses| PendingOut {
        sent_at: at(1),
        lapses_at: at(lapses),
        delivered: true,
        note: None,
    };
    let offer = |upgrade| StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade,
    };
    s.set_pending_out(&mb(1), &mb(2), Some(&asked(50))).unwrap();
    s.set_offer(&fp(1), &fp(2), Some(&offer(false))).unwrap();
    s.set_offer(&fp(1), &fp(3), Some(&offer(true))).unwrap();
    s.set_pending_out(&mb(1), &mb(4), Some(&asked(500)))
        .unwrap();
    s.set_offer(&fp(1), &fp(4), Some(&offer(false))).unwrap();
    s.take_as_upgrade(&mb(1), &mb(4)).unwrap();
    assert!(
        s.relationship(&mb(1), &mb(4), at(10))
            .unwrap()
            .is_none_or(|r| r.pending_out.is_none()),
        "{case}: the request ended"
    );
    assert_eq!(
        s.offer(&fp(1), &fp(4), at(10)).unwrap(),
        Some(offer(true)),
        "{case}: taken as an upgrade"
    );
    s.cleanup(at(60), at(0), 100).unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(60)).unwrap(),
        None,
        "{case}: gone with its request"
    );
    for n in [3, 4] {
        assert_eq!(
            s.offer(&fp(1), &fp(n), at(60)).unwrap(),
            Some(offer(true)),
            "{case}: an upgrade, no request's"
        );
    }
}

fn a_request_takes_the_place_of_an_offer_an_earlier_one_left(s: &dyn RelationshipStore) {
    let case = "a_request_takes_the_place_of_an_offer_an_earlier_one_left";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let asked = PendingOut {
        sent_at: at(1),
        lapses_at: at(500),
        delivered: true,
        note: None,
    };
    let offer = |b: u8, upgrade| StoredOffer {
        offer: vec![b],
        lapses_at: at(1000),
        upgrade,
    };
    s.set_offer(&fp(1), &fp(2), Some(&offer(1, false))).unwrap();
    s.ask(&mb(1), &mb(2), &asked, None).unwrap();
    assert_eq!(s.offer(&fp(1), &fp(2), at(10)).unwrap(), None, "{case}");
    let row = s.relationship(&mb(1), &mb(2), at(10)).unwrap();
    assert_eq!(
        row.and_then(|r| r.pending_out),
        Some(asked.clone()),
        "{case}"
    );
    s.ask(&mb(1), &mb(2), &asked, Some(&offer(2, false)))
        .unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(10)).unwrap(),
        Some(offer(2, false)),
        "{case}: the offer it carries"
    );
    s.set_offer(&fp(1), &fp(3), Some(&offer(3, true))).unwrap();
    s.ask(&mb(1), &mb(3), &asked, None).unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(3), at(10)).unwrap(),
        Some(offer(3, true)),
        "{case}: an upgrade stays"
    );
}

fn cleanup_counts_the_offers_lapsed_requests_take(s: &dyn RelationshipStore) {
    let case = "cleanup_counts_the_offers_lapsed_requests_take";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let asked = PendingOut {
        sent_at: at(1),
        lapses_at: at(50),
        delivered: true,
        note: None,
    };
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
        upgrade: false,
    };
    s.set_pending_out(&mb(1), &mb(2), Some(&asked)).unwrap();
    s.set_offer(&fp(1), &fp(2), Some(&offer)).unwrap();
    s.set_pending_out(&mb(3), &mb(4), Some(&asked)).unwrap();
    assert_eq!(
        s.cleanup(at(60), at(0), 100).unwrap(),
        3,
        "{case}: two requests and one offer"
    );
}
