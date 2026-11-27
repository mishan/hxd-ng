//! A suite every [`RelationshipStore`] must pass, for the reason
//! [`crate::inbox::conformance`] gives: the in-memory store and SQLite's
//! must agree exactly, and above all about which mailbox a row is
//! keyed by, where a disagreement is a block that stopped applying.
//!
//! Clocks are fixed values, never `SystemTime::now()`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    AccountUpdate, Birthdate, Cause, Charge, Ending, HeldWithdrawal, Ignore, IgnoreMode,
    LedgerEntry, MessagingAccount, PendingOut, Presentation, Profile, Recorded, RelationshipStore,
    Report, RequestKind, Requester, StoredOffer, Work,
};
use crate::inbox::{Mailbox, MessageGuid, Sent};

/// Run every case against a freshly built store.
pub fn run(new_store: &dyn Fn() -> Box<dyn RelationshipStore>) {
    blocks_are_directional_and_idempotent(&*new_store());
    blocks_follow_an_identity_and_are_listed(&*new_store());
    the_rows_naming_a_mailbox_are_found_by_its_key(&*new_store());
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
    a_requests_offer_lapses_and_goes_with_its_request(&*new_store());
    an_ask_takes_the_place_of_what_was_pending(&*new_store());
    a_reset_answer_is_one_step(&*new_store());
    dropping_an_offer_drops_either_kind(&*new_store());
    a_block_or_a_friendship_takes_offers_and_records(&*new_store());
    a_rotation_drops_the_offers_to_the_key_it_retires(&*new_store());
    a_record_leaving_takes_the_upgrade_it_qualified(&*new_store());
    an_upgrade_beside_a_friendship_ends_with_it(&*new_store());
    a_rotation_into_a_pair_keeps_each_direction_one_state(&*new_store());
    a_row_left_with_nothing_is_reclaimed(&*new_store());
    a_record_is_kept_while_its_upgrade_is_pending(&*new_store());
    a_merged_pending_out_goes_with_its_record(&*new_store());
    an_upgrade_goes_where_a_rotation_keeps_another_record(&*new_store());
    a_rotation_keeps_the_upgrades_the_successor_and_the_other_party_hold(&*new_store());
    an_ask_counts_its_request_in_the_same_step(&*new_store());
    #[cfg(any(test, feature = "test-support"))]
    a_write_is_whole_or_not_at_all_and_reports_what_it_left(&*new_store());
    an_older_cutoff_kept_by_an_ending_still_holds_the_owner_to_its_cap(&*new_store());
    a_block_ends_the_requests_and_approvals_either_way(&*new_store());
    owed_work_is_one_piece_per_owe_until_settled(&*new_store());
    #[cfg(any(test, feature = "test-support"))]
    owed_work_is_written_and_settled_whole_with_its_write(&*new_store());
    a_rotation_moves_owed_work_and_folds_what_it_duplicates(&*new_store());
    work_owed_after_a_rotation_is_owed_where_its_rows_went(&*new_store());
    a_chain_of_moves_is_followed_to_its_end(&*new_store());
    for steps in MOVES_FOUND {
        the_moves_say_where_the_rows_are(&*new_store(), steps);
    }
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
    // An upgrade offer, beside the friendship it would make portable.
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
    };
    let (a, b) = (
        Mailbox::identified("a", fp(1)),
        Mailbox::identified("b", fp(2)),
    );
    s.befriend(&a, &b, at(1)).unwrap();
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

    let (new, p3) = (
        Mailbox::identified("new", fp(5)),
        Mailbox::identified("p3", fp(3)),
    );
    let report = Report::of(&new, &p3, at(2));
    let (rotated, left) = s.rotate_reporting(&fp(1), &fp(5), &report, &[]).unwrap();
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
    // What the rotation left of the pair asked of, then of the edge it
    // ended, by the parties as their rows keep them.
    assert_eq!(left.len(), 2, "{case}: reported");
    assert_eq!(left[0].pair, [new.clone(), p3.clone()], "{case}");
    assert_eq!(
        left[0]
            .rows
            .each_ref()
            .map(|r| r.as_ref().and_then(|r| r.friendship)),
        [Some(ids[1]); 2],
        "{case}: as it left them"
    );
    let [x, y] = &rotated.ended[0].parties;
    assert_eq!(
        left[1].pair,
        [x.clone(), y.clone()],
        "{case}: the ended edge"
    );
    assert_eq!(
        left[1]
            .presentations
            .each_ref()
            .map(|p| p.as_ref().and_then(|p| p.edge)),
        [Some(ids[0]); 2],
        "{case}: the ended edge's id on what is left"
    );
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
            false => s.claim(&from.login, &fp(10 + n), &[]),
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
        s.claim(&login, &fp(60 + n as u8), &[]).unwrap();
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
        pending: false,
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
        offer: None,
        upgrade: false,
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

fn the_rows_naming_a_mailbox_are_found_by_its_key(s: &dyn RelationshipStore) {
    let case = "the_rows_naming_a_mailbox_are_found_by_its_key";
    let alice = Mailbox::identified("alice", fp(1));
    s.set_blocked(
        &Mailbox::login("bob"),
        &Mailbox::login("alice"),
        true,
        at(1),
    )
    .unwrap();
    s.set_blocked(&Mailbox::login("carol"), &alice, true, at(2))
        .unwrap();
    s.set_blocked(&alice, &Mailbox::login("dave"), true, at(3))
        .unwrap();
    let owners = |m: &Mailbox| {
        logins(
            s.naming(m, at(4))
                .unwrap()
                .into_iter()
                .map(|r| r.owner)
                .collect(),
        )
    };
    assert_eq!(
        owners(&alice),
        ["carol"],
        "{case}: by its key, never its own"
    );
    assert_eq!(
        owners(&Mailbox::login("alice")),
        ["bob"],
        "{case}: by its login alone"
    );
    s.claim("alice", &fp(1), &[]).unwrap();
    assert_eq!(
        owners(&Mailbox::identified("", fp(1))),
        ["bob", "carol"],
        "{case}: whatever login it is asked by"
    );
    assert!(
        owners(&Mailbox::login("alice")).is_empty(),
        "{case}: claimed"
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

    assert!(
        s.claim("dave", &fp(1), &[]).unwrap().moved > 0,
        "{case}: moved"
    );
    assert_eq!(
        s.claim("dave", &fp(1), &[]).unwrap().moved,
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
    s.claim("one", &fp(2), &[]).unwrap();
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
    s.claim("alice", &fp(1), &[]).unwrap();
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

    let claimed = s.claim("alice", &fp(1), &[]).unwrap();
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
    s.claim("pest", &fp(3), &[]).unwrap();
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
    s.claim("x", &fp(5), &[]).unwrap();
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
            offer: None,
            upgrade: false,
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
        Mailbox::identified("m1", fp(1)),
        Mailbox::identified("m2", fp(2)),
    );
    asked_with(s, 2, 1, true);
    let decline = Ending {
        offers: vec![fp(2)],
        pending: true,
        declined: Some(at(500)),
        ..Ending::default()
    };
    s.end_friendship(&a, &b, &decline).unwrap();
    assert_eq!(s.offer(&fp(2), &fp(1), at(4)).unwrap(), None, "{case}");
    assert_eq!(asked(s, 2, 1, 4), None, "{case}: its pending out");
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

/// A request with the offer it carries, and an upgrade offer with the
/// pending out it shows its owner, for the pairs given, lapsing at 1000.
fn asked_with(s: &dyn RelationshipStore, from: u8, to: u8, upgrade: bool) -> StoredOffer {
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let offer = StoredOffer {
        offer: vec![from, to],
        lapses_at: at(1000),
    };
    let shown = PendingOut {
        offer: (!upgrade).then(|| offer.clone()),
        upgrade,
        ..pending(1, 1000, true)
    };
    s.ask(
        &mb(from),
        &mb(to),
        &shown,
        upgrade.then_some(&offer),
        None,
        &Report::none(),
    )
    .unwrap();
    offer
}

/// `from`'s request to `to` as it reads at `secs`: whether there is one,
/// whether `to` is shown it, and its offer.
fn asked(
    s: &dyn RelationshipStore,
    from: u8,
    to: u8,
    secs: u64,
) -> Option<(bool, Option<Vec<u8>>)> {
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let row = s.relationship(&mb(from), &mb(to), at(secs)).unwrap()?;
    let p = row.pending_out?;
    let shown = s
        .pending_in(&mb(to), at(secs))
        .unwrap()
        .iter()
        .any(|r| r.owner.login == format!("m{from}"));
    Some((shown, p.offer.map(|o| o.offer)))
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
    asked_with(s, 4, 3, true);
    asked_with(s, 2, 1, false);
    s.set_offer(
        &fp(6),
        &fp(5),
        Some(&StoredOffer {
            offer: vec![1],
            lapses_at: at(25),
        }),
    )
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

#[cfg(any(test, feature = "test-support"))]
fn a_write_is_whole_or_not_at_all_and_reports_what_it_left(s: &dyn RelationshipStore) {
    use super::{Did, Part};
    let case = "a_write_is_whole_or_not_at_all_and_reports_what_it_left";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let offer = StoredOffer {
        offer: vec![1, 2],
        lapses_at: at(1000),
    };
    let parts = |fail: bool| {
        let mut parts = vec![
            Part::Present(presentation(2, 1, 2, 7)),
            Part::SetOffer(fp(1), fp(2), Some(offer.clone())),
        ];
        if fail {
            parts.push(Part::Fail);
        }
        parts
    };
    s.update_account(
        &mb(2),
        &AccountUpdate {
            shown_text: Some(Some("away".into())),
            ..AccountUpdate::default()
        },
    )
    .unwrap();
    let report = Report::of(&mb(1), &mb(2), at(10));
    assert!(s.write(&parts(true), &report).is_err(), "{case}: failed");
    assert_eq!(
        s.presentation(&fp(2), &fp(1)).unwrap(),
        None,
        "{case}: nothing"
    );
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(10)).unwrap(),
        None,
        "{case}: nothing"
    );
    let (did, left) = s.write(&parts(false), &report).unwrap();
    assert_eq!(did, [Did::Replaced(None), Did::Nothing], "{case}: answered");
    let left = &left[0];
    assert_eq!(left.pair, [mb(1), mb(2)], "{case}");
    assert_eq!(
        left.presentations,
        [None, Some(presentation(2, 1, 2, 7))],
        "{case}"
    );
    assert_eq!(left.offers, [Some(offer.clone()), None], "{case}");
    assert_eq!(left.shown, [None, Some("away".into())], "{case}");
    assert_eq!(left.rows, [None, None], "{case}: no rows");
}

fn an_ask_counts_its_request_in_the_same_step(s: &dyn RelationshipStore) {
    let case = "an_ask_counts_its_request_in_the_same_step";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let charge = Charge {
        entry: entry(RequestKind::Friend, Some(&mb(1)), &mb(2), 1),
        dropped: true,
    };
    let shown = PendingOut {
        delivered: false,
        ..pending(1, 500, true)
    };
    let report = Report::of(&mb(1), &mb(2), at(10));
    let left = s
        .ask(&mb(1), &mb(2), &shown, None, Some(&charge), &report)
        .unwrap();
    assert_eq!(left.len(), 1, "{case}: the pair asked of");
    assert_eq!(left[0].pair, [mb(1), mb(2)], "{case}");
    let sent = left[0].rows[0].as_ref().and_then(|r| r.pending_out.clone());
    assert_eq!(
        sent.map(|p| p.delivered),
        Some(false),
        "{case}: as it left it"
    );
    assert_eq!(left[0].rows[1], None, "{case}: no row the other way");
    let from = Requester::Account(mb(1));
    let counted = s.requests_to(&from, &mb(2), RequestKind::Friend, at(0));
    assert_eq!(counted.unwrap(), 1, "{case}: in the ledger");
    assert_eq!(s.requests_listed(&mb(2)).unwrap(), 1, "{case}: dropped");
    assert!(asked(s, 1, 2, 10).is_some(), "{case}: asked");
}

fn a_requests_offer_lapses_and_goes_with_its_request(s: &dyn RelationshipStore) {
    let case = "a_requests_offer_lapses_and_goes_with_its_request";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(50),
    };
    let shown = PendingOut {
        offer: Some(offer.clone()),
        ..pending(1, 500, true)
    };
    s.ask(&mb(1), &mb(2), &shown, None, None, &Report::none())
        .unwrap();
    assert_eq!(asked(s, 1, 2, 10), Some((true, Some(vec![1]))), "{case}");
    assert_eq!(
        s.offers_from(&fp(1), at(10)).unwrap(),
        [(fp(2), offer)],
        "{case}"
    );
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(10)).unwrap(),
        None,
        "{case}: no upgrade"
    );
    assert_eq!(
        asked(s, 1, 2, 60),
        Some((true, None)),
        "{case}: the request stays, plain"
    );
    s.cleanup(at(60), at(0), 100).unwrap();
    assert_eq!(
        asked(s, 1, 2, 10),
        Some((true, None)),
        "{case}: reclaimed, read again before it lapsed"
    );
    assert_eq!(
        s.cleanup(at(600), at(0), 100).unwrap(),
        1,
        "{case}: one row"
    );
    assert_eq!(asked(s, 1, 2, 600), None, "{case}");
}

fn an_ask_takes_the_place_of_what_was_pending(s: &dyn RelationshipStore) {
    let case = "an_ask_takes_the_place_of_what_was_pending";
    let up = asked_with(s, 1, 2, true);
    assert_eq!(
        asked(s, 1, 2, 10),
        Some((false, None)),
        "{case}: shown its owner alone"
    );
    assert_eq!(s.offer(&fp(1), &fp(2), at(10)).unwrap(), Some(up), "{case}");
    let req = asked_with(s, 1, 2, false);
    assert_eq!(
        s.offer(&fp(1), &fp(2), at(10)).unwrap(),
        None,
        "{case}: no upgrade beside"
    );
    assert_eq!(asked(s, 1, 2, 10), Some((true, Some(req.offer))), "{case}");
}

fn a_reset_answer_is_one_step(s: &dyn RelationshipStore) {
    let case = "a_reset_answer_is_one_step";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let a = Mailbox::identified("m1", fp(1));
    let b = Mailbox::identified("m2", fp(2));
    let id = s.befriend(&a, &b, at(1)).unwrap();
    s.present(&presentation(1, 2, 10, 7)).unwrap();
    s.present(&presentation(2, 1, 10, 7)).unwrap();
    let offer = asked_with(s, 3, 2, false);
    let record = Presentation {
        friendship: None,
        reset: Some(vec![9; 3]),
        ..presentation(2, 3, 9, 7)
    };
    let (ended, replaced) = s
        .answer_reset(
            &[(fp(2), fp(1), vec![fp(2)])],
            Some(&record),
            Some((&mb(3), &mb(2))),
        )
        .unwrap();
    assert_eq!(ended.len(), 1, "{case}");
    assert_eq!(
        ended[0].ended.as_ref().map(|e| e.id),
        Some(id),
        "{case}: the edge"
    );
    assert_eq!(replaced, None, "{case}");
    assert_eq!(
        s.presentation(&fp(2), &fp(3)).unwrap(),
        Some(record),
        "{case}"
    );
    assert_eq!(
        asked(s, 3, 2, 10),
        Some((false, None)),
        "{case}: an upgrade now"
    );
    assert_eq!(
        s.offer(&fp(3), &fp(2), at(10)).unwrap(),
        Some(offer),
        "{case}"
    );
}

fn dropping_an_offer_drops_either_kind(s: &dyn RelationshipStore) {
    let case = "dropping_an_offer_drops_either_kind";
    asked_with(s, 1, 2, false);
    asked_with(s, 1, 3, true);
    asked_with(s, 4, 1, false);
    asked_with(s, 5, 6, true);
    s.drop_offers(&[(fp(1), fp(2)), (fp(1), fp(3))]).unwrap();
    assert_eq!(
        asked(s, 1, 2, 10),
        Some((true, None)),
        "{case}: the request stays"
    );
    assert_eq!(
        asked(s, 1, 3, 10),
        None,
        "{case}: the upgrade's pending out goes"
    );
    assert_eq!(s.offer(&fp(1), &fp(3), at(10)).unwrap(), None, "{case}");
    s.drop_offers_naming(&fp(1)).unwrap();
    assert_eq!(asked(s, 4, 1, 10), Some((true, None)), "{case}: one to it");
    assert!(
        s.offer(&fp(5), &fp(6), at(10)).unwrap().is_some(),
        "{case}: another's"
    );
}

fn a_block_or_a_friendship_takes_offers_and_records(s: &dyn RelationshipStore) {
    let case = "a_block_or_a_friendship_takes_offers_and_records";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let record = |p: u8, o: u8| Presentation {
        friendship: None,
        reset: Some(vec![p; 3]),
        ..presentation(p, o, p, 7)
    };
    // Blocked: 1 and 2.
    s.present(&record(2, 1)).unwrap();
    asked_with(s, 1, 2, true);
    asked_with(s, 2, 1, false);
    let block = Ending {
        block: Some(at(5)),
        ..Ending::default()
    };
    s.end_friendship(&mb(2), &mb(1), &block).unwrap();
    assert_eq!(s.offer(&fp(1), &fp(2), at(10)).unwrap(), None, "{case}");
    assert_eq!(
        (asked(s, 1, 2, 10), asked(s, 2, 1, 10)),
        (None, None),
        "{case}"
    );
    let kept = s.presentation(&fp(2), &fp(1)).unwrap().unwrap();
    assert_eq!(
        (kept.hash, kept.reset),
        ([2; 32], None),
        "{case}: its hash alone"
    );
    // Friends: 3 and 4.
    s.present(&record(4, 3)).unwrap();
    s.befriend_dropping(&mb(3), &mb(4), at(5), None, &[])
        .unwrap();
    let kept = s.presentation(&fp(4), &fp(3)).unwrap().unwrap();
    assert_eq!(kept.reset, None, "{case}: a friendship's");
}

fn a_rotation_drops_the_offers_to_the_key_it_retires(s: &dyn RelationshipStore) {
    let case = "a_rotation_drops_the_offers_to_the_key_it_retires";
    asked_with(s, 1, 2, false);
    asked_with(s, 3, 2, true);
    asked_with(s, 2, 4, false);
    s.rotate(&fp(2), &fp(5)).unwrap();
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let row = s
        .relationship(&mb(1), &Mailbox::identified("m2", fp(5)), at(10))
        .unwrap();
    assert_eq!(
        row.and_then(|r| r.pending_out).map(|p| p.offer),
        Some(None),
        "{case}: a request to it stays, plain"
    );
    assert_eq!(
        s.offer(&fp(3), &fp(5), at(10)).unwrap(),
        None,
        "{case}: an upgrade goes"
    );
    assert!(
        s.offers_from(&fp(5), at(10))
            .unwrap()
            .iter()
            .any(|(to, _)| *to == fp(4)),
        "{case}: one from it moves"
    );
    let _ = mb;
}

fn a_record_leaving_takes_the_upgrade_it_qualified(s: &dyn RelationshipStore) {
    let case = "a_record_leaving_takes_the_upgrade_it_qualified";
    let record = |p: u8, o: u8, bytes: u8| Presentation {
        friendship: None,
        reset: Some(vec![bytes; 3]),
        ..presentation(p, o, bytes, 7)
    };
    // Kept by the same record recorded again; gone with another one,
    // with evidence in its place, and with the row dropped.
    for (n, (o, t)) in [(1, 2), (3, 4), (5, 6), (7, 8)].into_iter().enumerate() {
        s.present(&record(t, o, 1)).unwrap();
        asked_with(s, o, t, true);
        match n {
            0 => drop(s.present(&record(t, o, 1)).unwrap()),
            1 => drop(s.present(&record(t, o, 2)).unwrap()),
            2 => drop(s.present(&presentation(t, o, 3, 7)).unwrap()),
            _ => drop(s.drop_presentations(&fp(t), &fp(o), &[fp(t)]).unwrap()),
        }
        let waits = s.offer(&fp(o), &fp(t), at(10)).unwrap().is_some();
        assert_eq!(waits, n == 0, "{case}: {n}");
        assert_eq!(
            asked(s, o, t, 10).is_some(),
            n == 0,
            "{case}: {n}, its pending out"
        );
    }
}

fn an_upgrade_beside_a_friendship_ends_with_it(s: &dyn RelationshipStore) {
    let case = "an_upgrade_beside_a_friendship_ends_with_it";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    s.befriend(&mb(1), &mb(2), at(1)).unwrap();
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(1000),
    };
    s.set_offer(&fp(1), &fp(2), Some(&offer)).unwrap();
    let end = Ending {
        friendship: true,
        ..Ending::default()
    };
    s.end_friendship(&mb(1), &mb(2), &end).unwrap();
    assert_eq!(s.offer(&fp(1), &fp(2), at(10)).unwrap(), None, "{case}");
}

fn a_rotation_into_a_pair_keeps_each_direction_one_state(s: &dyn RelationshipStore) {
    let case = "a_rotation_into_a_pair_keeps_each_direction_one_state";
    let record = |p: u8, o: u8| Presentation {
        friendship: None,
        reset: Some(vec![p; 3]),
        ..presentation(p, o, p, 7)
    };
    // 2's record for 1's upgrade, and 2 rotating to 5, which presented
    // to 1 already: the successor keeps its own, and the upgrade goes.
    s.present(&record(2, 1)).unwrap();
    asked_with(s, 1, 2, true);
    s.present(&presentation(5, 1, 9, 7)).unwrap();
    s.rotate(&fp(2), &fp(5)).unwrap();
    assert_eq!(
        s.offer(&fp(1), &fp(5), at(10)).unwrap(),
        None,
        "{case}: no record, no upgrade"
    );
    assert_eq!(asked(s, 1, 5, 10), None, "{case}: nor its pending out");
    // 3's upgrade to 4, and 3 rotating to 6, which asked 4 already: the
    // request stays, the upgrade goes.
    s.present(&record(4, 3)).unwrap();
    asked_with(s, 3, 4, true);
    let req = asked_with(s, 6, 4, false);
    s.rotate(&fp(3), &fp(6)).unwrap();
    assert_eq!(
        s.offer(&fp(6), &fp(4), at(10)).unwrap(),
        None,
        "{case}: never both"
    );
    assert_eq!(asked(s, 6, 4, 10), Some((true, Some(req.offer))), "{case}");
}

fn a_row_left_with_nothing_is_reclaimed(s: &dyn RelationshipStore) {
    let case = "a_row_left_with_nothing_is_reclaimed";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let record = |p: u8, o: u8| Presentation {
        friendship: None,
        reset: Some(vec![p; 3]),
        ..presentation(p, o, p, 7)
    };
    // By a drop, by its record going, and by a rotation's settling.
    asked_with(s, 1, 2, true);
    s.drop_offers(&[(fp(1), fp(2))]).unwrap();
    assert_eq!(s.purge_count(&mb(1)).unwrap(), 0, "{case}: dropped");
    s.present(&record(4, 3)).unwrap();
    asked_with(s, 3, 4, true);
    s.unpresent(&fp(4), &fp(3)).unwrap();
    assert_eq!(s.purge_count(&mb(3)).unwrap(), 0, "{case}: its record gone");
    asked_with(s, 5, 6, true);
    s.rotate(&fp(6), &fp(7)).unwrap();
    assert_eq!(s.purge_count(&mb(5)).unwrap(), 0, "{case}: settled");
}

fn a_record_is_kept_while_its_upgrade_is_pending(s: &dyn RelationshipStore) {
    let case = "a_record_is_kept_while_its_upgrade_is_pending";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    s.present(&Presentation {
        friendship: None,
        reset: Some(vec![2; 3]),
        at: at(10),
        ..presentation(2, 1, 2, 7)
    })
    .unwrap();
    let shown = PendingOut {
        upgrade: true,
        ..pending(1, 1000, true)
    };
    let offer = StoredOffer {
        offer: vec![1],
        lapses_at: at(25),
    };
    s.ask(&mb(1), &mb(2), &shown, Some(&offer), None, &Report::none())
        .unwrap();
    assert_eq!(
        s.lapse_resets(at(20), at(30)).unwrap(),
        0,
        "{case}: its pending out keeps it, the offer lapsed"
    );
    assert_eq!(
        s.lapse_resets(at(20), at(1000)).unwrap(),
        1,
        "{case}: until the pending out lapses"
    );
}

fn a_rotation_keeps_the_upgrades_the_successor_and_the_other_party_hold(s: &dyn RelationshipStore) {
    let case = "a_rotation_keeps_the_upgrades_the_successor_and_the_other_party_hold";
    let mb = |n: u8| Mailbox::identified(format!("m{n}"), fp(n));
    let record = |p: u8, o: u8, bytes: u8| Presentation {
        friendship: None,
        reset: Some(vec![bytes; 3]),
        ..presentation(p, o, bytes, 7)
    };
    let shown = |from: u8, to: u8| {
        s.relationship(&mb(from), &mb(to), at(10))
            .unwrap()
            .and_then(|r| r.pending_out)
            .is_some_and(|p| p.upgrade)
    };
    let offered = |from: u8, to: u8| {
        s.offer(&fp(from), &fp(to), at(10))
            .unwrap()
            .map(|o| o.offer)
    };
    // 1 and its successor 5 each have an upgrade to 2, on records 2 holds
    // for each: the successor's own stays, offer and all.
    s.present(&record(2, 1, 2)).unwrap();
    s.present(&record(2, 5, 9)).unwrap();
    asked_with(s, 1, 2, true);
    asked_with(s, 5, 2, true);
    // 3 has upgrades to both 1 and 5, on records each holds for it: the
    // one to the successor stays, the one to the key retired goes.
    s.present(&record(1, 3, 4)).unwrap();
    s.present(&record(5, 3, 6)).unwrap();
    asked_with(s, 3, 1, true);
    asked_with(s, 3, 5, true);
    // 4 has an upgrade to 1 alone: it goes, its pending out with it; and
    // 6's pending out to 1, its offer already gone, goes too.
    s.present(&record(1, 4, 8)).unwrap();
    asked_with(s, 4, 1, true);
    s.present(&record(1, 6, 3)).unwrap();
    asked_with(s, 6, 1, true);
    s.set_offer(&fp(6), &fp(1), None).unwrap();
    s.rotate(&fp(1), &fp(5)).unwrap();
    assert!(shown(5, 2), "{case}: the successor's own");
    assert_eq!(offered(5, 2), Some(vec![5, 2]), "{case}: its own offer");
    assert!(shown(3, 5), "{case}: the other's to the successor");
    assert_eq!(offered(3, 5), Some(vec![3, 5]), "{case}: its own offer");
    assert!(
        !shown(4, 5),
        "{case}: one to the key retired, pending out and all"
    );
    assert_eq!(offered(4, 5), None, "{case}: nor its offer");
    assert!(
        !shown(6, 5),
        "{case}: a pending out whose offer went before"
    );
}

fn an_upgrade_goes_where_a_rotation_keeps_another_record(s: &dyn RelationshipStore) {
    let case = "an_upgrade_goes_where_a_rotation_keeps_another_record";
    // 1's upgrade offer to 2, on 2's record; 1 rotates to 5, where 2 kept
    // a record of another friendship: that one stays, and the upgrade
    // taken on the first goes with it. 3's to 4, on a record that moves
    // whole with 3's rotation to 6, stays.
    let record = |p: u8, o: u8, bytes: u8| Presentation {
        friendship: None,
        reset: Some(vec![bytes; 3]),
        ..presentation(p, o, bytes, 7)
    };
    s.present(&record(2, 1, 2)).unwrap();
    asked_with(s, 1, 2, true);
    s.present(&record(2, 5, 9)).unwrap();
    s.rotate(&fp(1), &fp(5)).unwrap();
    assert_eq!(asked(s, 5, 2, 10), None, "{case}: another record");
    assert_eq!(s.offer(&fp(5), &fp(2), at(10)).unwrap(), None, "{case}");
    s.present(&record(4, 3, 4)).unwrap();
    asked_with(s, 3, 4, true);
    s.rotate(&fp(3), &fp(6)).unwrap();
    assert!(asked(s, 6, 4, 10).is_some(), "{case}: its own record");
    assert!(s.offer(&fp(6), &fp(4), at(10)).unwrap().is_some(), "{case}");
}

fn a_merged_pending_out_goes_with_its_record(s: &dyn RelationshipStore) {
    let case = "a_merged_pending_out_goes_with_its_record";
    // 1's upgrade offer to 2, on 2's record; 1 rotates to 5, toward which
    // 2 has presented already, so 2's record collides with its own row
    // and the successor keeps that one: the upgrade's record is gone.
    s.present(&Presentation {
        friendship: None,
        reset: Some(vec![2; 3]),
        ..presentation(2, 1, 2, 7)
    })
    .unwrap();
    asked_with(s, 1, 2, true);
    s.present(&presentation(2, 5, 9, 7)).unwrap();
    s.rotate(&fp(1), &fp(5)).unwrap();
    assert_eq!(
        asked(s, 5, 2, 10),
        None,
        "{case}: no record, no pending out"
    );
    assert_eq!(
        s.offer(&fp(5), &fp(2), at(10)).unwrap(),
        None,
        "{case}: nor its offer"
    );
}

/// One of every kind of work, each under a cause of its own.
fn every_owed() -> Vec<(Work, Cause)> {
    vec![
        (
            Work::DropOffersBy {
                under: Some(fp(1)),
                device: fp(7),
            },
            Cause::PublishedDevice {
                identity: fp(1),
                device: fp(7),
            },
        ),
        (
            Work::DropOffersBy {
                under: None,
                device: fp(7),
            },
            Cause::OperatorDevice(fp(7)),
        ),
        (
            Work::DropOffersNaming(fp(1)),
            Cause::OperatorIdentity(fp(1)),
        ),
        (
            Work::DropOffersNaming(fp(1)),
            Cause::PublishedIdentity(fp(1)),
        ),
        (
            Work::DropPresentedBy {
                under: Some(fp(1)),
                device: fp(7),
            },
            Cause::PublishedDevice {
                identity: fp(1),
                device: fp(7),
            },
        ),
        (
            Work::DropPresentedBy {
                under: None,
                device: fp(7),
            },
            Cause::OperatorDevice(fp(7)),
        ),
        (Work::DropPresentationsOf(fp(1)), Cause::Unlinked),
        (Work::Judge(fp(1), fp(2)), Cause::Always),
        (Work::Judge(fp(2), fp(1)), Cause::Always),
        (Work::Settle(fp(1)), Cause::Always),
    ]
}

fn owed_work_is_one_piece_per_owe_until_settled(s: &dyn RelationshipStore) {
    let case = "owed_work_is_one_piece_per_owe_until_settled";
    let every = every_owed();
    let ids = s.owe(&every).unwrap();
    let mut distinct = ids.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), every.len(), "{case}: one id each: {ids:?}");
    let read = |s: &dyn RelationshipStore| {
        s.owed()
            .unwrap()
            .into_iter()
            .map(|o| (o.id, (o.work, o.cause)))
            .collect::<Vec<_>>()
    };
    let want: Vec<_> = ids.iter().copied().zip(every.iter().cloned()).collect();
    assert_eq!(read(s), want, "{case}: read back whole, oldest first");
    let again = [every[2].clone(), every[0].clone(), every[2].clone()];
    assert_eq!(
        s.owe(&again).unwrap(),
        [ids[2], ids[0], ids[2]],
        "{case}: owed again is the same piece"
    );
    assert_eq!(read(s), want, "{case}: and no more of it");
    s.settle(&[ids[0], ids[3], ids[0], 1 << 40]).unwrap();
    let left: Vec<_> = (want.iter().enumerate())
        .filter(|(i, _)| ![0, 3].contains(i))
        .map(|(_, w)| w.clone())
        .collect();
    assert_eq!(read(s), left, "{case}: settled, the rest untouched");
    s.settle(&ids).unwrap();
    let anew = s.owe(&every[..1]).unwrap()[0];
    assert!(!ids.contains(&anew), "{case}: an id is never reused");
}

#[cfg(any(test, feature = "test-support"))]
fn owed_work_is_written_and_settled_whole_with_its_write(s: &dyn RelationshipStore) {
    use super::{Did, Part};
    let case = "owed_work_is_written_and_settled_whole_with_its_write";
    let every = every_owed();
    let kept = s.owe(&every[..1]).unwrap()[0];
    let owe = |i: usize| Part::Owe(every[i].0.clone(), every[i].1.clone());
    let failing = [
        Part::Present(presentation(2, 1, 2, 7)),
        owe(1),
        Part::Settle(kept),
        owe(2),
        Part::Fail,
    ];
    assert!(
        s.write(&failing, &Report::none()).is_err(),
        "{case}: failed"
    );
    let owed = s.owed().unwrap();
    assert_eq!(
        owed.iter().map(|o| o.id).collect::<Vec<_>>(),
        [kept],
        "{case}: nothing owed or settled: {owed:?}"
    );
    assert_eq!(s.presentation(&fp(2), &fp(1)).unwrap(), None, "{case}");
    let (did, _) = s
        .write(&[owe(1), Part::Settle(kept), owe(1)], &Report::none())
        .unwrap();
    let Did::Owed(id) = did[0] else {
        panic!("{case}: answered {did:?}")
    };
    assert_eq!(
        did,
        [Did::Owed(id), Did::Nothing, Did::Owed(id)],
        "{case}: answered"
    );
    let owed = s.owed().unwrap();
    assert_eq!(
        owed.iter()
            .map(|o| (o.id, o.work.clone()))
            .collect::<Vec<_>>(),
        [(id, every[1].0.clone())],
        "{case}: owed and settled"
    );
}

fn a_rotation_moves_owed_work_and_folds_what_it_duplicates(s: &dyn RelationshipStore) {
    let case = "a_rotation_moves_owed_work_and_folds_what_it_duplicates";
    let owing = [
        (Work::Judge(fp(1), fp(3)), Cause::Always),
        (Work::Judge(fp(3), fp(1)), Cause::Always),
        (
            Work::DropOffersNaming(fp(1)),
            Cause::OperatorIdentity(fp(1)),
        ),
        (
            Work::DropPresentedBy {
                under: Some(fp(1)),
                device: fp(1),
            },
            Cause::PublishedDevice {
                identity: fp(1),
                device: fp(1),
            },
        ),
        (Work::Settle(fp(1)), Cause::Always),
        (Work::Settle(fp(2)), Cause::Always),
        (Work::DropPresentationsOf(fp(3)), Cause::Unlinked),
        (Work::DropPresentationsOf(fp(1)), Cause::Unlinked),
        (Work::DropPresentationsOf(fp(2)), Cause::Unlinked),
        (Work::Judge(fp(4), fp(3)), Cause::Always),
        (
            Work::DropOffersNaming(fp(2)),
            Cause::PublishedIdentity(fp(2)),
        ),
        (Work::Judge(fp(1), fp(2)), Cause::Always),
        (Work::Judge(fp(2), fp(1)), Cause::Always),
        (
            Work::DropOffersBy {
                under: Some(fp(1)),
                device: fp(1),
            },
            Cause::Always,
        ),
        (
            Work::DropOffersBy {
                under: None,
                device: fp(1),
            },
            Cause::Always,
        ),
    ];
    let ids = s.owe(&owing).unwrap();
    let rekeyed = s.rotate(&fp(1), &fp(2)).unwrap();
    assert_eq!(
        rekeyed.owed_merged,
        [(ids[4], ids[5]), (ids[7], ids[8]), (ids[12], ids[11])],
        "{case}: folded into what the successor owed"
    );
    let read = || {
        s.owed()
            .unwrap()
            .into_iter()
            .map(|o| (o.id, o.work, o.cause))
            .collect::<Vec<_>>()
    };
    let at = |i: usize, work: Work| (ids[i], work, owing[i].1.clone());
    assert_eq!(
        read(),
        [
            at(0, Work::Judge(fp(2), fp(3))),
            at(1, Work::Judge(fp(3), fp(2))),
            at(2, Work::DropOffersNaming(fp(2))),
            at(
                3,
                Work::DropPresentedBy {
                    under: Some(fp(2)),
                    device: fp(1),
                }
            ),
            at(5, Work::Settle(fp(2))),
            at(6, Work::DropPresentationsOf(fp(3))),
            at(8, Work::DropPresentationsOf(fp(2))),
            at(9, Work::Judge(fp(4), fp(3))),
            at(10, Work::DropOffersNaming(fp(2))),
            at(11, Work::Judge(fp(2), fp(2))),
            at(
                13,
                Work::DropOffersBy {
                    under: Some(fp(2)),
                    device: fp(1),
                }
            ),
            at(
                14,
                Work::DropOffersBy {
                    under: None,
                    device: fp(1),
                }
            ),
        ],
        "{case}: keys moved, devices and causes as they were"
    );
    let rekeyed = s.rotate(&fp(2), &fp(4)).unwrap();
    assert_eq!(
        rekeyed.owed_merged,
        [(ids[0], ids[9])],
        "{case}: a second hop folds too"
    );
    assert_eq!(
        read(),
        [
            at(1, Work::Judge(fp(3), fp(4))),
            at(2, Work::DropOffersNaming(fp(4))),
            at(
                3,
                Work::DropPresentedBy {
                    under: Some(fp(4)),
                    device: fp(1),
                }
            ),
            at(5, Work::Settle(fp(4))),
            at(6, Work::DropPresentationsOf(fp(3))),
            at(8, Work::DropPresentationsOf(fp(4))),
            at(9, Work::Judge(fp(4), fp(3))),
            at(10, Work::DropOffersNaming(fp(4))),
            at(11, Work::Judge(fp(4), fp(4))),
            at(
                13,
                Work::DropOffersBy {
                    under: Some(fp(4)),
                    device: fp(1),
                }
            ),
            at(
                14,
                Work::DropOffersBy {
                    under: None,
                    device: fp(1),
                }
            ),
        ],
        "{case}: two hops"
    );
}

/// A rotation records its move in its step, and work owed there, or after
/// it under the key it left, by `owe`, a write or a claim, names the key
/// the rows went to; a device and a cause are kept as given.
fn work_owed_after_a_rotation_is_owed_where_its_rows_went(s: &dyn RelationshipStore) {
    use super::{Did, OwedId, Part};
    let case = "work_owed_after_a_rotation_is_owed_where_its_rows_went";
    assert_eq!(s.moved(&fp(1)).unwrap(), fp(1), "{case}: never moved");
    let owing = [
        (Work::Settle(fp(2)), Cause::Always),
        (Work::DropOffersNaming(fp(2)), Cause::Unlinked),
        (Work::Settle(fp(1)), Cause::OperatorIdentity(fp(1))),
    ];
    let (rekeyed, _) = s
        .rotate_reporting(&fp(1), &fp(2), &Report::none(), &owing)
        .unwrap();
    let read = || {
        let owed = s.owed().unwrap().into_iter();
        owed.map(|o| (o.id, o.work, o.cause)).collect::<Vec<_>>()
    };
    let at = |id: OwedId, (w, c): &(Work, Cause)| (id, w.clone(), c.clone());
    assert_eq!(
        read(),
        [
            at(rekeyed.owed[0], &owing[0]),
            at(rekeyed.owed[1], &owing[1]),
            (rekeyed.owed[2], Work::Settle(fp(2)), owing[2].1.clone()),
        ],
        "{case}: owed in the rotation's step once its rows moved, answered in order"
    );
    s.rotate(&fp(2), &fp(3)).unwrap();
    for k in [1, 2, 3] {
        assert_eq!(s.moved(&fp(k)).unwrap(), fp(3), "{case}: {k} moved on");
    }
    s.settle(&rekeyed.owed).unwrap();
    let late = (
        Work::DropOffersBy {
            under: Some(fp(1)),
            device: fp(1),
        },
        Cause::OperatorIdentity(fp(1)),
    );
    let id = s.owe(std::slice::from_ref(&late)).unwrap()[0];
    let (did, _) = s
        .write(
            &[Part::Owe(Work::Judge(fp(5), fp(2)), Cause::Always)],
            &Report::none(),
        )
        .unwrap();
    let [Did::Owed(judged)] = did[..] else {
        panic!("{case}: {did:?}");
    };
    let claimed = s
        .claim("dave", &fp(7), &[(Work::Settle(fp(1)), Cause::Always)])
        .unwrap();
    let moved = Work::DropOffersBy {
        under: Some(fp(3)),
        device: fp(1),
    };
    assert_eq!(
        read(),
        [
            (id, moved, late.1),
            (judged, Work::Judge(fp(5), fp(3)), Cause::Always),
            (claimed.owed[0], Work::Settle(fp(3)), Cause::Always),
        ],
        "{case}: owed where the rows went, its device and cause as given"
    );
    // A rotation back to a key the rows left: its moves forgotten.
    s.rotate(&fp(3), &fp(1)).unwrap();
    for k in [1, 2, 3] {
        assert_eq!(s.moved(&fp(k)).unwrap(), fp(1), "{case}: {k} moved back");
    }
}

/// A chain of moves is followed to its end, however long.
fn a_chain_of_moves_is_followed_to_its_end(s: &dyn RelationshipStore) {
    let case = "a_chain_of_moves_is_followed_to_its_end";
    for n in 100..165 {
        s.rotate(&fp(n), &fp(n + 1)).unwrap();
    }
    assert_eq!(s.moved(&fp(100)).unwrap(), fp(165), "{case}: 65 moves");
}

/// Sequences [`the_moves_say_where_the_rows_are`] failed on, kept: a
/// rotation to itself, then work owed there; one into a key that moved
/// on, holding rows; one made again after its successor moved on; one
/// from a key that moved on, to another; and one made again after the
/// rows went back and on.
pub const MOVES_FOUND: &[&[u32]] = &[
    &[rot(6, 6), owe(6)],
    &[rot(1, 2), rot(2, 3), place(4), rot(4, 2)],
    &[place(1), rot(1, 2), rot(2, 3), again(0), owe(1)],
    &[place(4), rot(4, 2), rot(4, 5)],
    &[place(1), rot(2, 1), rot(1, 2), rot(2, 3), again(0)],
];

const fn place(k: u32) -> u32 {
    (k - 1) << 8
}

const fn owe(k: u32) -> u32 {
    1 | (k - 1) << 8
}

/// The `i`th rotation made again.
const fn again(i: u32) -> u32 {
    2 | i << 8
}

const fn rot(from: u32, to: u32) -> u32 {
    3 | (from - 1) << 8 | (to - 1) << 16
}

/// Rotations drawn from `steps` over a few keys, each key's rows placed
/// while they are its own, and work owed under any key: after every step
/// each key's [`RelationshipStore::moved`] answers where its rows are,
/// never an error, and each piece of owed work sits where the rows of the
/// key it was owed under are. Where the rows are is a model's: a rotation
/// from a key to itself moves nothing, one into a key that moved on moves
/// to where that key's rows went, and one back to an earlier key moves
/// there.
pub fn the_moves_say_where_the_rows_are(s: &dyn RelationshipStore, steps: &[u32]) {
    const KEYS: u32 = 6;
    let key = |n: u32| ((n & 0xff) % KEYS) as u8 + 1;
    // Where each key's rows are, by the model.
    let mut model: Vec<u8> = (0..=KEYS as u8).collect();
    let mut placed = [false; KEYS as usize + 1];
    // Owed work, by the cause it is told apart by: the key it was owed
    // under.
    let mut owed: Vec<u8> = Vec::new();
    let mut rotations: Vec<(u8, u8)> = Vec::new();
    let owner = |k: u8| Mailbox::identified(format!("o{k}"), fp(k));
    let blocked = |k: u8| Mailbox::login(format!("x{k}"));
    let mut done = Vec::new();
    for (i, &n) in steps.iter().enumerate() {
        let (a, b) = (key(n >> 8), key(n >> 16));
        let step = match n % 8 {
            0 if !placed[a as usize] && model[a as usize] == a => {
                placed[a as usize] = true;
                s.set_blocked(&owner(a), &blocked(a), true, at(1)).unwrap();
                format!("place {a}")
            }
            1 if owed.len() < 64 => {
                let cause = Cause::OperatorIdentity([owed.len() as u8; 32]);
                owed.push(a);
                s.owe(&[(Work::Settle(fp(a)), cause)])
                    .unwrap_or_else(|e| panic!("{steps:?} step {i}: owe under {a}: {e}"));
                format!("owe under {a}")
            }
            2 if !rotations.is_empty() => {
                let (from, to) = rotations[(n >> 8 & 0xff) as usize % rotations.len()];
                rotate(s, &mut model, from, to, steps, i);
                format!("again {from} -> {to}")
            }
            _ => {
                rotations.push((a, b));
                rotate(s, &mut model, a, b, steps, i);
                format!("{a} -> {b}")
            }
        };
        done.push(step);
        let what = format!("{steps:?}: {}", done.join(", "));
        for k in 1..=KEYS as u8 {
            let moved = s
                .moved(&fp(k))
                .unwrap_or_else(|e| panic!("{what}: moved({k}): {e}"));
            assert_eq!(moved, fp(model[k as usize]), "{what}: moved({k})");
            let mut holds = logins(s.blocked(&Mailbox::identified("", fp(k))).unwrap());
            holds.sort();
            let mut rows: Vec<String> = (1..=KEYS as u8)
                .filter(|&t| placed[t as usize] && model[t as usize] == k)
                .map(|t| format!("x{t}"))
                .collect();
            rows.sort();
            assert_eq!(holds, rows, "{what}: the rows at {k}");
        }
        let mut stored: Vec<_> = (s.owed().unwrap().into_iter())
            .map(|o| match (o.work, o.cause) {
                (Work::Settle(k), Cause::OperatorIdentity(c)) => (c[0], k[0]),
                other => panic!("{what}: {other:?}"),
            })
            .collect();
        stored.sort();
        let owing: Vec<_> = (owed.iter().enumerate())
            .map(|(c, &k)| (c as u8, model[k as usize]))
            .collect();
        assert_eq!(stored, owing, "{what}: owed where the rows are");
    }
}

/// A rotation, made in the store and in the model of where rows are.
fn rotate(s: &dyn RelationshipStore, model: &mut [u8], from: u8, to: u8, steps: &[u32], i: usize) {
    s.rotate(&fp(from), &fp(to))
        .unwrap_or_else(|e| panic!("{steps:?} step {i}: {from} -> {to}: {e}"));
    if from == to {
        return;
    }
    let end = model[to as usize];
    let dest = if end == from { to } else { end };
    for k in model.iter_mut() {
        if *k == from {
            *k = dest;
        }
    }
}
