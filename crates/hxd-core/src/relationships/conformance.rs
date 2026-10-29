//! A suite every [`RelationshipStore`] must pass, for the reason
//! [`crate::inbox::conformance`] gives: the in-memory store and SQLite's
//! must agree exactly, and above all about which mailbox a row is
//! keyed by, where a disagreement is a block that stopped applying.
//!
//! Clocks are fixed values, never `SystemTime::now()`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    AccountUpdate, Birthdate, Ignore, IgnoreMode, LedgerEntry, MessagingAccount, PendingOut,
    Profile, Recorded, RelationshipStore, RequestKind, Requester,
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
    the_ledger_counts_what_was_sent_and_answers_a_retry(&*new_store());
    a_listing_takes_the_dropped_count(&*new_store());
    an_account_keeps_what_it_was_told_and_nothing_else(&*new_store());
    the_cleanup_changes_no_answer(&*new_store());
    times_are_kept_to_the_second(&*new_store());
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
            takes_requests: Some(true),
            opted_at: Some(at(5)),
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
            discoverable: Some(true),
            takes_requests: Some(false),
            opted_at: None,
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
    assert!(got.discoverable && !got.takes_requests, "{case}: kept");
    assert_eq!(
        got.requests_opted_at, None,
        "{case}: opting out forgets when"
    );
    assert_eq!(
        got.profile,
        Profile {
            languages: vec!["en".into(), "ru".into(), "fr".into()],
            ..profile
        },
        "{case}: the profile whole, with at most three languages"
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
