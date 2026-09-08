//! A suite every [`MessageStore`] must pass.
//!
//! The inbox has two implementations that must agree exactly — the
//! in-memory one this crate's tests run against, and the SQLite one a
//! server actually stores mail in — and the way that goes wrong is quiet
//! drift in the corners: the `delivered_at` stamp [`MessageStore::mark_read`]
//! sets, the two clocks [`MessageStore::prune`] measures against, and
//! above all [`Mailbox`]'s matching rule, where a disagreement means mail
//! delivered to the wrong person. So the cases live here once rather than
//! being written twice and diverging once.
//!
//! Public, like [`crate::voice::fake`], because the implementation it
//! most needs to check is in another crate.
//!
//! Clocks are fixed values, never `SystemTime::now()`: a store test that
//! reads the wall clock is a store test that fails at midnight.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageStore, NewMessage,
    Pushed,
};

/// Run every case against a freshly built store. `new_store` is called
/// once per case, so no case can see another's mail.
///
/// Panics with the failing case's name, which is what a test failure in
/// an implementation crate has to be able to tell you.
pub fn run(new_store: &dyn Fn() -> Box<dyn MessageStore>) {
    pending_is_oldest_first_and_bounded(&*new_store());
    a_message_round_trips_whole(&*new_store());
    delivery_is_idempotent_and_removes_from_pending(&*new_store());
    reading_stamps_delivery_so_it_is_never_flushed_later(&*new_store());
    mark_read_never_reaches_another_mailbox(&*new_store());
    list_is_newest_first_and_pages_backwards(&*new_store());
    counts_of_a_mailbox_with_no_mail_are_zero(&*new_store());
    prune_ages_unread_from_sent_and_read_from_read(&*new_store());
    a_retention_window_older_than_the_clock_prunes_nothing(&*new_store());
    // The mailbox key — where a disagreement is a wrong-recipient bug.
    an_identity_and_a_bare_login_are_different_mailboxes(&*new_store());
    claiming_moves_a_logins_mail_onto_its_new_fingerprint(&*new_store());
    a_rename_takes_the_mailbox_and_leaves_the_login_free(&*new_store());
    purging_takes_everything_on_both_sides(&*new_store());
    rotation_moves_a_mailbox_and_its_blocks_to_the_successor_key(&*new_store());
    claiming_merges_a_guid_that_exists_on_both_sides(&*new_store());
    claiming_merges_a_guid_the_sender_sent_twice(&*new_store());
    claiming_merges_a_duplicate_the_recipient_was_renamed_out_of(&*new_store());
    a_collapse_keeps_what_the_duplicate_knew(&*new_store());
    rotating_merges_a_guid_the_successor_already_holds(&*new_store());
    rotating_merges_a_guid_the_sender_sent_twice(&*new_store());
    a_merge_leaves_one_block_per_pair(&*new_store());
    // Blocking.
    blocks_are_directional_and_idempotent(&*new_store());
    blocks_follow_an_identity_and_are_listed(&*new_store());
    // Retry, and the kinds the inbox holds but does not show.
    the_same_guid_twice_is_one_message(&*new_store());
    pushing_the_same_guid_twice_stores_one_row(&*new_store());
    the_cap_is_enforced_by_the_insert(&*new_store());
    a_flush_can_stamp_read_in_the_same_step(&*new_store());
    a_guid_is_scoped_to_one_sender_and_one_recipient(&*new_store());
    a_receipt_is_stored_but_never_read_as_mail(&*new_store());
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A distinguishable fingerprint. Bytes, because that is what a mailbox
/// key is — see `Mailbox`.
fn fp(n: u8) -> [u8; 32] {
    [n; 32]
}

fn guid(n: u8) -> MessageGuid {
    MessageGuid::parse(&format!("{n:08x}-0000-4000-8000-000000000000")).unwrap()
}

fn msg(to: &Mailbox, from: &Mailbox, body: &str, sent_at: SystemTime) -> NewMessage {
    NewMessage {
        recipient: to.clone(),
        sender: Some(from.clone()),
        sender_nick: from.login.clone(),
        body: body.into(),
        sent_at,
        guid: None,
        kind: MessageKind::Message,
    }
}

/// `push` with the cap out of the way and the id unwrapped: every case
/// below is about something other than the cap, and the cap has its own.
fn push(s: &dyn MessageStore, m: &NewMessage) -> MessageId {
    match s.push(m, usize::MAX).unwrap() {
        Pushed::Stored(id) => id,
        other => panic!("expected a new row, got {other:?}"),
    }
}

fn bodies(msgs: &[super::StoredMessage]) -> Vec<&str> {
    msgs.iter().map(|m| m.body.as_str()).collect()
}

fn a_message_round_trips_whole(s: &dyn MessageStore) {
    let case = "a_message_round_trips_whole";
    let id = push(
        s,
        &NewMessage {
            recipient: Mailbox::identified("dave", fp(1)),
            // None: the sender was a plain guest, with nothing durable
            // about it at all.
            sender: None,
            sender_nick: "Мишенька 🎈".into(),
            body: "line one\nline two".into(),
            sent_at: at(1_700_000_000),
            guid: None,
            kind: MessageKind::Message,
        },
    );
    let got = &s.pending(&Mailbox::identified("dave", fp(1)), 10).unwrap()[0];
    assert_eq!(got.id, id, "{case}: id");
    assert_eq!(got.recipient.login, "dave", "{case}: login");
    assert_eq!(
        got.recipient.fingerprint,
        Some(fp(1)),
        "{case}: fingerprint"
    );
    assert_eq!(got.sender, None, "{case}: an accountless sender stays None");
    assert_eq!(got.sender_nick, "Мишенька 🎈", "{case}: nick is UTF-8");
    assert_eq!(got.body, "line one\nline two", "{case}: body keeps its LF");
    assert_eq!(got.sent_at, at(1_700_000_000), "{case}: sent_at");
    assert_eq!(got.delivered_at, None, "{case}: not delivered yet");
    assert_eq!(got.read_at, None, "{case}: not read yet");
}

fn pending_is_oldest_first_and_bounded(s: &dyn MessageStore) {
    let case = "pending_is_oldest_first_and_bounded";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    for i in 0..5 {
        push(s, &msg(&dave, &alice, &format!("m{i}"), at(i)));
    }
    let got = s.pending(&dave, 3).unwrap();
    assert_eq!(bodies(&got), ["m0", "m1", "m2"], "{case}");
    assert_eq!(
        s.pending_count(&dave).unwrap(),
        5,
        "{case}: the count is what is waiting, not what one flush takes"
    );
    assert!(
        s.pending(&Mailbox::login("nobody"), 10).unwrap().is_empty(),
        "{case}: another mailbox's pending is its own"
    );
}

fn delivery_is_idempotent_and_removes_from_pending(s: &dyn MessageStore) {
    let case = "delivery_is_idempotent_and_removes_from_pending";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let id = push(s, &msg(&dave, &alice, "hi", at(1)));
    s.mark_delivered(&[id], at(10), Delivery::Delivered)
        .unwrap();
    s.mark_delivered(&[id], at(20), Delivery::Delivered)
        .unwrap();
    assert!(s.pending(&dave, 10).unwrap().is_empty(), "{case}: flushed");
    assert_eq!(s.pending_count(&dave).unwrap(), 0, "{case}: none waiting");
    assert_eq!(
        s.list(&dave, None, 1).unwrap()[0].delivered_at,
        Some(at(10)),
        "{case}: a second flush must not restamp it"
    );
    assert_eq!(
        s.counts(&dave).unwrap(),
        InboxCounts {
            unread: 1,
            total: 1
        },
        "{case}: delivered is not read — the badge still counts it"
    );
    // An empty flush is legal and touches nothing.
    s.mark_delivered(&[], at(30), Delivery::Delivered).unwrap();
}

fn reading_stamps_delivery_so_it_is_never_flushed_later(s: &dyn MessageStore) {
    let case = "reading_stamps_delivery_so_it_is_never_flushed_later";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let id = push(s, &msg(&dave, &alice, "hi", at(1)));
    assert_eq!(s.mark_read(&dave, id, at(5)).unwrap(), 1, "{case}: marked");
    assert!(
        s.pending(&dave, 10).unwrap().is_empty(),
        "{case}: a message read out of `list` must not flush later"
    );
    assert_eq!(
        s.list(&dave, None, 1).unwrap()[0].delivered_at,
        Some(at(5)),
        "{case}: reading implies delivery"
    );
    assert_eq!(
        s.mark_read(&dave, id, at(9)).unwrap(),
        0,
        "{case}: marking twice marks nothing"
    );
}

fn mark_read_never_reaches_another_mailbox(s: &dyn MessageStore) {
    let case = "mark_read_never_reaches_another_mailbox";
    let (dave, bob, alice) = (
        Mailbox::login("dave"),
        Mailbox::login("bob"),
        Mailbox::login("alice"),
    );
    push(s, &msg(&dave, &alice, "for dave", at(1)));
    let theirs = push(s, &msg(&bob, &alice, "for bob", at(2)));
    // A client naming an id it does not own marks only its own mail.
    assert_eq!(
        s.mark_read(&dave, theirs, at(5)).unwrap(),
        1,
        "{case}: only dave's"
    );
    assert_eq!(
        s.counts(&bob).unwrap().unread,
        1,
        "{case}: bob's mail is untouched"
    );
}

fn list_is_newest_first_and_pages_backwards(s: &dyn MessageStore) {
    let case = "list_is_newest_first_and_pages_backwards";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let ids: Vec<MessageId> = (0..5)
        .map(|i| push(s, &msg(&dave, &alice, &format!("m{i}"), at(i))))
        .collect();
    let page = s.list(&dave, None, 2).unwrap();
    assert_eq!(bodies(&page), ["m4", "m3"], "{case}: first page");
    let next = s.list(&dave, Some(ids[3]), 2).unwrap();
    assert_eq!(bodies(&next), ["m2", "m1"], "{case}: `before` is exclusive");
    assert!(
        s.list(&dave, Some(ids[0]), 10).unwrap().is_empty(),
        "{case}: paging past the start ends"
    );
}

fn counts_of_a_mailbox_with_no_mail_are_zero(s: &dyn MessageStore) {
    let case = "counts_of_a_mailbox_with_no_mail_are_zero";
    assert_eq!(
        s.counts(&Mailbox::login("nobody")).unwrap(),
        InboxCounts::default(),
        "{case}: no row, not an error"
    );
}

fn prune_ages_unread_from_sent_and_read_from_read(s: &dyn MessageStore) {
    let case = "prune_ages_unread_from_sent_and_read_from_read";
    let (dave, a) = (Mailbox::login("dave"), Mailbox::login("a"));
    // Pushed and read in id order, because mark_read sweeps everything up
    // to the id it is given.
    let ancient = push(s, &msg(&dave, &a, "ancient", at(0)));
    s.mark_read(&dave, ancient, at(100)).unwrap();
    let recent = push(s, &msg(&dave, &a, "recent", at(0)));
    s.mark_read(&dave, recent, at(890)).unwrap();
    push(s, &msg(&dave, &a, "old unread", at(0)));
    push(s, &msg(&dave, &a, "fresh", at(900)));

    // At t=1000, unread kept 500s and read kept 200s. Both clocks bite
    // once: "ancient" was read long ago, "old unread" was sent long ago —
    // and "recent" survives despite being as old as either of them,
    // because it was read recently.
    let n = s
        .prune(at(1000), Duration::from_secs(500), Duration::from_secs(200))
        .unwrap();
    assert_eq!(n, 2, "{case}: one per clock");
    let left = s.list(&dave, None, 10).unwrap();
    assert_eq!(bodies(&left), ["fresh", "recent"], "{case}: survivors");
}

fn a_retention_window_older_than_the_clock_prunes_nothing(s: &dyn MessageStore) {
    let case = "a_retention_window_older_than_the_clock_prunes_nothing";
    let (dave, a) = (Mailbox::login("dave"), Mailbox::login("a"));
    push(s, &msg(&dave, &a, "hi", at(10)));
    let forever = Duration::from_secs(u32::MAX as u64);
    assert_eq!(
        s.prune(at(1000), forever, forever).unwrap(),
        0,
        "{case}: a cutoff before the epoch must floor, not wrap"
    );
}

// --- The mailbox key -----------------------------------------------------

fn an_identity_and_a_bare_login_are_different_mailboxes(s: &dyn MessageStore) {
    let case = "an_identity_and_a_bare_login_are_different_mailboxes";
    let bare = Mailbox::login("alice");
    let identified = Mailbox::identified("alice", fp(10));
    let sender = Mailbox::login("sender");
    push(s, &msg(&bare, &sender, "to the login", at(1)));
    push(s, &msg(&identified, &sender, "to the identity", at(2)));

    assert_eq!(
        bodies(&s.pending(&bare, 10).unwrap()),
        ["to the login"],
        "{case}: a bare login never claims identified mail"
    );
    assert_eq!(
        bodies(&s.pending(&identified, 10).unwrap()),
        ["to the identity"],
        "{case}: an identity never claims unidentified mail"
    );
    // A different identity wearing the same login gets neither.
    assert!(
        s.pending(&Mailbox::identified("alice", fp(11)), 10)
            .unwrap()
            .is_empty(),
        "{case}: the fingerprint is the key, not the login beside it"
    );
}

fn claiming_moves_a_logins_mail_onto_its_new_fingerprint(s: &dyn MessageStore) {
    let case = "claiming_moves_a_logins_mail_onto_its_new_fingerprint";
    let bare = Mailbox::login("dave");
    let alice = Mailbox::login("alice");
    push(s, &msg(&bare, &alice, "before linking", at(1)));
    push(s, &msg(&alice, &bare, "from dave", at(2)));

    // dave links an identity: mail to her *and* from her moves with it.
    let moved = s.claim("dave", &fp(1)).unwrap();
    assert_eq!(moved, 2, "{case}: recipient and sender both stamped");

    let identified = Mailbox::identified("dave", fp(1));
    assert_eq!(
        bodies(&s.pending(&identified, 10).unwrap()),
        ["before linking"],
        "{case}: nothing is stranded by linking"
    );
    assert!(
        s.pending(&bare, 10).unwrap().is_empty(),
        "{case}: and the bare login no longer answers for it"
    );
    assert_eq!(
        s.list(&alice, None, 1).unwrap()[0]
            .sender
            .as_ref()
            .unwrap()
            .fingerprint,
        Some(fp(1)),
        "{case}: so a reply resolves to the identity"
    );
    assert_eq!(
        s.claim("dave", &fp(1)).unwrap(),
        0,
        "{case}: claiming twice finds nothing left"
    );
}

/// A guid is unique per mailbox, and `claim` merges two mailboxes: the
/// same guid can exist on both sides, because a client that unlinked,
/// retried a send, and relinked would produce exactly that. One is the
/// SQL store's unique index and the other is not, so this is a case the
/// two implementations drifted on and nothing noticed.
fn claiming_merges_a_guid_that_exists_on_both_sides(s: &dyn MessageStore) {
    let case = "claiming_merges_a_guid_that_exists_on_both_sides";
    let bare = Mailbox::login("dave");
    let identified = Mailbox::identified("dave", fp(1));
    let alice = Mailbox::login("alice");

    let mut first = msg(&identified, &alice, "the one already there", at(1));
    first.guid = Some(guid(9));
    push(s, &first);
    let mut retry = msg(&bare, &alice, "the retry on the bare login", at(2));
    retry.guid = Some(guid(9));
    push(s, &retry);

    s.claim("dave", &fp(1)).unwrap();
    assert_eq!(
        bodies(&s.pending(&identified, 10).unwrap()),
        ["the one already there"],
        "{case}: one message, and the older claim on the name wins"
    );
    assert_eq!(
        s.counts(&identified).unwrap(),
        InboxCounts {
            unread: 1,
            total: 1
        },
        "{case}: and the duplicate is gone rather than hidden"
    );
}

/// The other half of the same key. `message_guid` covers the *sender*
/// mailbox too, so a claim collides there as readily: alice, linked,
/// sends bob a message; she unlinks; her client retries the same guid,
/// which stores as a second row because the sender mailbox differs; she
/// relinks, and the claim's sender-side update hits the constraint. The
/// SQL store rolls the whole transaction back, which strands every row
/// addressed *to* alice as well — and, since claim runs at every login,
/// warns on every one of her logins from then on.
fn claiming_merges_a_guid_the_sender_sent_twice(s: &dyn MessageStore) {
    let case = "claiming_merges_a_guid_the_sender_sent_twice";
    let bob = Mailbox::login("bob");
    let alice_linked = Mailbox::identified("alice", fp(1));
    let alice_bare = Mailbox::login("alice");

    let mut first = msg(&bob, &alice_linked, "sent while linked", at(1));
    first.guid = Some(guid(9));
    push(s, &first);
    let mut retry = msg(&bob, &alice_bare, "the retry after the unlink", at(2));
    retry.guid = Some(guid(9));
    push(s, &retry);
    // Mail addressed to her, waiting on the bare login: what a failed
    // claim strands.
    push(s, &msg(&alice_bare, &bob, "waiting for her", at(3)));

    assert_eq!(
        s.claim("alice", &fp(1)).unwrap(),
        1,
        "{case}: the mail waiting for her moves; the duplicate is gone, \
         and the row it duplicated was already on the fingerprint"
    );
    assert_eq!(
        bodies(&s.pending(&bob, 10).unwrap()),
        ["sent while linked"],
        "{case}: one message, and the row already on the fingerprint wins"
    );
    assert_eq!(
        bodies(&s.pending(&alice_linked, 10).unwrap()),
        ["waiting for her"],
        "{case}: and her own mail came with her"
    );
}

/// The collapse compares the *index's* key, not the login beside it. The
/// unique index keys on `IFNULL(recipient_fp, recipient)`, so after a
/// rename the kept row carries the old login — and a collapse that also
/// compared logins would miss the collision the index then raises.
fn claiming_merges_a_duplicate_the_recipient_was_renamed_out_of(s: &dyn MessageStore) {
    let case = "claiming_merges_a_duplicate_the_recipient_was_renamed_out_of";
    let alice = Mailbox::login("alice");
    // The kept row was stored before the rename, so it carries `dave`
    // beside the fingerprint.
    let old_name = Mailbox::identified("dave", fp(1));
    let new_name = Mailbox::identified("mn", fp(1));
    let bare_new_name = Mailbox::login("mn");

    let mut first = msg(&old_name, &alice, "stored under the old login", at(1));
    first.guid = Some(guid(9));
    push(s, &first);
    let mut retry = msg(&bare_new_name, &alice, "the retry, after the rename", at(2));
    retry.guid = Some(guid(9));
    push(s, &retry);

    s.claim("mn", &fp(1)).unwrap();
    assert_eq!(
        bodies(&s.pending(&new_name, 10).unwrap()),
        ["stored under the old login"],
        "{case}: one message; the login beside the fingerprint is not the key"
    );
}

/// A collapse deletes a row, and what that row *knew* has to survive it:
/// the two are one message by the guid rule, so a duplicate that was read
/// makes the survivor read.
///
/// The sequence is ordinary. Bob's message reaches alice's mailbox while
/// she is linked and waits there; she unlinks; bob's client retries the
/// guid, which stores as a second row because the sender pair differs;
/// she reads *that* row; she relinks. The read row is the one the merge
/// removes, so without this the message is flushed to her a second time
/// as unread — a store that forgets someone read something.
fn a_collapse_keeps_what_the_duplicate_knew(s: &dyn MessageStore) {
    let case = "a_collapse_keeps_what_the_duplicate_knew";
    let bob = Mailbox::login("bob");
    let identified = Mailbox::identified("dave", fp(1));
    let bare = Mailbox::login("dave");

    let mut waiting = msg(&identified, &bob, "the one already there", at(1));
    waiting.guid = Some(guid(9));
    push(s, &waiting);
    let mut retry = msg(&bare, &bob, "the retry on the bare login", at(2));
    retry.guid = Some(guid(9));
    let read_id = push(s, &retry);
    s.mark_read(&bare, read_id, at(3)).unwrap();

    s.claim("dave", &fp(1)).unwrap();
    assert_eq!(
        s.counts(&identified).unwrap(),
        InboxCounts {
            unread: 0,
            total: 1
        },
        "{case}: one message, and it is still read"
    );
    assert!(
        s.pending(&identified, 10).unwrap().is_empty(),
        "{case}: so nothing is handed over a second time"
    );
}

/// The same merge one step later: rotation moves a mailbox onto the
/// successor key, which may already hold a row with that guid.
fn rotating_merges_a_guid_the_successor_already_holds(s: &dyn MessageStore) {
    let case = "rotating_merges_a_guid_the_successor_already_holds";
    let old_key = Mailbox::identified("dave", fp(1));
    let new_key = Mailbox::identified("dave", fp(2));
    let alice = Mailbox::login("alice");

    let mut on_new = msg(&new_key, &alice, "already on the successor", at(1));
    on_new.guid = Some(guid(9));
    push(s, &on_new);
    let mut on_old = msg(&old_key, &alice, "still on the old key", at(2));
    on_old.guid = Some(guid(9));
    push(s, &on_old);

    // A rotation that refuses over one duplicate strands everything else
    // the identity had, so it merges instead.
    s.rotate(&fp(1), &fp(2)).unwrap();
    assert_eq!(
        bodies(&s.pending(&new_key, 10).unwrap()),
        ["already on the successor"],
        "{case}: one message, and the successor's own row is kept"
    );
    assert!(
        s.pending(&old_key, 10).unwrap().is_empty(),
        "{case}: nothing is left on the predecessor"
    );
}

/// `rotate`'s sender side, for the same reason as `claim`'s.
fn rotating_merges_a_guid_the_sender_sent_twice(s: &dyn MessageStore) {
    let case = "rotating_merges_a_guid_the_sender_sent_twice";
    let bob = Mailbox::login("bob");
    let old_key = Mailbox::identified("alice", fp(1));
    let new_key = Mailbox::identified("alice", fp(2));

    let mut on_new = msg(&bob, &new_key, "sent from the successor", at(1));
    on_new.guid = Some(guid(9));
    push(s, &on_new);
    let mut on_old = msg(&bob, &old_key, "sent from the old key", at(2));
    on_old.guid = Some(guid(9));
    push(s, &on_old);

    s.rotate(&fp(1), &fp(2)).unwrap();
    assert_eq!(
        bodies(&s.pending(&bob, 10).unwrap()),
        ["sent from the successor"],
        "{case}: one message, and the successor's own row is kept"
    );
}

/// A merge can make two blocks where a client only ever asked for one:
/// block while linked, unlink, block again, relink. The stores then
/// disagreed about `unblock` — one deleted every match, the other one —
/// so a merge leaves one row per pair.
fn a_merge_leaves_one_block_per_pair(s: &dyn MessageStore) {
    let case = "a_merge_leaves_one_block_per_pair";
    let bob = Mailbox::login("bob");
    let alice_linked = Mailbox::identified("alice", fp(1));
    let alice_bare = Mailbox::login("alice");

    s.set_blocked(&alice_linked, &bob, true, at(1)).unwrap();
    s.set_blocked(&alice_bare, &bob, true, at(2)).unwrap();
    s.claim("alice", &fp(1)).unwrap();
    assert_eq!(
        s.blocked(&alice_linked).unwrap().len(),
        1,
        "{case}: one block, however many merges made it"
    );
    s.set_blocked(&alice_linked, &bob, false, at(3)).unwrap();
    assert!(
        !s.is_blocked(&alice_linked, &bob).unwrap(),
        "{case}: and unblocking means unblocked"
    );
    assert!(
        s.blocked(&alice_linked).unwrap().is_empty(),
        "{case}: on both of the ways to ask"
    );
}

fn a_rename_takes_the_mailbox_and_leaves_the_login_free(s: &dyn MessageStore) {
    let case = "a_rename_takes_the_mailbox_and_leaves_the_login_free";
    let sender = Mailbox::login("sender");
    // alice, identity A, has mail waiting.
    let alice_a = Mailbox::identified("alice", fp(10));
    push(s, &msg(&alice_a, &sender, "private", at(1)));

    // She renames to alicia. Same identity, new login.
    let alicia_a = Mailbox::identified("alicia", fp(10));
    assert_eq!(
        bodies(&s.pending(&alicia_a, 10).unwrap()),
        ["private"],
        "{case}: the mailbox follows the identity through a rename"
    );

    // Someone else registers the freed login — with no identity, and then
    // with one of their own. Neither inherits a word of it.
    assert!(
        s.pending(&Mailbox::login("alice"), 10).unwrap().is_empty(),
        "{case}: a new holder of the freed login inherits nothing"
    );
    assert!(
        s.pending(&Mailbox::identified("alice", fp(11)), 10)
            .unwrap()
            .is_empty(),
        "{case}: nor does a new holder with an identity of their own"
    );
}

fn purging_takes_everything_on_both_sides(s: &dyn MessageStore) {
    let case = "purging_takes_everything_on_both_sides";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let bob = Mailbox::login("bob");
    push(s, &msg(&dave, &alice, "to dave", at(1)));
    push(s, &msg(&alice, &dave, "from dave", at(2)));
    push(s, &msg(&alice, &bob, "unrelated", at(3)));
    s.set_blocked(&dave, &bob, true, SystemTime::now()).unwrap();
    s.set_blocked(&bob, &dave, true, SystemTime::now()).unwrap();

    assert_eq!(
        s.purge_count(&dave).unwrap(),
        4,
        "{case}: dry run counts exactly what purge will remove"
    );
    let gone = s.purge(&dave).unwrap();
    assert_eq!(gone, 4, "{case}: two messages and two blocks");
    assert_eq!(
        bodies(&s.list(&alice, None, 10).unwrap()),
        ["unrelated"],
        "{case}: and nobody else's mail"
    );
    assert!(
        !s.is_blocked(&bob, &dave).unwrap(),
        "{case}: a block naming the purged account goes too"
    );
}

// --- Blocking ------------------------------------------------------------

fn blocks_are_directional_and_idempotent(s: &dyn MessageStore) {
    let case = "blocks_are_directional_and_idempotent";
    let (dave, spammer) = (Mailbox::login("dave"), Mailbox::login("spammer"));
    assert!(
        !s.is_blocked(&dave, &spammer).unwrap(),
        "{case}: clean slate"
    );

    s.set_blocked(&dave, &spammer, true, SystemTime::now())
        .unwrap();
    s.set_blocked(&dave, &spammer, true, SystemTime::now())
        .unwrap();
    assert!(s.is_blocked(&dave, &spammer).unwrap(), "{case}: blocked");
    assert!(
        !s.is_blocked(&spammer, &dave).unwrap(),
        "{case}: blocking is one-way — it says nothing about the reverse"
    );
    assert_eq!(s.blocked(&dave).unwrap().len(), 1, "{case}: listed once");

    s.set_blocked(&dave, &spammer, false, SystemTime::now())
        .unwrap();
    s.set_blocked(&dave, &spammer, false, SystemTime::now())
        .unwrap();
    assert!(!s.is_blocked(&dave, &spammer).unwrap(), "{case}: unblocked");
    assert!(s.blocked(&dave).unwrap().is_empty(), "{case}: and delisted");
}

fn blocks_follow_an_identity_and_are_listed(s: &dyn MessageStore) {
    let case = "blocks_follow_an_identity_and_are_listed";
    let dave = Mailbox::login("dave");
    s.set_blocked(&dave, &Mailbox::login("one"), true, SystemTime::now())
        .unwrap();
    s.set_blocked(&dave, &Mailbox::login("two"), true, SystemTime::now())
        .unwrap();

    s.claim("dave", &fp(1)).unwrap();
    let identified = Mailbox::identified("dave", fp(1));
    let listed: Vec<String> = s
        .blocked(&identified)
        .unwrap()
        .into_iter()
        .map(|m| m.login)
        .collect();
    assert_eq!(listed, ["one", "two"], "{case}: the list follows the owner");
    assert!(
        s.blocked(&dave).unwrap().is_empty(),
        "{case}: and the bare login no longer holds it"
    );

    // A blocked account linking an identity keeps being blocked.
    s.claim("one", &fp(2)).unwrap();
    assert!(
        s.is_blocked(&identified, &Mailbox::identified("one", fp(2)))
            .unwrap(),
        "{case}: a block is not shaken off by linking an identity"
    );
}

fn rotation_moves_a_mailbox_and_its_blocks_to_the_successor_key(s: &dyn MessageStore) {
    let case = "rotation_moves_a_mailbox_and_its_blocks_to_the_successor_key";
    let old = Mailbox::identified("dave", fp(1));
    let new = Mailbox::identified("dave", fp(2));
    let sender = Mailbox::login("sender");
    push(s, &msg(&old, &sender, "before the rotation", at(1)));
    s.set_blocked(&old, &Mailbox::login("spammer"), true, SystemTime::now())
        .unwrap();

    assert_eq!(
        s.rotate(&fp(1), &fp(2)).unwrap(),
        2,
        "{case}: mail and block"
    );
    assert_eq!(
        bodies(&s.pending(&new, 10).unwrap()),
        ["before the rotation"],
        "{case}: the mailbox moved to the successor key"
    );
    assert!(
        s.pending(&old, 10).unwrap().is_empty(),
        "{case}: and the retired key holds nothing"
    );
    assert!(
        s.is_blocked(&new, &Mailbox::login("spammer")).unwrap(),
        "{case}: a block that quietly stopped applying is the worse half"
    );
    assert_eq!(s.rotate(&fp(1), &fp(2)).unwrap(), 0, "{case}: idempotent");
}

fn the_same_guid_twice_is_one_message(s: &dyn MessageStore) {
    let case = "the_same_guid_twice_is_one_message";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let mut m = msg(&dave, &alice, "sent once", at(1));
    m.guid = Some(guid(1));
    let id = push(s, &m);

    let found = s
        .find_guid(&dave, Some(&alice), &guid(1))
        .unwrap()
        .unwrap_or_else(|| panic!("{case}: the first send is findable"));
    assert_eq!(found.id, id, "{case}: and it is the same row");
    assert_eq!(found.guid.as_ref(), Some(&guid(1)), "{case}: round-trips");
    assert!(
        s.find_guid(&dave, Some(&alice), &guid(2))
            .unwrap()
            .is_none(),
        "{case}: a guid nobody sent finds nothing"
    );
}

/// The retry a guid exists for, done twice against the store directly —
/// which is what a client whose socket died mid-ack does, and what
/// `find_guid` then `push` could not make safe.
fn pushing_the_same_guid_twice_stores_one_row(s: &dyn MessageStore) {
    let case = "pushing_the_same_guid_twice_stores_one_row";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let mut m = msg(&dave, &alice, "sent once", at(1));
    m.guid = Some(guid(9));
    let first = match s.push(&m, usize::MAX).unwrap() {
        Pushed::Stored(id) => id,
        other => panic!("{case}: {other:?}"),
    };
    // Same guid, different body — a retry, not a new message.
    let mut again = m.clone();
    again.body = "sent once (retry)".into();
    match s.push(&again, usize::MAX).unwrap() {
        Pushed::Existing(existing) => {
            assert_eq!(existing.id, first, "{case}: the same row");
            assert_eq!(existing.body, "sent once", "{case}: the first body stands");
        }
        other => panic!("{case}: expected the existing row, got {other:?}"),
    }
    assert_eq!(
        s.counts(&dave).unwrap().total,
        1,
        "{case}: one row, not two"
    );
    // A sender with no mailbox at all is its own scope, and NULL is not a
    // value that compares equal to itself — so this is the case a bare
    // column list in the unique index would let through.
    let mut anon = msg(&dave, &alice, "from nobody", at(2));
    anon.sender = None;
    anon.guid = Some(guid(10));
    let id = match s.push(&anon, usize::MAX).unwrap() {
        Pushed::Stored(id) => id,
        other => panic!("{case}: {other:?}"),
    };
    match s.push(&anon, usize::MAX).unwrap() {
        Pushed::Existing(existing) => assert_eq!(existing.id, id, "{case}: anonymous dedup"),
        other => panic!("{case}: expected the existing row, got {other:?}"),
    }
}

/// The cap belongs to the insert, not to a count the caller took a moment
/// earlier: two senders in parallel are exactly what it is for.
fn the_cap_is_enforced_by_the_insert(s: &dyn MessageStore) {
    let case = "the_cap_is_enforced_by_the_insert";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    for i in 0..3 {
        assert!(
            matches!(
                s.push(&msg(&dave, &alice, &format!("m{i}"), at(i)), 3)
                    .unwrap(),
                Pushed::Stored(_)
            ),
            "{case}: under the cap"
        );
    }
    assert_eq!(
        s.push(&msg(&dave, &alice, "one too many", at(9)), 3)
            .unwrap(),
        Pushed::Full,
        "{case}: at the cap"
    );
    // The cap counts what is *waiting*, so delivering makes room.
    let waiting: Vec<MessageId> = s.pending(&dave, 10).unwrap().iter().map(|m| m.id).collect();
    s.mark_delivered(&waiting[..1], at(10), Delivery::Delivered)
        .unwrap();
    assert!(
        matches!(
            s.push(&msg(&dave, &alice, "room again", at(11)), 3)
                .unwrap(),
            Pushed::Stored(_)
        ),
        "{case}: delivery makes room"
    );
    // A receipt is not mail and is not what the cap is about.
    let mut receipt = msg(&dave, &alice, "ack", at(12));
    receipt.kind = MessageKind::ReadReceipt;
    assert!(
        matches!(s.push(&receipt, 3).unwrap(), Pushed::Stored(_)),
        "{case}: receipts are not capped as mail"
    );
}

/// The legacy wire has no `msg_read`, so its flush is the read.
fn a_flush_can_stamp_read_in_the_same_step(s: &dyn MessageStore) {
    let case = "a_flush_can_stamp_read_in_the_same_step";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let a = push(s, &msg(&dave, &alice, "one", at(1)));
    let b = push(s, &msg(&dave, &alice, "two", at(2)));
    assert_eq!(s.counts(&dave).unwrap().unread, 2, "{case}: both unread");

    s.mark_delivered(&[a], at(10), Delivery::Delivered).unwrap();
    assert_eq!(
        s.counts(&dave).unwrap().unread,
        2,
        "{case}: delivery alone is not a read"
    );
    s.mark_delivered(&[b], at(11), Delivery::Read).unwrap();
    assert_eq!(
        s.counts(&dave).unwrap().unread,
        1,
        "{case}: the legacy flush is the read"
    );
    // Both are out of `pending` either way, and neither is re-stamped.
    assert!(s.pending(&dave, 10).unwrap().is_empty(), "{case}: pending");
    s.mark_delivered(&[b], at(99), Delivery::Read).unwrap();
    let seen = s.list(&dave, None, 10).unwrap();
    let two = seen.iter().find(|m| m.id == b).unwrap();
    assert_eq!(two.read_at, Some(at(11)), "{case}: idempotent");
    assert_eq!(two.delivered_at, Some(at(11)), "{case}: idempotent");
    assert!(!s.is_pending(&dave, b).unwrap(), "{case}: is_pending");
    assert!(
        !s.is_pending(&Mailbox::login("bob"), b).unwrap(),
        "{case}: is_pending is scoped by mailbox"
    );
}

fn a_guid_is_scoped_to_one_sender_and_one_recipient(s: &dyn MessageStore) {
    let case = "a_guid_is_scoped_to_one_sender_and_one_recipient";
    let (dave, bob) = (Mailbox::login("dave"), Mailbox::login("bob"));
    let (alice, carol) = (Mailbox::login("alice"), Mailbox::login("carol"));

    let mut a_to_dave = msg(&dave, &alice, "from alice", at(1));
    a_to_dave.guid = Some(guid(7));
    push(s, &a_to_dave);

    // The same guid from someone else, and toward someone else, are
    // different messages: two people cannot collide on each other's
    // guids, and one person may reuse a guid toward two recipients.
    assert!(
        s.find_guid(&dave, Some(&carol), &guid(7))
            .unwrap()
            .is_none(),
        "{case}: another sender's guid is not this one"
    );
    assert!(
        s.find_guid(&bob, Some(&alice), &guid(7)).unwrap().is_none(),
        "{case}: nor the same sender's toward another recipient"
    );
    // A guest sender has no mailbox at all, and is its own scope.
    let mut anon = msg(&dave, &alice, "from a guest", at(2));
    anon.sender = None;
    anon.guid = Some(guid(7));
    push(s, &anon);
    assert_eq!(
        s.find_guid(&dave, None, &guid(7)).unwrap().map(|m| m.body),
        Some("from a guest".to_string()),
        "{case}: and a sender with no mailbox is not every sender"
    );
}

fn a_receipt_is_stored_but_never_read_as_mail(s: &dyn MessageStore) {
    let case = "a_receipt_is_stored_but_never_read_as_mail";
    let (alice, dave) = (Mailbox::login("alice"), Mailbox::login("dave"));
    push(s, &msg(&alice, &dave, "real mail", at(1)));

    // "Dave read your message", addressed back to alice who sent it.
    let mut receipt = msg(&alice, &dave, "some-guid", at(2));
    receipt.kind = MessageKind::ReadReceipt;
    push(s, &receipt);

    assert_eq!(
        bodies(&s.pending(&alice, 10).unwrap()),
        ["real mail"],
        "{case}: a kind no wire can carry must not occupy a flush slot"
    );
    assert_eq!(
        s.pending_count(&alice).unwrap(),
        1,
        "{case}: nor fill the mailbox it is acking into"
    );
    assert_eq!(
        bodies(&s.list(&alice, None, 10).unwrap()),
        ["real mail"],
        "{case}: nor be listed as mail"
    );
    assert_eq!(
        s.counts(&alice).unwrap(),
        InboxCounts {
            unread: 1,
            total: 1
        },
        "{case}: nor counted as mail"
    );

    // It is still stored, still follows its owner, and still goes when
    // the owner does.
    s.claim("alice", &fp(3)).unwrap();
    let claimed = Mailbox::identified("alice", fp(3));
    assert_eq!(s.purge_count(&claimed).unwrap(), 2, "{case}: dry run");
    assert_eq!(
        s.purge(&claimed).unwrap(),
        2,
        "{case}: purge takes the receipt with the mail"
    );
}
