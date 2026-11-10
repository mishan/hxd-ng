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

use std::sync::Arc;

use crate::reaction::{
    MessageReactAct, MessageReacted, MessageState, Parties, ReactionKey, Reactions,
};
use crate::relationships::{RelationshipStore, SentOn};

use super::{
    Cursor, Delivery, Found, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageRef,
    MessageStore, NewMessage, Pending, Pushed, Sent, StoredMessage, Stub,
};

/// Run every case against a freshly built store. `new_store` is called
/// once per case, so no case can see another's mail.
///
/// Panics with the failing case's name, which is what a test failure in
/// an implementation crate has to be able to tell you.
pub fn run(new_store: &dyn Fn() -> Gated) {
    pending_is_oldest_first_and_bounded(&*new_store().inbox);
    a_message_round_trips_whole(&*new_store().inbox);
    the_friendship_column_round_trips(&*new_store().inbox);
    a_merge_restamps_what_was_sent_on_the_id_it_ended(&*new_store().inbox);
    delivery_is_idempotent_and_removes_from_pending(&*new_store().inbox);
    reading_stamps_delivery_so_it_is_never_flushed_later(&*new_store().inbox);
    mark_read_never_reaches_another_mailbox(&*new_store().inbox);
    list_is_newest_first_and_pages_backwards(&*new_store().inbox);
    // A message's names (`docs/private-messages.md` §5).
    each_mailbox_numbers_its_own_mail(&*new_store().inbox);
    references_are_random_and_follow_the_row(&*new_store().inbox);
    a_message_keeps_what_it_answers(&*new_store().inbox);
    a_message_keeps_the_emoji_it_names(&*new_store().inbox);
    a_cursor_is_not_handed_out_again(&*new_store().inbox);
    a_merge_numbers_what_it_moves_after_both_mailboxes(&*new_store().inbox);
    an_unlinked_login_counts_on_past_its_identity(&*new_store().inbox);
    a_merge_into_a_fresh_mailbox_keeps_its_cursors(&*new_store().inbox);
    a_claim_that_moves_nothing_keeps_the_logins_count(&*new_store().inbox);
    counts_of_a_mailbox_with_no_mail_are_zero(&*new_store().inbox);
    prune_ages_unread_from_sent_and_read_from_read(&*new_store().inbox);
    a_retention_window_older_than_the_clock_prunes_nothing(&*new_store().inbox);
    // The mailbox key — where a disagreement is a wrong-recipient bug.
    an_identity_and_a_bare_login_are_different_mailboxes(&*new_store().inbox);
    claiming_moves_a_logins_mail_onto_its_new_fingerprint(&*new_store().inbox);
    a_rename_takes_the_mailbox_and_leaves_the_login_free(&*new_store().inbox);
    purging_takes_everything_on_both_sides(&*new_store().inbox);
    rotation_moves_a_mailbox_to_the_successor_key(&*new_store().inbox);
    claiming_merges_a_guid_that_exists_on_both_sides(&*new_store().inbox);
    claiming_merges_a_guid_the_sender_sent_twice(&*new_store().inbox);
    claiming_merges_a_duplicate_the_recipient_was_renamed_out_of(&*new_store().inbox);
    a_collapse_keeps_what_the_duplicate_knew(&*new_store().inbox);
    rotating_merges_a_guid_the_successor_already_holds(&*new_store().inbox);
    rotating_merges_a_guid_the_sender_sent_twice(&*new_store().inbox);
    // Retry, and the kinds the inbox holds but does not show.
    the_same_guid_twice_is_one_message(&*new_store().inbox);
    pushing_the_same_guid_twice_stores_one_row(&*new_store().inbox);
    the_cap_is_enforced_by_the_insert(&*new_store().inbox);
    a_flush_can_stamp_read_in_the_same_step(&*new_store().inbox);
    a_guid_is_scoped_to_one_sender_and_one_recipient(&*new_store().inbox);
    a_receipt_is_stored_but_never_read_as_mail(&*new_store().inbox);
    // What retention leaves of a read message for its sender's window.
    a_stub_answers_a_retry_as_its_row_did(&*new_store().inbox);
    a_read_message_kept_past_the_window_answers_a_retry_as_an_unread_one_would(&*new_store().inbox);
    a_stub_is_never_mail(&*new_store().inbox);
    a_stub_follows_a_claim_and_a_rotation(&*new_store().inbox);
    a_claim_answers_a_retry_under_one_reference_read_or_not(&*new_store().inbox);
    only_a_private_message_leaves_a_stub_or_loses_its_guid(&*new_store().inbox);
    purging_an_account_takes_its_stubs(&*new_store().inbox);
    an_early_pruned_message_leaves_a_stub_its_parties_still_find(&*new_store().inbox);
    a_message_kept_past_the_window_answers_its_recipient_and_not_its_sender(&*new_store().inbox);
    mail_to_ones_own_account_kept_past_the_window_is_still_its_recipients(&*new_store().inbox);
    // Reactions on stored private messages.
    a_message_reaction_adds_removes_and_holds(&*new_store().inbox);
    message_reactions_keep_first_added_order_and_name_holders_newest_first(&*new_store().inbox);
    a_message_holds_its_caps_in_the_write(&*new_store().inbox);
    either_party_and_no_one_else_reacts_and_reads(&*new_store().inbox);
    only_a_private_message_takes_reactions(&*new_store().inbox);
    a_messages_reactions_go_with_it_however_it_goes(&*new_store().inbox);
    a_stubs_reactions_last_until_the_window_ends(&*new_store().inbox);
    a_kept_rows_reactions_are_the_recipients_after_the_window(&*new_store().inbox);
    a_merged_duplicate_gives_the_survivor_its_reactions(new_store);
    message_reactions_follow_a_reactors_claim_and_rotation(&*new_store().inbox);
    purging_an_account_takes_every_reaction_it_made(&*new_store().inbox);
    forgetting_a_persons_message_reactions_keeps_those_before_the_window_and_the_stubs(
        &*new_store().inbox,
    );
    // The per-sender quota's measure.
    sent_since_counts_a_senders_stored_mail_in_its_window(&*new_store().inbox);
    // The gate (`docs/instant-messaging.md` §5).
    the_gate_holds_what_was_sent_on_nothing_live(&new_store());
    a_handed_message_waits_for_its_ack(&new_store());
    a_receipt_waits_behind_the_gate(&new_store());
    requests_are_listed_released_and_deleted_by_sender(&new_store());
    a_request_released_onto_a_relation_is_not_counted_as_sent(&new_store());
    requests_turned_to_mail_are_gated_as_mail_and_still_not_counted_as_sent(&*new_store().inbox);
    a_guests_requests_are_deleted_by_address(&*new_store().inbox);
}

/// A store under test, and the relationship store its gate reads: for
/// SQLite one store under both traits.
pub struct Gated {
    pub inbox: Arc<dyn MessageStore>,
    pub relationships: Arc<dyn RelationshipStore>,
}

/// What a session that understands requests reads.
const INSTANT: Pending = Pending::Instant {
    again: false,
    approvals: true,
};
const AGAIN: Pending = Pending::Instant {
    again: true,
    approvals: true,
};
const RECEIPTS: Pending = Pending::Receipts { approvals: true };

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
        media: None,
        signed: None,
        friendship: None,
        sender_address: None,
        re: None,
        emoji: None,
    }
}

/// `push` with the cap out of the way and the id unwrapped: every case
/// below is about something other than the cap, and the cap has its own.
fn push(s: &dyn MessageStore, m: &NewMessage) -> MessageId {
    match s.push(m, usize::MAX).unwrap() {
        Pushed::Stored { id, .. } => id,
        other => panic!("expected a new row, got {other:?}"),
    }
}

/// [`push`], for the row's place in its recipient's mailbox.
fn place(s: &dyn MessageStore, m: &NewMessage) -> Cursor {
    match s.push(m, usize::MAX).unwrap() {
        Pushed::Stored { cursor, .. } => cursor,
        other => panic!("expected a new row, got {other:?}"),
    }
}

/// What a lookup found, as the row it must be.
fn row(found: Option<Found>) -> Option<StoredMessage> {
    found.map(|f| match f {
        Found::Row(m) => *m,
        other => panic!("expected a row, got {other:?}"),
    })
}

/// Each listed row's cursor, as `list` orders them.
fn cursors(s: &dyn MessageStore, of: &Mailbox) -> Vec<Cursor> {
    s.list(of, None, 100)
        .unwrap()
        .iter()
        .map(|m| m.cursor)
        .collect()
}

fn each_mailbox_numbers_its_own_mail(s: &dyn MessageStore) {
    let case = "each_mailbox_numbers_its_own_mail";
    let (dave, bob, alice) = (
        Mailbox::login("dave"),
        Mailbox::login("bob"),
        Mailbox::identified("alice", fp(1)),
    );
    let mut receipt = msg(&dave, &bob, "read", at(0));
    receipt.kind = MessageKind::ReadReceipt;
    // Interleaved across three mailboxes and both kinds of key, with a
    // receipt, which is not mail, in the middle.
    let got: Vec<Cursor> = [
        msg(&dave, &bob, "d1", at(1)),
        msg(&bob, &dave, "b1", at(2)),
        msg(&alice, &dave, "a1", at(3)),
        receipt,
        msg(&dave, &bob, "d2", at(4)),
        msg(&bob, &dave, "b2", at(5)),
        msg(&dave, &alice, "d3", at(6)),
    ]
    .iter()
    .map(|m| place(s, m))
    .collect();
    assert_eq!(got, [1, 1, 1, 0, 2, 2, 3], "{case}: as pushed");
    assert_eq!(cursors(s, &dave), [3, 2, 1], "{case}: dave's, gapless");
    assert_eq!(cursors(s, &bob), [2, 1], "{case}: bob's, his own");
    assert_eq!(cursors(s, &alice), [1], "{case}: alice's, her own");
    assert_eq!(
        bodies(&s.list(&dave, Some(3), 1).unwrap()),
        ["d2"],
        "{case}: `before` is dave's cursor"
    );
    assert_eq!(
        s.mark_read(&dave, 2, at(9)).unwrap(),
        2,
        "{case}: and so is `up_to`"
    );
}

fn a_message_keeps_what_it_answers(s: &dyn MessageStore) {
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::identified("alice", fp(1)));
    let re = crate::reply::Reply::im("dave".into(), guid(7)).unwrap();
    let mut m = msg(&dave, &alice, "yes", at(1));
    m.re = Some(re.clone());
    push(s, &m);
    assert_eq!(s.list(&dave, None, 1).unwrap()[0].re, Some(re));
}

fn a_message_keeps_the_emoji_it_names(s: &dyn MessageStore) {
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let refs = crate::emoji::conformance::refs();
    let mut m = msg(&dave, &alice, ":party: :polly:", at(1));
    m.emoji = Some(refs.clone());
    push(s, &m);
    push(s, &msg(&dave, &alice, "plain", at(2)));
    let listed = s.list(&dave, None, 2).unwrap();
    let kept: Vec<_> = listed.iter().map(|m| m.emoji.as_ref()).collect();
    assert_eq!(kept, [None, Some(&refs)]);
    assert_eq!(s.pending(&dave, 1).unwrap()[0].emoji, Some(refs));
}

fn references_are_random_and_follow_the_row(s: &dyn MessageStore) {
    let case = "references_are_random_and_follow_the_row";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let pushed: Vec<MessageRef> = (0..16u8)
        .map(|i| {
            let mut m = msg(&dave, &alice, &format!("m{i}"), at(i.into()));
            m.guid = Some(guid(i));
            match s.push(&m, usize::MAX).unwrap() {
                Pushed::Stored { reference, .. } => reference,
                other => panic!("{case}: expected a new row, got {other:?}"),
            }
        })
        .collect();
    let distinct: std::collections::HashSet<_> = pushed.iter().collect();
    assert_eq!(distinct.len(), pushed.len(), "{case}: no two alike");
    let mut sorted = pushed.clone();
    sorted.sort();
    assert_ne!(sorted, pushed, "{case}: not counted up");
    sorted.reverse();
    assert_ne!(sorted, pushed, "{case}: nor down");

    let mut listed: Vec<MessageRef> = s
        .list(&dave, None, 100)
        .unwrap()
        .iter()
        .map(|m| m.reference)
        .collect();
    listed.reverse();
    assert_eq!(listed, pushed, "{case}: the row keeps the one it was given");
    let mut retry = msg(&dave, &alice, "m3", at(3));
    retry.guid = Some(guid(3));
    match s.push(&retry, usize::MAX).unwrap() {
        Pushed::Existing(m) => assert_eq!(m.reference, pushed[3], "{case}: a retry's"),
        other => panic!("{case}: expected the stored row, got {other:?}"),
    }
}

fn a_cursor_is_not_handed_out_again(s: &dyn MessageStore) {
    let case = "a_cursor_is_not_handed_out_again";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    place(s, &msg(&dave, &alice, "one", at(1)));
    place(s, &msg(&dave, &alice, "two", at(2)));
    let day = Duration::from_secs(86_400);
    assert_eq!(
        s.prune(at(10) + day, day, day).unwrap(),
        2,
        "{case}: pruned"
    );
    assert_eq!(s.last_cursor(&dave).unwrap(), 2, "{case}: what it issued");
    assert_eq!(s.last_cursor(&alice).unwrap(), 0, "{case}: and none");
    assert_eq!(
        place(s, &msg(&dave, &alice, "three", at(3))),
        3,
        "{case}: a client that saw two is never shown another two"
    );
    s.purge(&dave).unwrap();
    assert_eq!(
        place(s, &msg(&dave, &alice, "anew", at(4))),
        1,
        "{case}: a purged mailbox is a new one, counting nothing of before"
    );
}

/// An account that unlinks reads its bare login's mailbox again: that
/// counts on past the identity's, and a login that never had one is left
/// as it was.
fn an_unlinked_login_counts_on_past_its_identity(s: &dyn MessageStore) {
    let case = "an_unlinked_login_counts_on_past_its_identity";
    let (bare, identified, alice) = (
        Mailbox::login("dave"),
        Mailbox::identified("dave", fp(1)),
        Mailbox::login("alice"),
    );
    place(s, &msg(&bare, &alice, "before linking", at(1)));
    s.claim("dave", &fp(1)).unwrap();
    for i in 0..3 {
        place(s, &msg(&identified, &alice, "linked", at(i)));
    }
    s.unlinked("dave", &fp(1)).unwrap();
    assert_eq!(
        place(s, &msg(&bare, &alice, "after", at(4))),
        5,
        "{case}: past the identity's four, the claimed one among them"
    );
    s.unlinked("erin", &fp(9)).unwrap();
    let erin = Mailbox::login("erin");
    assert_eq!(
        place(s, &msg(&erin, &alice, "first", at(5))),
        1,
        "{case}: no identity mailbox, nothing to pass"
    );
}

/// The usual merge — a first link, a rotation to a fresh key — is into a
/// mailbox that never issued a cursor: what moves keeps its cursors, so
/// no client's go stale, and the count carries over. A claim with
/// nothing to move, which every login of a linked account makes,
/// changes nothing.
fn a_merge_into_a_fresh_mailbox_keeps_its_cursors(s: &dyn MessageStore) {
    let case = "a_merge_into_a_fresh_mailbox_keeps_its_cursors";
    let alice = Mailbox::login("alice");
    let (bare, linked, rotated) = (
        Mailbox::login("dave"),
        Mailbox::identified("dave", fp(1)),
        Mailbox::identified("dave", fp(2)),
    );
    for i in 0..3 {
        place(s, &msg(&bare, &alice, "before linking", at(i)));
    }
    s.claim("dave", &fp(1)).unwrap();
    assert_eq!(
        cursors(s, &linked),
        [3, 2, 1],
        "{case}: claimed as they were"
    );
    s.claim("dave", &fp(1)).unwrap();
    assert_eq!(
        cursors(s, &linked),
        [3, 2, 1],
        "{case}: claimed again, unmoved"
    );
    assert_eq!(
        place(s, &msg(&linked, &alice, "linked", at(4))),
        4,
        "{case}: counting on from the login's"
    );
    s.rotate(&fp(1), &fp(2)).unwrap();
    assert_eq!(
        cursors(s, &rotated),
        [4, 3, 2, 1],
        "{case}: rotated as they were"
    );
    assert_eq!(
        place(s, &msg(&rotated, &alice, "rotated", at(5))),
        5,
        "{case}: counting on from the old key's"
    );
    assert_eq!(
        place(s, &msg(&bare, &alice, "to whoever holds dave now", at(6))),
        1,
        "{case}: the claimed login's count went with its mail"
    );
}

/// A login whose mail was all pruned has still issued its cursors: a
/// claim that moves nothing carries its count all the same, so the
/// owner is never shown one of them again, by the identity or after an
/// unlink.
fn a_claim_that_moves_nothing_keeps_the_logins_count(s: &dyn MessageStore) {
    let case = "a_claim_that_moves_nothing_keeps_the_logins_count";
    let alice = Mailbox::login("alice");
    let (bare, linked) = (Mailbox::login("dave"), Mailbox::identified("dave", fp(1)));
    let day = Duration::from_secs(86_400);
    place(s, &msg(&linked, &alice, "kept", at(10) + day));
    for i in 0..3 {
        place(s, &msg(&bare, &alice, "pruned", at(i)));
    }
    assert_eq!(
        s.prune(at(10) + day, day, day).unwrap(),
        3,
        "{case}: pruned"
    );
    assert_eq!(
        s.claim("dave", &fp(1)).unwrap(),
        0,
        "{case}: nothing to move"
    );
    assert_eq!(
        place(s, &msg(&linked, &alice, "next", at(11) + day)),
        4,
        "{case}: past the login's three"
    );
    s.unlinked("dave", &fp(1)).unwrap();
    assert_eq!(
        place(s, &msg(&bare, &alice, "after", at(12) + day)),
        5,
        "{case}: and past the identity's after an unlink"
    );
}

/// A claim or a rotation makes two mailboxes one: what it moves is
/// numbered after the cursors of both, in the order it had, and what was
/// already there keeps its numbers. References do not move at all.
fn a_merge_numbers_what_it_moves_after_both_mailboxes(s: &dyn MessageStore) {
    let case = "a_merge_numbers_what_it_moves_after_both_mailboxes";
    let alice = Mailbox::login("alice");
    let identified = Mailbox::identified("dave", fp(1));
    let bare = Mailbox::login("dave");
    let refs = |of: &Mailbox| -> Vec<(String, MessageRef)> {
        let mut r: Vec<_> = s
            .list(of, None, 100)
            .unwrap()
            .into_iter()
            .map(|m| (m.body, m.reference))
            .collect();
        r.sort();
        r
    };
    for (to, body) in [
        (&identified, "linked 1"),
        (&bare, "bare 1"),
        (&bare, "bare 2"),
        (&identified, "linked 2"),
        (&bare, "bare 3"),
    ] {
        place(s, &msg(to, &alice, body, at(1)));
    }
    let mut before = refs(&identified);
    before.extend(refs(&bare));
    before.sort();

    s.claim("dave", &fp(1)).unwrap();
    let listed: Vec<(Cursor, String)> = s
        .list(&identified, None, 100)
        .unwrap()
        .into_iter()
        .map(|m| (m.cursor, m.body))
        .collect();
    assert_eq!(
        listed,
        [
            (6, "bare 3".to_string()),
            (5, "bare 2".to_string()),
            (4, "bare 1".to_string()),
            (2, "linked 2".to_string()),
            (1, "linked 1".to_string()),
        ],
        "{case}: claimed after the larger of the two"
    );
    assert_eq!(refs(&identified), before, "{case}: references unmoved");
    assert_eq!(
        place(s, &msg(&identified, &alice, "next", at(2))),
        7,
        "{case}: and the mailbox counts on from there"
    );

    let successor = Mailbox::identified("dave", fp(2));
    place(s, &msg(&successor, &alice, "already there", at(3)));
    let before = refs(&identified);
    s.rotate(&fp(1), &fp(2)).unwrap();
    assert_eq!(
        cursors(s, &successor),
        [13, 12, 11, 10, 9, 8, 1],
        "{case}: rotated after the old key's"
    );
    assert_eq!(
        bodies(&s.list(&successor, None, 1).unwrap()),
        ["next"],
        "{case}: in the order they had"
    );
    assert_eq!(
        s.list(&successor, None, 100)
            .unwrap()
            .iter()
            .find(|m| m.body == "already there")
            .map(|m| m.cursor),
        Some(1),
        "{case}: what was there keeps its place"
    );
    let mut after = refs(&successor);
    after.retain(|(b, _)| b != "already there");
    assert_eq!(after, before, "{case}: references unmoved by a rotation");
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
            // An image rides as canonical metadata, not as bytes: the
            // store holds the record and the media store holds the
            // image, which may well die first
            // (`docs/inline-media.md` §9).
            media: Some(crate::history::MediaMeta {
                id: vec![7; 16],
                mime: "image/png".into(),
                width: 800,
                height: 600,
                bytes: 124_000,
            }),
            signed: Some(crate::history::Signature {
                form: vec![0xa5, 1, 2],
                content: [4; 32],
            }),
            friendship: None,
            sender_address: None,
            re: None,
            emoji: None,
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
    let media = got.media.as_ref().expect("{case}: media survived");
    assert_eq!(media.id, vec![7; 16], "{case}: handle bytes");
    assert_eq!(media.mime, "image/png", "{case}: canonical mime");
    assert_eq!(
        (media.width, media.height, media.bytes),
        (800, 600, 124_000),
        "{case}: canonical dimensions and size"
    );
    let signed = got.signed.as_ref().expect("{case}: the signature survived");
    assert_eq!(
        (&signed.form[..], signed.content),
        (&[0xa5, 1, 2][..], [4; 32]),
        "{case}: its form and content"
    );
}

fn the_friendship_column_round_trips(s: &dyn MessageStore) {
    let case = "the_friendship_column_round_trips";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let sent = [None, Some(SentOn::Request), Some(SentOn::Relation(7))];
    for (i, on) in sent.iter().enumerate() {
        push(
            s,
            &NewMessage {
                friendship: *on,
                guid: Some(guid(i as u8)),
                ..msg(&dave, &alice, "m", at(i as u64))
            },
        );
    }
    let got: Vec<_> = (0..sent.len())
        .map(|i| {
            row(s.find_guid(&dave, Some(&alice), &guid(i as u8)).unwrap())
                .unwrap()
                .friendship
        })
        .collect();
    assert_eq!(got, sent, "{case}");
}

fn a_merge_restamps_what_was_sent_on_the_id_it_ended(s: &dyn MessageStore) {
    let case = "a_merge_restamps_what_was_sent_on_the_id_it_ended";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let sent = [
        Some(SentOn::Relation(3)),
        Some(SentOn::Relation(5)),
        Some(SentOn::Relation(4)),
        Some(SentOn::Request),
        None,
    ];
    for (i, on) in sent.iter().enumerate() {
        push(
            s,
            &NewMessage {
                friendship: *on,
                guid: Some(guid(i as u8)),
                ..msg(&dave, &alice, "m", at(i as u64))
            },
        );
    }
    s.restamp(&[(3, 5), (5, 9)]).unwrap();
    let got: Vec<_> = (0..sent.len())
        .map(|i| {
            row(s.find_guid(&dave, Some(&alice), &guid(i as u8)).unwrap())
                .unwrap()
                .friendship
        })
        .collect();
    assert_eq!(
        got,
        [
            Some(SentOn::Relation(9)),
            Some(SentOn::Relation(9)),
            Some(SentOn::Relation(4)),
            Some(SentOn::Request),
            None,
        ],
        "{case}: a chain of merges lands on its last id, and nothing else moves"
    );
}

/// The ledger counts a request toward its sender's quota, so the row
/// it stored is never counted again, waiting or released.
fn a_request_released_onto_a_relation_is_not_counted_as_sent(g: &Gated) {
    let case = "a_request_released_onto_a_relation_is_not_counted_as_sent";
    let (s, rel) = (&*g.inbox, &*g.relationships);
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    push(
        s,
        &NewMessage {
            friendship: Some(SentOn::Request),
            ..msg(&dave, &alice, "may I?", at(1))
        },
    );
    let approval = rel.approve(&dave, &alice, at(2)).unwrap();
    assert_eq!(
        s.release_requests(&dave, &alice, approval, at(0)).unwrap(),
        1,
        "{case}"
    );
    push(
        s,
        &NewMessage {
            friendship: Some(SentOn::Relation(approval)),
            ..msg(&dave, &alice, "thanks", at(3))
        },
    );
    assert_eq!(
        s.sent_since(&alice, at(0)).unwrap(),
        Sent {
            messages: 1,
            bytes: 6,
        },
        "{case}: what was sent on the approval alone"
    );
}

fn requests_turned_to_mail_are_gated_as_mail_and_still_not_counted_as_sent(s: &dyn MessageStore) {
    let case = "requests_turned_to_mail_are_gated_as_mail_and_still_not_counted_as_sent";
    let (dave, guest, alice) = (
        Mailbox::login("dave"),
        Mailbox::login("guest"),
        Mailbox::login("alice"),
    );
    let identified = Mailbox::identified("guest", fp(4));
    for (from, address, body, t) in [
        (&guest, Some("k1"), "lapsed", 0),
        (&guest, Some("k1"), "g1", 1),
        (&alice, None, "a1", 2),
        (&guest, Some("k2"), "another guest", 3),
        (&guest, Some("k1"), "g2", 4),
        (&identified, None, "identity", 5),
    ] {
        push(
            s,
            &NewMessage {
                friendship: Some(SentOn::Request),
                sender_address: address.map(str::to_owned),
                re: None,
                emoji: None,
                ..msg(&dave, from, body, at(t))
            },
        );
    }
    assert_eq!(
        s.requests_to_mail(&dave, &guest, Some("k1"), at(1))
            .unwrap(),
        2,
        "{case}"
    );
    assert_eq!(
        s.requests_to_mail(&dave, &identified, None, at(0)).unwrap(),
        1,
        "{case}: an identity guest's by its fingerprint alone"
    );
    assert_eq!(
        bodies(&s.requests(&dave, at(0), 10).unwrap()),
        ["lapsed", "a1", "another guest"],
        "{case}: the rest still requests, another guest's among them"
    );
    assert_eq!(
        bodies(&s.pending(&dave, 10).unwrap()),
        ["g1", "g2", "identity"],
        "{case}: through the gate as mail"
    );
    assert_eq!(
        s.sent_since(&guest, at(0)).unwrap(),
        Sent::default(),
        "{case}: the ledger counted them"
    );
}

fn a_guests_requests_are_deleted_by_address(s: &dyn MessageStore) {
    let case = "a_guests_requests_are_deleted_by_address";
    let (dave, guest, alice) = (
        Mailbox::login("dave"),
        Mailbox::login("guest"),
        Mailbox::login("alice"),
    );
    for (from, address, body) in [
        (&guest, Some("k1"), "g1"),
        (&guest, Some("k2"), "another guest"),
        (&alice, None, "a1"),
        (&guest, Some("k1"), "g2"),
    ] {
        push(
            s,
            &NewMessage {
                friendship: Some(SentOn::Request),
                sender_address: address.map(str::to_owned),
                re: None,
                emoji: None,
                ..msg(&dave, from, body, at(1))
            },
        );
    }
    assert_eq!(
        s.delete_requests_from(&dave, &guest, "k1").unwrap(),
        2,
        "{case}"
    );
    assert_eq!(
        bodies(&s.requests(&dave, at(0), 10).unwrap()),
        ["another guest", "a1"],
        "{case}: another address's and an account's stay"
    );
}

fn requests_are_listed_released_and_deleted_by_sender(g: &Gated) {
    let case = "requests_are_listed_released_and_deleted_by_sender";
    let (s, rel) = (&*g.inbox, &*g.relationships);
    let (dave, erin) = (Mailbox::login("dave"), Mailbox::login("erin"));
    let alice = Mailbox::identified("alice", fp(1));
    let bob = Mailbox::login("bob");
    let request = |to: &Mailbox, from: &Mailbox, body: &str, t: u64| {
        push(
            s,
            &NewMessage {
                friendship: Some(SentOn::Request),
                ..msg(to, from, body, at(t))
            },
        )
    };
    request(&dave, &alice, "a1", 1);
    request(&dave, &bob, "b1", 2);
    request(&dave, &alice, "a2", 3);
    request(&erin, &alice, "to erin", 4);
    push(s, &msg(&dave, &bob, "mail", at(5)));
    assert_eq!(
        bodies(&s.requests(&dave, at(0), 10).unwrap()),
        ["a1", "b1", "a2"],
        "{case}: oldest first, the recipient's alone"
    );
    assert_eq!(
        bodies(&s.requests(&dave, at(0), 2).unwrap()),
        ["a1", "b1"],
        "{case}"
    );
    assert_eq!(
        bodies(&s.requests(&dave, at(2), 10).unwrap()),
        ["b1", "a2"],
        "{case}: what was sent before `since` has lapsed"
    );

    let approval = rel.approve(&dave, &alice, at(6)).unwrap();
    assert_eq!(
        s.release_requests(&dave, &alice, approval, at(4)).unwrap(),
        0,
        "{case}: a lapsed request is never released"
    );
    assert_eq!(
        s.release_requests(&dave, &alice, approval, at(0)).unwrap(),
        2,
        "{case}"
    );
    assert_eq!(
        bodies(&s.requests(&dave, at(0), 10).unwrap()),
        ["b1"],
        "{case}"
    );
    assert_eq!(
        bodies(&s.pending_of(&dave, 10, INSTANT).unwrap()),
        ["a1", "a2"],
        "{case}: released onto the approval"
    );
    assert_eq!(s.delete_requests(&dave, &bob).unwrap(), 1, "{case}");
    assert!(s.requests(&dave, at(0), 10).unwrap().is_empty(), "{case}");
    assert_eq!(
        bodies(&s.requests(&erin, at(0), 10).unwrap()),
        ["to erin"],
        "{case}: another recipient's untouched"
    );
    assert_eq!(
        bodies(&s.pending(&dave, 10).unwrap()),
        ["a1", "a2", "mail"],
        "{case}"
    );
}

/// One row sent on each thing a row can be sent on, and what the gate
/// lets through of them.
fn the_gate_holds_what_was_sent_on_nothing_live(g: &Gated) {
    let case = "the_gate_holds_what_was_sent_on_nothing_live";
    let (s, rel) = (&*g.inbox, &*g.relationships);
    let (dave, alice, bob, carol) = (
        Mailbox::login("dave"),
        Mailbox::login("alice"),
        Mailbox::login("bob"),
        Mailbox::login("carol"),
    );
    let friend = rel.befriend(&dave, &alice, at(0)).unwrap();
    let ended = rel.befriend(&dave, &bob, at(0)).unwrap();
    rel.unfriend(&dave, &bob).unwrap();
    let approved = rel.approve(&dave, &carol, at(0)).unwrap();
    let sent = [
        ("mail", &carol, None),
        ("friend", &alice, Some(SentOn::Relation(friend))),
        ("ended", &bob, Some(SentOn::Relation(ended))),
        ("request", &carol, Some(SentOn::Request)),
        ("approved", &carol, Some(SentOn::Relation(approved))),
    ];
    for (i, (body, from, on)) in sent.iter().enumerate() {
        push(
            s,
            &NewMessage {
                friendship: *on,
                ..msg(&dave, from, body, at(i as u64))
            },
        );
    }
    let read = |which| -> Vec<String> {
        let rows = s.pending_of(&dave, 10, which).unwrap();
        assert_eq!(
            s.pending_count_of(&dave, which).unwrap(),
            rows.len(),
            "{case}: {which:?} counted as read"
        );
        rows.into_iter().map(|m| m.body).collect()
    };
    assert_eq!(read(Pending::All), ["mail", "friend", "approved"], "{case}");
    assert_eq!(read(Pending::Mail), ["mail"], "{case}");
    assert_eq!(
        read(Pending::MailApproved),
        ["mail", "approved"],
        "{case}: mail, and what an approval carries"
    );
    assert_eq!(
        read(Pending::Unapproved),
        ["mail", "friend"],
        "{case}: what an approval carries is left out"
    );
    assert_eq!(read(INSTANT), ["friend", "approved"], "{case}");
    assert_eq!(
        read(Pending::Instant {
            again: false,
            approvals: false
        }),
        ["friend"],
        "{case}: or without what an approval carries"
    );
    assert_eq!(
        s.pending_count(&dave).unwrap(),
        3,
        "{case}: held rows take no place"
    );
    assert_eq!(
        bodies(&s.list(&dave, None, 10).unwrap()),
        ["approved", "friend", "mail"],
        "{case}: nor are they listed"
    );
    assert_eq!(
        s.counts(&dave).unwrap(),
        InboxCounts {
            unread: 3,
            total: 3
        },
        "{case}"
    );
    // A cap counts what passes the gate, so a held backlog fills nothing.
    assert!(
        matches!(
            s.push(&msg(&dave, &alice, "one more", at(9)), 4).unwrap(),
            Pushed::Stored { .. }
        ),
        "{case}"
    );

    // Made again, a friendship has a new id, and what was queued on the
    // old one stays held; ended, what was sent on it is held too.
    rel.befriend(&dave, &bob, at(10)).unwrap();
    rel.unfriend(&dave, &alice).unwrap();
    assert_eq!(read(INSTANT), ["approved"], "{case}");
    assert_eq!(
        s.mark_read(&dave, Cursor::MAX, at(11)).unwrap(),
        3,
        "{case}: a read cursor skips what the gate holds"
    );
}

fn a_handed_message_waits_for_its_ack(g: &Gated) {
    let case = "a_handed_message_waits_for_its_ack";
    let (s, rel) = (&*g.inbox, &*g.relationships);
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let friend = rel.befriend(&dave, &alice, at(0)).unwrap();
    let id = push(
        s,
        &NewMessage {
            friendship: Some(SentOn::Relation(friend)),
            ..msg(&dave, &alice, "im", at(1))
        },
    );
    s.mark_handed(&[id], at(2)).unwrap();
    assert_eq!(
        s.pending_count(&dave).unwrap(),
        0,
        "{case}: counted as delivered"
    );
    assert!(!s.is_pending(&dave, id).unwrap(), "{case}");
    assert!(
        s.pending_of(&dave, 10, INSTANT).unwrap().is_empty(),
        "{case}: not handed over twice in one go"
    );
    assert_eq!(
        bodies(&s.pending_of(&dave, 10, AGAIN).unwrap()),
        ["im"],
        "{case}: but again at the next roster read"
    );
    s.mark_delivered(&[id], at(3), Delivery::Delivered).unwrap();
    assert!(
        s.pending_of(&dave, 10, AGAIN).unwrap().is_empty(),
        "{case}: until it is acknowledged"
    );
    assert!(
        s.receipt_told(id, at(4)).unwrap(),
        "{case}: a read told once"
    );
    assert!(
        !s.receipt_told(id, at(5)).unwrap(),
        "{case}: and never again"
    );
}

fn a_receipt_waits_behind_the_gate(g: &Gated) {
    let case = "a_receipt_waits_behind_the_gate";
    let (s, rel) = (&*g.inbox, &*g.relationships);
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let friend = rel.befriend(&dave, &alice, at(0)).unwrap();
    let id = push(
        s,
        &NewMessage {
            kind: MessageKind::ReadReceipt,
            friendship: Some(SentOn::Relation(friend)),
            ..msg(&dave, &alice, "a guid", at(1))
        },
    );
    assert!(
        s.pending(&dave, 10).unwrap().is_empty(),
        "{case}: never mail"
    );
    assert_eq!(
        bodies(&s.pending_of(&dave, 10, RECEIPTS).unwrap()),
        ["a guid"],
        "{case}"
    );
    rel.unfriend(&dave, &alice).unwrap();
    assert!(
        s.pending_of(&dave, 10, RECEIPTS).unwrap().is_empty(),
        "{case}: held with the friendship"
    );
    rel.befriend(&dave, &alice, at(2)).unwrap();
    s.mark_delivered(&[id], at(3), Delivery::Delivered).unwrap();
    assert!(
        s.pending_of(&dave, 10, RECEIPTS).unwrap().is_empty(),
        "{case}"
    );
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
    let id = place(s, &msg(&dave, &alice, "hi", at(1)));
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
    let theirs = place(s, &msg(&bob, &alice, "for bob", at(2)));
    // A client naming a cursor of another mailbox marks only its own mail.
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
    let ids: Vec<Cursor> = (0..5)
        .map(|i| place(s, &msg(&dave, &alice, &format!("m{i}"), at(i))))
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
    // Pushed and read in cursor order, because mark_read sweeps everything
    // up to the cursor it is given.
    let ancient = place(s, &msg(&dave, &a, "ancient", at(0)));
    s.mark_read(&dave, ancient, at(100)).unwrap();
    let recent = place(s, &msg(&dave, &a, "recent", at(0)));
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
    let read_at = place(s, &retry);
    s.mark_read(&bare, read_at, at(3)).unwrap();

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

    assert_eq!(
        s.purge_count(&dave).unwrap(),
        2,
        "{case}: dry run counts exactly what purge will remove"
    );
    let gone = s.purge(&dave).unwrap();
    assert_eq!(gone, 2, "{case}: one to it and one from it");
    assert_eq!(
        bodies(&s.list(&alice, None, 10).unwrap()),
        ["unrelated"],
        "{case}: and nobody else's mail"
    );
}

fn rotation_moves_a_mailbox_to_the_successor_key(s: &dyn MessageStore) {
    let case = "rotation_moves_a_mailbox_to_the_successor_key";
    let old = Mailbox::identified("dave", fp(1));
    let new = Mailbox::identified("dave", fp(2));
    let sender = Mailbox::login("sender");
    push(s, &msg(&old, &sender, "before the rotation", at(1)));

    assert_eq!(s.rotate(&fp(1), &fp(2)).unwrap(), 1, "{case}: the mail");
    assert_eq!(
        bodies(&s.pending(&new, 10).unwrap()),
        ["before the rotation"],
        "{case}: the mailbox moved to the successor key"
    );
    assert!(
        s.pending(&old, 10).unwrap().is_empty(),
        "{case}: and the retired key holds nothing"
    );
    assert_eq!(s.rotate(&fp(1), &fp(2)).unwrap(), 0, "{case}: idempotent");
}

fn the_same_guid_twice_is_one_message(s: &dyn MessageStore) {
    let case = "the_same_guid_twice_is_one_message";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let mut m = msg(&dave, &alice, "sent once", at(1));
    m.guid = Some(guid(1));
    let id = push(s, &m);

    let found = row(s.find_guid(&dave, Some(&alice), &guid(1)).unwrap())
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
        Pushed::Stored { id, .. } => id,
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
        Pushed::Stored { id, .. } => id,
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
                Pushed::Stored { .. }
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
            Pushed::Stored { .. }
        ),
        "{case}: delivery makes room"
    );
    // A receipt is not mail and is not what the cap is about.
    let mut receipt = msg(&dave, &alice, "ack", at(12));
    receipt.kind = MessageKind::ReadReceipt;
    assert!(
        matches!(s.push(&receipt, 3).unwrap(), Pushed::Stored { .. }),
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
        row(s.find_guid(&dave, None, &guid(7)).unwrap()).map(|m| m.body),
        Some("from a guest".to_string()),
        "{case}: and a sender with no mailbox is not every sender"
    );
    // Toward anyone, a sender's guid finds what it sent under it.
    assert_eq!(
        row(s.find_sent(&alice, &guid(7)).unwrap()).map(|m| m.body),
        Some("from alice".to_string()),
        "{case}: what a sender sent under a guid, to anyone"
    );
    assert!(
        s.find_sent(&carol, &guid(7)).unwrap().is_none(),
        "{case}: and nobody else's"
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

/// What the per-sender quota measures: one sender's mail since a time,
/// delivered or still waiting, under the mailbox rule on the sender's
/// side — bytes rather than characters, and never a receipt, another
/// sender's mail, or a row from before the window.
fn sent_since_counts_a_senders_stored_mail_in_its_window(s: &dyn MessageStore) {
    let case = "sent_since_counts_a_senders_stored_mail_in_its_window";
    let (dave, bob) = (Mailbox::login("dave"), Mailbox::login("bob"));
    let alice = Mailbox::identified("alice", fp(1));
    push(s, &msg(&dave, &alice, "before the window", at(100)));
    // Two characters and three bytes, and delivered: a delivered row is
    // still stored, and storage is what the quota is about.
    let read = push(s, &msg(&dave, &alice, "h\u{e9}", at(200)));
    s.mark_delivered(&[read], at(201), Delivery::Read).unwrap();
    push(s, &msg(&bob, &alice, "four", at(300)));
    push(s, &msg(&dave, &bob, "bob's", at(300)));
    push(
        s,
        &NewMessage {
            kind: MessageKind::ReadReceipt,
            ..msg(&bob, &alice, "a receipt", at(300))
        },
    );
    push(
        s,
        &NewMessage {
            friendship: Some(SentOn::Request),
            ..msg(&bob, &alice, "a request, which the ledger counts", at(300))
        },
    );
    let sent = |who: &Mailbox| s.sent_since(who, at(150)).unwrap();
    assert_eq!(
        sent(&alice),
        Sent {
            messages: 2,
            bytes: 3 + 4,
        },
        "{case}"
    );
    assert_eq!(
        sent(&Mailbox::identified("alicia", fp(1))),
        sent(&alice),
        "{case}: a rename is the same sender"
    );
    assert_eq!(
        sent(&Mailbox::login("alice")),
        Sent::default(),
        "{case}: a bare login never claims an identity's mail"
    );
    assert_eq!(
        sent(&bob),
        Sent {
            messages: 1,
            bytes: 5,
        },
        "{case}"
    );
}

// --- Stubs (`docs/private-messages.md` §9) --------------------------------

/// Retention as the stub cases run it: a read message goes 100s after it
/// was read, and its sender's window closes 500s after it was sent. Every
/// age below stays a second or more off either edge, which the two stores
/// measure in different units.
fn prune_at(s: &dyn MessageStore, now: u64) -> usize {
    s.prune(at(now), Duration::from_secs(500), Duration::from_secs(100))
        .unwrap()
}

/// Store `m`, sent at 0, read at 10 and pruned at 200: well inside its
/// sender's window, so it leaves a stub.
fn stubbed(s: &dyn MessageStore, m: &NewMessage) -> MessageRef {
    let (reference, cursor) = match s.push(m, usize::MAX).unwrap() {
        Pushed::Stored {
            reference, cursor, ..
        } => (reference, cursor),
        other => panic!("expected a new row, got {other:?}"),
    };
    s.mark_read(&m.recipient, cursor, at(10)).unwrap();
    assert_eq!(prune_at(s, 200), 1, "read and pruned");
    reference
}

fn sent_as(to: &Mailbox, from: &Mailbox, n: u8) -> NewMessage {
    NewMessage {
        guid: Some(guid(n)),
        ..msg(to, from, "read", at(0))
    }
}

fn a_stub_answers_a_retry_as_its_row_did(s: &dyn MessageStore) {
    let case = "a_stub_answers_a_retry_as_its_row_did";
    let (dave, carol) = (Mailbox::login("dave"), Mailbox::login("carol"));
    let alice = Mailbox::identified("alice", fp(1));
    let signature = crate::history::Signature {
        form: vec![1],
        content: [7; 32],
    };
    for (n, signed) in [(1, None), (2, Some(signature))] {
        let sent = NewMessage {
            signed: signed.clone(),
            ..sent_as(&dave, &alice, n)
        };
        let reference = stubbed(s, &sent);
        let signed = signed.map(|x| x.content);
        assert_eq!(
            s.push(&sent, usize::MAX).unwrap(),
            Pushed::Pruned { reference, signed },
            "{case}: a retry of {n}"
        );
        assert_eq!(s.counts(&dave).unwrap().total, 0, "{case}: writes nothing");
        let stub = Some(Found::Stub(Box::new(Stub {
            reference,
            recipient: dave.clone(),
            sender: Some(alice.clone()),
            guid: Some(guid(n)),
            signed,
            sent_at: at(0),
        })));
        assert_eq!(s.find_guid(&dave, Some(&alice), &guid(n)).unwrap(), stub);
        assert_eq!(s.find_sent(&alice, &guid(n)).unwrap(), stub);
        assert_eq!(s.find_guid(&dave, Some(&carol), &guid(n)).unwrap(), None);
        assert_eq!(s.find_guid(&carol, Some(&alice), &guid(n)).unwrap(), None);
        assert_eq!(s.find_sent(&carol, &guid(n)).unwrap(), None);
    }
    assert_eq!(prune_at(s, 600), 0, "{case}: the window closes");
    assert_eq!(s.find_sent(&alice, &guid(2)).unwrap(), None, "{case}");
    assert!(
        matches!(
            s.push(&sent_as(&dave, &alice, 1), usize::MAX).unwrap(),
            Pushed::Stored { .. }
        ),
        "{case}: a retry after it is a new message"
    );
}

/// Past its sender's window a read message the recipient kept and an
/// unread one retention deleted look alike to a retry: both store anew.
fn a_read_message_kept_past_the_window_answers_a_retry_as_an_unread_one_would(
    s: &dyn MessageStore,
) {
    let case = "a_read_message_kept_past_the_window_answers_a_retry_as_an_unread_one_would";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let sent = [sent_as(&dave, &alice, 1), sent_as(&dave, &alice, 2)];
    let read = place(s, &sent[0]);
    s.mark_read(&dave, read, at(450)).unwrap();
    push(s, &sent[1]);
    for (now, inside) in [(490, true), (540, false)] {
        prune_at(s, now);
        for (m, which) in sent.iter().zip(["read late", "unread"]) {
            let stored = match s.push(m, usize::MAX).unwrap() {
                Pushed::Existing(_) => false,
                Pushed::Stored { .. } => true,
                other => panic!("{case}: {which} at {now}: {other:?}"),
            };
            assert_eq!(stored, !inside, "{case}: {which} at {now}");
        }
    }
}

fn a_stub_is_never_mail(s: &dyn MessageStore) {
    let case = "a_stub_is_never_mail";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    stubbed(s, &sent_as(&dave, &alice, 1));
    push(s, &msg(&dave, &alice, "waiting", at(150)));
    assert_eq!(
        bodies(&s.list(&dave, None, 10).unwrap()),
        ["waiting"],
        "{case}"
    );
    assert_eq!(
        bodies(&s.pending_of(&dave, 10, Pending::All).unwrap()),
        ["waiting"],
        "{case}"
    );
    assert_eq!(
        s.counts(&dave).unwrap(),
        InboxCounts {
            unread: 1,
            total: 1
        },
        "{case}"
    );
    assert_eq!(s.sent_since(&alice, at(0)).unwrap().messages, 1, "{case}");
    assert_eq!(s.purge_count(&dave).unwrap(), 1, "{case}: dave's");
    assert_eq!(s.purge_count(&alice).unwrap(), 1, "{case}: alice's");
}

fn a_stub_follows_a_claim_and_a_rotation(s: &dyn MessageStore) {
    let case = "a_stub_follows_a_claim_and_a_rotation";
    let found = |to: Mailbox, from: Mailbox| {
        matches!(
            s.find_guid(&to, Some(&from), &guid(1)).unwrap(),
            Some(Found::Stub(_))
        )
    };
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    stubbed(s, &sent_as(&dave, &alice, 1));
    s.claim("dave", &fp(1)).unwrap();
    s.claim("alice", &fp(2)).unwrap();
    let id = Mailbox::identified;
    assert!(
        found(id("dave", fp(1)), id("alice", fp(2))),
        "{case}: claimed"
    );
    assert!(!found(dave, alice), "{case}: and off the logins");
    s.rotate(&fp(1), &fp(3)).unwrap();
    s.rotate(&fp(2), &fp(4)).unwrap();
    assert!(
        found(id("dave", fp(3)), id("alice", fp(4))),
        "{case}: rotated"
    );
    assert!(
        !found(id("dave", fp(1)), id("alice", fp(2))),
        "{case}: and off the old keys"
    );
}

fn purging_an_account_takes_its_stubs(s: &dyn MessageStore) {
    let case = "purging_an_account_takes_its_stubs";
    let l = Mailbox::login;
    // Dave is purged as a recipient, frank as a sender, and bob's to
    // carol is nobody's business.
    let pairs = [
        (l("dave"), l("alice")),
        (l("erin"), l("frank")),
        (l("carol"), l("bob")),
    ];
    for (n, (to, from)) in pairs.iter().enumerate() {
        stubbed(s, &sent_as(to, from, n as u8));
    }
    s.purge(&l("dave")).unwrap();
    s.purge(&l("frank")).unwrap();
    let left: Vec<bool> = pairs
        .iter()
        .enumerate()
        .map(|(n, (to, from))| {
            s.find_guid(to, Some(from), &guid(n as u8))
                .unwrap()
                .is_some()
        })
        .collect();
    assert_eq!(left, [false, false, true], "{case}");
}

/// Sent to an identity, retried to the bare login after an unlink, and
/// claimed back: the retry is answered under the identity's reference
/// whether either copy was read and pruned, before the identity's copy
/// is read and pruned and after, and a copy that was read leaves the
/// survivor read.
fn a_claim_answers_a_retry_under_one_reference_read_or_not(s: &dyn MessageStore) {
    let case = "a_claim_answers_a_retry_under_one_reference_read_or_not";
    let alice = Mailbox::login("alice");
    let send = |m: &NewMessage, read: bool| match read {
        true => stubbed(s, m),
        false => match s.push(m, usize::MAX).unwrap() {
            Pushed::Stored { reference, .. } => reference,
            other => panic!("{case}: {other:?}"),
        },
    };
    // Where the retry was read, a store that kept its stub beside the
    // survivor answers with it about half the time once both are
    // pruned, so those cases are asked often.
    let often = |c| std::iter::repeat_n(c, 16);
    for (n, (linked, bare)) in [(false, false), (true, false)]
        .into_iter()
        .chain(often((false, true)))
        .chain(often((true, true)))
        .enumerate()
    {
        let login = format!("dave{n}");
        let id = Mailbox::identified(&login, fp(n as u8));
        let first = send(&sent_as(&id, &alice, 1), linked);
        send(&sent_as(&Mailbox::login(&login), &alice, 1), bare);
        s.claim(&login, &fp(n as u8)).unwrap();
        let unread = usize::from(!linked && !bare);
        assert_eq!(s.pending_count(&id).unwrap(), unread, "{case}: {n} pending");
        assert_eq!(s.counts(&id).unwrap().unread, unread, "{case}: {n} unread");
        for when in ["claimed", "pruned"] {
            let answered = match s.push(&sent_as(&id, &alice, 1), usize::MAX).unwrap() {
                Pushed::Existing(m) => m.reference,
                Pushed::Pruned { reference, .. } => reference,
                other => panic!("{case}: {other:?}"),
            };
            assert_eq!(
                answered, first,
                "{case}: read {linked}, retry read {bare}, {when}"
            );
            s.mark_read(&id, Cursor::MAX, at(10)).unwrap();
            prune_at(s, 200);
        }
    }
}

/// An instant message, a request and a receipt, read and pruned inside
/// the window and read and kept past it: none is a private message, so
/// none leaves a stub or loses its guid.
fn only_a_private_message_leaves_a_stub_or_loses_its_guid(s: &dyn MessageStore) {
    let case = "only_a_private_message_leaves_a_stub_or_loses_its_guid";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let kinds = [
        ("instant", MessageKind::Message, Some(SentOn::Relation(1))),
        ("request", MessageKind::Message, Some(SentOn::Request)),
        ("receipt", MessageKind::ReadReceipt, None),
    ];
    for (phase, read, now, first) in [("pruned", 100, 200, 10u8), ("kept", 1000, 540, 20)] {
        let sent: Vec<NewMessage> = kinds
            .iter()
            .zip(first..)
            .map(|((_, kind, friendship), n)| NewMessage {
                kind: *kind,
                friendship: *friendship,
                ..sent_as(&dave, &alice, n)
            })
            .collect();
        let ids: Vec<MessageId> = sent.iter().map(|m| push(s, m)).collect();
        s.mark_delivered(&ids, at(10), Delivery::Read).unwrap();
        s.prune(at(now), Duration::from_secs(500), Duration::from_secs(read))
            .unwrap();
        for (m, (which, ..)) in sent.iter().zip(&kinds) {
            let retry = s.push(m, usize::MAX).unwrap();
            let held = match &retry {
                Pushed::Stored { .. } => false,
                Pushed::Existing(_) => true,
                other => panic!("{case}: {which} {phase}: {other:?}"),
            };
            assert_eq!(held, phase == "kept", "{case}: {which} {phase}");
        }
    }
}

/// The parties' side of a stub: each finds it while the sender's window
/// holds its `sent_at`, whether or not retention has taken it yet, and
/// neither after.
fn an_early_pruned_message_leaves_a_stub_its_parties_still_find(s: &dyn MessageStore) {
    let case = "an_early_pruned_message_leaves_a_stub_its_parties_still_find";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = stubbed(s, &sent_as(&dave, &alice, 1));
    for (now, prune, inside) in [(490, false, true), (510, false, false), (600, true, false)] {
        if prune {
            prune_at(s, now);
        }
        for who in [&dave, &alice] {
            let found = s.message_party(&r, who, window(now)).unwrap();
            assert_eq!(found.is_some(), inside, "{case}: {} at {now}", who.login);
        }
    }
}

fn a_message_kept_past_the_window_answers_its_recipient_and_not_its_sender(s: &dyn MessageStore) {
    let case = "a_message_kept_past_the_window_answers_its_recipient_and_not_its_sender";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(s, &msg(&dave, &alice, "kept", at(0)), false, &[]);
    s.mark_read(&dave, Cursor::MAX, at(450)).unwrap();
    let parties = Parties {
        recipient: dave.clone(),
        sender: Some(alice.clone()),
    };
    for (now, sender) in [(490, true), (540, false)] {
        prune_at(s, now);
        let party = |who| s.message_party(&r, who, window(now)).unwrap();
        assert_eq!(party(&dave), Some(parties.clone()), "{case}: dave at {now}");
        let seen = party(&alice).is_some();
        assert_eq!(seen, sender, "{case}: alice at {now}");
    }
}

/// A message to one's own account is held to the recipient's rule, so
/// it is not shut out with the sender's window.
fn mail_to_ones_own_account_kept_past_the_window_is_still_its_recipients(s: &dyn MessageStore) {
    let case = "mail_to_ones_own_account_kept_past_the_window_is_still_its_recipients";
    let dave = Mailbox::login("dave");
    let r = put(s, &msg(&dave, &dave, "note", at(0)), false, &[]);
    s.mark_read(&dave, Cursor::MAX, at(450)).unwrap();
    prune_at(s, 540);
    assert!(
        s.message_party(&r, &dave, window(540)).unwrap().is_some(),
        "{case}"
    );
    applied(react(s, r, &dave, "👍", true, 540));
    assert_eq!(shown(s, r, &dave, 540), shows(&[("👍", 1)], &[0]), "{case}");
}

// --- Reactions on stored messages (`docs/private-messages.md` §5) ------

/// Where the sender's window opens at `now`, as `prune_at` closes it.
fn window(now: u64) -> SystemTime {
    at(now.saturating_sub(500))
}

fn key(s: &str) -> ReactionKey {
    ReactionKey::emoji(s).unwrap()
}

/// `who`, under its login as its nick, adding or removing `k` on `r` at
/// `now`, held to `caps` (keys, and keys an account holds).
fn react_capped(
    s: &dyn MessageStore,
    r: MessageRef,
    who: &Mailbox,
    k: &str,
    add: bool,
    now: u64,
    caps: (usize, usize),
) -> MessageReacted {
    s.react_message(&MessageReactAct {
        reference: r,
        who,
        nick: &who.login,
        key: &key(k),
        add,
        at: at(now),
        open_since: window(now),
        max_keys: caps.0,
        max_per_user: caps.1,
    })
    .unwrap()
}

fn react(
    s: &dyn MessageStore,
    r: MessageRef,
    who: &Mailbox,
    k: &str,
    add: bool,
    now: u64,
) -> MessageReacted {
    react_capped(s, r, who, k, add, now, (8, 8))
}

fn applied(reacted: MessageReacted) -> MessageState {
    match reacted {
        MessageReacted::Applied(state) => *state,
        other => panic!("expected it applied, got {other:?}"),
    }
}

/// What `reader` is shown of `r` at `now`, `None` for nothing.
fn shown(s: &dyn MessageStore, r: MessageRef, reader: &Mailbox, now: u64) -> Option<Reactions> {
    let mut shown = s
        .message_reactions(&[r], reader, window(now), None)
        .unwrap();
    shown.remove(&r).map(|(reactions, _)| reactions)
}

fn shows(keys: &[(&str, u32)], mine: &[u8]) -> Option<Reactions> {
    Some(Reactions {
        keys: keys.iter().map(|&(k, n)| (key(k), n)).collect(),
        mine: mine.to_vec(),
    })
}

/// Store `m` with `reactions` made at 1, 2, …, and as a stub with
/// `stub`: read at 10 and pruned at 200.
fn put(
    s: &dyn MessageStore,
    m: &NewMessage,
    stub: bool,
    reactions: &[(&Mailbox, &str)],
) -> MessageRef {
    let (id, reference) = match s.push(m, usize::MAX).unwrap() {
        Pushed::Stored { id, reference, .. } => (id, reference),
        other => panic!("expected a new row, got {other:?}"),
    };
    for (n, (who, k)) in (1..).zip(reactions) {
        applied(react(s, reference, who, k, true, n));
    }
    if stub {
        s.mark_delivered(&[id], at(10), Delivery::Read).unwrap();
        prune_at(s, 200);
    }
    reference
}

/// Each add or removal that changes nothing is answered as held, and
/// each that does with the state it leaves.
fn a_message_reaction_adds_removes_and_holds(s: &dyn MessageStore) {
    let case = "a_message_reaction_adds_removes_and_holds";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(s, &msg(&dave, &alice, "hi", at(0)), false, &[]);
    assert_eq!(
        applied(react(s, r, &alice, "👍", true, 1)),
        MessageState {
            reference: r,
            recipient: dave.clone(),
            sender: Some(alice.clone()),
            sent_at: at(0),
            delivered: false,
            row: true,
            keys: vec![(key("👍"), 1)],
            held: vec![("l:alice".into(), key("👍"))],
        },
        "{case}"
    );
    assert_eq!(react(s, r, &alice, "👍", true, 2), MessageReacted::Held);
    assert_eq!(react(s, r, &dave, "🎉", false, 3), MessageReacted::Held);
    let state = applied(react(s, r, &dave, "👍", true, 4));
    assert_eq!(state.keys, [(key("👍"), 2)], "{case}");
    assert_eq!(shown(s, r, &dave, 5), shows(&[("👍", 2)], &[0]), "{case}");
    applied(react(s, r, &alice, "👍", false, 6));
    let state = applied(react(s, r, &dave, "👍", false, 7));
    assert_eq!((state.keys, state.held), (vec![], vec![]), "{case}");
    assert_eq!(shown(s, r, &dave, 8), None, "{case}: nothing left to show");
}

/// Keys in the order first added; who holds one newest first, the later
/// of two made in one second first.
fn message_reactions_keep_first_added_order_and_name_holders_newest_first(s: &dyn MessageStore) {
    let case = "message_reactions_keep_first_added_order_and_name_holders_newest_first";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(s, &msg(&dave, &alice, "hi", at(0)), false, &[]);
    for (who, k, now) in [
        (&alice, "🎉", 5),
        (&dave, "👍", 5),
        (&alice, "👍", 5),
        (&dave, "🎉", 9),
    ] {
        applied(react(s, r, who, k, true, now));
    }
    for (asked, holders) in [
        (None, vec![]),
        (Some("🎉"), vec!["dave", "alice"]),
        (Some("👍"), vec!["alice", "dave"]),
        (Some("😀"), vec![]),
    ] {
        let asked = asked.map(key);
        let got = s
            .message_reactions(&[r], &alice, window(10), asked.as_ref())
            .unwrap();
        let holders = holders.into_iter().map(String::from).collect();
        let expected = (shows(&[("🎉", 2), ("👍", 2)], &[0, 1]).unwrap(), holders);
        assert_eq!(got.get(&r), Some(&expected), "{case}: {asked:?}");
    }
}

/// A new key past the message's keys, or past what one account may
/// hold on it, is dropped; adding to a key already there never is.
fn a_message_holds_its_caps_in_the_write(s: &dyn MessageStore) {
    let case = "a_message_holds_its_caps_in_the_write";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(s, &msg(&dave, &alice, "hi", at(0)), false, &[]);
    for (n, (who, k, ok)) in (1..).zip([
        (&alice, "👍", true),
        (&alice, "🎉", true),
        (&alice, "😀", false),
        (&dave, "😀", true),
        (&dave, "🔥", false),
        (&dave, "👍", true),
        (&dave, "🎉", false),
    ]) {
        let reacted = react_capped(s, r, who, k, true, n, (3, 2));
        let dropped = reacted == MessageReacted::Dropped;
        assert_eq!(!dropped, ok, "{case}: {} {k}", who.login);
    }
    assert_eq!(
        shown(s, r, &dave, 10),
        shows(&[("👍", 2), ("🎉", 1), ("😀", 1)], &[0, 2]),
        "{case}"
    );
}

/// Neither a stranger nor the other kind of mailbox key reacts to, reads
/// or is a party to a message.
fn either_party_and_no_one_else_reacts_and_reads(s: &dyn MessageStore) {
    let case = "either_party_and_no_one_else_reacts_and_reads";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::identified("alice", fp(1)));
    let r = put(s, &msg(&dave, &alice, "hi", at(0)), false, &[]);
    let others = [
        Mailbox::login("carol"),
        Mailbox::login("alice"),
        Mailbox::identified("dave", fp(2)),
    ];
    for (n, who) in (1..).zip(&others) {
        let reacted = react(s, r, who, "👍", true, n);
        assert_eq!(reacted, MessageReacted::Dropped, "{case}: {who:?}");
    }
    for (n, who) in (10..).zip([&dave, &alice]) {
        applied(react(s, r, who, "👍", true, n));
        let parties = s.message_party(&r, who, window(n)).unwrap();
        let expected = Parties {
            recipient: dave.clone(),
            sender: Some(alice.clone()),
        };
        assert_eq!(parties, Some(expected), "{case}: {who:?}");
    }
    for who in &others {
        assert_eq!(
            s.message_party(&r, who, window(20)).unwrap(),
            None,
            "{case}"
        );
        assert_eq!(shown(s, r, who, 20), None, "{case}: {who:?} reads");
    }
}

/// Instant messages, requests and receipts take none, and a request the
/// recipient turns into mail does from then on.
fn only_a_private_message_takes_reactions(s: &dyn MessageStore) {
    let case = "only_a_private_message_takes_reactions";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    for (which, kind, friendship) in [
        ("instant", MessageKind::Message, Some(SentOn::Relation(1))),
        ("request", MessageKind::Message, Some(SentOn::Request)),
        ("receipt", MessageKind::ReadReceipt, None),
    ] {
        let sent = NewMessage {
            kind,
            friendship,
            ..msg(&dave, &alice, "not mail", at(0))
        };
        let r = put(s, &sent, false, &[]);
        let reacted = react(s, r, &alice, "👍", true, 1);
        assert_eq!(reacted, MessageReacted::Dropped, "{case}: {which}");
        let party = s.message_party(&r, &alice, window(1)).unwrap();
        assert_eq!(party, None, "{case}: {which}");
        if which == "request" {
            s.requests_to_mail(&dave, &alice, None, at(0)).unwrap();
            applied(react(s, r, &alice, "👍", true, 2));
        }
    }
}

/// A purge of either party, and retention of an unread message past its
/// window, leave none of its reactions anywhere.
fn a_messages_reactions_go_with_it_however_it_goes(s: &dyn MessageStore) {
    let case = "a_messages_reactions_go_with_it_however_it_goes";
    let l = |name: String| Mailbox::login(name);
    for (n, how) in [
        "recipient purged",
        "sender purged",
        "unread past its window",
    ]
    .into_iter()
    .enumerate()
    {
        let (to, from) = (l(format!("to{n}")), l(format!("from{n}")));
        put(
            s,
            &msg(&to, &from, "hi", at(0)),
            false,
            &[(&to, "👍"), (&from, "🎉")],
        );
        match n {
            0 => s.purge(&to).map(drop).unwrap(),
            1 => s.purge(&from).map(drop).unwrap(),
            _ => assert_eq!(prune_at(s, 600), 1, "{case}"),
        }
        for who in [&to, &from] {
            let left = s.forget_message_reactions(who, at(0)).unwrap();
            assert!(left.is_empty(), "{case}: {how}, {}'s", who.login);
        }
    }
}

/// A read message pruned inside its window keeps its reactions on its
/// stub, and both parties go on reading and making them there, until
/// the stub goes and takes them.
fn a_stubs_reactions_last_until_the_window_ends(s: &dyn MessageStore) {
    let case = "a_stubs_reactions_last_until_the_window_ends";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(s, &msg(&dave, &alice, "hi", at(0)), true, &[(&alice, "👍")]);
    applied(react(s, r, &dave, "🎉", true, 300));
    applied(react(s, r, &alice, "😀", true, 300));
    let all = [("👍", 1), ("🎉", 1), ("😀", 1)];
    assert_eq!(shown(s, r, &alice, 300), shows(&all, &[0, 2]), "{case}");
    assert_eq!(shown(s, r, &dave, 300), shows(&all, &[1]), "{case}");
    let states = s.message_reaction_states(&[r]).unwrap();
    assert!(states[0].delivered, "{case}: a stub answers as delivered");
    assert!(!states[0].row, "{case}");
    prune_at(s, 600);
    assert!(
        s.message_reaction_states(&[r]).unwrap().is_empty(),
        "{case}"
    );
    let left = s.forget_message_reactions(&alice, at(0)).unwrap();
    assert!(left.is_empty(), "{case}: gone with the stub");
}

/// A read row the recipient keeps past its sender's window keeps its
/// reactions for the recipient, who still makes them, and shows the
/// sender nothing.
fn a_kept_rows_reactions_are_the_recipients_after_the_window(s: &dyn MessageStore) {
    let case = "a_kept_rows_reactions_are_the_recipients_after_the_window";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(
        s,
        &msg(&dave, &alice, "hi", at(0)),
        false,
        &[(&alice, "👍")],
    );
    s.mark_read(&dave, Cursor::MAX, at(450)).unwrap();
    prune_at(s, 540);
    let reacted = react(s, r, &alice, "🎉", true, 540);
    assert_eq!(reacted, MessageReacted::Dropped, "{case}: the sender");
    let state = applied(react(s, r, &dave, "😀", true, 540));
    assert_eq!(state.sent_at, at(0), "{case}: which shuts the sender out");
    let both = [("👍", 1), ("😀", 1)];
    assert_eq!(shown(s, r, &dave, 540), shows(&both, &[1]), "{case}");
    assert_eq!(shown(s, r, &alice, 540), None, "{case}");
}

/// A claim or rotation that merges a duplicate, a row or a stub, into a
/// row or stub already at the destination, on either half of the guid
/// key, moves the duplicate's reactions onto the survivor, one both
/// held kept once.
fn a_merged_duplicate_gives_the_survivor_its_reactions(new_store: &dyn Fn() -> Gated) {
    let case = "a_merged_duplicate_gives_the_survivor_its_reactions";
    let (alice, bare) = (Mailbox::login("alice"), Mailbox::login("dave"));
    let (dave1, dave2) = (
        Mailbox::identified("dave", fp(1)),
        Mailbox::identified("dave", fp(2)),
    );
    for rotate in [false, true] {
        let (from, to) = match rotate {
            false => (&bare, &dave1),
            true => (&dave1, &dave2),
        };
        for sender_half in [false, true] {
            for (kept_stub, moving_stub) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let s = &*new_store().inbox;
                let sent = |dave: &Mailbox| match sender_half {
                    false => sent_as(dave, &alice, 1),
                    true => sent_as(&alice, dave, 1),
                };
                let kept = put(s, &sent(to), kept_stub, &[(&alice, "👍")]);
                let carried = [(&alice, "👍"), (from, "🎉"), (from, "😀")];
                let moving = put(s, &sent(from), moving_stub, &carried);
                match rotate {
                    false => s.claim("dave", &fp(1)).map(drop).unwrap(),
                    true => s.rotate(&fp(1), &fp(2)).map(drop).unwrap(),
                }
                let what = format!(
                    "{case}: rotate {rotate}, sender {sender_half}, stubs {kept_stub} {moving_stub}"
                );
                let states = s.message_reaction_states(&[kept, moving]).unwrap();
                let keys: Vec<_> = states
                    .iter()
                    .map(|x| (x.reference, x.keys.clone()))
                    .collect();
                assert_eq!(
                    keys,
                    [(kept, vec![(key("👍"), 1), (key("🎉"), 1), (key("😀"), 1)])],
                    "{what}"
                );
                let carried = s.forget_message_reactions(from, at(0)).unwrap();
                assert_eq!(carried, [kept], "{what}: and nothing left on the duplicate");
            }
        }
    }
}

/// A reactor's claim and rotation move its reactions to its new key, a
/// key it held under both going once and its message answered.
fn message_reactions_follow_a_reactors_claim_and_rotation(s: &dyn MessageStore) {
    let case = "message_reactions_follow_a_reactors_claim_and_rotation";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let (alice1, alice2) = (
        Mailbox::identified("alice", fp(1)),
        Mailbox::identified("alice", fp(2)),
    );
    let r = put(
        s,
        &msg(&dave, &alice, "hi", at(0)),
        false,
        &[(&alice, "👍"), (&alice, "🎉")],
    );
    s.claim("alice", &fp(1)).unwrap();
    applied(react(s, r, &alice1, "👍", true, 5));
    let both = [("👍", 2), ("🎉", 1)];
    assert_eq!(shown(s, r, &dave, 5), shows(&both, &[]), "{case}");
    assert_eq!(
        s.rekey_message_reactions(&alice, &alice1).unwrap(),
        [r],
        "{case}"
    );
    // The 👍 that went was the first made, so 🎉 is first now.
    let after = [("🎉", 1), ("👍", 1)];
    assert_eq!(
        shown(s, r, &alice1, 6),
        shows(&after, &[0, 1]),
        "{case}: claimed"
    );
    s.rotate(&fp(1), &fp(2)).unwrap();
    for (from, why) in [(&alice1, "nothing to fold"), (&alice2, "onto itself")] {
        let lost = s.rekey_message_reactions(from, &alice2).unwrap();
        assert!(lost.is_empty(), "{case}: {why}");
    }
    assert_eq!(
        shown(s, r, &alice2, 7),
        shows(&after, &[0, 1]),
        "{case}: rotated"
    );
}

/// A purge takes every reaction made under the mailbox's key, on mail
/// that is no longer its own too, so a later holder of the login holds
/// none: here mail claimed by an identity before its reactions moved.
fn purging_an_account_takes_every_reaction_it_made(s: &dyn MessageStore) {
    let case = "purging_an_account_takes_every_reaction_it_made";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let r = put(
        s,
        &msg(&dave, &alice, "hi", at(0)),
        false,
        &[(&alice, "👍")],
    );
    s.claim("alice", &fp(1)).unwrap();
    s.purge(&alice).unwrap();
    assert_eq!(shown(s, r, &dave, 5), None, "{case}");
}

/// A moderator's purge of what a person did lately takes its reactions
/// made since then, on rows and stubs alike, and leaves the older ones
/// and the stubs.
fn forgetting_a_persons_message_reactions_keeps_those_before_the_window_and_the_stubs(
    s: &dyn MessageStore,
) {
    let case = "forgetting_a_persons_message_reactions_keeps_those_before_the_window_and_the_stubs";
    let (dave, alice) = (Mailbox::login("dave"), Mailbox::login("alice"));
    let reactions = [(&alice, "👍"), (&alice, "🎉"), (&dave, "😀")];
    let stub = put(s, &sent_as(&dave, &alice, 0), true, &reactions);
    // Enough random refs that answers out of order are never in order by
    // chance.
    let mut all: Vec<MessageRef> = (1..8)
        .map(|n| put(s, &sent_as(&dave, &alice, n), false, &reactions))
        .chain([stub])
        .collect();
    let lost = s.forget_message_reactions(&alice, at(2)).unwrap();
    all.sort_unstable();
    assert_eq!(lost, all, "{case}: in ref order");
    for &r in &all {
        let left = [("👍", 1), ("😀", 1)];
        assert_eq!(shown(s, r, &dave, 300), shows(&left, &[1]), "{case}");
    }
    assert!(
        s.message_party(&stub, &dave, window(300))
            .unwrap()
            .is_some(),
        "{case}"
    );
}
