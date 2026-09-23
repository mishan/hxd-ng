//! A suite every [`RegistrarStore`] must pass.
//!
//! Two implementations, one set of answers: the in-memory store the
//! domain's tests run on and the SQLite one a registrar keeps. Public,
//! like `hxd_core::inbox::conformance`, because the implementation it
//! most needs to check is in another crate. The bytes stored here are
//! arbitrary — the store never reads what it keeps — and times are fixed
//! numbers, never the wall clock.

use sha2::{Digest, Sha256};

use crate::store::{
    Effect, HandleRow, Issue, Issued, Key, NewRecord, Pending, Publish, RecordFilter, RecordKind,
    Recovery, RegistrarStore,
};

/// Run every case against a freshly built store.
pub fn run(new_store: &dyn Fn() -> Box<dyn RegistrarStore>) {
    an_issuance_creates_the_identity_and_logs_in_order(&*new_store());
    a_commitment_is_set_once(&*new_store());
    an_invite_is_spent_exactly_once(&*new_store());
    a_record_is_published_once_and_answers_with_its_seq(&*new_store());
    a_rotation_moves_every_handle_and_keeps_its_age(&*new_store());
    lapsing_keeps_the_earliest_time_and_bars_on_request(&*new_store());
    a_per_identity_list_carries_both_sides_of_a_rotation(&*new_store());
    the_full_list_prunes_what_has_stopped_mattering(&*new_store());
    the_full_list_keeps_a_bounded_number_of_device_revocations(&*new_store());
    pages_are_cut_by_budget_and_always_make_progress(&*new_store());
    pending_rotations_come_due_in_order(&*new_store());
    a_recovery_is_redeemed_by_the_issuance_it_grants(&*new_store());
    attestation_expiry_is_bounded_by_issue_time(&*new_store());
    counts_are_what_the_stats_say(&*new_store());
    identities_are_found_by_fingerprint(&*new_store());
}

const T: u64 = 1_750_000_000;
const YEAR: u64 = 365 * 86_400;

fn key(n: u8) -> Key {
    [n; 32]
}

fn fp(k: &Key) -> [u8; 32] {
    Sha256::digest(k).into()
}

fn handle(name: &str, id: Key, registered: u64, expires: u64) -> HandleRow {
    HandleRow {
        name: name.into(),
        identity: id,
        registered,
        expires,
        lapsed_at: None,
        barred: false,
    }
}

fn issue(id: Key, name: &str, at: u64) -> Issue {
    Issue {
        identity: id,
        commitment: None,
        handle: handle(name, id, at, at + YEAR),
        first: true,
        issued: at,
        attestation: format!("att:{name}:{at}").into_bytes(),
        invite: None,
        recovery: None,
    }
}

fn logged(r: Issued) -> u64 {
    match r {
        Issued::Logged(seq) => seq,
        Issued::InviteSpent => panic!("an issuance with no invite cannot be refused one"),
    }
}

fn record(
    kind: RecordKind,
    id: Key,
    other: Option<Key>,
    until: Option<u64>,
    tag: &str,
) -> NewRecord {
    let bytes = format!("{}:{tag}", kind.as_str()).into_bytes();
    NewRecord {
        kind,
        identity: id,
        other,
        until,
        digest: Sha256::digest(&bytes).into(),
        bytes,
    }
}

fn publish(s: &dyn RegistrarStore, records: Vec<NewRecord>, effects: Vec<Effect>) -> Vec<u64> {
    s.publish(&Publish { records, effects }).unwrap()
}

fn seqs(s: &dyn RegistrarStore, filter: RecordFilter) -> Vec<u64> {
    s.records_page(filter, 0, usize::MAX)
        .unwrap()
        .entries
        .into_iter()
        .map(|(seq, _)| seq)
        .collect()
}

fn an_issuance_creates_the_identity_and_logs_in_order(s: &dyn RegistrarStore) {
    assert!(s.identity(&key(1)).unwrap().is_none());
    let a = logged(s.issue(&issue(key(1), "alice", T)).unwrap());
    let b = logged(s.issue(&issue(key(2), "bob", T + 1)).unwrap());
    assert!(b > a, "log seqs increase");
    let row = s
        .identity(&key(1))
        .unwrap()
        .expect("created by the issuance");
    assert_eq!(row.created, T);
    assert!(!row.frozen && !row.revoked && row.rotated_to.is_none());
    assert_eq!(s.handle("alice").unwrap().unwrap().identity, key(1));
    assert!(s.handle("carol").unwrap().is_none());

    // A reissue replaces the handle row and appends to the log; it never
    // rewrites an entry.
    let mut again = issue(key(1), "alice", T + 10);
    again.handle.registered = T;
    again.first = false;
    let c = logged(s.issue(&again).unwrap());
    assert!(c > b);
    let h = s.handle("alice").unwrap().unwrap();
    assert_eq!((h.registered, h.expires), (T, T + 10 + YEAR));
    let log = s.log_page(0, usize::MAX).unwrap();
    assert_eq!(
        log.entries.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![a, b, c]
    );
    assert_eq!(log.entries[2].1, b"att:alice:1750000010");
    assert_eq!(s.log_page(b, usize::MAX).unwrap().entries.len(), 1);
    assert_eq!(s.handles_of(&key(1)).unwrap().len(), 1);
}

fn a_commitment_is_set_once(s: &dyn RegistrarStore) {
    let mut w = issue(key(1), "alice", T);
    w.commitment = Some([7; 32]);
    s.issue(&w).unwrap();
    assert_eq!(
        s.identity(&key(1)).unwrap().unwrap().commitment,
        Some([7; 32])
    );
    // An issuance never replaces one; neither does `set_commitment`.
    w.commitment = Some([8; 32]);
    w.issued = T + 1;
    s.issue(&w).unwrap();
    assert!(!s.set_commitment(&key(1), &[9; 32]).unwrap());
    assert_eq!(
        s.identity(&key(1)).unwrap().unwrap().commitment,
        Some([7; 32])
    );

    s.issue(&issue(key(2), "bob", T)).unwrap();
    assert!(s.set_commitment(&key(2), &[5; 32]).unwrap());
    assert_eq!(
        s.identity(&key(2)).unwrap().unwrap().commitment,
        Some([5; 32])
    );
    assert!(
        !s.set_commitment(&key(3), &[5; 32]).unwrap(),
        "no such identity"
    );
}

fn an_invite_is_spent_exactly_once(s: &dyn RegistrarStore) {
    assert_eq!(s.add_invites(&[[1; 32], [2; 32]]).unwrap(), 2);
    assert_eq!(s.add_invites(&[[2; 32], [3; 32]]).unwrap(), 1);
    assert!(s.invite_open(&[1; 32]).unwrap());
    assert!(!s.invite_open(&[9; 32]).unwrap());

    let mut w = issue(key(1), "alice", T);
    w.invite = Some([1; 32]);
    assert!(matches!(s.issue(&w).unwrap(), Issued::Logged(_)));
    assert!(!s.invite_open(&[1; 32]).unwrap());

    // The second spend writes nothing at all.
    let mut w = issue(key(2), "bob", T);
    w.invite = Some([1; 32]);
    assert_eq!(s.issue(&w).unwrap(), Issued::InviteSpent);
    assert!(s.handle("bob").unwrap().is_none());
    assert!(s.identity(&key(2)).unwrap().is_none());
    assert_eq!(s.log_page(0, usize::MAX).unwrap().entries.len(), 1);

    // An unknown invite is refused the same way, and re-adding a spent
    // one does not reopen it.
    w.invite = Some([9; 32]);
    assert_eq!(s.issue(&w).unwrap(), Issued::InviteSpent);
    assert_eq!(s.add_invites(&[[1; 32]]).unwrap(), 0);
    assert!(!s.invite_open(&[1; 32]).unwrap());
}

fn a_record_is_published_once_and_answers_with_its_seq(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    let r = record(RecordKind::Freeze, key(1), None, None, "a");
    let first = publish(s, vec![r.clone()], vec![Effect::SetFrozen(key(1), true)]);
    assert!(s.identity(&key(1)).unwrap().unwrap().frozen);
    assert_eq!(s.record_seq(&r.digest).unwrap(), Some(first[0]));

    let other = record(RecordKind::Freeze, key(1), None, None, "b");
    let again = publish(
        s,
        vec![r.clone(), other.clone()],
        vec![Effect::SetFrozen(key(1), false)],
    );
    assert_eq!(again[0], first[0], "a held record keeps its seq");
    assert!(again[1] > first[0]);
    assert!(!s.identity(&key(1)).unwrap().unwrap().frozen);
    assert_eq!(
        seqs(s, RecordFilter::Identity(key(1))),
        vec![first[0], again[1]]
    );
    assert_eq!(s.record_seq(&[0; 32]).unwrap(), None);

    publish(s, vec![], vec![Effect::Revoke(key(1))]);
    assert!(s.identity(&key(1)).unwrap().unwrap().revoked);
}

fn a_rotation_moves_every_handle_and_keeps_its_age(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    s.issue(&issue(key(1), "al", T + 5)).unwrap();
    s.issue(&issue(key(3), "carol", T)).unwrap();
    publish(
        s,
        vec![record(RecordKind::Rotate, key(1), Some(key(2)), None, "r")],
        vec![Effect::Rotate {
            from: key(1),
            to: key(2),
            at: T + 100,
        }],
    );
    assert_eq!(
        s.identity(&key(1)).unwrap().unwrap().rotated_to,
        Some(key(2))
    );
    let succ = s
        .identity(&key(2))
        .unwrap()
        .expect("the successor gets a row");
    assert_eq!(succ.created, T + 100);
    assert!(s.handles_of(&key(1)).unwrap().is_empty());
    let moved = s.handles_of(&key(2)).unwrap();
    assert_eq!(
        moved
            .iter()
            .map(|h| (h.name.as_str(), h.registered))
            .collect::<Vec<_>>(),
        vec![("al", T + 5), ("alice", T)]
    );
    assert_eq!(s.handle("carol").unwrap().unwrap().identity, key(3));
}

fn lapsing_keeps_the_earliest_time_and_bars_on_request(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    s.issue(&issue(key(1), "al", T)).unwrap();
    publish(
        s,
        vec![],
        vec![Effect::LapseHandle {
            name: "al".into(),
            at: T + 10,
            barred: true,
        }],
    );
    publish(
        s,
        vec![],
        vec![Effect::LapseHandles {
            identity: key(1),
            at: T + 20,
        }],
    );
    let al = s.handle("al").unwrap().unwrap();
    assert_eq!((al.lapsed_at, al.barred), (Some(T + 10), true));
    let alice = s.handle("alice").unwrap().unwrap();
    assert_eq!((alice.lapsed_at, alice.barred), (Some(T + 20), false));
}

fn a_per_identity_list_carries_both_sides_of_a_rotation(s: &dyn RegistrarStore) {
    let dev = record(RecordKind::RevokeDevice, key(1), None, Some(T), "d");
    let rot = record(RecordKind::Rotate, key(1), Some(key(2)), None, "r");
    let unrelated = record(RecordKind::RevokeIdentity, key(3), None, None, "i");
    let seq = publish(s, vec![dev, rot, unrelated], vec![]);
    assert_eq!(
        seqs(s, RecordFilter::Identity(key(1))),
        vec![seq[0], seq[1]]
    );
    assert_eq!(seqs(s, RecordFilter::Identity(key(2))), vec![seq[1]]);
    assert_eq!(seqs(s, RecordFilter::Identity(key(3))), vec![seq[2]]);
    assert!(seqs(s, RecordFilter::Identity(key(4))).is_empty());
    // A per-identity list never prunes, however old the entry.
    let page = s
        .records_page(RecordFilter::Identity(key(1)), seq[0], usize::MAX)
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert!(!page.more);
}

fn the_full_list_prunes_what_has_stopped_mattering(s: &dyn RegistrarStore) {
    let seq = publish(
        s,
        vec![
            record(
                RecordKind::RevokeDevice,
                key(1),
                None,
                Some(T),
                "old device",
            ),
            record(
                RecordKind::RevokeDevice,
                key(1),
                None,
                Some(T + 100),
                "live device",
            ),
            record(
                RecordKind::RevokeAttestation,
                key(1),
                None,
                Some(T),
                "old attestation",
            ),
            record(
                RecordKind::RevokeAttestation,
                key(1),
                None,
                Some(T + 100),
                "live attestation",
            ),
            record(RecordKind::Rotate, key(1), Some(key(2)), None, "r"),
            record(RecordKind::Freeze, key(3), None, None, "f"),
            record(RecordKind::RevokeIdentity, key(4), None, None, "i"),
        ],
        vec![],
    );
    let all = |now| {
        seqs(
            s,
            RecordFilter::All {
                now,
                device_cap: 256,
            },
        )
    };
    // At `until` itself a record still matters; after, it does not.
    assert_eq!(all(T), seq);
    assert_eq!(all(T + 1), vec![seq[1], seq[3], seq[4], seq[5], seq[6]]);
    assert_eq!(all(T + 1_000_000), vec![seq[4], seq[5], seq[6]]);
    // `since` pages the pruned list like any other.
    let page = s
        .records_page(
            RecordFilter::All {
                now: T + 1,
                device_cap: 256,
            },
            seq[3],
            usize::MAX,
        )
        .unwrap();
    assert_eq!(
        page.entries.iter().map(|e| e.0).collect::<Vec<_>>(),
        vec![seq[4], seq[5], seq[6]]
    );
}

fn the_full_list_keeps_a_bounded_number_of_device_revocations(s: &dyn RegistrarStore) {
    // Five for one identity with distinct `until`s, one for another.
    let mut records: Vec<NewRecord> = [30, 10, 50, 20, 40]
        .iter()
        .map(|u| {
            record(
                RecordKind::RevokeDevice,
                key(1),
                None,
                Some(T + u),
                &u.to_string(),
            )
        })
        .collect();
    records.push(record(
        RecordKind::RevokeDevice,
        key(2),
        None,
        Some(T + 1),
        "x",
    ));
    let seq = publish(s, records, vec![]);
    let kept = seqs(
        s,
        RecordFilter::All {
            now: T,
            device_cap: 3,
        },
    );
    // The latest three by `until` (50, 40, 30), in seq order, and the
    // other identity's one, which its own cap covers.
    assert_eq!(kept, vec![seq[0], seq[2], seq[4], seq[5]]);
    // The per-identity list keeps all of them.
    assert_eq!(seqs(s, RecordFilter::Identity(key(1))).len(), 5);
}

fn pages_are_cut_by_budget_and_always_make_progress(s: &dyn RegistrarStore) {
    let records: Vec<NewRecord> = (0..5)
        .map(|i| {
            record(
                RecordKind::RevokeIdentity,
                key(1),
                None,
                None,
                &format!("{i:04}"),
            )
        })
        .collect();
    let one = crate::store::entry_cost(&records[0].bytes);
    let seq = publish(s, records, vec![]);
    let filter = RecordFilter::Identity(key(1));

    let page = s.records_page(filter, 0, one * 2).unwrap();
    assert_eq!(
        page.entries.iter().map(|e| e.0).collect::<Vec<_>>(),
        seq[..2]
    );
    assert!(page.more);
    let page = s.records_page(filter, seq[1], one * 2 + one - 1).unwrap();
    assert_eq!(
        page.entries.iter().map(|e| e.0).collect::<Vec<_>>(),
        seq[2..4]
    );
    assert!(page.more);
    let page = s.records_page(filter, seq[3], one * 2).unwrap();
    assert_eq!(
        page.entries.iter().map(|e| e.0).collect::<Vec<_>>(),
        seq[4..]
    );
    assert!(!page.more);

    // A budget smaller than one entry still yields that entry.
    let page = s.records_page(filter, 0, 1).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert!(page.more);

    // The log is cut the same way.
    for i in 0..3 {
        s.issue(&issue(key(1), "alice", T + i)).unwrap();
    }
    let cost = crate::store::entry_cost(b"att:alice:1750000000");
    let page = s.log_page(0, cost * 2).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert!(page.more);
    assert!(s
        .records_page(filter, seq[4], 1)
        .unwrap()
        .entries
        .is_empty());
}

fn pending_rotations_come_due_in_order(s: &dyn RegistrarStore) {
    let p = |id: u8, at: u64| Pending {
        identity: key(id),
        successor: key(id + 100),
        publish_at: at,
        digest: [id; 32],
        bytes: vec![id],
    };
    publish(
        s,
        vec![],
        vec![
            Effect::SetPending(p(1, T + 50)),
            Effect::SetPending(p(2, T + 10)),
            Effect::SetPending(p(3, T + 90)),
        ],
    );
    assert_eq!(s.pending(&key(1)).unwrap(), Some(p(1, T + 50)));
    assert!(s.pending_due(T).unwrap().is_empty());
    assert_eq!(
        s.pending_due(T + 50).unwrap(),
        vec![p(2, T + 10), p(1, T + 50)]
    );
    publish(s, vec![], vec![Effect::DropPending(key(2))]);
    assert_eq!(
        s.pending_due(T + 100).unwrap(),
        vec![p(1, T + 50), p(3, T + 90)]
    );
    assert!(s.pending(&key(2)).unwrap().is_none());
}

fn a_recovery_is_redeemed_by_the_issuance_it_grants(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    let grant = Recovery {
        handle: "alice".into(),
        fingerprint: fp(&key(2)),
        keep_age: true,
        granted: T + 5,
    };
    publish(s, vec![], vec![Effect::GrantRecovery(grant.clone())]);
    assert_eq!(s.recovery("alice").unwrap(), Some(grant));
    assert!(s.recovery("bob").unwrap().is_none());

    let mut w = issue(key(2), "alice", T + 10);
    w.handle.registered = T;
    w.first = false;
    w.recovery = Some("alice".into());
    s.issue(&w).unwrap();
    assert!(s.recovery("alice").unwrap().is_none());
    assert_eq!(s.handle("alice").unwrap().unwrap().identity, key(2));
    assert!(s.handles_of(&key(1)).unwrap().is_empty());
}

fn attestation_expiry_is_bounded_by_issue_time(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    s.issue(&issue(key(1), "alice", T + 100)).unwrap();
    s.issue(&issue(key(1), "al", T + 200)).unwrap();
    assert_eq!(
        s.attestations_expire(&key(1), "alice", T + 50).unwrap(),
        Some(T + YEAR)
    );
    assert_eq!(
        s.attestations_expire(&key(1), "alice", T + 100).unwrap(),
        Some(T + 100 + YEAR)
    );
    assert_eq!(
        s.attestations_expire(&key(1), "alice", T - 1).unwrap(),
        None
    );
    assert_eq!(
        s.attestations_expire(&key(2), "alice", T + 100).unwrap(),
        None
    );
}

fn counts_are_what_the_stats_say(s: &dyn RegistrarStore) {
    let empty = s.counts(T).unwrap();
    assert_eq!(empty, Default::default());

    s.issue(&issue(key(1), "alice", T - 8 * 86_400)).unwrap();
    s.issue(&issue(key(2), "bob", T - 2 * 86_400)).unwrap();
    s.issue(&issue(key(3), "carol", T - 3600)).unwrap();
    let mut reissue = issue(key(3), "carol", T - 60);
    reissue.first = false;
    let last = logged(s.issue(&reissue).unwrap());
    // Lapsed handles hold nobody.
    let mut gone = issue(key(4), "dave", T - 2 * YEAR);
    gone.handle.expires = T - YEAR;
    s.issue(&gone).unwrap();
    publish(
        s,
        vec![
            record(RecordKind::RevokeAttestation, key(2), None, None, "a"),
            record(RecordKind::RevokeAttestation, key(2), None, None, "b"),
            record(RecordKind::Freeze, key(2), None, None, "f"),
        ],
        vec![
            Effect::SetFrozen(key(2), true),
            Effect::LapseHandle {
                name: "bob".into(),
                at: T - 10,
                barred: false,
            },
        ],
    );
    let c = s.counts(T).unwrap();
    assert_eq!(c.identities, 2, "alice and carol hold a handle");
    assert_eq!(c.issued_24h, 1);
    assert_eq!(c.issued_7d, 2);
    assert_eq!(c.issued_total, 4, "first registrations only");
    assert_eq!(c.revoked_total, 2);
    assert_eq!(c.frozen, 1);
    assert_eq!(c.log_seq, last + 1);
}

fn identities_are_found_by_fingerprint(s: &dyn RegistrarStore) {
    s.issue(&issue(key(1), "alice", T)).unwrap();
    assert_eq!(
        s.identity_by_fingerprint(&fp(&key(1)))
            .unwrap()
            .map(|r| r.key),
        Some(key(1))
    );
    assert!(s.identity_by_fingerprint(&fp(&key(2))).unwrap().is_none());
    assert!(s.identity_by_fingerprint(&key(1)).unwrap().is_none());
}
