//! What every [`ModerationStore`] must do, run against each of them —
//! the in-memory one here, the SQLite one in its own crate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    Act, ActKind, Closed, ModerationStore, Outcome, Report, ReportFilter, ReportTarget, Subject,
};
use crate::inbox::Mailbox;

pub fn run(new_store: &dyn Fn() -> Box<dyn ModerationStore>) {
    acts_round_trip_and_page_newest_first(&*new_store());
    evidence_is_scrubbed_and_the_row_stays(&*new_store());
    reports_round_trip_and_filter(&*new_store());
    open_reports_are_found_by_what_they_name(&*new_store());
    a_report_closes_once(&*new_store());
    closed_reports_age_out_and_ids_are_never_reused(&*new_store());
    blocks_are_a_set(&*new_store());
    a_reports_image_is_held_while_it_is_open(&*new_store());
    a_close_keeps_its_outcome_through_the_scrub(&*new_store());
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn act(kind: ActKind, at: u64) -> Act {
    Act {
        id: 0,
        kind,
        actor: "carol".into(),
        actor_fp: Some([3; 32]),
        line: Some(17),
        media: Some([9; 16]),
        article: Some(51),
        report: Some(4),
        login: Some("bob".into()),
        fingerprint: Some([2; 32]),
        reason: "spam".into(),
        evidence: Some("#17 Bob: buy now".into()),
        media_hash: Some([8; 32]),
        at: t(at),
    }
}

fn report(target: ReportTarget, at: u64) -> Report {
    Report {
        id: 0,
        at: t(at),
        reporter: Some(Mailbox::identified("alice", [1; 32])),
        target,
        about: Subject {
            login: Some("bob".into()),
            fingerprint: None,
            nick: "Bob".into(),
        },
        reason: "rude".into(),
        evidence: Some("the body".into()),
        verified: false,
        media: match target {
            ReportTarget::Media(h) => Some(h),
            _ => None,
        },
        closed: None,
    }
}

fn closed(outcome: Outcome, at: u64) -> Closed {
    Closed {
        at: t(at),
        by: "carol".into(),
        outcome,
        note: Some("seen".into()),
        duplicate_of: (outcome == Outcome::Duplicate).then_some(1),
    }
}

fn acts_round_trip_and_page_newest_first(s: &dyn ModerationStore) {
    let first = s.record(&act(ActKind::Redact, 100)).unwrap();
    let second = s.record(&act(ActKind::Purge, 200)).unwrap();
    let third = s.record(&act(ActKind::NewsDelete, 300)).unwrap();
    assert!(first < second && second < third);
    let all = s.acts(None, 10).unwrap();
    assert_eq!(
        all.iter().map(|a| a.id).collect::<Vec<_>>(),
        [third, second, first]
    );
    assert_eq!(
        all[2],
        Act {
            id: first,
            ..act(ActKind::Redact, 100)
        },
        "every field comes back as it went in"
    );
    let older = s.acts(Some(third), 1).unwrap();
    assert_eq!(older.len(), 1);
    assert_eq!(older[0].id, second);
    assert_eq!(older[0].kind, ActKind::Purge);
    // An act about nobody in particular round-trips its absences.
    let bare = Act {
        actor_fp: None,
        line: None,
        media: None,
        article: None,
        report: None,
        login: None,
        fingerprint: None,
        evidence: None,
        media_hash: None,
        ..act(ActKind::Close, 400)
    };
    let id = s.record(&bare).unwrap();
    assert_eq!(s.acts(None, 1).unwrap()[0], Act { id, ..bare });
}

fn evidence_is_scrubbed_and_the_row_stays(s: &dyn ModerationStore) {
    s.record(&act(ActKind::Redact, 100)).unwrap();
    s.record(&act(ActKind::Redact, 300)).unwrap();
    assert_eq!(s.scrub_evidence(t(200)).unwrap(), 1);
    // A second pass finds nothing left to scrub.
    assert_eq!(s.scrub_evidence(t(200)).unwrap(), 0);
    let all = s.acts(None, 10).unwrap();
    assert_eq!(all.len(), 2, "the rows stay");
    assert_eq!(all[1].evidence.as_deref(), Some(""));
    assert_eq!(all[1].reason, "spam", "and so does why");
    assert_eq!(all[0].evidence.as_deref(), Some("#17 Bob: buy now"));
}

fn reports_round_trip_and_filter(s: &dyn ModerationStore) {
    let line = s.file(&report(ReportTarget::Line(17), 100)).unwrap();
    let media = s.file(&report(ReportTarget::Media([9; 16]), 110)).unwrap();
    let msg = s.file(&report(ReportTarget::Msg(5), 120)).unwrap();
    let user = s
        .file(&Report {
            reporter: None,
            about: Subject {
                login: None,
                fingerprint: Some([2; 32]),
                nick: String::new(),
            },
            evidence: None,
            verified: true,
            ..report(ReportTarget::User, 130)
        })
        .unwrap();
    let gone = s
        .file(&Report {
            closed: Some(Closed {
                note: None,
                ..closed(Outcome::Removed, 140)
            }),
            ..report(ReportTarget::Article(51), 140)
        })
        .unwrap();
    assert_eq!(
        s.report(line).unwrap().unwrap(),
        Report {
            id: line,
            ..report(ReportTarget::Line(17), 100)
        }
    );
    assert_eq!(
        s.report(media).unwrap().unwrap().target,
        ReportTarget::Media([9; 16])
    );
    assert_eq!(s.report(msg).unwrap().unwrap().target, ReportTarget::Msg(5));
    let u = s.report(user).unwrap().unwrap();
    assert_eq!(u.reporter, None);
    assert_eq!(u.about.fingerprint, Some([2; 32]));
    assert_eq!(u.about.login, None);
    assert!(u.verified);
    let g = s.report(gone).unwrap().unwrap();
    assert_eq!(g.target, ReportTarget::Article(51));
    assert_eq!(g.closed.unwrap().outcome, Outcome::Removed);
    assert!(s.report(gone + 100).unwrap().is_none());

    let ids = |f, before, limit| {
        s.reports(f, before, limit)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(ReportFilter::Open, None, 10), [user, msg, media, line]);
    assert_eq!(ids(ReportFilter::Closed, None, 10), [gone]);
    assert_eq!(
        ids(ReportFilter::All, None, 10),
        [gone, user, msg, media, line]
    );
    assert_eq!(ids(ReportFilter::Open, Some(msg), 1), [media]);
    assert_eq!(s.open_count().unwrap(), 4);
}

fn open_reports_are_found_by_what_they_name(s: &dyn ModerationStore) {
    let a = s.file(&report(ReportTarget::Line(17), 100)).unwrap();
    let b = s.file(&report(ReportTarget::Line(17), 110)).unwrap();
    s.file(&report(ReportTarget::Line(18), 120)).unwrap();
    let u1 = s.file(&report(ReportTarget::User, 130)).unwrap();
    let u2 = s
        .file(&Report {
            about: Subject {
                login: Some("dave".into()),
                fingerprint: None,
                nick: "Dave".into(),
            },
            ..report(ReportTarget::User, 140)
        })
        .unwrap();
    let on = |target| {
        s.open_on(&target)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(on(ReportTarget::Line(17)), [a, b], "oldest first");
    assert_eq!(on(ReportTarget::User), [u1, u2], "every person's");
    assert!(on(ReportTarget::Media([1; 16])).is_empty());
    assert!(s.close(a, &closed(Outcome::Dismissed, 200)).unwrap());
    assert_eq!(on(ReportTarget::Line(17)), [b], "and only while open");
}

fn a_report_closes_once(s: &dyn ModerationStore) {
    let id = s.file(&report(ReportTarget::Line(17), 100)).unwrap();
    let dup = closed(Outcome::Duplicate, 200);
    assert!(s.close(id, &dup).unwrap());
    assert!(
        !s.close(id, &closed(Outcome::Dismissed, 300)).unwrap(),
        "a closed report stays as it was closed"
    );
    assert_eq!(s.report(id).unwrap().unwrap().closed, Some(dup));
    assert!(!s.close(id + 1, &closed(Outcome::Dismissed, 300)).unwrap());
    assert_eq!(s.open_count().unwrap(), 0);
}

fn closed_reports_age_out_and_ids_are_never_reused(s: &dyn ModerationStore) {
    let old = s.file(&report(ReportTarget::Line(1), 100)).unwrap();
    let open = s.file(&report(ReportTarget::Line(2), 100)).unwrap();
    let recent = s.file(&report(ReportTarget::Line(3), 100)).unwrap();
    s.close(old, &closed(Outcome::Dismissed, 150)).unwrap();
    s.close(recent, &closed(Outcome::Dismissed, 250)).unwrap();
    assert_eq!(s.prune_reports(t(200)).unwrap(), 1);
    assert!(s.report(old).unwrap().is_none());
    assert!(
        s.report(open).unwrap().is_some(),
        "an open report is never aged out"
    );
    assert!(s.report(recent).unwrap().is_some());
    s.close(recent, &closed(Outcome::Dismissed, 250)).unwrap();
    assert_eq!(s.prune_reports(t(300)).unwrap(), 1);
    // The newest report is gone, and "#3" still names it forever.
    let next = s.file(&report(ReportTarget::Line(4), 400)).unwrap();
    assert!(next > recent, "{next} reuses an id");
}

fn a_reports_image_is_held_while_it_is_open(s: &dyn ModerationStore) {
    // A line that carried an image holds it, as an image report does.
    let line = s
        .file(&Report {
            media: Some([7; 16]),
            ..report(ReportTarget::Line(3), 100)
        })
        .unwrap();
    assert_eq!(s.report(line).unwrap().unwrap().media, Some([7; 16]));
    assert!(s.holds_media(&[7; 16]).unwrap());
    assert!(!s.holds_media(&[8; 16]).unwrap());
    let image = s.file(&report(ReportTarget::Media([7; 16]), 110)).unwrap();
    s.close(line, &closed(Outcome::Dismissed, 200)).unwrap();
    assert!(
        s.holds_media(&[7; 16]).unwrap(),
        "another open report still holds it"
    );
    s.close(image, &closed(Outcome::Dismissed, 210)).unwrap();
    assert!(!s.holds_media(&[7; 16]).unwrap());
}

fn a_close_keeps_its_outcome_through_the_scrub(s: &dyn ModerationStore) {
    s.record(&Act {
        evidence: Some("dismissed".into()),
        ..act(ActKind::Close, 100)
    })
    .unwrap();
    s.record(&act(ActKind::NodeDelete, 100)).unwrap();
    assert_eq!(s.scrub_evidence(t(200)).unwrap(), 1);
    let all = s.acts(None, 10).unwrap();
    assert_eq!(all[1].evidence.as_deref(), Some("dismissed"));
    assert_eq!(all[0].evidence.as_deref(), Some(""));
}

fn blocks_are_a_set(s: &dyn ModerationStore) {
    assert!(s.blocked_hashes().unwrap().is_empty());
    s.block_hash(&[1; 32], "carol", t(100)).unwrap();
    s.block_hash(&[2; 32], "cli", t(110)).unwrap();
    s.block_hash(&[1; 32], "dave", t(120)).unwrap();
    let mut blocked = s.blocked_hashes().unwrap();
    blocked.sort();
    assert_eq!(blocked, [[1; 32], [2; 32]]);
}

#[cfg(test)]
#[test]
fn memory_moderation_passes() {
    run(&|| Box::<super::MemoryModeration>::default());
}
