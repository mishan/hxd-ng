//! Domain-side moderation: who may act, whom on, what each act leaves
//! behind, and where reports go.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedReceiver;

use super::*;
use crate::access::{bit, AccessBits};
use crate::account::AccountDirectory;
use crate::history::{ChatLog, HistoryPolicy, MemoryLog};
use crate::inbox::MemoryStore;
use crate::media::{
    Canonical, MediaCodec, MediaConfig, MediaReject, MediaType, UploadOutcome, UploadPart,
};
use crate::news::{BodyType, MemoryNews, NewsPolicy, NodeKind, PostRequest};
use crate::roster::InboxPolicy;
use crate::roster::{drain, AttachInfo, SeqEvent, Transport};

/// Accounts nobody is logged into: login → (identity, access).
#[derive(Default)]
struct Directory(HashMap<String, (Option<[u8; 32]>, AccessBits)>);

impl AccountDirectory for Directory {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        self.0.get(login).map(|(fp, _)| Mailbox {
            login: login.into(),
            fingerprint: *fp,
        })
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
        self.0
            .iter()
            .find(|(login, (fp, _))| who.matches(login, fp.as_ref()))
            .map(|(_, (_, access))| *access)
    }
}

/// Decodes nothing; its canonical bytes are the input reversed.
struct FakeCodec;

impl MediaCodec for FakeCodec {
    fn canonicalize(&self, input: &[u8]) -> Result<Canonical, MediaReject> {
        Ok(Canonical {
            mime: MediaType::Png,
            width: 8,
            height: 4,
            bytes: input.iter().rev().copied().collect(),
        })
    }
}

struct Server {
    core: Core,
    log: Arc<MemoryLog>,
    store: Arc<MemoryModeration>,
}

fn server_with(directory: Directory) -> Server {
    server_full(Arc::new(directory), Duration::from_secs(24 * 3600))
}

fn server_full(directory: Arc<dyn AccountDirectory>, handle_ttl: Duration) -> Server {
    let log = Arc::new(MemoryLog::default());
    let store = Arc::new(MemoryModeration::default());
    let core = Core::new()
        .with_history(log.clone(), HistoryPolicy::default())
        .with_inbox(
            Arc::new(MemoryStore::default()),
            directory,
            InboxPolicy::default(),
        )
        .with_news(Arc::new(MemoryNews::default()), NewsPolicy::default())
        .with_media(
            Arc::new(FakeCodec),
            MediaConfig {
                upload_interval: Duration::ZERO,
                handle_ttl,
                ..Default::default()
            },
        )
        .with_moderation(store.clone(), ModerationPolicy::default());
    Server { core, log, store }
}

fn server() -> Server {
    server_with(Directory::default())
}

fn member_access() -> AccessBits {
    AccessBits::empty()
        .with(bit::READ_CHAT)
        .with(bit::SEND_CHAT)
        .with(bit::SEND_MSGS)
        .with(bit::SEND_MEDIA)
        .with(bit::READ_NEWS)
        .with(bit::POST_NEWS)
}

struct Who {
    login: &'static str,
    access: AccessBits,
    moderate: bool,
    identity: Option<[u8; 32]>,
    person: bool,
    addr: Option<std::net::IpAddr>,
}

fn person(login: &'static str) -> Who {
    Who {
        login,
        access: member_access(),
        moderate: false,
        identity: None,
        person: true,
        addr: None,
    }
}

fn moderator(login: &'static str) -> Who {
    Who {
        access: member_access().with(bit::DISCONNECT_USERS),
        moderate: true,
        ..person(login)
    }
}

fn guest() -> Who {
    Who {
        person: false,
        ..person("guest")
    }
}

fn attach(core: &Core, who: Who) -> (Uid, UnboundedReceiver<SeqEvent>) {
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: who.login.to_uppercase(),
            icon: 1,
            admin: who.moderate,
            access: who.access,
            login: who.login.into(),
            addr: who.addr,
            can_detach: false,
            transport: Transport {
                inline_media: true,
                ..Default::default()
            },
            has_inbox: who.person,
            attach_news: false,
            moderate: who.moderate,
            is_person: who.person,
            reads_on_delivery: false,
            identity: who.identity,
            system: false,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn say(core: &Core, uid: Uid, text: &str) -> LineId {
    core.chat_public(uid, text.into(), 0, None)
        .unwrap()
        .expect("a logged line")
}

fn upload(core: &Core, uid: Uid, bytes: &[u8]) -> Handle {
    match core
        .media_upload_part(
            uid,
            UploadPart {
                payload: bytes,
                declared: None,
                token: None,
                index: 0,
                count: None,
                last: true,
            },
        )
        .unwrap()
    {
        UploadOutcome::Done(m) => m.id.unwrap(),
        UploadOutcome::Token(_) => panic!("single-shot upload answered with a token"),
    }
}

fn redactions(events: Vec<Event>) -> Vec<LineId> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::ChatRedacted { id } => Some(id),
            _ => None,
        })
        .collect()
}

fn reports_in(events: Vec<Event>) -> Vec<Report> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::Report(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn closes_in(events: Vec<Event>) -> Vec<(ReportId, Outcome, bool)> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::ReportClosed { id, outcome, yours } => Some((id, outcome, yours)),
            _ => None,
        })
        .collect()
}

#[test]
fn only_a_moderator_acts_and_every_act_needs_a_reason() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let line = say(&s.core, bob, "hello");
    assert_eq!(
        s.core.redact_line(Actor::Session(bob), line, "mine"),
        Err(ModError::AccessDenied),
        "the kick bit is not enough without `moderate`, and nothing is without either"
    );
    assert_eq!(
        s.core.redact_line(Actor::Session(carol), line, "   "),
        Err(ModError::BadRequest("A reason is required."))
    );
    assert_eq!(
        s.core
            .redact_line(Actor::Session(carol), line, &"x".repeat(MAX_ACT_REASON + 1)),
        Err(ModError::BadRequest("That reason is too long."))
    );
    assert!(
        s.store.acts(None, 10).unwrap().is_empty(),
        "nothing refused left a row"
    );
    assert_eq!(
        s.core.moderation_log(Actor::Session(bob), None, 10),
        Err(ModError::AccessDenied)
    );
}

#[test]
fn a_redacted_line_keeps_its_id_and_loses_its_words_everywhere() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let (_dave, mut dave_rx) = attach(&s.core, person("dave"));
    let (_mute, mut mute_rx) = attach(
        &s.core,
        Who {
            access: AccessBits::empty(),
            ..person("mute")
        },
    );
    let line = say(&s.core, bob, "a slur");
    drain(&mut dave_rx);
    s.core
        .redact_line(Actor::Session(carol), line, "slur")
        .unwrap();

    let stored = s.log.line(line).unwrap().unwrap();
    assert!(stored.flags.contains(LineFlags::DELETED));
    assert!(stored.text.is_empty() && stored.from_nick.is_empty());
    assert_eq!(redactions(drain(&mut dave_rx)), [line], "a reader is told");
    assert!(
        redactions(drain(&mut mute_rx)).is_empty(),
        "someone who never reads chat is not"
    );

    let (acts, more) = s
        .core
        .moderation_log(Actor::Session(carol), None, 10)
        .unwrap();
    assert!(!more);
    assert_eq!(acts.len(), 1);
    let act = &acts[0];
    assert_eq!(act.kind, ActKind::Redact);
    assert_eq!(act.actor, "carol");
    assert_eq!(act.line, Some(line));
    assert_eq!(act.login.as_deref(), Some("bob"));
    assert_eq!(act.reason, "slur");
    assert_eq!(
        act.evidence.as_deref(),
        Some(format!("#{line} BOB: a slur").as_str()),
        "the words live on in the audit row, for moderators only"
    );

    // Redacting it again is not an error, and not a second row.
    s.core
        .redact_line(Actor::Session(carol), line, "again")
        .unwrap();
    assert_eq!(s.store.acts(None, 10).unwrap().len(), 1);
    assert_eq!(
        s.core.redact_line(Actor::Session(carol), 999, "nothing"),
        Err(ModError::NoSuchLine)
    );
}

#[test]
fn the_kick_ladder_protects_the_unkickable_on_the_roster_and_off_it() {
    let mut directory = Directory::default();
    directory.0.insert(
        "admin".into(),
        (None, member_access().with(bit::CANT_BE_DISCONNECTED)),
    );
    let s = server_with(directory);
    let (admin, _) = attach(
        &s.core,
        Who {
            access: member_access().with(bit::CANT_BE_DISCONNECTED),
            ..person("admin")
        },
    );
    let (carol, _) = attach(&s.core, moderator("carol"));
    let (root, _) = attach(
        &s.core,
        Who {
            access: member_access()
                .with(bit::DISCONNECT_USERS)
                .with(bit::DELETE_USERS),
            ..moderator("root")
        },
    );
    let line = say(&s.core, admin, "above the law");
    assert_eq!(
        s.core.redact_line(Actor::Session(carol), line, "no"),
        Err(ModError::Protected)
    );
    // Gone from the roster, still protected: the account says so.
    s.core.end_session(admin);
    assert_eq!(
        s.core.redact_line(Actor::Session(carol), line, "no"),
        Err(ModError::Protected)
    );
    assert_eq!(
        s.core.purge_sender(
            Actor::Session(carol),
            &PersonRef::Login("admin".into()),
            Duration::from_secs(3600),
            "no"
        ),
        Err(ModError::Protected)
    );
    // Delete-users is the rung above, and the operator is above both.
    s.core
        .redact_line(Actor::Session(root), line, "yes")
        .unwrap();
    let (again, _) = attach(
        &s.core,
        Who {
            access: member_access().with(bit::CANT_BE_DISCONNECTED),
            ..person("admin")
        },
    );
    let other = say(&s.core, again, "still");
    s.core
        .redact_line(Actor::Operator, other, "operator")
        .unwrap();
    assert_eq!(s.store.acts(None, 1).unwrap()[0].actor, OPERATOR);
}

#[test]
fn a_revoked_image_is_gone_at_once_and_cannot_come_back() {
    let s = server();
    let (bob, mut bob_rx) = attach(&s.core, person("bob"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let handle = upload(&s.core, bob, b"picture");
    drain(&mut bob_rx);
    s.core
        .revoke_media(Actor::Session(carol), &handle, "gore", true)
        .unwrap();
    assert!(s.core.media_fetch(bob, &handle).is_none());
    assert!(
        drain(&mut bob_rx).contains(&Event::MediaRevoked { id: handle }),
        "whoever might have it on screen is told"
    );
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!(act.kind, ActKind::Revoke);
    assert_eq!(act.media, Some(handle));
    assert_eq!(act.login.as_deref(), Some("bob"));
    let hash = act.media_hash.expect("the hash is recorded");
    assert_eq!(s.store.blocked_hashes().unwrap(), [hash], "and remembered");
    assert!(s.core.media_hash_blocked(&hash));
    assert!(
        s.core
            .media_upload_part(
                bob,
                UploadPart {
                    payload: b"picture",
                    declared: None,
                    token: None,
                    index: 0,
                    count: None,
                    last: true,
                },
            )
            .is_err(),
        "the same file does not come back"
    );
    assert_eq!(
        s.core
            .revoke_media(Actor::Session(carol), &[0; 16], "nothing", true),
        Err(ModError::NoSuchMedia)
    );
}

#[test]
fn a_restarted_server_remembers_what_was_blocked() {
    let store = Arc::new(MemoryModeration::default());
    store
        .block_hash(&[5; 32], "carol", SystemTime::now())
        .unwrap();
    let core = Core::new()
        .with_media(Arc::new(FakeCodec), MediaConfig::default())
        .with_moderation(store, ModerationPolicy::default());
    assert!(core.media_hash_blocked(&[5; 32]));
}

#[test]
fn a_redacted_line_takes_its_image_with_it() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let handle = upload(&s.core, bob, b"photo");
    let line = s
        .core
        .chat_public(bob, "look".into(), 0, Some(handle))
        .unwrap()
        .unwrap();
    s.core
        .redact_line(Actor::Session(carol), line, "no")
        .unwrap();
    assert!(s.core.media_fetch(bob, &handle).is_none());
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!(act.media, Some(handle), "one act, one row");
    assert!(act.media_hash.is_some());
}

#[test]
fn a_purge_takes_a_persons_window_across_every_store_and_nothing_else() {
    let s = server();
    let (bob, _) = attach(
        &s.core,
        Who {
            identity: Some([2; 32]),
            ..person("bob")
        },
    );
    let (dave, _) = attach(&s.core, person("dave"));
    let (carol, mut carol_rx) = attach(
        &s.core,
        Who {
            access: moderator("carol").access.with(bit::CREATE_CATEGORIES),
            ..moderator("carol")
        },
    );
    let cat = s
        .core
        .news_node_create(carol, None, NodeKind::Category, "General")
        .unwrap()
        .id;
    let post = |uid, body: &str| {
        s.core
            .news_post(
                uid,
                PostRequest {
                    category: cat,
                    parent: None,
                    subject: "s".into(),
                    body: body.into(),
                    mime: BodyType::Plain,
                    attachments: Vec::new(),
                },
            )
            .unwrap()
    };
    let bob_lines = [say(&s.core, bob, "spam 1"), say(&s.core, bob, "spam 2")];
    let dave_line = say(&s.core, dave, "innocent");
    let bob_image = upload(&s.core, bob, b"spam image");
    let dave_image = upload(&s.core, dave, b"cat");
    let bob_article = post(bob, "spam article");
    let dave_article = post(dave, "real article");
    // A report on bob, which the purge answers.
    let filed = s
        .core
        .report(
            dave,
            ReportRequest::User(PersonRef::Uid(bob)),
            "spammer",
            None,
        )
        .unwrap();
    drain(&mut carol_rx);

    // By the uid: the purge finds the identity behind it.
    let preview = s
        .core
        .purge_preview(&PersonRef::Uid(bob), Duration::from_secs(3600))
        .unwrap();
    let purged = s
        .core
        .purge_sender(
            Actor::Session(carol),
            &PersonRef::Uid(bob),
            Duration::from_secs(3600),
            "spam run",
        )
        .unwrap();
    assert_eq!(purged, preview, "the preview is the selection");
    assert_eq!(purged.lines, bob_lines);
    assert_eq!(purged.media, [bob_image]);
    assert_eq!(purged.articles, [bob_article]);

    for id in bob_lines {
        assert!(s
            .log
            .line(id)
            .unwrap()
            .unwrap()
            .flags
            .contains(LineFlags::DELETED));
    }
    assert!(!s
        .log
        .line(dave_line)
        .unwrap()
        .unwrap()
        .flags
        .contains(LineFlags::DELETED));
    assert!(s.core.media_fetch(bob, &bob_image).is_none());
    assert!(s.core.media_fetch(dave, &dave_image).is_some());
    assert!(s.core.news_article(carol, bob_article).unwrap().deleted);
    assert!(!s.core.news_article(carol, dave_article).unwrap().deleted);

    let events = drain(&mut carol_rx);
    assert_eq!(redactions(events.clone()), bob_lines);
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::NewsDeleted { id, .. } if *id == bob_article)));
    assert_eq!(
        closes_in(events),
        [(filed.id, Outcome::Removed, false)],
        "the report on the person is answered by the purge"
    );

    let acts = s.store.acts(None, 10).unwrap();
    assert_eq!(acts.len(), 1, "one row records the lot");
    assert_eq!(acts[0].kind, ActKind::Purge);
    assert_eq!(acts[0].fingerprint, Some([2; 32]));
    let evidence = acts[0].evidence.as_deref().unwrap();
    assert!(evidence.contains("spam 1") && evidence.contains("spam 2"));
    assert!(evidence.contains(&format!("#{bob_article}")));
}

#[test]
fn a_guest_has_nothing_to_purge_by() {
    let s = server();
    let (g, _) = attach(&s.core, guest());
    let (carol, _) = attach(&s.core, moderator("carol"));
    assert_eq!(
        s.core.purge_sender(
            Actor::Session(carol),
            &PersonRef::Uid(g),
            Duration::from_secs(60),
            "x"
        ),
        Err(ModError::NoIdentity),
        "said distinctly, so a kick with a purge can still kick"
    );
    assert_eq!(
        s.core.purge_sender(
            Actor::Session(carol),
            &PersonRef::Login("guest".into()),
            Duration::from_secs(60),
            "x"
        ),
        Err(ModError::NoSuchUser)
    );
}

#[test]
fn a_report_reaches_every_moderator_at_once_and_nobody_else() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, mut alice_rx) = attach(&s.core, person("alice"));
    let (_carol, mut carol_rx) = attach(&s.core, moderator("carol"));
    let (_erin, mut erin_rx) = attach(&s.core, moderator("erin"));
    let line = say(&s.core, bob, "rude");
    drain(&mut alice_rx);
    drain(&mut carol_rx);
    drain(&mut erin_rx);

    let filed = s
        .core
        .report(alice, ReportRequest::Line(line), "rude", None)
        .unwrap();
    assert_eq!(filed.outcome, None);
    assert!(filed.follow_up);
    for rx in [&mut carol_rx, &mut erin_rx] {
        let got = reports_in(drain(rx));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, filed.id);
        assert_eq!(got[0].target, ReportTarget::Line(line));
        assert_eq!(got[0].about.login.as_deref(), Some("bob"));
        assert_eq!(got[0].reporter.as_ref().unwrap().login, "alice");
    }
    assert!(reports_in(drain(&mut alice_rx)).is_empty());
    assert_eq!(
        s.core.moderation_open(alice),
        None,
        "not a moderator's badge"
    );
}

#[test]
fn a_second_report_of_the_same_thing_is_the_first() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let (dave, _) = attach(&s.core, person("dave"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let line = say(&s.core, bob, "rude");
    let first = s
        .core
        .report(alice, ReportRequest::Line(line), "rude", None)
        .unwrap();
    let again = s
        .core
        .report(alice, ReportRequest::Line(line), "really rude", None)
        .unwrap();
    assert_eq!(again.id, first.id);
    let other = s
        .core
        .report(dave, ReportRequest::Line(line), "rude", None)
        .unwrap();
    assert_ne!(other.id, first.id, "someone else's report is theirs");
    assert_eq!(s.core.moderation_open(carol), Some(2));
}

#[test]
fn reports_are_rationed_per_reporter() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let lines: Vec<_> = (0..=REPORTS_PER_HOUR)
        .map(|n| say(&s.core, bob, &format!("line {n}")))
        .collect();
    for line in &lines[..REPORTS_PER_HOUR as usize] {
        s.core
            .report(alice, ReportRequest::Line(*line), "x", None)
            .unwrap();
    }
    assert_eq!(
        s.core.report(
            alice,
            ReportRequest::Line(lines[REPORTS_PER_HOUR as usize]),
            "x",
            None
        ),
        Err(ModError::RateLimited)
    );
}

#[test]
fn a_report_on_something_gone_is_answered_at_once() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let (carol, mut carol_rx) = attach(&s.core, moderator("carol"));
    let line = say(&s.core, bob, "rude");
    s.core
        .redact_line(Actor::Session(carol), line, "rude")
        .unwrap();
    drain(&mut carol_rx);
    let filed = s
        .core
        .report(alice, ReportRequest::Line(line), "rude", None)
        .unwrap();
    assert_eq!(filed.outcome, Some(Outcome::Removed));
    assert!(
        reports_in(drain(&mut carol_rx)).is_empty(),
        "no moderator is bothered with it"
    );
    let stored = s.store.report(filed.id).unwrap().unwrap();
    assert_eq!(stored.closed.unwrap().by, CLOSED_BY_SERVER);
    assert_eq!(
        s.core.report(alice, ReportRequest::Line(999), "x", None),
        Err(ModError::NoSuchTarget)
    );
}

#[test]
fn a_guest_may_report_and_is_told_it_will_not_hear_back() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (g, _) = attach(&s.core, guest());
    let line = say(&s.core, bob, "rude");
    let filed = s
        .core
        .report(g, ReportRequest::Line(line), "rude", None)
        .unwrap();
    assert!(!filed.follow_up);
    assert_eq!(s.store.report(filed.id).unwrap().unwrap().reporter, None);
}

#[test]
fn only_its_recipient_may_report_a_private_message_and_the_body_goes_with_it() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, mut alice_rx) = attach(&s.core, person("alice"));
    let (dave, _) = attach(&s.core, person("dave"));
    let (_carol, mut carol_rx) = attach(&s.core, moderator("carol"));
    s.core
        .msg(bob, alice, "a threat".into(), None, None)
        .unwrap();
    let id = drain(&mut alice_rx)
        .into_iter()
        .find_map(|e| match e {
            Event::Msg { id, .. } => id,
            _ => None,
        })
        .expect("a stored message");
    drain(&mut carol_rx);
    assert_eq!(
        s.core.report(dave, ReportRequest::Msg(id), "x", None),
        Err(ModError::NoSuchTarget),
        "someone else's mail is not theirs to show"
    );
    let filed = s
        .core
        .report(alice, ReportRequest::Msg(id), "threat", None)
        .unwrap();
    let got = reports_in(drain(&mut carol_rx));
    assert_eq!(got[0].id, filed.id);
    assert_eq!(got[0].evidence.as_deref(), Some("a threat"));
    assert!(got[0].verified);
    assert_eq!(got[0].about.login.as_deref(), Some("bob"));
}

#[test]
fn a_pasted_message_is_the_reporters_word_and_says_so() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let filed = s
        .core
        .report(
            alice,
            ReportRequest::User(PersonRef::Uid(bob)),
            "threatened me",
            Some("what bob said".into()),
        )
        .unwrap();
    let stored = s.store.report(filed.id).unwrap().unwrap();
    assert!(!stored.verified);
    assert_eq!(stored.evidence.as_deref(), Some("what bob said"));
    assert_eq!(stored.target, ReportTarget::User);
    assert_eq!(stored.about.login.as_deref(), Some("bob"));
    assert_eq!(
        s.core.report(
            alice,
            ReportRequest::User(PersonRef::Login("nobody".into())),
            "x",
            None
        ),
        Err(ModError::NoSuchTarget)
    );
}

#[test]
fn a_moderator_sees_a_reported_image_they_were_never_shown() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let handle = upload(&s.core, bob, b"awful");
    // Shown to alice in a private message; not to carol.
    s.core
        .msg(bob, alice, "look".into(), None, Some(handle))
        .unwrap();
    assert!(s.core.media_fetch(carol, &handle).is_none());
    assert_eq!(
        s.core
            .report(carol, ReportRequest::Media(handle), "x", None),
        Err(ModError::NoSuchTarget),
        "nobody reports an image they were never shown"
    );
    let filed = s
        .core
        .report(alice, ReportRequest::Media(handle), "awful", None)
        .unwrap();
    assert!(
        s.core.media_fetch(carol, &handle).is_some(),
        "a moderator is added to the set, the one widening allowed"
    );
    s.core
        .report_close(
            Actor::Session(carol),
            filed.id,
            Outcome::Dismissed,
            None,
            None,
        )
        .unwrap();
}

#[test]
fn a_moderator_who_arrives_later_is_granted_what_they_list() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let handle = upload(&s.core, bob, b"awful");
    s.core
        .msg(bob, alice, "look".into(), None, Some(handle))
        .unwrap();
    s.core
        .report(alice, ReportRequest::Media(handle), "awful", None)
        .unwrap();
    let (carol, _) = attach(&s.core, moderator("carol"));
    assert!(s.core.media_fetch(carol, &handle).is_none());
    let (page, _) = s
        .core
        .reports(Actor::Session(carol), ReportFilter::Open, None, 10)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(s.core.media_fetch(carol, &handle).is_some());
}

#[test]
fn closing_a_report_tells_its_reporter_and_the_moderators() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, mut alice_rx) = attach(&s.core, person("alice"));
    let (carol, mut carol_rx) = attach(&s.core, moderator("carol"));
    let (_erin, mut erin_rx) = attach(&s.core, moderator("erin"));
    let first = say(&s.core, bob, "one");
    let second = say(&s.core, bob, "two");
    let a = s
        .core
        .report(alice, ReportRequest::Line(first), "x", None)
        .unwrap();
    let b = s
        .core
        .report(alice, ReportRequest::Line(second), "x", None)
        .unwrap();
    drain(&mut alice_rx);
    drain(&mut carol_rx);
    drain(&mut erin_rx);
    assert_eq!(
        s.core
            .report_close(Actor::Session(alice), a.id, Outcome::Dismissed, None, None),
        Err(ModError::AccessDenied)
    );
    assert!(matches!(
        s.core
            .report_close(Actor::Session(carol), a.id, Outcome::Removed, None, None),
        Err(ModError::BadRequest(_))
    ));
    assert!(matches!(
        s.core
            .report_close(Actor::Session(carol), b.id, Outcome::Duplicate, None, None),
        Err(ModError::BadRequest(_))
    ));
    s.core
        .report_close(
            Actor::Session(carol),
            b.id,
            Outcome::Duplicate,
            Some("same thing".into()),
            Some(a.id),
        )
        .unwrap();
    assert_eq!(
        closes_in(drain(&mut alice_rx)),
        [(b.id, Outcome::Duplicate, true)]
    );
    assert_eq!(
        closes_in(drain(&mut erin_rx)),
        [(b.id, Outcome::Duplicate, false)]
    );
    let closed = s.store.report(b.id).unwrap().unwrap().closed.unwrap();
    assert_eq!(closed.by, "carol");
    assert_eq!(closed.duplicate_of, Some(a.id));
    assert_eq!(closed.note.as_deref(), Some("same thing"));
    assert!(matches!(
        s.core
            .report_close(Actor::Session(carol), b.id, Outcome::Dismissed, None, None),
        Err(ModError::BadRequest(_))
    ));
    assert_eq!(
        s.core
            .report_close(Actor::Session(carol), 999, Outcome::Dismissed, None, None),
        Err(ModError::NoSuchReport)
    );
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!(act.kind, ActKind::Close);
    assert_eq!(act.report, Some(b.id));

    // An act answers the rest.
    s.core
        .redact_line(Actor::Session(carol), first, "rude")
        .unwrap();
    assert_eq!(
        closes_in(drain(&mut alice_rx)),
        [(a.id, Outcome::Removed, true)]
    );
    assert_eq!(s.core.moderation_open(carol), Some(0));
}

#[test]
fn deleting_someone_elses_article_is_an_act_with_a_ladder() {
    let mut directory = Directory::default();
    directory.0.insert(
        "admin".into(),
        (None, member_access().with(bit::CANT_BE_DISCONNECTED)),
    );
    let s = server_with(directory);
    let (bob, _) = attach(&s.core, person("bob"));
    let (admin, _) = attach(
        &s.core,
        Who {
            access: member_access().with(bit::CANT_BE_DISCONNECTED),
            ..person("admin")
        },
    );
    let editor = member_access()
        .with(bit::CREATE_CATEGORIES)
        .with(bit::DELETE_ARTICLES);
    let (carol, _) = attach(
        &s.core,
        Who {
            access: editor,
            ..person("carol")
        },
    );
    let cat = s
        .core
        .news_node_create(carol, None, NodeKind::Category, "General")
        .unwrap()
        .id;
    let post = |uid, body: &str| {
        s.core
            .news_post(
                uid,
                PostRequest {
                    category: cat,
                    parent: None,
                    subject: "subject".into(),
                    body: body.into(),
                    mime: BodyType::Plain,
                    attachments: Vec::new(),
                },
            )
            .unwrap()
    };
    let bobs = post(bob, "bob's words");
    let admins = post(admin, "the admin's");
    let own = post(carol, "carol's");
    let filed = s
        .core
        .report(bob, ReportRequest::Article(admins), "x", None)
        .unwrap();

    s.core.news_delete_for(carol, own, "").unwrap();
    assert!(
        s.store.acts(None, 10).unwrap().is_empty(),
        "one's own is not an act"
    );

    s.core.news_delete_for(carol, bobs, "off topic").unwrap();
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!(act.kind, ActKind::NewsDelete);
    assert_eq!(act.article, Some(bobs));
    assert_eq!(act.login.as_deref(), Some("bob"));
    assert_eq!(act.reason, "off topic");
    assert!(act.evidence.as_deref().unwrap().contains("bob's words"));

    // The ladder holds whether or not the author is here.
    assert_eq!(
        s.core.news_delete_for(carol, admins, ""),
        Err(NewsError::Protected)
    );
    s.core.end_session(admin);
    assert_eq!(s.core.news_delete(carol, admins), Err(NewsError::Protected));
    let (root, _) = attach(
        &s.core,
        Who {
            access: editor.with(bit::DELETE_USERS),
            ..person("root")
        },
    );
    s.core.news_delete(root, admins).unwrap();
    assert_eq!(
        s.store
            .report(filed.id)
            .unwrap()
            .unwrap()
            .closed
            .unwrap()
            .outcome,
        Outcome::Removed
    );
}

#[test]
fn the_sweeper_scrubs_evidence_and_ages_out_closed_reports() {
    let s = server();
    let old = SystemTime::now() - Duration::from_secs(400 * 24 * 3600);
    s.store
        .record(&Act {
            at: old,
            evidence: Some("old words".into()),
            ..Act::new(
                ActKind::Redact,
                &Acting {
                    name: "carol".into(),
                    fingerprint: None,
                    overrides: false,
                    uid: None,
                    person: None,
                },
                "x".into(),
            )
        })
        .unwrap();
    let id = s
        .store
        .file(&Report {
            id: 0,
            at: old,
            reporter: None,
            target: ReportTarget::Line(1),
            about: Subject::default(),
            reason: "x".into(),
            evidence: None,
            verified: true,
            media: None,
            closed: Some(Closed {
                at: old,
                by: "carol".into(),
                outcome: Outcome::Dismissed,
                note: None,
                duplicate_of: None,
            }),
        })
        .unwrap();
    assert_eq!(s.core.prune_moderation(), (1, 1));
    assert!(s.store.report(id).unwrap().is_none());
    assert_eq!(
        s.store.acts(None, 1).unwrap()[0].evidence.as_deref(),
        Some("")
    );
}

#[test]
fn without_a_store_moderation_is_not_available() {
    let core = Core::new().with_history(Arc::new(MemoryLog::default()), HistoryPolicy::default());
    let (bob, _) = attach(&core, person("bob"));
    let (carol, _) = attach(&core, moderator("carol"));
    let line = say(&core, bob, "x");
    assert_eq!(
        core.redact_line(Actor::Session(carol), line, "x"),
        Err(ModError::Disabled)
    );
    assert_eq!(
        core.report(bob, ReportRequest::Line(line), "x", None),
        Err(ModError::Disabled)
    );
    assert_eq!(core.moderation_open(carol), None);
}

/// Accounts that keep no mailbox: nothing answers the mail questions,
/// and the account questions still do.
struct NoMail(Directory);

impl AccountDirectory for NoMail {
    fn inbox_account(&self, _login: &str) -> Option<Mailbox> {
        None
    }

    fn mailbox_access(&self, _who: &Mailbox) -> Option<AccessBits> {
        None
    }

    fn account(&self, login: &str) -> Option<(Mailbox, AccessBits)> {
        self.0 .0.get(login).map(|(fp, access)| {
            (
                Mailbox {
                    login: login.into(),
                    fingerprint: *fp,
                },
                *access,
            )
        })
    }

    fn account_by_key(&self, key: &[u8; 32]) -> Option<(Mailbox, AccessBits)> {
        self.0
             .0
            .iter()
            .find(|(_, (fp, _))| fp.as_ref() == Some(key))
            .map(|(login, (fp, access))| {
                (
                    Mailbox {
                        login: login.clone(),
                        fingerprint: *fp,
                    },
                    *access,
                )
            })
    }
}

#[test]
fn an_offline_author_is_protected_and_found_whether_or_not_they_take_mail() {
    let mut accounts = Directory::default();
    accounts.0.insert(
        "admin".into(),
        (
            Some([9; 32]),
            member_access().with(bit::CANT_BE_DISCONNECTED),
        ),
    );
    let s = server_full(Arc::new(NoMail(accounts)), Duration::from_secs(24 * 3600));
    let (admin, _) = attach(
        &s.core,
        Who {
            access: member_access().with(bit::CANT_BE_DISCONNECTED),
            identity: Some([9; 32]),
            ..person("admin")
        },
    );
    let (carol, _) = attach(&s.core, moderator("carol"));
    let line = say(&s.core, admin, "rules");
    s.core.end_session(admin);
    assert_eq!(
        s.core.redact_line(Actor::Session(carol), line, "x"),
        Err(ModError::Protected),
        "an account with no mailbox is protected for what it may do"
    );
    // And a purge by login finds the rows it wrote under its key.
    let found = s
        .core
        .purge_preview(&PersonRef::Login("admin".into()), Duration::from_secs(3600))
        .unwrap();
    assert_eq!(found.lines, [line]);
}

#[test]
fn two_guests_reported_by_one_reporter_are_two_reports() {
    let s = server();
    let (alice, _) = attach(&s.core, person("alice"));
    let (g1, _) = attach(&s.core, guest());
    let (g2, _) = attach(&s.core, guest());
    let first = s
        .core
        .report(alice, ReportRequest::User(PersonRef::Uid(g1)), "spam", None)
        .unwrap();
    let second = s
        .core
        .report(
            alice,
            ReportRequest::User(PersonRef::Uid(g2)),
            "threats",
            None,
        )
        .unwrap();
    assert_ne!(
        first.id, second.id,
        "nothing says the two guests are one person"
    );
    assert_eq!(
        s.store.report(second.id).unwrap().unwrap().reason,
        "threats"
    );
}

#[test]
fn guests_at_one_address_share_a_ration_and_a_reconnect_does_not_reset_it() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let here: std::net::IpAddr = [192, 0, 2, 1].into();
    let there: std::net::IpAddr = [192, 0, 2, 2].into();
    let at = |addr| Who {
        addr: Some(addr),
        ..guest()
    };
    let lines: Vec<_> = (0..=REPORTS_PER_HOUR)
        .map(|n| say(&s.core, bob, &format!("line {n}")))
        .collect();
    let (first, _) = attach(&s.core, at(here));
    for line in &lines[..REPORTS_PER_HOUR as usize] {
        s.core
            .report(first, ReportRequest::Line(*line), "x", None)
            .unwrap();
    }
    let last = lines[REPORTS_PER_HOUR as usize];
    s.core.end_session(first);
    let (again, _) = attach(&s.core, at(here));
    assert_eq!(
        s.core.report(again, ReportRequest::Line(last), "x", None),
        Err(ModError::RateLimited),
        "a new session at the same address is the same guest"
    );
    let (elsewhere, _) = attach(&s.core, at(there));
    s.core
        .report(elsewhere, ReportRequest::Line(last), "x", None)
        .unwrap();
    // Accounts are people, and people behind one address are not
    // rationed together.
    let (alice, _) = attach(
        &s.core,
        Who {
            addr: Some(here),
            ..person("alice")
        },
    );
    s.core
        .report(alice, ReportRequest::Line(last), "x", None)
        .unwrap();
}

#[test]
fn a_reported_line_holds_its_image_until_the_last_report_on_it_closes() {
    // Handles that live a fifth of a second, so the test can outlast one.
    let ttl = Duration::from_millis(200);
    let s = server_full(Arc::new(Directory::default()), ttl);
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let (dave, _) = attach(&s.core, person("dave"));
    let handle = upload(&s.core, bob, b"awful");
    let line = s
        .core
        .chat_public(bob, "look".into(), 0, Some(handle))
        .unwrap()
        .unwrap();
    // A moderator who arrives afterwards was never shown it.
    let (carol, _) = attach(&s.core, moderator("carol"));
    assert!(s.core.media_fetch(carol, &handle).is_none());

    let on_line = s
        .core
        .report(alice, ReportRequest::Line(line), "awful", None)
        .unwrap();
    assert_eq!(
        s.store.report(on_line.id).unwrap().unwrap().media,
        Some(handle),
        "the line's image is part of what was reported"
    );
    assert!(
        s.core.media_fetch(carol, &handle).is_some(),
        "and the moderator may see it"
    );
    let on_image = s
        .core
        .report(dave, ReportRequest::Media(handle), "awful", None)
        .unwrap();

    std::thread::sleep(ttl + Duration::from_millis(100));
    s.core.media_sweep();
    assert!(s.core.media_fetch(carol, &handle).is_some(), "past its TTL");

    s.core
        .report_close(
            Actor::Session(carol),
            on_line.id,
            Outcome::Dismissed,
            None,
            None,
        )
        .unwrap();
    s.core.media_sweep();
    assert!(
        s.core.media_fetch(carol, &handle).is_some(),
        "another open report still holds it"
    );
    s.core
        .report_close(
            Actor::Session(carol),
            on_image.id,
            Outcome::Dismissed,
            None,
            None,
        )
        .unwrap();
    s.core.media_sweep();
    assert!(
        s.core.media_fetch(carol, &handle).is_none(),
        "judged, and let go"
    );
}

#[test]
fn a_moderator_does_not_close_a_report_about_themselves() {
    let s = server();
    let (alice, _) = attach(&s.core, person("alice"));
    let (carol, _) = attach(&s.core, moderator("carol"));
    let (erin, _) = attach(&s.core, moderator("erin"));
    let about_carol = s
        .core
        .report(
            alice,
            ReportRequest::User(PersonRef::Uid(carol)),
            "abuse",
            None,
        )
        .unwrap();
    assert_eq!(
        s.core.report_close(
            Actor::Session(carol),
            about_carol.id,
            Outcome::Dismissed,
            None,
            None
        ),
        Err(ModError::OwnReport)
    );
    s.core
        .report_close(
            Actor::Session(erin),
            about_carol.id,
            Outcome::Dismissed,
            None,
            None,
        )
        .unwrap();
    // The operator is nobody's subject.
    let again = s
        .core
        .report(
            alice,
            ReportRequest::User(PersonRef::Uid(carol)),
            "again",
            None,
        )
        .unwrap();
    s.core
        .report_close(Actor::Operator, again.id, Outcome::Dismissed, None, None)
        .unwrap();
}

#[test]
fn deleting_a_category_is_on_the_record_and_answers_its_reports() {
    let s = server();
    let (bob, _) = attach(&s.core, person("bob"));
    let (alice, _) = attach(&s.core, person("alice"));
    let (editor, _) = attach(
        &s.core,
        Who {
            access: member_access()
                .with(bit::CREATE_CATEGORIES)
                .with(bit::DELETE_CATEGORIES),
            ..person("editor")
        },
    );
    let cat = s
        .core
        .news_node_create(editor, None, NodeKind::Category, "Flame")
        .unwrap()
        .id;
    let post = |uid| {
        s.core
            .news_post(
                uid,
                PostRequest {
                    category: cat,
                    parent: None,
                    subject: "s".into(),
                    body: "b".into(),
                    mime: BodyType::Plain,
                    attachments: Vec::new(),
                },
            )
            .unwrap()
    };
    let reported = post(bob);
    post(bob);
    post(alice);
    let filed = s
        .core
        .report(alice, ReportRequest::Article(reported), "flame", None)
        .unwrap();
    assert_eq!(s.core.news_node_delete(editor, cat).unwrap(), 3);
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!(act.kind, ActKind::NodeDelete);
    assert_eq!(act.actor, "editor");
    let evidence = act.evidence.as_deref().unwrap();
    assert!(evidence.contains("\"Flame\""), "{evidence}");
    assert!(evidence.contains("3 articles"), "{evidence}");
    assert!(evidence.contains("BOB (2), ALICE (1)"), "{evidence}");
    assert_eq!(
        s.store
            .report(filed.id)
            .unwrap()
            .unwrap()
            .closed
            .unwrap()
            .outcome,
        Outcome::Removed
    );
}
