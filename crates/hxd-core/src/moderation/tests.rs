//! Domain-side moderation: who may act, whom on, what each act leaves
//! behind, and where reports go.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::Events;

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
use crate::roster::{drain, AttachInfo, Transport};

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
    /// On the classic wire, which cannot take a line back.
    classic: bool,
}

fn person(login: &'static str) -> Who {
    Who {
        login,
        access: member_access(),
        moderate: false,
        identity: None,
        person: true,
        addr: None,
        classic: false,
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

fn attach(core: &Core, who: Who) -> (Uid, Events) {
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
                redactions: !who.classic,
                ..Default::default()
            },
            has_inbox: who.person,
            attach_news: false,
            set_avatar: false,
            moderate: who.moderate,
            can_spam: false,
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
    let (_erin, mut erin_rx) = attach(
        &s.core,
        Who {
            classic: true,
            ..person("erin")
        },
    );
    let line = say(&s.core, bob, "a slur");
    drain(&mut dave_rx);
    drain(&mut erin_rx);
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
    // Nor is a classic reader, whose wire cannot take the line back: an
    // event it would drop unread would only take room in its channel.
    assert!(
        redactions(drain(&mut erin_rx)).is_empty(),
        "a reader who cannot blank the line is not"
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
fn a_purge_of_a_flood_goes_out_batched_and_a_small_one_line_by_line() {
    let s = server();
    let (bob, _) = attach(
        &s.core,
        Who {
            identity: Some([2; 32]),
            ..person("bob")
        },
    );
    let (carol, mut carol_rx) = attach(&s.core, moderator("carol"));
    let (_dave, mut dave_rx) = attach(&s.core, person("dave"));
    let lines: Vec<LineId> = (0..2500)
        .map(|i| say(&s.core, bob, &format!("spam {i}")))
        .collect();
    drain(&mut carol_rx);
    drain(&mut dave_rx);

    s.core
        .purge_sender(
            Actor::Session(carol),
            &PersonRef::Fingerprint([2; 32]),
            Duration::from_secs(3600),
            "flood",
        )
        .unwrap();
    for rx in [&mut carol_rx, &mut dave_rx] {
        let events = drain(rx);
        let batches: Vec<Vec<LineId>> = events
            .iter()
            .filter_map(|e| match e {
                Event::ChatPurged { ids } => Some(ids.clone()),
                _ => None,
            })
            .collect();
        // Three events, not 2500, and every line in them, in order.
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            [1000, 1000, 500]
        );
        assert_eq!(batches.concat(), lines);
        assert!(redactions(events).is_empty());
    }

    // A handful is still told line by line, which every client reads.
    let few: Vec<LineId> = (0..3)
        .map(|i| say(&s.core, bob, &format!("more {i}")))
        .collect();
    drain(&mut dave_rx);
    s.core
        .purge_sender(
            Actor::Session(carol),
            &PersonRef::Fingerprint([2; 32]),
            Duration::from_secs(3600),
            "again",
        )
        .unwrap();
    assert_eq!(redactions(drain(&mut dave_rx)), few);
}

/// What a reader hears of a purge of `n` lines: one `chat_redacted` each,
/// and the sizes of the `chat_purged` batches.
fn purge_of(n: usize) -> (Vec<LineId>, Vec<usize>, Vec<LineId>) {
    let s = server();
    let who = Who {
        identity: Some([2; 32]),
        ..person("bob")
    };
    let (bob, _) = attach(&s.core, who);
    let (carol, _) = attach(&s.core, moderator("carol"));
    let (_dave, mut dave_rx) = attach(&s.core, person("dave"));
    let lines: Vec<LineId> = (0..n).map(|i| say(&s.core, bob, &format!("{i}"))).collect();
    drain(&mut dave_rx);
    s.core
        .purge_sender(
            Actor::Session(carol),
            &PersonRef::Fingerprint([2; 32]),
            Duration::from_secs(3600),
            "flood",
        )
        .unwrap();
    let events = drain(&mut dave_rx);
    let batches = events
        .iter()
        .filter_map(|e| match e {
            Event::ChatPurged { ids } => Some(ids.len()),
            _ => None,
        })
        .collect();
    (redactions(events), batches, lines)
}

#[test]
fn a_purge_is_batched_from_just_past_its_threshold_and_split_at_the_batch_size() {
    let (singly, batches, lines) = purge_of(PURGE_SINGLY);
    assert_eq!((singly, batches), (lines, vec![]));
    let (singly, batches, _) = purge_of(PURGE_SINGLY + 1);
    assert_eq!((singly, batches), (vec![], vec![PURGE_SINGLY + 1]));
    let (singly, batches, _) = purge_of(PURGE_EVENT_IDS + 1);
    assert_eq!((singly, batches), (vec![], vec![PURGE_EVENT_IDS, 1]));
}

/// A flood of articles is as easy to post as a flood of lines, and its
/// purge is batched the same way: a reader who kept up with the flood is
/// not cut off by its removal.
#[test]
fn a_purge_of_a_news_flood_goes_out_batched_and_cuts_no_reader_off() {
    let s = server();
    let who = Who {
        identity: Some([2; 32]),
        ..person("bob")
    };
    let (bob, _) = attach(&s.core, who);
    let (carol, mut carol_rx) = attach(
        &s.core,
        Who {
            access: moderator("carol").access.with(bit::CREATE_CATEGORIES),
            ..moderator("carol")
        },
    );
    let (_dave, mut dave_rx) = attach(&s.core, person("dave"));
    let cat = s
        .core
        .news_node_create(carol, None, NodeKind::Category, "General")
        .unwrap()
        .id;
    let n = crate::LIVE_QUEUE_CAP + PURGE_EVENT_IDS / 2;
    let mut articles = Vec::with_capacity(n);
    for i in 0..n {
        let posted = s
            .core
            .news_post(
                bob,
                PostRequest {
                    category: cat,
                    parent: None,
                    subject: format!("spam {i}"),
                    body: "spam".into(),
                    mime: BodyType::Plain,
                    attachments: Vec::new(),
                },
            )
            .unwrap();
        articles.push((posted, cat));
        if i % 1000 == 0 {
            drain(&mut carol_rx);
            drain(&mut dave_rx);
        }
    }
    drain(&mut carol_rx);
    drain(&mut dave_rx);

    s.core
        .purge_sender(
            Actor::Session(carol),
            &PersonRef::Fingerprint([2; 32]),
            Duration::from_secs(3600),
            "flood",
        )
        .unwrap();
    for (who, rx) in [("carol", &mut carol_rx), ("dave", &mut dave_rx)] {
        let events = drain(rx);
        assert!(!rx.lagged(), "{who} was cut off by the purge");
        let batches: Vec<Vec<_>> = events
            .iter()
            .filter_map(|e| match e {
                Event::NewsPurged { articles } => Some(articles.clone()),
                _ => None,
            })
            .collect();
        assert!(batches.iter().all(|b| b.len() <= PURGE_EVENT_IDS));
        assert_eq!(batches.concat(), articles, "{who} heard of every one");
        assert!(!events
            .iter()
            .any(|e| matches!(e, Event::NewsDeleted { .. })));
    }
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
    // Reports on bob, on a line and an article of his, which
    // the purge answers; and one on dave's line, which it does not.
    let (erin, _) = attach(&s.core, person("erin"));
    let on_line = s
        .core
        .report(erin, ReportRequest::Line(bob_lines[0]), "spam", None)
        .unwrap();
    let on_article = s
        .core
        .report(erin, ReportRequest::Article(bob_article), "spam", None)
        .unwrap();
    let on_dave = s
        .core
        .report(erin, ReportRequest::Line(dave_line), "rude", None)
        .unwrap();
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
        [
            (on_line.id, Outcome::Removed, false),
            (on_article.id, Outcome::Removed, false),
            (filed.id, Outcome::Removed, false),
        ],
        "the reports on the person and on what was removed are answered"
    );
    let open = s.store.open_on(&ReportTarget::Line(dave_line)).unwrap();
    assert_eq!(open.iter().map(|r| r.id).collect::<Vec<_>>(), [on_dave.id]);

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
    let ban = |target: &str, expires_at| crate::ban::Ban {
        id: 0,
        target: crate::ban::BanTarget::login(target).unwrap(),
        reason: "x".into(),
        note: None,
        actor: "carol".into(),
        actor_fp: None,
        source: crate::ban::BanSource::Moderator,
        created_at: old,
        expires_at,
        lifted_at: None,
        lifted_by: None,
        act: None,
    };
    s.store.ban(&ban("expired", Some(old))).unwrap();
    let recent = s
        .store
        .ban(&ban(
            "recent",
            Some(SystemTime::now() - Duration::from_secs(60)),
        ))
        .unwrap();
    let standing = s.store.ban(&ban("standing", None)).unwrap();
    assert_eq!(s.core.prune_moderation(), (1, 1, 1));
    let kept: Vec<_> = s
        .store
        .bans(None, None, 10)
        .unwrap()
        .iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(
        kept,
        [standing.id, recent.id],
        "only a ban ended report_days ago goes; a standing one never does"
    );
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

fn kicked(events: Vec<Event>) -> bool {
    events.iter().any(|e| matches!(e, Event::Kicked))
}

#[test]
fn a_kick_with_a_ban_refuses_the_address_and_ends_only_its_target() {
    let s = server();
    let shared: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let at = |who: Who| Who {
        addr: Some(shared),
        ..who
    };
    let (carol, mut carol_rx) = attach(&s.core, at(moderator("carol")));
    let (bob, mut bob_rx) = attach(&s.core, at(person("bob")));
    let (_, mut eve_rx) = attach(&s.core, at(person("eve")));
    let (_, mut tank_rx) = attach(
        &s.core,
        at(Who {
            access: member_access().with(bit::CANT_BE_DISCONNECTED),
            ..person("tank")
        }),
    );
    let (_, mut dave_rx) = attach(
        &s.core,
        Who {
            addr: Some("192.0.2.8".parse().unwrap()),
            ..person("dave")
        },
    );
    for rx in [
        &mut carol_rx,
        &mut bob_rx,
        &mut eve_rx,
        &mut tank_rx,
        &mut dave_rx,
    ] {
        drain(rx);
    }
    s.core
        .kick_by(
            bob,
            Some(crate::KickBan {
                by: Actor::Session(carol),
                for_: Duration::from_secs(3600),
                reason: "spam".into(),
            }),
        )
        .unwrap();
    assert!(kicked(drain(&mut bob_rx)));
    assert!(
        !kicked(drain(&mut eve_rx)),
        "a kick's ban ends only whom it kicks, as the reference server's does"
    );
    assert!(!kicked(drain(&mut carol_rx)), "not the kicker");
    assert!(!kicked(drain(&mut tank_rx)), "nor the unkickable");
    assert!(!kicked(drain(&mut dave_rx)), "nor another address");
    assert!(s.core.is_banned("::ffff:192.0.2.7".parse().unwrap()));
    assert!(!s.core.is_banned("192.0.2.8".parse().unwrap()));

    let bans = s.core.list_bans(true, None, 10).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].source, crate::ban::BanSource::Kick);
    assert_eq!(bans[0].actor, "carol");
    assert!(bans[0].expires_at.is_some());
    let act = &s.store.acts(None, 1).unwrap()[0];
    assert_eq!((act.kind, act.id), (ActKind::Ban, bans[0].act.unwrap()));
}

#[test]
fn a_login_ban_takes_the_linked_key_and_is_lifted_by_id() {
    let mut directory = Directory::default();
    directory
        .0
        .insert("bob".into(), (Some([9; 32]), member_access()));
    let s = server_with(directory);
    let (carol, _) = attach(&s.core, moderator("carol"));
    let (_, mut bob_rx) = attach(&s.core, person("bob"));
    drain(&mut bob_rx);
    let ban = |target| crate::ban::NewBan {
        target,
        reason: "no".into(),
        note: None,
        expires_at: None,
        source: crate::ban::BanSource::Moderator,
    };
    let login = |l: &str| crate::ban::BanTarget::login(l).unwrap();
    for refused in ["guest", "Carol"] {
        assert!(matches!(
            s.core.place_ban(Actor::Session(carol), ban(login(refused))),
            Err(ModError::BadRequest(_))
        ));
    }
    let placed = s
        .core
        .place_ban(Actor::Session(carol), ban(login("Bob")))
        .unwrap();
    assert_eq!(
        placed.iter().map(|b| b.target.clone()).collect::<Vec<_>>(),
        [login("bob"), crate::ban::BanTarget::Identity([9; 32])],
        "the account and the key it links"
    );
    assert!(kicked(drain(&mut bob_rx)));
    assert!(s.core.person_banned(Some("BOB"), None, None).is_some());
    assert!(
        s.core
            .person_banned(Some("robert"), Some(&[9; 32]), None)
            .is_some(),
        "the key under another account"
    );

    // Lifting either row lifts the person: the twin goes with it.
    let lifted = s
        .core
        .lift_ban(Actor::Session(carol), placed[1].id)
        .unwrap();
    assert_eq!(
        lifted.iter().map(|b| b.id).collect::<Vec<_>>(),
        [placed[1].id, placed[0].id],
        "the one named, then its twin"
    );
    assert!(s
        .core
        .person_banned(Some("bob"), Some(&[9; 32]), None)
        .is_none());
    assert!(s.core.list_bans(true, None, 10).unwrap().is_empty());
    assert_eq!(s.core.list_bans(false, None, 10).unwrap().len(), 2);
    for b in &placed {
        assert_eq!(
            s.core.lift_ban(Actor::Session(carol), b.id),
            Err(ModError::NoSuchBan),
            "lifted is lifted"
        );
    }
    assert_eq!(s.store.acts(None, 1).unwrap()[0].kind, ActKind::Unban);

    let config = s
        .core
        .place_ban(
            Actor::Operator,
            crate::ban::NewBan {
                source: crate::ban::BanSource::Config,
                ..ban(login("mallory"))
            },
        )
        .unwrap();
    assert_eq!(
        s.core.lift_ban(Actor::Operator, config[0].id),
        Err(ModError::ConfigBan)
    );
}

#[test]
fn lifting_a_ban_leaves_a_row_it_only_extended() {
    let mut directory = Directory::default();
    directory
        .0
        .insert("bob".into(), (Some([9; 32]), member_access()));
    let s = server_with(directory);
    let (carol, _) = attach(&s.core, moderator("carol"));
    let key = crate::ban::BanTarget::Identity([9; 32]);
    let week = SystemTime::now() + Duration::from_secs(7 * 86400);
    let ban = |target, expires_at| crate::ban::NewBan {
        target,
        reason: "no".into(),
        note: None,
        expires_at,
        source: crate::ban::BanSource::Moderator,
    };
    // One act bans the identity for good; a later one bans an account
    // linking it for a week, which extends the identity's row.
    let forever = s
        .core
        .place_ban(Actor::Operator, ban(key.clone(), None))
        .unwrap();
    let placed = s
        .core
        .place_ban(
            Actor::Session(carol),
            ban(crate::ban::BanTarget::login("bob").unwrap(), Some(week)),
        )
        .unwrap();
    assert_eq!(placed[1].id, forever[0].id, "the identity's one row");
    assert_eq!(
        placed[1].act, forever[0].act,
        "still the act that placed it"
    );
    assert_eq!(placed[1].expires_at, None, "until lifted outlasts a week");

    // Lifting the week lifts the login only: the permanent ban stands,
    // as it now is.
    let lifted = s
        .core
        .lift_ban(Actor::Session(carol), placed[0].id)
        .unwrap();
    assert_eq!(
        lifted.iter().map(|b| b.id).collect::<Vec<_>>(),
        [placed[0].id]
    );
    assert!(s.core.person_banned(Some("bob"), None, None).is_none());
    assert!(
        s.core
            .person_banned(Some("robert"), Some(&[9; 32]), None)
            .is_some(),
        "the identity is still banned"
    );
    let standing = s.core.list_bans(true, None, 10).unwrap();
    assert_eq!(standing.len(), 1);
    assert_eq!(
        (standing[0].id, standing[0].expires_at),
        (forever[0].id, None)
    );

    // And lifting the identity's own ban lifts it alone.
    let lifted = s.core.lift_ban(Actor::Operator, forever[0].id).unwrap();
    assert_eq!(
        lifted.iter().map(|b| b.id).collect::<Vec<_>>(),
        [forever[0].id]
    );
    assert!(s.core.list_bans(true, None, 10).unwrap().is_empty());
}

#[test]
fn a_ban_ends_the_sessions_it_refuses_and_a_reread_only_a_new_bans() {
    let s = server();
    let shared: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let at = |who: Who| Who {
        addr: Some(shared),
        ..who
    };
    let (carol, mut carol_rx) = attach(&s.core, at(moderator("carol")));
    let (eve, mut eve_rx) = attach(&s.core, at(person("eve")));
    let (dave, mut dave_rx) = attach(&s.core, person("dave"));
    for rx in [&mut carol_rx, &mut eve_rx, &mut dave_rx] {
        drain(rx);
    }
    s.core
        .place_ban(
            Actor::Session(carol),
            crate::ban::NewBan {
                target: crate::ban::BanTarget::address(shared, 32).unwrap(),
                reason: "a botnet".into(),
                note: None,
                expires_at: None,
                source: crate::ban::BanSource::Moderator,
            },
        )
        .unwrap();
    assert!(
        kicked(drain(&mut eve_rx)),
        "a moderator's ban ends what it refuses"
    );
    assert!(
        !kicked(drain(&mut carol_rx)),
        "not the moderator, on its own ban"
    );
    let _ = eve;

    // The command line writes to the store; the server hears on SIGHUP.
    ModerationStore::ban(
        &*s.store,
        &crate::ban::Ban {
            id: 0,
            target: crate::ban::BanTarget::login("dave").unwrap(),
            reason: "spam".into(),
            note: None,
            actor: OPERATOR.into(),
            actor_fp: None,
            source: crate::ban::BanSource::Cli,
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            lifted_at: None,
            lifted_by: None,
            act: None,
        },
    )
    .unwrap();
    s.core.reload_bans();
    assert!(
        kicked(drain(&mut dave_rx)),
        "a new ban ends whom it refuses"
    );
    assert!(
        !kicked(drain(&mut carol_rx)),
        "a reread does not end whom a ban it held spared"
    );
    assert!(s.core.user(carol).is_some());
    assert!(s.core.person_banned(Some("dave"), None, None).is_some());
    let _ = dave;
}

#[test]
fn a_login_ban_takes_the_key_of_an_account_that_keeps_no_mailbox() {
    let mut accounts = Directory::default();
    accounts
        .0
        .insert("bob".into(), (Some([9; 32]), member_access()));
    let s = server_full(Arc::new(NoMail(accounts)), Duration::from_secs(24 * 3600));
    let placed = s
        .core
        .place_ban(
            Actor::Operator,
            crate::ban::NewBan {
                target: crate::ban::BanTarget::login("bob").unwrap(),
                reason: "no".into(),
                note: None,
                expires_at: None,
                source: crate::ban::BanSource::Cli,
            },
        )
        .unwrap();
    assert_eq!(
        placed.iter().map(|b| b.target.clone()).collect::<Vec<_>>(),
        [
            crate::ban::BanTarget::login("bob").unwrap(),
            crate::ban::BanTarget::Identity([9; 32])
        ],
    );
}

#[test]
fn a_ban_that_lands_while_a_session_attaches_ends_it() {
    let s = server();
    let (bob, _bob_rx) = attach(&s.core, person("bob"));
    let (eve, _eve_rx) = attach(&s.core, person("eve"));
    // Placed after bob's login was checked and before he attached: no
    // session to end yet, so only the matcher knows.
    s.core.bans.write().unwrap().insert(&crate::ban::Ban {
        id: 1,
        target: crate::ban::BanTarget::login("bob").unwrap(),
        reason: "spam".into(),
        note: None,
        actor: OPERATOR.into(),
        actor_fp: None,
        source: crate::ban::BanSource::Cli,
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        lifted_at: None,
        lifted_by: None,
        act: None,
    });
    assert_eq!(
        s.core.end_if_banned(bob).map(|hit| hit.reason),
        Some("spam".into())
    );
    assert!(s.core.user(bob).is_none(), "ended, not left behind");
    assert!(s.core.end_if_banned(eve).is_none());
    assert!(s.core.user(eve).is_some());
}

#[test]
fn a_restarted_server_refuses_whom_it_banned() {
    let store = Arc::new(MemoryModeration::default());
    let core = Core::new().with_moderation(store.clone(), ModerationPolicy::default());
    core.place_ban(
        Actor::Operator,
        crate::ban::NewBan {
            target: crate::ban::BanTarget::parse("2001:db8:1:2::/64", |_| None).unwrap(),
            reason: "flood".into(),
            note: None,
            expires_at: None,
            source: crate::ban::BanSource::Cli,
        },
    )
    .unwrap();
    let core = Core::new().with_moderation(store, ModerationPolicy::default());
    assert!(core.is_banned("2001:db8:1:2:ffff::1".parse().unwrap()));
    assert!(!core.is_banned("2001:db8:1:3::1".parse().unwrap()));
}

/// A ration table full of spent buckets makes room by forgetting the
/// ones that give back least, never by handing everyone a fresh ration:
/// a reporter who has spent every report stays out of them however many
/// new keys arrive.
#[test]
fn a_full_ration_table_forgets_the_fullest_and_keeps_the_spent() {
    let core = Core::new();
    let spent = ReporterKey::Mailbox(None, "spammer".into());
    for _ in 0..REPORTS_PER_HOUR {
        assert!(core.report_rate_allows(std::slice::from_ref(&spent)));
    }
    assert!(!core.report_rate_allows(std::slice::from_ref(&spent)));
    // Every other place taken by a bucket one report down: none has
    // refilled, so the old answer was to clear the lot.
    {
        let mut rates = core.report_rate.lock().unwrap();
        let now = std::time::Instant::now();
        let almost = f64::from(REPORTS_PER_HOUR) - 1.0;
        for n in 0..RATES_KEPT as u64 {
            rates.insert(ReporterKey::Session(n as crate::Uid, n), (now, almost));
        }
    }
    let newcomer = ReporterKey::Mailbox(None, "newcomer".into());
    assert!(core.report_rate_allows(std::slice::from_ref(&newcomer)));
    assert!(core.report_rate.lock().unwrap().len() <= RATES_KEPT);
    assert!(
        !core.report_rate_allows(std::slice::from_ref(&spent)),
        "the spent ration survived the room being made"
    );
}
