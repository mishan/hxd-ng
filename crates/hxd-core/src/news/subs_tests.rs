//! Subscriptions and the notify decision for the news (`docs/news.md`
//! §10.5–§10.7): who a post reaches, which of them get a push, and the
//! rule that stops a busy thread ringing forty times. A recording gateway
//! and no network, as the private-message cases in `chat.rs` are — the
//! decision is the whole subject.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedReceiver;

use super::*;
use crate::inbox::MemoryStore;
use crate::notify::{Notification, NotificationGateway};
use crate::roster::{drain, AttachInfo, SeqEvent, Transport};
use crate::{AccountDirectory, InboxPolicy};

/// Accounts as a file backend answers for them, with bits that can change
/// while the server runs — which is what revoking one is.
struct Directory(Mutex<Vec<(Mailbox, AccessBits)>>);

impl AccountDirectory for Directory {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| m.login == login)
            .map(|(m, _)| m.clone())
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
        let accounts = self.0.lock().unwrap();
        accounts
            .iter()
            .find(|(m, _)| who.matches(&m.login, m.fingerprint.as_ref()))
            .map(|(_, access)| *access)
    }
}

/// What a gateway was asked to send: recipient, reason, collapse key and
/// unread, in order.
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, NotifyReason, String, usize)>>);

impl Recorder {
    fn sent(&self) -> Vec<(String, NotifyReason, String, usize)> {
        self.0.lock().unwrap().clone()
    }

    fn to(&self, login: &str) -> usize {
        self.sent().iter().filter(|s| s.0 == login).count()
    }
}

impl NotificationGateway for Recorder {
    fn notify(&self, n: &Notification<'_>) {
        let Notification::News(n) = n else {
            panic!("the news notified something else: {n:?}");
        };
        self.0
            .lock()
            .unwrap()
            .push((n.to.login.clone(), n.reason, n.scope.key(), n.unread));
    }
}

fn member() -> AccessBits {
    AccessBits::empty()
        .with(bit::READ_NEWS)
        .with(bit::POST_NEWS)
}

struct Server {
    core: Arc<Core>,
    gw: Arc<Recorder>,
    dir: Arc<Directory>,
    cat: NodeId,
}

impl Server {
    fn new(notify: NotifyPolicy) -> Self {
        Self::with(Some(notify))
    }

    fn with(notify: Option<NotifyPolicy>) -> Self {
        let dir = Arc::new(Directory(Mutex::new(
            ["alice", "bob", "carol", "dave"]
                .iter()
                .map(|l| (Mailbox::login(*l), member()))
                .collect(),
        )));
        let news = Arc::new(MemoryNews::new());
        let cat = news
            .create_node(
                &NewNode {
                    parent: None,
                    kind: NodeKind::Category,
                    name: "General".into(),
                    guid: [1; 16],
                    at: SystemTime::now(),
                },
                16,
            )
            .unwrap()
            .id;
        let gw = Arc::new(Recorder::default());
        let core = Core::new()
            .with_inbox(
                Arc::new(MemoryStore::new()),
                dir.clone(),
                InboxPolicy::default(),
            )
            .with_news(
                news,
                NewsPolicy {
                    notify,
                    ..NewsPolicy::default()
                },
            )
            .with_notifications(gw.clone());
        Server {
            core: Arc::new(core),
            gw,
            dir,
            cat,
        }
    }

    /// A session with an account behind it, and its events. `guest` is
    /// the one login with no mailbox, as a real login makes it.
    fn login(&self, login: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
        self.login_as(login, None)
    }

    fn login_as(
        &self,
        login: &str,
        identity: Option<[u8; 32]>,
    ) -> (Uid, UnboundedReceiver<SeqEvent>) {
        self.attach(login, identity, false)
    }

    /// A session on the legacy wire, which drops `news_notify`.
    fn login_classic(&self, login: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
        self.attach(login, None, true)
    }

    fn attach(
        &self,
        login: &str,
        identity: Option<[u8; 32]>,
        classic: bool,
    ) -> (Uid, UnboundedReceiver<SeqEvent>) {
        let (uid, rx) = self
            .core
            .attach(AttachInfo {
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: member(),
                login: login.to_string(),
                addr: None,
                can_detach: true,
                transport: Transport::default(),
                has_inbox: login != "guest",
                attach_news: false,
                is_person: login != "guest",
                reads_on_delivery: classic,
                identity,
            })
            .unwrap();
        self.core.announce(uid);
        (uid, rx)
    }

    /// Log in, do something, and leave — so the account is somewhere a
    /// push is for.
    fn as_absent<T>(&self, login: &str, f: impl FnOnce(Uid) -> T) -> T {
        let (uid, _rx) = self.login(login);
        let out = f(uid);
        self.core.end_session(uid);
        out
    }

    fn post(&self, uid: Uid, parent: Option<ArticleId>, body: &str) -> ArticleId {
        self.core
            .news_post(
                uid,
                PostRequest {
                    category: self.cat,
                    parent,
                    subject: "subject".into(),
                    body: body.into(),
                    mime: BodyType::Plain,
                    attachments: Vec::new(),
                },
            )
            .unwrap()
    }

    /// Post as `login` from a session that leaves straight after.
    fn post_as(&self, login: &str, parent: Option<ArticleId>, body: &str) -> ArticleId {
        self.as_absent(login, |uid| self.post(uid, parent, body))
    }

    fn subs_of(&self, login: &str) -> Vec<Subscription> {
        self.as_absent(login, |uid| self.core.news_subs(uid).unwrap())
    }
}

fn notices(rx: &mut UnboundedReceiver<SeqEvent>) -> Vec<Notified> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::NewsNotify(n) => Some(n),
            _ => None,
        })
        .collect()
}

fn thread(id: ArticleId) -> String {
    SubScope::Thread(id).key()
}

#[test]
fn a_reply_rings_the_author_and_not_the_poster() {
    let s = Server::new(NotifyPolicy::default());
    let root = s.post_as("alice", None, "a question");
    s.post_as("bob", Some(root), "an answer");
    assert_eq!(
        s.gw.sent(),
        vec![("alice".into(), NotifyReason::Reply, thread(root), 1)],
        "bob subscribed to the thread by answering, and is still not news to himself"
    );
}

#[test]
fn someone_reading_gets_the_event_and_no_push() {
    let s = Server::new(NotifyPolicy::default());
    let (alice, mut rx) = s.login("alice");
    let root = s.post(alice, None, "a question");
    let answer = s.post_as("bob", Some(root), "an answer\n\nwith a second paragraph");
    let got = notices(&mut rx);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].reason, NotifyReason::Reply);
    assert_eq!(got[0].scope, SubScope::Thread(root));
    assert_eq!((got[0].article, got[0].root), (answer, root));
    assert_eq!(got[0].from_nick, "bob");
    assert_eq!(got[0].from_login.as_deref(), Some("bob"));
    assert_eq!(got[0].excerpt, "an answer with a second paragraph");
    assert_eq!(got[0].unread, 1);
    assert!(
        s.gw.sent().is_empty(),
        "a connection is attached and it got the event"
    );
}

#[test]
fn a_detached_session_is_rung() {
    let s = Server::new(NotifyPolicy::default());
    let (alice, _rx) = s.login("alice");
    let root = s.post(alice, None, "a question");
    assert!(s.core.connection_lost(alice, 8));
    s.post_as("bob", Some(root), "an answer");
    assert_eq!(s.gw.to("alice"), 1, "the phone is what the push is for");
}

#[test]
fn a_classic_client_at_the_desk_is_not_someone_who_was_told() {
    let s = Server::new(NotifyPolicy::default());
    let (alice, _rx) = s.login_classic("alice");
    let root = s.post(alice, None, "a question");
    s.post_as("bob", Some(root), "an answer");
    assert_eq!(
        s.gw.to("alice"),
        1,
        "the legacy wire cannot show the event, so the phone is where it goes"
    );
}

#[test]
fn no_pushes_an_hour_keeps_nothing() {
    let s = Server::new(NotifyPolicy {
        max_per_hour: 0,
        ..NotifyPolicy::default()
    });
    let root = s.post_as("alice", None, "a question");
    s.post_as("bob", Some(root), "an answer");
    assert!(s.gw.sent().is_empty());
    assert!(
        s.core.news_push.lock().unwrap().is_empty(),
        "a bucket that can never fill would never be forgotten"
    );
}

#[test]
fn a_purge_in_the_servers_own_process_forgets_the_push_budget() {
    // Only there: `hxd inbox purge` runs in a process of its own and
    // never reaches these, which `news_subs_rotate` says out loud.
    let s = Server::new(NotifyPolicy {
        max_per_hour: 1,
        ..NotifyPolicy::default()
    });
    let root = s.post_as("alice", None, "a question");
    s.post_as("bob", Some(root), "an answer");
    assert_eq!(s.gw.to("alice"), 1);
    assert_eq!(s.core.news_push.lock().unwrap().len(), 1);
    s.core.inbox_purge(&Mailbox::login("alice"));
    assert!(
        s.core.news_push.lock().unwrap().is_empty(),
        "the next alice starts with a full hour, not this one's spent one"
    );
}

#[test]
fn a_replier_hears_the_next_reply() {
    // Posting's subscription is made in the post's own write, so it
    // exists before the next article does and starts at the post: the
    // next reply by someone else is the first thing it has not seen, and
    // rings.
    let s = Server::new(NotifyPolicy::default());
    let root = s.post_as("alice", None, "a question");
    s.post_as("bob", Some(root), "an answer");
    s.post_as("carol", Some(root), "another answer");
    let to_bob: Vec<_> = s.gw.sent().into_iter().filter(|n| n.0 == "bob").collect();
    assert_eq!(
        to_bob,
        vec![("bob".into(), NotifyReason::Subscription, thread(root), 1)]
    );
}

#[test]
fn a_busy_thread_rings_once_per_visit() {
    let s = Server::new(NotifyPolicy::default());
    let root = s.post_as("alice", None, "a question");
    for i in 0..3 {
        s.post_as("bob", Some(root), &format!("answer {i}"));
    }
    assert_eq!(
        s.gw.sent(),
        vec![("alice".into(), NotifyReason::Reply, thread(root), 1)],
        "told once, and not told again until she has looked"
    );
    assert_eq!(s.subs_of("alice")[0].unread, 3, "the count kept going");
    assert_eq!(
        s.as_absent("alice", |a| s.core.news_unread(a)),
        Some(3),
        "and it is the login badge"
    );

    // Saying so re-arms it.
    let left = s.as_absent("alice", |a| {
        s.core
            .news_seen(a, SubScope::Thread(root), ArticleId::MAX)
            .unwrap()
    });
    assert_eq!(left, 0);
    s.post_as("bob", Some(root), "one more");
    assert_eq!(s.gw.to("alice"), 2);
}

#[test]
fn two_scopes_ring_independently() {
    let s = Server::new(NotifyPolicy::default());
    let a = s.post_as("alice", None, "first");
    let b = s.post_as("alice", None, "second");
    s.post_as("bob", Some(a), "one");
    s.post_as("bob", Some(a), "two");
    s.post_as("bob", Some(b), "three");
    assert_eq!(
        s.gw.sent()
            .into_iter()
            .map(|(_, _, key, _)| key)
            .collect::<Vec<_>>(),
        [thread(a), thread(b)],
        "a quiet thread is not silenced by a loud one"
    );
}

#[test]
fn the_hourly_ceiling_drops_the_push_and_nothing_else() {
    let s = Server::new(NotifyPolicy {
        max_per_hour: 1,
        ..NotifyPolicy::default()
    });
    let a = s.post_as("alice", None, "first");
    let b = s.post_as("alice", None, "second");
    s.post_as("bob", Some(a), "one");
    s.post_as("bob", Some(b), "two");
    assert_eq!(s.gw.to("alice"), 1);
    let subs = s.subs_of("alice");
    assert!(
        subs.iter().all(|sub| sub.unread == 1),
        "the count is never what the ceiling drops: {subs:?}"
    );
}

#[test]
fn a_citation_rings_once_however_often_it_is_made() {
    let s = Server::new(NotifyPolicy::default());
    let a = s.post_as("carol", None, "first");
    let b = s.post_as("carol", None, "second");
    let cites = s.post_as("bob", None, &format!("see #{a}, #{b} and #{a} again"));
    assert_eq!(
        s.gw.sent(),
        vec![("carol".into(), NotifyReason::Reference, thread(cites), 1)]
    );
}

#[test]
fn a_reply_that_also_cites_says_reply() {
    let s = Server::new(NotifyPolicy::default());
    let root = s.post_as("carol", None, "a claim");
    s.post_as("bob", Some(root), &format!("as #{root} says"));
    assert_eq!(
        s.gw.sent(),
        vec![("carol".into(), NotifyReason::Reply, thread(root), 1)]
    );
}

#[test]
fn citations_can_be_told_to_stay_quiet() {
    let s = Server::new(NotifyPolicy {
        reference: false,
        ..NotifyPolicy::default()
    });
    let a = s.post_as("carol", None, "a claim");
    s.post_as("bob", None, &format!("about #{a}"));
    assert!(s.gw.sent().is_empty());
    s.post_as("bob", Some(a), "and a reply");
    assert_eq!(
        s.gw.sent(),
        vec![("carol".into(), NotifyReason::Reply, thread(a), 1)],
        "the reply and subscription paths are untouched by it"
    );
}

#[test]
fn a_muted_thread_is_silent_whatever_the_reason() {
    let s = Server::new(NotifyPolicy::default());
    let (alice, mut rx) = s.login("alice");
    let root = s.post(alice, None, "a question");
    s.core
        .news_mute(alice, SubScope::Thread(root), true)
        .unwrap();
    s.post_as("bob", Some(root), &format!("a reply citing #{root}"));
    assert!(notices(&mut rx).is_empty());
    assert!(s.gw.sent().is_empty());
}

#[test]
fn a_muted_category_silences_only_its_own_reason() {
    let s = Server::new(NotifyPolicy::default());
    let everything = SubScope::Category(s.cat);
    s.as_absent("dave", |d| s.core.news_mute(d, everything, true).unwrap());
    s.post_as("alice", None, "a new thread");
    assert!(s.gw.sent().is_empty());

    let own = s.post_as("dave", None, "dave asks");
    s.post_as("bob", Some(own), "bob answers");
    assert_eq!(
        s.gw.sent(),
        vec![("dave".into(), NotifyReason::Reply, thread(own), 1)],
        "a reply to your article is not what muting a category was about"
    );
}

#[test]
fn a_blocked_poster_rings_nobody() {
    let s = Server::new(NotifyPolicy::default());
    let root = s.as_absent("alice", |a| {
        s.core.inbox_block(a, "bob", true).unwrap();
        s.post(a, None, "a question")
    });
    s.post_as("bob", Some(root), &format!("an answer citing #{root}"));
    assert!(s.gw.sent().is_empty());
    assert_eq!(
        s.subs_of("alice")[0].unread,
        1,
        "the article is public; only the doorbell is withheld"
    );
}

#[test]
fn losing_read_news_stops_the_pushes() {
    let s = Server::new(NotifyPolicy::default());
    let root = s.post_as("alice", None, "a question");
    s.dir.0.lock().unwrap()[0].1 = AccessBits::empty().with(bit::POST_NEWS);
    s.post_as("bob", Some(root), "an answer");
    assert!(s.gw.sent().is_empty());
}

#[test]
fn a_guest_neither_follows_nor_hears() {
    let s = Server::new(NotifyPolicy::default());
    let (guest, mut rx) = s.login("guest");
    assert!(!s.core.news_may_subscribe(guest));
    assert_eq!(s.core.news_unread(guest), None);
    assert_eq!(
        s.core.news_subscribe(guest, SubScope::Category(s.cat)),
        Err(NewsError::NoMailbox)
    );
    let root = s.post(guest, None, "from nobody in particular");
    s.post_as("alice", Some(root), "a reply");
    assert!(notices(&mut rx).is_empty());
    assert!(s.gw.sent().is_empty());
}

#[test]
fn posting_subscribes_as_the_policy_says() {
    for (mode, starter, replier) in [
        (AutoSubscribe::Participated, true, true),
        (AutoSubscribe::OwnThread, true, false),
        (AutoSubscribe::Off, false, false),
    ] {
        let s = Server::new(NotifyPolicy {
            auto_subscribe: mode,
            ..NotifyPolicy::default()
        });
        let root = s.post_as("alice", None, "a question");
        s.post_as("bob", Some(root), "an answer");
        let alice = s.subs_of("alice");
        let bob = s.subs_of("bob");
        assert_eq!(!alice.is_empty(), starter, "{mode:?}: the starter");
        assert_eq!(!bob.is_empty(), replier, "{mode:?}: the replier");
        assert!(
            alice.iter().chain(&bob).all(|sub| sub.auto),
            "{mode:?}: marked as made by posting"
        );
    }
}

#[test]
fn a_category_hears_new_threads_and_not_their_replies() {
    let s = Server::new(NotifyPolicy::default());
    s.as_absent("dave", |d| {
        assert_eq!(
            s.core.news_subscribe(d, SubScope::Category(s.cat)).unwrap(),
            0
        )
    });
    let root = s.post_as("alice", None, "something new");
    assert_eq!(
        s.gw.sent(),
        vec![(
            "dave".into(),
            NotifyReason::Subscription,
            SubScope::Category(s.cat).key(),
            1
        )]
    );
    s.post_as("bob", Some(root), "a reply");
    assert_eq!(s.gw.to("dave"), 1, "a reply is the thread's business");
}

#[test]
fn one_post_has_two_audiences() {
    let s = Server::new(NotifyPolicy::default());
    let (alice, mut arx) = s.login("alice");
    let (_carol, mut crx) = s.login("carol");
    let root = s.post(alice, None, "a question");
    drain(&mut arx);
    drain(&mut crx);

    s.post_as("bob", Some(root), "an answer");
    let posted = |e: &Event| matches!(e, Event::NewsPosted { .. });
    let notify = |e: &Event| matches!(e, Event::NewsNotify(_));
    let (a, c) = (drain(&mut arx), drain(&mut crx));
    assert_eq!(a.iter().filter(|e| posted(e)).count(), 1);
    assert_eq!(a.iter().filter(|e| notify(e)).count(), 1);
    assert!(
        a.iter().position(posted) < a.iter().position(notify),
        "stale before yours"
    );
    assert_eq!(c.iter().filter(|e| posted(e)).count(), 1);
    assert!(
        !c.iter().any(notify),
        "every reader hears it changed; only its author hears it is hers"
    );
}

#[test]
fn a_server_without_subscriptions_says_so() {
    let s = Server::with(None);
    let (alice, mut rx) = s.login("alice");
    assert!(!s.core.news_may_subscribe(alice));
    assert_eq!(s.core.news_unread(alice), None);
    assert_eq!(
        s.core.news_subscribe(alice, SubScope::Category(s.cat)),
        Err(NewsError::NotifyOff)
    );
    let root = s.post(alice, None, "a question");
    s.post_as("bob", Some(root), "an answer");
    assert!(notices(&mut rx).is_empty());
    assert!(s.gw.sent().is_empty());
}

#[test]
fn linking_an_identity_takes_the_subscriptions_along() {
    let s = Server::new(NotifyPolicy::default());
    let fp = [9u8; 32];
    let root = s.post_as("alice", None, "a question");
    s.core.inbox_claim("alice", &fp);
    // As the file backend answers once the link is in alice's file.
    s.dir.0.lock().unwrap()[0].0 = Mailbox::identified("alice", fp);

    let (linked, _rx) = s.login_as("alice", Some(fp));
    assert_eq!(s.core.news_subs(linked).unwrap().len(), 1);
    s.core.end_session(linked);
    s.post_as("bob", Some(root), "an answer");
    assert_eq!(s.gw.to("alice"), 1);
}
