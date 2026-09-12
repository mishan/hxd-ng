//! Threaded news end to end: the ng wire against a real server on a real
//! loopback port, with the real SQLite store underneath and a classic
//! client in the room to prove the legacy wire is untouched by it.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::{Core, MarkdownMode, NewsPolicy, NotifyPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::Caps;
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const EVERY_NEWS_BIT: &str = "read_news = true\npost_news = true\ndelete_articles = true\n\
    create_categories = true\ndelete_categories = true\ncreate_news_bundles = true\n\
    delete_news_bundles = true\n";

fn account(name: &str, access: &str) -> String {
    format!("name = \"{name}\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n{access}")
}

/// A server with news (or without, when `news` is `None`), and the two
/// addresses its wires listen on.
async fn start_server(dir: &Path, news: Option<NewsPolicy>) -> (SocketAddr, SocketAddr) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, access) in [
        ("admin", EVERY_NEWS_BIT),
        ("alice", "read_news = true\npost_news = true\n"),
        ("bob", "read_news = true\npost_news = true\n"),
        ("lurker", "read_news = true\n"),
        ("outsider", ""),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            account(login, access),
        )
        .unwrap();
    }
    let files = Arc::new(hxd_auth_file::FileAuth::new(&accounts));
    let core = match news {
        // The accounts as well, as `hxd` wires them: who a post may
        // notify is a question about accounts nobody is logged into.
        Some(policy) => {
            let store = SqliteStore::open(dir.join("server.sqlite"), Synchronous::Normal).unwrap();
            let core = Core::new()
                .with_news(Arc::new(store), policy)
                .with_accounts(files.clone());
            // The parser `render` asks for, as `hxd` gives it one.
            if policy.markdown == MarkdownMode::Render {
                core.with_body_renderer(Arc::new(hxd_markdown::Markdown))
            } else {
                core
            }
        }
        None => Core::new(),
    };
    let core = Arc::new(core);
    let auth: Arc<dyn hxd_core::AuthBackend> = files;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "news-test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: Caps::empty(),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
        files: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "news-test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 8,
            caps: Vec::new(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
    };
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addresses = (legacy.local_addr().unwrap(), ng.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    addresses
}

fn news_server() -> NewsPolicy {
    NewsPolicy {
        max_depth: 3,
        notify: Some(NotifyPolicy::default()),
        markdown: MarkdownMode::Render,
        ..NewsPolicy::default()
    }
}

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    events: Vec<Value>,
}

impl Ng {
    async fn login(addr: SocketAddr, login: &str) -> (Self, Value) {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut client = Self {
            ws,
            next: 1,
            events: Vec::new(),
        };
        let reply = client
            .request("login", json!({ "login": login, "password": "pw" }))
            .await;
        assert!(reply.get("ok").is_some(), "{reply}");
        (client, reply["ok"].clone())
    }

    /// Come back to a detached session on a fresh socket.
    async fn resume(addr: SocketAddr, session: &str, token: &str, last_seq: u64) -> Self {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut client = Self {
            ws,
            next: 1,
            events: Vec::new(),
        };
        client
            .ok(
                "resume",
                json!({ "session": session, "token": token, "last_seq": last_seq }),
            )
            .await;
        client
    }

    async fn frame(&mut self) -> Value {
        loop {
            let message = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .expect("ng socket error");
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let value = self.frame().await;
            if value["reply"] == id {
                return value;
            }
            if value.get("seq").is_some() {
                self.events.push(value);
            }
        }
    }

    /// The `ok` of a request that must succeed.
    async fn ok(&mut self, method: &str, params: Value) -> Value {
        let reply = self.request(method, params).await;
        assert!(reply.get("ok").is_some(), "{method}: {reply}");
        reply["ok"].clone()
    }

    /// The error code of a request that must fail.
    async fn refused(&mut self, method: &str, params: Value) -> String {
        let reply = self.request(method, params).await;
        reply["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} was not refused: {reply}"))
            .to_string()
    }

    /// Wait for an event matching `pred`, looking first at what has
    /// already arrived. A predicate rather than a name, because a poster
    /// hears its own `news_posted` too.
    async fn event(&mut self, kind: &str, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(i) = self
            .events
            .iter()
            .position(|e| e["ev"] == kind && pred(&e["data"]))
        {
            return self.events.remove(i);
        }
        loop {
            let value = self.frame().await;
            if value["ev"] == kind && pred(&value["data"]) {
                return value;
            }
            if value.get("seq").is_some() {
                self.events.push(value);
            }
        }
    }

    /// Nothing named `kind` arrives: a ping round trip is the fence, since
    /// replies never overtake events the session was handed first.
    async fn no_event(&mut self, kind: &str) {
        self.request("ping", json!({})).await;
        assert!(
            !self.events.iter().any(|e| e["ev"] == kind),
            "unexpected {kind}: {:?}",
            self.events
        );
    }
}

/// Make a category (and the bundle above it, when there is one) and hand
/// back its id.
async fn category(admin: &mut Ng, parent: Option<u64>, name: &str) -> u64 {
    let ok = admin
        .ok(
            "news_node_create",
            json!({ "parent": parent, "kind": "category", "name": name }),
        )
        .await;
    ok["node"]["id"].as_u64().unwrap()
}

async fn post(
    client: &mut Ng,
    category: u64,
    parent: Option<u64>,
    subject: &str,
    body: &str,
) -> u64 {
    let ok = client
        .ok(
            "news_post",
            json!({ "category": category, "parent": parent, "subject": subject, "body": body }),
        )
        .await;
    ok["id"].as_u64().unwrap()
}

fn ids(list: &Value, key: &str) -> Vec<u64> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if key.is_empty() {
                v["id"].as_u64().unwrap()
            } else {
                v[key]["id"].as_u64().unwrap()
            }
        })
        .collect()
}

#[tokio::test]
async fn the_login_reply_says_what_this_session_may_do() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (_alice, hello) = Ng::login(ng, "alice").await;
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "news"));
    let news = &hello["news"];
    assert_eq!(news["post"], true);
    assert_eq!(news["attach"], false);
    assert_eq!(news["max_body"], 65_535);
    assert_eq!(news["max_subject"], 255);
    assert_eq!(news["max_depth"], 3);
    assert_eq!(news["markdown"], "render");
    assert_eq!(news["body_types"], json!(["text/plain", "text/markdown"]));
    assert_eq!(news["search"], true);
    assert_eq!(news["search_max_results"], 500);

    let (_lurker, hello) = Ng::login(ng, "lurker").await;
    assert_eq!(
        hello["news"]["post"], false,
        "a reader who may not post is told so"
    );
}

#[tokio::test]
async fn an_answer_reaches_whoever_asked_and_nobody_else() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, hello) = Ng::login(ng, "alice").await;
    assert_eq!(hello["news"]["subscribe"], true);
    assert_eq!(hello["news"]["auto_subscribe"], "participated");
    assert_eq!(hello["news"]["unread"], 0);
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let (mut lurker, _) = Ng::login(ng, "lurker").await;

    let cat = category(&mut admin, None, "General").await;
    let root = post(&mut alice, cat, None, "A question", "Does it ring?").await;
    // Asking followed the thread, with nothing to click.
    let subs = alice.ok("news_subs", json!({})).await;
    assert_eq!(
        subs["subs"],
        json!([{
            "scope": "thread", "target": root, "category": cat, "subject": "A question",
            "auto": true, "muted": false, "unread": 0, "last_seen": root,
        }])
    );

    let answer = post(&mut bob, cat, Some(root), "Re: A question", "It rings.").await;
    let notice = alice.event("news_notify", |d| d["article"] == answer).await;
    let d = &notice["data"];
    assert_eq!(d["reason"], "reply");
    assert_eq!(
        (d["scope"].clone(), d["target"].clone()),
        (json!("thread"), json!(root))
    );
    assert_eq!(
        (d["root"].clone(), d["category"].clone()),
        (json!(root), json!(cat))
    );
    assert_eq!(d["from"]["login"], "bob");
    assert_eq!(d["excerpt"], "It rings.");
    assert_eq!(d["unread"], 1);

    // Every reader hears that the category changed; only the asker hears
    // that the answer is hers, and the answerer is not news to himself.
    lurker.event("news_posted", |d| d["id"] == answer).await;
    lurker.no_event("news_notify").await;
    bob.no_event("news_notify").await;

    // A second answer is still hers, and the badge climbs.
    let again = post(&mut bob, cat, Some(root), "Re: A question", "Twice.").await;
    let notice = alice.event("news_notify", |d| d["article"] == again).await;
    assert_eq!(notice["data"]["unread"], 2);
    let (_, hello) = Ng::login(ng, "alice").await;
    assert_eq!(hello["news"]["unread"], 2, "the badge on the first frame");

    // Saying so is what clears it, and an id from the future is the
    // newest there is.
    let seen = alice
        .ok("news_seen", json!({ "thread": root, "up_to": u32::MAX }))
        .await;
    assert_eq!(seen["unread"], 0);
    assert_eq!(
        alice.ok("news_subs", json!({})).await["subs"][0]["last_seen"],
        again
    );
}

#[tokio::test]
async fn a_category_hears_new_threads_and_a_mute_says_never() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let (mut lurker, _) = Ng::login(ng, "lurker").await;
    let cat = category(&mut admin, None, "General").await;

    let followed = lurker
        .ok("news_subscribe", json!({ "category": cat }))
        .await;
    assert_eq!(followed["unread"], 0);
    let root = post(&mut alice, cat, None, "Something new", "Start here.").await;
    let notice = lurker.event("news_notify", |d| d["article"] == root).await;
    assert_eq!(notice["data"]["reason"], "subscription");
    assert_eq!(notice["data"]["scope"], "category");
    assert_eq!(notice["data"]["target"], cat);

    let reply = post(&mut bob, cat, Some(root), "Re: Something new", "Here.").await;
    alice.event("news_notify", |d| d["article"] == reply).await;
    lurker.event("news_posted", |d| d["id"] == reply).await;
    lurker.no_event("news_notify").await;

    // Muted: the row stays, and nothing in the thread rings.
    alice
        .ok("news_mute", json!({ "thread": root, "muted": true }))
        .await;
    let quiet = post(&mut bob, cat, Some(root), "Re: Something new", "Hello?").await;
    alice.event("news_posted", |d| d["id"] == quiet).await;
    alice.no_event("news_notify").await;
    let subs = alice.ok("news_subs", json!({})).await;
    assert_eq!(subs["subs"][0]["muted"], true);
    assert_eq!(
        subs["subs"][0]["unread"], 2,
        "a cursor without a doorbell still counts"
    );

    // Unfollowing is idempotent, and leaves nothing to list.
    for _ in 0..2 {
        lurker
            .ok("news_unsubscribe", json!({ "category": cat }))
            .await;
    }
    assert_eq!(lurker.ok("news_subs", json!({})).await["subs"], json!([]));
}

#[tokio::test]
async fn subscribing_says_why_not() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut outsider, hello) = Ng::login(ng, "outsider").await;
    assert_eq!(hello["news"]["subscribe"], false);
    assert!(hello["news"].get("unread").is_none());
    let cat = category(&mut admin, None, "General").await;
    let root = post(&mut alice, cat, None, "Root", "body").await;
    let reply = post(&mut alice, cat, Some(root), "Re: Root", "reply").await;

    for (method, params, code) in [
        ("news_subscribe", json!({}), "bad_request"),
        (
            "news_subscribe",
            json!({ "thread": root, "category": cat }),
            "bad_request",
        ),
        (
            "news_subscribe",
            json!({ "thread": reply }),
            "no_such_article",
        ),
        ("news_subscribe", json!({ "category": 999 }), "no_such_node"),
        // The requests that make no row refuse a scope that names
        // nothing as well.
        (
            "news_unsubscribe",
            json!({ "thread": reply }),
            "no_such_article",
        ),
        (
            "news_unsubscribe",
            json!({ "category": 999 }),
            "no_such_node",
        ),
        (
            "news_mute",
            json!({ "category": 999, "muted": false }),
            "no_such_node",
        ),
        (
            "news_seen",
            json!({ "thread": reply, "up_to": reply }),
            "no_such_article",
        ),
        ("news_mute", json!({ "thread": root }), "bad_request"),
        ("news_seen", json!({ "thread": root }), "bad_request"),
        ("news_subscribe", json!({ "thread": "one" }), "bad_request"),
    ] {
        assert_eq!(
            alice.refused(method, params.clone()).await,
            code,
            "{method} {params}"
        );
    }
    assert_eq!(
        outsider
            .refused("news_subscribe", json!({ "category": cat }))
            .await,
        "access_denied"
    );
    assert_eq!(
        alice
            .ok("news_seen", json!({ "category": cat, "up_to": root }))
            .await["unread"],
        0,
        "seeing what you do not follow is nothing to refuse"
    );
    // Nor is leaving what you never followed, so long as it is there.
    alice
        .ok("news_unsubscribe", json!({ "category": cat }))
        .await;
    alice
        .ok("news_mute", json!({ "category": cat, "muted": false }))
        .await;

    // A server that keeps no subscriptions says so, and offers none.
    let quiet = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(
        quiet.path(),
        Some(NewsPolicy {
            notify: None,
            ..news_server()
        }),
    )
    .await;
    let (mut alice, hello) = Ng::login(ng, "alice").await;
    assert_eq!(hello["news"]["subscribe"], false);
    assert!(hello["news"].get("auto_subscribe").is_none());
    assert_eq!(alice.refused("news_subs", json!({})).await, "not_available");
}

#[tokio::test]
async fn a_markdown_article_is_kept_as_written_and_read_as_text() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let cat = category(&mut admin, None, "General").await;
    let sizes = post(&mut bob, cat, None, "Sizes", "The numbers.").await;
    let other = post(&mut bob, cat, None, "Other", "More numbers.").await;
    let quoted = post(&mut bob, cat, None, "Quoted", "Only ever in code.").await;

    let body = format!(
        "# Settled\n\nIn [the sizes thread](news:{sizes}) and **#{other}**, \
         not `#{quoted}`:\n\n```\n#{quoted}\n```\n"
    );
    let summary = alice
        .ok(
            "news_post",
            json!({ "category": cat, "parent": sizes, "subject": "Re: Sizes",
                    "body": body, "mime": "text/markdown" }),
        )
        .await["id"]
        .as_u64()
        .unwrap();

    let article = alice.ok("news_article", json!({ "id": summary })).await["article"].clone();
    assert_eq!(article["mime"], "text/markdown");
    assert_eq!(article["body"], body, "kept exactly as typed");
    assert_eq!(
        ids(&article["refs"], ""),
        [sizes, other],
        "a news: link and the shorthand, and nothing quoted as code"
    );

    // What the replied-to author is told is text, not syntax.
    let notice = bob.event("news_notify", |d| d["article"] == summary).await;
    let excerpt = notice["data"]["excerpt"].as_str().unwrap().to_string();
    assert!(
        excerpt.starts_with(&format!(
            "Settled In the sizes thread (news #{sizes}) and #{other}"
        )),
        "{excerpt}"
    );
    assert!(!excerpt.contains("**"), "{excerpt}");

    // And what search reads is the downgrade: found by its words, and
    // snipped without its asterisks.
    let found = alice
        .ok("news_search", json!({ "q": "settled", "order": "recent" }))
        .await;
    assert_eq!(ids(&found["hits"], ""), [summary]);
    let snippet = found["hits"][0]["snippet"].as_str().unwrap();
    assert!(
        !snippet.contains("**") && !snippet.contains("# "),
        "{snippet}"
    );

    // A reference definition cited over and over repeats its destination
    // each time, so this downgrade runs past what a body may be. Search
    // still reads all of it; cutting it to size is the legacy edge's job.
    let url = format!("https://hl.example/{}", "a".repeat(1_000));
    let long = format!("{} farthest\n\n[r]: {url}\n", "[r] ".repeat(100));
    assert!(long.len() < 65_535 && 100 * url.len() > 65_535);
    let expanded = alice
        .ok(
            "news_post",
            json!({ "category": cat, "subject": "Long", "body": long, "mime": "text/markdown" }),
        )
        .await["id"]
        .as_u64()
        .unwrap();
    let found = alice
        .ok("news_search", json!({ "q": "farthest", "order": "recent" }))
        .await;
    assert_eq!(ids(&found["hits"], ""), [expanded]);

    // A body nested past what a parse can afford is refused before it is
    // parsed, however small it is.
    let deep = format!("{}a\n{}", "- ".repeat(1_000), "\n".repeat(1_000));
    assert_eq!(
        alice
            .refused(
                "news_post",
                json!({ "category": cat, "subject": "Deep", "body": deep, "mime": "text/markdown" }),
            )
            .await,
        "bad_request"
    );

    // A server that takes plain text only says so up front and refuses
    // the rest.
    let plain = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(
        plain.path(),
        Some(NewsPolicy {
            markdown: MarkdownMode::Off,
            ..news_server()
        }),
    )
    .await;
    let (mut admin, hello) = Ng::login(ng, "admin").await;
    assert_eq!(hello["news"]["markdown"], "off");
    assert_eq!(hello["news"]["body_types"], json!(["text/plain"]));
    let cat = category(&mut admin, None, "General").await;
    assert_eq!(
        admin
            .refused(
                "news_post",
                json!({ "category": cat, "subject": "s", "body": "**x**", "mime": "text/markdown" }),
            )
            .await,
        "bad_body_type"
    );
}

#[tokio::test]
async fn a_server_without_news_answers_no_news() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), None).await;
    let (mut alice, hello) = Ng::login(ng, "alice").await;
    assert!(!hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "news"));
    assert!(hello.get("news").is_none());
    assert_eq!(alice.refused("news_tree", json!({})).await, "no_news");
    assert_eq!(
        alice.refused("news_post", json!({ "garbage": true })).await,
        "no_news",
        "about the server, before anything about the request"
    );
}

#[tokio::test]
async fn a_thread_comes_back_in_the_order_it_reads() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;

    let bundle = admin
        .ok(
            "news_node_create",
            json!({ "kind": "bundle", "name": "Projects" }),
        )
        .await["node"]["id"]
        .as_u64()
        .unwrap();
    let cat = category(&mut admin, Some(bundle), "hxd-ng").await;

    let root = post(&mut alice, cat, None, "Phase 4 is open", "News, finally.").await;
    let first = post(
        &mut bob,
        cat,
        Some(root),
        "Re: Phase 4 is open",
        "About time.",
    )
    .await;
    let second = post(
        &mut alice,
        cat,
        Some(root),
        "Re: Phase 4 is open",
        "Attachments?",
    )
    .await;
    let late = post(
        &mut alice,
        cat,
        Some(first),
        "Re: Re: Phase 4 is open",
        "Ha.",
    )
    .await;

    let thread = alice.ok("news_thread", json!({ "root": root })).await;
    assert_eq!(ids(&thread["articles"], ""), [root, first, late, second]);
    assert_eq!(thread["has_more"], false);
    let starter = &thread["articles"][0];
    assert_eq!(starter["parent"], Value::Null);
    assert_eq!(starter["root"], root);
    assert_eq!(starter["depth"], 0);
    assert_eq!(starter["category"], cat);
    assert_eq!(starter["from"]["nick"], "alice");
    assert_eq!(starter["from"]["login"], "alice");
    assert!(
        starter["from"].get("fingerprint").is_none(),
        "no identity, no key"
    );
    assert_eq!(starter["subject"], "Phase 4 is open");
    assert_eq!(starter["body"], "News, finally.");
    assert_eq!(starter["mime"], "text/plain");
    assert_eq!(starter["deleted"], false);
    assert_eq!(starter["attachments"], json!([]));
    assert!(starter["at"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(thread["articles"][2]["depth"], 2);
    assert_eq!(thread["articles"][2]["parent"], first);

    let listing = bob.ok("news_threads", json!({ "category": cat })).await;
    let head = &listing["threads"][0];
    assert_eq!(head["article"]["id"], root);
    assert_eq!(
        head["article"]["body"], "News, finally.",
        "the starter comes whole"
    );
    assert_eq!(head["replies"], 3);
    assert_eq!(head["last_id"], late);

    let tree = bob.ok("news_tree", json!({ "depth": 2 })).await;
    assert_eq!(tree["nodes"][0]["name"], "Projects");
    assert_eq!(tree["nodes"][0]["kind"], "bundle");
    assert_eq!(tree["nodes"][0]["count"], 1);
    let inner = &tree["nodes"][0]["children"][0];
    assert_eq!(inner["name"], "hxd-ng");
    assert_eq!(inner["count"], 4);
    assert!(
        inner.get("children").is_none(),
        "a category holds articles, not nodes"
    );

    let one = bob.ok("news_article", json!({ "id": late })).await;
    assert_eq!(one["article"]["body"], "Ha.");
    assert_eq!(
        bob.refused("news_article", json!({ "id": 99_999 })).await,
        "no_such_article"
    );
    assert_eq!(
        bob.refused("news_thread", json!({ "root": first })).await,
        "no_such_article",
        "a reply is not a thread"
    );
}

#[tokio::test]
async fn pages_move_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let cat = category(&mut admin, None, "General").await;
    let mut threads = Vec::new();
    for n in 1..=5 {
        threads.push(post(&mut admin, cat, None, &format!("thread {n}"), "body").await);
    }
    let [t1, t2, t3, t4, t5] = threads[..] else {
        unreachable!()
    };

    let newest = admin
        .ok("news_threads", json!({ "category": cat, "limit": 2 }))
        .await;
    assert_eq!(ids(&newest["threads"], "article"), [t5, t4]);
    assert_eq!(newest["has_more"], true);
    let older = admin
        .ok(
            "news_threads",
            json!({ "category": cat, "before": t4, "limit": 2 }),
        )
        .await;
    assert_eq!(ids(&older["threads"], "article"), [t3, t2]);
    let newer = admin
        .ok(
            "news_threads",
            json!({ "category": cat, "after": t1, "limit": 2 }),
        )
        .await;
    assert_eq!(ids(&newer["threads"], "article"), [t3, t2]);
    assert_eq!(newer["has_more"], true);

    let r1 = post(&mut admin, cat, Some(t1), "re", "1").await;
    let r2 = post(&mut admin, cat, Some(r1), "re", "2").await;
    let r3 = post(&mut admin, cat, Some(t1), "re", "3").await;
    let r4 = post(&mut admin, cat, Some(r3), "re", "4").await;
    let page = admin
        .ok("news_thread", json!({ "root": t1, "limit": 2 }))
        .await;
    assert_eq!(ids(&page["articles"], ""), [t1, r1]);
    assert_eq!(page["has_more"], true);
    let snapshot = page["snapshot"].as_u64().unwrap();
    assert_eq!(snapshot, r4);
    let late = post(&mut admin, cat, Some(r1), "re", "late").await;
    assert_eq!(
        admin
            .refused("news_thread", json!({ "root": t1, "after": r1 }))
            .await,
        "bad_request"
    );
    let rest = admin
        .ok(
            "news_thread",
            json!({ "root": t1, "after": r1, "snapshot": snapshot, "limit": 10 }),
        )
        .await;
    assert_eq!(ids(&rest["articles"], ""), [r2, r3, r4]);
    assert_eq!(rest["has_more"], false);
    assert_eq!(rest["snapshot"], snapshot);
    let fresh = admin
        .ok("news_thread", json!({ "root": t1, "limit": 10 }))
        .await;
    assert_eq!(ids(&fresh["articles"], ""), [t1, r1, r2, late, r3, r4]);
}

#[tokio::test]
async fn readers_hear_that_the_news_changed_and_nobody_else_does() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut lurker, _) = Ng::login(ng, "lurker").await;
    let (mut outsider, _) = Ng::login(ng, "outsider").await;
    // A 1.5 client in the same room. The legacy news binding is a later
    // stage; until then this wire must simply not notice any of it.
    let mut classic = Classic::login(legacy, "classic").await;

    let cat = category(&mut admin, None, "General").await;
    let node = lurker.event("news_node", |d| d["node"]["id"] == cat).await;
    assert_eq!(node["data"]["node"]["kind"], "category");

    let root = post(&mut admin, cat, None, "Hello", "first").await;
    let heard = lurker.event("news_posted", |d| d["id"] == root).await;
    assert_eq!(
        heard["data"],
        json!({
            "id": root,
            "category": cat,
            "root": root,
            "parent": null,
            "subject": "Hello",
            "from": { "nick": "admin" },
            "at": heard["data"]["at"],
            "attachments": 0,
        })
    );
    assert!(heard["seq"].as_u64().is_some());
    admin.event("news_posted", |d| d["id"] == root).await;

    admin.ok("news_delete", json!({ "id": root })).await;
    lurker
        .event("news_deleted", |d| d["id"] == root && d["category"] == cat)
        .await;

    outsider.no_event("news_posted").await;
    outsider.no_event("news_node").await;
    assert_eq!(
        outsider.refused("news_tree", json!({})).await,
        "access_denied"
    );
    assert_eq!(
        outsider
            .refused("news_threads", json!({ "category": cat }))
            .await,
        "access_denied"
    );

    // The echo is the fence: the classic client's writer sends in order,
    // so anything the news had made it send is already passed over.
    classic.chat(b"still here").await;
    // The agreement and access bits that follow a login, and the user
    // list: nothing else.
    let about_the_room = [0x006d, 0x0162, 0x012d, 0x012e];
    assert!(
        classic.passed.iter().all(|ty| about_the_room.contains(ty)),
        "the legacy wire heard something besides the room: {:#x?}",
        classic.passed
    );
}

#[tokio::test]
async fn a_detached_reader_hears_the_news_on_resume_with_no_gap() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    // The classic client is the fence: it sees the reader arrive, and
    // then go away.
    let mut classic = Classic::login(legacy, "classic").await;
    let (lurker, hello) = Ng::login(ng, "lurker").await;
    let session = hello["session"].as_str().unwrap().to_string();
    let token = hello["token"].as_str().unwrap().to_string();
    let last_seq = hello["seq"].as_u64().unwrap();
    classic.recv(0x012d).await;

    // An account with a password detaches rather than leaving, so the
    // news goes on into its outbox while nobody is reading it. Only once
    // the server has noticed, though: until then an event is handed to
    // the dead socket, and a resume rightly calls that a gap.
    drop(lurker);
    classic.recv(0x012d).await;
    let cat = category(&mut admin, None, "General").await;
    let root = post(&mut admin, cat, None, "While you were out", "hello").await;

    let mut lurker = Ng::resume(ng, &session, &token, last_seq).await;
    let node = lurker.event("news_node", |d| d["node"]["id"] == cat).await;
    let posted = lurker.event("news_posted", |d| d["id"] == root).await;
    lurker.request("ping", json!({})).await;
    // Everything replayed, the news and whatever else there was, is one
    // unbroken run of seqs from where the reader left off.
    let mut seqs: Vec<u64> = [&node, &posted]
        .into_iter()
        .chain(&lurker.events)
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    seqs.sort_unstable();
    let run: Vec<u64> = (last_seq + 1..).take(seqs.len()).collect();
    assert_eq!(seqs, run);
}

#[tokio::test]
async fn a_reference_resolves_once_and_reports_its_target_now() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let cat = category(&mut admin, None, "General").await;
    let elsewhere = category(&mut admin, None, "Elsewhere").await;

    let cited = post(&mut alice, elsewhere, None, "Attachment sizes", "Numbers.").await;
    let citing = post(
        &mut bob,
        cat,
        None,
        "Sizes",
        &format!("Settled in #{cited}, and #99999 names nothing."),
    )
    .await;

    let article = bob.ok("news_article", json!({ "id": citing })).await["article"].clone();
    assert_eq!(
        article["refs"],
        json!([{
            "id": cited,
            "subject": "Attachment sizes",
            "from": "alice",
            "at": article["refs"][0]["at"],
            "deleted": false,
        }])
    );
    assert_eq!(
        article["body"],
        format!("Settled in #{cited}, and #99999 names nothing."),
        "the body is stored exactly as typed"
    );
    let target = bob.ok("news_article", json!({ "id": cited })).await;
    assert_eq!(target["article"]["referenced_by"], 1);
    let back = bob.ok("news_refs", json!({ "id": cited })).await;
    assert_eq!(ids(&back["referenced_by"], ""), [citing]);

    alice.ok("news_delete", json!({ "id": cited })).await;
    let article = bob.ok("news_article", json!({ "id": citing })).await["article"].clone();
    assert_eq!(article["refs"][0]["id"], cited);
    assert_eq!(
        article["refs"][0]["deleted"], true,
        "the link says its target is gone"
    );
    assert!(article["refs"][0].get("subject").is_none());
}

#[tokio::test]
async fn deleting_leaves_a_tombstone_and_asks_whose_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let cat = category(&mut admin, None, "General").await;
    let root = post(&mut alice, cat, None, "Mine", "alice wrote this").await;
    let reply = post(&mut bob, cat, Some(root), "Re: Mine", "bob answered").await;

    assert_eq!(
        bob.refused("news_delete", json!({ "id": root })).await,
        "access_denied"
    );
    alice.ok("news_delete", json!({ "id": root })).await;
    assert_eq!(
        alice.refused("news_delete", json!({ "id": root })).await,
        "no_such_article"
    );

    let thread = bob.ok("news_thread", json!({ "root": root })).await;
    assert_eq!(
        ids(&thread["articles"], ""),
        [root, reply],
        "the reply stays put"
    );
    let stone = &thread["articles"][0];
    assert_eq!(stone["deleted"], true);
    assert_eq!(stone["subject"], "");
    assert_eq!(stone["body"], "");
    assert_eq!(stone["from"], json!({ "nick": "" }));
    assert_eq!(thread["articles"][1]["body"], "bob answered");

    // A moderator's bit reaches anyone's.
    admin.ok("news_delete", json!({ "id": reply })).await;
    let listing = bob.ok("news_threads", json!({ "category": cat })).await;
    assert!(
        listing["threads"].as_array().unwrap().is_empty(),
        "a thread of nothing but tombstones is not listed"
    );
}

#[tokio::test]
async fn the_tree_keeps_the_legacy_wires_rules() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;

    let bundle = admin
        .ok(
            "news_node_create",
            json!({ "kind": "bundle", "name": "Bundle" }),
        )
        .await["node"]["id"]
        .as_u64()
        .unwrap();
    let cat = category(&mut admin, Some(bundle), "Inside").await;
    let other = category(&mut admin, None, "Other").await;

    assert_eq!(
        admin
            .refused(
                "news_node_create",
                json!({ "kind": "category", "name": "Other" })
            )
            .await,
        "name_taken"
    );
    assert_eq!(
        admin
            .refused(
                "news_node_create",
                json!({ "parent": cat, "kind": "category", "name": "Nested" })
            )
            .await,
        "not_a_category"
    );
    assert_eq!(
        admin
            .refused(
                "news_post",
                json!({ "category": bundle, "subject": "s", "body": "b" })
            )
            .await,
        "not_a_category"
    );
    assert_eq!(
        admin
            .refused(
                "news_post",
                json!({ "category": 99_999, "subject": "s", "body": "b" })
            )
            .await,
        "no_such_node"
    );

    let root = post(&mut alice, cat, None, "Deep", "0").await;
    let mut parent = root;
    for n in 1..=3 {
        parent = post(&mut alice, cat, Some(parent), "Re", &n.to_string()).await;
    }
    assert_eq!(
        alice
            .refused(
                "news_post",
                json!({ "category": cat, "parent": parent, "subject": "Re", "body": "4" })
            )
            .await,
        "too_deep"
    );
    assert_eq!(
        alice
            .refused(
                "news_post",
                json!({ "category": other, "parent": root, "subject": "Re", "body": "x" })
            )
            .await,
        "wrong_category"
    );

    assert_eq!(
        alice
            .refused(
                "news_node_create",
                json!({ "kind": "category", "name": "Mine" })
            )
            .await,
        "access_denied"
    );
    admin
        .ok(
            "news_node_rename",
            json!({ "id": other, "name": "Renamed" }),
        )
        .await;
    assert_eq!(
        admin
            .refused(
                "news_node_rename",
                json!({ "id": bundle, "name": "Renamed" })
            )
            .await,
        "name_taken",
        "unique among siblings"
    );
    // One level down is a different address, so the same name is free.
    admin
        .ok("news_node_rename", json!({ "id": cat, "name": "Renamed" }))
        .await;

    assert_eq!(
        admin
            .refused("news_node_delete", json!({ "id": bundle }))
            .await,
        "not_empty"
    );
    let gone = admin.ok("news_node_delete", json!({ "id": cat })).await;
    assert_eq!(gone["articles"], 4);
    admin.ok("news_node_delete", json!({ "id": bundle })).await;
}

#[tokio::test]
async fn malformed_requests_are_answered_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let cat = category(&mut admin, None, "General").await;

    let cases = [
        (
            "news_post",
            json!({ "category": cat, "body": "no subject" }),
            "bad_request",
        ),
        (
            "news_post",
            json!({ "category": cat, "subject": " ", "body": "x" }),
            "bad_request",
        ),
        (
            "news_post",
            json!({ "category": cat, "subject": "s", "body": "x", "mime": "text/html" }),
            "bad_request",
        ),
        (
            "news_post",
            json!({ "category": cat, "subject": "s", "body": "x", "attach": ["abc"] }),
            "no_such_media",
        ),
        (
            "news_post",
            json!({ "category": cat, "subject": "s".repeat(256), "body": "x" }),
            "bad_request",
        ),
        (
            "news_post",
            json!({ "category": cat, "subject": "s", "body": "x".repeat(65_536) }),
            "bad_request",
        ),
        ("news_tree", json!({ "depth": 5 }), "bad_request"),
        (
            "news_threads",
            json!({ "category": cat, "limit": 0 }),
            "bad_request",
        ),
        (
            "news_threads",
            json!({ "category": cat, "order": "recent" }),
            "bad_request",
        ),
        (
            "news_node_create",
            json!({ "kind": "folder", "name": "x" }),
            "bad_request",
        ),
        (
            "news_node_create",
            json!({ "kind": "category", "name": "a\nb" }),
            "bad_request",
        ),
        ("news_whatever", json!({}), "unknown_method"),
    ];
    for (method, params, code) in cases {
        assert_eq!(
            admin.refused(method, params.clone()).await,
            code,
            "{method} {params}"
        );
    }
}

/// The text a mark covers, sliced the way a JSON client slices: in UTF-16
/// code units, which is what the wire promises the offsets are.
fn marked(hit: &Value) -> Vec<String> {
    let units: Vec<u16> = hit["snippet"].as_str().unwrap().encode_utf16().collect();
    hit["marks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let (a, b) = (
                m[0].as_u64().unwrap() as usize,
                m[1].as_u64().unwrap() as usize,
            );
            String::from_utf16(&units[a..b]).unwrap()
        })
        .collect()
}

#[tokio::test]
async fn a_search_finds_what_was_posted_and_says_where() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(dir.path(), Some(news_server())).await;
    let (mut admin, _) = Ng::login(ng, "admin").await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;
    let bundle = admin
        .ok(
            "news_node_create",
            json!({ "kind": "bundle", "name": "Projects" }),
        )
        .await["node"]["id"]
        .as_u64()
        .unwrap();
    let inside = category(&mut admin, Some(bundle), "hxd-ng").await;
    let outside = category(&mut admin, None, "Elsewhere").await;

    let sizes = post(
        &mut alice,
        inside,
        None,
        "Attachment sizes",
        "Ünïcødé 🎈 first: the derivative is a u16.",
    )
    .await;
    let reply = post(
        &mut bob,
        inside,
        Some(sizes),
        "Re: Attachment sizes",
        "A derivative of a derivative.",
    )
    .await;
    let away = post(&mut bob, outside, None, "Derivative works", "Licensing.").await;

    let page = bob.ok("news_search", json!({ "q": "derivative" })).await;
    assert_eq!(page["total"], 3);
    assert_eq!(page["capped"], false);
    assert_eq!(
        ids(&page["hits"], "").first(),
        Some(&away),
        "a match in the subject outranks one in the body"
    );
    let hit = page["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == sizes)
        .unwrap()
        .clone();
    assert_eq!(hit["root"], sizes);
    assert_eq!(hit["category"], inside);
    assert_eq!(hit["subject"], "Attachment sizes");
    assert_eq!(hit["from"], "alice");
    assert!(hit["at"].as_u64().is_some());
    assert_eq!(
        marked(&hit),
        ["derivative"],
        "marks are UTF-16 offsets, past the accents and the balloon"
    );
    let the_reply = page["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == reply)
        .unwrap()
        .clone();
    assert_eq!(the_reply["root"], sizes, "a hit says which thread to open");

    let scoped = bob
        .ok(
            "news_search",
            json!({ "q": "derivative", "category": bundle }),
        )
        .await;
    let mut in_bundle = ids(&scoped["hits"], "");
    in_bundle.sort_unstable();
    assert_eq!(
        in_bundle,
        [sizes, reply],
        "a bundle is every category under it"
    );
    let by = bob
        .ok("news_search", json!({ "q": "", "from": "alice" }))
        .await;
    assert_eq!(ids(&by["hits"], ""), [sizes]);
    let recent = bob
        .ok(
            "news_search",
            json!({ "q": "derivative", "order": "recent", "limit": 2 }),
        )
        .await;
    assert_eq!(ids(&recent["hits"], ""), [away, reply]);
    let next = bob
        .ok(
            "news_search",
            json!({ "q": "derivative", "order": "recent", "limit": 2, "offset": 2 }),
        )
        .await;
    assert_eq!(ids(&next["hits"], ""), [sizes]);

    // Nothing anyone types is an error.
    for q in ["\"", "(OR", "-", "subject:", "NEAR/3 *", "💥"] {
        bob.ok("news_search", json!({ "q": q })).await;
    }

    alice.ok("news_delete", json!({ "id": sizes })).await;
    let after = bob.ok("news_search", json!({ "q": "u16" })).await;
    assert_eq!(
        after["total"], 0,
        "a deleted article cannot be found by its words"
    );
}

#[tokio::test]
async fn search_is_rationed_and_can_be_off() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(
        dir.path(),
        Some(NewsPolicy {
            search_per_minute: 2,
            ..news_server()
        }),
    )
    .await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    alice.ok("news_search", json!({ "q": "x" })).await;
    alice.ok("news_search", json!({ "q": "x" })).await;
    assert_eq!(
        alice.refused("news_search", json!({ "q": "x" })).await,
        "rate_limited"
    );
    assert_eq!(
        alice
            .refused("news_search", json!({ "q": "x", "order": "sideways" }))
            .await,
        "bad_request"
    );
    assert_eq!(
        alice
            .refused("news_search", json!({ "q": "x", "limit": 0 }))
            .await,
        "bad_request"
    );
    assert_eq!(alice.refused("news_search", json!({})).await, "bad_request");
    // A date past what the clock can hold is answered, and the session
    // is still there to ask again.
    for field in ["before", "after"] {
        let mut params = json!({ "q": "x" });
        params[field] = json!(u64::MAX);
        assert_eq!(
            alice.refused("news_search", params).await,
            "bad_request",
            "{field}"
        );
    }
    alice.request("ping", json!({})).await;

    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(
        dir.path(),
        Some(NewsPolicy {
            search: false,
            ..news_server()
        }),
    )
    .await;
    let (mut alice, hello) = Ng::login(ng, "alice").await;
    assert_eq!(hello["news"]["search"], false);
    assert_eq!(
        alice.refused("news_search", json!({ "q": "x" })).await,
        "not_available"
    );
}

/// Just enough of a 1.5 client to be in the room.
struct Classic {
    stream: TcpStream,
    trans: u32,
    /// The type of every frame `recv` passed over on its way to the one
    /// it was waiting for, so a test can say what else arrived.
    passed: Vec<u32>,
}

impl Classic {
    async fn login(addr: SocketAddr, nick: &str) -> Self {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let chunks = vec![
            (tag::NAME, nick.as_bytes().to_vec()),
            (tag::ICON, 128u16.to_be_bytes().to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ];
        stream
            .write_all(&pack_frame(0x6b, 1, 0, &chunks))
            .await
            .unwrap();
        let mut client = Self {
            stream,
            trans: 1,
            passed: Vec::new(),
        };
        let reply = client.recv(0x0001_0000).await;
        assert_eq!(reply.flag, 0);
        client
    }

    async fn recv(&mut self, ty: u32) -> Frame {
        for _ in 0..64 {
            let frame = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("legacy timed out")
                .expect("legacy closed");
            if frame.ty == ty {
                return frame;
            }
            self.passed.push(frame.ty);
        }
        panic!("legacy frame {ty:#x} did not arrive");
    }

    async fn chat(&mut self, text: &[u8]) {
        self.trans += 1;
        self.stream
            .write_all(&pack_frame(
                0x69,
                self.trans,
                0,
                &[(tag::BODY, text.to_vec())],
            ))
            .await
            .unwrap();
        let echo = self.recv(0x6a).await;
        assert!(echo.chunks().any(|c| c.tag == tag::BODY));
    }
}
