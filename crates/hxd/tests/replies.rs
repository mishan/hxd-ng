//! Replies on the ng wire (`docs/hotline-ng.md` §7.3): `re` on `chat`
//! and `msg`, kept and relayed as sent to sessions that declared
//! `replies`, held to the conversation it is sent in, and `history`'s
//! `ids`, between scripted clients on a real server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, HistoryPolicy, InboxPolicy, MessagingPolicy, ModerationPolicy, RoomPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::ng::{Client, Resumed};
use hxd_testclient::Error;
use serde_json::{json, Value};

/// History, mail, messaging, moderation and rooms, on one SQLite file.
/// `carol` moderates and `boss` makes rooms.
async fn start(dir: &Path) -> SocketAddr {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    // `erin` takes no part in messaging, so mail by login reaches her
    // inbox rather than becoming a request.
    for (login, extra) in [
        ("alice", "messaging = true\n"),
        ("bob", "messaging = true\n"),
        ("dave", "messaging = true\n"),
        ("erin", ""),
        ("carol", "messaging = true\ndisconnect_users = true\n"),
        ("boss", "messaging = true\n[extra]\nmanage_rooms = true\n"),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                 send_chat = true\nsend_msgs = true\nread_chat_history = true\n{extra}"
            ),
        )
        .unwrap();
    }
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let core = Core::new()
        .with_inbox(store.clone(), auth.clone(), InboxPolicy::default())
        .with_relationships(store.clone())
        .with_messaging(MessagingPolicy {
            enabled: true,
            presence_debounce: Duration::from_millis(50),
            ..MessagingPolicy::default()
        })
        .with_history(
            store.clone(),
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        )
        .with_moderation(store, ModerationPolicy::default())
        .with_rooms(
            Arc::new(hxd::rooms::FileRooms::new(&dir.join("rooms.toml"))),
            RoomPolicy::default(),
        )
        .unwrap();
    let core = Arc::new(core);
    tokio::spawn(hxd::presence_flusher(core.clone()));
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "replies".into(),
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 4,
            caps: vec!["history".into(), "inbox".into()],
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: None,
        banner: None,
        metrics: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hxd_ng_session::serve(listener, ng_ctx));
    addr
}

/// A client, declaring `replies` or not, and its login reply.
async fn login(addr: SocketAddr, who: &str, replies: bool) -> (Client, Value) {
    let mut c = Client::connect(addr).await.unwrap();
    let hello = c
        .login(json!({
            "login": who, "password": "pw", "nick": who,
            "messaging": true, "replies": replies,
        }))
        .await
        .unwrap();
    (c, hello)
}

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn refused(c: &mut Client, req: &str, params: Value) -> String {
    match c.request(req, params).await {
        Err(Error::Refused { code, .. }) => code,
        other => panic!("{req} was not refused: {other:?}"),
    }
}

async fn event(c: &mut Client, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
    c.event_where(ev, pred)
        .await
        .unwrap_or_else(|e| panic!("no {ev}: {e:?}"))
        .data
}

async fn say(c: &mut Client, params: Value) -> u64 {
    ok(c, "chat", params).await["id"].as_u64().unwrap()
}

fn guid(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
}

#[tokio::test]
async fn a_reply_to_a_line_reaches_the_readers_that_asked_and_the_text_alone_the_rest() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut alice, hello) = login(addr, "alice", true).await;
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("replies")));
    assert_eq!(hello["replies"], json!({ "targets": ["line", "pm", "im"] }));
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut dave, hello) = login(addr, "dave", false).await;
    assert!(!hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("replies")));
    assert!(hello.get("replies").is_none());

    let asked = say(&mut alice, json!({ "text": "lunch?" })).await;
    let re = json!({ "line": asked });
    say(&mut bob, json!({ "text": "yes", "re": re })).await;
    let heard = event(&mut alice, "chat", |d| d["text"] == "yes").await;
    assert_eq!(heard["re"], re);
    let plain = event(&mut dave, "chat", |d| d["text"] == "yes").await;
    assert!(plain.get("re").is_none(), "{plain}");

    // Never refused for pointing at nothing, and a sender that did not
    // declare `replies` has its `re` ignored.
    let never = json!({ "line": asked + 1000 });
    say(&mut bob, json!({ "text": "dangling", "re": never })).await;
    say(&mut dave, json!({ "text": "unasked", "re": re })).await;
    assert_eq!(
        event(&mut alice, "chat", |d| d["text"] == "dangling").await["re"],
        never
    );
    let unasked = event(&mut alice, "chat", |d| d["text"] == "unasked").await;
    assert!(unasked.get("re").is_none(), "{unasked}");

    let page = json!({ "after": asked - 1 });
    let lines = ok(&mut alice, "history", page.clone()).await["lines"].clone();
    assert_eq!(
        lines
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["re"].clone())
            .collect::<Vec<_>>(),
        [Value::Null, re.clone(), never, Value::Null]
    );
    let lines = ok(&mut dave, "history", page).await["lines"].clone();
    assert!(lines
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l.get("re").is_none()));
}

#[tokio::test]
async fn a_reply_across_rooms_or_conversations_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss", true).await;
    let room = ok(&mut boss, "room_create", json!({ "name": "lounge" })).await["room"]["id"]
        .as_u64()
        .unwrap();
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (dave, _) = login(addr, "dave", true).await;
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    let lobby = say(&mut alice, json!({ "text": "in the lobby" })).await;
    let sent = ok(
        &mut alice,
        "msg",
        json!({ "to": bob.uid, "text": "psst", "guid": guid(1) }),
    )
    .await;
    let between = sent["ref"].clone();

    for (case, req, params) in [
        (
            "a lobby line from a room",
            "chat",
            json!({ "text": "x", "room": room, "re": { "line": lobby } }),
        ),
        (
            "a room's line from the lobby",
            "chat",
            json!({ "text": "x", "re": { "line": lobby, "room": room } }),
        ),
        (
            "a message from public chat",
            "chat",
            json!({ "text": "x", "re": { "pm": between } }),
        ),
        (
            "a line from a message",
            "msg",
            json!({ "to": bob.uid, "text": "x", "re": { "line": lobby } }),
        ),
        (
            "a third party's instant message",
            "msg",
            json!({ "to": bob.uid, "text": "x",
                    "re": { "im": { "login": "dave", "guid": guid(2) } } }),
        ),
        (
            "a malformed target",
            "chat",
            json!({ "text": "x", "re": { "line": "one" } }),
        ),
    ] {
        assert_eq!(
            refused(&mut alice, req, params).await,
            "bad_request",
            "{case}"
        );
    }
    // A signed line has nowhere to bind `re` yet, refused before its
    // signature is looked at.
    match alice
        .request(
            "chat",
            json!({ "text": "x", "guid": guid(3), "signed": "AAAA", "re": { "line": lobby } }),
        )
        .await
    {
        Err(Error::Refused { code, text }) => {
            assert_eq!(code, "bad_request");
            assert!(text.contains("cannot carry `re`"), "{text}");
        }
        other => panic!("signed with `re` was not refused: {other:?}"),
    }
    // The same targets, where they belong, a room's line in its room.
    say(&mut alice, json!({ "text": "ok", "re": { "line": lobby } })).await;
    let in_room = say(&mut alice, json!({ "text": "here", "room": room })).await;
    let re = json!({ "line": in_room, "room": room });
    say(
        &mut alice,
        json!({ "text": "and here", "room": room, "re": re }),
    )
    .await;
    assert_eq!(
        event(&mut alice, "chat", |d| d["text"] == "and here").await["re"],
        re
    );
    ok(
        &mut bob,
        "msg",
        json!({ "to": alice.uid, "text": "ok", "re": { "pm": between } }),
    )
    .await;
    ok(
        &mut alice,
        "msg",
        json!({ "to": dave.uid, "text": "ok", "re": { "pm": "AAAAAAAAAAAAAAAAAAAAAA" } }),
    )
    .await;
    // Another pair's reference too: the server does not look, so a reply
    // cannot ask it whether that message still exists.
    ok(
        &mut bob,
        "msg",
        json!({ "to": dave.uid, "text": "ok", "re": { "pm": between } }),
    )
    .await;
}

/// However a line or message is handed over, a reader that declared
/// `replies` is handed what it answers: a resume's replay, mail flushed
/// at login, and a `requests` listing.
#[tokio::test]
async fn re_survives_every_way_of_being_handed_over() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let asked = say(&mut bob, json!({ "text": "lunch?" })).await;

    event(&mut alice, "chat", |d| d["text"] == "lunch?").await;
    ok(&mut alice, "ping", json!({})).await;
    let (session, last_seq) = (alice.session.clone().unwrap(), alice.rx.last_seq);
    alice.close().await.unwrap();
    event(&mut bob, "user_changed", |d| {
        d["user"]["status"] == "detached"
    })
    .await;
    let re = json!({ "line": asked });
    say(&mut bob, json!({ "text": "missed", "re": re })).await;
    let (mut alice, resumed) = Client::resume(addr, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert!(matches!(resumed, Resumed::Replayed(_)), "{resumed:?}");
    assert_eq!(
        event(&mut alice, "chat", |d| d["text"] == "missed").await["re"],
        re
    );

    let mail = json!({ "pm": "AAAAAAAAAAAAAAAAAAAAAA" });
    let sent = ok(
        &mut bob,
        "msg",
        json!({ "to_login": "erin", "text": "while you were out", "re": mail }),
    )
    .await;
    assert_eq!(sent["queued"], true);
    let (mut erin, _) = login(addr, "erin", true).await;
    assert_eq!(
        event(&mut erin, "msg", |d| d["text"] == "while you were out").await["re"],
        mail
    );

    let (mut dave, _) = login(addr, "dave", true).await;
    ok(&mut dave, "presence", json!({ "takes_requests": true })).await;
    ok(&mut alice, "requests", json!({})).await;
    let re = json!({ "im": { "login": "dave", "guid": guid(8) } });
    let sent = ok(
        &mut alice,
        "msg",
        json!({ "to_login": "dave", "text": "hello?", "guid": guid(9), "re": re }),
    )
    .await;
    assert_eq!(sent["requested"], true);
    let listed = ok(&mut dave, "requests", json!({})).await;
    assert_eq!(listed["requests"][0]["messages"][0]["re"], re, "{listed}");
}

#[tokio::test]
async fn a_reply_to_a_message_and_to_an_instant_message() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;

    // A private message, named by the reference both are given.
    let sent = ok(&mut alice, "msg", json!({ "to": bob.uid, "text": "psst" })).await;
    let got = event(&mut bob, "msg", |d| d["text"] == "psst").await;
    assert_eq!(got["ref"], sent["ref"]);
    let re = json!({ "pm": got["ref"] });
    ok(
        &mut bob,
        "msg",
        json!({ "to": alice.uid, "text": "what?", "re": re }),
    )
    .await;
    assert_eq!(
        event(&mut alice, "msg", |d| d["text"] == "what?").await["re"],
        re
    );
    let inbox = ok(&mut alice, "inbox", json!({})).await;
    assert_eq!(inbox["messages"][0]["re"], re);

    // An instant message, named by its sender's login and its guid.
    ok(&mut alice, "friend_add", json!({ "login": "bob" })).await;
    event(&mut bob, "friend_request", |d| d["login"] == "alice").await;
    ok(
        &mut bob,
        "friend_respond",
        json!({ "login": "alice", "accept": true }),
    )
    .await;
    event(&mut alice, "friend", |d| d["friend"]["state"] == "accepted").await;
    ok(
        &mut alice,
        "msg",
        json!({ "to_login": "bob", "text": "lunch?", "guid": guid(1) }),
    )
    .await;
    event(&mut bob, "im", |d| d["text"] == "lunch?").await;
    let re = json!({ "im": { "login": "alice", "guid": guid(1) } });
    ok(
        &mut bob,
        "msg",
        json!({ "to_login": "alice", "text": "yes", "guid": guid(2), "re": re }),
    )
    .await;
    assert_eq!(
        event(&mut alice, "im", |d| d["text"] == "yes").await["re"],
        re
    );
}

#[tokio::test]
async fn history_ids_answer_under_the_readers_own_checks_and_bound() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss", true).await;
    let staff = ok(
        &mut boss,
        "room_create",
        json!({ "name": "staff", "read": ["alice"] }),
    )
    .await["room"]["id"]
        .as_u64()
        .unwrap();
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut carol, _) = login(addr, "carol", true).await;
    ok(&mut alice, "room_join", json!({ "room": staff })).await;
    let hidden = say(&mut alice, json!({ "text": "staff only", "room": staff })).await;
    let first = say(&mut alice, json!({ "text": "one" })).await;
    let second = say(&mut alice, json!({ "text": "two" })).await;
    ok(&mut carol, "redact", json!({ "id": second, "reason": "x" })).await;

    let got = ok(
        &mut bob,
        "history",
        json!({ "ids": [second, hidden, first, second + 1000] }),
    )
    .await;
    let lines = got["lines"].as_array().unwrap();
    assert_eq!(
        lines
            .iter()
            .map(|l| l["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [first, second],
        "the lobby's, ascending, with neither another room's nor a missing one"
    );
    assert_eq!(
        (&lines[0]["text"], &lines[1]["deleted"]),
        (&json!("one"), &json!(true))
    );
    assert_eq!(got["has_more"], false);
    assert_eq!(
        refused(
            &mut bob,
            "history",
            json!({ "room": staff, "ids": [hidden] })
        )
        .await,
        "no_such_room"
    );
    let got = ok(
        &mut alice,
        "history",
        json!({ "room": staff, "ids": [hidden, first] }),
    )
    .await;
    assert_eq!(got["lines"][0]["id"], hidden);
    assert_eq!(got["lines"].as_array().unwrap().len(), 1);
    // A session that did not declare `replies` is served a page, as an
    // unknown param is ignored.
    let (mut dave, _) = login(addr, "dave", false).await;
    let page = ok(&mut dave, "history", json!({ "ids": [first] })).await;
    assert!(page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["id"] == second));
    for params in [
        json!({ "ids": [] }),
        json!({ "ids": (1..=51).collect::<Vec<u64>>() }),
        json!({ "ids": [first], "before": second }),
    ] {
        assert_eq!(refused(&mut bob, "history", params).await, "bad_request");
    }

    // Past what one reply may hold, the highest ids are left to ask for
    // again.
    let long = "x".repeat(4000);
    let mut said = Vec::new();
    for _ in 0..24 {
        said.push(say(&mut alice, json!({ "text": long })).await);
    }
    let got = ok(&mut bob, "history", json!({ "ids": said })).await;
    let shown: Vec<u64> = got["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["id"].as_u64().unwrap())
        .collect();
    assert_eq!(got["has_more"], true);
    assert!(!shown.is_empty() && shown.len() < said.len());
    assert_eq!(shown, said[..shown.len()]);
    let rest = ok(&mut bob, "history", json!({ "ids": said[shown.len()..] })).await;
    assert_eq!(rest["has_more"], false);
    assert_eq!(
        rest["lines"].as_array().unwrap().len(),
        said.len() - shown.len()
    );
}

#[tokio::test]
async fn a_redacted_reply_loses_its_target_and_a_reply_to_a_redacted_line_keeps_it() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut carol, _) = login(addr, "carol", true).await;
    let asked = say(&mut alice, json!({ "text": "lunch?" })).await;
    let re = json!({ "line": asked });
    let answer = say(&mut bob, json!({ "text": "yes", "re": re })).await;
    let again = say(&mut bob, json!({ "text": "really", "re": re })).await;
    ok(&mut carol, "redact", json!({ "id": asked, "reason": "x" })).await;
    ok(&mut carol, "redact", json!({ "id": again, "reason": "x" })).await;
    let got = ok(
        &mut alice,
        "history",
        json!({ "ids": [asked, answer, again] }),
    )
    .await;
    let lines = got["lines"].as_array().unwrap();
    assert_eq!(lines[1]["re"], re, "a reply outlives what it answered");
    assert_eq!(lines[2]["deleted"], true);
    assert!(lines[2].get("re").is_none(), "{}", lines[2]);
}
