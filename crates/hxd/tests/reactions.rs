//! Reactions on the ng wire (`docs/hotline-ng.md` §7.3): `react` on a
//! lobby or a room line, held to its caps, its rate and who may react,
//! counted on `history` for the sessions that declared `reactions`, told
//! live in `reactions_changed` batches to a room's readers, cleared by a
//! moderator and taken by a redaction and a purge, and on an instant
//! message relayed to its other party, between scripted clients on a
//! real server. Emoji in the test data are the reactions themselves.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{
    Core, HistoryPolicy, InboxPolicy, MessagingPolicy, ModerationPolicy, ReactionPolicy, RoomPolicy,
};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::ng::{Client, Incoming, Resumed};
use hxd_testclient::Error;
use serde_json::{json, Value};

/// History, moderation, rooms and messaging on one SQLite file,
/// reactions under `policy`, their batches sent as the binary sends them.
/// `carol` moderates, `boss` makes rooms, `reader` may read and not chat,
/// and the guest may chat.
async fn start(dir: &Path, policy: ReactionPolicy) -> SocketAddr {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    const CHATTER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                           send_msgs = true\nmessaging = true\n";
    for (login, password, access) in [
        ("alice", true, CHATTER.to_string()),
        ("bob", true, CHATTER.to_string()),
        ("dave", true, CHATTER.to_string()),
        ("erin", true, CHATTER.to_string()),
        ("carol", true, format!("{CHATTER}disconnect_users = true\n")),
        (
            "boss",
            true,
            format!("{CHATTER}[extra]\nmanage_rooms = true\n"),
        ),
        (
            "reader",
            true,
            "read_chat = true\nread_chat_history = true\n".into(),
        ),
        ("guest", false, CHATTER.to_string()),
    ] {
        let password = if password { "password = \"pw\"\n" } else { "" };
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\n{password}[access]\n{access}"),
        )
        .unwrap();
    }
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let core = Core::new()
        .with_inbox(store.clone(), auth.clone(), InboxPolicy::default())
        .with_history(
            store.clone(),
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        )
        .with_reactions(policy)
        .with_relationships(store.clone())
        .with_messaging(MessagingPolicy {
            enabled: true,
            ..MessagingPolicy::default()
        })
        .with_moderation(store, ModerationPolicy::default())
        .with_rooms(
            Arc::new(hxd::rooms::FileRooms::new(&dir.join("rooms.toml"))),
            RoomPolicy::default(),
        )
        .unwrap();
    let core = Arc::new(core);
    tokio::spawn(hxd::reactions_flusher(core.clone()));
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "reactions".into(),
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 4,
            caps: vec!["history".into()],
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

/// A client, declaring `reactions` (and `replies`, for `history`'s
/// `ids`) or not, and its login reply.
async fn login(addr: SocketAddr, who: &str, reactions: bool) -> (Client, Value) {
    let mut c = Client::connect(addr).await.unwrap();
    let password = if who == "guest" { "" } else { "pw" };
    let hello = c
        .login(json!({
            "login": who, "password": password, "nick": who,
            "reactions": reactions, "replies": true,
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

/// A request's whole reply, error and all.
async fn raw(c: &mut Client, req: &str, params: Value) -> Value {
    let id = c.tx.send(req, params).await.unwrap();
    loop {
        if let Incoming::Reply(v) = c.rx.next().await.unwrap() {
            if v["reply"] == id {
                return v;
            }
        }
    }
}

async fn say(c: &mut Client, params: Value) -> u64 {
    ok(c, "chat", params).await["id"].as_u64().unwrap()
}

/// `who` reacts with `emoji` on `target`, answering the key's count.
async fn react(c: &mut Client, target: Value, emoji: &str) -> u64 {
    let params = json!({ "target": target, "key": { "emoji": emoji } });
    ok(c, "react", params).await["count"].as_u64().unwrap()
}

/// The line `id` of `room` as `c`'s `history` shows it.
async fn shown(c: &mut Client, room: u64, id: u64) -> Value {
    let page = ok(
        c,
        "history",
        json!({ "room": room, "before": id + 1, "limit": 1 }),
    )
    .await;
    assert_eq!(page["lines"][0]["id"], id, "{page}");
    page["lines"][0].clone()
}

fn caps(hello: &Value) -> Vec<Value> {
    hello["caps"].as_array().unwrap().clone()
}

#[tokio::test]
async fn reactions_are_counted_per_account_and_shown_to_the_readers_that_asked() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut alice, hello) = login(addr, "alice", true).await;
    assert!(caps(&hello).contains(&json!("reactions")));
    assert_eq!(
        hello["reactions"],
        json!({ "targets": ["line", "im"], "max_keys": 20, "max_per_user": 5 })
    );
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut dave, hello) = login(addr, "dave", false).await;
    assert!(!caps(&hello).contains(&json!("reactions")));
    assert!(hello.get("reactions").is_none());

    let line = say(&mut alice, json!({ "text": "lunch?" })).await;
    let target = json!({ "line": line });
    assert_eq!(react(&mut bob, target.clone(), "👍").await, 1);
    assert_eq!(react(&mut alice, target.clone(), "👍").await, 2);
    assert_eq!(react(&mut alice, target.clone(), "🎉").await, 1);
    assert_eq!(
        react(&mut alice, target.clone(), "👍").await,
        2,
        "held once"
    );
    let keys = json!([
        { "key": { "emoji": "👍" }, "count": 2 },
        { "key": { "emoji": "🎉" }, "count": 1 },
    ]);
    let seen = shown(&mut bob, 0, line).await;
    assert_eq!(
        (&seen["reactions"], &seen["reactions_mine"]),
        (&keys, &json!([0]))
    );
    let seen = shown(&mut alice, 0, line).await;
    assert_eq!(seen["reactions_mine"], json!([0, 1]));
    let by_id = ok(&mut alice, "history", json!({ "ids": [line] })).await;
    assert_eq!(by_id["lines"][0]["reactions"], keys);
    assert_eq!(by_id["lines"][0]["reactions_mine"], json!([0, 1]));

    // A reader that did not ask sees the line as it always did, and is
    // not taken up on a reaction.
    let plain = shown(&mut dave, 0, line).await;
    assert!(plain.get("reactions").is_none() && plain.get("reactions_mine").is_none());
    let params = json!({ "target": target, "key": { "emoji": "👍" } });
    assert_eq!(refused(&mut dave, "react", params).await, "not_available");

    let undone = json!({ "target": target, "key": { "emoji": "🎉" }, "remove": true });
    assert_eq!(ok(&mut alice, "react", undone.clone()).await["count"], 0);
    assert_eq!(
        ok(&mut alice, "react", undone).await["count"],
        0,
        "held by none"
    );
    let seen = shown(&mut bob, 0, line).await;
    assert_eq!(
        seen["reactions"],
        json!([{ "key": { "emoji": "👍" }, "count": 2 }])
    );

    // A room's line is named with its room, and read there in history by
    // someone who never joined.
    let (mut boss, _) = login(addr, "boss", true).await;
    let room = ok(&mut boss, "room_create", json!({ "name": "lounge" })).await["room"]["id"]
        .as_u64()
        .unwrap();
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    let there = say(&mut alice, json!({ "text": "in here", "room": room })).await;
    assert_eq!(
        react(&mut bob, json!({ "line": there, "room": room }), "👀").await,
        1
    );
    let lobby = json!({ "target": { "line": there }, "key": { "emoji": "👀" } });
    assert_eq!(refused(&mut bob, "react", lobby).await, "no_such_target");
    let seen = shown(&mut alice, room, there).await;
    assert_eq!(
        seen["reactions"],
        json!([{ "key": { "emoji": "👀" }, "count": 1 }])
    );
    assert!(seen.get("reactions_mine").is_none());
}

#[tokio::test]
async fn a_reaction_past_what_a_line_or_an_account_may_hold_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let policy = ReactionPolicy {
        max_keys: 3,
        max_per_user: 2,
        ..ReactionPolicy::default()
    };
    let addr = start(td.path(), policy).await;
    let (mut alice, hello) = login(addr, "alice", true).await;
    assert_eq!(hello["reactions"]["max_keys"], 3);
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut erin, _) = login(addr, "erin", true).await;
    let line = say(&mut alice, json!({ "text": "vote" })).await;
    let target = json!({ "line": line });
    let to = |e: &str| json!({ "target": target, "key": { "emoji": e } });
    react(&mut alice, target.clone(), "👍").await;
    react(&mut alice, target.clone(), "🎉").await;
    assert_eq!(
        refused(&mut alice, "react", to("🔥")).await,
        "too_many_reactions",
        "past what one account may hold"
    );
    react(&mut bob, target.clone(), "🔥").await;
    assert_eq!(
        refused(&mut erin, "react", to("😀")).await,
        "too_many_reactions",
        "past the line's keys"
    );
    assert_eq!(
        react(&mut erin, target.clone(), "👍").await,
        2,
        "a key already there"
    );

    for (case, params, code) in [
        (
            "text",
            json!({ "target": target, "key": { "emoji": "ok" } }),
            "bad_request",
        ),
        ("two emoji", to("👍👍"), "bad_request"),
        (
            "a server's emoji",
            json!({ "target": target, "key": { "custom": 1 } }),
            "bad_request",
        ),
        ("no key", json!({ "target": target }), "bad_request"),
        (
            "a message",
            json!({ "target": { "pm": "AAAAAAAAAAAAAAAAAAAAAA" }, "key": { "emoji": "👍" } }),
            "bad_request",
        ),
        (
            "a line never said",
            json!({ "target": { "line": line + 1000 }, "key": { "emoji": "👍" } }),
            "no_such_target",
        ),
        (
            "a room that is not there",
            json!({ "target": { "line": line, "room": 77 }, "key": { "emoji": "👍" } }),
            "no_such_target",
        ),
    ] {
        assert_eq!(refused(&mut bob, "react", params).await, code, "{case}");
    }

    // Who reacts is an account of one person that may chat.
    let (mut guest, hello) = login(addr, "guest", true).await;
    assert!(caps(&hello).contains(&json!("reactions")));
    assert_eq!(
        refused(&mut guest, "react", to("👍")).await,
        "access_denied"
    );
    let (mut reader, _) = login(addr, "reader", true).await;
    assert_eq!(
        refused(&mut reader, "react", to("👍")).await,
        "access_denied"
    );
}

#[tokio::test]
async fn an_account_reacts_a_burst_and_then_is_told_to_wait() {
    let td = tempfile::tempdir().unwrap();
    let policy = ReactionPolicy {
        burst: 3,
        per_second: 1,
        ..ReactionPolicy::default()
    };
    let addr = start(td.path(), policy).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut again, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let line = say(&mut alice, json!({ "text": "go" })).await;
    let target = json!({ "line": line });
    for remove in [false, true, false] {
        let params = json!({ "target": target, "key": { "emoji": "👍" }, "remove": remove });
        ok(&mut alice, "react", params).await;
    }
    // The account's, whichever of its sessions asks: a delay, never a
    // kick.
    let reply = raw(
        &mut again,
        "react",
        json!({ "target": target, "key": { "emoji": "🎉" } }),
    )
    .await;
    assert_eq!(reply["error"]["code"], "rate_limited", "{reply}");
    assert_eq!(reply["error"]["retry_after"], 1, "{reply}");
    ok(&mut again, "ping", json!({})).await;
    assert_eq!(
        react(&mut bob, target, "🎉").await,
        1,
        "another account's own"
    );
}

#[tokio::test]
async fn a_redaction_takes_a_lines_reactions_and_a_purge_a_persons() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut erin, _) = login(addr, "erin", true).await;
    let (mut carol, _) = login(addr, "carol", true).await;
    let gone = say(&mut alice, json!({ "text": "regrettable" })).await;
    let kept = say(&mut alice, json!({ "text": "fine" })).await;
    for line in [gone, kept] {
        react(&mut bob, json!({ "line": line }), "👍").await;
    }
    react(&mut erin, json!({ "line": kept }), "👍").await;
    react(&mut erin, json!({ "line": kept }), "😂").await;

    ok(&mut carol, "redact", json!({ "id": gone, "reason": "no" })).await;
    let tomb = shown(&mut alice, 0, gone).await;
    assert_eq!(tomb["deleted"], true);
    assert!(tomb.get("reactions").is_none(), "{tomb}");
    let params = json!({ "target": { "line": gone }, "key": { "emoji": "👍" } });
    assert_eq!(refused(&mut erin, "react", params).await, "no_such_target");

    ok(
        &mut carol,
        "purge",
        json!({ "login": "bob", "since": 3600, "reason": "ballot stuffing" }),
    )
    .await;
    let seen = shown(&mut erin, 0, kept).await;
    assert_eq!(
        (&seen["reactions"], &seen["reactions_mine"]),
        (
            &json!([
                { "key": { "emoji": "👍" }, "count": 1 },
                { "key": { "emoji": "😂" }, "count": 1 },
            ]),
            &json!([0, 1])
        )
    );
    assert!(shown(&mut bob, 0, kept)
        .await
        .get("reactions_mine")
        .is_none());
}

/// A resume keeps what the login was granted.
#[tokio::test]
async fn a_resumed_session_still_reacts_and_reads_reactions() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let line = say(&mut alice, json!({ "text": "still here?" })).await;
    alice
        .event_where("chat", |d| d["id"] == line)
        .await
        .unwrap();
    let (session, last_seq) = (alice.session.clone().unwrap(), alice.rx.last_seq);
    alice.close().await.unwrap();
    let (mut alice, resumed) = Client::resume(addr, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert!(matches!(resumed, Resumed::Replayed(_)), "{resumed:?}");
    assert_eq!(react(&mut alice, json!({ "line": line }), "👋").await, 1);
    let seen = shown(&mut alice, 0, line).await;
    assert_eq!(seen["reactions_mine"], json!([0]), "{seen}");
}

/// The next `reactions_changed` naming `target`, and what it said of it.
async fn changed(c: &mut Client, target: &Value) -> (Value, Value) {
    let t = target.clone();
    let names = move |d: &Value| {
        d["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["target"] == t)
    };
    let ev = c.event_where("reactions_changed", names).await.unwrap();
    let group = (ev.data["changes"].as_array().unwrap().iter())
        .find(|g| g["target"] == *target)
        .unwrap()
        .clone();
    (ev.data, group)
}

/// A reaction is told as it happens to everyone reading the line who
/// declared `reactions`: one batch for what changed together, each
/// reader's own keys its own, and nothing to a reader that did not ask.
#[tokio::test]
async fn a_reaction_is_told_live_to_the_readers_in_one_batch() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut erin, _) = login(addr, "erin", true).await;
    let (mut dave, _) = login(addr, "dave", false).await;
    let line = say(&mut alice, json!({ "text": "pizza?" })).await;
    let target = json!({ "line": line });
    react(&mut erin, target.clone(), "👍").await;
    react(&mut erin, target.clone(), "🍕").await;
    let keys = json!([
        { "key": { "emoji": "👍" }, "count": 1 },
        { "key": { "emoji": "🍕" }, "count": 1 },
    ]);
    for c in [&mut alice, &mut bob] {
        let (_, group) = changed(c, &target).await;
        assert_eq!(
            group,
            json!({ "target": target, "action": "summary", "keys": keys })
        );
    }
    let (_, group) = changed(&mut erin, &target).await;
    assert_eq!(group["mine"], json!([0, 1]));

    // The next change is a batch of its own.
    react(&mut bob, target.clone(), "👍").await;
    let (_, group) = changed(&mut alice, &target).await;
    assert_eq!(group["keys"][0]["count"], 2);
    ok(&mut dave, "ping", json!({})).await;
    assert!(
        dave.rx
            .take_backlog()
            .iter()
            .all(|e| e.ev != "reactions_changed"),
        "a reader that did not declare reactions"
    );
}

/// A room's changes reach its members, never the lobby or a reader
/// outside it; a moderator's clear is told as one, and nobody else may
/// clear.
#[tokio::test]
async fn a_rooms_reactions_stay_in_the_room_and_a_moderator_clears_them() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut boss, _) = login(addr, "boss", true).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let (mut carol, _) = login(addr, "carol", true).await;
    let room = ok(&mut boss, "room_create", json!({ "name": "den" })).await["room"]["id"]
        .as_u64()
        .unwrap();
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    ok(&mut carol, "room_join", json!({ "room": room })).await;
    let inside = say(&mut alice, json!({ "text": "in here", "room": room })).await;
    let target = json!({ "line": inside, "room": room });
    react(&mut alice, target.clone(), "👀").await;
    changed(&mut carol, &target).await;
    changed(&mut alice, &target).await;
    // Bob reads the lobby: its next batch is the first he hears.
    let lobby = say(&mut alice, json!({ "text": "out here" })).await;
    let out = json!({ "line": lobby });
    react(&mut alice, out.clone(), "👋").await;
    let (data, _) = changed(&mut bob, &out).await;
    assert_eq!(data["changes"].as_array().unwrap().len(), 1, "{data}");
    for e in bob.rx.take_backlog() {
        assert_ne!(e.ev, "reactions_changed", "{e:?}");
    }

    let clear = json!({ "target": target, "clear": true });
    assert_eq!(
        refused(&mut alice, "react", clear.clone()).await,
        "access_denied"
    );
    let with_key = json!({ "target": target, "clear": true, "key": { "emoji": "👀" } });
    assert_eq!(refused(&mut carol, "react", with_key).await, "bad_request");
    assert_eq!(ok(&mut carol, "react", clear).await, json!({}));
    let (_, group) = changed(&mut alice, &target).await;
    assert_eq!(group, json!({ "target": target, "action": "clear" }));
    assert!(shown(&mut alice, room, inside)
        .await
        .get("reactions")
        .is_none());
}

/// An instant message's reaction goes to the conversation's other party
/// as a change, and to nobody else; to a stranger there is no such
/// target.
#[tokio::test]
async fn an_im_reaction_reaches_its_party_and_not_a_stranger() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let messenger = |who: &'static str| async move {
        let mut c = Client::connect(addr).await.unwrap();
        c.login(json!({
            "login": who, "password": "pw", "nick": who,
            "reactions": true, "messaging": true,
        }))
        .await
        .unwrap();
        ok(&mut c, "friends", json!({})).await;
        c
    };
    let (mut alice, mut bob, mut erin) = (
        messenger("alice").await,
        messenger("bob").await,
        messenger("erin").await,
    );
    ok(&mut alice, "friend_add", json!({ "login": "bob" })).await;
    bob.event_where("friend_request", |d| d["login"] == "alice")
        .await
        .unwrap();
    ok(
        &mut bob,
        "friend_respond",
        json!({ "login": "alice", "accept": true }),
    )
    .await;
    let target =
        json!({ "im": { "login": "bob", "guid": "5f5e1000-1234-4abc-89ab-000000000001" } });
    let params = json!({ "target": target, "with": "bob", "key": { "emoji": "❤\u{FE0F}" } });
    assert_eq!(ok(&mut alice, "react", params).await, json!({}));
    let (_, group) = changed(&mut bob, &target).await;
    assert_eq!(
        group,
        json!({ "target": target, "action": "add", "key": { "emoji": "❤\u{FE0F}" }, "from": { "login": "alice" } })
    );

    let stranger = json!({ "target": target, "with": "erin", "key": { "emoji": "❤\u{FE0F}" } });
    assert_eq!(refused(&mut alice, "react", stranger).await, "bad_request");
    let erins =
        json!({ "im": { "login": "erin", "guid": "5f5e1000-1234-4abc-89ab-000000000002" } });
    let stranger = json!({ "target": erins, "with": "erin", "key": { "emoji": "❤\u{FE0F}" } });
    assert_eq!(
        refused(&mut alice, "react", stranger).await,
        "no_such_target"
    );
    let unnamed = json!({ "target": erins, "key": { "emoji": "❤\u{FE0F}" } });
    assert_eq!(refused(&mut alice, "react", unnamed).await, "bad_request");
    ok(&mut erin, "ping", json!({})).await;
    assert!(erin
        .rx
        .take_backlog()
        .iter()
        .all(|e| e.ev != "reactions_changed"));
}

/// A batch sent while a session is detached is held for it like any
/// other event, and replayed in order at its resume.
#[tokio::test]
async fn a_batch_while_detached_is_replayed_gaplessly() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path(), ReactionPolicy::default()).await;
    let (mut alice, _) = login(addr, "alice", true).await;
    let (mut bob, _) = login(addr, "bob", true).await;
    let line = say(&mut alice, json!({ "text": "back soon" })).await;
    bob.event_where("chat", |d| d["id"] == line).await.unwrap();
    let (session, last_seq) = (bob.session.clone().unwrap(), bob.rx.last_seq);
    bob.close().await.unwrap();
    let target = json!({ "line": line });
    react(&mut alice, target.clone(), "👍").await;
    changed(&mut alice, &target).await;
    let (mut bob, resumed) = Client::resume(addr, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert!(
        matches!(resumed, Resumed::Replayed(n) if n > 0),
        "{resumed:?}"
    );
    let (_, group) = changed(&mut bob, &target).await;
    assert_eq!(group["keys"][0]["count"], 1);
    assert!(bob.rx.seq_faults.is_empty(), "{:?}", bob.rx.seq_faults);
}
