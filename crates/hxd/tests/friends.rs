//! Instant messaging on the ng wire (`docs/hotline-ng.md` §7.5): friends
//! made by request and response, their presence, instant messages with
//! receipts and typing, and message requests, between scripted clients
//! on a real server with the binary's presence flusher running.
//!
//! What is here is what the domain's tests cannot show: what each client
//! is sent and answered, that a client which never declared the family
//! is sent nothing new and stays gapless across a resume, that a server
//! without messaging answers as it did before the family existed, and
//! that a period client beside it all hears nothing of it.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, InboxPolicy, MessagingPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::legacy::{self, push, Login};
use hxd_testclient::ng::{Client, Event, Resumed};
use hxd_testclient::Error;
use serde_json::{json, Value};

/// Every name the family's events go by, and the placeholder they were
/// before it.
const FAMILY_EVENTS: &[&str] = &[
    "friend",
    "friend_request",
    "presence",
    "im",
    "receipt",
    "typing",
    "requests_changed",
    "unsupported",
];

struct Server {
    ng: SocketAddr,
    classic: SocketAddr,
}

/// Both frontends on one core keeping mail and relationships in SQLite,
/// with messaging on unless `messaging` is false. `zed` has no
/// `AccessMessaging`; everyone else has it.
async fn start(dir: &Path, messaging: bool) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, bits) in [
        ("alice", "messaging = true\n"),
        ("bob", "messaging = true\n"),
        ("carol", "messaging = true\n"),
        ("dave", "messaging = true\n"),
        ("erin", "messaging = true\n"),
        ("zed", ""),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                 send_chat = true\nsend_msgs = true\n{bits}"
            ),
        )
        .unwrap();
    }
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let core = Core::new()
        .with_inbox(store.clone(), auth.clone(), InboxPolicy::default())
        .with_relationships(store)
        .with_messaging(MessagingPolicy {
            enabled: messaging,
            presence_debounce: Duration::from_millis(50),
            ..MessagingPolicy::default()
        });
    let core = Arc::new(core);
    tokio::spawn(hxd::presence_flusher(core.clone()));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig::default()),
        files: None,
        banner: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "friends".into(),
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 4,
            caps: vec!["inbox".into()],
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
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (classic, ng) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    Server { ng, classic }
}

/// A client that speaks the family, and its login reply.
async fn messenger(s: &Server, who: &str) -> (Client, Value) {
    login(s, who, true).await
}

async fn login(s: &Server, who: &str, messaging: bool) -> (Client, Value) {
    let mut c = Client::connect(s.ng).await.unwrap();
    let hello = c
        .login(json!({ "login": who, "password": "pw", "nick": who, "messaging": messaging }))
        .await
        .unwrap();
    (c, hello)
}

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn outcome(c: &mut Client, req: &str, params: Value) -> Result<Value, String> {
    match c.request(req, params).await {
        Ok(v) => Ok(v),
        Err(Error::Refused { code, .. }) => Err(code),
        Err(e) => panic!("{req}: {e:?}"),
    }
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

/// `a` and `b` friends, as two clients make them.
async fn befriend(a: &mut Client, b: &mut Client, b_login: &str, a_login: &str) {
    let asked = ok(a, "friend_add", json!({ "login": b_login })).await;
    assert_eq!(asked["state"], "pending_out");
    event(b, "friend_request", |d| d["login"] == a_login).await;
    let accepted = ok(
        b,
        "friend_respond",
        json!({ "login": a_login, "accept": true }),
    )
    .await;
    assert_eq!(accepted["state"], "accepted");
    event(a, "friend", |d| {
        d["friend"]["login"] == b_login && d["friend"]["state"] == "accepted"
    })
    .await;
}

fn guid(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
}

#[tokio::test]
async fn two_clients_become_friends_and_talk() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, hello) = messenger(&s, "alice").await;
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("messaging")));
    let block = &hello["messaging"];
    assert_eq!(block["takes_part"], true);
    assert_eq!(
        (
            &block["state"],
            &block["discoverable"],
            &block["takes_requests"]
        ),
        (&json!("online"), &json!(false), &json!(false))
    );
    let (mut bob, _) = messenger(&s, "bob").await;

    let asked = ok(
        &mut alice,
        "friend_add",
        json!({ "login": "bob", "note": "hi, it's alice" }),
    )
    .await;
    assert_eq!(asked, json!({ "state": "pending_out" }));
    // The acting session hears of its own row too.
    event(&mut alice, "friend", |d| {
        d["friend"]["state"] == "pending_out"
    })
    .await;
    let request = event(&mut bob, "friend_request", |d| d["login"] == "alice").await;
    assert_eq!(request["note"], "hi, it's alice");
    let rows = ok(&mut bob, "friends", json!({})).await;
    assert_eq!(
        rows["friends"],
        json!([{ "login": "alice", "state": "pending_in", "note": "hi, it's alice" }])
    );
    ok(
        &mut bob,
        "friend_respond",
        json!({ "login": "alice", "accept": true }),
    )
    .await;
    event(&mut bob, "friend", |d| d["friend"]["state"] == "accepted").await;
    let entry = event(&mut alice, "friend", |d| d["friend"]["state"] == "accepted").await;
    assert_eq!(entry["friend"]["login"], "bob");
    // A friend is shown what bob's friends were last told, so bob's
    // sign-on may still be owed under the debounce; then it is told.
    if entry["friend"]["presence"] != "online" {
        event(&mut alice, "presence", |d| {
            d["login"] == "bob" && d["state"] == "online"
        })
        .await;
    }

    // Presence, told once the burst settles.
    ok(
        &mut alice,
        "presence",
        json!({ "state": "away", "status_text": "at lunch" }),
    )
    .await;
    let seen = event(&mut bob, "presence", |d| d["state"] == "away").await;
    assert_eq!(
        seen,
        json!({ "login": "alice", "state": "away", "status_text": "at lunch" })
    );

    // An instant message, its receipts, and typing.
    let sent = ok(
        &mut alice,
        "msg",
        json!({ "to_login": "bob", "text": "lunch?", "guid": guid(1) }),
    )
    .await;
    assert_eq!(sent["queued"], false);
    let im = event(&mut bob, "im", |d| d["text"] == "lunch?").await;
    assert_eq!(im["from"]["login"], "alice");
    assert_eq!(im["guid"], guid(1));
    assert_eq!(im["queued"], false);
    assert!(im.get("approval").is_none());
    for read in [false, true] {
        ok(
            &mut bob,
            "receipt",
            json!({ "login": "alice", "guid": guid(1), "read": read }),
        )
        .await;
        let receipt = event(&mut alice, "receipt", |d| d["read"] == read).await;
        assert_eq!(
            receipt,
            json!({ "login": "bob", "guid": guid(1), "read": read })
        );
    }
    ok(
        &mut bob,
        "typing",
        json!({ "login": "alice", "typing": true }),
    )
    .await;
    let typing = event(&mut alice, "typing", |d| d["login"] == "bob").await;
    assert_eq!(typing["typing"], true);

    // What the profile shows a friend.
    let found = ok(&mut bob, "user_profile", json!({ "login": "alice" })).await;
    assert_eq!(found["user"]["presence"], "away");
    assert_eq!(found["user"]["status_text"], "at lunch");
    assert!(found["user"]["profile"].is_object());

    for c in [&alice, &bob] {
        assert!(c.rx.seq_faults.is_empty());
    }
}

#[tokio::test]
async fn an_instant_message_sent_while_away_arrives_at_the_roster_read() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut bob, _) = messenger(&s, "bob").await;
    befriend(&mut alice, &mut bob, "bob", "alice").await;
    bob.logout().await.unwrap();

    let sent = ok(
        &mut alice,
        "msg",
        json!({ "to_login": "bob", "text": "while you were out", "guid": guid(2) }),
    )
    .await;
    assert_eq!(sent["queued"], true);
    assert!(sent["id"].is_u64());

    let (mut bob, _) = messenger(&s, "bob").await;
    let rows = ok(&mut bob, "friends", json!({})).await;
    assert_eq!(rows["friends"][0]["login"], "alice");
    let im = event(&mut bob, "im", |d| d["text"] == "while you were out").await;
    assert_eq!(im["queued"], true);
    assert_eq!(im["id"], sent["id"]);
    // Handed over as an instant message alone, never as mail too.
    assert!(!bob.rx.take_backlog().iter().any(|e| e.ev == "msg"));
}

#[tokio::test]
async fn a_block_reads_as_a_missing_account() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut carol, _) = messenger(&s, "carol").await;
    ok(&mut carol, "block", json!({ "login": "alice" })).await;
    ok(&mut alice, "presence", json!({ "takes_requests": false })).await;

    // A blocker is answered as an account nobody holds, and one that
    // takes no part as neither, on every request that names one.
    for (req, params) in [
        ("friend_add", json!({})),
        ("friend_respond", json!({ "accept": true })),
        ("friend_remove", json!({})),
        ("friend_alias", json!({ "alias": "x" })),
        ("find_user", json!({})),
        ("user_profile", json!({})),
        ("typing", json!({ "typing": true })),
        ("receipt", json!({ "guid": guid(9) })),
    ] {
        let mut answers = Vec::new();
        for who in ["carol", "nobody", "zed"] {
            let mut params = params.clone();
            params["login"] = json!(who);
            answers.push(outcome(&mut alice, req, params).await);
        }
        let quiet = matches!(req, "typing" | "receipt");
        let want = if quiet {
            Ok(json!({}))
        } else {
            Err("no_such_user".to_owned())
        };
        assert_eq!(answers, vec![want; 3], "{req}");
    }
    // `zed` takes no part, so a `msg` to it is mail, as before.
    for who in ["carol", "nobody"] {
        let sent = json!({ "to_login": who, "text": "hello?" });
        assert_eq!(refused(&mut alice, "msg", sent).await, "no_such_user");
    }
    let found = ok(&mut carol, "find_user", json!({ "login": "alice" })).await;
    assert_eq!(found["user"], json!({ "login": "alice", "name": "alice" }));
}

#[tokio::test]
async fn a_request_is_listed_approved_and_answered() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut dave, _) = messenger(&s, "dave").await;
    ok(&mut dave, "presence", json!({ "takes_requests": true })).await;

    // Not understanding requests, alice cannot send one.
    let code = refused(
        &mut alice,
        "msg",
        json!({ "to_login": "dave", "text": "hello dave" }),
    )
    .await;
    assert_eq!(code, "not_friends");
    ok(&mut alice, "presence", json!({ "takes_requests": false })).await;
    let sent = ok(
        &mut alice,
        "msg",
        json!({ "to_login": "dave", "text": "hello dave", "guid": guid(3) }),
    )
    .await;
    assert_eq!(sent, json!({ "queued": true, "requested": true }));
    event(&mut dave, "requests_changed", |d| d["count"] == 1).await;

    let listed = ok(&mut dave, "requests", json!({})).await;
    assert_eq!(listed["dropped"], 0);
    assert_eq!(listed["takes_requests"], true);
    assert_eq!(listed["approvals"], json!([]));
    assert!(listed.get("cursor").is_none());
    let group = &listed["requests"][0];
    assert_eq!(group["login"], "alice");
    assert_eq!(group["messages"][0]["text"], "hello dave");
    assert_eq!(group["messages"][0]["guid"], guid(3));

    ok(
        &mut dave,
        "request_answer",
        json!({ "login": "alice", "action": "approve" }),
    )
    .await;
    let im = event(&mut dave, "im", |d| d["text"] == "hello dave").await;
    assert_eq!(im["approval"], true);
    let listed = ok(&mut dave, "requests", json!({})).await;
    assert_eq!(listed["requests"], json!([]));
    assert_eq!(listed["approvals"], json!([{ "login": "alice" }]));

    // Under an approval every send is answered as queued.
    let back = ok(
        &mut dave,
        "msg",
        json!({ "to_login": "alice", "text": "hi alice", "guid": guid(4) }),
    )
    .await;
    assert_eq!(back["queued"], true);
    let im = event(&mut alice, "im", |d| d["text"] == "hi alice").await;
    assert_eq!(im["approval"], true);

    // Ending it holds alice, whose next message is answered as a request.
    ok(
        &mut dave,
        "request_answer",
        json!({ "login": "alice", "action": "end" }),
    )
    .await;
    let code = refused(
        &mut dave,
        "request_answer",
        json!({ "login": "alice", "action": "delete" }),
    )
    .await;
    assert_eq!(code, "no_such_request");
    let again = ok(
        &mut alice,
        "msg",
        json!({ "to_login": "dave", "text": "still there?" }),
    )
    .await;
    assert_eq!(again, json!({ "queued": true, "requested": true }));
    let listed = ok(&mut dave, "requests", json!({})).await;
    assert_eq!(listed["requests"], json!([]));

    let cleared = ok(&mut dave, "requests_clear", json!({})).await;
    assert_eq!(cleared, json!({ "declined": 0, "deleted": 0 }));
}

#[tokio::test]
async fn crossing_requests_accept_each_other_only_where_requests_are_understood() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    for (first, second, understands, answer) in [
        ("alice", "bob", true, Ok("accepted")),
        ("carol", "dave", false, Err("request_pending")),
    ] {
        let (mut a, _) = messenger(&s, first).await;
        let (mut b, _) = messenger(&s, second).await;
        ok(&mut a, "friend_add", json!({ "login": second })).await;
        if understands {
            ok(&mut b, "presence", json!({ "takes_requests": false })).await;
        }
        let got = outcome(&mut b, "friend_add", json!({ "login": first })).await;
        assert_eq!(
            got,
            answer
                .map(|state| json!({ "state": state }))
                .map_err(str::to_owned),
            "{second}"
        );
    }
}

#[tokio::test]
async fn a_session_that_never_declared_the_family_sees_nothing_new() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut bob, hello) = login(&s, "bob", false).await;
    assert!(hello["messaging"].is_object());

    ok(&mut alice, "friend_add", json!({ "login": "bob" })).await;
    let code = refused(
        &mut alice,
        "msg",
        json!({ "to_login": "bob", "text": "are you there?" }),
    )
    .await;
    assert_eq!(code, "not_friends");
    bob.request("ping", json!({})).await.unwrap();
    let mut seen: Vec<Event> = bob.rx.take_backlog();

    let session = bob.session.clone().unwrap();
    let last = bob.rx.last_seq;
    bob.close().await.unwrap();
    ok(&mut alice, "presence", json!({ "state": "busy" })).await;
    ok(&mut alice, "friend_remove", json!({ "login": "bob" })).await;
    ok(&mut alice, "friend_add", json!({ "login": "bob" })).await;
    alice.chat("while bob was away").await.unwrap();

    let (mut bob, resumed) = Client::resume(s.ng, session, last, Vec::new())
        .await
        .unwrap();
    let Resumed::Replayed(n) = resumed else {
        panic!("{resumed:?}");
    };
    for _ in 0..n {
        seen.push(bob.next_event().await.unwrap());
    }
    assert!(seen.iter().any(|e| e.ev == "chat"));
    let family: Vec<&str> = seen
        .iter()
        .map(|e| e.ev.as_str())
        .filter(|ev| FAMILY_EVENTS.contains(ev))
        .collect();
    assert!(family.is_empty(), "{family:?}");

    // Its first request of the family makes it a session that speaks it.
    let rows = ok(&mut bob, "friends", json!({})).await;
    assert_eq!(rows["friends"][0]["state"], "pending_in");
    ok(&mut alice, "friend_remove", json!({ "login": "bob" })).await;
    let gone = event(&mut bob, "friend", |d| d["friend"]["login"] == "alice").await;
    assert_eq!(gone["friend"]["state"], "removed");
    assert!(bob.rx.seq_faults.is_empty());
}

#[tokio::test]
async fn an_account_without_the_bit_takes_no_part() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut zed, hello) = messenger(&s, "zed").await;
    assert_eq!(hello["messaging"]["takes_part"], false);
    assert!(hello["messaging"].get("state").is_none());
    for req in ["friends", "requests", "presence", "find_user"] {
        let code = refused(&mut zed, req, json!({ "login": "alice" })).await;
        assert_eq!(code, "access_denied", "{req}");
    }
}

#[tokio::test]
async fn invisible_hides_presence_and_nothing_else() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut bob, _) = messenger(&s, "bob").await;
    befriend(&mut alice, &mut bob, "bob", "alice").await;
    // Once bob has been told of alice, so that what follows is a change.
    ok(&mut alice, "presence", json!({ "state": "away" })).await;
    event(&mut bob, "presence", |d| d["state"] == "away").await;

    ok(&mut alice, "presence", json!({ "state": "invisible" })).await;
    event(&mut bob, "presence", |d| {
        d["login"] == "alice" && d["state"] == "offline"
    })
    .await;
    let rows = ok(&mut bob, "friends", json!({})).await;
    assert_eq!(rows["friends"][0]["presence"], "offline");
    // Alice alone sees herself as she set it.
    let me = ok(&mut alice, "find_user", json!({ "login": "alice" })).await;
    assert_eq!(me["user"]["presence"], "invisible");
    let synced = alice.sync().await.unwrap();
    assert_eq!(synced["messaging"]["state"], "invisible");
    // A message to her is delivered, and said so, as to anyone there.
    let sent = ok(
        &mut bob,
        "msg",
        json!({ "to_login": "alice", "text": "you there?", "guid": guid(6) }),
    )
    .await;
    assert_eq!(sent["queued"], false);
    event(&mut alice, "im", |d| d["text"] == "you there?").await;
}

#[tokio::test]
async fn without_messaging_the_wire_is_as_it_was() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), false).await;
    let (mut alice, hello) = messenger(&s, "alice").await;
    assert!(!hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("messaging")));
    assert!(hello.get("messaging").is_none());
    for req in ["friends", "friend_add", "presence", "requests"] {
        assert_eq!(
            refused(&mut alice, req, json!({ "login": "bob" })).await,
            "unknown_method"
        );
    }
}

#[tokio::test]
async fn a_classic_client_beside_friends_hears_nothing_of_them() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut erin = legacy::Client::login_at(s.classic, &Login::account("erin", "erin", "pw"))
        .await
        .unwrap();
    erin.user_list().await.unwrap();
    let (mut alice, _) = messenger(&s, "alice").await;
    let (mut bob, _) = messenger(&s, "bob").await;
    befriend(&mut alice, &mut bob, "bob", "alice").await;
    ok(&mut alice, "presence", json!({ "state": "away" })).await;
    ok(
        &mut alice,
        "msg",
        json!({ "to_login": "bob", "text": "psst", "guid": guid(5) }),
    )
    .await;
    event(&mut bob, "im", |d| d["text"] == "psst").await;
    // A friend request to erin, whose classic session does not speak the
    // family, reaches it as nothing.
    ok(&mut alice, "friend_add", json!({ "login": "erin" })).await;

    erin.chat(b"still here").await.unwrap();
    erin.recv_where(|f| f.ty == push::CHAT).await.unwrap();
    let stray: Vec<u32> = erin
        .rx
        .take_backlog()
        .iter()
        .map(|f| f.ty)
        .filter(|ty| ![push::CHAT, push::USER_CHANGE, push::SELFINFO].contains(ty))
        .collect();
    assert!(stray.is_empty(), "{stray:x?}");
}
