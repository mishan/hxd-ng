//! Rooms on the ng wire (`docs/chat-rooms.md` §7): a real server with a
//! chat log, scripted WebSocket clients, and the rooms a manager makes
//! from one of them.
//!
//! What is here is what the domain's tests cannot show: what each client
//! is sent and answered, that a room a session may not see is one that
//! does not exist on every request naming it, that a client which never
//! asks about rooms is sent nothing about them, and that a client cut off
//! catches up on each of its rooms from `sync`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::voice::fake::RecordingMedia;
use hxd_core::{Core, HistoryPolicy, ModerationPolicy, RoomPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::ng::{Client, Resumed};
use hxd_testclient::Error;
use serde_json::{json, Value};

const MEMBER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      voice_chat = true\n";

async fn start(dir: &Path) -> SocketAddr {
    start_with_core(dir).await.0
}

/// A server, and its domain for what an operator does beside it: an
/// account file or the rooms file edited, and the SIGHUP that follows.
async fn start_with_core(dir: &Path) -> (SocketAddr, Arc<Core>) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let account = |login: &str, extra: &str| {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{MEMBER}{extra}"),
        )
        .unwrap();
    };
    for login in ["alice", "bob", "eve"] {
        account(login, "");
    }
    account("dave", "[extra]\nset_subject = true\n");
    account("boss", "[extra]\nmanage_rooms = true\nset_subject = true\n");
    // The kick bit makes a moderator.
    account("carol", "disconnect_users = true\n");
    std::fs::write(
        accounts.join("frank.toml"),
        format!("name = \"frank\"\npassword = \"pw\"\nroles = [\"staff\"]\n[access]\n{MEMBER}"),
    )
    .unwrap();
    let roles = dir.join("roles.toml");
    std::fs::write(&roles, "[role.staff]\ntitle = \"Staff\"\n").unwrap();

    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth = Arc::new(
        hxd_auth_file::FileAuth::new(accounts)
            .with_roles(roles)
            .unwrap(),
    );
    let core = Core::new()
        .with_admin(auth.clone())
        .with_voice(Arc::new(RecordingMedia::new()), 8)
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
            RoomPolicy {
                max_joined: 2,
                ..RoomPolicy::default()
            },
        )
        .unwrap();
    let core = Arc::new(core);
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "rooms".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
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
    (addr, core)
}

async fn login(addr: SocketAddr, who: &str) -> (Client, Value) {
    Client::account(addr, who, "pw", who).await.unwrap()
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

async fn create(boss: &mut Client, params: Value) -> u64 {
    ok(boss, "room_create", params).await["room"]["id"]
        .as_u64()
        .unwrap()
}

/// What `c` has been sent so far, everything it was sent before the
/// reply to a ping having arrived ahead of that reply.
async fn sent(c: &mut Client) -> Vec<hxd_testclient::ng::Event> {
    ok(c, "ping", json!({})).await;
    c.rx.take_backlog()
}

fn no_seq_faults(c: &Client) {
    assert!(c.rx.seq_faults.is_empty(), "{:?}", c.rx.seq_faults);
}

#[tokio::test]
async fn create_list_join_talk_and_page() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, hello) = login(addr, "boss").await;
    assert!(hello["caps"].as_array().unwrap().contains(&json!("rooms")));
    assert_eq!(hello["self"]["manage_rooms"], true);
    let room = create(
        &mut boss,
        json!({ "name": "lounge", "topic": "anything goes" }),
    )
    .await;

    let (mut alice, hello) = login(addr, "alice").await;
    assert!(hello["self"].get("manage_rooms").is_none());
    assert_eq!(hello["rooms"]["lobby"]["id"], 0);
    assert_eq!(hello["rooms"]["max_joined"], 2);
    let listed = &hello["rooms"]["list"][0];
    assert_eq!(listed["id"], room);
    assert_eq!(listed["name"], "lounge");
    assert_eq!(listed["may_post"], true);
    // Who is admitted is a manager's business alone.
    assert!(listed.get("read").is_none());
    let mine = ok(&mut boss, "rooms", json!({})).await;
    assert_eq!(mine["list"][0]["read"], json!([]));

    let joined = ok(&mut alice, "room_join", json!({ "room": room })).await;
    assert_eq!(joined["topic"], "anything goes");
    assert_eq!(joined["topic_by"], "boss");
    assert_eq!(joined["may_post"], true);
    // A second join is answered as the first, and tells nobody again.
    assert_eq!(
        ok(&mut alice, "room_join", json!({ "room": room })).await,
        joined
    );
    assert_eq!(joined["members"], json!([alice.uid]));

    let (mut bob, _) = login(addr, "bob").await;
    ok(&mut bob, "room_join", json!({ "room": room })).await;
    let ev = alice.event("room_member_joined").await.unwrap();
    assert_eq!(
        (ev.data["room"].as_u64(), ev.data["user"]["uid"].as_u64()),
        (Some(room), bob.uid)
    );

    ok(
        &mut bob,
        "chat",
        json!({ "room": room, "text": "in the lounge" }),
    )
    .await;
    ok(&mut bob, "chat", json!({ "text": "in the lobby" })).await;
    let line = alice
        .event_where("chat", |d| d["text"] == "in the lounge")
        .await
        .unwrap();
    assert_eq!(line.data["room"], room);
    let lobby = alice
        .event_where("chat", |d| d["text"] == "in the lobby")
        .await
        .unwrap();
    assert!(
        lobby.data.get("room").is_none(),
        "the lobby's carry no room"
    );

    let page = ok(&mut alice, "history", json!({ "room": room })).await;
    let lines = page["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], line.data["id"]);
    let lobby_page = ok(&mut alice, "history", json!({})).await;
    assert!(lobby_page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l["text"] != "in the lounge"));

    // A topic: its members hear the subject, and one that may see it
    // and is not in it hears the room changed.
    let (mut eve, _) = login(addr, "eve").await;
    ok(&mut eve, "rooms", json!({})).await;
    ok(
        &mut boss,
        "room_topic",
        json!({ "room": room, "topic": "quiet now" }),
    )
    .await;
    let subject = alice.event("subject").await.unwrap();
    assert_eq!(
        (subject.data["room"].as_u64(), &subject.data["subject"]),
        (Some(room), &json!("quiet now"))
    );
    let changed = eve.event("room_changed").await.unwrap();
    assert_eq!(changed.data["room"]["topic"], "quiet now");
    assert!(!sent(&mut alice)
        .await
        .iter()
        .any(|e| e.ev == "room_changed"));

    ok(&mut bob, "room_part", json!({ "room": room })).await;
    let parted = alice.event("room_member_parted").await.unwrap();
    assert_eq!(parted.data, json!({ "room": room, "uid": bob.uid }));
    for c in [&alice, &bob, &boss, &eve] {
        no_seq_faults(c);
    }
}

#[tokio::test]
async fn the_lobby_is_neither_joined_nor_left_and_a_session_is_in_so_many_rooms() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let mut rooms = Vec::new();
    for name in ["a", "b", "c"] {
        rooms.push(create(&mut boss, json!({ "name": name })).await);
    }
    let (mut alice, _) = login(addr, "alice").await;
    for req in ["room_join", "room_part"] {
        for params in [json!({}), json!({ "room": 0 })] {
            assert_eq!(
                refused(&mut alice, req, params).await,
                "bad_request",
                "{req}"
            );
        }
    }
    ok(&mut alice, "room_join", json!({ "room": rooms[0] })).await;
    ok(&mut alice, "room_join", json!({ "room": rooms[1] })).await;
    let past = refused(&mut alice, "room_join", json!({ "room": rooms[2] })).await;
    assert_eq!(past, "too_many_rooms");
}

/// A room that names who may read it does not exist for anyone else, on
/// every request that names it: the same answers as for an id nobody
/// holds. Only a session that may see it is told it is not a member.
#[tokio::test]
async fn a_room_an_outsider_may_not_see_does_not_exist_for_it() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let staff = create(&mut boss, json!({ "name": "staff", "read": ["alice"] })).await;
    let (mut eve, hello) = login(addr, "eve").await;
    assert_eq!(hello["rooms"]["list"], json!([]));
    assert_eq!(ok(&mut eve, "rooms", json!({})).await["list"], json!([]));

    let asks = |room: u64| {
        [
            ("room_join", json!({ "room": room }), "no_such_room"),
            ("room_part", json!({ "room": room }), "no_such_room"),
            (
                "room_topic",
                json!({ "room": room, "topic": "hi" }),
                "no_such_room",
            ),
            (
                "chat",
                json!({ "room": room, "text": "hi" }),
                "no_such_room",
            ),
            ("history", json!({ "room": room }), "no_such_room"),
            ("voice_join", json!({ "cid": room }), "no_such_chat"),
        ]
    };
    for room in [staff, 12345] {
        for (req, params, code) in asks(room) {
            assert_eq!(
                refused(&mut eve, req, params).await,
                code,
                "{req} of {room}"
            );
        }
    }
    let (mut alice, _) = login(addr, "alice").await;
    for (req, params) in [
        ("chat", json!({ "room": staff, "text": "hi" })),
        ("room_part", json!({ "room": staff })),
        ("voice_join", json!({ "cid": staff })),
    ] {
        assert_eq!(
            refused(&mut alice, req, params).await,
            "not_a_member",
            "{req}"
        );
    }
}

#[tokio::test]
async fn a_read_only_room_refuses_a_send() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let news = create(
        &mut boss,
        json!({ "name": "announcements", "post": ["boss"] }),
    )
    .await;
    let (mut alice, _) = login(addr, "alice").await;
    let joined = ok(&mut alice, "room_join", json!({ "room": news })).await;
    assert_eq!(joined["may_post"], false);
    let said = json!({ "room": news, "text": "me too" });
    assert_eq!(refused(&mut alice, "chat", said).await, "read_only");
    ok(&mut boss, "room_join", json!({ "room": news })).await;
    ok(&mut boss, "chat", json!({ "room": news, "text": "news" })).await;
    alice
        .event_where("chat", |d| d["text"] == "news")
        .await
        .unwrap();
}

#[tokio::test]
async fn managing_rooms_is_a_managers_and_refuses_what_no_room_may_be() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(&mut boss, json!({ "name": "lounge" })).await;
    for (params, code) in [
        (json!({ "name": "lounge" }), "name_taken"),
        (json!({ "name": "Not A Name" }), "bad_request"),
        (
            json!({ "name": "staff", "read": ["@everyone"] }),
            "bad_request",
        ),
    ] {
        assert_eq!(refused(&mut boss, "room_create", params).await, code);
    }
    let (mut alice, _) = login(addr, "alice").await;
    for (req, params) in [
        ("room_create", json!({ "name": "mine" })),
        ("room_edit", json!({ "room": room, "name": "mine" })),
        ("room_archive", json!({ "room": room })),
        ("room_unarchive", json!({ "room": room })),
    ] {
        assert_eq!(
            refused(&mut alice, req, params).await,
            "access_denied",
            "{req}"
        );
    }
    let edited = ok(
        &mut boss,
        "room_edit",
        json!({ "room": room, "name": "hangout", "max_lines": 50 }),
    )
    .await;
    assert_eq!(edited["room"]["name"], "hangout");
    assert_eq!(edited["room"]["max_lines"], 50);
    let cleared = ok(
        &mut boss,
        "room_edit",
        json!({ "room": room, "max_lines": null }),
    )
    .await;
    assert!(cleared["room"].get("max_lines").is_none());
}

/// An archive parts its members, saying why, and takes the room out of
/// every listing; bringing it back puts it in again.
#[tokio::test]
async fn archive_parts_members_and_unarchive_brings_the_room_back() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(&mut boss, json!({ "name": "lounge" })).await;
    let (mut alice, _) = login(addr, "alice").await;
    let (mut bob, _) = login(addr, "bob").await;
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    ok(&mut bob, "rooms", json!({})).await;

    ok(&mut boss, "room_archive", json!({ "room": room })).await;
    let alice_heard: Vec<(String, Value)> = sent(&mut alice)
        .await
        .into_iter()
        .filter(|e| e.ev.starts_with("room_"))
        .map(|e| (e.ev, e.data))
        .collect();
    assert_eq!(
        alice_heard,
        [
            (
                "room_member_parted".into(),
                json!({ "room": room, "uid": alice.uid, "reason": "archived" })
            ),
            ("room_removed".into(), json!({ "room": room })),
        ]
    );
    assert_eq!(bob.event("room_removed").await.unwrap().data["room"], room);
    assert_eq!(ok(&mut bob, "rooms", json!({})).await["list"], json!([]));
    let join = json!({ "room": room });
    assert_eq!(
        refused(&mut alice, "room_join", join.clone()).await,
        "no_such_room"
    );

    ok(&mut boss, "room_unarchive", json!({ "room": room })).await;
    for c in [&mut alice, &mut bob] {
        assert_eq!(
            c.event("room_added").await.unwrap().data["room"]["id"],
            room
        );
    }
    ok(&mut alice, "room_join", join).await;
    for c in [&alice, &bob] {
        no_seq_faults(c);
    }
}

/// A client written before rooms is sent nothing about one, whatever
/// happens in them, and its seqs stay whole; a member leaving the server
/// is told once, by `user_parted`.
#[tokio::test]
async fn a_client_that_never_asks_about_rooms_hears_nothing_of_them() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut dave, _) = login(addr, "dave").await;
    // The lobby's subject is today's protocol, not a rooms request.
    ok(&mut dave, "room_topic", json!({ "topic": "lobby talk" })).await;
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(&mut boss, json!({ "name": "lounge" })).await;
    let (mut alice, _) = login(addr, "alice").await;
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    ok(&mut boss, "room_join", json!({ "room": room })).await;
    ok(&mut alice, "chat", json!({ "room": room, "text": "psst" })).await;
    ok(
        &mut boss,
        "room_edit",
        json!({ "room": room, "name": "hangout" }),
    )
    .await;
    ok(
        &mut boss,
        "room_topic",
        json!({ "room": room, "topic": "new" }),
    )
    .await;
    alice.logout().await.unwrap();

    boss.event("user_parted").await.unwrap();
    let boss_heard = sent(&mut boss).await;
    assert!(
        !boss_heard.iter().any(|e| e.ev == "room_member_parted"),
        "{boss_heard:?}"
    );

    ok(&mut boss, "chat", json!({ "text": "lobby" })).await;
    dave.event_where("chat", |d| d["text"] == "lobby")
        .await
        .unwrap();
    let heard = sent(&mut dave).await;
    assert!(
        heard
            .iter()
            .all(|e| !e.ev.starts_with("room_") && e.data.get("room").is_none()),
        "{heard:?}"
    );
    assert!(heard.iter().all(|e| e.ev != "unsupported"), "{heard:?}");
    no_seq_faults(&dave);
    no_seq_faults(&boss);
}

/// A redaction of a room's line goes to whoever may read the room,
/// member or not, and to nobody who may not.
#[tokio::test]
async fn a_redaction_in_a_room_reaches_its_readers_and_no_one_else() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(
        &mut boss,
        json!({ "name": "staff", "read": ["alice", "bob"] }),
    )
    .await;
    let (mut alice, _) = login(addr, "alice").await;
    let (mut bob, _) = login(addr, "bob").await;
    let (mut eve, _) = login(addr, "eve").await;
    ok(&mut eve, "rooms", json!({})).await;
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    ok(&mut alice, "chat", json!({ "room": room, "text": "oops" })).await;
    let id = alice
        .event_where("chat", |d| d["text"] == "oops")
        .await
        .unwrap()
        .data["id"]
        .clone();
    // Bob paged it without joining.
    let page = ok(&mut bob, "history", json!({ "room": room })).await;
    assert_eq!(page["lines"][0]["id"], id);

    let (mut carol, _) = login(addr, "carol").await;
    ok(&mut carol, "redact", json!({ "id": id, "reason": "oops" })).await;
    for c in [&mut alice, &mut bob] {
        let ev = c.event("chat_redacted").await.unwrap();
        assert_eq!(ev.data, json!({ "id": id, "room": room }));
    }
    let heard = sent(&mut eve).await;
    assert!(heard.iter().all(|e| e.ev != "chat_redacted"), "{heard:?}");
}

/// A client cut off past what its buffer holds catches up on each of its
/// rooms: `sync` says how far each has got, and `history` after its own
/// cursor fills the gap.
#[tokio::test]
async fn resync_catches_up_per_room() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(&mut boss, json!({ "name": "lounge" })).await;
    let (mut alice, _) = login(addr, "alice").await;
    ok(&mut alice, "room_join", json!({ "room": room })).await;
    ok(&mut boss, "room_join", json!({ "room": room })).await;
    ok(&mut boss, "chat", json!({ "room": room, "text": "seen" })).await;
    let cursor = alice
        .event_where("chat", |d| d["text"] == "seen")
        .await
        .unwrap()
        .data["id"]
        .as_u64()
        .unwrap();
    let session = alice.session.clone().unwrap();
    sent(&mut alice).await;
    let last_seq = alice.rx.last_seq;
    alice.close().await.unwrap();
    // Detached: more than its buffer holds, then two lines in the room.
    let (mut bob, _) = login(addr, "bob").await;
    for i in 0..600 {
        bob.chat(&format!("{i}")).await.unwrap();
    }
    ok(
        &mut boss,
        "chat",
        json!({ "room": room, "text": "missed one" }),
    )
    .await;
    ok(
        &mut boss,
        "chat",
        json!({ "room": room, "text": "missed two" }),
    )
    .await;

    let (mut alice, resumed) = Client::resume(addr, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert_eq!(resumed, Resumed::ResyncRequired);
    let synced = alice.sync().await.unwrap();
    let joined = synced["rooms"]["joined"].as_array().unwrap();
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0]["id"], room);
    assert!(joined[0]["last_id"].as_u64().unwrap() > cursor);
    let page = ok(
        &mut alice,
        "history",
        json!({ "room": room, "after": cursor }),
    )
    .await;
    let texts: Vec<&Value> = page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| &l["text"])
        .collect();
    assert_eq!(texts, [&json!("missed one"), &json!("missed two")]);
    assert_eq!(joined[0]["last_id"], page["lines"][1]["id"]);
}

/// What an operator does beside the server reaches the rooms-aware: an
/// account that loses what let it in is parted, saying why, and loses the
/// room; one no longer a manager is shown the room without its gates;
/// and a room added to or taken out of the file by hand is announced to
/// those who asked about rooms and nobody else.
#[tokio::test]
async fn an_operators_edits_reach_the_rooms_aware() {
    let td = tempfile::tempdir().unwrap();
    let (addr, core) = start_with_core(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let staff = create(&mut boss, json!({ "name": "staff", "read": ["alice"] })).await;
    let lounge = create(&mut boss, json!({ "name": "lounge" })).await;
    let (mut alice, _) = login(addr, "alice").await;
    let (mut eve, _) = login(addr, "eve").await;
    let (mut dave, _) = login(addr, "dave").await;
    ok(&mut alice, "room_join", json!({ "room": staff })).await;
    ok(&mut eve, "rooms", json!({})).await;

    let accounts = td.path().join("accounts");
    std::fs::write(
        accounts.join("alice.toml"),
        "name = \"alice\"\npassword = \"pw\"\n[access]\nsend_chat = true\n",
    )
    .unwrap();
    std::fs::write(
        accounts.join("boss.toml"),
        format!("name = \"boss\"\npassword = \"pw\"\n[access]\n{MEMBER}"),
    )
    .unwrap();
    core.reload_accounts();
    let heard: Vec<(String, Value)> = sent(&mut alice)
        .await
        .into_iter()
        .filter(|e| e.ev.starts_with("room_"))
        .map(|e| (e.ev, e.data))
        .collect();
    assert_eq!(
        heard[0],
        (
            "room_member_parted".into(),
            json!({ "room": staff, "uid": alice.uid, "reason": "access" })
        )
    );
    // Without read chat, it may read no room at all. Removals go out in
    // room id order, and ids are random.
    let mut removed: Vec<u64> = heard[1..]
        .iter()
        .map(|(ev, data)| {
            assert_eq!(ev, "room_removed");
            data["room"].as_u64().unwrap()
        })
        .collect();
    removed.sort_unstable();
    let mut expected = vec![staff, lounge];
    expected.sort_unstable();
    assert_eq!(removed, expected);
    // The staff room is one boss no longer sees at all, and the lounge
    // one whose gates are no longer its business.
    assert_eq!(
        boss.event("room_removed").await.unwrap().data["room"],
        staff
    );
    let changed = boss.event("room_changed").await.unwrap().data["room"].clone();
    assert_eq!(changed["id"], lounge);
    assert!(changed.get("read").is_none(), "{changed}");

    let rooms_toml = td.path().join("rooms.toml");
    let before = std::fs::read_to_string(&rooms_toml).unwrap();
    std::fs::write(
        &rooms_toml,
        format!("{before}\n[[room]]\nname = \"added\"\n"),
    )
    .unwrap();
    core.reload_rooms().unwrap();
    let added = eve.event("room_added").await.unwrap().data["room"].clone();
    assert_eq!(added["name"], "added");
    std::fs::write(&rooms_toml, before).unwrap();
    core.reload_rooms().unwrap();
    assert_eq!(
        eve.event("room_removed").await.unwrap().data["room"],
        added["id"]
    );

    let heard = sent(&mut dave).await;
    assert!(
        heard.iter().all(|e| !e.ev.starts_with("room_")),
        "{heard:?}"
    );
    for c in [&alice, &boss, &eve, &dave] {
        no_seq_faults(c);
    }
}

/// One reload that takes a room from several members at once: each is
/// told once that it was parted and nothing of the others, and the
/// member who stays hears one part for each.
#[tokio::test]
async fn a_reload_parting_many_tells_each_of_them_once() {
    let td = tempfile::tempdir().unwrap();
    let (addr, core) = start_with_core(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    let lounge = create(&mut boss, json!({ "name": "lounge" })).await;
    let mut losing = Vec::new();
    for who in ["alice", "bob", "eve"] {
        let (mut c, _) = login(addr, who).await;
        ok(&mut c, "room_join", json!({ "room": lounge })).await;
        losing.push(c);
    }
    let (mut dave, _) = login(addr, "dave").await;
    ok(&mut dave, "room_join", json!({ "room": lounge })).await;
    for c in losing.iter_mut().chain([&mut dave]) {
        sent(c).await;
    }

    let accounts = td.path().join("accounts");
    for who in ["alice", "bob", "eve"] {
        std::fs::write(
            accounts.join(format!("{who}.toml")),
            format!("name = \"{who}\"\npassword = \"pw\"\n[access]\nsend_chat = true\n"),
        )
        .unwrap();
    }
    core.reload_accounts();
    let parts = |events: Vec<hxd_testclient::ng::Event>| -> Vec<Value> {
        events
            .into_iter()
            .filter(|e| e.ev == "room_member_parted")
            .map(|e| e.data)
            .collect()
    };
    for c in &mut losing {
        let uid = c.uid;
        assert_eq!(
            parts(sent(c).await),
            [json!({ "room": lounge, "uid": uid, "reason": "access" })]
        );
    }
    let mut heard: Vec<u64> = parts(sent(&mut dave).await)
        .iter()
        .map(|d| d["uid"].as_u64().unwrap())
        .collect();
    heard.sort_unstable();
    let mut expected: Vec<u64> = losing.iter().map(|c| c.uid.unwrap()).collect();
    expected.sort_unstable();
    assert_eq!(heard, expected);
    for c in losing.iter().chain([&dave]) {
        no_seq_faults(c);
    }
}

/// The operator moves room management and moderation: boss stops
/// managing rooms, carol stops moderating, and dave starts doing both.
fn reassign(dir: &Path) {
    let write = |login: &str, access: &str, extra: &str| {
        std::fs::write(
            dir.join("accounts").join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"pw\"\n[access]\n{MEMBER}{access}[extra]\n{extra}"
            ),
        )
        .unwrap();
    };
    write("boss", "", "set_subject = true\n");
    write("carol", "disconnect_users = true\n", "moderate = false\n");
    write("dave", "", "manage_rooms = true\nmoderate = true\n");
}

/// `manage_rooms` and `moderate` are no access bits, so
/// `account_changed` says them beside the bits: a session made a manager
/// or a moderator by a reload is told so, and one that stops being one
/// is told by their absence.
#[tokio::test]
async fn a_reload_tells_a_session_it_manages_or_moderates_or_no_longer_does() {
    let td = tempfile::tempdir().unwrap();
    let (addr, core) = start_with_core(td.path()).await;
    let (mut boss, hello) = login(addr, "boss").await;
    assert_eq!(hello["self"]["manage_rooms"], true);
    let (mut carol, hello) = login(addr, "carol").await;
    assert_eq!(hello["self"]["moderator"], true);
    let (mut dave, _) = login(addr, "dave").await;

    reassign(td.path());
    core.reload_accounts();
    for c in [&mut boss, &mut carol] {
        let told = c.event("account_changed").await.unwrap().data;
        assert!(told.get("manage_rooms").is_none(), "{told}");
        assert!(told.get("moderator").is_none(), "{told}");
    }
    let told = dave.event("account_changed").await.unwrap().data;
    assert_eq!(told["manage_rooms"], true, "{told}");
    assert_eq!(told["moderator"], true, "{told}");
    for c in [&boss, &carol, &dave] {
        no_seq_faults(c);
    }
}

/// What a reload changed while a session was away, in a gap that
/// swallowed its `account_changed`, `sync` says again.
#[tokio::test]
async fn sync_repeats_management_and_moderation_a_gap_swallowed() {
    let td = tempfile::tempdir().unwrap();
    let (addr, core) = start_with_core(td.path()).await;
    let mut away = Vec::new();
    for who in ["boss", "dave"] {
        let (mut c, _) = login(addr, who).await;
        sent(&mut c).await;
        away.push((c.session.clone().unwrap(), c.rx.last_seq));
        c.close().await.unwrap();
    }
    // More than a detached session's buffer holds.
    let (mut bob, _) = login(addr, "bob").await;
    for i in 0..600 {
        bob.chat(&format!("{i}")).await.unwrap();
    }
    reassign(td.path());
    core.reload_accounts();

    let mut synced = Vec::new();
    for (session, last_seq) in away {
        let (mut c, resumed) = Client::resume(addr, session, last_seq, Vec::new())
            .await
            .unwrap();
        assert_eq!(resumed, Resumed::ResyncRequired);
        synced.push(c.sync().await.unwrap()["accounts"].clone());
    }
    assert!(synced[0].get("manage_rooms").is_none(), "{}", synced[0]);
    assert_eq!(synced[1]["manage_rooms"], true, "{}", synced[1]);
    assert_eq!(synced[1]["moderator"], true, "{}", synced[1]);
}

/// Awareness is the session's: one that asked about rooms and is in
/// none is still told of a new room after a resume.
#[tokio::test]
async fn awareness_survives_a_resume() {
    let td = tempfile::tempdir().unwrap();
    let addr = start(td.path()).await;
    let (mut alice, _) = login(addr, "alice").await;
    ok(&mut alice, "rooms", json!({})).await;
    let session = alice.session.clone().unwrap();
    let last_seq = alice.rx.last_seq;
    alice.close().await.unwrap();
    let (mut alice, resumed) = Client::resume(addr, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert!(matches!(resumed, Resumed::Replayed(_)), "{resumed:?}");
    let (mut boss, _) = login(addr, "boss").await;
    let room = create(&mut boss, json!({ "name": "lounge" })).await;
    assert_eq!(
        alice.event("room_added").await.unwrap().data["room"]["id"],
        room
    );
    no_seq_faults(&alice);
}

/// A gate naming `@staff` admits whoever holds it and nobody else, on
/// every request, and an account that stops holding it is parted on the
/// reload that says so.
#[tokio::test]
async fn a_role_in_a_gate_admits_its_holders_until_they_stop_holding_it() {
    let td = tempfile::tempdir().unwrap();
    let (addr, core) = start_with_core(td.path()).await;
    let (mut boss, _) = login(addr, "boss").await;
    assert_eq!(
        refused(
            &mut boss,
            "room_create",
            json!({ "name": "x", "read": ["@nobody"] })
        )
        .await,
        "no_such_role"
    );
    let staff = create(&mut boss, json!({ "name": "staff", "read": ["@staff"] })).await;
    let briefing = create(&mut boss, json!({ "name": "briefing", "post": ["@staff"] })).await;
    assert_eq!(
        refused(
            &mut boss,
            "room_edit",
            json!({ "room": briefing, "post": ["@nobody"] })
        )
        .await,
        "no_such_role"
    );

    let (mut frank, hello) = login(addr, "frank").await;
    let listed = |hello: &Value| -> Vec<u64> {
        hello["rooms"]["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_u64().unwrap())
            .collect()
    };
    assert!(listed(&hello).contains(&staff));
    ok(&mut frank, "room_join", json!({ "room": staff })).await;
    ok(&mut frank, "chat", json!({ "room": staff, "text": "hi" })).await;
    let joined = ok(&mut frank, "room_join", json!({ "room": briefing })).await;
    assert_eq!(joined["may_post"], true);

    let (mut eve, hello) = login(addr, "eve").await;
    assert!(!listed(&hello).contains(&staff));
    assert_eq!(
        refused(&mut eve, "room_join", json!({ "room": staff })).await,
        "no_such_room"
    );
    let joined = ok(&mut eve, "room_join", json!({ "room": briefing })).await;
    assert_eq!(joined["may_post"], false);
    // A login with no password is shared by whoever knows it, and a role
    // it lists lets none of them in.
    std::fs::write(
        td.path().join("accounts").join("lobby.toml"),
        format!("name = \"lobby\"\nroles = [\"staff\"]\n[access]\n{MEMBER}"),
    )
    .unwrap();
    let (mut shared, hello) = Client::account(addr, "lobby", "", "lobby").await.unwrap();
    assert!(!listed(&hello).contains(&staff));
    assert_eq!(
        refused(&mut shared, "room_join", json!({ "room": staff })).await,
        "no_such_room"
    );
    sent(&mut frank).await;

    // The role gone from the roles file by hand, frank's file still
    // listing it: a name with no role behind it passes no gate.
    std::fs::write(td.path().join("roles.toml"), "").unwrap();
    core.reload_accounts();
    let heard: Vec<(String, Value)> = sent(&mut frank)
        .await
        .into_iter()
        .filter(|e| e.ev.starts_with("room_"))
        .map(|e| (e.ev, e.data))
        .collect();
    assert!(
        heard.contains(&(
            "room_member_parted".into(),
            json!({ "room": staff, "uid": frank.uid, "reason": "access" })
        )),
        "{heard:?}"
    );
    assert!(heard.contains(&("room_removed".into(), json!({ "room": staff }))));
    assert!(
        heard.iter().any(|(ev, d)| ev == "room_changed"
            && d["room"]["id"] == briefing
            && d["room"]["may_post"] == false),
        "{heard:?}"
    );
    assert_eq!(
        refused(
            &mut frank,
            "chat",
            json!({ "room": briefing, "text": "hi" })
        )
        .await,
        "read_only"
    );
    for c in [&frank, &eve] {
        no_seq_faults(c);
    }
}
