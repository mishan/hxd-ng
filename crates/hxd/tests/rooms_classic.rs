//! Rooms for period clients (`docs/chat-rooms.md` §6): a scripted 1.5
//! client, framed with the pinned `hxproto`, and an ng client on one
//! server, the classic one shown each room as a private chat it was
//! invited to by the system account.
//!
//! What is here is the classic wire's side of rooms: `/join` and the
//! invite it sends, 115's reply and the line after it, talking across
//! both wires, a room out of sight answered byte for byte as a chat that
//! does not exist, the read-only and removal notices, the lobby notice,
//! and a client that uses none of it hearing nothing of rooms.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::voice::fake::RecordingMedia;
use hxd_core::{Core, HistoryPolicy, Room, RoomStore, SystemPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::legacy::{push, Client, Frame, Login, UserRow};
use hxproto::messages::{tag, ClientHdr};
use serde_json::json;

const INVITE: u32 = 0x71;
const CHAT_USER_CHANGE: u32 = 0x75;
const CHAT_USER_PART: u32 = 0x76;
const CHAT_SUBJECT: u32 = 0x77;

const MEMBER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      voice_chat = true\n";

const ROOMS: &str = "[[room]]\nname = \"lounge\"\ntopic = \"anything goes\"\n\n\
                     [[room]]\nname = \"staff\"\nread = [\"carol\"]\n\n\
                     [[room]]\nname = \"announcements\"\npost = [\"carol\"]\n";

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
    rooms: hxd::rooms::FileRooms,
}

impl Server {
    /// The room called `name`, as the server wrote it back with its id.
    fn room(&self, name: &str) -> Room {
        self.rooms
            .load()
            .unwrap()
            .rooms
            .into_iter()
            .find(|r| r.name == name)
            .unwrap()
    }

    fn system(&self) -> u16 {
        self.core.system_uid().unwrap()
    }
}

/// Both frontends on one core keeping history and rooms, with `system`
/// as the system account where there is one, and `config` read as the
/// binary reads it for `[server]` and `[rooms]`.
async fn start(dir: &Path, system: Option<SystemPolicy>, config: &str) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, extra) in [
        ("alice", "[extra]\nset_subject = true\n"),
        ("bob", ""),
        ("carol", ""),
        ("dave", ""),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{MEMBER}{extra}"),
        )
        .unwrap();
    }
    let path = dir.join("rooms.toml");
    std::fs::write(&path, ROOMS).unwrap();
    let config: hxd::Config =
        toml::from_str(&config.replace("[rooms]", &format!("[rooms]\nfile = {path:?}"))).unwrap();

    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth: Arc<dyn hxd_core::AuthBackend> =
        Arc::new(hxd_auth_file::FileAuth::new(accounts).reserving("server"));
    let core = Core::new()
        .with_voice(Arc::new(RecordingMedia::new()), 8)
        .with_history(
            store,
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        );
    let core = hxd::rooms::with_rooms(core, &config).unwrap();
    let core = Arc::new(match system {
        Some(system) => core.with_system(system),
        None => core,
    });
    core.start_system_session();
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            caps: Caps::empty().with(cap::VOICE),
            version: config.server.version,
            ..ServerConfig::default()
        }),
        files: None,
        banner: None,
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "rooms".into(),
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
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
    Server {
        classic,
        ng,
        core,
        rooms: hxd::rooms::FileRooms::new(&path),
    }
}

async fn start_default(dir: &Path) -> Server {
    start(dir, Some(SystemPolicy::default()), "[rooms]\n").await
}

/// A 1.5 client logged in, with its user list, as a period client does.
async fn classic(s: &Server, who: &str) -> Client {
    let mut c = Client::login_at(s.classic, &Login::account(who, who, "pw"))
        .await
        .unwrap();
    c.user_list().await.unwrap();
    c
}

async fn ng(s: &Server, who: &str) -> hxd_testclient::ng::Client {
    hxd_testclient::ng::Client::account(s.ng, who, "pw", who)
        .await
        .unwrap()
        .0
}

/// `text` to the system account, and its answer.
async fn command(c: &mut Client, system: u16, text: &str) -> String {
    let trans = c
        .send(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, system.to_be_bytes().to_vec()),
                (tag::BODY, text.as_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    assert!(!c.reply(trans).await.unwrap().is_error());
    let answer = c
        .recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(u32::from(system)))
        .await
        .unwrap();
    mac(&answer.bytes(tag::BODY).unwrap())
}

/// Mac Roman text as the server writes it, for the two characters it
/// uses past ASCII.
fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0xd1 => '—',
            0xc9 => '…',
            b => char::from(b),
        })
        .collect()
}

fn cid(id: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, id.to_be_bytes().to_vec())
}

fn body(f: &Frame) -> String {
    mac(&f.bytes(tag::BODY).unwrap_or_default())
}

/// Everything `c` was sent before the reply to a ping.
async fn sent(c: &mut Client) -> Vec<Frame> {
    c.ping().await.unwrap();
    c.rx.take_backlog()
}

/// A task reply's flag and chunks: all of it a client can tell apart.
fn answer(f: &Frame) -> (u32, Vec<(u16, Vec<u8>)>) {
    (
        f.flag,
        f.chunks().map(|c| (c.tag, c.data.to_vec())).collect(),
    )
}

#[tokio::test]
async fn a_period_client_joins_through_the_system_account_and_talks_with_ng() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let lounge = s.room("lounge").id;
    let mut bob = ng(&s, "bob").await;
    bob.request("room_join", json!({ "room": lounge }))
        .await
        .unwrap();

    let mut alice = classic(&s, "alice").await;
    let me = u32::from(alice.uid.unwrap());
    let answer = command(&mut alice, s.system(), "/join #lounge").await;
    assert_eq!(answer, "ok: invited to #lounge");
    let invite = alice.recv_type(INVITE).await.unwrap();
    assert_eq!(invite.uint(tag::CHAT_ID), Some(lounge));
    assert_eq!(invite.uint(tag::UID), Some(u32::from(s.system())));
    assert_eq!(invite.bytes(tag::NAME).unwrap(), b"Server");

    let joined = alice
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(lounge)])
        .await
        .unwrap();
    let mut members: Vec<u32> = joined
        .all(tag::USER_LIST)
        .iter()
        .map(|row| u32::from(UserRow::parse(row).unwrap().uid))
        .collect();
    members.sort_unstable();
    let mut expected = vec![me, bob.uid.unwrap() as u32];
    expected.sort_unstable();
    assert_eq!(
        members, expected,
        "every session in the room, on either wire"
    );
    assert_eq!(joined.bytes(tag::CHAT_SUBJECT).unwrap(), b"anything goes");
    let notice = alice
        .recv_where(|f| f.ty == push::CHAT && f.uint(tag::CHAT_ID) == Some(lounge))
        .await
        .unwrap();
    assert_eq!(
        body(&notice),
        "\r *** #lounge — this room is public and logged"
    );
    assert_eq!(notice.uint(tag::CHAT_ID), Some(lounge));
    let ev = bob.event("room_member_joined").await.unwrap();
    assert_eq!(ev.data["user"]["uid"].as_u64(), Some(u64::from(me)));

    alice
        .send(
            ClientHdr::Chat.as_u32(),
            &[(tag::BODY, b"hello ng".to_vec()), cid(lounge)],
        )
        .await
        .unwrap();
    let line = bob
        .event_where("chat", |d| d["text"] == "hello ng")
        .await
        .unwrap();
    assert_eq!(line.data["room"], lounge);

    bob.request("chat", json!({ "room": lounge, "text": "hello classic" }))
        .await
        .unwrap();
    let line = alice
        .recv_where(|f| f.ty == push::CHAT && body(f).ends_with("hello classic"))
        .await
        .unwrap();
    assert_eq!(body(&line), "\r          bob:  hello classic");
    assert_eq!(line.uint(tag::CHAT_ID), Some(lounge));

    alice
        .send(
            ClientHdr::ChatSubject.as_u32(),
            &[cid(lounge), (tag::CHAT_SUBJECT, b"quiet please".to_vec())],
        )
        .await
        .unwrap();
    let subject = bob.event("subject").await.unwrap();
    assert_eq!(
        (subject.data["room"].as_u64(), &subject.data["subject"]),
        (Some(u64::from(lounge)), &json!("quiet please"))
    );
    let subject = alice.recv_type(CHAT_SUBJECT).await.unwrap();
    assert_eq!(subject.uint(tag::CHAT_ID), Some(lounge));

    // Already in: said so, and no window opened again.
    let answer = command(&mut alice, s.system(), "/join lounge").await;
    assert_eq!(answer, "ok: already in #lounge");
    assert!(!sent(&mut alice).await.iter().any(|f| f.ty == INVITE));

    // A member invites someone who may see the room, as into a private
    // chat; bob's leaving is tracked as a private chat's member.
    let mut carol = classic(&s, "carol").await;
    let carol_uid = carol.uid.unwrap();
    alice
        .call(
            ClientHdr::ChatInvite.as_u32(),
            &[cid(lounge), (tag::UID, carol_uid.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let invite = carol.recv_type(INVITE).await.unwrap();
    assert_eq!(invite.uint(tag::UID), Some(me));
    bob.request("room_part", json!({ "room": lounge }))
        .await
        .unwrap();
    let part = alice.recv_type(CHAT_USER_PART).await.unwrap();
    assert_eq!(part.uint(tag::UID), Some(bob.uid.unwrap() as u32));

    let list = command(&mut alice, s.system(), "/rooms").await;
    assert!(
        list.starts_with("#lounge — quiet please (1 here)\r"),
        "the session's own first: {list:?}"
    );
    alice
        .send(ClientHdr::ChatPart.as_u32(), &[cid(lounge)])
        .await
        .unwrap();
    sent(&mut alice).await;
    assert!(s.core.rooms_of(me as u16).is_empty());
}

#[tokio::test]
async fn a_room_out_of_sight_is_a_chat_that_does_not_exist() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let staff = s.room("staff").id;
    let nowhere = (1..).find(|id| !s.core.is_room(*id)).unwrap();
    let mut carol = classic(&s, "carol").await;
    // Joined with no invite at all: the gate admits, not the invite.
    carol
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(staff)])
        .await
        .unwrap();
    sent(&mut carol).await;
    let mut alice = Client::login_at(
        s.classic,
        &Login {
            caps: Some(1 << cap::VOICE),
            ..Login::account("alice", "alice", "pw")
        },
    )
    .await
    .unwrap();
    alice.user_list().await.unwrap();
    let carol_uid = carol.uid.unwrap().to_be_bytes().to_vec();

    let asks = [
        ("113", ClientHdr::ChatInvite, Some((tag::UID, carol_uid))),
        ("115", ClientHdr::ChatJoin, None),
        ("600", ClientHdr::VoiceJoin, None),
    ];
    for (name, ty, extra) in asks {
        let mut answers = Vec::new();
        for id in [staff, nowhere] {
            let mut chunks = vec![cid(id)];
            chunks.extend(extra.clone());
            let ty = ty.as_u32();
            let trans = alice.send(ty, &chunks).await.unwrap();
            answers.push(answer(&alice.reply(trans).await.unwrap()));
        }
        assert_eq!(answers[0], answers[1], "{name}");
        let missing = (tag::TASK_ERROR, b"That chat does not exist.".to_vec());
        assert!(answers[0].1.contains(&missing), "{name}: {:?}", answers[0]);
    }
    // No reply to these, and nothing done: carol hears nothing of them.
    for (ty, extra) in [
        (ClientHdr::ChatPart.as_u32(), None),
        (
            ClientHdr::ChatSubject.as_u32(),
            Some((tag::CHAT_SUBJECT, b"mine now".to_vec())),
        ),
        (
            ClientHdr::Chat.as_u32(),
            Some((tag::BODY, b"psst".to_vec())),
        ),
    ] {
        let mut chunks = vec![cid(staff)];
        chunks.extend(extra);
        alice.send(ty, &chunks).await.unwrap();
    }
    let alice_sent = sent(&mut alice).await;
    assert!(
        alice_sent.iter().all(|f| f.uint(tag::CHAT_ID).is_none()),
        "{alice_sent:?}"
    );
    let heard = sent(&mut carol).await;
    assert!(
        !heard.iter().any(
            |f| [push::CHAT, CHAT_SUBJECT, CHAT_USER_PART].contains(&f.ty)
                && f.uint(tag::CHAT_ID) == Some(staff)
        ),
        "{heard:?}"
    );
    assert_eq!(
        command(&mut alice, s.system(), "/join staff").await,
        command(&mut alice, s.system(), "/join nowhere").await,
    );
    assert!(!command(&mut alice, s.system(), "/rooms")
        .await
        .contains("staff"));
}

#[tokio::test]
async fn a_read_only_room_says_so_once() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let room = s.room("announcements").id;
    let mut carol = classic(&s, "carol").await;
    carol
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(room)])
        .await
        .unwrap();
    sent(&mut carol).await;
    let mut alice = classic(&s, "alice").await;
    alice
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(room)])
        .await
        .unwrap();
    for line in [&b"first"[..], b"second"] {
        alice
            .send(
                ClientHdr::Chat.as_u32(),
                &[(tag::BODY, line.to_vec()), cid(room)],
            )
            .await
            .unwrap();
    }
    let in_room: Vec<String> = sent(&mut alice)
        .await
        .iter()
        .filter(|f| f.ty == push::CHAT && f.uint(tag::CHAT_ID) == Some(room))
        .map(body)
        .collect();
    assert_eq!(
        in_room,
        [
            "\r *** #announcements — this room is public, logged and read-only",
            "\r *** this room is read-only",
        ]
    );
    assert!(!sent(&mut carol)
        .await
        .iter()
        .any(|f| f.ty == push::CHAT && f.uint(tag::CHAT_ID) == Some(room)));
}

#[tokio::test]
async fn a_parted_session_is_told_and_sent_a_part_naming_itself() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let lounge = s.room("lounge");
    let mut alice = classic(&s, "alice").await;
    let mut bob = classic(&s, "bob").await;
    for c in [&mut alice, &mut bob] {
        c.call(ClientHdr::ChatJoin.as_u32(), &[cid(lounge.id)])
            .await
            .unwrap();
    }
    s.rooms
        .put(&Room {
            read: vec!["bob".into()],
            ..lounge.clone()
        })
        .unwrap();
    s.core.reload_rooms().unwrap();
    let me = u32::from(alice.uid.unwrap());
    let told = alice
        .recv_where(|f| f.ty == push::CHAT && body(f).contains("removed"))
        .await
        .unwrap();
    assert_eq!(body(&told), "\r *** you were removed from #lounge");
    assert_eq!(told.uint(tag::CHAT_ID), Some(lounge.id));
    let part = alice.recv_type(CHAT_USER_PART).await.unwrap();
    assert_eq!(
        (part.uint(tag::CHAT_ID), part.uint(tag::UID)),
        (Some(lounge.id), Some(me))
    );
    let part = bob.recv_type(CHAT_USER_PART).await.unwrap();
    assert_eq!(part.uint(tag::UID), Some(me));
    assert!(!sent(&mut bob)
        .await
        .iter()
        .any(|f| body(f).contains("removed")));
}

/// The lobby notice: after the user list, once a day an account or a
/// guest's address, and only where it can point at commands.
#[tokio::test]
async fn the_lobby_notice_is_sent_once_a_day_and_only_to_classic() {
    const SEND: &str = " Send /rooms to Server to see them, /join <name> to join one.";
    let cases = [
        (
            "default",
            "[rooms]\n",
            true,
            Some("#announcements, #lounge."),
        ),
        (
            "one name",
            "[rooms]\nannounce_names = 1\n",
            true,
            Some("#announcements and 1 more."),
        ),
        ("announce off", "[rooms]\nannounce = false\n", true, None),
        ("commands off", "[rooms]\n", false, None),
    ];
    for (name, config, commands, rooms) in cases {
        let td = tempfile::tempdir().unwrap();
        let system = SystemPolicy {
            commands,
            ..SystemPolicy::default()
        };
        let s = start(td.path(), Some(system), config).await;
        // An ng login first, which lists rooms natively and is not the
        // account's one notice of the day.
        let mut bob_ng = ng(&s, "bob").await;
        bob_ng.request("ping", json!({})).await.unwrap();
        assert!(
            !bob_ng.rx.take_backlog().iter().any(|e| e.ev == "notice"),
            "{name}"
        );
        let told = rooms
            .map(|r| {
                vec![(
                    format!("\r *** Rooms: {r}{SEND}"),
                    Some(u32::from(s.system())),
                )]
            })
            .unwrap_or_default();
        let mut logins = Vec::new();
        for login in [
            Login::account("bob", "bob", "pw"),
            Login::guest("one"),
            Login::guest("two"),
            Login::account("bob", "bob", "pw"),
        ] {
            let mut c = Client::login_at(s.classic, &login).await.unwrap();
            c.user_list().await.unwrap();
            logins.push(notices(sent(&mut c).await));
        }
        let none = Vec::new();
        assert_eq!(
            logins,
            [told.clone(), told.clone(), none.clone(), none.clone()],
            "{name}: an account and an address, each once"
        );
        s.core.clock().advance(Duration::from_secs(25 * 3600));
        let mut c = classic(&s, "bob").await;
        assert_eq!(notices(sent(&mut c).await), told, "{name}: a day on");
    }
}

/// The lobby notices among `frames`, with the uid each came from.
fn notices(frames: Vec<Frame>) -> Vec<(String, Option<u32>)> {
    frames
        .iter()
        .filter(|f| f.ty == push::CHAT && body(f).contains("Rooms:"))
        .map(|f| (body(f), f.uint(tag::UID)))
        .collect()
}

/// `[server] version` below 151, read from the config as the binary reads
/// it: a client set to refuse private chat declines by itself, so `/join`
/// says what to turn off.
#[tokio::test]
async fn join_warns_where_a_client_would_decline_by_itself() {
    let cases = [
        (
            150,
            " — if no window opens, turn off \"refuse private chat\" and \"automatic response\"",
        ),
        (151, ""),
    ];
    for (version, warning) in cases {
        let td = tempfile::tempdir().unwrap();
        let config = format!("[server]\nversion = {version}\n[rooms]\n");
        let s = start(td.path(), Some(SystemPolicy::default()), &config).await;
        let mut alice = classic(&s, "alice").await;
        assert_eq!(
            command(&mut alice, s.system(), "/join lounge").await,
            format!("ok: invited to #lounge{warning}"),
            "{version}"
        );
    }
}

/// From the ng wire, which has no invite to answer, `/join` joins.
#[tokio::test]
async fn join_from_ng_joins_at_once() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let lounge = s.room("lounge").id;
    let mut bob = ng(&s, "bob").await;
    let system = s.system();
    bob.request("msg", json!({ "to": system, "text": "/join lounge" }))
        .await
        .unwrap();
    let answer = bob
        .event_where("msg", |d| d["from"]["uid"] == system)
        .await
        .unwrap();
    assert_eq!(answer.data["text"], "ok: joined #lounge");
    assert_eq!(s.core.rooms_of(bob.uid.unwrap() as u16), [lounge]);
    // It asked about a room, so it hears the room's traffic.
    let mut alice = classic(&s, "alice").await;
    alice
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(lounge)])
        .await
        .unwrap();
    let joined = bob.event("room_member_joined").await.unwrap();
    assert_eq!(joined.data["room"], lounge);
}

/// Inviting someone who may not see the room is refused as an invite to
/// a chat that does not exist.
#[tokio::test]
async fn an_invite_to_a_room_the_invitee_may_not_see_is_to_no_chat() {
    let td = tempfile::tempdir().unwrap();
    let s = start_default(td.path()).await;
    let staff = s.room("staff").id;
    let alice = classic(&s, "alice").await;
    let mut carol = classic(&s, "carol").await;
    carol
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(staff)])
        .await
        .unwrap();
    let alice_uid = alice.uid.unwrap().to_be_bytes().to_vec();
    let refused = carol
        .call(
            ClientHdr::ChatInvite.as_u32(),
            &[cid(staff), (tag::UID, alice_uid)],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, hxd_testclient::Error::Refused { text, .. }
            if text == "That chat does not exist."),
        "{refused:?}"
    );
}

/// At `max_joined` a join of a room it may see is refused as too many,
/// and a room out of sight is still a chat that does not exist.
#[tokio::test]
async fn a_join_past_max_joined_is_refused_without_telling_what_is_hidden() {
    let td = tempfile::tempdir().unwrap();
    let s = start(
        td.path(),
        Some(SystemPolicy::default()),
        "[rooms]\nmax_joined = 1\n",
    )
    .await;
    let mut alice = classic(&s, "alice").await;
    alice
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(s.room("lounge").id)])
        .await
        .unwrap();
    for (room, text) in [
        (
            "announcements",
            "You are in as many rooms as you may be. Leave one first.",
        ),
        ("staff", "That chat does not exist."),
    ] {
        let refused = alice
            .call(ClientHdr::ChatJoin.as_u32(), &[cid(s.room(room).id)])
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, hxd_testclient::Error::Refused { text: t, .. } if t == text),
            "{room}: {refused:?}"
        );
    }
}

/// A period client that uses nothing new: no system account to announce
/// rooms, and rooms busy around it. It hears the lobby as it always did,
/// and nothing of any room.
#[tokio::test]
async fn a_client_that_never_joins_hears_nothing_of_rooms() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), None, "[rooms]\n").await;
    let lounge = s.room("lounge").id;
    let mut dave = classic(&s, "dave").await;
    let mut alice = classic(&s, "alice").await;
    alice
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(lounge)])
        .await
        .unwrap();
    let mut bob = ng(&s, "bob").await;
    bob.request("room_join", json!({ "room": lounge }))
        .await
        .unwrap();
    bob.request("chat", json!({ "room": lounge, "text": "in the lounge" }))
        .await
        .unwrap();
    for (ty, said) in [
        (ClientHdr::Chat.as_u32(), (tag::BODY, b"me too".to_vec())),
        (
            ClientHdr::ChatSubject.as_u32(),
            (tag::CHAT_SUBJECT, b"busy".to_vec()),
        ),
    ] {
        alice.send(ty, &[said, cid(lounge)]).await.unwrap();
    }
    alice.chat(b"in the lobby").await.unwrap();
    alice
        .recv_where(|f| f.ty == push::CHAT && body(f).ends_with("in the lobby"))
        .await
        .unwrap();
    let heard = sent(&mut dave).await;
    assert!(
        heard.iter().all(|f| f.uint(tag::CHAT_ID).is_none()
            && ![INVITE, CHAT_USER_CHANGE, CHAT_USER_PART, CHAT_SUBJECT].contains(&f.ty)),
        "{heard:?}"
    );
    let lobby: Vec<String> = heard
        .iter()
        .filter(|f| f.ty == push::CHAT)
        .map(body)
        .collect();
    assert_eq!(lobby, ["\r        alice:  in the lobby"]);
}
