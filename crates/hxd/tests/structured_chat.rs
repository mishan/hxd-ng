//! The Structured Chat draft on the classic wire (`docs/chat-history.md`
//! §12), against servers built from a real config: a session with
//! capability bit 17 is sent each line as its Chat History entry beside
//! the formatted text, and a session without it, or on the ng wire, is
//! sent what it always was.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use hxd_core::RoomStore;
use hxd_session::structured::{DATA_CHAT_LINE, EPHEMERAL};
use hxd_testclient::legacy::{push, Client, Frame, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::Value;

const STRUCTURED: u32 = 1 << 17;
const EMOJI: u32 = 1 << 20;
const EMOJI_REFS_FIELD: u16 = hxd_session::emoji::DATA_EMOJI_REFS;
const UTF8: u32 = 1 << 1;
const HISTORY: u32 = 1 << 4;
const ACTION: u16 = 1;
const SERVER_MSG: u16 = 2;

const MEMBER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      create_pchats = true\nuse_any_name = true\n";

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
    rooms: std::path::PathBuf,
}

impl Server {
    fn room(&self, name: &str) -> u32 {
        hxd::rooms::FileRooms::new(&self.rooms)
            .load()
            .unwrap()
            .rooms
            .into_iter()
            .find(|r| r.name == name)
            .unwrap()
            .id
    }
}

/// A server keeping history in `dir`, with `extra` added to its config.
async fn start(dir: &Path, extra: &str) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, access) in [
        ("alice", MEMBER),
        ("bob", MEMBER),
        ("dave", MEMBER),
        ("erin", MEMBER),
        ("frank", MEMBER),
        ("gina", MEMBER),
        (
            "admin",
            "read_chat = true\nsend_chat = true\ndisconnect_users = true\n",
        ),
        ("writer", "send_chat = true\n"),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{access}"),
        )
        .unwrap();
    }
    std::fs::write(dir.join("rooms.toml"), "[[room]]\nname = \"lounge\"\n").unwrap();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n\
         [limits]\nspam_points = 0\nchat_lines = 0\nng_requests = 0\n\
         [rooms]\nfile = \"{d}/rooms.toml\"\n{extra}"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    if config.system.is_some() {
        ctx.core.start_system_session().unwrap();
    }
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        classic: l1.local_addr().unwrap(),
        ng: l2.local_addr().unwrap(),
        core: ctx.core.clone(),
        rooms: dir.join("rooms.toml"),
    };
    tokio::spawn(hxd_session::serve(l1, ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    server
}

fn history(dir: &Path) -> String {
    format!("[history]\ndb = \"{}/hx.db\"\n", dir.display())
}

const ON: &str = "[structured_chat]\nenabled = true\n";

/// An account logged in as a period client does, offering `caps`.
async fn classic(s: &Server, who: &str, caps: Option<u32>) -> Client {
    let login = Login {
        caps,
        ..Login::account(who, who, "pw")
    };
    let mut c = Client::login_at(s.classic, &login).await.unwrap();
    c.user_list().await.unwrap();
    c
}

/// A Chat History entry, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    id: u64,
    at: i64,
    flags: u16,
    icon: u16,
    nick: Vec<u8>,
    text: Vec<u8>,
}

fn parse(data: &[u8]) -> Entry {
    let e = hxproto::parse::parse_history_entry(data).unwrap();
    Entry {
        id: e.message_id,
        at: e.timestamp,
        flags: e.flags,
        icon: e.icon_id,
        nick: e.nick.to_vec(),
        text: e.message.to_vec(),
    }
}

fn entry(f: &Frame) -> Option<Entry> {
    f.bytes(DATA_CHAT_LINE).map(|d| parse(&d))
}

/// The next 106 whose formatted text ends with `tail`.
async fn line(c: &mut Client, tail: impl AsRef<[u8]>) -> Frame {
    c.recv_where(|f| {
        f.ty == push::CHAT
            && f.bytes(tag::BODY)
                .is_some_and(|b| b.ends_with(tail.as_ref()))
    })
    .await
    .unwrap()
}

async fn emote(c: &mut Client, text: &str) {
    c.send(
        ClientHdr::Chat.as_u32(),
        &[
            (tag::STYLE, 1u16.to_be_bytes().to_vec()),
            (tag::BODY, text.as_bytes().to_vec()),
        ],
    )
    .await
    .unwrap();
}

fn cid(id: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, id.to_be_bytes().to_vec())
}

async fn kick(admin: &mut Client, uid: u16) {
    admin
        .call(
            ClientHdr::UserKick.as_u32(),
            &[(tag::UID, uid.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
}

/// A 106 as a client can tell it apart, every byte but the transaction
/// id the connection's own pushes count.
fn seen(f: &Frame) -> Vec<u8> {
    [&f.wire()[..4], &f.wire()[8..]].concat()
}

/// A 106 to a bit-17 session as [`seen`], its entry's timestamp zeroed,
/// and its id where it is ephemeral, which is random: what two runs of
/// one script can agree on.
fn seen_structured(f: &Frame) -> Vec<u8> {
    let entry = f.bytes(DATA_CHAT_LINE).expect("an entry");
    let mut out = seen(f);
    let at = out
        .windows(entry.len())
        .position(|w| w == entry)
        .expect("the entry in the frame");
    out[at + 8..at + 16].fill(0);
    if parse(&entry).flags & EPHEMERAL != 0 {
        out[at..at + 8].fill(0);
    }
    out
}

/// What each client is sent of one script, with the server offering bit
/// 17 or not and serving a catalog or not: a period client's 106s, a
/// period sender's that may not read the lobby, a bit-17 client's and an
/// ng client's chat events. A sender that offers bit 20 sends refs
/// throughout.
type Seen = (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Value>);

async fn period_and_ng(structured: bool, emoji: bool) -> Seen {
    let td = tempfile::tempdir().unwrap();
    let mut extra = history(td.path()) + if structured { ON } else { "" };
    if emoji {
        extra += "[emoji]\nenabled = true\n";
    }
    let s = start(td.path(), &extra).await;
    if emoji {
        use hxd_core::emoji::{EmojiStore, NewEmojiName};
        let store = hxd_store_sqlite::SqliteStore::open(
            td.path().join("hx.db"),
            hxd_store_sqlite::Synchronous::Normal,
        )
        .unwrap();
        let image = hxd_core::emoji::conformance::image(2);
        let party = NewEmojiName::parse("party").unwrap();
        store
            .add(&party, &image, std::time::SystemTime::now(), 10)
            .unwrap();
        s.core.emoji_reload().unwrap();
    }
    let party = (
        EMOJI_REFS_FIELD,
        [&[0, 1, 0, 0, 0, 1, 5][..], b"party"].concat(),
    );
    let (mut carol, _) = ng::Client::account(s.ng, "erin", "pw", "carol")
        .await
        .unwrap();
    let mut alice = classic(&s, "alice", Some(STRUCTURED | HISTORY)).await;
    let mut bob = classic(&s, "bob", None).await;
    let mut admin = classic(&s, "admin", None).await;
    let dave = classic(&s, "dave", Some(STRUCTURED)).await;
    let mut writer = classic(&s, "writer", None).await;
    let mut frank = classic(&s, "frank", Some(EMOJI | UTF8 | STRUCTURED)).await;
    let mut gina = classic(&s, "gina", Some(STRUCTURED | UTF8)).await;

    alice.chat(b"hi").await.unwrap();
    assert_eq!(entry(&line(&mut alice, "hi").await).is_some(), structured);
    emote(&mut alice, "waves").await;
    line(&mut alice, "waves").await;
    alice.chat(b"one\rtwo").await.unwrap();
    line(&mut alice, "two").await;
    carol.chat("from ng").await.unwrap();
    line(&mut alice, "from ng").await;
    // Each waits for its own line by nick: frank's is still unread at alice
    // when she sends hers.
    for (c, nick) in [(&mut frank, "frank"), (&mut alice, "alice")] {
        c.send(
            ClientHdr::Chat.as_u32(),
            &[(tag::BODY, b"a :party:".to_vec()), party.clone()],
        )
        .await
        .unwrap();
        line(c, format!("{nick}:  a :party:")).await;
    }
    frank
        .send(
            ClientHdr::Chat.as_u32(),
            &[
                (tag::STYLE, 1u16.to_be_bytes().to_vec()),
                (tag::BODY, b"dances :party:".to_vec()),
                party.clone(),
            ],
        )
        .await
        .unwrap();
    line(&mut alice, "dances :party:").await;
    kick(&mut admin, dave.uid.unwrap()).await;
    line(&mut alice, "by admin>").await;
    writer.chat(b"blind").await.unwrap();
    line(&mut alice, "blind").await;
    alice.chat(b"end").await.unwrap();

    let normal = |f: &Frame| {
        if structured {
            seen_structured(f)
        } else {
            seen(f)
        }
    };
    let last = line(&mut gina, "end").await;
    let mut structured_frames: Vec<Vec<u8>> = (gina.rx.take_backlog().iter())
        .filter(|f| f.ty == push::CHAT)
        .map(normal)
        .collect();
    structured_frames.push(normal(&last));
    let last = line(&mut bob, "end").await;
    let mut frames: Vec<Vec<u8>> = bob
        .rx
        .take_backlog()
        .iter()
        .filter(|f| f.ty == push::CHAT)
        .map(seen)
        .collect();
    frames.push(seen(&last));
    writer.ping().await.unwrap();
    let to_writer: Vec<Frame> = (writer.rx.take_backlog().into_iter())
        .filter(|f| f.ty == push::CHAT)
        .collect();
    assert!(
        !to_writer
            .iter()
            .any(|f| f.bytes(tag::BODY).is_some_and(|b| b.ends_with(b"blind"))),
        "a period sender that may not read the lobby is sent no echo"
    );
    let blind: Vec<Vec<u8>> = to_writer.iter().map(seen).collect();
    let mut events = Vec::new();
    loop {
        let mut e = carol.event_where("chat", |_| true).await.unwrap();
        e.data.as_object_mut().unwrap().remove("at");
        let done = e.data["text"] == "end";
        events.push(e.data);
        if done {
            break;
        }
    }
    (frames, blind, structured_frames, events)
}

#[tokio::test]
async fn a_period_client_and_an_ng_client_are_sent_the_same_whether_bit_17_is_offered_or_not() {
    let (frames, blind, _, events) = period_and_ng(false, false).await;
    assert!(frames.len() >= 6, "{frames:?}");
    let (on, on_blind, _, on_events) = period_and_ng(true, false).await;
    assert_eq!((on, on_blind, on_events), (frames, blind, events));
}

#[tokio::test]
async fn every_client_without_bit_20_is_sent_the_same_whether_emoji_are_served_or_not() {
    for structured in [false, true] {
        let off = period_and_ng(structured, false).await;
        assert!(off.2.len() >= 9, "{:?}", off.2);
        assert_eq!(
            period_and_ng(structured, true).await,
            off,
            "bit 17 {structured}"
        );
    }
}

#[tokio::test]
async fn a_live_line_carries_the_entry_history_pages_for_it() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), &(history(td.path()) + ON)).await;
    let mut alice = classic(&s, "alice", Some(STRUCTURED | HISTORY)).await;
    let mut bob = classic(&s, "bob", None).await;
    let (alice_uid, bob_uid) = (alice.uid.unwrap(), bob.uid.unwrap());

    alice.chat(b"hi").await.unwrap();
    let echo = line(&mut alice, "hi").await;
    bob.chat(b"one\rtwo").await.unwrap();
    let bobs = line(&mut alice, "two").await;
    emote(&mut alice, "waves").await;
    let waved = line(&mut alice, "waves").await;

    // Beside the formatted text, unchanged, and the sender's uid; no chat
    // id, as public chat.
    assert_eq!(echo.bytes(tag::BODY).unwrap(), b"\r        alice:  hi");
    assert_eq!(echo.uint(tag::UID), Some(alice_uid.into()));
    assert_eq!(bobs.uint(tag::UID), Some(bob_uid.into()));
    assert!(echo.chunk(tag::CHAT_ID).is_none());
    let live = [entry(&echo), entry(&bobs), entry(&waved)].map(Option::unwrap);
    let want = [
        (0, &b"alice"[..], &b"hi"[..]),
        (0, b"bob", b"one\rtwo"),
        (ACTION, b"alice", b"waves"),
    ];
    for (e, (flags, nick, text)) in live.iter().zip(want) {
        assert_eq!((e.flags, &e.nick[..], &e.text[..]), (flags, nick, text));
        assert_eq!(e.icon, 1);
    }

    // And paged back, the same bytes under the same id.
    let page = alice
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    let paged = page.all(tag::HISTORY_ENTRY);
    for f in [&echo, &bobs, &waved] {
        let mine = f.bytes(DATA_CHAT_LINE).unwrap();
        let id = parse(&mine).id;
        assert!(id != 0);
        assert_eq!(
            paged.iter().find(|p| parse(p).id == id),
            Some(&mine),
            "the 700 entry for {id}"
        );
    }

    // A sender that may not read the lobby still learns its line's id.
    let mut writer = classic(&s, "writer", Some(STRUCTURED)).await;
    writer.chat(b"blind").await.unwrap();
    let blind = line(&mut writer, "blind").await;
    let paged = alice
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert_eq!(
        paged.all(tag::HISTORY_ENTRY).last(),
        Some(&blind.bytes(DATA_CHAT_LINE).unwrap())
    );

    // A nick past the user list's 31 bytes is cut as the list cuts it,
    // live and paged back alike.
    let long = Login {
        caps: Some(STRUCTURED | HISTORY | UTF8),
        ..Login::account(&"\u{e9}".repeat(20), "erin", "pw")
    };
    let mut erin = Client::login_at(s.classic, &long).await.unwrap();
    erin.chat(b"long").await.unwrap();
    let mine = line(&mut erin, "long").await.bytes(DATA_CHAT_LINE).unwrap();
    assert_eq!(parse(&mine).nick, "\u{e9}".repeat(15).as_bytes());
    let paged = erin
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert_eq!(paged.all(tag::HISTORY_ENTRY).last(), Some(&mine));
}

#[tokio::test]
async fn an_entry_is_written_in_the_sessions_encoding_and_line_endings() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), &(history(td.path()) + ON)).await;
    let mut mac = classic(&s, "alice", Some(STRUCTURED | HISTORY)).await;
    let mut utf = classic(&s, "bob", Some(STRUCTURED | HISTORY | UTF8)).await;
    let (mut zoe, _) = ng::Client::account(s.ng, "dave", "pw", "zo\u{eb}")
        .await
        .unwrap();
    zoe.chat("caf\u{e9}\nzo\u{eb}").await.unwrap();
    for (c, nick, text) in [
        (&mut mac, &b"zo\x91"[..], &b"caf\x8e\rzo\x91"[..]),
        (
            &mut utf,
            "zo\u{eb}".as_bytes(),
            "caf\u{e9}\nzo\u{eb}".as_bytes(),
        ),
    ] {
        let live = line(c, nick).await.bytes(DATA_CHAT_LINE).unwrap();
        let e = parse(&live);
        assert_eq!((&e.nick[..], &e.text[..]), (nick, text));
        // Paged back the same way, the ng sender's LF and all.
        let paged = c
            .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
            .await
            .unwrap();
        assert_eq!(paged.all(tag::HISTORY_ENTRY).last(), Some(&live));
    }
}

#[tokio::test]
async fn a_private_chat_numbers_its_lines_for_its_members_alone() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), &(history(td.path()) + ON)).await;
    let mut alice = classic(&s, "alice", Some(STRUCTURED)).await;
    let mut dave = classic(&s, "dave", Some(STRUCTURED)).await;
    let mut erin = classic(&s, "erin", Some(STRUCTURED)).await;
    let created = alice
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, dave.uid.unwrap().to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let chat = created.uint(tag::CHAT_ID).unwrap();
    dave.call(ClientHdr::ChatJoin.as_u32(), &[cid(chat)])
        .await
        .unwrap();
    for text in ["one", "two"] {
        alice
            .send(
                ClientHdr::Chat.as_u32(),
                &[cid(chat), (tag::BODY, text.as_bytes().to_vec())],
            )
            .await
            .unwrap();
    }
    let mut heard = Vec::new();
    for c in [&mut alice, &mut dave] {
        let one = line(c, "one").await;
        let two = line(c, "two").await;
        assert_eq!(one.uint(tag::CHAT_ID), Some(chat));
        heard.push([entry(&one).unwrap(), entry(&two).unwrap()]);
    }
    let first = heard[0][0].id;
    assert_eq!(heard[0], heard[1], "the same entry for every member");
    assert_eq!(
        heard[0].clone().map(|e| (e.id, e.flags)),
        [(first, EPHEMERAL), (first + 1, EPHEMERAL)]
    );

    // A member who joins later is numbered from where the chat is, and
    // never sent what came before.
    alice
        .call(
            ClientHdr::ChatInvite.as_u32(),
            &[
                cid(chat),
                (tag::UID, erin.uid.unwrap().to_be_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    erin.call(ClientHdr::ChatJoin.as_u32(), &[cid(chat)])
        .await
        .unwrap();
    alice
        .send(
            ClientHdr::Chat.as_u32(),
            &[cid(chat), (tag::BODY, b"three".to_vec())],
        )
        .await
        .unwrap();
    let three = entry(&line(&mut erin, "three").await).unwrap();
    assert_eq!((three.id, three.flags), (first + 2, EPHEMERAL));
    assert!(erin.rx.take_backlog().iter().all(|f| f.ty != push::CHAT));
}

#[tokio::test]
async fn a_line_to_one_session_is_numbered_0_and_from_the_system_account_or_nobody() {
    for system in [false, true] {
        let td = tempfile::tempdir().unwrap();
        let extra = history(td.path()) + ON + if system { "[system]\n" } else { "" };
        let s = start(td.path(), &extra).await;
        let from = s.core.system_uid().map_or(0, u32::from);
        let lounge = s.room("lounge");
        let mut alice = classic(&s, "alice", Some(STRUCTURED)).await;
        let mut bob = classic(&s, "bob", None).await;
        for c in [&mut alice, &mut bob] {
            c.call(ClientHdr::ChatJoin.as_u32(), &[cid(lounge)])
                .await
                .unwrap();
        }
        let told = "#lounge \u{2014} this room is public and logged";
        let mac_told = b"#lounge \xd1 this room is public and logged";
        let a = line(&mut alice, "logged").await;
        let b = line(&mut bob, "logged").await;
        for f in [&a, &b] {
            assert_eq!(f.uint(tag::UID), Some(from), "system {system}");
            assert_eq!(f.uint(tag::CHAT_ID), Some(lounge));
        }
        let e = entry(&a).unwrap();
        assert_eq!(
            (e.id, e.flags, e.icon, &e.nick[..], &e.text[..]),
            (0, SERVER_MSG, 0, &b""[..], &mac_told[..]),
            "{told}"
        );
        assert!(entry(&b).is_none());

        // A room's line is kept, so it carries its history id.
        alice
            .send(
                ClientHdr::Chat.as_u32(),
                &[cid(lounge), (tag::BODY, b"in the room".to_vec())],
            )
            .await
            .unwrap();
        let said = entry(&line(&mut alice, "in the room").await).unwrap();
        assert_eq!(said.flags, 0);
        assert!(said.id != 0);
    }
}

#[tokio::test]
async fn a_kick_notice_is_a_server_line_naming_the_kicker() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), &(history(td.path()) + ON)).await;
    let mut alice = classic(&s, "alice", Some(STRUCTURED)).await;
    let mut admin = classic(&s, "admin", None).await;
    let dave = classic(&s, "dave", None).await;
    kick(&mut admin, dave.uid.unwrap()).await;
    let notice = line(&mut alice, "by admin>").await;
    assert_eq!(notice.uint(tag::UID), Some(admin.uid.unwrap().into()));
    let drawn = notice.bytes(tag::BODY).unwrap();
    let e = entry(&notice).unwrap();
    assert_eq!(
        (e.flags, e.icon, &e.nick[..], &e.text[..]),
        (
            SERVER_MSG | EPHEMERAL,
            0,
            &b""[..],
            &drawn[2..drawn.len() - 1]
        )
    );
    assert!(e.text.starts_with(b"dave has been "));
}

#[tokio::test]
async fn without_history_the_lobby_numbers_its_own_lines() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), ON).await;
    let mut alice = classic(&s, "alice", Some(STRUCTURED)).await;
    let mut bob = classic(&s, "bob", Some(STRUCTURED)).await;
    // Two connections race to the server, so bob speaks once alice's
    // line has been numbered.
    alice.chat(b"first").await.unwrap();
    let first = entry(&line(&mut alice, "first").await).unwrap();
    bob.chat(b"second").await.unwrap();
    let second = entry(&line(&mut alice, "second").await).unwrap();
    assert_eq!(first.flags, EPHEMERAL);
    assert_eq!((second.id, second.flags), (first.id + 1, EPHEMERAL));
    assert_eq!(entry(&line(&mut bob, "second").await), Some(second));
}

#[tokio::test]
async fn a_legacy_replay_to_a_session_without_bit_4_carries_no_entry() {
    let td = tempfile::tempdir().unwrap();
    let extra = format!("{}replay = 10\n{ON}", history(td.path()));
    let s = start(td.path(), &extra).await;
    let mut alice = classic(&s, "alice", Some(STRUCTURED)).await;
    alice.chat(b"before").await.unwrap();
    assert!(entry(&line(&mut alice, "before").await).is_some());

    let mut dave = classic(&s, "dave", Some(STRUCTURED)).await;
    let replayed = dave
        .recv_where(|f| {
            f.ty == push::CHAT
                && f.bytes(tag::BODY)
                    .is_some_and(|b| b.starts_with(b"\r[") && b.ends_with(b"alice:  before"))
        })
        .await
        .unwrap();
    assert!(entry(&replayed).is_none());
}
