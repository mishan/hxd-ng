//! Reactions on the classic wire (the Reactions draft), against servers
//! built from a real config: capability bit 19 confirmed beside bits 1
//! and 17 on a server that keeps reactions, Send Reaction (710) on a
//! lobby line and a room's, held to who may react, the caps and the rate,
//! a moderator's clear, Reaction Changed (711) heard in one batch by the
//! readers that negotiated the bit and crossing to the ng wire and back,
//! a redaction and a purge, and a session without the bit sent what it
//! always was.
//!
//! Targets, keys and summaries are laid out by hand from the draft here
//! rather than by the server's encoder, so a disagreement between the
//! two shows. The binary does not offer bit 19 yet, so each server here
//! is given it by hand.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use hxd_session::caps::cap;
use hxd_session::reactions::{
    CHANGED, CLEAR_REASON, DATA_MAX_REACTIONS_PER_USER, DATA_MAX_REACTION_KEYS,
    DATA_REACTION_ACTION, DATA_REACTION_COUNT, DATA_REACTION_KEY, DATA_REACTION_MINE,
    DATA_REACTION_SUMMARY, DATA_REACTION_TARGETS, DATA_TARGET, SEND,
};
use hxd_session::structured::{DATA_CHAT_LINE, DATA_CHAT_REASON};
use hxd_testclient::legacy::{push, Client, Frame, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::{json, Value};

const UTF8: u32 = 1 << 1;
const HISTORY: u32 = 1 << 4;
const STRUCTURED: u32 = 1 << 17;
const REACTIONS: u32 = 1 << 19;
const EMOJI: u32 = 1 << 20;
const ON: u32 = UTF8 | HISTORY | STRUCTURED | REACTIONS;

const NO_SUCH_TARGET: u32 = 1;
const NOT_ALLOWED: u32 = 2;
const INVALID_KEY: u32 = 3;
const TOO_MANY_KEYS: u32 = 4;
const TOO_MANY_OF_YOURS: u32 = 5;
const RATE_LIMITED: u32 = 6;
const NO_SUCH_EMOJI: u32 = 7;
const INVALID_TARGET: u32 = 12;

const ADD: u16 = 1;
const REMOVE: u16 = 2;
const CLEAR: u16 = 3;
const SUMMARY: u16 = 4;

const MEMBER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      create_pchats = true\nuse_any_name = true\n";

const LOUNGE: u32 = 4000;
const STAFF: u32 = 4001;
const NEWS: u32 = 4002;
const OLD: u32 = 4003;

const ROOMS: &str = "[[room]]\nid = 4000\nname = \"lounge\"\n\n\
                     [[room]]\nid = 4001\nname = \"staff\"\nread = [\"carol\"]\n\n\
                     [[room]]\nid = 4002\nname = \"news\"\npost = [\"carol\"]\n\n\
                     [[room]]\nid = 4003\nname = \"old\"\n";

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
    config: hxd::Config,
    dir: std::path::PathBuf,
}

/// What a server is built with beside history and moderation.
struct Opts<'a> {
    /// `[reactions]`, turned on, with these keys; none at all where
    /// `None`.
    reactions: Option<&'a str>,
    rooms: bool,
    structured: bool,
    spam_points: u32,
    extra: &'a str,
}

impl Default for Opts<'_> {
    fn default() -> Self {
        Opts {
            reactions: Some(""),
            rooms: true,
            structured: true,
            spam_points: 0,
            extra: "",
        }
    }
}

/// A server keeping history and moderation in `dir`, built as `o` says,
/// with bit 19 among what its classic port offers.
async fn start(dir: &Path, o: Opts<'_>) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, password, access) in [
        ("alice", true, MEMBER.to_string()),
        ("bob", true, MEMBER.to_string()),
        ("erin", true, MEMBER.to_string()),
        ("frank", true, MEMBER.to_string()),
        (
            "late",
            true,
            MEMBER.replace("read_chat_history = true", "read_chat_history = false"),
        ),
        ("mute", true, MEMBER.replace("send_chat = true\n", "")),
        ("carol", true, format!("{MEMBER}disconnect_users = true\n")),
        (
            "boss",
            true,
            format!("{MEMBER}cant_be_disconnected = true\n[extra]\nmanage_rooms = true\n"),
        ),
        ("guest", false, MEMBER.to_string()),
    ] {
        let password = if password { "password = \"pw\"\n" } else { "" };
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\n{password}[access]\n{access}"),
        )
        .unwrap();
    }
    std::fs::write(dir.join("rooms.toml"), ROOMS).unwrap();
    let reactions = o.reactions.map_or(String::new(), |r| {
        format!("[reactions]\nenabled = true\n{r}\n")
    });
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n\
         [history]\ndb = \"{d}/hx.db\"\n\
         [limits]\nspam_points = {}\nchat_lines = 0\nng_requests = 0\n\
         [rooms]\nenabled = {}\nfile = \"{d}/rooms.toml\"\nannounce = false\n\
         [structured_chat]\nenabled = {}\n{reactions}{}",
        o.spam_points, o.rooms, o.structured, o.extra
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let mut ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let caps = ctx.cfg.caps.with(cap::REACTIONS);
    Arc::make_mut(&mut ctx.cfg).caps = caps;
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    tokio::spawn(hxd::reactions_flusher(ctx.core.clone()));
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        classic: l1.local_addr().unwrap(),
        ng: l2.local_addr().unwrap(),
        core: ctx.core.clone(),
        config,
        dir: dir.to_path_buf(),
    };
    tokio::spawn(hxd_session::serve(l1, ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    server
}

/// [`start`] with `[reactions]` at its defaults.
async fn start_on(dir: &Path) -> Server {
    start(dir, Opts::default()).await
}

/// [`start`] with these `[reactions]` keys.
async fn start_with(dir: &Path, reactions: &str) -> Server {
    let o = Opts {
        reactions: Some(reactions),
        ..Opts::default()
    };
    start(dir, o).await
}

/// `who` logged in offering `caps`, and its login reply.
async fn login(s: &Server, who: &str, caps: Option<u32>) -> (Client, Frame) {
    let mut c = Client::connect(s.classic).await.unwrap();
    let password = if who == "guest" { "" } else { "pw" };
    let reply = c
        .login(&Login {
            caps,
            ..Login::account(who, who, password)
        })
        .await
        .unwrap();
    c.user_list().await.unwrap();
    (c, reply)
}

async fn classic(s: &Server, who: &str, caps: u32) -> Client {
    login(s, who, Some(caps)).await.0
}

/// `who` on the ng wire, declaring `reactions`.
async fn ng_client(s: &Server, who: &str) -> ng::Client {
    let mut c = ng::Client::connect(s.ng).await.unwrap();
    c.login(json!({ "login": who, "password": "pw", "nick": who, "reactions": true }))
        .await
        .unwrap();
    c
}

async fn ok(c: &mut ng::Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

fn cid(id: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, id.to_be_bytes().to_vec())
}

async fn join(c: &mut Client, room: u32) {
    c.call(ClientHdr::ChatJoin.as_u32(), &[cid(room)])
        .await
        .unwrap();
}

/// `c` says `text` in `chat`, 0 the lobby, answering the id its echo's
/// entry gives it.
async fn say(c: &mut Client, chat: u32, text: &str) -> u64 {
    let mut fields = vec![(tag::BODY, text.as_bytes().to_vec())];
    if chat != 0 {
        fields.push(cid(chat));
    }
    c.send(ClientHdr::Chat.as_u32(), &fields).await.unwrap();
    let echo = heard(c, text).await;
    let entry = echo.bytes(DATA_CHAT_LINE).expect("an entry");
    u64::from_be_bytes(entry[..8].try_into().unwrap())
}

/// The next 106 whose text ends with `tail`.
async fn heard(c: &mut Client, tail: &str) -> Frame {
    c.recv_where(|f| {
        f.ty == push::CHAT
            && f.bytes(tag::BODY)
                .is_some_and(|b| b.ends_with(tail.as_bytes()))
    })
    .await
    .unwrap()
}

/// A line target, kind 1 or 4, as the Replies draft lays it out.
fn target(kind: u8, chat: u32, id: u64) -> Vec<u8> {
    [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
}

fn lobby(id: u64) -> Vec<u8> {
    target(1, 0, id)
}

fn room(chat: u32, id: u64) -> Vec<u8> {
    target(4, chat, id)
}

fn key(emoji: &str) -> Vec<u8> {
    [&[1][..], emoji.as_bytes()].concat()
}

/// A 710's reply, refused or not.
async fn send(c: &mut Client, target: &[u8], action: u16, key: Option<Vec<u8>>) -> Frame {
    let mut fields = vec![
        (DATA_TARGET, target.to_vec()),
        (DATA_REACTION_ACTION, action.to_be_bytes().to_vec()),
    ];
    fields.extend(key.map(|k| (DATA_REACTION_KEY, k)));
    let trans = c.send(SEND, &fields).await.unwrap();
    c.reply(trans).await.unwrap()
}

/// `c` adds `emoji` on `target`, answering the key's count after.
async fn react(c: &mut Client, target: &[u8], emoji: &str) -> u32 {
    let reply = send(c, target, ADD, Some(key(emoji))).await;
    assert!(!reply.is_error(), "{:?}", reply.error_text());
    reply.uint(DATA_REACTION_COUNT).expect("a count")
}

/// The reason a 710 was refused with.
async fn refused(c: &mut Client, target: &[u8], action: u16, key: Option<Vec<u8>>) -> u32 {
    let reply = send(c, target, action, key).await;
    assert!(reply.is_error(), "not refused");
    reply.uint(DATA_CHAT_REASON).unwrap_or(0)
}

type Group = Vec<(u16, Vec<u8>)>;

/// A 711's groups, each from its `DATA_TARGET` on.
fn groups(f: &Frame) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    for c in f.chunks() {
        if c.tag == DATA_TARGET {
            out.push(Vec::new());
        }
        out.last_mut()
            .expect("a 711 starts with a target")
            .push((c.tag, c.data.to_vec()));
    }
    out
}

fn names(f: &Frame, t: &[u8]) -> bool {
    f.ty == CHANGED && groups(f).iter().any(|g| g[0].1 == t)
}

/// The next 711 naming `t`, and its group for it.
async fn changed(c: &mut Client, t: &[u8]) -> (Frame, Group) {
    let f = c.recv_where(|f| names(f, t)).await.unwrap();
    let g = groups(&f).into_iter().find(|g| g[0].1 == t).unwrap();
    (f, g)
}

/// A summary group as the draft lays it out: the keys and counts, then
/// the reader's indexes where it holds any.
fn summary_group(t: &[u8], keys: &[(&str, u32)], mine: &[u8]) -> Group {
    let mut s = (keys.len() as u16).to_be_bytes().to_vec();
    for (k, n) in keys {
        let k = key(k);
        s.extend_from_slice(&n.to_be_bytes());
        s.extend_from_slice(&(k.len() as u16).to_be_bytes());
        s.extend_from_slice(&k);
    }
    let mut g = vec![
        (DATA_TARGET, t.to_vec()),
        (DATA_REACTION_ACTION, SUMMARY.to_be_bytes().to_vec()),
        (DATA_REACTION_SUMMARY, s),
    ];
    if !mine.is_empty() {
        g.push((DATA_REACTION_MINE, [&[mine.len() as u8][..], mine].concat()));
    }
    g
}

/// No 711 that `c` has been sent, read up to a 711 naming `marker`
/// that a later change makes, names `t`.
async fn never_told(c: &mut Client, t: &[u8], marker: &[u8]) {
    let (f, _) = changed(c, marker).await;
    for f in c.rx.take_backlog().iter().chain([&f]) {
        assert!(!names(f, t), "told of {t:?}");
    }
}

fn confirmed(reply: &Frame) -> u32 {
    reply.uint(tag::CAPABILITIES).unwrap_or(0)
}

/// Bit 19 only beside bits 1 and 17, on a server that keeps reactions,
/// and the login fields with it alone: lines, and rooms where there are
/// rooms, with the configured caps.
#[tokio::test]
async fn bit_19_is_confirmed_beside_bits_1_and_17_on_a_server_that_keeps_reactions() {
    let caps = "max_keys = 7\nmax_per_user = 3";
    let full = Opts {
        reactions: Some(caps),
        ..Opts::default()
    };
    let no_rooms = Opts {
        reactions: Some(caps),
        rooms: false,
        ..Opts::default()
    };
    let unstructured = Opts {
        structured: false,
        ..Opts::default()
    };
    let none = Opts {
        reactions: None,
        ..Opts::default()
    };
    let fields = |targets: u8| {
        Some([
            Some(vec![0, targets]),
            Some(vec![0, 0, 0, 7]),
            Some(vec![0, 0, 0, 3]),
        ])
    };
    for (server, opts, cases) in [
        (
            "rooms",
            full,
            vec![
                ("with 1 and 17", ON, fields(0x12)),
                ("alone", REACTIONS, None),
                ("Mac Roman", HISTORY | STRUCTURED | REACTIONS, None),
                ("without 17", UTF8 | HISTORY | REACTIONS, None),
            ],
        ),
        (
            "no rooms",
            no_rooms,
            vec![("with 1 and 17", ON, fields(0x02))],
        ),
        (
            "no [structured_chat]",
            unstructured,
            vec![("with 1 and 17", ON, None)],
        ),
        ("no [reactions]", none, vec![("with 1 and 17", ON, None)]),
    ] {
        let td = tempfile::tempdir().unwrap();
        let s = start(td.path(), opts).await;
        for (case, offered, want) in cases {
            let (_, reply) = login(&s, "alice", Some(offered)).await;
            let got = [
                DATA_REACTION_TARGETS,
                DATA_MAX_REACTION_KEYS,
                DATA_MAX_REACTIONS_PER_USER,
            ]
            .map(|t| reply.chunk(t).map(|c| c.data.to_vec()));
            let bit = confirmed(&reply) & REACTIONS != 0;
            assert_eq!(bit, want.is_some(), "{server}, {case}");
            assert_eq!(got, want.unwrap_or_default(), "{server}, {case}");
        }
    }
}

/// A reaction on a lobby line is answered with its count and told in one
/// batch to every reader that negotiated the bit, each account's own
/// keys its own on every session of it, and to an ng reader; one made
/// on the ng wire reaches the classic readers alike.
#[tokio::test]
async fn a_lobby_reaction_is_told_to_every_reader_on_both_wires() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut bob = classic(&s, "bob", ON).await;
    let mut bob2 = classic(&s, "bob", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut frank = ng_client(&s, "frank").await;
    let id = say(&mut alice, 0, "pizza?").await;
    let t = lobby(id);
    assert_eq!(react(&mut bob, &t, "👍").await, 1);
    for (who, c, mine) in [
        ("bob", &mut bob, &[0][..]),
        ("bob's other session", &mut bob2, &[0]),
        ("alice", &mut alice, &[]),
        ("erin", &mut erin, &[]),
    ] {
        let (f, g) = changed(c, &t).await;
        assert_eq!(g, summary_group(&t, &[("👍", 1)], mine), "{who}");
        assert_eq!(f.trans, 0, "{who}: a notification");
    }
    let ev = frank
        .event_where("reactions_changed", |d| {
            d["changes"][0]["target"] == json!({ "line": id })
        })
        .await
        .unwrap();
    assert_eq!(
        ev.data["changes"][0]["keys"],
        json!([{ "key": { "emoji": "👍" }, "count": 1 }])
    );

    let count = ok(
        &mut frank,
        "react",
        json!({ "target": { "line": id }, "key": { "emoji": "🎉" } }),
    )
    .await;
    assert_eq!(count["count"], 1);
    let (_, g) = changed(&mut erin, &t).await;
    assert_eq!(g, summary_group(&t, &[("👍", 1), ("🎉", 1)], &[]));
    let (_, g) = changed(&mut bob, &t).await;
    assert_eq!(g, summary_group(&t, &[("👍", 1), ("🎉", 1)], &[0]));
}

/// What changes inside one batch is one 711 a room; a line past the
/// live window is told nothing.
#[tokio::test]
async fn a_burst_is_one_711_and_a_line_past_the_window_none() {
    let td = tempfile::tempdir().unwrap();
    let s = start_with(td.path(), "live_window = 2\nbatch_seconds = 2").await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let old = lobby(say(&mut alice, 0, "old").await);
    let a = lobby(say(&mut alice, 0, "a").await);
    let b = lobby(say(&mut alice, 0, "b").await);
    for e in ["👍", "🎉", "🍕"] {
        react(&mut alice, &a, e).await;
    }
    react(&mut alice, &old, "👍").await;
    let (f, g) = changed(&mut erin, &a).await;
    assert_eq!(
        g,
        summary_group(&a, &[("👍", 1), ("🎉", 1), ("🍕", 1)], &[])
    );
    assert_eq!(groups(&f).len(), 1, "the line past the window is not in it");
    react(&mut alice, &b, "👍").await;
    never_told(&mut erin, &old, &b).await;
}

/// A room's line is named kind 4 under the room's chat id, sent and
/// told; kind 1 on the room's id names the same line, told back as kind
/// 4. Its members hear it on both wires and the lobby does not; one who
/// was never in it, without history's bit, could not have read it.
#[tokio::test]
async fn a_rooms_line_is_kind_4_and_stays_in_the_room() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut bob = classic(&s, "bob", ON).await;
    let mut late = classic(&s, "late", ON).await;
    let mut frank = ng_client(&s, "frank").await;
    for c in [&mut alice, &mut erin] {
        join(c, LOUNGE).await;
    }
    ok(&mut frank, "room_join", json!({ "room": LOUNGE })).await;
    let id = say(&mut alice, LOUNGE, "in here").await;
    let t = room(LOUNGE, id);
    assert_eq!(react(&mut erin, &t, "👀").await, 1);
    let (_, g) = changed(&mut alice, &t).await;
    assert_eq!(g, summary_group(&t, &[("👀", 1)], &[]));
    frank
        .event_where("reactions_changed", |d| {
            d["changes"][0]["target"] == json!({ "line": id, "room": LOUNGE })
        })
        .await
        .unwrap();
    assert_eq!(react(&mut erin, &target(1, LOUNGE, id), "🎉").await, 1);
    let (_, g) = changed(&mut alice, &t).await;
    assert_eq!(g, summary_group(&t, &[("👀", 1), ("🎉", 1)], &[]));
    assert_eq!(
        refused(&mut late, &t, ADD, Some(key("👍"))).await,
        NO_SUCH_TARGET
    );
    let out = lobby(say(&mut alice, 0, "out here").await);
    react(&mut alice, &out, "👋").await;
    never_told(&mut bob, &t, &out).await;
}

/// A private chat's line is named kind 4 too, and kind 4 on chat 0 an
/// ephemeral lobby line: this server keeps neither, so neither is a
/// line to react to, told only once who may react has been asked. A
/// member who parts a room needs history's bit to react there after.
#[tokio::test]
async fn an_unkept_line_is_no_target_and_a_parted_member_needs_history() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut late = classic(&s, "late", ON).await;
    let mut guest = classic(&s, "guest", ON).await;
    let mut carol = classic(&s, "carol", ON).await;
    let created = alice
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, erin.uid.unwrap().to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let chat = created.uint(tag::CHAT_ID).unwrap();
    join(&mut erin, chat).await;
    let id = say(&mut alice, chat, "between us").await;
    let k = Some(key("👍"));
    for (case, guest_asks, t, want) in [
        (
            "a private chat's line",
            false,
            room(chat, id),
            NO_SUCH_TARGET,
        ),
        ("chat 0", false, room(0, id), NO_SUCH_TARGET),
        ("chat 0 from a guest", true, room(0, id), NOT_ALLOWED),
    ] {
        let c = if guest_asks { &mut guest } else { &mut erin };
        assert_eq!(refused(c, &t, ADD, k.clone()).await, want, "{case}");
    }
    assert_eq!(
        refused(&mut erin, &room(0, id), CLEAR, None).await,
        NOT_ALLOWED,
        "a clear on chat 0 from one who may not clear"
    );
    assert_eq!(
        refused(&mut carol, &room(0, id), CLEAR, None).await,
        NO_SUCH_TARGET,
        "from a moderator"
    );

    for c in [&mut alice, &mut late] {
        join(c, LOUNGE).await;
    }
    join(&mut erin, LOUNGE).await;
    let line = room(LOUNGE, say(&mut erin, LOUNGE, "said while all in").await);
    heard(&mut late, "said while all in").await;
    assert_eq!(react(&mut late, &line, "👍").await, 1);
    for c in [&mut alice, &mut late] {
        c.send(ClientHdr::ChatPart.as_u32(), &[cid(LOUNGE)])
            .await
            .unwrap();
    }
    assert_eq!(
        refused(&mut late, &line, ADD, Some(key("🎉"))).await,
        NO_SUCH_TARGET,
        "without history's bit"
    );
    assert_eq!(react(&mut alice, &line, "🎉").await, 1, "with it");
}

/// A target of a kind this server does not take, or one that is no
/// target at all, is `InvalidTarget`, whatever the action.
#[tokio::test]
async fn a_target_not_taken_is_invalid() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let id = say(&mut alice, 0, "hi").await;
    let pm = |flags: u8| [&[5, flags][..], &[3; 16]].concat();
    let im = [&[2][..], &[7; 16], &[3], b"bob"].concat();
    let cases = [
        ("signed", [&[3][..], &[0; 80]].concat()),
        ("an unstored message", pm(0)),
        ("a stored message, on a server that takes none", pm(1)),
        ("an instant message, to a session without bit 6", im),
        ("an unknown kind", target(9, 0, id)),
        ("short", lobby(id)[..12].to_vec()),
        ("long", [lobby(id), vec![0]].concat()),
        ("empty", vec![]),
    ];
    for (case, t) in cases {
        for action in [ADD, CLEAR] {
            assert_eq!(
                refused(&mut alice, &t, action, Some(key("👍"))).await,
                INVALID_TARGET,
                "{case}, action {action}"
            );
        }
    }
    let td = tempfile::tempdir().unwrap();
    let no_rooms = Opts {
        rooms: false,
        ..Opts::default()
    };
    let s = start(td.path(), no_rooms).await;
    let mut alice = classic(&s, "alice", ON).await;
    assert_eq!(
        refused(&mut alice, &room(0, id), ADD, Some(key("👍"))).await,
        INVALID_TARGET,
        "kind 4 where there are no rooms"
    );
}

/// Who may not react is told `NotAllowed`: a guest, an account that may
/// not chat, an archived room and, under `deny`, a room it may not post
/// in.
#[tokio::test]
async fn who_may_not_react_is_not_allowed() {
    let td = tempfile::tempdir().unwrap();
    let s = start_with(td.path(), "read_only_rooms = \"deny\"").await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut guest = classic(&s, "guest", ON).await;
    let mut mute = classic(&s, "mute", ON).await;
    let mut carol = classic(&s, "carol", ON).await;
    let mut boss = ng_client(&s, "boss").await;
    for room in [NEWS, OLD] {
        join(&mut alice, room).await;
        join(&mut carol, room).await;
    }
    let lobby_line = lobby(say(&mut alice, 0, "hi").await);
    let news = room(NEWS, say(&mut carol, NEWS, "headline").await);
    let old = room(OLD, say(&mut alice, OLD, "before").await);
    ok(&mut boss, "room_archive", json!({ "room": OLD })).await;
    let k = || Some(key("👍"));
    assert_eq!(
        refused(&mut guest, &lobby_line, ADD, k()).await,
        NOT_ALLOWED,
        "a guest"
    );
    assert_eq!(
        refused(&mut mute, &lobby_line, ADD, k()).await,
        NOT_ALLOWED,
        "no send_chat"
    );
    assert_eq!(
        refused(&mut alice, &news, ADD, k()).await,
        NOT_ALLOWED,
        "read-only, deny"
    );
    assert_eq!(
        refused(&mut carol, &old, ADD, k()).await,
        NOT_ALLOWED,
        "archived"
    );
    assert_eq!(react(&mut carol, &news, "👍").await, 1, "one who may post");
}

/// A line that is not there, a tombstone, one the reactor cannot read,
/// one not yet relayed and id 0 are one answer.
#[tokio::test]
async fn every_line_not_to_be_reacted_to_is_no_such_target() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut carol = classic(&s, "carol", ON).await;
    let mut moderator = ng_client(&s, "carol").await;
    join(&mut carol, STAFF).await;
    let staff = room(STAFF, say(&mut carol, STAFF, "staff only").await);
    let gone = say(&mut alice, 0, "regrettable").await;
    ok(
        &mut moderator,
        "redact",
        json!({ "id": gone, "reason": "no" }),
    )
    .await;
    let last = say(&mut alice, 0, "last").await;
    for (case, t) in [
        ("a tombstone", lobby(gone)),
        ("unreadable", staff),
        ("not yet relayed", lobby(last + 1)),
        ("never said", lobby(last + 1000)),
        ("id 0", lobby(0)),
        ("another room's", target(1, LOUNGE, last)),
    ] {
        assert_eq!(
            refused(&mut alice, &t, ADD, Some(key("👍"))).await,
            NO_SUCH_TARGET,
            "{case}"
        );
    }
}

/// A key the draft does not take is `InvalidKey`, before any of the
/// reactor's rate is spent; past the rate, `RateLimited`.
#[tokio::test]
async fn an_invalid_key_spends_no_rate_and_past_the_rate_is_limited() {
    let td = tempfile::tempdir().unwrap();
    let s = start_with(td.path(), "burst = 2\nper_second = 1").await;
    let mut alice = classic(&s, "alice", ON).await;
    let t = lobby(say(&mut alice, 0, "hi").await);
    for (case, k) in [
        ("no key", None),
        ("empty", Some(vec![1])),
        ("two emoji", Some(key("👍👍"))),
        ("a word", Some(key("ok"))),
        ("a server's, without bit 20", Some(vec![2, 0, 0, 0, 1])),
        (
            "an unknown kind",
            Some([&[3][..], "👍".as_bytes()].concat()),
        ),
    ] {
        assert_eq!(refused(&mut alice, &t, ADD, k).await, INVALID_KEY, "{case}");
    }
    let reply = send(&mut alice, &t, 0, Some(key("👍"))).await;
    assert!(reply.is_error());
    assert_eq!(reply.uint(DATA_CHAT_REASON), None, "no code for an action");
    react(&mut alice, &t, "👍").await;
    react(&mut alice, &t, "🎉").await;
    assert_eq!(
        refused(&mut alice, &t, ADD, Some(key("🍕"))).await,
        RATE_LIMITED
    );
}

/// A line full of keys and an account full on a line are told apart.
#[tokio::test]
async fn the_two_caps_have_codes_of_their_own() {
    let td = tempfile::tempdir().unwrap();
    let s = start_with(td.path(), "max_keys = 3\nmax_per_user = 2").await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut bob = classic(&s, "bob", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let t = lobby(say(&mut alice, 0, "vote").await);
    react(&mut alice, &t, "👍").await;
    react(&mut alice, &t, "🎉").await;
    assert_eq!(
        refused(&mut alice, &t, ADD, Some(key("🔥"))).await,
        TOO_MANY_OF_YOURS
    );
    react(&mut bob, &t, "🔥").await;
    assert_eq!(
        refused(&mut erin, &t, ADD, Some(key("😀"))).await,
        TOO_MANY_KEYS
    );
}

/// A server emoji removed from the catalog takes no new reaction, from
/// a session that negotiated bit 20.
#[tokio::test]
async fn a_removed_server_emoji_is_no_such_emoji() {
    let td = tempfile::tempdir().unwrap();
    let o = Opts {
        extra: &format!(
            "[inbox]\ndb = \"{}/hx.db\"\n[emoji]\nenabled = true\n",
            td.path().display()
        ),
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let png = s.dir.join("party.png");
    image::RgbaImage::from_pixel(32, 32, image::Rgba([1, 2, 3, 0xff]))
        .save(&png)
        .unwrap();
    let emoji = |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        hxd::emoji::command(&s.config, &args).unwrap();
        s.core.emoji_reload().unwrap();
    };
    emoji(&["add", "party", &png.display().to_string()]);
    let listed = s.core.emoji_list(None, None, 10).unwrap();
    let id = listed
        .entries
        .iter()
        .find(|e| e.name.as_str() == "party")
        .unwrap()
        .id
        .0;
    emoji(&["remove", "party"]);
    let mut alice = classic(&s, "alice", ON | EMOJI).await;
    let t = lobby(say(&mut alice, 0, "hi").await);
    let custom = [&[2][..], &id.to_be_bytes()].concat();
    assert_eq!(
        refused(&mut alice, &t, ADD, Some(custom)).await,
        NO_SUCH_EMOJI
    );
}

/// Adding a key the account holds and removing one it does not succeed,
/// change nothing and are told to nobody.
#[tokio::test]
async fn a_reaction_that_changes_nothing_is_told_to_nobody() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let t = lobby(say(&mut alice, 0, "hi").await);
    let marker = lobby(say(&mut alice, 0, "marker").await);
    react(&mut alice, &t, "👍").await;
    changed(&mut erin, &t).await;
    assert_eq!(react(&mut alice, &t, "👍").await, 1, "held already");
    let reply = send(&mut alice, &t, REMOVE, Some(key("🎉"))).await;
    assert_eq!(reply.uint(DATA_REACTION_COUNT), Some(0), "not held");
    react(&mut alice, &marker, "👋").await;
    never_told(&mut erin, &t, &marker).await;
}

/// A moderator clears a line it reads, told to its readers as cleared
/// and recorded with the classic wire's reason; anyone else, a line
/// whose author it may not moderate, and a tombstone are refused.
#[tokio::test]
async fn a_clear_is_a_moderators_and_is_recorded() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut carol = classic(&s, "carol", ON).await;
    let mut boss = classic(&s, "boss", ON).await;
    let mut moderator = ng_client(&s, "carol").await;
    let t = lobby(say(&mut alice, 0, "spam").await);
    let protected = lobby(say(&mut boss, 0, "rules").await);
    let gone = say(&mut alice, 0, "gone").await;
    ok(
        &mut moderator,
        "redact",
        json!({ "id": gone, "reason": "no" }),
    )
    .await;
    react(&mut erin, &t, "👍").await;
    react(&mut erin, &protected, "👍").await;
    changed(&mut alice, &t).await;

    assert_eq!(refused(&mut alice, &t, CLEAR, None).await, NOT_ALLOWED);
    assert_eq!(
        refused(&mut carol, &protected, CLEAR, None).await,
        NOT_ALLOWED,
        "a protected author"
    );
    assert_eq!(
        refused(&mut carol, &lobby(gone), CLEAR, None).await,
        NO_SUCH_TARGET
    );
    let reply = send(&mut carol, &t, CLEAR, None).await;
    assert!(!reply.is_error(), "{:?}", reply.error_text());
    assert_eq!(reply.chunks().count(), 0);
    let (_, g) = changed(&mut alice, &t).await;
    assert_eq!(
        g,
        [
            (DATA_TARGET, t.clone()),
            (DATA_REACTION_ACTION, CLEAR.to_be_bytes().to_vec()),
        ]
    );
    let log = ok(&mut moderator, "moderation_log", json!({})).await;
    let clears: Vec<_> = (log["entries"].as_array().unwrap().iter())
        .filter(|e| e["kind"] == "reactions_clear")
        .map(|e| e["reason"].clone())
        .collect();
    assert_eq!(clears, [json!(CLEAR_REASON)]);
}

/// A redaction takes a line's reactions, which tells a classic reader
/// nothing it could show and an ng one a clear, and history shows its
/// tombstone; a purge of a reactor is told as summaries.
#[tokio::test]
async fn a_redaction_tells_classic_nothing_and_a_purge_is_told_as_summaries() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut bob = classic(&s, "bob", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut frank = ng_client(&s, "frank").await;
    let mut moderator = ng_client(&s, "carol").await;
    let gone_id = say(&mut alice, 0, "regrettable").await;
    let gone = lobby(gone_id);
    let kept = lobby(say(&mut alice, 0, "fine").await);
    react(&mut bob, &gone, "👍").await;
    react(&mut bob, &kept, "👍").await;
    react(&mut erin, &kept, "🎉").await;
    changed(&mut alice, &kept).await;
    alice.rx.take_backlog();
    ok(
        &mut moderator,
        "redact",
        json!({ "id": gone_id, "reason": "no" }),
    )
    .await;
    frank
        .event_where("reactions_changed", |d| {
            d["changes"][0] == json!({ "target": { "line": gone_id }, "action": "clear" })
        })
        .await
        .unwrap();
    let page = alice
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    let tomb = page
        .all(tag::HISTORY_ENTRY)
        .into_iter()
        .find(|e| u64::from_be_bytes(e[..8].try_into().unwrap()) == gone_id)
        .unwrap();
    let e = hxproto::parse::parse_history_entry(&tomb).unwrap();
    assert_ne!(e.flags & 4, 0, "a tombstone");

    ok(
        &mut moderator,
        "purge",
        json!({ "login": "bob", "since": 3600, "reason": "ballot stuffing" }),
    )
    .await;
    let (_, g) = changed(&mut alice, &kept).await;
    assert_eq!(g, summary_group(&kept, &[("🎉", 1)], &[]));
    for f in alice.rx.take_backlog() {
        assert!(!names(&f, &gone), "a redaction told to classic");
    }
}

/// What a client is sent, in order, as two runs of one script agree on
/// it: each frame's type and fields, a history entry's timestamp zeroed.
fn seen(frames: &[Frame]) -> Vec<(u32, Group)> {
    let zeroed = |d: &[u8]| {
        let mut d = d.to_vec();
        d[8..16].fill(0);
        d
    };
    frames
        .iter()
        .map(|f| {
            let fields = f
                .chunks()
                .map(|c| match c.tag {
                    DATA_CHAT_LINE | tag::HISTORY_ENTRY => (c.tag, zeroed(c.data)),
                    t => (t, c.data.to_vec()),
                })
                .collect();
            (f.ty, fields)
        })
        .collect()
}

/// A period client and one with bit 17 alone, in the lobby and a room,
/// while lines are reacted to, cleared and redacted around them: what
/// each is sent, and what 700 pages to the second, on a server keeping
/// reactions and on one without.
async fn bystanders(reactions: bool) -> (Vec<(u32, Group)>, Vec<(u32, Group)>) {
    let td = tempfile::tempdir().unwrap();
    let o = Opts {
        reactions: reactions.then_some(""),
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let mut alice = classic(&s, "alice", ON).await;
    let mut erin = classic(&s, "erin", ON).await;
    let mut carol = classic(&s, "carol", ON).await;
    let mut period = login(&s, "bob", None).await.0;
    let mut structured = classic(&s, "frank", UTF8 | HISTORY | STRUCTURED).await;
    let mut moderator = ng_client(&s, "carol").await;
    for c in [&mut alice, &mut erin, &mut period, &mut structured] {
        join(c, LOUNGE).await;
    }
    say(&mut alice, 0, "start").await;
    for c in [&mut period, &mut structured] {
        heard(c, "start").await;
        c.rx.take_backlog();
    }
    let one = say(&mut alice, 0, "one").await;
    let two = say(&mut alice, LOUNGE, "two").await;
    let three = say(&mut alice, 0, "three").await;
    send(&mut erin, &lobby(one), ADD, Some(key("👍"))).await;
    send(&mut erin, &room(LOUNGE, two), ADD, Some(key("🎉"))).await;
    send(&mut alice, &lobby(three), ADD, Some(key("👍"))).await;
    send(&mut alice, &lobby(one), ADD, Some(key("🎉"))).await;
    send(&mut carol, &lobby(one), CLEAR, None).await;
    ok(
        &mut moderator,
        "redact",
        json!({ "id": three, "reason": "no" }),
    )
    .await;
    if reactions {
        changed(&mut erin, &lobby(one)).await;
        changed(&mut erin, &room(LOUNGE, two)).await;
    }
    say(&mut alice, 0, "end").await;
    let mut sent = Vec::new();
    for c in [&mut period, &mut structured] {
        let end = heard(c, "end").await;
        let mut frames = c.rx.take_backlog();
        frames.push(end);
        sent.push(seen(&frames));
    }
    let page = structured
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    sent[1].extend(seen(&[page]));
    let structured = sent.pop().unwrap();
    (sent.pop().unwrap(), structured)
}

/// A session without bit 19 is sent what it always was: no 711, no field
/// of the family's reactions, and the same lines and history.
#[tokio::test]
async fn a_session_without_bit_19_is_sent_what_it_always_was() {
    let (period, structured) = bystanders(true).await;
    for (who, frames) in [("period", &period), ("bit 17", &structured)] {
        for (ty, fields) in frames.iter() {
            assert_ne!(*ty, CHANGED, "{who}");
            for (t, _) in fields {
                assert!(!(0x0f23..=0x0f31).contains(t), "{who}: {t:#x}");
            }
        }
    }
    assert_eq!((period, structured), bystanders(false).await);
}

/// A reaction costs a session's spam points what a line does: past them,
/// it is kicked.
#[tokio::test]
async fn a_reaction_costs_what_a_line_does() {
    let td = tempfile::tempdir().unwrap();
    // The user list at login is 20 of them, leaving four reactions' worth.
    let o = Opts {
        spam_points: 29,
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let mut bob = classic(&s, "bob", ON).await;
    let mut alice = classic(&s, "alice", ON).await;
    let t = lobby(say(&mut bob, 0, "hi").await);
    for e in ["👍", "🎉", "🍕", "🔥"] {
        react(&mut alice, &t, e).await;
    }
    let trans = alice
        .send(
            SEND,
            &[
                (DATA_TARGET, t),
                (DATA_REACTION_ACTION, ADD.to_be_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    assert!(alice.reply(trans).await.is_err(), "kicked, not answered");
}
