//! Replies on the classic wire (the Replies draft), against servers built
//! from a real config: capability bit 18 confirmed beside bits 1 and 17
//! with the kinds of target kept, Set Notifications (717) answered with
//! no type under bit 18 alone, `DATA_REPLY_TO` on a line of the lobby, a
//! room and a private chat, relayed on 106 and paged on 700 as the entry's
//! sub-field, crossing to the ng wire and back, dropped where it breaks
//! the draft and the line relayed, a stored private message's reference
//! to a session with bit 18, and every session without the bit sent what
//! it always was.
//!
//! Targets and sub-fields are laid out by hand from the draft here rather
//! than by the server's encoder, so a disagreement between the two shows.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;

use hxd_session::reactions::{CHANGED, DATA_NOTIFY_TYPES, SET_NOTIFICATIONS};
use hxd_session::replies::{DATA_REPLY_TARGETS, DATA_REPLY_TO};
use hxd_session::structured::DATA_CHAT_LINE;
use hxd_testclient::legacy::{push, Client, Frame, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::{json, Value};

const UTF8: u32 = 1 << 1;
const MEDIA: u32 = 1 << 3;
const HISTORY: u32 = 1 << 4;
const MESSAGING: u32 = 1 << 6;
const STRUCTURED: u32 = 1 << 17;
const REPLIES: u32 = 1 << 18;
const REACTIONS: u32 = 1 << 19;
const ON: u32 = UTF8 | HISTORY | STRUCTURED | REPLIES;

/// The entry's sub-field a reply's target rides in.
const REPLY_TO: u16 = 0x0020;

const MEMBER: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      create_pchats = true\nuse_any_name = true\nsend_msgs = true\n\
                      messaging = true\nsend_media = true\n";

const LOUNGE: u32 = 4000;
const STAFF: u32 = 4001;

const ROOMS: &str = "[[room]]\nid = 4000\nname = \"lounge\"\n\n\
                     [[room]]\nid = 4001\nname = \"staff\"\n";

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
}

/// What a server is built with beside moderation and rooms.
struct Opts<'a> {
    history: bool,
    structured: bool,
    reactions: bool,
    inbox: bool,
    spam_points: u32,
    extra: &'a str,
}

impl Default for Opts<'_> {
    fn default() -> Self {
        Opts {
            history: true,
            structured: true,
            reactions: true,
            inbox: false,
            spam_points: 0,
            extra: "",
        }
    }
}

async fn start(dir: &Path, o: Opts<'_>) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for login in ["alice", "bob", "dave", "erin", "frank", "boss"] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{MEMBER}"),
        )
        .unwrap();
    }
    std::fs::write(
        accounts.join("carol.toml"),
        format!("name = \"carol\"\npassword = \"pw\"\n[access]\n{MEMBER}disconnect_users = true\n"),
    )
    .unwrap();
    std::fs::write(dir.join("rooms.toml"), ROOMS).unwrap();
    let mut sections = String::new();
    if o.inbox {
        sections += &format!("[inbox]\ndb = \"{d}/hx.db\"\n");
    }
    if o.history {
        sections += &format!("[history]\ndb = \"{d}/hx.db\"\n");
    }
    if o.reactions {
        sections += "[reactions]\nenabled = true\n";
    }
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n{sections}\
         [limits]\nspam_points = {}\nchat_lines = 0\nng_requests = 0\n\
         [rooms]\nenabled = true\nfile = \"{d}/rooms.toml\"\nannounce = false\n\
         [structured_chat]\nenabled = {}\n{}",
        o.spam_points, o.structured, o.extra
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        classic: l1.local_addr().unwrap(),
        ng: l2.local_addr().unwrap(),
        core: ctx.core.clone(),
    };
    tokio::spawn(hxd::reactions_flusher(ctx.core.clone()));
    tokio::spawn(hxd_session::serve(l1, ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    server
}

async fn start_on(dir: &Path) -> Server {
    start(dir, Opts::default()).await
}

/// `who` logged in offering `caps`, without the user list, and its
/// login reply.
async fn logged_in(s: &Server, who: &str, caps: Option<u32>) -> (Client, Frame) {
    let mut c = Client::connect(s.classic).await.unwrap();
    let reply = c
        .login(&Login {
            caps,
            ..Login::account(who, who, "pw")
        })
        .await
        .unwrap();
    (c, reply)
}

async fn classic(s: &Server, who: &str, caps: Option<u32>) -> Client {
    let (mut c, _) = logged_in(s, who, caps).await;
    c.user_list().await.unwrap();
    c
}

/// `who` on the ng wire, declaring `replies` and `reactions`.
async fn ng_client(s: &Server, who: &str) -> ng::Client {
    let mut c = ng::Client::connect(s.ng).await.unwrap();
    c.login(json!({
        "login": who, "password": "pw", "nick": who, "replies": true, "reactions": true,
    }))
    .await
    .unwrap();
    c
}

async fn ok(c: &mut ng::Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn ng_heard(c: &mut ng::Client, text: &str) -> Value {
    c.event_where("chat", |d| d["text"] == text)
        .await
        .unwrap_or_else(|e| panic!("no {text:?}: {e:?}"))
        .data
}

fn cid(id: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, id.to_be_bytes().to_vec())
}

async fn join(c: &mut Client, room: u32) {
    let joined = c
        .call(ClientHdr::ChatJoin.as_u32(), &[cid(room)])
        .await
        .unwrap();
    assert!(!joined.is_error(), "{:?}", joined.error_text());
}

/// A private chat `c` opens and `members` join.
async fn private_chat(c: &mut Client, members: &mut [&mut Client]) -> u32 {
    let invite = |uid: u16| (tag::UID, uid.to_be_bytes().to_vec());
    let (first, rest) = members.split_first_mut().unwrap();
    let created = c
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[invite(first.uid.unwrap())],
        )
        .await
        .unwrap();
    let chat = created.uint(tag::CHAT_ID).unwrap();
    for m in rest.iter() {
        let fields = [cid(chat), invite(m.uid.unwrap())];
        c.call(ClientHdr::ChatInvite.as_u32(), &fields)
            .await
            .unwrap();
    }
    join(first, chat).await;
    for m in rest {
        join(m, chat).await;
    }
    chat
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

/// `c` says `text` in `chat`, 0 the lobby, with `fields` beside it, and
/// its echo.
async fn say_with(c: &mut Client, chat: u32, text: &str, fields: &[(u16, Vec<u8>)]) -> Frame {
    let mut all = vec![(tag::BODY, text.as_bytes().to_vec())];
    if chat != 0 {
        all.push(cid(chat));
    }
    all.extend_from_slice(fields);
    c.send(ClientHdr::Chat.as_u32(), &all).await.unwrap();
    heard(c, text).await
}

/// [`say_with`] naming `target`, and its echo.
async fn reply(c: &mut Client, chat: u32, text: &str, target: &[u8]) -> Frame {
    say_with(c, chat, text, &[(DATA_REPLY_TO, target.to_vec())]).await
}

/// `c` says `text`, answering the line's id.
async fn say(c: &mut Client, chat: u32, text: &str) -> u64 {
    line_id(&say_with(c, chat, text, &[]).await)
}

fn line_id(f: &Frame) -> u64 {
    let entry = f.bytes(DATA_CHAT_LINE).expect("an entry");
    u64::from_be_bytes(entry[..8].try_into().unwrap())
}

/// A line target, kind 1 or 4, as the draft lays it out.
fn target(kind: u8, chat: u32, id: u64) -> Vec<u8> {
    [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
}

fn lobby(id: u64) -> Vec<u8> {
    target(1, 0, id)
}

fn kind_4(chat: u32, id: u64) -> Vec<u8> {
    target(4, chat, id)
}

/// An entry's sub-fields, past its text.
fn subfields(entry: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let be16 = |at: usize| usize::from(u16::from_be_bytes([entry[at], entry[at + 1]]));
    let msg_at = 22 + be16(20);
    let mut at = msg_at + 2 + be16(msg_at);
    let mut out = Vec::new();
    while at < entry.len() {
        let (ty, len) = (be16(at) as u16, be16(at + 2));
        out.push((ty, entry[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    out
}

/// The target a 106's entry names, if any.
fn answers(f: &Frame) -> Option<Vec<u8>> {
    let entry = f.bytes(DATA_CHAT_LINE).expect("an entry");
    let found = subfields(&entry).into_iter().find(|(t, _)| *t == REPLY_TO);
    found.map(|(_, d)| d)
}

/// A frame as two lines that differ in their ids and times alone send
/// it: an entry's id and timestamp zeroed.
fn twin(f: &Frame) -> (u32, Vec<(u16, Vec<u8>)>) {
    let fields = f
        .chunks()
        .map(|c| match c.tag {
            DATA_CHAT_LINE | tag::HISTORY_ENTRY => {
                let mut d = c.data.to_vec();
                d[..16].fill(0);
                (c.tag, d)
            }
            t => (t, c.data.to_vec()),
        })
        .collect();
    (f.ty, fields)
}

fn confirmed(reply: &Frame) -> u32 {
    reply.uint(tag::CAPABILITIES).unwrap_or(0)
}

/// Bit 18 only beside bits 1 and 17, wherever there is Structured Chat,
/// and `DATA_REPLY_TARGETS` with it alone: kept lines where there is
/// `[history]`, and lines nobody keeps everywhere. Instant and private
/// messages are not yet among them.
#[tokio::test]
async fn bit_18_is_confirmed_beside_bits_1_and_17_with_the_kinds_kept() {
    let unkept = Opts {
        history: false,
        reactions: false,
        ..Opts::default()
    };
    let unstructured = Opts {
        structured: false,
        ..Opts::default()
    };
    let mail = Opts {
        inbox: true,
        extra: "[messaging]\nenabled = true\n",
        ..Opts::default()
    };
    for (server, opts, cases) in [
        (
            "history",
            Opts::default(),
            vec![
                ("with 1 and 17", ON, Some(0x0012)),
                ("beside 19", ON | REACTIONS, Some(0x0012)),
                ("alone", REPLIES, None),
                ("Mac Roman", HISTORY | STRUCTURED | REPLIES, None),
                ("without 17", UTF8 | HISTORY | REPLIES, None),
            ],
        ),
        (
            "no [history]",
            unkept,
            vec![("with 1 and 17", ON, Some(0x0010))],
        ),
        (
            "no [structured_chat]",
            unstructured,
            vec![("with 1 and 17", ON, None)],
        ),
        (
            "inbox and messaging",
            mail,
            vec![("with bit 6", ON | MESSAGING, Some(0x0012))],
        ),
    ] {
        let td = tempfile::tempdir().unwrap();
        let s = start(td.path(), opts).await;
        for (case, offered, want) in cases {
            let (_, reply) = logged_in(&s, "alice", Some(offered)).await;
            let bit = confirmed(&reply) & REPLIES != 0;
            assert_eq!(bit, want.is_some(), "{server}, {case}");
            let targets = reply.bytes(DATA_REPLY_TARGETS);
            let want = want.map(|t: u16| t.to_be_bytes().to_vec());
            assert_eq!(targets, want, "{server}, {case}");
        }
    }
}

/// Under bit 18 without bit 19, on a server that keeps no reactions: a
/// login that asks for notification types and 717 are answered with
/// none, 717 at its own price, while 710 is no transaction and costs
/// what any unknown one does.
#[tokio::test]
async fn set_notifications_is_answered_with_no_type_under_bit_18_alone() {
    let td = tempfile::tempdir().unwrap();
    // The user list is 20, then 717 1 and 710 10: the second 717 is over.
    let o = Opts {
        reactions: false,
        spam_points: 32,
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let asks = (DATA_NOTIFY_TYPES, 1u32.to_be_bytes().to_vec());
    for (case, caps, asking, want) in [
        ("bit 18", ON, true, Some(0)),
        ("bit 18, not asking", ON, false, None),
        ("bit 17 alone", UTF8 | HISTORY | STRUCTURED, true, None),
    ] {
        let mut c = Client::connect(s.classic).await.unwrap();
        let mut fields = Login {
            caps: Some(caps),
            ..Login::account("alice", "alice", "pw")
        }
        .chunks();
        fields.extend(asking.then(|| asks.clone()));
        let reply = c.call(ClientHdr::Login.as_u32(), &fields).await.unwrap();
        assert_eq!(reply.uint(DATA_NOTIFY_TYPES), want, "{case}: login");
    }
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let set = alice
        .call(SET_NOTIFICATIONS, std::slice::from_ref(&asks))
        .await
        .unwrap();
    assert_eq!(set.uint(DATA_NOTIFY_TYPES), Some(0));
    let fields = [(0x0f24, lobby(1)), (0x0f26, vec![0, 1])];
    let trans = alice.send(710, &fields).await.unwrap();
    let react = alice.reply(trans).await.unwrap();
    assert_eq!(react.error_text().as_deref(), Some("Not implemented."));
    let trans = alice.send(SET_NOTIFICATIONS, &[asks]).await.unwrap();
    assert!(alice.reply(trans).await.is_err(), "kicked, not answered");
}

/// A reply in the lobby reaches every reader with bit 18, its sender's
/// echo too, as the entry's sub-field, and an ng reader as `re`; one
/// from ng reaches classic alike. A reply to a lobby notice, kind 4 on
/// chat 0, is relayed to classic and heard on ng as the text alone. A
/// reader with bit 17 alone is sent what a line without one sends.
#[tokio::test]
async fn a_lobby_reply_reaches_the_readers_with_bit_18_on_both_wires() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let mut frank = classic(&s, "frank", Some(UTF8 | HISTORY | STRUCTURED)).await;
    let mut erin = ng_client(&s, "erin").await;
    let id = say(&mut alice, 0, "pizza?").await;

    let echo = reply(&mut bob, 0, "yes", &lobby(id)).await;
    assert_eq!(answers(&echo), Some(lobby(id)), "the echo");
    assert_eq!(answers(&heard(&mut alice, "yes").await), Some(lobby(id)));
    assert_eq!(
        ng_heard(&mut erin, "yes").await["re"],
        json!({ "line": id })
    );
    let with = heard(&mut frank, "yes").await;
    say_with(&mut bob, 0, "yes", &[]).await;
    let without = heard(&mut frank, "yes").await;
    assert_eq!(twin(&with), twin(&without), "bit 17 alone");

    let re = json!({ "line": id });
    ok(&mut erin, "chat", json!({ "text": "me too", "re": re })).await;
    assert_eq!(answers(&heard(&mut alice, "me too").await), Some(lobby(id)));

    let notice = kind_4(0, 77);
    reply(&mut bob, 0, "noted", &notice).await;
    assert_eq!(answers(&heard(&mut alice, "noted").await), Some(notice));
    let ev = ng_heard(&mut erin, "noted").await;
    assert!(ev.get("re").is_none(), "{ev}");
}

/// What the draft has dropped is: the line is relayed without it, and a
/// reply after it, which the reader does hear, shows the reader was
/// looking.
#[tokio::test]
async fn a_reference_that_breaks_the_draft_is_dropped_and_the_line_relayed() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let mut frank = classic(&s, "frank", Some(UTF8 | HISTORY | STRUCTURED)).await;
    let id = say(&mut alice, 0, "target").await;
    let field = |t: Vec<u8>| (DATA_REPLY_TO, t);
    let im = [&[2][..], &[7; 16], &[5], b"alice"].concat();
    let pm = [&[5, 1][..], &[3; 16]].concat();
    let signed = [&[3][..], &[0; 80]].concat();
    for (n, (case, from_frank, fields)) in [
        ("signed", false, vec![field(signed)]),
        ("an instant message", false, vec![field(im)]),
        ("a private message", false, vec![field(pm)]),
        (
            "a room's channel",
            false,
            vec![field(target(1, LOUNGE, id))],
        ),
        ("kind 4 off chat 0", false, vec![field(kind_4(LOUNGE, id))]),
        ("id 0", false, vec![field(lobby(0))]),
        (
            "past 128",
            false,
            vec![field([lobby(id), vec![0; 116]].concat())],
        ),
        ("two", false, vec![field(lobby(id)), field(lobby(id))]),
        ("a sender without bit 18", true, vec![field(lobby(id))]),
    ]
    .into_iter()
    .enumerate()
    {
        let (text, marker) = (format!("dropped {n}"), format!("kept {n}"));
        let sender = if from_frank { &mut frank } else { &mut bob };
        say_with(sender, 0, &text, &fields).await;
        assert_eq!(answers(&heard(&mut alice, &text).await), None, "{case}");
        reply(&mut bob, 0, &marker, &lobby(id)).await;
        let kept = heard(&mut alice, &marker).await;
        assert_eq!(answers(&kept), Some(lobby(id)), "{case}: the marker");
    }
}

/// A room's line is named kind 4 under its chat id, from classic and
/// back from ng, where it is `{ line, room }`; kind 1 on the room's
/// channel and another room's id are dropped.
#[tokio::test]
async fn a_rooms_reply_is_kind_4_and_stays_in_the_room() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let mut erin = ng_client(&s, "erin").await;
    for c in [&mut alice, &mut bob] {
        join(c, LOUNGE).await;
        join(c, STAFF).await;
    }
    ok(&mut erin, "room_join", json!({ "room": LOUNGE })).await;
    let id = say(&mut alice, LOUNGE, "in here").await;
    let elsewhere = say(&mut alice, STAFF, "over there").await;
    let t = kind_4(LOUNGE, id);
    reply(&mut bob, LOUNGE, "agreed", &t).await;
    assert_eq!(answers(&heard(&mut alice, "agreed").await), Some(t.clone()));
    let ev = ng_heard(&mut erin, "agreed").await;
    assert_eq!(ev["re"], json!({ "line": id, "room": LOUNGE }));

    let re = json!({ "line": id, "room": LOUNGE });
    ok(
        &mut erin,
        "chat",
        json!({ "text": "from ng", "room": LOUNGE, "re": re }),
    )
    .await;
    assert_eq!(
        answers(&heard(&mut alice, "from ng").await),
        Some(t.clone())
    );

    for (case, dropped) in [
        ("kind 1 on its channel", target(1, LOUNGE, id)),
        ("another room's", kind_4(STAFF, elsewhere)),
    ] {
        reply(&mut bob, LOUNGE, case, &dropped).await;
        assert_eq!(answers(&heard(&mut alice, case).await), None, "{case}");
        let marker = format!("{case}, kept");
        reply(&mut bob, LOUNGE, &marker, &t).await;
        assert_eq!(answers(&heard(&mut alice, &marker).await), Some(t.clone()));
    }
}

/// A private chat's line is kind 4 under its chat id, relayed to its
/// members with bit 18; one under another chat's id, or kind 1, is
/// dropped.
#[tokio::test]
async fn a_private_chats_reply_is_relayed_to_its_members() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let chat = private_chat(&mut alice, &mut [&mut bob]).await;
    let id = say(&mut alice, chat, "between us").await;
    let t = kind_4(chat, id);
    reply(&mut bob, chat, "quite", &t).await;
    assert_eq!(answers(&heard(&mut alice, "quite").await), Some(t.clone()));
    for (case, dropped) in [
        ("another chat's", kind_4(chat ^ 1, id)),
        ("the lobby's", kind_4(0, id)),
        ("kind 1", target(1, chat, id)),
    ] {
        reply(&mut bob, chat, case, &dropped).await;
        assert_eq!(answers(&heard(&mut alice, case).await), None, "{case}");
        let marker = format!("{case}, kept");
        reply(&mut bob, chat, &marker, &t).await;
        assert_eq!(answers(&heard(&mut alice, &marker).await), Some(t.clone()));
    }
}

/// Without `[history]` the lobby's lines and a room's are kept by nobody:
/// kind 4 under their chat ids is relayed to classic and heard on ng,
/// which `[inbox]` gives replies, as the text alone, and kind 1, which
/// the login did not offer, dropped.
#[tokio::test]
async fn without_history_a_reply_names_a_line_nobody_keeps() {
    let td = tempfile::tempdir().unwrap();
    let o = Opts {
        history: false,
        reactions: false,
        inbox: true,
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let mut erin = ng_client(&s, "erin").await;
    for c in [&mut alice, &mut bob] {
        join(c, LOUNGE).await;
    }
    ok(&mut erin, "room_join", json!({ "room": LOUNGE })).await;
    for (chat, text) in [(0, "the lobby"), (LOUNGE, "a room")] {
        let id = say(&mut alice, chat, text).await;
        let t = kind_4(chat, id);
        let answer = format!("{text}, answered");
        reply(&mut bob, chat, &answer, &t).await;
        assert_eq!(
            answers(&heard(&mut alice, &answer).await),
            Some(t),
            "{text}"
        );
        let ev = ng_heard(&mut erin, &answer).await;
        assert!(ev.get("re").is_none(), "{text}: {ev}");
    }
    let id = say(&mut alice, 0, "once more").await;
    reply(&mut bob, 0, "kind 1", &lobby(id)).await;
    assert_eq!(answers(&heard(&mut alice, "kind 1").await), None);
}

/// A small PNG.
fn png() -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(8, 8, image::Rgba([1, 2, 3, 0xff]));
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

/// Each lobby entry `c` is paged, by its text.
async fn page(c: &mut Client) -> Vec<(String, Vec<u8>)> {
    let page = c
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert!(!page.is_error(), "{:?}", page.error_text());
    let entries = page.all(tag::HISTORY_ENTRY).into_iter().map(|e| {
        let text = hxproto::parse::parse_history_entry(&e).unwrap().message;
        (String::from_utf8(text.to_vec()).unwrap(), e)
    });
    entries.collect()
}

fn types(entry: &[u8]) -> Vec<u16> {
    subfields(entry).into_iter().map(|(t, _)| t).collect()
}

/// A reply's target is its 106 entry's and its 700 entry's sub-field, in
/// type order after media's and before reactions', to a reader with bit
/// 18; a redacted reply's tombstone is bare, and a reply to a redacted
/// line keeps its target. A reader with bit 4 alone is paged a reply as
/// it is paged a line that answers nothing.
#[tokio::test]
async fn history_carries_a_replys_target_in_type_order() {
    let td = tempfile::tempdir().unwrap();
    let o = Opts {
        extra: "[media]\n",
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let rich = ON | MEDIA | REACTIONS;
    let mut alice = classic(&s, "alice", Some(rich)).await;
    let mut bob = classic(&s, "bob", Some(rich)).await;
    let mut dave = classic(&s, "dave", Some(UTF8 | HISTORY)).await;
    let mut carol = ng_client(&s, "carol").await;
    let id = say(&mut alice, 0, "original").await;
    let t = lobby(id);

    let uploaded = alice
        .call(
            hxd_session::media::trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, png()),
                (tag::CHAT_MEDIA_DECLARED_TYPE, b"image/png".to_vec()),
                (tag::CHAT_MEDIA_PART_FINAL, vec![1]),
            ],
        )
        .await
        .unwrap();
    let handle = uploaded.bytes(tag::CHAT_MEDIA_ID).expect("a handle");
    let fields = [
        (tag::CHAT_MEDIA_ID, handle),
        (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
        (DATA_REPLY_TO, t.clone()),
    ];
    let pictured = line_id(&say_with(&mut alice, 0, "look", &fields).await);
    let live = heard(&mut bob, "look").await;
    let entry = live.bytes(DATA_CHAT_LINE).unwrap();
    let media = [0x0010, 0x0011, 0x0012, 0x0013, 0x0014];
    assert_eq!(types(&entry), [&media[..], &[REPLY_TO]].concat(), "on 106");
    for c in [&mut alice, &mut bob] {
        let fields = [
            (0x0f24, lobby(pictured)),
            (0x0f26, vec![0, 1]),
            (0x0f25, [&[1][..], "\u{1F44D}".as_bytes()].concat()),
        ];
        let reacted = c.call(710, &fields).await.unwrap();
        assert!(!reacted.is_error(), "{:?}", reacted.error_text());
    }

    let doomed = say(&mut alice, 0, "doomed").await;
    let oops = line_id(&reply(&mut alice, 0, "oops", &t).await);
    reply(&mut bob, 0, "to the doomed", &lobby(doomed)).await;
    for line in [oops, doomed] {
        ok(&mut carol, "redact", json!({ "id": line, "reason": "no" })).await;
    }
    reply(&mut bob, 0, "twin", &t).await;
    say_with(&mut bob, 0, "twin", &[]).await;

    let paged = page(&mut alice).await;
    let entry = |text: &str| {
        let found = paged.iter().find(|(t, _)| t == text);
        found.unwrap_or_else(|| panic!("{text}")).1.clone()
    };
    let look = entry("look");
    let reactions = [0x0021, 0x0023];
    assert_eq!(
        types(&look),
        [&media[..], &[REPLY_TO], &reactions[..]].concat()
    );
    assert_eq!(subfields(&look)[5], (REPLY_TO, t.clone()));
    let tombstone = paged.iter().find(|(_, e)| id_from(e) == oops).unwrap();
    assert_eq!(subfields(&tombstone.1), [], "a redacted reply");
    let kept = subfields(&entry("to the doomed"));
    assert_eq!(
        kept,
        [(REPLY_TO, lobby(doomed))],
        "a reply to a redacted line"
    );

    let paged = page(&mut dave).await;
    let twins: Vec<_> = paged.iter().filter(|(t, _)| t == "twin").collect();
    let [with, without] = twins[..] else {
        panic!("two twins: {}", twins.len())
    };
    assert_eq!(with.1[16..], without.1[16..], "bit 4 alone");
}

fn id_from(entry: &[u8]) -> u64 {
    u64::from_be_bytes(entry[..8].try_into().unwrap())
}

/// The Replies draft's `DATA_PM_ID`.
const DATA_PM_ID: u16 = 0x0f23;

async fn msg(c: &mut Client, to: u16, text: &str) -> Frame {
    let fields = [
        (tag::UID, to.to_be_bytes().to_vec()),
        (tag::BODY, text.as_bytes().to_vec()),
    ];
    let reply = c.call(ClientHdr::Msg.as_u32(), &fields).await.unwrap();
    assert!(!reply.is_error(), "{:?}", reply.error_text());
    reply
}

async fn pm_heard(c: &mut Client, tail: &str) -> Frame {
    c.recv_where(|f| {
        f.ty == push::MSG
            && f.bytes(tag::BODY)
                .is_some_and(|b| b.ends_with(tail.as_bytes()))
    })
    .await
    .unwrap()
}

/// `alice` on ng leaves `erin` a message, reacted to while it waits, and
/// its `DATA_PM_ID`.
async fn waiting(alice: &mut ng::Client, text: &str) -> Vec<u8> {
    let sent = ok(alice, "msg", json!({ "to_login": "erin", "text": text })).await;
    let pm = json!({ "pm": sent["ref"] });
    let key = json!({ "emoji": "\u{1F44D}" });
    ok(alice, "react", json!({ "target": pm, "key": key })).await;
    let bytes = B64.decode(sent["ref"].as_str().unwrap()).unwrap();
    [&[1][..], &bytes].concat()
}

/// The 104 ending in `tail`, and the frame `c` is sent after it, a ping's
/// reply where nothing else follows it.
async fn handed(c: &mut Client, tail: &str) -> (Frame, Frame) {
    let pm = pm_heard(c, tail).await;
    let before = c.rx.take_backlog();
    assert!(before.iter().all(|f| f.ty != CHANGED), "{before:?}");
    c.send(ClientHdr::Ping.as_u32(), &[]).await.unwrap();
    (pm, c.recv_where(|_| true).await.unwrap())
}

/// A stored private message's reference reaches a session with bit 18
/// and not bit 19, on the 108 reply and the 104, live and after it
/// waited; the reactions it gathered meanwhile are told after the 104
/// to a session with bit 19 alone.
#[tokio::test]
async fn a_stored_messages_reference_reaches_a_session_with_bit_18() {
    let td = tempfile::tempdir().unwrap();
    let o = Opts {
        inbox: true,
        ..Opts::default()
    };
    let s = start(td.path(), o).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let id = msg(&mut alice, bob.uid.unwrap(), "one")
        .await
        .bytes(DATA_PM_ID);
    assert_eq!(id.as_ref().map(|i| (i.len(), i[0])), Some((17, 1)));
    assert_eq!(pm_heard(&mut bob, "one").await.bytes(DATA_PM_ID), id);

    let mut sender = ng_client(&s, "alice").await;
    for (caps, text, told) in [(ON, "later", false), (ON | REACTIONS, "again", true)] {
        let id = waiting(&mut sender, text).await;
        let (mut erin, _) = logged_in(&s, "erin", Some(caps)).await;
        let (pm, next) = handed(&mut erin, text).await;
        assert_eq!(pm.bytes(DATA_PM_ID), Some(id), "{text}");
        assert_eq!(next.ty == CHANGED, told, "{text}: {next:?}");
        let gone = erin.uid.unwrap();
        erin.shutdown().await.unwrap();
        let mut tries = 0;
        while s.core.user(gone).is_some() {
            tries += 1;
            assert!(tries < 500, "erin's session never ended");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// The second 106 ending in `tail`, a reply heard after its twin.
async fn told(c: &mut Client, tail: &str) -> Frame {
    heard(c, tail).await;
    heard(c, tail).await
}

/// While replies of every kind flow in the lobby, a room and a private
/// chat, from classic and from ng, and a sender without bit 18 sends a
/// reference anyway, a period client, one with bit 17 alone and one
/// with bits 17 and 19 are sent each reply as they are sent its twin
/// said without one, ids and times aside, and paged them alike.
#[tokio::test]
async fn a_session_without_bit_18_is_sent_what_it_always_was() {
    let td = tempfile::tempdir().unwrap();
    let s = start_on(td.path()).await;
    let mut alice = classic(&s, "alice", Some(ON)).await;
    let mut bob = classic(&s, "bob", Some(ON)).await;
    let mut boss = classic(&s, "boss", Some(UTF8 | HISTORY | STRUCTURED)).await;
    let mut period = classic(&s, "dave", None).await;
    let mut frank = classic(&s, "frank", Some(UTF8 | HISTORY | STRUCTURED)).await;
    let mut erin = classic(&s, "erin", Some(UTF8 | HISTORY | STRUCTURED | REACTIONS)).await;
    let mut carol = ng_client(&s, "carol").await;
    for c in [&mut alice, &mut bob, &mut period, &mut frank, &mut erin] {
        join(c, LOUNGE).await;
    }
    ok(&mut carol, "room_join", json!({ "room": LOUNGE })).await;
    let chat = private_chat(
        &mut alice,
        &mut [&mut bob, &mut period, &mut frank, &mut erin],
    )
    .await;
    let one = say(&mut alice, 0, "one").await;
    let two = say(&mut alice, LOUNGE, "two").await;
    let three = say(&mut alice, chat, "three").await;
    for c in [&mut period, &mut frank, &mut erin] {
        heard(c, "three").await;
        c.rx.take_backlog();
    }

    // Each case twice: its twin first, then with its reference.
    let mut pairs = 0;
    for (chat, text, t) in [
        (0, "re one", lobby(one)),
        (0, "re notice", kind_4(0, 77)),
        (LOUNGE, "re two", kind_4(LOUNGE, two)),
        (chat, "re three", kind_4(chat, three)),
    ] {
        say_with(&mut bob, chat, text, &[]).await;
        reply(&mut bob, chat, text, &t).await;
        assert_eq!(answers(&told(&mut alice, text).await), Some(t), "{text}");
        pairs += 1;
    }
    for (room, text, re) in [
        (None, "ng re one", json!({ "line": one })),
        (
            Some(LOUNGE),
            "ng re two",
            json!({ "line": two, "room": LOUNGE }),
        ),
    ] {
        let mut line = json!({ "text": text });
        if let Some(room) = room {
            line["room"] = json!(room);
        }
        ok(&mut carol, "chat", line.clone()).await;
        line["re"] = re;
        ok(&mut carol, "chat", line).await;
        assert!(answers(&told(&mut alice, text).await).is_some(), "{text}");
        pairs += 1;
    }
    say_with(&mut boss, 0, "unasked", &[]).await;
    say_with(&mut boss, 0, "unasked", &[(DATA_REPLY_TO, lobby(one))]).await;
    pairs += 1;

    say(&mut alice, 0, "end").await;
    for (who, c) in [
        ("period", &mut period),
        ("bit 17", &mut frank),
        ("bit 19", &mut erin),
    ] {
        let end = heard(c, "end").await;
        let mut frames = c.rx.take_backlog();
        frames.push(end);
        assert_eq!(frames.len(), 2 * pairs + 1, "{who}: {frames:?}");
        for pair in frames[..2 * pairs].chunks(2) {
            assert_eq!(twin(&pair[0]), twin(&pair[1]), "{who}");
        }
    }
    for (who, c) in [("bit 17", &mut frank), ("bit 19", &mut erin)] {
        let paged = page(c).await;
        for text in ["re one", "re notice", "ng re one", "unasked"] {
            let twins: Vec<_> = paged.iter().filter(|(t, _)| t == text).collect();
            let [twin, reply] = twins[..] else {
                panic!("{who}: {text}: {}", twins.len())
            };
            assert_eq!(twin.1[16..], reply.1[16..], "{who}: {text}");
        }
    }
}
