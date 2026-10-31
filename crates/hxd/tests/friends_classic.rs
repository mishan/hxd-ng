//! Instant messaging on the classic wire (`docs/instant-messaging.md`
//! §7): fogWraith's extension and the message requests draft, between
//! scripted classic clients, and with an ng client, on a real server with
//! the binary's presence flusher running.
//!
//! The requests are built by `hxproto`'s builders and the replies read by
//! its parsers, the ones GtkHx uses, so the server is checked against the
//! shared wire crate rather than against its own encoder. What is here is
//! what the domain's tests cannot show: what each client is sent and
//! answered, who is told what on which wire, and that a client that never
//! negotiated bit 6 sees the server as it was.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hxd_core::inbox::Mailbox;
use hxd_core::relationships::{AccountUpdate, RelationshipStore};
use hxd_core::{Core, FloodLimits, InboxPolicy, MessagingPolicy, Room, RoomStore};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::MAX_FRAME_DATA;
use hxd_session::{cap, Caps, ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::legacy::{self, push, Frame, Login};
use hxd_testclient::messaging::{self as im, reason};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use hxproto::messaging::{
    parse_entry, parse_message_requests, parse_roster, AckType, Limits, Presence, PresenceState,
    ReasonCode, RequestAction, RosterEntry, RosterState, TypingState, CAP_MESSAGING,
    CAP_MESSENGER_SESSION,
};
use hxproto::parse::capabilities_decode;
use serde_json::{json, Value};

const MESSAGING: u16 = CAP_MESSAGING as u16;
const MESSENGER: u16 = CAP_MESSENGER_SESSION as u16;
const UTF8: u16 = 1 << cap::TEXT_ENCODING;

struct Server {
    ng: SocketAddr,
    classic: SocketAddr,
    core: Arc<Core>,
    store: Arc<SqliteStore>,
    rooms: hxd::rooms::FileRooms,
}

impl Server {
    fn room(&self, name: &str) -> Room {
        let rooms = self.rooms.load().unwrap().rooms;
        rooms.into_iter().find(|r| r.name == name).unwrap()
    }
}

const TALK: &str = "read_chat = true\nsend_chat = true\n";
const MESSAGES: &str = "send_msgs = true\nmessaging = true\n";

/// Both frontends on one core keeping mail and relationships in SQLite,
/// with messaging on unless `messaging` is false.
async fn start(dir: &Path, messaging: bool) -> Server {
    start_with(
        dir,
        MessagingPolicy {
            enabled: messaging,
            ..MessagingPolicy::default()
        },
    )
    .await
}

/// [`start`] under `policy`, and a room. `zed` has no `AccessMessaging`
/// and `mute` no `send_msgs`; `moe` may make private chats and kick,
/// and `vip` cannot be kicked; `admin` and `guest` hold the bit, which
/// never lets them take part.
async fn start_with(dir: &Path, policy: MessagingPolicy) -> Server {
    start_held(dir, policy, FloodLimits::default()).await
}

/// [`start_with`], each session held to `flood`.
async fn start_held(dir: &Path, policy: MessagingPolicy, flood: FloodLimits) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let senders = (0..7).map(|n| (format!("s{n}"), MESSAGES.to_string()));
    let named = [
        ("alice", MESSAGES),
        ("bob", MESSAGES),
        ("carol", MESSAGES),
        ("dave", MESSAGES),
        ("erin", MESSAGES),
        ("admin", MESSAGES),
        ("zed", "send_msgs = true\n"),
        ("mute", "messaging = true\n"),
        (
            "vip",
            "send_msgs = true\nmessaging = true\ncant_be_disconnected = true\n",
        ),
        (
            "moe",
            "send_msgs = true\ncreate_pchats = true\ndisconnect_users = true\n",
        ),
    ]
    .map(|(l, b)| (l.to_string(), b.to_string()));
    for (login, bits) in named.into_iter().chain(senders) {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{TALK}{bits}"),
        )
        .unwrap();
    }
    let guest = accounts.join("guest.toml");
    let mut text = std::fs::read_to_string(&guest).unwrap();
    text.push_str("messaging = true\n");
    std::fs::write(&guest, text).unwrap();
    let rooms_file = dir.join("rooms.toml");
    std::fs::write(&rooms_file, "[[room]]\nname = \"lounge\"\n").unwrap();
    let config: hxd::Config = toml::from_str(&format!("[rooms]\nfile = {rooms_file:?}\n")).unwrap();
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let core = Core::new()
        .with_flood_limits(flood)
        .with_inbox(store.clone(), auth.clone(), InboxPolicy::default())
        .with_relationships(store.clone())
        .with_messaging(MessagingPolicy {
            presence_debounce: Duration::from_millis(50),
            ..policy
        });
    let core = Arc::new(hxd::rooms::with_rooms(core, &config).unwrap());
    tokio::spawn(hxd::presence_flusher(core.clone()));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            caps: Caps::empty().with(cap::TEXT_ENCODING),
            ..ServerConfig::default()
        }),
        files: None,
        banner: None,
        device_proof: None,
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
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
    Server {
        ng,
        classic,
        core,
        store,
        rooms: hxd::rooms::FileRooms::new(&rooms_file),
    }
}

/// A classic client offering `caps`, and its login reply.
async fn classic(s: &Server, who: &str, caps: u16) -> (legacy::Client, Frame) {
    let login = Login {
        caps: Some(caps),
        ..if who == "guest" {
            Login::guest(who)
        } else {
            Login::account(who, who, "pw")
        }
    };
    let mut c = legacy::Client::connect(s.classic).await.unwrap();
    let reply = c.login(&login).await.unwrap();
    (c, reply)
}

/// A classic client that negotiated the extension.
async fn messenger(s: &Server, who: &str) -> legacy::Client {
    let (c, reply) = classic(s, who, MESSAGING).await;
    assert_eq!(confirmed(&reply) & CAP_MESSAGING, CAP_MESSAGING, "{who}");
    c
}

async fn ng_messenger(s: &Server, who: &str) -> (ng::Client, Value) {
    let mut c = ng::Client::connect(s.ng).await.unwrap();
    let hello = c
        .login(json!({ "login": who, "password": "pw", "nick": who, "messaging": true }))
        .await
        .unwrap();
    (c, hello)
}

fn confirmed(reply: &Frame) -> u64 {
    reply
        .chunk(tag::CAPABILITIES)
        .map_or(0, |c| capabilities_decode(c.data))
}

async fn ask(c: &mut legacy::Client, hdr: ClientHdr, chunks: im::Chunks) -> Frame {
    c.ask(hdr, &chunks)
        .await
        .unwrap_or_else(|e| panic!("{hdr:?}: {e}"))
}

/// A successful reply, and its reason code.
async fn ok(c: &mut legacy::Client, hdr: ClientHdr, chunks: im::Chunks) -> Frame {
    let f = ask(c, hdr, chunks).await;
    assert!(!f.is_error(), "{hdr:?}: {:?}", f.error_text());
    f
}

/// A failure's reason code.
async fn refused(c: &mut legacy::Client, hdr: ClientHdr, chunks: im::Chunks) -> Option<ReasonCode> {
    let f = ask(c, hdr, chunks).await;
    assert!(f.is_error(), "{hdr:?} was not refused");
    reason(&f)
}

fn entry(f: &Frame) -> RosterEntry<'_> {
    parse_entry(f.wire(), f.wire().len()).unwrap()
}

/// The first notification of type `ty` about `login` that `pred` takes.
async fn told(
    c: &mut legacy::Client,
    ty: ServerHdr,
    login: &str,
    pred: impl Fn(&RosterEntry<'_>) -> bool,
) -> Frame {
    let f = c
        .recv_where(|f| {
            f.ty == ty.as_u32() && f.trans == 0 && {
                let e = entry(f);
                e.login == login.as_bytes() && pred(&e)
            }
        })
        .await
        .unwrap_or_else(|e| panic!("no {ty:?} about {login}: {e}"));
    f
}

async fn im_of(c: &mut legacy::Client, body: &[u8]) -> Frame {
    c.recv_where(|f| {
        f.ty == ServerHdr::ImDeliver.as_u32() && f.bytes(tag::MESSAGE_BODY).as_deref() == Some(body)
    })
    .await
    .unwrap_or_else(|e| panic!("no 811 {body:?}: {e}"))
}

fn heard(f: &Frame, text: &[u8]) -> bool {
    f.bytes(tag::BODY)
        .is_some_and(|b| b.windows(text.len()).any(|w| w == text))
}

fn state(s: RosterState) -> impl Fn(&RosterEntry<'_>) -> bool {
    move |e| e.state == Some(s.wire())
}

/// `a` and `b`, both classic, friends, and the Roster Entry that told
/// `a` so.
async fn befriend(
    a: &mut legacy::Client,
    a_login: &str,
    b: &mut legacy::Client,
    b_login: &str,
) -> Frame {
    ok(
        a,
        ClientHdr::AddFriend,
        im::add_friend(b_login.as_bytes(), None),
    )
    .await;
    told(b, ServerHdr::FriendRequest, a_login, |_| true).await;
    ok(
        b,
        ClientHdr::FriendResponse,
        im::friend_response(a_login.as_bytes(), true),
    )
    .await;
    told(
        a,
        ServerHdr::RosterEntry,
        b_login,
        state(RosterState::Accepted),
    )
    .await
}

fn guid(n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[6] = 0x40;
    g[8] = 0x80;
    g[15] = n;
    g
}

fn ng_guid(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
}

fn presence(state: PresenceState, text: Option<&[u8]>, takes: Option<bool>) -> im::Chunks {
    im::set_presence(&Presence {
        state,
        status_text: text,
        discoverable: None,
        takes_requests: takes,
    })
}

#[tokio::test]
async fn two_classic_clients_become_friends_and_talk() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let mut bob = messenger(&s, "bob").await;
    for c in [&mut alice, &mut bob] {
        ok(
            c,
            ClientHdr::SetPresence,
            presence(PresenceState::Online, None, None),
        )
        .await;
    }

    let asked = ok(
        &mut alice,
        ClientHdr::AddFriend,
        im::add_friend(b"bob", Some(b"hi, it's alice")),
    )
    .await;
    assert_eq!(
        asked.uint(tag::ROSTER_STATE),
        Some(RosterState::PendingOut.wire().into())
    );
    told(
        &mut alice,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::PendingOut),
    )
    .await;
    let request = told(&mut bob, ServerHdr::FriendRequest, "alice", |_| true).await;
    assert_eq!(entry(&request).note, Some(&b"hi, it's alice"[..]));

    // The roster lists the request, and its Friend Request follows.
    let rows = ok(&mut bob, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(rows.wire(), rows.wire().len()).unwrap();
    let listed: Vec<_> = roster.entries().collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].login, listed[0].roster_state()),
        (&b"alice"[..], Some(RosterState::PendingIn))
    );
    let again = bob
        .recv_where(|f| f.ty == ServerHdr::FriendRequest.as_u32())
        .await
        .unwrap();
    assert_eq!(entry(&again).login, b"alice");

    ok(
        &mut bob,
        ClientHdr::FriendResponse,
        im::friend_response(b"alice", true),
    )
    .await;
    told(
        &mut bob,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Accepted),
    )
    .await;
    told(
        &mut alice,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;

    // Presence, told once the burst settles.
    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Away, Some(b"at lunch"), None),
    )
    .await;
    let seen = told(&mut bob, ServerHdr::PresenceChanged, "alice", |e| {
        e.presence_state() == Some(PresenceState::Away)
    })
    .await;
    assert_eq!(entry(&seen).status_text, Some(&b"at lunch"[..]));

    // An instant message, its receipts, and typing.
    let sent = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"bob", &guid(1), b"lunch?"),
    )
    .await;
    assert_eq!(reason(&sent), Some(ReasonCode::Ok));
    let m = im_of(&mut bob, b"lunch?").await;
    assert_eq!(m.bytes(tag::MESSAGE_GUID), Some(guid(1).to_vec()));
    assert_eq!(m.bytes(tag::FRIEND_LOGIN), Some(b"alice".to_vec()));
    assert_eq!(m.chunk(tag::MESSAGE_TIMESTAMP).unwrap().data.len(), 8);
    for ack in [AckType::Delivered, AckType::Read] {
        ok(
            &mut bob,
            ClientHdr::ImAck,
            im::im_ack(&guid(1), ack, b"alice"),
        )
        .await;
        let receipt = alice
            .recv_where(|f| {
                f.ty == ServerHdr::ImAck.as_u32()
                    && f.uint(tag::ACK_TYPE) == Some(ack.wire().into())
            })
            .await
            .unwrap();
        assert_eq!(receipt.bytes(tag::MESSAGE_GUID), Some(guid(1).to_vec()));
        assert_eq!(receipt.bytes(tag::FRIEND_LOGIN), Some(b"bob".to_vec()));
    }
    bob.send(
        ClientHdr::ImTyping.as_u32(),
        &im::im_typing(b"alice", TypingState::Started),
    )
    .await
    .unwrap();
    let typing = alice
        .recv_where(|f| f.ty == ServerHdr::ImTyping.as_u32())
        .await
        .unwrap();
    assert_eq!(typing.bytes(tag::FRIEND_LOGIN), Some(b"bob".to_vec()));
    assert_eq!(
        typing.uint(tag::TYPING_STATE),
        Some(TypingState::Started.wire().into())
    );

    // An alias, told to the caller's sessions whole.
    ok(
        &mut bob,
        ClientHdr::SetFriendNickname,
        im::set_friend_nickname(b"alice", b"Al"),
    )
    .await;
    let aliased = told(&mut bob, ServerHdr::RosterEntry, "alice", |e| {
        e.nickname.is_some()
    })
    .await;
    let e = entry(&aliased);
    assert_eq!(
        (
            e.nickname,
            e.roster_state(),
            e.presence_state(),
            e.status_text
        ),
        (
            Some(&b"Al"[..]),
            Some(RosterState::Accepted),
            Some(PresenceState::Away),
            Some(&b"at lunch"[..])
        )
    );

    // What the profile shows a friend.
    let profile = ok(&mut bob, ClientHdr::GetProfile, im::login_only(b"alice")).await;
    assert_eq!(reason(&profile), Some(ReasonCode::Ok));
    assert_eq!(profile.bytes(tag::FRIEND_LOGIN), Some(b"alice".to_vec()));
    assert_eq!(profile.bytes(tag::NAME), Some(b"alice".to_vec()));
}

#[tokio::test]
async fn an_instant_message_sent_while_away_arrives_at_get_roster() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let mut bob = messenger(&s, "bob").await;
    // Once bob's sign-on has been told, which the debounce may still
    // owe, so that his leaving is a change.
    let accepted = befriend(&mut alice, "alice", &mut bob, "bob").await;
    if entry(&accepted).presence_state() != Some(PresenceState::Online) {
        told(&mut alice, ServerHdr::PresenceChanged, "bob", |e| {
            e.presence_state() == Some(PresenceState::Online)
        })
        .await;
    }
    bob.shutdown().await.unwrap();
    told(&mut alice, ServerHdr::PresenceChanged, "bob", |e| {
        e.presence_state() == Some(PresenceState::Offline)
    })
    .await;

    let sent = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"bob", &guid(2), b"while you were out"),
    )
    .await;
    assert_eq!(reason(&sent), Some(ReasonCode::OfflineQueued));

    let mut bob = messenger(&s, "bob").await;
    bob.ping().await.unwrap();
    let before: Vec<u32> = bob.rx.take_backlog().iter().map(|f| f.ty).collect();
    assert!(
        !before.contains(&ServerHdr::ImDeliver.as_u32()),
        "{before:x?}"
    );
    let rows = ok(&mut bob, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(rows.wire(), rows.wire().len()).unwrap();
    assert_eq!(roster.entries().next().unwrap().login, b"alice");
    let m = im_of(&mut bob, b"while you were out").await;
    assert_eq!(m.bytes(tag::MESSAGE_GUID), Some(guid(2).to_vec()));
    // Handed over as an instant message alone, never as mail too.
    bob.ping().await.unwrap();
    assert!(!bob.rx.take_backlog().iter().any(|f| f.ty == push::MSG));
}

#[tokio::test]
async fn a_block_reads_as_a_missing_account() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let mut carol = messenger(&s, "carol").await;
    ok(&mut carol, ClientHdr::BlockUser, im::block(b"alice")).await;
    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(false)),
    )
    .await;

    // A blocker is answered as an account nobody holds, and one that
    // takes no part as neither, on every request that names one.
    type Build = fn(&[u8]) -> im::Chunks;
    let naming: [(ClientHdr, Build); 7] = [
        (ClientHdr::AddFriend, |l| im::add_friend(l, None)),
        (ClientHdr::FriendResponse, |l| im::friend_response(l, true)),
        (ClientHdr::RemoveFriend, im::remove_friend),
        (ClientHdr::SetFriendNickname, |l| {
            im::set_friend_nickname(l, b"x")
        }),
        (ClientHdr::FindUser, im::find_user),
        (ClientHdr::GetProfile, im::login_only),
        (ClientHdr::ImSend, |l| im::im_send(l, &guid(3), b"hello?")),
    ];
    for (hdr, build) in naming {
        for who in ["carol", "nobody", "zed"] {
            let got = refused(&mut alice, hdr, build(who.as_bytes())).await;
            assert_eq!(got, Some(ReasonCode::AccountNotFound), "{hdr:?} {who}");
        }
    }
    // A receipt is dropped unsaid, and a block or unblock of anyone is
    // answered as usual.
    type Quiet = fn(&[u8]) -> im::Chunks;
    let quiet: [(ClientHdr, Quiet); 3] = [
        (ClientHdr::ImAck, |l| im::im_ack(&guid(9), AckType::Read, l)),
        (ClientHdr::BlockUser, im::block),
        (ClientHdr::UnblockUser, im::login_only),
    ];
    for (hdr, build) in quiet {
        for who in ["carol", "nobody", "zed"] {
            let f = ok(&mut alice, hdr, build(who.as_bytes())).await;
            assert_eq!(reason(&f), Some(ReasonCode::Ok), "{hdr:?} {who}");
        }
    }
    let found = ok(&mut carol, ClientHdr::FindUser, im::find_user(b"alice")).await;
    assert_eq!(found.bytes(tag::FRIEND_LOGIN), Some(b"alice".to_vec()));
}

#[tokio::test]
async fn a_request_is_listed_approved_and_answered() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let mut dave = messenger(&s, "dave").await;
    ok(
        &mut dave,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(true)),
    )
    .await;

    // Not understanding requests, alice cannot send one.
    let got = refused(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"dave", &guid(3), b"hello dave"),
    )
    .await;
    assert_eq!(got, Some(ReasonCode::NotFriends));
    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(false)),
    )
    .await;
    let sent = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"dave", &guid(3), b"hello dave"),
    )
    .await;
    assert_eq!(reason(&sent), Some(ReasonCode::Requested));
    dave.recv_where(|f| {
        f.ty == ServerHdr::MessageRequestsChanged.as_u32() && f.uint(tag::REQUEST_COUNT) == Some(1)
    })
    .await
    .unwrap();

    let listed = ok(
        &mut dave,
        ClientHdr::GetMessageRequests,
        im::get_message_requests(None),
    )
    .await;
    let l = parse_message_requests(listed.wire(), listed.wire().len()).unwrap();
    assert_eq!(
        (l.takes_requests, l.dropped, l.cursor),
        (Some(true), Some(0), None)
    );
    let groups: Vec<_> = l.groups().collect();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].login, b"alice");
    assert!(!groups[0].is_approval());
    let msgs: Vec<_> = groups[0].messages().collect();
    assert_eq!(msgs.len(), 1);
    assert_eq!((msgs[0].guid, msgs[0].body), (&guid(3), &b"hello dave"[..]));

    ok(
        &mut dave,
        ClientHdr::AnswerMessageRequest,
        im::answer_message_request(b"alice", RequestAction::Approve),
    )
    .await;
    im_of(&mut dave, b"hello dave").await;
    let listed = ok(
        &mut dave,
        ClientHdr::GetMessageRequests,
        im::get_message_requests(None),
    )
    .await;
    let l = parse_message_requests(listed.wire(), listed.wire().len()).unwrap();
    let groups: Vec<_> = l.groups().collect();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].login, b"alice");
    assert!(groups[0].is_approval());

    // Under an approval every send is answered as queued.
    let back = ok(
        &mut dave,
        ClientHdr::ImSend,
        im::im_send(b"alice", &guid(4), b"hi alice"),
    )
    .await;
    assert_eq!(reason(&back), Some(ReasonCode::OfflineQueued));
    im_of(&mut alice, b"hi alice").await;

    // Ending it holds alice, whose next message is answered as a request.
    ok(
        &mut dave,
        ClientHdr::AnswerMessageRequest,
        im::answer_message_request(b"alice", RequestAction::EndApproval),
    )
    .await;
    let got = refused(
        &mut dave,
        ClientHdr::AnswerMessageRequest,
        im::answer_message_request(b"alice", RequestAction::Delete),
    )
    .await;
    assert_eq!(got, Some(ReasonCode::AccountNotFound));
    let again = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"dave", &guid(5), b"still there?"),
    )
    .await;
    assert_eq!(reason(&again), Some(ReasonCode::Requested));
    let listed = ok(
        &mut dave,
        ClientHdr::GetMessageRequests,
        im::get_message_requests(None),
    )
    .await;
    let l = parse_message_requests(listed.wire(), listed.wire().len()).unwrap();
    assert_eq!(l.groups().count(), 0);

    let cleared = ok(
        &mut dave,
        ClientHdr::ClearMessageRequests,
        im::clear_message_requests(None, None),
    )
    .await;
    assert_eq!(
        (
            cleared.uint(tag::REQUEST_COUNT),
            cleared.uint(tag::FRIEND_REQUEST_COUNT)
        ),
        (Some(0), Some(0))
    );
}

#[tokio::test]
async fn a_classic_client_and_an_ng_client_are_friends() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let (mut bob, _) = ng_messenger(&s, "bob").await;

    ok(
        &mut alice,
        ClientHdr::AddFriend,
        im::add_friend(b"bob", None),
    )
    .await;
    bob.event_where("friend_request", |d| d["login"] == "alice")
        .await
        .unwrap();
    bob.request(
        "friend_respond",
        json!({ "login": "alice", "accept": true }),
    )
    .await
    .unwrap();
    told(
        &mut alice,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;

    // Each way, an instant message and presence.
    let sent = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"bob", &guid(1), b"hi bob"),
    )
    .await;
    assert_eq!(reason(&sent), Some(ReasonCode::Ok));
    let m = bob
        .event_where("im", |d| d["text"] == "hi bob")
        .await
        .unwrap();
    assert_eq!(m.data["from"]["login"], "alice");
    assert_eq!(m.data["guid"], ng_guid(1));
    bob.request(
        "msg",
        json!({ "to_login": "alice", "text": "hi alice", "guid": ng_guid(2) }),
    )
    .await
    .unwrap();
    let m = im_of(&mut alice, b"hi alice").await;
    assert_eq!(m.bytes(tag::FRIEND_LOGIN), Some(b"bob".to_vec()));
    assert_eq!(m.bytes(tag::MESSAGE_GUID), Some(guid(2).to_vec()));

    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Busy, None, None),
    )
    .await;
    bob.event_where("presence", |d| {
        d["login"] == "alice" && d["state"] == "busy"
    })
    .await
    .unwrap();
    bob.request("presence", json!({ "state": "away" }))
        .await
        .unwrap();
    told(&mut alice, ServerHdr::PresenceChanged, "bob", |e| {
        e.presence_state() == Some(PresenceState::Away)
    })
    .await;

    // Each way, a removal: bob's holds alice, so the friendship is made
    // again from bob's side before alice's.
    bob.request("friend_remove", json!({ "login": "alice" }))
        .await
        .unwrap();
    told(
        &mut alice,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Removed),
    )
    .await;
    bob.request("friend_add", json!({ "login": "alice" }))
        .await
        .unwrap();
    told(&mut alice, ServerHdr::FriendRequest, "bob", |_| true).await;
    ok(
        &mut alice,
        ClientHdr::FriendResponse,
        im::friend_response(b"bob", true),
    )
    .await;
    bob.event_where("friend", |d| {
        d["friend"]["login"] == "alice" && d["friend"]["state"] == "accepted"
    })
    .await
    .unwrap();
    ok(
        &mut alice,
        ClientHdr::RemoveFriend,
        im::remove_friend(b"bob"),
    )
    .await;
    bob.event_where("friend", |d| {
        d["friend"]["login"] == "alice" && d["friend"]["state"] == "removed"
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_messenger_session_is_on_no_user_list() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut erin = legacy::Client::login_at(s.classic, &Login::account("erin", "erin", "pw"))
        .await
        .unwrap();
    erin.user_list().await.unwrap();
    let (mut carol, _) = ng_messenger(&s, "carol").await;
    erin.recv_type(push::USER_CHANGE).await.unwrap();

    let (mut alice, reply) = classic(&s, "alice", MESSAGING | MESSENGER).await;
    let both = CAP_MESSAGING | CAP_MESSENGER_SESSION;
    assert_eq!(confirmed(&reply) & both, both);
    let uid = alice.uid.unwrap();
    assert!(erin.user_list().await.unwrap().iter().all(|u| u.uid != uid));
    let synced = carol.sync().await.unwrap();
    assert!(synced["users"]
        .as_array()
        .unwrap()
        .iter()
        .all(|u| u["uid"] != uid));

    // Nobody to message, invite or kick by uid: answered as a uid nobody
    // holds is.
    let mut moe = legacy::Client::login_at(s.classic, &Login::account("moe", "moe", "pw"))
        .await
        .unwrap();
    let moe_uid = moe.uid.unwrap();
    let chat = moe
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, moe_uid.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let cid = chat.uint(tag::CHAT_ID).unwrap();
    let room = s.room("lounge").id;
    s.core.room_join(moe_uid, room).unwrap();
    let to = |u: u16| (tag::UID, u.to_be_bytes().to_vec());
    let in_ = |c: u32| (tag::CHAT_ID, c.to_be_bytes().to_vec());
    let acts: [(ClientHdr, im::Chunks); 5] = [
        (ClientHdr::Msg, vec![(tag::BODY, b"hi".to_vec())]),
        (ClientHdr::ChatCreate, vec![]),
        (ClientHdr::ChatInvite, vec![in_(cid)]),
        (ClientHdr::ChatInvite, vec![in_(room)]),
        (ClientHdr::UserKick, vec![]),
    ];
    for (hdr, rest) in acts {
        let mut answers = Vec::new();
        for who in [uid, 9999] {
            let mut chunks = vec![to(who)];
            chunks.extend(rest.iter().cloned());
            let f = ask(&mut moe, hdr, chunks).await;
            answers.push((f.is_error(), f.error_text()));
        }
        assert!(answers[0].0, "{hdr:?}");
        assert_eq!(answers[0], answers[1], "{hdr:?}");
    }
    // One that may not be kicked says so no more than one nobody holds.
    let (vip, _) = classic(&s, "vip", MESSAGING | MESSENGER).await;
    let mut answers = Vec::new();
    for who in [vip.uid.unwrap(), 9999] {
        let f = ask(&mut moe, ClientHdr::UserKick, vec![to(who)]).await;
        answers.push((f.is_error(), f.error_text()));
    }
    assert!(answers[0].0);
    assert_eq!(answers[0], answers[1]);

    // Nor does it act in the classic world: a list, a private message
    // and a chat line are refused, the line dropped unheard.
    for (hdr, chunks) in [
        (ClientHdr::UserGetList, vec![]),
        (
            ClientHdr::Msg,
            vec![to(erin.uid.unwrap()), (tag::BODY, b"psst".to_vec())],
        ),
    ] {
        let f = ask(&mut alice, hdr, chunks).await;
        assert_eq!(
            f.error_text().as_deref(),
            Some("A messenger session may not do that."),
            "{hdr:?}"
        );
    }
    alice.chat(b"from nowhere").await.unwrap();
    alice.ping().await.unwrap();
    erin.chat(b"still here").await.unwrap();
    erin.recv_where(|f| f.ty == push::CHAT && heard(f, b"still here"))
        .await
        .unwrap();
    assert!(!erin
        .rx
        .take_backlog()
        .iter()
        .any(|f| f.ty == push::CHAT && heard(f, b"from nowhere")));

    // Reached through the friend family alone.
    carol
        .request("friend_add", json!({ "login": "alice" }))
        .await
        .unwrap();
    told(&mut alice, ServerHdr::FriendRequest, "carol", |_| true).await;
    ok(
        &mut alice,
        ClientHdr::FriendResponse,
        im::friend_response(b"carol", true),
    )
    .await;
    let accepted = carol
        .event_where("friend", |d| d["friend"]["state"] == "accepted")
        .await
        .unwrap();
    if accepted.data["friend"]["presence"] != "online" {
        carol
            .event_where("presence", |d| {
                d["login"] == "alice" && d["state"] == "online"
            })
            .await
            .unwrap();
    }
    let sent = carol
        .request(
            "msg",
            json!({ "to_login": "alice", "text": "psst", "guid": ng_guid(1) }),
        )
        .await
        .unwrap();
    assert_eq!(sent["queued"], false);
    im_of(&mut alice, b"psst").await;

    alice.shutdown().await.unwrap();
    carol
        .event_where("presence", |d| {
            d["login"] == "alice" && d["state"] == "offline"
        })
        .await
        .unwrap();
    erin.ping().await.unwrap();
    let about_alice: Vec<u32> = erin
        .rx
        .take_backlog()
        .iter()
        .filter(|f| f.uint(tag::UID) == Some(uid.into()))
        .map(|f| f.ty)
        .collect();
    assert!(about_alice.is_empty(), "{about_alice:x?}");
    let rows: Vec<String> = carol
        .rx
        .take_backlog()
        .iter()
        .filter(|e| {
            e.ev.starts_with("user_") && (e.data["user"]["uid"] == uid || e.data["uid"] == uid)
        })
        .map(|e| e.ev.clone())
        .collect();
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn bit_6_is_confirmed_only_where_messaging_is() {
    let td = tempfile::tempdir().unwrap();
    let (on, off) = (td.path().join("on"), td.path().join("off"));
    for dir in [&on, &off] {
        std::fs::create_dir(dir).unwrap();
    }
    let (on, off) = (start(&on, true).await, start(&off, false).await);
    let limits = |message_bytes| Limits {
        max_message_bytes: Some(message_bytes),
        max_roster_size: Some(500),
        max_offline_queue: Some(200),
        max_request_messages: Some(5),
        ..Limits::default()
    };
    // A Mac Roman character can take three of the UTF-8 bytes the domain
    // bounds, so a Mac Roman session is told a third of the bound.
    let cases = [
        (&on, "alice", MESSAGING, CAP_MESSAGING, limits(1365)),
        (
            &on,
            "alice",
            MESSAGING | MESSENGER | UTF8,
            CAP_MESSAGING | CAP_MESSENGER_SESSION,
            limits(4096),
        ),
        (&on, "alice", MESSENGER, 0, Limits::default()),
        (&on, "zed", MESSAGING, 0, Limits::default()),
        (&on, "admin", MESSAGING, 0, Limits::default()),
        (&on, "guest", MESSAGING, 0, Limits::default()),
        (&off, "alice", MESSAGING, 0, Limits::default()),
    ];
    for (server, who, offered, want, advertised) in cases {
        let (mut c, reply) = classic(server, who, offered).await;
        let both = CAP_MESSAGING | CAP_MESSENGER_SESSION;
        assert_eq!(confirmed(&reply) & both, want, "{who} {offered:#x}");
        assert_eq!(
            Limits::extract(reply.wire(), reply.wire().len()),
            advertised,
            "{who} {offered:#x}"
        );
        if want == 0 {
            // Answered as before the family existed.
            let f = ask(&mut c, ClientHdr::GetRoster, Vec::new()).await;
            assert_eq!(f.error_text().as_deref(), Some("Not implemented."));
            assert_eq!(f.wire_len(), 22 + 4 + "Not implemented.".len());
        }
    }
}

#[tokio::test]
async fn a_period_client_beside_it_all_hears_nothing_new() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut erin = legacy::Client::login_at(s.classic, &Login::account("erin", "erin", "pw"))
        .await
        .unwrap();
    erin.user_list().await.unwrap();
    let mut alice = messenger(&s, "alice").await;
    let mut bob = messenger(&s, "bob").await;
    befriend(&mut alice, "alice", &mut bob, "bob").await;
    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Away, Some(b"out"), None),
    )
    .await;
    ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"bob", &guid(1), b"psst"),
    )
    .await;
    im_of(&mut bob, b"psst").await;
    // A friend request to erin, whose session does not speak the family,
    // reaches it as nothing.
    ok(
        &mut alice,
        ClientHdr::AddFriend,
        im::add_friend(b"erin", None),
    )
    .await;

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

#[tokio::test]
async fn a_messenger_sessions_mail_waits_for_a_visible_session() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    // Mail to oneself goes as mail whatever messaging is, and waits.
    let (mut note, _) = ng_messenger(&s, "alice").await;
    let sent = note
        .request("msg", json!({ "to_login": "alice", "text": "for alice" }))
        .await
        .unwrap();
    assert_eq!(sent["queued"], true);
    note.logout().await.unwrap();

    let (mut hidden, _) = classic(&s, "alice", MESSAGING | MESSENGER).await;
    hidden.ping().await.unwrap();
    assert!(!hidden.rx.take_backlog().iter().any(|f| f.ty == push::MSG));
    let mut shown = legacy::Client::login_at(s.classic, &Login::account("alice", "alice", "pw"))
        .await
        .unwrap();
    shown
        .recv_where(|f| f.ty == push::MSG && heard(f, b"for alice"))
        .await
        .unwrap();
}

#[tokio::test]
async fn clearing_requests_declines_and_deletes_them() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let mut bob = messenger(&s, "bob").await;
    let mut dave = messenger(&s, "dave").await;
    ok(
        &mut dave,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(true)),
    )
    .await;
    ok(
        &mut alice,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(false)),
    )
    .await;
    let sent = ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"dave", &guid(1), b"hello"),
    )
    .await;
    assert_eq!(reason(&sent), Some(ReasonCode::Requested));
    ok(
        &mut bob,
        ClientHdr::AddFriend,
        im::add_friend(b"dave", None),
    )
    .await;
    told(&mut dave, ServerHdr::FriendRequest, "bob", |_| true).await;

    // A span past what a clock holds, and one of the wrong width, are
    // malformed, and the session goes on.
    let malformed = [
        im::clear_message_requests(Some(u64::MAX), None),
        vec![(tag::SPAN_BEFORE, vec![0; 7])],
    ];
    for chunks in malformed {
        let f = ask(&mut dave, ClientHdr::ClearMessageRequests, chunks).await;
        assert_eq!(f.error_text().as_deref(), Some("Malformed request."));
    }
    dave.ping().await.unwrap();

    let cleared = ok(
        &mut dave,
        ClientHdr::ClearMessageRequests,
        im::clear_message_requests(None, None),
    )
    .await;
    assert_eq!(
        (
            cleared.uint(tag::REQUEST_COUNT),
            cleared.uint(tag::FRIEND_REQUEST_COUNT)
        ),
        (Some(1), Some(1))
    );
    dave.recv_where(|f| {
        f.ty == ServerHdr::MessageRequestsChanged.as_u32() && f.uint(tag::REQUEST_COUNT) == Some(0)
    })
    .await
    .unwrap();
    told(
        &mut bob,
        ServerHdr::RosterEntry,
        "dave",
        state(RosterState::Removed),
    )
    .await;
}

#[tokio::test]
async fn an_account_without_send_msgs_sends_no_instant_message() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut mute = messenger(&s, "mute").await;
    let f = ask(
        &mut mute,
        ClientHdr::ImSend,
        im::im_send(b"alice", &guid(1), b"hello"),
    )
    .await;
    assert_eq!(
        f.error_text().as_deref(),
        Some("You are not allowed to send private messages.")
    );
}

#[tokio::test]
async fn text_crosses_between_mac_roman_and_utf8() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let mut alice = messenger(&s, "alice").await;
    let (mut bob, reply) = classic(&s, "bob", MESSAGING | UTF8).await;
    assert_ne!(confirmed(&reply) & u64::from(UTF8), 0);
    befriend(&mut alice, "alice", &mut bob, "bob").await;
    // e-acute and the trade mark sign in Mac Roman, then i-diaeresis.
    ok(
        &mut alice,
        ClientHdr::ImSend,
        im::im_send(b"bob", &guid(1), b"caf\x8e \xaa"),
    )
    .await;
    im_of(&mut bob, "caf\u{e9} \u{2122}".as_bytes()).await;
    ok(
        &mut bob,
        ClientHdr::ImSend,
        im::im_send(b"alice", &guid(2), "na\u{ef}ve".as_bytes()),
    )
    .await;
    im_of(&mut alice, b"na\x95ve").await;
}

#[tokio::test]
async fn a_roster_past_a_frame_goes_on_in_roster_entries() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), true).await;
    let me = Mailbox {
        login: "alice".into(),
        fingerprint: None,
    };
    let status = "\u{2122}".repeat(255);
    let friends = 400;
    for n in 0..friends {
        let f = Mailbox {
            login: format!("f{n:03}"),
            fingerprint: None,
        };
        s.store.befriend(&me, &f, SystemTime::now()).unwrap();
        let update = AccountUpdate {
            shown_text: Some(Some(status.clone())),
            ..AccountUpdate::default()
        };
        s.store.update_account(&f, &update).unwrap();
    }
    let (mut alice, _) = classic(&s, "alice", MESSAGING | UTF8).await;
    let reply = ok(&mut alice, ClientHdr::GetRoster, Vec::new()).await;
    assert!(reply.wire_len() <= 22 + MAX_FRAME_DATA as usize);
    let roster = parse_roster(reply.wire(), reply.wire().len()).unwrap();
    let mut seen: Vec<Vec<u8>> = roster.entries().map(|e| e.login.to_vec()).collect();
    assert!(seen.len() < friends, "the reply holds them all");
    while seen.len() < friends {
        let f = alice
            .recv_where(|f| f.ty == ServerHdr::RosterEntry.as_u32())
            .await
            .unwrap();
        let e = entry(&f);
        assert_eq!(e.status_text, Some(status.as_bytes()));
        seen.push(e.login.to_vec());
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), friends);
}

/// A 60000-byte request from sender `n` to dave.
async fn ask_dave(c: &mut legacy::Client, n: u8) {
    let body = vec![b'a' + n; 60_000];
    let sent = ok(c, ClientHdr::ImSend, im::im_send(b"dave", &guid(n), &body)).await;
    assert_eq!(reason(&sent), Some(ReasonCode::Requested));
}

/// A page of dave's requests: its dropped count, its setting, its cursor
/// and its senders.
type RequestsPage = (Option<u32>, Option<bool>, Option<Vec<u8>>, Vec<Vec<u8>>);

async fn page_of(dave: &mut legacy::Client, cursor: Option<&[u8]>) -> RequestsPage {
    let f = ok(
        dave,
        ClientHdr::GetMessageRequests,
        im::get_message_requests(cursor),
    )
    .await;
    assert!(f.wire_len() <= 22 + MAX_FRAME_DATA as usize);
    let page = parse_message_requests(f.wire(), f.wire().len()).unwrap();
    let logins = page.groups().map(|g| g.login.to_vec()).collect();
    (
        page.dropped,
        page.takes_requests,
        page.cursor.map(<[u8]>::to_vec),
        logins,
    )
}

#[tokio::test]
async fn requests_page_across_frames() {
    let td = tempfile::tempdir().unwrap();
    let s = start_with(
        td.path(),
        MessagingPolicy {
            enabled: true,
            request_messages: 1,
            max_message_bytes: 60_000,
            max_requests: 5,
            ..MessagingPolicy::default()
        },
    )
    .await;
    let mut dave = messenger(&s, "dave").await;
    ok(
        &mut dave,
        ClientHdr::SetPresence,
        presence(PresenceState::Online, None, Some(true)),
    )
    .await;
    // Six senders to a box of five: the sixth is dropped.
    let mut senders = Vec::new();
    for n in 0..7u8 {
        let mut c = messenger(&s, &format!("s{n}")).await;
        ok(
            &mut c,
            ClientHdr::SetPresence,
            presence(PresenceState::Online, None, Some(false)),
        )
        .await;
        senders.push(c);
    }
    for n in 0..6u8 {
        ask_dave(&mut senders[usize::from(n)], n).await;
    }

    let (dropped, takes, mut cursor, mut seen) = page_of(&mut dave, None).await;
    assert_eq!((dropped, takes), (Some(1), Some(true)));
    // A drop after the first page is not the later pages' to say, nor
    // theirs to reset: the next first page says it.
    ask_dave(&mut senders[6], 6).await;
    let mut pages = 1;
    while let Some(c) = cursor {
        let (dropped, takes, next, logins) = page_of(&mut dave, Some(&c)).await;
        assert_eq!((dropped, takes), (None, None), "page {pages}");
        seen.extend(logins);
        cursor = next;
        pages += 1;
    }
    assert!(pages >= 2, "{pages}");
    let want: Vec<Vec<u8>> = (0..5).map(|n| format!("s{n}").into_bytes()).collect();
    assert_eq!(seen, want);
    let (dropped, ..) = page_of(&mut dave, None).await;
    assert_eq!(dropped, Some(1));
}

#[tokio::test]
async fn a_messenger_kicked_for_flooding_is_not_announced() {
    let td = tempfile::tempdir().unwrap();
    let s = start_held(
        td.path(),
        MessagingPolicy {
            enabled: true,
            ..MessagingPolicy::default()
        },
        FloodLimits {
            spam_points: 100,
            spam_per: Duration::from_secs(5),
            ..FloodLimits::default()
        },
    )
    .await;
    let mut erin = legacy::Client::login_at(s.classic, &Login::account("erin", "erin", "pw"))
        .await
        .unwrap();
    erin.user_list().await.unwrap();
    let (mut alice, _) = classic(&s, "alice", MESSAGING | MESSENGER).await;
    // Refused, and each charged at Get User List's price, until a kick.
    for _ in 0..6 {
        alice
            .send(ClientHdr::UserGetList.as_u32(), &[])
            .await
            .unwrap();
    }
    loop {
        match alice.recv().await {
            Ok(_) => continue,
            Err(hxd_testclient::Error::Closed) => break,
            Err(e) => panic!("{e}"),
        }
    }
    erin.chat(b"after").await.unwrap();
    erin.recv_where(|f| f.ty == push::CHAT && heard(f, b"after"))
        .await
        .unwrap();
    assert!(!erin
        .rx
        .take_backlog()
        .iter()
        .any(|f| f.ty == push::CHAT && heard(f, b"spam_max")));
}
