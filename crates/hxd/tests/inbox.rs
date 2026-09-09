//! The private-message inbox, end to end: a real server with a real
//! SQLite store on a real file, driven by a legacy scripted client and a
//! WebSocket client at the same time.
//!
//! The scenarios that matter are the cross-wire ones — mail queued by one
//! era and read in the other — because that is what the design is for and
//! it is what unit tests on either side cannot show. See
//! docs/private-messages.md §11 M4.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::{Core, InboxPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_SELFINFO: u32 = 0x162;
const HDR_MSG: u32 = 0x68;
const REQ_LOGIN: u32 = 0x6b;
const REQ_MSG: u32 = 0x6c;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
}

/// Two accounts with passwords, so both have inboxes (a password-less
/// account is a shared door, and gets none).
async fn start(dir: &Path, policy: InboxPolicy) -> Server {
    start_with(dir, policy, &["bob", "alice"]).await
}

/// A server with no `[inbox]` at all — what a deployment that configures
/// no database gets, and the shape private messaging had before this
/// work existed.
async fn start_without_inbox(dir: &Path) -> Server {
    start_full(dir, InboxPolicy::default(), &["bob", "alice"], false).await
}

async fn start_with(dir: &Path, policy: InboxPolicy, who: &[&str]) -> Server {
    start_full(dir, policy, who, true).await
}

async fn start_full(dir: &Path, policy: InboxPolicy, who: &[&str], inbox: bool) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for who in who {
        std::fs::write(
            accounts.join(format!("{who}.toml")),
            "password = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
             send_msgs = true\nuse_any_name = true\n",
        )
        .unwrap();
    }

    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = Arc::new(if inbox {
        let store =
            Arc::new(SqliteStore::open(dir.join("messages.db"), Synchronous::Full).unwrap());
        Core::new().with_inbox(store, auth.clone(), policy)
    } else {
        Core::new()
    });

    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "inbox".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: hxd_session::Caps::empty(),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "inbox".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: if inbox {
                vec!["inbox".to_string()]
            } else {
                Vec::new()
            },
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        // The inbox suite runs without the identity subsystem: every
        // mailbox here is login-keyed, which is the shape a server that
        // never turns identity on has.
        identity: None,
        tunnel: None,
        enroll: None,
    };

    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (legacy, ng) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    Server { legacy, ng, core }
}

// --- A scripted 1.5 client -----------------------------------------------

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

struct Legacy {
    stream: TcpStream,
    trans: u32,
    uid: u16,
}

impl Legacy {
    async fn login(addr: SocketAddr, login: &str) -> Legacy {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut reply = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .unwrap();
        let mut c = Legacy {
            stream,
            trans: 0,
            uid: 0,
        };
        c.send(
            REQ_LOGIN,
            &[
                (tag::NAME, login.as_bytes().to_vec()),
                (tag::ICON, 1u16.to_be_bytes().to_vec()),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
                (tag::LOGIN, xor(login.as_bytes())),
                (tag::PASSWORD, xor(b"pw")),
            ],
        )
        .await;
        let f = c.recv_type(HDR_TASK).await;
        assert_eq!(f.flag, 0, "login must succeed");
        c.uid = f
            .chunks()
            .find(|ch| ch.tag == tag::UID)
            .map(|ch| ch.as_uint() as u16)
            .unwrap();
        c.recv_type(HDR_SELFINFO).await;
        c
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.trans
    }

    /// Send a private message and wait for the server's ack, so a test
    /// knows the message is stored rather than guessing with a sleep.
    async fn msg(&mut self, to: u16, text: &str) -> Frame {
        let trans = self
            .send(
                REQ_MSG,
                &[
                    (tag::UID, to.to_be_bytes().to_vec()),
                    (tag::BODY, text.as_bytes().to_vec()),
                ],
            )
            .await;
        self.reply_to(trans).await
    }

    /// The reply frame for one transaction, skipping the events that
    /// arrive alongside it.
    async fn reply_to(&mut self, trans: u32) -> Frame {
        for _ in 0..24 {
            let f = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("legacy: timed out")
                .expect("legacy: closed");
            if f.ty == HDR_TASK && f.trans == trans {
                return f;
            }
        }
        panic!("legacy: no reply to transaction {trans}");
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..24 {
            let f = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("legacy: timed out")
                .expect("legacy: closed");
            if f.ty == ty {
                return f;
            }
        }
        panic!("legacy: frame {ty:#x} never arrived");
    }

    async fn body(&mut self) -> String {
        self.private_message().await.0
    }

    /// A 104 as the client sees it: body, the UID it dispatches on, and
    /// the NAME it shows. GtkHx decides "private message" from the uid
    /// (`is_pm = !is_broadcast && pm.uid > 0`, `gtkhx/src/rcv.c`), so
    /// these three are the difference between a PM window and a line in
    /// the chat pane.
    async fn private_message(&mut self) -> (String, u16, String) {
        let f = self.recv_type(HDR_MSG).await;
        let chunk = |t: u16| {
            f.chunks()
                .find(|c| c.tag == t)
                .map(|c| c.data.to_vec())
                .unwrap_or_else(|| panic!("a private message carries {t}"))
        };
        (
            String::from_utf8_lossy(&chunk(tag::BODY)).into_owned(),
            u16::from_be_bytes(chunk(tag::UID).try_into().expect("a 2-byte uid")),
            String::from_utf8_lossy(&chunk(tag::NAME)).into_owned(),
        )
    }
}

// --- A scripted ng client ------------------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next_id: u64,
    queued: Vec<Value>,
}

impl Ng {
    /// A connected socket that has not logged in yet.
    async fn connect(addr: SocketAddr) -> Ng {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        Ng {
            ws,
            next_id: 1,
            queued: Vec::new(),
        }
    }

    async fn login(addr: SocketAddr, login: &str) -> (Ng, Value) {
        let mut c = Ng::connect(addr).await;
        let hello = c
            .request_ok("login", json!({ "login": login, "password": "pw" }))
            .await;
        (c, hello)
    }

    /// A session with no account behind it — `guest`, which the bootstrap
    /// creates password-less.
    async fn guest(addr: SocketAddr) -> Ng {
        let mut c = Ng::connect(addr).await;
        c.request_ok("login", json!({ "nick": "drifter" })).await;
        c
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let v = self.recv().await;
            if v.get("reply").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            self.queued.push(v);
        }
    }

    async fn request_ok(&mut self, method: &str, params: Value) -> Value {
        let v = self.request(method, params).await;
        assert!(v.get("ok").is_some(), "{method} should succeed, got: {v}");
        v["ok"].clone()
    }

    async fn recv(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng: timed out")
                .expect("ng: closed")
                .expect("ng: ws error");
            if let Message::Text(t) = msg {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    /// The next event of a kind, from the queue or the wire.
    async fn event(&mut self, ev: &str) -> Value {
        if let Some(i) = self.queued.iter().position(|v| v["ev"] == ev) {
            return self.queued.remove(i)["data"].clone();
        }
        for _ in 0..24 {
            let v = self.recv().await;
            if v["ev"] == ev {
                return v["data"].clone();
            }
            if v.get("seq").is_some() {
                self.queued.push(v);
            }
        }
        panic!("ng: no {ev} event arrived");
    }

    async fn msg_event(&mut self) -> Value {
        self.event("msg").await
    }

    async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

/// Poll for a condition instead of sleeping at it: a fixed wait is a race
/// that passes on this machine and fails on a loaded one.
async fn until(mut ready: impl FnMut() -> bool, what: &str) {
    for _ in 0..200 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

// -------------------------------------------------------------------------

/// The headline: a legacy client messages someone whose phone is asleep,
/// the grace window lapses so the session is gone entirely, and the
/// message is still there when they come back.
#[tokio::test]
async fn a_message_outlives_the_grace_window_and_crosses_the_wires() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(hello["inbox"]["unread"], 0, "a fresh inbox is empty");
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    bob.close().await;
    // The socket died; the session is detached, still on the roster, and
    // still addressable from a client that has no idea any of that is so.
    // Polled rather than slept: a fixed wait is a race that passes on
    // this machine and fails on a loaded one.
    until(|| srv.core.is_detached(bob_uid), "bob detaches").await;

    let mut alice = Legacy::login(srv.legacy, "alice").await;
    // The ack is the message being stored: the domain writes before it
    // acks, which is the whole point of the design.
    assert_eq!(alice.msg(bob_uid, "dinner at eight?").await.flag, 0);

    // The grace window lapses. The session is gone; the message is not.
    assert_eq!(srv.core.sweep_detached(Duration::ZERO), 1);
    assert!(srv.core.user(bob_uid).is_none());

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(
        hello["inbox"]["unread"], 1,
        "the badge is right before any of it arrives"
    );
    let m = bob.msg_event().await;
    assert_eq!(m["text"], "dinner at eight?");
    assert_eq!(m["queued"], true, "it waited");
    assert_eq!(m["from"]["login"], "alice");
    assert!(m["at"].as_u64().unwrap() > 0);

    // Reading it is what clears the badge, not receiving it.
    let id = m["id"].as_u64().unwrap();
    let left = bob.request_ok("msg_read", json!({ "up_to": id })).await;
    assert_eq!(left["unread"], 0);
    assert_eq!(left["total"], 1);
}

/// The other direction: an ng client addresses an account that holds no
/// session at all, and it is read on a twenty-five-year-old client.
#[tokio::test]
async fn ng_addresses_an_absent_account_and_a_legacy_client_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    // Alice has never logged in. There is no uid to name her by.
    let ok = bob
        .request_ok(
            "msg",
            json!({ "to_login": "ALICE", "text": "the keys are under the mat\nback tomorrow" }),
        )
        .await;
    assert_eq!(ok["queued"], true, "nobody was there to take it");
    assert!(ok.get("id").is_none(), "and the sender is told no more");

    // And the sender is gone by the time it is read — which is the case
    // the frame shape below has to answer.
    bob.close().await;
    until(|| srv.core.is_detached(bob_uid), "bob detaches").await;
    assert_eq!(srv.core.sweep_detached(Duration::ZERO), 1);

    let mut alice = Legacy::login(srv.legacy, "alice").await;
    let (body, uid, name) = alice.private_message().await;
    assert!(
        body.starts_with("[queued ") && body.ends_with("back tomorrow"),
        "a queued message says when it was sent: {body:?}"
    );
    assert!(body.contains(" UTC]"), "and in a zone it names: {body:?}");
    // One kind of line ending on this wire: the stamp's break and the
    // sender's are the same byte, and a bare `\n` would draw as a glyph.
    assert!(!body.contains('\n'), "no LF reaches a 1.x client: {body:?}");
    assert_eq!(
        body.matches('\r').count(),
        2,
        "the stamp's break and the body's: {body:?}"
    );
    // The sender has no session, so there is no uid of theirs to name.
    // A 104 with UID 0 is not a private message to a 1.x client — it
    // goes through the broadcast path and lands in the chat pane — so
    // the recipient's own uid stands in, and the NAME says who wrote it.
    assert_eq!(uid, alice.uid, "a queued message is still a PM");
    assert_eq!(name, "bob");
}

/// A message to someone who is right there is not dressed up as old mail,
/// and the sender is told the difference.
#[tokio::test]
async fn a_message_to_someone_present_is_not_marked_queued() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;

    let ok = alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "right now" }))
        .await;
    assert_eq!(ok["queued"], false);

    let m = bob.msg_event().await;
    assert_eq!(m["text"], "right now");
    assert_eq!(
        m["queued"], false,
        "a recipient watching the screen is not told their message is old news"
    );
    // It is still stored, so a dropped socket would not have lost it.
    let inbox = bob.request_ok("inbox", json!({})).await;
    assert_eq!(inbox["total"], 1);
    assert_eq!(inbox["unread"], 1);
    assert_eq!(inbox["messages"][0]["text"], "right now");
    assert_eq!(inbox["messages"][0]["from"]["login"], "alice");
}

/// Naming an account that does not exist, and one that takes no mail, must
/// look the same from outside.
#[tokio::test]
async fn a_bad_address_says_nothing_about_which_accounts_exist() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;

    let nobody = bob
        .request("msg", json!({ "to_login": "nobody", "text": "hi" }))
        .await;
    // `guest` exists, and has no password, so it has no inbox.
    let guest = bob
        .request("msg", json!({ "to_login": "guest", "text": "hi" }))
        .await;
    assert_eq!(nobody["error"], guest["error"], "one answer for both");
    assert_eq!(nobody["error"]["code"], "no_such_user");

    // And naming both addresses, or neither, is refused rather than
    // guessed at.
    let both = bob
        .request("msg", json!({ "to": 1, "to_login": "alice", "text": "hi" }))
        .await;
    assert_eq!(both["error"]["code"], "bad_request");
    let neither = bob.request("msg", json!({ "text": "hi" })).await;
    assert_eq!(neither["error"]["code"], "bad_request");

    // An empty message is refused as it is on the legacy wire: it would
    // take a queue slot, notify a phone, and render as a bare
    // `[queued …]` stamp with nothing under it.
    let empty = bob
        .request("msg", json!({ "to_login": "alice", "text": "" }))
        .await;
    assert_eq!(empty["error"]["code"], "bad_request", "{empty}");
    assert_eq!(
        srv.core
            .inbox_counts_of(&hxd_core::inbox::Mailbox::login("alice"))
            .total,
        0,
        "and nothing was stored on the way to the refusal"
    );
}

/// A flush hands over one batch and says what is left, rather than opening
/// forty windows on a period client.
#[tokio::test]
async fn a_capped_flush_says_how_much_is_still_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(
        dir.path(),
        InboxPolicy {
            deliver_at_flush: 2,
            ..InboxPolicy::default()
        },
    )
    .await;

    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    for i in 0..5 {
        alice
            .request_ok("msg", json!({ "to_login": "bob", "text": format!("m{i}") }))
            .await;
    }

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(hello["inbox"]["unread"], 5);
    assert_eq!(bob.msg_event().await["text"], "m0");
    assert_eq!(bob.msg_event().await["text"], "m1");
    // The rest is still there and says so, and `inbox` can fetch it
    // without waiting for another login.
    let notice = bob.event("notice").await;
    assert!(
        notice["text"].as_str().unwrap().starts_with("3 more"),
        "got {notice}"
    );
    let inbox = bob.request_ok("inbox", json!({ "limit": 10 })).await;
    assert_eq!(inbox["total"], 5);
    assert_eq!(
        inbox["messages"][0]["text"], "m4",
        "newest first, whether or not it has been handed over"
    );
}

/// Paging backwards, and read state that cannot reach another mailbox.
#[tokio::test]
async fn the_inbox_pages_backwards_and_read_state_is_scoped_to_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    for i in 0..5 {
        alice
            .request_ok("msg", json!({ "to_login": "bob", "text": format!("m{i}") }))
            .await;
    }
    // One for alice too, so "someone else's id" is a real id.
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    bob.request_ok("msg", json!({ "to_login": "alice", "text": "for alice" }))
        .await;
    let hers = alice.request_ok("inbox", json!({})).await["messages"][0]["id"]
        .as_u64()
        .unwrap();

    // Newest first, `limit` bounded, `before` walking backwards.
    let page = bob.request_ok("inbox", json!({ "limit": 2 })).await;
    assert_eq!(page["total"], 5);
    let texts: Vec<_> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(texts, ["m4", "m3"]);
    let oldest_seen = page["messages"][1]["id"].as_u64().unwrap();
    let next = bob
        .request_ok("inbox", json!({ "limit": 2, "before": oldest_seen }))
        .await;
    let texts: Vec<_> = next["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(texts, ["m2", "m1"], "the next page continues backwards");

    // `up_to` is a cursor in the caller's own mailbox, so an id the
    // caller never received cannot reach the mailbox it belongs to.
    let left = bob.request_ok("msg_read", json!({ "up_to": hers })).await;
    assert_eq!(left["unread"], 0, "it moves the caller's own cursor");
    assert_eq!(
        alice.request_ok("inbox", json!({})).await["unread"],
        1,
        "and marks nothing of the mailbox the id belongs to"
    );
}

/// A live private message on the legacy wire is refused when the sender
/// is blocked — the block is not an inbox feature.
#[tokio::test]
async fn a_blocked_sender_is_refused_on_the_legacy_wire_too() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    bob.request_ok("block", json!({ "login": "alice" })).await;

    let mut alice = Legacy::login(srv.legacy, "alice").await;
    let reply = alice.msg(bob_uid, "let me in").await;
    assert_ne!(reply.flag, 0, "a blocked sender is told, on this wire too");
    // A round-trip first: replies are in order, so anything the server
    // sent before this one is in hand by the time it arrives. Without
    // it, "nothing arrived" is a statement about a queue nothing has
    // been read into.
    bob.request_ok("ping", json!({})).await;
    assert!(
        bob.queued.iter().all(|v| v["ev"] != "msg"),
        "and nothing reached the recipient"
    );
}

/// Blocking, over the wire and across the two addressing modes.
#[tokio::test]
async fn a_block_holds_against_both_ways_of_naming_someone() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;

    bob.request_ok("block", json!({ "login": "alice" })).await;
    assert_eq!(
        bob.request_ok("blocks", json!({})).await["blocked"][0]["login"],
        "alice"
    );

    let by_login = alice
        .request("msg", json!({ "to_login": "bob", "text": "hi" }))
        .await;
    assert_eq!(by_login["error"]["code"], "blocked");
    // And clicking the name in the user list gets no further.
    let by_uid = alice
        .request("msg", json!({ "to": bob_uid, "text": "hi" }))
        .await;
    assert_eq!(by_uid["error"]["code"], "blocked");

    bob.request_ok("unblock", json!({ "login": "alice" })).await;
    let after = alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "hi" }))
        .await;
    assert_eq!(after["queued"], false);
}

/// A retry after a lost reply must not arrive twice.
#[tokio::test]
async fn the_same_guid_sent_twice_is_one_message() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;

    let guid = "5f5e1000-1234-4abc-89ab-000000000001";
    let first = alice
        .request_ok(
            "msg",
            json!({ "to_login": "bob", "text": "did that send?", "guid": guid }),
        )
        .await;
    assert_eq!(first["queued"], true);

    // The client never saw the reply and tries again — in the other
    // spelling, which is still the same id.
    let retry = alice
        .request_ok(
            "msg",
            json!({
                "to_login": "bob",
                "text": "did that send?",
                "guid": "5F5E1000-1234-4ABC-89AB-000000000001",
            }),
        )
        .await;
    assert_eq!(retry, first, "the same answer, not a second message");

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(hello["inbox"]["unread"], 1, "one message, not two");
    assert_eq!(bob.msg_event().await["text"], "did that send?");

    // Anything that is not a uuid is refused rather than indexed.
    let junk = alice
        .request(
            "msg",
            json!({ "to_login": "bob", "text": "x", "guid": "hello" }),
        )
        .await;
    assert_eq!(junk["error"]["code"], "bad_request");
}

/// Blocking by uid, which is the only way to name a sender that has no
/// account login of its own.
#[tokio::test]
async fn a_block_can_name_a_roster_row_rather_than_a_login() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, hello) = Ng::login(srv.ng, "alice").await;
    let alice_uid = hello["self"]["uid"].as_u64().unwrap();

    bob.request_ok("block", json!({ "uid": alice_uid })).await;
    let refused = alice
        .request("msg", json!({ "to_login": "bob", "text": "hi" }))
        .await;
    assert_eq!(refused["error"]["code"], "blocked");
    assert_eq!(
        bob.request_ok("blocks", json!({})).await["blocked"][0]["login"],
        "alice",
        "and it is listed under the account it resolved to"
    );

    // Naming both, or neither, is refused rather than guessed at.
    for params in [json!({ "uid": alice_uid, "login": "alice" }), json!({})] {
        let bad = bob.request("block", params).await;
        assert_eq!(bad["error"]["code"], "bad_request");
    }
}

/// The store is a file, and the point of a file is that it outlives the
/// process. Nothing here restarts the server, but the mail is committed
/// where a restart would find it.
#[tokio::test]
async fn queued_mail_is_on_disk_before_the_sender_is_acked() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "on disk" }))
        .await;

    // A second handle on the same file, as a restarted server would open
    // it: the ack the client already has is backed by a committed row.
    let reopened = SqliteStore::open(dir.path().join("messages.db"), Synchronous::Normal).unwrap();
    use hxd_core::MessageStore;
    let pending = reopened
        .pending(&hxd_core::inbox::Mailbox::login("bob"), 10)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].body, "on disk");
    assert_eq!(
        pending[0].sender.as_ref().map(|s| s.login.as_str()),
        Some("alice")
    );
}

/// A guest — no account, so nothing to block — can reach whoever is on
/// the roster and cannot put a single message in anyone's queue.
#[tokio::test]
async fn a_guest_cannot_fill_a_mailbox_and_cannot_be_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    // Bob is offline. A guest tries the whole cap and more.
    let mut guest = Ng::guest(srv.ng).await;
    for i in 0..12 {
        let v = guest
            .request(
                "msg",
                json!({ "to_login": "bob", "text": format!("flood {i}") }),
            )
            .await;
        assert_eq!(
            v["error"]["code"], "no_such_user",
            "a guest may not queue mail: {v}"
        );
    }
    // An account can still reach him, which is the whole point.
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let ok = alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "dinner?" }))
        .await;
    assert_eq!(ok["queued"], true);

    // And a guest reaches a session that is actually there.
    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    let bob_uid = hello["self"]["uid"].as_u64().unwrap();
    let _ = bob.msg_event().await; // alice's, from the flush
    let ok = guest
        .request_ok("msg", json!({ "to": bob_uid, "text": "hello there" }))
        .await;
    assert_eq!(ok["queued"], false, "live delivery still works");
    let m = bob.msg_event().await;
    assert_eq!(m["text"], "hello there");
    assert!(m.get("id").is_none(), "nothing durable was written");
    assert!(
        m["from"].get("login").is_none(),
        "and no reply address, because there is nobody to reply to"
    );
    // The mailbox holds exactly alice's message.
    let inbox = bob.request_ok("inbox", json!({})).await;
    assert_eq!(inbox["total"], 1, "{inbox}");
}

/// A link is claimed at *any* login, not only at the ones that prove an
/// identity. Someone who linked once through ng and thereafter uses
/// GtkHx has a fingerprint-keyed mailbox; the rows the two claim windows
/// leave on the bare login would otherwise sit there unread forever,
/// because nothing on the plain port ever looks at that mailbox again.
#[tokio::test]
async fn a_password_login_claims_the_accounts_mail_too() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    // Mail arrives while the account is keyed by its bare login.
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    alice
        .request_ok(
            "msg",
            json!({ "to_login": "bob", "text": "before the link" }),
        )
        .await;

    // The link is made somewhere else — another device, or the operator
    // editing the file, which is what this is.
    let fingerprint = hl_identity::Fingerprint([7u8; 32]).to_string();
    let path = dir.path().join("accounts/bob.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!("{text}\n[identity]\nfingerprint = \"{fingerprint}\"\n"),
    )
    .unwrap();

    // A plain password login on the legacy port: no transport identity
    // anywhere in it, and the mail still arrives. The mailbox is checked
    // first, so a login that does not claim fails here rather than in the
    // receive helper's timeout for a frame that is never coming.
    let mut legacy = Legacy::login(srv.legacy, "bob").await;
    let identified = hxd_core::inbox::Mailbox::identified("bob".to_string(), [7u8; 32]);
    until(
        || srv.core.inbox_counts_of(&identified).total == 1,
        "the login to claim the account's mail onto its fingerprint",
    )
    .await;
    assert_eq!(
        srv.core
            .inbox_counts_of(&hxd_core::inbox::Mailbox::login("bob"))
            .total,
        0,
        "nothing is left on the bare login"
    );
    let body = legacy.body().await;
    assert!(body.ends_with("before the link"), "{body}");
}

/// The legacy wire has no `msg_read`; its flush is the read. Without
/// that, a GtkHx user's badge is wrong forever on every other client.
#[tokio::test]
async fn a_legacy_flush_counts_as_reading() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    for i in 0..3 {
        alice
            .request_ok(
                "msg",
                json!({ "to_login": "bob", "text": format!("note {i}") }),
            )
            .await;
    }

    // Bob reads them on a twenty-five-year-old client.
    let mut legacy = Legacy::login(srv.legacy, "bob").await;
    for i in 0..3 {
        let body = legacy.body().await;
        assert!(body.ends_with(&format!("note {i}")), "{body}");
    }

    // The `Read` stamp is written after the frames go out, and the ng
    // login below takes no lock against it: poll for it rather than
    // racing a `synchronous = FULL` fsync.
    let mailbox = hxd_core::inbox::Mailbox::login("bob");
    until(
        || srv.core.inbox_counts_of(&mailbox).unread == 0,
        "the legacy flush to be stamped read",
    )
    .await;

    // His phone logs in afterwards and finds nothing owing.
    let (_bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(
        hello["inbox"]["unread"], 0,
        "delivery is the read on a wire that cannot say otherwise"
    );
    assert_eq!(hello["inbox"]["total"], 3, "the mail is still there");
}

/// The other half of the same rule: a legacy client that is *already
/// online* when the message arrives has read it too. The flag belongs to
/// the session's wire, not to the login flush, or a 1.5 user who never
/// logs out accumulates unread mail they are looking at.
#[tokio::test]
async fn a_live_delivery_to_a_legacy_client_also_counts_as_reading() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    // Bob is sitting in GtkHx with the window open.
    let mut legacy = Legacy::login(srv.legacy, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let ok = alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "right now" }))
        .await;
    assert_eq!(ok["queued"], false, "he was there to take it");
    assert!(legacy.body().await.ends_with("right now"));

    // His phone finds nothing owing.
    let (_phone, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(
        hello["inbox"]["unread"], 0,
        "delivery is the read on a wire that cannot say otherwise, \
         whether the message waited or not"
    );
    assert_eq!(hello["inbox"]["total"], 1);
}

/// Two ng sessions on one account, one of them asleep. The message must
/// reach the one holding a socket, not the one with the lower uid.
#[tokio::test]
async fn a_message_reaches_the_attached_session_of_two() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (phone, hello) = Ng::login(srv.ng, "bob").await;
    let phone_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    let (mut laptop, hello) = Ng::login(srv.ng, "bob").await;
    let laptop_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    assert!(phone_uid < laptop_uid, "the sleeper has the lower uid");
    phone.close().await;
    until(|| srv.core.is_detached(phone_uid), "the phone detaches").await;

    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let ok = alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "you up?" }))
        .await;
    assert_eq!(ok["queued"], false, "somebody was there to take it");
    let m = laptop.msg_event().await;
    assert_eq!(m["text"], "you up?");
    assert_eq!(m["queued"], false, "it did not wait");
}

/// The by-login live path stores nothing, so it has to reach a session
/// that can actually take the message — there is no second copy.
#[tokio::test]
async fn a_message_by_uid_goes_to_the_device_it_named() {
    // Naming a uid names a *device*. An account with a phone and a
    // laptop both live, and a legacy user clicking the laptop in the
    // user list: the durable path resolved the recipient by mailbox and
    // handed it to the lowest attached session, so it arrived on the
    // phone. §15's multi-device question, answered.
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut phone, hello) = Ng::login(srv.ng, "bob").await;
    let phone_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    let (mut laptop, hello) = Ng::login(srv.ng, "bob").await;
    let laptop_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    assert!(phone_uid < laptop_uid);

    let mut alice = Legacy::login(srv.legacy, "alice").await;
    assert_eq!(alice.msg(laptop_uid, "on the big screen").await.flag, 0);
    let m = laptop.msg_event().await;
    assert_eq!(m["text"], "on the big screen");
    assert_eq!(m["queued"], false);

    // And the phone hears nothing: one message, one device.
    let ok = alice.msg(phone_uid, "and on the small one").await;
    assert_eq!(ok.flag, 0);
    let m = phone.msg_event().await;
    assert_eq!(m["text"], "and on the small one");
    // In-order round-trip, so "nothing else arrived" is about what the
    // server sent rather than about what this client has read.
    phone.request_ok("ping", json!({})).await;
    assert!(
        phone.queued.iter().all(|v| v["ev"] != "msg"),
        "the phone was not sent the laptop's message"
    );
}

#[tokio::test]
async fn a_guest_reaches_the_attached_session_of_two() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (phone, hello) = Ng::login(srv.ng, "bob").await;
    let phone_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    let (mut laptop, hello) = Ng::login(srv.ng, "bob").await;
    assert!(
        phone_uid < hello["self"]["uid"].as_u64().unwrap() as u16,
        "the sleeper has the lower uid"
    );
    phone.close().await;
    until(|| srv.core.is_detached(phone_uid), "the phone detaches").await;

    // A guest queues nothing, so aiming this at the detached phone would
    // put it in an outbox buffer that dies with the grace window.
    let mut guest = Ng::guest(srv.ng).await;
    let ok = guest
        .request_ok("msg", json!({ "to_login": "bob", "text": "knock knock" }))
        .await;
    assert_eq!(ok["queued"], false);
    let m = laptop.msg_event().await;
    assert_eq!(m["text"], "knock knock");
    assert!(m.get("id").is_none(), "a guest stores nothing");
}

/// MS6 end to end on the path that stores nothing: a guest sender, both
/// of the recipient's sessions attached, and the one that was *named* is
/// the one that hears it. The unit test covers the resolution; this
/// covers the wire it arrives on.
#[tokio::test]
async fn a_guest_reaches_the_session_it_named_of_two_attached() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (mut phone, hello) = Ng::login(srv.ng, "bob").await;
    let phone_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    let (mut laptop, hello) = Ng::login(srv.ng, "bob").await;
    let laptop_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    assert!(phone_uid < laptop_uid, "the named one has the higher uid");

    // A guest has no mailbox, so nothing it sends is stored — this is
    // the resolution that used to ignore the uid the sender clicked and
    // hand the message to the lowest attached session instead.
    let mut guest = Ng::guest(srv.ng).await;
    let ok = guest
        .request_ok(
            "msg",
            json!({ "to": laptop_uid, "text": "on the big screen" }),
        )
        .await;
    assert_eq!(ok["queued"], false);
    // Barrier on the session that must not receive it first: with the old
    // lowest-uid bug this request collects the stray message and the named
    // assertion fails, rather than timing out waiting on the laptop.
    phone.request_ok("ping", json!({})).await;
    assert!(
        phone.queued.iter().all(|v| v["ev"] != "msg"),
        "the phone was not sent the laptop's message"
    );
    let m = laptop.msg_event().await;
    assert_eq!(m["text"], "on the big screen");
    assert!(m.get("id").is_none(), "a guest stores nothing");
}

/// A resume that cannot replay tells the client to sync. The mail that
/// arrived in the gap must survive that — flushing it into events the
/// client is then told to skip is the one way to lose a stored message.
#[tokio::test]
async fn mail_that_arrives_during_an_unreplayable_gap_survives_the_resync() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;

    let (bob, hello) = Ng::login(srv.ng, "bob").await;
    let (session, token) = (
        hello["session"].as_str().unwrap().to_owned(),
        hello["token"].as_str().unwrap().to_owned(),
    );
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    bob.close().await;
    until(|| srv.core.is_detached(bob_uid), "bob detaches").await;

    let (mut alice, ahello) = Ng::login(srv.ng, "alice").await;
    let alice_uid = ahello["self"]["uid"].as_u64().unwrap() as u16;
    alice
        .request_ok("msg", json!({ "to_login": "bob", "text": "in the gap" }))
        .await;

    // Break the replay buffer for real: past its cap the outbox is
    // marked broken, which is the only thing that makes `resume` answer
    // `resync_required`. Without this the test resumed cleanly and never
    // touched the path it exists for.
    for i in 0..(hxd_core::roster::OUTBOX_BUFFER_CAP + 10) {
        srv.core
            .chat_public(alice_uid, format!("line {i}"), 0, None)
            .unwrap();
    }

    let mut back = Ng::connect(srv.ng).await;
    let v = back
        .request(
            "resume",
            json!({ "session": session, "token": token, "last_seq": 0 }),
        )
        .await;
    assert_eq!(v["error"]["code"], "resync_required", "{v}");

    // No mail arrives with that refusal: the seq `sync` is about to
    // report is past whatever a flush here would emit, so those events
    // would be marked delivered and then skipped — the one way a stored
    // message is lost outright. The `ping` is what makes that assertion
    // about the server: its reply cannot overtake anything sent before
    // it, so if a flush had happened it would be in `queued` now.
    back.request_ok("ping", json!({})).await;
    assert!(
        back.queued.iter().all(|v| v["ev"] != "msg"),
        "nothing is flushed into a gap the client is about to skip"
    );

    let sync = back.request_ok("sync", json!({})).await;
    let at = sync["seq"].as_u64().unwrap();
    // Whatever the client was handed before that reply is accounted for
    // by the number in it: `sync` drains the session's events and
    // reports the highest seq it wrote, so a client that continues from
    // this number has not been told it is past anything it will see
    // later (§6).
    for v in &back.queued {
        if let Some(seq) = v["seq"].as_u64() {
            assert!(
                seq <= at,
                "an event before the sync reply is past the seq it reports: {v}"
            );
        }
    }
    // The mail follows the reply, as ordinary events with later seqs.
    let m = loop {
        let v = back.recv().await;
        assert!(
            v["seq"].as_u64().is_some_and(|seq| seq > at),
            "every event after the sync reply must be past its seq: {v}"
        );
        if v["ev"] == "msg" {
            break v;
        }
    };
    assert_eq!(m["data"]["text"], "in the gap");
    assert!(
        m["seq"].as_u64().unwrap() > at,
        "the message is past the seq the client was told it was at: {m}"
    );

    // And a second sync does not hand it over again — nor report a seq
    // behind the message it already sent.
    let sync = back.request_ok("sync", json!({})).await;
    assert!(sync["seq"].as_u64().unwrap() >= m["seq"].as_u64().unwrap());
    // The `inbox` request is itself the ordered round-trip; nothing more
    // is needed to make this assertion about the server.
    let inbox = back.request_ok("inbox", json!({})).await;
    assert_eq!(inbox["total"], 1);
    assert_eq!(inbox["messages"][0]["text"], "in the gap");
    assert!(
        back.queued.iter().all(|v| v["ev"] != "msg"),
        "a delivered message is delivered once"
    );
}

/// The same message sent twice from one client is one message, even when
/// both sends are in flight together — which is the case a guid is for.
#[tokio::test]
async fn a_guid_retried_in_parallel_is_still_one_message() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path(), InboxPolicy::default()).await;
    let guid = "8f14e45f-ceea-467a-9b4e-000000000001";

    // Two connections, one account, the same guid: a client that
    // reconnected and retried without knowing the first send landed.
    let (mut a, _) = Ng::login(srv.ng, "alice").await;
    let (mut b, _) = Ng::login(srv.ng, "alice").await;
    let body = json!({ "to_login": "bob", "text": "only once", "guid": guid });
    let (ra, rb) = tokio::join!(
        a.request_ok("msg", body.clone()),
        b.request_ok("msg", body.clone()),
    );
    let _ = (ra, rb);

    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    assert_eq!(hello["inbox"]["total"], 1, "one row, not two");
    let m = bob.msg_event().await;
    assert_eq!(m["text"], "only once");
    let inbox = bob.request_ok("inbox", json!({})).await;
    assert_eq!(inbox["total"], 1);
}

/// A store failure is the server's, and must not be reported to a sender
/// as "no such user" — a lie they would act on.
#[tokio::test]
async fn a_server_with_no_store_says_so_and_still_carries_a_live_message() {
    // No `[inbox]`: private messaging is exactly what it was before the
    // store existed, and the login reply says so rather than offering a
    // badge nothing can fill.
    let dir = tempfile::tempdir().unwrap();
    let srv = start_without_inbox(dir.path()).await;
    let (mut bob, hello) = Ng::login(srv.ng, "bob").await;
    assert!(hello.get("inbox").is_none(), "no store, no badge: {hello}");
    assert!(
        !hello["caps"]
            .as_array()
            .map(|c| c.contains(&json!("inbox")))
            .unwrap_or(false),
        "and the capability is not offered: {hello}"
    );

    let (mut alice, ahello) = Ng::login(srv.ng, "alice").await;
    let alice_uid = ahello["self"]["uid"].as_u64().unwrap();
    let bob_uid = hello["self"]["uid"].as_u64().unwrap();
    // By uid: addressing an account by login is a directory lookup, and
    // the directory arrives with the store.
    let ok = alice
        .request_ok("msg", json!({ "to": bob_uid, "text": "live only" }))
        .await;
    assert_eq!(ok["queued"], false);
    let by_login = alice
        .request("msg", json!({ "to_login": "bob", "text": "no" }))
        .await;
    assert_eq!(
        by_login["error"]["code"], "no_such_user",
        "no store, no way to address an account that isn't on the roster"
    );
    let m = bob.msg_event().await;
    assert_eq!(m["text"], "live only");
    assert!(m.get("id").is_none(), "nothing was stored to mark read");

    // And the requests that need a store say which one is missing.
    for (req, params) in [
        ("inbox", json!({})),
        ("blocks", json!({})),
        ("msg_read", json!({ "up_to": 1 })),
        ("block", json!({ "uid": alice_uid })),
    ] {
        let v = bob.request(req, params).await;
        assert_eq!(v["error"]["code"], "no_inbox", "{req}: {v}");
    }
}

#[tokio::test]
async fn an_account_with_no_inbox_of_its_own_hears_no_inbox() {
    let dir = tempfile::tempdir().unwrap();
    // `kiosk` has no password, so no inbox — but it can still send.
    let srv = start_with(dir.path(), InboxPolicy::default(), &["bob", "alice"]).await;
    std::fs::write(
        dir.path().join("accounts/kiosk.toml"),
        "[access]\nread_chat = true\nsend_chat = true\nsend_msgs = true\nuse_any_name = true\n",
    )
    .unwrap();

    let mut c = Ng::connect(srv.ng).await;
    let hello = c
        .request_ok("login", json!({ "login": "kiosk", "password": "" }))
        .await;
    assert!(
        hello.get("inbox").is_some(),
        "the server has an inbox even if this account does not"
    );
    for (req, params) in [
        ("inbox", json!({})),
        ("blocks", json!({})),
        ("msg_read", json!({ "up_to": 1 })),
        ("block", json!({ "login": "bob" })),
    ] {
        let v = c.request(req, params).await;
        assert_eq!(
            v["error"]["code"], "no_inbox",
            "{req} should say whose inbox is missing: {v}"
        );
    }
}
