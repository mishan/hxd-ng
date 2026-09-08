//! Hotline-ng end-to-end tests: a WebSocket client and a legacy scripted
//! client sharing one server — one roster, one chat, two wire eras.
//! Covers the frontend and the cross-frontend scenarios from
//! docs/hotline-ng.md §10.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hotline_proto::messages::tag;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_USER_CHANGE: u32 = 0x12d;
const HDR_USER_PART: u32 = 0x12e;
const HDR_SELFINFO: u32 = 0x162;
const HDR_CHAT: u32 = 0x6a;
const REQ_LOGIN: u32 = 0x6b;
const REQ_CHAT: u32 = 0x69;
const REQ_MSG: u32 = 0x6c;
const HDR_MSG: u32 = 0x68;

async fn start_server(dir: &Path) -> (SocketAddr, SocketAddr, NgCtx) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("bob.toml"),
        "name = \"Bob\"\npassword = \"s3cret\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\nuse_any_name = true\n",
    )
    .unwrap();
    let core = Arc::new(Core::new());
    let auth: Arc<dyn hxd_core::AuthBackend> = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "xover".into(),
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
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "xover".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
    };
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (legacy_addr, ng_addr) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx.clone()));
    (legacy_addr, ng_addr, ng_ctx)
}

// --- Minimal legacy scripted client (as in the phase1/2 suites) ---------

struct Legacy {
    stream: TcpStream,
    trans: u32,
}

impl Legacy {
    async fn login(addr: SocketAddr, nick: &str) -> Legacy {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut reply = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .unwrap();
        let mut c = Legacy { stream, trans: 0 };
        c.send(
            REQ_LOGIN,
            &[
                (tag::NAME, nick.as_bytes().to_vec()),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
        c.recv_type(HDR_TASK).await;
        c.recv_type(HDR_SELFINFO).await;
        c
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.trans
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..16 {
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
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

fn chunk_u16(f: &Frame, want: u16) -> Option<u16> {
    f.chunks()
        .find(|c| c.tag == want)
        .map(|c| c.as_uint() as u16)
}

// --- Minimal ng WebSocket client -----------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next_id: u64,
    last_seq: u64,
    queued_events: Vec<Value>,
}

impl Ng {
    async fn connect(addr: SocketAddr) -> Ng {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        Ng {
            ws,
            next_id: 1,
            last_seq: 0,
            queued_events: Vec::new(),
        }
    }

    /// Send a request and wait for its reply, queueing any events that
    /// arrive in between. Returns the raw reply object.
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
            let v = self.recv_json().await;
            if v.get("reply").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            self.note_event(v);
        }
    }

    async fn request_ok(&mut self, method: &str, params: Value) -> Value {
        let v = self.request(method, params).await;
        assert!(v.get("ok").is_some(), "{method} should succeed, got: {v}");
        v["ok"].clone()
    }

    async fn recv_json(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng: timed out")
                .expect("ng: closed")
                .expect("ng: ws error");
            match msg {
                Message::Text(t) => return serde_json::from_str(&t).unwrap(),
                _ => continue,
            }
        }
    }

    fn note_event(&mut self, v: Value) {
        if let Some(seq) = v.get("seq").and_then(Value::as_u64) {
            self.last_seq = seq;
            self.queued_events.push(v);
        }
    }

    /// Wait for an event of a given type (consuming queued ones first).
    async fn event(&mut self, ev: &str) -> Value {
        self.event_matching(ev, |_| true).await
    }

    /// Wait for an event of a given type whose data matches — needed
    /// because a chat sender receives its own echo, which would otherwise
    /// shadow the event under test.
    async fn event_matching(&mut self, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(i) = self
            .queued_events
            .iter()
            .position(|v| v["ev"] == ev && pred(&v["data"]))
        {
            return self.queued_events.remove(i);
        }
        for _ in 0..16 {
            let v = self.recv_json().await;
            if v.get("seq").is_some() {
                self.note_event(v.clone());
                if v["ev"] == ev && pred(&v["data"]) {
                    self.queued_events.retain(|q| q["seq"] != v["seq"]);
                    return v;
                }
            }
        }
        panic!("ng: matching event {ev} never arrived");
    }

    async fn login(addr: SocketAddr, login: &str, password: &str, nick: &str) -> (Ng, Value) {
        let mut c = Ng::connect(addr).await;
        let hello = c
            .request_ok(
                "login",
                json!({ "login": login, "password": password, "nick": nick }),
            )
            .await;
        c.last_seq = hello["seq"].as_u64().unwrap();
        (c, hello)
    }
}

// -------------------------------------------------------------------------

#[tokio::test]
async fn one_roster_two_wire_eras() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut alice = Legacy::login(legacy_addr, "alice").await;
    let (mut app, hello) = Ng::login(ng_addr, "bob", "s3cret", "MobileBob").await;

    // The ng hello: roster carries the legacy user; detach granted.
    assert_eq!(hello["server"]["name"], "xover");
    assert!(hello["detach"]["grace"].as_u64().unwrap() > 0);
    let users = hello["users"].as_array().unwrap();
    assert!(users.iter().any(|u| u["nick"] == "alice"));
    assert!(users.iter().any(|u| u["nick"] == "MobileBob"));

    // The legacy side sees the ng join, Mac Roman wire form.
    let join = alice.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk(&join, tag::NAME).unwrap(), b"MobileBob".to_vec());

    // ng → legacy: the legacy client receives the server-formatted line.
    app.request_ok("chat", json!({ "text": "hi from the future" }))
        .await;
    let line = alice.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&line, tag::BODY).unwrap(),
        b"\r    MobileBob:  hi from the future".to_vec()
    );

    // legacy → ng: the ng client receives the semantic event, unformatted.
    alice
        .send(REQ_CHAT, &[(tag::BODY, b"greetings from 1997".to_vec())])
        .await;
    let ev = app
        .event_matching("chat", |d| d["from"]["nick"] == "alice")
        .await;
    assert_eq!(ev["data"]["from"]["nick"], "alice");
    assert_eq!(ev["data"]["text"], "greetings from 1997");
    assert_eq!(ev["data"]["style"], "normal");
    alice.recv_type(HDR_CHAT).await; // her own echo

    // /me crosses too.
    app.request_ok("chat", json!({ "text": "waves", "style": "action" }))
        .await;
    let line = alice.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&line, tag::BODY).unwrap(),
        b"\r *** MobileBob waves".to_vec()
    );
}

#[tokio::test]
async fn detach_shows_away_to_legacy_and_resume_replays() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut alice = Legacy::login(legacy_addr, "alice").await;
    let (app, hello) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let (session, token) = (
        hello["session"].as_str().unwrap().to_string(),
        hello["token"].as_str().unwrap().to_string(),
    );
    let bob_uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    alice.recv_type(HDR_USER_CHANGE).await; // the join

    // Drop the socket without logout: legacy sees the away bit (color 1).
    drop(app);
    let away = alice.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk_u16(&away, tag::UID), Some(bob_uid));
    assert_eq!(chunk_u16(&away, tag::COLOUR), Some(1));

    // Chat happens while the app is away.
    alice
        .send(REQ_CHAT, &[(tag::BODY, b"anyone home?".to_vec())])
        .await;
    alice.recv_type(HDR_CHAT).await; // own echo

    // Resume: replay carries the missed traffic; legacy sees active again.
    let mut app = Ng::connect(ng_addr).await;
    let ok = app
        .request_ok(
            "resume",
            json!({ "session": session, "token": token, "last_seq": 0 }),
        )
        .await;
    assert!(ok["replay"].as_u64().unwrap() >= 1);
    let ev = app.event("chat").await;
    assert_eq!(ev["data"]["text"], "anyone home?");
    let active = alice.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk_u16(&active, tag::COLOUR), Some(0));

    // And the resumed session chats normally.
    app.request_ok("chat", json!({ "text": "back!" })).await;
    let line = alice.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&line, tag::BODY).unwrap(),
        b"\r          Bob:  back!".to_vec()
    );
}

#[tokio::test]
async fn guest_gets_no_detach_and_parts_on_drop() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut alice = Legacy::login(legacy_addr, "alice").await;
    let (app, hello) = Ng::login(ng_addr, "", "", "driveby").await;
    assert!(hello["detach"].is_null(), "guests must not detach");
    let uid = hello["self"]["uid"].as_u64().unwrap() as u16;
    alice.recv_type(HDR_USER_CHANGE).await;

    drop(app);
    let part = alice.recv_type(HDR_USER_PART).await;
    assert_eq!(chunk_u16(&part, tag::UID), Some(uid));
}

#[tokio::test]
async fn bad_token_and_stale_gap_paths() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let (mut app, hello) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let session = hello["session"].as_str().unwrap().to_string();
    let token = hello["token"].as_str().unwrap().to_string();

    // A second ng user chats so the first accumulates live-delivered seqs.
    let (mut other, _) = Ng::login(ng_addr, "", "", "guest2").await;
    other.request_ok("chat", json!({ "text": "one" })).await;
    app.event("chat").await;
    drop(app);

    // Wrong token: session_expired.
    let mut bad = Ng::connect(ng_addr).await;
    let v = bad
        .request(
            "resume",
            json!({ "session": session, "token": "deadbeef", "last_seq": 0 }),
        )
        .await;
    assert_eq!(v["error"]["code"], "session_expired");

    // Right token, but last_seq 0 predates the buffer (the chat was
    // delivered live): resync_required, then sync recovers on the same
    // connection.
    let mut app = Ng::connect(ng_addr).await;
    let v = app
        .request(
            "resume",
            json!({ "session": session, "token": token, "last_seq": 0 }),
        )
        .await;
    assert_eq!(v["error"]["code"], "resync_required");
    let ok = app.request_ok("sync", json!({})).await;
    assert!(ok["users"].as_array().unwrap().len() >= 2);
    app.request_ok("chat", json!({ "text": "recovered" })).await;
    let ev = other
        .event_matching("chat", |d| d["text"] == "recovered")
        .await;
    assert_eq!(ev["data"]["from"]["nick"], "Bob");
}

#[tokio::test]
async fn private_messages_cross_both_wire_eras() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut alice = Legacy::login(legacy_addr, "alice").await;
    let (mut app, hello) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let app_uid = hello["self"]["uid"].as_u64().unwrap();
    let alice_uid = hello["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "alice")
        .unwrap()["uid"]
        .as_u64()
        .unwrap();
    alice.recv_type(HDR_USER_CHANGE).await; // bob's join

    // ng → legacy: the 1.5 client gets the 0x68 push with uid/text/nick.
    app.request_ok("msg", json!({ "to": alice_uid, "text": "hi alice" }))
        .await;
    let pm = alice.recv_type(HDR_MSG).await;
    assert_eq!(chunk(&pm, tag::BODY).unwrap(), b"hi alice".to_vec());
    assert_eq!(chunk(&pm, tag::NAME).unwrap(), b"Bob".to_vec());
    assert_eq!(chunk_u16(&pm, tag::UID), Some(app_uid as u16));

    // legacy → ng: the ack comes back to alice, the semantic event to the
    // app.
    let t = alice
        .send(
            REQ_MSG,
            &[
                (tag::UID, (app_uid as u32).to_be_bytes().to_vec()),
                (tag::BODY, b"hi bob".to_vec()),
            ],
        )
        .await;
    let ack = alice.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));
    let ev = app.event("msg").await;
    assert_eq!(ev["data"]["from"]["nick"], "alice");
    assert_eq!(ev["data"]["text"], "hi bob");
}

#[tokio::test]
async fn private_messages_to_detached_sessions_replay_on_resume() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut alice = Legacy::login(legacy_addr, "alice").await;
    let (app, hello) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let session = hello["session"].as_str().unwrap().to_string();
    let token = hello["token"].as_str().unwrap().to_string();
    let app_uid = hello["self"]["uid"].as_u64().unwrap();
    let last_seq = app.last_seq;
    alice.recv_type(HDR_USER_CHANGE).await;

    // The app drops; alice PMs it while it's detached. The sender's ack
    // succeeds — the session is still on the roster.
    drop(app);
    alice.recv_type(HDR_USER_CHANGE).await; // away flip
    let t = alice
        .send(
            REQ_MSG,
            &[
                (tag::UID, (app_uid as u32).to_be_bytes().to_vec()),
                (tag::BODY, b"call me when you're back".to_vec()),
            ],
        )
        .await;
    let ack = alice.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));

    // Resume replays the PM — the grace window's answer to offline
    // delivery.
    let mut app = Ng::connect(ng_addr).await;
    app.request_ok(
        "resume",
        json!({ "session": session, "token": token, "last_seq": last_seq }),
    )
    .await;
    let ev = app.event("msg").await;
    assert_eq!(ev["data"]["from"]["nick"], "alice");
    assert_eq!(ev["data"]["text"], "call me when you're back");
}

#[tokio::test]
async fn malformed_login_params_are_rejected_not_guested() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let mut c = Ng::connect(ng_addr).await;
    let v = c.request("login", json!(42)).await;
    assert_eq!(v["error"]["code"], "bad_request");
}

#[tokio::test]
async fn oversized_private_messages_are_truncated() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let (mut a, _) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let (mut b, hello_b) = Ng::login(ng_addr, "", "", "target").await;
    let b_uid = hello_b["self"]["uid"].as_u64().unwrap();

    let big = "x".repeat(5000);
    a.request_ok("msg", json!({ "to": b_uid, "text": big }))
        .await;
    let ev = b.event("msg").await;
    assert_eq!(ev["data"]["text"].as_str().unwrap().len(), 4096);
}

#[tokio::test]
async fn takeover_closes_the_older_connection() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy_addr, ng_addr, _ctx) = start_server(td.path()).await;

    let (mut first, hello) = Ng::login(ng_addr, "bob", "s3cret", "Bob").await;
    let session = hello["session"].as_str().unwrap().to_string();
    let token = hello["token"].as_str().unwrap().to_string();

    let mut second = Ng::connect(ng_addr).await;
    second
        .request_ok(
            "resume",
            json!({ "session": session, "token": token, "last_seq": first.last_seq }),
        )
        .await;

    // The first connection is closed out from under us ("replaced").
    let end = timeout(Duration::from_secs(5), async {
        loop {
            match first.ws.next().await {
                None | Some(Err(_)) => break true,
                Some(Ok(Message::Close(_))) => break true,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .expect("first connection should be closed by the takeover");
    assert!(end);

    // The second is fully functional.
    second.request_ok("ping", json!({})).await;
}
