//! Chat-history end to end: one durable log, exercised through both wire
//! frontends against real loopback servers.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::{Core, HistoryPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_CHAT: u32 = 0x6a;
const HDR_SELFINFO: u32 = 0x162;
const HDR_USER_CHANGE: u32 = 0x12d;
const REQ_LOGIN: u32 = 0x6b;
const REQ_CHAT: u32 = 0x69;
const REQ_USER_GETLIST: u32 = 0x12c;
const REQ_HISTORY: u32 = 700;

async fn start_server(dir: &Path, replay: usize) -> (SocketAddr, SocketAddr) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("bob.toml"),
        "name = \"Bob\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         use_any_name = true\n",
    )
    .unwrap();
    std::fs::write(
        accounts.join("nohistory.toml"),
        "name = \"No History\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
         read_chat_history = false\nsend_chat = true\nuse_any_name = true\n",
    )
    .unwrap();

    let store = Arc::new(SqliteStore::open(dir.join("server.sqlite"), Synchronous::Full).unwrap());
    let core = Arc::new(Core::new().with_history(
        store,
        HistoryPolicy {
            max_lines: 10_000,
            max_days: 30,
            max_page: 200,
            replay,
        },
    ));
    let auth: Arc<dyn hxd_core::AuthBackend> = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "history-test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: Caps::empty().with(cap::CHAT_HISTORY),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
        files: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "history-test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: vec!["history".into()],
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
    };
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addresses = (legacy.local_addr().unwrap(), ng.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    addresses
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| !byte).collect()
}

struct Legacy {
    stream: TcpStream,
    trans: u32,
}

impl Legacy {
    async fn login(
        addr: SocketAddr,
        nick: &str,
        login: &str,
        password: &str,
        offer_history: bool,
    ) -> (Self, Frame) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut chunks = vec![
            (tag::NAME, nick.as_bytes().to_vec()),
            (tag::ICON, 128u16.to_be_bytes().to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ];
        if !login.is_empty() {
            chunks.push((tag::LOGIN, xor(login.as_bytes())));
            chunks.push((tag::PASSWORD, xor(password.as_bytes())));
        }
        if offer_history {
            chunks.push((
                tag::CAPABILITIES,
                Caps::empty().with(cap::CHAT_HISTORY).to_wire(),
            ));
        }
        let mut client = Self { stream, trans: 1 };
        client
            .stream
            .write_all(&pack_frame(REQ_LOGIN, 1, 0, &chunks))
            .await
            .unwrap();
        let login_reply = client.recv_type(HDR_TASK).await;
        assert_eq!(login_reply.flag, 0);
        client.recv_type(HDR_SELFINFO).await;
        (client, login_reply)
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        self.stream
            .write_all(&pack_frame(ty, self.trans, 0, chunks))
            .await
            .unwrap();
        self.trans
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..24 {
            let frame = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("legacy timed out")
                .expect("legacy closed");
            if frame.ty == ty {
                return frame;
            }
        }
        panic!("legacy frame {ty:#x} did not arrive");
    }

    async fn chat(&mut self, text: &[u8]) {
        self.send(REQ_CHAT, &[(tag::BODY, text.to_vec())]).await;
        self.recv_type(HDR_CHAT).await;
    }

    async fn history(&mut self, before: u64, after: u64, limit: u16) -> Frame {
        let mut chunks = vec![(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())];
        if before != 0 {
            chunks.push((tag::HISTORY_BEFORE, before.to_be_bytes().to_vec()));
        }
        if after != 0 {
            chunks.push((tag::HISTORY_AFTER, after.to_be_bytes().to_vec()));
        }
        if limit != 0 {
            chunks.push((tag::HISTORY_LIMIT, limit.to_be_bytes().to_vec()));
        }
        let trans = self.send(REQ_HISTORY, &chunks).await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, trans);
        reply
    }
}

fn history_entries(frame: &Frame) -> Vec<(u64, String)> {
    frame
        .chunks()
        .filter(|chunk| chunk.tag == tag::HISTORY_ENTRY)
        .map(|chunk| {
            let entry = hxproto::parse::parse_history_entry(chunk.data).unwrap();
            (entry.message_id, hxproto::text::to_utf8(entry.message))
        })
        .collect()
}

fn has_more(frame: &Frame) -> bool {
    frame
        .chunks()
        .find(|chunk| chunk.tag == tag::HISTORY_HAS_MORE)
        .is_some_and(|chunk| chunk.data == [1])
}

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    events: Vec<Value>,
}

impl Ng {
    async fn login(addr: SocketAddr) -> (Self, Value) {
        Self::login_as(addr, "bob", "pw", "Bob").await
    }

    async fn login_as(addr: SocketAddr, login: &str, password: &str, nick: &str) -> (Self, Value) {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut client = Self {
            ws,
            next: 1,
            events: Vec::new(),
        };
        let reply = client
            .request(
                "login",
                json!({ "login": login, "password": password, "nick": nick }),
            )
            .await;
        assert!(reply.get("ok").is_some(), "{reply}");
        (client, reply["ok"].clone())
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let message = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .expect("ng socket error");
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["reply"] == id {
                    return value;
                }
                if value.get("seq").is_some() {
                    self.events.push(value);
                }
            }
        }
    }

    async fn event(&mut self, kind: &str) -> Value {
        if let Some(index) = self.events.iter().position(|event| event["ev"] == kind) {
            return self.events.remove(index);
        }
        loop {
            let message = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .expect("ng socket error");
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["ev"] == kind {
                    return value;
                }
            }
        }
    }
}

#[tokio::test]
async fn both_wires_page_the_same_public_log() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr) = start_server(dir.path(), 0).await;
    let (mut legacy, login) = Legacy::login(legacy_addr, "alice", "", "", true).await;
    let echoed = login
        .chunks()
        .find(|chunk| chunk.tag == tag::CAPABILITIES)
        .map(|chunk| Caps::from_wire(chunk.data))
        .unwrap();
    assert!(echoed.has(cap::CHAT_HISTORY));
    assert_eq!(
        login
            .chunks()
            .find(|c| c.tag == tag::HISTORY_MAX_MSGS)
            .unwrap()
            .as_uint(),
        10_000
    );
    assert_eq!(
        login
            .chunks()
            .find(|c| c.tag == tag::HISTORY_MAX_DAYS)
            .unwrap()
            .as_uint(),
        30
    );

    let (mut ng, hello) = Ng::login(ng_addr).await;
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|cap| cap == "history"));
    assert_eq!(
        hello["history"],
        json!({ "max_lines": 10_000, "max_days": 30 })
    );
    legacy.recv_type(HDR_USER_CHANGE).await;

    for line in ["one", "two", "three", "four", "five"] {
        legacy.chat(line.as_bytes()).await;
        let event = ng.event("chat").await;
        assert_eq!(event["data"]["text"], line);
        assert!(event["data"]["id"].as_u64().is_some());
        assert!(event["data"]["at"].as_u64().is_some());
    }

    let latest = legacy.history(0, 0, 2).await;
    assert_eq!(
        history_entries(&latest),
        [(4, "four".into()), (5, "five".into())]
    );
    assert!(has_more(&latest));
    let older = legacy.history(4, 0, 2).await;
    assert_eq!(
        history_entries(&older),
        [(2, "two".into()), (3, "three".into())]
    );
    assert!(has_more(&older));
    let catchup = legacy.history(0, 3, 50).await;
    assert_eq!(
        history_entries(&catchup),
        [(4, "four".into()), (5, "five".into())]
    );
    assert!(!has_more(&catchup));

    let bounded = legacy.history(6, 2, 2).await;
    assert_eq!(
        history_entries(&bounded),
        [(3, "three".into()), (4, "four".into())]
    );
    assert!(has_more(&bounded));

    let reply = ng.request("history", json!({ "after": 3 })).await;
    assert_eq!(reply["ok"]["lines"][0]["id"], 4);
    assert_eq!(reply["ok"]["lines"][0]["text"], "four");
    assert!(reply["ok"]["lines"][0]["from"].get("uid").is_none());
    assert_eq!(reply["ok"]["lines"][1]["id"], 5);
    assert_eq!(reply["ok"]["has_more"], false);

    let bounded = ng
        .request("history", json!({ "after": 2, "before": 6, "limit": 3 }))
        .await;
    assert_eq!(
        bounded["ok"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    assert_eq!(bounded["ok"]["has_more"], false);
}

#[tokio::test]
async fn negotiation_access_channel_and_encoding_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr) = start_server(dir.path(), 0).await;
    let (mut capable, _) = Legacy::login(legacy_addr, "alice", "", "", true).await;
    let (mut ng, _) = Ng::login(ng_addr).await;
    capable.recv_type(HDR_USER_CHANGE).await;

    let chat = ng.request("chat", json!({ "text": "snowman ☃" })).await;
    assert!(chat.get("ok").is_some());
    capable.recv_type(HDR_CHAT).await;
    let page = capable.history(0, 0, 10).await;
    assert_eq!(history_entries(&page)[0].1, "snowman ?");

    let bad_channel = capable
        .send(
            REQ_HISTORY,
            &[(tag::CHANNEL_ID, 1u32.to_be_bytes().to_vec())],
        )
        .await;
    let reply = capable.recv_type(HDR_TASK).await;
    assert_eq!(reply.trans, bad_channel);
    assert_ne!(reply.flag, 0);

    let (mut plain, _) = Legacy::login(legacy_addr, "plain", "", "", false).await;
    let reply = plain.history(0, 0, 10).await;
    assert_ne!(reply.flag, 0);

    let (mut denied, _) = Legacy::login(legacy_addr, "denied", "nohistory", "pw", true).await;
    let reply = denied.history(0, 0, 10).await;
    assert_ne!(reply.flag, 0);
    let (mut denied_ng, _) = Ng::login_as(ng_addr, "nohistory", "pw", "Denied").await;
    let reply = denied_ng.request("history", json!({})).await;
    assert_eq!(reply["error"]["code"], "access_denied");
}

#[tokio::test]
async fn compatibility_replay_waits_for_user_list_and_capable_clients_do_not_get_it() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy_addr, _ng_addr) = start_server(dir.path(), 2).await;
    let (mut writer, _) = Legacy::login(legacy_addr, "writer", "", "", true).await;
    for line in [b"first".as_slice(), b"second", b"third"] {
        writer.chat(line).await;
    }
    writer.send(REQ_USER_GETLIST, &[]).await;
    writer.recv_type(HDR_TASK).await;
    assert!(
        timeout(Duration::from_millis(200), read_frame(&mut writer.stream))
            .await
            .is_err(),
        "history-capable client received compatibility replay"
    );

    let (mut old, _) = Legacy::login(legacy_addr, "old", "", "", false).await;
    writer.recv_type(HDR_USER_CHANGE).await;
    old.send(REQ_USER_GETLIST, &[]).await;
    old.recv_type(HDR_TASK).await;
    let first = old.recv_type(HDR_CHAT).await;
    let second = old.recv_type(HDR_CHAT).await;
    let bodies = [first, second].map(|frame| {
        hxproto::text::to_utf8(frame.chunks().find(|c| c.tag == tag::BODY).unwrap().data)
    });
    assert!(bodies[0].contains("second"), "{}", bodies[0]);
    assert!(bodies[1].contains("third"), "{}", bodies[1]);
    assert!(bodies.iter().all(|body| body.starts_with("\r[")));
}

#[tokio::test]
async fn the_compatibility_replay_attributes_every_line_of_a_body() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy_addr, _ng_addr) = start_server(dir.path(), 4).await;
    let (mut mallory, _) = Legacy::login(legacy_addr, "mallory", "", "", true).await;
    // A body carrying a carriage return. Live delivery attributes both
    // halves; the replay has to as well, or the second half arrives in
    // an old client's scrollback looking like a line someone else said.
    mallory
        .chat(b"hello\r        admin:  server is closing")
        .await;

    let (mut old, _) = Legacy::login(legacy_addr, "old", "", "", false).await;
    mallory.recv_type(HDR_USER_CHANGE).await;
    old.send(REQ_USER_GETLIST, &[]).await;
    old.recv_type(HDR_TASK).await;
    let replayed = old.recv_type(HDR_CHAT).await;
    let body = hxproto::text::to_utf8(replayed.chunks().find(|c| c.tag == tag::BODY).unwrap().data);
    let lines: Vec<&str> = body.split('\r').filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 2, "{body}");
    assert!(
        lines
            .iter()
            .all(|line| line.starts_with('[') && line.contains("mallory:  ")),
        "{body}"
    );
}

#[tokio::test]
async fn a_page_of_long_lines_stays_inside_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy_addr, _ng_addr) = start_server(dir.path(), 0).await;
    let (mut writer, _) = Legacy::login(legacy_addr, "writer", "", "", true).await;
    // Seventy lines at the 4 KiB input cap is over a quarter-megabyte of
    // entries — more than one transaction may carry, and well inside the
    // 200-line `max_page` a client is allowed to ask for.
    const LINES: u64 = 70;
    for n in 0..LINES {
        let mut body = format!("line-{n} ").into_bytes();
        body.resize(4096, b'x');
        writer.chat(&body).await;
    }

    // Paging back keeps the newest and drops the oldest, so the oldest
    // id the client was given is still the right cursor for the next
    // page. Reading the reply at all is half the assertion: an oversized
    // transaction would not frame.
    let page = writer.history(0, 0, 200).await;
    assert_eq!(page.flag, 0);
    let entries = history_entries(&page);
    assert!(
        !entries.is_empty() && (entries.len() as u64) < LINES,
        "{} entries",
        entries.len()
    );
    assert!(has_more(&page));
    assert!(entries
        .last()
        .unwrap()
        .1
        .starts_with(&format!("line-{} ", LINES - 1)));
    let oldest = entries.first().unwrap().0;
    let older = history_entries(&writer.history(oldest, 0, 200).await);
    assert_eq!(older.last().unwrap().0, oldest - 1);

    // Catching up forwards drops from the other end, for the same
    // reason: there the cursor is the newest id the client holds.
    let forward = writer.history(0, 1, 200).await;
    assert_eq!(forward.flag, 0);
    let forward = history_entries(&forward);
    assert_eq!(forward.first().unwrap().0, 2);
    assert!((forward.len() as u64) < LINES - 1);
    assert!(has_more(&page));
}
