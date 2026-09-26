//! Moderation end to end (`docs/moderation.md` §8): real servers on
//! loopback, one SQLite file holding the inbox, the chat log, the news
//! and the audit trail, the real image pipeline, a scripted 1.5 client
//! and WebSocket clients at once.
//!
//! What is here is what the unit tests cannot show: that a redaction
//! reaches the clients that rendered the line, on the wire that can say
//! so, and the tombstone on both; that a report filed on one wire
//! reaches a moderator on the other; and that the acts leave every store
//! as the design says.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::media::MediaConfig;
use hxd_core::{Core, HistoryPolicy, ModerationPolicy, NewsPolicy, SystemPolicy};
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
const HDR_MSG: u32 = 0x68;
const HDR_SELFINFO: u32 = 0x162;
const REQ_LOGIN: u32 = 0x6b;
const REQ_CHAT: u32 = 0x69;
const REQ_MSG: u32 = 0x6c;
const REQ_KICK: u32 = 0x6e;
const REQ_HISTORY: u32 = 700;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
    store: Arc<SqliteStore>,
}

/// What an account may do, by name, as its file says it.
const MEMBER: &str = "read_chat = true\nsend_chat = true\nsend_msgs = true\nuse_any_name = true\n\
                      send_media = true\nread_chat_history = true\nread_news = true\n\
                      post_news = true\n";

async fn start(dir: &Path) -> Server {
    start_with(dir, ModerationPolicy::default()).await
}

async fn start_with(dir: &Path, policy: ModerationPolicy) -> Server {
    start_full(dir, policy, Duration::from_secs(24 * 3600)).await
}

async fn start_full(dir: &Path, policy: ModerationPolicy, handle_ttl: Duration) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let account = |login: &str, extra: &str| {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{MEMBER}{extra}"),
        )
        .unwrap();
    };
    account("alice", "");
    account("bob", "");
    // The kick bit makes a moderator, with no `[extra]` to say so.
    account(
        "carol",
        "disconnect_users = true\ncreate_categories = true\ndelete_articles = true\n",
    );
    account("dave", "disconnect_users = true\n");
    account("boss", "cant_be_disconnected = true\n");

    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let codec = Arc::new(hxd_media::Codec::new(Default::default()));
    let core = Arc::new(
        Core::new()
            .with_inbox(store.clone(), auth.clone(), Default::default())
            .with_history(
                store.clone(),
                HistoryPolicy {
                    max_lines: 10_000,
                    max_days: 30,
                    max_page: 200,
                    replay: 0,
                },
            )
            .with_news(store.clone(), NewsPolicy::default())
            .with_media(
                codec,
                MediaConfig {
                    upload_interval: Duration::ZERO,
                    handle_ttl,
                    ..Default::default()
                },
            )
            .with_system(SystemPolicy::default())
            .with_moderation(store.clone(), policy),
    );
    core.start_system_session().unwrap();

    let auth: Arc<dyn hxd_core::AuthBackend> = auth;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "moderation".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: Caps::empty()
                .with(cap::CHAT_HISTORY)
                .with(cap::INLINE_MEDIA),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            news: Default::default(),
        }),
        files: None,
        banner: None,
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "moderation".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: vec!["history".into(), "inbox".into()],
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
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
    let server = Server {
        legacy: l1.local_addr().unwrap(),
        ng: l2.local_addr().unwrap(),
        core,
        store,
    };
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    server
}

/// A small PNG, through the same encoder a client would use.
fn png(w: u32, h: u32, shade: u8) -> Vec<u8> {
    use image::{DynamicImage, ImageEncoder, RgbaImage};
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([(x * 5 % 256) as u8, (y * 3 % 256) as u8, shade, 0xff]);
    }
    let img = DynamicImage::ImageRgba8(img);
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(std::io::Cursor::new(&mut out))
        .write_image(img.as_bytes(), w, h, img.color().into())
        .unwrap();
    out
}

// --- A scripted 1.5 client ----------------------------------------------

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| !b).collect()
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
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut c = Legacy {
            stream,
            trans: 0,
            uid: 0,
        };
        let trans = c
            .send(
                REQ_LOGIN,
                &[
                    (tag::NAME, login.as_bytes().to_vec()),
                    (tag::ICON, 128u16.to_be_bytes().to_vec()),
                    (tag::VERSION, 150u16.to_be_bytes().to_vec()),
                    (tag::LOGIN, xor(login.as_bytes())),
                    (tag::PASSWORD, xor(b"pw")),
                    (
                        tag::CAPABILITIES,
                        Caps::empty().with(cap::CHAT_HISTORY).to_wire(),
                    ),
                ],
            )
            .await;
        let reply = c.reply_to(trans).await;
        assert_eq!(reply.flag, 0, "{login} logs in");
        c.uid = reply
            .chunks()
            .find(|ch| ch.tag == tag::UID)
            .map(|ch| ch.as_uint() as u16)
            .unwrap();
        c.recv_type(HDR_SELFINFO).await;
        c
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        self.stream
            .write_all(&pack_frame(ty, self.trans, 0, chunks))
            .await
            .unwrap();
        self.trans
    }

    async fn next(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("legacy: timed out")
            .expect("legacy: closed")
    }

    async fn reply_to(&mut self, trans: u32) -> Frame {
        for _ in 0..48 {
            let f = self.next().await;
            if f.ty == HDR_TASK && f.trans == trans {
                return f;
            }
        }
        panic!("legacy: no reply to {trans}");
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..48 {
            let f = self.next().await;
            if f.ty == ty {
                return f;
            }
        }
        panic!("legacy: {ty:#x} never arrived");
    }

    async fn chat(&mut self, text: &str) {
        self.send(REQ_CHAT, &[(tag::BODY, text.as_bytes().to_vec())])
            .await;
        self.recv_type(HDR_CHAT).await;
    }

    /// A private message as the client sees it: body, the uid it is from
    /// and the name it shows.
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
            u16::from_be_bytes(chunk(tag::UID).try_into().unwrap()),
            String::from_utf8_lossy(&chunk(tag::NAME)).into_owned(),
        )
    }

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

    /// The history page, as `(id, flags, nick, text)`.
    async fn history(&mut self) -> Vec<(u64, u16, String, String)> {
        let trans = self
            .send(
                REQ_HISTORY,
                &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())],
            )
            .await;
        let reply = self.reply_to(trans).await;
        assert_eq!(reply.flag, 0, "history is served");
        reply
            .chunks()
            .filter(|c| c.tag == tag::HISTORY_ENTRY)
            .map(|c| {
                let e = hxproto::parse::parse_history_entry(c.data).unwrap();
                (
                    e.message_id,
                    e.flags,
                    hxproto::text::to_utf8(e.nick),
                    hxproto::text::to_utf8(e.message),
                )
            })
            .collect()
    }
}

// --- A scripted ng client -----------------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    events: Vec<Value>,
    bearer: String,
    uid: u16,
}

impl Ng {
    async fn login(addr: SocketAddr, login: &str) -> (Ng, Value) {
        Ng::login_with(
            addr,
            json!({ "login": login, "password": "pw", "nick": login }),
        )
        .await
    }

    async fn guest(addr: SocketAddr) -> Ng {
        Ng::login_with(addr, json!({ "nick": "drifter" })).await.0
    }

    async fn login_with(addr: SocketAddr, params: Value) -> (Ng, Value) {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut c = Ng {
            ws,
            next: 1,
            events: Vec::new(),
            bearer: String::new(),
            uid: 0,
        };
        let ok = c.ok("login", params).await;
        c.bearer = format!(
            "Bearer {}.{}",
            ok["session"].as_str().unwrap(),
            ok["token"].as_str().unwrap()
        );
        c.uid = ok["self"]["uid"].as_u64().unwrap() as u16;
        (c, ok)
    }

    async fn frame(&mut self) -> Option<Value> {
        let msg = timeout(Duration::from_secs(5), self.ws.next())
            .await
            .expect("ng: timed out")?;
        match msg.ok()? {
            Message::Text(t) => Some(serde_json::from_str(&t).unwrap()),
            Message::Close(_) => None,
            _ => Some(json!({})),
        }
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
            let v = self.frame().await.expect("ng: closed");
            if v.get("reply") == Some(&json!(id)) {
                return v;
            }
            if v.get("ev").is_some() {
                self.events.push(v);
            }
        }
    }

    async fn ok(&mut self, method: &str, params: Value) -> Value {
        let v = self.request(method, params).await;
        assert!(v.get("ok").is_some(), "{method} should succeed: {v}");
        v["ok"].clone()
    }

    async fn refused(&mut self, method: &str, params: Value) -> String {
        let v = self.request(method, params).await;
        v["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} should be refused: {v}"))
            .to_string()
    }

    async fn event(&mut self, kind: &str) -> Value {
        if let Some(i) = self.events.iter().position(|e| e["ev"] == kind) {
            return self.events.remove(i)["data"].clone();
        }
        for _ in 0..48 {
            let v = self.frame().await.expect("ng: closed");
            if v["ev"] == kind {
                return v["data"].clone();
            }
            if v.get("ev").is_some() {
                self.events.push(v);
            }
        }
        panic!("ng: no {kind} event arrived");
    }

    /// Nothing of this kind arrives while a round trip completes.
    async fn none(&mut self, kind: &str) {
        self.ok("ping", json!({})).await;
        assert!(
            !self.events.iter().any(|e| e["ev"] == kind),
            "no {kind} event was expected: {:?}",
            self.events
        );
    }
}

// --- A little HTTP, for images --------------------------------------------

async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Authorization: {bearer}\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&raw[..split])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, raw[split + 4..].to_vec())
}

async fn upload(addr: SocketAddr, bearer: &str, bytes: &[u8]) -> String {
    let (status, body) = http(addr, "POST", "/media", bearer, bytes).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let v: Value = serde_json::from_slice(&body).unwrap();
    v["media"]["id"].as_str().unwrap().to_string()
}

async fn fetch(addr: SocketAddr, bearer: &str, id: &str) -> u16 {
    http(addr, "GET", &format!("/media/{id}"), bearer, b"")
        .await
        .0
}

// -------------------------------------------------------------------------

/// A moderator's session says so, and says how much is waiting.
#[tokio::test]
async fn a_moderator_is_told_at_login_and_nobody_else_is() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (_, hello) = Ng::login(srv.ng, "alice").await;
    assert!(hello["self"].get("moderator").is_none());
    assert!(hello.get("moderation").is_none());
    let (_, hello) = Ng::login(srv.ng, "carol").await;
    assert_eq!(hello["self"]["moderator"], true);
    assert_eq!(hello["moderation"]["open"], 0);
}

/// §8's first case: a redacted line is a tombstone through 700 and
/// `history`, and a `chat_redacted` to an ng client that had rendered it.
#[tokio::test]
async fn a_redacted_line_is_a_tombstone_on_both_wires_and_blanked_where_it_was_rendered() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let mut classic = Legacy::login(srv.legacy, "bob").await;
    let (mut reader, _) = Ng::login(srv.ng, "alice").await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;

    classic.chat("a slur").await;
    let line = reader.event("chat").await;
    assert_eq!(line["text"], "a slur");
    let id = line["id"].as_u64().unwrap();

    assert_eq!(
        reader
            .refused("redact", json!({ "id": id, "reason": "mine" }))
            .await,
        "access_denied"
    );
    assert_eq!(
        carol.refused("redact", json!({ "id": id })).await,
        "bad_request",
        "a reason is required"
    );
    carol
        .ok("redact", json!({ "id": id, "reason": "slur" }))
        .await;

    assert_eq!(reader.event("chat_redacted").await["id"], id);
    let page = reader.ok("history", json!({})).await;
    let entry = page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == id)
        .expect("the line keeps its place");
    assert_eq!(entry["deleted"], true);
    assert_eq!(entry["text"], "");
    assert!(entry["from"].get("nick").is_none());

    // The period wire cannot unsend a 106; what it can do is page the
    // tombstone.
    let entries = classic.history().await;
    let (_, flags, nick, text) = entries
        .iter()
        .find(|(line, ..)| *line == id)
        .expect("in 700 too");
    assert_ne!(flags & 0b100, 0, "flagged deleted");
    assert!(nick.is_empty() && text.is_empty());

    // And the words are where a moderator can read them, for now.
    let log = carol.ok("moderation_log", json!({})).await;
    let act = &log["entries"][0];
    assert_eq!(act["kind"], "redact");
    assert_eq!(act["by"], "carol");
    assert_eq!(act["target"]["line"], id);
    assert_eq!(act["target"]["login"], "bob");
    assert!(act["evidence"].as_str().unwrap().contains("a slur"));
}

/// §8's second: a revoked image is gone at once and its re-upload is
/// refused — and the moderator never needed the handle to be theirs.
#[tokio::test]
async fn a_revoked_image_is_gone_at_once_and_does_not_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let id = upload(srv.ng, &bob.bearer, &png(24, 24, 0x10)).await;
    bob.ok("chat", json!({ "text": "look", "media": id })).await;
    alice.event("chat").await;
    assert_eq!(fetch(srv.ng, &alice.bearer, &id).await, 200);

    carol
        .ok("revoke", json!({ "media": id, "reason": "gore" }))
        .await;
    assert_eq!(alice.event("media_revoked").await["id"], json!(id));
    assert_eq!(fetch(srv.ng, &alice.bearer, &id).await, 404);
    assert_eq!(fetch(srv.ng, &bob.bearer, &id).await, 404);

    let (status, body) = http(srv.ng, "POST", "/media", &bob.bearer, &png(24, 24, 0x10)).await;
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
    // Blocked durably: the hash is in the file a restart reads.
    use hxd_core::ModerationStore;
    assert_eq!(srv.store.blocked_hashes().unwrap().len(), 1);
    // A different image is not.
    upload(srv.ng, &bob.bearer, &png(24, 24, 0x90)).await;
    assert_eq!(
        carol
            .refused(
                "revoke",
                json!({ "media": "AAAAAAAAAAAAAAAAAAAAAA", "reason": "x" })
            )
            .await,
        "no_such_media"
    );
}

/// §8's third: a purge with a kick empties the last hour of a sender
/// across the chat log and the news, and the room hears it.
#[tokio::test]
async fn a_kick_with_a_purge_empties_the_senders_hour_across_both_stores() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let cat = carol
        .ok(
            "news_node_create",
            json!({ "kind": "category", "name": "General" }),
        )
        .await["node"]["id"]
        .as_u64()
        .unwrap();
    let mine = alice
        .ok(
            "news_post",
            json!({ "category": cat, "subject": "hi", "body": "a real post" }),
        )
        .await["id"]
        .as_u64()
        .unwrap();
    let spam = bob
        .ok(
            "news_post",
            json!({ "category": cat, "subject": "buy", "body": "buy now" }),
        )
        .await["id"]
        .as_u64()
        .unwrap();
    bob.ok("chat", json!({ "text": "buy now" })).await;
    bob.ok("chat", json!({ "text": "BUY NOW" })).await;
    alice.ok("chat", json!({ "text": "stop it" })).await;
    let mut lines = Vec::new();
    while lines.len() < 3 {
        let ev = carol.event("chat").await;
        lines.push((ev["id"].as_u64().unwrap(), ev["from"]["nick"].clone()));
    }

    assert_eq!(
        carol
            .refused("kick", json!({ "uid": bob.uid, "purge": 3600 }))
            .await,
        "bad_request",
        "a purge says why"
    );
    carol
        .ok(
            "kick",
            json!({ "uid": bob.uid, "purge": 3600, "reason": "spam run" }),
        )
        .await;
    assert_eq!(bob.event("kicked").await, json!({}));
    let redacted: Vec<u64> = vec![
        alice.event("chat_redacted").await["id"].as_u64().unwrap(),
        alice.event("chat_redacted").await["id"].as_u64().unwrap(),
    ];
    let bobs: Vec<u64> = lines
        .iter()
        .filter(|(_, nick)| *nick == "bob")
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(redacted, bobs);
    let deleted = alice.event("news_deleted").await;
    assert_eq!(deleted["id"], spam);
    let notice = alice.event("notice").await;
    assert_eq!(notice["text"], "bob has been kicked by carol");

    let thread = alice.ok("news_article", json!({ "id": mine })).await;
    assert_eq!(
        thread["article"]["body"], "a real post",
        "not theirs, not touched"
    );
    let page = alice.ok("history", json!({})).await;
    let alive: Vec<&Value> = page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l.get("deleted").is_none())
        .collect();
    assert_eq!(alive.len(), 1);
    assert_eq!(alive[0]["text"], "stop it");

    let log = carol.ok("moderation_log", json!({})).await;
    assert_eq!(
        log["entries"].as_array().unwrap().len(),
        1,
        "one row for the lot"
    );
    assert_eq!(log["entries"][0]["kind"], "purge");
    assert_eq!(log["entries"][0]["reason"], "spam run");
}

/// A guest has nothing to purge by, and is who a kick-and-purge is
/// pressed on most: the kick happens anyway.
#[tokio::test]
async fn a_kick_with_a_purge_still_kicks_a_guest() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let mut guest = Ng::guest(srv.ng).await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    carol
        .ok(
            "kick",
            json!({ "uid": guest.uid, "purge": 3600, "reason": "spam" }),
        )
        .await;
    assert_eq!(guest.event("kicked").await, json!({}));
    assert_eq!(
        carol.event("notice").await["text"],
        "drifter has been kicked by carol"
    );
}

/// The ladder: the unkickable are not moderated by someone who may only
/// kick, on the ng `kick` and on the acts.
#[tokio::test]
async fn the_unkickable_are_protected_from_a_moderator_who_may_only_kick() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut boss, _) = Ng::login(srv.ng, "boss").await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    boss.ok("chat", json!({ "text": "rules" })).await;
    let id = carol.event("chat").await["id"].as_u64().unwrap();
    assert_eq!(
        carol.refused("kick", json!({ "uid": boss.uid })).await,
        "protected"
    );
    assert_eq!(
        carol
            .refused("redact", json!({ "id": id, "reason": "x" }))
            .await,
        "protected"
    );
    assert_eq!(
        carol
            .refused("purge", json!({ "login": "boss", "reason": "x" }))
            .await,
        "protected"
    );
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    assert_eq!(
        alice.refused("kick", json!({ "uid": boss.uid })).await,
        "access_denied"
    );
}

/// §8's fourth: a report from an ng client reaches a legacy moderator as
/// a private message from the system account, and an ng moderator as an
/// event — and closing it tells the reporter.
#[tokio::test]
async fn a_report_reaches_a_moderator_on_either_wire_and_its_close_reaches_the_reporter() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let mut dave = Legacy::login(srv.legacy, "dave").await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    bob.ok("chat", json!({ "text": "you are all idiots" }))
        .await;
    let line = alice.event("chat").await["id"].as_u64().unwrap();

    let filed = alice
        .ok("report", json!({ "line": line, "reason": "rude" }))
        .await;
    assert_eq!(filed["outcome"], "open");
    assert_eq!(filed["follow_up"], true);
    let id = filed["id"].as_u64().unwrap();

    let report = carol.event("report").await;
    assert_eq!(report["id"], id);
    assert_eq!(report["status"], "open");
    assert_eq!(report["by"]["login"], "alice");
    assert_eq!(report["target"]["kind"], "line");
    assert_eq!(report["target"]["line"], line);
    assert_eq!(report["target"]["from"]["login"], "bob");
    assert_eq!(report["reason"], "rude");

    let (body, from, name) = dave.private_message().await;
    assert_eq!(
        body,
        format!("[report #{id}] alice reported a chat line from bob: \"rude\"")
    );
    assert_eq!(Some(from), srv.core.system_uid(), "from the system account");
    assert_eq!(name, "Server");

    // Nobody else hears of it.
    bob.none("report").await;

    // A second report of the same line by the same reporter is the first.
    let again = alice
        .ok("report", json!({ "line": line, "reason": "still rude" }))
        .await;
    assert_eq!(again["id"], id);

    let (_, hello) = Ng::login(srv.ng, "carol").await;
    assert_eq!(hello["moderation"]["open"], 1, "a moderator's badge");

    carol
        .ok(
            "report_close",
            json!({ "id": id, "outcome": "dismissed", "note": "banter" }),
        )
        .await;
    let closed = alice.event("report_closed").await;
    assert_eq!(closed["id"], id);
    assert_eq!(closed["outcome"], "dismissed");
    assert_eq!(closed["yours"], true);

    let listed = carol.ok("reports", json!({ "status": "closed" })).await;
    assert_eq!(listed["reports"][0]["closed"]["by"], "carol");
    assert_eq!(listed["reports"][0]["closed"]["note"], "banter");
    assert_eq!(
        carol.ok("reports", json!({})).await["reports"],
        json!([]),
        "nothing open"
    );
    assert_eq!(alice.refused("reports", json!({})).await, "access_denied");
}

/// The legacy wire files reports too, by the system account's `/report`
/// — a private message, never a chat line — and hears how they end.
#[tokio::test]
async fn a_period_client_reports_through_the_system_account() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let (bob, _) = Ng::login(srv.ng, "bob").await;
    let mut alice = Legacy::login(srv.legacy, "alice").await;
    let system = srv.core.system_uid().unwrap();

    // `/report` in public chat is chat: nothing is parsed there.
    alice.chat("/report bob hates everyone").await;
    carol.none("report").await;

    assert_eq!(
        alice.msg(system, "/report bob hates everyone").await.flag,
        0
    );
    let (answer, ..) = alice.private_message().await;
    let id: u64 = answer
        .strip_prefix("ok: report #")
        .and_then(|rest| rest.strip_suffix(" filed"))
        .unwrap_or_else(|| panic!("an answer: {answer}"))
        .parse()
        .unwrap();
    let report = carol.event("report").await;
    assert_eq!(report["id"], id);
    assert_eq!(report["target"]["kind"], "user");
    assert_eq!(report["target"]["from"]["login"], "bob");

    carol
        .ok("purge", json!({ "uid": bob.uid, "reason": "confirmed" }))
        .await;
    let (closed, ..) = alice.private_message().await;
    assert_eq!(closed, format!("[report #{id}] closed: removed"));
}

/// §8's fifth: a private message report carries the body, and only its
/// recipient may file it.
#[tokio::test]
async fn a_private_message_is_reported_by_its_recipient_with_its_body() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let (mut dave, _) = Ng::login(srv.ng, "dave").await;
    let mut bob = Legacy::login(srv.legacy, "bob").await;
    assert_eq!(bob.msg(alice.uid, "I know where you live").await.flag, 0);
    let msg = alice.event("msg").await;
    let id = msg["id"].as_u64().expect("a stored message");

    assert_eq!(
        dave.refused("report", json!({ "msg": id, "reason": "x" }))
            .await,
        "no_such_target",
        "someone else's mail is not theirs to show"
    );
    alice
        .ok("report", json!({ "msg": id, "reason": "threat" }))
        .await;
    let report = carol.event("report").await;
    assert_eq!(report["target"]["kind"], "msg");
    assert_eq!(report["evidence"], "I know where you live");
    assert_eq!(report["verified"], true);
    assert_eq!(report["target"]["from"]["login"], "bob");

    // Pasted, it is the reporter's word, and says so.
    let pasted = alice
        .ok(
            "report",
            json!({ "user": { "login": "bob" }, "reason": "and on the phone", "evidence": "…" }),
        )
        .await;
    let listed = carol.ok("reports", json!({})).await;
    let entry = listed["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == pasted["id"])
        .unwrap()
        .clone();
    assert_eq!(entry["verified"], false);
    assert_eq!(entry["target"]["kind"], "user");
    assert_eq!(
        alice
            .refused("report", json!({ "msg": id, "line": 1, "reason": "both" }))
            .await,
        "bad_request"
    );
}

/// §8's sixth: a report on an image keeps it past its TTL and lets a
/// moderator — who was never shown it — fetch it.
#[tokio::test]
async fn a_reported_image_is_held_for_the_moderator_to_see() {
    let dir = tempfile::tempdir().unwrap();
    // Handles that live two seconds, so the test can outlast one.
    let srv = start_full(
        dir.path(),
        ModerationPolicy::default(),
        Duration::from_secs(2),
    )
    .await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let id = upload(srv.ng, &bob.bearer, &png(20, 20, 0x40)).await;
    bob.ok(
        "msg",
        json!({ "to": alice.uid, "text": "look", "media": id }),
    )
    .await;
    alice.event("msg").await;
    // A moderator who logs in afterwards, and was never shown it.
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    assert_eq!(fetch(srv.ng, &carol.bearer, &id).await, 404);
    assert_eq!(
        carol
            .refused("report", json!({ "media": id, "reason": "x" }))
            .await,
        "no_such_target",
        "nobody reports what they were never shown"
    );
    alice
        .ok("report", json!({ "media": id, "reason": "vile" }))
        .await;
    let report = carol.event("report").await;
    assert_eq!(report["target"]["media"], json!(id));
    assert_eq!(fetch(srv.ng, &carol.bearer, &id).await, 200);
    // Past its TTL: the sweep that would have taken it spares it. An
    // image nobody reported, uploaded alongside, is the control.
    let control = upload(srv.ng, &bob.bearer, &png(20, 20, 0x41)).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    srv.core.media_sweep();
    assert_eq!(fetch(srv.ng, &bob.bearer, &control).await, 404);
    assert_eq!(fetch(srv.ng, &carol.bearer, &id).await, 200);
    // Judged, and the room hears the outcome it asked about.
    carol
        .ok("revoke", json!({ "media": id, "reason": "vile" }))
        .await;
    let closed = alice.event("report_closed").await;
    assert_eq!(closed["outcome"], "removed");
    assert_eq!(fetch(srv.ng, &carol.bearer, &id).await, 404);
}

/// A guest may report, and is told it will not hear how it ends.
#[tokio::test]
async fn a_guest_reports_and_is_told_it_will_not_hear_back() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let (bob, _) = Ng::login(srv.ng, "bob").await;
    let mut guest = Ng::guest(srv.ng).await;
    let filed = guest
        .ok(
            "report",
            json!({ "user": { "uid": bob.uid }, "reason": "creep" }),
        )
        .await;
    assert_eq!(filed["follow_up"], false);
    let report = carol.event("report").await;
    assert!(report.get("by").is_none(), "a guest has no name to give");
}

/// `[moderation] kick_purges`: a legacy kick takes the target's recent
/// output with it — when its kicker may purge.
#[tokio::test]
async fn a_legacy_kick_purges_when_the_operator_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start_with(
        dir.path(),
        ModerationPolicy {
            kick_purges: Duration::from_secs(600),
            ..Default::default()
        },
    )
    .await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    bob.ok("chat", json!({ "text": "spam" })).await;
    let id = alice.event("chat").await["id"].as_u64().unwrap();
    let mut dave = Legacy::login(srv.legacy, "dave").await;
    let trans = dave
        .send(REQ_KICK, &[(tag::UID, bob.uid.to_be_bytes().to_vec())])
        .await;
    assert_eq!(dave.reply_to(trans).await.flag, 0);
    assert_eq!(alice.event("chat_redacted").await["id"], id);
}

/// And without the key, a legacy kick is what it has always been.
#[tokio::test]
async fn a_legacy_kick_purges_nothing_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    bob.ok("chat", json!({ "text": "hello" })).await;
    alice.event("chat").await;
    let mut dave = Legacy::login(srv.legacy, "dave").await;
    let trans = dave
        .send(REQ_KICK, &[(tag::UID, bob.uid.to_be_bytes().to_vec())])
        .await;
    assert_eq!(dave.reply_to(trans).await.flag, 0);
    alice.event("notice").await;
    alice.none("chat_redacted").await;
    use hxd_core::ModerationStore;
    assert!(srv.store.acts(None, 10).unwrap().is_empty());
}

/// A moderator deleting someone else's article leaves a record with its
/// words, and the reports on it are answered.
#[tokio::test]
async fn a_moderators_news_delete_is_on_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let srv = start(dir.path()).await;
    let (mut carol, _) = Ng::login(srv.ng, "carol").await;
    let (mut alice, _) = Ng::login(srv.ng, "alice").await;
    let (mut bob, _) = Ng::login(srv.ng, "bob").await;
    let cat = carol
        .ok(
            "news_node_create",
            json!({ "kind": "category", "name": "General" }),
        )
        .await["node"]["id"]
        .as_u64()
        .unwrap();
    let id = bob
        .ok(
            "news_post",
            json!({ "category": cat, "subject": "flame", "body": "you all suck" }),
        )
        .await["id"]
        .as_u64()
        .unwrap();
    alice
        .ok("report", json!({ "article": id, "reason": "flame" }))
        .await;
    carol
        .ok("news_delete", json!({ "id": id, "reason": "flame war" }))
        .await;
    assert_eq!(alice.event("report_closed").await["outcome"], "removed");
    let log = carol.ok("moderation_log", json!({})).await;
    let act = &log["entries"][0];
    assert_eq!(act["kind"], "news_delete");
    assert_eq!(act["target"]["article"], id);
    assert_eq!(act["reason"], "flame war");
    assert!(act["evidence"].as_str().unwrap().contains("you all suck"));
}
