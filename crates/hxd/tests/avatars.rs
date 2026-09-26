//! Avatars end to end (`docs/avatars.md`): the GIF Icons extension on the
//! legacy wire, the `avatars` capability on the ng one, and one avatar
//! crossing between them — through the real codec and a real SQLite
//! store, against live loopback servers.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::{AvatarPolicy, Core};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::SqliteStore;
use hxproto::messages::tag;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const TASK: u32 = 0x0001_0000;
const LOGIN: u32 = 0x6b;
const ICON_GETLIST: u32 = 0x745;
const ICON_SET: u32 = 0x746;
const ICON_GET: u32 = 0x747;
const ICON_CHANGE: u32 = 0x748;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

/// A server on `dir`, with avatars when `avatars` says so. The store is a
/// file in `dir`, so a second server on the same directory is the same
/// server restarted.
async fn start(dir: &Path, avatars: Option<AvatarPolicy>) -> Server {
    let accounts = dir.join("accounts");
    if !accounts.exists() {
        hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
        for who in ["alice", "bob", "carol"] {
            std::fs::write(
                accounts.join(format!("{who}.toml")),
                format!(
                    "name = \"{who}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                     send_chat = true\nuse_any_name = true\n"
                ),
            )
            .unwrap();
        }
    }
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = match avatars {
        Some(policy) => Core::new().with_avatars(
            Arc::new(SqliteStore::open(dir.join("avatars.db"), Default::default()).unwrap()),
            Arc::new(hxd_media::Codec::new(Default::default())),
            policy,
        ),
        None => Core::new(),
    };
    let core = Arc::new(core);
    let auth: Arc<dyn hxd_core::AuthBackend> = auth;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "avatars".into(),
            ..Default::default()
        }),
        files: None,
        banner: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "avatars".into(),
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
    };
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

/// Every change allowed at once: a test that sets twice is testing
/// something other than the throttle, which has a case of its own.
fn unthrottled() -> AvatarPolicy {
    AvatarPolicy {
        set_interval: Duration::ZERO,
        ..Default::default()
    }
}

fn png(w: u32, h: u32) -> Vec<u8> {
    use image::ImageEncoder;
    let img = image::RgbaImage::from_fn(w, h, |x, y| image::Rgba([x as u8, y as u8, 0x80, 0xff]));
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(&img, w, h, image::ExtendedColorType::Rgba8)
        .unwrap();
    out
}

fn gif(frames: u32, w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        enc.set_repeat(image::codecs::gif::Repeat::Infinite)
            .unwrap();
        for n in 0..frames {
            let img = image::RgbaImage::from_fn(w, h, |x, y| {
                image::Rgba([(x + n * 40) as u8, y as u8, 0x20, 0xff])
            });
            enc.encode_frame(image::Frame::from_parts(
                img,
                0,
                0,
                image::Delay::from_numer_denom_ms(100, 1),
            ))
            .unwrap();
        }
    }
    out
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| !b).collect()
}

fn field(frame: &Frame, wanted: u16) -> Option<Vec<u8>> {
    frame
        .chunks()
        .find(|c| c.tag == wanted)
        .map(|c| c.data.to_vec())
}

// --- The legacy wire ----------------------------------------------------

struct Legacy {
    stream: TcpStream,
    trans: u32,
    uid: u16,
}

impl Legacy {
    async fn login(addr: SocketAddr, login: &str) -> Self {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let chunks = vec![
            (tag::NAME, login.as_bytes().to_vec()),
            (tag::ICON, 128u16.to_be_bytes().to_vec()),
            (tag::VERSION, 190u16.to_be_bytes().to_vec()),
            (tag::LOGIN, xor(login.as_bytes())),
            (tag::PASSWORD, xor(b"pw")),
        ];
        stream
            .write_all(&pack_frame(LOGIN, 1, 0, &chunks))
            .await
            .unwrap();
        let mut client = Self {
            stream,
            trans: 1,
            uid: 0,
        };
        let (_, reply) = client.until_task(1).await;
        assert_eq!(reply.flag, 0, "login refused");
        client.uid = u16::from_be_bytes(field(&reply, tag::UID).unwrap().try_into().unwrap());
        client
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        self.stream
            .write_all(&pack_frame(ty, self.trans, 0, chunks))
            .await
            .unwrap();
        self.trans
    }

    async fn recv(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("legacy timed out")
            .expect("legacy closed")
    }

    /// Everything before the reply to `trans`, and the reply.
    async fn until_task(&mut self, trans: u32) -> (Vec<Frame>, Frame) {
        let mut before = Vec::new();
        loop {
            let frame = self.recv().await;
            if frame.ty == TASK && frame.trans == trans {
                return (before, frame);
            }
            before.push(frame);
        }
    }

    async fn call(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Frame {
        let trans = self.send(ty, chunks).await;
        self.until_task(trans).await.1
    }

    /// Wait for `uid` to join (a user-change push naming it).
    async fn joined(&mut self, uid: u16) {
        for _ in 0..24 {
            let frame = self.recv().await;
            if frame.ty == 0x12d && field(&frame, tag::UID) == Some(uid.to_be_bytes().to_vec()) {
                return;
            }
        }
        panic!("{uid} never joined");
    }

    /// Wait for one Icon Change naming `uid`.
    async fn icon_change(&mut self, uid: u16) {
        for _ in 0..24 {
            let frame = self.recv().await;
            if frame.ty == ICON_CHANGE
                && field(&frame, tag::UID) == Some(uid.to_be_bytes().to_vec())
            {
                return;
            }
        }
        panic!("no Icon Change for {uid}");
    }

    async fn icon_of(&mut self, uid: u16) -> Vec<u8> {
        let reply = self
            .call(ICON_GET, &[(tag::UID, uid.to_be_bytes().to_vec())])
            .await;
        assert_eq!(reply.flag, 0, "Get Icon refused");
        assert_eq!(field(&reply, tag::UID), Some(uid.to_be_bytes().to_vec()));
        field(&reply, tag::ICON_GIF).expect("an icon field, empty or not")
    }

    async fn icon_list(&mut self) -> Vec<(u16, Vec<u8>)> {
        let reply = self.call(ICON_GETLIST, &[]).await;
        assert_eq!(reply.flag, 0, "Get Icon List refused");
        reply
            .chunks()
            .filter(|c| c.tag == tag::ICON_LIST)
            .map(|c| {
                let uid = u16::from_be_bytes([c.data[0], c.data[1]]);
                let len = u16::from_be_bytes([c.data[2], c.data[3]]) as usize;
                assert_eq!(c.data.len(), 4 + len, "entry length");
                (uid, c.data[4..].to_vec())
            })
            .collect()
    }
}

// --- The ng wire --------------------------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    events: Vec<Value>,
    bearer: String,
    uid: u64,
}

impl Ng {
    async fn login(addr: SocketAddr, login: &str) -> (Self, Value) {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut client = Self {
            ws,
            next: 1,
            events: Vec::new(),
            bearer: String::new(),
            uid: 0,
        };
        let reply = client
            .request("login", json!({ "login": login, "password": "pw" }))
            .await;
        let ok = reply["ok"].clone();
        assert!(ok.is_object(), "{reply}");
        client.bearer = format!(
            "Bearer {}.{}",
            ok["session"].as_str().unwrap(),
            ok["token"].as_str().unwrap()
        );
        client.uid = ok["self"]["uid"].as_u64().unwrap();
        (client, ok)
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let frame = json!({ "id": id, "req": method, "params": params }).to_string();
        self.ws.send(Message::Text(frame)).await.unwrap();
        loop {
            let value = self.recv().await;
            if value.get("reply") == Some(&json!(id)) {
                return value;
            }
            if value.get("ev").is_some() {
                self.events.push(value);
            }
        }
    }

    async fn recv(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .unwrap();
            if let Message::Text(text) = msg {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    /// The next `user_changed` for `uid`, keeping everything else.
    async fn user_changed(&mut self, uid: u64) -> Value {
        let matches = |e: &Value| e["ev"] == "user_changed" && e["data"]["user"]["uid"] == uid;
        if let Some(pos) = self.events.iter().position(matches) {
            return self.events.remove(pos)["data"]["user"].clone();
        }
        for _ in 0..24 {
            let value = self.recv().await;
            if matches(&value) {
                return value["data"]["user"].clone();
            }
            if value.get("ev").is_some() {
                self.events.push(value);
            }
        }
        panic!("no user_changed for {uid}");
    }
}

// --- A minimal HTTP/1.1 client ------------------------------------------

struct HttpReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpReply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> HttpReply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    HttpReply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

async fn put_avatar(addr: SocketAddr, bearer: &str, bytes: &[u8]) -> HttpReply {
    http(addr, "PUT", "/avatar", &[("Authorization", bearer)], bytes).await
}

async fn get_avatar(addr: SocketAddr, bearer: &str, id: &str) -> HttpReply {
    http(
        addr,
        "GET",
        &format!("/avatars/{id}"),
        &[("Authorization", bearer)],
        b"",
    )
    .await
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// --- The tests ----------------------------------------------------------

#[tokio::test]
async fn an_ng_avatar_reaches_a_gif_icon_client_as_a_gif() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), Some(unthrottled())).await;
    let mut bob = Legacy::login(server.legacy, "bob").await;
    // The probe GtkHx sends after login, and what makes bob aware.
    assert!(bob.icon_list().await.is_empty());

    let (mut alice, ok) = Ng::login(server.ng, "alice").await;
    assert!(ok["caps"].as_array().unwrap().contains(&json!("avatars")));
    assert_eq!(ok["avatars"]["max_dimension"], 128);
    assert!(ok["self"].get("avatar").is_none(), "no avatar yet");

    let put = put_avatar(server.ng, &alice.bearer, &png(300, 150)).await;
    assert_eq!(put.status, 200, "{:?}", String::from_utf8_lossy(&put.body));
    let avatar = put.json()["avatar"].clone();
    assert_eq!(avatar["type"], "image/png");
    assert_eq!(
        (avatar["width"].clone(), avatar["height"].clone()),
        (json!(128), json!(64))
    );
    let id = avatar["id"].as_str().unwrap().to_string();

    // The changer hears it on its own user object.
    assert_eq!(alice.user_changed(alice.uid).await["avatar"], avatar);

    // Bob hears which uid changed, and fetches a GIF.
    bob.icon_change(alice.uid as u16).await;
    let icon = bob.icon_of(alice.uid as u16).await;
    assert!(icon.starts_with(b"GIF89a"));
    assert!(icon.len() <= 32 * 1024);
    assert_eq!(bob.icon_list().await, vec![(alice.uid as u16, icon)]);

    // The ng bytes are the canonical PNG, named by their own hash.
    let got = get_avatar(server.ng, &alice.bearer, &id).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.header("content-type"), Some("image/png"));
    assert_eq!(hex_sha256(&got.body), id);
    assert!(got.header("cache-control").unwrap().contains("immutable"));
    let etag = got.header("etag").unwrap().to_string();
    let again = http(
        server.ng,
        "GET",
        &format!("/avatars/{id}"),
        &[("Authorization", &alice.bearer), ("If-None-Match", &etag)],
        b"",
    )
    .await;
    assert_eq!(again.status, 304);
}

#[tokio::test]
async fn a_gif_icon_set_on_the_legacy_wire_is_an_ng_avatar() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), Some(unthrottled())).await;
    let (mut alice, _) = Ng::login(server.ng, "alice").await;
    let mut bob = Legacy::login(server.legacy, "bob").await;

    // The extension's rule: a GIF or nothing.
    let refused = bob.call(ICON_SET, &[(tag::ICON_GIF, png(16, 16))]).await;
    assert_eq!(refused.flag, 1);

    let animated = gif(3, 48, 48);
    let set = bob.call(ICON_SET, &[(tag::ICON_GIF, animated)]).await;
    assert_eq!(set.flag, 0);
    let seen = alice.user_changed(u64::from(bob.uid)).await;
    assert_eq!(
        seen["avatar"]["type"], "image/gif",
        "an animation stays one"
    );
    let id = seen["avatar"]["id"].as_str().unwrap();
    let got = get_avatar(server.ng, &alice.bearer, id).await;
    assert_eq!(got.status, 200);
    assert!(got.body.starts_with(b"GIF89a"));
    // Bob's own copy is the server's re-encode, not the bytes he sent.
    assert_eq!(bob.icon_of(bob.uid).await, got.body);

    // An empty payload clears, and ng hears the key go.
    let clear = bob.call(ICON_SET, &[(tag::ICON_GIF, vec![])]).await;
    assert_eq!(clear.flag, 0);
    assert!(alice
        .user_changed(u64::from(bob.uid))
        .await
        .get("avatar")
        .is_none());
    assert!(bob.icon_of(bob.uid).await.is_empty());
}

#[tokio::test]
async fn a_classic_client_that_never_asked_is_never_told() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), Some(unthrottled())).await;
    let mut carol = Legacy::login(server.legacy, "carol").await;
    let mut bob = Legacy::login(server.legacy, "bob").await;
    bob.icon_list().await;
    let (alice, _) = Ng::login(server.ng, "alice").await;
    assert_eq!(
        put_avatar(server.ng, &alice.bearer, &png(32, 32))
            .await
            .status,
        200
    );
    bob.icon_change(alice.uid as u16).await;

    // Carol asks only now, and then bob changes his. Events reach a
    // session in order, so had alice's change been sent to her, it would
    // be the first she sees.
    carol.icon_list().await;
    assert_eq!(
        bob.call(ICON_SET, &[(tag::ICON_GIF, gif(1, 16, 16))])
            .await
            .flag,
        0
    );
    let first = loop {
        let frame = carol.recv().await;
        if frame.ty == ICON_CHANGE {
            break field(&frame, tag::UID).unwrap();
        }
    };
    assert_eq!(first, bob.uid.to_be_bytes().to_vec());
}

#[tokio::test]
async fn an_avatar_belongs_to_the_account_and_outlives_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), Some(unthrottled())).await;
    let (mut alice, _) = Ng::login(server.ng, "alice").await;
    let put = put_avatar(server.ng, &alice.bearer, &png(64, 64)).await;
    let avatar = put.json()["avatar"].clone();
    assert_eq!(alice.request("logout", json!({})).await["ok"], json!({}));

    // The same account on the other wire joins with it, and a GIF-icon
    // client already here is told so: Icon Change is the only thing that
    // makes GtkHx fetch an icon after its first list.
    let mut bob = Legacy::login(server.legacy, "bob").await;
    assert!(bob.icon_list().await.is_empty());
    let alice_legacy = Legacy::login(server.legacy, "alice").await;
    bob.joined(alice_legacy.uid).await;
    bob.icon_change(alice_legacy.uid).await;
    assert!(bob.icon_of(alice_legacy.uid).await.starts_with(b"GIF89a"));
    drop(alice_legacy);
    // The same on a join from the ng wire.
    let (alice_ng, _) = Ng::login(server.ng, "alice").await;
    bob.icon_change(alice_ng.uid as u16).await;

    // A new process on the same database still has it, and a fetch by id
    // answers with nobody on the roster wearing it.
    let restarted = start(dir.path(), Some(unthrottled())).await;
    let (carol, _) = Ng::login(restarted.ng, "carol").await;
    let got = get_avatar(restarted.ng, &carol.bearer, avatar["id"].as_str().unwrap()).await;
    assert_eq!(got.status, 200);
    let (_, ok) = Ng::login(restarted.ng, "alice").await;
    assert_eq!(ok["self"]["avatar"], avatar);

    // Clearing is a request on the socket, and it sticks.
    let (mut again, _) = Ng::login(restarted.ng, "alice").await;
    assert_eq!(
        again.request("avatar_clear", json!({})).await["ok"],
        json!({})
    );
    let (_, ok) = Ng::login(restarted.ng, "alice").await;
    assert!(ok["self"].get("avatar").is_none());
}

#[tokio::test]
async fn refusals_come_back_as_statuses_and_task_errors() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), Some(AvatarPolicy::default())).await;
    let (alice, _) = Ng::login(server.ng, "alice").await;
    assert_eq!(
        put_avatar(server.ng, "Bearer nope.nope", &png(8, 8))
            .await
            .status,
        401
    );
    let text = "not an image ".repeat(10);
    assert_eq!(
        put_avatar(server.ng, &alice.bearer, text.as_bytes())
            .await
            .status,
        415
    );
    // That refusal spent the turn: a change a decode was paid for, or
    // refused, is one change.
    let limited = put_avatar(server.ng, &alice.bearer, &png(8, 8)).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.header("retry-after"), Some("10"), "set_interval");

    let unknown = "0".repeat(64);
    assert_eq!(
        get_avatar(server.ng, &alice.bearer, &unknown).await.status,
        404
    );
    assert_eq!(
        get_avatar(server.ng, &alice.bearer, "short").await.status,
        404
    );
    assert_eq!(get_avatar(server.ng, "", &unknown).await.status, 401);

    let mut bob = Legacy::login(server.legacy, "bob").await;
    let nobody = bob
        .call(ICON_GET, &[(tag::UID, 999u16.to_be_bytes().to_vec())])
        .await;
    assert_eq!(nobody.flag, 1);
}

#[tokio::test]
async fn without_avatars_neither_wire_offers_them() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), None).await;
    let mut bob = Legacy::login(server.legacy, "bob").await;
    // An error, which is how GtkHx's probe learns there is no support.
    assert_eq!(bob.call(ICON_GETLIST, &[]).await.flag, 1);
    let (mut alice, ok) = Ng::login(server.ng, "alice").await;
    assert!(!ok["caps"].as_array().unwrap().contains(&json!("avatars")));
    assert!(ok.get("avatars").is_none());
    assert_eq!(
        put_avatar(server.ng, &alice.bearer, &png(8, 8))
            .await
            .status,
        404
    );
    assert_eq!(
        alice.request("avatar_clear", json!({})).await["error"]["code"],
        "unknown_method"
    );
}
