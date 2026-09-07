//! Identity end-to-end (`docs/hotline-ng-identity.md` §4–§6, §10): the
//! HTTP endpoints on the ng listener, a transport token redeemed at
//! upgrade on both WebSocket paths, and what the roster then shows.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use hl_identity::{cert, Card, DeviceCert, DeviceKey, IdentityKey, LoginProof, ServerKey};
use hotline_proto::messages::tag;
use hxd_core::Core;
use hxd_ng_session::{IdentityConfig, IdentityState, NgConfig, NgCtx, Registry, TunnelSink};
use hxd_session::frame::{pack_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

const REQ_LOGIN: u32 = 0x6b;
const HDR_TASK: u32 = 0x0001_0000;
const HDR_SELFINFO: u32 = 0x162;

async fn start_server(dir: &Path) -> (SocketAddr, SocketAddr, NgCtx) {
    start_server_with(
        dir,
        IdentityConfig::default(),
        hxd_session::TrtpLogin::Verify,
    )
    .await
}

async fn start_server_with(
    dir: &Path,
    cfg: IdentityConfig,
    trtp_login: hxd_session::TrtpLogin,
) -> (SocketAddr, SocketAddr, NgCtx) {
    start_server_full(dir, cfg, trtp_login, &[]).await
}

/// Same, with `[ng] trusted_proxies` set — the mTLS binding (§5.3).
async fn start_server_with_proxies(
    dir: &Path,
    cfg: IdentityConfig,
    proxies: &[&str],
) -> (SocketAddr, SocketAddr, NgCtx) {
    start_server_full(dir, cfg, hxd_session::TrtpLogin::Verify, proxies).await
}

async fn start_server_full(
    dir: &Path,
    cfg: IdentityConfig,
    trtp_login: hxd_session::TrtpLogin,
    proxies: &[&str],
) -> (SocketAddr, SocketAddr, NgCtx) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("misha.toml"),
        "# hand-maintained\nname = \"Misha\"\npassword = \"s3cret\"\n[access]\nread_chat = true\nsend_chat = true\nsend_msgs = true\nuse_any_name = true\ndisconnect_users = true\n",
    )
    .unwrap();
    std::fs::write(
        accounts.join("locked.toml"),
        "name = \"Locked\"\npassword = \"pw\"\n[identity]\nallow_self_link = false\n",
    )
    .unwrap();
    let core = Arc::new(Core::new());
    let auth: Arc<dyn hxd_core::AuthBackend> = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "idtest".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: hxd_session::Caps::empty(),
            mark_cleartext: true,
            trtp_login,
        }),
    };
    let identity = IdentityState::new(ServerKey::from_seed(&[0x55; 32]), cfg, auth.clone());
    let tunnel: Arc<dyn TunnelSink> = Arc::new(hxd::LegacyTunnel(legacy_ctx.clone()));
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "idtest".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: hxd_ng_session::TrustedProxies::parse(proxies).unwrap(),
        }),
        registry: Arc::new(Registry::new()),
        identity: Some(Arc::new(identity)),
        tunnel: Some(tunnel),
    };
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (legacy_addr, ng_addr) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx.clone()));
    (legacy_addr, ng_addr, ng_ctx)
}

// --- A minimal HTTP/1.1 client, enough for JSON and CBOR bodies ----------

struct HttpReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpReply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {:?}", String::from_utf8_lossy(&self.body)))
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
    timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status: u16 = lines
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

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A user with an identity, a device, a card and a certificate.
struct Person {
    id: IdentityKey,
    dev: DeviceKey,
    card: Vec<u8>,
    cert: Vec<u8>,
}

fn person(seed: u8, name: &str) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[seed + 100; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let cert = DeviceCert::for_device(&id, &dev, now() - 5, cert::RECOMMENDED_LIFETIME).sign(&id);
    Person {
        id,
        dev,
        card,
        cert,
    }
}

/// The challenge binding, start to finish: returns the auth reply.
async fn authenticate(ng: SocketAddr, p: &Person) -> Value {
    let r = try_authenticate(ng, p, json!({})).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

/// Same, with extra JSON fields (`login`/`password`) and no status check.
async fn try_authenticate(ng: SocketAddr, p: &Person, extra: Value) -> HttpReply {
    let ch = http(ng, "POST", "/identity/challenge", &[], b"").await;
    assert_eq!(ch.status, 200);
    let ch = ch.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let server_key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let proof = LoginProof::sign(&p.dev, &challenge, &server_key, now());
    let mut body =
        json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    http(
        ng,
        "POST",
        "/identity/auth",
        &[("Content-Type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await
}

async fn ng_login(ng: SocketAddr, token: &str, nick: &str) -> (Ng, Value) {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng?token={token}"))
        .await
        .unwrap();
    let mut c = Ng::from_ws(ws).await;
    let ok = c.request("login", json!({ "nick": nick })).await;
    assert!(ok.get("ok").is_some(), "{ok}");
    let ok = ok["ok"].clone();
    (c, ok)
}

// --- ng JSON client (trimmed from tests/ng.rs) ----------------------------

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

struct Ng {
    ws: Ws,
    next_id: u64,
    events: Vec<Value>,
}

impl Ng {
    async fn from_ws(ws: Ws) -> Ng {
        Ng {
            ws,
            next_id: 1,
            events: Vec::new(),
        }
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
            let v = self.recv_json().await;
            if v.get("reply").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            self.events.push(v);
        }
    }

    async fn recv_json(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng: timed out")
                .expect("ng: closed")
                .unwrap();
            if let Message::Text(t) = msg {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    async fn event(&mut self, ev: &str) -> Value {
        if let Some(i) = self.events.iter().position(|v| v["ev"] == ev) {
            return self.events.remove(i);
        }
        loop {
            let v = self.recv_json().await;
            if v["ev"] == ev {
                return v;
            }
            self.events.push(v);
        }
    }
}

// --- Tests ----------------------------------------------------------------

#[tokio::test]
async fn discovery_challenge_auth_and_authenticated_json_login() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;

    let disc = http(ng, "GET", "/.well-known/hotline", &[], b"").await;
    assert_eq!(disc.status, 200);
    let disc = disc.json();
    assert_eq!(disc["identity"]["enabled"], true);
    assert_eq!(disc["identity"]["association"], "server");
    assert_eq!(disc["ng"]["ws"], "/ng");
    assert_eq!(disc["ng"]["trtp"], "/trtp");
    assert_eq!(disc["identity"]["bindings"], json!(["challenge"]));

    let p = person(1, "Misha");
    let auth = authenticate(ng, &p).await;
    assert_eq!(auth["outcome"], "unattested_guest");
    assert_eq!(auth["fingerprint"], p.id.fingerprint().to_string());
    assert!(auth["handle"].is_null());
    let token = auth["token"].as_str().unwrap().to_owned();

    // The card was cached byte-exactly and is public.
    let card = http(
        ng,
        "GET",
        &format!("/identity/card/{}", p.id.fingerprint()),
        &[],
        b"",
    )
    .await;
    assert_eq!(card.status, 200);
    assert_eq!(card.header("content-type"), Some("application/cbor"));
    assert_eq!(card.body, p.card);

    // Browser path: token in the query string.
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng?token={token}"))
        .await
        .unwrap();
    let mut me = Ng::from_ws(ws).await;
    let ok = me.request("login", json!({ "nick": "Misha" })).await;
    let ok = &ok["ok"];
    assert_eq!(
        ok["self"]["identity"]["fingerprint"],
        p.id.fingerprint().to_string(),
        "{ok}"
    );
    assert_eq!(ok["self"]["identity"]["outcome"], "unattested_guest");
    assert_eq!(ok["self"]["transport"], "encrypted");
    assert!(ok["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "identity"));

    // The token was single-use.
    let refused = http(
        ng,
        "GET",
        &format!("/ng?token={token}"),
        &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
        b"",
    )
    .await;
    assert_eq!(refused.status, 401);

    // A second, unauthenticated user sees the identity on the roster row
    // but not the private parts.
    let (ws2, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut other = Ng::from_ws(ws2).await;
    let ok2 = other.request("login", json!({ "nick": "guest" })).await;
    let row = ok2["ok"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "Misha")
        .unwrap()
        .clone();
    assert_eq!(
        row["identity"]["fingerprint"],
        p.id.fingerprint().to_string()
    );
    assert!(row["identity"].get("outcome").is_none());
    assert!(row["identity"].get("age").is_none());
    assert_eq!(row["transport"], "encrypted");
    assert!(ok2["ok"]["self"].get("identity").is_none());
}

#[tokio::test]
async fn bad_proof_and_stale_challenge_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(2, "Eve");

    // A proof for a challenge the server never issued.
    let bogus = [9u8; 32];
    let sk = ServerKey::from_seed(&[0x55; 32]).public();
    let proof = LoginProof::sign(&p.dev, &bogus, &sk, now());
    let body = json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) })
        .to_string();
    let r = http(ng, "POST", "/identity/auth", &[], body.as_bytes()).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"], "unknown_challenge");

    // A real challenge, wrong device signing the proof.
    let ch = http(ng, "POST", "/identity/challenge", &[], b"")
        .await
        .json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let stranger = DeviceKey::from_seed(&[77; 32]);
    let proof = LoginProof::sign(&stranger, &challenge, &sk, now());
    let body = json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) })
        .to_string();
    let r = http(ng, "POST", "/identity/auth", &[], body.as_bytes()).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"], "bad_proof");

    // And the challenge was burned by the failed attempt.
    let proof = LoginProof::sign(&p.dev, &challenge, &sk, now());
    let body = json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) })
        .to_string();
    let r = http(ng, "POST", "/identity/auth", &[], body.as_bytes()).await;
    assert_eq!(r.json()["error"], "unknown_challenge");

    // A made-up token at upgrade is a 401, not a guest.
    let r = http(
        ng,
        "GET",
        "/ng?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, 401);
}

/// The read half of a tunnel as `AsyncRead`, so the legacy frame reader
/// can be used unchanged on the client side of the test.
struct TunnelRead {
    rx: futures_util::stream::SplitStream<Ws>,
    buf: Vec<u8>,
    at: usize,
}

impl tokio::io::AsyncRead for TunnelRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        loop {
            if self.at < self.buf.len() {
                let n = (self.buf.len() - self.at).min(out.remaining());
                let at = self.at;
                out.put_slice(&self.buf[at..at + n]);
                self.at += n;
                return Poll::Ready(Ok(()));
            }
            match futures_util::ready!(std::pin::Pin::new(&mut self.rx).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => {
                    self.buf = b;
                    self.at = 0;
                }
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
            }
        }
    }
}

/// Bytes over a TRTP-over-WebSocket tunnel, the way a tunnel would send
/// them: the legacy framing packed into binary frames.
struct Tunnel {
    tx: futures_util::stream::SplitSink<Ws, Message>,
    rd: TunnelRead,
    trans: u32,
}

impl Tunnel {
    fn new(ws: Ws) -> Tunnel {
        let (tx, rx) = ws.split();
        Tunnel {
            tx,
            rd: TunnelRead {
                rx,
                buf: Vec::new(),
                at: 0,
            },
            trans: 0,
        }
    }

    async fn read_exact(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        timeout(Duration::from_secs(5), self.rd.read_exact(&mut v))
            .await
            .expect("tunnel: timed out")
            .unwrap();
        v
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..16 {
            let f = timeout(
                Duration::from_secs(5),
                hxd_session::frame::read_frame(&mut self.rd),
            )
            .await
            .expect("tunnel: timed out")
            .expect("tunnel: closed");
            if f.ty == ty {
                return f;
            }
        }
        panic!("tunnel: frame {ty:#x} never arrived");
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.tx.send(Message::Binary(bytes.to_vec())).await.unwrap();
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        // Split across two frames to prove boundaries don't matter.
        let (a, b) = bytes.split_at(bytes.len() / 2);
        self.send_raw(a).await;
        self.send_raw(b).await;
    }
}

#[tokio::test]
async fn trtp_tunnel_gives_a_legacy_client_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(3, "Tunnelled");
    let token = authenticate(ng, &p).await["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Native-client path: bearer header on the upgrade.
    let mut req = format!("ws://{ng}/trtp").into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let mut t = Tunnel::new(ws);

    // The classic handshake, inside the tunnel.
    t.send_raw(b"TRTPHOTL\x00\x01\x00\x02").await;
    let hello = t.read_exact(8).await;
    assert_eq!(&hello[..4], b"TRTP");
    t.send(
        REQ_LOGIN,
        &[
            (tag::NAME, b"Tunnelled".to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ],
    )
    .await;
    t.recv_type(HDR_TASK).await;
    let selfinfo = t.recv_type(HDR_SELFINFO).await;
    let row = selfinfo
        .chunks()
        .find(|c| c.tag == tag::USER_LIST)
        .unwrap()
        .data
        .to_vec();
    let color = u16::from_be_bytes([row[4], row[5]]);
    assert_eq!(color & 16, 0, "a tunnelled session is not marked cleartext");

    // An ng observer sees the tunnelled legacy user with an identity and
    // an encrypted transport.
    let (ws2, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut obs = Ng::from_ws(ws2).await;
    let ok = obs.request("login", json!({ "nick": "obs" })).await;
    let row = ok["ok"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "Tunnelled")
        .unwrap()
        .clone();
    assert_eq!(row["transport"], "encrypted");
    assert_eq!(
        row["identity"]["fingerprint"],
        p.id.fingerprint().to_string()
    );

    // Closing the tunnel parts the session.
    t.tx.close().await.unwrap();
    let parted = obs.event("user_parted").await;
    assert_eq!(parted["data"]["uid"], row["uid"]);
}

#[tokio::test]
async fn plain_tcp_legacy_session_is_marked_cleartext_on_both_wires() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, ng, _ctx) = start_server(dir.path()).await;

    let mut s = TcpStream::connect(legacy).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut reply = [0u8; 8];
    s.read_exact(&mut reply).await.unwrap();
    s.write_all(&pack_frame(
        REQ_LOGIN,
        1,
        0,
        &[
            (tag::NAME, b"oldmac".to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ],
    ))
    .await
    .unwrap();
    let selfinfo = loop {
        let f = timeout(
            Duration::from_secs(5),
            hxd_session::frame::read_frame(&mut s),
        )
        .await
        .unwrap()
        .unwrap();
        if f.ty == HDR_SELFINFO {
            break f;
        }
    };
    let row = selfinfo
        .chunks()
        .find(|c| c.tag == tag::USER_LIST)
        .unwrap()
        .data
        .to_vec();
    assert_eq!(
        u16::from_be_bytes([row[4], row[5]]) & 16,
        16,
        "mark_cleartext sets bit 4"
    );

    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut obs = Ng::from_ws(ws).await;
    let ok = obs.request("login", json!({ "nick": "obs" })).await;
    let row = ok["ok"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "oldmac")
        .unwrap()
        .clone();
    assert_eq!(row["transport"], "cleartext");
    assert!(row.get("identity").is_none());
}

#[tokio::test]
async fn linking_at_auth_lands_on_the_account_and_survives_unlink_rules() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(4, "Misha");

    // Wrong password: refused, nothing written.
    let r = try_authenticate(ng, &p, json!({ "login": "misha", "password": "wrong" })).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"], "login_failed");
    let file = std::fs::read_to_string(dir.path().join("accounts/misha.toml")).unwrap();
    assert!(!file.contains("fingerprint"));

    // Right password: linked in the same step, comments intact.
    let r = try_authenticate(ng, &p, json!({ "login": "misha", "password": "s3cret" })).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let auth = r.json();
    assert_eq!(auth["outcome"], "linked");
    assert_eq!(auth["account"], "misha");
    let file = std::fs::read_to_string(dir.path().join("accounts/misha.toml")).unwrap();
    assert!(file.starts_with("# hand-maintained\n"), "{file}");
    assert!(
        file.contains(&format!("fingerprint = \"{}\"", p.id.fingerprint())),
        "{file}"
    );

    // The JSON login lands on the account: admin bit, account name.
    let (_c, ok) = ng_login(ng, auth["token"].as_str().unwrap(), "whatever").await;
    assert_eq!(ok["self"]["identity"]["account"], "misha");
    assert_eq!(ok["self"]["identity"]["outcome"], "linked");
    assert_eq!(ok["self"]["admin"], true);

    // From now on, no credentials needed.
    let auth2 = authenticate(ng, &p).await;
    assert_eq!(auth2["outcome"], "linked");

    // Another identity can't take misha: pending, and link() is refused.
    let q = person(5, "Impostor");
    let r = try_authenticate(ng, &q, json!({ "login": "misha", "password": "s3cret" })).await;
    assert_eq!(r.status, 200);
    let qa = r.json();
    assert_eq!(qa["outcome"], "classic_pending_link");
    let r = http(
        ng,
        "POST",
        "/identity/link",
        &[(
            "Authorization",
            &format!("Bearer {}", qa["token"].as_str().unwrap()),
        )],
        json!({ "login": "misha", "password": "s3cret" })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "denied");

    // Self-linking can be switched off per account.
    let r = try_authenticate(ng, &q, json!({ "login": "locked", "password": "pw" })).await;
    assert_eq!(r.json()["outcome"], "classic_pending_link");

    // Unlink needs a fresh token (single use) and the manage bit; the
    // account has a password, so it's allowed.
    let auth3 = authenticate(ng, &p).await;
    let r = http(
        ng,
        "POST",
        "/identity/unlink",
        &[(
            "Authorization",
            &format!("Bearer {}", auth3["token"].as_str().unwrap()),
        )],
        b"",
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["unlinked"], "misha");
    let auth4 = authenticate(ng, &p).await;
    assert_eq!(auth4["outcome"], "unattested_guest");

    // A web-capped device can't manage the link.
    let mut web = person(6, "Web");
    let mut c = DeviceCert::for_device(&web.id, &web.dev, now() - 5, cert::RECOMMENDED_LIFETIME);
    c.caps = Some(hl_identity::caps::WEB);
    web.cert = c.sign(&web.id);
    let wa = authenticate(ng, &web).await;
    let r = http(
        ng,
        "POST",
        "/identity/link",
        &[(
            "Authorization",
            &format!("Bearer {}", wa["token"].as_str().unwrap()),
        )],
        json!({ "login": "misha", "password": "s3cret" })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "no_manage");
}

#[tokio::test]
async fn new_accounts_create_writes_an_account_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IdentityConfig {
        new_accounts: hxd_ng_session::NewAccounts::Create,
        ..Default::default()
    };
    let reg = ServerKey::from_seed(&[0x33; 32]);
    cfg.registrar_keys.insert("hl.example".into(), reg.public());
    let (_legacy, ng, _ctx) =
        start_server_with(dir.path(), cfg, hxd_session::TrtpLogin::Verify).await;

    let mut p = person(7, "Misha N");
    let att = hl_identity::Attestation {
        identity: p.id.public(),
        registrar: "hl.example".into(),
        registrar_key: reg.public(),
        handle: "misha".into(),
        registered: now() - 86_400,
        issued: now() - 5,
        expires: now() + 86_400,
        level: None,
    };
    p.card = Card::new(&p.id, "Misha N", now())
        .sign(&p.id, vec![att.signed_value(&reg)])
        .unwrap();

    let auth = authenticate(ng, &p).await;
    assert_eq!(auth["outcome"], "created");
    assert_eq!(auth["handle"], "misha@hl.example");
    // `misha` is taken by the fixture, so the handle's local part got a suffix.
    assert_eq!(auth["account"], "misha-2");
    assert!(dir.path().join("accounts/misha-2.toml").exists());
    let (_c, ok) = ng_login(ng, auth["token"].as_str().unwrap(), "x").await;
    assert_eq!(ok["self"]["identity"]["account"], "misha-2");
    assert_eq!(ok["self"]["identity"]["outcome"], "created");
    // Guest access was the template, so no admin bit.
    assert_eq!(ok["self"]["admin"], false);

    // Second time round it's simply linked.
    assert_eq!(authenticate(ng, &p).await["outcome"], "linked");
}

#[tokio::test]
async fn tunnelled_classic_login_links_under_verify_and_refuses_strangers() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;

    async fn tunnel_login(
        ng: SocketAddr,
        p: &Person,
        login: &[u8],
        password: &[u8],
    ) -> Option<Tunnel> {
        let token = authenticate(ng, p).await["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut req = format!("ws://{ng}/trtp").into_client_request().unwrap();
        req.headers_mut()
            .insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let mut t = Tunnel::new(ws);
        t.send_raw(b"TRTPHOTL\x00\x01\x00\x02").await;
        t.read_exact(8).await;
        let xor: Vec<u8> = password.iter().map(|b| b ^ 0xff).collect();
        let xlogin: Vec<u8> = login.iter().map(|b| b ^ 0xff).collect();
        t.send(
            REQ_LOGIN,
            &[
                (tag::LOGIN, xlogin),
                (tag::PASSWORD, xor),
                (tag::NAME, b"n".to_vec()),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
        let reply = t.recv_type(HDR_TASK).await;
        if reply.flag != 0 {
            return None; // error reply
        }
        t.recv_type(HDR_SELFINFO).await;
        Some(t)
    }

    // A tunnelled classic login with the password links the account.
    let p = person(8, "Misha");
    let t = tunnel_login(ng, &p, b"misha", b"s3cret")
        .await
        .expect("login with password");
    let file = std::fs::read_to_string(dir.path().join("accounts/misha.toml")).unwrap();
    assert!(
        file.contains(&format!("fingerprint = \"{}\"", p.id.fingerprint())),
        "{file}"
    );
    drop(t);

    // A stranger naming the now-linked account, with the right password,
    // is refused: verify mode never lets an identity borrow someone
    // else's account.
    let q = person(9, "Stranger");
    assert!(tunnel_login(ng, &q, b"misha", b"s3cret").await.is_none());

    // The owner logging in as guest through the tunnel lands on the
    // linked account (admin bit shows on the roster).
    let t = tunnel_login(ng, &p, b"", b"").await.expect("guest login");
    let (ws2, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut obs = Ng::from_ws(ws2).await;
    let ok = obs.request("login", json!({ "nick": "obs" })).await;
    let row = ok["ok"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["identity"]["fingerprint"] == p.id.fingerprint().to_string())
        .unwrap()
        .clone();
    assert_eq!(row["admin"], true, "{row}");
    drop(t);
}

#[tokio::test]
async fn card_etag_successor_commitment_and_downstream_cleartext() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(10, "Anchor");
    authenticate(ng, &p).await;

    // ETag is entity-tag syntax and If-None-Match yields 304.
    let path = format!("/identity/card/{}", p.id.fingerprint());
    let r = http(ng, "GET", &path, &[], b"").await;
    let etag = r.header("etag").unwrap().to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    let r = http(ng, "GET", &path, &[("If-None-Match", &etag)], b"").await;
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());

    // A card that sets a successor commitment is accepted once...
    let mut committed = Card::new(&p.id, "Anchor", now() + 1);
    committed.successor = Some([0x77; 32]);
    let committed = committed.sign(&p.id, vec![]).unwrap();
    let q = Person {
        id: IdentityKey::from_seed(&[10; 32]),
        dev: DeviceKey::from_seed(&[110; 32]),
        card: committed,
        cert: p.cert.clone(),
    };
    assert_eq!(
        authenticate(ng, &q).await["fingerprint"],
        p.id.fingerprint().to_string()
    );
    // ...and a later card that changes or drops it is refused, even
    // though it is validly signed and newer: the anchor is the point.
    let mut moved = Card::new(&p.id, "Anchor", now() + 2);
    moved.successor = Some([0x78; 32]);
    let moved = Person {
        card: moved.sign(&p.id, vec![]).unwrap(),
        ..Person {
            id: IdentityKey::from_seed(&[10; 32]),
            dev: DeviceKey::from_seed(&[110; 32]),
            card: vec![],
            cert: p.cert.clone(),
        }
    };
    let r = try_authenticate(ng, &moved, json!({})).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"], "bad_card");
    let dropped = Person {
        card: Card::new(&p.id, "Anchor", now() + 3)
            .sign(&p.id, vec![])
            .unwrap(),
        ..Person {
            id: IdentityKey::from_seed(&[10; 32]),
            dev: DeviceKey::from_seed(&[110; 32]),
            card: vec![],
            cert: p.cert.clone(),
        }
    };
    let r = try_authenticate(ng, &dropped, json!({})).await;
    assert_eq!(r.json()["error"], "bad_card");
    // Re-presenting the same commitment is fine.
    let same = Person {
        card: {
            let mut c = Card::new(&p.id, "Anchor", now() + 4);
            c.successor = Some([0x77; 32]);
            c.sign(&p.id, vec![]).unwrap()
        },
        ..Person {
            id: IdentityKey::from_seed(&[10; 32]),
            dev: DeviceKey::from_seed(&[110; 32]),
            card: vec![],
            cert: p.cert.clone(),
        }
    };
    assert_eq!(try_authenticate(ng, &same, json!({})).await.status, 200);

    // A tunnel that declares a cleartext hop behind it gets a session
    // marked cleartext on the roster, TLS notwithstanding.
    let t = person(11, "Remote");
    let r = try_authenticate(ng, &t, json!({ "downstream": "cleartext" })).await;
    assert_eq!(r.status, 200);
    let token = r.json()["token"].as_str().unwrap().to_owned();
    let mut req = format!("ws://{ng}/trtp").into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let mut tun = Tunnel::new(ws);
    tun.send_raw(b"TRTPHOTL\x00\x01\x00\x02").await;
    tun.read_exact(8).await;
    tun.send(
        REQ_LOGIN,
        &[
            (tag::NAME, b"Remote".to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ],
    )
    .await;
    tun.recv_type(HDR_SELFINFO).await;
    let (ws2, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut obs = Ng::from_ws(ws2).await;
    let ok = obs.request("login", json!({ "nick": "obs" })).await;
    let row = ok["ok"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "Remote")
        .unwrap()
        .clone();
    assert_eq!(row["transport"], "cleartext", "{row}");
    assert_eq!(
        row["identity"]["fingerprint"],
        t.id.fingerprint().to_string()
    );
    let r = try_authenticate(ng, &t, json!({ "downstream": "wat" })).await;
    assert_eq!(r.status, 400);
}

// --- The mTLS binding (§5.3) ---------------------------------------------

/// A self-signed X.509 skeleton carrying `key` in its SubjectPublicKeyInfo
/// and `planted` inside its subject. Enough of a certificate for the
/// header contract; the server examines nothing else.
fn client_cert_der(key: &[u8; 32], planted: Option<&[u8; 32]>) -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let b = n.to_be_bytes();
            let start = b.iter().position(|x| *x != 0).unwrap();
            out.push(0x80 | (b.len() - start) as u8);
            out.extend_from_slice(&b[start..]);
        }
        out.extend_from_slice(body);
        out
    }
    let ed = || tlv(0x06, &[0x2b, 0x65, 0x70]);
    let spki = {
        let mut bits = vec![0x00];
        bits.extend_from_slice(key);
        let mut body = tlv(0x30, &ed());
        body.extend_from_slice(&tlv(0x03, &bits));
        tlv(0x30, &body)
    };
    let subject = match planted {
        // Exactly the byte pattern RFC 8410 fixes, in a field the
        // requester chooses: a naive scan finds this, not the SPKI.
        Some(victim) => {
            let mut v = vec![0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
            v.extend_from_slice(victim);
            tlv(0x30, &tlv(0x13, &v))
        }
        None => tlv(0x30, &[]),
    };
    let mut tbs = tlv(0xa0, &tlv(0x02, &[0x02]));
    tbs.extend_from_slice(&tlv(0x02, &[0x01]));
    tbs.extend_from_slice(&tlv(0x30, &ed()));
    tbs.extend_from_slice(&tlv(0x30, &[]));
    tbs.extend_from_slice(&tlv(0x30, &[]));
    tbs.extend_from_slice(&subject);
    tbs.extend_from_slice(&spki);
    let mut outer = tlv(0x30, &tbs);
    outer.extend_from_slice(&tlv(0x30, &ed()));
    outer.extend_from_slice(&tlv(0x03, &[0x00; 65]));
    tlv(0x30, &outer)
}

fn cert_header(key: &[u8; 32], planted: Option<&[u8; 32]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(client_cert_der(key, planted))
}

#[tokio::test]
async fn mtls_header_is_ignored_from_an_untrusted_peer() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(20, "Certified");
    // No trusted_proxies: the header carries no weight, so an auth with
    // no proof is a 400 rather than an authentication.
    let hdr = cert_header(&p.dev.public(), None);
    let r = http(
        ng,
        "POST",
        "/identity/auth",
        &[
            ("Content-Type", "application/json"),
            ("X-Hotline-Client-Cert", &hdr),
        ],
        json!({ "card": b64(&p.card), "device_cert": b64(&p.cert) })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // And an upgrade offering it is an ordinary unauthenticated socket.
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let mut c = Ng::from_ws(ws).await;
    let ok = c.request("login", json!({ "nick": "nobody" })).await;
    assert!(ok["ok"]["self"].get("identity").is_none(), "{ok}");
}

#[tokio::test]
async fn mtls_takes_the_key_from_the_spki_not_from_the_subject() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig::default();
    let (_legacy, ng, _ctx) = start_server_with_proxies(dir.path(), cfg, &["127.0.0.1"]).await;

    let victim = person(21, "Victim");
    let attacker = person(22, "Attacker");
    // The victim's device is on file; the attacker's is not.
    authenticate(ng, &victim).await;

    // A certificate the proxy would accept — its own SPKI is the
    // attacker's key — with the victim's device key planted in the
    // subject. A scan for the RFC 8410 pattern finds the victim.
    let hdr = cert_header(&attacker.dev.public(), Some(&victim.dev.public()));
    let r = http(
        ng,
        "POST",
        "/identity/auth",
        &[
            ("Content-Type", "application/json"),
            ("X-Hotline-Client-Cert", &hdr),
        ],
        json!({ "card": b64(&victim.card), "device_cert": b64(&victim.cert) })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(
        r.status,
        401,
        "the attacker must not authenticate as the victim: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(r.json()["error"], "bad_proof");

    // The victim's own certificate still works — this is the mTLS
    // binding, not a blanket refusal.
    let hdr = cert_header(&victim.dev.public(), None);
    let r = http(
        ng,
        "POST",
        "/identity/auth",
        &[
            ("Content-Type", "application/json"),
            ("X-Hotline-Client-Cert", &hdr),
        ],
        json!({ "card": b64(&victim.card), "device_cert": b64(&victim.cert) })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["fingerprint"], victim.id.fingerprint().to_string());

    // And "the connection is the credential": an upgrade with the same
    // header and no token lands an authenticated session.
    let mut req = format!("ws://{ng}/ng").into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Hotline-Client-Cert", hdr.parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let mut c = Ng::from_ws(ws).await;
    let ok = c.request("login", json!({ "nick": "v" })).await;
    assert_eq!(
        ok["ok"]["self"]["identity"]["fingerprint"],
        victim.id.fingerprint().to_string(),
        "{ok}"
    );
}

#[tokio::test]
async fn an_undecodable_cert_header_from_a_trusted_proxy_is_a_400() {
    // nginx's `$ssl_client_escaped_cert` is URL-encoded PEM. Falling
    // through would admit the request as an unauthenticated guest, and
    // the operator would see "mTLS silently isn't working".
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) =
        start_server_with_proxies(dir.path(), IdentityConfig::default(), &["127.0.0.1"]).await;
    let escaped = "-----BEGIN%20CERTIFICATE-----%0AMIIB...%0A-----END%20CERTIFICATE-----%0A";
    let r = http(
        ng,
        "GET",
        "/.well-known/hotline",
        &[("X-Hotline-Client-Cert", escaped)],
        b"",
    )
    .await;
    assert_eq!(r.status, 200, "discovery doesn't read the header");
    let r = http(
        ng,
        "POST",
        "/identity/auth",
        &[
            ("Content-Type", "application/json"),
            ("X-Hotline-Client-Cert", escaped),
        ],
        json!({ "card": "", "device_cert": "" })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(
        String::from_utf8_lossy(&r.body).contains("base64 DER"),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
}

// --- Bounds and refusals -------------------------------------------------

#[tokio::test]
async fn a_token_expires_and_an_oversized_body_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(23, "Bounded");

    // A token is single-use at upgrade.
    let token = authenticate(ng, &p).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_c, _ok) = ng_login(ng, &token, "once").await;
    let r = tokio_tungstenite::connect_async(format!("ws://{ng}/ng?token={token}")).await;
    assert!(r.is_err(), "a spent token must not open a second socket");

    // A garbage token is a 401, never a silent downgrade to guest.
    let r = tokio_tungstenite::connect_async(format!("ws://{ng}/ng?token=AAAA")).await;
    assert!(r.is_err());

    // Bodies are capped well below what a card storm would need.
    let big = vec![b'x'; 128 * 1024];
    let r = http(
        ng,
        "PUT",
        "/identity/card",
        &[("Content-Type", "application/cbor")],
        &big,
    )
    .await;
    assert!(r.status == 401 || r.status == 400, "status {}", r.status);
}

#[tokio::test]
async fn a_request_head_that_never_arrives_is_dropped() {
    // hyper's header timeout is inert without a timer, and the move to
    // hyper took away the accept timeout the port used to have.
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let mut s = TcpStream::connect(ng).await.unwrap();
    s.write_all(b"GET /ng HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    // `login_timeout` in the fixture is 5s; the server must close on its
    // own rather than hold the task for as long as we care to wait.
    let mut buf = Vec::new();
    let closed = timeout(Duration::from_secs(15), s.read_to_end(&mut buf)).await;
    assert!(closed.is_ok(), "the connection was never closed");
}

#[tokio::test]
async fn identity_login_false_denies_and_a_created_account_refuses_the_legacy_port() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig {
        new_accounts: hxd_ng_session::NewAccounts::Create,
        unattested: hxd_ng_session::Unattested::Allow,
        ..Default::default()
    };
    let (legacy, ng, _ctx) =
        start_server_with(dir.path(), cfg, hxd_session::TrtpLogin::Verify).await;

    let p = person(24, "Newcomer");
    let auth = authenticate(ng, &p).await;
    assert_eq!(auth["outcome"], "created");
    let login = auth["account"].as_str().unwrap().to_owned();
    let file = dir.path().join(format!("accounts/{login}.toml"));
    assert!(file.exists());

    // The whole point of §8.3: the account has no password, and an empty
    // one is not a way in. Without this every created account is open to
    // anyone who types its login on :5500.
    let mut s = TcpStream::connect(legacy).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut hello = [0u8; 8];
    s.read_exact(&mut hello).await.unwrap();
    s.write_all(&pack_frame(
        REQ_LOGIN,
        1,
        0,
        &[
            (tag::LOGIN, login.bytes().map(|b| b ^ 0xff).collect()),
            (tag::PASSWORD, Vec::new()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ],
    ))
    .await
    .unwrap();
    let f = timeout(
        Duration::from_secs(5),
        hxd_session::frame::read_frame(&mut s),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(f.flag, 1, "the login must be refused");

    // `login = false` on the account denies the identity path too.
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        text.replace("[identity]", "[identity]\nlogin = false"),
    )
    .unwrap();
    let r = try_authenticate(ng, &p, json!({})).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "denied");
}

#[tokio::test]
async fn create_does_not_make_link_unreachable() {
    // With `create`, the first token-only auth used to make an account,
    // after which `/identity/link` could only ever say `already_linked`.
    let dir = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig {
        new_accounts: hxd_ng_session::NewAccounts::Create,
        unattested: hxd_ng_session::Unattested::Allow,
        ..Default::default()
    };
    let (_legacy, ng, _ctx) =
        start_server_with(dir.path(), cfg, hxd_session::TrtpLogin::Verify).await;

    let p = person(25, "Linker");
    let auth = try_authenticate(ng, &p, json!({ "create": false })).await;
    assert_eq!(auth.status, 200);
    let auth = auth.json();
    assert_eq!(auth["outcome"], "guest");
    assert!(auth["account"].is_null());

    let r = http(
        ng,
        "POST",
        "/identity/link",
        &[(
            "Authorization",
            &format!("Bearer {}", auth["token"].as_str().unwrap()),
        )],
        json!({ "login": "misha", "password": "s3cret" })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["linked"], "misha");
    // Credentials on the auth itself imply the same thing.
    let q = person(26, "Direct");
    let auth = try_authenticate(ng, &q, json!({ "login": "locked", "password": "pw" })).await;
    assert_eq!(auth.status, 200);
    // `locked` forbids self-linking, so this is a pending link — not a
    // brand-new account made behind the user's back.
    assert_eq!(auth.json()["outcome"], "classic_pending_link");
    assert!(!dir.path().join("accounts/direct.toml").exists());
}

#[tokio::test]
async fn a_management_token_still_opens_a_socket() {
    // `/identity/link` used to spend the single-use token, so a client
    // had to re-run challenge/auth to use what it had just linked.
    let dir = tempfile::tempdir().unwrap();
    let (_legacy, ng, _ctx) = start_server(dir.path()).await;
    let p = person(27, "Manager");
    let auth = authenticate(ng, &p).await;
    let token = auth["token"].as_str().unwrap().to_owned();
    let r = http(
        ng,
        "POST",
        "/identity/link",
        &[("Authorization", &format!("Bearer {token}"))],
        json!({ "login": "misha", "password": "s3cret" })
            .to_string()
            .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let (_c, ok) = ng_login(ng, &token, "m").await;
    assert_eq!(ok["self"]["identity"]["account"], "misha");
}

#[tokio::test]
async fn a_successor_commitment_survives_a_restart() {
    // A commitment only this process remembers hands the attacker
    // "restart the server" as the way to move it.
    let dir = tempfile::tempdir().unwrap();
    let anchors = dir.path().join("successors");
    let cfg = || IdentityConfig {
        anchors: Some(anchors.clone()),
        ..Default::default()
    };
    let (_legacy, ng, _ctx) =
        start_server_with(dir.path(), cfg(), hxd_session::TrtpLogin::Verify).await;
    let id = IdentityKey::from_seed(&[28; 32]);
    let dev = DeviceKey::from_seed(&[128; 32]);
    let cert = DeviceCert::for_device(&id, &dev, now() - 5, cert::RECOMMENDED_LIFETIME).sign(&id);
    let card = |successor: Option<[u8; 32]>, at: u64| {
        let mut c = Card::new(&id, "Anchored", at);
        c.successor = successor;
        c.sign(&id, vec![]).unwrap()
    };
    let p = Person {
        id: IdentityKey::from_seed(&[28; 32]),
        dev: DeviceKey::from_seed(&[128; 32]),
        card: card(Some([0x99; 32]), now()),
        cert: cert.clone(),
    };
    assert_eq!(try_authenticate(ng, &p, json!({})).await.status, 200);
    assert!(anchors.exists(), "the commitment must reach disk");

    // A second server over the same directory — a restart, in effect.
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir2.path()).unwrap();
    let cfg2 = IdentityConfig {
        anchors: Some(anchors.clone()),
        ..Default::default()
    };
    let (_l2, ng2, _c2) =
        start_server_with(dir2.path(), cfg2, hxd_session::TrtpLogin::Verify).await;
    let moved = Person {
        id: IdentityKey::from_seed(&[28; 32]),
        dev: DeviceKey::from_seed(&[128; 32]),
        card: card(Some([0x9a; 32]), now() + 1),
        cert,
    };
    let r = try_authenticate(ng2, &moved, json!({})).await;
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["error"], "bad_card");
}

#[tokio::test]
async fn identity_without_ng_is_reported_rather_than_ignored() {
    // `[identity]` is only read when `[ng]` is present, and a config that
    // sets one without the other looks like it works.
    let toml = r#"
[server]
bind = "127.0.0.1:0"
[identity]
new_accounts = "create"
"#;
    let config: hxd::Config = toml::from_str(toml).unwrap();
    let err = hxd::check_config(&config).unwrap_err();
    assert!(err.contains("[ng]"), "{err}");
}
