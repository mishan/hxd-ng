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
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
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
        }),
    };
    let identity = IdentityState::new(ServerKey::from_seed(&[0x55; 32]), IdentityConfig::default());
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
            trusted_proxies: Vec::new(),
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
    let ch = http(ng, "POST", "/identity/challenge", &[], b"").await;
    assert_eq!(ch.status, 200);
    let ch = ch.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let server_key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let proof = LoginProof::sign(&p.dev, &challenge, &server_key, now());
    let body = json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) })
        .to_string();
    let auth = http(
        ng,
        "POST",
        "/identity/auth",
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    )
    .await;
    assert_eq!(auth.status, 200, "{}", String::from_utf8_lossy(&auth.body));
    auth.json()
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
