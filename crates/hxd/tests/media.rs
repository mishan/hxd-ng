//! Inline media end to end: one store and one pipeline, reached from
//! both wires against real loopback servers.
//!
//! The images here go through the real codec — these are the tests that
//! would catch a canonicalization that quietly stopped happening — and
//! the handles are the real sixteen bytes, spelled one way for a 1.5
//! client and another for a browser.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::media::MediaConfig;
use hxd_core::{Core, HistoryPolicy};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::media::trans;
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::SqliteStore;
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

/// An SVG, which the capability forbids by name. Long enough to clear
/// the pipeline's "too small to be an image" floor, so that what refuses
/// it is the sniff and not the size.
fn svg_bytes() -> Vec<u8> {
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16'>\
         <rect width='16' height='16' fill='#123456'/><!--{}--></svg>",
        "padding ".repeat(8)
    )
    .into_bytes()
}

/// A PNG of noise, which is the fixture the size cases need: a gradient
/// compresses to almost nothing, so a "too large" test built on one
/// would be testing the encoder rather than the cap.
fn noisy_png(w: u32, h: u32) -> Vec<u8> {
    use image::{DynamicImage, ImageEncoder, RgbaImage};
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state & 0xff) as u8
    };
    let mut img = RgbaImage::new(w, h);
    for p in img.pixels_mut() {
        *p = image::Rgba([next(), next(), next(), 0xff]);
    }
    let img = DynamicImage::ImageRgba8(img);
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(std::io::Cursor::new(&mut out))
        .write_image(img.as_bytes(), w, h, img.color().into())
        .unwrap();
    out
}

/// A PNG carrying a text chunk, for the "the server re-encoded" case:
/// what comes back is the server's own encoding, and the proof is that
/// nothing of the sender's metadata is in it.
fn png_with_text(w: u32, h: u32) -> Vec<u8> {
    let png = png(w, h);
    let payload = b"Comment\0a private note";
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"tEXt");
    chunk.extend_from_slice(payload);
    let mut crc_over = b"tEXt".to_vec();
    crc_over.extend_from_slice(payload);
    let mut crc = 0xffff_ffffu32;
    for &b in &crc_over {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    chunk.extend_from_slice(&(!crc).to_be_bytes());
    // After the signature and IHDR.
    let at = 8 + 25;
    let mut out = png[..at].to_vec();
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&png[at..]);
    out
}

/// Does this PNG carry a chunk of this type?
fn has_chunk(png: &[u8], kind: &[u8; 4]) -> bool {
    let mut at = 8;
    while at + 8 <= png.len() {
        let len = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
        if &png[at + 4..at + 8] == kind {
            return true;
        }
        at += 12 + len;
    }
    false
}

/// A small PNG, through the same encoder a client would use.
fn png(w: u32, h: u32) -> Vec<u8> {
    use image::{DynamicImage, ImageEncoder, RgbaImage};
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([(x * 5 % 256) as u8, (y * 3 % 256) as u8, 0x30, 0xff]);
    }
    let img = DynamicImage::ImageRgba8(img);
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(std::io::Cursor::new(&mut out))
        .write_image(img.as_bytes(), w, h, img.color().into())
        .unwrap();
    out
}

/// The two listeners, and the domain behind them — which a moderation
/// test needs, because revoking is an act the wires do not carry yet
/// (moderation.md §5 defines the requests; they land with that branch).
struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
    /// The chat log, when the server has one — so a test can tombstone a
    /// line the way a moderator will, which has no wire surface on this
    /// branch (`moderation.md` owns that).
    log: Option<Arc<SqliteStore>>,
}

async fn start_server(dir: &Path, cfg: MediaConfig) -> (SocketAddr, SocketAddr) {
    let server = start_with(dir, cfg, false, false).await;
    (server.legacy, server.ng)
}

async fn start(dir: &Path, cfg: MediaConfig) -> Server {
    start_with(dir, cfg, false, false).await
}

/// A server that keeps public chat, for the two questions history asks
/// of media: what a page says about an image, and who paging one grants
/// it to.
async fn start_with_history(dir: &Path, cfg: MediaConfig) -> Server {
    start_with(dir, cfg, false, true).await
}

/// `inbox` gives the server a durable store, which is what turns a
/// private message to somebody who is not here into mail rather than a
/// refusal — and what makes an image outlive the moment it was sent.
async fn start_with(dir: &Path, cfg: MediaConfig, inbox: bool, history: bool) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for who in ["alice", "bob"] {
        std::fs::write(
            accounts.join(format!("{who}.toml")),
            format!(
                "name = \"{who}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                 send_chat = true\nsend_msgs = true\nuse_any_name = true\nsend_media = true\n"
            ),
        )
        .unwrap();
    }
    // The account the spec's default describes: everything but the bit.
    std::fs::write(
        accounts.join("nomedia.toml"),
        "name = \"nomedia\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\nuse_any_name = true\n",
    )
    .unwrap();

    let codec = Arc::new(hxd_media::Codec::new(cfg.codec));
    let files = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = Core::new().with_media(codec, cfg);
    let log = history.then(|| {
        Arc::new(
            SqliteStore::open(
                dir.join("history.db"),
                hxd_store_sqlite::Synchronous::Normal,
            )
            .unwrap(),
        )
    });
    let core = match &log {
        Some(store) => core.with_history(
            store.clone(),
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        ),
        None => core,
    };
    let core = if inbox {
        let store = Arc::new(
            SqliteStore::open(
                dir.join("messages.db"),
                hxd_store_sqlite::Synchronous::Normal,
            )
            .unwrap(),
        );
        core.with_inbox(store, files.clone(), Default::default())
    } else {
        core
    };
    let core = Arc::new(core);
    let auth: Arc<dyn hxd_core::AuthBackend> = files;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "media-test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: {
                let base = Caps::empty().with(cap::INLINE_MEDIA);
                if history {
                    base.with(cap::CHAT_HISTORY)
                } else {
                    base
                }
            },
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "media-test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: if history {
                vec!["media".into(), "history".into()]
            } else {
                vec!["media".into()]
            },
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
    };
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        core: legacy_ctx.core.clone(),
        log,
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

/// The defaults, with the ten-second interval out of the way: a test
/// that uploads twice is testing something other than the throttle.
fn media_config() -> MediaConfig {
    MediaConfig {
        upload_interval: Duration::ZERO,
        ..Default::default()
    }
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| !byte).collect()
}

// --- The legacy wire ----------------------------------------------------

struct Legacy {
    stream: TcpStream,
    trans: u32,
}

impl Legacy {
    async fn login(addr: SocketAddr, login: &str, offer_media: bool) -> (Self, Frame) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut chunks = vec![
            (tag::NAME, login.as_bytes().to_vec()),
            (tag::ICON, 128u16.to_be_bytes().to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            (tag::LOGIN, xor(login.as_bytes())),
            (tag::PASSWORD, xor(b"pw")),
        ];
        if offer_media {
            chunks.push((
                tag::CAPABILITIES,
                Caps::empty().with(cap::INLINE_MEDIA).to_wire(),
            ));
        }
        let mut client = Self { stream, trans: 1 };
        client
            .stream
            .write_all(&pack_frame(REQ_LOGIN, 1, 0, &chunks))
            .await
            .unwrap();
        let reply = client.recv_type(HDR_TASK).await;
        assert_eq!(reply.flag, 0, "login refused");
        client.recv_type(HDR_SELFINFO).await;
        (client, reply)
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

    /// One transaction, one reply.
    async fn call(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Frame {
        let trans = self.send(ty, chunks).await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, trans);
        reply
    }

    /// Which uid the user list gives that nick.
    async fn uid_of(&mut self, nick: &str) -> u16 {
        for _ in 0..24 {
            let frame = self.recv_type(0x12d).await;
            let name = field(&frame, tag::NAME).unwrap_or_default();
            if name == nick.as_bytes() {
                return u16::from_be_bytes(field(&frame, tag::UID).unwrap().try_into().unwrap());
            }
        }
        panic!("no user-change push named {nick}");
    }

    /// The same, for an image too big for one 65 535-byte field: the
    /// part machinery, with only the handle kept.
    async fn upload_chunked(&mut self, bytes: &[u8], part: usize) -> Vec<u8> {
        let parts: Vec<&[u8]> = bytes.chunks(part).collect();
        let count = parts.len() as u16;
        let mut token = Vec::new();
        for (n, payload) in parts.iter().enumerate() {
            let last = n + 1 == parts.len();
            let mut chunks = vec![
                (
                    tag::CHAT_MEDIA_PART_INDEX,
                    (n as u16).to_be_bytes().to_vec(),
                ),
                (tag::CHAT_MEDIA_PAYLOAD, payload.to_vec()),
                (tag::CHAT_MEDIA_PART_FINAL, vec![u8::from(last)]),
            ];
            if n == 0 {
                chunks.push((tag::CHAT_MEDIA_DECLARED_TYPE, b"image/png".to_vec()));
                chunks.push((tag::CHAT_MEDIA_PART_COUNT, count.to_be_bytes().to_vec()));
            } else {
                chunks.push((tag::CHAT_MEDIA_UPLOAD_TOKEN, token.clone()));
            }
            let reply = self.call(trans::UPLOAD_MEDIA, &chunks).await;
            assert_eq!(reply.flag, 0, "part {n} refused");
            if n == 0 {
                token = field(&reply, tag::CHAT_MEDIA_UPLOAD_TOKEN).expect("a token");
            }
            if last {
                return field(&reply, tag::CHAT_MEDIA_ID).expect("a handle on the final part");
            }
        }
        unreachable!("a non-empty image has a final part")
    }

    async fn upload(&mut self, bytes: &[u8]) -> Frame {
        self.call(
            trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, bytes.to_vec()),
                (tag::CHAT_MEDIA_DECLARED_TYPE, b"image/png".to_vec()),
                (tag::CHAT_MEDIA_PART_FINAL, vec![1]),
            ],
        )
        .await
    }

    /// The whole image, however many parts it takes.
    async fn download(&mut self, handle: &[u8]) -> (Vec<u8>, String) {
        let (mut out, mut index) = (Vec::new(), 0u16);
        let mut mime;
        loop {
            let reply = self
                .call(
                    trans::DOWNLOAD_MEDIA,
                    &[
                        (tag::CHAT_MEDIA_ID, handle.to_vec()),
                        (tag::CHAT_MEDIA_PART_INDEX, index.to_be_bytes().to_vec()),
                    ],
                )
                .await;
            assert_eq!(reply.flag, 0, "download refused at part {index}");
            out.extend_from_slice(&field(&reply, tag::CHAT_MEDIA_PAYLOAD).unwrap());
            mime = String::from_utf8(field(&reply, tag::CHAT_MEDIA_TYPE).unwrap()).unwrap();
            if field(&reply, tag::CHAT_MEDIA_PART_FINAL).unwrap() != vec![0] {
                return (out, mime);
            }
            index += 1;
        }
    }
}

fn field(frame: &Frame, tag: u16) -> Option<Vec<u8>> {
    frame
        .chunks()
        .find(|c| c.tag == tag)
        .map(|c| c.data.to_vec())
}

fn be32(frame: &Frame, tag: u16) -> Option<u32> {
    field(frame, tag).map(|d| u32::from_be_bytes(d.try_into().unwrap()))
}

fn error_code(frame: &Frame) -> Option<u16> {
    field(frame, tag::CHAT_MEDIA_ERROR_CODE).map(|d| u16::from_be_bytes(d.try_into().unwrap()))
}

// --- The ng wire --------------------------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    events: Vec<Value>,
    bearer: String,
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
        };
        let reply = client
            .request(
                "login",
                json!({ "login": login, "password": "pw", "nick": login }),
            )
            .await;
        assert!(reply.get("ok").is_some(), "{reply}");
        let ok = reply["ok"].clone();
        client.bearer = format!(
            "Bearer {}.{}",
            ok["session"].as_str().unwrap(),
            ok["token"].as_str().unwrap()
        );
        (client, ok)
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let frame = json!({ "id": id, "req": method, "params": params }).to_string();
        self.ws.send(Message::Text(frame)).await.unwrap();
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .unwrap();
            let Message::Text(text) = msg else { continue };
            let value: Value = serde_json::from_str(&text).unwrap();
            if value.get("reply") == Some(&json!(id)) {
                return value;
            }
            if value.get("ev").is_some() {
                self.events.push(value);
            }
        }
    }

    /// Wait for an event of a kind, keeping everything else.
    async fn event(&mut self, kind: &str) -> Value {
        if let Some(pos) = self.events.iter().position(|e| e["ev"] == kind) {
            return self.events.remove(pos);
        }
        for _ in 0..24 {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng timed out")
                .expect("ng closed")
                .unwrap();
            let Message::Text(text) = msg else { continue };
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["ev"] == kind {
                return value;
            }
            if value.get("ev").is_some() {
                self.events.push(value);
            }
        }
        panic!("ng event {kind} did not arrive");
    }
}

// --- A minimal HTTP/1.1 client, enough for one image --------------------

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

async fn ng_upload(addr: SocketAddr, bearer: &str, bytes: &[u8]) -> HttpReply {
    http(
        addr,
        "POST",
        "/media",
        &[("Authorization", bearer), ("Content-Type", "image/png")],
        bytes,
    )
    .await
}

// --- The tests ----------------------------------------------------------

#[tokio::test]
async fn the_legacy_login_advertises_the_bit_and_its_limits() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;

    let (_client, reply) = Legacy::login(legacy, "alice", true).await;
    let caps = Caps::from_wire(&field(&reply, tag::CAPABILITIES).unwrap());
    assert!(caps.has(cap::INLINE_MEDIA), "the bit was echoed");
    // All six, which the spec makes a MUST beside a confirmed bit.
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_BYTES), Some(256 * 1024));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_DIMENSION), Some(2048));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_PIXELS), Some(2048 * 2048));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_CHUNK_SIZE), Some(60_000));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_FRAMES), Some(150));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_DURATION_MS), Some(15_000));

    // A client that did not ask gets neither the bit nor the numbers.
    let (_classic, reply) = Legacy::login(legacy, "bob", false).await;
    assert_eq!(field(&reply, tag::CAPABILITIES), None);
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_MAX_BYTES), None);
}

#[tokio::test]
async fn a_capable_room_sees_the_image_and_a_classic_one_sees_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;

    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;
    let (mut classic, _) = Legacy::login(legacy, "nomedia", false).await;

    // Uploaded with a text chunk in it, so the download can show that
    // what came back is the server's encoding and not the sender's file.
    let sent = png_with_text(24, 16);
    assert!(has_chunk(&sent, b"tEXt"), "the fixture carries metadata");
    let reply = alice.upload(&sent).await;
    assert_eq!(
        reply.flag,
        0,
        "upload refused: {:?} code {:?}",
        field(&reply, tag::TASK_ERROR).map(|d| String::from_utf8_lossy(&d).into_owned()),
        error_code(&reply)
    );
    let handle = field(&reply, tag::CHAT_MEDIA_ID).unwrap();
    assert_eq!(handle.len(), 16, "128 bits of handle");
    assert_eq!(
        field(&reply, tag::CHAT_MEDIA_TYPE).unwrap(),
        b"image/png".to_vec()
    );
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_WIDTH), Some(24));
    assert_eq!(be32(&reply, tag::CHAT_MEDIA_HEIGHT), Some(16));
    let canonical_size = be32(&reply, tag::CHAT_MEDIA_BYTES).unwrap();

    alice
        .send(
            REQ_CHAT,
            &[
                (tag::BODY, b"look at this".to_vec()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;

    // Bob negotiated the bit: he gets the companions, sized so he can
    // draw a placeholder before the bytes arrive.
    let line = bob.recv_type(HDR_CHAT).await;
    assert_eq!(field(&line, tag::CHAT_MEDIA_ID), Some(handle.clone()));
    assert_eq!(be32(&line, tag::CHAT_MEDIA_WIDTH), Some(24));
    assert_eq!(be32(&line, tag::CHAT_MEDIA_BYTES), Some(canonical_size));
    let body = String::from_utf8_lossy(&field(&line, tag::BODY).unwrap()).into_owned();
    assert!(body.contains("look at this"));

    // The classic client sees the same line with nothing added, which is
    // the spec's fallback and the whole reason this is per connection.
    let line = classic.recv_type(HDR_CHAT).await;
    assert_eq!(field(&line, tag::CHAT_MEDIA_ID), None);
    assert_eq!(field(&line, tag::CHAT_MEDIA_TYPE), None);
    let body = String::from_utf8_lossy(&field(&line, tag::BODY).unwrap()).into_owned();
    assert!(body.contains("look at this"));

    // And Bob can fetch what he was shown. The bytes are the server's,
    // not Alice's: it decoded and re-encoded them.
    let (bytes, mime) = bob.download(&handle).await;
    assert_eq!(mime, "image/png");
    assert_eq!(bytes.len() as u32, canonical_size);
    assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));
    assert!(
        !has_chunk(&bytes, b"tEXt"),
        "the sender's metadata came back with the image"
    );
}

#[tokio::test]
async fn a_chunked_upload_and_a_multi_part_download_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;

    // Large enough that the canonical image needs more than one download
    // part at the advertised 60 000-byte chunk size — noise, because a
    // gradient this size still fits in one.
    let image = noisy_png(200, 200);
    assert!(image.len() > 60_000, "the fixture is big enough to slice");
    let parts: Vec<&[u8]> = image.chunks(20_000).collect();
    let count = parts.len() as u16;

    let first = alice
        .call(
            trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, parts[0].to_vec()),
                (tag::CHAT_MEDIA_DECLARED_TYPE, b"image/png".to_vec()),
                (tag::CHAT_MEDIA_PART_INDEX, 0u16.to_be_bytes().to_vec()),
                (tag::CHAT_MEDIA_PART_COUNT, count.to_be_bytes().to_vec()),
                (tag::CHAT_MEDIA_PART_FINAL, vec![0]),
            ],
        )
        .await;
    assert_eq!(first.flag, 0, "the first chunk was refused");
    let token = field(&first, tag::CHAT_MEDIA_UPLOAD_TOKEN).expect("a token for the follow-ups");
    assert_eq!(
        field(&first, tag::CHAT_MEDIA_ID),
        None,
        "no handle until the last part"
    );

    let mut handle = Vec::new();
    for (n, part) in parts.iter().enumerate().skip(1) {
        let last = n + 1 == parts.len();
        let reply = alice
            .call(
                trans::UPLOAD_MEDIA,
                &[
                    (tag::CHAT_MEDIA_UPLOAD_TOKEN, token.clone()),
                    (
                        tag::CHAT_MEDIA_PART_INDEX,
                        (n as u16).to_be_bytes().to_vec(),
                    ),
                    (tag::CHAT_MEDIA_PAYLOAD, part.to_vec()),
                    (tag::CHAT_MEDIA_PART_FINAL, vec![u8::from(last)]),
                ],
            )
            .await;
        assert_eq!(reply.flag, 0, "chunk {n} refused");
        if last {
            handle = field(&reply, tag::CHAT_MEDIA_ID).expect("the handle on the final part");
        }
    }

    alice
        .send(
            REQ_CHAT,
            &[
                (tag::BODY, Vec::new()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;
    bob.recv_type(HDR_CHAT).await;

    let (bytes, _) = bob.download(&handle).await;
    assert!(
        bytes.len() > 60_000,
        "the download really did span several parts"
    );
    assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));
}

#[tokio::test]
async fn a_sliced_download_costs_one_token_however_many_parts_it_takes() {
    // `download_per_minute` is one knob with one meaning, and the ng
    // wire spends it once per image. Charging the legacy wire once per
    // 751 *part* would quietly hand a classic client a fraction of the
    // advertised budget — the fraction being whatever chunk size this
    // server happens to advertise.
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(
        dir.path(),
        MediaConfig {
            download_per_minute: 1,
            ..media_config()
        },
    )
    .await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;

    let image = noisy_png(200, 200);
    assert!(image.len() > 60_000, "the fixture spans several parts");
    let handle = alice.upload_chunked(&image, 20_000).await;
    alice
        .send(
            REQ_CHAT,
            &[
                (tag::BODY, Vec::new()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;
    bob.recv_type(HDR_CHAT).await;

    // One token, and `download` asserts on a refusal at every part.
    let (bytes, _) = bob.download(&handle).await;
    assert!(bytes.len() > 60_000, "the whole image came back");

    // The budget really is spent, though: a restart of the same download
    // is a second one and there is nothing left to pay with.
    let again = bob
        .call(
            trans::DOWNLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_PART_INDEX, 0u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
    assert_ne!(again.flag, 0, "the second download had no token to take");
}

#[tokio::test]
async fn a_download_answers_the_same_way_to_everyone_who_may_not_have_it() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;

    let reply = alice.upload(&png(16, 16)).await;
    let handle = field(&reply, tag::CHAT_MEDIA_ID).unwrap();

    // Bob is on the roster but was never shown this image: nothing was
    // relayed, so nothing captured him.
    let refused = bob
        .call(
            trans::DOWNLOAD_MEDIA,
            &[(tag::CHAT_MEDIA_ID, handle.clone())],
        )
        .await;
    assert_eq!(refused.flag, 1, "a stranger's download was allowed");
    let unauthorized = error_code(&refused);

    // A handle that never existed answers identically — the spec's
    // "never distinguish expired from unauthorized", which is what stops
    // a download being a test for whether a handle exists.
    let bogus = bob
        .call(trans::DOWNLOAD_MEDIA, &[(tag::CHAT_MEDIA_ID, vec![7; 16])])
        .await;
    assert_eq!(bogus.flag, 1);
    assert_eq!(error_code(&bogus), unauthorized);
    assert_eq!(
        field(&bogus, tag::TASK_ERROR),
        field(&refused, tag::TASK_ERROR),
        "the text tells them apart as little as the code does"
    );

    // The uploader can always fetch their own.
    let (bytes, _) = alice.download(&handle).await;
    assert!(!bytes.is_empty());
}

#[tokio::test]
async fn the_pipeline_refuses_what_the_spec_forbids() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(
        dir.path(),
        MediaConfig {
            max_bytes: 4096,
            upload_interval: Duration::ZERO,
            ..Default::default()
        },
    )
    .await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;

    // Over the size cap: code 1.
    // Noise, and small enough to fit one wire frame: a single-shot
    // upload is one chunk, and the field is sixteen bits wide.
    let too_big = alice.upload(&noisy_png(100, 100)).await;
    assert_eq!(too_big.flag, 1);
    assert_eq!(error_code(&too_big), Some(1));

    // An SVG, which the capability forbids by name: code 2. The declared
    // type is `image/png` and makes no difference — the sniff decides.
    let svg = alice
        .call(
            trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, svg_bytes()),
                (tag::CHAT_MEDIA_DECLARED_TYPE, b"image/png".to_vec()),
                (tag::CHAT_MEDIA_PART_FINAL, vec![1]),
            ],
        )
        .await;
    assert_eq!(svg.flag, 1);
    assert_eq!(error_code(&svg), Some(2));

    // Garbage: the sniff trips before anything else.
    let garbage = alice
        .call(
            trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, vec![0x42; 512]),
                (tag::CHAT_MEDIA_PART_FINAL, vec![1]),
            ],
        )
        .await;
    assert_eq!(garbage.flag, 1);
    assert_eq!(error_code(&garbage), Some(2));

    // A polyglot: a valid PNG with something glued to its tail.
    let mut polyglot = png(8, 8);
    polyglot.extend_from_slice(b"PK\x03\x04and an archive");
    let refused = alice
        .call(
            trans::UPLOAD_MEDIA,
            &[
                (tag::CHAT_MEDIA_PAYLOAD, polyglot),
                (tag::CHAT_MEDIA_PART_FINAL, vec![1]),
            ],
        )
        .await;
    assert_eq!(refused.flag, 1);
    assert_eq!(error_code(&refused), Some(2));

    // And an account without bit 57 cannot upload at all: code 4.
    let (mut nobody, _) = Legacy::login(legacy, "nomedia", true).await;
    let denied = nobody.upload(&png(8, 8)).await;
    assert_eq!(denied.flag, 1);
    assert_eq!(error_code(&denied), Some(4));
}

#[tokio::test]
async fn a_sender_without_the_bit_has_its_media_fields_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;
    // Carol never negotiated, so anything media-shaped she sends is not
    // hers to send — "servers MUST drop these fields from any inbound
    // transaction whose sender did not negotiate the capability".
    let (mut carol, _) = Legacy::login(legacy, "nomedia", false).await;

    let handle = field(&alice.upload(&png(8, 8)).await, tag::CHAT_MEDIA_ID).unwrap();
    carol
        .send(
            REQ_CHAT,
            &[
                (tag::BODY, b"borrowed".to_vec()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;

    let line = bob.recv_type(HDR_CHAT).await;
    let body = String::from_utf8_lossy(&field(&line, tag::BODY).unwrap()).into_owned();
    assert!(body.contains("borrowed"), "the text went through");
    assert_eq!(field(&line, tag::CHAT_MEDIA_ID), None, "the handle did not");
}

#[tokio::test]
async fn a_private_message_carries_an_image_across_the_legacy_wire() {
    let dir = tempfile::tempdir().unwrap();
    let (legacy, _) = start_server(dir.path(), media_config()).await;
    let (mut alice, _) = Legacy::login(legacy, "alice", true).await;
    let (mut bob, _) = Legacy::login(legacy, "bob", true).await;

    // Bob's uid, by name: the pushes Alice has seen include her own
    // join, and taking the first one would address the message to
    // whoever happened to be first.
    let bob_uid = alice.uid_of("bob").await;

    let handle = field(&alice.upload(&png(12, 12)).await, tag::CHAT_MEDIA_ID).unwrap();
    let reply = alice
        .call(
            REQ_MSG,
            &[
                (tag::UID, bob_uid.to_be_bytes().to_vec()),
                (tag::BODY, b"here it is".to_vec()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;
    assert_eq!(
        reply.flag,
        0,
        "the message was refused: {:?}",
        field(&reply, tag::TASK_ERROR).map(|d| String::from_utf8_lossy(&d).into_owned())
    );

    let msg = bob.recv_type(HDR_MSG).await;
    assert_eq!(field(&msg, tag::CHAT_MEDIA_ID), Some(handle.clone()));
    let (bytes, _) = bob.download(&handle).await;
    assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));
}

#[tokio::test]
async fn the_ng_login_carries_the_cap_and_the_limits() {
    let dir = tempfile::tempdir().unwrap();
    let (_, ng) = start_server(dir.path(), media_config()).await;
    let (_client, ok) = Ng::login(ng, "alice").await;

    assert!(ok["caps"].as_array().unwrap().iter().any(|c| c == "media"));
    let media = &ok["media"];
    assert_eq!(media["max_bytes"], json!(256 * 1024));
    assert_eq!(media["max_dimension"], json!(2048));
    assert_eq!(media["max_frames"], json!(150));
    // So a file picker can filter without hard-coding the spec's list.
    assert_eq!(
        media["types"],
        json!(["image/jpeg", "image/png", "image/gif"])
    );
}

#[tokio::test]
async fn an_ng_client_uploads_over_http_and_chats_the_handle() {
    let dir = tempfile::tempdir().unwrap();
    let (_, ng) = start_server(dir.path(), media_config()).await;
    let (mut alice, _) = Ng::login(ng, "alice").await;
    let (mut bob, _) = Ng::login(ng, "bob").await;

    let uploaded = ng_upload(ng, &alice.bearer, &png(20, 10)).await;
    assert_eq!(uploaded.status, 201, "{:?}", uploaded.json());
    let media = uploaded.json()["media"].clone();
    let id = media["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 22, "sixteen bytes, base64url");
    assert_eq!(media["type"], "image/png");
    assert_eq!(media["width"], json!(20));
    assert_eq!(media["height"], json!(10));

    let reply = alice
        .request("chat", json!({ "text": "look", "media": id }))
        .await;
    assert!(reply.get("ok").is_some(), "{reply}");

    let line = bob.event("chat").await;
    assert_eq!(line["data"]["media"]["id"], json!(id));
    assert_eq!(line["data"]["media"]["type"], "image/png");
    assert_eq!(line["data"]["text"], "look");

    // And the bytes come back over HTTP, with the headers that keep a
    // browser from treating them as anything but an image.
    let fetched = http(
        ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", &bob.bearer)],
        b"",
    )
    .await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.header("content-type"), Some("image/png"));
    assert_eq!(fetched.header("x-content-type-options"), Some("nosniff"));
    assert!(fetched
        .header("cache-control")
        .is_some_and(|v| v.contains("private")));
    assert!(fetched.body.starts_with(&[0x89, b'P', b'N', b'G']));
}

#[tokio::test]
async fn every_ng_download_failure_is_a_404() {
    let dir = tempfile::tempdir().unwrap();
    let (_, ng) = start_server(dir.path(), media_config()).await;
    let (alice, _) = Ng::login(ng, "alice").await;
    let (bob, _) = Ng::login(ng, "bob").await;

    let uploaded = ng_upload(ng, &alice.bearer, &png(8, 8)).await;
    let id = uploaded.json()["media"]["id"].as_str().unwrap().to_owned();

    // Never shown it, a handle that does not exist, and one that is not
    // even handle-shaped: one status, one body.
    for path in [
        format!("/media/{id}"),
        "/media/AAAAAAAAAAAAAAAAAAAAAA".into(),
        "/media/nonsense".into(),
    ] {
        let refused = http(ng, "GET", &path, &[("Authorization", &bob.bearer)], b"").await;
        assert_eq!(refused.status, 404, "{path}");
        assert_eq!(refused.json()["error"]["code"], "no_such_media");
    }

    // No credential at all is the one thing that is *not* a 404: there
    // is no session to answer for, and saying so is not a leak.
    let anonymous = http(ng, "GET", &format!("/media/{id}"), &[], b"").await;
    assert_eq!(anonymous.status, 401);
    // A bad one is the same answer.
    let wrong = http(
        ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", "Bearer s_00000001.deadbeef")],
        b"",
    )
    .await;
    assert_eq!(wrong.status, 401);
}

#[tokio::test]
async fn the_ng_upload_maps_each_refusal_onto_a_status() {
    let dir = tempfile::tempdir().unwrap();
    let (_, ng) = start_server(
        dir.path(),
        MediaConfig {
            max_bytes: 4096,
            upload_interval: Duration::ZERO,
            ..Default::default()
        },
    )
    .await;
    let (alice, _) = Ng::login(ng, "alice").await;

    let too_big = ng_upload(ng, &alice.bearer, &noisy_png(128, 128)).await;
    assert_eq!(too_big.status, 413);
    assert_eq!(too_big.json()["error"]["code"], "media_too_large");

    let svg = ng_upload(ng, &alice.bearer, &svg_bytes()).await;
    assert_eq!(svg.status, 415);
    assert_eq!(svg.json()["error"]["code"], "unsupported_media");

    // No bit 57, no upload — 403, and the same generic text the wire
    // gives.
    let (nobody, _) = Ng::login(ng, "nomedia").await;
    let denied = ng_upload(ng, &nobody.bearer, &png(8, 8)).await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.json()["error"]["code"], "access_denied");
}

#[tokio::test]
async fn a_photo_crosses_between_the_two_wires() {
    // The point of the whole design: one store, one handle, two
    // spellings. A photo attached in a 1.5 client is an `<img>` in the
    // browser, and one dropped in the browser is an inline row in the
    // 1.5 client.
    let dir = tempfile::tempdir().unwrap();
    let (legacy, ng) = start_server(dir.path(), media_config()).await;

    let (mut classic, _) = Legacy::login(legacy, "alice", true).await;
    let (mut web, _) = Ng::login(ng, "bob").await;

    // Browser → 1.5 client.
    let uploaded = ng_upload(ng, &web.bearer, &png(18, 9)).await;
    let id = uploaded.json()["media"]["id"].as_str().unwrap().to_owned();
    web.request("chat", json!({ "text": "from the web", "media": id }))
        .await;
    let line = classic.recv_type(HDR_CHAT).await;
    let handle = field(&line, tag::CHAT_MEDIA_ID).expect("the classic client got the handle");
    assert_eq!(be32(&line, tag::CHAT_MEDIA_WIDTH), Some(18));
    let (bytes, mime) = classic.download(&handle).await;
    assert_eq!(mime, "image/png");
    assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));

    // 1.5 client → browser. The same sixteen bytes, spelled base64url.
    let reply = classic.upload(&png(9, 18)).await;
    let handle = field(&reply, tag::CHAT_MEDIA_ID).unwrap();
    classic
        .send(
            REQ_CHAT,
            &[
                (tag::BODY, b"from 1.5".to_vec()),
                (tag::CHAT_MEDIA_ID, handle.clone()),
                (tag::CHAT_MEDIA_TYPE, b"image/png".to_vec()),
            ],
        )
        .await;
    let event = web.event("chat").await;
    let id = event["data"]["media"]["id"].as_str().unwrap().to_owned();
    let fetched = http(
        ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", &web.bearer)],
        b"",
    )
    .await;
    assert_eq!(fetched.status, 200);
    assert_eq!(
        fetched.body.len(),
        event["data"]["media"]["bytes"].as_u64().unwrap() as usize
    );
}

#[tokio::test]
async fn an_image_waits_in_the_inbox_for_a_recipient_who_was_not_here() {
    // The case §9 of the design leads with: mail sent to a phone that
    // was asleep. The handle is captured against the recipient's
    // *mailbox* rather than any session, so whichever session eventually
    // collects the message can fetch the picture too.
    let dir = tempfile::tempdir().unwrap();
    let server = start_with(dir.path(), media_config(), true, false).await;
    let (mut alice, _) = Ng::login(server.ng, "alice").await;

    let uploaded = ng_upload(server.ng, &alice.bearer, &png(14, 7)).await;
    let id = uploaded.json()["media"]["id"].as_str().unwrap().to_owned();
    // Bob is nowhere: no session, no socket. `to_login` is the only way
    // to name him, and the store is what holds it.
    let reply = alice
        .request(
            "msg",
            json!({ "to_login": "bob", "text": "for when you're back", "media": id }),
        )
        .await;
    assert_eq!(reply["ok"]["queued"], json!(true), "{reply}");

    // Bob arrives. The flush hands him the message, image and all.
    let (mut bob, _) = Ng::login(server.ng, "bob").await;
    let msg = bob.event("msg").await;
    assert_eq!(msg["data"]["queued"], json!(true));
    assert_eq!(msg["data"]["media"]["id"], json!(id));
    assert_eq!(msg["data"]["media"]["width"], json!(14));

    let fetched = http(
        server.ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", &bob.bearer)],
        b"",
    )
    .await;
    assert_eq!(fetched.status, 200, "the mailbox's grant outlived the send");

    // And the pull side says the same thing as the push side: the
    // `inbox` listing carries the reference too, so a client that woke
    // to a push and asked rather than waiting sees the same message.
    let listed = bob.request("inbox", json!({})).await;
    let first = &listed["ok"]["messages"][0];
    assert_eq!(first["media"]["id"], json!(id));
    assert_eq!(first["text"], "for when you're back");
}

#[tokio::test]
async fn a_revocation_stops_the_next_download_and_tells_the_room() {
    // The media half of moderation.md §3.2, from the domain — the wire
    // requests that will call it land with that document's own branch.
    // What matters here is what the two wires do either side of it.
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path(), media_config()).await;
    let (mut classic, _) = Legacy::login(server.legacy, "alice", true).await;
    let (mut web, _) = Ng::login(server.ng, "bob").await;

    let uploaded = ng_upload(server.ng, &web.bearer, &png(16, 16)).await;
    let id = uploaded.json()["media"]["id"].as_str().unwrap().to_owned();
    web.request("chat", json!({ "text": "look", "media": id }))
        .await;
    let line = classic.recv_type(HDR_CHAT).await;
    let handle: Vec<u8> = field(&line, tag::CHAT_MEDIA_ID).unwrap();
    // Both wires spell one handle.
    let raw: [u8; 16] = handle.clone().try_into().unwrap();
    assert_eq!(hxd_core::media::handle_str(&raw), id);
    classic.download(&handle).await;

    let reference = server.core.media_revoke(&raw, true).expect("a live handle");
    assert_eq!(reference.id, None, "the handle stops resolving");
    // The metadata survives, so a line that carried it still renders a
    // placeholder rather than nothing.
    assert_eq!((reference.width, reference.height), (16, 16));

    // The 1.5 client keeps the line it already rendered — this wire has
    // no transaction to unsend a 106 — and its next download is
    // refused, with the same answer a bogus handle gets.
    let refused = classic
        .call(trans::DOWNLOAD_MEDIA, &[(tag::CHAT_MEDIA_ID, handle)])
        .await;
    assert_eq!(refused.flag, 1);
    assert_eq!(error_code(&refused), Some(4));

    // The browser, which can say so, is told: it drops the image and
    // keeps the placeholder.
    let revoked = web.event("media_revoked").await;
    assert_eq!(revoked["data"]["id"], json!(id));
    let gone = http(
        server.ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", &web.bearer)],
        b"",
    )
    .await;
    assert_eq!(gone.status, 404);

    // And the same file cannot come back: the block is on the canonical
    // hash, so re-uploading the same image is refused (moderation.md
    // §3.2 — a nuisance filter, not a fingerprint system).
    let again = ng_upload(server.ng, &web.bearer, &png(16, 16)).await;
    assert_eq!(again.status, 400);
    assert_eq!(again.json()["error"]["code"], "media_rejected");
}

#[tokio::test]
async fn paging_a_deleted_line_grants_its_image_to_nobody() {
    // `history_access = "readers"` is the operator's other answer: a
    // public line's audience is everyone holding read-chat, so paging
    // one grants the image (§5.4). A *redacted* line is not that. The
    // page already withholds the handle and says `removed`, but the
    // grant is a separate act with a separate consequence — it never
    // expires — and a reader who was shown nothing must be granted
    // nothing.
    let dir = tempfile::tempdir().unwrap();
    let server = start_with_history(
        dir.path(),
        MediaConfig {
            history_access: hxd_core::HistoryAccess::Readers,
            ..media_config()
        },
    )
    .await;
    let (mut alice, _) = Ng::login(server.ng, "alice").await;

    let uploaded = ng_upload(server.ng, &alice.bearer, &png(16, 16)).await;
    let id = uploaded.json()["media"]["id"].as_str().unwrap().to_owned();
    let reply = alice
        .request("chat", json!({ "text": "look", "media": id }))
        .await;
    assert!(reply.get("ok").is_some(), "{reply}");
    // A sender sees its own echo, and that is where the durable id is.
    let line_id = alice.event("chat").await["data"]["id"]
        .as_u64()
        .expect("a durable line id");

    // A moderator takes the line down. The bytes are not revoked — this
    // is a redaction, and the handle is still perfectly live, which is
    // what makes the grant reachable at all.
    use hxd_core::history::ChatLog;
    assert!(server
        .log
        .as_ref()
        .expect("a log")
        .tombstone(line_id, std::time::SystemTime::now())
        .unwrap());

    // Bob arrives afterwards: he never saw the line live, so nothing has
    // captured him.
    let (mut bob, _) = Ng::login(server.ng, "bob").await;
    let page = bob.request("history", json!({ "limit": 10 })).await;
    let lines = page["ok"]["lines"].as_array().expect("a page").clone();
    let row = lines
        .iter()
        .find(|l| l["id"].as_u64() == Some(line_id))
        .expect("the redacted line is still in the page");
    assert_eq!(row["deleted"], json!(true));
    assert_eq!(row["media"]["removed"], json!(true));
    assert_eq!(row["media"]["id"], Value::Null, "the handle was withheld");

    // And it was withheld *and* ungranted: the handle the test knows
    // still resolves for nobody Bob is.
    let refused = http(
        server.ng,
        "GET",
        &format!("/media/{id}"),
        &[("Authorization", &bob.bearer)],
        b"",
    )
    .await;
    assert_eq!(
        refused.status, 404,
        "the handle resolved for a reader who was shown nothing"
    );
}
