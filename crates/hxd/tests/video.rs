//! Video end to end, on both wires: scripted 1.5 clients speaking
//! transactions 607–611, and scripted ng clients speaking `video_*`, to
//! one live server.
//!
//! The media layer is `hxd_core::voice::fake::RecordingMedia`, so what
//! these test is the *signalling* — the capability gate and its
//! dependency on voice, the two privilege gates, the packed chunk shapes,
//! the task ids, and which notification lands on whom. Whether the SDP is
//! any good is `hxd-voice`'s question, and its tests answer it against
//! real DTLS.
//!
//! The load-bearing test is the last one: a 1.5 client and a browser in
//! the same room, seeing each other's publications.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hotline_proto::messages::tag;
use hxd_core::video::VideoConfig;
use hxd_core::voice::fake::RecordingMedia;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_SELFINFO: u32 = 0x162;
const REQ_LOGIN: u32 = 0x6b;

// Voice's, because video is layered on it and every test here has to get
// into a room first.
const REQ_VOICE_JOIN: u32 = 600;
const NOTIFY_VOICE_OFFER: u32 = 602;
const REQ_VOICE_ANSWER: u32 = 603;

// The video extension's opcodes and fields, spelled out rather than
// imported so a change on either side has to be deliberate.
const REQ_VIDEO_START: u32 = 607;
const REQ_VIDEO_STOP: u32 = 608;
const REQ_VIDEO_STATE: u32 = 609;
const REQ_VIDEO_SUBSCRIBE: u32 = 610;
const NOTIFY_VIDEO_STATUS: u32 = 611;

const FIELD_VIDEO_KIND: u16 = 0x0220;
const FIELD_VIDEO_PAUSED: u16 = 0x0221;
const FIELD_VIDEO_PUBLISHERS: u16 = 0x0222;
const FIELD_VIDEO_CODEC: u16 = 0x0223;
const FIELD_VIDEO_LIMITS: u16 = 0x0224;
const FIELD_VIDEO_SUBSCRIPTIONS: u16 = 0x0225;

const KIND_CAMERA: u16 = 1;
const KIND_SCREEN: u16 = 2;

/// A server on both wires sharing one core, with video on unless asked
/// otherwise.
async fn start_both(dir: &Path, video: bool) -> (SocketAddr, SocketAddr, Arc<RecordingMedia>) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    // Everything: voice, camera and screen.
    std::fs::write(
        accounts.join("sharer.toml"),
        "name = \"Sharer\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         create_pchats = true\nuse_any_name = true\nvoice_chat = true\nvideo_chat = true\n\
         screen_share = true\n",
    )
    .unwrap();
    // Voice and a camera, but no screen share — the two bits are separate
    // trust decisions and neither implies the other.
    std::fs::write(
        accounts.join("camera.toml"),
        "name = \"Camera\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         use_any_name = true\nvoice_chat = true\nvideo_chat = true\n",
    )
    .unwrap();
    // Voice only: allowed in the room, allowed to watch, allowed to
    // publish nothing.
    std::fs::write(
        accounts.join("watcher.toml"),
        "name = \"Watcher\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         use_any_name = true\nvoice_chat = true\n",
    )
    .unwrap();

    let media = Arc::new(RecordingMedia::new());
    let mut core = Core::new().with_voice(media.clone(), 4);
    if video {
        core = core.with_video(VideoConfig::default());
    }
    let caps = if video {
        Caps::empty().with(cap::VOICE).with(cap::VIDEO)
    } else {
        Caps::empty().with(cap::VOICE)
    };
    let ctx = ServerCtx {
        core: Arc::new(core),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "video test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps,
        }),
    };
    let ng_caps = if video {
        vec!["voice".to_string(), "video".to_string()]
    } else {
        vec!["voice".to_string()]
    };
    let ng_ctx = NgCtx {
        core: ctx.core.clone(),
        auth: ctx.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "video test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: ng_caps,
        }),
        registry: Arc::new(Registry::new()),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ng_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng_addr = ng_listener.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(listener, ctx));
    tokio::spawn(hxd_ng_session::serve(ng_listener, ng_ctx));
    (addr, ng_addr, media)
}

async fn start_server(dir: &Path) -> (SocketAddr, Arc<RecordingMedia>) {
    let (legacy, _ng, media) = start_both(dir, true).await;
    (legacy, media)
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

// --- The legacy client --------------------------------------------------

struct Client {
    stream: TcpStream,
    trans: u32,
    uid: u16,
    caps: Option<Vec<u8>>,
    limits: Vec<Vec<u8>>,
    /// Frames read while looking for something else. Video interleaves
    /// replies and notifications freely — a start's reply and the status
    /// it caused race on the wire — so a client that threw away what it
    /// wasn't waiting for would drop the very notifications these tests
    /// are about.
    pending: Vec<Frame>,
}

impl Client {
    async fn login(addr: SocketAddr, login: &str, offer: Caps) -> Client {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut magic)
            .await
            .unwrap();
        let mut c = Client {
            stream,
            trans: 0,
            uid: 0,
            caps: None,
            limits: Vec::new(),
            pending: Vec::new(),
        };
        let mut chunks = vec![
            (tag::NAME, login.as_bytes().to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
            (tag::VERSION, 195u16.to_be_bytes().to_vec()),
            (tag::LOGIN, xor(login.as_bytes())),
            (tag::PASSWORD, xor(b"pw")),
        ];
        if !offer.is_empty() {
            chunks.push((tag::CAPABILITIES, offer.to_wire()));
        }
        c.send(REQ_LOGIN, &chunks).await;
        let f = c.recv_type(HDR_TASK).await;
        assert_eq!(f.flag, 0, "login must succeed");
        c.uid = chunk_u32(&f, tag::UID).unwrap() as u16;
        c.caps = chunk(&f, tag::CAPABILITIES);
        c.limits = f
            .chunks()
            .filter(|ch| ch.tag == FIELD_VIDEO_LIMITS)
            .map(|ch| ch.data.to_vec())
            .collect();
        c.recv_type(HDR_SELFINFO).await;
        c.pending.clear();
        c
    }

    /// Logged in advertising both bits, which is what a video-capable
    /// client does.
    async fn video_login(addr: SocketAddr, login: &str) -> Client {
        Client::login(addr, login, Caps::empty().with(cap::VOICE).with(cap::VIDEO)).await
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.trans
    }

    async fn recv(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while a frame was expected")
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        if let Some(i) = self.pending.iter().position(|f| f.ty == ty) {
            return self.pending.remove(i);
        }
        for _ in 0..24 {
            let f = self.recv().await;
            if f.ty == ty {
                return f;
            }
            self.pending.push(f);
        }
        panic!("frame type {ty} never arrived");
    }

    /// A request and its reply, which must succeed.
    async fn ok(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Frame {
        let t = self.send(ty, chunks).await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, t);
        assert_eq!(reply.flag, 0, "{ty} refused: {}", task_error(&reply));
        reply
    }

    /// A request whose refusal is the point.
    async fn refused(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> String {
        let t = self.send(ty, chunks).await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, t);
        assert_eq!(reply.flag, 1, "expected {ty} to be refused");
        assert_eq!(reply.trans, t, "an error reply still echoes the request");
        task_error(&reply)
    }

    async fn join_voice(&mut self, cid: u32) {
        let reply = self.ok(REQ_VOICE_JOIN, &[chat_id(cid)]).await;
        let sdp = String::from_utf8(chunk(&reply, tag::VOICE_SDP).unwrap()).unwrap();
        self.answer(cid, &format!("answer to {sdp}")).await;
    }

    async fn answer(&mut self, cid: u32, sdp: &str) {
        self.ok(
            REQ_VOICE_ANSWER,
            &[chat_id(cid), (tag::VOICE_SDP, sdp.as_bytes().to_vec())],
        )
        .await;
    }

    /// Answer every offer waiting for us, so the serialisation rule isn't
    /// what a later assertion accidentally measures.
    async fn settle(&mut self, cid: u32) {
        while let Some(i) = self.pending.iter().position(|f| f.ty == NOTIFY_VOICE_OFFER) {
            let f = self.pending.remove(i);
            let sdp = String::from_utf8(chunk(&f, tag::VOICE_SDP).unwrap()).unwrap();
            self.answer(cid, &format!("answer to {sdp}")).await;
        }
    }

    async fn start(&mut self, cid: u32, kind: u16) -> Frame {
        self.ok(REQ_VIDEO_START, &[chat_id(cid), kind_chunk(kind)])
            .await
    }

    /// Wait for a status describing exactly this publication list.
    ///
    /// Matching by predicate rather than taking the next one: a room that
    /// changes twice in quick succession produces two notifications, and
    /// which arrives first is not what these tests are about.
    async fn status_for(&mut self, want: &[(u16, u16, bool)]) -> Frame {
        for _ in 0..24 {
            let f = self.recv_type(NOTIFY_VIDEO_STATUS).await;
            if publishers(&f) == want {
                return f;
            }
        }
        panic!("no video status matching {want:?}");
    }

    async fn expect_quiet(&mut self) {
        assert!(
            self.pending.iter().all(|f| f.ty != NOTIFY_VIDEO_STATUS),
            "expected no video status, but one was already buffered"
        );
        let r = timeout(Duration::from_millis(200), read_frame(&mut self.stream)).await;
        if let Ok(Ok(f)) = r {
            assert_ne!(
                f.ty, NOTIFY_VIDEO_STATUS,
                "a client without the capability must never see 611"
            );
            self.pending.push(f);
        }
    }
}

fn chat_id(cid: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, cid.to_be_bytes().to_vec())
}

fn kind_chunk(kind: u16) -> (u16, Vec<u8>) {
    (FIELD_VIDEO_KIND, kind.to_be_bytes().to_vec())
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

fn chunk_u32(f: &Frame, want: u16) -> Option<u32> {
    f.chunks().find(|c| c.tag == want).map(|c| c.as_uint())
}

fn task_error(f: &Frame) -> String {
    chunk(f, tag::TASK_ERROR)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Decode a `DATA_VIDEO_PUBLISHERS` blob the way a client would: eight
/// bytes an entry, count derived from the field length.
fn publishers(f: &Frame) -> Vec<(u16, u16, bool)> {
    let blob = chunk(f, FIELD_VIDEO_PUBLISHERS).expect("publishers blob");
    blob.chunks_exact(8)
        .map(|e| {
            let uid = u16::from_be_bytes([e[0], e[1]]);
            let kind = u16::from_be_bytes([e[2], e[3]]);
            let flags = u16::from_be_bytes([e[4], e[5]]);
            let codec = u16::from_be_bytes([e[6], e[7]]);
            assert_eq!(codec, 0, "VP8 is codec 0 in *this* number space");
            (uid, kind, flags & 1 != 0)
        })
        .collect()
}

/// A subscription blob: four bytes an entry.
fn subscriptions(streams: &[(u16, u16)]) -> (u16, Vec<u8>) {
    let mut v = Vec::with_capacity(streams.len() * 4);
    for (uid, kind) in streams {
        v.extend_from_slice(&uid.to_be_bytes());
        v.extend_from_slice(&kind.to_be_bytes());
    }
    (FIELD_VIDEO_SUBSCRIPTIONS, v)
}

// --- The ng client ------------------------------------------------------

struct Ng {
    ws: WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    id: u64,
    uid: u16,
    caps: Value,
    video: Value,
    pending: Vec<Value>,
}

impl Ng {
    async fn login(addr: SocketAddr, login: &str) -> Ng {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
            .await
            .unwrap();
        let mut c = Ng {
            ws,
            id: 0,
            uid: 0,
            caps: Value::Null,
            video: Value::Null,
            pending: Vec::new(),
        };
        let ok = c
            .request(
                "login",
                json!({ "login": login, "password": "pw", "nick": login }),
            )
            .await
            .expect("login");
        c.uid = ok["self"]["uid"].as_u64().unwrap() as u16;
        c.caps = ok["caps"].clone();
        c.video = ok.get("video").cloned().unwrap_or(Value::Null);
        c
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, (String, String)> {
        self.id += 1;
        let id = self.id;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let v = self.recv().await;
            if v["reply"] == json!(id) {
                return match v.get("error") {
                    Some(e) => Err((
                        e["code"].as_str().unwrap_or_default().to_string(),
                        e["text"].as_str().unwrap_or_default().to_string(),
                    )),
                    None => Ok(v["ok"].clone()),
                };
            }
            self.pending.push(v);
        }
    }

    async fn ok(&mut self, method: &str, params: Value) -> Value {
        self.request(method, params)
            .await
            .unwrap_or_else(|(c, t)| panic!("{method} refused: {c}: {t}"))
    }

    async fn recv(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("timed out waiting for an ng frame")
                .expect("stream ended")
                .expect("ws error");
            if let Message::Text(t) = msg {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    async fn event(&mut self, ev: &str) -> Value {
        if let Some(i) = self.pending.iter().position(|v| v["ev"] == json!(ev)) {
            return self.pending.remove(i);
        }
        for _ in 0..24 {
            let v = self.recv().await;
            if v["ev"] == json!(ev) {
                return v;
            }
            self.pending.push(v);
        }
        panic!("ng event {ev} never arrived");
    }

    async fn join_voice(&mut self, cid: u32) {
        let ok = self.ok("voice_join", json!({ "cid": cid })).await;
        let sdp = ok["sdp"].as_str().unwrap().to_string();
        self.ok(
            "voice_answer",
            json!({ "cid": cid, "sdp": format!("answer to {sdp}") }),
        )
        .await;
    }

    async fn settle(&mut self, cid: u32) {
        while let Some(i) = self
            .pending
            .iter()
            .position(|v| v["ev"] == json!("voice_offer"))
        {
            let v = self.pending.remove(i);
            let sdp = v["data"]["sdp"].as_str().unwrap().to_string();
            self.ok(
                "voice_answer",
                json!({ "cid": cid, "sdp": format!("answer to {sdp}") }),
            )
            .await;
        }
    }

    async fn status_for(&mut self, want: &[(u16, &str, bool)]) -> Value {
        for _ in 0..24 {
            let v = self.event("video_status").await;
            if ng_publishers(&v) == want {
                return v;
            }
        }
        panic!("no ng video status matching {want:?}");
    }
}

fn ng_publishers(ev: &Value) -> Vec<(u16, &str, bool)> {
    ev["data"]["publishers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["uid"].as_u64().unwrap() as u16,
                p["kind"].as_str().unwrap(),
                p["paused"].as_bool().unwrap(),
            )
        })
        .collect()
}

// --- Negotiation --------------------------------------------------------

#[tokio::test]
async fn the_video_bit_is_echoed_only_alongside_the_voice_bit() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;

    let both = Client::video_login(addr, "sharer").await;
    assert_eq!(
        both.caps,
        Some(Caps::empty().with(cap::VOICE).with(cap::VIDEO).to_wire()),
        "voice and video, 0x0404"
    );

    // Bit 10 depends on bit 2. A client asking for video alone gets
    // neither — echoing a bit whose transactions would all fail is the
    // one thing the handshake must never do.
    let video_only = Client::login(addr, "sharer", Caps::empty().with(cap::VIDEO)).await;
    assert_eq!(video_only.caps, None);

    // And a voice-only client is untouched by the extension existing.
    let voice_only = Client::login(addr, "sharer", Caps::empty().with(cap::VOICE)).await;
    assert_eq!(
        voice_only.caps,
        Some(Caps::empty().with(cap::VOICE).to_wire())
    );
    assert!(voice_only.limits.is_empty(), "no limits without the bit");
}

#[tokio::test]
async fn the_login_reply_carries_one_limits_field_per_kind() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let c = Client::video_login(addr, "sharer").await;

    assert_eq!(
        c.limits.len(),
        2,
        "one per kind, so both encoders can be \
                                   configured before the first join"
    );
    for blob in &c.limits {
        assert!(blob.len() >= 16, "sixteen bytes in this revision");
        assert_eq!(&blob[14..16], &[0, 0], "the reserved pair MUST be zero");
    }
    let camera = &c.limits[0];
    assert_eq!(u16::from_be_bytes([camera[0], camera[1]]), KIND_CAMERA);
    assert_eq!(u16::from_be_bytes([camera[2], camera[3]]), 1280);
    assert_eq!(u16::from_be_bytes([camera[6], camera[7]]), 30);
    assert_eq!(u16::from_be_bytes([camera[12], camera[13]]), 8);
    let screen = &c.limits[1];
    assert_eq!(u16::from_be_bytes([screen[0], screen[1]]), KIND_SCREEN);
    assert_eq!(u16::from_be_bytes([screen[2], screen[3]]), 1920);
    assert_eq!(u16::from_be_bytes([screen[12], screen[13]]), 1);
}

#[tokio::test]
async fn a_server_without_video_advertises_none_and_refuses_it() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _ng, _) = start_both(td.path(), false).await;
    let mut c = Client::video_login(addr, "sharer").await;
    assert_eq!(
        c.caps,
        Some(Caps::empty().with(cap::VOICE).to_wire()),
        "voice yes, video no"
    );
    c.join_voice(0).await;
    let err = c
        .refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(KIND_CAMERA)])
        .await;
    assert!(err.contains("not available"), "got {err:?}");
}

// --- Publishing on the legacy wire --------------------------------------

#[tokio::test]
async fn starting_replies_with_the_codec_and_tells_the_room() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let mut b = Client::video_login(addr, "camera").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    a.settle(0).await;

    let reply = a.start(0, KIND_CAMERA).await;
    assert_eq!(chunk_u32(&reply, tag::CHAT_ID), Some(0), "the room echoes");
    assert_eq!(chunk_u32(&reply, FIELD_VIDEO_KIND), Some(1));
    assert_eq!(
        chunk(&reply, FIELD_VIDEO_CODEC).as_deref(),
        Some(&b"VP8"[..])
    );
    assert!(
        chunk(&reply, tag::VOICE_SDP).is_none(),
        "the reply carries no offer: one may already be outstanding, and \
         the offer follows as a 602 when serialisation allows"
    );

    // Both hear about it, and the notification carries task id 0.
    let status = b.status_for(&[(a.uid, KIND_CAMERA, false)]).await;
    assert_eq!(status.trans, 0, "611 is a notification, not a push");
    assert_eq!(status.flag, 0);
    assert_eq!(
        chunk(&status, FIELD_VIDEO_CODEC).as_deref(),
        Some(&b"VP8"[..])
    );
    a.status_for(&[(a.uid, KIND_CAMERA, false)]).await;
}

#[tokio::test]
async fn one_participant_can_publish_a_camera_and_a_screen_at_once() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    a.join_voice(0).await;

    a.start(0, KIND_CAMERA).await;
    a.start(0, KIND_SCREEN).await;
    // Two entries for one uid, correlated by kind — which is why this
    // blob is not a widening of the voice participants one.
    a.status_for(&[(a.uid, KIND_CAMERA, false), (a.uid, KIND_SCREEN, false)])
        .await;

    // Stop without a kind ends both.
    a.ok(REQ_VIDEO_STOP, &[chat_id(0)]).await;
    a.status_for(&[]).await;
}

#[tokio::test]
async fn pausing_reaches_the_room_without_renegotiating_anyone() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let mut b = Client::video_login(addr, "camera").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    a.settle(0).await;
    a.start(0, KIND_CAMERA).await;
    b.status_for(&[(a.uid, KIND_CAMERA, false)]).await;
    b.pending.clear();

    a.ok(
        REQ_VIDEO_STATE,
        &[
            chat_id(0),
            kind_chunk(KIND_CAMERA),
            (FIELD_VIDEO_PAUSED, 1u16.to_be_bytes().to_vec()),
        ],
    )
    .await;
    b.status_for(&[(a.uid, KIND_CAMERA, true)]).await;
    assert!(
        !b.pending.iter().any(|f| f.ty == NOTIFY_VOICE_OFFER),
        "pause is to video what mute is to audio: no offer/answer at all"
    );
}

#[tokio::test]
async fn stopping_what_is_not_running_is_accepted() {
    // Disconnect races make this idempotent, and a client should not have
    // to tell a real failure from a lost race.
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    a.join_voice(0).await;
    a.ok(REQ_VIDEO_STOP, &[chat_id(0), kind_chunk(KIND_SCREEN)])
        .await;
    a.ok(REQ_VIDEO_STOP, &[chat_id(0)]).await;
}

#[tokio::test]
async fn an_invalid_kind_is_refused_rather_than_read_as_a_camera() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    a.join_voice(0).await;
    // Joining already brought one status — an empty one, which is how a
    // joiner learns the room's video state without asking. Clear it so
    // the assertion below is about the refusals and nothing else.
    a.status_for(&[]).await;
    a.pending.clear();

    // Kind 0 is deliberately invalid so a zeroed field is caught.
    a.refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(0)])
        .await;
    // Kind 3 is reserved for screen audio: a later revision's client must
    // not have its request answered with a camera.
    a.refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(3)])
        .await;
    // Nothing was published, so nothing was announced.
    assert!(
        !a.pending.iter().any(|f| f.ty == NOTIFY_VIDEO_STATUS),
        "a refused start must not tell the room anything"
    );
}

#[tokio::test]
async fn video_outside_a_voice_room_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let err = a
        .refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(KIND_CAMERA)])
        .await;
    assert!(err.contains("voice chat"), "got {err:?}");
}

// --- Privileges ---------------------------------------------------------

#[tokio::test]
async fn the_camera_bit_and_the_screen_bit_are_separate_decisions() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut cam = Client::video_login(addr, "camera").await;
    cam.join_voice(0).await;

    // video_chat but not screen_share: the camera works, the desktop
    // doesn't. Neither bit implies the other.
    cam.start(0, KIND_CAMERA).await;
    let err = cam
        .refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(KIND_SCREEN)])
        .await;
    assert!(err.contains("screen"), "got {err:?}");
}

#[tokio::test]
async fn a_watcher_may_receive_everything_and_publish_nothing() {
    // Receiving video requires no privilege bit beyond being in the room;
    // the bits govern publishing.
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let mut w = Client::video_login(addr, "watcher").await;
    a.join_voice(0).await;
    w.join_voice(0).await;
    a.settle(0).await;
    a.start(0, KIND_CAMERA).await;

    w.refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(KIND_CAMERA)])
        .await;
    w.ok(
        REQ_VIDEO_SUBSCRIBE,
        &[chat_id(0), subscriptions(&[(a.uid, KIND_CAMERA)])],
    )
    .await;
    // Subscribing gets the subscriber an offer, and tells the publisher
    // nothing: who is watching whom is not published.
    w.recv_type(NOTIFY_VOICE_OFFER).await;
}

#[tokio::test]
async fn the_capability_echo_survives_a_privilege_refusal() {
    // The bit states server support; the privilege states user
    // permission. A client shows a disabled control with a tooltip
    // rather than hiding it, which it can only do if the bit came back.
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let w = Client::video_login(addr, "watcher").await;
    assert_eq!(
        w.caps,
        Some(Caps::empty().with(cap::VOICE).with(cap::VIDEO).to_wire())
    );
    assert_eq!(w.limits.len(), 2);
}

// --- Slots --------------------------------------------------------------

#[tokio::test]
async fn the_screen_slot_is_room_wide_and_the_refusal_says_why() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let mut b = Client::video_login(addr, "sharer").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    a.settle(0).await;
    a.start(0, KIND_SCREEN).await;

    let err = b
        .refused(REQ_VIDEO_START, &[chat_id(0), kind_chunk(KIND_SCREEN)])
        .await;
    assert!(
        err.contains("sharing"),
        "the error should say someone else is sharing so the client can \
         say so plainly; got {err:?}"
    );
    // The existing share is never preempted.
    a.status_for(&[(a.uid, KIND_SCREEN, false)]).await;
    // And cameras have their own slots.
    b.start(0, KIND_CAMERA).await;
}

// --- Compatibility ------------------------------------------------------

#[tokio::test]
async fn a_voice_only_client_never_sees_a_video_transaction() {
    // The whole compatibility story: a client that implements none of
    // this document is a full member of a room in which others use all
    // of it.
    let td = tempfile::tempdir().unwrap();
    let (addr, _) = start_server(td.path()).await;
    let mut a = Client::video_login(addr, "sharer").await;
    let mut legacy = Client::login(addr, "watcher", Caps::empty().with(cap::VOICE)).await;
    a.join_voice(0).await;
    legacy.join_voice(0).await;
    a.settle(0).await;
    legacy.settle(0).await;
    legacy.pending.clear();

    a.start(0, KIND_CAMERA).await;
    a.start(0, KIND_SCREEN).await;
    a.status_for(&[(a.uid, KIND_CAMERA, false), (a.uid, KIND_SCREEN, false)])
        .await;

    // Not one 611, and the voice session is untouched.
    legacy.expect_quiet().await;
}

// --- The ng wire --------------------------------------------------------

#[tokio::test]
async fn the_ng_login_reply_carries_the_caps_and_the_ceilings() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _) = start_both(td.path(), true).await;
    let c = Ng::login(ng, "sharer").await;
    assert_eq!(
        c.caps,
        json!(["voice", "video"]),
        "video never without voice"
    );
    assert_eq!(c.video["camera"]["max_width"], json!(1280));
    assert_eq!(c.video["camera"]["max_per_room"], json!(8));
    assert_eq!(c.video["screen"]["max_fps"], json!(15));
    assert_eq!(c.video["screen"]["max_per_room"], json!(1));
}

#[tokio::test]
async fn the_ng_binding_publishes_pauses_and_subscribes() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _) = start_both(td.path(), true).await;
    let mut a = Ng::login(ng, "sharer").await;
    let mut b = Ng::login(ng, "camera").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    a.settle(0).await;

    let ok = a
        .ok("video_start", json!({ "cid": 0, "kind": "camera" }))
        .await;
    assert_eq!(ok, json!({ "codec": "VP8" }));
    // A string kind and a boolean paused, not an integer and a flags
    // word: this transport is already JSON.
    b.status_for(&[(a.uid, "camera", false)]).await;

    a.ok(
        "video_state",
        json!({ "cid": 0, "kind": "camera", "paused": true }),
    )
    .await;
    b.status_for(&[(a.uid, "camera", true)]).await;

    // The complete desired set, and `[]` turns it all off in one request.
    b.ok(
        "video_subscribe",
        json!({ "cid": 0, "streams": [{ "uid": a.uid, "kind": "camera" }] }),
    )
    .await;
    b.ok("video_subscribe", json!({ "cid": 0, "streams": [] }))
        .await;

    a.ok("video_stop", json!({ "cid": 0 })).await;
    b.status_for(&[]).await;
}

#[tokio::test]
async fn the_ng_error_codes_are_the_closed_set() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _) = start_both(td.path(), true).await;
    let mut a = Ng::login(ng, "sharer").await;

    assert_eq!(
        a.request("video_start", json!({ "cid": 0, "kind": "camera" }))
            .await
            .unwrap_err()
            .0,
        "not_in_voice"
    );
    a.join_voice(0).await;
    a.ok("video_start", json!({ "cid": 0, "kind": "camera" }))
        .await;
    assert_eq!(
        a.request("video_start", json!({ "cid": 0, "kind": "camera" }))
            .await
            .unwrap_err()
            .0,
        "already_publishing"
    );
    assert_eq!(
        a.request(
            "video_state",
            json!({ "cid": 0, "kind": "screen", "paused": true })
        )
        .await
        .unwrap_err()
        .0,
        "not_publishing"
    );
    assert_eq!(
        a.request("video_start", json!({ "cid": 0, "kind": "hologram" }))
            .await
            .unwrap_err()
            .0,
        "bad_request"
    );

    // A camera user asking to share a screen.
    let mut cam = Ng::login(ng, "camera").await;
    cam.join_voice(0).await;
    assert_eq!(
        cam.request("video_start", json!({ "cid": 0, "kind": "screen" }))
            .await
            .unwrap_err()
            .0,
        "access_denied"
    );

    // And the room's one screen slot.
    let mut second = Ng::login(ng, "sharer").await;
    second.join_voice(0).await;
    a.ok("video_start", json!({ "cid": 0, "kind": "screen" }))
        .await;
    assert_eq!(
        second
            .request("video_start", json!({ "cid": 0, "kind": "screen" }))
            .await
            .unwrap_err()
            .0,
        "video_full"
    );
}

// --- One room, both eras ------------------------------------------------

#[tokio::test]
async fn a_1_5_client_and_a_browser_share_one_video_room() {
    // The test this suite exists for. One room, one SFU, two wires: the
    // classic client's packed publishers blob and the ng client's JSON
    // array describe the same publications, and each sees the other's.
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _) = start_both(td.path(), true).await;

    let mut old = Client::video_login(legacy_addr, "sharer").await;
    let mut new = Ng::login(ng_addr, "camera").await;
    old.join_voice(0).await;
    new.join_voice(0).await;
    old.settle(0).await;

    // The 1.5 client shares a screen; the browser sees it, spelled its
    // own way.
    old.start(0, KIND_SCREEN).await;
    new.status_for(&[(old.uid, "screen", false)]).await;

    // The browser turns a camera on; the 1.5 client sees both, in one
    // eight-byte-stride blob.
    new.ok("video_start", json!({ "cid": 0, "kind": "camera" }))
        .await;
    old.status_for(&[(old.uid, KIND_SCREEN, false), (new.uid, KIND_CAMERA, false)])
        .await;

    // Each subscribes to the other, across the era boundary.
    old.ok(
        REQ_VIDEO_SUBSCRIBE,
        &[chat_id(0), subscriptions(&[(new.uid, KIND_CAMERA)])],
    )
    .await;
    new.ok(
        "video_subscribe",
        json!({ "cid": 0, "streams": [{ "uid": old.uid, "kind": "screen" }] }),
    )
    .await;

    // A pause on one wire is a paused flag on the other.
    new.ok(
        "video_state",
        json!({ "cid": 0, "kind": "camera", "paused": true }),
    )
    .await;
    old.status_for(&[(old.uid, KIND_SCREEN, false), (new.uid, KIND_CAMERA, true)])
        .await;

    // And leaving voice on one wire clears that publisher for the other.
    old.ok(REQ_VIDEO_STOP, &[chat_id(0)]).await;
    new.status_for(&[(new.uid, "camera", true)]).await;
}
