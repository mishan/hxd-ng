//! Voice end to end, on both wires: scripted 1.5 clients speaking
//! transactions 600–606, and scripted ng clients speaking `voice_*`, to
//! one live server.
//!
//! The media layer is `hxd_core::voice::fake::RecordingMedia`, so these
//! test the *signalling* — the capability gate, the privilege gate, the
//! chunk and JSON shapes, the task ids, and which notification lands on
//! whom. Whether the SDP is any good is `hxd-voice`'s question and its
//! tests answer it with real DTLS; whether the two wires share one room
//! is the last test here.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hotline_proto::messages::tag;
use hotline_proto::voice::{ice as wire_ice, parse_voice_participants};
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

// The extension's opcodes, spelled out rather than imported so a change
// on either side has to be deliberate.
const REQ_VOICE_JOIN: u32 = 600;
const REQ_VOICE_LEAVE: u32 = 601;
const NOTIFY_VOICE_OFFER: u32 = 602;
const REQ_VOICE_ANSWER: u32 = 603;
const VOICE_ICE: u32 = 604;
const NOTIFY_VOICE_STATUS: u32 = 605;
const REQ_VOICE_MUTE: u32 = 606;

async fn start_server(dir: &Path, voice: bool) -> (SocketAddr, Arc<RecordingMedia>) {
    let (legacy, _ng, media) = start_both(dir, voice).await;
    (legacy, media)
}

/// A server on both wires, sharing one core — which is the whole point.
async fn start_both(dir: &Path, voice: bool) -> (SocketAddr, SocketAddr, Arc<RecordingMedia>) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("talker.toml"),
        "name = \"Talker\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         create_pchats = true\nuse_any_name = true\nvoice_chat = true\n",
    )
    .unwrap();
    // Same as talker, but without the voice privilege.
    std::fs::write(
        accounts.join("listener.toml"),
        "name = \"Listener\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         use_any_name = true\n",
    )
    .unwrap();

    let media = Arc::new(RecordingMedia::new());
    let core = if voice {
        Core::new().with_voice(media.clone(), 2)
    } else {
        Core::new()
    };
    let ctx = ServerCtx {
        core: Arc::new(core),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "voice test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: if voice {
                Caps::empty().with(cap::VOICE)
            } else {
                Caps::empty()
            },
        }),
    };
    let ng_ctx = NgCtx {
        core: ctx.core.clone(),
        auth: ctx.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "voice test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: if voice {
                vec!["voice".to_string()]
            } else {
                Vec::new()
            },
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

/// A scripted ng client: the same buffering discipline as the legacy one,
/// because voice interleaves replies and events on this wire too.
struct Ng {
    ws: WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    id: u64,
    uid: u16,
    caps: Value,
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

    /// The next event of this kind, buffering anything else.
    async fn event(&mut self, ev: &str) -> Value {
        if let Some(i) = self.pending.iter().position(|v| v["ev"] == json!(ev)) {
            return self.pending.remove(i);
        }
        for _ in 0..16 {
            let v = self.recv().await;
            if v["ev"] == json!(ev) {
                return v;
            }
            self.pending.push(v);
        }
        panic!("ng event {ev} never arrived");
    }

    /// Wait for a room status describing exactly this room.
    async fn status_for(&mut self, want: &[(u16, bool)]) -> Value {
        for _ in 0..16 {
            let v = self.event("voice_status").await;
            if ng_participants(&v) == want {
                return v;
            }
        }
        panic!("no ng room status matching {want:?}");
    }

    /// Join and answer, as a real client does the moment it has an offer.
    async fn join_voice(&mut self, cid: u32) -> Value {
        let ok = self.ok("voice_join", json!({ "cid": cid })).await;
        let sdp = ok["sdp"].as_str().unwrap().to_string();
        self.ok(
            "voice_answer",
            json!({ "cid": cid, "sdp": format!("answer to {sdp}") }),
        )
        .await;
        ok
    }
}

/// The uids in a `voice_status` event's participant list.
fn ng_participants(ev: &Value) -> Vec<(u16, bool)> {
    ev["data"]["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["uid"].as_u64().unwrap() as u16,
                p["muted"].as_bool().unwrap(),
            )
        })
        .collect()
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

struct Client {
    stream: TcpStream,
    trans: u32,
    uid: u16,
    caps: Option<Vec<u8>>,
    /// Frames read while looking for something else. Voice interleaves
    /// replies and notifications freely — an answer's reply and the room
    /// status it caused race on the wire — so a test client that threw
    /// away what it wasn't waiting for would drop the very
    /// notifications these tests are about.
    pending: Vec<Frame>,
}

impl Client {
    /// Log in as `login`, advertising voice unless `offer_voice` is off.
    async fn login(addr: SocketAddr, login: &str, offer_voice: bool) -> Client {
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
            pending: Vec::new(),
        };
        let mut chunks = vec![
            (tag::NAME, login.as_bytes().to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
            (tag::VERSION, 195u16.to_be_bytes().to_vec()),
            (tag::LOGIN, xor(login.as_bytes())),
            (tag::PASSWORD, xor(b"pw")),
        ];
        if offer_voice {
            chunks.push((tag::CAPABILITIES, Caps::empty().with(cap::VOICE).to_wire()));
        }
        c.send(REQ_LOGIN, &chunks).await;
        let f = c.recv_type(HDR_TASK).await;
        assert_eq!(f.flag, 0, "login must succeed");
        c.uid = chunk_u32(&f, tag::UID).unwrap() as u16;
        c.caps = chunk(&f, tag::CAPABILITIES);
        c.recv_type(HDR_SELFINFO).await;
        // The login flow's own pushes (the agreement dance) buffered on
        // the way to the self-info; none of them are this suite's
        // business, and a test asserting silence shouldn't trip over
        // them.
        c.pending.clear();
        c
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
        for _ in 0..16 {
            let f = self.recv().await;
            if f.ty == ty {
                return f;
            }
            self.pending.push(f);
        }
        panic!("frame type {ty} never arrived");
    }

    /// Nothing more is coming: nothing buffered, and nothing arrives
    /// within a short window.
    async fn expect_quiet(&mut self) {
        assert!(
            self.pending.is_empty(),
            "expected silence, but {} frame(s) were already buffered",
            self.pending.len()
        );
        let r = timeout(Duration::from_millis(200), read_frame(&mut self.stream)).await;
        if let Ok(Ok(f)) = r {
            panic!("expected silence, got a frame of type {}", f.ty);
        }
    }

    /// Wait for a room status describing exactly this room.
    ///
    /// Matching by predicate rather than taking the next one: a room that
    /// changes twice in quick succession produces two notifications, and
    /// which one arrives first is not what any of these tests are about.
    async fn status_for(&mut self, want: &[(u16, bool)]) -> Frame {
        for _ in 0..16 {
            let f = self.recv_type(NOTIFY_VOICE_STATUS).await;
            if participants(&f) == want {
                return f;
            }
        }
        panic!("no room status matching {want:?}");
    }

    /// Join voice and answer the offer, which is what a real client does
    /// the moment its WebRTC stack has one.
    async fn join_voice(&mut self, cid: u32) -> Frame {
        let t = self.send(REQ_VOICE_JOIN, &[chat_id(cid)]).await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, t);
        assert_eq!(reply.flag, 0, "join refused: {}", task_error(&reply));
        let sdp = String::from_utf8(chunk(&reply, tag::VOICE_SDP).unwrap()).unwrap();
        self.answer_voice(cid, &format!("answer to {sdp}")).await;
        reply
    }

    async fn answer_voice(&mut self, cid: u32, sdp: &str) {
        let t = self
            .send(
                REQ_VOICE_ANSWER,
                &[chat_id(cid), (tag::VOICE_SDP, sdp.as_bytes().to_vec())],
            )
            .await;
        let reply = self.recv_type(HDR_TASK).await;
        assert_eq!(reply.trans, t);
        assert_eq!(reply.flag, 0, "answer refused: {}", task_error(&reply));
    }
}

fn chat_id(cid: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, cid.to_be_bytes().to_vec())
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

/// The uids in a `VOICE_PARTICIPANTS` blob, and whether each is muted.
fn participants(f: &Frame) -> Vec<(u16, bool)> {
    let blob = chunk(f, tag::VOICE_PARTICIPANTS).expect("participants blob");
    parse_voice_participants(&blob)
        .map(|p| (p.user_id, p.is_muted()))
        .collect()
}

// --- Tests ---------------------------------------------------------------

#[tokio::test]
async fn the_join_reply_carries_the_offer_the_codec_and_the_room() {
    let td = tempfile::tempdir().unwrap();
    let (addr, media) = start_server(td.path(), true).await;

    let mut a = Client::login(addr, "talker", true).await;
    assert_eq!(
        a.caps.as_deref(),
        Some(&[0x00, 0x04][..]),
        "the server echoes the voice capability"
    );

    let t = a.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!((reply.trans, reply.flag), (t, 0));
    assert_eq!(chunk_u32(&reply, tag::CHAT_ID), Some(0));
    assert_eq!(chunk(&reply, tag::VOICE_CODEC).unwrap(), b"PCMU".to_vec());
    assert!(!chunk(&reply, tag::VOICE_SDP).unwrap().is_empty());
    assert!(
        participants(&reply).is_empty(),
        "the room as the joiner found it"
    );
    assert!(media.calls().iter().any(
        |c| matches!(c, hxd_core::voice::fake::MediaCall::Join { uid, cid: 0 } if *uid == a.uid)
    ));

    // Then the room status, as a notification with task id 0 — the
    // extension's transaction semantics, not this frontend's push
    // counter.
    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(status.trans, 0, "server-initiated voice uses task id 0");
    assert_eq!(status.flag, 0, "and the reply flag stays unset");
    assert_eq!(participants(&status), vec![(a.uid, false)]);
}

#[tokio::test]
async fn a_second_joiner_is_announced_and_renegotiated_to_the_first() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), true).await;

    let mut a = Client::login(addr, "talker", true).await;
    a.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;

    let mut b = Client::login(addr, "talker", true).await;
    let b_join = b.join_voice(0).await;
    assert_eq!(
        participants(&b_join),
        vec![(a.uid, false)],
        "B's reply lists the room before B"
    );

    // A gets a fresh offer, because it now has someone to hear.
    let offer = a.recv_type(NOTIFY_VOICE_OFFER).await;
    assert_eq!(offer.trans, 0);
    assert_eq!(chunk_u32(&offer, tag::CHAT_ID), Some(0));
    assert!(!chunk(&offer, tag::VOICE_SDP).unwrap().is_empty());

    // And both hear the room's new shape.
    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(participants(&status), vec![(a.uid, false), (b.uid, false)]);
    let status = b.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(participants(&status), vec![(a.uid, false), (b.uid, false)]);
}

#[tokio::test]
async fn muting_is_announced_to_the_room() {
    let td = tempfile::tempdir().unwrap();
    let (addr, media) = start_server(td.path(), true).await;
    let mut a = Client::login(addr, "talker", true).await;
    a.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;

    let t = a
        .send(
            REQ_VOICE_MUTE,
            &[chat_id(0), (tag::VOICE_MUTED, 1u16.to_be_bytes().to_vec())],
        )
        .await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!((reply.trans, reply.flag), (t, 0));
    assert_eq!(reply.hc, 0, "an empty success reply");

    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(participants(&status), vec![(a.uid, true)]);
    assert!(media.calls().iter().any(|c| matches!(
        c,
        hxd_core::voice::fake::MediaCall::SetMuted { muted: true, .. }
    )));

    // Push-to-talk bounces; a toggle to the state we're already in is
    // acked and announced to nobody.
    let t = a
        .send(
            REQ_VOICE_MUTE,
            &[chat_id(0), (tag::VOICE_MUTED, 1u16.to_be_bytes().to_vec())],
        )
        .await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!((reply.trans, reply.flag), (t, 0));
    a.expect_quiet().await;
}

#[tokio::test]
async fn ice_candidates_cross_the_wire_as_the_json_the_spec_names() {
    let td = tempfile::tempdir().unwrap();
    let (addr, media) = start_server(td.path(), true).await;
    let mut a = Client::login(addr, "talker", true).await;

    // The join's answer makes the SFU emit its end-of-candidates; with
    // the fake media layer nothing does, so drive the client→server
    // direction and read it back out of the recorder.
    a.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;

    let json = wire_ice::build(&wire_ice::IceCandidate {
        candidate: Some("candidate:1 1 UDP 2130706431 192.0.2.9 40000 typ host".into()),
        sdp_mid: Some("send".into()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    });
    a.send(
        VOICE_ICE,
        &[chat_id(0), (tag::VOICE_ICE, json.clone().into_bytes())],
    )
    .await;
    // 604 is a notification: no reply comes back, and the candidate
    // reaches the media layer.
    a.expect_quiet().await;
    let got = media
        .calls()
        .into_iter()
        .find_map(|c| match c {
            hxd_core::voice::fake::MediaCall::Ice { candidate, .. } => Some(candidate),
            _ => None,
        })
        .expect("the candidate reached the media layer");
    assert_eq!(
        got.candidate,
        "candidate:1 1 UDP 2130706431 192.0.2.9 40000 typ host"
    );
    assert_eq!(got.sdp_mid.as_deref(), Some("send"));

    // An empty field is end-of-candidates, not a malformed candidate.
    a.send(VOICE_ICE, &[chat_id(0), (tag::VOICE_ICE, Vec::new())])
        .await;
    a.expect_quiet().await;
}

#[tokio::test]
async fn leaving_tells_the_room_and_frees_the_slot() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), true).await;
    let mut a = Client::login(addr, "talker", true).await;
    let mut b = Client::login(addr, "talker", true).await;
    a.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;
    b.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_OFFER).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;
    b.recv_type(NOTIFY_VOICE_STATUS).await;

    let t = b.send(REQ_VOICE_LEAVE, &[chat_id(0)]).await;
    let reply = b.recv_type(HDR_TASK).await;
    assert_eq!((reply.trans, reply.flag, reply.hc), (t, 0, 0));

    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(participants(&status), vec![(a.uid, false)]);

    // Leaving a room you're not in is an error, not a silent success.
    let t = b.send(REQ_VOICE_LEAVE, &[chat_id(0)]).await;
    let reply = b.recv_type(HDR_TASK).await;
    assert_eq!((reply.trans, reply.flag), (t, 1));
    assert!(task_error(&reply).contains("not in that voice chat"));
}

#[tokio::test]
async fn a_disconnect_takes_the_speaker_out_of_the_room() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), true).await;
    let mut a = Client::login(addr, "talker", true).await;
    let mut b = Client::login(addr, "talker", true).await;
    a.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;
    b.join_voice(0).await;
    a.recv_type(NOTIFY_VOICE_OFFER).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;

    // "If a client disconnects without sending Leave Voice Room, the
    // server MUST clean up automatically."
    drop(b);
    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(participants(&status), vec![(a.uid, false)]);
}

#[tokio::test]
async fn the_privilege_bit_and_the_room_cap_are_both_enforced() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), true).await;

    // No voice_chat bit: the capability is still echoed (the client
    // shows a disabled button), but the join is refused in the spec's
    // own words.
    let mut l = Client::login(addr, "listener", true).await;
    assert_eq!(l.caps.as_deref(), Some(&[0x00, 0x04][..]));
    l.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    let reply = l.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 1);
    assert_eq!(
        task_error(&reply),
        "You are not allowed to join voice chat."
    );

    // The room cap (2 in these tests).
    let mut a = Client::login(addr, "talker", true).await;
    let mut b = Client::login(addr, "talker", true).await;
    let mut c = Client::login(addr, "talker", true).await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    c.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    let reply = c.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 1);
    assert!(task_error(&reply).contains("full"));
}

#[tokio::test]
async fn a_private_chats_voice_room_needs_membership_in_that_chat() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), true).await;
    let mut a = Client::login(addr, "talker", true).await;
    let mut b = Client::login(addr, "talker", true).await;

    // A creates a private chat and does not invite B.
    const REQ_CHAT_CREATE: u32 = 0x70;
    a.send(REQ_CHAT_CREATE, &[(tag::UID, a.uid.to_be_bytes().to_vec())])
        .await;
    let created = a.recv_type(HDR_TASK).await;
    let cid = chunk_u32(&created, tag::CHAT_ID).unwrap();

    // A guessed room id is the attack the spec's membership rule is
    // there to stop, and it is stopped here rather than by the bit.
    b.send(REQ_VOICE_JOIN, &[chat_id(cid)]).await;
    let reply = b.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 1);
    assert!(task_error(&reply).contains("not in that chat"));

    // A, who is in it, may join.
    a.join_voice(cid).await;
    let status = a.recv_type(NOTIFY_VOICE_STATUS).await;
    assert_eq!(chunk_u32(&status, tag::CHAT_ID), Some(cid));
}

#[tokio::test]
async fn an_answer_that_is_not_utf8_is_refused_rather_than_repaired() {
    // The spec says the SDP on this wire is UTF-8, and unlike every other
    // string here it is never Mac Roman. Decoding it lossily would put
    // U+FFFD into a fingerprint or an ICE password and hand the media
    // layer an answer subtly unlike the one the client sent — a session
    // that fails later, somewhere less obvious.
    let td = tempfile::tempdir().unwrap();
    let (addr, media) = start_server(td.path(), true).await;

    let mut a = Client::login(addr, "talker", true).await;
    a.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    a.recv_type(HDR_TASK).await;
    a.recv_type(NOTIFY_VOICE_STATUS).await;
    let before = media.calls().len();

    let t = a
        .send(
            REQ_VOICE_ANSWER,
            &[chat_id(0), (tag::VOICE_SDP, vec![b'v', b'=', 0xff, 0xfe])],
        )
        .await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!(reply.trans, t);
    assert_eq!(reply.flag, 1, "the answer is refused");
    assert_eq!(
        task_error(&reply),
        "Your client's voice session was rejected."
    );
    assert_eq!(
        media.calls().len(),
        before,
        "and nothing reached the media layer"
    );
}

#[tokio::test]
async fn a_client_that_did_not_negotiate_voice_is_told_so_and_nothing_more() {
    let td = tempfile::tempdir().unwrap();
    let (addr, media) = start_server(td.path(), true).await;

    let mut a = Client::login(addr, "talker", false).await;
    assert!(a.caps.is_none(), "nothing offered, nothing echoed");

    a.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 1);
    assert!(task_error(&reply).contains("not available"));
    // A task error is a base-protocol reply, not a voice transaction:
    // the client is never sent 602/604/605, and never reaches the SFU.
    assert!(media.calls().is_empty());

    // The 604 notification has no reply to refuse with, so it is simply
    // dropped.
    a.send(VOICE_ICE, &[chat_id(0), (tag::VOICE_ICE, Vec::new())])
        .await;
    a.expect_quiet().await;
}

#[tokio::test]
async fn a_server_without_an_sfu_never_offers_voice_at_all() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _media) = start_server(td.path(), false).await;

    let mut a = Client::login(addr, "talker", true).await;
    assert!(
        a.caps.is_none(),
        "the capability is a promise the server can keep"
    );
    a.send(REQ_VOICE_JOIN, &[chat_id(0)]).await;
    let reply = a.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 1);
}

// --- The ng wire ---------------------------------------------------------

#[tokio::test]
async fn the_ng_join_reply_mirrors_the_legacy_one() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, media) = start_both(td.path(), true).await;

    let mut a = Ng::login(ng, "talker").await;
    assert_eq!(a.caps, json!(["voice"]), "the login reply feature-detects");

    let ok = a.ok("voice_join", json!({ "cid": 0 })).await;
    assert_eq!(ok["codec"], json!("PCMU"));
    assert!(!ok["sdp"].as_str().unwrap().is_empty());
    assert_eq!(ok["participants"], json!([]), "the room before the joiner");
    assert!(media.calls().iter().any(
        |c| matches!(c, hxd_core::voice::fake::MediaCall::Join { uid, cid: 0 } if *uid == a.uid)
    ));

    let status = a.event("voice_status").await;
    assert_eq!(status["data"]["cid"], json!(0));
    assert_eq!(ng_participants(&status), vec![(a.uid, false)]);
}

#[tokio::test]
async fn ng_ice_carries_the_dictionary_as_an_object_and_null_for_the_end() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, media) = start_both(td.path(), true).await;
    let mut a = Ng::login(ng, "talker").await;
    a.join_voice(0).await;

    a.ok(
        "voice_ice",
        json!({ "cid": 0, "candidate": {
            "candidate": "candidate:1 1 UDP 2130706431 192.0.2.9 40000 typ host",
            "sdpMid": "send",
            "sdpMLineIndex": 0,
        }}),
    )
    .await;
    let got = media
        .calls()
        .into_iter()
        .find_map(|c| match c {
            hxd_core::voice::fake::MediaCall::Ice { candidate, .. } => Some(candidate),
            _ => None,
        })
        .expect("the candidate reached the media layer");
    assert_eq!(got.sdp_mid.as_deref(), Some("send"));
    assert!(got.candidate.contains("192.0.2.9"));

    // `null` is end-of-candidates — what a browser passes to
    // addIceCandidate to mean the same thing.
    a.ok("voice_ice", json!({ "cid": 0, "candidate": null }))
        .await;
    let last = media
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            hxd_core::voice::fake::MediaCall::Ice { candidate, .. } => Some(candidate),
            _ => None,
        })
        .next_back()
        .unwrap();
    assert!(last.is_end_of_candidates());
}

#[tokio::test]
async fn ng_voice_errors_use_the_documented_codes() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _media) = start_both(td.path(), true).await;

    // No voice_chat bit.
    let mut l = Ng::login(ng, "listener").await;
    let (code, _) = l.request("voice_join", json!({})).await.unwrap_err();
    assert_eq!(code, "access_denied");

    let mut a = Ng::login(ng, "talker").await;
    let (code, _) = a.request("voice_leave", json!({})).await.unwrap_err();
    assert_eq!(code, "not_in_voice");
    let (code, _) = a
        .request("voice_answer", json!({ "sdp": "v=0" }))
        .await
        .unwrap_err();
    assert_eq!(code, "not_in_voice");
    let (code, _) = a
        .request("voice_mute", json!({ "muted": true }))
        .await
        .unwrap_err();
    assert_eq!(code, "not_in_voice");
    // voice_ice answers like its neighbours. On the legacy wire this is a
    // notification with nowhere to put a refusal; here every request gets
    // a reply, so acknowledging a candidate for a room the caller isn't
    // in would be a lie in the shape of an `ok`.
    let (code, _) = a
        .request("voice_ice", json!({ "cid": 0, "candidate": null }))
        .await
        .unwrap_err();
    assert_eq!(code, "not_in_voice");
    // A missing required field is a bad request, not a guess.
    let (code, _) = a.request("voice_mute", json!({})).await.unwrap_err();
    assert_eq!(code, "bad_request");
    // Including inside the candidate: an empty string there is
    // end-of-candidates, so a missing `candidate` must not default into
    // one and turn a malformed request into a signal.
    let (code, _) = a
        .request("voice_ice", json!({ "cid": 0, "candidate": {} }))
        .await
        .unwrap_err();
    assert_eq!(code, "bad_request");
    let (code, _) = a
        .request(
            "voice_ice",
            json!({ "cid": 0, "candidate": { "sdpMid": "send" } }),
        )
        .await
        .unwrap_err();
    assert_eq!(code, "bad_request");

    // The room cap is 2 in these tests.
    let mut b = Ng::login(ng, "talker").await;
    let mut c = Ng::login(ng, "talker").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    let (code, _) = c.request("voice_join", json!({})).await.unwrap_err();
    assert_eq!(code, "voice_full");
}

#[tokio::test]
async fn a_server_without_an_sfu_says_so_on_the_ng_wire_too() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _media) = start_both(td.path(), false).await;
    let mut a = Ng::login(ng, "talker").await;
    assert_eq!(a.caps, json!([]));
    let (code, _) = a.request("voice_join", json!({})).await.unwrap_err();
    assert_eq!(code, "voice_disabled");
}

#[tokio::test]
async fn ng_voice_ends_when_the_connection_does() {
    // A detached session is out of voice: its UDP path went with its
    // WebSocket, and a resumed client re-joins explicitly.
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng, _media) = start_both(td.path(), true).await;
    let mut a = Ng::login(ng, "talker").await;
    let mut b = Ng::login(ng, "talker").await;
    a.join_voice(0).await;
    b.join_voice(0).await;
    a.status_for(&[(a.uid, false), (b.uid, false)]).await;

    drop(b);
    a.status_for(&[(a.uid, false)]).await;
}

// --- One room, both eras -------------------------------------------------

#[tokio::test]
async fn a_legacy_client_and_an_ng_client_share_one_voice_room() {
    let td = tempfile::tempdir().unwrap();
    let (legacy, ng, _media) = start_both(td.path(), true).await;

    let mut old = Client::login(legacy, "talker", true).await;
    old.join_voice(0).await;
    old.recv_type(NOTIFY_VOICE_STATUS).await;

    let mut new = Ng::login(ng, "talker").await;
    let ok = new.join_voice(0).await;
    assert_eq!(
        ok["participants"],
        json!([{ "uid": old.uid, "muted": false }]),
        "the ng client's reply names the 1.x client already in the room"
    );

    // The legacy client is renegotiated in its own wire's shape — a 602
    // with task id 0 — because someone it can now hear arrived.
    let offer = old.recv_type(NOTIFY_VOICE_OFFER).await;
    assert_eq!(offer.trans, 0);

    // And both are told the same room, each in its own encoding.
    old.status_for(&[(old.uid, false), (new.uid, false)]).await;
    new.status_for(&[(old.uid, false), (new.uid, false)]).await;

    // Mute crosses too: the ng client mutes, the 1.x client sees it.
    new.ok("voice_mute", json!({ "cid": 0, "muted": true }))
        .await;
    old.status_for(&[(old.uid, false), (new.uid, true)]).await;

    // And a departure on one wire is a departure on the other.
    old.send(REQ_VOICE_LEAVE, &[chat_id(0)]).await;
    old.recv_type(HDR_TASK).await;
    new.status_for(&[(new.uid, true)]).await;
}
