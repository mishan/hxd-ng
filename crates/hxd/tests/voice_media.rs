//! The exit criterion, minus the humans: a 1.5 client and an ng client in
//! one voice room, hearing each other, through the real SFU over a real
//! UDP socket.
//!
//! `voice.rs` covers the signalling with a fake media layer, and
//! `hxd-voice`'s own tests cover the media with no signalling at all.
//! This is the join: two WebRTC clients that negotiated over *different
//! control protocols* complete real DTLS against the server's media port
//! and exchange real SRTP. What is left after this is a real GtkHx and a
//! real browser, which need a machine with a microphone.
//!
//! The clients are str0m rather than a browser for the same reason
//! `hxd-voice`'s tests use it: it is a real WebRTC stack that can be
//! driven deterministically from a test.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use hotline_proto::messages::tag;
use hxd_core::video::VideoConfig;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_voice::Sfu;
use serde_json::{json, Value};
use str0m::config::Fingerprint;
use str0m::media::MediaKind;
use str0m::net::{Protocol, Receive};
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_SELFINFO: u32 = 0x162;
const REQ_LOGIN: u32 = 0x6b;
const REQ_VOICE_JOIN: u32 = 600;
const NOTIFY_VOICE_OFFER: u32 = 602;
const REQ_VOICE_ANSWER: u32 = 603;
const VOICE_ICE: u32 = 604;
const PCMU_PT: u8 = 0;

/// A server with the real SFU on a loopback UDP port.
async fn start(dir: &Path) -> (SocketAddr, SocketAddr) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("talker.toml"),
        "name = \"Talker\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         use_any_name = true\nvoice_chat = true\n",
    )
    .unwrap();

    // Bind first, advertise what we got: the port is ephemeral, and
    // ICE-lite means the candidate we hand out is the only address a
    // client will ever try.
    let media_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let media_addr = media_socket.local_addr().unwrap();
    let (sfu, mut events) = Sfu::new(&[media_addr], VideoConfig::default()).unwrap();

    let core = Arc::new(Core::new().with_voice(sfu.clone(), 16));
    let core_for_events = core.clone();
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            core_for_events.voice_media_event(ev);
        }
    });
    tokio::spawn(hxd_voice::run(sfu, media_socket));

    let ctx = ServerCtx {
        core: core.clone(),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "media test".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: Caps::empty().with(cap::VOICE),
        }),
    };
    let ng_ctx = NgCtx {
        core,
        auth: ctx.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "media test".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: vec!["voice".to_string()],
        }),
        registry: Arc::new(Registry::new()),
    };

    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let legacy = l.local_addr().unwrap();
    let n = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = n.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(l, ctx));
    tokio::spawn(hxd_ng_session::serve(n, ng_ctx));
    (legacy, ng)
}

// --- A WebRTC client on a real socket -----------------------------------

struct Media {
    rtc: Rtc,
    sock: UdpSocket,
    addr: SocketAddr,
    server: Option<SocketAddr>,
    mic_ssrc: u32,
    heard: HashMap<String, usize>,
    seq: u64,
    time: u32,
}

impl Media {
    async fn new() -> Media {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let mut rtc = RtcConfig::new()
            .clear_codecs()
            .enable_pcmu(true)
            .set_rtp_mode(true)
            .build(Instant::now());
        rtc.add_local_candidate(Candidate::host(addr, "udp").unwrap());
        rtc.direct_api().set_ice_controlling(true);
        let mic_ssrc = *rtc.direct_api().new_ssrc();
        Media {
            rtc,
            sock,
            addr,
            server: None,
            mic_ssrc,
            heard: HashMap::new(),
            seq: 1000,
            time: 160_000,
        }
    }

    /// Take the server's offer, declare what it describes, and answer.
    fn answer(&mut self, offer: &str) -> String {
        let sections = sections_of(offer);
        for (mid, dir, ssrc) in &sections {
            if self.rtc.media(mid.as_str().into()).is_none() {
                self.rtc
                    .direct_api()
                    .declare_media(mid.as_str().into(), MediaKind::Audio);
            }
            if mid == "send" {
                self.rtc.direct_api().declare_stream_tx(
                    Ssrc::from(self.mic_ssrc),
                    None,
                    mid.as_str().into(),
                    None,
                );
            } else if dir == "sendonly" {
                let ssrc = ssrc.expect("a live section declares its ssrc");
                self.rtc.direct_api().expect_stream_rx(
                    Ssrc::from(ssrc),
                    None,
                    mid.as_str().into(),
                    None,
                );
            }
        }

        if self.server.is_none() {
            self.rtc.direct_api().set_remote_ice_credentials(IceCreds {
                ufrag: attr(offer, "a=ice-ufrag:").unwrap(),
                pass: attr(offer, "a=ice-pwd:").unwrap(),
            });
            self.rtc
                .direct_api()
                .set_remote_fingerprint(parse_fingerprint(&attr(offer, "a=fingerprint:").unwrap()));
            let cand = Candidate::from_sdp_string(&format!(
                "candidate:{}",
                attr(offer, "a=candidate:").unwrap()
            ))
            .unwrap();
            self.server = Some(cand.addr());
            self.rtc.add_remote_candidate(cand);
            self.rtc.direct_api().start_dtls(true).unwrap();
        }

        let creds = self.rtc.direct_api().local_ice_credentials();
        let fp = self.rtc.direct_api().local_dtls_fingerprint().clone();
        let hex: Vec<String> = fp.bytes.iter().map(|b| format!("{b:02X}")).collect();
        let mut s = String::from("v=0\r\no=- 7 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
        s.push_str("a=group:BUNDLE");
        for (mid, _, _) in &sections {
            s.push_str(&format!(" {mid}"));
        }
        s.push_str("\r\na=msid-semantic: WMS\r\n");
        for (mid, dir, _) in &sections {
            let mirrored = match dir.as_str() {
                "sendonly" => "recvonly",
                "recvonly" => "sendonly",
                _ => "inactive",
            };
            s.push_str("m=audio 9 UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 0.0.0.0\r\n");
            s.push_str(&format!(
                "a=mid:{mid}\r\na=rtpmap:0 PCMU/8000\r\na={mirrored}\r\n"
            ));
            s.push_str("a=rtcp-mux\r\na=setup:active\r\n");
            s.push_str(&format!(
                "a=ice-ufrag:{}\r\na=ice-pwd:{}\r\n",
                creds.ufrag, creds.pass
            ));
            s.push_str(&format!(
                "a=fingerprint:{} {}\r\n",
                fp.hash_func,
                hex.join(":")
            ));
            if mid == "send" {
                s.push_str(&format!("a=ssrc:{} cname:mic\r\n", self.mic_ssrc));
            }
        }
        s
    }

    fn candidate_json(&self) -> String {
        json!({
            "candidate": Candidate::host(self.addr, "udp").unwrap().to_sdp_string(),
            "sdpMid": "send",
            "sdpMLineIndex": 0,
        })
        .to_string()
    }

    fn speak(&mut self) {
        self.seq += 1;
        self.time += 160;
        let ssrc = Ssrc::from(self.mic_ssrc);
        let mut api = self.rtc.direct_api();
        let Some(stream) = api.stream_tx(&ssrc) else {
            return;
        };
        stream.write_rtp(RtpWrite::new(
            PCMU_PT.into(),
            self.seq.into(),
            self.time,
            Instant::now(),
            vec![0xffu8; 160],
        ));
    }

    /// One pass: hand str0m the clock, send what it wants sent, and take
    /// whatever has arrived.
    async fn step(&mut self, buf: &mut [u8]) {
        let now = Instant::now();
        let _ = self.rtc.handle_input(Input::Timeout(now));
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Timeout(_)) => break,
                Ok(Output::Transmit(t)) => {
                    let _ = self.sock.send_to(&t.contents, t.destination).await;
                }
                Ok(Output::Event(Event::RtpPacket(p))) => {
                    let mid = self
                        .rtc
                        .direct_api()
                        .stream_rx(&p.header.ssrc)
                        .map(|s| s.mid().to_string())
                        // str0m rewrites `-` to `_` inside a Mid; the
                        // wire spelling is the server's own string.
                        .map(|m| m.replace('_', "-"))
                        .unwrap_or_default();
                    *self.heard.entry(mid).or_default() += 1;
                }
                Ok(Output::Event(_)) => {}
                Err(_) => break,
            }
        }
        while let Ok((n, from)) = self.sock.try_recv_from(buf) {
            let Ok(contents) = buf[..n].try_into() else {
                continue;
            };
            let input = Input::Receive(
                Instant::now(),
                Receive {
                    proto: Protocol::Udp,
                    source: from,
                    destination: self.addr,
                    contents,
                },
            );
            if self.rtc.accepts(&input) {
                let _ = self.rtc.handle_input(input);
            }
        }
    }
}

/// Drive the clients for a while, so ICE, DTLS and RTP can happen.
async fn drive(clients: &mut [&mut Media], how_long: Duration) {
    let mut buf = vec![0u8; 2048];
    let until = Instant::now() + how_long;
    while Instant::now() < until {
        for c in clients.iter_mut() {
            c.step(&mut buf).await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Drive until `done`, or panic after `limit`.
async fn drive_until(
    clients: &mut [&mut Media],
    limit: Duration,
    what: &str,
    done: impl Fn(&[&mut Media]) -> bool,
) {
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + limit;
    loop {
        for c in clients.iter_mut() {
            c.step(&mut buf).await;
        }
        if done(clients) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn sections_of(sdp: &str) -> Vec<(String, String, Option<u32>)> {
    let mut out: Vec<(String, String, Option<u32>)> = Vec::new();
    for line in sdp.lines() {
        if let Some(mid) = line.strip_prefix("a=mid:") {
            out.push((mid.to_string(), String::new(), None));
        } else if let Some(rest) = line.strip_prefix("a=") {
            if let Some(last) = out.last_mut() {
                match rest {
                    "sendonly" | "recvonly" | "inactive" => last.1 = rest.to_string(),
                    _ => {
                        if let Some(v) = rest.strip_prefix("ssrc:") {
                            last.2 = v.split_whitespace().next().and_then(|n| n.parse().ok());
                        }
                    }
                }
            }
        }
    }
    out
}

fn attr(sdp: &str, prefix: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|v| v.trim().to_string())
}

fn parse_fingerprint(v: &str) -> Fingerprint {
    let (hash_func, hex) = v.split_once(' ').unwrap();
    Fingerprint {
        hash_func: hash_func.to_string(),
        bytes: hex
            .split(':')
            .map(|p| u8::from_str_radix(p, 16).unwrap())
            .collect(),
    }
}

// --- The two control connections ----------------------------------------

struct Legacy {
    stream: TcpStream,
    trans: u32,
    uid: u16,
}

impl Legacy {
    async fn login(addr: SocketAddr) -> Legacy {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut magic)
            .await
            .unwrap();
        let mut c = Legacy {
            stream,
            trans: 0,
            uid: 0,
        };
        let xor = |b: &[u8]| -> Vec<u8> { b.iter().map(|x| !x).collect() };
        c.send(
            REQ_LOGIN,
            &[
                (tag::NAME, b"talker".to_vec()),
                (tag::ICON, 1u16.to_be_bytes().to_vec()),
                (tag::VERSION, 195u16.to_be_bytes().to_vec()),
                (tag::LOGIN, xor(b"talker")),
                (tag::PASSWORD, xor(b"pw")),
                (tag::CAPABILITIES, Caps::empty().with(cap::VOICE).to_wire()),
            ],
        )
        .await;
        let f = c.recv_type(HDR_TASK).await;
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
        self.stream
            .write_all(&pack_frame(ty, self.trans, 0, chunks))
            .await
            .unwrap();
        self.trans
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..24 {
            let f = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("timed out")
                .expect("closed");
            if f.ty == ty {
                return f;
            }
        }
        panic!("frame {ty} never arrived");
    }
}

fn sdp_of(f: &Frame) -> String {
    String::from_utf8(
        f.chunks()
            .find(|c| c.tag == tag::VOICE_SDP)
            .unwrap()
            .data
            .to_vec(),
    )
    .unwrap()
}

// --- The test ------------------------------------------------------------

#[tokio::test]
async fn a_legacy_client_and_an_ng_client_hear_each_other() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr) = start(td.path()).await;

    // --- The 1.x client joins, over transactions. -----------------------
    let mut old = Legacy::login(legacy_addr).await;
    let mut old_media = Media::new().await;
    old.send(
        REQ_VOICE_JOIN,
        &[(tag::CHAT_ID, 0u32.to_be_bytes().to_vec())],
    )
    .await;
    let reply = old.recv_type(HDR_TASK).await;
    assert_eq!(reply.flag, 0, "join refused");
    let answer = old_media.answer(&sdp_of(&reply));
    old.send(
        REQ_VOICE_ANSWER,
        &[
            (tag::CHAT_ID, 0u32.to_be_bytes().to_vec()),
            (tag::VOICE_SDP, answer.into_bytes()),
        ],
    )
    .await;
    old.recv_type(HDR_TASK).await;
    old.send(
        VOICE_ICE,
        &[
            (tag::CHAT_ID, 0u32.to_be_bytes().to_vec()),
            (tag::VOICE_ICE, old_media.candidate_json().into_bytes()),
        ],
    )
    .await;

    drive_until(
        &mut [&mut old_media],
        Duration::from_secs(10),
        "the 1.x client's DTLS",
        |c| c[0].rtc.is_connected(),
    )
    .await;

    // --- The ng client joins, over JSON. --------------------------------
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng_addr}/"))
        .await
        .unwrap();
    let mut new_media = Media::new().await;
    let mut id = 0u64;
    let mut request = |method: &str, params: Value| {
        id += 1;
        (
            id,
            json!({ "id": id, "req": method, "params": params }).to_string(),
        )
    };

    let (want, frame) = request("login", json!({"login": "talker", "password": "pw"}));
    ws.send(Message::Text(frame)).await.unwrap();
    let ok = ng_reply(&mut ws, want).await;
    let new_uid = ok["self"]["uid"].as_u64().unwrap() as u16;

    let (want, frame) = request("voice_join", json!({ "cid": 0 }));
    ws.send(Message::Text(frame)).await.unwrap();
    let ok = ng_reply(&mut ws, want).await;
    let answer = new_media.answer(ok["sdp"].as_str().unwrap());
    let (want, frame) = request("voice_answer", json!({"cid": 0, "sdp": answer}));
    ws.send(Message::Text(frame)).await.unwrap();
    ng_reply(&mut ws, want).await;
    let (want, frame) = request(
        "voice_ice",
        json!({"cid": 0, "candidate": {
            "candidate": Candidate::host(new_media.addr, "udp").unwrap().to_sdp_string(),
            "sdpMid": "send",
            "sdpMLineIndex": 0,
        }}),
    );
    ws.send(Message::Text(frame)).await.unwrap();
    ng_reply(&mut ws, want).await;

    // The 1.x client is renegotiated because someone it can now hear
    // arrived — on its own wire, as a 602.
    let offer = old.recv_type(NOTIFY_VOICE_OFFER).await;
    let answer = old_media.answer(&sdp_of(&offer));
    old.send(
        REQ_VOICE_ANSWER,
        &[
            (tag::CHAT_ID, 0u32.to_be_bytes().to_vec()),
            (tag::VOICE_SDP, answer.into_bytes()),
        ],
    )
    .await;
    old.recv_type(HDR_TASK).await;

    drive_until(
        &mut [&mut old_media, &mut new_media],
        Duration::from_secs(10),
        "both clients connected",
        |c| c.iter().all(|m| m.rtc.is_connected()),
    )
    .await;

    // --- And now the only thing that matters. ---------------------------
    for _ in 0..40 {
        old_media.speak();
        new_media.speak();
        drive(
            &mut [&mut old_media, &mut new_media],
            Duration::from_millis(20),
        )
        .await;
    }
    drive(
        &mut [&mut old_media, &mut new_media],
        Duration::from_millis(300),
    )
    .await;

    let old_mid = format!("user-{}", old.uid);
    let new_mid = format!("user-{new_uid}");
    assert!(
        new_media.heard.get(&old_mid).copied().unwrap_or(0) > 0,
        "the ng client heard nothing from the 1.x client (heard {:?})",
        new_media.heard
    );
    assert!(
        old_media.heard.get(&new_mid).copied().unwrap_or(0) > 0,
        "the 1.x client heard nothing from the ng client (heard {:?})",
        old_media.heard
    );
    // Each speaker on its own section, never bundled onto the listener's
    // own microphone mid.
    assert_eq!(old_media.heard.get("send"), None);
    assert_eq!(new_media.heard.get("send"), None);
}

async fn ng_reply<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, id: u64) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for an ng reply")
            .expect("stream ended")
            .expect("ws error");
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["reply"] == json!(id) {
                assert!(v.get("error").is_none(), "ng request failed: {v}");
                return v["ok"].clone();
            }
        }
    }
}
