//! The SFU against real WebRTC clients, with no sockets anywhere.
//!
//! str0m is sans-I/O on both sides, so a test can stand a client-side
//! `Rtc` up against the server's, hand each one the other's datagrams,
//! and get a real ICE exchange, a real DTLS handshake and real SRTP — in
//! a few milliseconds of virtual time, deterministically, in CI, with no
//! audio device and no network. That is the whole reason this crate has
//! its I/O at the edges.
//!
//! What these assert is the list of things a client would notice and the
//! two Janus bugs `docs/voice.md` §6 exists to not repeat: that a joiner
//! is heard by the people already in the room, that every remote gets its
//! own `user-{UID}` section rather than being bundled onto `send`, that
//! mute is enforced by the server, and that a departure leaves the mid in
//! place and inactive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hxd_core::video::{VideoConfig, VideoKind, VideoStream};
use hxd_core::voice::{IceCandidate, VoiceError, VoiceMedia};
use hxd_core::Uid;
use hxd_voice::sdp::{CAM_SEND_MID, SCR_SEND_MID, VP8_PT};
use hxd_voice::Sfu;
use str0m::config::Fingerprint;
use str0m::media::MediaKind;
use str0m::net::{Protocol, Receive};
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};

const SERVER: &str = "192.0.2.1:5504";
const PCMU_PT: u8 = 0;

fn cam(uid: Uid) -> VideoStream {
    VideoStream {
        uid,
        kind: VideoKind::Camera,
    }
}

fn screen(uid: Uid) -> VideoStream {
    VideoStream {
        uid,
        kind: VideoKind::Screen,
    }
}

fn server_addr() -> SocketAddr {
    SERVER.parse().unwrap()
}

// --- A client, built the same way a browser's would be ------------------

struct Client {
    uid: Uid,
    addr: SocketAddr,
    rtc: Rtc,
    mic_ssrc: u32,
    /// One SSRC per publication kind. **Two of them, distinct**, because
    /// a camera and a screen are both VP8 at payload type 96 on one
    /// bundled transport and the SSRC is the only thing that tells the
    /// server which is which.
    cam_ssrc: u32,
    scr_ssrc: u32,
    /// Suppress the `a=ssrc` on a video send section, to stand in for a
    /// client whose stack didn't emit one.
    declare_video_ssrc: bool,
    /// What arrived, by the mid it arrived on.
    heard: HashMap<String, Vec<Vec<u8>>>,
    seq: u64,
    time: u32,
    video_seq: u64,
    video_time: u32,
}

impl Client {
    fn new(uid: Uid, port: u16, now: Instant) -> Client {
        let addr: SocketAddr = format!("192.0.2.{}:{}", 100 + uid, port).parse().unwrap();
        let mut rtc = RtcConfig::new()
            .clear_codecs()
            .enable_pcmu(true)
            .enable_vp8(true)
            .set_rtp_mode(true)
            .build(now);
        rtc.add_local_candidate(Candidate::host(addr, "udp").unwrap());
        // The client is the ICE controlling agent against an ICE-lite
        // server, and takes the DTLS client role.
        rtc.direct_api().set_ice_controlling(true);
        let mic_ssrc = *rtc.direct_api().new_ssrc();
        let cam_ssrc = *rtc.direct_api().new_ssrc();
        let scr_ssrc = *rtc.direct_api().new_ssrc();
        Client {
            uid,
            addr,
            rtc,
            mic_ssrc,
            cam_ssrc,
            scr_ssrc,
            declare_video_ssrc: true,
            heard: HashMap::new(),
            seq: 1000,
            time: 160_000,
            video_seq: 5000,
            video_time: 900_000,
        }
    }

    fn send_ssrc(&self, mid: &str) -> u32 {
        match mid {
            CAM_SEND_MID => self.cam_ssrc,
            SCR_SEND_MID => self.scr_ssrc,
            _ => self.mic_ssrc,
        }
    }

    /// Take the server's offer: declare everything it describes, then
    /// answer it the way a conforming client would.
    fn answer(&mut self, offer: &str, first_time: bool) -> String {
        let sections = sections_of(offer);
        for sec in &sections {
            let mid = sec.mid.as_str();
            if self.rtc.media(mid.into()).is_none() {
                let kind = if sec.video {
                    MediaKind::Video
                } else {
                    MediaKind::Audio
                };
                self.rtc.direct_api().declare_media(mid.into(), kind);
            }
            let is_send_section = mid == "send" || mid == CAM_SEND_MID || mid == SCR_SEND_MID;
            if is_send_section {
                let ssrc = self.send_ssrc(mid);
                if self.rtc.direct_api().stream_tx(&ssrc.into()).is_none() {
                    self.rtc.direct_api().declare_stream_tx(
                        Ssrc::from(ssrc),
                        None,
                        mid.into(),
                        None,
                    );
                }
            } else if sec.dir == "sendonly" {
                // The server told us which SSRC this section carries;
                // without that a bundled client has nothing to
                // demultiplex on.
                let ssrc = sec.ssrc.expect("a live section declares its ssrc");
                if self.rtc.direct_api().stream_rx(&ssrc.into()).is_none() {
                    self.rtc.direct_api().expect_stream_rx(
                        Ssrc::from(ssrc),
                        None,
                        mid.into(),
                        None,
                    );
                }
            }
        }

        if first_time {
            let creds = IceCreds {
                ufrag: attr(offer, "a=ice-ufrag:").unwrap(),
                pass: attr(offer, "a=ice-pwd:").unwrap(),
            };
            let fp = parse_fingerprint(&attr(offer, "a=fingerprint:").unwrap());
            self.rtc.direct_api().set_remote_ice_credentials(creds);
            self.rtc.direct_api().set_remote_fingerprint(fp);
            let cand = attr(offer, "a=candidate:").unwrap();
            self.rtc.add_remote_candidate(
                Candidate::from_sdp_string(&format!("candidate:{cand}")).unwrap(),
            );
            self.rtc.direct_api().start_dtls(true).unwrap();
        }

        // A conforming answer: the offer's mids, directions mirrored,
        // our credentials, setup:active, and the microphone's SSRC.
        let creds = self.rtc.direct_api().local_ice_credentials();
        let fp = self.rtc.direct_api().local_dtls_fingerprint().clone();
        let fp_hex: Vec<String> = fp.bytes.iter().map(|b| format!("{b:02X}")).collect();
        let mut s = String::from("v=0\r\no=- 42 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
        s.push_str("a=group:BUNDLE");
        for sec in &sections {
            s.push_str(&format!(" {}", sec.mid));
        }
        s.push_str("\r\na=msid-semantic: WMS\r\n");
        for sec in &sections {
            let mid = sec.mid.as_str();
            let mirrored = match sec.dir.as_str() {
                "sendonly" => "recvonly",
                "recvonly" => "sendonly",
                _ => "inactive",
            };
            if sec.video {
                s.push_str("m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\nc=IN IP4 0.0.0.0\r\n");
            } else {
                s.push_str("m=audio 9 UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 0.0.0.0\r\n");
            }
            s.push_str(&format!("a=mid:{mid}\r\n"));
            if sec.video {
                s.push_str("a=rtpmap:96 VP8/90000\r\n");
            } else {
                s.push_str("a=rtpmap:0 PCMU/8000\r\n");
            }
            s.push_str(&format!("a={mirrored}\r\n"));
            s.push_str("a=rtcp-mux\r\na=setup:active\r\n");
            s.push_str(&format!("a=ice-ufrag:{}\r\n", creds.ufrag));
            s.push_str(&format!("a=ice-pwd:{}\r\n", creds.pass));
            s.push_str(&format!(
                "a=fingerprint:{} {}\r\n",
                fp.hash_func,
                fp_hex.join(":")
            ));
            if mid == "send" {
                s.push_str(&format!(
                    "a=ssrc:{} cname:mic-{}\r\n",
                    self.mic_ssrc, self.uid
                ));
            } else if (mid == CAM_SEND_MID || mid == SCR_SEND_MID) && self.declare_video_ssrc {
                // Mandatory on video send sections, with no fallback: the
                // server cannot tell a face from a spreadsheet without it.
                s.push_str(&format!(
                    "a=ssrc:{} cname:{}-{}\r\n",
                    self.send_ssrc(mid),
                    if mid == CAM_SEND_MID {
                        "video"
                    } else {
                        "screen"
                    },
                    self.uid
                ));
            }
        }
        s
    }

    /// Send one VP8 packet on a publication.
    fn publish_frame(&mut self, kind: VideoKind, payload: &[u8], now: Instant) {
        self.video_seq += 1;
        self.video_time += 3000;
        let ssrc = Ssrc::from(match kind {
            VideoKind::Camera => self.cam_ssrc,
            VideoKind::Screen => self.scr_ssrc,
        });
        let mut api = self.rtc.direct_api();
        let stream = api.stream_tx(&ssrc).expect("video stream");
        stream.write_rtp(RtpWrite::new(
            VP8_PT.into(),
            self.video_seq.into(),
            self.video_time,
            now,
            payload.to_vec(),
        ));
    }

    fn ice_candidate(&self) -> IceCandidate {
        IceCandidate {
            candidate: Candidate::host(self.addr, "udp").unwrap().to_sdp_string(),
            sdp_mid: Some("send".into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        }
    }

    /// Speak one 20 ms frame.
    fn speak(&mut self, payload: &[u8], now: Instant) {
        self.speak_as(PCMU_PT, payload, now);
    }

    /// The same, with a payload type of the caller's choosing.
    fn speak_as(&mut self, pt: u8, payload: &[u8], now: Instant) {
        self.seq += 1;
        self.time += 160;
        let ssrc = Ssrc::from(self.mic_ssrc);
        let mut api = self.rtc.direct_api();
        let stream = api.stream_tx(&ssrc).expect("microphone stream");
        stream.write_rtp(RtpWrite::new(
            pt.into(),
            self.seq.into(),
            self.time,
            now,
            payload.to_vec(),
        ));
    }

    fn is_connected(&self) -> bool {
        self.rtc.is_connected()
    }

    fn heard_on(&self, mid: &str) -> &[Vec<u8>] {
        self.heard.get(mid).map(Vec::as_slice).unwrap_or(&[])
    }

    fn heard_total(&self) -> usize {
        self.heard.values().map(Vec::len).sum()
    }
}

/// `(mid, direction, ssrc)` for each media section of an SDP.
fn sections_of(sdp: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    let mut video = false;
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("m=") {
            video = rest.starts_with("video");
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            out.push(Section {
                mid: mid.to_string(),
                dir: String::new(),
                ssrc: None,
                video,
            });
        } else if let Some(rest) = line.strip_prefix("a=") {
            if let Some(last) = out.last_mut() {
                match rest {
                    "sendonly" | "recvonly" | "inactive" => last.dir = rest.to_string(),
                    _ => {
                        if let Some(v) = rest.strip_prefix("ssrc:") {
                            if last.ssrc.is_none() {
                                last.ssrc =
                                    v.split_whitespace().next().and_then(|n| n.parse().ok());
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// One media section of an offer, as a client reads it.
struct Section {
    mid: String,
    dir: String,
    ssrc: Option<u32>,
    video: bool,
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

// --- The wire between them ---------------------------------------------

/// Run the exchange forward: everything the server wants to send goes to
/// the client it is addressed to, and vice versa.
fn pump(sfu: &Sfu, clients: &mut [&mut Client], now: &mut Instant, steps: usize) {
    pump_filtered(sfu, clients, now, steps, Duration::from_millis(5), |_| true)
}

/// The same, with two things a timeout test needs: a step size, and a
/// filter on what actually reaches the server.
///
/// RFC 7983 is what `allow` gets to discriminate on: the first byte says
/// STUN (0..=3), DTLS (20..=63) or SRTP/SRTCP (128..=191). Dropping one
/// class and not the others is how a test produces a peer that is stuck
/// in exactly one phase.
fn pump_filtered(
    sfu: &Sfu,
    clients: &mut [&mut Client],
    now: &mut Instant,
    steps: usize,
    step: Duration,
    allow: impl Fn(&[u8]) -> bool,
) {
    for _ in 0..steps {
        let (out, _deadline) = sfu.poll(*now);
        for d in out {
            if let Some(c) = clients.iter_mut().find(|c| c.addr == d.to) {
                let input = Input::Receive(
                    *now,
                    Receive {
                        proto: Protocol::Udp,
                        source: server_addr(),
                        destination: c.addr,
                        contents: d.data.as_slice().try_into().unwrap(),
                    },
                );
                if c.rtc.accepts(&input) {
                    c.rtc.handle_input(input).unwrap();
                }
            }
        }
        for c in clients.iter_mut() {
            c.rtc.handle_input(Input::Timeout(*now)).unwrap();
            let mut transmits: Vec<Vec<u8>> = Vec::new();
            loop {
                match c.rtc.poll_output().unwrap() {
                    Output::Timeout(_) => break,
                    Output::Transmit(t) => transmits.push(t.contents.to_vec()),
                    Output::Event(Event::RtpPacket(p)) => {
                        let mid = mid_of_ssrc(&mut c.rtc, p.header.ssrc);
                        c.heard.entry(mid).or_default().push(p.payload.to_vec());
                    }
                    Output::Event(_) => {}
                }
            }
            for data in transmits {
                if allow(&data) {
                    sfu.handle_datagram(c.addr, server_addr(), &data, *now);
                }
            }
        }
        *now += step;
    }
}

/// Only a client's STUN reaches the server: ICE stays live and every
/// other phase stalls.
fn stun_only(d: &[u8]) -> bool {
    d.first().is_some_and(|b| *b <= 3)
}

/// Which section a packet arrived on: in RTP mode the mid isn't in the
/// header, so the receive stream the SSRC was declared against is what
/// says who is speaking — which is the whole point of the server
/// declaring it in `a=ssrc`.
fn mid_of_ssrc(rtc: &mut Rtc, ssrc: str0m::rtp::Ssrc) -> String {
    rtc.direct_api()
        .stream_rx(&ssrc)
        .map(|s| spec_mid(&s.mid().to_string()))
        .unwrap_or_default()
}

/// str0m's `Mid` is a 16-byte inline id that rewrites every
/// non-alphanumeric character to `_`, so the spec's `user-5` is `user_5`
/// once it's inside the library. That is invisible on the wire — the
/// server writes its own SDP from its own strings — but a test reading
/// mids back out of str0m has to undo it.
fn spec_mid(m: &str) -> String {
    m.replace('_', "-")
}

/// The offer for a peer that has a session. `None` is the sentinel for a
/// peer that doesn't — see `VoiceMedia::offer` — which is never what a
/// test asking for an offer means.
fn offer_of(sfu: &Sfu, uid: Uid, cid: u32) -> String {
    sfu.offer(uid, cid).expect("the peer has a session")
}

/// Join a client, answer the offer it gets, and trickle its candidate.
fn join(sfu: &Sfu, c: &mut Client, cid: u32) {
    sfu.join(c.uid, cid);
    let offer = offer_of(sfu, c.uid, cid);
    let answer = c.answer(&offer, true);
    sfu.answer(c.uid, cid, &answer).unwrap();
    sfu.remote_ice(c.uid, cid, &c.ice_candidate());
}

/// Renegotiate one client — what the domain does to everyone else when a
/// room changes.
fn renegotiate(sfu: &Sfu, c: &mut Client, cid: u32) {
    let offer = offer_of(sfu, c.uid, cid);
    let answer = c.answer(&offer, false);
    sfu.answer(c.uid, cid, &answer).unwrap();
}

fn new_sfu() -> Arc<Sfu> {
    let (sfu, _events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    // The event receiver is dropped: sends into a closed channel are
    // discarded, which is what a server with no domain attached wants.
    sfu
}

// --- Tests ---------------------------------------------------------------

#[test]
fn two_clients_hear_each_other_over_real_dtls_srtp() {
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6000, now);
    let mut b = Client::new(2, 6001, now);

    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &mut now, 60);
    assert!(a.is_connected(), "the first joiner completes ICE and DTLS");

    join(&sfu, &mut b, 0);
    // A learns about B the way the domain would tell it to.
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 80);
    assert!(b.is_connected());

    // The Janus bug that motivated this design: the first joiner must
    // hear the second.
    for _ in 0..5 {
        b.speak(&[0xff; 160], now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert!(
        !a.heard_on("user-2").is_empty(),
        "the first joiner hears the second: {:?}",
        a.heard.keys().collect::<Vec<_>>()
    );
    assert_eq!(a.heard_on("user-2")[0], vec![0xff; 160]);
    // And the second hears the first.
    for _ in 0..5 {
        a.speak(&[0x7f; 160], now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert!(!b.heard_on("user-1").is_empty());

    // The other Janus bug: audio arrives on its own per-user section,
    // never bundled onto the listener's own microphone mid.
    assert!(a.heard_on("send").is_empty());
    assert!(b.heard_on("send").is_empty());
}

#[test]
fn mute_is_enforced_by_the_server() {
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6000, now);
    let mut b = Client::new(2, 6001, now);
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &mut now, 60);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 80);

    sfu.set_muted(2, 0, true);
    // A muted client that keeps streaming — which is exactly what a
    // client sending digital silence to keep its NAT binding warm does —
    // is dropped at the server.
    for _ in 0..5 {
        b.speak(&[0x11; 160], now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert_eq!(a.heard_total(), 0, "muted audio must not be forwarded");

    sfu.set_muted(2, 0, false);
    for _ in 0..5 {
        b.speak(&[0x22; 160], now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert!(!a.heard_on("user-2").is_empty(), "unmuting restores audio");
}

#[test]
fn a_departure_leaves_the_mid_in_place_and_inactive() {
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6000, now);
    let mut b = Client::new(2, 6001, now);
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &mut now, 40);
    join(&sfu, &mut b, 0);
    let with_b = offer_of(&sfu, 1, 0);
    assert!(with_b.contains("a=mid:user-2\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n"));

    sfu.leave(2, 0);
    let without_b = offer_of(&sfu, 1, 0);
    // The section stays, the port stays 9, the direction is what says
    // "gone" — deleting the m= line would misalign every later
    // sdpMLineIndex, and GtkHx reads a=inactive as its teardown signal.
    assert!(without_b.contains("a=mid:user-2\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n"));
    assert_eq!(
        without_b.matches("m=audio 9 ").count(),
        with_b.matches("m=audio 9 ").count()
    );
    // uid 1 joined an empty room, so its own microphone was negotiated
    // first and uid 2's section was appended after it.
    assert!(without_b.contains("a=group:BUNDLE send user-2\r\n"));

    // A rejoin reactivates the same mid rather than adding a second one,
    // with the fresh SSRC that a new session gets.
    sfu.join(2, 0);
    let rejoined = offer_of(&sfu, 1, 0);
    assert!(rejoined.contains("a=mid:user-2\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n"));
    assert_eq!(rejoined.matches("a=mid:user-2").count(), 1);
    let ssrc_before = attr(&with_b, "a=ssrc:").unwrap();
    let ssrc_after = attr(&rejoined, "a=ssrc:").unwrap();
    assert_ne!(ssrc_before, ssrc_after);
}

#[test]
fn the_offer_grows_one_section_per_participant() {
    let sfu = new_sfu();
    sfu.join(1, 0);
    sfu.join(2, 0);
    sfu.join(3, 0);
    // The last joiner is the one whose offer describes a full room, and
    // it is the shape of the spec's own example: a section per user
    // already there, then its own microphone.
    let offer = offer_of(&sfu, 3, 0);
    assert_eq!(offer.matches("m=audio 9 ").count(), 3);
    assert!(offer.contains("a=mid:user-1\r\n"));
    assert!(offer.contains("a=mid:user-2\r\n"));
    assert!(offer.contains("a=mid:send\r\n"));
    assert!(
        !offer.contains("a=mid:user-3"),
        "never a section for itself"
    );
    assert_eq!(offer.matches("cname:voice-").count(), 2);
    let mic = offer.find("a=mid:send").unwrap();
    assert!(mic > offer.find("a=mid:user-1").unwrap());
    assert!(mic > offer.find("a=mid:user-2").unwrap());
}

#[test]
fn a_later_joiner_appends_after_the_microphone() {
    let sfu = new_sfu();
    sfu.join(1, 0);
    sfu.join(2, 0);
    let offer = offer_of(&sfu, 1, 0);
    // uid 1 negotiated `send` before uid 2 existed, so 2's section is
    // appended after it: m-line indices never shift for a section that
    // has already been negotiated.
    assert!(offer.find("a=mid:send").unwrap() < offer.find("a=mid:user-2").unwrap());
    assert!(offer.contains("a=group:BUNDLE send user-2\r\n"));
}

#[test]
fn an_answer_without_pcmu_is_refused_and_one_with_it_is_not() {
    let now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6000, now);
    sfu.join(1, 0);
    let offer = offer_of(&sfu, 1, 0);
    let answer = a.answer(&offer, true);
    let opus_only = answer.replace("UDP/TLS/RTP/SAVPF 0", "UDP/TLS/RTP/SAVPF 111");
    assert_eq!(sfu.answer(1, 0, &opus_only), Err(VoiceError::BadAnswer));
    assert!(sfu.answer(1, 0, &answer).is_ok());
}

#[test]
fn the_offer_parses_as_sdp_in_a_real_stack() {
    // Our offer is hand-written, so the thing worth proving is that a
    // WebRTC stack that has never seen this server can read it: str0m's
    // own SDP parser, standing in for the browser and webrtcbin.
    let sfu = new_sfu();
    sfu.join(1, 0);
    sfu.join(2, 0);
    let offer = offer_of(&sfu, 2, 0);
    let parsed = str0m::change::SdpOffer::from_sdp_string(&offer)
        .unwrap_or_else(|e| panic!("a real SDP parser refused our offer: {e}\n{offer}"));
    let text = parsed.to_sdp_string();
    // Re-serialised, the mids come back through str0m's own Mid type
    // and its `_` rewriting (see spec_mid) — what matters is that both
    // sections survived the round trip with PCMU and the BUNDLE group.
    assert_eq!(text.matches("a=mid:").count(), 2);
    assert!(spec_mid(&text).contains("a=mid:user-1"));
    assert!(text.contains("a=mid:send"));
    assert!(text.contains("PCMU/8000"));
    assert!(text.contains("a=group:BUNDLE"));
}

#[test]
fn an_unknown_datagram_is_dropped_without_a_session() {
    let sfu = new_sfu();
    sfu.join(1, 0);
    // An open UDP port on the internet gets scanned. Nothing that
    // doesn't match a live ICE credential or an established peer may
    // reach a session.
    sfu.handle_datagram(
        "198.51.100.7:1234".parse().unwrap(),
        server_addr(),
        &[0u8; 64],
        Instant::now(),
    );
    assert_eq!(sfu.peer_count(), 1);
}

#[test]
fn a_server_with_no_advertisable_address_refuses_to_start() {
    assert!(Sfu::new(&[], VideoConfig::default()).is_err());
    assert!(Sfu::new(&["0.0.0.0:5504".parse().unwrap()], VideoConfig::default()).is_err());
}

// --- The spec's timeout table -------------------------------------------

#[test]
fn a_peer_that_never_answers_is_torn_down() {
    // "No SDP answer received after Join Voice Room reply: 10 seconds."
    // The SFU is sans-I/O, so the clock is whatever the caller says it
    // is and this costs no wall time at all.
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    let t0 = Instant::now();
    sfu.join(1, 0);
    offer_of(&sfu, 1, 0);

    sfu.poll(t0 + Duration::from_secs(9));
    assert_eq!(sfu.peer_count(), 1, "still inside the window");
    assert!(events.try_recv().is_err());

    sfu.poll(t0 + Duration::from_secs(11));
    assert_eq!(sfu.peer_count(), 0);
    assert_eq!(
        events.try_recv().ok(),
        Some(hxd_core::voice::MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_peer_whose_dtls_stalls_gets_the_dtls_deadline_not_the_ice_one() {
    // "ICE connectivity checks fail: 30 seconds. DTLS handshake failure:
    // 10 seconds." Two deadlines, and which one a peer is under depends
    // on how far it got: once ICE has a path, the thirty seconds are
    // spent and only the handshake is left.
    let t0 = Instant::now();
    let mut now = t0;
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    let mut a = Client::new(1, 6000, now);
    sfu.join(1, 0);
    let offer = offer_of(&sfu, 1, 0);
    let answer = a.answer(&offer, true);
    sfu.answer(1, 0, &answer).unwrap();
    let _ = events.try_recv(); // the end-of-candidates the answer emits

    // STUN gets through and DTLS does not: ICE nominates a pair, and the
    // handshake it exists to carry never happens. Keeping the checks
    // flowing for the whole window is the point — it is what stops
    // str0m's own ICE liveness from being what reaps this peer, so the
    // deadline under test is the only thing that can.
    pump_filtered(
        &sfu,
        &mut [&mut a],
        &mut now,
        90,
        Duration::from_millis(100),
        stun_only,
    );
    assert!(
        now.duration_since(t0) >= Duration::from_secs(9),
        "nine seconds of stalled handshake"
    );
    assert_eq!(sfu.peer_count(), 1, "still inside the DTLS window");
    assert!(events.try_recv().is_err());

    pump_filtered(
        &sfu,
        &mut [&mut a],
        &mut now,
        20,
        Duration::from_millis(100),
        stun_only,
    );
    assert_eq!(
        sfu.peer_count(),
        0,
        "gone at eleven seconds — not carried to thirty by the ICE budget"
    );
    assert_eq!(
        events.try_recv().ok(),
        Some(hxd_core::voice::MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_forged_datagram_cannot_hold_a_dead_session_open() {
    // The no-media timeout watches media the stack authenticated, and
    // nothing else. A datagram's first byte is not evidence of anything:
    // it arrives before str0m has verified a byte, and the address
    // fallback in handle_datagram will route anything from a remembered
    // endpoint to this peer. If the shape of it counted, anyone who
    // could reach the port and guess an address could hold a dead
    // session's room slot open indefinitely, one byte at a time.
    let t0 = Instant::now();
    let mut now = t0;
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    let mut a = Client::new(1, 6000, now);
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &mut now, 40);
    assert_eq!(sfu.peer_count(), 1, "a real session, fully connected");
    let _ = events.try_recv();

    // The client goes silent — no RTP, no RTCP — but its ICE keeps
    // running, so the session stays up on every count except media. The
    // attacker sends RTP-shaped noise from the client's address
    // throughout.
    let forged = [0x80u8; 64];
    for _ in 0..118 {
        pump_filtered(
            &sfu,
            &mut [&mut a],
            &mut now,
            1,
            Duration::from_millis(250),
            stun_only,
        );
        sfu.handle_datagram(a.addr, server_addr(), &forged, now);
    }
    assert!(now.duration_since(t0) < Duration::from_secs(30));
    assert_eq!(sfu.peer_count(), 1, "not yet — the window hasn't closed");

    for _ in 0..16 {
        pump_filtered(
            &sfu,
            &mut [&mut a],
            &mut now,
            1,
            Duration::from_millis(250),
            stun_only,
        );
        sfu.handle_datagram(a.addr, server_addr(), &forged, now);
    }
    assert_eq!(
        sfu.peer_count(),
        0,
        "reaped on schedule, whatever the forger sent"
    );
    assert_eq!(
        events.try_recv().ok(),
        Some(hxd_core::voice::MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_peer_that_answers_but_never_connects_is_torn_down() {
    // The ICE deadline proper: answered, and no path ever found.
    let now = Instant::now();
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    let mut a = Client::new(1, 6000, now);
    sfu.join(1, 0);
    let offer = offer_of(&sfu, 1, 0);
    let answer = a.answer(&offer, true);
    sfu.answer(1, 0, &answer).unwrap();
    // The client is never driven, so nothing ever reaches the server.
    let _ = events.try_recv(); // the end-of-candidates the answer emits

    sfu.poll(now + Duration::from_secs(20));
    assert_eq!(sfu.peer_count(), 1);
    sfu.poll(now + Duration::from_secs(31));
    assert_eq!(sfu.peer_count(), 0);
    assert_eq!(
        events.try_recv().ok(),
        Some(hxd_core::voice::MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_session_that_collects_too_many_sections_is_ended() {
    // A peer's sections are append-only, so one that sits in a busy room
    // accumulates an inactive section per person who ever joined
    // alongside it. Unbounded that would outgrow the wire's own chunk
    // length; the session is ended at the cap instead, and the client
    // reconnects with a clean list.
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    sfu.join(1, 0);
    offer_of(&sfu, 1, 0);

    let mut ended = false;
    for visitor in 2u16..200 {
        sfu.join(visitor, 0);
        let offer = sfu.offer(1, 0);
        let Some(offer) = offer else {
            // The cap. The offer that would have gone out is short by
            // the visitor that didn't fit and belongs to a session that
            // no longer exists, so what comes back is the sentinel and
            // not a truncated description of the room.
            assert_eq!(
                events.try_recv().ok(),
                Some(hxd_core::voice::MediaEvent::Failed { uid: 1, cid: 0 }),
                "and the domain is told, in the same breath"
            );
            sfu.leave(visitor, 0);
            ended = true;
            break;
        };
        assert!(
            offer.len() < 32 * 1024,
            "the spec's SHOULD-NOT ceiling was passed at {} bytes",
            offer.len()
        );
        sfu.leave(visitor, 0);
        assert!(
            events.try_recv().is_err(),
            "nothing failed while there was still room"
        );
    }
    assert!(ended, "the session grew without bound");
    // The long-lived peer is the one that was ended; the visitor of the
    // moment had already left under its own steam.
    assert_eq!(sfu.peer_count(), 0);
    // And a rejoin is back under the cap immediately, which is the whole
    // point of ending it rather than refusing to grow.
    sfu.join(1, 0);
    assert!(offer_of(&sfu, 1, 0).len() < 1024);
}

#[test]
fn only_pcmu_is_forwarded() {
    // The spec's payload type table has one row. Anything else on the
    // wire is a client bug or an attack, and is dropped rather than
    // relayed to everyone in the room.
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6000, now);
    let mut b = Client::new(2, 6001, now);
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &mut now, 60);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 80);

    for _ in 0..5 {
        b.speak_as(111, &[0x33; 160], now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert_eq!(a.heard_total(), 0, "a non-PCMU payload type is dropped");
}

// --- Video ---------------------------------------------------------------

#[test]
fn video_reaches_a_subscriber_and_nobody_else() {
    // The rule the whole extension rests on: publishing announces a
    // stream, it does not deliver it. A peer in the room that never
    // subscribed is on the same code path as a client that has never
    // heard of this document.
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6100, now);
    let mut b = Client::new(2, 6101, now);
    let mut c = Client::new(3, 6102, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    join(&sfu, &mut c, 0);
    renegotiate(&sfu, &mut a, 0);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b, &mut c], &mut now, 60);
    assert!(a.is_connected() && b.is_connected() && c.is_connected());

    // A publishes; B asks to see it; C does not.
    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b, &mut c], &mut now, 40);

    b.heard.clear();
    c.heard.clear();
    for i in 0..5u8 {
        a.publish_frame(VideoKind::Camera, &[0xf0, i], now);
        pump(&sfu, &mut [&mut a, &mut b, &mut c], &mut now, 4);
    }

    assert_eq!(
        b.heard_on("cam-user-1").len(),
        5,
        "the subscriber sees it on the mid the spec names"
    );
    assert_eq!(
        c.heard_total(),
        0,
        "and a peer that asked for nothing is sent nothing — no video          section in its offer, no RTP on its transport"
    );
}

#[test]
fn a_camera_and_a_screen_from_one_peer_are_told_apart_by_ssrc() {
    // The implementation note that matters most: both are VP8 at payload
    // type 96 on one bundled transport within one peer connection, so a
    // server keying receive state by mid or payload type would collide
    // them — and forwarding a screen share into the tile where a face
    // belongs is worse than forwarding nothing.
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6110, now);
    let mut b = Client::new(2, 6111, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 60);

    sfu.publish(1, 0, VideoKind::Camera);
    sfu.publish(1, 0, VideoKind::Screen);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1), screen(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 40);

    b.heard.clear();
    a.publish_frame(VideoKind::Camera, b"face", now);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 6);
    a.publish_frame(VideoKind::Screen, b"desktop", now);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 6);

    assert_eq!(b.heard_on("cam-user-1"), [b"face".to_vec()]);
    assert_eq!(b.heard_on("scr-user-1"), [b"desktop".to_vec()]);
}

#[test]
fn pause_is_enforced_by_dropping_the_publishers_rtp() {
    // Exactly as mute is, and for the same reason: a client that keeps
    // capturing must not keep being forwarded.
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6120, now);
    let mut b = Client::new(2, 6121, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 60);

    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 40);
    b.heard.clear();

    sfu.set_paused(1, 0, VideoKind::Camera, true);
    for _ in 0..4 {
        a.publish_frame(VideoKind::Camera, b"paused", now);
        pump(&sfu, &mut [&mut a, &mut b], &mut now, 4);
    }
    assert_eq!(b.heard_total(), 0, "nothing is forwarded while paused");

    // Resume needs no renegotiation — the section, the mid and the slot
    // all stayed.
    sfu.set_paused(1, 0, VideoKind::Camera, false);
    a.publish_frame(VideoKind::Camera, b"live", now);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 6);
    assert_eq!(b.heard_on("cam-user-1"), [b"live".to_vec()]);
}

#[test]
fn unsubscribing_stops_the_stream_and_keeps_the_mid() {
    // From a receiver's point of view unsubscribing is indistinguishable
    // from the publisher having stopped, which is what lets the same
    // machinery serve both.
    let mut now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6130, now);
    let mut b = Client::new(2, 6131, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 60);

    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    let subscribed = offer_of(&sfu, 2, 0);
    assert!(subscribed.contains("a=mid:cam-user-1\r\n"));
    assert!(
        subscribed.contains("b=AS:1500\r\n"),
        "the configured ceiling"
    );
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 40);
    b.heard.clear();

    sfu.set_subscriptions(2, 0, &[]);
    let dropped = offer_of(&sfu, 2, 0);
    // The m= line is still there and still port 9: deleting it would
    // misalign every later sdpMLineIndex.
    assert!(dropped.contains("a=mid:cam-user-1\r\n"));
    assert!(
        dropped.contains("a=mid:cam-user-1\r\na=rtpmap:96 VP8/90000"),
        "the section keeps its codec attributes"
    );
    assert_eq!(
        dropped.matches("a=inactive\r\n").count(),
        1,
        "and goes inactive rather than away"
    );
    renegotiate(&sfu, &mut b, 0);

    a.publish_frame(VideoKind::Camera, b"unwatched", now);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 6);
    assert_eq!(b.heard_total(), 0);
}

#[test]
fn a_video_send_section_without_an_ssrc_costs_the_publication_not_the_call() {
    // The one place this implementation refuses to guess. The answer is
    // otherwise fine, so audio carries on; the publication does not.
    let mut now = Instant::now();
    let (sfu, mut events) = Sfu::new(&[server_addr()], VideoConfig::default()).unwrap();
    let mut a = Client::new(1, 6140, now);
    let mut b = Client::new(2, 6141, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 60);
    while events.try_recv().is_ok() {}

    // A's stack answers the camera section without declaring an SSRC.
    a.declare_video_ssrc = false;
    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);

    let failed = std::iter::from_fn(|| events.try_recv().ok())
        .find(|e| matches!(e, hxd_core::voice::MediaEvent::VideoFailed { .. }));
    assert!(
        matches!(
            failed,
            Some(hxd_core::voice::MediaEvent::VideoFailed {
                uid: 1,
                cid: 0,
                kind: VideoKind::Camera
            })
        ),
        "the domain is told to release the slot"
    );

    // Audio is untouched: losing video is a degradation, losing the call
    // is a failure.
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 10);
    assert!(a.is_connected());
    b.heard.clear();
    a.speak(b"still talking", now);
    pump(&sfu, &mut [&mut a, &mut b], &mut now, 6);
    assert_eq!(b.heard_on("user-1"), [b"still talking".to_vec()]);
}

#[test]
fn a_voice_only_peers_offer_never_grows_a_video_section() {
    // The normative rule, checked where it is actually enforced: a server
    // MUST NOT include a video media section in an offer to a peer that
    // has not subscribed to that publication.
    let now = Instant::now();
    let sfu = new_sfu();
    let mut a = Client::new(1, 6150, now);
    let mut b = Client::new(2, 6151, now);
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    sfu.publish(1, 0, VideoKind::Camera);
    sfu.publish(1, 0, VideoKind::Screen);

    // The publisher gets its own send sections, and nothing else does.
    let publisher = offer_of(&sfu, 1, 0);
    assert!(publisher.contains("a=mid:cam-send\r\n"));
    assert!(publisher.contains("a=mid:scr-send\r\n"));
    assert!(publisher.contains("a=content:slides\r\n"), "only on screen");
    assert_eq!(publisher.matches("a=content:slides").count(), 1);

    let bystander = offer_of(&sfu, 2, 0);
    assert!(
        !bystander.contains("m=video"),
        "not one video section for a peer that asked for nothing"
    );
    assert!(
        bystander.contains("a=mid:user-1\r\n"),
        "audio is unaffected"
    );
}
