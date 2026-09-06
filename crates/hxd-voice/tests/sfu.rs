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
//!
//! **One clock, shared with the server.** Every test drives a [`Clock`]
//! that it also hands to `Sfu::with_locals`, so the instant a test
//! computes and the instant the SFU reads inside `join`, `answer`,
//! `set_muted`, `set_paused` and `set_subscriptions` are the same value.
//! Those five used to reach for `Instant::now()` on their own, which put
//! real elapsed time inside otherwise deterministic tests — a stalled CI
//! runner could age a session past a deadline the test had not advanced
//! its clock to — and made anything measured in seconds, the keyframe
//! limiter above all, untestable without sleeping.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hxd_core::video::{VideoConfig, VideoKind, VideoStream};
use hxd_core::voice::{IceCandidate, MediaEvent, VoiceError, VoiceMedia};
use hxd_core::Uid;
use hxd_voice::sdp::{CAM_SEND_MID, SCR_SEND_MID, VP8_PT};
use hxd_voice::Sfu;
use str0m::config::Fingerprint;
use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::sync::mpsc::UnboundedReceiver;

const SERVER: &str = "192.0.2.1:5504";
const PCMU_PT: u8 = 0;

/// The one source of "now" for a test and for the SFU it is driving.
///
/// A test advances this and both sides move together: `pump` steps it,
/// and the closure `Sfu::with_locals` holds reads the same cell. Without
/// that the `VoiceMedia` methods measured against wall time while the
/// rest of the test measured against a virtual one, so two deadlines were
/// only accidentally deterministic and the one-second keyframe interval
/// could not be crossed at all.
struct Clock(Arc<Mutex<Instant>>);

impl Clock {
    fn new() -> Clock {
        Clock(Arc::new(Mutex::new(Instant::now())))
    }

    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }

    /// The clock as `Sfu::with_locals` wants it.
    fn source(&self) -> Box<dyn Fn() -> Instant + Send + Sync> {
        let cell = Arc::clone(&self.0);
        Box::new(move || *cell.lock().unwrap())
    }
}

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
    /// The SSRC the server declared for each section this client
    /// receives on, as of the last offer it answered. A receiver needs it
    /// to ask for a keyframe, and it is the thing that must change when a
    /// section is resubscribed.
    rx_ssrc: HashMap<String, u32>,
    /// Keyframe requests that reached this client, by the mid they name.
    /// A publisher's stack raises one for every PLI or FIR the server
    /// relays to it, which is the same event a real encoder acts on — so
    /// this is the honest observation point for "the server asked".
    keyframes: HashMap<String, usize>,
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
            rx_ssrc: HashMap::new(),
            keyframes: HashMap::new(),
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
                self.rx_ssrc.insert(mid.to_string(), ssrc);
                if self.rtc.direct_api().stream_rx(&ssrc.into()).is_none() {
                    // The repair SSRC comes from `a=ssrc-group:FID`, and
                    // a receiver that ignored it would drop every
                    // retransmission the server sent as an unknown
                    // source — which is what makes naming it in the
                    // offer worth anything.
                    self.rtc.direct_api().expect_stream_rx(
                        Ssrc::from(ssrc),
                        sec.rtx.map(Ssrc::from),
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

    /// Say "I have no keyframe" on a section this client receives on,
    /// which is what a decoder handed a mid-stream first packet does.
    fn ask_for_a_keyframe(&mut self, mid: &str) {
        self.ask_for_a_keyframe_as(mid, KeyframeRequestKind::Pli);
    }

    /// The same, in either of the two forms the offer's `a=rtcp-fb` lines
    /// invite. Which one a receiver picks is its own business — both mean
    /// the same thing to the publisher, and the server relays either.
    fn ask_for_a_keyframe_as(&mut self, mid: &str, kind: KeyframeRequestKind) {
        let ssrc = *self
            .rx_ssrc
            .get(mid)
            .unwrap_or_else(|| panic!("{mid} was never declared to this client"));
        self.rtc
            .direct_api()
            .stream_rx(&Ssrc::from(ssrc))
            .expect("a receive stream for the section")
            .request_keyframe(kind);
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

    /// How many keyframe requests have reached this client on a section
    /// it publishes.
    fn keyframes_on(&self, mid: &str) -> usize {
        self.keyframes.get(mid).copied().unwrap_or(0)
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
                rtx: None,
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
                        } else if let Some(v) = rest.strip_prefix("ssrc-group:FID ") {
                            // The group names the pair, and its second
                            // member is the repair stream. Read as a pair
                            // rather than inferred from the order of the
                            // `a=ssrc` lines, for the same reason the
                            // server's own parser does.
                            let mut it = v.split_whitespace().filter_map(|n| n.parse().ok());
                            if let (Some(primary), Some(rtx)) = (it.next(), it.next()) {
                                last.ssrc = Some(primary);
                                last.rtx = Some(rtx);
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
    /// The repair SSRC of this section's `a=ssrc-group:FID`, if it has one.
    rtx: Option<u32>,
    video: bool,
}

/// One named section of an SDP, for a test that wants to look at it.
fn section_of(sdp: &str, mid: &str) -> Section {
    sections_of(sdp)
        .into_iter()
        .find(|s| s.mid == mid)
        .unwrap_or_else(|| panic!("no section {mid} in\n{sdp}"))
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
fn pump(sfu: &Sfu, clients: &mut [&mut Client], clock: &Clock, steps: usize) {
    pump_filtered(sfu, clients, clock, steps, Duration::from_millis(5), |_| {
        true
    })
}

/// The same, in strides long enough that a second of virtual time passes
/// in a handful of them — which is what a test of the keyframe limiter
/// needs, and what it would otherwise spend hundreds of steps reaching.
fn pump_slowly(sfu: &Sfu, clients: &mut [&mut Client], clock: &Clock, steps: usize) {
    pump_filtered(
        sfu,
        clients,
        clock,
        steps,
        Duration::from_millis(250),
        |_| true,
    )
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
    clock: &Clock,
    steps: usize,
    step: Duration,
    allow: impl Fn(&[u8]) -> bool,
) {
    for _ in 0..steps {
        let now = clock.now();
        let (out, _deadline) = sfu.poll(now);
        for d in out {
            if let Some(c) = clients.iter_mut().find(|c| c.addr == d.to) {
                let input = Input::Receive(
                    now,
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
            c.rtc.handle_input(Input::Timeout(now)).unwrap();
            let mut transmits: Vec<Vec<u8>> = Vec::new();
            loop {
                match c.rtc.poll_output().unwrap() {
                    Output::Timeout(_) => break,
                    Output::Transmit(t) => transmits.push(t.contents.to_vec()),
                    Output::Event(Event::RtpPacket(p)) => {
                        let mid = mid_of_ssrc(&mut c.rtc, p.header.ssrc);
                        c.heard.entry(mid).or_default().push(p.payload.to_vec());
                    }
                    Output::Event(Event::KeyframeRequest(req)) => {
                        *c.keyframes
                            .entry(spec_mid(&req.mid.to_string()))
                            .or_default() += 1;
                    }
                    Output::Event(_) => {}
                }
            }
            for data in transmits {
                if allow(&data) {
                    sfu.handle_datagram(c.addr, server_addr(), &data, now);
                }
            }
        }
        clock.advance(step);
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

/// An SFU reading the test's clock, and the events it emits.
fn sfu_with_events(clock: &Clock) -> (Arc<Sfu>, UnboundedReceiver<MediaEvent>) {
    Sfu::with_locals(
        &[server_addr()],
        &[],
        VideoConfig::default(),
        clock.source(),
    )
    .unwrap()
}

fn new_sfu(clock: &Clock) -> Arc<Sfu> {
    let (sfu, _events) = sfu_with_events(clock);
    // The event receiver is dropped: sends into a closed channel are
    // discarded, which is what a server with no domain attached wants.
    sfu
}

// --- Tests ---------------------------------------------------------------

#[test]
fn two_clients_hear_each_other_over_real_dtls_srtp() {
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    let mut b = Client::new(2, 6001, clock.now());

    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &clock, 60);
    assert!(a.is_connected(), "the first joiner completes ICE and DTLS");

    join(&sfu, &mut b, 0);
    // A learns about B the way the domain would tell it to.
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 80);
    assert!(b.is_connected());

    // The Janus bug that motivated this design: the first joiner must
    // hear the second.
    for _ in 0..5 {
        b.speak(&[0xff; 160], clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert!(
        !a.heard_on("user-2").is_empty(),
        "the first joiner hears the second: {:?}",
        a.heard.keys().collect::<Vec<_>>()
    );
    assert_eq!(a.heard_on("user-2")[0], vec![0xff; 160]);
    // And the second hears the first.
    for _ in 0..5 {
        a.speak(&[0x7f; 160], clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert!(!b.heard_on("user-1").is_empty());

    // The other Janus bug: audio arrives on its own per-user section,
    // never bundled onto the listener's own microphone mid.
    assert!(a.heard_on("send").is_empty());
    assert!(b.heard_on("send").is_empty());
}

#[test]
fn mute_is_enforced_by_the_server() {
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    let mut b = Client::new(2, 6001, clock.now());
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &clock, 60);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 80);

    sfu.set_muted(2, 0, true);
    // A muted client that keeps streaming — which is exactly what a
    // client sending digital silence to keep its NAT binding warm does —
    // is dropped at the server.
    for _ in 0..5 {
        b.speak(&[0x11; 160], clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert_eq!(a.heard_total(), 0, "muted audio must not be forwarded");

    sfu.set_muted(2, 0, false);
    for _ in 0..5 {
        b.speak(&[0x22; 160], clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert!(!a.heard_on("user-2").is_empty(), "unmuting restores audio");
}

#[test]
fn a_departure_leaves_the_mid_in_place_and_inactive() {
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    let mut b = Client::new(2, 6001, clock.now());
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &clock, 40);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6000, clock.now());
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    sfu.join(1, 0);
    // An open UDP port on the internet gets scanned. Nothing that
    // doesn't match a live ICE credential or an established peer may
    // reach a session.
    let matched = sfu.handle_datagram(
        "198.51.100.7:1234".parse().unwrap(),
        server_addr(),
        &[0u8; 64],
        clock.now(),
    );
    // And the caller is told so, which is what the pump charges against
    // the source: deciding a datagram matches nothing means offering it
    // to every live session, so it is the expensive answer.
    assert!(!matched);
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
    // is and this costs no wall time at all — and `join` reads the same
    // clock the poll below is measured against, so the ten seconds are
    // entirely virtual rather than nine virtual and however many real
    // ones the test itself took.
    let clock = Clock::new();
    let (sfu, mut events) = sfu_with_events(&clock);
    let t0 = clock.now();
    sfu.join(1, 0);
    offer_of(&sfu, 1, 0);

    sfu.poll(t0 + Duration::from_secs(9));
    assert_eq!(sfu.peer_count(), 1, "still inside the window");
    assert!(events.try_recv().is_err());

    sfu.poll(t0 + Duration::from_secs(11));
    assert_eq!(sfu.peer_count(), 0);
    assert_eq!(
        events.try_recv().ok(),
        Some(MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_peer_whose_dtls_stalls_gets_the_dtls_deadline_not_the_ice_one() {
    // "ICE connectivity checks fail: 30 seconds. DTLS handshake failure:
    // 10 seconds." Two deadlines, and which one a peer is under depends
    // on how far it got: once ICE has a path, the thirty seconds are
    // spent and only the handshake is left.
    let clock = Clock::new();
    let t0 = clock.now();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6000, clock.now());
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
        &clock,
        90,
        Duration::from_millis(100),
        stun_only,
    );
    assert!(
        clock.now().duration_since(t0) >= Duration::from_secs(9),
        "nine seconds of stalled handshake"
    );
    assert_eq!(sfu.peer_count(), 1, "still inside the DTLS window");
    assert!(events.try_recv().is_err());

    pump_filtered(
        &sfu,
        &mut [&mut a],
        &clock,
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
        Some(MediaEvent::Failed { uid: 1, cid: 0 })
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
    let clock = Clock::new();
    let t0 = clock.now();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &clock, 40);
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
            &clock,
            1,
            Duration::from_millis(250),
            stun_only,
        );
        sfu.handle_datagram(a.addr, server_addr(), &forged, clock.now());
    }
    assert!(clock.now().duration_since(t0) < Duration::from_secs(30));
    assert_eq!(sfu.peer_count(), 1, "not yet — the window hasn't closed");

    for _ in 0..16 {
        pump_filtered(
            &sfu,
            &mut [&mut a],
            &clock,
            1,
            Duration::from_millis(250),
            stun_only,
        );
        sfu.handle_datagram(a.addr, server_addr(), &forged, clock.now());
    }
    assert_eq!(
        sfu.peer_count(),
        0,
        "reaped on schedule, whatever the forger sent"
    );
    assert_eq!(
        events.try_recv().ok(),
        Some(MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_peer_that_answers_but_never_connects_is_torn_down() {
    // The ICE deadline proper: answered, and no path ever found.
    let clock = Clock::new();
    let t0 = clock.now();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    sfu.join(1, 0);
    let offer = offer_of(&sfu, 1, 0);
    let answer = a.answer(&offer, true);
    sfu.answer(1, 0, &answer).unwrap();
    // The client is never driven, so nothing ever reaches the server.
    let _ = events.try_recv(); // the end-of-candidates the answer emits

    sfu.poll(t0 + Duration::from_secs(20));
    assert_eq!(sfu.peer_count(), 1);
    sfu.poll(t0 + Duration::from_secs(31));
    assert_eq!(sfu.peer_count(), 0);
    assert_eq!(
        events.try_recv().ok(),
        Some(MediaEvent::Failed { uid: 1, cid: 0 })
    );
}

#[test]
fn a_session_whose_offer_outgrows_its_byte_budget_is_ended() {
    // A peer's sections are append-only, so one that sits in a busy room
    // accumulates an inactive section per person who ever joined
    // alongside it. Unbounded that would outgrow the wire's own chunk
    // length; the session is ended at the cap instead, and the client
    // reconnects with a clean list.
    //
    // **The cap is `sdp::MAX_OFFER_BYTES` and not a section count**,
    // which is why the assertion below is the one that matters: a video
    // section costs half as much again as an audio one, so a fixed count
    // that fitted 32 KB of audio was already over the line for a room
    // with cameras in it. This loop's visitors are voice-only, so what it
    // measures is that the budget still bites at all and still bites
    // before the ceiling — not how many sections that came to.
    let clock = Clock::new();
    let (sfu, mut events) = sfu_with_events(&clock);
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
                Some(MediaEvent::Failed { uid: 1, cid: 0 }),
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6000, clock.now());
    let mut b = Client::new(2, 6001, clock.now());
    join(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a], &clock, 60);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 80);

    for _ in 0..5 {
        b.speak_as(111, &[0x33; 160], clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6100, clock.now());
    let mut b = Client::new(2, 6101, clock.now());
    let mut c = Client::new(3, 6102, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    join(&sfu, &mut c, 0);
    renegotiate(&sfu, &mut a, 0);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b, &mut c], &clock, 60);
    assert!(a.is_connected() && b.is_connected() && c.is_connected());

    // A publishes; B asks to see it; C does not.
    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b, &mut c], &clock, 40);

    b.heard.clear();
    c.heard.clear();
    for i in 0..5u8 {
        a.publish_frame(VideoKind::Camera, &[0xf0, i], clock.now());
        pump(&sfu, &mut [&mut a, &mut b, &mut c], &clock, 4);
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
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6110, clock.now());
    let mut b = Client::new(2, 6111, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);

    sfu.publish(1, 0, VideoKind::Camera);
    sfu.publish(1, 0, VideoKind::Screen);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1), screen(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 40);

    b.heard.clear();
    a.publish_frame(VideoKind::Camera, b"face", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    a.publish_frame(VideoKind::Screen, b"desktop", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);

    assert_eq!(b.heard_on("cam-user-1"), [b"face".to_vec()]);
    assert_eq!(b.heard_on("scr-user-1"), [b"desktop".to_vec()]);
}

#[test]
fn pause_is_enforced_by_dropping_the_publishers_rtp() {
    // Exactly as mute is, and for the same reason: a client that keeps
    // capturing must not keep being forwarded.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6120, clock.now());
    let mut b = Client::new(2, 6121, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);

    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 40);
    b.heard.clear();

    sfu.set_paused(1, 0, VideoKind::Camera, true);
    for _ in 0..4 {
        a.publish_frame(VideoKind::Camera, b"paused", clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert_eq!(b.heard_total(), 0, "nothing is forwarded while paused");

    // Resume needs no renegotiation — the section, the mid and the slot
    // all stayed.
    sfu.set_paused(1, 0, VideoKind::Camera, false);
    a.publish_frame(VideoKind::Camera, b"live", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_on("cam-user-1"), [b"live".to_vec()]);
}

#[test]
fn unsubscribing_stops_the_stream_and_keeps_the_mid() {
    // From a receiver's point of view unsubscribing is indistinguishable
    // from the publisher having stopped, which is what lets the same
    // machinery serve both.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6130, clock.now());
    let mut b = Client::new(2, 6131, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);

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
    pump(&sfu, &mut [&mut a, &mut b], &clock, 40);
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

    a.publish_frame(VideoKind::Camera, b"unwatched", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_total(), 0);
}

#[test]
fn a_video_send_section_without_an_ssrc_costs_the_publication_not_the_call() {
    // The one place this implementation refuses to guess. The answer is
    // otherwise fine, so audio carries on; the publication does not.
    let clock = Clock::new();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6140, clock.now());
    let mut b = Client::new(2, 6141, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);
    while events.try_recv().is_ok() {}

    // A's stack answers the camera section without declaring an SSRC.
    a.declare_video_ssrc = false;
    sfu.publish(1, 0, VideoKind::Camera);
    renegotiate(&sfu, &mut a, 0);

    let failed = std::iter::from_fn(|| events.try_recv().ok())
        .find(|e| matches!(e, MediaEvent::VideoFailed { .. }));
    assert!(
        matches!(
            failed,
            Some(MediaEvent::VideoFailed {
                uid: 1,
                cid: 0,
                kind: VideoKind::Camera
            })
        ),
        "the domain is told to release the slot"
    );

    // Audio is untouched: losing video is a degradation, losing the call
    // is a failure.
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert!(a.is_connected());
    b.heard.clear();
    a.speak(b"still talking", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_on("user-1"), [b"still talking".to_vec()]);
}

#[test]
fn a_voice_only_peers_offer_never_grows_a_video_section() {
    // The normative rule, checked where it is actually enforced: a server
    // MUST NOT include a video media section in an offer to a peer that
    // has not subscribed to that publication.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6150, clock.now());
    let mut b = Client::new(2, 6151, clock.now());
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

/// One publisher — `clients[0]` — with a live camera every other client
/// in the slice is subscribed to, negotiated and connected.
///
/// The publication's *receive* SSRC is bound by the time this returns,
/// which is the part that matters for the keyframe tests below: a
/// request for a publication nothing has been bound to has nowhere to go
/// and is silently not sent, so a test that skipped the publisher's own
/// renegotiation would be asserting on the wrong absence.
fn camera_published(sfu: &Sfu, clock: &Clock, clients: &mut [&mut Client]) {
    for c in clients.iter_mut() {
        join(sfu, c, 0);
    }
    // Everyone who joined before the last arrival has to be told about
    // the ones after it, which is what the domain does.
    for c in clients.iter_mut() {
        renegotiate(sfu, c, 0);
    }
    pump(sfu, clients, clock, 80);
    let publisher = clients[0].uid;
    assert!(
        sfu.publish(publisher, 0, VideoKind::Camera),
        "the SFU seated the publication"
    );
    renegotiate(sfu, clients[0], 0);
    for c in clients.iter_mut().skip(1) {
        sfu.set_subscriptions(c.uid, 0, &[cam(publisher)]);
        renegotiate(sfu, c, 0);
    }
    pump(sfu, clients, clock, 40);
}

// --- Keyframes -----------------------------------------------------------

#[test]
fn a_new_subscription_asks_the_publisher_for_a_keyframe() {
    // The first of the spec's four keyframe triggers. A subscriber
    // arriving mid-stream has no keyframe and can decode nothing until
    // one comes, and VP8 will not volunteer one for many seconds — so the
    // server asks rather than waiting.
    //
    // The observation point is the publisher's own stack raising
    // `KeyframeRequest`, which is the event a real encoder acts on: it
    // means the PLI was built, encrypted, sent, and understood at the far
    // end, rather than merely that a field moved on the server.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6160, clock.now());
    let mut b = Client::new(2, 6161, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);

    assert!(sfu.publish(1, 0, VideoKind::Camera));
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(
        a.keyframes_on(CAM_SEND_MID),
        0,
        "publishing announces a stream; nobody is watching it yet"
    );

    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(
        a.keyframes_on(CAM_SEND_MID),
        1,
        "the subscriber's arrival is what asks"
    );
}

#[test]
fn resuming_a_paused_publication_asks_for_a_keyframe() {
    // A decoder cannot start mid-stream, so a resumed publication is a
    // black tile in every subscriber's grid until the next keyframe.
    // Pausing keeps the section, the mid and the slot, which is why
    // nothing else in the negotiation would prompt one.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6170, clock.now());
    let mut b = Client::new(2, 6171, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);

    // Past the limiter's second, so what is counted below is the resume's
    // own request and not the subscription's still being in flight.
    pump_slowly(&sfu, &mut [&mut a, &mut b], &clock, 6);
    let before = a.keyframes_on(CAM_SEND_MID);

    sfu.set_paused(1, 0, VideoKind::Camera, true);
    sfu.set_paused(1, 0, VideoKind::Camera, false);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(a.keyframes_on(CAM_SEND_MID), before + 1);
}

#[test]
fn a_receivers_keyframe_request_is_relayed_to_the_publisher() {
    // The server does not decode, so it cannot produce a keyframe itself;
    // a receiver that says "I have no keyframe" is asking the publisher,
    // through us. The three `a=rtcp-fb` lines on every video section are
    // what make the request legal in the first place.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6180, clock.now());
    let mut b = Client::new(2, 6181, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);
    pump_slowly(&sfu, &mut [&mut a, &mut b], &clock, 6);
    let before = a.keyframes_on(CAM_SEND_MID);

    b.ask_for_a_keyframe_as("cam-user-1", KeyframeRequestKind::Pli);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(
        a.keyframes_on(CAM_SEND_MID),
        before + 1,
        "the PLI arrived on the receiver's mid and left on the publisher's"
    );

    // FIR is the other half of what the offer's `a=rtcp-fb` lines invite,
    // and means the same thing to a publisher: a receiver that has picked
    // it must not be ignored because it picked the other spelling.
    pump_slowly(&sfu, &mut [&mut a, &mut b], &clock, 6);
    b.ask_for_a_keyframe_as("cam-user-1", KeyframeRequestKind::Fir);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(a.keyframes_on(CAM_SEND_MID), before + 2);
}

#[test]
fn a_burst_of_requests_from_a_room_costs_the_publisher_one_keyframe() {
    // The rate limit is not an optimisation. Three receivers whose
    // renegotiations complete together each want a keyframe within a few
    // milliseconds of each other, and three keyframes is a bitrate spike
    // at precisely the moment the network is busiest — for one keyframe's
    // worth of benefit, because the first satisfies all three.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6190, clock.now());
    let mut b = Client::new(2, 6191, clock.now());
    let mut c = Client::new(3, 6192, clock.now());
    let mut d = Client::new(4, 6193, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b, &mut c, &mut d]);
    pump_slowly(&sfu, &mut [&mut a, &mut b, &mut c, &mut d], &clock, 6);
    a.keyframes.clear();
    let burst_began = clock.now();

    // Pumped between each, so every request really does reach the
    // publisher's stack separately: without the limiter this would be
    // three events, and not one only because a pending request is an
    // `Option` that the next one overwrote.
    b.ask_for_a_keyframe("cam-user-1");
    pump(&sfu, &mut [&mut a, &mut b, &mut c, &mut d], &clock, 6);
    c.ask_for_a_keyframe("cam-user-1");
    pump(&sfu, &mut [&mut a, &mut b, &mut c, &mut d], &clock, 6);
    d.ask_for_a_keyframe("cam-user-1");
    pump(&sfu, &mut [&mut a, &mut b, &mut c, &mut d], &clock, 6);

    assert!(
        clock.now().duration_since(burst_began) < Duration::from_secs(1),
        "the whole burst has to fit inside one interval to be a burst"
    );
    assert_eq!(
        a.keyframes_on(CAM_SEND_MID),
        1,
        "three askers, one keyframe"
    );
}

#[test]
fn a_peer_that_has_unsubscribed_can_no_longer_ask_for_a_keyframe() {
    // Sections are never removed, so a peer that subscribed once and
    // unsubscribed still has one, still has a receive stream behind it,
    // and its stack will happily go on sending PLIs for a tile nobody is
    // looking at. Answering those would spend the publisher's keyframes —
    // and so the whole room's bitrate — on a viewer who left.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6194, clock.now());
    let mut b = Client::new(2, 6195, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);

    sfu.set_subscriptions(2, 0, &[]);
    renegotiate(&sfu, &mut b, 0);
    pump_slowly(&sfu, &mut [&mut a, &mut b], &clock, 6);
    let before = a.keyframes_on(CAM_SEND_MID);

    b.ask_for_a_keyframe("cam-user-1");
    pump(&sfu, &mut [&mut a, &mut b], &clock, 10);
    assert_eq!(
        a.keyframes_on(CAM_SEND_MID),
        before,
        "a request only counts while the subscription does"
    );
}

// --- Stopping a publication ----------------------------------------------

#[test]
fn unpublishing_deactivates_both_ends_and_stops_the_forwarding() {
    // The publisher's half of "the stream stopped", which is a different
    // code path from the receiver's: unsubscribing changes one peer's
    // subscription set, unpublishing removes the publication every
    // subscriber's section was derived from. Both must leave the mid
    // where it is — deleting an `m=` line would misalign every later
    // sdpMLineIndex — and both must stop the RTP.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6200, clock.now());
    let mut b = Client::new(2, 6201, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);

    b.heard.clear();
    a.publish_frame(VideoKind::Camera, b"live", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(
        b.heard_on("cam-user-1"),
        [b"live".to_vec()],
        "flowing before it is stopped"
    );

    sfu.unpublish(1, 0, VideoKind::Camera);
    let publisher = offer_of(&sfu, 1, 0);
    assert!(
        publisher.contains("a=mid:cam-send\r\n"),
        "the mid is kept, which is how the publication comes back"
    );
    assert_eq!(section_of(&publisher, CAM_SEND_MID).dir, "inactive");
    let viewer = offer_of(&sfu, 2, 0);
    assert!(viewer.contains("a=mid:cam-user-1\r\n"));
    assert_eq!(
        section_of(&viewer, "cam-user-1").dir,
        "inactive",
        "and every subscriber's section goes with it"
    );
    renegotiate(&sfu, &mut a, 0);
    renegotiate(&sfu, &mut b, 0);

    // The client keeps capturing, because a stop is a server-side fact
    // and the SFU does not trust a client to have honoured it.
    b.heard.clear();
    for _ in 0..4 {
        a.publish_frame(VideoKind::Camera, b"stopped", clock.now());
        pump(&sfu, &mut [&mut a, &mut b], &clock, 4);
    }
    assert_eq!(b.heard_total(), 0, "nothing is forwarded after the stop");
}

// --- Publications and outstanding offers ---------------------------------

#[test]
fn a_publication_started_under_an_outstanding_offer_survives_its_answer() {
    // The start transaction deliberately carries no offer of its own — a
    // renegotiation may already be in flight, and the extension forbids a
    // second offer before the first is answered — so between the start
    // and the offer that follows it, the next answer to arrive is the
    // answer to the *previous* offer, which of course never mentioned
    // `cam-send`. Reading that absence as "the client declined the
    // section" destroyed the publication a moment after it started and
    // told the domain to release a slot it had just claimed.
    let clock = Clock::new();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6210, clock.now());
    let mut b = Client::new(2, 6211, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);
    while events.try_recv().is_ok() {}

    // An offer goes out for something else entirely, and is not answered
    // yet when the publication starts.
    let outstanding = offer_of(&sfu, 1, 0);
    assert!(
        !outstanding.contains("cam-send"),
        "the offer was built before the publication existed"
    );
    assert!(sfu.publish(1, 0, VideoKind::Camera));

    // Now the client answers the offer it was actually sent.
    let answer = a.answer(&outstanding, false);
    sfu.answer(1, 0, &answer).unwrap();
    assert!(
        !std::iter::from_fn(|| events.try_recv().ok())
            .any(|e| matches!(e, MediaEvent::VideoFailed { .. })),
        "a section the client has never been shown cannot have been declined by it"
    );

    // And the publication is still there to be offered, answered and used.
    renegotiate(&sfu, &mut a, 0);
    sfu.set_subscriptions(2, 0, &[cam(1)]);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 40);
    b.heard.clear();
    a.publish_frame(VideoKind::Camera, b"face", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_on("cam-user-1"), [b"face".to_vec()]);
}

#[test]
fn one_ssrc_declared_for_two_publications_costs_the_second_one() {
    // `expect_stream_rx` is keyed by SSRC, so a second call with the same
    // number and a different mid keeps the first binding and returns
    // silently. An answer that spends one SSRC on both send sections
    // therefore used to leave camera and screen pointing at the same
    // inbound stream, with whichever publication was found first winning
    // — which is a screen share arriving in the tile where a face belongs.
    // There is nothing left to demultiplex by, so the second section is
    // refused exactly as one with no SSRC at all is.
    let clock = Clock::new();
    let (sfu, mut events) = sfu_with_events(&clock);
    let mut a = Client::new(1, 6220, clock.now());
    let mut b = Client::new(2, 6221, clock.now());
    join(&sfu, &mut a, 0);
    join(&sfu, &mut b, 0);
    renegotiate(&sfu, &mut a, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 60);
    while events.try_recv().is_ok() {}

    assert!(sfu.publish(1, 0, VideoKind::Camera));
    assert!(sfu.publish(1, 0, VideoKind::Screen));
    let offer = offer_of(&sfu, 1, 0);
    let answer = a.answer(&offer, false);
    let colliding = answer.replace(
        &format!("a=ssrc:{} cname:screen-1", a.scr_ssrc),
        &format!("a=ssrc:{} cname:screen-1", a.cam_ssrc),
    );
    assert_ne!(colliding, answer, "the screen section declared an SSRC");
    sfu.answer(1, 0, &colliding).unwrap();

    let failed: Vec<MediaEvent> = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|e| matches!(e, MediaEvent::VideoFailed { .. }))
        .collect();
    assert_eq!(
        failed,
        vec![MediaEvent::VideoFailed {
            uid: 1,
            cid: 0,
            kind: VideoKind::Screen
        }],
        "the camera was seated first, so the screen is the one with nothing to bind to"
    );

    // The camera keeps its section live; the screen's keeps its mid and
    // goes inactive, which is the same shape a stopped publication has.
    let publisher = offer_of(&sfu, 1, 0);
    assert_eq!(section_of(&publisher, CAM_SEND_MID).dir, "recvonly");
    assert_eq!(section_of(&publisher, SCR_SEND_MID).dir, "inactive");

    // A subscriber to both is offered a section for the publication that
    // exists and none at all for the one that doesn't, so the streams
    // cannot cross however the client's SDP was written.
    sfu.set_subscriptions(2, 0, &[cam(1), screen(1)]);
    let viewer = offer_of(&sfu, 2, 0);
    assert_eq!(section_of(&viewer, "cam-user-1").dir, "sendonly");
    assert!(
        !viewer.contains("a=mid:scr-user-1"),
        "no section for a publication the answer cost"
    );
    renegotiate(&sfu, &mut a, 0);
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 40);

    b.heard.clear();
    a.publish_frame(VideoKind::Screen, b"desktop", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(
        b.heard_total(),
        0,
        "the refused publication forwards nothing, least of all as the camera"
    );
    a.publish_frame(VideoKind::Camera, b"face", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_on("cam-user-1"), [b"face".to_vec()]);
}

// --- Remote video sections -----------------------------------------------

#[test]
fn resubscribing_gets_a_fresh_ssrc_on_the_same_mid() {
    // Subscription is per-receiver, so between one peer unsubscribing and
    // resubscribing the publisher's stream carried on to everyone else.
    // Resuming it on the SSRC this receiver already knew would hand it a
    // sequence-number gap of every packet it missed, and libwebrtc
    // answers a gap that size with a NACK storm for packets no cache
    // still holds. A new SSRC is a new stream, which is what actually
    // happened from the receiver's side — while the mid must not move,
    // because it is the spec's track-to-user mapping.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6230, clock.now());
    let mut b = Client::new(2, 6231, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);

    let subscribed = offer_of(&sfu, 2, 0);
    let first = section_of(&subscribed, "cam-user-1")
        .ssrc
        .expect("a live section declares its ssrc");

    sfu.set_subscriptions(2, 0, &[]);
    let dropped = offer_of(&sfu, 2, 0);
    assert_eq!(section_of(&dropped, "cam-user-1").dir, "inactive");
    renegotiate(&sfu, &mut b, 0);

    sfu.set_subscriptions(2, 0, &[cam(1)]);
    let again = offer_of(&sfu, 2, 0);
    let back = section_of(&again, "cam-user-1");
    assert_eq!(back.dir, "sendonly");
    assert_ne!(
        back.ssrc.expect("a live section declares its ssrc"),
        first,
        "a resumed subscription is a new stream to the receiver"
    );
    assert_eq!(
        again.matches("a=mid:cam-user-1\r\n").count(),
        1,
        "on the mid it always had, and only that one"
    );

    // And the new stream is one the receiver can actually decode, which
    // is the whole reason for the change.
    renegotiate(&sfu, &mut b, 0);
    pump(&sfu, &mut [&mut a, &mut b], &clock, 20);
    b.heard.clear();
    a.publish_frame(VideoKind::Camera, b"back", clock.now());
    pump(&sfu, &mut [&mut a, &mut b], &clock, 6);
    assert_eq!(b.heard_on("cam-user-1"), [b"back".to_vec()]);
}

#[test]
fn a_live_video_section_names_its_repair_ssrc_and_an_inactive_one_does_not() {
    // Offering `a=rtpmap:97 rtx` and never saying which SSRC the
    // retransmissions arrive on is worse than offering no RTX at all: the
    // receiver NACKs, the server resends on an SSRC the receiver was
    // never told about, and the repair is dropped as unknown — bandwidth
    // spent on both hops, nothing recovered. `a=ssrc-group:FID` is the
    // binding, and it belongs only on a section that is actually flowing.
    let clock = Clock::new();
    let sfu = new_sfu(&clock);
    let mut a = Client::new(1, 6240, clock.now());
    let mut b = Client::new(2, 6241, clock.now());
    camera_published(&sfu, &clock, &mut [&mut a, &mut b]);

    let subscribed = offer_of(&sfu, 2, 0);
    let sec = section_of(&subscribed, "cam-user-1");
    let ssrc = sec.ssrc.expect("a live section declares its ssrc");
    let rtx = sec.rtx.expect("and groups the repair stream with it");
    assert_ne!(ssrc, rtx);
    assert!(subscribed.contains(&format!("a=ssrc-group:FID {ssrc} {rtx}\r\n")));
    assert!(subscribed.contains(&format!("a=ssrc:{ssrc} cname:video-1\r\n")));
    assert!(
        subscribed.contains(&format!("a=ssrc:{rtx} cname:video-1\r\n")),
        "the repair stream shares the cname or it is a different source"
    );
    // The publisher's own capture section carries no SSRC — the client
    // declares that one — so it names no repair stream either.
    assert!(!offer_of(&sfu, 1, 0).contains("a=ssrc-group"));

    sfu.set_subscriptions(2, 0, &[]);
    let dropped = offer_of(&sfu, 2, 0);
    assert_eq!(section_of(&dropped, "cam-user-1").dir, "inactive");
    assert!(
        !dropped.contains("a=ssrc-group"),
        "naming a repair SSRC for a stream that isn't flowing says nothing"
    );
}
