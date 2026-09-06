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

use hxd_core::voice::{IceCandidate, VoiceError, VoiceMedia};
use hxd_core::Uid;
use hxd_voice::Sfu;
use str0m::config::Fingerprint;
use str0m::media::MediaKind;
use str0m::net::{Protocol, Receive};
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};

const SERVER: &str = "192.0.2.1:5504";
const PCMU_PT: u8 = 0;

fn server_addr() -> SocketAddr {
    SERVER.parse().unwrap()
}

// --- A client, built the same way a browser's would be ------------------

struct Client {
    uid: Uid,
    addr: SocketAddr,
    rtc: Rtc,
    mic_ssrc: u32,
    /// What arrived, by the mid it arrived on.
    heard: HashMap<String, Vec<Vec<u8>>>,
    seq: u64,
    time: u32,
}

impl Client {
    fn new(uid: Uid, port: u16, now: Instant) -> Client {
        let addr: SocketAddr = format!("192.0.2.{}:{}", 100 + uid, port).parse().unwrap();
        let mut rtc = RtcConfig::new()
            .clear_codecs()
            .enable_pcmu(true)
            .set_rtp_mode(true)
            .build(now);
        rtc.add_local_candidate(Candidate::host(addr, "udp").unwrap());
        // The client is the ICE controlling agent against an ICE-lite
        // server, and takes the DTLS client role.
        rtc.direct_api().set_ice_controlling(true);
        let mic_ssrc = *rtc.direct_api().new_ssrc();
        Client {
            uid,
            addr,
            rtc,
            mic_ssrc,
            heard: HashMap::new(),
            seq: 1000,
            time: 160_000,
        }
    }

    /// Take the server's offer: declare everything it describes, then
    /// answer it the way a conforming client would.
    fn answer(&mut self, offer: &str, first_time: bool) -> String {
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
                // The server told us which SSRC this section carries;
                // without that a bundled client has nothing to
                // demultiplex on.
                let ssrc = ssrc.expect("a live section declares its ssrc");
                self.rtc.direct_api().expect_stream_rx(
                    Ssrc::from(ssrc),
                    None,
                    mid.as_str().into(),
                    None,
                );
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
            s.push_str(&format!("a=mid:{mid}\r\n"));
            s.push_str("a=rtpmap:0 PCMU/8000\r\n");
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
            }
        }
        s
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
    let (sfu, _events) = Sfu::new(&[server_addr()]).unwrap();
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
    assert!(Sfu::new(&[]).is_err());
    assert!(Sfu::new(&["0.0.0.0:5504".parse().unwrap()]).is_err());
}

// --- The spec's timeout table -------------------------------------------

#[test]
fn a_peer_that_never_answers_is_torn_down() {
    // "No SDP answer received after Join Voice Room reply: 10 seconds."
    // The SFU is sans-I/O, so the clock is whatever the caller says it
    // is and this costs no wall time at all.
    let (sfu, mut events) = Sfu::new(&[server_addr()]).unwrap();
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
    let (sfu, mut events) = Sfu::new(&[server_addr()]).unwrap();
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
    let (sfu, mut events) = Sfu::new(&[server_addr()]).unwrap();
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
    let (sfu, mut events) = Sfu::new(&[server_addr()]).unwrap();
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
    let (sfu, mut events) = Sfu::new(&[server_addr()]).unwrap();
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
