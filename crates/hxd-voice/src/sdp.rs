//! The offer template and the answer parser.
//!
//! **Hand-written SDP is a feature here, not a cost.** The spec fixes the
//! offer's shape down to the attribute list, and with ICE-lite the only
//! variable parts are our credentials, our fingerprint, the room's mids
//! and directions, and the SSRC on each forwarded section. That makes the
//! offer a template — deterministic per (peer, room state) — which is
//! what lets the domain ask for "the current offer for this peer" on
//! demand instead of diffing. It is also why we use str0m's direct API:
//! its SDP API generates random mids, and the spec's whole track-to-user
//! mapping *is* the mid names.
//!
//! The answer parser wants five things — ICE credentials, the DTLS
//! fingerprint and role, PCMU's presence, and the `send` section's
//! `a=ssrc` — and is deliberately tolerant about everything else. A
//! client may reorder attributes, add its own, or answer sections we
//! don't care about; none of that is our business.
//!
//! **Video changes one of those tolerances and nothing else.** Camera and
//! screen are both VP8 at payload type 96 on one bundled transport, so
//! the payload-type fallback that saves an audio answer with no `a=ssrc`
//! cannot tell a face from a spreadsheet. For video send sections the
//! SSRC is required and there is no guess to fall back on: forwarding a
//! screen share into the tile where a face belongs is worse than
//! forwarding nothing. See `docs/capabilities-video.md` §"Send SSRC
//! Declaration".

use std::fmt::Write as _;
use std::net::SocketAddr;

use str0m::config::Fingerprint;
use str0m::{Candidate, IceCreds};

/// The mid of a client's own microphone section.
pub const MIC_MID: &str = "send";

/// PCMU's static payload type (RFC 3551). No dynamic negotiation exists
/// for it, which is half of why the spec chose it.
pub const PCMU_PT: u8 = 0;

/// The mid of a client's own camera section.
pub const CAM_SEND_MID: &str = "cam-send";

/// The mid of a client's own screen-share section.
pub const SCR_SEND_MID: &str = "scr-send";

/// VP8's payload type. Dynamic, so the video spec fixes it rather than
/// negotiating: the server is always the offerer, and str0m's own
/// `enable_vp8` uses 96/97 for exactly the same reason everyone else
/// does.
pub const VP8_PT: u8 = 96;

/// The RTX payload type paired with [`VP8_PT`] (`a=fmtp:97 apt=96`).
pub const VP8_RTX_PT: u8 = 97;

/// The longest mid this implementation will put on the wire.
///
/// **Not stylistic.** WebRTC stacks negotiate the MID RTP header
/// extension, and RFC 8285's one-byte header form carries at most 16
/// bytes of extension data — a longer mid simply cannot be represented
/// in it. It is why the spec's prefixes are abbreviated: `scr-user-65535`
/// is 14 bytes where the more readable `screen-user-65535` would be 17.
pub const MAX_MID_LEN: usize = 16;

/// What a media section carries, which decides its `m=` line, its codec
/// attributes and the `cname` on its SSRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionMedia {
    Audio,
    Camera,
    Screen,
}

impl SectionMedia {
    fn is_video(self) -> bool {
        !matches!(self, SectionMedia::Audio)
    }

    /// The `cname` prefix the spec's offer example uses for each kind.
    /// GtkHx reads the cname as its fallback when a mid can't be
    /// resolved, so the three name spaces stay distinguishable.
    fn cname_prefix(self) -> &'static str {
        match self {
            SectionMedia::Audio => "voice",
            SectionMedia::Camera => "video",
            SectionMedia::Screen => "screen",
        }
    }
}

/// A media section's direction, from the offerer's — the server's — point
/// of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The server forwards this participant's audio to the client.
    SendOnly,
    /// The server receives the client's microphone here.
    RecvOnly,
    /// This participant has left. The section stays, keeping its mid and
    /// its `m=` line index; the port stays 9.
    Inactive,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }
}

/// One media section of an offer.
pub struct OfferSection<'a> {
    pub mid: &'a str,
    /// Audio, camera or screen. Screen sections additionally carry
    /// `a=content:slides` (RFC 4796), so a client that ignores the video
    /// extension's status notifications can still tell a shared desktop
    /// from a face out of the SDP alone.
    pub media: SectionMedia,
    pub direction: Direction,
    /// The SSRC this section carries, and the user it belongs to — the
    /// `a=ssrc:<n> cname:<kind>-<uid>` line. Absent on the client's own
    /// capture sections, whose SSRCs the *client* declares in its answer.
    pub ssrc: Option<(u32, u16)>,
    /// The `b=AS` ceiling in kbit/s for this section, from the server's
    /// configured limit for the kind. Ceilings are configuration, not
    /// negotiation.
    pub bandwidth_kbps: Option<u32>,
}

impl<'a> OfferSection<'a> {
    /// An audio section, which is every section the voice extension has.
    pub fn audio(mid: &'a str, direction: Direction, ssrc: Option<(u32, u16)>) -> Self {
        OfferSection {
            mid,
            media: SectionMedia::Audio,
            direction,
            ssrc,
            bandwidth_kbps: None,
        }
    }
}

/// Everything the offer needs that isn't a section.
pub struct OfferParams<'a> {
    pub session_id: u64,
    /// Bumped on every offer: RFC 3264 wants the version to change
    /// whenever the description does, and every renegotiation changes it.
    pub version: u64,
    pub creds: &'a IceCreds,
    pub fingerprint: &'a Fingerprint,
    pub candidates: &'a [Candidate],
}

/// Build the server's offer.
///
/// Every section carries the ICE credentials, fingerprint and candidates,
/// which is redundant under BUNDLE and is exactly what the spec's example
/// does — a client that ignores BUNDLE for a moment still sees a complete
/// section.
pub fn offer(params: &OfferParams<'_>, sections: &[OfferSection<'_>]) -> String {
    let mut s = String::with_capacity(512 + sections.len() * 384);
    let _ = write!(
        s,
        "v=0\r\n\
         o=- {} {} IN IP4 0.0.0.0\r\n\
         s=-\r\n\
         t=0 0\r\n",
        params.session_id, params.version
    );
    s.push_str("a=group:BUNDLE");
    for sec in sections {
        let _ = write!(s, " {}", sec.mid);
    }
    s.push_str("\r\n");
    s.push_str("a=msid-semantic: WMS\r\n");
    // We are the passive ICE side with host candidates only: the client
    // does the connectivity checks against an address it already knows.
    s.push_str("a=ice-lite\r\n");

    let fp = fingerprint_hex(params.fingerprint);
    for sec in sections {
        // Port 9 is the placeholder for a bundled description (RFC 8843
        // §9.3); the media path is the ICE candidates. It stays 9 even
        // for a section that has gone inactive.
        if sec.media.is_video() {
            let _ = write!(s, "m=video 9 UDP/TLS/RTP/SAVPF {VP8_PT} {VP8_RTX_PT}\r\n");
        } else {
            s.push_str("m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n");
        }
        s.push_str("c=IN IP4 0.0.0.0\r\n");
        if let Some(kbps) = sec.bandwidth_kbps {
            let _ = write!(s, "b=AS:{kbps}\r\n");
        }
        let _ = write!(s, "a=mid:{}\r\n", sec.mid);
        if sec.media == SectionMedia::Screen {
            s.push_str("a=content:slides\r\n");
        }
        if sec.media.is_video() {
            let _ = write!(s, "a=rtpmap:{VP8_PT} VP8/90000\r\n");
            let _ = write!(s, "a=rtpmap:{VP8_RTX_PT} rtx/90000\r\n");
            let _ = write!(s, "a=fmtp:{VP8_RTX_PT} apt={VP8_PT}\r\n");
            // The feedback the spec mandates, and what makes a keyframe
            // request legal at all: without these lines a receiver has
            // no way to say "I have no keyframe" and the tile stays
            // black until the encoder happens to send one.
            let _ = write!(s, "a=rtcp-fb:{VP8_PT} nack\r\n");
            let _ = write!(s, "a=rtcp-fb:{VP8_PT} nack pli\r\n");
            let _ = write!(s, "a=rtcp-fb:{VP8_PT} ccm fir\r\n");
        } else {
            let _ = write!(s, "a=rtpmap:{PCMU_PT} PCMU/8000\r\n");
        }
        let _ = write!(s, "a={}\r\n", sec.direction.as_str());
        s.push_str("a=rtcp-mux\r\n");
        s.push_str("a=setup:actpass\r\n");
        let _ = write!(s, "a=ice-ufrag:{}\r\n", params.creds.ufrag);
        let _ = write!(s, "a=ice-pwd:{}\r\n", params.creds.pass);
        let _ = write!(
            s,
            "a=fingerprint:{} {}\r\n",
            params.fingerprint.hash_func, fp
        );
        for c in params.candidates {
            let _ = write!(s, "a={}\r\n", c.to_sdp_string());
        }
        if let Some((ssrc, uid)) = sec.ssrc {
            // Not required by the spec for audio, and load-bearing
            // anyway: without a declared SSRC a bundled client has
            // nothing to demultiplex remote media by, and every
            // speaker's audio lands on one track with no user attached
            // to it. GtkHx reads the cname as its fallback when a mid
            // can't be resolved. For video it is doubly so — two
            // publications from one participant share a payload type and
            // a transport, and the SSRC is the only thing that separates
            // them.
            let _ = write!(
                s,
                "a=ssrc:{ssrc} cname:{}-{uid}\r\n",
                sec.media.cname_prefix()
            );
        }
    }
    s
}

fn fingerprint_hex(fp: &Fingerprint) -> String {
    let mut out = String::with_capacity(fp.bytes.len() * 3);
    for (i, b) in fp.bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Why an answer is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerError {
    /// No `a=ice-ufrag` / `a=ice-pwd`.
    NoIceCredentials,
    /// No `a=fingerprint`, or one we can't read.
    NoFingerprint,
    /// No PCMU. "If a client's SDP answer does not include PCMU (payload
    /// type 0), the server MUST reject the answer."
    NoPcmu,
}

impl std::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AnswerError::NoIceCredentials => "no ICE credentials",
            AnswerError::NoFingerprint => "no usable DTLS fingerprint",
            AnswerError::NoPcmu => "no PCMU in the answer",
        };
        f.write_str(s)
    }
}

/// One of the client's own video send sections, as its answer described
/// it. Produced for `cam-send` and `scr-send` only — a section carrying
/// somebody else's video back to us is not something we send on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoSendAnswer {
    /// `cam-send` or `scr-send`.
    pub mid: String,
    /// The section was accepted: a non-zero port, and VP8 at PT 96 in
    /// its format list. A client that cannot do VP8 answers with port 0,
    /// which costs it that publication and nothing else.
    pub accepted: bool,
    /// The SSRC the client declared for the stream it will send here.
    /// **Required**, unlike the microphone's — see the module docs.
    pub ssrc: Option<u32>,
}

/// What the server needs out of a client's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub creds: IceCreds,
    pub fingerprint: Fingerprint,
    /// The client took the DTLS client role (`a=setup:active`, which is
    /// what an answerer sends to our `actpass`). We take the other one.
    pub client_is_dtls_client: bool,
    /// The SSRC the client declared for its microphone. Its absence is
    /// tolerated by the spec and costs us the ability to bind inbound
    /// RTP to the mic track until the first packet arrives.
    pub mic_ssrc: Option<u32>,
    /// The client's own video send sections, in the order they appeared.
    /// Empty when the peer publishes nothing, which is every peer until
    /// its user asks otherwise.
    pub video_send: Vec<VideoSendAnswer>,
}

impl Answer {
    /// What the client declared for one of its send sections, if it
    /// answered that section at all.
    pub fn video_send(&self, mid: &str) -> Option<&VideoSendAnswer> {
        self.video_send.iter().find(|v| v.mid == mid)
    }
}

/// Parse a client's SDP answer.
pub fn parse_answer(sdp: &str) -> Result<Answer, AnswerError> {
    let mut ufrag: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut fingerprint: Option<Fingerprint> = None;
    let mut setup: Option<String> = None;
    let mut mic_ssrc: Option<u32> = None;
    let mut has_pcmu = false;
    let mut video_send: Vec<VideoSendAnswer> = Vec::new();

    // Which section we're inside; the mic's `a=ssrc` is the one we want,
    // and a client may well declare SSRCs elsewhere.
    let mut in_mic_section = false;
    // The section currently open, when it is a video one: whether its
    // `m=` line accepted VP8, and which of our send mids it turned out to
    // be. The mid arrives *after* the `m=` line, so both halves are
    // carried until the section closes.
    let mut video_open: Option<bool> = None;
    let mut video_mid: Option<String> = None;
    let mut video_ssrc: Option<u32> = None;

    // Close whichever video send section was open, if it was one of ours.
    fn flush(
        out: &mut Vec<VideoSendAnswer>,
        open: &mut Option<bool>,
        mid: &mut Option<String>,
        ssrc: &mut Option<u32>,
    ) {
        let accepted = open.take().unwrap_or(false);
        let ssrc = ssrc.take();
        if let Some(mid) = mid.take() {
            if mid == CAM_SEND_MID || mid == SCR_SEND_MID {
                out.push(VideoSendAnswer {
                    mid,
                    accepted,
                    ssrc,
                });
            }
        }
    }

    for line in sdp.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("m=") {
            flush(
                &mut video_send,
                &mut video_open,
                &mut video_mid,
                &mut video_ssrc,
            );
            in_mic_section = false;
            // "m=audio 9 UDP/TLS/RTP/SAVPF 0 8" — PCMU is payload type 0
            // in the format list. A rejected section has port 0 and
            // tells us nothing.
            let mut parts = rest.split_whitespace();
            let kind = parts.next().unwrap_or("");
            let port = parts.next().unwrap_or("0");
            let _proto = parts.next();
            let live = port != "0";
            match kind {
                "audio" if live && parts.any(|pt| pt == "0") => has_pcmu = true,
                "video" => {
                    let vp8 = parts.any(|pt| pt == "96");
                    video_open = Some(live && vp8);
                }
                _ => {}
            }
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            let mid = mid.trim();
            in_mic_section = mid == MIC_MID;
            if video_open.is_some() {
                video_mid = Some(mid.to_string());
            }
        } else if let Some(v) = line.strip_prefix("a=ice-ufrag:") {
            ufrag.get_or_insert_with(|| v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("a=ice-pwd:") {
            pass.get_or_insert_with(|| v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("a=fingerprint:") {
            if fingerprint.is_none() {
                fingerprint = parse_fingerprint(v.trim());
            }
        } else if let Some(v) = line.strip_prefix("a=setup:") {
            setup.get_or_insert_with(|| v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("a=ssrc:") {
            let n = v.split_whitespace().next().unwrap_or("");
            if in_mic_section && mic_ssrc.is_none() {
                mic_ssrc = n.parse::<u32>().ok();
            }
            if video_open.is_some() && video_ssrc.is_none() {
                // The first `a=ssrc` in the section. A stack that emits
                // the RTX SSRC as well lists the primary first and pairs
                // them in `a=ssrc-group:FID`; taking the first is what
                // that grouping means.
                video_ssrc = n.parse::<u32>().ok();
            }
        }
    }
    flush(
        &mut video_send,
        &mut video_open,
        &mut video_mid,
        &mut video_ssrc,
    );

    if !has_pcmu {
        return Err(AnswerError::NoPcmu);
    }
    let (Some(ufrag), Some(pass)) = (ufrag, pass) else {
        return Err(AnswerError::NoIceCredentials);
    };
    let Some(fingerprint) = fingerprint else {
        return Err(AnswerError::NoFingerprint);
    };
    Ok(Answer {
        creds: IceCreds { ufrag, pass },
        fingerprint,
        // An answerer that says nothing has answered our `actpass` badly;
        // `active` is what RFC 8842 requires of it, so assume that rather
        // than fail a session over a missing attribute.
        client_is_dtls_client: setup.as_deref() != Some("passive"),
        mic_ssrc,
        video_send,
    })
}

fn parse_fingerprint(v: &str) -> Option<Fingerprint> {
    let (hash_func, hex) = v.split_once(char::is_whitespace)?;
    let mut bytes = Vec::with_capacity(32);
    for pair in hex.trim().split(':') {
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    if bytes.is_empty() {
        return None;
    }
    Some(Fingerprint {
        hash_func: hash_func.to_ascii_lowercase(),
        bytes,
    })
}

/// The host candidates for the advertised addresses. An address str0m
/// refuses (a wildcard, a broadcast) is dropped rather than fatal — the
/// caller checks that something survived.
pub fn host_candidates(addrs: &[SocketAddr]) -> Vec<Candidate> {
    addrs
        .iter()
        .filter_map(|a| Candidate::host(*a, "udp").ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> IceCreds {
        IceCreds {
            ufrag: "srvr".into(),
            pass: "servericepasswordvalue1234".into(),
        }
    }

    fn fp() -> Fingerprint {
        Fingerprint {
            hash_func: "sha-256".into(),
            bytes: (0..32).collect(),
        }
    }

    fn build(sections: &[OfferSection<'_>]) -> String {
        let cands = host_candidates(&["192.0.2.1:5504".parse().unwrap()]);
        let creds = creds();
        let fp = fp();
        offer(
            &OfferParams {
                session_id: 1234567890,
                version: 3,
                creds: &creds,
                fingerprint: &fp,
                candidates: &cands,
            },
            sections,
        )
    }

    #[test]
    fn the_offer_has_the_shape_the_spec_fixes() {
        let sdp = build(&[
            OfferSection::audio("user-12", Direction::SendOnly, Some((4242, 12))),
            OfferSection::audio(MIC_MID, Direction::RecvOnly, None),
        ]);

        assert!(sdp.starts_with("v=0\r\no=- 1234567890 3 IN IP4 0.0.0.0\r\n"));
        assert!(sdp.contains("\r\na=group:BUNDLE user-12 send\r\n"));
        assert!(sdp.contains("\r\na=ice-lite\r\n"));
        // One section per participant plus the microphone, port 9 on all.
        assert_eq!(sdp.matches("m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n").count(), 2);
        assert_eq!(sdp.matches("a=rtcp-mux\r\n").count(), 2);
        assert_eq!(sdp.matches("a=setup:actpass\r\n").count(), 2);
        assert_eq!(sdp.matches("a=rtpmap:0 PCMU/8000\r\n").count(), 2);
        assert_eq!(sdp.matches("a=ice-ufrag:srvr\r\n").count(), 2);
        assert_eq!(
            sdp.matches("a=fingerprint:sha-256 00:01:02:03").count(),
            2,
            "each section carries the fingerprint, hex-pair uppercase"
        );
        // Directions are the server's, so the client's microphone is the
        // section the *server* receives on.
        assert!(sdp.contains("a=mid:user-12\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n"));
        assert!(sdp.contains("a=mid:send\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n"));
        // The forwarded section names its stream; the microphone doesn't
        // — the client declares that one.
        assert!(sdp.contains("a=ssrc:4242 cname:voice-12\r\n"));
        assert_eq!(sdp.matches("a=ssrc:").count(), 1);
        // ICE-lite means our candidates are known at offer time.
        assert!(sdp.contains("a=candidate:"));
        assert!(sdp.contains(" 192.0.2.1 5504 typ host"));
    }

    #[test]
    fn a_departed_participant_keeps_its_section() {
        let sdp = build(&[
            OfferSection::audio("user-12", Direction::Inactive, None),
            OfferSection::audio(MIC_MID, Direction::RecvOnly, None),
            OfferSection::audio("user-23", Direction::SendOnly, Some((7, 23))),
        ]);
        // The departed user's m= line is still there, still port 9, still
        // in BUNDLE: deleting it would misalign every later
        // sdpMLineIndex, and GtkHx reads `a=inactive` as the teardown
        // signal for that receive bin.
        assert!(sdp.contains("a=mid:user-12\r\na=rtpmap:0 PCMU/8000\r\na=inactive\r\n"));
        assert_eq!(sdp.matches("m=audio 9 ").count(), 3);
        assert!(sdp.contains("a=group:BUNDLE user-12 send user-23\r\n"));
    }

    // A GtkHx-shaped answer: webrtcbin's output, trimmed to the lines a
    // server reads.
    const CLIENT_ANSWER: &str = "v=0\r\n\
        o=- 9876543210 1 IN IP4 0.0.0.0\r\n\
        s=-\r\n\
        t=0 0\r\n\
        a=group:BUNDLE user-12 send\r\n\
        a=msid-semantic: WMS\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:user-12\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=recvonly\r\n\
        a=rtcp-mux\r\n\
        a=setup:active\r\n\
        a=ice-ufrag:clnt\r\n\
        a=ice-pwd:clienticepasswordvalue5678\r\n\
        a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:\
11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
        a=ssrc:1111 cname:someothercname\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:send\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=sendonly\r\n\
        a=rtcp-mux\r\n\
        a=setup:active\r\n\
        a=ice-ufrag:clnt\r\n\
        a=ice-pwd:clienticepasswordvalue5678\r\n\
        a=ssrc:2226456186 cname:janusclientmic01\r\n";

    #[test]
    fn the_answer_yields_credentials_role_and_the_microphone_ssrc() {
        let a = parse_answer(CLIENT_ANSWER).unwrap();
        assert_eq!(a.creds.ufrag, "clnt");
        assert_eq!(a.creds.pass, "clienticepasswordvalue5678");
        assert_eq!(a.fingerprint.hash_func, "sha-256");
        assert_eq!(a.fingerprint.bytes.len(), 32);
        assert_eq!(a.fingerprint.bytes[0], 0x11);
        assert!(a.client_is_dtls_client, "a=setup:active is the answerer's");
        // The microphone's SSRC, not the one declared on the section
        // carrying somebody else's audio back to us.
        assert_eq!(a.mic_ssrc, Some(2226456186));
    }

    #[test]
    fn an_answer_without_pcmu_is_refused() {
        let opus_only = CLIENT_ANSWER.replace(
            "m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        );
        assert_eq!(parse_answer(&opus_only), Err(AnswerError::NoPcmu));
    }

    #[test]
    fn an_answer_without_credentials_or_fingerprint_is_refused() {
        let no_creds: String = CLIENT_ANSWER
            .lines()
            .filter(|l| !l.starts_with("a=ice-"))
            .collect::<Vec<_>>()
            .join("\r\n");
        assert_eq!(parse_answer(&no_creds), Err(AnswerError::NoIceCredentials));

        let no_fp: String = CLIENT_ANSWER
            .lines()
            .filter(|l| !l.starts_with("a=fingerprint"))
            .collect::<Vec<_>>()
            .join("\r\n");
        assert_eq!(parse_answer(&no_fp), Err(AnswerError::NoFingerprint));
    }

    #[test]
    fn a_missing_ssrc_declaration_is_tolerated() {
        // The spec allows it and makes the server fall back; what must
        // not happen is losing the whole answer over it.
        let no_ssrc: String = CLIENT_ANSWER
            .lines()
            .filter(|l| !l.starts_with("a=ssrc:2226456186"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let a = parse_answer(&no_ssrc).unwrap();
        assert_eq!(a.mic_ssrc, None);
        assert_eq!(a.creds.ufrag, "clnt");
    }

    // --- Video ---------------------------------------------------------

    #[test]
    fn a_video_section_carries_what_the_spec_fixes() {
        let sdp = build(&[
            OfferSection {
                mid: "cam-user-12",
                media: SectionMedia::Camera,
                direction: Direction::SendOnly,
                ssrc: Some((1111111111, 12)),
                bandwidth_kbps: Some(1500),
            },
            OfferSection {
                mid: "scr-user-23",
                media: SectionMedia::Screen,
                direction: Direction::SendOnly,
                ssrc: Some((2222222222, 23)),
                bandwidth_kbps: Some(2500),
            },
            OfferSection {
                mid: CAM_SEND_MID,
                media: SectionMedia::Camera,
                direction: Direction::RecvOnly,
                ssrc: None,
                bandwidth_kbps: Some(1500),
            },
        ]);

        // Both kinds are VP8 at 96 with RTX at 97 — distinguished by mid
        // and SSRC and by nothing else, which is what makes the SSRC
        // declaration mandatory on the answer.
        assert_eq!(
            sdp.matches("m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n").count(),
            3
        );
        assert_eq!(sdp.matches("a=rtpmap:96 VP8/90000\r\n").count(), 3);
        assert_eq!(sdp.matches("a=fmtp:97 apt=96\r\n").count(), 3);
        // The three feedback lines are what make a keyframe request legal.
        assert_eq!(sdp.matches("a=rtcp-fb:96 nack\r\n").count(), 3);
        assert_eq!(sdp.matches("a=rtcp-fb:96 nack pli\r\n").count(), 3);
        assert_eq!(sdp.matches("a=rtcp-fb:96 ccm fir\r\n").count(), 3);
        // Only the screen section is slides, and the ceiling rides each
        // section as b=AS.
        assert_eq!(sdp.matches("a=content:slides\r\n").count(), 1);
        assert!(sdp.contains("b=AS:2500\r\na=mid:scr-user-23\r\na=content:slides\r\n"));
        assert_eq!(sdp.matches("b=AS:1500\r\n").count(), 2);
        // cname name spaces stay apart, so a client that falls back to
        // the cname can still tell a face from a desktop.
        assert!(sdp.contains("a=ssrc:1111111111 cname:video-12\r\n"));
        assert!(sdp.contains("a=ssrc:2222222222 cname:screen-23\r\n"));
        // The client's own camera is the section the server receives on.
        assert!(sdp.contains("a=mid:cam-send\r\n"));
        assert!(sdp.contains("\r\na=group:BUNDLE cam-user-12 scr-user-23 cam-send\r\n"));
    }

    #[test]
    fn audio_sections_are_untouched_by_video_existing() {
        // A voice-only peer's offer must be byte-identical to what the
        // voice extension produced before video existed — no b=AS, no
        // video attributes, and PCMU still the only rtpmap.
        let sdp = build(&[OfferSection::audio(MIC_MID, Direction::RecvOnly, None)]);
        assert!(sdp.contains("m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n"));
        assert!(!sdp.contains("b=AS"));
        assert!(!sdp.contains("a=rtcp-fb"));
        assert!(!sdp.contains("VP8"));
        assert!(!sdp.contains("m=video"));
    }

    #[test]
    fn every_mid_this_grammar_can_produce_fits_the_header_extension() {
        // RFC 8285's one-byte form carries 16 bytes; the longest mid the
        // spec's grammar can make is the screen one at uid 65535.
        for mid in [
            "send",
            "user-65535",
            CAM_SEND_MID,
            SCR_SEND_MID,
            "cam-user-65535",
            "scr-user-65535",
        ] {
            assert!(
                mid.len() <= MAX_MID_LEN,
                "{mid} is {} bytes, over the {MAX_MID_LEN}-byte ceiling",
                mid.len()
            );
        }
    }

    // A browser-shaped answer: one camera send section alongside the
    // microphone, which is what `RTCPeerConnection` produces.
    const VIDEO_ANSWER: &str = "v=0\r\n\
        o=- 9876543210 2 IN IP4 0.0.0.0\r\n\
        s=-\r\n\
        t=0 0\r\n\
        a=group:BUNDLE send cam-send scr-send\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
        a=mid:send\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=sendonly\r\n\
        a=setup:active\r\n\
        a=ice-ufrag:clnt\r\n\
        a=ice-pwd:clienticepasswordvalue5678\r\n\
        a=fingerprint:sha-256 11:22:33:44\r\n\
        a=ssrc:2226456186 cname:clientmic\r\n\
        m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
        a=mid:cam-send\r\n\
        a=rtpmap:96 VP8/90000\r\n\
        a=sendonly\r\n\
        a=ssrc-group:FID 3000 3001\r\n\
        a=ssrc:3000 cname:clientvideo\r\n\
        a=ssrc:3001 cname:clientvideo\r\n\
        m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
        a=mid:scr-send\r\n\
        a=rtpmap:96 VP8/90000\r\n\
        a=sendonly\r\n\
        a=ssrc:4000 cname:clientscreen\r\n";

    #[test]
    fn video_send_sections_yield_one_ssrc_each() {
        let a = parse_answer(VIDEO_ANSWER).unwrap();
        assert_eq!(a.mic_ssrc, Some(2226456186));
        // The primary of the FID pair, not the RTX one that follows it.
        let cam = a.video_send(CAM_SEND_MID).unwrap();
        assert!(cam.accepted);
        assert_eq!(cam.ssrc, Some(3000));
        let scr = a.video_send(SCR_SEND_MID).unwrap();
        assert_eq!(scr.ssrc, Some(4000));
        // Sections carrying somebody else's video back to us are not
        // send sections and are not reported as ones.
        assert_eq!(a.video_send.len(), 2);
    }

    #[test]
    fn a_video_send_section_without_an_ssrc_is_reported_not_guessed() {
        // The whole point: camera and screen are the same codec at the
        // same payload type, so there is nothing to fall back to. The
        // answer still parses — losing video must not lose the call.
        let no_ssrc: String = VIDEO_ANSWER
            .lines()
            .filter(|l| !l.starts_with("a=ssrc:3000") && !l.starts_with("a=ssrc:3001"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let a = parse_answer(&no_ssrc).unwrap();
        assert_eq!(a.mic_ssrc, Some(2226456186));
        let cam = a.video_send(CAM_SEND_MID).unwrap();
        assert!(cam.accepted, "the section itself was answered");
        assert_eq!(cam.ssrc, None, "and it is unusable without an SSRC");
    }

    #[test]
    fn a_client_that_cannot_do_vp8_declines_the_section_not_the_call() {
        let no_vp8 = VIDEO_ANSWER.replace(
            "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:cam-send",
            "m=video 0 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:cam-send",
        );
        let a = parse_answer(&no_vp8).unwrap();
        assert!(!a.video_send(CAM_SEND_MID).unwrap().accepted);
        // Audio is untouched, which is the rule that matters: a video
        // failure is not a call failure.
        assert_eq!(a.mic_ssrc, Some(2226456186));
    }

    #[test]
    fn line_endings_and_a_rejected_section_are_survivable() {
        // Bare LF (real stacks vary), and the first section refused with
        // port 0 — the microphone below it still carries everything the
        // server needs.
        let lf = CLIENT_ANSWER
            .replace("\r\n", "\n")
            .replacen("m=audio 9", "m=audio 0", 1);
        let a = parse_answer(&lf).unwrap();
        assert_eq!(a.mic_ssrc, Some(2226456186));
    }
}
