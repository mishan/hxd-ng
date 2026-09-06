//! One participant's WebRTC session.
//!
//! A peer owns exactly one str0m `Rtc`, built through the direct API: we
//! declare the media ourselves, with the mids the spec names, and write
//! the SDP by hand around them. Its media sections are **append-only** —
//! a mid is never reassigned, a departed participant's section goes
//! `a=inactive` and comes back when they do, and a new participant's
//! section is appended after everything already negotiated so no
//! `sdpMLineIndex` ever shifts.
//!
//! **Video rides the same session.** Camera and screen add sections to
//! this peer connection; they never open a second one. What that costs is
//! that a mid alone no longer identifies an inbound stream — a
//! participant publishing both a camera and a screen sends two VP8
//! streams at payload type 96 over one bundled transport — so inbound
//! video is keyed by the SSRC the answer declared, and the mid is only a
//! label. Audio is unaffected: PCMU at payload type 0 is still one stream
//! per peer.

use std::net::SocketAddr;
use std::time::Instant;

use hxd_core::video::{VideoConfig, VideoKind, VideoStream};
use hxd_core::Uid;
use str0m::config::DtlsCert;
use str0m::media::MediaKind;
use str0m::rtp::Ssrc;
use str0m::{Candidate, Rtc, RtcConfig};

use crate::sdp::{
    self, candidate_bytes, section_bytes, Direction, OfferParams, OfferSection, SectionMedia,
    CAM_SEND_MID, MIC_MID, OFFER_BASE_BYTES, SCR_SEND_MID,
};

/// How large one peer's offer may grow before the session is ended.
///
/// Sections are append-only and a departed participant keeps theirs
/// forever — the spec forbids deleting an `m=` line from a later offer,
/// because that would misalign every `sdpMLineIndex` after it. So a peer
/// sitting in a busy lobby collects one inactive section per person who
/// has *ever* joined alongside it, and the offer grows by a few hundred
/// bytes each time. Unbounded, that walks past the spec's 32 KB
/// SHOULD-NOT and then past the Hotline wire's 16-bit chunk length, and
/// what a 1.x client would get at that point is a broken frame.
///
/// **The budget is in bytes and not in sections**, which is the whole of
/// the change video forced. A fixed count of 64 was a fair proxy for
/// 32 KB while every section was audio; a video section carries three
/// more `a=rtpmap`/`a=fmtp` lines, three `a=rtcp-fb` lines, a `b=AS` and
/// two more `a=ssrc` lines, so the same 64 sections come to roughly 37 KB
/// of video against 28 KB of audio — and 64 audio sections were already
/// over the line on a host advertising both a v4 and a v6 candidate. One
/// count cannot serve both, and the thing actually being bounded was
/// always the size.
///
/// At the ceiling the peer's session is ended instead, so it reconnects
/// with a clean section list — a rejoin is exactly the reset the spec's
/// own model has for this, and it keeps "a mid is never reassigned
/// *within a session*" true.
const MAX_OFFER_BYTES: usize = sdp::MAX_OFFER_BYTES;

/// What a media section carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind {
    /// This client's own microphone, mid `send`.
    Mic,
    /// Another participant's audio, mid `user-{UID}`.
    Remote(Uid),
    /// This client's own camera or screen, mid `cam-send` / `scr-send`.
    VideoSend(VideoKind),
    /// Another participant's camera or screen, mid `cam-user-{UID}` /
    /// `scr-user-{UID}`.
    RemoteVideo(Uid, VideoKind),
}

impl SectionKind {
    fn media(self) -> SectionMedia {
        match self {
            SectionKind::Mic | SectionKind::Remote(_) => SectionMedia::Audio,
            SectionKind::VideoSend(k) | SectionKind::RemoteVideo(_, k) => match k {
                VideoKind::Camera => SectionMedia::Camera,
                VideoKind::Screen => SectionMedia::Screen,
            },
        }
    }
}

/// The mid prefix for a kind. Abbreviated because the whole mid must fit
/// RFC 8285's 16-byte one-byte-header form; see [`sdp::MAX_MID_LEN`].
fn kind_prefix(kind: VideoKind) -> &'static str {
    match kind {
        VideoKind::Camera => "cam",
        VideoKind::Screen => "scr",
    }
}

/// The mid of a client's own send section for `kind`.
pub(crate) fn send_mid(kind: VideoKind) -> &'static str {
    match kind {
        VideoKind::Camera => CAM_SEND_MID,
        VideoKind::Screen => SCR_SEND_MID,
    }
}

/// The mid carrying `other`'s publication of `kind`.
pub(crate) fn remote_video_mid(other: Uid, kind: VideoKind) -> String {
    format!("{}-user-{other}", kind_prefix(kind))
}

pub(crate) struct Section {
    /// The mid **as the SDP spells it**: `send`, `user-{UID}`,
    /// `cam-send`, `scr-user-{UID}` and so on.
    ///
    /// This is a `String` and not str0m's `Mid` on purpose. `Mid` is a
    /// 16-byte inline id that rewrites every non-alphanumeric character
    /// to `_`, so the spec's `user-5` is `user_5` once it is inside the
    /// library. That is harmless as long as it stays inside — every
    /// lookup goes through the same conversion — but an offer built from
    /// str0m's spelling would put `a=mid:user_5` on the wire, where the
    /// spec's strict `user-{UID}` parse rejects it and the client drops
    /// the track. So the wire spelling lives here and str0m never
    /// supplies it.
    pub(crate) mid: String,
    pub(crate) kind: SectionKind,
    /// The SSRC currently declared for this section, if any. A rejoin
    /// gives the participant a new forwarding SSRC, and the section has
    /// to be re-declared to match.
    pub(crate) ssrc: Option<u32>,
    /// The repair SSRC paired with [`Section::ssrc`] in
    /// `a=ssrc-group:FID`, on a video section.
    pub(crate) rtx_ssrc: Option<u32>,
    /// What the *source* of this section's stream was when its SSRC was
    /// last chosen: the publisher's forwarding SSRC for a remote video
    /// section. A change means the publisher restarted, and the section
    /// has to be re-declared even if it never went inactive.
    pub(crate) source: Option<u32>,
    /// Whether the last offer described this section as live. Sections
    /// are never removed, so this is what distinguishes "still running"
    /// from "coming back", and coming back needs a fresh SSRC — see
    /// [`Peer::declare_remote_video`].
    pub(crate) active: bool,
}

/// One of this peer's outbound publications.
pub(crate) struct Publication {
    pub(crate) kind: VideoKind,
    /// Paused publications keep their section, their mid and their slot;
    /// only the forwarding stops. Enforced here rather than trusted to
    /// the client.
    pub(crate) paused: bool,
    /// The SSRC every subscriber's `{cam,scr}-user-{this uid}` section
    /// declares and this publication's RTP is forwarded on — ours, not
    /// the publisher's, for the same reason audio's is: it is known at
    /// publish time, so an offer is complete before any answer arrives.
    pub(crate) forward_ssrc: u32,
    /// The SSRC the client's answer declared for what it sends here.
    /// `None` until an answer binds it — and inbound video with no
    /// matching publication is dropped rather than guessed at.
    pub(crate) recv_ssrc: Option<u32>,
    /// When RTP last arrived for this publication, for the stall reaper.
    /// `None` means nothing has ever arrived, which is also true of a
    /// publication that has never been unpaused — so it is never on its
    /// own a reason to reap.
    pub(crate) last_media: Option<Instant>,
    /// When we last asked this publisher for a keyframe. **Rate limiting
    /// is not an optimisation here**: a room of eight receivers whose
    /// renegotiations complete together would otherwise ask for eight
    /// keyframes in a few milliseconds and get eight, a bitrate spike
    /// precisely when the network is busiest.
    pub(crate) last_keyframe: Option<Instant>,
    /// Whether an offer carrying this publication's send section has
    /// actually been built yet.
    ///
    /// **This is what stops an answer destroying a publication that was
    /// started a moment ago.** The start transaction deliberately carries
    /// no offer — a renegotiation may already be outstanding, and the
    /// voice extension forbids a second offer before the first is
    /// answered — so between the start and the offer that follows it, the
    /// next answer to arrive is the answer to the *previous* offer, which
    /// of course never mentioned `cam-send`. Reading that absence as "the
    /// client declined" killed the publication before its offer had even
    /// been written. A section the client has never been shown cannot
    /// have been declined by it.
    pub(crate) offered: bool,
}

pub(crate) struct Peer {
    /// The room this session belongs to. The uid is the key it is filed
    /// under, so it isn't repeated here.
    pub(crate) cid: u32,
    pub(crate) rtc: Rtc,
    pub(crate) sections: Vec<Section>,
    /// What this peer's candidate lines cost, once. Fixed for the
    /// session's life, so the section budget doesn't re-measure them.
    candidate_bytes: usize,
    /// A running upper bound on the size of this peer's next offer, kept
    /// so a section can be refused *before* it is appended. See
    /// [`MAX_OFFER_BYTES`].
    offer_bytes: usize,
    /// The SSRC every *other* peer's `user-{this uid}` section declares
    /// and this peer's audio is forwarded on. Allocated per join, so a
    /// rejoin can't collide its fresh sequence numbers with the stream
    /// listeners were already tracking.
    pub(crate) forward_ssrc: u32,
    pub(crate) muted: bool,
    /// This peer's video publications: at most one per kind.
    pub(crate) publications: Vec<Publication>,
    /// What this peer has been told to receive, as the domain computed
    /// it — already filtered to publications that exist. **A peer with
    /// an empty set receives no video at all**, which is the state every
    /// participant starts in and the state a video-less client never
    /// leaves. There is no "is this client video-capable" branch
    /// anywhere below; that absence is the compatibility guarantee.
    pub(crate) subscriptions: Vec<VideoStream>,
    /// The SSRC the client's answer last declared for its microphone,
    /// so a renegotiation that moves it can retire the old binding.
    pub(crate) mic_ssrc: Option<u32>,
    /// The client's answer has been applied and DTLS has been started.
    pub(crate) answered: bool,
    /// Whether we've seen ICE + DTLS complete.
    pub(crate) connected: bool,
    /// When ICE first reported a usable path. The DTLS handshake's own
    /// deadline runs from here, so a peer that nominates a pair and then
    /// stalls mid-handshake isn't carried by the much longer ICE budget.
    pub(crate) ice_connected_at: Option<Instant>,
    session_id: u64,
    version: u64,
    pub(crate) joined_at: Instant,
    pub(crate) answered_at: Option<Instant>,
    /// The last time **authenticated** media arrived: RTP the stack
    /// decrypted, or an RTCP sender report it verified. Never set from
    /// the shape of a raw datagram — anyone who can reach the port and
    /// guess a peer's address could then hold a dead session open
    /// forever with one byte.
    pub(crate) last_media: Option<Instant>,
    pub(crate) remote: Option<SocketAddr>,
    /// When str0m last said it wanted its clock driven.
    pub(crate) next_timeout: Option<Instant>,
}

impl Peer {
    pub(crate) fn new(
        cid: u32,
        now: Instant,
        candidates: &[Candidate],
        extra_locals: &[Candidate],
        cert: DtlsCert,
        session_id: u64,
        forward_ssrc: u32,
    ) -> Self {
        let mut rtc = RtcConfig::new()
            // One certificate for the whole server rather than one per
            // session: generating a P-256 key pair and self-signing it
            // costs milliseconds, and this constructor runs under the
            // domain's roster lock.
            .set_dtls_cert(cert)
            // The server is the passive side: it publishes host
            // candidates and answers checks rather than making them.
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            // VP8 and nothing else, at str0m's own 96/97 — which are the
            // payload types the video spec fixes, for the same reason it
            // fixes them: an SFU does not transcode, so a room must agree
            // on one codec, and VP8 is the one with no profile to
            // negotiate.
            .enable_vp8(true)
            // Hand us the packets as they arrive and let us write them
            // back out unchanged — the spec's "forwards RTP without
            // modification; never decodes".
            .set_rtp_mode(true)
            .build(now);

        for c in candidates.iter().chain(extra_locals) {
            // Both sets are local candidates as far as ICE is concerned;
            // only `candidates` reaches the SDP. See `Inner::extra_locals`.
            rtc.add_local_candidate(c.clone());
        }
        {
            let mut api = rtc.direct_api();
            // ICE-lite is always the controlled agent.
            api.set_ice_controlling(false);
        }

        Peer {
            cid,
            rtc,
            sections: Vec::new(),
            candidate_bytes: candidate_bytes(candidates),
            offer_bytes: OFFER_BASE_BYTES,
            forward_ssrc,
            muted: false,
            publications: Vec::new(),
            subscriptions: Vec::new(),
            mic_ssrc: None,
            answered: false,
            connected: false,
            ice_connected_at: None,
            session_id,
            version: 0,
            joined_at: now,
            answered_at: None,
            last_media: None,
            remote: None,
            next_timeout: None,
        }
    }

    /// The section for a given participant, if this peer has ever had one.
    fn section_index(&self, kind: SectionKind) -> Option<usize> {
        self.sections.iter().position(|s| s.kind == kind)
    }

    /// Append a section, or refuse it because the offer has no room left.
    ///
    /// Every section this peer will ever have goes through here, so the
    /// budget is enforced in exactly one place and there is nowhere for a
    /// caller to forget it.
    fn push_section(&mut self, mid: String, kind: SectionKind) -> bool {
        let media = kind.media();
        // A mid too long for RFC 8285's one-byte header form cannot be
        // carried by the MID extension every mainstream stack negotiates,
        // and the abbreviated prefixes exist precisely so this never
        // happens. `Uid` is a `u16`, so the longest mid this grammar can
        // build is `scr-user-65535` at 14 bytes; the check is here so the
        // invariant is load-bearing rather than a comment, and so a
        // future kind with a longer prefix fails loudly instead of
        // colliding inside str0m — which truncates a `Mid` to 16 bytes
        // silently, turning `screen-user-65535` and `screen-user-65534`
        // into the same id.
        debug_assert!(
            mid.len() <= sdp::MAX_MID_LEN,
            "mid {mid:?} exceeds the RFC 8285 one-byte header form"
        );
        if mid.len() > sdp::MAX_MID_LEN {
            return false;
        }
        let cost = section_bytes(&mid, media, self.candidate_bytes);
        if self.offer_bytes + cost > MAX_OFFER_BYTES {
            return false;
        }
        let media_kind = match media {
            SectionMedia::Audio => MediaKind::Audio,
            _ => MediaKind::Video,
        };
        self.rtc
            .direct_api()
            .declare_media(mid.as_str().into(), media_kind);
        self.offer_bytes += cost;
        self.sections.push(Section {
            mid,
            kind,
            ssrc: None,
            rtx_ssrc: None,
            source: None,
            active: false,
        });
        true
    }

    /// Declare this peer's own microphone section. Called once, at join,
    /// after the sections for whoever is already in the room — which is
    /// the order the spec's own offer example uses.
    pub(crate) fn declare_mic(&mut self) {
        if self.section_index(SectionKind::Mic).is_some() {
            return;
        }
        // A fresh session's budget cannot be exhausted by its own
        // microphone, so this cannot fail in practice; ignoring the
        // answer keeps the signature honest for the one caller.
        self.push_section(MIC_MID.to_string(), SectionKind::Mic);
    }

    /// Make sure this peer has a section for `other`, carrying `ssrc`.
    ///
    /// A new participant appends a section; a returning one reuses the
    /// mid it already had, with its new forwarding SSRC swapped in. The
    /// mid is the spec's track-to-user mapping and is never reassigned.
    ///
    /// Returns `false` when the offer has no room left for it — see
    /// [`MAX_OFFER_BYTES`].
    pub(crate) fn declare_remote(&mut self, other: Uid, ssrc: u32) -> bool {
        let section = SectionKind::Remote(other);
        let mid = format!("user-{other}");
        match self.section_index(section) {
            Some(i) => {
                if self.sections[i].ssrc == Some(ssrc) {
                    self.sections[i].active = true;
                    return true;
                }
                if let Some(old) = self.sections[i].ssrc {
                    self.rtc.direct_api().remove_stream_tx(old.into());
                }
            }
            None => {
                if !self.push_section(mid.clone(), section) {
                    return false;
                }
            }
        }
        let Some(i) = self.section_index(section) else {
            return false;
        };
        self.sections[i].ssrc = Some(ssrc);
        self.sections[i].source = Some(ssrc);
        self.sections[i].active = true;
        self.rtc
            .direct_api()
            .declare_stream_tx(ssrc.into(), None, mid.as_str().into(), None);
        true
    }

    /// The mid carrying `other`'s audio to this peer, if negotiated.
    pub(crate) fn mid_for(&self, other: Uid) -> Option<&str> {
        self.section_index(SectionKind::Remote(other))
            .map(|i| self.sections[i].mid.as_str())
    }

    // --- Video ----------------------------------------------------------

    pub(crate) fn publication(&self, kind: VideoKind) -> Option<&Publication> {
        self.publications.iter().find(|p| p.kind == kind)
    }

    pub(crate) fn publication_mut(&mut self, kind: VideoKind) -> Option<&mut Publication> {
        self.publications.iter_mut().find(|p| p.kind == kind)
    }

    /// Which publication an inbound video SSRC belongs to.
    ///
    /// **This lookup, and not the mid, is the track-to-publication
    /// mapping on the receive side.** Camera and screen arrive as VP8 at
    /// payload type 96 on one bundled transport; there is nothing else
    /// to tell them apart, which is why the answer's `a=ssrc` is
    /// mandatory and why a packet with no match here is dropped rather
    /// than attributed to a guess.
    pub(crate) fn publication_by_ssrc(&self, ssrc: u32) -> Option<&Publication> {
        self.publications.iter().find(|p| p.recv_ssrc == Some(ssrc))
    }

    /// Add a send section for `kind`, so this peer's next offer has
    /// somewhere to publish on. Returns `false` if the section list is
    /// full or the publication already exists.
    pub(crate) fn declare_video_send(&mut self, kind: VideoKind, forward_ssrc: u32) -> bool {
        if self.publication(kind).is_some() {
            return false;
        }
        let mid = send_mid(kind);
        if self.section_index(SectionKind::VideoSend(kind)).is_none()
            && !self.push_section(mid.to_string(), SectionKind::VideoSend(kind))
        {
            return false;
        }
        self.publications.push(Publication {
            kind,
            paused: false,
            forward_ssrc,
            recv_ssrc: None,
            last_media: None,
            last_keyframe: None,
            offered: false,
        });
        true
    }

    /// Drop a publication. The **section stays** — mids are never
    /// reassigned and `m=` lines are never deleted — and simply goes
    /// `a=inactive` in the next offer, which is also how it comes back if
    /// the user publishes again.
    pub(crate) fn undeclare_video_send(&mut self, kind: VideoKind) -> bool {
        let Some(i) = self.publications.iter().position(|p| p.kind == kind) else {
            return false;
        };
        let p = self.publications.remove(i);
        if let Some(ssrc) = p.recv_ssrc {
            self.rtc.direct_api().remove_stream_rx(ssrc.into());
        }
        true
    }

    /// Make sure this peer has a live receive section for `other`'s
    /// publication of `kind`. `source` is the publisher's forwarding
    /// SSRC, used only to notice that the publisher restarted.
    ///
    /// **The SSRC on the wire is this peer's, not the publisher's**, and
    /// it is drawn fresh whenever the section comes back to life. That is
    /// not symmetry with audio for its own sake: subscription is
    /// per-receiver, so between one peer unsubscribing and resubscribing
    /// the publisher's stream carried on to everyone else, and resuming
    /// it on the same SSRC would hand this receiver a sequence-number gap
    /// of every packet it missed. libwebrtc answers a gap that size with
    /// a NACK storm for packets no cache still holds. A new SSRC is a new
    /// stream, which is what actually happened from the receiver's side.
    pub(crate) fn declare_remote_video(
        &mut self,
        other: Uid,
        kind: VideoKind,
        source: u32,
    ) -> bool {
        let mid = remote_video_mid(other, kind);
        let section = SectionKind::RemoteVideo(other, kind);
        match self.section_index(section) {
            Some(i) => {
                // Still running on the same publisher stream: nothing to
                // re-declare, and re-declaring would reset a stream the
                // receiver is happily decoding.
                if self.sections[i].active && self.sections[i].source == Some(source) {
                    return true;
                }
                if let Some(old) = self.sections[i].ssrc {
                    self.rtc.direct_api().remove_stream_tx(old.into());
                }
            }
            None => {
                if !self.push_section(mid.clone(), section) {
                    return false;
                }
            }
        }
        let ssrc: Ssrc = self.rtc.direct_api().new_ssrc();
        let rtx: Ssrc = self.rtc.direct_api().new_ssrc();
        let Some(i) = self.section_index(section) else {
            return false;
        };
        self.sections[i].ssrc = Some(*ssrc);
        self.sections[i].rtx_ssrc = Some(*rtx);
        self.sections[i].source = Some(source);
        self.sections[i].active = true;
        // With an RTX SSRC declared, str0m answers a receiver's NACK from
        // its own cache, recovering the loss a hop earlier than forwarding
        // the NACK to the publisher would. That only works if the offer
        // *names* the repair SSRC in `a=ssrc-group:FID`, which is what
        // `Section::rtx_ssrc` is carried into the offer for — declaring it
        // here and not there is what made the whole mechanism inert.
        self.rtc
            .direct_api()
            .declare_stream_tx(ssrc, Some(rtx), mid.as_str().into(), None);
        true
    }

    /// Mark every remote-video section not in `present` as no longer
    /// live, so that if it comes back it comes back on a new SSRC.
    ///
    /// Called from the offer path, which is the only place that knows the
    /// room's current shape. Unsubscribed, stopped and departed all land
    /// here, which is right: the spec says a receiver should not be able
    /// to tell those three apart.
    pub(crate) fn deactivate_absent_video(&mut self, present: &[(Uid, VideoKind, u32)]) {
        for s in &mut self.sections {
            if let SectionKind::RemoteVideo(other, kind) = s.kind {
                if !present.iter().any(|(u, k, _)| *u == other && *k == kind) {
                    s.active = false;
                }
            }
        }
    }

    /// The mid carrying `other`'s publication of `kind` to this peer.
    pub(crate) fn video_mid_for(&self, other: Uid, kind: VideoKind) -> Option<&str> {
        self.section_index(SectionKind::RemoteVideo(other, kind))
            .map(|i| self.sections[i].mid.as_str())
    }

    /// Whose publication a section of ours describes, given str0m's
    /// spelling of the mid.
    ///
    /// str0m rewrites every non-alphanumeric character of a mid to `_`,
    /// so `cam-user-12` is `cam_user_12` once it is inside the library
    /// and the two spellings can't be compared as strings. Converting our
    /// wire spelling the same way and comparing the results is what keeps
    /// the round trip honest — parsing str0m's form back would mean
    /// guessing which underscores used to be hyphens.
    /// Sections are never removed, so a peer that subscribed once and
    /// unsubscribed still has one, still has a receive stream behind it,
    /// and its stack will happily go on sending PLIs for a tile nobody is
    /// looking at. Answering those would spend the publisher's keyframes
    /// — and therefore the whole room's bitrate — on a viewer who left.
    /// A request only counts while the subscription does.
    pub(crate) fn publisher_for_mid(&self, mid: str0m::media::Mid) -> Option<(Uid, VideoKind)> {
        self.sections
            .iter()
            .find(|s| str0m::media::Mid::from(s.mid.as_str()) == mid)
            .and_then(|s| match s.kind {
                SectionKind::RemoteVideo(uid, kind) => Some((uid, kind)),
                _ => None,
            })
            .filter(|(uid, kind)| self.subscribes_to(*uid, *kind))
    }

    /// Drop a receive stream this session no longer expects anything on.
    fn retire_rx(&mut self, ssrc: Option<u32>) {
        if let Some(ssrc) = ssrc {
            self.rtc.direct_api().remove_stream_rx(ssrc.into());
        }
    }

    /// Is this peer subscribed to that publication? The one question the
    /// forwarding path asks, and the reason a peer that has asked for
    /// nothing receives nothing.
    pub(crate) fn subscribes_to(&self, other: Uid, kind: VideoKind) -> bool {
        self.subscriptions
            .iter()
            .any(|s| s.uid == other && s.kind == kind)
    }

    /// Ask this peer for a keyframe on `kind`, no more often than
    /// `interval`. Returns whether a request was actually sent, which is
    /// what the caller logs.
    pub(crate) fn request_keyframe(
        &mut self,
        kind: VideoKind,
        now: Instant,
        interval: std::time::Duration,
    ) -> bool {
        let Some(p) = self.publication(kind) else {
            return false;
        };
        let Some(ssrc) = p.recv_ssrc else {
            // Nothing has been bound yet; the first keyframe will arrive
            // with the stream itself.
            return false;
        };
        if p.last_keyframe
            .is_some_and(|t| now.duration_since(t) < interval)
        {
            return false;
        }
        let sent = self
            .rtc
            .direct_api()
            .stream_rx(&Ssrc::from(ssrc))
            .map(|rx| rx.request_keyframe(str0m::media::KeyframeRequestKind::Pli))
            .is_some();
        if sent {
            if let Some(p) = self.publication_mut(kind) {
                p.last_keyframe = Some(now);
            }
        }
        sent
    }

    /// The current offer, given who is in the room right now and what
    /// this peer has subscribed to.
    ///
    /// Deterministic per (peer, room state) apart from the version
    /// counter, which RFC 3264 wants bumped whenever the description
    /// changes. Computing it on demand rather than diffing is what makes
    /// the domain's consolidation rule fall out for free: a burst of
    /// changes during one outstanding offer produces exactly one
    /// follow-up offer, because the follow-up is just this function
    /// called again.
    pub(crate) fn offer(
        &mut self,
        present: &[(Uid, u32)],
        present_video: &[(Uid, VideoKind, u32)],
        candidates: &[Candidate],
        limits: &VideoConfig,
    ) -> String {
        self.version += 1;
        let creds = self.rtc.direct_api().local_ice_credentials();
        let fingerprint = self.rtc.direct_api().local_dtls_fingerprint().clone();
        let publishing: Vec<VideoKind> = self.publications.iter().map(|p| p.kind).collect();
        // A send section is about to be described to the client, so from
        // here on its absence from an answer really does mean the client
        // declined it. See `Publication::offered`.
        for p in &mut self.publications {
            p.offered = true;
        }
        let sections: Vec<OfferSection<'_>> = self
            .sections
            .iter()
            .map(|s| {
                let media = s.kind.media();
                let bandwidth_kbps = match s.kind {
                    SectionKind::VideoSend(k) | SectionKind::RemoteVideo(_, k) => {
                        Some(limits.limits(k).bandwidth_kbps())
                    }
                    _ => None,
                };
                // The SSRC comes from the section and not from the room
                // state: the section is what was declared to str0m, and
                // an offer that named a different one would describe a
                // stream this peer will never receive.
                let live = |other: Uid| (Direction::SendOnly, s.ssrc.map(|n| (n, other)));
                let (direction, ssrc) = match s.kind {
                    SectionKind::Mic => (Direction::RecvOnly, None),
                    SectionKind::Remote(other) => {
                        match present.iter().find(|(u, _)| *u == other) {
                            // Live while its offered direction says so; a
                            // participant who has left keeps the section
                            // and loses the direction.
                            Some(_) => live(other),
                            None => (Direction::Inactive, None),
                        }
                    }
                    // The client's own capture section is live while it
                    // holds the publication. A stopped one keeps its mid
                    // and goes inactive, which is how it comes back.
                    SectionKind::VideoSend(k) if publishing.contains(&k) => {
                        (Direction::RecvOnly, None)
                    }
                    SectionKind::VideoSend(_) => (Direction::Inactive, None),
                    SectionKind::RemoteVideo(other, k) => {
                        match present_video
                            .iter()
                            .find(|(u, pk, _)| *u == other && *pk == k)
                        {
                            Some(_) => live(other),
                            // Unsubscribed, stopped, or the publisher
                            // left: all three look the same from here,
                            // which is exactly what the spec says a
                            // receiver should not be able to tell apart.
                            None => (Direction::Inactive, None),
                        }
                    }
                };
                OfferSection {
                    mid: &s.mid,
                    media,
                    direction,
                    ssrc,
                    // Only on a live video section: naming a repair SSRC
                    // for a stream that isn't flowing says nothing, and
                    // the section is `a=inactive` anyway.
                    rtx_ssrc: match direction {
                        Direction::SendOnly if media.is_video() => s.rtx_ssrc,
                        _ => None,
                    },
                    bandwidth_kbps,
                }
            })
            .collect();

        sdp::offer(
            &OfferParams {
                session_id: self.session_id,
                version: self.version,
                creds: &creds,
                fingerprint: &fingerprint,
                candidates,
            },
            &sections,
        )
    }

    /// Apply the client's answer: its ICE credentials, its fingerprint,
    /// the DTLS role, and — in the same call, before anything can arrive
    /// on the wire — the SSRCs to expect on each of its send sections.
    ///
    /// That last part is the whole of the Janus bug this design exists
    /// not to repeat. Binding the SSRC *after* the answer is acknowledged
    /// leaves a window in which the client's first packets arrive against
    /// an undeclared SSRC, get dropped, and the publisher is never heard
    /// by anyone. There is no window here.
    ///
    /// Returns the publications the answer failed to bind — a video send
    /// section the client answered without an `a=ssrc`, or declined
    /// outright. Those are dropped by the caller, and the call carries on
    /// without them: **losing video is a degradation, losing the call is
    /// a failure.**
    pub(crate) fn apply_answer(
        &mut self,
        answer: &sdp::Answer,
        now: Instant,
    ) -> Result<Vec<VideoKind>, str0m::RtcError> {
        // Only from the *first* answer. Every renegotiation carries the
        // client's credentials and fingerprint again, and re-applying
        // them would let a client swap the fingerprint its already-
        // completed DTLS session was verified against.
        if !self.answered {
            let mut api = self.rtc.direct_api();
            api.set_remote_ice_credentials(answer.creds.clone());
            api.set_remote_fingerprint(answer.fingerprint.clone());
        }
        // Every SSRC this session has already been told to expect. An
        // answer that reuses one is ambiguous, and `expect_stream_rx` is
        // keyed by SSRC — a second call with the same number and a
        // different mid keeps the *first* binding and returns silently,
        // so nothing downstream would ever notice.
        let mut claimed: Vec<u32> = Vec::with_capacity(3);
        if let Some(ssrc) = answer.mic_ssrc {
            // A renegotiation that moves the microphone to a new SSRC
            // must retire the old binding, or the session accumulates one
            // `StreamRx` per answer for the rest of its life.
            if self.mic_ssrc.is_some_and(|old| old != ssrc) {
                self.retire_rx(self.mic_ssrc);
            }
            self.rtc
                .direct_api()
                .expect_stream_rx(Ssrc::from(ssrc), None, MIC_MID.into(), None);
            self.mic_ssrc = Some(ssrc);
            claimed.push(ssrc);
        }

        let mut unbindable = Vec::new();
        let kinds: Vec<VideoKind> = self.publications.iter().map(|p| p.kind).collect();
        for kind in kinds {
            let mid = send_mid(kind);
            match answer.video_send(mid) {
                // A renegotiation that didn't carry this section leaves
                // whatever we already bound alone — a client only answers
                // the sections the offer held. Unbindable only if the
                // client has actually *seen* the section and left it out;
                // a publication started since the last offer has not been
                // offered yet, and this answer belongs to the offer
                // before it.
                None => {
                    let never_bound = self
                        .publication(kind)
                        .is_some_and(|p| p.recv_ssrc.is_none() && p.offered);
                    if never_bound {
                        unbindable.push(kind);
                    }
                }
                Some(v) if !v.accepted => unbindable.push(kind),
                // The rule with no fallback: two video streams from one
                // peer share a payload type and a transport, so an
                // answer with no SSRC — or one that reuses an SSRC it
                // already spent — leaves nothing to demultiplex by, and
                // forwarding a screen share into the tile where a face
                // belongs is worse than forwarding nothing. The spec is
                // explicit that the server rejects such a section rather
                // than guessing.
                Some(v) => match v.ssrc {
                    None => unbindable.push(kind),
                    Some(ssrc) if claimed.contains(&ssrc) => unbindable.push(kind),
                    Some(ssrc) => {
                        let previous = self.publication(kind).and_then(|p| p.recv_ssrc);
                        if previous.is_some_and(|old| old != ssrc) {
                            self.retire_rx(previous);
                        }
                        self.rtc.direct_api().expect_stream_rx(
                            Ssrc::from(ssrc),
                            v.rtx_ssrc.map(Ssrc::from),
                            mid.into(),
                            None,
                        );
                        claimed.push(ssrc);
                        if let Some(rtx) = v.rtx_ssrc {
                            claimed.push(rtx);
                        }
                        if let Some(p) = self.publication_mut(kind) {
                            p.recv_ssrc = Some(ssrc);
                        }
                    }
                },
            }
        }

        // The answerer takes `active`, so we take the other role.
        // `start_dtls` is idempotent — str0m returns early once DTLS is
        // inited — so a renegotiation's answer passes through it.
        self.rtc
            .direct_api()
            .start_dtls(!answer.client_is_dtls_client)?;
        self.answered = true;
        self.answered_at = Some(now);
        Ok(unbindable)
    }
}
