//! One participant's WebRTC session.
//!
//! A peer owns exactly one str0m `Rtc`, built through the direct API: we
//! declare the media ourselves, with the mids the spec names, and write
//! the SDP by hand around them. Its media sections are **append-only** —
//! a mid is never reassigned, a departed participant's section goes
//! `a=inactive` and comes back when they do, and a new participant's
//! section is appended after everything already negotiated so no
//! `sdpMLineIndex` ever shifts.

use std::net::SocketAddr;
use std::time::Instant;

use hxd_core::Uid;
use str0m::media::MediaKind;
use str0m::rtp::Ssrc;
use str0m::{Candidate, Rtc, RtcConfig};

use crate::sdp::{self, Direction, OfferParams, OfferSection, MIC_MID};

/// How many media sections one peer's session may accumulate.
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
/// At the cap the peer's session is ended instead, so it reconnects with
/// a clean section list — a rejoin is exactly the reset the spec's own
/// model has for this, and it keeps "a mid is never reassigned *within a
/// session*" true. Sixty-four sections is roughly 26 KB of SDP, and a
/// peer that has seen sixty-four other people come and go without ever
/// leaving voice itself has been there a very long time.
const MAX_SECTIONS: usize = 64;

/// What a media section carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind {
    /// This client's own microphone, mid `send`.
    Mic,
    /// Another participant's audio, mid `user-{UID}`.
    Remote(Uid),
}

pub(crate) struct Section {
    /// The mid **as the SDP spells it**: `send`, or `user-{UID}`.
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
}

pub(crate) struct Peer {
    /// The room this session belongs to. The uid is the key it is filed
    /// under, so it isn't repeated here.
    pub(crate) cid: u32,
    pub(crate) rtc: Rtc,
    pub(crate) sections: Vec<Section>,
    /// The SSRC every *other* peer's `user-{this uid}` section declares
    /// and this peer's audio is forwarded on. Allocated per join, so a
    /// rejoin can't collide its fresh sequence numbers with the stream
    /// listeners were already tracking.
    pub(crate) forward_ssrc: u32,
    pub(crate) muted: bool,
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
        session_id: u64,
        forward_ssrc: u32,
    ) -> Self {
        let mut rtc = RtcConfig::new()
            // The server is the passive side: it publishes host
            // candidates and answers checks rather than making them.
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            // Hand us the packets as they arrive and let us write them
            // back out unchanged — the spec's "forwards RTP without
            // modification; never decodes".
            .set_rtp_mode(true)
            .build(now);

        for c in candidates {
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
            forward_ssrc,
            muted: false,
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

    /// Declare this peer's own microphone section. Called once, at join,
    /// after the sections for whoever is already in the room — which is
    /// the order the spec's own offer example shows.
    pub(crate) fn declare_mic(&mut self) {
        if self.section_index(SectionKind::Mic).is_some() {
            return;
        }
        self.rtc
            .direct_api()
            .declare_media(MIC_MID.into(), MediaKind::Audio);
        self.sections.push(Section {
            mid: MIC_MID.to_string(),
            kind: SectionKind::Mic,
            ssrc: None,
        });
    }

    /// Make sure this peer has a section for `other`, carrying `ssrc`.
    ///
    /// A new participant appends a section; a returning one reuses the
    /// mid it already had, with its new forwarding SSRC swapped in. The
    /// mid is the spec's track-to-user mapping and is never reassigned.
    ///
    /// Returns `false` when the section list is full — see
    /// [`MAX_SECTIONS`].
    pub(crate) fn declare_remote(&mut self, other: Uid, ssrc: u32) -> bool {
        let mid = format!("user-{other}");
        match self.section_index(SectionKind::Remote(other)) {
            Some(i) => {
                if self.sections[i].ssrc == Some(ssrc) {
                    return true;
                }
                if let Some(old) = self.sections[i].ssrc {
                    self.rtc.direct_api().remove_stream_tx(old.into());
                }
                self.sections[i].ssrc = Some(ssrc);
            }
            None => {
                if self.sections.len() >= MAX_SECTIONS {
                    return false;
                }
                self.rtc
                    .direct_api()
                    .declare_media(mid.as_str().into(), MediaKind::Audio);
                self.sections.push(Section {
                    mid: mid.clone(),
                    kind: SectionKind::Remote(other),
                    ssrc: Some(ssrc),
                });
            }
        }
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

    /// The current offer, given who is in the room right now.
    ///
    /// Deterministic per (peer, room state) apart from the version
    /// counter, which RFC 3264 wants bumped whenever the description
    /// changes.
    pub(crate) fn offer(&mut self, present: &[(Uid, u32)], candidates: &[Candidate]) -> String {
        self.version += 1;
        let creds = self.rtc.direct_api().local_ice_credentials();
        let fingerprint = self.rtc.direct_api().local_dtls_fingerprint().clone();
        let sections: Vec<OfferSection<'_>> = self
            .sections
            .iter()
            .map(|s| match s.kind {
                SectionKind::Mic => OfferSection {
                    mid: &s.mid,
                    direction: Direction::RecvOnly,
                    ssrc: None,
                },
                SectionKind::Remote(other) => match present.iter().find(|(u, _)| *u == other) {
                    // Live while its offered direction says so; a
                    // participant who has left keeps the section and
                    // loses the direction.
                    Some((_, ssrc)) => OfferSection {
                        mid: &s.mid,
                        direction: Direction::SendOnly,
                        ssrc: Some((*ssrc, other)),
                    },
                    None => OfferSection {
                        mid: &s.mid,
                        direction: Direction::Inactive,
                        ssrc: None,
                    },
                },
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
    /// on the wire — the microphone SSRC to expect.
    ///
    /// That last part is the whole of the Janus bug this design exists
    /// not to repeat. Binding the SSRC *after* the answer is acknowledged
    /// leaves a window in which the client's first packets arrive against
    /// an undeclared SSRC, get dropped, and the publisher is never heard
    /// by anyone. There is no window here.
    pub(crate) fn apply_answer(
        &mut self,
        answer: &sdp::Answer,
        now: Instant,
    ) -> Result<(), str0m::RtcError> {
        // Only from the *first* answer. Every renegotiation carries the
        // client's credentials and fingerprint again, and re-applying
        // them would let a client swap the fingerprint its already-
        // completed DTLS session was verified against.
        if !self.answered {
            let mut api = self.rtc.direct_api();
            api.set_remote_ice_credentials(answer.creds.clone());
            api.set_remote_fingerprint(answer.fingerprint.clone());
        }
        if let Some(ssrc) = answer.mic_ssrc {
            self.rtc
                .direct_api()
                .expect_stream_rx(Ssrc::from(ssrc), None, MIC_MID.into(), None);
        }
        // The answerer takes `active`, so we take the other role.
        // `start_dtls` is idempotent — str0m returns early once DTLS is
        // inited — so a renegotiation's answer passes through it.
        self.rtc
            .direct_api()
            .start_dtls(!answer.client_is_dtls_client)?;
        self.answered = true;
        self.answered_at = Some(now);
        Ok(())
    }
}
