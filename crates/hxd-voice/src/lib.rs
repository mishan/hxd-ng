//! The voice SFU: one UDP port, one WebRTC session per participant, and
//! RTP forwarded between them without ever being decoded.
//!
//! This crate knows nothing about Hotline. It implements
//! [`hxd_core::VoiceMedia`] and is handed uids and chat ids by the
//! domain, which owns the rooms and the policy; what happens here is
//! SDP, ICE, DTLS-SRTP, and copying packets from one peer to the others.
//!
//! **Sans-I/O, with the sockets at the edge.** [`Sfu`] never touches the
//! network: datagrams are handed in with [`Sfu::handle_datagram`] and
//! taken out with [`Sfu::poll`]. [`run`] is the thin tokio task that
//! wraps a real `UdpSocket` around those two calls. That split is what
//! makes the interesting tests possible — two str0m instances can be
//! wired directly to each other, so a test can stand a real WebRTC
//! client up against this server, complete a real DTLS handshake, and
//! assert on real forwarded RTP without a socket anywhere.
//!
//! **One socket for every peer.** Each participant is an `Rtc`; an
//! arriving datagram is offered to each in turn with `rtc.accepts()`,
//! which demultiplexes on ICE credentials for STUN and on the address
//! ICE nominated for everything else. That is str0m's documented pattern
//! and the spec's "a single UDP port handles all WebRTC sessions" — with
//! one addition for the ICE-lite case, at [`Sfu::handle_datagram`].
//!
//! **The forwarding SSRC is ours, not the sender's.** The spec describes
//! an SFU that forwards a publisher's own SSRC untouched; we allocate one
//! per join instead and declare it in `a=ssrc` on every listener's
//! `user-{UID}` section, forwarding the sender's payload, sequence
//! numbers, timestamps and marker bits on it unchanged. The reason is
//! that a publisher's SSRC isn't known until its answer arrives, so
//! offers built from it would be incomplete for anyone who joined first
//! — the server would have to renegotiate the whole room again on every
//! answer. Ours is known at join, which keeps "the current offer for this
//! peer" a pure function of room state and keeps the domain's
//! renegotiation model honest. It is invisible on the wire: a client
//! demultiplexes by the SSRC we declared, which is the same thing it
//! would do with a forwarded one, and a rejoin gets a fresh SSRC exactly
//! as the spec's own rejoin case does.

pub mod peer;
pub mod sdp;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use hxd_core::video::{VideoConfig, VideoKind, VideoStream};
use hxd_core::voice::{IceCandidate, MediaEvent, VoiceError, VoiceMedia};
use hxd_core::Uid;
use str0m::config::DtlsCert;
use str0m::net::{Protocol, Receive};
use str0m::rtp::RtpWrite;
use str0m::{Candidate, Event, IceConnectionState, Input, Output};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, warn};

use crate::peer::Peer;
use crate::sdp::{host_candidates, MIC_MID, PCMU_PT, VP8_PT};

/// The spec's timeouts, as minimums. All measured against the monotonic
/// clock the caller passes in.
mod timeouts {
    use std::time::Duration;
    /// No SDP answer after the join reply.
    pub const ANSWER: Duration = Duration::from_secs(10);
    /// ICE connectivity checks, from the answer. Ends when ICE says it
    /// is connected, which is where [`DTLS`] takes over.
    pub const ICE: Duration = Duration::from_secs(30);
    /// The DTLS handshake, from the moment ICE connects. Its own, much
    /// shorter deadline: a handshake over a path ICE has already proved
    /// is a couple of round trips, and rolling it into the ICE budget
    /// would leave a peer whose DTLS is stalled sitting in the room for
    /// twenty seconds longer than the table allows.
    pub const DTLS: Duration = Duration::from_secs(10);
    /// No RTP *or RTCP* from a client whose session was established.
    pub const MEDIA: Duration = Duration::from_secs(30);
    /// A publication whose RTP has stopped while the peer's session
    /// stays alive. It costs the publication and its slot, and **never**
    /// the call: losing video is a degradation, losing the call is a
    /// failure.
    pub const VIDEO: Duration = Duration::from_secs(30);
}

/// The floor between keyframe requests for one publication.
///
/// The spec RECOMMENDS one second, and the number is load-bearing rather
/// than decorative: eight receivers whose renegotiations complete
/// together will each want a keyframe within a few milliseconds, and
/// eight keyframes is a bitrate spike at precisely the wrong moment. One
/// request coalesces the burst into the one keyframe that satisfies all
/// of them.
const KEYFRAME_INTERVAL: Duration = Duration::from_secs(1);

/// How long the pump waits when no peer has anything to do.
const IDLE_TICK: Duration = Duration::from_millis(500);

/// A datagram the SFU wants sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

/// Why an SFU couldn't be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfuError {
    /// No usable host candidate. A server behind NAT, or bound to a
    /// wildcard with nothing advertised, has no address to offer a
    /// client — it would hand out `0.0.0.0` and let every session time
    /// out. Better to refuse at startup.
    NoAdvertisableAddress,
    /// The crypto provider would not produce a DTLS certificate. Nothing
    /// can be negotiated without one, so this is fatal rather than
    /// per-session.
    NoDtlsCertificate,
}

impl std::fmt::Display for SfuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SfuError::NoAdvertisableAddress => f.write_str(
                "voice has no advertisable address: set [voice] advertise to an address \
                 clients can reach",
            ),
            SfuError::NoDtlsCertificate => {
                f.write_str("voice could not generate a DTLS certificate")
            }
        }
    }
}

impl std::error::Error for SfuError {}

/// The forwarder.
pub struct Sfu {
    inner: Mutex<Inner>,
    /// Where "now" comes from for the [`VoiceMedia`] calls, which the
    /// domain makes without a clock of its own.
    ///
    /// [`Sfu::poll`] and [`Sfu::handle_datagram`] take the caller's
    /// instant, so the sans-I/O tests drive a virtual clock through
    /// them — but the trait's methods had no such parameter and reached
    /// for `Instant::now()`, which put real time inside otherwise
    /// deterministic tests: a two-second stall between a join and a poll
    /// eleven virtual seconds later flipped a timeout assertion. It also
    /// made the keyframe rate limiter untestable without sleeping. One
    /// injectable source fixes both.
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

struct Inner {
    peers: HashMap<Uid, Peer>,
    /// Room membership, kept only so forwarding knows where a packet
    /// goes. The domain owns the authoritative one.
    rooms: HashMap<u32, Vec<Uid>>,
    /// The host candidates every peer offers, which is exactly what the
    /// operator asked us to advertise.
    candidates: Vec<Candidate>,
    /// Addresses a datagram may legitimately have arrived on, but which
    /// are **not** put in an offer.
    ///
    /// A server behind NAT advertises the public address it is
    /// port-forwarded from and binds a private one. ICE checks the
    /// destination of an inbound STUN request against the agent's local
    /// candidates and silently discards anything else — after
    /// `Rtc::accepts` has already claimed the datagram by ufrag, so the
    /// packet is not even stray enough to log. Giving the agent the bind
    /// address as well makes that config work, and telling nobody about
    /// it keeps the offer honest: a client is still only ever pointed at
    /// an address the operator says it can reach.
    extra_locals: Vec<Candidate>,
    events: UnboundedSender<MediaEvent>,
    next_session_id: u64,
    /// The server's DTLS certificate, generated once and shared by every
    /// peer.
    ///
    /// Letting `RtcConfig::build` generate one per session meant a P-256
    /// key pair and a self-signature on every join — about 1.4 ms, spent
    /// inside `Core::voice_join` with the **server-wide roster lock
    /// held**, because `VoiceMedia` calls are made under it. One
    /// authenticated client looping joins could therefore saturate the
    /// lock that every login, chat message and user-list update on both
    /// wires also needs. `docs/voice.md` §4 permits calls under that lock
    /// only because they are in-memory state changes; certificate
    /// generation never was one.
    ///
    /// Sharing it is the ordinary shape for a server — a fingerprint
    /// identifies the server, not the session, and each peer still
    /// verifies the one its own offer carried. Nothing about the private
    /// key reaches a peer.
    cert: DtlsCert,
    /// The configured per-kind ceilings, reflected in `b=AS` on every
    /// video section. Configuration, not negotiation.
    video: VideoConfig,
}

/// Which of a peer's streams a packet belongs to. Audio is the peer
/// itself; video needs the kind too, because one peer can be sending a
/// camera and a screen at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Audio,
    Video(VideoKind),
}

/// One packet on its way from one peer to the others.
struct Forward {
    from: Uid,
    cid: u32,
    stream: Stream,
    pt: u8,
    seq_no: str0m::rtp::SeqNo,
    time: u32,
    marker: bool,
    payload: Arc<[u8]>,
}

impl Sfu {
    /// Build an SFU advertising `advertise` as its host candidates.
    ///
    /// Returns the media events the domain must be fed — server ICE
    /// candidates and peers that failed a timeout — on the channel it
    /// hands back.
    pub fn new(
        advertise: &[SocketAddr],
        video: VideoConfig,
    ) -> Result<(Arc<Sfu>, UnboundedReceiver<MediaEvent>), SfuError> {
        Sfu::with_locals(advertise, &[], video, Box::new(Instant::now))
    }

    /// The same, plus addresses a datagram may arrive on that are not
    /// advertised (see [`Inner::extra_locals`]), and the clock the
    /// [`VoiceMedia`] methods read.
    pub fn with_locals(
        advertise: &[SocketAddr],
        extra: &[SocketAddr],
        video: VideoConfig,
        clock: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Result<(Arc<Sfu>, UnboundedReceiver<MediaEvent>), SfuError> {
        install_crypto();
        let candidates = host_candidates(advertise);
        if candidates.is_empty() {
            return Err(SfuError::NoAdvertisableAddress);
        }
        // Anything already advertised is not "extra", and offering the
        // same address twice would only give ICE a duplicate to check.
        let extra_locals: Vec<Candidate> = host_candidates(extra)
            .into_iter()
            .filter(|c| !candidates.iter().any(|a| a.addr() == c.addr()))
            .collect();
        let cert = str0m::crypto::from_feature_flags()
            .dtls_provider
            .generate_certificate()
            .ok_or(SfuError::NoDtlsCertificate)?;
        let (tx, rx) = unbounded_channel();
        let sfu = Arc::new(Sfu {
            inner: Mutex::new(Inner {
                peers: HashMap::new(),
                rooms: HashMap::new(),
                candidates,
                extra_locals,
                events: tx,
                next_session_id: 1,
                video,
                cert,
            }),
            clock,
        });
        Ok((sfu, rx))
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Feed one received datagram. `to` is the local address it arrived
    /// on, which ICE matches against our host candidates.
    ///
    /// Returns whether it belonged to a live session. A `false` is what
    /// the pump's rate limiter charges against the source: deciding a
    /// datagram matches nothing means offering it to every `Rtc` under
    /// this mutex, so it is the expensive answer, not the cheap one.
    pub fn handle_datagram(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        let Ok(contents) = data.try_into() else {
            debug!(%from, "unparseable datagram");
            return false;
        };
        let input = Input::Receive(
            now,
            Receive {
                proto: Protocol::Udp,
                source: from,
                destination: to,
                contents,
            },
        );
        let mut inner = self.inner.lock().unwrap();
        let Some(uid) = inner
            .peers
            .iter()
            .find(|(_, p)| p.rtc.accepts(&input))
            .map(|(uid, _)| *uid)
            // `accepts` recognises STUN by ICE credentials, traffic from
            // the address ICE nominated for sending, and traffic from a
            // remote candidate a check of our own validated. An ICE-lite
            // agent sends no checks, so that third path never fires for
            // it, and the peer's first DTLS record routinely arrives
            // between our answering its binding request and our polling
            // out the nomination that sets a send address. A pure
            // `accepts` demux drops that record and the handshake waits
            // out a DTLS retransmit — a second of silence on every join.
            // The address a peer's own integrity-checked STUN came from
            // vouches for it exactly as the fast path's does, so this
            // fallback costs nothing and buys the second back. Reported
            // upstream with a patch; drop this when it lands.
            .or_else(|| {
                inner
                    .peers
                    .iter()
                    .find(|(_, p)| p.remote == Some(from))
                    .map(|(uid, _)| *uid)
            })
        else {
            // Not for any live session. On an open UDP port this is the
            // normal case for scanners and stray packets alike, and
            // dropping it is most of the defence; the pump rate-limits
            // the source so that deciding this stays cheap in aggregate.
            debug!(%from, "datagram matched no voice session");
            return false;
        };
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return false;
        };
        // Note what is *not* here: the media clock. A datagram's shape
        // says nothing about who sent it — this code runs before str0m
        // has authenticated a byte of it, and the address fallback above
        // will route anything from a remembered endpoint to this peer.
        // Refreshing liveness here let anyone who could reach the port
        // and guess an address suppress the no-media timeout with a
        // single byte ≥ 128, keeping a dead session's room slot and
        // section occupied for as long as they cared to keep sending.
        // Liveness is taken from what the stack decrypts instead; see
        // `poll_all`.
        peer.remote = Some(from);
        if let Err(e) = peer.rtc.handle_input(input) {
            warn!(uid, "voice session error: {e}");
            inner.fail(uid);
        }
        true
    }

    /// Drain everything the SFU wants to send and report when it next
    /// wants to be called.
    pub fn poll(&self, now: Instant) -> (Vec<Datagram>, Instant) {
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let mut out = Vec::new();
        // Forwarding a packet makes the receiving peer want to transmit,
        // so keep going until a pass produces nothing new to forward.
        for _ in 0..4 {
            let forwards = inner.poll_all(now, &mut out);
            if forwards.is_empty() {
                break;
            }
            inner.forward_all(forwards, now);
        }
        let deadline = inner.deadline(now);
        (out, deadline)
    }

    /// How many participants are in voice right now (metrics, tests).
    pub fn peer_count(&self) -> usize {
        self.inner.lock().unwrap().peers.len()
    }
}

impl Inner {
    fn emit(&self, ev: MediaEvent) {
        let _ = self.events.send(ev);
    }

    /// Tear a peer down and tell the domain, which turns it into a leave
    /// with the room status any leave produces.
    fn fail(&mut self, uid: Uid) {
        let Some(peer) = self.peers.get(&uid) else {
            return;
        };
        let cid = peer.cid;
        self.remove(uid);
        self.emit(MediaEvent::Failed { uid, cid });
    }

    fn remove(&mut self, uid: Uid) {
        let Some(peer) = self.peers.remove(&uid) else {
            return;
        };
        if let Some(room) = self.rooms.get_mut(&peer.cid) {
            room.retain(|u| *u != uid);
            if room.is_empty() {
                self.rooms.remove(&peer.cid);
            }
        }
    }

    /// The spec's timeout table, applied.
    ///
    /// The media deadline is the one with a judgement call in it. What it
    /// watches is authenticated RTP and RTCP sender reports, because
    /// those are the only inbound media str0m hands us with the sender's
    /// identity proved. A client's RTCP *receiver* reports, which the
    /// spec's table also counts, are consumed inside the stack and never
    /// surface — so a peer that is deliberately silent would be reaped
    /// on their evidence alone. A muted peer is exactly that peer: the
    /// spec asks clients to join muted, and a client that mutes by
    /// dropping its track is conforming, not dead. So mute suspends this
    /// deadline, and a peer that is silent without being muted is one
    /// the table means. Neither case loses its safety net: a session
    /// whose path has really gone stops answering ICE, and str0m closes
    /// it — which is the `is_alive` check below, and it is authenticated
    /// the whole way down.
    fn expire(&mut self, now: Instant) {
        let mut failed = Vec::new();
        for (uid, p) in &self.peers {
            let reason = if !p.answered {
                (now.duration_since(p.joined_at) >= timeouts::ANSWER).then_some("no answer")
            } else if !p.connected {
                match p.ice_connected_at {
                    // ICE has a path; only the handshake is left.
                    Some(t) => (now.duration_since(t) >= timeouts::DTLS).then_some("DTLS"),
                    None => {
                        let since = p.answered_at.unwrap_or(p.joined_at);
                        (now.duration_since(since) >= timeouts::ICE).then_some("ICE")
                    }
                }
            } else if p.muted {
                None
            } else {
                p.last_media
                    .filter(|t| now.duration_since(*t) >= timeouts::MEDIA)
                    .map(|_| "no media")
            };
            if let Some(reason) = reason {
                info!(uid, cid = p.cid, "voice session timed out: {reason}");
                failed.push(*uid);
            } else if !p.rtc.is_alive() {
                info!(uid, cid = p.cid, "voice session closed");
                failed.push(*uid);
            }
        }
        for uid in failed {
            self.fail(uid);
        }
        self.expire_publications(now);
    }

    /// A publication whose media has stopped while its peer's session is
    /// healthy: drop it, release its slot, and leave the audio alone.
    ///
    /// Only a publication that has been live counts. One that has never
    /// sent anything is either paused or still negotiating, and both of
    /// those are legitimately silent — reaping them would make "turn my
    /// camera off for a minute" end the publication.
    fn expire_publications(&mut self, now: Instant) {
        let mut stalled = Vec::new();
        for (uid, p) in &self.peers {
            for pubn in &p.publications {
                if pubn.paused {
                    continue;
                }
                if pubn
                    .last_media
                    .is_some_and(|t| now.duration_since(t) >= timeouts::VIDEO)
                {
                    stalled.push((*uid, p.cid, pubn.kind));
                }
            }
        }
        for (uid, cid, kind) in stalled {
            info!(uid, cid, ?kind, "video publication stalled; dropping it");
            if let Some(peer) = self.peers.get_mut(&uid) {
                peer.undeclare_video_send(kind);
            }
            self.emit(MediaEvent::VideoFailed { uid, cid, kind });
        }
    }

    /// One pass over every peer: drive its clock, take its outbound
    /// datagrams, and collect the RTP it wants forwarded.
    fn poll_all(&mut self, now: Instant, out: &mut Vec<Datagram>) -> Vec<Forward> {
        let mut forwards = Vec::new();
        let uids: Vec<Uid> = self.peers.keys().copied().collect();
        let mut broken = Vec::new();
        let mut keyframes: Vec<(Uid, VideoKind)> = Vec::new();
        for uid in uids {
            let Some(peer) = self.peers.get_mut(&uid) else {
                continue;
            };
            if peer.rtc.handle_input(Input::Timeout(now)).is_err() {
                broken.push(uid);
                continue;
            }
            loop {
                match peer.rtc.poll_output() {
                    Ok(Output::Timeout(t)) => {
                        peer.next_timeout = Some(t);
                        break;
                    }
                    Ok(Output::Transmit(t)) => out.push(Datagram {
                        to: t.destination,
                        data: t.contents.to_vec(),
                    }),
                    Ok(Output::Event(ev)) => match ev {
                        // ICE is done arguing about paths; the DTLS clock
                        // starts here (see `timeouts::DTLS`). First
                        // transition only — a flap later in the session
                        // must not hand a stalled handshake a fresh
                        // deadline.
                        Event::IceConnectionStateChange(
                            IceConnectionState::Connected | IceConnectionState::Completed,
                        ) if peer.ice_connected_at.is_none() => {
                            peer.ice_connected_at = Some(now);
                            debug!(uid, cid = peer.cid, "voice ICE connected");
                        }
                        Event::Connected => {
                            peer.connected = true;
                            peer.last_media = Some(now);
                            info!(uid, cid = peer.cid, "voice session connected");
                        }
                        // An RTCP sender report the stack verified: a
                        // client that is sending is alive even if its
                        // RTP is momentarily lost. Unlike a raw
                        // datagram, this one has been authenticated.
                        Event::SenderFeedback(_) => peer.last_media = Some(now),
                        Event::RtpPacket(p) => {
                            peer.last_media = Some(now);
                            let pt = *p.header.payload_type;
                            let stream = if pt == PCMU_PT {
                                if peer.muted {
                                    // Server-enforced mute, and it really
                                    // is one `if`: the packet is dropped
                                    // before anyone could be sent it,
                                    // whatever the client keeps sending.
                                    continue;
                                }
                                Stream::Audio
                            } else if pt == VP8_PT {
                                // Keyed by SSRC, never by mid or payload
                                // type: a camera and a screen from one
                                // peer are the same codec on the same
                                // transport, and the SSRC the answer
                                // declared is the only thing that tells
                                // them apart. No match means no
                                // publication to attribute it to, and
                                // guessing is worse than dropping.
                                let Some(pubn) = peer.publication_by_ssrc(*p.header.ssrc) else {
                                    continue;
                                };
                                let kind = pubn.kind;
                                let paused = pubn.paused;
                                if let Some(pubn) = peer.publication_mut(kind) {
                                    pubn.last_media = Some(now);
                                }
                                if paused {
                                    // Pause is enforced exactly as mute
                                    // is: by discarding the inbound RTP,
                                    // not by trusting the client to have
                                    // stopped capturing.
                                    continue;
                                }
                                Stream::Video(kind)
                            } else {
                                // RTX (97) and anything else a client
                                // sends uninvited.
                                continue;
                            };
                            forwards.push(Forward {
                                from: uid,
                                cid: peer.cid,
                                stream,
                                pt,
                                seq_no: p.seq_no,
                                time: p.header.timestamp,
                                marker: p.header.marker,
                                payload: p.payload.clone(),
                            });
                        }
                        Event::KeyframeRequest(req) => {
                            // A receiver has no keyframe and said so.
                            // Relay it to whoever is publishing that
                            // section — rate-limited at the publisher, so
                            // a room asking at once costs one keyframe.
                            if let Some((publisher, kind)) = peer.publisher_for_mid(req.mid) {
                                keyframes.push((publisher, kind));
                            }
                        }
                        _ => {}
                    },
                    Err(e) => {
                        warn!(uid, "voice session error: {e}");
                        broken.push(uid);
                        break;
                    }
                }
            }
        }
        for uid in broken {
            self.fail(uid);
        }
        for (uid, kind) in keyframes {
            self.request_keyframe(uid, kind, now);
        }
        forwards
    }

    /// Ask a publisher for a keyframe, no more than once a second per
    /// publication.
    fn request_keyframe(&mut self, uid: Uid, kind: VideoKind, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&uid) {
            if peer.request_keyframe(kind, now, KEYFRAME_INTERVAL) {
                debug!(uid, ?kind, "requested a keyframe from the publisher");
            }
        }
    }

    /// The SFU's whole job: copy each packet onto every other peer in the
    /// room, on the section that peer knows as this speaker's.
    ///
    /// Audio goes to everyone in the room; **video goes only to peers
    /// that asked for it.** That single difference is what keeps a
    /// video-less client safe without a special case for it: it is a peer
    /// whose subscription set is empty, and it takes the same code path
    /// as a video-capable one that hasn't subscribed yet.
    fn forward_all(&mut self, forwards: Vec<Forward>, now: Instant) {
        for f in forwards {
            let Some(room) = self.rooms.get(&f.cid) else {
                continue;
            };
            let targets: Vec<Uid> = room.iter().copied().filter(|u| *u != f.from).collect();
            for to in targets {
                let Some(peer) = self.peers.get_mut(&to) else {
                    continue;
                };
                if !peer.connected {
                    continue;
                }
                let mid = match f.stream {
                    Stream::Audio => peer.mid_for(f.from).map(str::to_string),
                    Stream::Video(kind) => {
                        if !peer.subscribes_to(f.from, kind) {
                            continue;
                        }
                        peer.video_mid_for(f.from, kind).map(str::to_string)
                    }
                };
                let Some(mid) = mid else {
                    continue;
                };
                let mut api = peer.rtc.direct_api();
                let Some(stream) = api.stream_tx_by_mid(mid.as_str().into(), None) else {
                    continue;
                };
                // Payload type, sequence number, timestamp and marker
                // pass through untouched; only the SSRC is ours, and it
                // is the one this peer's SDP declared.
                stream.write_rtp(
                    RtpWrite::new(f.pt.into(), f.seq_no, f.time, now, Arc::clone(&f.payload))
                        .marker(f.marker),
                );
            }
        }
    }

    fn deadline(&self, now: Instant) -> Instant {
        self.peers
            .values()
            .filter_map(|p| p.next_timeout)
            .min()
            .unwrap_or(now + IDLE_TICK)
            .max(now)
            .min(now + IDLE_TICK)
    }

    /// The publications `viewer` has subscribed to that still exist, and
    /// the SSRC each is forwarded on.
    ///
    /// The intersection is taken here rather than trusted from the
    /// domain's last call, because a publisher can stop or leave between
    /// one and the next and an offer must never describe a section the
    /// forwarding path won't fill.
    fn present_video(&self, cid: u32, viewer: Uid) -> Vec<(Uid, VideoKind, u32)> {
        let Some(peer) = self.peers.get(&viewer) else {
            return Vec::new();
        };
        let Some(room) = self.rooms.get(&cid) else {
            return Vec::new();
        };
        peer.subscriptions
            .iter()
            .filter(|s| s.uid != viewer && room.contains(&s.uid))
            .filter_map(|s| {
                let publisher = self.peers.get(&s.uid)?;
                let pubn = publisher.publication(s.kind)?;
                Some((s.uid, s.kind, pubn.forward_ssrc))
            })
            .collect()
    }

    /// Who else is in this room, and on which SSRC their audio arrives.
    fn present(&self, cid: u32, except: Uid) -> Vec<(Uid, u32)> {
        self.rooms
            .get(&cid)
            .map(|room| {
                room.iter()
                    .filter(|u| **u != except)
                    .filter_map(|u| self.peers.get(u).map(|p| (*u, p.forward_ssrc)))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl VoiceMedia for Sfu {
    fn codec(&self) -> &'static str {
        "PCMU"
    }

    fn join(&self, uid: Uid, cid: u32) {
        let now = self.now();
        let mut inner = self.inner.lock().unwrap();
        // A rejoin arrives here as leave-then-join from the domain, but
        // the media layer must not depend on that to avoid two sessions
        // for one user.
        inner.remove(uid);

        let session_id = inner.next_session_id;
        inner.next_session_id += 1;
        let candidates = inner.candidates.clone();
        let extra = inner.extra_locals.clone();
        let cert = inner.cert.clone();
        let mut peer = Peer::new(cid, now, &candidates, &extra, cert, session_id, 0);
        // str0m's own SSRC allocator: random, and one less dependency
        // than reaching for a CSPRNG here.
        peer.forward_ssrc = *peer.rtc.direct_api().new_ssrc();

        // The joiner's first offer lists the room it is joining and then
        // its own microphone, which is the order the spec's example uses.
        // A fresh session starts with an empty section list, so the cap
        // can't bite here — the room cap is far below it.
        for (other, ssrc) in inner.present(cid, uid) {
            peer.declare_remote(other, ssrc);
        }
        peer.declare_mic();

        inner.peers.insert(uid, peer);
        inner.rooms.entry(cid).or_default().push(uid);
        info!(uid, cid, "voice session created");
    }

    fn leave(&self, uid: Uid, cid: u32) {
        let mut inner = self.inner.lock().unwrap();
        if inner.peers.get(&uid).is_some_and(|p| p.cid == cid) {
            inner.remove(uid);
            info!(uid, cid, "voice session torn down");
        }
    }

    fn offer(&self, uid: Uid, cid: u32) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        let present = inner.present(cid, uid);
        let present_video = inner.present_video(cid, uid);
        let candidates = inner.candidates.clone();
        let limits = inner.video;
        let Some(peer) = inner.peers.get_mut(&uid) else {
            // The domain never asks for an offer for a peer it hasn't
            // joined, but the sentinel is exactly for the case where it
            // does: there is no session here to describe.
            return None;
        };
        let mut full = false;
        for (other, ssrc) in &present {
            if !peer.declare_remote(*other, *ssrc) {
                full = true;
            }
        }
        // Retire whatever is no longer coming through before declaring
        // what is, so a publication this peer has just resubscribed to is
        // seen as returning rather than continuing — which is what earns
        // it a fresh SSRC instead of a sequence-number cliff.
        peer.deactivate_absent_video(&present_video);
        // Only subscribed publications get a section. A peer that has
        // subscribed to nothing is offered no video sections at all,
        // which is what stops the server inviting itself to send
        // megabits to a client that would decode them and throw them
        // away.
        for (other, kind, ssrc) in &present_video {
            if !peer.declare_remote_video(*other, *kind, *ssrc) {
                full = true;
            }
        }
        let sdp = peer.offer(&present, &present_video, &candidates, &limits);
        let peer_cid = peer.cid;
        if full {
            // This session has been in the room long enough that its
            // offer has no room left for another section. End it: the
            // client reconnects with a clean section list, which is the
            // only way back under the ceiling.
            //
            // The offer just built goes in the bin with it. It is short
            // by whoever didn't fit, and by the next line it describes a
            // session that no longer exists — sending it would start a
            // renegotiation with a client whose `Failed` is already on
            // its way to the domain. The sentinel is what says so.
            warn!(
                uid,
                cid = peer_cid,
                "voice session ended: media sections exhausted"
            );
            inner.fail(uid);
            return None;
        }
        Some(sdp)
    }

    fn answer(&self, uid: Uid, cid: u32, sdp: &str) -> Result<(), VoiceError> {
        let now = self.now();
        let mut inner = self.inner.lock().unwrap();
        let answer = match sdp::parse_answer(sdp) {
            Ok(a) => a,
            Err(e) => {
                info!(uid, cid, "rejecting voice answer: {e}");
                return Err(VoiceError::BadAnswer);
            }
        };
        if answer.mic_ssrc.is_none() {
            // Tolerated by the spec, and it costs this session the
            // ability to bind inbound RTP until the payload-type
            // fallback would kick in — which we don't implement yet.
            warn!(uid, cid, "voice answer declares no microphone SSRC");
        }
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return Err(VoiceError::NotInVoice);
        };
        let unbindable = match peer.apply_answer(&answer, now) {
            Ok(u) => u,
            Err(e) => {
                warn!(uid, cid, "voice answer refused by the stack: {e}");
                return Err(VoiceError::BadAnswer);
            }
        };
        // A video send section the client answered without an `a=ssrc`,
        // or declined outright. The publication goes; the call stays.
        for kind in unbindable {
            warn!(
                uid,
                cid,
                ?kind,
                "video answer declares no SSRC for this publication; dropping it"
            );
            if let Some(peer) = inner.peers.get_mut(&uid) {
                peer.undeclare_video_send(kind);
            }
            inner.emit(MediaEvent::VideoFailed { uid, cid, kind });
        }
        // The renegotiation this answer completes is the moment a
        // receiver's newly-active sections actually have a decoder behind
        // them, and the spec makes that one of the four keyframe
        // triggers. Asking at subscribe time alone is not enough: the
        // subscriber's offer may sit behind an unanswered one for an
        // arbitrary interval, so the keyframe arrives before there is
        // anything to decode it and the rate limiter then blocks the
        // retry. Asking again here costs nothing when it is redundant —
        // the limiter collapses it.
        let subscriptions: Vec<VideoStream> = inner
            .peers
            .get(&uid)
            .map(|p| p.subscriptions.clone())
            .unwrap_or_default();
        for s in subscriptions {
            inner.request_keyframe(s.uid, s.kind, now);
        }
        // ICE-lite: our candidates rode the offer, so the only thing
        // left to trickle is the end of them. Sending it after the
        // answer means the client already has the offer it refers to.
        inner.emit(MediaEvent::Ice {
            uid,
            cid,
            candidate: IceCandidate::end_of_candidates(MIC_MID),
        });
        Ok(())
    }

    fn remote_ice(&self, uid: Uid, cid: u32, candidate: &IceCandidate) {
        if candidate.is_end_of_candidates() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return;
        };
        match Candidate::from_sdp_string(&candidate.candidate) {
            Ok(c) => peer.rtc.add_remote_candidate(c),
            Err(e) => debug!(uid, cid, "ignoring unparseable ICE candidate: {e}"),
        }
    }

    fn set_muted(&self, uid: Uid, cid: u32, muted: bool) {
        let now = self.now();
        let mut inner = self.inner.lock().unwrap();
        if let Some(peer) = inner.peers.get_mut(&uid) {
            if peer.cid == cid {
                // Coming off mute restarts the media clock. Mute
                // suspends the no-media deadline (see `expire`), so
                // without this a peer that spent ten minutes muted would
                // be reaped the instant it unmuted, on the strength of
                // silence it was entitled to.
                if peer.muted && !muted {
                    peer.last_media = Some(now);
                }
                peer.muted = muted;
            }
        }
    }

    // --- Video ----------------------------------------------------------

    fn video_codec(&self) -> &'static str {
        "VP8"
    }

    fn publish(&self, uid: Uid, cid: u32, kind: VideoKind) -> bool {
        let mut inner = self.inner.lock().unwrap();
        // The forwarding SSRC is allocated up front, exactly as audio's
        // is: the offer for a publication has to be complete before the
        // publisher's answer arrives, or every subscriber who joined
        // first would need renegotiating again the moment it did.
        //
        // The `bool` matters. This can fail — the session may have been
        // reaped with a `Failed` already in flight, or its offer may have
        // no room left for another section — and the domain has by this
        // point claimed a room slot and is about to announce the
        // publication to everyone. Dropping the answer left the publisher
        // with no send section, no way to send a frame, no `VideoFailed`
        // to release the slot, and a room whose single screen slot stayed
        // occupied by a publication that could never produce a pixel.
        // `answer` reports its failures through `VideoFailed` for exactly
        // this reason; this had no channel at all.
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return false;
        };
        if peer.cid != cid {
            return false;
        }
        let ssrc = *peer.rtc.direct_api().new_ssrc();
        if !peer.declare_video_send(kind, ssrc) {
            warn!(
                uid,
                cid,
                ?kind,
                "video publication refused: no room in the offer"
            );
            return false;
        }
        info!(uid, cid, ?kind, "video publication started");
        true
    }

    fn unpublish(&self, uid: Uid, cid: u32, kind: VideoKind) {
        let mut inner = self.inner.lock().unwrap();
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return;
        };
        if peer.cid == cid && peer.undeclare_video_send(kind) {
            info!(uid, cid, ?kind, "video publication stopped");
        }
    }

    fn set_paused(&self, uid: Uid, cid: u32, kind: VideoKind, paused: bool) {
        let now = self.now();
        let mut inner = self.inner.lock().unwrap();
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return;
        };
        if peer.cid != cid {
            return;
        }
        if let Some(pubn) = peer.publication_mut(kind) {
            pubn.paused = paused;
            if paused {
                // A paused publication sends nothing, so its media clock
                // must stop counting against the stall reaper too.
                pubn.last_media = None;
            }
        }
        if !paused {
            // A decoder cannot start mid-stream, so a resumed publication
            // is a black tile until the next keyframe. Ask for one rather
            // than waiting for the encoder to volunteer it, which VP8 may
            // not do for many seconds.
            inner.request_keyframe(uid, kind, now);
        }
    }

    fn set_subscriptions(&self, uid: Uid, cid: u32, streams: &[VideoStream]) {
        let now = self.now();
        let mut inner = self.inner.lock().unwrap();
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return;
        };
        if peer.cid != cid {
            return;
        }
        // Only what is newly arriving needs a keyframe. A set that is
        // re-declared unchanged — which is what an idempotent absolute
        // set invites a client to do — must not cost the room a keyframe
        // each time.
        let added: Vec<VideoStream> = streams
            .iter()
            .filter(|s| !peer.subscriptions.contains(s))
            .copied()
            .collect();
        peer.subscriptions = streams.to_vec();
        for s in added {
            inner.request_keyframe(s.uid, s.kind, now);
        }
    }
}

/// The UDP pump: the only part of this crate that touches a socket.
///
/// One task, one socket, every session. It alternates between waiting for
/// a datagram and waiting for whatever the SFU said it wanted next, which
/// is how a sans-I/O stack's timers get driven.
pub async fn run(sfu: Arc<Sfu>, socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let local = socket.local_addr()?;
    let mut buf = vec![0u8; 2048];
    let mut unmatched = UnmatchedLimiter::default();
    loop {
        let (datagrams, deadline) = sfu.poll(Instant::now());
        for d in datagrams {
            if let Err(e) = socket.send_to(&d.data, d.to).await {
                debug!("voice send to {} failed: {e}", d.to);
            }
        }
        tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok((n, from)) => {
                    feed(&sfu, &socket, local, from, &buf[..n], &mut unmatched);
                    // Drain whatever else is already queued before going
                    // back round. Polling is O(peers) and the loop polls
                    // once per iteration, so a burst — a talkative room,
                    // or a flood — otherwise costs one full pass over
                    // every session per packet. Taking the burst in one
                    // go amortises that, and the deadline below is
                    // recomputed straight after.
                    for _ in 0..BURST_DRAIN {
                        match socket.try_recv_from(&mut buf) {
                            Ok((n, from)) => {
                                feed(&sfu, &socket, local, from, &buf[..n], &mut unmatched);
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => debug!("voice recv failed: {e}"),
            },
            _ = tokio::time::sleep_until(deadline.into()) => {}
        }
    }
}

/// How many further datagrams one wake-up may take before polling again.
/// Bounded so a sustained flood can't starve the timers that drive ICE,
/// DTLS and the timeout table.
const BURST_DRAIN: usize = 64;

/// Hand one datagram to the SFU, unless its source has spent its budget
/// for datagrams that match no session.
fn feed(
    sfu: &Sfu,
    socket: &tokio::net::UdpSocket,
    local: SocketAddr,
    from: SocketAddr,
    data: &[u8],
    unmatched: &mut UnmatchedLimiter,
) {
    let _ = socket;
    if !unmatched.allow(from, Instant::now()) {
        return;
    }
    // With a wildcard bind the socket can't tell us which local address
    // the datagram arrived on, and ICE matches candidates by it — so
    // report the advertised address of the right family.
    let to = local_for(sfu, local, from);
    if !sfu.handle_datagram(from, to, data, Instant::now()) {
        unmatched.miss(from, Instant::now());
    }
}

/// A token bucket over sources whose datagrams match no live session.
///
/// `docs/voice.md` §10 names this as the answer to "an unauthenticated
/// UDP port on the internet", and it was the one part of that answer not
/// implemented. Dropping an unmatched datagram is cheap, but *deciding*
/// it is unmatched is not: the datagram is offered to every live `Rtc` in
/// turn, under the SFU's mutex. A trivial spoofed flood therefore costs
/// the room its forwarding latency, with nothing above a `debug!` to say
/// why.
///
/// Only misses are charged, so a peer sending real media is never
/// throttled however fast it sends. The table is keyed by address and
/// swept whole rather than per entry, which keeps a spoofed-source flood
/// from turning the defence into the memory leak.
#[derive(Default)]
struct UnmatchedLimiter {
    seen: HashMap<SocketAddr, u32>,
    window_started: Option<Instant>,
}

impl UnmatchedLimiter {
    /// Misses one source may spend per window before it is ignored.
    /// Generous next to a real handshake, which matches on its first
    /// STUN and is never charged at all.
    const BUDGET: u32 = 32;
    const WINDOW: Duration = Duration::from_secs(1);
    /// Distinct sources tracked before the table is swept early. A
    /// spoofed flood is the case this bounds.
    const MAX_SOURCES: usize = 4096;

    fn roll(&mut self, now: Instant) {
        let stale = self
            .window_started
            .is_none_or(|t| now.duration_since(t) >= Self::WINDOW);
        if stale || self.seen.len() > Self::MAX_SOURCES {
            self.seen.clear();
            self.window_started = Some(now);
        }
    }

    fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        self.roll(now);
        self.seen.get(&from).is_none_or(|n| *n < Self::BUDGET)
    }

    fn miss(&mut self, from: SocketAddr, now: Instant) {
        self.roll(now);
        let n = self.seen.entry(from).or_insert(0);
        *n += 1;
        if *n == Self::BUDGET {
            debug!(%from, "ignoring further unmatched voice datagrams this second");
        }
    }
}

/// The local address to report for a datagram from `from`: the socket's
/// own when it is a concrete one, otherwise the advertised candidate of
/// the same address family.
fn local_for(sfu: &Sfu, local: SocketAddr, from: SocketAddr) -> SocketAddr {
    if !local.ip().is_unspecified() {
        return local;
    }
    let inner = sfu.inner.lock().unwrap();
    inner
        .candidates
        .iter()
        .map(|c| c.addr())
        .find(|a| a.is_ipv4() == from.is_ipv4())
        .unwrap_or(local)
}

/// str0m wants a crypto provider installed once per process.
fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        str0m::crypto::from_feature_flags().install_process_default();
    });
}
