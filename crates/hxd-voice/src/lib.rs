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

use hxd_core::voice::{IceCandidate, MediaEvent, VoiceError, VoiceMedia};
use hxd_core::Uid;
use str0m::net::{Protocol, Receive};
use str0m::rtp::RtpWrite;
use str0m::{Candidate, Event, IceConnectionState, Input, Output};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, warn};

use crate::peer::Peer;
use crate::sdp::{host_candidates, MIC_MID, PCMU_PT};

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
}

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
}

impl std::fmt::Display for SfuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SfuError::NoAdvertisableAddress => f.write_str(
                "voice has no advertisable address: set [voice] advertise to an address \
                 clients can reach",
            ),
        }
    }
}

impl std::error::Error for SfuError {}

/// The forwarder.
pub struct Sfu {
    inner: Mutex<Inner>,
}

struct Inner {
    peers: HashMap<Uid, Peer>,
    /// Room membership, kept only so forwarding knows where a packet
    /// goes. The domain owns the authoritative one.
    rooms: HashMap<u32, Vec<Uid>>,
    candidates: Vec<Candidate>,
    events: UnboundedSender<MediaEvent>,
    next_session_id: u64,
}

/// One packet on its way from one peer to the others.
struct Forward {
    from: Uid,
    cid: u32,
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
    ) -> Result<(Arc<Sfu>, UnboundedReceiver<MediaEvent>), SfuError> {
        install_crypto();
        let candidates = host_candidates(advertise);
        if candidates.is_empty() {
            return Err(SfuError::NoAdvertisableAddress);
        }
        let (tx, rx) = unbounded_channel();
        let sfu = Arc::new(Sfu {
            inner: Mutex::new(Inner {
                peers: HashMap::new(),
                rooms: HashMap::new(),
                candidates,
                events: tx,
                next_session_id: 1,
            }),
        });
        Ok((sfu, rx))
    }

    /// Feed one received datagram. `to` is the local address it arrived
    /// on, which ICE matches against our host candidates.
    pub fn handle_datagram(&self, from: SocketAddr, to: SocketAddr, data: &[u8], now: Instant) {
        let Ok(contents) = data.try_into() else {
            debug!(%from, "unparseable datagram");
            return;
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
            // dropping it is the whole defence.
            debug!(%from, "datagram matched no voice session");
            return;
        };
        let Some(peer) = inner.peers.get_mut(&uid) else {
            return;
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
    }

    /// One pass over every peer: drive its clock, take its outbound
    /// datagrams, and collect the RTP it wants forwarded.
    fn poll_all(&mut self, now: Instant, out: &mut Vec<Datagram>) -> Vec<Forward> {
        let mut forwards = Vec::new();
        let uids: Vec<Uid> = self.peers.keys().copied().collect();
        let mut broken = Vec::new();
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
                            if peer.muted {
                                // Server-enforced mute, and it really is
                                // one `if`: the packet is dropped before
                                // anyone could be sent it, whatever the
                                // client chooses to keep sending.
                                continue;
                            }
                            if *p.header.payload_type != PCMU_PT {
                                continue;
                            }
                            forwards.push(Forward {
                                from: uid,
                                cid: peer.cid,
                                seq_no: p.seq_no,
                                time: p.header.timestamp,
                                marker: p.header.marker,
                                payload: p.payload.clone(),
                            });
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
        forwards
    }

    /// The SFU's whole job: copy each packet onto every other peer in the
    /// room, on the section that peer knows as this speaker's.
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
                let Some(mid) = peer.mid_for(f.from).map(str::to_string) else {
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
                    RtpWrite::new(
                        PCMU_PT.into(),
                        f.seq_no,
                        f.time,
                        now,
                        Arc::clone(&f.payload),
                    )
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
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        // A rejoin arrives here as leave-then-join from the domain, but
        // the media layer must not depend on that to avoid two sessions
        // for one user.
        inner.remove(uid);

        let session_id = inner.next_session_id;
        inner.next_session_id += 1;
        let candidates = inner.candidates.clone();
        let mut peer = Peer::new(cid, now, &candidates, session_id, 0);
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
        let candidates = inner.candidates.clone();
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
        let sdp = peer.offer(&present, &candidates);
        let peer_cid = peer.cid;
        if full {
            // This session has been in the room long enough to collect
            // MAX_SECTIONS worth of people, and its offer can't grow to
            // fit another. End it: the client reconnects with a clean
            // section list, which is the only way back under the cap.
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
        let now = Instant::now();
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
        if let Err(e) = peer.apply_answer(&answer, now) {
            warn!(uid, cid, "voice answer refused by the stack: {e}");
            return Err(VoiceError::BadAnswer);
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
        let mut inner = self.inner.lock().unwrap();
        if let Some(peer) = inner.peers.get_mut(&uid) {
            if peer.cid == cid {
                // Coming off mute restarts the media clock. Mute
                // suspends the no-media deadline (see `expire`), so
                // without this a peer that spent ten minutes muted would
                // be reaped the instant it unmuted, on the strength of
                // silence it was entitled to.
                if peer.muted && !muted {
                    peer.last_media = Some(Instant::now());
                }
                peer.muted = muted;
            }
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
                    // With a wildcard bind the socket can't tell us which
                    // local address the datagram arrived on, and ICE
                    // matches candidates by it — so report the advertised
                    // address of the right family.
                    let to = local_for(&sfu, local, from);
                    sfu.handle_datagram(from, to, &buf[..n], Instant::now());
                }
                Err(e) => debug!("voice recv failed: {e}"),
            },
            _ = tokio::time::sleep_until(deadline.into()) => {}
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
