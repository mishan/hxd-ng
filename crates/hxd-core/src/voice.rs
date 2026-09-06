//! Voice rooms: who is in voice where, and the choreography the fogWraith
//! voice extension asks of a server.
//!
//! The media plane is somebody else's problem — SDP, ICE, DTLS, RTP and
//! sockets all live behind the [`VoiceMedia`] trait, implemented by the
//! `hxd-voice` SFU. What lives here is everything that is really
//! chat-room-shaped: which users are in voice in which `cid`, their mute
//! flags, the one-room-at-a-time rule, the per-room cap, the membership
//! check that stops a voice-capable client naming a room it was never
//! invited to, the per-peer offer/answer serialisation, and cleanup on
//! every path by which a user can stop being present.
//!
//! **Why the domain owns the room.** Voice membership has chat-membership
//! lifecycle: part, kick, disconnect, last-one-out. Every one of those
//! transitions already lives in this crate, so putting voice state here
//! means the cross-frontend guarantee is the domain's, cleanup cannot be
//! remembered in one frontend and forgotten in the other, and the whole
//! policy surface is testable against a fake media layer with no WebRTC
//! in the test at all. See `docs/voice.md` §3.
//!
//! **SDP is opaque here.** [`Event::VoiceOffer`] carries a `String` the
//! domain never parses, exactly as a chat line is a `String` it never
//! formats. This is the one media-plane artefact that transits the
//! domain, and it does so as a payload, not as a type.
//!
//! **Locking.** Every [`VoiceMedia`] call is made while the roster lock is
//! held. That is safe only because the media layer is sans-I/O: each call
//! is an in-memory state change, never a socket operation, never an
//! await, and never a call back into [`Core`]. Media-originated events
//! come back the other way through [`Core::voice_media_event`], from the
//! SFU's own task.

pub mod fake;

use std::collections::HashMap;
use std::sync::Arc;

use crate::roster::{Event, RosterInner, Uid};
use crate::video::{VideoKind, VideoStream};
use crate::Core;

/// The spec's `VoiceMaxPerRoom` default.
pub const DEFAULT_MAX_PER_ROOM: usize = 16;

/// One voice participant, as a room status reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceParticipant {
    pub uid: Uid,
    pub muted: bool,
}

/// An ICE candidate crossing the signalling channel, in either direction.
///
/// The four fields mirror the WebRTC API's `RTCIceCandidateInit`, which
/// is what the spec puts on the wire: the legacy frontend carries it as
/// the JSON string the spec mandates, the ng frontend as a JSON object,
/// and a browser hands the result straight to `addIceCandidate`. Neither
/// encoding is a domain type; this is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IceCandidate {
    /// The RFC 8839 candidate-attribute line. **Empty is the
    /// end-of-candidates signal**, not a malformed candidate.
    pub candidate: String,
    /// The `a=mid` of the section this candidate belongs to.
    pub sdp_mid: Option<String>,
    /// Zero-based `m=` line index; a fallback for peers that can't match
    /// on the mid.
    pub sdp_mline_index: Option<u32>,
    pub username_fragment: Option<String>,
}

impl IceCandidate {
    /// The end-of-candidates marker for a section.
    pub fn end_of_candidates(mid: &str) -> Self {
        IceCandidate {
            candidate: String::new(),
            sdp_mid: Some(mid.to_string()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        }
    }

    /// Is this the end-of-candidates marker? The empty candidate string
    /// is the authoritative signal; the other fields don't matter.
    pub fn is_end_of_candidates(&self) -> bool {
        self.candidate.is_empty()
    }
}

/// What a successful [`Core::voice_join`] hands the frontend for its
/// reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceJoin {
    /// The server's initial SDP offer for this peer. The server is always
    /// the offerer; the client only ever answers.
    pub sdp: String,
    /// The room's codec, for the reply's codec field.
    pub codec: &'static str,
    /// The room's participants **as they were before this join** — what
    /// the spec's join-reply example carries, with the joiner itself
    /// arriving in the room status that follows.
    pub participants: Vec<VoiceParticipant>,
}

/// Why a voice operation was refused. Frontends map these to their own
/// wording, as they do for [`crate::ChatError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceError {
    /// No SFU is wired into this server.
    Disabled,
    /// No such private chat.
    NoSuchChat,
    /// Not a member of that chat — or not on the roster at all. A voice
    /// room is addressed by a bare chat id, so this check, not the
    /// access bit, is what stops a client joining a room it was never
    /// invited to.
    NotAMember,
    /// The room is at `VoiceMaxPerRoom` — or the media layer could not
    /// seat this peer and said so by returning no offer
    /// ([`VoiceMedia::offer`]). Both are "the room cannot take you right
    /// now, try again later", which is what a client does with this.
    RoomFull,
    /// The user isn't in voice in that room.
    NotInVoice,
    /// The client's SDP answer was rejected (no PCMU, unparseable). The
    /// peer connection is torn down with it, as the spec requires.
    BadAnswer,
}

/// The media plane, behind one trait so the domain can be tested without
/// WebRTC and the SFU can be replaced without touching policy.
///
/// Every method is called with the roster lock held, so an implementation
/// must be sans-I/O: in-memory state changes only, no blocking, no
/// awaiting, and above all no calls back into [`Core`] (those come back
/// asynchronously as a [`MediaEvent`] instead).
///
/// The implementation tracks its own room membership from `join`/`leave`
/// — it needs one anyway to know where to forward RTP — which is what
/// lets [`VoiceMedia::offer`] answer "the current offer for this peer"
/// on demand rather than diffing.
pub trait VoiceMedia: Send + Sync + 'static {
    /// The codec name for the join reply. One room, one codec, forever
    /// `PCMU` unless the spec grows another.
    fn codec(&self) -> &'static str;

    /// Create this peer's media session in `cid`.
    fn join(&self, uid: Uid, cid: u32);

    /// Tear this peer's media session down. Idempotent — cleanup paths
    /// overlap on purpose.
    fn leave(&self, uid: Uid, cid: u32);

    /// The offer describing the room as it stands right now, from this
    /// peer's point of view: one section per other participant plus the
    /// peer's own microphone. A template over state the media layer
    /// already holds, so for a peer that has a session it cannot fail.
    ///
    /// `None` is the one other answer, and it means exactly one thing:
    /// **this peer has no media session any more.** It was torn down
    /// inside this call, or it was already gone and the domain hasn't
    /// been told yet; either way a [`MediaEvent::Failed`] for it is on
    /// its way. The domain never sends a `None` on to a client — a
    /// renegotiation skips the peer and lets the failure arrive, and a
    /// join that gets one is a join that did not happen
    /// ([`VoiceError::RoomFull`]). An implementation that still holds a
    /// session for `uid` in `cid` must return `Some`.
    fn offer(&self, uid: Uid, cid: u32) -> Option<String>;

    /// Apply the peer's answer. `Err(VoiceError::BadAnswer)` means the
    /// answer is unusable (no PCMU, unparseable); the caller tears the
    /// peer down, per the spec.
    fn answer(&self, uid: Uid, cid: u32, sdp: &str) -> Result<(), VoiceError>;

    /// A candidate trickled in from the peer, or its end-of-candidates.
    fn remote_ice(&self, uid: Uid, cid: u32, candidate: &IceCandidate);

    /// Mute is enforced here: a muted peer's RTP is dropped rather than
    /// forwarded, whatever the client chooses to keep sending.
    fn set_muted(&self, uid: Uid, cid: u32, muted: bool);

    // --- Video (see [`crate::video`]) ---------------------------------
    //
    // Video is layered on this same peer connection: no new session, no
    // new port, no new SDP transaction. These five methods are the whole
    // of what the media layer has to be told about it — the rooms, the
    // slots and the subscription bookkeeping are the domain's, and
    // [`VoiceMedia::offer`] answers for video sections the same way it
    // already does for audio ones, from state the media layer holds.

    /// The room's video codec name, for a start reply and a status.
    /// One room, one codec, forever `VP8` unless the spec grows another
    /// — an SFU does not transcode.
    fn video_codec(&self) -> &'static str;

    /// Add a send section of `kind` for this peer, so its next offer
    /// carries somewhere to publish on.
    fn publish(&self, uid: Uid, cid: u32, kind: VideoKind);

    /// Drop a publication. The section survives as `a=inactive` — mids
    /// are never reassigned and `m=` lines are never deleted — but
    /// nothing is forwarded on it and any receiver's copy goes inactive
    /// too.
    fn unpublish(&self, uid: Uid, cid: u32, kind: VideoKind);

    /// Pause or resume forwarding of a publication. Enforced by
    /// discarding the publisher's inbound RTP, exactly as mute is, and
    /// **not** by trusting the client to stop sending. On resume the
    /// implementation must ask the publisher for a keyframe: a decoder
    /// cannot start mid-stream, so a resumed stream is a black tile
    /// until the next one arrives.
    fn set_paused(&self, uid: Uid, cid: u32, kind: VideoKind, paused: bool);

    /// This peer's complete set of receive streams, already filtered by
    /// the domain to publications that exist. Absolute, not a delta: a
    /// stream that has dropped out of the set has its section set
    /// inactive and stops being forwarded. Newly added streams get a
    /// keyframe request, for the same reason resume does.
    fn set_subscriptions(&self, uid: Uid, cid: u32, streams: &[VideoStream]);
}

/// Something the media plane noticed, on its way back into the domain.
/// Delivered by the SFU's own task through [`Core::voice_media_event`],
/// never by a call from inside a [`VoiceMedia`] method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEvent {
    /// A server-side ICE candidate to trickle to the peer. With ICE-lite
    /// the server's candidates ride in the offer itself, so in practice
    /// this is the end-of-candidates that follows it; the path exists
    /// for symmetry with clients, which really do trickle.
    Ice {
        uid: Uid,
        cid: u32,
        candidate: IceCandidate,
    },
    /// The peer's media session failed one of the spec's timeouts (no
    /// answer, ICE, DTLS, or no RTP). It is a leave, with the room
    /// status that any leave produces; the user's control connection is
    /// untouched.
    Failed { uid: Uid, cid: u32 },
    /// One publication's media stopped arriving while the peer's session
    /// stayed alive. The publication is dropped and its slot released;
    /// the call is not touched. **Losing video is a degradation; losing
    /// the call is a failure**, and the spec is explicit that a failed
    /// publication must never tear down the voice session.
    VideoFailed { uid: Uid, cid: u32, kind: VideoKind },
}

/// A peer's voice state within its room.
pub(crate) struct Peer {
    pub(crate) uid: Uid,
    muted: bool,
    /// An offer has been sent and not yet answered. **No second offer
    /// may go out while this is set** — most WebRTC stacks treat
    /// overlapping offers as undefined behaviour.
    offer_outstanding: bool,
    /// The room changed while an offer was outstanding. The answer
    /// releases one consolidated follow-up offer covering everything
    /// that accumulated.
    dirty: bool,
    /// What this peer is publishing and what it has asked to see. Video
    /// hangs off the voice peer rather than beside it, so the four
    /// cleanup paths that end a voice session end the publications too
    /// without any of them being told about video. See [`crate::video`].
    pub(crate) video: crate::video::PeerVideo,
}

impl Peer {
    fn new(uid: Uid) -> Self {
        // Joins land unmuted: the spec asks *clients* to join muted, and
        // a client that wants that sends its own mute the moment it has
        // a session. A server that mutes on its owner's behalf makes a
        // silent room the normal case and every silence ambiguous.
        Peer {
            uid,
            muted: false,
            offer_outstanding: false,
            dirty: false,
            video: crate::video::PeerVideo::default(),
        }
    }
}

/// The domain's whole voice state, living inside the roster so that every
/// path which removes a user can reach it.
pub(crate) struct VoiceState {
    pub(crate) media: Option<Arc<dyn VoiceMedia>>,
    max_per_room: usize,
    pub(crate) rooms: HashMap<u32, Vec<Peer>>,
    /// The one-room-at-a-time index: a user is in at most one room, and
    /// this is where.
    pub(crate) room_of: HashMap<Uid, u32>,
    /// Video is off unless an operator turns it on, and can only be on
    /// where voice is: the capability bit for it depends on voice's.
    pub(crate) video_enabled: bool,
    pub(crate) video: crate::video::VideoConfig,
}

impl Default for VoiceState {
    fn default() -> Self {
        VoiceState {
            media: None,
            max_per_room: DEFAULT_MAX_PER_ROOM,
            rooms: HashMap::new(),
            room_of: HashMap::new(),
            video_enabled: false,
            video: crate::video::VideoConfig::default(),
        }
    }
}

impl VoiceState {
    pub(crate) fn peer_mut(&mut self, cid: u32, uid: Uid) -> Option<&mut Peer> {
        self.rooms.get_mut(&cid)?.iter_mut().find(|p| p.uid == uid)
    }

    fn participants(&self, cid: u32) -> Vec<VoiceParticipant> {
        self.rooms
            .get(&cid)
            .map(|peers| {
                peers
                    .iter()
                    .map(|p| VoiceParticipant {
                        uid: p.uid,
                        muted: p.muted,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl RosterInner {
    fn voice_media(&self) -> Option<Arc<dyn VoiceMedia>> {
        self.voice.media.clone()
    }

    /// Remove `uid` from whatever voice room it is in, renegotiating and
    /// re-announcing that room. A no-op when the user isn't in voice, so
    /// every cleanup path can call it unconditionally.
    pub(crate) fn voice_part(&mut self, uid: Uid) {
        let Some(cid) = self.voice.room_of.remove(&uid) else {
            return;
        };
        if let Some(media) = self.voice_media() {
            media.leave(uid, cid);
        }
        let Some(peers) = self.voice.rooms.get_mut(&cid) else {
            return;
        };
        peers.retain(|p| p.uid != uid);
        if peers.is_empty() {
            // Last one out: the room's state goes with them, publications
            // and subscriptions included.
            self.voice.rooms.remove(&cid);
        } else {
            // The leaver's publications went with it. Anyone subscribed
            // to one loses it here — before the offers are built, so the
            // sections they describe match what the media layer will
            // actually forward. `voice_renegotiate` then covers everyone,
            // so the peers `video_resync` names need no second offer.
            self.video_resync(cid);
            self.voice_renegotiate(cid, Some(uid));
        }
        // The room hears about it, and so does the user who left.
        //
        // That last part is not redundant. An explicit leave has the 601
        // reply for an ack, but a media timeout, a kick from the chat and
        // a lost connection have no reply at all, and without this the
        // client's voice UI would sit there live with nothing behind it.
        // It is also what makes `docs/voice.md` §8's promise true — that
        // a resuming ng session finds the status saying it is out of
        // voice waiting in its replay tail.
        let participants = self.voice.participants(cid);
        self.send_to(
            uid,
            Event::VoiceStatus {
                cid,
                participants: participants.clone(),
            },
        );
        self.voice_status(cid);
        // The same courtesy for video: the leaver's own publications are
        // gone, and the room needs to stop drawing their tile.
        self.send_to(
            uid,
            Event::VideoStatus {
                cid,
                publications: Vec::new(),
            },
        );
        self.video_status(cid);
    }

    /// The same, but only if the user's voice room is `cid` — for a chat
    /// part or a kick, which end voice in *that* room and leave any
    /// other alone.
    pub(crate) fn voice_part_room(&mut self, uid: Uid, cid: u32) {
        if self.voice.room_of.get(&uid) == Some(&cid) {
            self.voice_part(uid);
        }
    }

    /// Send every peer in the room (except `except`) a fresh offer, or
    /// mark it dirty if it still owes us an answer. This is the spec's
    /// per-peer serialisation, and it is short because the media layer
    /// produces the current offer on demand instead of diffing.
    fn voice_renegotiate(&mut self, cid: u32, except: Option<Uid>) {
        let Some(media) = self.voice_media() else {
            return;
        };
        let mut offers: Vec<(Uid, String)> = Vec::new();
        if let Some(peers) = self.voice.rooms.get_mut(&cid) {
            for p in peers.iter_mut().filter(|p| Some(p.uid) != except) {
                if p.offer_outstanding {
                    p.dirty = true;
                    continue;
                }
                // No offer means this peer no longer has a media session
                // and its `Failed` is already on its way (see
                // `VoiceMedia::offer`). Skip it and let the failure
                // arrive: it is about to be parted from the room anyway,
                // and marking an offer outstanding would only leave a
                // dead peer looking like it owes us an answer.
                let Some(sdp) = media.offer(p.uid, cid) else {
                    continue;
                };
                p.offer_outstanding = true;
                offers.push((p.uid, sdp));
            }
        }
        for (uid, sdp) in offers {
            self.send_to(uid, Event::VoiceOffer { cid, sdp });
        }
    }

    /// Send fresh offers to exactly these peers, obeying the same
    /// serialisation rule.
    ///
    /// Video needs this where voice never did. A voice change is a room
    /// change and every peer's offer moves with it; a video change moves
    /// the publisher's offer and the offers of whoever subscribed, and
    /// nobody else's. Renegotiating the room for one camera would be the
    /// fifteen-peer storm the opt-in receive model exists to avoid.
    pub(crate) fn voice_renegotiate_peers(&mut self, cid: u32, uids: &[Uid]) {
        let Some(media) = self.voice_media() else {
            return;
        };
        let mut offers: Vec<(Uid, String)> = Vec::new();
        if let Some(peers) = self.voice.rooms.get_mut(&cid) {
            for p in peers.iter_mut().filter(|p| uids.contains(&p.uid)) {
                if p.offer_outstanding {
                    p.dirty = true;
                    continue;
                }
                // See `voice_renegotiate`: no offer is a peer the media
                // layer has already torn down.
                let Some(sdp) = media.offer(p.uid, cid) else {
                    continue;
                };
                p.offer_outstanding = true;
                offers.push((p.uid, sdp));
            }
        }
        for (uid, sdp) in offers {
            self.send_to(uid, Event::VoiceOffer { cid, sdp });
        }
    }

    /// Announce the room's participant list to everyone in it.
    fn voice_status(&mut self, cid: u32) {
        let participants = self.voice.participants(cid);
        for p in participants.clone() {
            self.send_to(
                p.uid,
                Event::VoiceStatus {
                    cid,
                    participants: participants.clone(),
                },
            );
        }
    }
}

impl Core {
    /// Wire an SFU into a core that isn't shared yet, with the room cap
    /// the operator configured. Without this, voice is disabled and
    /// every voice call answers [`VoiceError::Disabled`].
    #[must_use]
    pub fn with_voice(self, media: Arc<dyn VoiceMedia>, max_per_room: usize) -> Self {
        {
            let mut r = self.roster.lock().unwrap();
            r.voice.media = Some(media);
            r.voice.max_per_room = max_per_room.max(1);
        }
        self
    }

    /// Is an SFU wired in? What the binary asks before advertising the
    /// voice capability — the bit is a promise that a join will work.
    pub fn voice_enabled(&self) -> bool {
        self.roster.lock().unwrap().voice.media.is_some()
    }

    /// Join voice in `cid`, leaving any room already joined.
    ///
    /// The order is the spec's: check that this user may be in this room
    /// at all, complete the teardown of any current room (including its
    /// status notification) before the new join starts, then check the
    /// cap. A failed join therefore leaves the user in *no* room — the
    /// spec forbids silently putting them back.
    ///
    /// The privilege check (access bit 55) is the frontend's, per the
    /// house rule that policy wording belongs with the wire. The
    /// structural rules are here.
    pub fn voice_join(&self, uid: Uid, cid: u32) -> Result<VoiceJoin, VoiceError> {
        let mut r = self.roster.lock().unwrap();
        let Some(media) = r.voice_media() else {
            return Err(VoiceError::Disabled);
        };
        if !r.users.contains_key(&uid) {
            return Err(VoiceError::NotAMember);
        }
        // Room membership, which the access bit does not cover: the
        // public chat is open to anyone, a private chat's voice room
        // only to that chat's current members.
        if cid != 0 {
            let chat = r.chats.get(&cid).ok_or(VoiceError::NoSuchChat)?;
            if !chat.members.contains(&uid) {
                return Err(VoiceError::NotAMember);
            }
        }

        r.voice_part(uid);

        let occupancy = r.voice.rooms.get(&cid).map_or(0, |p| p.len());
        if occupancy >= r.voice.max_per_room {
            return Err(VoiceError::RoomFull);
        }

        // The reply's list is the room as the joiner found it; the
        // joiner appears in the status that goes out below.
        let participants = r.voice.participants(cid);

        media.join(uid, cid);
        r.voice.rooms.entry(cid).or_default().push(Peer::new(uid));
        r.voice.room_of.insert(uid, cid);
        let Some(sdp) = media.offer(uid, cid) else {
            // The media layer took the join and then had no offer to
            // give, so this peer has no session (see `VoiceMedia::offer`)
            // and never will. Unwind the domain-side join by hand rather
            // than through `voice_part`: nobody has been told this user
            // is here yet, so there is nothing to re-announce and no
            // room to renegotiate — and the peers already in the room
            // must not be handed an offer describing a joiner that isn't
            // going to exist.
            media.leave(uid, cid);
            r.voice.room_of.remove(&uid);
            if let Some(peers) = r.voice.rooms.get_mut(&cid) {
                peers.retain(|p| p.uid != uid);
                if peers.is_empty() {
                    r.voice.rooms.remove(&cid);
                }
            }
            return Err(VoiceError::RoomFull);
        };
        if let Some(p) = r.voice.peer_mut(cid, uid) {
            p.offer_outstanding = true;
        }

        r.voice_renegotiate(cid, Some(uid));
        r.voice_status(cid);
        // Video state arrives as its own notification rather than as
        // extra fields on the join reply, so voice's reply shape is
        // untouched and a voice-only client sees exactly what it always
        // saw. A joiner with no publications still needs this: it is how
        // it learns what everyone else is already showing.
        r.video_status(cid);

        Ok(VoiceJoin {
            sdp,
            codec: media.codec(),
            participants,
        })
    }

    /// Leave voice in `cid`.
    pub fn voice_leave(&self, uid: Uid, cid: u32) -> Result<(), VoiceError> {
        let mut r = self.roster.lock().unwrap();
        if r.voice.media.is_none() {
            return Err(VoiceError::Disabled);
        }
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VoiceError::NotInVoice);
        }
        r.voice_part(uid);
        Ok(())
    }

    /// Apply a client's SDP answer.
    ///
    /// A rejected answer tears the peer down rather than leaving a
    /// half-negotiated session on the books, which is what the spec asks
    /// for and what keeps a client that can't do PCMU from occupying a
    /// slot. A successful one clears the outstanding offer and, if the
    /// room changed while it was in flight, immediately sends the one
    /// consolidated offer covering all of it.
    pub fn voice_answer(&self, uid: Uid, cid: u32, sdp: String) -> Result<(), VoiceError> {
        let mut r = self.roster.lock().unwrap();
        let Some(media) = r.voice_media() else {
            return Err(VoiceError::Disabled);
        };
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VoiceError::NotInVoice);
        }
        // Whatever the media layer refused this answer for, the peer goes
        // with it — a half-negotiated session is the thing we are here to
        // avoid. Its reason travels back to the client unchanged rather
        // than being flattened to `BadAnswer`: today that is `BadAnswer`
        // or a `NotInVoice` from a session that died under us, and a
        // reason this layer grows tomorrow should not arrive as a lie
        // about the client's SDP.
        if let Err(e) = media.answer(uid, cid, &sdp) {
            r.voice_part(uid);
            return Err(e);
        }
        let follow_up = match r.voice.peer_mut(cid, uid) {
            Some(p) => {
                p.offer_outstanding = false;
                let dirty = std::mem::take(&mut p.dirty);
                if dirty {
                    p.offer_outstanding = true;
                }
                dirty
            }
            None => false,
        };
        if follow_up {
            match media.offer(uid, cid) {
                Some(sdp) => r.send_to(uid, Event::VoiceOffer { cid, sdp }),
                // See `voice_renegotiate`: a peer with no session left,
                // whose failure we haven't been handed yet. Clear the
                // outstanding flag we just set on its behalf.
                None => {
                    if let Some(p) = r.voice.peer_mut(cid, uid) {
                        p.offer_outstanding = false;
                    }
                }
            }
        }
        Ok(())
    }

    /// A trickled ICE candidate from a client.
    ///
    /// A candidate for a room the user isn't in is dropped, and the
    /// refusal is returned rather than swallowed. On the legacy wire
    /// this is a notification with no reply to carry it, and that
    /// frontend discards it; the ng wire answers every request, and its
    /// spec (`docs/voice.md` §8) lists `not_in_voice` here exactly as it
    /// does for the calls either side of it. A check that lives in one
    /// place and is *reported* where a reply exists beats each frontend
    /// deciding for itself.
    pub fn voice_ice(&self, uid: Uid, cid: u32, candidate: IceCandidate) -> Result<(), VoiceError> {
        let r = self.roster.lock().unwrap();
        let Some(media) = r.voice_media() else {
            return Err(VoiceError::Disabled);
        };
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VoiceError::NotInVoice);
        }
        media.remote_ice(uid, cid, &candidate);
        Ok(())
    }

    /// Set a participant's mute flag. Server-enforced: the media layer
    /// drops a muted peer's RTP regardless of what the client sends.
    pub fn voice_mute(&self, uid: Uid, cid: u32, muted: bool) -> Result<(), VoiceError> {
        let mut r = self.roster.lock().unwrap();
        let Some(media) = r.voice_media() else {
            return Err(VoiceError::Disabled);
        };
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VoiceError::NotInVoice);
        }
        let changed = match r.voice.peer_mut(cid, uid) {
            Some(p) if p.muted != muted => {
                p.muted = muted;
                true
            }
            _ => false,
        };
        if changed {
            media.set_muted(uid, cid, muted);
            r.voice_status(cid);
        }
        // A toggle that changes nothing is acked and nothing else: the
        // cheap half of the mute-flap debounce the spec recommends, and
        // push-to-talk produces plenty of these.
        Ok(())
    }

    /// The room's participants, for a status the frontend needs to build
    /// on its own (a join reply, a re-sync).
    pub fn voice_participants(&self, cid: u32) -> Vec<VoiceParticipant> {
        self.roster.lock().unwrap().voice.participants(cid)
    }

    /// Which voice room this user is in, if any.
    pub fn voice_room_of(&self, uid: Uid) -> Option<u32> {
        self.roster.lock().unwrap().voice.room_of.get(&uid).copied()
    }

    /// Something the media plane noticed, on its way back in.
    pub fn voice_media_event(&self, ev: MediaEvent) {
        let mut r = self.roster.lock().unwrap();
        match ev {
            MediaEvent::Ice {
                uid,
                cid,
                candidate,
            } => {
                if r.voice.room_of.get(&uid) == Some(&cid) {
                    r.send_to(uid, Event::VoiceIce { cid, candidate });
                }
            }
            MediaEvent::Failed { uid, cid } => {
                if r.voice.room_of.get(&uid) == Some(&cid) {
                    r.voice_part(uid);
                }
            }
            MediaEvent::VideoFailed { uid, cid, kind } => {
                if r.voice.room_of.get(&uid) != Some(&cid) {
                    return;
                }
                let mut stopped = false;
                if let Some(p) = r.voice.peer_mut(cid, uid) {
                    let before = p.video.publications.len();
                    p.video.publications.retain(|(k, _)| *k != kind);
                    stopped = p.video.publications.len() != before;
                }
                if !stopped {
                    return;
                }
                // The media layer has already dropped it on its side; the
                // domain releases the slot, tells the subscribers, and
                // leaves the audio alone.
                let mut targets = vec![uid];
                targets.extend(r.video_resync(cid).into_iter().filter(|u| *u != uid));
                r.voice_renegotiate_peers(cid, &targets);
                r.video_status(cid);
            }
        }
    }
}

#[cfg(test)]
mod tests;
