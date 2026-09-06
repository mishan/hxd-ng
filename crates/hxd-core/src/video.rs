//! Video publications: who is showing a camera or a screen in a voice
//! room, who has asked to see it, and the slot accounting that bounds
//! both.
//!
//! Video is **layered on** voice, not parallel to it — one peer
//! connection, one SFU, one room. So there is no video room state here:
//! everything in this module hangs off the voice room in [`crate::voice`]
//! and dies with it. `docs/capabilities-video.md` is the spec; §"Room
//! Model" is the sentence this module exists to make true — "video rooms
//! are voice rooms".
//!
//! **Publish and subscribe are deliberately asymmetric.** A publication
//! is a room-wide fact: slot-bounded, announced to everyone through
//! [`Event::VideoStatus`], and visible to a voice-only participant who
//! can't render a pixel of it. A subscription is private between one
//! participant and the server: unannounced, unbounded, and never
//! disclosed to the publisher. What bounds it is the receiver's own
//! downlink, which is the resource that actually runs out first.
//!
//! **Nothing is delivered unasked.** A participant receives no video
//! until it names the streams it wants, which is what keeps a video-less
//! client — and a client that simply hasn't subscribed yet — on exactly
//! the same code path: a peer whose subscription set is empty. There is
//! no "is this client video-capable" branch in the forwarding path, and
//! that absence is the compatibility guarantee.

use crate::roster::{Event, RosterInner, Uid};
use crate::voice::VoiceError;
use crate::Core;

/// What a publication carries. The wire numbers are the spec's; `0` is
/// deliberately not a kind, so a zeroed field is caught rather than read
/// as a camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoKind {
    Camera,
    Screen,
}

impl VideoKind {
    /// Every kind this revision defines, in wire order. Iterating this
    /// rather than writing the two out by hand is what keeps "stop all of
    /// my publications" honest when kind 3 (screen audio) lands.
    pub const ALL: [VideoKind; 2] = [VideoKind::Camera, VideoKind::Screen];

    /// The `DATA_VIDEO_KIND` value.
    pub const fn wire(self) -> u16 {
        match self {
            VideoKind::Camera => 1,
            VideoKind::Screen => 2,
        }
    }

    /// A kind from the wire. `0` and everything reserved read as `None`,
    /// which the frontends turn into a refusal rather than a guess.
    pub const fn from_wire(v: u16) -> Option<VideoKind> {
        match v {
            1 => Some(VideoKind::Camera),
            2 => Some(VideoKind::Screen),
            _ => None,
        }
    }

    /// The ng wire's spelling — a string there rather than an integer,
    /// because that transport is already JSON. Named to pair with
    /// [`VideoKind::from_name`] rather than shadowing `FromStr`, which
    /// wants a `Result` this has no error to fill.
    pub const fn name(self) -> &'static str {
        match self {
            VideoKind::Camera => "camera",
            VideoKind::Screen => "screen",
        }
    }

    pub fn from_name(s: &str) -> Option<VideoKind> {
        match s {
            "camera" => Some(VideoKind::Camera),
            "screen" => Some(VideoKind::Screen),
            _ => None,
        }
    }
}

/// One publication, as a video status reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoPublication {
    pub uid: Uid,
    pub kind: VideoKind,
    pub paused: bool,
}

/// One entry in a client's desired receive set: whose, and of what kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VideoStream {
    pub uid: Uid,
    pub kind: VideoKind,
}

/// The server's ceiling for one stream kind, as `DATA_VIDEO_LIMITS`
/// reports it at login. Ceilings are configuration, not negotiation: the
/// server advertises them, reflects them in `b=AS`, and does not trust
/// clients to comply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoLimits {
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub max_bitrate: u32,
    /// Publication slots for this kind, per room.
    pub max_per_room: u16,
}

impl VideoLimits {
    /// The spec's camera defaults.
    pub const CAMERA: VideoLimits = VideoLimits {
        max_width: 1280,
        max_height: 720,
        max_fps: 30,
        max_bitrate: 1_500_000,
        max_per_room: 8,
    };

    /// The spec's screen-share defaults — lower frame rate, higher
    /// resolution and bitrate, and one slot a room.
    pub const SCREEN: VideoLimits = VideoLimits {
        max_width: 1920,
        max_height: 1080,
        max_fps: 15,
        max_bitrate: 2_500_000,
        max_per_room: 1,
    };

    /// The `b=AS` value for a section of this kind, in kilobits per
    /// second as SDP counts them.
    pub fn bandwidth_kbps(&self) -> u32 {
        self.max_bitrate / 1000
    }
}

/// Per-kind ceilings for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoConfig {
    pub camera: VideoLimits,
    pub screen: VideoLimits,
}

impl Default for VideoConfig {
    fn default() -> Self {
        VideoConfig {
            camera: VideoLimits::CAMERA,
            screen: VideoLimits::SCREEN,
        }
    }
}

impl VideoConfig {
    pub fn limits(&self, kind: VideoKind) -> VideoLimits {
        match kind {
            VideoKind::Camera => self.camera,
            VideoKind::Screen => self.screen,
        }
    }
}

/// Why a video operation was refused.
///
/// The privilege refusals (`accessVideoChat`, `accessScreenShare`) are
/// **not** here, for the same reason `accessVoiceChat` isn't in
/// [`VoiceError`]: the access bitmap is wire vocabulary and the wording of
/// a refusal belongs with the frontend that speaks it. The structural
/// rules are the domain's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoError {
    /// No SFU, or video is off in this server's configuration.
    Disabled,
    /// The user isn't in voice in that room. Video has no meaning
    /// outside the voice session that carries it.
    NotInVoice,
    /// A publication of that kind already exists for this user. One
    /// camera and one screen per participant is the whole model.
    AlreadyPublishing,
    /// No publication of that kind to pause, resume or describe.
    NotPublishing,
    /// The room's slots for that kind are taken. With the default
    /// `VideoMaxScreensPerRoom` of 1 this is what a second sharer gets,
    /// and the existing share is never preempted.
    Full,
}

impl From<VoiceError> for VideoError {
    /// The voice preconditions a video operation inherits. A room the
    /// user was never in and a room they simply aren't in voice in are
    /// the same refusal from here: the video transaction names a room by
    /// chat id, and "you are not in voice there" is the honest answer to
    /// all of it.
    fn from(e: VoiceError) -> VideoError {
        match e {
            VoiceError::Disabled => VideoError::Disabled,
            _ => VideoError::NotInVoice,
        }
    }
}

/// One participant's video state inside its voice room. Lives on the
/// voice [`crate::voice::Peer`], so every path that ends a voice session
/// ends the publications with it and there is no fifth cleanup path to
/// forget.
#[derive(Debug, Default)]
pub(crate) struct PeerVideo {
    /// This peer's publications and their paused flags. At most one per
    /// kind; a paused publication is still a publication and still holds
    /// its slot.
    pub(crate) publications: Vec<(VideoKind, bool)>,
    /// The client's **complete** desired receive set, exactly as it last
    /// declared it — including streams that do not exist. Retaining those
    /// is what lets a client say "show me everyone" once and have new
    /// publications light up without polling or racing the room.
    pub(crate) wanted: Vec<VideoStream>,
    /// The subset of `wanted` that names a live publication: what the
    /// media layer has actually been told to forward, and what the
    /// peer's offer describes.
    pub(crate) active: Vec<VideoStream>,
}

impl PeerVideo {
    fn publication(&self, kind: VideoKind) -> Option<bool> {
        self.publications
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, paused)| *paused)
    }

    fn publishes(&self, kind: VideoKind) -> bool {
        self.publication(kind).is_some()
    }
}

impl RosterInner {
    /// The room's publications, in participant order — the complete list
    /// every [`Event::VideoStatus`] carries, never a delta.
    pub(crate) fn video_publications(&self, cid: u32) -> Vec<VideoPublication> {
        self.voice
            .rooms
            .get(&cid)
            .map(|peers| {
                peers
                    .iter()
                    .flat_map(|p| {
                        p.video
                            .publications
                            .iter()
                            .map(move |(kind, paused)| VideoPublication {
                                uid: p.uid,
                                kind: *kind,
                                paused: *paused,
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many publications of `kind` the room holds. Paused ones count
    /// — that is what makes pause cheap and stop meaningful.
    fn video_slots_used(&self, cid: u32, kind: VideoKind) -> usize {
        self.voice.rooms.get(&cid).map_or(0, |peers| {
            peers.iter().filter(|p| p.video.publishes(kind)).count()
        })
    }

    /// Announce the room's whole publication list to everyone in it.
    ///
    /// Everyone, not just the video-capable: a voice-only participant is
    /// entitled to know a camera is on in the room it is sitting in, and
    /// the frontends drop the event for a session that didn't negotiate
    /// the capability. Deciding that here would put wire vocabulary in
    /// the domain.
    pub(crate) fn video_status(&mut self, cid: u32) {
        if !self.voice.video_enabled {
            return;
        }
        let publications = self.video_publications(cid);
        let uids: Vec<Uid> = self
            .voice
            .rooms
            .get(&cid)
            .map(|peers| peers.iter().map(|p| p.uid).collect())
            .unwrap_or_default();
        for uid in uids {
            self.send_to(
                uid,
                Event::VideoStatus {
                    cid,
                    publications: publications.clone(),
                },
            );
        }
    }

    /// Recompute every peer's active receive set against the room's
    /// current publications, telling the media layer about each change.
    ///
    /// This is the "retain a subscription to a publication that does not
    /// exist yet" rule, discharged in one place: the domain is what
    /// learns that a publication appeared or vanished, so the domain is
    /// what re-derives who should now be receiving what. Returns the
    /// peers whose set changed — those, and only those, need a fresh
    /// offer.
    pub(crate) fn video_resync(&mut self, cid: u32) -> Vec<Uid> {
        if !self.voice.video_enabled {
            return Vec::new();
        }
        let live = self.video_publications(cid);
        let mut changed = Vec::new();
        let mut updates: Vec<(Uid, Vec<VideoStream>)> = Vec::new();
        if let Some(peers) = self.voice.rooms.get_mut(&cid) {
            for p in peers.iter_mut() {
                let active: Vec<VideoStream> = p
                    .video
                    .wanted
                    .iter()
                    .copied()
                    .filter(|s| live.iter().any(|l| l.uid == s.uid && l.kind == s.kind))
                    .collect();
                if active != p.video.active {
                    p.video.active = active.clone();
                    changed.push(p.uid);
                    updates.push((p.uid, active));
                }
            }
        }
        if let Some(media) = self.voice.media.clone() {
            for (uid, active) in updates {
                media.set_subscriptions(uid, cid, &active);
            }
        }
        changed
    }
}

impl Core {
    /// Turn video on for a core that already has an SFU wired in.
    ///
    /// Video without voice is meaningless and the capability bit that
    /// advertises it depends on voice's, so this is a no-op on a core
    /// with no media layer rather than a state that could contradict it.
    #[must_use]
    pub fn with_video(self, config: VideoConfig) -> Self {
        {
            let mut r = self.roster.lock().unwrap();
            if r.voice.media.is_some() {
                r.voice.video_enabled = true;
                r.voice.video = config;
            }
        }
        self
    }

    /// Is video available? What the binary asks before advertising
    /// `CAPABILITY_VIDEO` — the bit is a promise that a start will work.
    pub fn video_enabled(&self) -> bool {
        let r = self.roster.lock().unwrap();
        r.voice.media.is_some() && r.voice.video_enabled
    }

    /// The configured ceilings, for the login reply's limits.
    pub fn video_config(&self) -> VideoConfig {
        self.roster.lock().unwrap().voice.video
    }

    /// The room's video codec name, for a start reply and a status.
    pub fn video_codec(&self) -> &'static str {
        self.roster
            .lock()
            .unwrap()
            .voice
            .media
            .as_ref()
            .map_or("VP8", |m| m.video_codec())
    }

    /// The room's publications, for a frontend building a status of its
    /// own (a join reply's follow-up, a re-sync).
    pub fn video_publications(&self, cid: u32) -> Vec<VideoPublication> {
        self.roster.lock().unwrap().video_publications(cid)
    }

    /// Begin publishing a stream of `kind` in `cid`.
    ///
    /// **The reply carries no offer**, and that is deliberate rather than
    /// an omission: a renegotiation may already be outstanding toward
    /// this peer and the voice extension forbids a second offer before
    /// the first is answered. The publisher's offer goes out through the
    /// ordinary renegotiation path — immediately if it is free, with the
    /// next consolidated one if it is not.
    ///
    /// Starting a publication renegotiates the **publisher**, to add its
    /// own send section, and notifies everyone else. Other peers
    /// renegotiate only if they had a standing subscription that this
    /// publication just satisfied.
    pub fn video_start(
        &self,
        uid: Uid,
        cid: u32,
        kind: VideoKind,
    ) -> Result<&'static str, VideoError> {
        let mut r = self.roster.lock().unwrap();
        let media = r.video_media()?;
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VideoError::NotInVoice);
        }
        let already = r
            .voice
            .peer_mut(cid, uid)
            .is_some_and(|p| p.video.publishes(kind));
        if already {
            return Err(VideoError::AlreadyPublishing);
        }
        // Slots are room-wide and counted across every participant, so a
        // screen share occupies the room's screen slot whether one
        // person is watching it or none.
        if r.video_slots_used(cid, kind) >= r.voice.video.limits(kind).max_per_room as usize {
            return Err(VideoError::Full);
        }

        if let Some(p) = r.voice.peer_mut(cid, uid) {
            p.video.publications.push((kind, false));
        }
        media.publish(uid, cid, kind);

        // The publisher, for its own send section; then anyone whose
        // standing subscription this publication just activated.
        let mut targets = vec![uid];
        targets.extend(r.video_resync(cid).into_iter().filter(|u| *u != uid));
        r.voice_renegotiate_peers(cid, &targets);
        r.video_status(cid);
        Ok(media.video_codec())
    }

    /// End a publication and release its slot. `kind` of `None` stops
    /// every publication this user holds in the room.
    ///
    /// Stopping something that isn't running is **not** an error. Leaving
    /// voice, being kicked and disconnecting all end publications on
    /// their own, and a client's stop routinely races one of them; making
    /// the loser of that race an error would mean every client had to
    /// tell a real failure from a lost race.
    pub fn video_stop(
        &self,
        uid: Uid,
        cid: u32,
        kind: Option<VideoKind>,
    ) -> Result<(), VideoError> {
        let mut r = self.roster.lock().unwrap();
        let media = r.video_media()?;
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VideoError::NotInVoice);
        }
        let mut stopped = Vec::new();
        if let Some(p) = r.voice.peer_mut(cid, uid) {
            p.video.publications.retain(|(k, _)| match kind {
                Some(want) if *k != want => true,
                _ => {
                    stopped.push(*k);
                    false
                }
            });
        }
        if stopped.is_empty() {
            return Ok(());
        }
        for k in stopped {
            media.unpublish(uid, cid, k);
        }

        // The publisher loses a send section; every subscriber to the
        // stopped publication loses a receive section, which goes
        // `a=inactive` and keeps its mid for a later resubscribe.
        let mut targets = vec![uid];
        targets.extend(r.video_resync(cid).into_iter().filter(|u| *u != uid));
        r.voice_renegotiate_peers(cid, &targets);
        r.video_status(cid);
        Ok(())
    }

    /// Pause or resume a publication.
    ///
    /// **Pause is to video what mute is to audio**, and costs the same:
    /// nothing. The section stays, the mid stays, the slot stays, and the
    /// server simply stops forwarding the RTP — server-enforced, so a
    /// client that keeps sending is discarded rather than trusted. No
    /// renegotiation, because a camera toggle is a casual and frequent
    /// act and a room of eight that renegotiated on each one would spend
    /// its life in offer/answer.
    pub fn video_state(
        &self,
        uid: Uid,
        cid: u32,
        kind: VideoKind,
        paused: bool,
    ) -> Result<(), VideoError> {
        let mut r = self.roster.lock().unwrap();
        let media = r.video_media()?;
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VideoError::NotInVoice);
        }
        let Some(was) = r
            .voice
            .peer_mut(cid, uid)
            .and_then(|p| p.video.publication(kind))
        else {
            return Err(VideoError::NotPublishing);
        };
        if was == paused {
            // A toggle that changes nothing is acked and nothing else —
            // the cheap half of the debounce the spec asks for, and a
            // client mashing a camera button produces plenty of these.
            return Ok(());
        }
        if let Some(p) = r.voice.peer_mut(cid, uid) {
            for (k, flag) in p.video.publications.iter_mut() {
                if *k == kind {
                    *flag = paused;
                }
            }
        }
        // The media layer requests a keyframe of its own on resume: a
        // decoder cannot start mid-stream, so a resumed publication is
        // invisible until the next one.
        media.set_paused(uid, cid, kind, paused);
        r.video_status(cid);
        Ok(())
    }

    /// Declare the complete set of streams this client wishes to receive
    /// in `cid`. **This is the only way video is ever delivered.**
    ///
    /// The set is absolute, not a delta, which makes it idempotent and —
    /// more to the point — lets a client opening a room with four cameras
    /// pay for one renegotiation instead of four serialised behind one
    /// another. Nobody is told: who is watching whom is not published, to
    /// the publisher or to anyone else.
    pub fn video_subscribe(
        &self,
        uid: Uid,
        cid: u32,
        streams: &[VideoStream],
    ) -> Result<(), VideoError> {
        let mut r = self.roster.lock().unwrap();
        r.video_media()?;
        if r.voice.room_of.get(&uid) != Some(&cid) {
            return Err(VideoError::NotInVoice);
        }
        let mut wanted: Vec<VideoStream> = Vec::with_capacity(streams.len());
        for s in streams {
            // A peer never receives its own publication back. The SFU
            // offers no loopback section for it — the same rule that
            // keeps a participant's own audio out of its offer — and a
            // client renders its camera from the local capture, which
            // costs nothing and has no round trip in it.
            if s.uid == uid || wanted.contains(s) {
                continue;
            }
            wanted.push(*s);
        }
        let changed = match r.voice.peer_mut(cid, uid) {
            Some(p) if p.video.wanted != wanted => {
                p.video.wanted = wanted;
                true
            }
            _ => false,
        };
        if changed {
            let dirty = r.video_resync(cid);
            r.voice_renegotiate_peers(cid, &dirty);
        }
        Ok(())
    }
}

impl RosterInner {
    /// The media layer, or the reason there isn't one to talk to.
    fn video_media(&self) -> Result<std::sync::Arc<dyn crate::voice::VoiceMedia>, VideoError> {
        if !self.voice.video_enabled {
            return Err(VideoError::Disabled);
        }
        self.voice.media.clone().ok_or(VideoError::Disabled)
    }
}

#[cfg(test)]
mod tests;
