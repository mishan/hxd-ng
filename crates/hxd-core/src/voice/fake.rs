//! A [`VoiceMedia`] that records what it was asked to do.
//!
//! The domain's voice tests are call-trace tests: they replay the spec's
//! own sequence diagrams ("B joins with A present", "B leaves") and
//! assert the exact series of media calls and outbox events. That needs
//! a media layer that is honest about being asked and produces
//! distinguishable SDP, and nothing else — no WebRTC anywhere near the
//! test.
//!
//! It is public rather than `#[cfg(test)]` because the end-to-end suites
//! in `crates/hxd/tests` want the same thing: a real server, real
//! frontends, real transactions on the wire, and a media plane that
//! doesn't need a UDP socket or a codec to answer.

use std::sync::Mutex;

use super::{IceCandidate, VoiceError, VoiceMedia};
use crate::roster::Uid;
use crate::video::{VideoKind, VideoStream};

/// One call the domain made into the media layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaCall {
    Join {
        uid: Uid,
        cid: u32,
    },
    Leave {
        uid: Uid,
        cid: u32,
    },
    Offer {
        uid: Uid,
        cid: u32,
    },
    Answer {
        uid: Uid,
        cid: u32,
        sdp: String,
    },
    Ice {
        uid: Uid,
        cid: u32,
        candidate: IceCandidate,
    },
    SetMuted {
        uid: Uid,
        cid: u32,
        muted: bool,
    },
    Publish {
        uid: Uid,
        cid: u32,
        kind: VideoKind,
    },
    Unpublish {
        uid: Uid,
        cid: u32,
        kind: VideoKind,
    },
    SetPaused {
        uid: Uid,
        cid: u32,
        kind: VideoKind,
        paused: bool,
    },
    /// The peer's whole receive set, as the domain computed it — already
    /// filtered to publications that exist, which is the half of the
    /// subscription rule these tests care about.
    SetSubscriptions {
        uid: Uid,
        cid: u32,
        streams: Vec<VideoStream>,
    },
}

struct Inner {
    calls: Vec<MediaCall>,
    /// Bumped per offer so two offers to the same peer never compare
    /// equal — "did this peer get a *fresh* offer" is the question most
    /// of these tests ask.
    generation: u64,
    /// Reject the next answer, standing in for a client that offers no
    /// PCMU.
    reject_next_answer: bool,
    /// Answer the next offer with `None`, standing in for a session the
    /// media layer has torn down.
    no_next_offer: bool,
    /// What a rejected answer is rejected with.
    answer_error: VoiceError,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            calls: Vec::new(),
            generation: 0,
            reject_next_answer: false,
            no_next_offer: false,
            answer_error: VoiceError::BadAnswer,
        }
    }
}

/// A recording, inert media layer.
#[derive(Default)]
pub struct RecordingMedia {
    inner: Mutex<Inner>,
}

impl RecordingMedia {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything asked of it so far.
    pub fn calls(&self) -> Vec<MediaCall> {
        self.inner.lock().unwrap().calls.clone()
    }

    /// Everything asked of it since the last take.
    pub fn take_calls(&self) -> Vec<MediaCall> {
        std::mem::take(&mut self.inner.lock().unwrap().calls)
    }

    /// Make the next answer fail, as an answer without PCMU would.
    pub fn reject_next_answer(&self) {
        self.inner.lock().unwrap().reject_next_answer = true;
    }

    /// Make the next answer fail with `err` rather than
    /// [`VoiceError::BadAnswer`] — for asserting that the domain hands a
    /// media-layer reason back unflattened.
    pub fn reject_next_answer_with(&self, err: VoiceError) {
        let mut inner = self.inner.lock().unwrap();
        inner.reject_next_answer = true;
        inner.answer_error = err;
    }

    /// Make the next offer come back as `None`: the sentinel for a peer
    /// whose media session is gone.
    pub fn no_next_offer(&self) {
        self.inner.lock().unwrap().no_next_offer = true;
    }
}

impl VoiceMedia for RecordingMedia {
    fn codec(&self) -> &'static str {
        "PCMU"
    }

    fn join(&self, uid: Uid, cid: u32) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::Join { uid, cid });
    }

    fn leave(&self, uid: Uid, cid: u32) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::Leave { uid, cid });
    }

    fn offer(&self, uid: Uid, cid: u32) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(MediaCall::Offer { uid, cid });
        if std::mem::take(&mut inner.no_next_offer) {
            return None;
        }
        inner.generation += 1;
        Some(format!(
            "sdp-offer to={uid} cid={cid} gen={}",
            inner.generation
        ))
    }

    fn answer(&self, uid: Uid, cid: u32, sdp: &str) -> Result<(), VoiceError> {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(MediaCall::Answer {
            uid,
            cid,
            sdp: sdp.to_string(),
        });
        if std::mem::take(&mut inner.reject_next_answer) {
            return Err(inner.answer_error);
        }
        Ok(())
    }

    fn remote_ice(&self, uid: Uid, cid: u32, candidate: &IceCandidate) {
        self.inner.lock().unwrap().calls.push(MediaCall::Ice {
            uid,
            cid,
            candidate: candidate.clone(),
        });
    }

    fn set_muted(&self, uid: Uid, cid: u32, muted: bool) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::SetMuted { uid, cid, muted });
    }

    fn video_codec(&self) -> &'static str {
        "VP8"
    }

    fn publish(&self, uid: Uid, cid: u32, kind: VideoKind) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::Publish { uid, cid, kind });
    }

    fn unpublish(&self, uid: Uid, cid: u32, kind: VideoKind) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::Unpublish { uid, cid, kind });
    }

    fn set_paused(&self, uid: Uid, cid: u32, kind: VideoKind, paused: bool) {
        self.inner.lock().unwrap().calls.push(MediaCall::SetPaused {
            uid,
            cid,
            kind,
            paused,
        });
    }

    fn set_subscriptions(&self, uid: Uid, cid: u32, streams: &[VideoStream]) {
        self.inner
            .lock()
            .unwrap()
            .calls
            .push(MediaCall::SetSubscriptions {
                uid,
                cid,
                streams: streams.to_vec(),
            });
    }
}
