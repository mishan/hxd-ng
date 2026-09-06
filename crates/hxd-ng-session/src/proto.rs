//! The Hotline-ng wire shapes: JSON envelopes and the domain-event → event
//! encoding. The normative description is `docs/hotline-ng.md` §5–§7; this
//! module is its executable form.

use hxd_core::video::{
    VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream,
};
use hxd_core::voice::{IceCandidate, VoiceError, VoiceParticipant};
use hxd_core::{Event, SeqEvent, SessionStatus, UserInfo};
use serde::Deserialize;
use serde_json::{json, Value};

/// A client → server request envelope. Unknown fields inside `params` are
/// ignored per spec (forward compatibility).
#[derive(Debug, Deserialize)]
pub struct ReqEnvelope {
    pub id: u64,
    pub req: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Default, Deserialize)]
pub struct LoginParams {
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub password: String,
    pub nick: Option<String>,
    pub icon: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct ResumeParams {
    pub session: String,
    pub token: String,
    #[serde(default)]
    pub last_seq: u64,
}

#[derive(Debug, Deserialize)]
pub struct ChatParams {
    pub text: String,
    #[serde(default)]
    pub style: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NickParams {
    pub nick: Option<String>,
    pub icon: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct MsgParams {
    pub to: u16,
    pub text: String,
}

// --- Voice (docs/voice.md §8) -------------------------------------------
//
// A transliteration of the same six messages the legacy wire carries as
// transactions 600-606. `cid` defaults to 0 because the ng MVP has no
// private chats and its voice is the lobby's; the field is here from the
// start so nothing changes when they land.

#[derive(Debug, Default, Deserialize)]
pub struct VoiceRoomParams {
    #[serde(default)]
    pub cid: u32,
}

#[derive(Debug, Deserialize)]
pub struct VoiceAnswerParams {
    #[serde(default)]
    pub cid: u32,
    pub sdp: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct VoiceIceParams {
    #[serde(default)]
    pub cid: u32,
    /// The `RTCIceCandidateInit` dictionary, or `null` for
    /// end-of-candidates. An object rather than the JSON *string* the
    /// legacy wire carries, because this transport is already JSON and a
    /// browser hands the result straight to `addIceCandidate`.
    #[serde(default)]
    pub candidate: Option<IceJson>,
}

#[derive(Debug, Deserialize)]
pub struct VoiceMuteParams {
    #[serde(default)]
    pub cid: u32,
    pub muted: bool,
}

/// `RTCIceCandidateInit`, spelled the way the WebRTC API spells it.
#[derive(Debug, Default, Deserialize)]
pub struct IceJson {
    /// Required, and deliberately not defaulted. An empty string here is
    /// meaningful — it is end-of-candidates — so letting a missing field
    /// produce one would turn `{"candidate": {}}` into a signal the
    /// client never sent. Absent means malformed, and gets said so.
    pub candidate: String,
    #[serde(default, rename = "sdpMid")]
    pub sdp_mid: Option<String>,
    #[serde(default, rename = "sdpMLineIndex")]
    pub sdp_mline_index: Option<u32>,
    #[serde(default, rename = "usernameFragment")]
    pub username_fragment: Option<String>,
}

impl From<IceJson> for IceCandidate {
    fn from(j: IceJson) -> Self {
        IceCandidate {
            candidate: j.candidate,
            sdp_mid: j.sdp_mid,
            sdp_mline_index: j.sdp_mline_index,
            username_fragment: j.username_fragment,
        }
    }
}

/// A candidate on its way out. End-of-candidates is `null` rather than an
/// object with an empty string: a browser passes `null` to
/// `addIceCandidate` to mean exactly that.
pub fn ice_json(c: &IceCandidate) -> Value {
    if c.is_end_of_candidates() {
        return Value::Null;
    }
    let mut v = json!({ "candidate": c.candidate });
    if let Some(m) = &c.sdp_mid {
        v["sdpMid"] = json!(m);
    }
    if let Some(i) = c.sdp_mline_index {
        v["sdpMLineIndex"] = json!(i);
    }
    if let Some(u) = &c.username_fragment {
        v["usernameFragment"] = json!(u);
    }
    v
}

pub fn participants_json(ps: &[VoiceParticipant]) -> Value {
    Value::Array(
        ps.iter()
            .map(|p| json!({ "uid": p.uid, "muted": p.muted }))
            .collect(),
    )
}

// --- Video (docs/capabilities-video.md §"Hotline-ng Binding") -----------
//
// The same four requests and one event the classic wire carries as
// 607-611, transliterated. `kind` is a string here rather than an
// integer, `paused` a boolean rather than a flags word, and `streams` an
// array of objects rather than a packed blob — for the same reason the
// voice binding sends a participant array: the transport is already JSON
// and a mobile client should not be decoding bit fields.
//
// SDP and ICE are *not* transliterated, because there is nothing to
// transliterate: video renegotiation is `voice_offer` / `voice_answer` /
// `voice_ice` on the same peer connection, unchanged in shape.

#[derive(Debug, Deserialize)]
pub struct VideoStartParams {
    #[serde(default)]
    pub cid: u32,
    pub kind: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct VideoStopParams {
    #[serde(default)]
    pub cid: u32,
    /// Omitted stops every publication this session holds in the room.
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VideoStateParams {
    #[serde(default)]
    pub cid: u32,
    pub kind: String,
    pub paused: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct VideoSubscribeParams {
    #[serde(default)]
    pub cid: u32,
    /// The **complete** desired set; `[]` turns all video off in one
    /// request. For a mobile client this is the whole point of the
    /// binding — the ng protocol exists for clients on cellular
    /// connections, and this is the message that keeps a video room
    /// affordable on one.
    #[serde(default)]
    pub streams: Vec<VideoStreamJson>,
}

#[derive(Debug, Deserialize)]
pub struct VideoStreamJson {
    pub uid: u16,
    pub kind: String,
}

/// Read a subscription array, dropping entries that name a kind this
/// revision doesn't define rather than failing the whole request — a
/// client from a later revision asking for screen audio should lose that
/// one stream, not its subscription set.
pub fn parse_streams(v: &[VideoStreamJson]) -> Vec<VideoStream> {
    v.iter()
        .filter_map(|s| {
            Some(VideoStream {
                uid: s.uid,
                kind: VideoKind::from_name(&s.kind)?,
            })
        })
        .collect()
}

pub fn publishers_json(ps: &[VideoPublication]) -> Value {
    Value::Array(
        ps.iter()
            .map(|p| json!({ "uid": p.uid, "kind": p.kind.name(), "paused": p.paused }))
            .collect(),
    )
}

fn limits_json(l: &VideoLimits) -> Value {
    json!({
        "max_width": l.max_width,
        "max_height": l.max_height,
        "max_fps": l.max_fps,
        "max_bitrate": l.max_bitrate,
        "max_per_room": l.max_per_room,
    })
}

/// The login reply's `video` object: the ceilings, reported once as an
/// object rather than as a repeated field.
pub fn video_limits_json(c: &VideoConfig) -> Value {
    json!({
        "camera": limits_json(&c.camera),
        "screen": limits_json(&c.screen),
    })
}

/// The error code and text for a refused video operation. Codes are the
/// closed set the spec's ng-binding table lists.
pub fn video_err(e: VideoError) -> (&'static str, &'static str) {
    match e {
        VideoError::Disabled => ("video_disabled", "Video is not available on this server."),
        VideoError::NotInVoice => ("not_in_voice", "You are not in that voice chat."),
        VideoError::AlreadyPublishing => ("already_publishing", "You are already publishing that."),
        VideoError::NotPublishing => ("not_publishing", "You are not publishing that."),
        VideoError::Full(VideoKind::Screen) => (
            "video_full",
            "Someone else is already sharing. Ask them to stop first.",
        ),
        VideoError::Full(VideoKind::Camera) => (
            "video_full",
            "This room has as many cameras on as it allows.",
        ),
    }
}

/// The error code and text for a refused voice operation. Codes are the
/// closed set docs/voice.md §8 lists; the text is for a human.
pub fn voice_err(e: VoiceError) -> (&'static str, &'static str) {
    match e {
        VoiceError::Disabled => (
            "voice_disabled",
            "Voice chat is not available on this server.",
        ),
        VoiceError::NoSuchChat => ("no_such_chat", "That chat does not exist."),
        VoiceError::NotAMember => ("not_a_member", "You are not in that chat."),
        VoiceError::RoomFull => ("voice_full", "That voice chat is full."),
        VoiceError::NotInVoice => ("not_in_voice", "You are not in that voice chat."),
        VoiceError::BadAnswer => ("bad_answer", "Your client's voice session was rejected."),
    }
}

pub fn reply_ok(id: u64, ok: Value) -> String {
    json!({ "reply": id, "ok": ok }).to_string()
}

pub fn reply_err(id: u64, code: &str, text: &str) -> String {
    json!({ "reply": id, "error": { "code": code, "text": text } }).to_string()
}

pub fn status_str(s: SessionStatus) -> &'static str {
    match s {
        SessionStatus::Active => "active",
        SessionStatus::Idle => "idle",
        SessionStatus::Detached => "detached",
    }
}

pub fn user_json(u: &UserInfo) -> Value {
    let mut v = json!({
        "uid": u.uid,
        "nick": u.nick,
        "icon": u.icon,
        "admin": u.admin,
        "status": status_str(u.status),
        // `docs/hotline-ng-identity.md` §6.2, §10: what other users may
        // know about this session's link.
        "transport": if u.transport.encrypted { "encrypted" } else { "cleartext" },
    });
    if let Some(id) = &u.transport.identity {
        v["identity"] = json!({
            "fingerprint": hl_identity::Fingerprint(id.fingerprint).to_string(),
            "handle": id.handle,
        });
    }
    v
}

/// Encode one domain event as a wire event frame.
///
/// Events without an ng mapping in the MVP (the private-chat family) are
/// not skipped — skipping would put holes in the seq stream that a client
/// couldn't distinguish from loss. They become a placeholder frame
/// instead, which clients ignore per the unknown-`ev` rule, keeping
/// `last_seq` accounting exact.
pub fn event_json(se: &SeqEvent) -> String {
    let (ev, data) = match &se.event {
        Event::Joined(u) => ("user_joined", json!({ "user": user_json(u) })),
        Event::Changed(u) => ("user_changed", json!({ "user": user_json(u) })),
        Event::Parted(uid) => ("user_parted", json!({ "uid": uid })),
        Event::Chat {
            cid: 0,
            from,
            text,
            style,
        } => (
            "chat",
            json!({
                "from": { "uid": from.uid, "nick": from.nick },
                "text": text,
                "style": if *style == 1 { "action" } else { "normal" },
            }),
        ),
        Event::Notice { cid: 0, text, .. } => ("notice", json!({ "text": text })),
        Event::ChatSubject { cid: 0, subject } => ("subject", json!({ "subject": subject })),
        Event::Msg {
            from,
            from_nick,
            text,
        } => (
            "msg",
            json!({ "from": { "uid": from, "nick": from_nick }, "text": text }),
        ),
        Event::Broadcast {
            from,
            from_nick,
            text,
        } => (
            "broadcast",
            json!({ "from": { "uid": from, "nick": from_nick }, "text": text }),
        ),
        Event::Kicked => ("kicked", json!({})),
        Event::VoiceOffer { cid, sdp } => ("voice_offer", json!({ "cid": cid, "sdp": sdp })),
        Event::VoiceIce { cid, candidate } => (
            "voice_ice",
            json!({ "cid": cid, "candidate": ice_json(candidate) }),
        ),
        Event::VoiceStatus { cid, participants } => (
            "voice_status",
            json!({ "cid": cid, "participants": participants_json(participants) }),
        ),
        // The complete publication list on every emission, exactly as
        // transaction 611 carries it: a client replaces its whole view of
        // the room's video state on each one.
        Event::VideoStatus { cid, publications } => (
            "video_status",
            json!({ "cid": cid, "publishers": publishers_json(publications) }),
        ),
        // No ng mapping yet (private-chat family, and any future event this
        // build predates): emit a placeholder so seq accounting stays
        // gapless. Clients ignore unknown `ev` values per spec.
        _ => ("unsupported", json!({})),
    };
    json!({ "seq": se.seq, "ev": ev, "data": data }).to_string()
}
