//! The Hotline-ng wire shapes: JSON envelopes and the domain-event → event
//! encoding. The normative description is `docs/hotline-ng.md` §5–§7; this
//! module is its executable form.

use hxd_core::media::MediaRef;
use hxd_core::video::{
    VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream,
};
use hxd_core::voice::{IceCandidate, VoiceError, VoiceParticipant};
use hxd_core::{Event, LineFlags, LogLine, SeqEvent, SessionStatus, UserInfo};
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
    /// A handle from `POST /media`, which must be this session's own
    /// upload and still live. The text may be empty when one is
    /// present: the image is the message.
    #[serde(default)]
    pub media: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NickParams {
    pub nick: Option<String>,
    pub icon: Option<u16>,
}

/// A private message names its recipient one of two ways: `to` is a uid
/// on the roster, `to_login` an account whether or not it holds a session.
/// Exactly one, and the frontend refuses both or neither rather than
/// picking — a client that sent both meant something, and guessing which
/// is how a message reaches the wrong person.
#[derive(Debug, Deserialize)]
pub struct MsgParams {
    #[serde(default)]
    pub to: Option<u16>,
    #[serde(default)]
    pub to_login: Option<String>,
    pub text: String,
    /// The client's own id for this message. Sending it again with the
    /// same guid is the same message — stored once — which is what makes
    /// a retry safe after a socket died between the send and the reply.
    /// The answer is as of now, not as of the first send: a recipient
    /// who has arrived in the meantime gets it, and the retry says
    /// `queued: false` where the original said `true`.
    #[serde(default)]
    pub guid: Option<String>,
    /// The same handle rule as `chat`: this session's own upload, still
    /// live. A retry with the same guid is the same message, image and
    /// all.
    #[serde(default)]
    pub media: Option<String>,
}

/// Both fields are optional, so `inbox` with no `params` at all is a
/// valid request for the first page — `from_value::<InboxParams>(Null)`
/// is not, which is why the handler treats a null as `{}`.
#[derive(Debug, Default, Deserialize)]
pub struct InboxParams {
    /// Page backwards from this id, exclusive.
    #[serde(default)]
    pub before: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HistoryParams {
    #[serde(default)]
    pub before: Option<u64>,
    #[serde(default)]
    pub after: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub struct FilesPathParams {
    /// Slash-separated UTF-8 path relative to the configured Files root.
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct FilesDownloadParams {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct MsgReadParams {
    pub up_to: u64,
}

/// Who to block. A login names an account; a uid names whoever is on the
/// roster under it, which is the only way to name an identity user
/// admitted as a guest — they have a fingerprint to hold a block against
/// but no account login of their own.
///
/// `unblock` may instead take a `fingerprint`, which `blocks` reports: once
/// that guest has left, the roster cannot answer for their uid and their
/// login is `guest`, so the fingerprint is the only name left.
#[derive(Debug, Deserialize)]
pub struct BlockParams {
    #[serde(default)]
    pub login: Option<String>,
    #[serde(default)]
    pub uid: Option<u16>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// One entry of the `blocks` list.
pub fn blocked_json(m: &hxd_core::inbox::Mailbox) -> serde_json::Value {
    let mut v = json!({ "login": m.login });
    if let Some(fp) = m.fingerprint {
        v["fingerprint"] = json!(hl_identity::Fingerprint(fp).to_string());
    }
    v
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
        // `docs/hotline-ng-auth.md` §7.2, §8: what other users may
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
            id,
            at,
            media,
        } => {
            let mut data = json!({
                "from": { "uid": from.uid, "nick": from.nick },
                "text": text,
                "style": if *style == 1 { "action" } else { "normal" },
                "at": unix(*at),
            });
            if let Some(id) = id {
                data["id"] = json!(id);
            }
            if let Some(media) = media {
                data["media"] = crate::media::media_json(media);
            }
            ("chat", data)
        }
        Event::Notice { cid: 0, text, .. } => ("notice", json!({ "text": text })),
        Event::ChatSubject { cid: 0, subject } => ("subject", json!({ "subject": subject })),
        Event::Msg {
            from,
            from_nick,
            from_login,
            text,
            id,
            sent_at,
            queued,
            media,
        } => {
            // `uid` is 0 when a queued message's sender has no session
            // now; `login` is the account that survives either way, and
            // is *absent* when there is nobody to reply to — a guest, or
            // a sender whose account has since gone. Absent rather than
            // null, so a client can test for the key; likewise `id`,
            // which only exists for a message the store holds.
            let mut from_obj = json!({ "uid": from, "nick": from_nick });
            if let Some(login) = from_login {
                from_obj["login"] = json!(login);
            }
            let mut data = json!({
                "from": from_obj,
                "text": text,
                "at": unix(*sent_at),
                "queued": queued,
            });
            if let Some(id) = id {
                data["id"] = json!(id);
            }
            // Present without an `id` for a message whose handle died
            // while it waited: the placeholder is still worth rendering
            // (`docs/inline-media.md` §9).
            if let Some(media) = media {
                data["media"] = crate::media::media_json(media);
            }
            ("msg", data)
        }
        Event::Broadcast {
            from,
            from_nick,
            text,
        } => (
            "broadcast",
            json!({ "from": { "uid": from, "nick": from_nick }, "text": text }),
        ),
        Event::Kicked => ("kicked", json!({})),
        // A client drops the image and keeps the placeholder the line or
        // message already carries (moderation.md §5).
        Event::MediaRevoked { id } => (
            "media_revoked",
            json!({ "id": hxd_core::media::handle_str(id) }),
        ),
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
        // "Your copy is stale", to everyone who may read news
        // (`docs/news.md` §9.3). A header, so a client showing that
        // category can splice one row in rather than refetch.
        Event::NewsPosted {
            id,
            category,
            root,
            parent,
            subject,
            from_nick,
            at,
        } => (
            "news_posted",
            json!({
                "id": id,
                "category": category,
                "root": root,
                "parent": parent,
                "subject": subject,
                "from": { "nick": from_nick },
                "at": unix(*at),
                "attachments": 0,
            }),
        ),
        Event::NewsDeleted { id, category } => {
            ("news_deleted", json!({ "id": id, "category": category }))
        }
        Event::NewsNode(node) => ("news_node", json!({ "node": crate::news::node_json(node) })),
        Event::NewsNodeDeleted { id } => ("news_node_deleted", json!({ "id": id })),
        // Addressed to one account, where the four above go to every
        // reader: the one a client raises a badge on (§10.6).
        Event::NewsNotify(n) => ("news_notify", crate::news::notified_json(n)),
        // No ng mapping yet (private-chat family, and any future event this
        // build predates): emit a placeholder so seq accounting stays
        // gapless. Clients ignore unknown `ev` values per spec.
        _ => ("unsupported", json!({})),
    };
    json!({ "seq": se.seq, "ev": ev, "data": data }).to_string()
}

/// Unix seconds, the shape every JSON timestamp here takes. Floored at the
/// epoch: a clock set before 1970 should not produce a negative timestamp
/// for a client to puzzle over.
pub fn unix(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A durable history row. Deliberately no uid: it may have been recycled
/// since the line was written.
/// One logged line, as `history` pages it.
///
/// `fetchable` is what the media store says *now*: a line keeps the
/// metadata of the image it carried forever, and the handle only while
/// the bytes are still there. A client renders the placeholder either
/// way and fetches only when there is something to fetch
/// (`docs/inline-media.md` §5.4, §9).
pub fn history_line_json(line: &LogLine, fetchable: bool) -> Value {
    let deleted = line.flags.contains(LineFlags::DELETED);
    let mut value = json!({
        "id": line.id,
        "at": unix(line.at),
        "from": if deleted {
            json!({ "icon": line.icon })
        } else {
            json!({ "nick": line.from_nick, "icon": line.icon })
        },
        "text": if deleted { "" } else { &line.text },
        "style": if line.flags.contains(LineFlags::ACTION) { "action" } else { "normal" },
    });
    if deleted {
        value["deleted"] = json!(true);
    }
    if let Some(media) = &line.media {
        value["media"] = if deleted {
            json!({
                "type": media.mime,
                "width": media.width,
                "height": media.height,
                "bytes": media.bytes,
                "removed": true,
            })
        } else {
            let mut m = json!({
                "type": media.mime,
                "width": media.width,
                "height": media.height,
                "bytes": media.bytes,
            });
            // Absent rather than null when the bytes have gone — expired,
            // evicted, revoked — so a client can test for the key. The
            // metadata stands on its own: "[an image was here]" is worth
            // rendering and an empty line is not.
            if fetchable {
                m["id"] = json!(media_handle(&media.id));
            }
            m
        };
    }
    value
}

fn media_handle(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// One stored message, as `inbox` lists it.
///
/// No uid: a message in the list was sent by a session that may be long
/// gone, and a uid from then may belong to someone else now. A client that
/// wants to reply names `from.login`.
pub fn stored_msg_json(m: &hxd_core::StoredMessage, media: Option<&MediaRef>) -> serde_json::Value {
    let mut from = json!({ "nick": m.sender_nick });
    if let Some(login) = m.sender.as_ref().map(|s| &s.login) {
        from["login"] = json!(login);
    }
    let mut value = json!({
        "id": m.id,
        "from": from,
        "text": m.body,
        "at": unix(m.sent_at),
        "read": m.read_at.is_some(),
    });
    // The same shape the `msg` event carries, resolved the same way: the
    // handle while there is one, the metadata either way.
    if let Some(media) = media {
        value["media"] = crate::media::media_json(media);
    }
    value
}
