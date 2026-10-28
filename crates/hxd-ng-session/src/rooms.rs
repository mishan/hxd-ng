//! Rooms on the ng wire (`docs/chat-rooms.md` §7): the family's
//! requests, its login and sync blocks, and the room object.
//!
//! A translation, as accounts' is: who may see, join and send where is
//! `hxd_core::rooms`'s, and so is which sessions hear of a room at all.

use hxd_core::rooms::TOPIC_MAX;
use hxd_core::{Core, RoomEdit, RoomError, RoomView, Uid};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::conn::{off_reactor, SessState};
use crate::proto::{reply_err, reply_ok, unix, ReqEnvelope, RoomTopicParams};
use crate::NgCtx;

pub(crate) fn handles(req: &str) -> bool {
    matches!(
        req,
        "rooms"
            | "room_join"
            | "room_part"
            | "room_topic"
            | "room_create"
            | "room_edit"
            | "room_archive"
            | "room_unarchive"
    )
}

/// Does this request make its session rooms-aware (§7)? One of the
/// family, or one that names a room other than the lobby: the lobby's
/// subject is not, so a client written before rooms that sets it still
/// sees today's protocol.
pub(crate) fn makes_aware(req: &ReqEnvelope) -> bool {
    (handles(&req.req) && req.req != "room_topic")
        || req
            .params
            .get("room")
            .and_then(Value::as_u64)
            .is_some_and(|room| room != 0)
}

/// A room as one session is shown it: its gates only to a manager.
pub fn room_json(v: &RoomView) -> Value {
    let r = &v.room;
    let mut out = json!({
        "id": r.id,
        "name": r.name,
        "topic": r.topic.text,
        "position": r.position,
        "members": v.members,
        "may_post": v.may_post,
    });
    if r.signed {
        out["signed"] = json!(true);
    }
    if let Some(id) = v.last_id {
        out["last_id"] = json!(id);
    }
    if let Some(n) = r.max_lines {
        out["max_lines"] = json!(n);
    }
    if let Some(n) = r.max_days {
        out["max_days"] = json!(n);
    }
    if v.manages {
        out["read"] = json!(r.read);
        out["post"] = json!(r.post);
        if r.archived_at.is_some() {
            out["archived"] = json!(true);
        }
    }
    out
}

fn list_json(core: &Core, uid: Uid) -> Vec<Value> {
    core.room_list(uid).iter().map(room_json).collect()
}

/// The login reply's `rooms` (§7.1), where the server has rooms.
pub(crate) fn login_json(core: &Core, uid: Uid) -> Option<Value> {
    let policy = core.room_policy()?;
    let mut lobby = json!({ "id": 0, "name": policy.lobby });
    if let Some(id) = core.last_line_id(0) {
        lobby["last_id"] = json!(id);
    }
    Some(json!({
        "lobby": lobby,
        "list": list_json(core, uid),
        "max_joined": policy.max_joined,
    }))
}

/// The sync reply's `rooms` (§7.4): the listing, and the rooms this
/// session is in with the newest line in each, to catch up from.
pub(crate) fn sync_json(core: &Core, uid: Uid) -> Option<Value> {
    let policy = core.room_policy()?;
    let joined: Vec<Value> = core
        .rooms_of(uid)
        .into_iter()
        .map(|id| {
            let mut room = json!({ "id": id });
            if let Some(last) = core.last_line_id(id) {
                room["last_id"] = json!(last);
            }
            room
        })
        .collect();
    Some(json!({
        "list": list_json(core, uid),
        "joined": joined,
        "max_joined": policy.max_joined,
    }))
}

pub(crate) fn room_err(id: u64, e: RoomError) -> String {
    let (code, text) = match e {
        RoomError::NoSuchRoom => ("no_such_room", "No such room."),
        RoomError::NotAMember => ("not_a_member", "You are not in that room."),
        RoomError::TooManyRooms => ("too_many_rooms", "You are in as many rooms as you may be."),
        RoomError::RoomsFull => ("rooms_full", "This server has as many rooms as it may."),
        RoomError::NameTaken => ("name_taken", "A room has that name already."),
        RoomError::NoSuchRole => ("no_such_role", "A gate names a role there is none of."),
        RoomError::Invalid(why) => ("bad_request", why),
        RoomError::AccessDenied => ("access_denied", "You are not allowed to do that."),
        RoomError::Disabled => ("not_available", "This server has no rooms."),
        RoomError::ServerError => ("server_error", "Server error."),
    };
    reply_err(id, code, text)
}

#[derive(Deserialize, Default)]
struct RoomParams {
    #[serde(default)]
    room: u32,
}

/// `null` clears a retention, a number sets it, and absent leaves it.
fn set_or_clear<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<u32>>, D::Error> {
    Option::<u32>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct EditParams {
    #[serde(default)]
    room: u32,
    name: Option<String>,
    topic: Option<String>,
    position: Option<i64>,
    read: Option<Vec<String>>,
    post: Option<Vec<String>>,
    #[serde(default, deserialize_with = "set_or_clear")]
    max_lines: Option<Option<u32>>,
    #[serde(default, deserialize_with = "set_or_clear")]
    max_days: Option<Option<u32>>,
    signed: Option<bool>,
}

impl EditParams {
    fn edit(self) -> RoomEdit {
        RoomEdit {
            name: self.name,
            topic: self.topic,
            position: self.position,
            read: self.read,
            post: self.post,
            max_lines: self.max_lines,
            max_days: self.max_days,
            signed: self.signed,
        }
    }
}

/// Answer one request of the family.
pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let (id, uid) = (req.id, state.uid);
    let bad = |text: &str| reply_err(id, "bad_request", text);
    // The lobby's subject is there whether or not rooms are.
    if req.req == "room_topic" {
        let Ok(p) = serde_json::from_value::<RoomTopicParams>(req.params.clone()) else {
            return bad("Malformed room_topic.");
        };
        let topic: String = p.topic.chars().take(TOPIC_MAX).collect();
        if p.room != 0 {
            return match ctx.core.room_topic(uid, p.room, topic) {
                Ok(()) => reply_ok(id, json!({})),
                Err(e) => room_err(id, e),
            };
        }
        // Refused rather than dropped as the classic wire does: that wire
        // has no reply to say it in.
        if !state.set_subject {
            return reply_err(
                id,
                "access_denied",
                "You are not allowed to set the subject.",
            );
        }
        // The lobby's subject is the roster's; setting it cannot fail.
        let _ = ctx.core.chat_subject(0, uid, topic);
        return reply_ok(id, json!({}));
    }
    if !ctx.core.rooms_enabled() {
        return reply_err(id, "not_available", "This server has no rooms.");
    }
    match req.req.as_str() {
        "rooms" => reply_ok(id, json!({ "list": list_json(&ctx.core, uid) })),
        "room_join" | "room_part" | "room_archive" | "room_unarchive" => {
            let Ok(p) = crate::conn::params_or_default::<RoomParams>(&req.params) else {
                return bad("Malformed room request.");
            };
            // The lobby is everyone's, always: nobody joins, leaves or
            // archives it.
            if p.room == 0 {
                return bad("The lobby is not joined, left or archived.");
            }
            let done = match req.req.as_str() {
                "room_join" => return join(ctx, id, uid, p.room),
                "room_part" => ctx.core.room_part(uid, p.room),
                verb => {
                    let archive = verb == "room_archive";
                    match off_reactor(&ctx.core, move |c| c.room_archive(uid, p.room, archive))
                        .await
                    {
                        Some(done) => done.map(|_| ()),
                        None => Err(RoomError::ServerError),
                    }
                }
            };
            match done {
                Ok(()) => reply_ok(id, json!({})),
                Err(e) => room_err(id, e),
            }
        }
        _ => {
            let Ok(p) = serde_json::from_value::<EditParams>(req.params.clone()) else {
                return bad("Malformed room request.");
            };
            let create = req.req == "room_create";
            if !create && p.room == 0 {
                return bad("The lobby is not edited here.");
            }
            let room = p.room;
            let edit = p.edit();
            let done = off_reactor(&ctx.core, move |c| {
                let made = if create {
                    c.room_create(uid, edit)
                } else {
                    c.room_edit(uid, room, edit)
                };
                made.map(|made| c.room_view(uid, made.id))
            })
            .await;
            match done {
                Some(Ok(Some(view))) => reply_ok(id, json!({ "room": room_json(&view) })),
                Some(Err(e)) => room_err(id, e),
                Some(Ok(None)) | None => room_err(id, RoomError::ServerError),
            }
        }
    }
}

/// `room_join`: who is in it, its topic, where its log is up to, and
/// whether this session may talk there.
fn join(ctx: &NgCtx, id: u64, uid: Uid, room: u32) -> String {
    let (members, topic) = match ctx.core.room_join(uid, room) {
        Ok(joined) => joined,
        Err(e) => return room_err(id, e),
    };
    let view = ctx.core.room_view(uid, room);
    let members: Vec<Uid> = members.iter().map(|u| u.uid).collect();
    let mut ok = json!({
        "members": members,
        "topic": topic.text,
        "may_post": view.as_ref().is_some_and(|v| v.may_post),
    });
    if !topic.by.is_empty() {
        ok["topic_by"] = json!(topic.by);
    }
    if let Some(at) = topic.at {
        ok["topic_at"] = json!(unix(at));
    }
    // So a client knows before it sends (`docs/e2e-messages.md` §4.8).
    if view.as_ref().is_some_and(|v| v.room.signed) {
        ok["signed"] = json!(true);
    }
    if let Some(last) = view.and_then(|v| v.last_id) {
        ok["last_id"] = json!(last);
    }
    reply_ok(id, ok)
}
