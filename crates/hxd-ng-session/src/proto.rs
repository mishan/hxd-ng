//! The Hotline-ng wire shapes: JSON envelopes and the domain-event → event
//! encoding. The normative description is `docs/hotline-ng.md` §5–§7; this
//! module is its executable form.

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
    json!({
        "uid": u.uid,
        "nick": u.nick,
        "icon": u.icon,
        "admin": u.admin,
        "status": status_str(u.status),
    })
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
        // No ng mapping yet (private-chat family, and any future event this
        // build predates): emit a placeholder so seq accounting stays
        // gapless. Clients ignore unknown `ev` values per spec.
        _ => ("unsupported", json!({})),
    };
    json!({ "seq": se.seq, "ev": ev, "data": data }).to_string()
}
