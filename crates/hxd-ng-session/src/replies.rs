//! The `replies` capability (`docs/hotline-ng.md` §7.3): `re` on `chat`
//! and `msg`, as this wire spells a [`Reply`], and the kinds this server
//! keeps.

use hl_identity::Fingerprint;
use hxd_core::inbox::MessageGuid;
use hxd_core::reply::{guid_bytes, guid_of};
use hxd_core::Reply;
use serde_json::{json, Value};

use crate::identity::unb64;
use crate::proto::b64url;
use crate::NgCtx;

/// The kinds of target this server keeps, as the login reply lists them:
/// a line where lines are kept, a message where messages are, and a
/// signed line or message where signatures are carried.
pub(crate) fn targets(ctx: &NgCtx) -> Vec<&'static str> {
    let core = &ctx.core;
    [
        ("line", core.history_policy().is_some()),
        ("pm", core.inbox_enabled()),
        ("im", core.messaging_enabled()),
        ("signed", crate::signed::offered(ctx)),
    ]
    .into_iter()
    .filter_map(|(kind, kept)| kept.then_some(kind))
    .collect()
}

fn kind(re: &Reply) -> &'static str {
    match re {
        Reply::Line { .. } => "line",
        Reply::Pm(_) => "pm",
        Reply::Im { .. } => "im",
        Reply::Signed { .. } => "signed",
    }
}

/// `re` as a client sent it, or `None` for anything malformed, of more
/// than one kind, or of a kind `targets` does not list.
pub(crate) fn parse(v: &Value, targets: &[&str]) -> Option<Reply> {
    let o = v.as_object()?;
    let re = match (o.get("line"), o.get("pm"), o.get("im"), o.get("signed")) {
        (Some(id), None, None, None) => {
            let room = match o.get("room") {
                None => 0,
                Some(r) => u32::try_from(r.as_u64()?).ok()?,
            };
            (o.len() == 1 + usize::from(o.contains_key("room"))).then_some(())?;
            Reply::Line {
                room,
                id: id.as_u64()?,
            }
        }
        _ if o.len() != 1 => return None,
        (None, Some(r), None, None) => Reply::Pm(hxd_core::media::handle_from_str(r.as_str()?)?),
        (None, None, Some(im), None) if im.as_object()?.len() == 2 => Reply::im(
            im.get("login")?.as_str()?.to_owned(),
            MessageGuid::parse(im.get("guid")?.as_str()?)?,
        )?,
        (None, None, None, Some(s)) if s.as_object()?.len() == 3 => Reply::Signed {
            signer: Fingerprint::parse(s.get("signer")?.as_str()?)?.0,
            id: guid_bytes(&MessageGuid::parse(s.get("id")?.as_str()?)?),
            hash: unb64(s.get("hash")?.as_str()?)?.try_into().ok()?,
        },
        _ => return None,
    };
    targets.contains(&kind(&re)).then_some(re)
}

/// A request's `re`, from a session that declared `replies`; any other's
/// is ignored, as a param the server does not know is (§5). The `text`
/// of a refusal on `Err`.
/// `takes` is the kinds the request may name: a line on `chat`, a
/// message on `msg`, and a signed target on either.
pub(crate) fn param(
    ctx: &NgCtx,
    declared: bool,
    re: Option<&Value>,
    signed: bool,
    takes: &[&str],
) -> Result<Option<Reply>, &'static str> {
    let Some(re) = re.filter(|_| declared) else {
        return Ok(None);
    };
    // A signed reply's `re` belongs inside its signed object, so the
    // signature binds it (e2e-messages.md §3), and that object has no key
    // for one yet: beside it, `re` would bind nothing.
    if signed {
        return Err("A signed line or message cannot carry `re` yet.");
    }
    let re = parse(re, &targets(ctx))
        .ok_or("Malformed `re`, or a kind of target this server does not keep.")?;
    if !takes.contains(&kind(&re)) {
        return Err("`chat` answers a line, and `msg` a message.");
    }
    Ok(Some(re))
}

/// A kept `re`, as a reader is sent it.
pub(crate) fn json(re: &Reply) -> Value {
    match re {
        Reply::Line { room: 0, id } => json!({ "line": id }),
        Reply::Line { room, id } => json!({ "line": id, "room": room }),
        Reply::Pm(r) => json!({ "pm": b64url(r) }),
        Reply::Im { login, guid } => json!({ "im": { "login": login, "guid": guid.as_str() } }),
        Reply::Signed { signer, id, hash } => json!({ "signed": {
            "signer": Fingerprint(*signer).to_string(),
            "id": guid_of(id).expect("any 16 bytes are a guid").as_str(),
            "hash": b64url(hash),
        } }),
    }
}

/// Put a kept `re` on `v`, for a reader that declared `replies`.
pub(crate) fn add(v: &mut Value, re: Option<&Reply>, replies: bool) {
    if let Some(re) = re.filter(|_| replies) {
        v["re"] = json(re);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[&str] = &["line", "pm", "im", "signed"];

    #[test]
    fn every_kind_reads_back_as_it_is_written() {
        let signer = Fingerprint([7; 32]).to_string();
        for v in [
            json!({ "line": 98124 }),
            json!({ "line": 98124, "room": 27 }),
            json!({ "pm": b64url(&[3; 16]) }),
            json!({ "im": { "login": "alice", "guid": "5f5e1000-1234-4abc-89ab-000000000001" } }),
            json!({ "signed": {
                "signer": signer,
                "id": "5f5e1000-1234-4abc-89ab-000000000002",
                "hash": b64url(&[9; 32]),
            } }),
        ] {
            let re = parse(&v, ALL).unwrap_or_else(|| panic!("{v}"));
            assert_eq!(json(&re), v);
        }
    }

    #[test]
    fn a_malformed_target_or_one_not_kept_is_refused() {
        for (v, targets) in [
            (json!(7), ALL),
            (json!({}), ALL),
            (json!({ "line": 1, "pm": b64url(&[3; 16]) }), ALL),
            (json!({ "line": 1, "extra": 2 }), ALL),
            (json!({ "line": "1" }), ALL),
            (json!({ "line": 1, "room": 1u64 << 32 }), ALL),
            (json!({ "pm": "short" }), ALL),
            (json!({ "pm": b64url(&[3; 16]), "room": 1 }), ALL),
            (
                json!({ "im": { "login": "", "guid": "5f5e1000-1234-4abc-89ab-000000000001" } }),
                ALL,
            ),
            (json!({ "im": { "login": "alice", "guid": "nope" } }), ALL),
            (
                json!({ "signed": { "signer": "x", "id": "y", "hash": "z" } }),
                ALL,
            ),
            (
                json!({ "im": { "login": "alice", "guid": "5f5e1000-1234-4abc-89ab-000000000001",
                                "room": 1 } }),
                ALL,
            ),
            (
                json!({ "signed": {
                    "signer": Fingerprint([7; 32]).to_string(),
                    "id": "5f5e1000-1234-4abc-89ab-000000000002",
                    "hash": b64url(&[9; 32]),
                    "extra": 1,
                } }),
                ALL,
            ),
            (json!({ "line": 1 }), &["pm", "im"][..]),
        ] {
            assert_eq!(parse(&v, targets), None, "{v}");
        }
    }
}
