//! The `reactions` capability (`docs/hotline-ng.md` §7.3): `react` on a
//! line, and a line's reactions on the `history` that shows it, to
//! sessions that declared it.

use hxd_core::{ReactError, ReactionKey, Reactions, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, retry_secs, SessState};
use crate::proto::{reply_err, reply_err_retry, reply_ok};
use crate::NgCtx;

/// The kinds of target this server takes reactions on: a line where
/// lines are kept.
pub(crate) fn targets(ctx: &NgCtx) -> Vec<&'static str> {
    match ctx.core.reaction_policy() {
        Some(_) => vec!["line"],
        None => Vec::new(),
    }
}

/// The login reply's `reactions` block.
pub(crate) fn login_json(ctx: &NgCtx) -> Value {
    let policy = ctx.core.reaction_policy().unwrap_or_default();
    json!({
        "targets": targets(ctx),
        "max_keys": policy.max_keys,
        "max_per_user": policy.max_per_user,
    })
}

/// A key as a client sent it: `{ "emoji" }` and nothing else. A server's
/// own emoji, `{ "custom" }`, is not offered here.
fn key(v: &Value) -> Option<ReactionKey> {
    let o = v.as_object().filter(|o| o.len() == 1)?;
    ReactionKey::emoji(o.get("emoji")?.as_str()?)
}

fn key_json(key: &ReactionKey) -> Value {
    match key {
        ReactionKey::Emoji(e) => json!({ "emoji": e }),
    }
}

/// Put a line's reactions on its `history` line, for a reader that
/// declared `reactions`: the keys and counts every reader shares, and the
/// reader's own as indexes into them, each left off when empty.
pub(crate) fn add(v: &mut Value, shown: Option<&Reactions>) {
    let Some(shown) = shown.filter(|s| !s.keys.is_empty()) else {
        return;
    };
    v["reactions"] = shown
        .keys
        .iter()
        .map(|(k, n)| json!({ "key": key_json(k), "count": n }))
        .collect();
    if !shown.mine.is_empty() {
        v["reactions_mine"] = json!(shown.mine);
    }
}

#[derive(Deserialize)]
struct ReactParams {
    target: Value,
    key: Value,
    #[serde(default)]
    remove: bool,
}

/// `react`: one key added to, or with `remove` taken from, one line.
pub(crate) async fn react(ctx: &NgCtx, state: &SessState, id: u64, params: &Value) -> String {
    if !state.reactions {
        return reply_err(id, "not_available", "Reactions are not available.");
    }
    let Ok(p) = serde_json::from_value::<ReactParams>(params.clone()) else {
        return reply_err(id, "bad_request", "Malformed react.");
    };
    let Some(Reply::Line { room, id: line }) = crate::replies::parse(&p.target, &targets(ctx))
    else {
        return reply_err(
            id,
            "bad_request",
            "`target` names no kind this server takes.",
        );
    };
    let Some(key) = key(&p.key) else {
        return reply_err(id, "bad_request", "`key` is not one emoji.");
    };
    let uid = state.uid;
    let reacted = off_reactor(&ctx.core, move |c| {
        c.react(uid, room, line, &key, !p.remove)
    })
    .await;
    match reacted {
        Some(Ok(count)) => reply_ok(id, json!({ "count": count })),
        Some(Err(ReactError::NotAllowed)) => {
            reply_err(id, "access_denied", "You may not react to that.")
        }
        Some(Err(ReactError::NoSuchTarget)) => reply_err(id, "no_such_target", "No such line."),
        Some(Err(ReactError::TooManyReactions)) => reply_err(
            id,
            "too_many_reactions",
            "That line has as many reactions as it may.",
        ),
        Some(Err(ReactError::RateLimited(wait))) => {
            hxd_core::instrument::rate_limited("ng", "react");
            reply_err_retry(id, "rate_limited", "Slow down.", retry_secs(wait))
        }
        Some(Err(ReactError::NotAvailable)) => {
            reply_err(id, "not_available", "Reactions are not available.")
        }
        _ => reply_err(id, "server_error", "Server error."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_one_emoji_by_name_and_nothing_else() {
        assert_eq!(key(&json!({ "emoji": "👍" })), ReactionKey::emoji("👍"));
        for bad in [
            json!("👍"),
            json!({ "emoji": "ok" }),
            json!({ "custom": 1234 }),
            json!({ "emoji": "👍", "custom": 1 }),
            json!({}),
        ] {
            assert_eq!(key(&bad), None, "{bad}");
        }
    }
}
