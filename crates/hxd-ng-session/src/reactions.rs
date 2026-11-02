//! The `reactions` capability (`docs/hotline-ng.md` §7.3): `react` on a
//! line or an instant message, a moderator's clear, a line's reactions on
//! the `history` that shows it, and `reactions_changed`, to sessions that
//! declared it.

use hxd_core::{ReactError, ReactionChange, ReactionKey, Reactions, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, retry_secs, SessState};
use crate::proto::{reply_err, reply_err_retry, reply_ok};
use crate::NgCtx;

/// The kinds of target this server takes reactions on: a line where
/// lines are kept, and an instant message where they are sent.
pub(crate) fn targets(ctx: &NgCtx) -> Vec<&'static str> {
    let core = &ctx.core;
    let on = core.reaction_policy().is_some();
    [("line", on), ("im", on && core.messaging_enabled())]
        .into_iter()
        .filter_map(|(kind, taken)| taken.then_some(kind))
        .collect()
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

/// A change as `reactions_changed` carries it.
pub(crate) fn change_json(change: &ReactionChange) -> Value {
    match change {
        ReactionChange::Summary { target, keys, mine } => {
            let mut v = json!({
                "target": crate::replies::json(target),
                "action": "summary",
                "keys": keys
                    .iter()
                    .map(|(k, n)| json!({ "key": key_json(k), "count": n }))
                    .collect::<Vec<_>>(),
            });
            if !mine.is_empty() {
                v["mine"] = json!(mine);
            }
            v
        }
        ReactionChange::Clear { target } => {
            json!({ "target": crate::replies::json(target), "action": "clear" })
        }
        ReactionChange::Changed {
            target,
            key,
            add,
            from,
        } => json!({
            "target": crate::replies::json(target),
            "action": if *add { "add" } else { "remove" },
            "key": key_json(key),
            "from": { "login": from },
        }),
    }
}

#[derive(Deserialize)]
struct ReactParams {
    target: Value,
    key: Option<Value>,
    #[serde(default)]
    remove: bool,
    with: Option<String>,
    #[serde(default)]
    clear: bool,
}

/// What a well-formed `react` asks.
enum Act {
    Line {
        room: u32,
        line: u64,
        key: ReactionKey,
        add: bool,
    },
    Clear {
        room: u32,
        line: u64,
    },
    Im {
        target: hxd_core::reply::ImTarget,
        with: String,
        key: ReactionKey,
        add: bool,
    },
}

/// `react`'s params, or the `bad_request` they earn: a key on every act
/// but a clear, which is of a line and takes neither `remove` nor a key,
/// and `with` on an `im` target alone.
fn act(ctx: &NgCtx, p: ReactParams) -> Result<Act, &'static str> {
    let target = crate::replies::parse(&p.target, &targets(ctx))
        .ok_or("`target` names no kind this server takes.")?;
    let emoji = |k: Option<Value>| k.as_ref().and_then(key).ok_or("`key` is not one emoji.");
    match (target, p.clear, p.with) {
        (Reply::Line { room, id }, true, None) if p.key.is_none() && !p.remove => {
            Ok(Act::Clear { room, line: id })
        }
        (_, true, _) => Err("`clear` takes a line, and no key."),
        (Reply::Line { room, id }, false, None) => Ok(Act::Line {
            room,
            line: id,
            key: emoji(p.key)?,
            add: !p.remove,
        }),
        (Reply::Im(target), false, Some(with)) => Ok(Act::Im {
            target,
            with,
            key: emoji(p.key)?,
            add: !p.remove,
        }),
        (Reply::Im(_), false, None) => Err("An `im` target needs `with`."),
        _ => Err("`with` is for an `im` target."),
    }
}

/// `react`: one key added to, or with `remove` taken from, one line or
/// instant message, or with `clear` every key on a line.
pub(crate) async fn react(ctx: &NgCtx, state: &SessState, id: u64, params: &Value) -> String {
    if !state.reactions {
        return reply_err(id, "not_available", "Reactions are not available.");
    }
    let Ok(p) = serde_json::from_value::<ReactParams>(params.clone()) else {
        return reply_err(id, "bad_request", "Malformed react.");
    };
    let act = match act(ctx, p) {
        Ok(act) => act,
        Err(why) => return reply_err(id, "bad_request", why),
    };
    let uid = state.uid;
    let reacted = off_reactor(&ctx.core, move |c| match act {
        Act::Line {
            room,
            line,
            key,
            add,
        } => c.react(uid, room, line, &key, add).map(Some),
        Act::Clear { room, line } => c.react_clear(uid, room, line).map(|()| None),
        Act::Im {
            target,
            with,
            key,
            add,
        } => c.react_im(uid, &target, &with, &key, add).map(|()| None),
    })
    .await;
    match reacted {
        Some(Ok(Some(count))) => reply_ok(id, json!({ "count": count })),
        Some(Ok(None)) => reply_ok(id, json!({})),
        Some(Err(ReactError::OutOfScope)) => reply_err(
            id,
            "bad_request",
            "An `im` target names the sender or `with`.",
        ),
        Some(Err(ReactError::NotAllowed)) => {
            reply_err(id, "access_denied", "You may not react to that.")
        }
        Some(Err(ReactError::NoSuchTarget)) => {
            reply_err(id, "no_such_target", "No such line or message.")
        }
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
