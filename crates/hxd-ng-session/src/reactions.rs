//! The `reactions` capability (`docs/hotline-ng.md` §7.3): `react` on a
//! line, an instant message or a stored private message, a moderator's
//! clear, a line's reactions on the `history` that shows it and a
//! message's on its `inbox` row, `reactions` to read them again and who
//! reacted, and `reactions_changed`, to sessions that declared it.

use hxd_core::{Asked, ReactError, ReactionChange, ReactionKey, Reactions, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, retry_secs, SessState};
use crate::proto::{reply_err, reply_err_retry, reply_ok, ReqEnvelope};
use crate::NgCtx;

/// The kinds of target this server takes reactions on: a line where
/// lines are kept, an instant message where they are sent, and a stored
/// private message where there is an inbox as well.
pub(crate) fn targets(ctx: &NgCtx) -> Vec<&'static str> {
    let core = &ctx.core;
    let on = core.reaction_policy().is_some();
    [
        ("line", on),
        ("im", on && core.messaging_enabled()),
        ("pm", on && core.inbox_enabled()),
    ]
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

/// A key as a client sent it: `{ "emoji" }`, or from a session that
/// declared `emoji` one of the server's by id, `{ "custom" }`, and
/// nothing else.
fn key(v: &Value, emoji: bool) -> Option<ReactionKey> {
    let o = v.as_object().filter(|o| o.len() == 1)?;
    match (o.get("emoji"), o.get("custom")) {
        (Some(e), _) => ReactionKey::emoji(e.as_str()?),
        (_, Some(id)) if emoji => {
            let id = u32::try_from(id.as_u64()?).ok()?;
            Some(ReactionKey::Custom(hxd_core::emoji::EmojiId(id)))
        }
        _ => None,
    }
}

fn key_json(key: &ReactionKey) -> Value {
    match key {
        ReactionKey::Emoji(e) => json!({ "emoji": e }),
        ReactionKey::Custom(id) => json!({ "custom": id.0 }),
    }
}

fn keys_json(keys: &[(ReactionKey, u32)]) -> Value {
    keys.iter()
        .map(|(k, n)| json!({ "key": key_json(k), "count": n }))
        .collect()
}

/// Put a line's reactions on its `history` line, for a reader that
/// declared `reactions`: the keys and counts every reader shares, and the
/// reader's own as indexes into them, each left off when empty.
pub(crate) fn add(v: &mut Value, shown: Option<&Reactions>) {
    let Some(shown) = shown.filter(|s| !s.keys.is_empty()) else {
        return;
    };
    v["reactions"] = keys_json(&shown.keys);
    if !shown.mine.is_empty() {
        v["reactions_mine"] = json!(shown.mine);
    }
}

/// A reaction's target, which is always one this wire can name.
fn target_json(target: &Reply) -> Value {
    crate::replies::json(target).expect("a reaction never names an ephemeral line")
}

/// A change as `reactions_changed` carries it.
pub(crate) fn change_json(change: &ReactionChange) -> Value {
    match change {
        ReactionChange::Summary { target, keys, mine } => {
            let mut v = json!({
                "target": target_json(target),
                "action": "summary",
                "keys": keys_json(keys),
            });
            if !mine.is_empty() {
                v["mine"] = json!(mine);
            }
            v
        }
        ReactionChange::Clear { target } => {
            json!({ "target": target_json(target), "action": "clear" })
        }
        ReactionChange::Changed {
            target,
            key,
            add,
            from,
        } => json!({
            "target": target_json(target),
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
    reason: Option<String>,
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
        reason: String,
    },
    Im {
        target: hxd_core::reply::ImTarget,
        with: String,
        key: ReactionKey,
        add: bool,
    },
    Pm {
        reference: hxd_core::inbox::MessageRef,
        key: ReactionKey,
        add: bool,
    },
}

const KEY_REFUSED: &str =
    "`key` is not one emoji, nor one of this server's from a session that declared `emoji`.";

/// `react`'s params, or the `bad_request` they earn: a key on every act
/// but a clear, which is of a line and takes neither `remove` nor a key,
/// a reason on a clear alone, and `with` on an `im` target alone.
fn act(ctx: &NgCtx, p: ReactParams, custom: bool) -> Result<Act, &'static str> {
    let target = crate::replies::parse(&p.target, &targets(ctx))
        .ok_or("`target` names no kind this server takes.")?;
    let emoji = |k: Option<Value>| k.as_ref().and_then(|k| key(k, custom)).ok_or(KEY_REFUSED);
    match (target, p.clear, p.with) {
        (Reply::Line { room, id }, true, None) if p.key.is_none() && !p.remove => Ok(Act::Clear {
            room,
            line: id,
            reason: p.reason.unwrap_or_default(),
        }),
        (_, true, _) => Err("`clear` takes a line, and no key."),
        (_, false, _) if p.reason.is_some() => Err("`reason` goes with `clear` alone."),
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
        (Reply::Pm(reference), false, None) => Ok(Act::Pm {
            reference,
            key: emoji(p.key)?,
            add: !p.remove,
        }),
        _ => Err("`with` is for an `im` target."),
    }
}

/// `react`: one key added to, or with `remove` taken from, one line,
/// instant message or stored message, or with `clear` every key on a
/// line.
pub(crate) async fn react(ctx: &NgCtx, state: &SessState, id: u64, params: &Value) -> String {
    if !state.reactions {
        return reply_err(id, "not_available", "Reactions are not available.");
    }
    let Ok(p) = serde_json::from_value::<ReactParams>(params.clone()) else {
        return reply_err(id, "bad_request", "Malformed react.");
    };
    let act = match act(ctx, p, state.emoji) {
        Ok(act) => act,
        Err(why) => return reply_err(id, "bad_request", why),
    };
    let uid = state.uid;
    let clearing = matches!(act, Act::Clear { .. });
    let reacted = off_reactor(&ctx.core, move |c| match act {
        Act::Line {
            room,
            line,
            key,
            add,
        } => c.react(uid, room, line, &key, add).map(Some),
        Act::Clear { room, line, reason } => c.react_clear(uid, room, line, &reason).map(|()| None),
        Act::Im {
            target,
            with,
            key,
            add,
        } => c.react_im(uid, &target, &with, &key, add).map(|()| None),
        Act::Pm {
            reference,
            key,
            add,
        } => c.react_pm(uid, reference, &key, add).map(|()| None),
    })
    .await;
    match reacted {
        Some(Ok(Some(count))) => reply_ok(id, json!({ "count": count })),
        Some(Ok(None)) => reply_ok(id, json!({})),
        Some(Err(ReactError::NotAllowed)) if clearing => {
            reply_err(id, "access_denied", "You may not clear reactions.")
        }
        Some(Err(ReactError::OutOfScope)) => reply_err(
            id,
            "bad_request",
            "An `im` target names the sender or `with`.",
        ),
        Some(Err(ReactError::NotAllowed)) => {
            reply_err(id, "access_denied", "You may not react to that.")
        }
        Some(Err(ReactError::BadRequest(why))) => reply_err(id, "bad_request", why),
        Some(Err(ReactError::Protected)) => {
            reply_err(id, "protected", "That user cannot be moderated by you.")
        }
        Some(Err(ReactError::NoSuchTarget)) => {
            reply_err(id, "no_such_target", "No such line or message.")
        }
        Some(Err(ReactError::NoSuchEmoji)) => reply_err(id, "no_such_emoji", "No such emoji."),
        Some(Err(ReactError::TooManyKeys | ReactError::TooManyOfYours)) => reply_err(
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

/// The kinds of target `reactions` answers, of those the login block
/// lists: an instant message is never kept to be read again.
const ASKED: &[&str] = &["line", "pm"];

/// The most targets one `reactions` names.
const TARGETS_MAX: usize = 50;

/// What the targets `reactions` names add to its price: one for each
/// ten, so that one full request costs what a few small ones do.
pub(crate) fn targets_weight(req: &ReqEnvelope) -> u32 {
    if req.req != "reactions" {
        return 0;
    }
    let n = req.params.get("targets").and_then(Value::as_array);
    u32::try_from(n.map_or(0, Vec::len).div_ceil(10)).unwrap_or(u32::MAX)
}

#[derive(Deserialize)]
struct AskedParams {
    targets: Vec<Value>,
    key: Option<Value>,
}

/// `reactions`' params, its targets of the kinds of `taken` it answers,
/// or the `bad_request` they earn.
fn asked_params(
    taken: &[&str],
    p: AskedParams,
    custom: bool,
) -> Result<(Vec<Reply>, Option<ReactionKey>), &'static str> {
    if !(1..=TARGETS_MAX).contains(&p.targets.len()) {
        return Err("`targets` takes 1 to 50 targets.");
    }
    let kinds: Vec<&str> = taken
        .iter()
        .copied()
        .filter(|k| ASKED.contains(k))
        .collect();
    let targets = (p.targets.iter())
        .map(|t| crate::replies::parse(t, &kinds))
        .collect::<Option<Vec<_>>>()
        .ok_or("`targets` names a kind `reactions` does not answer.")?;
    let key = match p.key {
        None => None,
        Some(_) if targets.len() != 1 => return Err("`key` goes with one target."),
        Some(k) => Some(key(&k, custom).ok_or(KEY_REFUSED)?),
    };
    Ok((targets, key))
}

fn asked_json(a: &Asked) -> Value {
    let mut v = json!({
        "target": target_json(&a.target),
        "keys": keys_json(&a.shown.keys),
    });
    if !a.shown.mine.is_empty() {
        v["mine"] = json!(a.shown.mine);
    }
    if let Some(from) = &a.from {
        v["from"] = from.iter().map(|nick| json!({ "nick": nick })).collect();
    }
    v
}

/// `reactions`: the reactions on each target this session could have
/// read, and with `key` and one target who holds that key, by nick.
pub(crate) async fn asked(ctx: &NgCtx, state: &SessState, id: u64, params: &Value) -> String {
    if !state.reactions {
        return reply_err(id, "not_available", "Reactions are not available.");
    }
    let Ok(p) = serde_json::from_value::<AskedParams>(params.clone()) else {
        return reply_err(id, "bad_request", "Malformed reactions.");
    };
    let (targets, key) = match asked_params(&targets(ctx), p, state.emoji) {
        Ok(asked) => asked,
        Err(why) => return reply_err(id, "bad_request", why),
    };
    let uid = state.uid;
    match off_reactor(&ctx.core, move |c| {
        c.reactions_asked(uid, &targets, key.as_ref())
    })
    .await
    {
        Some(Ok(asked)) => {
            let shown: Vec<_> = asked.iter().map(asked_json).collect();
            reply_ok(id, json!({ "reactions": shown }))
        }
        Some(Err(e)) => {
            tracing::warn!("chat log would not read reactions: {e}");
            reply_err(id, "server_error", "Server error.")
        }
        None => reply_err(id, "server_error", "Server error."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One to fifty targets of a kind `reactions` answers, and a key
    /// beside one alone, an emoji; anything else is refused.
    #[test]
    fn get_reactions_params_take_one_to_fifty_line_and_pm_targets() {
        let taken = ["line", "im", "pm"];
        let line = json!({ "line": 7 });
        let im =
            json!({ "im": { "login": "bob", "guid": "5f5e1000-1234-4abc-89ab-000000000001" } });
        let thumbs = json!({ "emoji": "👍" });
        let parse = |targets: Vec<Value>, key: Option<Value>| {
            asked_params(&taken, AskedParams { targets, key }, false)
        };
        let lines = |n: usize| vec![line.clone(); n];
        let (fifty, none) = parse(lines(50), None).unwrap();
        assert_eq!((fifty.len(), none), (50, None));
        let (one, key) = parse(lines(1), Some(thumbs.clone())).unwrap();
        assert_eq!(one, [Reply::Line { room: 0, id: 7 }]);
        assert_eq!(key, ReactionKey::emoji("👍"));
        let pm = json!({ "pm": "AAAAAAAAAAAAAAAAAAAAAA" });
        let (both, _) = parse(vec![pm, line.clone()], None).unwrap();
        assert_eq!(both, [Reply::Pm([0; 16]), Reply::Line { room: 0, id: 7 }]);
        for (case, targets, key) in [
            ("none", lines(0), None),
            ("fifty-one", lines(51), None),
            ("an instant message", vec![im], None),
            ("malformed", vec![json!({ "line": "seven" })], None),
            ("a key beside two", lines(2), Some(thumbs.clone())),
            (
                "a key that is no emoji",
                lines(1),
                Some(json!({ "emoji": "ok" })),
            ),
        ] {
            assert!(parse(targets, key).is_err(), "{case}");
        }
    }

    /// One emoji by name, or for a session that declared `emoji` one of
    /// the server's by an id that fits its four bytes.
    #[test]
    fn a_key_is_one_emoji_by_name_or_a_server_emoji_by_id() {
        use hxd_core::emoji::EmojiId;
        let custom = |id| Some(ReactionKey::Custom(EmojiId(id)));
        for (sent, plain, with_emoji) in [
            (
                json!({ "emoji": "👍" }),
                ReactionKey::emoji("👍"),
                ReactionKey::emoji("👍"),
            ),
            (json!({ "custom": 1234 }), None, custom(1234)),
            (json!({ "custom": u32::MAX }), None, custom(u32::MAX)),
            (json!({ "custom": u64::from(u32::MAX) + 1 }), None, None),
            (json!({ "custom": -1 }), None, None),
            (json!({ "custom": 1.5 }), None, None),
            (json!({ "custom": "1" }), None, None),
            (json!({ "emoji": "👍", "custom": 1 }), None, None),
            (json!("👍"), None, None),
            (json!({ "emoji": "ok" }), None, None),
            (json!({}), None, None),
        ] {
            assert_eq!(key(&sent, false), plain, "{sent}");
            assert_eq!(key(&sent, true), with_emoji, "{sent}, with emoji");
        }
    }
}
