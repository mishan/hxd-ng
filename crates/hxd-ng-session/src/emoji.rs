//! Server emoji on the ng wire (`docs/server-emoji.md` §8): the `emoji`
//! capability's block, `emoji_list`, refs on `chat` and `msg` and on
//! what carries them, and `GET /emoji/{hash}`.
//!
//! As with avatars, a fetch is no authorization question: anyone on the
//! server may draw any live emoji, and the bearer only keeps the catalog
//! from being a public web directory.

use bytes::Bytes;
use http_body_util::Full;
use hxd_core::emoji::{EmojiEntry, EmojiId, EmojiName, EmojiRef, EmojiRefs, MAX_REFS};
use hyper::body::Incoming;
use hyper::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, IF_NONE_MATCH,
};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::media::{bearer_session, json_resp, unauthorized};
use crate::proto::{reply_err, reply_ok};
use crate::NgCtx;

/// Entries an `emoji_list` page holds.
const PAGE: usize = 200;

/// The login reply's `emoji` block, where the server serves a catalog.
/// Read after the session attached, so a reread since is told by the
/// `emoji_changed` that follows.
pub(crate) fn login_json(core: &hxd_core::Core) -> Option<Value> {
    let (revision, policy) = (core.emoji_revision()?, core.emoji_policy()?);
    Some(json!({
        "revision": revision,
        "max_count": policy.max_count,
        "max_bytes": policy.max_bytes,
        "max_dimension": policy.max_dimension,
        "manage": false,
    }))
}

/// A request's `emoji`, from a session that declared it; any other's is
/// ignored, as a param the server does not know is (§5). Of those sent,
/// the first [`MAX_REFS`] are read, as the core keeps no more. A ref that
/// can name no entry, with no name an entry could have or an id past
/// any, is a catalog miss and dropped with the others the core drops.
pub(crate) fn param(declared: bool, v: Option<&Value>) -> Result<Vec<EmojiRef>, &'static str> {
    const MALFORMED: &str = "`emoji` is a list of `{ name, id }`.";
    let Some(v) = v.filter(|_| declared) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for r in v.as_array().ok_or(MALFORMED)?.iter().take(MAX_REFS) {
        let name = r.get("name").and_then(Value::as_str).ok_or(MALFORMED)?;
        let id = r.get("id").filter(|id| id.is_i64() || id.is_u64());
        let id = id
            .ok_or(MALFORMED)?
            .as_u64()
            .and_then(|id| u32::try_from(id).ok());
        if let (Some(id), Some(name)) = (id, EmojiName::parse(name)) {
            refs.push(EmojiRef {
                id: EmojiId(id),
                name,
            });
        }
    }
    Ok(refs)
}

/// Kept refs, as a reader is sent them.
pub(crate) fn json(refs: &EmojiRefs) -> Value {
    (refs.refs().iter())
        .map(|r| json!({ "name": r.name.as_str(), "id": r.id.0 }))
        .collect()
}

/// Put kept refs on `v`, for a reader that declared `emoji`.
pub(crate) fn add(v: &mut Value, refs: Option<&EmojiRefs>, emoji: bool) {
    if let Some(refs) = refs.filter(|_| emoji) {
        v["emoji"] = json(refs);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An entry as `emoji_list` lists it: a removed one is its id, revision
/// and last name, and nothing of the image it no longer has.
fn entry_json(e: &EmojiEntry) -> Value {
    let mut v = json!({ "id": e.id.0, "revision": e.revision, "name": e.name.as_str() });
    match &e.image {
        Some(i) => {
            v["hash"] = json!(hex(&i.hash));
            v["width"] = json!(i.width);
            v["height"] = json!(i.height);
            if i.animated {
                v["animated"] = json!(true);
            }
        }
        None => v["removed"] = json!(true),
    }
    v
}

#[derive(Default, Deserialize)]
struct ListParams {
    revision: Option<u32>,
    after: Option<u32>,
}

/// `emoji_list`: from the server's copy of the catalog, never the store.
pub(crate) fn list(ctx: &NgCtx, declared: bool, id: u64, params: &Value) -> String {
    if !declared || ctx.core.emoji_policy().is_none() {
        return reply_err(id, "not_available", "This server serves no emoji here.");
    }
    let Ok(p) = crate::conn::params_or_default::<ListParams>(params) else {
        return reply_err(id, "bad_request", "Malformed emoji_list.");
    };
    let Some(listing) = ctx.core.emoji_list(p.revision, p.after.map(EmojiId), PAGE) else {
        return reply_err(id, "not_available", "This server serves no emoji here.");
    };
    let mut ok = json!({ "revision": listing.revision });
    if !listing.entries.is_empty() {
        ok["emoji"] = listing.entries.iter().map(entry_json).collect();
    }
    if listing.delta {
        ok["delta"] = json!(true);
    }
    if listing.more {
        ok["has_more"] = json!(true);
    }
    reply_ok(id, ok)
}

/// The hash a path names: the SHA-256 in lowercase hex, as `emoji_list`
/// writes it.
fn parse_hash(s: &str) -> Option<[u8; 32]> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    (s.len() == 64).then_some(())?;
    for (o, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *o = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

type Resp = Response<Full<Bytes>>;

const IMMUTABLE: &str = "private, max-age=31536000, immutable";

/// `GET /emoji/{hash}`: a live emoji's bytes, whole. The lookup comes
/// before the revalidation, unlike an avatar's: a removed emoji's image
/// must leave a client's cache, so its hash is 404 even to a client
/// that holds it.
pub(crate) fn download(hash: &str, req: &Request<Incoming>, ctx: &NgCtx) -> Resp {
    if ctx.core.emoji_policy().is_none() {
        return not_found();
    }
    if bearer_session(req, ctx).is_none() {
        return unauthorized();
    }
    let Some(image) = parse_hash(hash).and_then(|h| ctx.core.emoji_by_hash(&h)) else {
        return not_found();
    };
    let etag = format!("\"{hash}\"");
    if req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, &etag)
            .header(CACHE_CONTROL, IMMUTABLE)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    // `nosniff` and the sandbox CSP as for an avatar: the bytes are this
    // server's encoding of an image someone handed its operator.
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, image.mime.mime())
        .header(CACHE_CONTROL, IMMUTABLE)
        .header(ETAG, &etag)
        .header("x-content-type-options", "nosniff")
        .header(CONTENT_DISPOSITION, "inline")
        .header(CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'")
        .body(Full::new(Bytes::copy_from_slice(&image.bytes)))
        .unwrap()
}

fn not_found() -> Resp {
    json_resp(
        StatusCode::NOT_FOUND,
        json!({ "error": { "code": "no_such_emoji", "text": "No live emoji has that hash." } }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every ref well shaped is read, those that can name no entry
    /// dropped as the catalog's misses are, and only the first 32.
    #[test]
    fn refs_are_names_and_ids_and_those_no_entry_could_have_are_dropped() {
        let party = |id: Value| json!({ "name": "party", "id": id });
        let past: Vec<Value> = (0..MAX_REFS)
            .map(|_| json!({ "name": "aa", "id": 1 }))
            .collect();
        for (case, sent, kept) in [
            ("one", json!([party(json!(1))]), vec![1]),
            ("none", json!([]), vec![]),
            (
                "an unknown key",
                json!([{ "name": "party", "id": 2, "x": 1 }]),
                vec![2],
            ),
            ("no name", json!([{ "name": "Party", "id": 3 }]), vec![]),
            ("an id past any", json!([party(json!(1u64 << 32))]), vec![]),
            ("a negative id", json!([party(json!(-1))]), vec![]),
            (
                "the 33rd unread",
                Value::Array([past.clone(), vec![json!("unread")]].concat()),
                vec![1; MAX_REFS],
            ),
        ] {
            let got: Vec<u32> = (param(true, Some(&sent)).unwrap().iter())
                .map(|r| r.id.0)
                .collect();
            assert_eq!(got, kept, "{case}");
        }
        assert_eq!(
            param(false, Some(&json!("party"))),
            Ok(vec![]),
            "undeclared"
        );
        assert_eq!(param(true, None), Ok(vec![]));
    }
}
