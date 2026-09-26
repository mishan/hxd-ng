//! Avatars on the ng wire (`docs/avatars.md` §4): `PUT /avatar` and
//! `GET /avatars/{id}`.
//!
//! The bytes go over HTTP for the reason inline media's do: a browser
//! wants `fetch` and a blob URL. The socket carries the reference, on the
//! `user` object, and `avatar_clear`. Both routes take the session's own
//! bearer, as `/media` does (`crate::media`).
//!
//! **A fetch is not an authorization question.** An avatar is shown to
//! the whole server by design, so any session may fetch any one; the
//! bearer keeps the server's pictures from being a public web directory
//! and nothing more. And because the id is the SHA-256 of the bytes, a
//! response never changes: it is cacheable indefinitely, and a
//! revalidation is answered from the id alone.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hxd_core::avatar::{AvatarId, AvatarPolicy, AvatarRef};
use hxd_core::media::MediaReject;
use hyper::body::Incoming;
use hyper::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    ETAG, IF_NONE_MATCH,
};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use tracing::debug;

use crate::media::{bearer_session, json_resp, reject, unauthorized};
use crate::NgCtx;

type Resp = Response<Full<Bytes>>;

/// As for `POST /media`: the size cap is the real bound, this is what
/// stops a body that never arrives from holding a task.
const UPLOAD_WINDOW: Duration = Duration::from_secs(30);

/// The `avatar` on a `user` object and in the upload's reply.
pub fn avatar_json(a: &AvatarRef) -> serde_json::Value {
    json!({
        "id": a.id.to_string(),
        "type": a.mime.mime(),
        "width": a.width,
        "height": a.height,
    })
}

/// The `avatars` block of the login reply.
pub fn limits_json(policy: &AvatarPolicy) -> serde_json::Value {
    json!({
        "max_bytes": policy.limits.max_bytes,
        "max_dimension": policy.limits.max_dimension,
        "types": hxd_core::media::MediaType::ALL
            .iter()
            .map(|t| t.mime())
            .collect::<Vec<_>>(),
    })
}

/// `PUT /avatar` — set the calling session's owner's avatar.
pub async fn upload(req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    let Some(policy) = ctx.core.avatar_policy() else {
        return not_found();
    };
    let Some(uid) = bearer_session(&req, ctx) else {
        return unauthorized();
    };
    let max = policy.limits.max_bytes;
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > max)
    {
        return reject(MediaReject::TooLarge);
    }
    let limited = Limited::new(req.into_body(), max);
    let body = match tokio::time::timeout(UPLOAD_WINDOW, limited.collect()).await {
        Ok(Ok(c)) => c.to_bytes().to_vec(),
        Ok(Err(_)) => return reject(MediaReject::TooLarge),
        Err(_) => return reject(MediaReject::Generic),
    };
    let core = ctx.core.clone();
    match tokio::task::spawn_blocking(move || core.set_avatar(uid, &body)).await {
        Ok(Ok(avatar)) => json_resp(StatusCode::OK, json!({ "avatar": avatar_json(&avatar) })),
        Ok(Err(e)) => {
            debug!(target: "avatar", uid, code = e.code(), "upload refused");
            reject(e)
        }
        Err(_) => reject(MediaReject::Busy),
    }
}

/// `GET /avatars/{id}` — the canonical bytes, whole.
pub async fn download(id: &str, req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    if ctx.core.avatar_policy().is_none() {
        return not_found();
    }
    if bearer_session(&req, ctx).is_none() {
        return unauthorized();
    }
    let Some(id) = AvatarId::parse(id) else {
        return not_found();
    };
    let etag = format!("\"{id}\"");
    // The id is the content, so a client holding it holds these bytes.
    if req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, &etag)
            .header(CACHE_CONTROL, "private, max-age=31536000, immutable")
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    let core = ctx.core.clone();
    let Ok(Some(avatar)) = tokio::task::spawn_blocking(move || core.avatar_by_id(&id)).await else {
        return not_found();
    };
    // `nosniff` and the sandbox CSP for the same reason as `/media`: the
    // bytes are this server's encoding of something a stranger uploaded.
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, avatar.meta.mime.mime())
        .header(CACHE_CONTROL, "private, max-age=31536000, immutable")
        .header(ETAG, &etag)
        .header("x-content-type-options", "nosniff")
        .header(CONTENT_DISPOSITION, "inline")
        .header(CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'")
        .body(Full::new(Bytes::copy_from_slice(&avatar.bytes)))
        .unwrap()
}

fn not_found() -> Resp {
    json_resp(
        StatusCode::NOT_FOUND,
        json!({ "error": { "code": "no_such_avatar", "text": "Avatar not found" } }),
    )
}
