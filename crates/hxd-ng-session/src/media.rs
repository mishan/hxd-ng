//! Inline media on the ng wire: `POST /media` and `GET /media/{id}`.
//!
//! The bytes go over HTTP and not inside the WebSocket
//! (`docs/inline-media.md` §8.2). A browser wants `fetch` and a blob
//! URL; base64 inside a JSON frame is the wrong shape for a 200 KB
//! image, and it would sit in the same stream as the chat the image is
//! attached to. The socket carries the *reference*; this module carries
//! the bytes.
//!
//! Both routes authenticate with the session's own credential —
//! `Authorization: Bearer <session>.<token>`, the public session id and
//! the secret token joined by a dot — which the registry validates
//! exactly as `resume` does, constant-time on the hash. A detached
//! session can still upload and fetch: its token is valid while the
//! session lives, and a phone that lost its socket mid-upload should not
//! have to log in again to finish.
//!
//! Errors map the pipeline's six coarse codes onto status codes, because
//! a `fetch` caller branches on the status before it parses anything. A
//! download that fails for *any* reason is 404 — the spec's
//! "never distinguish expired from unauthorized", in HTTP's own words.
//!
//! CORS is not stated here. Every response this module builds leaves
//! through `http.rs`'s shared wrapper, which is the one place the ng HTTP
//! surface says what a page from another origin may do with these
//! routes; a second copy beside them would be a second policy the day
//! either changed.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hxd_core::media::{MediaRef, MediaReject, UploadOutcome, UploadPart};
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, RETRY_AFTER,
};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use tracing::debug;

use crate::NgCtx;

type Resp = Response<Full<Bytes>>;

/// How long the whole upload may take to arrive. The size cap is the
/// real bound; this is what stops a `Content-Length` that never arrives
/// from holding a task open.
const UPLOAD_WINDOW: Duration = Duration::from_secs(30);

/// The media object as it appears in a reply, an event, and the upload
/// response — one shape, one place.
pub fn media_json(m: &MediaRef) -> serde_json::Value {
    let mut v = json!({
        "type": m.mime.mime(),
        "width": m.width,
        "height": m.height,
        "bytes": m.bytes,
    });
    // Absent rather than null when the bytes have gone, so a client can
    // test for the key: the metadata is still worth rendering as a
    // placeholder, and there is nothing to fetch.
    if let Some(id) = m.id {
        v["id"] = json!(hxd_core::media::handle_str(&id));
    }
    v
}

/// The `media` block of the login reply: what a client needs before it
/// opens a file picker.
pub fn limits_json(cfg: &hxd_core::media::MediaConfig) -> serde_json::Value {
    json!({
        "max_bytes": cfg.max_bytes,
        "max_dimension": cfg.codec.max_dimension,
        "max_pixels": cfg.codec.max_pixels,
        "max_frames": cfg.codec.max_frames,
        "max_duration_ms": cfg.codec.max_duration_ms,
        // So a file picker can filter without hard-coding the spec's
        // list, and so a client learns of a fourth format the day a
        // server offers one.
        "types": hxd_core::media::MediaType::ALL
            .iter()
            .map(|t| t.mime())
            .collect::<Vec<_>>(),
    })
}

/// `POST /media` — the whole image in one body.
///
/// No chunking: HTTP carries a body, and the legacy wire's part
/// machinery exists because a 65 535-byte field cannot hold an image.
pub async fn upload(req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    let Some(cfg) = ctx.core.media_config().cloned() else {
        return not_found();
    };
    let Some(uid) = bearer_session(&req, ctx) else {
        return unauthorized();
    };
    // Refuse an oversized body before reading it, when the client was
    // honest enough to say how big it is. `Limited` below is what holds
    // for one that was not.
    if req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > cfg.max_bytes)
    {
        return reject(MediaReject::TooLarge);
    }
    let declared = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // `Limited` is the bound that holds for a client that lied about its
    // length, or said nothing at all.
    let limited = Limited::new(req.into_body(), cfg.max_bytes);
    let body = match tokio::time::timeout(UPLOAD_WINDOW, limited.collect()).await {
        Ok(Ok(c)) => c.to_bytes().to_vec(),
        // Over the cap, or a body that stopped arriving. The first is by
        // far the likelier and is what the client can act on.
        Ok(Err(_)) => return reject(MediaReject::TooLarge),
        Err(_) => return reject(MediaReject::Generic),
    };
    let core = ctx.core.clone();
    let budget = cfg.codec.permit_wait * 2;
    // The pipeline is a decode and a re-encode: off the reactor, and
    // with the awaiting side giving up before the client does.
    let outcome = tokio::time::timeout(
        budget,
        tokio::task::spawn_blocking(move || {
            core.media_upload_part(
                uid,
                UploadPart {
                    payload: &body,
                    declared: declared.as_deref(),
                    token: None,
                    index: 0,
                    count: None,
                    last: true,
                },
            )
        }),
    )
    .await;
    match outcome {
        Ok(Ok(Ok(UploadOutcome::Done(reference)))) => json_resp(
            StatusCode::CREATED,
            json!({ "media": media_json(&reference) }),
        ),
        // The HTTP route is single-shot, so a token is not an answer it
        // can produce; treating it as one would leave a session open
        // that nothing will ever finish.
        Ok(Ok(Ok(UploadOutcome::Token(_)))) => reject(MediaReject::Generic),
        Ok(Ok(Err(e))) => {
            debug!(target: "media", uid, code = e.code(), "upload refused");
            reject(e)
        }
        Ok(Err(_)) | Err(_) => reject(MediaReject::Busy),
    }
}

/// `GET /media/{id}` — the canonical bytes, whole.
///
/// One answer for every failure, and it is 404: no such handle, expired,
/// revoked, someone else's, or a session that is not what it says it is.
/// A status that told those apart would be a way to test whether a
/// handle exists.
pub async fn download(id: &str, req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    if ctx.core.media_config().is_none() {
        return not_found();
    }
    let Some(uid) = bearer_session(&req, ctx) else {
        return unauthorized();
    };
    let per_minute = ctx
        .core
        .media_config()
        .map(|c| c.download_per_minute)
        .unwrap_or(0);
    if !ctx
        .registry
        .allow_download(&session_of(&req).unwrap_or_default(), per_minute)
    {
        // Through `reject`, not a bare string: this module promises one
        // parseable error shape for every failure it produces, and a
        // `fetch` caller that has to special-case one status is exactly
        // what that promise is against.
        return reject(MediaReject::RateLimited);
    }
    let Some(handle) = hxd_core::media::handle_from_str(id) else {
        return not_found();
    };
    let Some(fetched) = ctx.core.media_fetch(uid, &handle) else {
        return not_found();
    };
    // `nosniff` and the sandbox CSP are for the case where someone
    // navigates to this URL directly rather than fetching it: the bytes
    // are canonical and this server encoded them, but they are still
    // something a stranger uploaded, and a browser should render them as
    // an image or not at all. `private` keeps a shared cache from
    // holding an image whose authorization set it knows nothing about.
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, fetched.mime.mime())
        .header(CACHE_CONTROL, "private, max-age=86400")
        .header("x-content-type-options", "nosniff")
        .header(CONTENT_DISPOSITION, "inline")
        .header(CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'")
        .body(Full::new(Bytes::from(fetched.bytes.as_ref().clone())))
        .unwrap()
}

/// `Bearer <session>.<token>` → the uid it belongs to.
fn bearer_session(req: &Request<Incoming>, ctx: &NgCtx) -> Option<hxd_core::Uid> {
    let (session, token) = credential(req)?;
    ctx.registry.validate(&ctx.core, &session, &token)
}

fn session_of(req: &Request<Incoming>) -> Option<String> {
    credential(req).map(|(s, _)| s)
}

fn credential(req: &Request<Incoming>) -> Option<(String, String)> {
    let raw = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let value = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    // The session id is `s_<hex>` and carries no dot, so splitting on
    // the first one is unambiguous.
    let (session, token) = value.split_once('.')?;
    (!session.is_empty() && !token.is_empty()).then(|| (session.to_owned(), token.to_owned()))
}

/// The six codes onto statuses (§8.2), with the ng error shape in the
/// body so a client has one parser for every failure this server
/// produces.
fn reject(e: MediaReject) -> Resp {
    let (status, code) = match e {
        MediaReject::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "media_too_large"),
        MediaReject::Unsupported => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media"),
        MediaReject::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        MediaReject::NotAuthorized => (StatusCode::FORBIDDEN, "access_denied"),
        MediaReject::Busy => (StatusCode::SERVICE_UNAVAILABLE, "server_busy"),
        MediaReject::Generic => (StatusCode::BAD_REQUEST, "media_rejected"),
    };
    let resp = json_resp(
        status,
        json!({ "error": { "code": code, "text": e.text() } }),
    );
    if e == MediaReject::RateLimited {
        retry_after(resp)
    } else {
        resp
    }
}

fn retry_after(mut resp: Resp) -> Resp {
    resp.headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("10"));
    resp
}

fn not_found() -> Resp {
    json_resp(
        StatusCode::NOT_FOUND,
        json!({ "error": { "code": "no_such_media", "text": "Media not found" } }),
    )
}

fn unauthorized() -> Resp {
    json_resp(
        StatusCode::UNAUTHORIZED,
        json!({ "error": { "code": "not_logged_in", "text": "Media needs a session." } }),
    )
}

fn json_resp(status: StatusCode, v: serde_json::Value) -> Resp {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}
