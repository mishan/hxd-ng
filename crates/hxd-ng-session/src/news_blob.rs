//! Durable news image HTTP routes (`docs/news.md` §9.4).

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hxd_core::{MediaReject, NewsError};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use crate::media::{bearer_session, json_resp, not_found, reject, unauthorized};
use crate::NgCtx;

type Resp = Response<Full<Bytes>>;
const UPLOAD_WINDOW: Duration = Duration::from_secs(30);

pub async fn upload(req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    let Some(policy) = ctx.core.news_policy().and_then(|p| p.attach) else {
        return not_found();
    };
    let Some(uid) = bearer_session(&req, ctx) else {
        return unauthorized();
    };
    if req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > policy.max_bytes)
    {
        return reject(MediaReject::TooLarge);
    }
    let name = req
        .headers()
        .get("x-attachment-name")
        .and_then(|v| v.to_str().ok())
        .map(attachment_name);
    let body = match tokio::time::timeout(
        UPLOAD_WINDOW,
        Limited::new(req.into_body(), policy.max_bytes).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes().to_vec(),
        Ok(Err(_)) => return reject(MediaReject::TooLarge),
        Err(_) => return reject(MediaReject::Generic),
    };
    let core = ctx.core.clone();
    let result =
        tokio::task::spawn_blocking(move || core.news_stage_attachment(uid, &body, name)).await;
    match result {
        Ok(Ok(staged)) => {
            let a = staged.attachment;
            let mut blob = json!({
                "id": hxd_core::media::handle_str(&a.id),
                "type": a.mime.mime(),
                "width": a.width,
                "height": a.height,
                "bytes": a.bytes,
                "expires_in": policy.stage_ttl.as_secs(),
            });
            if let Some(name) = a.name {
                blob["name"] = json!(name);
            }
            json_resp(StatusCode::CREATED, json!({ "blob": blob }))
        }
        Ok(Err(e)) => refused(&e),
        // The blocking task itself died, which is the pool's trouble
        // rather than the upload's.
        Err(_) => reject(MediaReject::Busy),
    }
}

/// A staging refusal onto §9.4's statuses, which are `/media`'s wherever
/// the two routes can fail the same way. 503 means only "try again": a
/// refusal that retrying cannot fix never says it.
fn refused(e: &NewsError) -> Resp {
    let with = |status: StatusCode| {
        let (code, text) = crate::news::news_err(e);
        json_resp(status, json!({ "error": { "code": code, "text": text } }))
    };
    match e {
        NewsError::Media(r) => reject(*r),
        NewsError::AccessDenied => reject(MediaReject::NotAuthorized),
        NewsError::NoSession => unauthorized(),
        NewsError::Disabled => not_found(),
        NewsError::NoMailbox => with(StatusCode::FORBIDDEN),
        NewsError::NewsFull => with(StatusCode::INSUFFICIENT_STORAGE),
        _ => with(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// `X-Attachment-Name` is the UTF-8 name percent-encoded (§9.4), because
/// a header value is ASCII. A value that does not decode is kept as it
/// arrived: a name with a stray `%` in it is better than no name.
fn attachment_name(raw: &str) -> String {
    let hex = |b: Option<&u8>| b.and_then(|&b| (b as char).to_digit(16));
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let (Some(high), Some(low)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) else {
                return raw.to_owned();
            };
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| raw.to_owned())
}

pub async fn download(id: &str, req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    if ctx.core.news_policy().and_then(|p| p.attach).is_none() {
        return not_found();
    }
    let Some(uid) = bearer_session(&req, ctx) else {
        return not_found();
    };
    let Some(handle) = hxd_core::media::handle_from_str(id) else {
        return not_found();
    };
    let legacy = req
        .uri()
        .query()
        .is_some_and(|q| q.split('&').any(|part| part == "size=legacy"));
    let core = ctx.core.clone();
    let found =
        tokio::task::spawn_blocking(move || core.news_attachment(uid, &handle, legacy)).await;
    let Ok(Ok(Some((attachment, blob, bytes)))) = found else {
        return not_found();
    };
    let mime = if legacy {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            "image/png"
        } else {
            "image/jpeg"
        }
    } else {
        attachment.mime.mime()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, mime)
        .header(CACHE_CONTROL, "private, max-age=604800, immutable")
        .header("etag", format!("\"{}\"", hash_prefix(&blob)))
        .header("x-content-type-options", "nosniff")
        .header(CONTENT_DISPOSITION, "inline")
        .header(CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn hash_prefix(id: &hxd_core::BlobId) -> String {
    id[..8].iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::attachment_name;

    #[test]
    fn a_name_is_percent_decoded_utf8_and_anything_else_is_kept_as_sent() {
        assert_eq!(attachment_name("caf%C3%A9%20%E6%97%A5.png"), "café 日.png");
        assert_eq!(attachment_name("plain.png"), "plain.png");
        assert_eq!(attachment_name("100%.png"), "100%.png", "not an escape");
        assert_eq!(attachment_name("%FF.png"), "%FF.png", "not UTF-8");
    }
}
