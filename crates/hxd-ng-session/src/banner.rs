//! The server banner on the ng wire (`docs/banner.md` §3): a `banner`
//! block in the login reply, and `GET /banner` for a banner held here.
//!
//! The banner itself — the file, its format, its reload on SIGHUP — is the
//! legacy frontend's, which had one first. This crate does not depend on
//! that one, so it reads the banner through [`BannerSource`], and the
//! binary joins the two.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, IF_NONE_MATCH,
};
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use crate::media::{bearer_session, json_resp};
use crate::NgCtx;

type Resp = Response<Full<Bytes>>;

/// Where a held banner is fetched from, relative to the ng port.
pub const BANNER_PATH: &str = "/banner";

/// Every banner response revalidates: a SIGHUP can swap the file under
/// the same path, and the ETag answers "unchanged" cheaply.
const CACHE: &str = "private, no-cache";

/// The banner as it is now.
pub enum BannerView {
    /// An image held here.
    Held {
        mime: &'static str,
        bytes: Arc<[u8]>,
        /// A strong ETag, quoted, that changes exactly when the bytes do.
        etag: Arc<str>,
        /// Where a click on it goes, if anywhere.
        link: Option<String>,
    },
    /// An image the client fetches from an absolute http(s) URL itself.
    Remote { url: String },
}

/// Whatever holds the server's banner.
pub trait BannerSource: Send + Sync {
    fn view(&self) -> BannerView;
}

/// The login reply's `banner` block: `url` is always where the image is —
/// [`BANNER_PATH`] for one held here, fetched with the session's bearer,
/// or an absolute URL, fetched as it is — and `link`, when present, is
/// where a click goes.
pub fn login_json(source: &dyn BannerSource) -> serde_json::Value {
    match source.view() {
        BannerView::Held { mime, link, .. } => {
            let mut v = json!({ "url": BANNER_PATH, "type": mime });
            if let Some(link) = link {
                v["link"] = json!(link);
            }
            v
        }
        BannerView::Remote { url } => json!({ "url": url }),
    }
}

/// `GET /banner` — the banner held here, whole.
pub async fn download(req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    let Some(source) = ctx.banner.as_ref() else {
        return not_found();
    };
    if bearer_session(&req, ctx).is_none() {
        return unauthorized();
    }
    let BannerView::Held {
        mime, bytes, etag, ..
    } = source.view()
    else {
        return not_found();
    };
    if req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| none_match(v, &etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, &*etag)
            .header(CACHE_CONTROL, CACHE)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    // The operator's file, not a stranger's upload, but sniffed rather
    // than decoded: `nosniff` and the sandbox CSP as for `/media`.
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, mime)
        .header(CACHE_CONTROL, CACHE)
        .header(ETAG, &*etag)
        .header("x-content-type-options", "nosniff")
        .header(CONTENT_DISPOSITION, "inline")
        .header(CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'")
        .body(Full::new(Bytes::from_owner(bytes)))
        .unwrap()
}

/// `If-None-Match` against our ETag, by the weak comparison RFC 9110
/// §13.1.2 asks of it: `*` matches, and so does a tag a proxy weakened.
fn none_match(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|tag| {
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        tag == "*" || tag == etag
    })
}

fn not_found() -> Resp {
    json_resp(
        StatusCode::NOT_FOUND,
        json!({ "error": { "code": "no_such_banner", "text": "There is no banner to download." } }),
    )
}

fn unauthorized() -> Resp {
    json_resp(
        StatusCode::UNAUTHORIZED,
        json!({ "error": { "code": "not_logged_in", "text": "The banner needs a session." } }),
    )
}

#[cfg(test)]
mod tests {
    use super::none_match;

    #[test]
    fn if_none_match_compares_weakly() {
        let etag = "\"abc\"";
        assert!(none_match("\"abc\"", etag));
        assert!(none_match("W/\"abc\"", etag));
        assert!(none_match("\"x\", W/\"abc\"", etag));
        assert!(none_match("*", etag));
        assert!(!none_match("\"abd\"", etag));
        assert!(!none_match("", etag));
    }
}
