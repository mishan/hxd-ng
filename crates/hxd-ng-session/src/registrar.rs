//! The registrar's HTTP surface (`docs/identity-registrar.md` §3, §6).
//!
//! | route | |
//! |---|---|
//! | `POST /registrar/register` | §6.1: `{ "request": b64 }` → an attestation |
//! | `GET  /registrar/records/<fp>` | §6.2: the per-identity list |
//! | `GET  /registrar/records?since=` | §6.2: the full list, as a delta |
//! | `POST /registrar/records` | §6.2: `{ "record": b64 }` |
//! | `GET  /registrar/lookup/<handle>` | §6.3 |
//! | `GET  /registrar/lookup?identity=<fp>` | §6.3 |
//! | `GET  /registrar/log?since=` | §6.6: the issuance log |
//! | `GET  /registrar/stats` | §6.6 |
//!
//! None of these takes a transport token: every write is a signed
//! object, and every read is public (§6). The signed lists and the stats
//! are served as themselves, `application/cbor`, the way a card is —
//! they are what a verifier caches and re-checks, and wrapping them in
//! JSON would only be something to unwrap.
//!
//! Everything the registrar does is SQLite and signatures, so every call
//! goes to the blocking pool.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hxd_registrar::{Posted, Refusal, Registrar};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, RETRY_AFTER};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};
use tracing::debug;

use crate::identity::{b64, unb64};

type Resp = Response<Full<Bytes>>;

/// The largest object a user posts is a device revocation carrying a
/// certificate (6 KiB, §4.4); this is that in base64 and JSON.
const MAX_BODY: usize = 16 * 1024;
const BODY_WINDOW: Duration = Duration::from_secs(10);

pub const PREFIX: &str = "/registrar";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The `registrar` block of discovery (§3), or `null` when this server
/// is not one — or when the document was asked for under a name other
/// than the one this registrar signs as. `host` must equal the name the
/// document was fetched from, and a verifier trusts the key it finds
/// under that name, so a block served under any other name would be a
/// key vouched for by a host that never said so.
pub fn discovery(reg: Option<&Registrar>, host_header: Option<&str>) -> Value {
    let Some(reg) = reg else {
        return Value::Null;
    };
    let cfg = reg.config();
    let asked = host_header.map(strip_port).map(str::to_ascii_lowercase);
    if asked.as_deref() != Some(cfg.host.as_str()) {
        debug!(?asked, host = %cfg.host, "discovery asked for under another name; no registrar block");
        return Value::Null;
    }
    let (signup, proof) = match cfg.signup {
        hxd_registrar::Signup::Open => ("open", Value::Null),
        hxd_registrar::Signup::Invite => ("proof", json!("invite")),
        hxd_registrar::Signup::Closed => ("closed", Value::Null),
    };
    json!({
        "v": 1,
        "host": cfg.host,
        "key": b64(&reg.public_key()),
        "retiring": cfg.retiring.iter().map(|(k, until)| json!({ "key": b64(k), "until": until })).collect::<Vec<_>>(),
        "signup": signup,
        "proof": proof,
        "level": cfg.level,
        "attestation_days": cfg.attestation_days,
        "handle": { "min": cfg.handle_min, "max": cfg.handle_max },
        "records_max_age": cfg.records_max_age,
        "endpoints": {
            "register": "/registrar/register",
            "records": "/registrar/records",
            "lookup": "/registrar/lookup",
            "log": "/registrar/log",
            "stats": "/registrar/stats",
        },
    })
}

/// `Host` without its port. An IPv6 literal keeps its brackets, and so
/// never equals a registrar's host — which must be a name anyway.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

/// Every route under [`PREFIX`]. `client` is the request's address after
/// the proxy rules, which is what the rate limits count.
pub async fn route(req: Request<Incoming>, client: IpAddr, reg: Arc<Registrar>) -> Resp {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let rest = path.strip_prefix(PREFIX).unwrap_or("");
    match (req.method().clone(), rest) {
        (Method::POST, "/register") => {
            let Some(bytes) = signed_body(req, "request").await else {
                return bad_body("request");
            };
            let now = now();
            match blocking(move || reg.register(&bytes, client, now)).await {
                Ok(r) => json_resp(
                    StatusCode::OK,
                    json!({
                        "attestation": b64(&r.attestation),
                        "handle": r.handle,
                        "registered": r.registered,
                        "expires": r.expires,
                        "reissued": r.reissued,
                    }),
                ),
                Err(e) => refused(e),
            }
        }
        (Method::POST, "/records") => {
            let Some(bytes) = signed_body(req, "record").await else {
                return bad_body("record");
            };
            let now = now();
            match blocking(move || reg.post_record(&bytes, now)).await {
                Ok(Posted::Published { seq }) => {
                    json_resp(StatusCode::OK, json!({ "seq": seq, "published": true }))
                }
                Ok(Posted::Pending { until }) => json_resp(
                    StatusCode::OK,
                    json!({ "published": false, "pending_until": until }),
                ),
                Err(e) => refused(e),
            }
        }
        (Method::GET, "/records") => {
            let since = match since(query.as_deref()) {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            let max_age = reg.config().records_max_age;
            let now = now();
            list(
                blocking(move || reg.records_since(since, now)).await,
                now,
                max_age,
            )
        }
        (Method::GET, p) if p.starts_with("/records/") => {
            let Some(fp) = hl_identity::Fingerprint::parse(&p["/records/".len()..]) else {
                return refused(Refusal::BadRequest("malformed fingerprint".into()));
            };
            let since = match since(query.as_deref()) {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            let max_age = reg.config().records_max_age;
            let now = now();
            list(
                blocking(move || reg.records_for(&fp.0, since, now)).await,
                now,
                max_age,
            )
        }
        (Method::GET, "/log") => {
            let since = match since(query.as_deref()) {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            let max_age = reg.config().records_max_age;
            let now = now();
            list(
                blocking(move || reg.log_since(since, now)).await,
                now,
                max_age,
            )
        }
        (Method::GET, "/stats") => {
            let now = now();
            match blocking(move || reg.stats(now)).await {
                Ok(bytes) => cbor(bytes, None, 3600),
                Err(e) => refused(e),
            }
        }
        (Method::GET, "/lookup") => {
            let Some(fp) = query_param(query.as_deref(), "identity")
                .and_then(|s| hl_identity::Fingerprint::parse(&s))
            else {
                return refused(Refusal::BadRequest(
                    "lookup takes a handle in the path or ?identity=<fingerprint>".into(),
                ));
            };
            let now = now();
            match blocking(move || reg.lookup_identity(&fp.0, client, now)).await {
                Ok(handles) => json_resp(StatusCode::OK, json!({ "handles": handles })),
                Err(e) => refused(e),
            }
        }
        (Method::GET, p) if p.starts_with("/lookup/") => {
            let handle = p["/lookup/".len()..].to_owned();
            let now = now();
            match blocking(move || reg.lookup_handle(&handle, client, now)).await {
                Ok(Some(found)) => json_resp(
                    StatusCode::OK,
                    json!({
                        "fingerprint": hl_identity::Fingerprint::of(&found.identity).to_string(),
                        "identity": b64(&found.identity),
                        "registered": found.registered,
                        "expires": found.expires,
                    }),
                ),
                // One answer for free, lapsed, reserved and unknown.
                Ok(None) => refused(Refusal::NotFound),
                Err(e) => refused(e),
            }
        }
        _ => refused(Refusal::NotFound),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Refusal> + Send + 'static,
) -> Result<T, Refusal> {
    crate::spawn_blocking("registrar", f)
        .await
        .unwrap_or_else(|_| {
            Err(Refusal::Store(hxd_registrar::StoreError(
                "task failed".into(),
            )))
        })
}

/// A JSON body with one base64url field holding a signed object.
async fn signed_body(req: Request<Incoming>, field: &str) -> Option<Vec<u8>> {
    let limited = Limited::new(req.into_body(), MAX_BODY);
    let body = match tokio::time::timeout(BODY_WINDOW, limited.collect()).await {
        Ok(Ok(c)) => c.to_bytes(),
        _ => return None,
    };
    let v: Value = serde_json::from_slice(&body).ok()?;
    v.get(field).and_then(Value::as_str).and_then(unb64)
}

fn bad_body(field: &str) -> Resp {
    refused(Refusal::BadRequest(format!(
        "expected a JSON body with \"{field}\": base64url CBOR"
    )))
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_owned())
}

/// `?since=<seq>`: absent is from the beginning; anything but a number is
/// a mistake worth saying so about.
#[allow(clippy::result_large_err)]
fn since(query: Option<&str>) -> Result<Option<u64>, Resp> {
    match query_param(query, "since") {
        None => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| refused(Refusal::BadRequest("since must be a number".into()))),
    }
}

fn list(r: Result<Vec<u8>, Refusal>, now: u64, max_age: u64) -> Resp {
    match r {
        // `ETag` is the list's `issued` (§6.2), which is now.
        Ok(bytes) => cbor(bytes, Some(now), max_age),
        Err(e) => refused(e),
    }
}

fn cbor(bytes: Vec<u8>, etag: Option<u64>, max_age: u64) -> Resp {
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/cbor")
        .header(CACHE_CONTROL, format!("max-age={max_age}"));
    if let Some(tag) = etag {
        b = b.header(ETAG, format!("\"{tag}\""));
    }
    b.body(Full::new(Bytes::from(bytes))).unwrap()
}

fn json_resp(status: StatusCode, v: Value) -> Resp {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}

/// §6.5: `{ "error": code, "text": … }`, plus what the code carries.
fn refused(e: Refusal) -> Resp {
    let mut body = json!({ "error": e.code(), "text": e.text() });
    match &e {
        Refusal::ProofRequired { url: Some(url) } => body["url"] = json!(url),
        Refusal::Revoked {
            successor: Some(successor),
        } => {
            body["successor"] = json!(hl_identity::Fingerprint::of(successor).to_string());
        }
        Refusal::RateLimited { retry_after } => body["retry_after"] = json!(retry_after),
        _ => {}
    }
    let mut resp = json_resp(StatusCode::from_u16(e.status()).unwrap(), body);
    if let Refusal::RateLimited { retry_after } = e {
        resp.headers_mut()
            .insert(RETRY_AFTER, retry_after.to_string().parse().unwrap());
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_headers_lose_their_port() {
        assert_eq!(strip_port("hl.example"), "hl.example");
        assert_eq!(strip_port("hl.example:5700"), "hl.example");
        assert_eq!(strip_port("[::1]:5700"), "[::1]:5700");
    }

    #[test]
    fn since_is_a_number_or_absent() {
        assert_eq!(since(None).unwrap(), None);
        assert_eq!(since(Some("since=12")).unwrap(), Some(12));
        assert_eq!(since(Some("x=1&since=3")).unwrap(), Some(3));
        assert!(since(Some("since=soon")).is_err());
    }
}
