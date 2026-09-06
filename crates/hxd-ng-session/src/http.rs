//! The HTTP layer on the ng listener (`docs/hotline-ng-identity.md` §4–§6).
//!
//! Every connection to the ng port is HTTP first. Most of them upgrade to
//! a WebSocket in their first request and never come back here; the rest
//! are the identity endpoints, which are small enough to route by hand:
//!
//! | route | |
//! |---|---|
//! | `GET  /.well-known/hotline` | discovery |
//! | `POST /identity/challenge` | §5.2 step 1 |
//! | `POST /identity/auth` | §5.2 step 2 / §5.3 |
//! | `GET  /identity/card/<fp>` | §7 |
//! | `PUT  /identity/card` | §7 |
//! | `GET  /ng` (and `/`) | upgrade → the JSON protocol |
//! | `GET  /trtp` | upgrade → the TRTP tunnel |
//!
//! `/identity/link` and `/identity/unlink` (§8.2, §8.4) arrive with account
//! association and 404 until then, and discovery doesn't list them.
//!
//! TLS is still the reverse proxy's job. The one thing this layer asks of
//! the proxy is the mTLS header contract (§5.3): `X-Hotline-Client-Cert`
//! is believed only from `NgConfig::trusted_proxies`, and stripped from
//! everyone else.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hxd_core::{IdentityTag, Transport};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, ETAG};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

use crate::identity::{b64, unb64, AuthRefused, ClassicLogin, TransportIdentity};
use crate::{conn, tunnel, NgCtx};

type Resp = Response<Full<Bytes>>;

/// Request bodies on the identity endpoints: a card is at most 16 KiB,
/// so this bounds any one request at a few cards' worth.
const MAX_BODY: usize = 64 * 1024;

/// Serve one accepted TCP connection: HTTP/1.1 until it upgrades.
pub(crate) async fn serve_connection(stream: TcpStream, peer: SocketAddr, ctx: NgCtx) {
    if ctx.core.is_banned(peer.ip()) {
        info!("refusing banned address");
        return;
    }
    let io = TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, std::convert::Infallible>(route(req, peer, ctx).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades();
    if let Err(e) = conn.await {
        debug!("http connection ended: {e}");
    }
}

async fn route(mut req: Request<Incoming>, peer: SocketAddr, ctx: NgCtx) -> Resp {
    let path = req.uri().path().to_owned();

    if hyper_tungstenite::is_upgrade_request(&req) {
        return match path.as_str() {
            "/" | "/ng" => upgrade(&mut req, peer, ctx, Proto::Json),
            "/trtp"
                if ctx.identity.as_ref().is_some_and(|i| i.config().trtp)
                    && ctx.tunnel.is_some() =>
            {
                upgrade(&mut req, peer, ctx, Proto::Trtp)
            }
            _ => plain(StatusCode::NOT_FOUND, "no such WebSocket path"),
        };
    }

    match (req.method(), path.as_str()) {
        (&Method::GET, "/.well-known/hotline") => discovery(&ctx),
        (&Method::POST, "/identity/challenge") => challenge(&ctx),
        (&Method::POST, "/identity/auth") => auth(req, peer, &ctx).await,
        (&Method::POST, "/identity/link") => link(req, peer, &ctx).await,
        (&Method::POST, "/identity/unlink") => unlink(req, peer, &ctx).await,
        (&Method::PUT, "/identity/card") => put_card(req, peer, &ctx).await,
        (&Method::GET, p) if p.starts_with("/identity/card/") => {
            get_card(&p["/identity/card/".len()..], &ctx)
        }
        _ => plain(StatusCode::NOT_FOUND, "not found"),
    }
}

enum Proto {
    Json,
    Trtp,
}

/// Authenticate the upgrade (§6.1), then hand the socket to the
/// application protocol. The upgrade itself completes in a spawned task
/// once this response has gone out.
fn upgrade(req: &mut Request<Incoming>, peer: SocketAddr, ctx: NgCtx, proto: Proto) -> Resp {
    let identity = match transport_identity(req, peer, &ctx) {
        Ok(i) => i,
        Err(resp) => return *resp,
    };
    let config = WebSocketConfig {
        max_message_size: Some(256 * 1024),
        max_frame_size: Some(256 * 1024),
        ..Default::default()
    };
    let (response, websocket) = match hyper_tungstenite::upgrade(req, Some(config)) {
        Ok(v) => v,
        Err(e) => {
            debug!("bad upgrade request: {e}");
            return plain(StatusCode::BAD_REQUEST, "bad upgrade");
        }
    };
    tokio::spawn(async move {
        let ws = match websocket.await {
            Ok(ws) => ws,
            Err(e) => {
                debug!("upgrade failed: {e}");
                return;
            }
        };
        match proto {
            Proto::Json => conn::run(ws, peer, ctx, identity).await,
            Proto::Trtp => {
                let Some(sink) = ctx.tunnel.as_ref() else {
                    return;
                };
                let transport = Transport {
                    encrypted: true,
                    identity: identity.as_ref().map(TransportIdentity::tag),
                };
                sink.run(Box::new(tunnel::WsByteStream::new(ws)), peer, transport)
                    .await;
            }
        }
    });
    // hyper_tungstenite builds a body of its own type; re-wrap it.
    let (parts, _) = response.into_parts();
    Response::from_parts(parts, Full::new(Bytes::new()))
}

/// §6.1: bearer token in `Authorization`, `?token=` in the URL, or a
/// client certificate from a trusted proxy. An invalid token is a 401,
/// never a silent downgrade to unauthenticated.
fn transport_identity(
    req: &Request<Incoming>,
    peer: SocketAddr,
    ctx: &NgCtx,
) -> Result<Option<TransportIdentity>, Box<Resp>> {
    let Some(state) = ctx.identity.as_ref() else {
        return Ok(None);
    };
    let bearer = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let query = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
        .map(str::to_owned);
    if let Some(token) = bearer.or(query) {
        return match state.redeem(&token) {
            Some(i) => Ok(Some(i)),
            None => Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "invalid or expired transport token",
            ))),
        };
    }
    if let Some(device) = client_cert_device(req, peer.ip(), ctx) {
        return match state.identity_for_device(&device) {
            Some(i) => Ok(Some(i)),
            None => Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "client certificate not on file",
            ))),
        };
    }
    Ok(None)
}

/// The mTLS header contract (§5.3): `X-Hotline-Client-Cert` is base64
/// DER, believed only from `trusted_proxies`. Only the Ed25519 public key
/// is extracted; nothing else in the certificate is examined.
fn client_cert_device(req: &Request<Incoming>, peer: IpAddr, ctx: &NgCtx) -> Option<[u8; 32]> {
    let header = req.headers().get("x-hotline-client-cert")?;
    if !ctx.cfg.trusted_proxies.contains(&peer) {
        warn!(%peer, "X-Hotline-Client-Cert from an untrusted address, ignored");
        return None;
    }
    let der = base64_any(header.to_str().ok()?)?;
    spki_ed25519(&der)
}

/// Locate an Ed25519 SubjectPublicKeyInfo in a DER certificate: the
/// algorithm OID 1.3.101.112 (`06 03 2b 65 70`) followed by a 33-byte BIT
/// STRING with no unused bits. A full DER parser would find the same
/// bytes by a longer road; RFC 8410 fixes this encoding, so a search for
/// it is exact rather than heuristic. Replace with a real parser when
/// the certificate has to be examined for anything else.
fn spki_ed25519(der: &[u8]) -> Option<[u8; 32]> {
    const PATTERN: [u8; 8] = [0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let at = der.windows(PATTERN.len()).position(|w| w == PATTERN)?;
    der.get(at + PATTERN.len()..at + PATTERN.len() + 32)?
        .try_into()
        .ok()
}

fn base64_any(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let s = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .ok()
}

// --- Identity endpoints -----------------------------------------------

fn discovery(ctx: &NgCtx) -> Resp {
    let identity = match ctx.identity.as_ref() {
        Some(st) => {
            let cfg = st.config();
            let mut bindings = vec!["challenge"];
            if !ctx.cfg.trusted_proxies.is_empty() {
                bindings.push("mtls");
            }
            json!({
                "enabled": true,
                "bindings": bindings,
                "new_accounts": match cfg.new_accounts {
                    crate::identity::NewAccounts::Deny => "deny",
                    crate::identity::NewAccounts::Guest => "guest",
                    crate::identity::NewAccounts::Create => "create",
                },
                "min_attestation_age": cfg.min_attestation_age,
                "trusted_registrars": cfg.registrar_keys.keys().collect::<Vec<_>>(),
                "association": "server",
                "endpoints": {
                    "challenge": "/identity/challenge",
                    "auth": "/identity/auth",
                    "card": "/identity/card",
                    "link": "/identity/link",
                    "unlink": "/identity/unlink",
                },
            })
        }
        None => json!({ "enabled": false }),
    };
    let mut ng = json!({ "ws": "/ng" });
    if ctx.identity.as_ref().is_some_and(|i| i.config().trtp) && ctx.tunnel.is_some() {
        ng["trtp"] = json!("/trtp");
    }
    let doc = json!({
        "v": 1,
        "name": ctx.cfg.server_name,
        "server_key": ctx.identity.as_ref().map(|i| b64(&i.server_key())),
        "ng": ng,
        "identity": identity,
        "registrar": Value::Null,
    });
    json_resp(StatusCode::OK, doc)
}

fn challenge(ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    // Rate limiting belongs here (§13); it should share whatever the
    // login-attempt limiter becomes rather than grow its own.
    let ch = st.issue_challenge();
    json_resp(
        StatusCode::OK,
        json!({ "challenge": b64(&ch), "server_key": b64(&st.server_key()), "expires_in": 60 }),
    )
}

async fn auth(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let device_from_cert = client_cert_device(&req, peer.ip(), ctx);
    let Some(body) = read_json(req).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let field = |k: &str| body.get(k).and_then(Value::as_str).and_then(unb64);
    let (Some(card), Some(cert)) = (field("card"), field("device_cert")) else {
        return plain(StatusCode::BAD_REQUEST, "card and device_cert are required");
    };
    // §5.4: classic credentials, verified and linked in the same step.
    let login = body.get("login").and_then(Value::as_str).map(str::to_owned);
    let password = body
        .get("password")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if login.is_some() != password.is_some() {
        return plain(StatusCode::BAD_REQUEST, "login and password go together");
    }
    let proof = field("proof");
    if proof.is_none() && device_from_cert.is_none() {
        return plain(
            StatusCode::BAD_REQUEST,
            "proof is required without a client certificate",
        );
    }
    // The state does signature checks and, with credentials or a
    // create policy, file I/O: off the reactor.
    let st = st.clone();
    let result = tokio::task::spawn_blocking(move || {
        let classic = login
            .as_deref()
            .zip(password.as_deref())
            .map(|(login, password)| ClassicLogin {
                login,
                password: password.as_bytes(),
            });
        match (proof, device_from_cert) {
            (Some(proof), _) => st.auth_with_proof(&card, &cert, &proof, classic),
            (None, Some(device)) => st.auth_presented(&card, &cert, &device, classic),
            (None, None) => unreachable!("checked above"),
        }
    })
    .await;
    let Ok(result) = result else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "auth task failed");
    };
    match result {
        Ok((token, ident)) => {
            info!(fingerprint = %ident.fingerprint.short(), handle = ?ident.handle, outcome = ident.outcome.as_str(), "identity authenticated");
            json_resp(
                StatusCode::OK,
                json!({
                    "token": token,
                    "expires_in": 60,
                    "fingerprint": ident.fingerprint.to_string(),
                    "handle": ident.handle,
                    "age": ident.age,
                    "outcome": ident.outcome.as_str(),
                    "account": ident.account,
                }),
            )
        }
        Err(e) => refused(e),
    }
}

/// `POST /identity/link` (§8.2). The socket that proved the identity is
/// whichever presented the token or certificate; a running guest session
/// of the same identity is told to reconnect rather than upgraded in
/// place (the spec allows either).
async fn link(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let ident = match transport_identity(&req, peer, ctx) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return plain(
                StatusCode::UNAUTHORIZED,
                "a transport token or client certificate is required",
            )
        }
        Err(resp) => return *resp,
    };
    let Some(body) = read_json(req).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let (Some(login), Some(password)) = (
        body.get("login").and_then(Value::as_str).map(str::to_owned),
        body.get("password")
            .and_then(Value::as_str)
            .map(str::to_owned),
    ) else {
        return plain(StatusCode::BAD_REQUEST, "login and password are required");
    };
    let st = st.clone();
    let result =
        tokio::task::spawn_blocking(move || st.link(&ident, &login, password.as_bytes())).await;
    match result {
        Ok(Ok(account)) => json_resp(
            StatusCode::OK,
            json!({ "linked": account.login, "reconnect": true }),
        ),
        Ok(Err(e)) => refused(e),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "link task failed"),
    }
}

/// `POST /identity/unlink` (§8.4).
async fn unlink(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let ident = match transport_identity(&req, peer, ctx) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return plain(
                StatusCode::UNAUTHORIZED,
                "a transport token or client certificate is required",
            )
        }
        Err(resp) => return *resp,
    };
    let st = st.clone();
    let result = tokio::task::spawn_blocking(move || st.unlink(&ident)).await;
    match result {
        Ok(Ok(account)) => json_resp(StatusCode::OK, json!({ "unlinked": account.login })),
        Ok(Err(e)) => refused(e),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "unlink task failed"),
    }
}

fn get_card(fp: &str, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let Some(fp) = hl_identity::Fingerprint::parse(fp) else {
        return plain(StatusCode::BAD_REQUEST, "malformed fingerprint");
    };
    match st.card(&fp) {
        Some((updated, bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/cbor")
            .header(ETAG, format!("\"{updated}\""))
            .body(Full::new(Bytes::from(bytes)))
            .unwrap(),
        None => plain(StatusCode::NOT_FOUND, "no card for that identity"),
    }
}

async fn put_card(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let ident = match transport_identity(&req, peer, ctx) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return plain(
                StatusCode::UNAUTHORIZED,
                "a transport token or client certificate is required",
            )
        }
        Err(resp) => return *resp,
    };
    if !ident.allows(hl_identity::caps::MANAGE) {
        return refused(AuthRefused::NoManage);
    }
    let Some(bytes) = read_body(req).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a CBOR body");
    };
    match st.update_card(&ident.identity, &bytes) {
        Ok(true) => {
            // §7: notify sessions of the change. Sessions don't yet carry
            // an identity → uid index; this lands with account association.
            json_resp(StatusCode::OK, json!({ "updated": true }))
        }
        Ok(false) => json_resp(
            StatusCode::OK,
            json!({ "updated": false, "reason": "not newer" }),
        ),
        Err(e) => refused(e),
    }
}

// --- Plumbing -----------------------------------------------------------

async fn read_body(req: Request<Incoming>) -> Option<Vec<u8>> {
    let limited = Limited::new(req.into_body(), MAX_BODY);
    limited.collect().await.ok().map(|c| c.to_bytes().to_vec())
}

async fn read_json(req: Request<Incoming>) -> Option<Value> {
    let bytes = read_body(req).await?;
    serde_json::from_slice(&bytes).ok()
}

fn refused(e: AuthRefused) -> Resp {
    json_resp(
        StatusCode::from_u16(e.status()).unwrap(),
        json!({ "error": e.code(), "text": match e {
            AuthRefused::BadCard => "the user card did not verify",
            AuthRefused::BadCert => "the device certificate did not verify or is not valid now",
            AuthRefused::BadProof => "the login proof did not verify",
            AuthRefused::Revoked => "the device or identity is revoked",
            AuthRefused::Denied => "refused by server policy",
            AuthRefused::CardTooLarge => "the user card exceeds 16 KiB",
            AuthRefused::UnknownChallenge => "unknown or expired challenge",
            AuthRefused::LoginFailed => "the account name or password is wrong",
            AuthRefused::NoManage => "this device's certificate does not allow account management",
            AuthRefused::AlreadyLinked => "this identity is already linked to another account here",
            AuthRefused::WouldOrphan => "set a password on the account before unlinking; it has no other way in",
            AuthRefused::NotLinked => "this identity has no linked account here",
            AuthRefused::Backend => "server error",
        } }),
    )
}

fn json_resp(status: StatusCode, v: Value) -> Resp {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}

fn plain(status: StatusCode, text: &str) -> Resp {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(text.to_owned())))
        .unwrap()
}

// Keep the roster's view of an identity in one place for both paths.
impl From<&TransportIdentity> for IdentityTag {
    fn from(i: &TransportIdentity) -> Self {
        i.tag()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_extraction_finds_the_key() {
        let key = [0xabu8; 32];
        let mut der = vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x02];
        der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der.extend_from_slice(&key);
        der.extend_from_slice(&[0xa3, 0x00]);
        assert_eq!(spki_ed25519(&der), Some(key));
        assert_eq!(spki_ed25519(&der[..der.len() - 40]), None);
    }
}
