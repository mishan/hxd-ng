//! The HTTP layer on the ng listener (`docs/hotline-ng-auth.md` §5–§7).
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
//! | `POST /identity/link` | §8.2 |
//! | `POST /identity/unlink` | §8.4 |
//! | `/identity/enroll/…` | the enrollment mailbox, `identity-enrollment.md` §5 |
//! | `GET  /ng` (and `/`) | upgrade → the JSON protocol |
//! | `GET  /trtp` | upgrade → the TRTP tunnel |
//!
//! TLS is still the reverse proxy's job. The one thing this layer asks of
//! the proxy is the mTLS header contract (§5.3): `X-Hotline-Client-Cert`
//! is believed only from `NgConfig::trusted_proxies`, and stripped from
//! everyone else.
//!
//! Everything above the upgrades answers CORS. These routes are
//! authenticated by a token in the body or the URL and never by a cookie,
//! so a wildcard origin gives away nothing a `curl` would not — and
//! without it a browser client served from anywhere but this host cannot
//! read one of them. That case is not exotic: hx-ng's `allowCustomServer`
//! points a page at a server other than the one that served it, and the
//! enrollment mailbox is reached by a phone that followed a QR code.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use hl_identity::Fingerprint;
use http_body_util::{BodyExt, Full, Limited};
use hxd_core::{IdentityTag, LinkAuthority, Transport};
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    AUTHORIZATION, CONTENT_TYPE, ETAG, ORIGIN,
};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

use crate::identity::{
    b64, unb64, AuthRefused, AuthRequest, ClassicLogin, Downstream, TransportIdentity,
};
use crate::{conn, tunnel, ForwardedHeader, NgCtx};

type Resp = Response<Full<Bytes>>;

/// Request bodies on the identity endpoints. The objects inside are
/// bounded individually — a card at 16 KiB (§3.4), a certificate at 4
/// KiB (§3.3) — so this is the envelope around them plus the base64 and
/// JSON they arrive in, and it is what stops a body being read at all
/// before any of those limits can apply.
const MAX_BODY: usize = 64 * 1024;

/// A bundle the holder posts back (§5.4). Its members are bounded at 4
/// and 16 KiB by the identity spec, so this is those plus the map around
/// them — the mailbox forwards it without decoding, so this is the only
/// thing keeping the answer proportionate to what it answers.
const MAX_BUNDLE_BYTES: usize = 4 * 1024 + 16 * 1024 + 256;

/// Serve one accepted TCP connection: HTTP/1.1 until it upgrades.
pub(crate) async fn serve_connection(stream: TcpStream, peer: SocketAddr, ctx: NgCtx) {
    if ctx.core.is_banned(peer.ip()) {
        info!("refusing banned address");
        return;
    }
    let io = TokioIo::new(stream);
    let head_timeout = ctx.cfg.login_timeout;
    let svc = hyper::service::service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, std::convert::Infallible>(route(req, peer, ctx).await) }
    });
    // hyper's default 30 s header timeout is silently inert without a
    // timer, so a half-open `GET /ng` would hold a task forever. On the
    // TCP listener the accept itself was under `login_timeout`; here the
    // request head is, and the body timeout is in `read_body`.
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(head_timeout)
        .serve_connection(io, svc)
        .with_upgrades();
    if let Err(e) = conn.await {
        debug!("http connection ended: {e}");
    }
}

async fn route(mut req: Request<Incoming>, peer: SocketAddr, ctx: NgCtx) -> Resp {
    let path = req.uri().path().to_owned();

    // Everything keyed on an address — bans, `max_detached_per_addr`,
    // the roster's `addr` — wants the client's address, not the reverse
    // proxy's (§2). `serve_connection` checked the socket's peer once at
    // accept; this checks again per request, so that a ban lands on a
    // keep-alive connection that is already open as well as on the next
    // one, and so that it covers the identity endpoints and not only the
    // upgrade.
    let client = client_addr(&req, peer, &ctx);
    if ctx.core.is_banned(client.ip()) {
        info!(%client, "refusing banned address");
        return plain(StatusCode::FORBIDDEN, "banned");
    }

    if hyper_tungstenite::is_upgrade_request(&req) {
        return match path.as_str() {
            "/" | "/ng" => upgrade(&mut req, peer, client, ctx, Proto::Json).await,
            "/trtp"
                if ctx.identity.as_ref().is_some_and(|i| i.config().trtp)
                    && ctx.tunnel.is_some() =>
            {
                upgrade(&mut req, peer, client, ctx, Proto::Trtp).await
            }
            _ => plain(StatusCode::NOT_FOUND, "no such WebSocket path"),
        };
    }

    // Preflight comes before the table: a browser sends `OPTIONS` to a
    // path whose real method it has not used yet, so this cannot be one
    // more arm of it.
    if req.method() == Method::OPTIONS && cors_route(&path) {
        return preflight();
    }

    let resp = match (req.method(), path.as_str()) {
        (&Method::GET, "/.well-known/hotline") => discovery(&ctx),
        (&Method::POST, "/identity/challenge") => challenge(&ctx),
        (&Method::POST, "/identity/auth") => auth(req, peer, &ctx).await,
        (&Method::POST, "/identity/link") => link(req, peer, &ctx).await,
        (&Method::POST, "/identity/unlink") => unlink(req, peer, &ctx).await,
        (&Method::PUT, "/identity/card") => put_card(req, peer, &ctx).await,
        (_, p) if p.starts_with("/identity/enroll") => {
            return enroll_route(req, client, &ctx).await;
        }
        (&Method::GET, p) if p.starts_with("/identity/card/") => {
            let inm = req
                .headers()
                .get(hyper::header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            get_card(&p["/identity/card/".len()..], inm.as_deref(), &ctx)
        }
        _ => plain(StatusCode::NOT_FOUND, "not found"),
    };
    // Only the routes a page fetches, rather than everything that
    // reaches here. A 404 for `/ng` is about a WebSocket path, and
    // labelling it cross-origin-readable says something this layer does
    // not mean — as would doing the same for whatever non-CORS route is
    // added to this table next.
    if cors_route(&path) {
        return cors(resp);
    }
    resp
}

/// The routes a page fetches. An upgrade is not subject to CORS and has
/// returned above by the time this is asked.
fn cors_route(path: &str) -> bool {
    path == "/.well-known/hotline" || path.starts_with("/identity/")
}

/// `*` rather than an echo of `Origin`: there is no cookie or other
/// ambient credential on these routes for a hostile page to ride, so an
/// allow-list would protect nothing. That is a property the routes have
/// to keep rather than one this layer can assume — a proxy-forwarded TLS
/// client certificate *is* ambient, which is why `transport_identity`
/// refuses to authenticate by certificate on a request that carries
/// `Origin`. `ETag` is exposed because `GET /identity/card/<fp>` is worth
/// revalidating rather than refetching, and a cross-origin page cannot
/// read the header to do it otherwise.
fn cors(mut resp: Resp) -> Resp {
    let h = resp.headers_mut();
    h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("ETag"),
    );
    resp
}

fn preflight() -> Resp {
    let resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, PUT, OPTIONS")
        // `PUT /identity/card` sends `application/cbor`, which is not a
        // safelisted content type, so these are the headers that make the
        // preflight it triggers succeed.
        .header(
            ACCESS_CONTROL_ALLOW_HEADERS,
            "content-type, authorization, if-none-match",
        )
        .header(ACCESS_CONTROL_MAX_AGE, "86400")
        .body(Full::new(Bytes::new()))
        .unwrap();
    cors(resp)
}

enum Proto {
    Json,
    Trtp,
}

/// Whether presenting a transport token spends it.
///
/// §6.1 makes the token single-use for the *upgrade*. The management
/// endpoints are not upgrades, and spending the token there left the
/// client unable to open a socket afterwards without re-running the whole
/// challenge/auth dance — so a client would link and then have to
/// authenticate again to use what it had just linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consume {
    Yes,
    No,
}

/// Authenticate the upgrade (§6.1), then hand the socket to the
/// application protocol. The upgrade itself completes in a spawned task
/// once this response has gone out.
async fn upgrade(
    req: &mut Request<Incoming>,
    socket: SocketAddr,
    // Who the proxy says it is speaking for (`client_addr`); the same as
    // `socket` when there is no proxy. This is the address the session
    // layer keys bans, `max_detached_per_addr` and the roster's `addr`
    // on; `socket` is who the certificate header is believed from.
    peer: SocketAddr,
    ctx: NgCtx,
    proto: Proto,
) -> Resp {
    let config = WebSocketConfig {
        max_message_size: Some(256 * 1024),
        max_frame_size: Some(256 * 1024),
        ..Default::default()
    };
    // The upgrade request is validated *before* the token is redeemed:
    // §6.1 spends the token on the upgrade, and a malformed handshake
    // used to burn it on the way to a 400, leaving the client to run the
    // whole challenge dance again over a missing `Sec-WebSocket-Key`.
    let (response, websocket) = match hyper_tungstenite::upgrade(&mut *req, Some(config)) {
        Ok(v) => v,
        Err(e) => {
            debug!("bad upgrade request: {e}");
            return plain(StatusCode::BAD_REQUEST, "bad upgrade");
        }
    };
    // The certificate header is believed by the *socket's* peer, which
    // is the proxy; the forwarded address is who the proxy is speaking
    // for and carries no trust of its own.
    let identity = match transport_identity(req, socket, &ctx, Consume::Yes).await {
        Ok(i) => i,
        // The upgrade never happens: this response isn't a 101, so the
        // socket stays HTTP and the future above is dropped unpolled.
        Err(resp) => return *resp,
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
                // The WebSocket hop is TLS; the hop behind the tunnel is
                // whatever the tunnel said it was (§5.2 `downstream`).
                let transport = Transport {
                    encrypted: !identity.as_ref().is_some_and(|i| i.downstream_cleartext),
                    identity: identity.as_ref().map(TransportIdentity::tag),
                };
                // §8.2: the tunnelled login can self-link, which is a
                // write of an association — so it needs the same `manage`
                // capability `/identity/link` asks for. And §8.1's
                // `deny` has to reach this wire too: a token lives a
                // minute, and an unlink inside that window used to leave
                // the tunnelled login falling through to a guest, which
                // is the hole `deny` exists to close. The legacy
                // frontend cannot read `[identity]`, so the answer
                // travels with the socket.
                let link = LinkAuthority {
                    may_link: identity
                        .as_ref()
                        .is_some_and(|i| i.allows(hl_identity::caps::MANAGE)),
                    unlinked_ok: ctx
                        .identity
                        .as_ref()
                        .is_none_or(|s| s.config().new_accounts != crate::NewAccounts::Deny),
                };
                sink.run(
                    Box::new(tunnel::WsByteStream::new(ws)),
                    peer,
                    transport,
                    link,
                )
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
///
/// Async because the certificate path re-verifies two signatures and may
/// read the accounts directory: that is not work for the reactor, and it
/// used to run there on every upgrade.
async fn transport_identity(
    req: &Request<Incoming>,
    peer: SocketAddr,
    ctx: &NgCtx,
    consume: Consume,
) -> Result<Option<TransportIdentity>, Box<Resp>> {
    // A present `Authorization` that isn't a bearer token is a 401, not
    // an unauthenticated request: §6.1's rule is that a token that
    // doesn't work is never a silent downgrade, and a client sending
    // `Basic` or a mis-cased scheme believes it authenticated.
    let bearer = match req.headers().get(AUTHORIZATION) {
        Some(v) => match v.to_str().ok().and_then(bearer_token) {
            Some(t) => Some(t.to_owned()),
            None => {
                return Err(Box::new(plain(
                    StatusCode::UNAUTHORIZED,
                    "Authorization must be a Bearer transport token (see §6.1)",
                )))
            }
        },
        None => None,
    };
    let query = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
        .map(str::to_owned);
    let Some(state) = ctx.identity.as_ref() else {
        // Identity is off, so nothing here can redeem a token — but a
        // client that presented one believes it authenticated, and
        // upgrading it as an anonymous guest tells it otherwise only by
        // implication. The guarantee is the same either way: a token
        // that doesn't work is a 401, never a silent downgrade.
        if bearer.or(query).is_some() {
            return Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "identity is not enabled on this server",
            )));
        }
        return Ok(None);
    };
    if let Some(token) = bearer.or(query) {
        return match state.redeem(&token, consume == Consume::Yes) {
            Some(i) => Ok(Some(i)),
            None => Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "invalid or expired transport token",
            ))),
        };
    }
    // A client certificate stands in for a token (§6.1) — but only for a
    // caller that chose to present it. A browser does not: the TLS layer
    // attaches the certificate to whatever the page fetches, so on a
    // deployment behind an mTLS proxy a *hostile* page could call
    // `/identity/link`, `/identity/unlink` or `PUT /identity/card`
    // cross-origin, ride the certificate it never saw, and read the
    // answer back through these routes' `Access-Control-Allow-Origin: *`.
    // A WebSocket upgrade is not subject to CORS at all and would ride it
    // just as well.
    //
    // `Origin` is the tell. Browsers set it on every request that could
    // be that attack and native clients — hlid, the desktop client, a
    // relay — set it on none, so requiring a token when it is present
    // costs the mTLS binding nothing and closes the ambient path. A page
    // that is entitled to be here can still get in, by redeeming a
    // transport token like everyone else.
    //
    // Refused rather than ignored: a caller that presented a certificate
    // believes it authenticated, and treating it as an anonymous guest
    // would be exactly the silent downgrade the token path above refuses.
    // A browser that presents *no* certificate is untouched and still
    // arrives here as an ordinary unauthenticated request.
    if let Some(device) = client_cert_device(req, peer.ip(), ctx)? {
        if req.headers().contains_key(ORIGIN) {
            return Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "a transport token is required: a client certificate is not \
                 accepted in place of one on a request that carries Origin",
            )));
        }
        let state = state.clone();
        let found = tokio::task::spawn_blocking(move || state.identity_for_device(&device))
            .await
            .map_err(|_| {
                Box::new(plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "certificate check failed",
                ))
            })?;
        return match found {
            Some(i) => Ok(Some(i)),
            None => Err(Box::new(plain(
                StatusCode::UNAUTHORIZED,
                "client certificate not on file",
            ))),
        };
    }
    Ok(None)
}

/// The client's address, as far as this server can tell: the socket's
/// peer, unless it is a trusted proxy (§2, `[ng] trusted_proxies`) that
/// named someone else in the header it is configured to set
/// (`[ng] forwarded_header`).
///
/// Behind a proxy every client shares one socket peer, so a ban keyed on
/// it bans the deployment and `max_detached_per_addr` is a global cap of
/// two. Only trusted proxies are believed, for the same reason the
/// certificate header is.
///
/// The element taken is the *rightmost* one that isn't itself a trusted
/// proxy, read across every line of the header in order. Taking the
/// first element instead let the client choose its own address: the
/// stock directives (nginx's `$proxy_add_x_forwarded_for`, HAProxy's
/// `option forwardfor`) *append* the peer they see to whatever the
/// client sent, so the left of the list is client-supplied and only the
/// right of it was written by the proxy. The rightmost-untrusted walk is
/// correct under both those and a proxy that replaces the header
/// outright. An element that names nothing this server can parse ends
/// the walk at the socket peer: an unreadable chain is not evidence.
fn client_addr(req: &Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> SocketAddr {
    if !ctx.cfg.trusted_proxies.contains(peer.ip()) {
        return peer;
    }
    // Which header, if any, this deployment's proxy is documented to
    // set. `Forwarded` is off by default because nginx passes an unknown
    // `Forwarded:` line through untouched, so believing it would undo
    // the walk above on the commonest deployment.
    let name = match ctx.cfg.forwarded_header {
        ForwardedHeader::None => return peer,
        ForwardedHeader::XForwardedFor => "x-forwarded-for",
        ForwardedHeader::Forwarded => "forwarded",
    };
    let mut elements = Vec::new();
    for value in req.headers().get_all(name) {
        let Ok(text) = value.to_str() else {
            return peer;
        };
        elements.extend(text.split(','));
    }
    match forwarded_client(
        &elements,
        ctx.cfg.forwarded_header,
        &ctx.cfg.trusted_proxies,
    ) {
        Some(ip) => SocketAddr::new(ip, 0),
        None => peer,
    }
}

/// The rightmost element of a forwarded chain that isn't a trusted
/// proxy. `None` means "nobody was named": the chain is empty, every
/// element is our own infrastructure, or one of them is unreadable —
/// in each case the caller keeps the socket's peer.
fn forwarded_client(
    elements: &[&str],
    header: ForwardedHeader,
    trusted: &crate::TrustedProxies,
) -> Option<IpAddr> {
    for element in elements.iter().rev() {
        let named = match header {
            ForwardedHeader::Forwarded => forwarded_for(element).and_then(host_ip),
            _ => host_ip(element),
        };
        match named {
            // Another hop of our own infrastructure: keep walking left.
            Some(ip) if trusted.contains(ip) => continue,
            Some(ip) => return Some(ip),
            None => return None,
        }
    }
    None
}

/// The `for=` value of one RFC 7239 `Forwarded` element.
fn forwarded_for(element: &str) -> Option<&str> {
    for param in element.split(';') {
        let Some((k, v)) = param.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("for") {
            return Some(v.trim().trim_matches('"'));
        }
    }
    None
}

/// An IP out of a `for=` or `X-Forwarded-For` value, which may be
/// `1.2.3.4`, `1.2.3.4:5678`, `[2001:db8::1]:5678`, or one of RFC 7239's
/// obfuscated forms — those name nobody, so they leave the socket's peer
/// in place.
fn host_ip(value: &str) -> Option<IpAddr> {
    let v = value.trim();
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = v.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        return inside.parse().ok();
    }
    // `1.2.3.4:5678`; a bare IPv6 has colons of its own and parsed above.
    v.rsplit_once(':').and_then(|(host, _)| host.parse().ok())
}

/// The token out of an `Authorization` header. The scheme is
/// case-insensitive (RFC 7235) and the separator is one or more spaces;
/// a case-sensitive `strip_prefix("Bearer ")` treated `bearer x` as no
/// credentials at all.
fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim_start_matches(' ');
    (!token.is_empty()).then_some(token)
}

/// The mTLS header contract (§5.3): `X-Hotline-Client-Cert` is base64
/// DER, believed only from `trusted_proxies`. Only the Ed25519 public key
/// is extracted; nothing else in the certificate is examined.
///
/// `Ok(None)` means "no certificate was offered": either the header is
/// absent, or it came from somewhere we don't trust and was ignored. A
/// header we *do* trust but can't decode is an error, not an absence —
/// falling through would quietly admit the request as a guest, which is
/// the failure mode a misconfigured proxy (nginx's URL-encoded
/// `$ssl_client_escaped_cert`, say) produces.
fn client_cert_device(
    req: &Request<Incoming>,
    peer: IpAddr,
    ctx: &NgCtx,
) -> Result<Option<[u8; 32]>, Box<Resp>> {
    let Some(header) = req.headers().get("x-hotline-client-cert") else {
        return Ok(None);
    };
    // HAProxy's `%[ssl_c_der,base64]` sends an empty value when the
    // client offered no certificate, which is "no certificate", not a
    // broken one. Treating it as an error made every plain upgrade
    // through such a proxy a 400 with a `warn!` per request. Whitespace
    // is emptiness here too: a proxy template that interpolates nothing
    // between two spaces says the same thing, and answering it with a
    // 400 and a warning per request is the log-flood the empty case was
    // fixed for.
    if header.as_bytes().iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }
    if !ctx.cfg.trusted_proxies.contains(peer) {
        // `debug`, not `warn`: anyone on the internet can send this
        // header, and a per-request warning is a log-flood primitive.
        debug!(%peer, "X-Hotline-Client-Cert from an untrusted address, ignored");
        return Ok(None);
    }
    let bad = || {
        warn!(%peer, "trusted proxy sent an undecodable X-Hotline-Client-Cert");
        Box::new(plain(
            StatusCode::BAD_REQUEST,
            "X-Hotline-Client-Cert must be base64 DER (see §5.3)",
        ))
    };
    let der = header.to_str().ok().and_then(base64_any).ok_or_else(bad)?;
    spki_ed25519(&der).map(Some).ok_or_else(bad)
}

/// The Ed25519 public key from a DER certificate's
/// `subjectPublicKeyInfo`, found by position.
///
/// ```text
/// Certificate    ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber, signature,
///                               issuer, validity, subject, subjectPublicKeyInfo, ... }
/// ```
///
/// Everything ahead of the SPKI is chosen by whoever requested the
/// certificate — `serialNumber` is an arbitrary INTEGER and a `Name`
/// attribute value is `ANY` — so *searching* the DER for RFC 8410's
/// algorithm identifier finds whatever bytes the subject planted, not
/// the key the proxy validated the handshake against. That is an
/// impersonation primitive: a self-signed certificate carrying the
/// attacker's own key in the SPKI (so `optional_no_ca` accepts it) and a
/// victim's device key in the subject would yield the victim's key.
///
/// So: walk the skeleton, skip the five fields between the version and
/// the SPKI without looking inside them, and take the key only from the
/// SPKI, and only under the Ed25519 OID.
fn spki_ed25519(der: &[u8]) -> Option<[u8; 32]> {
    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    const BIT_STRING: u8 = 0x03;
    const OID: u8 = 0x06;
    /// `[0] EXPLICIT` — the optional version.
    const CONTEXT_0: u8 = 0xa0;
    /// 1.3.101.112 (RFC 8410), the OID body without its header.
    const ED25519_OID: [u8; 3] = [0x2b, 0x65, 0x70];

    let (cert, after) = der_tlv(der)?;
    if cert.tag != SEQUENCE || !after.is_empty() {
        return None;
    }
    let (tbs, _) = der_tlv(cert.value)?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs.value;
    // `version` is `[0] EXPLICIT` and absent from a v1 certificate.
    let (first, after_version) = der_tlv(rest)?;
    if first.tag == CONTEXT_0 {
        rest = after_version;
    }
    // serialNumber, signature, issuer, validity, subject: skipped by
    // shape. Their contents are never examined, which is the point.
    for tag in [INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
        let (field, after) = der_tlv(rest)?;
        if field.tag != tag {
            return None;
        }
        rest = after;
    }
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let (spki, _) = der_tlv(rest)?;
    if spki.tag != SEQUENCE {
        return None;
    }
    let (alg, after_alg) = der_tlv(spki.value)?;
    if alg.tag != SEQUENCE {
        return None;
    }
    // RFC 8410 §3: the algorithm identifier is the OID alone, and the
    // parameters field is absent.
    let (oid, alg_tail) = der_tlv(alg.value)?;
    if oid.tag != OID || oid.value != ED25519_OID || !alg_tail.is_empty() {
        return None;
    }
    let (key, spki_tail) = der_tlv(after_alg)?;
    if key.tag != BIT_STRING || !spki_tail.is_empty() {
        return None;
    }
    // A BIT STRING's first content byte counts its unused trailing bits;
    // a key has none.
    match key.value.split_first() {
        Some((0, bits)) => bits.try_into().ok(),
        _ => None,
    }
}

/// One DER tag-length-value.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Split the leading TLV off `der`, returning it and what follows.
/// Definite lengths in their minimal encoding only — DER permits nothing
/// else, and being strict here keeps the walk above honest.
fn der_tlv(der: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = der.split_first()?;
    // High-tag-number form doesn't occur in a certificate's skeleton.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // 0x80 is the indefinite form (not DER); four length bytes is
        // already longer than any certificate.
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (bytes, rest) = rest.split_at(n);
        if bytes[0] == 0 {
            return None; // non-minimal
        }
        let len = bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        if len < 0x80 {
            return None; // should have used the short form
        }
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    Some((Tlv { tag, value }, rest))
}

/// A JSON field that must be a string if it is there at all. `Err` means
/// "present and not a string", which is a client bug worth reporting
/// rather than treating as absence.
fn opt_str(body: &Value, key: &str) -> Result<Option<String>, ()> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(()),
    }
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
            let mut endpoints = json!({
                "challenge": "/identity/challenge",
                "auth": "/identity/auth",
                "card": "/identity/card",
                "link": "/identity/link",
                "unlink": "/identity/unlink",
            });
            // Absent means no mailbox here, and an enrollee that reads
            // discovery therefore knows to fall back to the paste
            // (`identity-enrollment.md` §3).
            if ctx.enroll.is_some() {
                endpoints["enroll"] = json!("/identity/enroll");
            }
            let mut identity = json!({
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
                "endpoints": endpoints,
            });
            // Omitted rather than null when no web client is configured.
            // Absence is what "there is nowhere to point a QR code"
            // means on this wire, and emitting a null would make every
            // reader test for two things instead of one.
            if let Some(web) = ctx.cfg.web_client.as_deref() {
                identity["web"] = json!(web);
            }
            identity
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

// --- The enrollment mailbox (`docs/identity-enrollment.md` §5) ---------
//
// Five routes under `/identity/enroll`. Two of them carry a secret in
// the path and one carries a secret and a literal, so they are matched
// by splitting the path rather than by prefix: `/sessions/<s>` and
// `/sessions/<s>/answers` differ only in what follows the secret, and a
// `starts_with` that got that wrong would route an answer to a poll.

async fn enroll_route(req: Request<Incoming>, client: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(mb) = ctx.enroll.as_ref() else {
        return cors(plain(StatusCode::NOT_FOUND, "no enrollment mailbox here"));
    };
    let path = req.uri().path().to_owned();
    // `strip_prefix`, not `trim_start_matches`, which strips the prefix as
    // many times as it appears: `/identity/enroll/identity/enroll/sessions`
    // would have opened a session. Both 404 today, since the router only
    // sends a path that starts with the prefix here, but only one of them
    // says what it means.
    let rest: Vec<&str> = path
        .strip_prefix("/identity/enroll")
        .unwrap_or_default()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let method = req.method().clone();
    let resp = match (&method, rest.as_slice()) {
        (&Method::POST, ["sessions"]) => enroll_open(req, client, ctx, mb).await,
        (&Method::POST, ["requests"]) => enroll_post(req, client, ctx, mb).await,
        (&Method::GET, ["sessions", secret]) => enroll_poll(secret, req.uri().query(), mb).await,
        (&Method::POST, ["sessions", secret, "answers"]) => {
            enroll_answer(req, secret, ctx, mb).await
        }
        (&Method::GET, ["requests", secret]) => enroll_fetch(secret, mb).await,
        _ => plain(StatusCode::NOT_FOUND, "not found"),
    };
    cors(resp)
}

/// `?wait=N` seconds, clamped to the long-poll deadline. Absent is the
/// full deadline, which is what an ordinary holder wants.
///
/// `wait=0` exists for one job: a holder rotating to a new session has
/// to sweep the old one for anything that arrived while the rotation was
/// in flight, and blocking thirty seconds to find nothing would stall
/// the session it just opened. Nothing here is weakened by asking for a
/// shorter wait — it is the same answer, sooner.
fn poll_wait(query: Option<&str>) -> Duration {
    let secs = query
        .and_then(|q| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(k, _)| *k == "wait")
                .and_then(|(_, v)| v.parse::<u64>().ok())
        })
        .map(Duration::from_secs);
    match secs {
        Some(d) if d <= crate::enroll::LONG_POLL => d,
        _ => crate::enroll::LONG_POLL,
    }
}

fn enroll_refused(e: crate::enroll::Refused) -> Resp {
    json_resp(
        StatusCode::from_u16(e.status()).unwrap(),
        json!({ "error": e.code(), "text": e.text() }),
    )
}

/// §5.1. The body is optional, and so is the `identity` in it.
async fn enroll_open(
    req: Request<Incoming>,
    client: SocketAddr,
    ctx: &NgCtx,
    mb: &crate::enroll::Mailbox,
) -> Resp {
    // An empty body is legal here, unlike everywhere else on this
    // listener. That is not the same as a *malformed* one: reading any
    // parse failure as "no fields" would accept `{{{` — and a body-read
    // timeout — as a valid request to open a session.
    let Some(bytes) = read_body(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "could not read the request body");
    };
    let body: Value = if bytes.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return plain(StatusCode::BAD_REQUEST, "expected a JSON body, or none"),
        }
    };
    let identity = match body["identity"].as_str() {
        Some(s) => match Fingerprint::parse(s) {
            Some(fp) => Some(fp),
            None => return plain(StatusCode::BAD_REQUEST, "identity: not a fingerprint"),
        },
        None => None,
    };
    match mb.open_session(client.ip(), identity) {
        Ok(o) => json_resp(
            StatusCode::OK,
            json!({ "session": o.session, "code": o.code, "expires_in": o.expires_in }),
        ),
        Err(e) => enroll_refused(e),
    }
}

/// §5.2. The mailbox decodes the request only far enough to enforce the
/// size limit and, with no code, to read `prev` for routing.
async fn enroll_post(
    req: Request<Incoming>,
    client: SocketAddr,
    ctx: &NgCtx,
    mb: &crate::enroll::Mailbox,
) -> Resp {
    let Some(body) = read_json(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let Some(request) = body["request"].as_str().and_then(unb64) else {
        return enroll_refused(crate::enroll::Refused::BadRequest);
    };
    let code = body["code"].as_str();
    match mb.post_request(client.ip(), code, &request) {
        Ok(p) => json_resp(
            StatusCode::CREATED,
            json!({ "request": p.request, "expires_in": p.expires_in }),
        ),
        Err(e) => enroll_refused(e),
    }
}

/// §5.3, long-polled.
async fn enroll_poll(secret: &str, query: Option<&str>, mb: &crate::enroll::Mailbox) -> Resp {
    match mb.poll_session(secret, poll_wait(query)).await {
        Ok(p) => json_resp(
            StatusCode::OK,
            json!({
                "pending": p.pending.iter().map(|r| json!({
                    "id": r.id,
                    "request": b64(&r.request),
                    "received": r.received,
                })).collect::<Vec<_>>(),
                "expires_in": p.expires_in,
                // False once the code has admitted its one request, so
                // a standing holder knows to open a new session rather
                // than keep showing a code that no longer works.
                "code_live": p.code_live,
            }),
        ),
        Err(e) => enroll_refused(e),
    }
}

/// §5.4. Only the session secret reaches this, which is the asymmetry
/// the whole flow rests on: the code is typed on another machine, the
/// session secret never leaves the holder.
async fn enroll_answer(
    req: Request<Incoming>,
    secret: &str,
    ctx: &NgCtx,
    mb: &crate::enroll::Mailbox,
) -> Resp {
    let Some(body) = read_json(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let Some(id) = body["id"].as_str() else {
        return plain(StatusCode::BAD_REQUEST, "id is required");
    };
    let answered = match (body["bundle"].as_str(), body["denied"].as_str()) {
        (Some(_), Some(_)) => {
            return plain(
                StatusCode::BAD_REQUEST,
                "bundle and denied are alternatives",
            )
        }
        (Some(b), None) => match unb64(b) {
            Some(bytes) if bytes.len() <= MAX_BUNDLE_BYTES => {
                crate::enroll::Answered::Bundle(bytes)
            }
            Some(_) => return plain(StatusCode::BAD_REQUEST, "bundle too large"),
            None => return plain(StatusCode::BAD_REQUEST, "bundle: not base64url"),
        },
        (None, Some(r)) => {
            // A free string for the enrollee's UI (§12), bounded because
            // it is echoed back to somebody else.
            crate::enroll::Answered::Denied(r.chars().take(64).collect())
        }
        (None, None) => return plain(StatusCode::BAD_REQUEST, "bundle or denied is required"),
    };
    match mb.answer(secret, id, answered) {
        Ok(()) => json_resp(StatusCode::OK, json!({ "ok": true })),
        Err(e) => enroll_refused(e),
    }
}

/// §5.5, long-polled. The four answers are distinct statuses because the
/// enrollee does something different with each.
async fn enroll_fetch(secret: &str, mb: &crate::enroll::Mailbox) -> Resp {
    use crate::enroll::Fetched;
    match mb.fetch_answer(secret, crate::enroll::LONG_POLL).await {
        Fetched::Bundle(b) => json_resp(StatusCode::OK, json!({ "bundle": b64(&b) })),
        Fetched::Denied(r) => json_resp(StatusCode::FORBIDDEN, json!({ "denied": r })),
        Fetched::Pending { expires_in } => {
            json_resp(StatusCode::ACCEPTED, json!({ "expires_in": expires_in }))
        }
        Fetched::Gone => plain(StatusCode::GONE, "expired, or already fetched"),
    }
}

fn challenge(ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    // Rate limiting belongs here (§13); it should share whatever the
    // login-attempt limiter becomes rather than grow its own. Until it
    // exists, the challenge table has a ceiling of its own, and reaching
    // it sheds rather than grows.
    let Some(ch) = st.issue_challenge() else {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many outstanding challenges; retry shortly",
        );
    };
    json_resp(
        StatusCode::OK,
        json!({ "challenge": b64(&ch), "server_key": b64(&st.server_key()), "expires_in": 60 }),
    )
}

async fn auth(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let device_from_cert = match client_cert_device(&req, peer.ip(), ctx) {
        Ok(d) => d,
        Err(resp) => return *resp,
    };
    let Some(body) = read_json(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let field = |k: &str| body.get(k).and_then(Value::as_str).and_then(unb64);
    let (Some(card), Some(cert)) = (field("card"), field("device_cert")) else {
        return plain(StatusCode::BAD_REQUEST, "card and device_cert are required");
    };
    // §5.4: classic credentials, verified and linked in the same step.
    //
    // A present field of the wrong type is an error, not an absence:
    // `{"login": 7, "password": 7}` would otherwise read as "no
    // credentials", pass the pairing check, and answer 200 with a guest
    // or created outcome — a link the client asked for and did not get,
    // reported as success.
    let (login, password) = match (opt_str(&body, "login"), opt_str(&body, "password")) {
        (Ok(l), Ok(p)) if l.is_some() == p.is_some() => (l, p),
        (Ok(_), Ok(_)) => return plain(StatusCode::BAD_REQUEST, "login and password go together"),
        _ => {
            return plain(
                StatusCode::BAD_REQUEST,
                "login and password must be strings",
            )
        }
    };
    let downstream = match body.get("downstream").and_then(Value::as_str) {
        None | Some("local") | Some("loopback") => Downstream::Local,
        Some("cleartext") => Downstream::Cleartext,
        Some(_) => {
            return plain(
                StatusCode::BAD_REQUEST,
                "downstream must be local, loopback or cleartext",
            )
        }
    };
    // §8.2: a client that means to link an existing classic account
    // says `create: false`, so the server doesn't make it a new one
    // first and then refuse the link as `already_linked`.
    let create = body.get("create").and_then(Value::as_bool).unwrap_or(true);
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
        let req = AuthRequest {
            classic,
            downstream,
            create,
        };
        match (proof, device_from_cert) {
            (Some(proof), _) => st.auth_with_proof(&card, &cert, &proof, req),
            (None, Some(device)) => st.auth_presented(&card, &cert, &device, req),
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
    let ident = match transport_identity(&req, peer, ctx, Consume::No).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return plain(
                StatusCode::UNAUTHORIZED,
                "a transport token or client certificate is required",
            )
        }
        Err(resp) => return *resp,
    };
    let Some(body) = read_json(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a JSON body");
    };
    let (Ok(Some(login)), Ok(Some(password))) =
        (opt_str(&body, "login"), opt_str(&body, "password"))
    else {
        return plain(
            StatusCode::BAD_REQUEST,
            "login and password are required, as strings",
        );
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
    let ident = match transport_identity(&req, peer, ctx, Consume::No).await {
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
        Ok(Ok((account, stays))) => json_resp(
            StatusCode::OK,
            // §8.4: mail stored while the account was linked belongs to
            // the identity, and goes wherever it links next. Say so —
            // from the account's side it just looks like the inbox
            // emptied.
            json!({ "unlinked": account.login, "mail_stays_with_identity": stays }),
        ),
        Ok(Err(e)) => refused(e),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "unlink task failed"),
    }
}

fn get_card(fp: &str, if_none_match: Option<&str>, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let Some(fp) = hl_identity::Fingerprint::parse(fp) else {
        return plain(StatusCode::BAD_REQUEST, "malformed fingerprint");
    };
    match st.card(&fp) {
        Some((updated, bytes)) => {
            // Entity-tag syntax: a quoted string (§7). `updated` is the
            // card's own version, so it is a strong validator.
            let etag = format!("\"{updated}\"");
            if if_none_match
                .is_some_and(|inm| inm.split(',').any(|t| t.trim() == etag || t.trim() == "*"))
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(ETAG, etag)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/cbor")
                .header(ETAG, etag)
                .body(Full::new(Bytes::from(bytes)))
                .unwrap()
        }
        None => plain(StatusCode::NOT_FOUND, "no card for that identity"),
    }
}

async fn put_card(req: Request<Incoming>, peer: SocketAddr, ctx: &NgCtx) -> Resp {
    let Some(st) = ctx.identity.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "identity disabled");
    };
    let ident = match transport_identity(&req, peer, ctx, Consume::No).await {
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
    let Some(bytes) = read_body(req, ctx.cfg.login_timeout).await else {
        return plain(StatusCode::BAD_REQUEST, "expected a CBOR body");
    };
    let state = st.clone();
    let updated = tokio::task::spawn_blocking(move || state.update_card(&ident, &bytes)).await;
    let Ok(updated) = updated else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "card update task failed");
    };
    match updated {
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

/// Read a request body, bounded in both size and time: `Content-Length:
/// 1000` followed by one byte is otherwise a task held open for as long
/// as the client cares to hold it.
async fn read_body(req: Request<Incoming>, within: Duration) -> Option<Vec<u8>> {
    let limited = Limited::new(req.into_body(), MAX_BODY);
    match tokio::time::timeout(within, limited.collect()).await {
        Ok(Ok(c)) => Some(c.to_bytes().to_vec()),
        Ok(Err(e)) => {
            debug!("body read failed: {e}");
            None
        }
        Err(_) => {
            debug!("body read timed out");
            None
        }
    }
}

async fn read_json(req: Request<Incoming>, within: Duration) -> Option<Value> {
    let bytes = read_body(req, within).await?;
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
    fn a_bearer_token_survives_its_scheme_being_shouted() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER  abc"), Some("abc"));
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Basic abc"), None);
    }

    #[test]
    fn a_forwarded_element_names_one_hop() {
        assert_eq!(forwarded_for("for=192.0.2.1"), Some("192.0.2.1"));
        assert_eq!(
            forwarded_for("proto=https;For=\"[2001:db8::1]:4711\""),
            Some("[2001:db8::1]:4711")
        );
        // A parameter without a value doesn't end the search for `for=`.
        assert_eq!(forwarded_for("secure;for=192.0.2.1"), Some("192.0.2.1"));
        assert_eq!(forwarded_for("proto=https"), None);

        assert_eq!(host_ip("192.0.2.1"), "192.0.2.1".parse().ok());
        assert_eq!(host_ip("192.0.2.1:4711"), "192.0.2.1".parse().ok());
        assert_eq!(host_ip("2001:db8::1"), "2001:db8::1".parse().ok());
        assert_eq!(host_ip("[2001:db8::1]:4711"), "2001:db8::1".parse().ok());
        // RFC 7239's obfuscated identifiers name nobody.
        assert_eq!(host_ip("_hidden"), None);
        assert_eq!(host_ip("unknown"), None);
    }

    #[test]
    fn the_forwarded_client_is_the_rightmost_untrusted_element() {
        let trusted = crate::TrustedProxies::parse(&["127.0.0.1", "10.0.0.0/8"]).unwrap();
        let xff = ForwardedHeader::XForwardedFor;
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());

        // What `$proxy_add_x_forwarded_for` writes when the client sent
        // a value of its own: the client's claim first, the address the
        // proxy actually saw last. The claim is not believed.
        assert_eq!(
            forwarded_client(&["203.0.113.9", " 198.51.100.4"], xff, &trusted),
            ip("198.51.100.4")
        );
        // A proxy that replaces the header: one element, and it is the
        // client.
        assert_eq!(
            forwarded_client(&["198.51.100.4"], xff, &trusted),
            ip("198.51.100.4")
        );
        // Two of our own hops behind the edge; the walk passes over both.
        assert_eq!(
            forwarded_client(&["198.51.100.4", "10.0.0.7", "10.0.0.8"], xff, &trusted),
            ip("198.51.100.4")
        );
        // Nobody untrusted is named, so the caller keeps the peer.
        assert_eq!(forwarded_client(&["10.0.0.7"], xff, &trusted), None);
        assert_eq!(forwarded_client(&[], xff, &trusted), None);
        // An element we can't read ends the walk: a chain that isn't
        // legible is not evidence about who is at the far end.
        assert_eq!(
            forwarded_client(&["198.51.100.4", "_hidden"], xff, &trusted),
            None
        );
        assert_eq!(forwarded_client(&[""], xff, &trusted), None);

        // RFC 7239 form, same walk.
        let fwd = ForwardedHeader::Forwarded;
        assert_eq!(
            forwarded_client(
                &["for=203.0.113.9", "for=198.51.100.4;proto=https"],
                fwd,
                &trusted
            ),
            ip("198.51.100.4")
        );
        assert_eq!(
            forwarded_client(&["for=198.51.100.4", "proto=https"], fwd, &trusted),
            None
        );
    }

    /// Encode one TLV with a minimal definite length.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let bytes = n.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap();
            out.push(0x80 | (bytes.len() - start) as u8);
            out.extend_from_slice(&bytes[start..]);
        }
        out.extend_from_slice(body);
        out
    }

    fn ed25519_spki(key: &[u8; 32]) -> Vec<u8> {
        let alg = tlv(0x06, &[0x2b, 0x65, 0x70]);
        let mut bits = vec![0x00];
        bits.extend_from_slice(key);
        let mut body = tlv(0x30, &alg);
        body.extend_from_slice(&tlv(0x03, &bits));
        tlv(0x30, &body)
    }

    /// A certificate skeleton: `subject` is whatever the requester asked
    /// for, `key` is what the proxy actually validated against.
    fn certificate(key: &[u8; 32], subject: &[u8], serial: &[u8]) -> Vec<u8> {
        let mut tbs = tlv(0xa0, &tlv(0x02, &[0x02])); // [0] version v3
        tbs.extend_from_slice(&tlv(0x02, serial)); // serialNumber
        tbs.extend_from_slice(&tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70]))); // signature
        tbs.extend_from_slice(&tlv(0x30, &[])); // issuer
        tbs.extend_from_slice(&tlv(0x30, &[])); // validity
        tbs.extend_from_slice(&tlv(0x30, subject)); // subject
        tbs.extend_from_slice(&ed25519_spki(key));
        let mut cert = tlv(0x30, &tbs);
        let mut outer = cert.clone();
        outer.extend_from_slice(&tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])));
        outer.extend_from_slice(&tlv(0x03, &[0x00; 65]));
        cert = tlv(0x30, &outer);
        cert
    }

    #[test]
    fn spki_extraction_finds_the_key() {
        let key = [0xabu8; 32];
        let der = certificate(&key, &[], &[0x01]);
        assert_eq!(spki_ed25519(&der), Some(key));
        assert_eq!(spki_ed25519(&der[..der.len() - 40]), None);
        assert_eq!(spki_ed25519(&[]), None);
        assert_eq!(spki_ed25519(&[0x30, 0x00]), None);
    }

    #[test]
    fn a_key_planted_ahead_of_the_spki_is_not_the_certificates_key() {
        let attacker = [0x11u8; 32];
        let victim = [0x22u8; 32];
        // Exactly the byte pattern RFC 8410 fixes for an Ed25519 SPKI,
        // planted where the requester controls the encoding: once in an
        // attribute value inside `subject`, once inside `serialNumber`.
        let mut planted = vec![0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        planted.extend_from_slice(&victim);

        let der = certificate(&attacker, &tlv(0x13, &planted), &[0x01]);
        assert_eq!(
            spki_ed25519(&der),
            Some(attacker),
            "the key must come from the SPKI, never from the subject"
        );

        let mut serial = vec![0x01];
        serial.extend_from_slice(&planted);
        let der = certificate(&attacker, &[], &serial);
        assert_eq!(spki_ed25519(&der), Some(attacker));
    }

    #[test]
    fn a_non_ed25519_certificate_yields_nothing() {
        // Same skeleton, but the SPKI names some other algorithm.
        let alg = tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // ecPublicKey
        let mut bits = vec![0x00];
        bits.extend_from_slice(&[0x04; 64]);
        let mut spki_body = tlv(0x30, &alg);
        spki_body.extend_from_slice(&tlv(0x03, &bits));
        let mut tbs = tlv(0xa0, &tlv(0x02, &[0x02]));
        tbs.extend_from_slice(&tlv(0x02, &[0x01]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &spki_body));
        let der = tlv(0x30, &tlv(0x30, &tbs));
        assert_eq!(spki_ed25519(&der), None);
    }

    #[test]
    fn v1_certificates_have_no_version_field() {
        let key = [0x33u8; 32];
        let mut tbs = tlv(0x02, &[0x01]); // serialNumber, no [0] version
        tbs.extend_from_slice(&tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&tlv(0x30, &[]));
        tbs.extend_from_slice(&ed25519_spki(&key));
        let der = tlv(0x30, &tlv(0x30, &tbs));
        assert_eq!(spki_ed25519(&der), Some(key));
    }

    #[test]
    fn lengths_must_be_definite_and_minimal() {
        // Indefinite length, and a long form that should have been short.
        assert!(der_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(der_tlv(&[0x30, 0x81, 0x01, 0xff]).is_none());
        // Trailing garbage after the certificate is not a certificate.
        let mut der = certificate(&[0x44u8; 32], &[], &[0x01]);
        der.push(0x00);
        assert_eq!(spki_ed25519(&der), None);
    }
}
