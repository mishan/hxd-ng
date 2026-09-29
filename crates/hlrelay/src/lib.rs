//! A relay (`docs/hotline-ng-auth.md` §10.2): a WebSocket front for a
//! server that speaks only the classic protocol, so that a browser —
//! which cannot open a TCP socket — can reach it.
//!
//! | route | |
//! |---|---|
//! | `GET /.well-known/hotline` | discovery (§5) |
//! | `GET /trtp` | upgrade → a TCP connection to the server's port (§7.3) |
//! | `GET /htxf` | upgrade → a TCP connection to its transfer port (§7.4) |
//!
//! It knows nothing about what it carries. Each socket's bytes are
//! copied to a fresh TCP connection and back, so a handshake, a login, a
//! HOPE negotiation and a transfer all happen between the client and the
//! server as they would on TCP. One socket is one connection: a transfer
//! opens its own socket, as a classic client opens its own connection to
//! the port after the server's.
//!
//! What it adds is exactly what the server's own ports already offer to
//! anyone who can reach them, which is why it can run without
//! authenticating (§10.2): it reaches one server, on two ports, and
//! nothing else. It does not terminate TLS; a reverse proxy in front of
//! it does, as one does in front of hxd-ng's ng listener.
//!
//! What it spends is bounded three ways: sockets relayed at once, HTTP
//! connections not yet upgraded, and connections held by any one client
//! address (`addr`), which is the socket's peer or, behind a proxy the
//! operator trusts, the address that proxy forwarded.

mod addr;

pub use addr::{limit_key, ForwardedHeader, TrustedProxies};

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, AUTHORIZATION, CACHE_CONTROL,
    CONTENT_TYPE,
};
use hyper::{Method, Request, Response, StatusCode};
use hyper_tungstenite::tungstenite::protocol::WebSocketConfig;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

type Resp = Response<Full<Bytes>>;

/// Where discovery is served. §5 fixes the path; a client finds it on the
/// classic port plus 200, or on 443.
pub const DISCOVERY_PATH: &str = "/.well-known/hotline";

/// What one relay fronts, and how much of itself it will spend doing so.
#[derive(Debug, Clone)]
pub struct Config {
    /// The classic server's control port, as `host:port`. Resolved on
    /// every connection, so a name that moves (a container's) follows.
    pub upstream: String,
    /// Its transfer port — by convention the one after `upstream`'s.
    /// `None` serves no `/htxf`, for a server that has no transfers.
    pub transfer: Option<String>,
    /// The server's name, for discovery. A relay cannot ask the server
    /// for it: a classic server says its name only to a client that has
    /// logged in. [`DEFAULT_NAME`] unless set, never the upstream's
    /// address, which is often one the public was not meant to see.
    pub name: String,
    /// The most sockets relayed at once, control and transfer together.
    pub max_connections: usize,
    /// The most HTTP connections accepted and not yet upgraded, which a
    /// client holds for as long as the header timeout lets it. Past it a
    /// connection is closed unanswered.
    pub max_pending: usize,
    /// The most connections one client address may hold at once, relayed
    /// or not yet upgraded; 0 is no limit. See [`limit_key`] for what
    /// counts as one address.
    pub max_per_address: usize,
    /// Proxies whose forwarded-address header is believed.
    pub trusted_proxies: TrustedProxies,
    /// Which header those proxies write the client's address into.
    pub forwarded_header: ForwardedHeader,
    /// How long a connection to the server may take before the upgrade
    /// is refused.
    pub connect_timeout: Duration,
    /// How long a client may take to send its request head.
    pub header_timeout: Duration,
}

impl Config {
    pub fn new(upstream: impl Into<String>) -> Self {
        let upstream = upstream.into();
        Config {
            transfer: transfer_of(&upstream),
            name: DEFAULT_NAME.into(),
            upstream,
            max_connections: 512,
            max_pending: 128,
            max_per_address: 16,
            trusted_proxies: TrustedProxies::default(),
            forwarded_header: ForwardedHeader::default(),
            connect_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
        }
    }
}

/// The name discovery gives when the operator gives none.
pub const DEFAULT_NAME: &str = "hlrelay";

/// The port after `host:port`'s, where a classic server takes transfers.
pub fn transfer_of(upstream: &str) -> Option<String> {
    let (host, port) = upstream.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(format!("{host}:{}", port.checked_add(1)?))
}

#[derive(Clone)]
struct Ctx {
    cfg: Arc<Config>,
    /// One permit per relayed socket, held until both directions end.
    slots: Arc<Semaphore>,
    /// One permit per HTTP connection until it upgrades or ends.
    pending: Arc<Semaphore>,
    /// Each client address's connections, pending and relayed.
    per_addr: Arc<addr::AddrLimit>,
}

/// The place a connection holds in its address's count from the moment
/// it is accepted, handed to the relayed socket when it upgrades. Empty
/// for a connection from a trusted proxy, whose client is known only once
/// its request has been read.
type HeldPermit = Arc<Mutex<Option<addr::AddrPermit>>>;

/// Accept on `listener`, relaying each connection. The same as
/// [`serve_all`] with one listener.
pub async fn serve(listener: TcpListener, cfg: Config) {
    serve_all(vec![listener], cfg).await
}

/// Accept on every one of `listeners`, relaying each connection. The
/// limits in `cfg` are the relay's, not each listener's: every listener
/// draws on one count of relayed sockets, one of pending connections and
/// one per address, so a client that reaches the relay on two of them is
/// the same client, and a second `--listen` does not double what the
/// operator said the relay may spend.
pub async fn serve_all(listeners: Vec<TcpListener>, cfg: Config) {
    let ctx = Ctx {
        slots: Arc::new(Semaphore::new(cfg.max_connections)),
        pending: Arc::new(Semaphore::new(cfg.max_pending)),
        per_addr: addr::AddrLimit::new(cfg.max_per_address),
        cfg: Arc::new(cfg),
    };
    let tasks: Vec<_> = listeners
        .into_iter()
        .map(|listener| tokio::spawn(accept_loop(listener, ctx.clone())))
        .collect();
    for task in tasks {
        let _ = task.await;
    }
}

async fn accept_loop(listener: TcpListener, ctx: Ctx) {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of descriptors, most likely: back off rather than
                // spin on an accept that will fail again at once.
                warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Refusals here close the connection unanswered: answering would
        // mean holding it open to read a request, which is what a flood
        // of them wants.
        let Ok(pending) = ctx.pending.clone().try_acquire_owned() else {
            debug!(%peer, "refusing a connection: at max_pending");
            continue;
        };
        let held = if ctx.cfg.trusted_proxies.contains(peer.ip()) {
            None
        } else {
            match ctx.per_addr.try_acquire(peer.ip()) {
                Some(p) => Some(p),
                None => {
                    debug!(%peer, "refusing a connection: at max_per_address");
                    continue;
                }
            }
        };
        let held = Arc::new(Mutex::new(held));
        tokio::spawn(connection(sock, peer, ctx.clone(), pending, held));
    }
}

async fn connection(
    sock: TcpStream,
    peer: SocketAddr,
    ctx: Ctx,
    // Held until the connection upgrades or ends: once it has upgraded,
    // the relayed socket is counted by `slots` instead.
    _pending: tokio::sync::OwnedSemaphorePermit,
    held: HeldPermit,
) {
    let _ = sock.set_nodelay(true);
    let head_timeout = ctx.cfg.header_timeout;
    // A request in flight may be dialing the server; winding down waits
    // for it that long, and for its answer to be written no longer than
    // a request head may take to arrive.
    let wind_down_bound = ctx.cfg.connect_timeout + head_timeout;
    let gate = Arc::new(Gate::default());
    let svc = {
        let gate = gate.clone();
        hyper::service::service_fn(move |req| {
            let ctx = ctx.clone();
            let held = held.clone();
            // Marked as the request is handed over, not when its future is
            // first polled, so there is no moment where it is neither.
            let busy = Busy::start(&gate);
            async move {
                let resp = if busy.gate.closing.load(Ordering::SeqCst) {
                    // Only a request whose head was still arriving at the
                    // deadline gets here. hyper has been told to close the
                    // connection, and so will add `Connection: close`,
                    // which spoils an upgrade: refuse it plainly instead.
                    plain(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "this connection's time is up; open another",
                    )
                } else {
                    route(req, peer, ctx, held).await
                };
                if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                    busy.gate.upgraded.store(true, Ordering::SeqCst);
                }
                drop(busy);
                Ok::<_, std::convert::Infallible>(resp)
            }
        })
    };
    // hyper's header timeout does nothing without a timer, and without it
    // a client that opens a connection and says nothing holds a task.
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(head_timeout)
        .serve_connection(TokioIo::new(sock), svc)
        .with_upgrades();
    let mut conn = std::pin::pin!(conn);
    // The header timeout bounds each request, and the wait for the next;
    // this bounds the connection. A client wants a request or two on it
    // (discovery, then the upgrade) and gets that long to make them, so
    // one that keeps asking cannot hold a pending place forever.
    let ended = tokio::select! {
        ended = conn.as_mut() => Some(ended),
        () = tokio::time::sleep(head_timeout) => None,
    };
    let ended = match ended {
        Some(ended) => ended,
        None => {
            let wind_down = async {
                // hyper's graceful shutdown closes an idle connection at
                // once, but on one with a request in flight it turns
                // keep-alive off, and then writes `Connection: close`
                // over the `Connection: Upgrade` of a 101, which no client
                // accepts. An upgrade whose dial straddles the deadline
                // would be lost to it. So the request in flight is
                // answered first, with the connection left as it is.
                // The service runs inside the connection's poll, so a
                // request that finishes is seen here as soon as it does,
                // with its answer's head already written.
                let ended = std::future::poll_fn(|cx| match conn.as_mut().poll(cx) {
                    Poll::Ready(ended) => Poll::Ready(Some(ended)),
                    Poll::Pending if gate.busy.load(Ordering::SeqCst) => Poll::Pending,
                    Poll::Pending => Poll::Ready(None),
                })
                .await;
                if let Some(ended) = ended {
                    return ended;
                }
                gate.closing.store(true, Ordering::SeqCst);
                // An answered upgrade ends the connection by itself, as
                // its socket is handed over.
                if !gate.upgraded.load(Ordering::SeqCst) {
                    conn.as_mut().graceful_shutdown();
                }
                conn.as_mut().await
            };
            match tokio::time::timeout(wind_down_bound, wind_down).await {
                Ok(ended) => ended,
                Err(_) => {
                    debug!(%peer, "http connection dropped: it did not wind down");
                    return;
                }
            }
        }
    };
    if let Err(e) = ended {
        debug!(%peer, "http connection ended: {e}");
    }
}

/// What a connection's service tells the task that drives it.
#[derive(Default)]
struct Gate {
    /// A request is being answered.
    busy: AtomicBool,
    /// An upgrade has been answered.
    upgraded: AtomicBool,
    /// The connection's time is up; a request that still arrives is
    /// refused.
    closing: AtomicBool,
}

/// A request in flight, until it is answered or dropped.
struct Busy {
    gate: Arc<Gate>,
}

impl Busy {
    fn start(gate: &Arc<Gate>) -> Self {
        gate.busy.store(true, Ordering::SeqCst);
        Busy { gate: gate.clone() }
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.gate.busy.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy)]
enum Port {
    Control,
    Transfer,
}

async fn route(mut req: Request<Incoming>, peer: SocketAddr, ctx: Ctx, held: HeldPermit) -> Resp {
    let path = req.uri().path().to_owned();
    if hyper_tungstenite::is_upgrade_request(&req) {
        let port = match path.as_str() {
            "/trtp" => Port::Control,
            "/htxf" if ctx.cfg.transfer.is_some() => Port::Transfer,
            _ => return plain(StatusCode::NOT_FOUND, "no such WebSocket path"),
        };
        let client = addr::client_addr(
            req.headers(),
            peer.ip(),
            &ctx.cfg.trusted_proxies,
            ctx.cfg.forwarded_header,
        );
        return upgrade(&mut req, peer, client, ctx, held, port).await;
    }
    match (req.method(), path.as_str()) {
        (&Method::GET, DISCOVERY_PATH) => cors(discovery(&ctx.cfg)),
        (&Method::OPTIONS, DISCOVERY_PATH) => cors(preflight()),
        _ => plain(StatusCode::NOT_FOUND, "not found"),
    }
}

/// §5, for a relay that does not authenticate: no server key, no
/// identity endpoints, and `ng.trtp` without `ng.ws` — which is how a
/// client knows to speak the classic protocol inside the socket.
fn discovery(cfg: &Config) -> Resp {
    let mut ng = json!({ "trtp": "/trtp" });
    if cfg.transfer.is_some() {
        ng["htxf"] = json!("/htxf");
    }
    let doc = json!({
        "v": 1,
        "name": cfg.name,
        "server_key": null,
        "ng": ng,
        "identity": { "enabled": false },
        "registrar": null,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        // A client reads it once per connection (§5); an operator who
        // changes the relay should not wait long for it to be seen.
        .header(CACHE_CONTROL, "max-age=300")
        .body(Full::new(Bytes::from(doc.to_string())))
        .unwrap()
}

/// `*`, as on hxd-ng's discovery: nothing here is authenticated by
/// anything ambient, so an allow-list would protect nothing, and a page
/// served from anywhere must be able to read it.
fn cors(mut resp: Resp) -> Resp {
    resp.headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp
}

fn preflight() -> Resp {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "content-type")
        .header(ACCESS_CONTROL_MAX_AGE, "86400")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn plain(status: StatusCode, text: &'static str) -> Resp {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(text.as_bytes())))
        .unwrap()
}

/// Whether the upgrade carries a transport token (§7.1), in either place
/// a client may put one.
fn presents_token(req: &Request<Incoming>) -> bool {
    req.headers().contains_key(AUTHORIZATION)
        || req
            .uri()
            .query()
            .is_some_and(|q| q.split('&').any(|kv| kv.starts_with("token=")))
}

/// Relay one socket. `peer` is the socket's; `client` is who it is for,
/// which differs only behind a trusted proxy, and is what is logged and
/// what the per-address limit counts.
async fn upgrade(
    req: &mut Request<Incoming>,
    peer: SocketAddr,
    client: IpAddr,
    ctx: Ctx,
    held: HeldPermit,
    port: Port,
) -> Resp {
    // The socket's own address, with its port, unless a proxy forwarded
    // it, in which case both.
    let who = if client == peer.ip() {
        peer.to_string()
    } else {
        format!("{client} via {peer}")
    };
    // A client that presented a token believes it authenticated. This
    // relay redeems none, and upgrading it anyway would tell it otherwise
    // only by implication: §7.1's rule, that a token which doesn't work
    // is refused rather than silently ignored, holds here too.
    if presents_token(req) {
        return plain(
            StatusCode::UNAUTHORIZED,
            "this relay does not authenticate; open the socket without a token",
        );
    }
    // hxd-ng's limits, so a client written against one works on the other.
    let config = WebSocketConfig {
        max_message_size: Some(256 * 1024),
        max_frame_size: Some(256 * 1024),
        ..Default::default()
    };
    let (response, websocket) = match hyper_tungstenite::upgrade(&mut *req, Some(config)) {
        Ok(v) => v,
        Err(e) => {
            debug!(client = %who, "bad upgrade request: {e}");
            return plain(StatusCode::BAD_REQUEST, "bad upgrade");
        }
    };
    // The slot first: a refusal here must leave the connection's place in
    // its address's count where it was, or a connection kept alive past
    // its refusal would hold a pending place while counting for nothing.
    let Ok(permit) = ctx.slots.clone().try_acquire_owned() else {
        warn!(client = %who, "refusing a socket: at max_connections");
        return plain(StatusCode::SERVICE_UNAVAILABLE, "relay is full");
    };
    // A direct client was counted when it was accepted, and that place
    // becomes the socket's. One behind a proxy is counted now, when its
    // address is known.
    let taken = held.lock().unwrap().take();
    let from_held = taken.is_some();
    let addr_permit = match taken {
        Some(p) => p,
        None => match ctx.per_addr.try_acquire(client) {
            Some(p) => p,
            None => {
                warn!(client = %who, "refusing a socket: at max_per_address");
                return plain(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many connections from your address",
                );
            }
        },
    };
    // The server is dialed before the upgrade is answered, so that a
    // server that is down is a 502 the client can read rather than a
    // socket that opens and closes at once.
    let target = match port {
        Port::Control => ctx.cfg.upstream.as_str(),
        Port::Transfer => ctx.cfg.transfer.as_deref().expect("routed only when set"),
    };
    let dialed = tokio::time::timeout(ctx.cfg.connect_timeout, TcpStream::connect(target)).await;
    let outcome = match dialed {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            warn!(client = %who, target, "server refused: {e}");
            Err(plain(
                StatusCode::BAD_GATEWAY,
                "the server is not answering",
            ))
        }
        Err(_) => {
            warn!(client = %who, target, "server connect timed out");
            Err(plain(
                StatusCode::GATEWAY_TIMEOUT,
                "the server is not answering",
            ))
        }
    };
    let upstream = match outcome {
        Ok(s) => s,
        Err(resp) => {
            // The connection lives on, so the place it came with goes
            // back to it.
            if from_held {
                *held.lock().unwrap() = Some(addr_permit);
            }
            return resp;
        }
    };
    let _ = upstream.set_nodelay(true);
    tokio::spawn(async move {
        let _permits = (permit, addr_permit);
        let ws = match websocket.await {
            Ok(ws) => ws,
            Err(e) => {
                debug!(client = %who, "upgrade failed: {e}");
                return;
            }
        };
        info!(client = %who, ?port, "relaying");
        let mut client = hl_tunnel::WsByteStream::new(ws);
        let mut server = upstream;
        match tokio::io::copy_bidirectional(&mut client, &mut server).await {
            Ok((up, down)) => info!(client = %who, ?port, up, down, "closed"),
            Err(e) => info!(client = %who, ?port, "closed: {e}"),
        }
    });
    let (parts, _) = response.into_parts();
    Response::from_parts(parts, Full::new(Bytes::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transfer_port_is_the_next_one() {
        assert_eq!(
            transfer_of("hl.example:5500").as_deref(),
            Some("hl.example:5501")
        );
        assert_eq!(transfer_of("[::1]:5500").as_deref(), Some("[::1]:5501"));
        assert_eq!(transfer_of("hl.example:65535"), None);
        assert_eq!(transfer_of("hl.example"), None);
    }
}
