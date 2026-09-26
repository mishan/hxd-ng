//! `GET /metrics`: the server's own numbers, in Prometheus's text format
//! (`docs/metrics.md`).
//!
//! This crate knows nothing about the exporter. The binary holds it and
//! hands this layer a [`MetricsSource`], or nothing — and then the route
//! does not exist, which is what a server built without the `metrics`
//! feature always gets.
//!
//! **Who may scrape.** The numbers say how busy the server is, which
//! accounts' sessions it is holding and how long its locks take: nothing
//! a client needs and something an attacker timing a flood would like.
//! So the source decides by address, loopback only unless the operator
//! said otherwise, and the address it is asked about is the *client's*,
//! as the rest of this layer reads it. Two cases never reach that
//! question, because in both the socket's address — most likely this
//! host's own — is standing in for a client nobody named:
//!
//! - a request carrying a forwarding header from a peer that is not in
//!   `trusted_proxies`: a proxy the layer does not believe;
//! - a request from a trusted proxy that did not name a client the layer
//!   could read: no header, the other header, an obfuscated one.
//!
//! What no rule here can see is a forwarder that adds nothing at all: an
//! onion service, stunnel, a TCP-mode proxy on this host. Behind one of
//! those, loopback is everyone, and `docs/metrics.md` says so.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};

use crate::NgCtx;

pub const METRICS_PATH: &str = "/metrics";

/// Whatever holds the recorder.
pub trait MetricsSource: Send + Sync {
    /// May a scrape from `client` read the numbers?
    fn allows(&self, client: IpAddr) -> bool;
    /// The exposition text, current as of this call.
    fn render(&self) -> String;
}

/// Headers a proxy adds to say whom it is forwarding for. Any of them on
/// a request the trusted-proxy rule did not already account for means
/// the socket's address is not the client's.
const FORWARDING: &[&str] = &["forwarded", "x-forwarded-for", "x-real-ip"];

pub(crate) async fn scrape(
    req: &Request<Incoming>,
    peer: SocketAddr,
    client: SocketAddr,
    source: Arc<dyn MetricsSource>,
    ctx: &NgCtx,
) -> Response<Full<Bytes>> {
    let via_trusted = ctx.cfg.trusted_proxies.contains(peer.ip());
    let forwarded = FORWARDING.iter().any(|h| req.headers().contains_key(*h));
    // `client_addr` falls back to the socket's peer when a trusted proxy
    // named nobody it could read, so the proxy's own address standing in
    // for the client is exactly `client == peer` behind one.
    let unnamed = via_trusted && client == peer;
    if (forwarded && !via_trusted) || unnamed || !source.allows(client.ip()) {
        return text(StatusCode::FORBIDDEN, PLAIN, "forbidden".into());
    }
    // The census takes the roster lock and the process gauges read
    // `/proc`, so the render is the blocking pool's work.
    match crate::spawn_blocking("metrics", move || source.render()).await {
        Ok(body) => text(StatusCode::OK, EXPOSITION, body),
        Err(_) => text(
            StatusCode::INTERNAL_SERVER_ERROR,
            PLAIN,
            "render failed".into(),
        ),
    }
}

const PLAIN: &str = "text/plain; charset=utf-8";
const EXPOSITION: &str = "text/plain; version=0.0.4; charset=utf-8";

fn text(status: StatusCode, mime: &'static str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, mime)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
