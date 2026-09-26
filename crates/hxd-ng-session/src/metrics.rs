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
//! as the rest of this layer reads it. A request that names a forwarded
//! client the layer does not believe — a proxy that is not in
//! `trusted_proxies` — is refused outright: that proxy is most likely on
//! this same host, so the socket's loopback address would otherwise let
//! the whole internet through it.

use std::net::{IpAddr, SocketAddr};

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

pub(crate) fn scrape(
    req: &Request<Incoming>,
    peer: SocketAddr,
    client: SocketAddr,
    source: &dyn MetricsSource,
    ctx: &NgCtx,
) -> Response<Full<Bytes>> {
    let via_trusted = ctx.cfg.trusted_proxies.contains(peer.ip());
    let forwarded = FORWARDING.iter().any(|h| req.headers().contains_key(*h));
    if (forwarded && !via_trusted) || !source.allows(client.ip()) {
        return text(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "forbidden".into(),
        );
    }
    text(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        source.render(),
    )
}

fn text(status: StatusCode, mime: &'static str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, mime)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
