//! The HTTPS half: RFC 8030's headers, the destination check applied to
//! the address actually connected to, and the status codes mapped to
//! [`Outcome`].
//!
//! **One resolution, and the connection goes where it said.** A name is
//! resolved once per send, every address is checked, and the TCP
//! connection is made to those checked addresses and nothing else. An
//! HTTP client that resolves the name again on its own is a DNS-rebinding
//! hole: an attacker's name server answers a public address to the check
//! and `169.254.169.254` to the connect (`docs/webpush-gateway.md` §6).
//! So there is no connector here, no pool and no resolver but this one:
//! a `TcpStream` to a vetted address, rustls over it with the endpoint's
//! host as the server name, and one hyper HTTP/1 exchange, all under the
//! one timeout. No proxy is honored for the same reason. The response
//! body is never read, and the connection is dropped with the answer, so
//! an endpoint that accepts and never hangs up costs a timeout and
//! nothing after it.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::Full;
use hyper::header::{
    HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST,
};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::Sha256;
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

use crate::endpoint;
use crate::{Outcome, Push, Transport};

/// The longest a `Retry-After` is honored for. A push service's answer
/// is a request, not an instruction, and it comes from a host the client
/// chose: a value of a century must not silence a subscription for one.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// RFC 8030's `Topic`: at most 32 characters of base64url. A collapse
/// key is a thread id or a login, which is neither short enough nor
/// private enough to send as it stands, so what travels is the head of
/// an HMAC under `key` — a secret of this server's — rather than of a
/// bare hash, which anyone who can count threads could enumerate. Same
/// key, same header; a provider that logs it learns that two pushes
/// collapse and nothing else.
pub fn topic(key: &[u8; 32], collapse: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(collapse.as_bytes());
    B64.encode(mac.finalize().into_bytes())[..32].to_string()
}

/// The real transport. Cheap to clone: the TLS configuration is shared.
#[derive(Clone)]
pub struct HttpsTransport {
    tls: TlsConnector,
    timeout: Duration,
    allow_private: bool,
}

impl HttpsTransport {
    /// Build a transport that speaks TLS, and only TLS, and follows
    /// nothing: a redirect from a push service is not a thing this
    /// obeys, because a redirect is a way to send our POST somewhere the
    /// destination check already refused.
    pub fn new(timeout: Duration, allow_private: bool) -> Result<Self, String> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(HttpsTransport {
            tls: TlsConnector::from(Arc::new(config)),
            timeout,
            allow_private,
        })
    }
}

/// Where this endpoint may be connected to: every address its host
/// resolves to, each checked, or the reason there is nowhere.
///
/// Asked per send, against the addresses actually resolved, because
/// registration's check was against a name and DNS moves: a host that
/// answered publicly last week can answer `127.0.0.1` today. A name with
/// any non-public answer is refused outright rather than filtered, since
/// a name that mixes the two is not a push service having a bad day.
async fn vetted(
    target: &endpoint::Target,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, Outcome> {
    let addrs: Vec<SocketAddr> = match target.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, target.port)],
        Err(_) => tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|_| Outcome::Unreachable(endpoint::Refused::Unresolvable.to_string()))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(Outcome::Unreachable(
            endpoint::Refused::Unresolvable.to_string(),
        ));
    }
    if !allow_private && addrs.iter().any(|a| !endpoint::is_public(a.ip())) {
        return Err(Outcome::Unreachable(
            endpoint::Refused::NotGloballyRoutable.to_string(),
        ));
    }
    Ok(addrs)
}

impl HttpsTransport {
    /// One push, start to answer. Everything in here is under the
    /// caller's timeout, name resolution included.
    async fn exchange(&self, push: &Push) -> Outcome {
        let target = match endpoint::check(&push.endpoint) {
            Ok(t) => t,
            Err(e) => return Outcome::Unreachable(format!("endpoint {e}")),
        };
        let addrs = match vetted(&target, self.allow_private).await {
            Ok(a) => a,
            Err(outcome) => return outcome,
        };
        let request = match build(push, &target) {
            Ok(r) => r,
            Err(e) => return Outcome::Unreachable(e),
        };
        let server_name = match rustls::pki_types::ServerName::try_from(target.host.clone()) {
            Ok(n) => n,
            Err(_) => return Outcome::Unreachable("not a TLS server name".into()),
        };

        // The checked addresses and no others, in the order they came.
        let mut tcp = None;
        let mut last = String::from("no address");
        for addr in &addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e.to_string(),
            }
        }
        let Some(tcp) = tcp else {
            return Outcome::Unreachable(last);
        };
        let tls = match self.tls.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => return Outcome::Unreachable(format!("TLS: {e}")),
        };
        let (mut sender, conn) =
            match hyper::client::conn::http1::handshake(TokioIo::new(tls)).await {
                Ok(pair) => pair,
                Err(e) => return Outcome::Unreachable(e.to_string()),
            };
        // The connection is driven here, beside the request, rather than
        // spawned: a spawned connection outlives the timeout that was
        // meant to bound it. Dropping both when the answer is in closes
        // the socket, and the body is never read.
        let mut conn = std::pin::pin!(conn);
        let response = tokio::select! {
            r = sender.send_request(request) => r,
            c = &mut conn => {
                return Outcome::Unreachable(match c {
                    Ok(()) => "closed before answering".into(),
                    Err(e) => e.to_string(),
                });
            }
        };
        match response {
            Err(e) => Outcome::Unreachable(e.to_string()),
            Ok(response) => outcome_of(
                response.status(),
                response
                    .headers()
                    .get(hyper::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(retry_after),
            ),
        }
    }
}

/// `Retry-After` in seconds, capped at [`MAX_RETRY_AFTER`]. The
/// HTTP-date form is not honored: a pause is the push service's request,
/// and one it cannot spell in seconds falls back to the configured
/// cooldown.
pub fn retry_after(v: &str) -> Option<Duration> {
    v.trim()
        .parse::<u64>()
        .ok()
        .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER))
}

impl Transport for HttpsTransport {
    fn post(&self, push: Push) -> Pin<Box<dyn Future<Output = Outcome> + Send>> {
        let this = self.clone();
        Box::pin(async move {
            match tokio::time::timeout(this.timeout, this.exchange(&push)).await {
                Err(_) => Outcome::Unreachable("timed out".into()),
                Ok(outcome) => outcome,
            }
        })
    }
}

/// The request, in origin form with a `Host`, as a client talking to one
/// server over its own connection sends it.
fn build(push: &Push, target: &endpoint::Target) -> Result<Request<Full<Bytes>>, String> {
    let after_scheme = &push.endpoint["https://".len()..];
    let path = match after_scheme.find(['/', '?']) {
        Some(i) => &after_scheme[i..],
        None => "/",
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    let host = match (target.host.contains(':'), target.port) {
        (true, 443) => format!("[{}]", target.host),
        (true, port) => format!("[{}]:{port}", target.host),
        (false, 443) => target.host.clone(),
        (false, port) => format!("{}:{port}", target.host),
    };
    let mut request = Request::post(path)
        .header(HOST, host)
        .header(CONTENT_ENCODING, "aes128gcm")
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, push.body.len())
        .header("TTL", push.ttl)
        .header("Urgency", push.urgency);
    if !push.topic.is_empty() {
        request = request.header("Topic", push.topic.as_str());
    }
    let authorization =
        HeaderValue::from_str(&push.authorization).map_err(|_| "a token that is not a header")?;
    request
        .header(AUTHORIZATION, authorization)
        .body(Full::new(Bytes::from(push.body.clone())))
        .map_err(|e| e.to_string())
}

/// The status table (`docs/webpush-gateway.md` §5). Written as a
/// function so it is testable without a server, because it is the part
/// that decides whether a user's device is deleted.
pub fn outcome_of(status: StatusCode, retry_after: Option<Duration>) -> Outcome {
    match status.as_u16() {
        200..=202 => Outcome::Accepted,
        404 | 410 => Outcome::Gone,
        429 => Outcome::Slow(retry_after),
        413 => Outcome::TooBig,
        500..=599 => Outcome::Failed(status.as_u16()),
        other => Outcome::Rejected(other),
    }
}

/// A transport is `Arc`-shared; this spells it once for the server.
pub fn shared(timeout: Duration, allow_private: bool) -> Result<Arc<dyn Transport>, String> {
    Ok(Arc::new(HttpsTransport::new(timeout, allow_private)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_table() {
        assert_eq!(outcome_of(StatusCode::CREATED, None), Outcome::Accepted);
        assert_eq!(outcome_of(StatusCode::OK, None), Outcome::Accepted);
        assert_eq!(outcome_of(StatusCode::ACCEPTED, None), Outcome::Accepted);
        assert_eq!(outcome_of(StatusCode::NOT_FOUND, None), Outcome::Gone);
        assert_eq!(outcome_of(StatusCode::GONE, None), Outcome::Gone);
        assert_eq!(
            outcome_of(StatusCode::TOO_MANY_REQUESTS, Some(Duration::from_secs(30))),
            Outcome::Slow(Some(Duration::from_secs(30)))
        );
        assert_eq!(
            outcome_of(StatusCode::PAYLOAD_TOO_LARGE, None),
            Outcome::TooBig
        );
        assert_eq!(
            outcome_of(StatusCode::UNAUTHORIZED, None),
            Outcome::Rejected(401),
            "a bad credential never retires a device"
        );
        assert_eq!(
            outcome_of(StatusCode::FORBIDDEN, None),
            Outcome::Rejected(403)
        );
        assert_eq!(
            outcome_of(StatusCode::INTERNAL_SERVER_ERROR, None),
            Outcome::Failed(500),
            "the provider's trouble, which the breaker hears about"
        );
    }

    #[test]
    fn a_retry_after_is_seconds_and_bounded() {
        assert_eq!(retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(
            retry_after("18446744073709551615"),
            Some(MAX_RETRY_AFTER),
            "a century is an hour"
        );
        assert_eq!(retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(retry_after("-5"), None);
    }

    #[test]
    fn the_request_is_origin_form_with_a_host() {
        let push = Push {
            endpoint: "https://push.example.net:8443/v/abc?x=1".into(),
            ttl: 60,
            urgency: "normal",
            topic: String::new(),
            authorization: "vapid t=a, k=b".into(),
            body: vec![1, 2, 3],
        };
        let target = endpoint::check(&push.endpoint).unwrap();
        let r = build(&push, &target).unwrap();
        assert_eq!(r.uri().to_string(), "/v/abc?x=1");
        assert_eq!(r.headers()[HOST], "push.example.net:8443");
        let v6 = Push {
            endpoint: "https://[2606:4700::1]/v".into(),
            ..push
        };
        let r = build(&v6, &endpoint::check(&v6.endpoint).unwrap()).unwrap();
        assert_eq!(r.headers()[HOST], "[2606:4700::1]");
    }

    /// A literal private address is refused before any connection is
    /// attempted, and a name is refused on its resolved address — the
    /// address the connection would then be made to.
    #[tokio::test]
    async fn the_destination_is_checked_where_it_is_connected() {
        let t = |url: &str| endpoint::check(url).unwrap();
        assert!(matches!(
            vetted(&t("https://127.0.0.1/v"), false).await,
            Err(Outcome::Unreachable(_))
        ));
        assert!(matches!(
            vetted(&t("https://localhost/v"), false).await,
            Err(Outcome::Unreachable(_))
        ));
        assert_eq!(
            vetted(&t("https://127.0.0.1:8443/v"), true).await.unwrap(),
            vec!["127.0.0.1:8443".parse().unwrap()],
            "the operator's own push service, on their own network"
        );
    }

    #[test]
    fn a_topic_fits_the_header_and_says_nothing() {
        let key = [3u8; 32];
        let topic = |c: &str| topic(&key, c);
        let t = topic("thread:398");
        assert_eq!(t.len(), 32);
        assert!(t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!t.contains("398"), "a provider learns nothing from it");
        assert_eq!(
            t,
            topic("thread:398"),
            "and it is stable, or it cannot collapse"
        );
        assert_ne!(t, topic("thread:399"));
        assert_ne!(
            t,
            super::topic(&[4u8; 32], "thread:398"),
            "and keyed, so it cannot be computed without the server's secret"
        );
    }
}
