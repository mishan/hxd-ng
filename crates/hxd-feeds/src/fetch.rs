//! The fetch (`docs/news-feeds.md` §4).
//!
//! **The address connected to is an address checked.** As the push
//! sender's (`docs/webpush-gateway.md` §6): each connection resolves its
//! host once, refuses the host if any answer is not public, and connects
//! to those answers and nothing else, so a name server cannot answer the
//! check one way and the connect another. Every hop of a redirect is a
//! new connection and is checked the same way: the operator chose the
//! URL, but the feed's host chooses where it redirects. A feed whose
//! configured URL is itself on the local network is the operator's to
//! choose and is fetched unchecked. There is no pool and no resolver but
//! this one, and the environment's proxy variables are never read.

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hxd_core::push::endpoint::is_public;
use hyper::header::{
    HeaderValue, ACCEPT, ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, ETAG, HOST,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, RETRY_AFTER, USER_AGENT,
};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

const MAX_REDIRECTS: usize = 5;

/// The longest `Retry-After` believed: a server asking for more is asked
/// again after this.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(6 * 3600);

/// How one fetch is made.
#[derive(Clone, Debug)]
pub struct FetchConfig {
    /// For the whole fetch: every hop, and the body read to its end.
    pub timeout: Duration,
    /// The body's limit after decompression.
    pub max_bytes: usize,
    /// `http://host:port`, connected to unchecked: what a name resolves
    /// to behind it is the proxy's business.
    pub proxy: Option<String>,
    pub user_agent: String,
}

/// What makes the next fetch conditional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub enum Fetched {
    NotModified,
    Body {
        bytes: Vec<u8>,
        validators: Validators,
        /// Where a permanent redirect says the feed now lives, for the
        /// operator to read in the log. Never followed next time.
        moved_to: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum FetchError {
    BadUrl(String),
    /// The host is, or resolves to, an address that is not public.
    AddressRefused,
    Unresolvable,
    /// A redirect from `https` to `http`.
    Downgrade,
    TooManyRedirects,
    TooLarge,
    Timeout,
    Status {
        code: u16,
        /// From a `429` or `503`, in seconds.
        retry_after: Option<Duration>,
    },
    Transport(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::BadUrl(e) => write!(f, "bad URL: {e}"),
            FetchError::AddressRefused => f.write_str("address is not public"),
            FetchError::Unresolvable => f.write_str("host does not resolve"),
            FetchError::Downgrade => f.write_str("redirect from https to http"),
            FetchError::TooManyRedirects => f.write_str("too many redirects"),
            FetchError::TooLarge => f.write_str("body too large"),
            FetchError::Timeout => f.write_str("timed out"),
            FetchError::Status { code, .. } => write!(f, "HTTP {code}"),
            FetchError::Transport(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for FetchError {}

fn transport(e: impl fmt::Display) -> FetchError {
    FetchError::Transport(e.to_string())
}

/// Where names resolve and connections go. The real one asks the
/// system; a test's answers what it likes, so a host can be public to
/// the check while the connection lands on a loopback test server.
pub(crate) trait Net: Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream>;
}

struct SystemNet;

impl Net for SystemNet {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// GET `url`, conditionally on `v`.
pub async fn fetch(cfg: &FetchConfig, url: &str, v: &Validators) -> Result<Fetched, FetchError> {
    fetch_with(&SystemNet, cfg, url, v).await
}

pub(crate) async fn fetch_with<N: Net>(
    net: &N,
    cfg: &FetchConfig,
    url: &str,
    v: &Validators,
) -> Result<Fetched, FetchError> {
    tokio::time::timeout(cfg.timeout, follow(net, cfg, url, v))
        .await
        .unwrap_or(Err(FetchError::Timeout))
}

/// A URL this fetches from: absolute `http` or `https` with a host and
/// no userinfo.
fn checked(url: Url) -> Result<Url, FetchError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(FetchError::BadUrl(format!("{} is not http", url.scheme())));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FetchError::BadUrl("userinfo".into()));
    }
    if url.host().is_none() {
        return Err(FetchError::BadUrl("no host".into()));
    }
    Ok(url)
}

/// Where a `Location` from `from` leads, if it may be followed.
fn redirect(from: &Url, location: &str) -> Result<Url, FetchError> {
    let to = checked(
        from.join(location)
            .map_err(|e| FetchError::BadUrl(e.to_string()))?,
    )?;
    if from.scheme() == "https" && to.scheme() == "http" {
        return Err(FetchError::Downgrade);
    }
    Ok(to)
}

enum Answer {
    NotModified,
    Body(Vec<u8>, Validators),
    Redirect { permanent: bool, location: String },
}

async fn follow<N: Net>(
    net: &N,
    cfg: &FetchConfig,
    url: &str,
    v: &Validators,
) -> Result<Fetched, FetchError> {
    let proxy = match &cfg.proxy {
        Some(p) => Some(proxy_url(p)?),
        None => None,
    };
    let mut url = checked(Url::parse(url).map_err(|e| FetchError::BadUrl(e.to_string()))?)?;
    let (local, mut pinned) = classify(net, &url, proxy.is_some()).await;
    let check = !local;
    let mut moved_to = None;
    let mut permanent_so_far = true;
    for hop in 0..=MAX_REDIRECTS {
        match get(net, cfg, proxy.as_ref(), &url, v, check, pinned.take()).await? {
            Answer::NotModified => return Ok(Fetched::NotModified),
            Answer::Body(bytes, validators) => {
                return Ok(Fetched::Body {
                    bytes,
                    validators,
                    moved_to,
                })
            }
            Answer::Redirect {
                permanent,
                location,
            } => {
                if hop == MAX_REDIRECTS {
                    break;
                }
                url = redirect(&url, &location)?;
                // Only a chain that is permanent from the configured URL
                // says where that URL has gone.
                permanent_so_far &= permanent;
                if permanent_so_far {
                    moved_to = Some(url.to_string());
                }
            }
        }
    }
    Err(FetchError::TooManyRedirects)
}

fn proxy_url(p: &str) -> Result<Url, FetchError> {
    let url = Url::parse(p).map_err(|e| FetchError::BadUrl(format!("proxy: {e}")))?;
    if url.scheme() != "http" || url.host().is_none() {
        return Err(FetchError::BadUrl("proxy is not http://host:port".into()));
    }
    Ok(url)
}

/// Is the configured URL on the local network: a literal non-public
/// address, or a name every answer for which is one? For a name, the
/// answers are returned too, and the first hop connects to them: a
/// second lookup could answer otherwise, and a name server that called
/// itself local for the check and public for the connect would have its
/// redirects followed unchecked. Behind a proxy, which resolves names
/// where this cannot see, only a literal is local.
async fn classify<N: Net>(net: &N, url: &Url, proxied: bool) -> (bool, Option<Vec<SocketAddr>>) {
    let port = url.port_or_known_default().unwrap_or(80);
    match (literal(url), url.host()) {
        (Some(ip), _) => (!is_public(ip), None),
        (None, Some(Host::Domain(name))) if !proxied => match net.resolve(name, port).await {
            Ok(addrs) if !addrs.is_empty() => {
                (addrs.iter().all(|a| !is_public(a.ip())), Some(addrs))
            }
            _ => (false, None),
        },
        _ => (false, None),
    }
}

fn literal(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        Host::Ipv4(a) => Some(a.into()),
        Host::Ipv6(a) => Some(a.into()),
        Host::Domain(_) => None,
    }
}

/// `host` or `[v6]`, with the port when it is not the scheme's.
fn authority(url: &Url, always_port: bool) -> String {
    let host = url.host_str().unwrap_or_default();
    match (url.port(), always_port) {
        (Some(p), _) => format!("{host}:{p}"),
        (None, true) => format!("{host}:{}", url.port_or_known_default().unwrap_or(80)),
        (None, false) => host.to_string(),
    }
}

/// The addresses `url`'s host may be reached at: a literal as it
/// stands, a name as resolved, each checked unless `check` is off.
async fn addresses<N: Net>(net: &N, url: &Url, check: bool) -> Result<Vec<SocketAddr>, FetchError> {
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs = match (literal(url), url.host()) {
        (Some(ip), _) => vec![SocketAddr::new(ip, port)],
        (None, Some(Host::Domain(name))) => net
            .resolve(name, port)
            .await
            .map_err(|_| FetchError::Unresolvable)?,
        _ => Vec::new(),
    };
    if addrs.is_empty() {
        return Err(FetchError::Unresolvable);
    }
    if check && addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(FetchError::AddressRefused);
    }
    Ok(addrs)
}

async fn connect<N: Net>(net: &N, addrs: &[SocketAddr]) -> Result<TcpStream, FetchError> {
    let mut last = String::from("no address");
    for addr in addrs {
        match net.connect(*addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(FetchError::Transport(last))
}

/// One hop: a connection of its own, one request, one answer.
async fn get<N: Net>(
    net: &N,
    cfg: &FetchConfig,
    proxy: Option<&Url>,
    url: &Url,
    v: &Validators,
    check: bool,
    pinned: Option<Vec<SocketAddr>>,
) -> Result<Answer, FetchError> {
    let https = url.scheme() == "https";
    let (tcp, absolute) = match proxy {
        None => {
            let addrs = match pinned {
                Some(addrs) if check && addrs.iter().any(|a| !is_public(a.ip())) => {
                    return Err(FetchError::AddressRefused)
                }
                Some(addrs) => addrs,
                None => addresses(net, url, check).await?,
            };
            (connect(net, &addrs).await?, false)
        }
        Some(proxy) => {
            // A name behind the proxy is resolved where this cannot see.
            if check && literal(url).is_some_and(|ip| !is_public(ip)) {
                return Err(FetchError::AddressRefused);
            }
            let mut tcp = connect(net, &addresses(net, proxy, false).await?).await?;
            if https {
                tunnel(&mut tcp, &authority(url, true)).await?;
            }
            (tcp, !https)
        }
    };
    let io: Box<dyn Io> = if https {
        let name = rustls::pki_types::ServerName::try_from(literal(url).map_or_else(
            || url.host_str().unwrap_or_default().to_owned(),
            |ip| ip.to_string(),
        ))
        .map_err(|_| FetchError::BadUrl("not a TLS server name".into()))?;
        Box::new(
            tls()
                .connect(name, tcp)
                .await
                .map_err(|e| transport(format!("TLS: {e}")))?,
        )
    } else {
        Box::new(tcp)
    };
    exchange(io, request(cfg, url, v, absolute)?, cfg.max_bytes).await
}

fn tls() -> &'static TlsConnector {
    static TLS: OnceLock<TlsConnector> = OnceLock::new();
    TLS.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(config))
    })
}

/// `CONNECT` through the proxy, read up to the end of its answer and no
/// further, since what follows is the origin's.
async fn tunnel(tcp: &mut TcpStream, authority: &str) -> Result<(), FetchError> {
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .map_err(transport)?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(transport("proxy answer too long"));
        }
        let mut b = [0u8; 1];
        if tcp.read(&mut b).await.map_err(transport)? == 0 {
            return Err(transport("proxy closed"));
        }
        head.push(b[0]);
    }
    let status = head.split(|b| *b == b' ').nth(1).unwrap_or_default();
    if status.first() != Some(&b'2') {
        return Err(transport(format!(
            "proxy refused: {}",
            String::from_utf8_lossy(status)
        )));
    }
    Ok(())
}

fn request(
    cfg: &FetchConfig,
    url: &Url,
    v: &Validators,
    absolute: bool,
) -> Result<Request<Empty<Bytes>>, FetchError> {
    let mut target = url.clone();
    target.set_fragment(None);
    let target = if absolute {
        target.to_string()
    } else {
        target[url::Position::BeforePath..].to_string()
    };
    let mut r = Request::get(target)
        .header(HOST, authority(url, false))
        .header(USER_AGENT, cfg.user_agent.as_str())
        .header(
            ACCEPT,
            "application/atom+xml, application/rss+xml, application/feed+json, \
             application/xml;q=0.9, text/xml;q=0.9, application/json;q=0.9, */*;q=0.8",
        )
        .header(ACCEPT_ENCODING, "gzip")
        .header(CONNECTION, "close");
    // A validator that is not a header value was never one this server
    // sent; the fetch goes unconditionally rather than not at all.
    let value = |s: &Option<String>| s.as_deref().and_then(|s| HeaderValue::from_str(s).ok());
    if let Some(etag) = value(&v.etag) {
        r = r.header(IF_NONE_MATCH, etag);
    }
    if let Some(lm) = value(&v.last_modified) {
        r = r.header(IF_MODIFIED_SINCE, lm);
    }
    r.body(Empty::new())
        .map_err(|e| FetchError::BadUrl(e.to_string()))
}

async fn exchange(
    io: Box<dyn Io>,
    request: Request<Empty<Bytes>>,
    max: usize,
) -> Result<Answer, FetchError> {
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(transport)?;
    // Driven here rather than spawned, so the caller's timeout bounds it
    // and dropping the fetch closes the socket.
    let mut conn = std::pin::pin!(conn);
    let mut work = std::pin::pin!(async move {
        let response = sender.send_request(request).await.map_err(transport)?;
        answer(response, max).await
    });
    tokio::select! {
        r = &mut work => r,
        c = &mut conn => {
            c.map_err(transport)?;
            work.await
        }
    }
}

fn header(r: &Response<hyper::body::Incoming>, name: hyper::header::HeaderName) -> Option<String> {
    r.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn answer(
    response: Response<hyper::body::Incoming>,
    max: usize,
) -> Result<Answer, FetchError> {
    let status = response.status().as_u16();
    if status == 304 {
        return Ok(Answer::NotModified);
    }
    if let (301 | 302 | 303 | 307 | 308, Some(location)) = (status, header(&response, LOCATION)) {
        return Ok(Answer::Redirect {
            permanent: matches!(status, 301 | 308),
            location,
        });
    }
    if !(200..300).contains(&status) {
        let retry_after = matches!(status, 429 | 503)
            .then(|| header(&response, RETRY_AFTER))
            .flatten()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER));
        return Err(FetchError::Status {
            code: status,
            retry_after,
        });
    }
    let gzip = match header(&response, CONTENT_ENCODING)
        .as_deref()
        .map(str::trim)
    {
        None | Some("") | Some("identity") => false,
        Some(e) if e.eq_ignore_ascii_case("gzip") || e.eq_ignore_ascii_case("x-gzip") => true,
        Some(e) => return Err(transport(format!("content encoding {e}"))),
    };
    let validators = Validators {
        etag: header(&response, ETAG),
        last_modified: header(&response, LAST_MODIFIED),
    };
    // The wire's bytes are held to the limit too: deflate cannot shrink
    // what it was given by more than a few bytes in a thousand, so a
    // compressed body past the limit is a body past it.
    let mut body = response.into_body();
    let mut raw = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.map_err(transport)?.into_data() {
            if raw.len() + data.len() > max {
                return Err(FetchError::TooLarge);
            }
            raw.extend_from_slice(&data);
        }
    }
    if !gzip {
        return Ok(Answer::Body(raw, validators));
    }
    let mut bytes = Vec::new();
    flate2::read::MultiGzDecoder::new(raw.as_slice())
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| transport(format!("gzip: {e}")))?;
    if bytes.len() > max {
        return Err(FetchError::TooLarge);
    }
    Ok(Answer::Body(bytes, validators))
}

#[cfg(test)]
mod tests;
