//! uniqush-push's REST API, as this gateway calls it: a form-encoded
//! `POST` and a JSON answer, over TCP with the bearer token or over the
//! Unix socket (`docs/push-notifications.md` §7).
//!
//! One connection per call, as the in-process sender makes one per push,
//! and the whole call under one timeout. What this module decides is only
//! which failures are uniqush's own: no connection, no answer in time, a
//! `5xx`, an answer that is not uniqush's JSON. Those are what
//! the breaker hears about; an answer uniqush gave, whatever its `code`,
//! is the caller's to read.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

/// The most of an answer read. `/removed` answers at most a thousand
/// entries, each well under a kilobyte; `/psps` lists every service's
/// providers, which is the larger one on a shared uniqush.
const MAX_ANSWER: usize = 16 * 1024 * 1024;

/// Where uniqush listens: `[push.uniqush] addr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    /// `http://host:port`.
    Tcp { host: String, port: u16 },
    /// `unix:/path`, as uniqush's own `addr` spells it.
    Unix(PathBuf),
}

impl Addr {
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(path) = s.strip_prefix("unix:") {
            if cfg!(not(unix)) {
                return Err(format!("{s:?}: this build has no Unix sockets"));
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(format!("{s:?}: a socket's path is absolute"));
            }
            return Ok(Addr::Unix(path));
        }
        let rest = s.strip_prefix("http://").ok_or_else(|| {
            format!("{s:?} is neither http://host:port nor unix:/path to a socket")
        })?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains(['/', '?', '#', '@']) {
            return Err(format!(
                "{s:?}: an address names a host and a port, and no path"
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (
                host,
                port.parse()
                    .map_err(|_| format!("{s:?}: {port:?} is not a port"))?,
            ),
            _ => (authority, 80),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(format!("{s:?} names no host"));
        }
        Ok(Addr::Tcp {
            host: host.to_string(),
            port,
        })
    }
}

/// Why a call has no answer to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// uniqush's own trouble: the breaker's business.
    Down(String),
    /// No answer in time. Uniqush's trouble, unless the call waits on
    /// someone else's: the caller decides.
    TimedOut(String),
    /// uniqush answered, and not with something to act on: a refused
    /// token, or a status that is not its own failure.
    Refused(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Down(e) | CallError::TimedOut(e) | CallError::Refused(e) => f.write_str(e),
        }
    }
}

#[derive(Clone)]
pub struct Client {
    addr: Addr,
    token: Option<String>,
    timeout: Duration,
}

impl Client {
    pub fn new(addr: Addr, token: Option<String>, timeout: Duration) -> Self {
        Client {
            addr,
            token,
            timeout,
        }
    }

    /// `POST` `form` to `path` and answer uniqush's JSON.
    pub async fn call(&self, path: &str, form: &[(&str, &str)]) -> Result<Value, CallError> {
        match tokio::time::timeout(self.timeout, self.exchange(path, form)).await {
            Ok(answer) => answer,
            Err(_) => Err(CallError::TimedOut(format!("{path}: timed out"))),
        }
    }

    async fn exchange(&self, path: &str, form: &[(&str, &str)]) -> Result<Value, CallError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let host = match &self.addr {
            Addr::Tcp { host, port } if host.contains(':') => format!("[{host}]:{port}"),
            Addr::Tcp { host, port } => format!("{host}:{port}"),
            Addr::Unix(_) => "localhost".to_string(),
        };
        let mut request = Request::post(path)
            .header(HOST, host)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(CONTENT_LENGTH, body.len());
        if let Some(token) = &self.token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| CallError::Refused(e.to_string()))?;
        let down = |e: std::io::Error| CallError::Down(format!("{path}: {e}"));
        match &self.addr {
            Addr::Tcp { host, port } => {
                let stream = tokio::net::TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(down)?;
                exchange_on(stream, request, path).await
            }
            #[cfg(unix)]
            Addr::Unix(socket) => {
                let stream = tokio::net::UnixStream::connect(socket)
                    .await
                    .map_err(down)?;
                exchange_on(stream, request, path).await
            }
            #[cfg(not(unix))]
            Addr::Unix(_) => Err(CallError::Down("no Unix sockets here".into())),
        }
    }
}

async fn exchange_on<S>(
    stream: S,
    request: Request<Full<Bytes>>,
    path: &str,
) -> Result<Value, CallError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let down = |e: String| CallError::Down(format!("{path}: {e}"));
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| down(e.to_string()))?;
    // Driven here rather than spawned, so the caller's timeout bounds the
    // connection as well as the answer. A connection that closes behind
    // its answer has delivered it, so either half finishing first is
    // waited out on the other.
    let mut conn = std::pin::pin!(conn);
    let mut closed = false;
    let mut send = std::pin::pin!(sender.send_request(request));
    let response = tokio::select! {
        r = &mut send => r,
        _ = &mut conn => {
            closed = true;
            send.as_mut().await
        }
    }
    .map_err(|e| down(e.to_string()))?;
    let status = response.status();
    let mut collect = std::pin::pin!(Limited::new(response.into_body(), MAX_ANSWER).collect());
    let body = if closed {
        collect.as_mut().await
    } else {
        tokio::select! {
            b = &mut collect => b,
            _ = &mut conn => collect.as_mut().await,
        }
    }
    .map_err(|e| down(e.to_string()))?
    .to_bytes();
    if status.as_u16() == 401 {
        return Err(CallError::Refused(format!(
            "{path}: uniqush refused the token; check [push.uniqush] token_file"
        )));
    }
    if status.is_server_error() {
        return Err(down(format!("HTTP {status}")));
    }
    // A failing `/health` is a 503, uniqush's own trouble above.
    if !status.is_success() {
        return Err(CallError::Refused(format!("{path}: HTTP {status}")));
    }
    serde_json::from_slice(&body).map_err(|_| down("the answer is not uniqush's".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_a_host_and_port_or_a_socket() {
        assert_eq!(
            Addr::parse("http://127.0.0.1:9898").unwrap(),
            Addr::Tcp {
                host: "127.0.0.1".into(),
                port: 9898
            }
        );
        assert_eq!(
            Addr::parse("http://[::1]:9898/").unwrap(),
            Addr::Tcp {
                host: "::1".into(),
                port: 9898
            }
        );
        #[cfg(unix)]
        assert_eq!(
            Addr::parse("unix:/run/uniqush/uniqush-push.sock").unwrap(),
            Addr::Unix("/run/uniqush/uniqush-push.sock".into())
        );
        for refused in [
            "localhost:9898",
            "https://uniqush.example:9898",
            "http://localhost:9898/push",
            "unix:relative.sock",
            "http://:9898",
        ] {
            assert!(Addr::parse(refused).is_err(), "{refused}");
        }
    }
}
