//! What the ng port's HTTP layer holds one address, and everyone, to
//! (`[limits]`, `hxd_ng_session::HttpLimits`): so many connections from
//! one address and so many from everyone, whatever they carry and before
//! a byte is read; an idle keep-alive connection closed; so many
//! challenges and avatar fetches a minute from one address; and a count
//! of failed logins shared by `/identity/auth` and both wires' password
//! logins, refused past it until one is earned back.
//!
//! Each case builds a real server from a config file that takes loopback
//! off the exempt list, which is what makes the test's own address one
//! that is limited.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hl_identity::{cert, Card, DeviceCert, DeviceKey, IdentityKey, LoginProof};
use hxd_testclient::legacy;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

/// A server whose config is `sections`, with `limits` under `[limits]`
/// and loopback not exempt unless `limits` names an `exempt` of its own.
/// Accounts: `alice`, password `pw`, and the guest.
async fn start(dir: &Path, sections: &str, limits: &str) -> Server {
    let d = dir.display();
    let exempt = if limits.contains("exempt") {
        ""
    } else {
        "exempt = []\n"
    };
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n{sections}\n\
         [limits]\n{exempt}{limits}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    std::fs::write(
        dir.join("accounts/alice.toml"),
        "name = \"Alice\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n",
    )
    .unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

// --- A minimal HTTP/1.1 client ------------------------------------------

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {:?}", String::from_utf8_lossy(&self.body)))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One request on its own connection, or `None` when the server closed
/// the connection without answering.
async fn try_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Option<Reply> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    // A connection closed unanswered may already be gone by the time
    // this is written.
    if s.write_all(req.as_bytes()).await.is_err() || s.write_all(body).await.is_err() {
        return None;
    }
    let mut raw = Vec::new();
    match timeout(Duration::from_secs(5), s.read_to_end(&mut raw)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return None,
        Err(_) => panic!("{method} {path}: the server neither answered nor closed"),
    }
    if raw.is_empty() {
        return None;
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    Some(Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    })
}

async fn http(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> Reply {
    try_http(addr, method, path, &[], body)
        .await
        .unwrap_or_else(|| panic!("{method} {path} was closed unanswered"))
}

/// A connection that says nothing, and so holds its place until the
/// header timeout.
async fn idle(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

/// [`idle`], from `from` rather than whatever address the system picks:
/// any of 127/8 reaches a server on 127.0.0.1, and each is an address
/// of its own to the limits.
async fn idle_from(from: IpAddr, addr: SocketAddr) -> TcpStream {
    let s = TcpSocket::new_v4().unwrap();
    s.bind(SocketAddr::new(from, 0)).unwrap();
    s.connect(addr).await.unwrap()
}

/// Does a request from `from` get an answer, rather than being closed
/// unanswered?
async fn answered_from(from: IpAddr, addr: SocketAddr) -> bool {
    let mut s = idle_from(from, addr).await;
    let req =
        format!("GET /.well-known/hotline HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut raw = Vec::new();
    match timeout(Duration::from_secs(5), s.read_to_end(&mut raw)).await {
        Ok(Ok(_)) => raw.starts_with(b"HTTP/1.1 200"),
        Ok(Err(_)) => false,
        Err(_) => panic!("the server neither answered nor closed"),
    }
}

fn retry_after(r: &Reply) -> u64 {
    let header: u64 = r
        .header("retry-after")
        .expect("a 429 says how long to wait")
        .parse()
        .unwrap();
    assert!(
        header >= 1,
        "never zero: that is an invitation to ask again"
    );
    header
}

// --- Connections --------------------------------------------------------

#[tokio::test]
async fn an_address_holds_so_many_connections_to_the_ng_port_whatever_they_carry() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "",
        "http_connections_per_addr = 3\nconnections_per_addr = 0\nreconnect_seconds = 0",
    )
    .await;
    // Plain HTTP that has not sent a byte, and a WebSocket: each holds a
    // place from accept.
    let first = idle(server.ng).await;
    let _second = idle(server.ng).await;
    let (_ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
        .await
        .expect("the third, a socket");
    assert!(
        try_http(server.ng, "GET", "/.well-known/hotline", &[], b"")
            .await
            .is_none(),
        "a fourth is closed unanswered"
    );
    // The classic port is counted apart.
    legacy::Client::login_at(server.legacy, &legacy::Login::guest("classic"))
        .await
        .expect("the classic port is not the ng port's count");
    // A place freed is a place taken.
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(r) = try_http(server.ng, "GET", "/.well-known/hotline", &[], b"").await {
            assert_eq!(r.status, 200);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the place never came back"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn everyone_together_holds_so_many_connections_to_the_ng_port() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "",
        "ng_connections = 2\nhttp_connections_per_addr = 0\nconnections_per_addr = 0",
    )
    .await;
    let _first = idle(server.ng).await;
    let second = idle(server.ng).await;
    assert!(
        try_http(server.ng, "GET", "/.well-known/hotline", &[], b"")
            .await
            .is_none(),
        "past the ceiling"
    );
    drop(second);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while try_http(server.ng, "GET", "/.well-known/hotline", &[], b"")
        .await
        .is_none()
    {
        assert!(tokio::time::Instant::now() < deadline, "never came back");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_exempt_address_is_kept_places_past_the_ceiling_and_no_more() {
    let td = tempfile::tempdir().unwrap();
    // Every place is held open, saying nothing, for as long as the test
    // takes to count them all, so the server must not close a silent
    // one as a slow request before then.
    let server = start(
        td.path(),
        "[server]\nlogin_timeout = 600\n",
        "exempt = [\"127.0.0.1\"]\nng_connections = 2\nhttp_connections_per_addr = 0\n\
         connections_per_addr = 0",
    )
    .await;
    let (flood, tools): (IpAddr, IpAddr) =
        ("127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap());
    // A flood fills the port...
    let _held = [
        idle_from(flood, server.ng).await,
        idle_from(flood, server.ng).await,
    ];
    assert!(!answered_from(flood, server.ng).await, "past the ceiling");
    // ...and the operator's own tools still get in, into a reserve that
    // is bounded in its turn: an exempt address can stand for many
    // clients, and the ceiling is what keeps the process inside its
    // descriptors.
    assert!(
        answered_from(tools, server.ng).await,
        "an exempt address past the ceiling"
    );
    let mut reserve = Vec::new();
    loop {
        let s = idle_from(tools, server.ng).await;
        // A place the server refused is closed at once; one it gave is
        // held open, saying nothing.
        let mut probe = [0u8; 1];
        let closed = matches!(
            timeout(Duration::from_millis(300), s.peek(&mut probe)).await,
            Ok(Ok(0) | Err(_))
        );
        if closed {
            break;
        }
        reserve.push(s);
        assert!(reserve.len() <= 64, "the reserve is not bounded");
    }
    assert!(!reserve.is_empty());
    assert!(
        !answered_from(tools, server.ng).await,
        "the reserve is full"
    );
}

#[tokio::test]
async fn an_idle_keep_alive_connection_is_closed() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "[server]\nlogin_timeout = 1\n", "").await;
    let mut s = TcpStream::connect(server.ng).await.unwrap();
    let req = format!(
        "GET /.well-known/hotline HTTP/1.1\r\nHost: {}\r\n\r\n",
        server.ng
    );
    s.write_all(req.as_bytes()).await.unwrap();
    // The answer, and then nothing more is asked: the connection is kept
    // alive only as long as the server waits for a request head.
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(got.starts_with(b"HTTP/1.1 200"), "answered first");
    assert!(
        closed.is_ok(),
        "an idle keep-alive connection was held open"
    );
}

// --- Requests -----------------------------------------------------------

/// A user with an identity, a device, a card and a certificate.
struct Person {
    dev: DeviceKey,
    card: Vec<u8>,
    cert: Vec<u8>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn person(seed: u8, name: &str) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[seed + 100; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let cert = DeviceCert::for_device(&id, &dev, now() - 5, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(&id);
    Person { dev, card, cert }
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// The challenge binding with classic credentials: the auth reply.
async fn auth_with_password(ng: SocketAddr, p: &Person, password: &str) -> Reply {
    let ch = http(ng, "POST", "/identity/challenge", b"").await;
    assert_eq!(ch.status, 200);
    let ch = ch.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let server_key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let proof = LoginProof::sign(&p.dev, &challenge, &server_key, now());
    let body = json!({
        "card": b64(&p.card),
        "device_cert": b64(&p.cert),
        "proof": b64(&proof),
        "login": "alice",
        "password": password,
    });
    try_http(
        ng,
        "POST",
        "/identity/auth",
        &[("Content-Type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await
    .expect("answered")
}

#[tokio::test]
async fn an_address_asks_for_so_many_challenges_a_minute() {
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let server = start(
        td.path(),
        &format!("[identity]\nkey = \"{d}/server.key\"\n"),
        "challenges_per_minute = 3",
    )
    .await;
    for _ in 0..3 {
        assert_eq!(
            http(server.ng, "POST", "/identity/challenge", b"")
                .await
                .status,
            200
        );
    }
    let refused = http(server.ng, "POST", "/identity/challenge", b"").await;
    assert_eq!(refused.status, 429);
    let wait = retry_after(&refused);
    assert!(wait <= 20, "a third of a minute at most: {wait}");
    assert_eq!(refused.json()["error"], "rate_limited");
    assert_eq!(refused.json()["retry_after"], wait);
    // What a page reads: the header is exposed cross-origin.
    assert_eq!(refused.header("access-control-allow-origin"), Some("*"));
}

/// An ng password login's raw reply.
async fn ng_login(ng: SocketAddr, password: &str) -> Value {
    ng_login_as(ng, "alice", password).await
}

/// An ng login's raw reply, as `login`.
async fn ng_login_as(ng: SocketAddr, login: &str, password: &str) -> Value {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{ng}/ng"))
        .await
        .unwrap();
    let login = json!({ "id": 1, "req": "login",
        "params": { "login": login, "password": password } });
    ws.send(Message::Text(login.to_string())).await.unwrap();
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("no reply")
            .unwrap()
            .unwrap();
        let Message::Text(t) = msg else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 1 {
            return v;
        }
    }
}

/// A classic password login's error text, or `None` when it succeeded.
async fn classic_login(addr: SocketAddr, password: &str) -> Option<String> {
    let login = legacy::Login {
        version: 0,
        ..legacy::Login::account("alice", "alice", password)
    };
    let mut c = legacy::Client::connect(addr).await.unwrap();
    match c.login(&login).await {
        Ok(_) => None,
        Err(hxd_testclient::Error::Refused { text, .. }) => Some(text),
        Err(e) => panic!("classic login: {e}"),
    }
}

#[tokio::test]
async fn failed_logins_on_any_wire_lock_the_address_out_until_it_earns_one_back() {
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let server = start(
        td.path(),
        &format!("[identity]\nkey = \"{d}/server.key\"\n"),
        "login_failures = 3\nlogin_failure_seconds = 2",
    )
    .await;
    let p = person(7, "Alice");

    // One wrong password on each wire, and each is only a failure.
    let r = auth_with_password(server.ng, &p, "wrong").await;
    assert_eq!(r.status, 401, "{:?}", r.json());
    assert_eq!(r.json()["error"], "login_failed");
    assert_eq!(
        classic_login(server.legacy, "wrong").await.as_deref(),
        Some("Login failed.")
    );
    let r = ng_login(server.ng, "wrong").await;
    assert_eq!(r["error"]["code"], "login_failed", "{r}");

    // Three between them, so the fourth is refused before its password
    // is looked at — the right one included — on every wire, each in
    // the shape that wire already has for a refusal.
    let refused = auth_with_password(server.ng, &p, "pw").await;
    assert_eq!(refused.status, 429);
    assert_eq!(refused.json()["error"], "rate_limited");
    assert!(retry_after(&refused) <= 2);
    let text = classic_login(server.legacy, "pw")
        .await
        .expect("refused on the classic wire");
    assert!(text.starts_with("Too many failed logins."), "{text}");
    let r = ng_login(server.ng, "pw").await;
    assert_eq!(r["error"]["code"], "rate_limited", "{r}");
    assert!(r["error"]["retry_after"].as_u64().unwrap() >= 1);

    // Then one is earned back, and the right password works.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(classic_login(server.legacy, "pw").await, None);
    let r = ng_login(server.ng, "pw").await;
    assert!(r.get("ok").is_some(), "{r}");
}

#[tokio::test]
async fn an_address_fetches_so_many_avatars_a_minute() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "[avatars]\n", "avatar_fetches_per_minute = 2").await;
    let id = "0".repeat(64);
    let path = format!("/avatars/{id}");
    // Asked without a session, so answered 401: counted all the same,
    // since the count is the address's and comes first.
    for _ in 0..2 {
        assert_ne!(http(server.ng, "GET", &path, b"").await.status, 429);
    }
    let refused = http(server.ng, "GET", &path, b"").await;
    assert_eq!(refused.status, 429);
    assert!(retry_after(&refused) <= 30);
    assert_eq!(refused.header("access-control-allow-origin"), Some("*"));
}

#[tokio::test]
async fn failed_logins_made_at_once_are_held_to_the_limit() {
    // Each password spends its failure as it is let in, not once it has
    // been found wrong: otherwise every guess in flight at once passes a
    // check none of them has failed yet, and an address gets as many as
    // it can open connections.
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let server = start(
        td.path(),
        &format!("[server]\nlogins_in_flight = 256\n[identity]\nkey = \"{d}/server.key\"\n"),
        "login_failures = 3\nlogin_failure_seconds = 600\nconnections_per_addr = 0\n\
         reconnect_seconds = 0\nhttp_connections_per_addr = 0\nchallenges_per_minute = 0",
    )
    .await;
    let p = std::sync::Arc::new(person(9, "Alice"));
    let mut guesses = tokio::task::JoinSet::new();
    for i in 0..30 {
        let (legacy, ng, p) = (server.legacy, server.ng, p.clone());
        guesses.spawn(async move {
            match i % 3 {
                0 => {
                    let text = classic_login(legacy, "wrong").await.expect("refused");
                    if text == "Login failed." {
                        true
                    } else {
                        assert!(text.starts_with("Too many failed logins."), "{text}");
                        false
                    }
                }
                1 => {
                    let r = ng_login(ng, "wrong").await;
                    match r["error"]["code"].as_str() {
                        Some("login_failed") => true,
                        Some("rate_limited") => false,
                        _ => panic!("{r}"),
                    }
                }
                _ => {
                    let r = auth_with_password(ng, &p, "wrong").await;
                    match r.status {
                        401 => true,
                        429 => false,
                        _ => panic!("{} {:?}", r.status, r.json()),
                    }
                }
            }
        });
    }
    let mut checked = 0;
    while let Some(r) = guesses.join_next().await {
        checked += usize::from(r.unwrap());
    }
    assert_eq!(checked, 3, "passwords checked, of the guesses made at once");
    // And a right one is refused as well, until one is earned back.
    let text = classic_login(server.legacy, "pw")
        .await
        .expect("locked out");
    assert!(text.starts_with("Too many failed logins."), "{text}");
}

#[tokio::test]
async fn a_login_without_a_password_is_not_held_to_the_count() {
    // A guest sends no password, and makes no guess: on an address that
    // one person has locked out by guessing, everyone else there can
    // still come in as a guest.
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "",
        "login_failures = 1\nlogin_failure_seconds = 600",
    )
    .await;
    assert_eq!(
        classic_login(server.legacy, "wrong").await.as_deref(),
        Some("Login failed.")
    );
    let text = classic_login(server.legacy, "pw")
        .await
        .expect("locked out");
    assert!(text.starts_with("Too many failed logins."), "{text}");
    legacy::Client::login_at(server.legacy, &legacy::Login::guest("classic guest"))
        .await
        .expect("a classic guest is not held to the count");
    let r = ng_login_as(server.ng, "", "").await;
    assert!(r.get("ok").is_some(), "an ng guest is not held to it: {r}");
    // Nor does a guest's login count: the lockout is the guesser's
    // failure alone, and still stands.
    let r = ng_login(server.ng, "pw").await;
    assert_eq!(r["error"]["code"], "rate_limited", "{r}");
}

#[tokio::test]
async fn an_auth_refused_before_its_password_is_checked_is_not_a_failed_login() {
    // A request `/identity/auth` refuses for its shape — here one with no
    // proof and no client certificate, as a buggy client or one that
    // lost its certificate on the way through a proxy sends it, again
    // and again — had its password looked at by no one, and does not
    // lock its address out.
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let server = start(
        td.path(),
        &format!("[identity]\nkey = \"{d}/server.key\"\n"),
        "login_failures = 1\nlogin_failure_seconds = 600",
    )
    .await;
    let p = person(11, "Alice");
    let body = json!({
        "card": b64(&p.card),
        "device_cert": b64(&p.cert),
        "login": "alice",
        "password": "wrong",
    });
    for origin in [None, Some("https://example.org")] {
        for _ in 0..3 {
            let mut headers = vec![("Content-Type", "application/json")];
            headers.extend(origin.map(|o| ("Origin", o)));
            let r = try_http(
                server.ng,
                "POST",
                "/identity/auth",
                &headers,
                body.to_string().as_bytes(),
            )
            .await
            .expect("answered");
            assert_eq!(r.status, 400, "{:?}", String::from_utf8_lossy(&r.body));
            assert!(
                String::from_utf8_lossy(&r.body).contains("proof is required"),
                "{:?}",
                String::from_utf8_lossy(&r.body)
            );
        }
    }
    // The one failure the address may make is still its own to make.
    let r = auth_with_password(server.ng, &p, "wrong").await;
    assert_eq!(r.status, 401, "{:?}", r.json());
    let r = auth_with_password(server.ng, &p, "pw").await;
    assert_eq!(r.status, 429, "and then it is spent");
}
