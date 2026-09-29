//! The relay against stand-in servers: what it serves, what it refuses,
//! and that the bytes it carries arrive unchanged in both directions on
//! both ports. `crates/hxd/tests/relay.rs` puts a real server behind it.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hlrelay::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

const WAIT: Duration = Duration::from_secs(5);

/// A server that answers every connection with `greeting` and then
/// echoes what it is sent.
async fn echo(greeting: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                sock.write_all(greeting).await.unwrap();
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => sock.write_all(&buf[..n]).await.unwrap(),
                    }
                }
            });
        }
    });
    addr
}

async fn relay(cfg: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hlrelay::serve(listener, cfg));
    addr
}

async fn relay_to(control: SocketAddr, transfer: SocketAddr) -> SocketAddr {
    let mut cfg = Config::new(control.to_string());
    cfg.transfer = Some(transfer.to_string());
    cfg.name = "Stand-in".into();
    relay(cfg).await
}

/// A plain HTTP/1.1 request, answered with the whole response as text.
async fn http(addr: SocketAddr, method: &str, path: &str) -> String {
    try_http(addr, method, path).await.unwrap()
}

/// The same, with a connection the relay reset handed back as an error
/// rather than a panic, for a caller waiting for a place to come free.
async fn try_http(addr: SocketAddr, method: &str, path: &str) -> std::io::Result<String> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(
        format!("{method} {path} HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut out = Vec::new();
    timeout(WAIT, sock.read_to_end(&mut out))
        .await
        .expect("the relay answers or closes")?;
    Ok(String::from_utf8(out).unwrap())
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").unwrap().1
}

/// Read binary frames until `want` bytes have arrived, however they were
/// split.
async fn read_bytes<S>(ws: &mut S, want: usize) -> Vec<u8>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut got = Vec::new();
    while got.len() < want {
        match timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap() {
            Message::Binary(b) => got.extend_from_slice(&b),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
    got
}

#[tokio::test]
async fn discovery_names_the_tunnels_and_no_ng_protocol() {
    let control = echo(b"").await;
    let relay = relay_to(control, control).await;
    let resp = http(relay, "GET", "/.well-known/hotline").await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("access-control-allow-origin: *"), "{resp}");
    let doc: serde_json::Value = serde_json::from_str(body(&resp)).unwrap();
    assert_eq!(doc["v"], 1);
    assert_eq!(doc["name"], "Stand-in");
    assert_eq!(doc["ng"]["trtp"], "/trtp");
    assert_eq!(doc["ng"]["htxf"], "/htxf");
    // No `ng.ws`: that absence is what says "classic inside" (§5).
    assert!(doc["ng"].get("ws").is_none());
    assert_eq!(doc["identity"]["enabled"], false);
    assert!(doc["server_key"].is_null());

    // A page on another origin preflights before it reads it.
    let pre = http(relay, "OPTIONS", "/.well-known/hotline").await;
    assert!(pre.starts_with("HTTP/1.1 204"), "{pre}");
    assert!(pre.contains("access-control-allow-origin: *"), "{pre}");

    // Nothing else is here.
    assert!(http(relay, "GET", "/identity/challenge")
        .await
        .starts_with("HTTP/1.1 404"));
}

#[tokio::test]
async fn without_transfers_there_is_no_htxf() {
    let control = echo(b"").await;
    let mut cfg = Config::new(control.to_string());
    cfg.transfer = None;
    let relay = relay(cfg).await;
    let doc: serde_json::Value =
        serde_json::from_str(body(&http(relay, "GET", "/.well-known/hotline").await)).unwrap();
    assert!(doc["ng"].get("htxf").is_none());
    let err = tokio_tungstenite::connect_async(format!("ws://{relay}/htxf"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}

#[tokio::test]
async fn each_path_reaches_its_own_port_byte_for_byte() {
    let control = echo(b"CONTROL:").await;
    let transfer = echo(b"TRANSFER:").await;
    let relay = relay_to(control, transfer).await;

    for (path, greeting) in [("/trtp", &b"CONTROL:"[..]), ("/htxf", &b"TRANSFER:"[..])] {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{relay}{path}"))
            .await
            .unwrap();
        assert_eq!(read_bytes(&mut ws, greeting.len()).await, greeting);

        // Frame boundaries carry nothing: one message split across two
        // frames comes back whole, and every byte value survives.
        let payload: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        let (a, b) = payload.split_at(12_345);
        ws.send(Message::Binary(a.to_vec())).await.unwrap();
        ws.send(Message::Binary(b.to_vec())).await.unwrap();
        assert_eq!(read_bytes(&mut ws, payload.len()).await, payload);
        ws.close(None).await.unwrap();
    }
}

#[tokio::test]
async fn the_server_hanging_up_closes_the_socket() {
    // A server that says one thing and hangs up, as a classic server does
    // at the end of a download.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        sock.write_all(b"bye").await.unwrap();
    });
    let relay = relay_to(server, server).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut ws, 3).await, b"bye");
    loop {
        match timeout(WAIT, ws.next()).await.expect("the socket closes") {
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(other)) => panic!("unexpected frame {other:?}"),
            // The relay may drop TCP right after its close frame.
            Some(Err(_)) => break,
        }
    }
}

#[tokio::test]
async fn the_client_hanging_up_closes_the_server_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut rest = Vec::new();
        let _ = sock.read_to_end(&mut rest).await;
        tx.send(rest).unwrap();
    });
    let relay = relay_to(server, server).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    ws.send(Message::Binary(b"TRTPHOTL".to_vec()))
        .await
        .unwrap();
    ws.close(None).await.unwrap();
    let rest = timeout(WAIT, rx)
        .await
        .expect("the server sees EOF")
        .unwrap();
    assert_eq!(rest, b"TRTPHOTL");
}

#[tokio::test]
async fn a_token_is_refused_rather_than_ignored() {
    let control = echo(b"").await;
    let relay = relay_to(control, control).await;

    let err = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp?token=abc"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");

    let mut req = format!("ws://{relay}/trtp").into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", "Bearer abc".parse().unwrap());
    let err = tokio_tungstenite::connect_async(req).await.unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
}

#[tokio::test]
async fn a_server_that_is_down_is_a_502() {
    // Bind and drop, so the port is very likely closed.
    let gone = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let relay = relay_to(gone, gone).await;
    let err = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("502"), "{err}");
}

#[tokio::test]
async fn a_full_relay_refuses_the_next_socket_and_frees_the_slot() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_connections = 1;
    let relay = relay(cfg).await;

    let (mut first, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut first, 2).await, b"hi");
    let err = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");

    // Once the first is gone its slot is free again.
    first.close(None).await.unwrap();
    drop(first);
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Ok((mut ws, _)) =
            tokio_tungstenite::connect_async(format!("ws://{relay}/trtp")).await
        {
            assert_eq!(read_bytes(&mut ws, 2).await, b"hi");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the slot was never freed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Retry `ws://{relay}{path}` until it opens, for a place that is given
/// back asynchronously.
async fn reopens(relay: SocketAddr, path: &str) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Ok((mut ws, _)) =
            tokio_tungstenite::connect_async(format!("ws://{relay}{path}")).await
        {
            return read_bytes(&mut ws, 2).await;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the place was never given back"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn one_address_cannot_take_every_slot() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.transfer = Some(control.to_string());
    cfg.max_per_address = 2;
    let relay = relay(cfg).await;

    let (mut first, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut first, 2).await, b"hi");
    let (mut second, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/htxf"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut second, 2).await, b"hi");
    // A third, and even a discovery request, from the same address is
    // closed before it is read: the address's connections, pending or
    // relayed, are what is counted.
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
            .await
            .is_err()
    );
    let mut sock = TcpStream::connect(relay).await.unwrap();
    let _ = sock
        .write_all(b"GET /.well-known/hotline HTTP/1.1\r\nHost: relay\r\n\r\n")
        .await;
    let mut out = Vec::new();
    let _ = timeout(WAIT, sock.read_to_end(&mut out)).await.unwrap();
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));

    first.close(None).await.unwrap();
    drop(first);
    assert_eq!(reopens(relay, "/trtp").await, b"hi");
}

#[tokio::test]
async fn every_listener_draws_on_one_set_of_limits() {
    // A second `--listen` is another way in to the same relay, not a
    // second relay: what one address may hold is counted across both.
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_per_address = 1;
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());
    tokio::spawn(hlrelay::serve_all(vec![a, b], cfg));

    let (mut first, _) = tokio_tungstenite::connect_async(format!("ws://{a_addr}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut first, 2).await, b"hi");
    // The other listener refuses the same address: its one place is
    // taken, on the first.
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{b_addr}/trtp"))
            .await
            .is_err()
    );
    // And gives it back to that listener's clients once it is free.
    first.close(None).await.unwrap();
    drop(first);
    assert_eq!(reopens(b_addr, "/trtp").await, b"hi");
}

/// An upgrade that arrives through a proxy on loopback, on behalf of
/// `client`.
async fn via_proxy(
    relay: SocketAddr,
    client: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    let mut req = format!("ws://{relay}/trtp").into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Forwarded-For", client.parse().unwrap());
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(ws, _)| ws)
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_forwarded_address_is_limited() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_per_address = 1;
    cfg.trusted_proxies = hlrelay::TrustedProxies::parse(&["127.0.0.1"]).unwrap();
    let relay = relay(cfg).await;

    let mut a = via_proxy(relay, "198.51.100.4").await.unwrap();
    assert_eq!(read_bytes(&mut a, 2).await, b"hi");
    // The same client again is refused, legibly this time: its address
    // was only known once its request was read.
    let err = via_proxy(relay, "198.51.100.4").await.unwrap_err();
    assert!(err.to_string().contains("429"), "{err}");
    // A client's own claim to the left of the proxy's is not believed.
    let err = via_proxy(relay, "203.0.113.9, 198.51.100.4")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("429"), "{err}");
    // Someone else behind the same proxy is not affected, and neither is
    // the proxy's own address.
    let mut b = via_proxy(relay, "198.51.100.5").await.unwrap();
    assert_eq!(read_bytes(&mut b, 2).await, b"hi");
    let (mut c, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut c, 2).await, b"hi");
}

#[tokio::test]
async fn an_untrusted_peer_cannot_claim_another_address() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_per_address = 1;
    let relay = relay(cfg).await;

    let mut a = via_proxy(relay, "198.51.100.4").await.unwrap();
    assert_eq!(read_bytes(&mut a, 2).await, b"hi");
    // Loopback is not a trusted proxy here, so the header names nobody
    // and this is loopback's second connection.
    assert!(via_proxy(relay, "198.51.100.5").await.is_err());
}

#[tokio::test]
async fn connections_not_yet_upgraded_are_capped() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_pending = 1;
    let relay = relay(cfg).await;

    // One that connects and says nothing holds the only pending place...
    let silent = TcpStream::connect(relay).await.unwrap();
    // ...so the next is closed unanswered.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut sock = TcpStream::connect(relay).await.unwrap();
    let _ = sock
        .write_all(b"GET /.well-known/hotline HTTP/1.1\r\nHost: relay\r\n\r\n")
        .await;
    let mut out = Vec::new();
    let _ = timeout(WAIT, sock.read_to_end(&mut out)).await.unwrap();
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));

    // Once it goes, the place is free; and an upgraded socket gives its
    // pending place back, so a second upgrade gets one too.
    drop(silent);
    let deadline = tokio::time::Instant::now() + WAIT;
    // A connection closed before the silent one's place was given back
    // can arrive as a reset, which is "not yet" as much as an empty
    // answer is.
    while !try_http(relay, "GET", "/.well-known/hotline")
        .await
        .is_ok_and(|resp| resp.starts_with("HTTP/1.1 200"))
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (mut first, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut first, 2).await, b"hi");
    assert_eq!(reopens(relay, "/trtp").await, b"hi");
}

#[tokio::test]
async fn a_kept_alive_connection_does_not_hold_its_place_forever() {
    let control = echo(b"").await;
    let mut cfg = Config::new(control.to_string());
    cfg.header_timeout = Duration::from_millis(300);
    let relay = relay(cfg).await;

    // A client that keeps asking, each request well inside the header
    // timeout, is still closed once the connection's time is up.
    let sock = TcpStream::connect(relay).await.unwrap();
    let (mut rd, mut wr) = sock.into_split();
    let asking = tokio::spawn(async move {
        loop {
            let req = b"GET /.well-known/hotline HTTP/1.1\r\nHost: relay\r\n\r\n";
            if wr.write_all(req).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let mut out = Vec::new();
    let closed = timeout(WAIT, async {
        let mut buf = [0u8; 4096];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    asking.abort();
    closed.expect("the connection is closed");
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
}

/// A server whose accept queue is full, so that a connection to it is
/// not made until the kernel retries its SYN, about a second on: a dial
/// that takes that long. It starts accepting, and greets with `hi`, once
/// `after` has passed.
async fn slow_to_accept(after: Duration) -> SocketAddr {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    let listener = socket.listen(1).unwrap();
    // Fill the queue: connect until a connection is no longer made.
    let mut fillers = Vec::new();
    loop {
        match timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => fillers.push(s),
            Ok(Err(e)) => panic!("filling the accept queue: {e}"),
            Err(_) => break,
        }
        assert!(fillers.len() < 64, "the accept queue never filled");
    }
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        drop(fillers);
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = sock.write_all(b"hi").await;
                let mut buf = [0u8; 64];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn an_upgrade_in_flight_at_the_deadline_still_opens() {
    // The dial to the server straddles the connection's deadline: the
    // upgrade must be answered as an upgrade, not closed as the deadline
    // would close an idle connection.
    let server = slow_to_accept(Duration::from_millis(400)).await;
    let mut cfg = Config::new(server.to_string());
    cfg.header_timeout = Duration::from_millis(200);
    cfg.connect_timeout = Duration::from_secs(5);
    let relay = relay(cfg).await;

    let started = tokio::time::Instant::now();
    let (mut ws, _) = timeout(
        WAIT,
        tokio_tungstenite::connect_async(format!("ws://{relay}/trtp")),
    )
    .await
    .expect("the upgrade is answered")
    .expect("the upgrade is answered as one");
    assert!(
        started.elapsed() > Duration::from_millis(200),
        "the dial was meant to outlast the deadline"
    );
    assert_eq!(read_bytes(&mut ws, 2).await, b"hi");
    ws.send(Message::Binary(b"still here".to_vec()))
        .await
        .unwrap();
}

/// Write an upgrade request for `path` on `sock` by hand, so that the
/// connection can be kept alive past its answer, and read that answer.
async fn upgrade_by_hand(sock: &mut TcpStream, path: &str) -> String {
    sock.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    // Byte by byte, so as to read no further than this answer.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        let n = timeout(WAIT, sock.read(&mut b)).await.unwrap().unwrap();
        assert_eq!(
            n,
            1,
            "closed mid-answer: {}",
            String::from_utf8_lossy(&head)
        );
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .map_or(0, |n| n.trim().parse().unwrap());
    let mut body = vec![0u8; length];
    timeout(WAIT, sock.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    head + &String::from_utf8(body).unwrap()
}

/// Whether a fresh connection is closed before its request is answered.
async fn refused_on_connect(relay: SocketAddr) -> bool {
    let mut sock = TcpStream::connect(relay).await.unwrap();
    let _ = sock
        .write_all(b"GET /.well-known/hotline HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n")
        .await;
    let mut out = Vec::new();
    let _ = timeout(WAIT, sock.read_to_end(&mut out)).await.unwrap();
    out.is_empty()
}

#[tokio::test]
async fn a_refused_upgrade_keeps_its_connection_counted() {
    let control = echo(b"hi").await;
    let mut cfg = Config::new(control.to_string());
    cfg.max_connections = 1;
    cfg.max_per_address = 2;
    let relay = relay(cfg).await;

    let (mut first, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    assert_eq!(read_bytes(&mut first, 2).await, b"hi");
    // A second connection is refused its upgrade, the relay being full,
    // and stays open...
    let mut kept = TcpStream::connect(relay).await.unwrap();
    let resp = upgrade_by_hand(&mut kept, "/trtp").await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
    // ...still counted against its address, which therefore holds two,
    // so a third is closed as it connects.
    assert!(refused_on_connect(relay).await);

    // And the place it kept is the one its next upgrade uses.
    first.close(None).await.unwrap();
    drop(first);
    let deadline = tokio::time::Instant::now() + WAIT;
    let mut resp = upgrade_by_hand(&mut kept, "/trtp").await;
    while resp.starts_with("HTTP/1.1 503") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the slot was never freed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        resp = upgrade_by_hand(&mut kept, "/trtp").await;
    }
    assert!(resp.starts_with("HTTP/1.1 101"), "{resp}");
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        kept,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    assert_eq!(read_bytes(&mut ws, 2).await, b"hi");
}

#[tokio::test]
async fn a_server_that_is_down_leaves_the_connection_its_place() {
    let gone = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut cfg = Config::new(gone.to_string());
    cfg.max_per_address = 1;
    let relay = relay(cfg).await;

    let mut kept = TcpStream::connect(relay).await.unwrap();
    let resp = upgrade_by_hand(&mut kept, "/trtp").await;
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    // The address still holds its one place, in the connection that was
    // refused.
    assert!(refused_on_connect(relay).await);
    // Which can ask again.
    let resp = upgrade_by_hand(&mut kept, "/trtp").await;
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
}
