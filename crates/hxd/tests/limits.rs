//! What one address is held to (`[limits]`, `hxd_core::limits`): so many
//! connections at once, and new ones no faster than a burst and then a
//! rate, on the classic wire and the ng one alike, counted together.
//!
//! Each case builds a real server from a config file that takes loopback
//! off the exempt list, which is what makes the test's own address one
//! that is limited.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    tls: SocketAddr,
    /// The TLS port's certificate, for the client's trust store.
    cert: CertificateDer<'static>,
}

/// A server whose `[limits]` are `limits`, exempting `exempt` (a TOML
/// array) rather than loopback.
async fn start(dir: &Path, limits: &str) -> Server {
    start_exempting(dir, "[]", limits).await
}

async fn start_exempting(dir: &Path, exempt: &str, limits: &str) -> Server {
    let d = dir.display();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n\
         [limits]\nexempt = {exempt}\n{limits}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, issued.cert.pem()).unwrap();
    std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();
    let tls = Arc::new(hxd_session::LegacyTls::load(&cert_path, &key_path).unwrap());
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        tls: secure.local_addr().unwrap(),
        cert: issued.cert.der().clone(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx.clone()));
    tokio::spawn(hxd_session::serve_tls(secure, ctx, tls));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

/// A classic connection over TLS that gets as far as the server's
/// magic, or `None` when the server closes it first.
async fn classic_tls(server: &Server) -> Option<()> {
    let mut roots = RootCertStore::empty();
    roots.add(server.cert.clone()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(server.tls).await.unwrap();
    let mut s = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .ok()?;
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.ok()?;
    let mut magic = [0u8; 8];
    match timeout(Duration::from_secs(5), s.read_exact(&mut magic)).await {
        Ok(Ok(_)) => Some(()),
        Ok(Err(_)) => None,
        Err(_) => panic!("the server neither answered nor closed"),
    }
}

/// Is `s` closed by the server within a moment, unanswered?
async fn closed_at_once(s: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        timeout(Duration::from_secs(3), s.read(&mut byte)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

/// A classic connection that gets as far as the server's magic, or
/// `None` when the server closes it first.
async fn classic(addr: SocketAddr) -> Option<TcpStream> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.ok()?;
    let mut magic = [0u8; 8];
    match timeout(Duration::from_secs(5), s.read_exact(&mut magic)).await {
        Ok(Ok(_)) => Some(s),
        Ok(Err(_)) => None,
        Err(_) => panic!("the server neither answered nor closed"),
    }
}

/// An ng WebSocket, or the HTTP status that refused it.
async fn ng(
    addr: SocketAddr,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, u16> {
    match tokio_tungstenite::connect_async(format!("ws://{addr}/ng")).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("ng: {e}"),
    }
}

#[tokio::test]
async fn an_address_holds_so_many_connections_across_both_wires() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "connections_per_addr = 3\nreconnect_seconds = 0").await;
    let first = classic(server.legacy).await.expect("the first");
    let _second = classic(server.legacy).await.expect("the second");
    let _third = ng(server.ng).await.expect("the third, on the other wire");
    // The fourth, on either wire: the classic one is closed unanswered,
    // as mhxd closes one past `conn_max`, and the ng one refused.
    assert!(classic(server.legacy).await.is_none(), "a fourth, classic");
    assert_eq!(ng(server.ng).await.err(), Some(429), "a fourth, ng");
    // A place freed is a place taken.
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while classic(server.legacy).await.is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the place never came back"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn past_its_burst_an_address_connects_no_faster_than_the_rate() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "connections_per_addr = 3\nreconnect_seconds = 60",
    )
    .await;
    for _ in 0..3 {
        drop(classic(server.legacy).await.expect("within the burst"));
    }
    // Every connection closed, and still no fourth for a minute.
    assert!(classic(server.legacy).await.is_none(), "classic");
    assert_eq!(ng(server.ng).await.err(), Some(429), "ng");
}

#[tokio::test]
async fn a_tls_handshake_holds_its_place_from_accept() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "connections_per_addr = 2\nreconnect_seconds = 0").await;
    // Two connections that never begin their handshakes: counted from
    // the moment they are accepted, so one address cannot fill the
    // server's handshake slots, which are shared by every address.
    let _a = TcpStream::connect(server.tls).await.unwrap();
    let _b = TcpStream::connect(server.tls).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = TcpStream::connect(server.tls).await.unwrap();
    assert!(
        closed_at_once(&mut third).await,
        "a third is closed at accept, not left to time its handshake out"
    );
    assert!(
        classic(server.legacy).await.is_none(),
        "nor one on the plain port"
    );
    // A place freed is a place taken, and a finished handshake counts
    // once rather than again when its session begins.
    drop(_a);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while classic_tls(&server).await.is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the place never came back"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_exempt_address_is_not_limited() {
    // Loopback exempted by name, beside a block it is not in, with limits
    // that would otherwise refuse a second connection.
    let td = tempfile::tempdir().unwrap();
    let server = start_exempting(
        td.path(),
        "[\"192.0.2.0/24\", \"127.0.0.1\"]",
        "connections_per_addr = 1\nreconnect_seconds = 60",
    )
    .await;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(classic(server.legacy).await.expect("127.0.0.1 is exempt"));
    }
    let _ws = ng(server.ng).await.expect("on the ng wire too");
    classic_tls(&server).await.expect("and on the TLS port");

    // The default config: loopback exempt.
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let path = td.path().join("hxd-ng.toml");
    std::fs::write(
        &path,
        format!("[paths]\naccounts = \"{d}/accounts\"\n[limits]\nconnections_per_addr = 1\n"),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = legacy.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(legacy, ctx));
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(classic(addr).await.expect("loopback is exempt by default"));
    }
}
