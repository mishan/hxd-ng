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

// --- Flooding ----------------------------------------------------------

use futures_util::{SinkExt, StreamExt};
use hxd_session::frame::{pack_frame, read_frame};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_LOGIN: u32 = 0x6b;
const HDR_CHAT: u32 = 0x69;

/// A 1.2-style guest login: no version, so no agreement to answer.
async fn classic_guest(addr: SocketAddr, nick: &str) -> TcpStream {
    let mut s = classic(addr).await.expect("admitted");
    let login = pack_frame(
        HDR_LOGIN,
        1,
        0,
        &[
            (tag::NAME, nick.as_bytes().to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
        ],
    );
    s.write_all(&login).await.unwrap();
    loop {
        let f = timeout(Duration::from_secs(5), read_frame(&mut s))
            .await
            .unwrap()
            .unwrap();
        if f.ty == HDR_TASK && f.trans == 1 {
            assert_eq!(f.flag, 0, "login failed");
            return s;
        }
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ng_guest(addr: SocketAddr, nick: &str) -> (Ws, Value) {
    let mut ws = ng(addr).await.expect("admitted");
    let login = json!({ "id": 1, "req": "login", "params": { "nick": nick } });
    ws.send(Message::Text(login.to_string())).await.unwrap();
    let hello = next_reply(&mut ws, 1).await;
    (ws, hello["ok"].clone())
}

async fn next_reply(ws: &mut Ws, id: u64) -> Value {
    loop {
        let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == id {
            return v;
        }
    }
}

/// An event of this kind matching `pred`, skipping the rest.
async fn event(ws: &mut Ws, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap_or_else(|_| panic!("no {ev}"))
            .unwrap()
            .unwrap();
        let Message::Text(t) = msg else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["ev"] == ev && pred(&v["data"]) {
            return v["data"].clone();
        }
    }
}

const HDR_CHAT_PUSH: u32 = 0x6a;
const HDR_USER_GETLIST: u32 = 0x12c;

fn chat_frame(trans: u32, text: &str) -> Vec<u8> {
    pack_frame(HDR_CHAT, trans, 0, &[(tag::BODY, text.as_bytes().to_vec())])
}

/// A chat push as a classic client reads it: the body, the uid it names,
/// and the chat id when it is a private chat's.
struct Push {
    body: Vec<u8>,
    uid: u32,
    cid: Option<u32>,
}

/// The next chat push, skipping every other frame.
async fn chat_push(s: &mut TcpStream) -> Push {
    loop {
        let f = timeout(Duration::from_secs(5), read_frame(s))
            .await
            .expect("no chat push")
            .unwrap();
        if f.ty != HDR_CHAT_PUSH {
            continue;
        }
        let mut push = Push {
            body: Vec::new(),
            uid: 0,
            cid: None,
        };
        for c in f.chunks() {
            match c.tag {
                tag::BODY => push.body = c.data.to_vec(),
                tag::UID => push.uid = c.as_uint(),
                tag::CHAT_ID => push.cid = Some(c.as_uint()),
                _ => {}
            }
        }
        return push;
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// The uid an ng watcher sees `nick` join as.
async fn joined_uid(ws: &mut Ws, nick: &str) -> u32 {
    let data = event(ws, "user_joined", |d| d["user"]["nick"] == nick).await;
    data["user"]["uid"].as_u64().unwrap() as u32
}

/// The server closes `s`: whatever it had left to say, then EOF.
async fn closed(s: &mut TcpStream) {
    let mut rest = Vec::new();
    let r = timeout(Duration::from_secs(5), s.read_to_end(&mut rest)).await;
    assert!(r.is_ok(), "the connection was not closed");
}

/// mhxd's `chat_max`: every line of a multi-line send counts, the send
/// that crosses the limit is refused whole, and the room hears mhxd's
/// `\r *** X was kicked for chat spamming` from the spammer — once,
/// however much more it had in flight.
#[tokio::test]
async fn a_user_past_its_chat_lines_is_kicked_once_and_the_room_told() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "connections_per_addr = 0\nreconnect_seconds = 0\n\
         chat_lines = 3\nchat_seconds = 60\nspam_points = 0",
    )
    .await;
    let (mut ng_watcher, _) = ng_guest(server.ng, "ngwatcher").await;
    let mut watcher = classic_guest(server.legacy, "watcher").await;
    let mut spammer = classic_guest(server.legacy, "spammer").await;
    let uid = joined_uid(&mut ng_watcher, "spammer").await;

    // Two lines, then two more: the fourth line is one past the limit.
    // And a burst behind it, already on the wire.
    let mut burst = chat_frame(2, "one\rtwo");
    burst.extend(chat_frame(3, "three\rfour"));
    for i in 0..40 {
        burst.extend(chat_frame(4 + i, &format!("buy now {i}")));
    }
    spammer.write_all(&burst).await.unwrap();

    let first = chat_push(&mut watcher).await;
    assert!(contains(&first.body, "one") && contains(&first.body, "two"));
    let notice = chat_push(&mut watcher).await;
    assert_eq!(
        notice.body, b"\r *** spammer was kicked for chat spamming",
        "mhxd's bytes, not a line of the send that crossed the limit"
    );
    assert_eq!(notice.uid, uid, "from the spammer, as mhxd sends it");
    assert_eq!(notice.cid, None, "into public chat, where it flooded");
    let heard = event(&mut ng_watcher, "notice", |d| {
        d["text"].as_str().is_some_and(|t| t.contains("spamming"))
    })
    .await;
    assert_eq!(heard["text"], "spammer was kicked for chat spamming");
    closed(&mut spammer).await;

    // Nothing more about it: a line of the watcher's own, after the
    // spammer is gone, is the next thing either watcher hears.
    watcher.write_all(&chat_frame(2, "sentinel")).await.unwrap();
    let next = chat_push(&mut watcher).await;
    assert!(contains(&next.body, "sentinel"), "{:?}", next.body);
    loop {
        let msg = timeout(Duration::from_secs(5), ng_watcher.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(t) = msg else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        assert!(
            !(v["ev"] == "notice" && v["data"]["text"].as_str().unwrap().contains("spamming")),
            "a second notice: {v}"
        );
        if v["ev"] == "chat" && v["data"]["text"] == "sentinel" {
            break;
        }
    }
}

/// mhxd's `spam_max`: every classic transaction spends its price from
/// the window's budget, a user list 20 of 100, and the one that reaches
/// it is never answered; its sender is kicked and banned, and public
/// chat hears mhxd's announcement.
#[tokio::test]
async fn a_classic_user_past_its_spam_points_is_banned() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "connections_per_addr = 0\nreconnect_seconds = 0\n\
         spam_points = 100\nspam_seconds = 60\n[server]\nban_time = 60",
    )
    .await;
    let mut watcher = classic_guest(server.legacy, "watcher").await;
    let mut flooder = classic_guest(server.legacy, "flooder").await;
    let mut burst = Vec::new();
    for trans in 2..=9 {
        burst.extend(pack_frame(HDR_USER_GETLIST, trans, 0, &[]));
    }
    flooder.write_all(&burst).await.unwrap();
    let mut answered = Vec::new();
    loop {
        match timeout(Duration::from_secs(5), read_frame(&mut flooder)).await {
            Ok(Ok(f)) if f.ty == HDR_TASK => answered.push(f.trans),
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => panic!("the flooder was not disconnected"),
        }
    }
    assert_eq!(answered, [2, 3, 4, 5], "the fifth reaches 100 and is not");
    let notice = chat_push(&mut watcher).await;
    assert_eq!(
        notice.body,
        b"\r<flooder has been banned by flooder: spam_max exceeded: \
          100 >= 100, last transaction: 0x12c>"
            .as_slice()
    );
    assert!(
        classic(server.legacy).await.is_none(),
        "its address is banned"
    );
}

/// The ng wire charges `msg` what mhxd charges a message, and answers
/// the one that reaches the budget `flooding` before the kick.
#[tokio::test]
async fn an_ng_user_past_its_spam_points_is_refused_flooding_and_banned() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "connections_per_addr = 0\nreconnect_seconds = 0\n\
         spam_points = 10\nspam_seconds = 60\n[server]\nban_time = 60",
    )
    .await;
    let (mut watcher, _) = ng_guest(server.ng, "watcher").await;
    let (mut sender, hello) = ng_guest(server.ng, "sender").await;
    let to = hello["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "watcher")
        .unwrap()["uid"]
        .clone();
    for id in 2..=5 {
        let msg = json!({ "id": id, "req": "msg", "params": { "to": to, "text": "hi" } });
        sender.send(Message::Text(msg.to_string())).await.unwrap();
        assert!(next_reply(&mut sender, id).await.get("ok").is_some());
    }
    let msg = json!({ "id": 6, "req": "msg", "params": { "to": to, "text": "hi" } });
    sender.send(Message::Text(msg.to_string())).await.unwrap();
    let refused = next_reply(&mut sender, 6).await;
    assert_eq!(refused["error"]["code"], "flooding", "{refused}");
    event(&mut sender, "kicked", |_| true).await;
    let notice = event(&mut watcher, "notice", |d| {
        d["text"].as_str().is_some_and(|t| t.contains("spam_max"))
    })
    .await;
    assert_eq!(
        notice["text"],
        "sender has been banned by sender: spam_max exceeded: 10 >= 10, last transaction: 0x6c"
    );
}
