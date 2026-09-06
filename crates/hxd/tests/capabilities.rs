//! Capability negotiation end-to-end, on both wires: the legacy
//! `DATA_CAPABILITIES` (`0x01F0`) bitmask exchange at LOGIN, and the ng
//! login reply's `caps` list. A live server on an ephemeral port, driven
//! by scripted clients — the legacy one packs with the same
//! `hotline-proto` a real client uses.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hotline_proto::messages::tag;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_LOGIN: u32 = 0x6b;

/// A server whose supported capability set is `supported`, plus its ng
/// twin advertising `ng_caps`.
async fn start_server(dir: &Path, supported: Caps, ng_caps: &[&str]) -> (SocketAddr, SocketAddr) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let ctx = ServerCtx {
        core: Arc::new(Core::new()),
        auth: Arc::new(hxd_auth_file::FileAuth::new(&accounts)),
        cfg: Arc::new(ServerConfig {
            name: "test server".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: supported,
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
    };
    let ng_ctx = NgCtx {
        core: ctx.core.clone(),
        auth: ctx.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "test server".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
            caps: ng_caps.iter().map(|s| s.to_string()).collect(),
            trusted_proxies: Vec::new(),
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
    };

    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let legacy_addr = legacy.local_addr().unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng_addr = ng.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    (legacy_addr, ng_addr)
}

/// Log in as a guest, optionally advertising capabilities, and return the
/// login reply.
async fn legacy_login(addr: SocketAddr, offered: Option<Caps>) -> Frame {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic).await.unwrap();

    let mut chunks = vec![
        (tag::NAME, b"alice".to_vec()),
        (tag::ICON, 2u16.to_be_bytes().to_vec()),
        (tag::VERSION, 195u16.to_be_bytes().to_vec()),
    ];
    if let Some(c) = offered {
        chunks.push((tag::CAPABILITIES, c.to_wire()));
    }
    stream
        .write_all(&pack_frame(HDR_LOGIN, 1, 0, &chunks))
        .await
        .unwrap();
    for _ in 0..8 {
        let f = timeout(Duration::from_secs(5), read_frame(&mut stream))
            .await
            .expect("timed out")
            .expect("closed");
        if f.ty == HDR_TASK {
            return f;
        }
    }
    panic!("no login reply");
}

fn caps_chunk(f: &Frame) -> Option<Vec<u8>> {
    f.chunks()
        .find(|c| c.tag == tag::CAPABILITIES)
        .map(|c| c.data.to_vec())
}

#[tokio::test]
async fn legacy_echo_is_the_intersection_and_nothing_else() {
    let td = tempfile::tempdir().unwrap();
    let supported = Caps::empty().with(cap::VOICE).with(cap::LARGE_FILES);
    let (legacy, _ng) = start_server(td.path(), supported, &[]).await;

    // A client offering voice + text-encoding gets voice back, alone: the
    // server supports large files too but the client never asked, and it
    // doesn't support text encoding however loudly the client asks.
    let offered = Caps::empty().with(cap::VOICE).with(cap::TEXT_ENCODING);
    let reply = legacy_login(legacy, Some(offered)).await;
    let echoed = Caps::from_wire(&caps_chunk(&reply).expect("capability echo"));
    assert!(echoed.has(cap::VOICE));
    assert!(!echoed.has(cap::TEXT_ENCODING));
    assert!(!echoed.has(cap::LARGE_FILES));
    // Two bytes on the wire, exactly as the spec's example and as every
    // client that reads the field by width expects.
    assert_eq!(caps_chunk(&reply).unwrap(), vec![0x00, 0x04]);

    // The rest of the login reply is untouched by the negotiation.
    assert!(reply.chunks().any(|c| c.tag == tag::UID));
    assert!(reply.chunks().any(|c| c.tag == tag::SERVERNAME));
}

#[tokio::test]
async fn a_client_that_offers_nothing_sees_no_capability_field() {
    let td = tempfile::tempdir().unwrap();
    let supported = Caps::empty().with(cap::VOICE);
    let (legacy, _ng) = start_server(td.path(), supported, &[]).await;

    // The 1.x case: no field in the request, so none in the reply — a
    // vintage client's login is byte-identical to what it was before
    // capability negotiation existed.
    let reply = legacy_login(legacy, None).await;
    assert!(caps_chunk(&reply).is_none());

    // And an empty offer is the same thing as no offer.
    let reply = legacy_login(legacy, Some(Caps::empty())).await;
    assert!(caps_chunk(&reply).is_none());
}

#[tokio::test]
async fn a_server_that_supports_nothing_stays_quiet() {
    let td = tempfile::tempdir().unwrap();
    let (legacy, _ng) = start_server(td.path(), Caps::empty(), &[]).await;

    let offered = Caps::empty().with(cap::VOICE).with(cap::CHAT_HISTORY);
    let reply = legacy_login(legacy, Some(offered)).await;
    assert!(
        caps_chunk(&reply).is_none(),
        "nothing agreed means the field is omitted, not sent as zero"
    );
}

#[tokio::test]
async fn unknown_bits_are_ignored_not_refused() {
    let td = tempfile::tempdir().unwrap();
    let supported = Caps::empty().with(cap::VOICE);
    let (legacy, _ng) = start_server(td.path(), supported, &[]).await;

    // A client from the future, offering voice plus bits nobody has
    // allocated yet, in the full eight-byte form. It logs in fine and
    // gets back only what we know.
    let offered = Caps::from_bits(0xdead_beef_0000_0000).with(cap::VOICE);
    let reply = legacy_login(legacy, Some(offered)).await;
    assert_eq!(caps_chunk(&reply).unwrap(), vec![0x00, 0x04]);
}

#[tokio::test]
async fn ng_login_reply_carries_the_capability_list() {
    let td = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(td.path(), Caps::empty(), &["voice"]).await;

    let ok = ng_login(ng).await;
    assert_eq!(ok["caps"], json!(["voice"]));

    // The list is always present, so a client can test it without
    // distinguishing "no capabilities" from "old server".
    let td2 = tempfile::tempdir().unwrap();
    let (_legacy, ng) = start_server(td2.path(), Caps::empty(), &[]).await;
    assert_eq!(ng_login(ng).await["caps"], json!([]));
}

async fn ng_login(addr: SocketAddr) -> Value {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
        .await
        .unwrap();
    ws.send(Message::Text(
        json!({ "id": 0, "req": "login", "params": { "nick": "alice" } }).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["reply"] == json!(0) {
                return v["ok"].clone();
            }
        }
    }
}
