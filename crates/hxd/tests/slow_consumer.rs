//! A client that stops reading is disconnected, and costs everyone else
//! nothing: the classic wire's bounded write queue, and the domain's
//! bounded live channel behind the ng wire (`LIVE_QUEUE_CAP`).
//!
//! Each case floods a room from a classic talker while one client reads
//! everything and another reads nothing at all, then checks that the
//! reader heard every line, in order, and that the server hung up on the
//! one that did not read — instead of holding everything addressed to it
//! for as long as its socket stayed open, which it did before.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_LOGIN: u32 = 0x6b;
const HDR_CHAT: u32 = 0x69;
const HDR_CHAT_PUSH: u32 = 0x6a;

/// Lines of this size fill a stalled socket's buffers, and then the
/// server's bound, in a few thousand lines.
const LINE: usize = 4000;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

async fn start(dir: &Path) -> Server {
    let d = dir.display();
    let text = format!("[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n");
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    // An account that may detach, for the ng case's resume.
    std::fs::write(
        dir.join("accounts/sleepy.toml"),
        "name = \"sleepy\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n",
    )
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

/// A 1.2-style guest login: no version, so no agreement to answer.
async fn classic(addr: SocketAddr, nick: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut magic = [0u8; 8];
    s.read_exact(&mut magic).await.unwrap();
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

fn body(f: &Frame) -> String {
    f.chunks()
        .find(|c| c.tag == tag::BODY)
        .map(|c| String::from_utf8_lossy(c.data).into_owned())
        .unwrap_or_default()
}

/// The line numbers a classic reader hears, until `end` or the socket
/// closes. Returns them and whether the server closed the socket.
fn listen(mut s: TcpStream, end: usize) -> JoinHandle<(Vec<usize>, bool)> {
    tokio::spawn(async move {
        let mut heard = Vec::new();
        loop {
            match timeout(Duration::from_secs(30), read_frame(&mut s)).await {
                Ok(Ok(f)) if f.ty == HDR_CHAT_PUSH => {
                    if let Some(n) = line_number(&body(&f)) {
                        heard.push(n);
                        if n == end {
                            return (heard, false);
                        }
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return (heard, true),
                Err(_) => panic!("heard nothing for 30s, after {} lines", heard.len()),
            }
        }
    })
}

fn line_number(text: &str) -> Option<usize> {
    let rest = &text[text.find("line ")? + 5..];
    rest.split(' ').next()?.parse().ok()
}

/// Send `n` lines as fast as the server takes them, then an `end` line.
/// The talker hears its own lines too, so something drains its socket
/// meanwhile: it must not become a slow consumer itself. The connection
/// stays open afterwards: closed with its echoes unread, it would be
/// reset, and the reset takes its last lines with it.
async fn flood(talker: TcpStream, n: usize) -> tokio::net::tcp::OwnedWriteHalf {
    let (mut rd, mut wr) = talker.into_split();
    tokio::spawn(async move {
        let mut sink = vec![0u8; 64 * 1024];
        while matches!(rd.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    let pad = "x".repeat(LINE);
    for i in 1..=n + 1 {
        let text = format!("line {i} {pad}");
        let frame = pack_frame(HDR_CHAT, i as u32, 0, &[(tag::BODY, text.into_bytes())]);
        wr.write_all(&frame).await.unwrap();
    }
    wr
}

/// Everyone who reads hears everything, in order.
fn assert_all_in_order(heard: &[usize], n: usize) {
    assert_eq!(heard.len(), n + 1, "the reader missed lines");
    assert!(heard.windows(2).all(|w| w[1] == w[0] + 1), "out of order");
}

/// Each case must finish well inside the ng pong deadline (90 s): a
/// server that only noticed a stalled client when that ran out would
/// pass the ng case eventually, having buffered for it all the while.
const PROMPTLY: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_classic_client_that_stops_reading_is_disconnected() {
    timeout(PROMPTLY, classic_case())
        .await
        .expect("the stalled client was not dropped promptly");
}

async fn classic_case() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let n = 8000;

    let stalled = classic(server.legacy, "stalled").await;
    let reader = listen(classic(server.legacy, "reader").await, n + 1);
    let talker = classic(server.legacy, "talker").await;
    let talking = tokio::spawn(flood(talker, n));

    let (heard, _) = timeout(Duration::from_secs(60), reader)
        .await
        .unwrap()
        .unwrap();
    assert_all_in_order(&heard, n);

    // Only now does the stalled client read: what the kernel had buffered
    // for it, and then the end of the connection, well short of the room.
    let (got, closed) = timeout(Duration::from_secs(60), listen(stalled, n + 1))
        .await
        .unwrap()
        .unwrap();
    assert!(
        closed,
        "the server never hung up on a client that did not read"
    );
    assert!(got.len() < n, "it heard {} of {n} lines", got.len());
    drop(talking);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ng_client_that_stops_reading_is_dropped_and_resumes_into_a_resync() {
    timeout(PROMPTLY, ng_case())
        .await
        .expect("the stalled client was not dropped promptly");
}

async fn ng_case() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    // Enough to fill the socket's buffers and then the whole channel.
    let n = hxd_core::LIVE_QUEUE_CAP + 4000;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
        .await
        .unwrap();
    let login = json!({ "id": 1, "req": "login",
        "params": { "login": "sleepy", "password": "pw", "nick": "sleepy" } });
    ws.send(Message::Text(login.to_string())).await.unwrap();
    let hello = loop {
        let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 1 {
            break v["ok"].clone();
        }
    };
    let (session, token) = (hello["session"].clone(), hello["token"].clone());

    let reader = listen(classic(server.legacy, "reader").await, n + 1);
    let talker = classic(server.legacy, "talker").await;
    let talking = tokio::spawn(flood(talker, n));
    let (heard, _) = timeout(Duration::from_secs(120), reader)
        .await
        .unwrap()
        .unwrap();
    assert_all_in_order(&heard, n);

    // Now the stalled client reads: some of the room, then the close.
    let mut last_seq = 0u64;
    let mut lines = 0usize;
    loop {
        match timeout(Duration::from_secs(120), ws.next()).await.unwrap() {
            Some(Ok(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if let Some(seq) = v["seq"].as_u64() {
                    assert_eq!(seq, last_seq + 1, "a gap before the drop");
                    last_seq = seq;
                    lines += usize::from(v["ev"] == "chat");
                }
            }
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
            Some(Ok(_)) => {}
        }
    }
    assert!(lines < n, "it heard {lines} of {n} lines before the close");
    drop(talking);

    // Its session detached, and what it lost cannot be replayed.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
        .await
        .unwrap();
    let resume = json!({ "id": 1, "req": "resume",
        "params": { "session": session, "token": token, "last_seq": last_seq } });
    ws.send(Message::Text(resume.to_string())).await.unwrap();
    let reply = loop {
        let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 1 {
            break v;
        }
    };
    assert_eq!(reply["error"]["code"], "resync_required", "{reply}");
    // And the session is whole again from there: `sync` reports where
    // the stream stands, past everything that was lost.
    ws.send(Message::Text(json!({ "id": 2, "req": "sync" }).to_string()))
        .await
        .unwrap();
    let synced = loop {
        let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 2 {
            break v;
        }
    };
    let seq = synced["ok"]["seq"].as_u64().unwrap();
    assert!(seq > last_seq, "sync at {seq}, having had {last_seq}");
}
