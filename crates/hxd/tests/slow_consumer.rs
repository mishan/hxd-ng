//! A client that stops reading is disconnected, and costs everyone else
//! nothing: the classic wire's bounded write queue, the domain's
//! bounded live channel behind the ng wire (`LIVE_QUEUE_CAP`), and the
//! budget they share (`[server] queue_budget_mb`).
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
use tokio::sync::watch;
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
    start_with(dir, "").await
}

/// With `server` lines for the config's `[server]` section.
async fn start_with(dir: &Path, server: &str) -> Server {
    let d = dir.display();
    let text = format!(
        "[server]\n{server}\n[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n"
    );
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
/// closes. Returns them and whether the server closed the socket, and
/// meanwhile publishes the last line it heard, for [`flood`] to keep
/// pace with. The publisher goes when the reader does, however it ends.
fn listen(
    mut s: TcpStream,
    end: usize,
) -> (JoinHandle<(Vec<usize>, bool)>, watch::Receiver<usize>) {
    let (last, heard_to) = watch::channel(0);
    let task = tokio::spawn(async move {
        let mut heard = Vec::new();
        loop {
            match timeout(Duration::from_secs(30), read_frame(&mut s)).await {
                Ok(Ok(f)) if f.ty == HDR_CHAT_PUSH => {
                    if let Some(n) = line_number(&body(&f)) {
                        heard.push(n);
                        last.send_replace(n);
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
    });
    (task, heard_to)
}

fn line_number(text: &str) -> Option<usize> {
    let rest = &text[text.find("line ")? + 5..];
    rest.split(' ').next()?.parse().ok()
}

/// How far the talker may run ahead of what it and the reader have heard,
/// in lines. Flooded as fast as the server took them, the room raced the
/// reader as well as the stalled client, and a reader descheduled for a
/// moment on a busy machine fell a whole connection's bound behind and was
/// cut off with the client that never read; pausing on a clock only
/// narrowed that race, and made the run as long as the scheduler's latency.
/// So the talker waits on its hearers instead. The window is a small
/// fraction of every bound a hearer could be held to: the classic writer's
/// queue, the live channel, and in the budget case the half of the average
/// that a queue which has kept up may always hold. Wide enough that the
/// hearers, not the window, set the pace.
const WINDOW: usize = 64;

/// Send `n` lines, then an `end` line, never more than [`WINDOW`] ahead
/// of the last line `heard` says the reader has, nor of the last of its
/// own lines the talker has heard back. Nothing waits on the stalled
/// client, so it is buried as fast as the others read.
///
/// The talker hears its own lines too, so something reads its socket
/// meanwhile: it must not become a slow consumer itself. Nor may it run
/// ahead of its own echoes. While the server is busy taking its lines, the
/// echoes queue for it, and against a tight budget a talker far enough
/// ahead of them is cut off as the one holding the most.
///
/// Should either hearer stop, its publisher goes with it, and the flood
/// stops there too rather than waiting forever: the reader's shortfall is
/// the failure, reported by its own timeout. The connection stays open
/// afterwards: closed with its echoes unread, it would be reset, and the
/// reset takes its last lines with it.
async fn flood(
    talker: TcpStream,
    n: usize,
    mut heard: watch::Receiver<usize>,
) -> tokio::net::tcp::OwnedWriteHalf {
    let (mut rd, mut wr) = talker.into_split();
    let (echo, mut echoed) = watch::channel(0);
    tokio::spawn(async move {
        while let Ok(f) = read_frame(&mut rd).await {
            if f.ty == HDR_CHAT_PUSH {
                if let Some(n) = line_number(&body(&f)) {
                    echo.send_replace(n);
                }
            }
        }
    });
    let pad = "x".repeat(LINE);
    for i in 1..=n + 1 {
        let text = format!("line {i} {pad}");
        let frame = pack_frame(HDR_CHAT, i as u32, 0, &[(tag::BODY, text.into_bytes())]);
        wr.write_all(&frame).await.unwrap();
        let caught_up = |&h: &usize| i < h + WINDOW;
        if heard.wait_for(caught_up).await.is_err() || echoed.wait_for(caught_up).await.is_err() {
            break;
        }
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
/// The ng case also checks the drop happened while the client was still
/// silent, before it read anything.
const PROMPTLY: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
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
    let (reader, heard) = listen(classic(server.legacy, "reader").await, n + 1);
    let talker = classic(server.legacy, "talker").await;
    let talking = tokio::spawn(flood(talker, n, heard));

    let (heard, _) = timeout(Duration::from_secs(60), reader)
        .await
        .unwrap()
        .unwrap();
    assert_all_in_order(&heard, n);

    // Only now does the stalled client read: what the kernel had buffered
    // for it, and then the end of the connection, well short of the room.
    let (got, closed) = timeout(Duration::from_secs(60), listen(stalled, n + 1).0)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
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

    let (reader, heard) = listen(classic(server.legacy, "reader").await, n + 1);
    let talker = classic(server.legacy, "talker").await;
    let talking = tokio::spawn(flood(talker, n, heard));
    let (heard, _) = timeout(Duration::from_secs(30), reader)
        .await
        .unwrap()
        .unwrap();
    assert_all_in_order(&heard, n);

    // Still without its having read a byte, the server has already let it
    // go: the session shows as detached to everyone else. Not after the
    // pong deadline — the connection was cut when it fell a channel
    // behind, in the middle of a send it was not taking.
    let (mut watcher, _) = tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
        .await
        .unwrap();
    let hello = json!({ "id": 1, "req": "login", "params": { "nick": "watcher" } });
    watcher
        .send(Message::Text(hello.to_string()))
        .await
        .unwrap();
    let mut id = 1;
    loop {
        let reply = loop {
            let Message::Text(t) = watcher.next().await.unwrap().unwrap() else {
                continue;
            };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["reply"] == id {
                break v;
            }
        };
        let users = &reply["ok"]["users"];
        let sleepy = users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["nick"] == "sleepy")
            .cloned();
        if sleepy.is_some_and(|u| u["status"] == "detached") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        id += 1;
        let sync = json!({ "id": id, "req": "sync" });
        watcher.send(Message::Text(sync.to_string())).await.unwrap();
    }

    // Now the stalled client reads: some of the room, then the close.
    let mut last_seq = 0u64;
    let mut lines = 0usize;
    loop {
        match timeout(Duration::from_secs(30), ws.next()).await.unwrap() {
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

/// Clients each far inside their own bounds are dropped all the same
/// once what the server holds for them together passes its budget
/// (`[server] queue_budget_mb`), and the room goes on as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stalled_clients_past_the_servers_budget_are_dropped() {
    timeout(PROMPTLY, budget_case())
        .await
        .expect("the stalled clients were not dropped promptly");
}

async fn budget_case() {
    let td = tempfile::tempdir().unwrap();
    let server = start_with(td.path(), "queue_budget_mb = 4").await;
    // Well short of any one connection's bounds, socket buffers or not:
    // without the budget nobody is dropped.
    let n = 2000;

    let mut stalled = Vec::new();
    for i in 0..4 {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
            .await
            .unwrap();
        let login = json!({ "id": 1, "req": "login", "params": { "nick": format!("stalled{i}") } });
        ws.send(Message::Text(login.to_string())).await.unwrap();
        loop {
            let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
                continue;
            };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["reply"] == 1 {
                assert!(v.get("ok").is_some(), "{v}");
                break;
            }
        }
        stalled.push(ws);
    }
    let (reader, heard) = listen(classic(server.legacy, "reader").await, n + 1);
    let talker = classic(server.legacy, "talker").await;
    let talking = tokio::spawn(flood(talker, n, heard));
    let (heard, _) = timeout(Duration::from_secs(30), reader)
        .await
        .unwrap()
        .unwrap();
    assert_all_in_order(&heard, n);

    // Now each stalled client reads: some of the room, then the end.
    for (i, mut ws) in stalled.into_iter().enumerate() {
        let mut lines = 0usize;
        let closed = loop {
            match timeout(Duration::from_secs(5), ws.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    lines += usize::from(t.contains("\"ev\":\"chat\""));
                }
                Ok(Some(Ok(Message::Close(_))) | None | Some(Err(_))) => break true,
                Ok(Some(Ok(_))) => {}
                Err(_) => break false,
            }
        };
        assert!(closed, "stalled{i} was kept, having heard {lines} lines");
        assert!(lines < n, "stalled{i} heard {lines} of {n} lines");
    }
    drop(talking);
}
