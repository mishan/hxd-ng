//! Durable bans end to end (`hxd_core::ban`): real servers built from a
//! config file whose `[inbox]` database keeps the bans, the operator's
//! `hxd ban` commands run against it, and logins on both wires.
//!
//! What the unit tests cannot show: that a ban outlives the process that
//! placed it, that one placed from the command line reaches a running
//! server when it rereads (SIGHUP), and what each wire is told when it
//! is refused.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_session::frame::{pack_frame, read_frame};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const REQ_LOGIN: u32 = 0x6b;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
    config: hxd::Config,
    serving: [tokio::task::JoinHandle<()>; 2],
}

impl Server {
    /// Stop serving, and let go of everything the server held: its
    /// listeners, its contexts and its store, as a process that exits
    /// would. Nothing was left connected to it.
    async fn stop(self) {
        for task in self.serving {
            task.abort();
            let ended = task.await;
            assert!(
                ended.as_ref().is_err_and(|e| e.is_cancelled()),
                "a serve task ended by itself: {ended:?}"
            );
        }
        assert_eq!(
            Arc::strong_count(&self.core),
            1,
            "something of the stopped server still holds its core"
        );
    }
}

/// A server on `dir`'s config and database, written on first use: a
/// restart is a second call on the same directory.
async fn start(dir: &Path) -> Server {
    let d = dir.display();
    let path = dir.join("hxd-ng.toml");
    if !path.exists() {
        std::fs::write(
            &path,
            format!(
                "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n\
                 [ng]\nbind = \"127.0.0.1:0\"\n"
            ),
        )
        .unwrap();
    }
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    std::fs::write(
        dir.join("accounts/bob.toml"),
        "name = \"bob\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n",
    )
    .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        core: ctx.core.clone(),
        config,
        serving: [
            tokio::spawn(hxd_session::serve(legacy, ctx)),
            tokio::spawn(hxd_ng_session::serve(ng, ng_ctx)),
        ],
    }
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| !b).collect()
}

/// Bob's classic login: `Ok` or the task error's text.
async fn classic(addr: SocketAddr) -> Result<(), String> {
    classic_login(classic_connect(addr).await).await
}

/// A classic connection past the handshake, not yet logged in.
async fn classic_connect(addr: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut magic = [0u8; 8];
    s.read_exact(&mut magic).await.unwrap();
    s
}

/// Bob's login on a classic connection: `Ok` or the task error's text.
async fn classic_login(mut s: TcpStream) -> Result<(), String> {
    let login = pack_frame(
        REQ_LOGIN,
        1,
        0,
        &[
            (tag::LOGIN, xor(b"bob")),
            (tag::PASSWORD, xor(b"pw")),
            (tag::NAME, b"bob".to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
        ],
    );
    s.write_all(&login).await.unwrap();
    loop {
        let f = timeout(Duration::from_secs(5), read_frame(&mut s))
            .await
            .expect("no reply to the login")
            .expect("closed before the reply");
        if f.ty == HDR_TASK && f.trans == 1 {
            if f.flag == 0 {
                return Ok(());
            }
            let text = f
                .chunks()
                .find(|c| c.tag == tag::TASK_ERROR)
                .map(|c| String::from_utf8_lossy(c.data).into_owned())
                .unwrap_or_default();
            return Err(text);
        }
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Bob's ng login: `Ok` or the reply's error.
async fn ng(addr: SocketAddr) -> Result<(), Value> {
    ng_login(ng_connect(addr).await).await
}

/// An ng connection past the upgrade, not yet logged in.
async fn ng_connect(addr: SocketAddr) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ng"))
        .await
        .unwrap();
    ws
}

/// Bob's login on an ng connection: `Ok` or the reply's error.
async fn ng_login(mut ws: Ws) -> Result<(), Value> {
    let login = json!({ "id": 1, "req": "login",
        "params": { "login": "bob", "password": "pw", "nick": "bob" } });
    ws.send(Message::Text(login.to_string())).await.unwrap();
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("no reply to the login")
            .expect("closed before the reply")
            .unwrap();
        let Message::Text(t) = msg else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 1 {
            return match v.get("error") {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            };
        }
    }
}

#[tokio::test]
async fn the_command_line_bans_a_login_on_both_wires_until_it_lifts_it() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    classic(server.legacy).await.expect("not banned yet");

    let placed = hxd::moderation::ban_add(
        &server.config,
        "login:bob",
        "spam",
        Some("the operator's note".into()),
        None,
    )
    .unwrap();
    assert!(placed.starts_with("#1 login bob: spam"), "{placed}");
    // Placed against the store, the running server hears of it when it
    // rereads: SIGHUP.
    classic(server.legacy).await.expect("not reread yet");
    server.core.reload_bans();

    let refused = classic(server.legacy).await.unwrap_err();
    assert_eq!(refused, "You are banned from this server: spam");
    let refused = ng(server.ng).await.unwrap_err();
    assert_eq!(refused["code"], "banned");
    assert_eq!(refused["reason"], "spam");
    assert_eq!(refused["expires_at"], Value::Null);

    let listed = hxd::moderation::ban_list(&server.config, false).unwrap();
    assert!(listed.contains("#1 login bob: spam"), "{listed}");
    hxd::moderation::ban_lift(&server.config, 1).unwrap();
    assert_eq!(
        hxd::moderation::ban_list(&server.config, false).unwrap(),
        "nobody is banned"
    );
    assert!(hxd::moderation::ban_list(&server.config, true)
        .unwrap()
        .contains("#1"));
    assert!(hxd::moderation::ban_lift(&server.config, 1).is_err());
    server.core.reload_bans();
    classic(server.legacy).await.expect("lifted");
    ng(server.ng).await.expect("lifted");
}

#[tokio::test]
async fn a_ban_outlives_the_server_that_placed_it() {
    let td = tempfile::tempdir().unwrap();
    let first = start(td.path()).await;
    first
        .core
        .place_ban(
            hxd_core::moderation::Actor::Operator,
            hxd_core::ban::NewBan {
                target: hxd_core::ban::BanTarget::login("bob").unwrap(),
                reason: "flood".into(),
                note: None,
                expires_at: Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                source: hxd_core::ban::BanSource::Moderator,
            },
        )
        .unwrap();
    hxd::moderation::ban_add(&first.config, "192.0.2.0/24", "a botnet", None, None).unwrap();
    first.stop().await;

    let second = start(td.path()).await;
    assert!(second.core.is_banned("192.0.2.200".parse().unwrap()));
    assert!(!second.core.is_banned("192.0.3.1".parse().unwrap()));
    let refused = ng(second.ng).await.unwrap_err();
    assert_eq!(refused["code"], "banned");
    assert!(refused["expires_at"].is_u64(), "a ban for an hour says so");
    assert!(classic(second.legacy).await.is_err());
}

/// One request on `ws` and its reply.
async fn request(ws: &mut Ws, req: &str, params: Value) -> Value {
    let msg = json!({ "id": 1, "req": req, "params": params });
    ws.send(Message::Text(msg.to_string())).await.unwrap();
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("no reply")
            .expect("closed before the reply")
            .unwrap();
        let Message::Text(t) = msg else {
            continue;
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["reply"] == 1 {
            return v;
        }
    }
}

#[tokio::test]
async fn a_session_banned_while_away_is_refused_its_resume_and_ended() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    // Unkickable, so the ban spares the session where it stands and its
    // resume is the next connection that is refused.
    std::fs::write(
        td.path().join("accounts/tank.toml"),
        "name = \"tank\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
         cant_be_disconnected = true\n",
    )
    .unwrap();
    let url = format!("ws://{}/ng", server.ng);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let hello = request(
        &mut ws,
        "login",
        json!({ "login": "tank", "password": "pw", "nick": "tank" }),
    )
    .await;
    let ok = &hello["ok"];
    let uid = ok["self"]["uid"].as_u64().expect("the login's uid") as u16;
    let (session, token) = (ok["session"].clone(), ok["token"].clone());
    drop(ws);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !server.core.is_detached(uid) {
        assert!(tokio::time::Instant::now() < deadline, "never detached");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server
        .core
        .place_ban(
            hxd_core::moderation::Actor::Operator,
            hxd_core::ban::NewBan {
                target: hxd_core::ban::BanTarget::login("tank").unwrap(),
                reason: "flood".into(),
                note: None,
                expires_at: None,
                source: hxd_core::ban::BanSource::Moderator,
            },
        )
        .unwrap();
    assert!(server.core.is_detached(uid), "spared where it stood");

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let refused = request(
        &mut ws,
        "resume",
        json!({ "session": session, "token": token, "last_seq": 0 }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "banned", "{refused}");
    assert_eq!(refused["error"]["reason"], "flood");
    assert!(
        server.core.user(uid).is_none(),
        "ended, not left detached for its grace"
    );
}

#[tokio::test]
async fn an_address_ban_placed_between_connecting_and_logging_in_ends_the_session_as_it_joins() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    // Both connections are past the door the address is asked at, and
    // neither is on the roster for the ban to end.
    let classic_conn = classic_connect(server.legacy).await;
    let ng_conn = ng_connect(server.ng).await;
    server
        .core
        .place_ban(
            hxd_core::moderation::Actor::Operator,
            hxd_core::ban::NewBan {
                target: hxd_core::ban::BanTarget::parse("127.0.0.0/8", |_| None).unwrap(),
                reason: "a botnet".into(),
                note: None,
                expires_at: None,
                source: hxd_core::ban::BanSource::Moderator,
            },
        )
        .unwrap();

    let refused = classic_login(classic_conn).await.unwrap_err();
    assert_eq!(refused, "You are banned from this server: a botnet");
    let refused = ng_login(ng_conn).await.unwrap_err();
    assert_eq!(refused["code"], "banned");
    assert_eq!(refused["reason"], "a botnet");
    assert!(
        server.core.snapshot().iter().all(|u| u.nick != "bob"),
        "ended as it joined, not left on the roster"
    );
}
