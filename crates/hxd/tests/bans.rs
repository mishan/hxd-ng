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
const REQ_USER_KICK: u32 = 0x6e;

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
    start_with(dir, "").await
}

/// [`start`], with `extra` at the end of a config written now.
async fn start_with(dir: &Path, extra: &str) -> Server {
    let d = dir.display();
    let path = dir.join("hxd-ng.toml");
    if !path.exists() {
        std::fs::write(
            &path,
            format!(
                "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n\
                 [ng]\nbind = \"127.0.0.1:0\"\n{extra}"
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
async fn classic_login(s: TcpStream) -> Result<(), String> {
    classic_login_as(s, "bob").await.map(drop)
}

/// A login to `login`, whose password is `pw`, on a classic connection:
/// the connection, logged in, or the task error's text.
async fn classic_login_as(mut s: TcpStream, login: &str) -> Result<TcpStream, String> {
    let frame = pack_frame(
        REQ_LOGIN,
        1,
        0,
        &[
            (tag::LOGIN, xor(login.as_bytes())),
            (tag::PASSWORD, xor(b"pw")),
            (tag::NAME, login.as_bytes().to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
        ],
    );
    s.write_all(&frame).await.unwrap();
    loop {
        let f = timeout(Duration::from_secs(5), read_frame(&mut s))
            .await
            .expect("no reply to the login")
            .expect("closed before the reply");
        if f.ty == HDR_TASK && f.trans == 1 {
            if f.flag == 0 {
                return Ok(s);
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

/// A moderator's account, and alice's, beside bob's: every password
/// `pw`.
fn more_accounts(dir: &Path) {
    std::fs::write(
        dir.join("accounts/mod.toml"),
        "name = \"mod\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
         send_chat = true\ndisconnect_users = true\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("accounts/alice.toml"),
        "name = \"alice\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
}

/// `login`'s ng session, kept open: the connection and its uid.
async fn ng_session(addr: SocketAddr, login: &str) -> (Ws, u64) {
    let mut ws = ng_connect(addr).await;
    let ok = request(
        &mut ws,
        "login",
        json!({ "login": login, "password": "pw", "nick": login }),
    )
    .await;
    let uid = ok["ok"]["self"]["uid"].as_u64().expect("logged in");
    (ws, uid)
}

/// Does a connection from here get the classic server's magic?
async fn classic_answers(addr: SocketAddr) -> bool {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    let mut magic = [0u8; 8];
    matches!(
        timeout(Duration::from_secs(5), s.read_exact(&mut magic)).await,
        Ok(Ok(_))
    )
}

/// A moderator's kick-with-ban bans the person and, unlike mhxd's, the
/// address only where `[limits] exempt` does not hold it. With loopback
/// off the list, a classic kick-with-ban of bob refuses his login and
/// the address both, as one ban that one lift undoes.
#[tokio::test]
async fn a_kick_ban_from_an_address_not_exempt_refuses_the_person_and_the_address() {
    let td = tempfile::tempdir().unwrap();
    let server = start_with(
        td.path(),
        "[limits]\nexempt = []\nconnections_per_addr = 0\nreconnect_seconds = 0\n",
    )
    .await;
    more_accounts(td.path());
    let (_bob, bob) = ng_session(server.ng, "bob").await;
    let mut moderator = classic_login_as(classic_connect(server.legacy).await, "mod")
        .await
        .expect("the moderator logs in");
    let kick = pack_frame(
        REQ_USER_KICK,
        2,
        0,
        &[
            (tag::UID, (bob as u32).to_be_bytes().to_vec()),
            (tag::BAN, 1u32.to_be_bytes().to_vec()),
        ],
    );
    moderator.write_all(&kick).await.unwrap();
    loop {
        let f = timeout(Duration::from_secs(5), read_frame(&mut moderator))
            .await
            .expect("no reply to the kick")
            .unwrap();
        if f.ty == HDR_TASK && f.trans == 2 {
            assert_eq!(f.flag, 0, "the kick is done");
            break;
        }
    }

    assert!(server.core.is_banned("127.0.0.1".parse().unwrap()));
    assert!(server.core.person_banned(Some("bob"), None, None).is_some());
    assert!(
        !classic_answers(server.legacy).await,
        "the address, refused"
    );
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{}/ng", server.ng))
            .await
            .is_err(),
        "on both wires"
    );
    let bans = server.core.list_bans(true, None, 10).unwrap();
    assert_eq!(bans.len(), 2, "bob's login and his address: {bans:?}");
    assert_eq!(bans[0].act, bans[1].act, "one act");
    assert!(bans
        .iter()
        .all(|b| b.source == hxd_core::ban::BanSource::Kick && b.actor == "mod"));

    let lifted = server
        .core
        .lift_ban(hxd_core::moderation::Actor::Operator, bans[0].id)
        .unwrap();
    assert_eq!(lifted.len(), 2, "lifting either row lifts both");
    classic(server.legacy).await.expect("bob, lifted");
    ng(server.ng).await.expect("bob, lifted, on ng");
}

/// From an address `[limits] exempt` holds (loopback, by default), a
/// moderator's kick-with-ban refuses the person alone: bob is refused
/// on both wires, and alice, from the very same address, gets in.
#[tokio::test]
async fn a_kick_ban_from_an_exempt_address_refuses_the_person_alone() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    more_accounts(td.path());
    let (_bob, bob) = ng_session(server.ng, "bob").await;
    let (mut moderator, _) = ng_session(server.ng, "mod").await;
    let kicked = request(&mut moderator, "kick", json!({ "uid": bob, "ban": 60 })).await;
    assert!(kicked.get("ok").is_some(), "{kicked}");

    assert!(!server.core.is_banned("127.0.0.1".parse().unwrap()));
    let refused = classic(server.legacy).await.unwrap_err();
    assert_eq!(
        refused,
        "You are banned from this server: banned by a moderator"
    );
    assert_eq!(ng(server.ng).await.unwrap_err()["code"], "banned");
    classic_login_as(classic_connect(server.legacy).await, "alice")
        .await
        .expect("another account from the same address");

    let bans = server.core.list_bans(true, None, 10).unwrap();
    assert_eq!(bans.len(), 1, "bob's login alone: {bans:?}");
    server
        .core
        .lift_ban(hxd_core::moderation::Actor::Operator, bans[0].id)
        .unwrap();
    classic(server.legacy).await.expect("bob, lifted");
}

/// A plain guest on an address `[limits] exempt` holds (loopback, by
/// default) has nothing of its own to ban: a classic kick-with-ban of
/// one places no ban, and public chat hears, in the reference server's
/// bytes, that it was kicked, not banned.
#[tokio::test]
async fn a_classic_kick_ban_of_a_plain_guest_on_an_exempt_address_only_kicks() {
    const HDR_CHAT: u32 = 0x6a;
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    more_accounts(td.path());
    let mut guest = ng_connect(server.ng).await;
    let ok = request(&mut guest, "login", json!({ "nick": "drifter" })).await;
    let guest_uid = ok["ok"]["self"]["uid"].as_u64().expect("a guest logs in");
    let mut moderator = classic_login_as(classic_connect(server.legacy).await, "mod")
        .await
        .expect("the moderator logs in");
    let kick = pack_frame(
        REQ_USER_KICK,
        2,
        0,
        &[
            (tag::UID, (guest_uid as u32).to_be_bytes().to_vec()),
            (tag::BAN, 1u32.to_be_bytes().to_vec()),
        ],
    );
    moderator.write_all(&kick).await.unwrap();
    let mut done = false;
    let mut announced = None;
    while !done || announced.is_none() {
        let f = timeout(Duration::from_secs(5), read_frame(&mut moderator))
            .await
            .expect("no reply to the kick, or no announcement")
            .unwrap();
        if f.ty == HDR_TASK && f.trans == 2 {
            assert_eq!(f.flag, 0, "the kick is done");
            done = true;
        } else if f.ty == HDR_CHAT {
            let body = f
                .chunks()
                .find(|c| c.tag == tag::BODY)
                .map(|c| c.data.to_vec())
                .unwrap_or_default();
            if body.windows(6).any(|w| w == b"drifte") {
                announced = Some(body);
            }
        }
    }
    assert_eq!(
        String::from_utf8_lossy(&announced.unwrap()),
        "\r<drifter has been kicked by mod>"
    );
    assert!(server.core.list_bans(true, None, 10).unwrap().is_empty());
    assert!(!server.core.is_banned("127.0.0.1".parse().unwrap()));
    let mut again = ng_connect(server.ng).await;
    let back = request(&mut again, "login", json!({ "nick": "drifter" })).await;
    assert!(back.get("ok").is_some(), "the guest may come back: {back}");
}
