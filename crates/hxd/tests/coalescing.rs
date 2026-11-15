//! A person's devices as one row (`[server] coalesce`), on real servers
//! built from a config: clients of an account whose identity is linked,
//! each on several devices and on either wire, and a classic watcher
//! that sees the person as one user: joining once, leaving once, and
//! kicked, banned or flooding as one; in a private chat or a room as one
//! member, each device hearing it once it joined it itself, and one
//! device leaving it leaving it for all. And with coalescing off, each
//! device a user of its own, as it always was.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use hxd_testclient::legacy::{self, Client, Frame, Login};
use hxd_testclient::ng;
use hxproto::messages::tag;
use serde_json::json;
use tokio::net::TcpSocket;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_CHAT: u32 = 0x69;
const HDR_CHAT_PUSH: u32 = 0x6a;
const HDR_USER_KICK: u32 = 0x6e;
const HDR_CHAT_CREATE: u32 = 0x70;
const HDR_CHAT_INVITE: u32 = 0x71;
const HDR_CHAT_JOIN: u32 = 0x73;
const HDR_CHAT_PART: u32 = 0x74;
const HDR_CHAT_USER_CHANGE: u32 = 0x75;
const HDR_CHAT_USER_PART: u32 = 0x76;
const HDR_USER_CHANGED: u32 = 0x12d;
const HDR_USER_LEFT: u32 = 0x12e;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
}

/// A server coalescing persons, with `limits` in its `[limits]`.
async fn start(dir: &Path, limits: &str) -> Server {
    start_with(dir, true, limits).await
}

async fn start_with(dir: &Path, coalesce: bool, limits: &str) -> Server {
    let d = dir.display();
    let path = dir.join("hxd-ng.toml");
    std::fs::write(dir.join("rooms.toml"), "[[room]]\nname = \"lounge\"\n").unwrap();
    std::fs::write(
        &path,
        format!(
            "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n\
             [ng]\nbind = \"127.0.0.1:0\"\n[server]\ncoalesce = {coalesce}\n\
             [rooms]\nfile = \"{d}/rooms.toml\"\n[system]\n\
             [limits]\nconnections_per_addr = 0\nreconnect_seconds = 0\n{limits}\n"
        ),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    // As the binary does, before anyone connects.
    ctx.core.start_system_session().unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let chat = "read_chat = true\nsend_chat = true\ncreate_pchats = true\n";
    for (login, access, linked) in [
        ("alice", "", Some(7)),
        ("bob", "", None),
        ("boss", "cant_be_disconnected = true\n", Some(8)),
        ("dave", "disconnect_users = true\n", Some(9)),
        ("keeper", "[extra]\nmanage_rooms = true\n", None),
    ] {
        let identity = linked
            .map(|b| {
                let fp = hl_identity::Fingerprint([b; 32]);
                format!("[identity]\nfingerprint = \"{fp}\"\n")
            })
            .unwrap_or_default();
        std::fs::write(
            dir.join(format!("accounts/{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{chat}{access}{identity}"),
        )
        .unwrap();
    }
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        core: ctx.core.clone(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

/// `login` on a classic device of its own, connecting from `from`.
async fn device_at(server: &Server, login: &str, from: &str) -> Client {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{from}:0").parse().unwrap()).unwrap();
    let stream = socket.connect(server.legacy).await.unwrap();
    let mut c = Client::over(Box::new(stream)).await.unwrap();
    let reply = c.login(&Login::account(login, login, "pw")).await.unwrap();
    assert!(!reply.is_error(), "{login}: {:?}", reply.error_text());
    c
}

async fn device(server: &Server, login: &str) -> Client {
    device_at(server, login, "127.0.0.1").await
}

/// `login` on an ng device.
async fn ng_device(server: &Server, login: &str) -> ng::Client {
    ng::Client::account(server.ng, login, "pw", login)
        .await
        .unwrap()
        .0
}

/// The uid `watcher` is told `nick` joined as.
async fn joined(watcher: &mut Client, nick: &str) -> u32 {
    let f = watcher
        .recv_where(|f| {
            f.ty == HDR_USER_CHANGED && f.bytes(tag::NAME).as_deref() == Some(nick.as_bytes())
        })
        .await
        .unwrap();
    f.uint(tag::UID).unwrap()
}

/// What `watcher` has been told of `uid` until now: its changes and its
/// leaving, by type.
async fn told_of(watcher: &mut Client, uid: u32) -> Vec<u32> {
    watcher.ping().await.unwrap();
    watcher
        .rx
        .take_backlog()
        .into_iter()
        .filter(|f| matches!(f.ty, HDR_USER_CHANGED | HDR_USER_LEFT))
        .filter(|f| f.uint(tag::UID) == Some(uid))
        .map(|f| f.ty)
        .collect()
}

/// Whether the server has closed `c`'s connection.
async fn closed(c: &mut Client) -> bool {
    loop {
        match c.recv().await {
            Ok(_) => continue,
            Err(hxd_testclient::Error::Timeout) => return false,
            Err(_) => return true,
        }
    }
}

/// A public chat push whose body is `body`.
fn notice(body: &str) -> impl Fn(&Frame) -> bool + '_ {
    move |f| f.ty == HDR_CHAT_PUSH && f.bytes(tag::BODY).as_deref() == Some(body.as_bytes())
}

/// A moderator on either wire.
enum Moderator {
    Classic(Client),
    Ng(ng::Client),
}

impl Moderator {
    async fn on(server: &Server, login: &str, ng: bool) -> Moderator {
        match ng {
            false => Moderator::Classic(device(server, login).await),
            true => Moderator::Ng(ng_device(server, login).await),
        }
    }

    /// A kick of `uid`, with a ban when `ban`: `Ok`, or the refusal's
    /// code (empty on the classic wire) and text.
    async fn kick(&mut self, uid: u32, ban: bool) -> Result<(), (String, String)> {
        match self {
            Moderator::Classic(c) => {
                let mut chunks = vec![(tag::UID, uid.to_be_bytes().to_vec())];
                if ban {
                    chunks.push((tag::BAN, 1u32.to_be_bytes().to_vec()));
                }
                let trans = c.send(HDR_USER_KICK, &chunks).await.unwrap();
                let reply = c
                    .recv_where(|f| f.ty == HDR_TASK && f.trans == trans)
                    .await
                    .unwrap();
                match reply.error_text() {
                    Some(text) => Err((String::new(), text)),
                    None => Ok(()),
                }
            }
            Moderator::Ng(c) => {
                let params = match ban {
                    true => json!({ "uid": uid, "ban": 60 }),
                    false => json!({ "uid": uid }),
                };
                match c.request("kick", params).await {
                    Ok(_) => Ok(()),
                    Err(hxd_testclient::Error::Refused { code, text }) => Err((code, text)),
                    Err(e) => panic!("kick: {e}"),
                }
            }
        }
    }
}

#[tokio::test]
async fn three_devices_join_as_one_user_and_leave_as_one() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let mut a3 = device(&server, "alice").await;
    assert_eq!(
        told_of(&mut bob, row).await,
        Vec::<u32>::new(),
        "no join but the first"
    );
    let listed = bob.user_list().await.unwrap();
    assert_eq!(listed.iter().filter(|u| u.nick == b"alice").count(), 1);

    for c in [&mut a1, &mut a2, &mut a3] {
        c.shutdown().await.unwrap();
        assert!(closed(c).await);
    }
    bob.recv_where(|f| f.ty == HDR_USER_LEFT && f.uint(tag::UID) == Some(row))
        .await
        .unwrap();
    assert_eq!(
        told_of(&mut bob, row).await,
        Vec::<u32>::new(),
        "one leaving, with the last"
    );
}

#[tokio::test]
async fn a_kick_on_either_wire_ends_a_person_on_both_and_is_told_once() {
    for (ng_moderator, ban) in [(false, false), (false, true), (true, false), (true, true)] {
        let case = format!("ng moderator {ng_moderator}, ban {ban}");
        let td = tempfile::tempdir().unwrap();
        let server = start(td.path(), "").await;
        let mut bob = device(&server, "bob").await;
        let mut dave = Moderator::on(&server, "dave", ng_moderator).await;
        let mut a1 = device(&server, "alice").await;
        let row = joined(&mut bob, "alice").await;
        let mut a2 = ng_device(&server, "alice").await;
        assert_eq!(
            a2.uid,
            Some(u64::from(row)),
            "{case}: one row on both wires"
        );

        // What the ng device's joining changed of the row.
        told_of(&mut bob, row).await;
        assert_eq!(dave.kick(row, ban).await, Ok(()), "{case}");
        let verb = if ban { "banned" } else { "kicked" };
        bob.recv_where(notice(&format!("\r<alice has been {verb} by dave>")))
            .await
            .unwrap();
        assert!(closed(&mut a1).await, "{case}: the classic device");
        assert!(a2.event("kicked").await.is_ok(), "{case}: the ng device");
        bob.recv_where(|f| f.ty == HDR_USER_LEFT && f.uint(tag::UID) == Some(row))
            .await
            .unwrap();
        assert_eq!(told_of(&mut bob, row).await, Vec::<u32>::new(), "{case}");
    }
}

#[tokio::test]
async fn a_person_flooding_from_two_devices_is_kicked_once() {
    let td = tempfile::tempdir().unwrap();
    let server = start(
        td.path(),
        "chat_lines = 3\nchat_seconds = 60\nspam_points = 0",
    )
    .await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device(&server, "alice").await;
    let mut a2 = device(&server, "alice").await;
    // Two lines from each: either device alone is inside the limit.
    a1.chat(b"one\rtwo").await.unwrap();
    a2.chat(b"three\rfour").await.unwrap();
    let kicked = notice("\r *** alice was kicked for chat spamming");
    bob.recv_where(&kicked).await.unwrap();
    assert!(
        closed(&mut a1).await && closed(&mut a2).await,
        "both devices"
    );
    bob.ping().await.unwrap();
    assert!(!bob.rx.take_backlog().iter().any(kicked), "told once");
}

#[tokio::test]
async fn an_address_ban_ends_the_device_at_that_address_alone() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device_at(&server, "alice", "127.0.0.1").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device_at(&server, "alice", "127.0.0.2").await;
    server
        .core
        .place_ban(
            hxd_core::Actor::Operator,
            hxd_core::ban::NewBan {
                target: hxd_core::ban::BanTarget::address("127.0.0.2".parse().unwrap(), 32)
                    .unwrap(),
                reason: "spam".into(),
                note: None,
                expires_at: None,
                source: hxd_core::ban::BanSource::Cli,
            },
        )
        .unwrap();
    assert!(closed(&mut a2).await);
    a1.ping().await.unwrap();
    assert_eq!(
        told_of(&mut bob, row).await,
        Vec::<u32>::new(),
        "the person stays"
    );
}

#[tokio::test]
async fn a_protected_person_stays_protected_once_the_device_holding_its_row_is_gone() {
    for (ng_moderator, refusal) in [
        (false, ("", "That user cannot be disconnected.")),
        (true, ("protected", "That user cannot be moderated by you.")),
    ] {
        let td = tempfile::tempdir().unwrap();
        let server = start(td.path(), "").await;
        let mut watcher = device(&server, "bob").await;
        let mut dave = Moderator::on(&server, "dave", ng_moderator).await;
        let mut b1 = device(&server, "boss").await;
        let row = joined(&mut watcher, "boss").await;
        let mut b2 = device(&server, "boss").await;
        b1.shutdown().await.unwrap();
        assert!(closed(&mut b1).await);
        assert_eq!(
            dave.kick(row, false).await,
            Err((refusal.0.into(), refusal.1.into())),
            "ng moderator {ng_moderator}"
        );
        b2.ping().await.unwrap();
    }
}

#[tokio::test]
async fn a_moderator_may_not_kick_their_own_person() {
    for (ng_kicker, refusal) in [
        (false, ("", "You cannot disconnect yourself.")),
        (true, ("bad_request", "You cannot kick yourself.")),
    ] {
        let td = tempfile::tempdir().unwrap();
        let server = start(td.path(), "").await;
        let mut bob = device(&server, "bob").await;
        let mut d1 = device(&server, "dave").await;
        let row = joined(&mut bob, "dave").await;
        let mut d2 = Moderator::on(&server, "dave", ng_kicker).await;
        // What the second device's joining changed of the row.
        told_of(&mut bob, row).await;
        assert_eq!(
            d2.kick(row, false).await,
            Err((refusal.0.into(), refusal.1.into())),
            "ng kicker {ng_kicker}"
        );
        d1.ping().await.unwrap();
        assert_eq!(told_of(&mut bob, row).await, Vec::<u32>::new());
    }
}

#[tokio::test]
async fn a_line_racing_the_kick_is_not_heard_after_it() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "chat_lines = 0\nspam_points = 0").await;
    let mut bob = device(&server, "bob").await;
    let mut dave = Moderator::on(&server, "dave", false).await;
    let _a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let burst: Vec<u8> = (0..400)
        .flat_map(|i| {
            legacy::pack(
                HDR_CHAT,
                1000 + i,
                0,
                &[(tag::BODY, format!("line {i}").into_bytes())],
            )
        })
        .collect();
    bob.ping().await.unwrap();
    bob.rx.take_backlog();
    a2.tx.send_raw(&burst).await.unwrap();
    assert_eq!(dave.kick(row, false).await, Ok(()));
    let kicked = notice("\r<alice has been kicked by dave>");
    // In the order heard: whatever came before the notice may, nothing
    // after it may.
    while !kicked(&bob.recv().await.unwrap()) {}
    bob.ping().await.unwrap();
    let after = bob
        .rx
        .take_backlog()
        .into_iter()
        .filter(|f| f.ty == HDR_CHAT_PUSH && f.uint(tag::UID) == Some(row))
        .count();
    assert_eq!(after, 0, "lines heard after the kick");
}

#[tokio::test]
async fn a_kick_with_a_ban_racing_a_login_leaves_nothing_of_the_person() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut bob = device(&server, "bob").await;
    let mut dave = Moderator::on(&server, "dave", false).await;
    let mut a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let racing = {
        let stream = TcpSocket::new_v4()
            .unwrap()
            .connect(server.legacy)
            .await
            .unwrap();
        tokio::spawn(async move {
            let mut c = Client::over(Box::new(stream)).await.ok()?;
            c.login(&Login::account("alice", "alice", "pw"))
                .await
                .ok()?;
            Some(c)
        })
    };
    assert_eq!(dave.kick(row, true).await, Ok(()));
    assert!(closed(&mut a1).await && closed(&mut a2).await);
    // Refused at the door, or let in and ended by the ban: never left on.
    if let Some(mut late) = racing.await.unwrap() {
        assert!(closed(&mut late).await, "the racing login");
    }
    let listed = bob.user_list().await.unwrap();
    assert!(!listed.iter().any(|u| u.nick == b"alice"), "{listed:?}");
}

#[tokio::test]
async fn a_mask_set_on_one_device_is_told_to_the_other() {
    const HDR_USER_ACCESS: u32 = 0x162;
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut bob = device(&server, "bob").await;
    let _a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    a2.ping().await.unwrap();
    a2.rx.take_backlog();
    let mask = hxd_core::DenyMask {
        access: hxd_core::AccessBits::empty().with(hxd_core::access::bit::SEND_CHAT),
        ..Default::default()
    };
    assert!(server.core.set_session_mask(row as u16, mask));
    let pushed = a2.recv_where(|f| f.ty == HDR_USER_ACCESS).await.unwrap();
    assert!(!sends(&pushed), "the other device's access");
}

/// Whether a SELFINFO says its session may send to public chat.
fn sends(f: &Frame) -> bool {
    let wire: [u8; 8] = f.bytes(tag::ACCESS).unwrap().try_into().unwrap();
    hxd_core::AccessBits::from_wire(wire).has(hxd_core::access::bit::SEND_CHAT)
}

#[tokio::test]
async fn a_device_joining_a_masked_person_is_told_it_is_masked_as_it_joins() {
    const HDR_USER_ACCESS: u32 = 0x162;
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut bob = device(&server, "bob").await;
    let _a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mask = hxd_core::DenyMask {
        access: hxd_core::AccessBits::empty().with(hxd_core::access::bit::SEND_CHAT),
        ..Default::default()
    };
    assert!(server.core.set_session_mask(row as u16, mask));
    let mut a2 = device(&server, "alice").await;
    a2.ping().await.unwrap();
    let told: Vec<bool> = a2
        .rx
        .take_backlog()
        .iter()
        .filter(|f| f.ty == HDR_USER_ACCESS)
        .map(sends)
        .collect();
    // Before it joins it is its account's; once it has, the person's.
    assert_eq!(told.get(1), Some(&false), "{told:?}");
}

#[tokio::test]
async fn with_coalescing_off_each_device_is_a_user_of_its_own() {
    let td = tempfile::tempdir().unwrap();
    let server = start_with(
        td.path(),
        false,
        "chat_lines = 3\nchat_seconds = 60\nspam_points = 0",
    )
    .await;
    let mut bob = device(&server, "bob").await;
    let mut d1 = device(&server, "dave").await;
    let dave = joined(&mut bob, "dave").await;
    let mut a1 = device(&server, "alice").await;
    let first = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let second = joined(&mut bob, "alice").await;
    assert_ne!(first, second, "two users");
    // Two lines each: inside each session's own limit.
    a1.chat(b"one\rtwo").await.unwrap();
    a2.chat(b"three\rfour").await.unwrap();
    a1.ping().await.unwrap();
    a2.ping().await.unwrap();

    let mut d2 = Moderator::on(&server, "dave", false).await;
    assert_eq!(d2.kick(first, false).await, Ok(()));
    assert!(closed(&mut a1).await);
    a2.ping().await.unwrap();
    bob.recv_where(|f| f.ty == HDR_USER_LEFT && f.uint(tag::UID) == Some(first))
        .await
        .unwrap();
    // A moderator's other session is someone else to kick, as ever.
    assert_eq!(d2.kick(dave, false).await, Ok(()));
    assert!(closed(&mut d1).await);
}

/// A watcher here pings to see what it was told, more often than a
/// person would.
const PINGS: &str = "spam_points = 0";

/// The uids a 115 reply lists.
fn listed(reply: &Frame) -> Vec<u32> {
    reply
        .all(tag::USER_LIST)
        .iter()
        .map(|row| u32::from(u16::from_be_bytes([row[0], row[1]])))
        .collect()
}

/// `c`'s 115 of chat or room `cid`: who it lists, or the refusal.
async fn join_chat(c: &mut Client, cid: u32) -> Result<Vec<u32>, String> {
    let reply = c
        .call(HDR_CHAT_JOIN, &[(tag::CHAT_ID, cid.to_be_bytes().to_vec())])
        .await
        .unwrap();
    match reply.error_text() {
        Some(text) => Err(text),
        None => Ok(listed(&reply)),
    }
}

/// A line `c` says in chat or room `cid`, relayed by the time this
/// returns.
async fn say_in(c: &mut Client, cid: u32, text: &str) {
    c.send(
        HDR_CHAT,
        &[
            (tag::BODY, text.as_bytes().to_vec()),
            (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
        ],
    )
    .await
    .unwrap();
    c.ping().await.unwrap();
}

/// What `c` has been told of chat or room `cid` until now: joins and
/// parts by type and the uid they name, and lines by their body.
async fn told_in(c: &mut Client, cid: u32) -> Vec<String> {
    c.ping().await.unwrap();
    c.rx.take_backlog()
        .into_iter()
        .filter(|f| f.uint(tag::CHAT_ID) == Some(cid))
        .filter_map(|f| match f.ty {
            HDR_CHAT_INVITE => Some(format!("invite {}", f.uint(tag::UID)?)),
            HDR_CHAT_USER_CHANGE => Some(format!("join {}", f.uint(tag::UID)?)),
            HDR_CHAT_USER_PART => Some(format!("part {}", f.uint(tag::UID)?)),
            HDR_CHAT_PUSH => Some(String::from_utf8_lossy(&f.bytes(tag::BODY)?).into_owned()),
            _ => None,
        })
        .collect()
}

/// What an ng client has been told of room `room` until now: its
/// members' comings and goings and its lines, as `told_in` puts them.
async fn ng_told_in(c: &mut ng::Client, room: u32) -> Vec<String> {
    c.request("ping", json!({})).await.unwrap();
    c.rx.take_backlog()
        .into_iter()
        .filter(|e| e.data["room"].as_u64() == Some(u64::from(room)))
        .filter_map(|e| match e.ev.as_str() {
            "room_member_joined" => Some(format!("join {}", e.data["user"]["uid"])),
            "room_member_parted" => Some(format!("part {}", e.data["uid"])),
            "chat" => Some(format!("{}: {}", e.data["from"]["uid"], e.data["text"])),
            _ => None,
        })
        .collect()
}

fn line(nick: &str, text: &str) -> String {
    format!("\r{nick:>13}:  {text}")
}

#[tokio::test]
async fn a_persons_devices_are_one_member_of_a_private_chat_and_one_leaving_leaves_for_both() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), PINGS).await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let b = u32::from(bob.uid.unwrap());

    let created = bob
        .call(HDR_CHAT_CREATE, &[(tag::UID, row.to_be_bytes().to_vec())])
        .await
        .unwrap();
    let cid = created.uint(tag::CHAT_ID).unwrap();
    let invite = vec![format!("invite {b}")];
    assert_eq!(told_in(&mut a1, cid).await, invite);
    assert_eq!(told_in(&mut a2, cid).await, invite, "both devices");

    assert_eq!(join_chat(&mut a1, cid).await, Ok(vec![b, row]));
    assert_eq!(told_in(&mut bob, cid).await, [format!("join {row}")]);
    say_in(&mut bob, cid, "before").await;
    told_in(&mut bob, cid).await;
    assert_eq!(told_in(&mut a1, cid).await, [line("bob", "before")]);
    assert_eq!(told_in(&mut a2, cid).await, Vec::<String>::new());

    assert_eq!(join_chat(&mut a2, cid).await, Ok(vec![b, row]), "once");
    assert_eq!(
        told_in(&mut bob, cid).await,
        Vec::<String>::new(),
        "no join"
    );
    say_in(&mut a2, cid, "from the phone").await;
    let theirs = vec![line("alice", "from the phone")];
    assert_eq!(told_in(&mut bob, cid).await, theirs);
    assert_eq!(told_in(&mut a1, cid).await, theirs);
    assert_eq!(told_in(&mut a2, cid).await, theirs, "its own too");

    a1.send(HDR_CHAT_PART, &[(tag::CHAT_ID, cid.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert_eq!(told_in(&mut bob, cid).await, [format!("part {row}")]);
    let told = told_in(&mut a2, cid).await;
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(
        told[0].contains("you left this chat on another device"),
        "{told:?}"
    );
    say_in(&mut bob, cid, "gone?").await;
    assert_eq!(told_in(&mut a1, cid).await, Vec::<String>::new());
    assert_eq!(told_in(&mut a2, cid).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_private_chat_made_on_one_device_is_its_rows_and_its_others_are_invited_to_it() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), PINGS).await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let b = u32::from(bob.uid.unwrap());

    let created = a2
        .call(HDR_CHAT_CREATE, &[(tag::UID, b.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert_eq!(created.uint(tag::UID), Some(row), "the 112 reply's row");
    let cid = created.uint(tag::CHAT_ID).unwrap();
    assert_eq!(told_in(&mut bob, cid).await, [format!("invite {row}")]);
    let server_uid = server.core.system_uid().unwrap();
    assert_eq!(
        told_in(&mut a1, cid).await,
        [format!("invite {server_uid}")],
        "by the server"
    );
    assert_eq!(join_chat(&mut bob, cid).await, Ok(vec![row, b]));
    assert_eq!(told_in(&mut a2, cid).await, [format!("join {b}")]);
    assert_eq!(
        told_in(&mut a1, cid).await,
        Vec::<String>::new(),
        "not open"
    );
    assert_eq!(join_chat(&mut a1, cid).await, Ok(vec![row, b]));
    assert_eq!(told_in(&mut bob, cid).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_device_hears_its_persons_room_once_it_joins_it_on_either_wire() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), PINGS).await;
    let mut bob = device(&server, "bob").await;
    let mut dave = ng_device(&server, "dave").await;
    let mut a1 = device(&server, "alice").await;
    let row = joined(&mut bob, "alice").await;
    let mut a2 = ng_device(&server, "alice").await;
    let b = u32::from(bob.uid.unwrap());
    let lounge = server.core.room_list(bob.uid.unwrap())[0].room.id;
    let rq = json!({ "room": lounge });
    join_chat(&mut bob, lounge).await.unwrap();
    dave.request("room_join", rq.clone()).await.unwrap();
    ng_told_in(&mut dave, lounge).await;
    told_in(&mut bob, lounge).await;

    let members = join_chat(&mut a1, lounge).await.unwrap();
    assert_eq!(members.iter().filter(|u| **u == row).count(), 1);
    // The line saying what the room is.
    told_in(&mut a1, lounge).await;
    assert_eq!(told_in(&mut bob, lounge).await, [format!("join {row}")]);
    assert_eq!(ng_told_in(&mut dave, lounge).await, [format!("join {row}")]);
    say_in(&mut bob, lounge, "before").await;
    told_in(&mut bob, lounge).await;
    ng_told_in(&mut dave, lounge).await;
    assert_eq!(told_in(&mut a1, lounge).await, [line("bob", "before")]);
    assert_eq!(ng_told_in(&mut a2, lounge).await, Vec::<String>::new());
    let refused = a2
        .request("chat", json!({ "room": lounge, "text": "x" }))
        .await;
    assert!(refused.is_err(), "not in it to speak there");

    let joined_ng = a2.request("room_join", rq.clone()).await.unwrap();
    let uids: Vec<u64> = joined_ng["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_u64())
        .collect();
    assert_eq!(uids.iter().filter(|u| **u == u64::from(row)).count(), 1);
    assert_eq!(
        told_in(&mut bob, lounge).await,
        Vec::<String>::new(),
        "no join"
    );
    assert_eq!(ng_told_in(&mut dave, lounge).await, Vec::<String>::new());
    a2.request("chat", json!({ "room": lounge, "text": "from the phone" }))
        .await
        .unwrap();
    assert_eq!(
        told_in(&mut bob, lounge).await,
        [line("alice", "from the phone")]
    );
    assert_eq!(
        ng_told_in(&mut dave, lounge).await,
        [format!("{row}: \"from the phone\"")],
        "the row's line"
    );
    assert_eq!(
        told_in(&mut a1, lounge).await,
        [line("alice", "from the phone")]
    );
    assert_eq!(
        ng_told_in(&mut a2, lounge).await,
        [format!("{row}: \"from the phone\"")]
    );

    a2.request("room_part", rq).await.unwrap();
    assert_eq!(told_in(&mut bob, lounge).await, [format!("part {row}")]);
    assert_eq!(ng_told_in(&mut dave, lounge).await, [format!("part {row}")]);
    let told = told_in(&mut a1, lounge).await;
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(
        told[0].contains("you left #lounge on another device"),
        "{told:?}"
    );
    say_in(&mut bob, lounge, "gone?").await;
    assert_eq!(told_in(&mut a1, lounge).await, Vec::<String>::new());
    assert_eq!(ng_told_in(&mut a2, lounge).await, Vec::<String>::new());
    assert_eq!(b, u32::from(bob.uid.unwrap()));
}

#[tokio::test]
async fn with_coalescing_off_each_device_is_a_member_of_its_own() {
    let td = tempfile::tempdir().unwrap();
    let server = start_with(td.path(), false, PINGS).await;
    let mut bob = device(&server, "bob").await;
    let mut a1 = device(&server, "alice").await;
    let first = joined(&mut bob, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let second = joined(&mut bob, "alice").await;
    let b = u32::from(bob.uid.unwrap());
    let created = bob
        .call(HDR_CHAT_CREATE, &[(tag::UID, first.to_be_bytes().to_vec())])
        .await
        .unwrap();
    let cid = created.uint(tag::CHAT_ID).unwrap();
    assert_eq!(told_in(&mut a2, cid).await, Vec::<String>::new());
    assert_eq!(join_chat(&mut a1, cid).await, Ok(vec![b, first]));
    assert_eq!(join_chat(&mut a2, cid).await, Ok(vec![b, first, second]));
    assert_eq!(
        told_in(&mut bob, cid).await,
        [format!("join {first}"), format!("join {second}")]
    );

    let lounge = server.core.room_list(bob.uid.unwrap())[0].room.id;
    join_chat(&mut bob, lounge).await.unwrap();
    told_in(&mut bob, lounge).await;
    join_chat(&mut a1, lounge).await.unwrap();
    join_chat(&mut a2, lounge).await.unwrap();
    told_in(&mut a2, lounge).await;
    assert_eq!(
        told_in(&mut bob, lounge).await,
        [format!("join {first}"), format!("join {second}")]
    );
    a1.send(
        HDR_CHAT_PART,
        &[(tag::CHAT_ID, lounge.to_be_bytes().to_vec())],
    )
    .await
    .unwrap();
    assert_eq!(told_in(&mut a2, lounge).await, [format!("part {first}")]);
    say_in(&mut bob, lounge, "still here").await;
    assert_eq!(told_in(&mut a2, lounge).await, [line("bob", "still here")]);
}

/// A room a person may no longer be in, told to each classic device that
/// had it open by its removal line, and never as a 118: the device whose
/// uid is the row's no more than the other, whose own uid nobody lists.
#[tokio::test]
async fn a_room_the_person_is_removed_from_is_a_line_to_each_device_and_no_part() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), PINGS).await;
    let keeper = device(&server, "keeper").await;
    let mut a1 = device(&server, "alice").await;
    let mut a2 = device(&server, "alice").await;
    let lounge = server.core.room_list(keeper.uid.unwrap())[0].room.id;
    for a in [&mut a1, &mut a2] {
        join_chat(a, lounge).await.unwrap();
        told_in(a, lounge).await;
    }
    let gate = hxd_core::RoomEdit {
        read: Some(vec!["keeper".into()]),
        ..hxd_core::RoomEdit::default()
    };
    server
        .core
        .room_edit(keeper.uid.unwrap(), lounge, gate)
        .unwrap();
    for a in [&mut a1, &mut a2] {
        let told = told_in(a, lounge).await;
        assert_eq!(told.len(), 1, "{told:?}");
        assert!(
            told[0].contains("you were removed from #lounge"),
            "{told:?}"
        );
    }
}
