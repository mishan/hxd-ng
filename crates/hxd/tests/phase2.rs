//! Phase 2a end-to-end tests: chat, private chats, messaging, and
//! moderation, driven by scripted legacy clients over real TCP.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hotline_proto::messages::tag;
use hxd_core::Core;
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_CHAT: u32 = 0x6a;
const HDR_MSG: u32 = 0x68;
const HDR_BROADCAST: u32 = 0x163;
const HDR_CHAT_INVITE_PUSH: u32 = 0x71;
const HDR_CHAT_USER_CHANGE: u32 = 0x75;
const HDR_CHAT_USER_PART: u32 = 0x76;
const HDR_CHAT_SUBJECT_PUSH: u32 = 0x77;
const HDR_SELFINFO: u32 = 0x162;
const HDR_USER_PART: u32 = 0x12e;

const REQ_LOGIN: u32 = 0x6b;
const REQ_CHAT: u32 = 0x69;
const REQ_CHAT_CREATE: u32 = 0x70;
const REQ_CHAT_INVITE: u32 = 0x71;
const REQ_CHAT_JOIN: u32 = 0x73;
const REQ_CHAT_PART: u32 = 0x74;
const REQ_CHAT_SUBJECT: u32 = 0x78;
const REQ_MSG: u32 = 0x6c;
const REQ_BROADCAST: u32 = 0x163;
const REQ_USER_GETINFO: u32 = 0x12f;
const REQ_USER_KICK: u32 = 0x6e;

async fn start_server(dir: &Path) -> (SocketAddr, ServerCtx) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    // An admin account for the moderation tests.
    std::fs::write(
        accounts.join("admin.toml"),
        "name = \"Admin\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\ncan_broadcast = true\nget_user_info = true\ndisconnect_users = true\n\
         use_any_name = true\ncreate_pchats = true\n",
    )
    .unwrap();
    // An untouchable account.
    std::fs::write(
        accounts.join("armored.toml"),
        "name = \"Armored\"\n[access]\nread_chat = true\ncant_be_disconnected = true\nuse_any_name = true\n",
    )
    .unwrap();
    let ctx = ServerCtx {
        core: Arc::new(Core::new()),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "p2".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
        }),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(listener, ctx.clone()));
    (addr, ctx)
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

struct Client {
    stream: TcpStream,
    trans: u32,
    uid: u16,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Client {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut reply = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .unwrap();
        Client {
            stream,
            trans: 0,
            uid: 0,
        }
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.trans
    }

    async fn recv(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while a frame was expected")
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..12 {
            let f = self.recv().await;
            if f.ty == ty {
                return f;
            }
        }
        panic!("frame type {ty:#x} never arrived");
    }

    /// Log in ready-to-chat: name, icon, 1.5 version; consume the
    /// self-info push so the session is fully announced.
    async fn login(addr: SocketAddr, nick: &str, login: &str, password: &str) -> Client {
        let mut c = Client::connect(addr).await;
        let mut chunks = vec![
            (tag::NAME, nick.as_bytes().to_vec()),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
        ];
        if !login.is_empty() {
            chunks.push((tag::LOGIN, xor(login.as_bytes())));
            chunks.push((tag::PASSWORD, xor(password.as_bytes())));
        }
        c.send(REQ_LOGIN, &chunks).await;
        let f = c.recv_type(HDR_TASK).await;
        assert_eq!(f.flag, 0, "login must succeed");
        c.uid = f
            .chunks()
            .find(|ch| ch.tag == tag::UID)
            .map(|ch| ch.as_uint() as u16)
            .unwrap();
        c.recv_type(HDR_SELFINFO).await;
        c
    }
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

fn chunk_u32(f: &Frame, want: u16) -> Option<u32> {
    f.chunks().find(|c| c.tag == want).map(|c| c.as_uint())
}

#[tokio::test]
async fn public_chat_is_formatted_and_echoed() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _ctx) = start_server(td.path()).await;
    let mut a = Client::login(addr, "alice", "", "").await;
    let mut b = Client::login(addr, "bob", "", "").await;

    a.send(REQ_CHAT, &[(tag::BODY, b"hello there".to_vec())])
        .await;
    // Both sides receive the server-formatted line: CR, name right-aligned
    // to 13 columns, colon, two spaces — the reference server's default.
    let expected = b"\r        alice:  hello there".to_vec();
    let fa = a.recv_type(HDR_CHAT).await;
    assert_eq!(chunk(&fa, tag::BODY).unwrap(), expected);
    assert_eq!(chunk_u32(&fa, tag::UID), Some(a.uid as u32));
    assert!(chunk(&fa, tag::CHAT_ID).is_none(), "public chat has no cid");
    let fb = b.recv_type(HDR_CHAT).await;
    assert_eq!(chunk(&fb, tag::BODY).unwrap(), expected);

    // Action style (/me).
    a.send(
        REQ_CHAT,
        &[
            (tag::BODY, b"waves".to_vec()),
            (tag::STYLE, 1u16.to_be_bytes().to_vec()),
        ],
    )
    .await;
    let fb = b.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&fb, tag::BODY).unwrap(),
        b"\r *** alice waves".to_vec()
    );

    // Multi-line input becomes one push with each line formatted.
    a.send(REQ_CHAT, &[(tag::BODY, b"one\rtwo".to_vec())]).await;
    let fb = b.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&fb, tag::BODY).unwrap(),
        b"\r        alice:  one\r        alice:  two".to_vec()
    );

    // Empty segments — CRLF pairs, doubled and trailing delimiters — are
    // skipped, not rendered as blank attributed lines (the reference
    // server's tokenizer behavior).
    a.send(REQ_CHAT, &[(tag::BODY, b"one\r\ntwo\r\r\n".to_vec())])
        .await;
    let fb = b.recv_type(HDR_CHAT).await;
    assert_eq!(
        chunk(&fb, tag::BODY).unwrap(),
        b"\r        alice:  one\r        alice:  two".to_vec()
    );
}

#[tokio::test]
async fn private_chat_full_lifecycle_over_the_wire() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _ctx) = start_server(td.path()).await;
    let mut a = Client::login(addr, "alice", "", "").await;
    let mut b = Client::login(addr, "bob", "", "").await;
    a.recv_type(0x12d).await; // bob's join broadcast

    // Create, inviting bob: reply carries cid + creator row; bob gets the
    // invite push with the inviter's name.
    let t = a
        .send(
            REQ_CHAT_CREATE,
            &[(tag::UID, (b.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let created = a.recv_type(HDR_TASK).await;
    assert_eq!((created.trans, created.flag), (t, 0));
    let cid = chunk_u32(&created, tag::CHAT_ID).unwrap();
    assert!(cid != 0);
    let invite = b.recv_type(HDR_CHAT_INVITE_PUSH).await;
    assert_eq!(chunk_u32(&invite, tag::CHAT_ID), Some(cid));
    assert_eq!(chunk(&invite, tag::NAME).unwrap(), b"alice".to_vec());

    // Join: reply has both member rows; alice sees the join push.
    let t = b
        .send(REQ_CHAT_JOIN, &[(tag::CHAT_ID, cid.to_be_bytes().to_vec())])
        .await;
    let joined = b.recv_type(HDR_TASK).await;
    assert_eq!(joined.trans, t);
    assert_eq!(
        joined.chunks().filter(|c| c.tag == tag::USER_LIST).count(),
        2
    );
    let push = a.recv_type(HDR_CHAT_USER_CHANGE).await;
    assert_eq!(chunk_u32(&push, tag::UID), Some(b.uid as u32));

    // Chat inside the room routes only to members, tagged with the cid.
    b.send(
        REQ_CHAT,
        &[
            (tag::BODY, b"psst".to_vec()),
            (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
        ],
    )
    .await;
    let fa = a.recv_type(HDR_CHAT).await;
    assert_eq!(chunk_u32(&fa, tag::CHAT_ID), Some(cid));
    assert_eq!(
        chunk(&fa, tag::BODY).unwrap(),
        b"\r          bob:  psst".to_vec()
    );

    // Subject: any member; both get the push.
    b.send(
        REQ_CHAT_SUBJECT,
        &[
            (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
            (tag::CHAT_SUBJECT, b"plans".to_vec()),
        ],
    )
    .await;
    let subj = a.recv_type(HDR_CHAT_SUBJECT_PUSH).await;
    assert_eq!(chunk(&subj, tag::CHAT_SUBJECT).unwrap(), b"plans".to_vec());
    b.recv_type(HDR_CHAT_SUBJECT_PUSH).await;

    // Invite requires membership.
    let t = b
        .send(
            REQ_CHAT_INVITE,
            &[
                (tag::CHAT_ID, 9999u32.to_be_bytes().to_vec()),
                (tag::UID, (a.uid as u32).to_be_bytes().to_vec()),
            ],
        )
        .await;
    let denied = b.recv_type(HDR_TASK).await;
    assert_eq!((denied.trans, denied.flag), (t, 1));

    // Part: the survivor sees it.
    b.send(REQ_CHAT_PART, &[(tag::CHAT_ID, cid.to_be_bytes().to_vec())])
        .await;
    let part = a.recv_type(HDR_CHAT_USER_PART).await;
    assert_eq!(chunk_u32(&part, tag::UID), Some(b.uid as u32));
}

#[tokio::test]
async fn pm_broadcast_and_access_gates() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _ctx) = start_server(td.path()).await;
    let mut admin = Client::login(addr, "root", "admin", "pw").await;
    let mut g = Client::login(addr, "guestie", "", "").await;
    admin.recv_type(0x12d).await;

    // PM: ack to sender, push to target with name + text.
    let t = admin
        .send(
            REQ_MSG,
            &[
                (tag::UID, (g.uid as u32).to_be_bytes().to_vec()),
                (tag::BODY, b"hi guest".to_vec()),
            ],
        )
        .await;
    let ack = admin.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));
    let msg = g.recv_type(HDR_MSG).await;
    assert_eq!(chunk(&msg, tag::BODY).unwrap(), b"hi guest".to_vec());
    assert_eq!(chunk(&msg, tag::NAME).unwrap(), b"root".to_vec());
    assert_eq!(chunk_u32(&msg, tag::UID), Some(admin.uid as u32));

    // Broadcast: admin allowed (everyone receives, sender included);
    // guest denied.
    let t = admin
        .send(REQ_BROADCAST, &[(tag::BODY, b"attention".to_vec())])
        .await;
    let ack = admin.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));
    let bc = g.recv_type(HDR_BROADCAST).await;
    assert_eq!(chunk(&bc, tag::BODY).unwrap(), b"attention".to_vec());
    admin.recv_type(HDR_BROADCAST).await;

    let t = g
        .send(REQ_BROADCAST, &[(tag::BODY, b"me too".to_vec())])
        .await;
    let denied = g.recv_type(HDR_TASK).await;
    assert_eq!((denied.trans, denied.flag), (t, 1));

    // User info: admin may inspect the guest; an account without the
    // get_user_info bit may only inspect itself.
    let mut peon = Client::login(addr, "peon", "armored", "").await;
    admin.recv_type(0x12d).await;
    g.recv_type(0x12d).await;
    let t = admin
        .send(
            REQ_USER_GETINFO,
            &[(tag::UID, (g.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let info = admin.recv_type(HDR_TASK).await;
    assert_eq!((info.trans, info.flag), (t, 0));
    let body = chunk(&info, tag::BODY).unwrap();
    let text = String::from_utf8_lossy(&body).into_owned();
    assert!(text.contains("login: guest"), "info text was: {text}");
    assert_eq!(chunk(&info, tag::NAME).unwrap(), b"guestie".to_vec());

    let t = peon
        .send(
            REQ_USER_GETINFO,
            &[(tag::UID, (admin.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let denied = peon.recv_type(HDR_TASK).await;
    assert_eq!((denied.trans, denied.flag), (t, 1));
    let t = peon
        .send(
            REQ_USER_GETINFO,
            &[(tag::UID, (peon.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let selfinfo = peon.recv_type(HDR_TASK).await;
    assert_eq!((selfinfo.trans, selfinfo.flag), (t, 0));
}

#[tokio::test]
async fn kick_ban_and_untouchable_targets() {
    let td = tempfile::tempdir().unwrap();
    let (addr, ctx) = start_server(td.path()).await;
    let mut admin = Client::login(addr, "root", "admin", "pw").await;
    let mut victim = Client::login(addr, "victim", "", "").await;
    let armored = Client::login(addr, "tank", "armored", "").await;
    admin.recv_type(0x12d).await;

    // A guest cannot kick.
    let t = victim
        .send(
            REQ_USER_KICK,
            &[(tag::UID, (admin.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let denied = victim.recv_type(HDR_TASK).await;
    assert_eq!((denied.trans, denied.flag), (t, 1));

    // cant_be_disconnected protects its holder.
    let t = admin
        .send(
            REQ_USER_KICK,
            &[(tag::UID, (armored.uid as u32).to_be_bytes().to_vec())],
        )
        .await;
    let denied = admin.recv_type(HDR_TASK).await;
    assert_eq!((denied.trans, denied.flag), (t, 1));

    // Kick with ban: ack, the victim's connection dies, survivors see the
    // part and the public-chat announcement.
    let t = admin
        .send(
            REQ_USER_KICK,
            &[
                (tag::UID, (victim.uid as u32).to_be_bytes().to_vec()),
                (tag::BAN, 1u32.to_be_bytes().to_vec()),
            ],
        )
        .await;
    let ack = admin.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));
    let chat = admin.recv_type(HDR_CHAT).await;
    let line = chunk(&chat, tag::BODY).unwrap();
    assert_eq!(line, b"\r<victim has been banned by root>".to_vec());
    let part = admin.recv_type(HDR_USER_PART).await;
    assert_eq!(chunk_u32(&part, tag::UID), Some(victim.uid as u32));

    // The victim's socket is dead.
    let end = timeout(Duration::from_secs(5), read_frame(&mut victim.stream)).await;
    let mut saw_close = false;
    if let Ok(r) = end {
        // Drain whatever was queued; the channel must end.
        let mut r = r;
        for _ in 0..12 {
            if r.is_err() {
                saw_close = true;
                break;
            }
            r = match timeout(Duration::from_secs(5), read_frame(&mut victim.stream)).await {
                Ok(next) => next,
                Err(_) => break,
            };
        }
    }
    assert!(saw_close, "kicked client's connection must close");

    // The ban sticks: the same address is refused before magic.
    assert!(ctx.core.is_banned("127.0.0.1".parse().unwrap()));
    let mut refused = TcpStream::connect(addr).await.unwrap();
    refused
        .write_all(b"TRTPHOTL\x00\x01\x00\x02")
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    let r = timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read_exact(&mut refused, &mut buf),
    )
    .await;
    assert!(
        !matches!(r, Ok(Ok(_))),
        "banned address must not get the server magic"
    );

    let _ = armored; // keep the session alive to the end
}
