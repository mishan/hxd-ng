//! Legacy login and presence end-to-end tests: a scripted client against
//! a live server on an ephemeral port. The client side packs and parses with the
//! same `hxproto` the real gtkhx client uses, so these double as
//! wire-compat checks, not just self-consistency.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::access::bit;
use hxd_core::Core;
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxproto::messages::tag;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_AGREEMENT: u32 = 0x6d;
const HDR_USER_CHANGE: u32 = 0x12d;
const HDR_USER_PART: u32 = 0x12e;
const HDR_SELFINFO: u32 = 0x162;
const HDR_LOGIN: u32 = 0x6b;
const HDR_AGREEMENTAGREE: u32 = 0x79;
const HDR_GETLIST: u32 = 0x12c;
const HDR_USERCHANGE_REQ: u32 = 0x130;
const HDR_PING: u32 = 0x1f4;

async fn start_server(accounts: &Path, agreement: Option<&str>) -> SocketAddr {
    let ctx = ServerCtx {
        core: Arc::new(Core::new()),
        auth: Arc::new(hxd_auth_file_backend(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "test server".into(),
            version: 185,
            agreement: agreement.map(String::from),
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: hxd_session::Caps::empty(),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(listener, ctx));
    addr
}

fn hxd_auth_file_backend(dir: &Path) -> impl hxd_core::AuthBackend {
    // Bootstrap only fires on a not-yet-existing directory (it never
    // overwrites), so give it one below the tempdir.
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    hxd_auth_file::FileAuth::new(accounts)
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

struct Client {
    stream: TcpStream,
    trans: u32,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Client {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut reply = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .unwrap();
        assert_eq!(&reply, b"TRTP\x00\x00\x00\x00", "bad server magic");
        Client { stream, trans: 0 }
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

    /// Receive frames until one of type `ty` arrives; unrelated pushes in
    /// between are allowed but replies are not skipped silently.
    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..8 {
            let f = self.recv().await;
            if f.ty == ty {
                return f;
            }
        }
        panic!("frame type {ty:#x} never arrived");
    }

    async fn login_guest(&mut self, nick: &str, icon: u16, clientversion: u16) -> Frame {
        let mut chunks = vec![
            (tag::NAME, nick.as_bytes().to_vec()),
            (tag::ICON, icon.to_be_bytes().to_vec()),
        ];
        if clientversion != 0 {
            chunks.push((tag::VERSION, clientversion.to_be_bytes().to_vec()));
        }
        let t = self.send(HDR_LOGIN, &chunks).await;
        let f = self.recv_type(HDR_TASK).await;
        assert_eq!(f.trans, t, "login reply must echo the request trans");
        f
    }
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

fn chunk_u16(f: &Frame, want: u16) -> Option<u16> {
    f.chunks()
        .find(|c| c.tag == want)
        .map(|c| c.as_uint() as u16)
}

/// uid/icon/color/name out of a USER_LIST chunk payload.
fn parse_userlist(data: &[u8]) -> (u16, u16, u16, Vec<u8>) {
    let u16at = |i: usize| u16::from_be_bytes([data[i], data[i + 1]]);
    let nlen = u16at(6) as usize;
    (u16at(0), u16at(2), u16at(4), data[8..8 + nlen].to_vec())
}

#[tokio::test]
async fn guest_login_userlist_and_ping() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), None).await;

    let mut c = Client::connect(addr).await;
    let login = c.login_guest("alice", 2, 150).await;
    assert_eq!(login.flag, 0);
    let uid = chunk_u16(&login, tag::UID).expect("login reply carries the uid");
    assert_eq!(chunk_u16(&login, tag::VERSION), Some(185));
    assert_eq!(
        chunk(&login, tag::SERVERNAME).unwrap(),
        b"test server".to_vec()
    );

    // No agreement configured + a 1.5 client → explicit NOAGREEMENT.
    let agreement = c.recv_type(HDR_AGREEMENT).await;
    assert!(chunk(&agreement, tag::NOAGREEMENT).is_some());

    // Self-info: real access bits (guest bootstrap grants read_chat), and
    // our own row.
    let selfinfo = c.recv_type(HDR_SELFINFO).await;
    let access = chunk(&selfinfo, tag::ACCESS).unwrap();
    let bits = hxd_core::AccessBits::from_wire(access.try_into().unwrap());
    assert!(bits.has(bit::READ_CHAT));
    assert!(!bits.has(bit::DELETE_FILES));
    let (self_uid, _, _, nick) = parse_userlist(&chunk(&selfinfo, tag::USER_LIST).unwrap());
    assert_eq!(self_uid, uid);
    assert_eq!(nick, b"alice");

    // User list: just us, plus the (empty, for now) chat subject.
    let t = c.send(HDR_GETLIST, &[]).await;
    let list = c.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    let rows: Vec<_> = list.chunks().filter(|c| c.tag == tag::USER_LIST).collect();
    assert_eq!(rows.len(), 1);
    let (luid, licon, lcolor, lnick) = parse_userlist(rows[0].data);
    assert_eq!((luid, licon, lcolor), (uid, 2, 0));
    assert_eq!(lnick, b"alice");
    assert!(chunk(&list, tag::CHAT_SUBJECT).is_some());

    // Ping → empty ok reply.
    let t = c.send(HDR_PING, &[]).await;
    let pong = c.recv_type(HDR_TASK).await;
    assert_eq!((pong.trans, pong.flag, pong.hc), (t, 0, 0));
}

#[tokio::test]
async fn two_clients_see_each_other_join_change_and_part() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), None).await;

    let mut a = Client::connect(addr).await;
    a.login_guest("alice", 1, 150).await;
    a.recv_type(HDR_SELFINFO).await;

    let mut b = Client::connect(addr).await;
    let b_login = b.login_guest("bob", 7, 150).await;
    let b_uid = chunk_u16(&b_login, tag::UID).unwrap();

    // A sees bob join.
    let join = a.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk_u16(&join, tag::UID), Some(b_uid));
    assert_eq!(chunk(&join, tag::NAME).unwrap(), b"bob".to_vec());
    assert_eq!(chunk_u16(&join, tag::ICON), Some(7));

    // B's list has both users.
    let t = b.send(HDR_GETLIST, &[]).await;
    let list = b.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    assert_eq!(list.chunks().filter(|c| c.tag == tag::USER_LIST).count(), 2);

    // B renames; both sides get the change (echo included).
    b.send(
        HDR_USERCHANGE_REQ,
        &[
            (tag::NAME, b"bobby".to_vec()),
            (tag::ICON, 7u16.to_be_bytes().to_vec()),
        ],
    )
    .await;
    let change_a = a.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk(&change_a, tag::NAME).unwrap(), b"bobby".to_vec());
    let change_b = b.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk_u16(&change_b, tag::UID), Some(b_uid));

    // B hangs up; A sees the part.
    drop(b);
    let part = a.recv_type(HDR_USER_PART).await;
    assert_eq!(chunk_u16(&part, tag::UID), Some(b_uid));
}

#[tokio::test]
async fn account_login_wrong_password_and_name_policy() {
    let td = tempfile::tempdir().unwrap();
    std::fs::create_dir(td.path().join("accounts")).unwrap();
    std::fs::write(
        td.path().join("accounts/dave.toml"),
        "name = \"Dave\"\npassword = \"s3cret\"\n[access]\ndisconnect_users = true\n",
    )
    .unwrap();
    let addr = start_server(td.path(), None).await;

    // Wrong password: error reply, then the server hangs up.
    let mut c = Client::connect(addr).await;
    let t = c
        .send(
            HDR_LOGIN,
            &[
                (tag::LOGIN, xor(b"dave")),
                (tag::PASSWORD, xor(b"wrong")),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
    let f = c.recv_type(HDR_TASK).await;
    assert_eq!((f.trans, f.flag), (t, 1));
    assert!(chunk(&f, tag::TASK_ERROR).is_some());

    // Right password. No use_any_name on the account → the account name
    // wins over the client's requested nick; admin color from
    // disconnect_users.
    let mut c = Client::connect(addr).await;
    let t = c
        .send(
            HDR_LOGIN,
            &[
                (tag::NAME, b"l33t".to_vec()),
                (tag::LOGIN, xor(b"dave")),
                (tag::PASSWORD, xor(b"s3cret")),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
    let f = c.recv_type(HDR_TASK).await;
    assert_eq!((f.trans, f.flag), (t, 0));
    let selfinfo = c.recv_type(HDR_SELFINFO).await;
    let (_, _, color, nick) = parse_userlist(&chunk(&selfinfo, tag::USER_LIST).unwrap());
    assert_eq!(nick, b"Dave");
    assert_eq!(color, 2);
}

#[tokio::test]
async fn agreement_flow_parks_login_until_agree() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), Some("Be nice\nOr else\n")).await;

    // Watcher to observe when the parked client becomes visible.
    let mut w = Client::connect(addr).await;
    w.login_guest("watcher", 1, 150).await;
    w.recv_type(HDR_SELFINFO).await;

    // A real 1.5-style login: version but no name.
    let mut c = Client::connect(addr).await;
    let t = c
        .send(HDR_LOGIN, &[(tag::VERSION, 150u16.to_be_bytes().to_vec())])
        .await;
    let login = c.recv_type(HDR_TASK).await;
    assert_eq!(login.trans, t);
    let uid = chunk_u16(&login, tag::UID).unwrap();

    // The agreement push carries the text, CR line endings on the wire.
    let agreement = c.recv_type(HDR_AGREEMENT).await;
    assert_eq!(
        chunk(&agreement, tag::BODY).unwrap(),
        b"Be nice\rOr else\r".to_vec()
    );

    // Not visible yet: watcher's list still shows only itself.
    let t = w.send(HDR_GETLIST, &[]).await;
    let list = w.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    assert_eq!(list.chunks().filter(|c| c.tag == tag::USER_LIST).count(), 1);

    // Agree with a name+icon → ack, self-info, and the join broadcast.
    let t = c
        .send(
            HDR_AGREEMENTAGREE,
            &[
                (tag::NAME, b"latecomer".to_vec()),
                (tag::ICON, 9u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
    let ack = c.recv_type(HDR_TASK).await;
    assert_eq!((ack.trans, ack.flag), (t, 0));
    c.recv_type(HDR_SELFINFO).await;

    let join = w.recv_type(HDR_USER_CHANGE).await;
    assert_eq!(chunk_u16(&join, tag::UID), Some(uid));
    assert_eq!(chunk(&join, tag::NAME).unwrap(), b"latecomer".to_vec());
}

#[tokio::test]
async fn old_client_without_version_skips_the_agreement_dance() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), Some("Terms.\n")).await;

    let mut c = Client::connect(addr).await;
    c.login_guest("oldtimer", 3, 0).await;
    // The agreement text still goes out (the account didn't opt out), but
    // no NOAGREEMENT handshake is required: self-info follows directly and
    // the user is visible without any agree round-trip.
    let agreement = c.recv_type(HDR_AGREEMENT).await;
    assert!(chunk(&agreement, tag::BODY).is_some());
    let selfinfo = c.recv_type(HDR_SELFINFO).await;
    let (_, icon, _, nick) = parse_userlist(&chunk(&selfinfo, tag::USER_LIST).unwrap());
    assert_eq!((icon, nick.as_slice()), (3, b"oldtimer".as_slice()));
}

#[tokio::test]
async fn mac_roman_nick_roundtrips_exactly() {
    // The domain is UTF-8 but the wire is Mac Roman; a legacy nick with a
    // high byte (0x8e = é) must come back byte-identical through the
    // convert-in/convert-out path.
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), None).await;
    let mut c = Client::connect(addr).await;
    let nick = vec![b'r', b'e', b'n', 0x8e, b'e']; // "renée" in Mac Roman
    let t = c
        .send(
            HDR_LOGIN,
            &[
                (tag::NAME, nick.clone()),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            ],
        )
        .await;
    let f = c.recv_type(HDR_TASK).await;
    assert_eq!((f.trans, f.flag), (t, 0));
    let selfinfo = c.recv_type(HDR_SELFINFO).await;
    let (_, _, _, wire_nick) = parse_userlist(&chunk(&selfinfo, tag::USER_LIST).unwrap());
    assert_eq!(wire_nick, nick);
}

#[tokio::test]
async fn hope_probe_and_prelogin_requests_are_refused_cleanly() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), None).await;

    // The HOPE session-key probe (1-byte zero login) gets a readable
    // error, not a hang or a desync.
    let mut c = Client::connect(addr).await;
    let t = c.send(HDR_LOGIN, &[(tag::LOGIN, vec![0])]).await;
    let f = c.recv_type(HDR_TASK).await;
    assert_eq!((f.trans, f.flag), (t, 1));

    // A request before login is refused.
    let mut c = Client::connect(addr).await;
    let t = c.send(HDR_GETLIST, &[]).await;
    let f = c.recv_type(HDR_TASK).await;
    assert_eq!((f.trans, f.flag), (t, 1));
}
