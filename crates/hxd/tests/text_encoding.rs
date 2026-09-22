//! The Text-Encoding capability end to end (fogWraith
//! `Capabilities-Text-Encoding.md`): a client that negotiates bit 1 speaks
//! UTF-8 in every text field, one that doesn't speaks Mac Roman, and the
//! two share a room without either seeing the other's bytes.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::Core;
use hxd_session::caps::{cap, Caps};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxproto::messages::tag;
use hxproto::text;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_CHAT: u32 = 0x6a;
const HDR_MSG: u32 = 0x68;
const HDR_AGREEMENT: u32 = 0x6d;
const HDR_SELFINFO: u32 = 0x162;
const HDR_USER_CHANGE: u32 = 0x12d;

const REQ_LOGIN: u32 = 0x6b;
const REQ_CHAT: u32 = 0x69;
const REQ_MSG: u32 = 0x6c;
const REQ_USER_GETLIST: u32 = 0x12c;

/// "Zo\u{eb} " followed by two kanji: a name Mac Roman can half spell.
const KLEIN_NICK: &str = "Zo\u{eb} \u{65e5}\u{672c}";
/// A name Mac Roman spells exactly.
const CLASSIC_NICK: &str = "Andr\u{e9}";
/// Both clients log in with it, each in its own encoding.
const PASSWORD: &str = "p\u{e4}ss";

async fn start_server(dir: &Path, agreement: &str) -> SocketAddr {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("member.toml"),
        format!(
            "name = \"Member\"\npassword = \"{PASSWORD}\"\n[access]\nread_chat = true\n\
             send_chat = true\nsend_msgs = true\nuse_any_name = true\n"
        ),
    )
    .unwrap();
    let ctx = ServerCtx {
        core: Arc::new(Core::new()),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
        cfg: Arc::new(ServerConfig {
            name: "Caf\u{e9} \u{2615}".into(),
            version: 185,
            agreement: Some(agreement.into()),
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            // What the binary offers: bit 1 always.
            caps: Caps::empty().with(cap::TEXT_ENCODING),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
        }),
        files: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(listener, ctx));
    addr
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

struct Client {
    stream: TcpStream,
    trans: u32,
    uid: u16,
    /// The login reply.
    reply: Option<Frame>,
    agreement: Vec<u8>,
}

impl Client {
    /// Log in to the member account, spelling the nick and password in
    /// `utf8`'s encoding and offering bit 1 when it is set.
    async fn login(addr: SocketAddr, nick: &str, utf8: bool) -> Client {
        let spell = |s: &str| {
            if utf8 {
                s.as_bytes().to_vec()
            } else {
                text::from_utf8(s)
            }
        };
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut magic = [0u8; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut chunks = vec![
            (tag::NAME, spell(nick)),
            (tag::ICON, 1u16.to_be_bytes().to_vec()),
            (tag::VERSION, 150u16.to_be_bytes().to_vec()),
            (tag::LOGIN, xor(b"member")),
            (tag::PASSWORD, xor(&spell(PASSWORD))),
        ];
        if utf8 {
            chunks.push((
                tag::CAPABILITIES,
                Caps::empty()
                    .with(cap::LARGE_FILES)
                    .with(cap::TEXT_ENCODING)
                    .to_wire(),
            ));
        }
        let mut c = Client {
            stream,
            trans: 0,
            uid: 0,
            reply: None,
            agreement: Vec::new(),
        };
        c.send(REQ_LOGIN, &chunks).await;
        let reply = c.recv_type(HDR_TASK).await;
        assert_eq!(reply.flag, 0, "login must succeed");
        c.uid = reply
            .chunks()
            .find(|ch| ch.tag == tag::UID)
            .map(|ch| ch.as_uint() as u16)
            .unwrap();
        c.reply = Some(reply);
        c.agreement = chunk(&c.recv_type(HDR_AGREEMENT).await, tag::BODY).unwrap();
        c.recv_type(HDR_SELFINFO).await;
        c
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.trans
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..12 {
            let f = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("timed out waiting for a frame")
                .expect("connection closed while a frame was expected");
            if f.ty == ty {
                return f;
            }
        }
        panic!("frame type {ty:#x} never arrived");
    }
}

/// `"\r%13.13s:  %s"`, with the column counted in characters.
fn chat_line(nick: &[u8], width: usize, body: &[u8]) -> Vec<u8> {
    let mut v = b"\r".to_vec();
    v.extend(std::iter::repeat_n(b' ', 13 - width));
    v.extend_from_slice(nick);
    v.extend_from_slice(b":  ");
    v.extend_from_slice(body);
    v
}

#[tokio::test]
async fn a_utf8_client_and_a_mac_roman_client_share_a_room() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), "Welcome\nto the caf\u{e9}").await;

    // Both log in with the same non-ASCII password, each spelled in its
    // own encoding: credentials reach the backend as the same UTF-8.
    let mut klein = Client::login(addr, KLEIN_NICK, true).await;
    let mut classic = Client::login(addr, CLASSIC_NICK, false).await;
    klein.recv_type(HDR_USER_CHANGE).await;

    // The echo is bit 1 alone: the client also offered large files,
    // which this server doesn't. The classic client's reply has no field.
    assert_eq!(
        chunk(klein.reply.as_ref().unwrap(), tag::CAPABILITIES).unwrap(),
        vec![0, 2]
    );
    assert!(chunk(classic.reply.as_ref().unwrap(), tag::CAPABILITIES).is_none());

    // Server name and agreement in each connection's encoding, and the
    // agreement's line breaks in each connection's convention.
    assert_eq!(
        chunk(klein.reply.as_ref().unwrap(), tag::SERVERNAME).unwrap(),
        "Caf\u{e9} \u{2615}".as_bytes()
    );
    assert_eq!(
        chunk(classic.reply.as_ref().unwrap(), tag::SERVERNAME).unwrap(),
        text::from_utf8("Caf\u{e9} \u{2615}")
    );
    assert_eq!(klein.agreement, "Welcome\nto the caf\u{e9}".as_bytes());
    assert_eq!(
        classic.agreement,
        text::from_utf8("Welcome\rto the caf\u{e9}")
    );

    // The user list spells each nick for its reader.
    let t = klein.send(REQ_USER_GETLIST, &[]).await;
    let list = klein.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    let names: Vec<Vec<u8>> = list
        .chunks()
        .filter(|c| c.tag == tag::USER_LIST)
        .map(|c| c.data[8..].to_vec())
        .collect();
    assert!(names.contains(&KLEIN_NICK.as_bytes().to_vec()));
    assert!(names.contains(&CLASSIC_NICK.as_bytes().to_vec()));
    let t = classic.send(REQ_USER_GETLIST, &[]).await;
    let list = classic.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    let names: Vec<Vec<u8>> = list
        .chunks()
        .filter(|c| c.tag == tag::USER_LIST)
        .map(|c| c.data[8..].to_vec())
        .collect();
    assert!(names.contains(&text::from_utf8(KLEIN_NICK)));
    assert!(names.contains(&text::from_utf8(CLASSIC_NICK)));

    // Chat from the UTF-8 client: kanji in UTF-8 to itself, `?` to the
    // classic client, and the name column counted in characters on the
    // UTF-8 side, in bytes on the Mac Roman side — which, one byte a
    // character, is the same count.
    let said = "\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}";
    klein
        .send(REQ_CHAT, &[(tag::BODY, said.as_bytes().to_vec())])
        .await;
    let seen = chunk(&klein.recv_type(HDR_CHAT).await, tag::BODY).unwrap();
    assert_eq!(seen, chat_line(KLEIN_NICK.as_bytes(), 6, said.as_bytes()));
    let seen = chunk(&classic.recv_type(HDR_CHAT).await, tag::BODY).unwrap();
    assert_eq!(seen, chat_line(&text::from_utf8(KLEIN_NICK), 6, b"?????"));

    // And from the classic client, Mac Roman in, UTF-8 out.
    classic
        .send(REQ_CHAT, &[(tag::BODY, text::from_utf8("caf\u{e9}"))])
        .await;
    let seen = chunk(&klein.recv_type(HDR_CHAT).await, tag::BODY).unwrap();
    assert_eq!(
        seen,
        chat_line(CLASSIC_NICK.as_bytes(), 5, "caf\u{e9}".as_bytes())
    );
    classic.recv_type(HDR_CHAT).await;

    // A private message's line breaks follow the reader, not the writer.
    classic
        .send(
            REQ_MSG,
            &[
                (tag::UID, (klein.uid as u32).to_be_bytes().to_vec()),
                (tag::BODY, text::from_utf8("one\rtwo \u{e9}")),
            ],
        )
        .await;
    assert_eq!(classic.recv_type(HDR_TASK).await.flag, 0);
    let msg = klein.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk(&msg, tag::BODY).unwrap(),
        "one\ntwo \u{e9}".as_bytes()
    );
    assert_eq!(chunk(&msg, tag::NAME).unwrap(), CLASSIC_NICK.as_bytes());

    klein
        .send(
            REQ_MSG,
            &[
                (tag::UID, (classic.uid as u32).to_be_bytes().to_vec()),
                (tag::BODY, "a\nb \u{e9}".as_bytes().to_vec()),
            ],
        )
        .await;
    assert_eq!(klein.recv_type(HDR_TASK).await.flag, 0);
    let msg = classic.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk(&msg, tag::BODY).unwrap(),
        text::from_utf8("a\rb \u{e9}")
    );
    assert_eq!(chunk(&msg, tag::NAME).unwrap(), text::from_utf8(KLEIN_NICK));
}

#[tokio::test]
async fn a_utf8_nick_is_cut_on_a_character() {
    let td = tempfile::tempdir().unwrap();
    let addr = start_server(td.path(), "hi").await;
    // Eleven three-byte characters: 33 bytes, over the wire's 31. The
    // server keeps ten whole ones rather than ten and a broken tail.
    let long = "\u{3042}".repeat(11);
    let mut klein = Client::login(addr, &long, true).await;
    let t = klein.send(REQ_USER_GETLIST, &[]).await;
    let list = klein.recv_type(HDR_TASK).await;
    assert_eq!(list.trans, t);
    let mine = list
        .chunks()
        .filter(|c| c.tag == tag::USER_LIST)
        .map(|c| c.data[8..].to_vec())
        .next()
        .unwrap();
    assert_eq!(mine, "\u{3042}".repeat(10).as_bytes());
}
