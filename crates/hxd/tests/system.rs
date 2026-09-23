//! The system account end-to-end (`docs/system-account.md`): a period
//! client and an ng client typing at the server over real sockets, the
//! account on both rosters, and the reserved login refused on both
//! wires.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::{Core, SystemPolicy, Uid};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{ServerConfig, ServerCtx};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const HDR_TASK: u32 = 0x0001_0000;
const HDR_SELFINFO: u32 = 0x162;
const HDR_MSG: u32 = 0x68;
const REQ_LOGIN: u32 = 0x6b;
const REQ_MSG: u32 = 0x6c;

/// Both frontends on one core that runs the system account, the way
/// `hxd` wires it: the login reserved in the auth backend, the session
/// started before anyone connects.
async fn start_server(dir: &Path) -> (SocketAddr, SocketAddr, Arc<Core>) {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("bob.toml"),
        "name = \"Bob\"\npassword = \"s3cret\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\nuse_any_name = true\n",
    )
    .unwrap();
    // Someone who may not message anyone: the commands that act on
    // their own settings are still theirs.
    std::fs::write(
        accounts.join("quiet.toml"),
        "name = \"Quiet\"\npassword = \"pw\"\n[access]\nread_chat = true\nuse_any_name = true\n",
    )
    .unwrap();
    // What a migrated server might leave behind: an account file under
    // the reserved login, with a password that works.
    std::fs::write(
        accounts.join("server.toml"),
        "name = \"Old\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let core = Arc::new(Core::new().with_system(SystemPolicy::default()));
    core.start_system_session().unwrap();
    let auth: Arc<dyn hxd_core::AuthBackend> =
        Arc::new(hxd_auth_file::FileAuth::new(accounts).reserving("server"));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "sys".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: hxd_session::Caps::empty(),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            news: Default::default(),
        }),
        files: None,
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "sys".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: None,
    };
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (legacy_addr, ng_addr) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    (legacy_addr, ng_addr, core)
}

fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

fn chunk(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

fn chunk_u16(f: &Frame, want: u16) -> Option<u16> {
    f.chunks()
        .find(|c| c.tag == want)
        .map(|c| c.as_uint() as u16)
}

// --- Minimal legacy scripted client ---------------------------------------

struct Legacy {
    stream: TcpStream,
    trans: u32,
    /// Frames read while waiting for another type. An answer from the
    /// system account and the task reply to the message that asked for
    /// it travel different paths, so either may land first.
    skipped: Vec<Frame>,
}

impl Legacy {
    /// Send the login and answer its task reply, whatever it says.
    async fn try_login(addr: SocketAddr, login: &str, password: &str) -> (Legacy, Frame) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
        let mut reply = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .unwrap();
        let mut c = Legacy {
            stream,
            trans: 0,
            skipped: Vec::new(),
        };
        c.send(
            REQ_LOGIN,
            &[
                (tag::NAME, login.as_bytes().to_vec()),
                (tag::VERSION, 150u16.to_be_bytes().to_vec()),
                (tag::LOGIN, xor(login.as_bytes())),
                (tag::PASSWORD, xor(password.as_bytes())),
            ],
        )
        .await;
        let task = c.recv_type(HDR_TASK).await;
        (c, task)
    }

    async fn login(addr: SocketAddr, login: &str, password: &str) -> Legacy {
        let (mut c, task) = Legacy::try_login(addr, login, password).await;
        assert_eq!(task.flag, 0, "{login} should log in");
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
        if let Some(i) = self.skipped.iter().position(|f| f.ty == ty) {
            return self.skipped.remove(i);
        }
        for _ in 0..16 {
            let f = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .expect("legacy: timed out")
                .expect("legacy: closed");
            if f.ty == ty {
                return f;
            }
            self.skipped.push(f);
        }
        panic!("legacy: frame {ty:#x} never arrived");
    }

    /// A private message to `to`, and the task reply to it.
    async fn msg(&mut self, to: Uid, text: &str) -> Frame {
        let t = self
            .send(
                REQ_MSG,
                &[
                    (tag::UID, u32::from(to).to_be_bytes().to_vec()),
                    (tag::BODY, text.as_bytes().to_vec()),
                ],
            )
            .await;
        let ack = self.recv_type(HDR_TASK).await;
        assert_eq!(ack.trans, t);
        ack
    }
}

// --- Minimal ng WebSocket client -------------------------------------------

struct Ng {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next_id: u64,
    events: Vec<Value>,
}

impl Ng {
    async fn connect(addr: SocketAddr) -> Ng {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        Ng {
            ws,
            next_id: 1,
            events: Vec::new(),
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let v = self.recv_json().await;
            if v.get("reply").and_then(Value::as_u64) == Some(id) {
                return v;
            }
            if v.get("seq").is_some() {
                self.events.push(v);
            }
        }
    }

    async fn recv_json(&mut self) -> Value {
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("ng: timed out")
                .expect("ng: closed")
                .expect("ng: ws error");
            if let Message::Text(t) = msg {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    async fn event(&mut self, ev: &str) -> Value {
        if let Some(i) = self.events.iter().position(|v| v["ev"] == ev) {
            return self.events.remove(i);
        }
        for _ in 0..16 {
            let v = self.recv_json().await;
            if v["ev"] == ev {
                return v;
            }
        }
        panic!("ng: event {ev} never arrived");
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_period_client_types_at_the_server() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, _, core) = start_server(td.path()).await;
    let server = core.system_uid().unwrap();
    let mut bob = Legacy::login(legacy_addr, "bob", "s3cret").await;

    let ack = bob.msg(server, "/help").await;
    assert_eq!(ack.flag, 0, "the message arrived");
    let answer = bob.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk_u16(&answer, tag::UID),
        Some(server),
        "from a uid a 1.x client can open a window on and reply to"
    );
    assert_eq!(chunk(&answer, tag::NAME).unwrap(), b"Server".to_vec());
    let body = chunk(&answer, tag::BODY).unwrap();
    assert!(body.starts_with(b"commands"), "{body:?}");

    // `/msg` reaches an account by login, which is the thing that wire
    // cannot otherwise name.
    bob.msg(server, "/msg quiet hello").await;
    let answer = bob.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk(&answer, tag::BODY).unwrap(),
        b"error: no such account"
    );
}

#[tokio::test]
async fn a_user_who_may_not_message_anyone_may_still_type_at_the_server() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, _, core) = start_server(td.path()).await;
    let server = core.system_uid().unwrap();
    let _bob = Legacy::login(legacy_addr, "bob", "s3cret").await;
    let bob_uid = core
        .snapshot()
        .into_iter()
        .find(|u| u.nick == "bob")
        .unwrap()
        .uid;
    let mut quiet = Legacy::login(legacy_addr, "quiet", "pw").await;

    // `/blocks` is about their own settings, and needs no right to
    // message anyone. This core keeps no block list, which is an answer
    // too — the point is that the command got through.
    let ack = quiet.msg(server, "/blocks").await;
    assert_eq!(ack.flag, 0);
    let answer = quiet.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk(&answer, tag::BODY).unwrap(),
        b"error: this server does not keep a block list"
    );

    // `/msg` does reach a person, and runs as the session that sent it.
    quiet.msg(server, "/msg bob hi").await;
    let answer = quiet.recv_type(HDR_MSG).await;
    assert_eq!(
        chunk(&answer, tag::BODY).unwrap(),
        b"error: you are not allowed to send messages"
    );

    // And a private message to a person is refused as it always was.
    let ack = quiet.msg(bob_uid, "hi").await;
    assert_ne!(ack.flag, 0);
}

#[tokio::test]
async fn nobody_logs_in_as_the_server() {
    let td = tempfile::tempdir().unwrap();
    let (legacy_addr, ng_addr, _core) = start_server(td.path()).await;

    // The account file is there and the password is right.
    let (_, task) = Legacy::try_login(legacy_addr, "server", "pw").await;
    assert_ne!(task.flag, 0, "the legacy wire refuses the reserved login");

    let mut app = Ng::connect(ng_addr).await;
    let v = app
        .request(
            "login",
            json!({ "login": "SERVER", "password": "pw", "nick": "x" }),
        )
        .await;
    assert!(
        v.get("ok").is_none(),
        "the ng wire refuses it too, in any case: {v}"
    );
}

#[tokio::test]
async fn an_ng_client_sees_the_account_and_can_address_it_by_login() {
    let td = tempfile::tempdir().unwrap();
    let (_, ng_addr, core) = start_server(td.path()).await;
    let server = core.system_uid().unwrap();

    let mut app = Ng::connect(ng_addr).await;
    let hello = app
        .request(
            "login",
            json!({ "login": "bob", "password": "s3cret", "nick": "Bob" }),
        )
        .await["ok"]
        .clone();
    let users = hello["users"].as_array().unwrap();
    let row = users
        .iter()
        .find(|u| u["uid"] == server)
        .expect("the account is on the ng roster");
    assert_eq!(row["system"], true);
    assert_eq!(row["admin"], true);
    let me = users.iter().find(|u| u["nick"] == "Bob").unwrap();
    assert!(
        me.get("system").is_none(),
        "the key is left out for everyone else: {me}"
    );

    let v = app
        .request("msg", json!({ "to_login": "server", "text": "help" }))
        .await;
    assert!(v.get("ok").is_some(), "{v}");
    let ev = app.event("msg").await;
    assert_eq!(ev["data"]["from"]["uid"], server);
    assert!(
        ev["data"]["text"].as_str().unwrap().starts_with("commands"),
        "{ev}"
    );
}
