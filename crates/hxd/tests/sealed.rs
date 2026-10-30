//! Sealed private messages on the ng wire (`docs/e2e-messages.md`
//! §4.1–§4.5, §4.12): real servers on loopback with an identity and one
//! SQLite file for the inbox, the log and the moderation trail, users who
//! seal and open with hl-identity's own API, and classic and password
//! clients beside them.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hl_identity::message::{Object, PrivateMessage, Sender};
use hl_identity::sealed::{open, seal, seal_to, Opened, Opening, Replay};
use hl_identity::{
    cert, Card, DeviceCert, DeviceKey, Fingerprint, IdentityKey, LoginProof, ServerKey,
};
use hxd_core::{Core, HistoryPolicy, ModerationPolicy};
use hxd_ng_session::{IdentityConfig, IdentityState, NgConfig, NgCtx, Registry};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::ng::Client;
use hxd_testclient::Error;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    clock: hxd_core::clock::Clock,
}

/// A user with an identity, a device and a certificate for it.
struct Person {
    id: IdentityKey,
    dev: DeviceKey,
    card: Vec<u8>,
    cert: Vec<u8>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `device` tells two devices of one identity apart.
fn person(seed: u8, device: u8, name: &str) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[device; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let cert = DeviceCert::for_device(&id, &dev, now() - 3600, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(&id);
    Person {
        id,
        dev,
        card,
        cert,
    }
}

fn fingerprint(p: &Person) -> Fingerprint {
    Fingerprint::of(&p.id.public())
}

async fn start(dir: &Path) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let member = "read_chat = true\nsend_chat = true\nsend_msgs = true\nread_chat_history = true\n";
    let account = |login: &str, extra: &str| {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{member}{extra}"),
        )
        .unwrap();
    };
    for (seed, login) in [(1, "alice"), (2, "bob"), (3, "erin")] {
        let fp = fingerprint(&person(seed, seed, login));
        account(login, &format!("[identity]\nfingerprint = \"{fp}\"\n"));
    }
    account("dave", "");
    account("eve", "");

    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = Core::new()
        .with_inbox(
            store.clone(),
            auth.clone(),
            hxd_core::InboxPolicy::default(),
        )
        .with_relationships(store.clone())
        .with_history(
            store.clone(),
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        )
        .with_moderation(store, ModerationPolicy::default())
        // Small enough that two senders reach it inside their own shares.
        .with_sealed_holds(hxd_core::SealedHolds {
            per_sender: 64 * 1024,
            all: 96 * 1024,
        });
    let core = Arc::new(core);
    let clock = core.clock().clone();
    let auth: Arc<dyn hxd_core::AuthBackend> = auth;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "sealed".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: hxd_session::Caps::empty(),
            hope: None,
            mark_cleartext: false,
            stamp_queued: true,
            trtp_login: hxd_session::TrtpLogin::Verify,
            news: Default::default(),
        }),
        files: None,
        banner: None,
        device_proof: None,
    };
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (legacy, ng) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    let identity = IdentityState::new(
        ServerKey::from_seed(&[0x55; 32]),
        IdentityConfig {
            hosts: vec![ng.to_string()],
            ..Default::default()
        },
        auth.clone(),
        core.clone(),
    );
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "sealed".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 4,
            caps: vec!["history".into(), "inbox".into()],
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: Some(Arc::new(identity)),
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: None,
        banner: None,
        metrics: None,
    };
    tokio::spawn(hxd_session::serve(l1, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(l2, ng_ctx));
    Server { legacy, ng, clock }
}

/// One HTTP/1.1 request, closed after its answer: the JSON body.
async fn http_json(addr: SocketAddr, path: &str, body: &[u8]) -> Value {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    serde_json::from_slice(&raw[split + 4..]).unwrap()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// The challenge binding, then a login on the socket it admits.
async fn login_as(ng: SocketAddr, p: &Person, params: Value) -> (Client, Value) {
    let ch = http_json(ng, "/identity/challenge", b"").await;
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let proof = LoginProof::sign(&p.dev, &challenge, &key, &ng.to_string(), now()).unwrap();
    let body = json!({ "card": b64(&p.card), "device_cert": b64(&p.cert), "proof": b64(&proof) });
    let auth = http_json(ng, "/identity/auth", body.to_string().as_bytes()).await;
    let token = auth["token"].as_str().expect("a transport token");
    let tcp = TcpStream::connect(ng).await.unwrap();
    let mut c = Client::over(Box::new(tcp), &format!("ws://{ng}/ng?token={token}"))
        .await
        .unwrap();
    let hello = c.login(params).await.unwrap();
    (c, hello)
}

/// A request, waited past the request limit for, so a test's pace is not
/// what it checks.
async fn ask(c: &mut Client, req: &str, params: Value) -> Result<Value, (String, String)> {
    loop {
        match c.request(req, params.clone()).await {
            Ok(ok) => return Ok(ok),
            Err(Error::Refused { code, text })
                if code == "rate_limited" && text == "Slow down." =>
            {
                tokio::time::sleep(Duration::from_secs(1)).await
            }
            Err(Error::Refused { code, text }) => return Err((code, text)),
            Err(e) => panic!("{req}: {e:?}"),
        }
    }
}

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    ask(c, req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn code(c: &mut Client, req: &str, params: Value) -> String {
    match ask(c, req, params).await {
        Err((code, _)) => code,
        Ok(ok) => panic!("{req} was not refused: {ok}"),
    }
}

/// A message from `from` to `to`, `text` long.
fn message(from: &Person, n: u8, to: &Person, text: &str) -> PrivateMessage {
    PrivateMessage {
        id: [n; 16],
        sent: now(),
        to: fingerprint(to),
        cert: from.cert.clone(),
        text: text.into(),
        quote: None,
        auto: false,
    }
}

/// What `msg` names a box's key by.
fn key_hash(cert: &[u8]) -> String {
    b64(&Sha256::digest(DeviceCert::parse(cert).unwrap().device_enc))
}

fn sealed_msg(to: u64, sealed: &[u8], cert: &[u8]) -> Value {
    json!({ "to": to, "sealed": b64(sealed), "cert": key_hash(cert) })
}

/// A replay memory that starts empty.
#[derive(Default)]
struct Memory {
    latest: u64,
    accepted: Vec<(Fingerprint, [u8; 16])>,
}

impl Replay for Memory {
    fn latest(&mut self, now: u64) -> u64 {
        self.latest = self.latest.max(now);
        self.latest
    }

    fn accepted(&self, signer: &Fingerprint, id: &[u8; 16]) -> bool {
        self.accepted.contains(&(*signer, *id))
    }

    fn accept(&mut self, signer: Fingerprint, id: [u8; 16], _: u64) -> bool {
        if self.accepted(&signer, &id) {
            return false;
        }
        self.accepted.push((signer, id));
        true
    }
}

/// A `msg` event's box, opened by `reader` as from `from`.
fn opened(event: &Value, reader: &Person, from: &Person) -> Opened {
    assert_eq!(event["text"], "[Encrypted message]");
    assert_eq!(event["queued"], false);
    assert!(event.get("id").is_none(), "never stored: {event}");
    assert_eq!(event["from"]["fingerprint"], fingerprint(from).to_string());
    let ctx = Opening {
        now: now(),
        at: event["at"].as_u64().unwrap(),
        reader: fingerprint(reader),
        sender: Sender::Named(fingerprint(from)),
    };
    open(
        &unb64(event["sealed"].as_str().unwrap()),
        &reader.dev,
        &ctx,
        &mut Memory::default(),
    )
}

fn uid_of(users: &Value, nick: &str) -> u64 {
    users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == nick)
        .unwrap_or_else(|| panic!("{nick} in {users}"))["uid"]
        .as_u64()
        .unwrap()
}

/// Whether any file of the database holds `bytes`.
fn stored(dir: &Path, bytes: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().any(|e| {
        let path = e.unwrap().path();
        path.is_file()
            && std::fs::read(&path)
                .unwrap()
                .windows(bytes.len())
                .any(|w| w == bytes)
    })
}

/// A resume that says, or does not say, it can open sealed messages.
async fn resume(
    ng: SocketAddr,
    session: (String, String),
    last_seq: u64,
    sealed: bool,
) -> (Client, Value) {
    let mut c = Client::connect(ng).await.unwrap();
    c.rx.last_seq = last_seq;
    c.session = Some(session.clone());
    let p =
        json!({ "session": session.0, "token": session.1, "last_seq": last_seq, "sealed": sealed });
    let ok = c.request("resume", p).await.unwrap();
    (c, ok)
}

/// Drop `c`'s connection once it has read everything it was sent, so a
/// resume from where it got to replays the rest: its session and seq.
async fn away(mut c: Client) -> ((String, String), u64) {
    ok(&mut c, "inbox", json!({})).await;
    let left = (c.session.clone().unwrap(), c.rx.last_seq);
    c.close().await.unwrap();
    left
}

/// Bob's client sees alice's session leave its connection.
async fn detached(watcher: &mut Client, who: &Person) {
    let fp = fingerprint(who).to_string();
    watcher
        .event_where("user_changed", |e| {
            e["user"]["identity"]["fingerprint"] == fp && e["user"]["status"] == "detached"
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_sealed_message_reaches_the_device_it_was_sealed_to_alone() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, phone, bob) = (
        person(1, 1, "alice"),
        person(1, 11, "alice"),
        person(2, 2, "bob"),
    );
    let (mut a, hello) = login_as(server.ng, &alice, json!({ "sealed": true })).await;
    assert_eq!(hello["sealed"], true);
    assert_eq!(hello["self"]["identity"]["sealed"], true);
    let (mut p, _) = login_as(server.ng, &phone, json!({ "sealed": true })).await;
    let (mut b, hello) = login_as(server.ng, &bob, json!({ "sealed": true })).await;
    let users = hello["users"].as_array().unwrap();
    let rows: Vec<&Value> = users.iter().filter(|u| u["nick"] == "alice").collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|u| u["identity"]["sealed"] == true));
    let (a_uid, p_uid) = (a.uid.unwrap(), p.uid.unwrap());

    // Each session's certificate is its own device's.
    let got = ok(&mut b, "device_cert", json!({ "uid": a_uid })).await;
    assert_eq!(unb64(got["cert"].as_str().unwrap()), alice.cert);
    let got = ok(&mut b, "device_cert", json!({ "uid": p_uid })).await;
    assert_eq!(unb64(got["cert"].as_str().unwrap()), phone.cert);

    let m = message(&bob, 1, &alice, "only you");
    let sealed = seal_to(
        &m,
        &bob.dev,
        &DeviceCert::parse(&alice.cert).unwrap(),
        false,
    )
    .unwrap();
    let sent = ok(&mut b, "msg", sealed_msg(a_uid, &sealed, &alice.cert)).await;
    assert_eq!(sent, json!({ "queued": false }));
    let ev = a
        .event_where("msg", |d| d.get("sealed").is_some())
        .await
        .unwrap()
        .data;
    assert_eq!(
        unb64(ev["sealed"].as_str().unwrap()),
        sealed,
        "exactly as sent"
    );
    let Opened::Verified { message: got, .. } = opened(&ev, &alice, &bob) else {
        panic!("not verified");
    };
    assert_eq!(got.message.text, "only you");

    // A box to the laptop's key is not the phone's to receive.
    let to_phone = sealed_msg(p_uid, &sealed, &alice.cert);
    assert_eq!(code(&mut b, "msg", to_phone).await, "cert_changed");
    ok(&mut b, "msg", json!({ "to": p_uid, "text": "fence" })).await;
    p.event_where("msg", |d| d["text"] == "fence")
        .await
        .unwrap();
    assert!(
        !p.rx
            .take_backlog()
            .iter()
            .any(|e| e.data.get("sealed").is_some()),
        "the phone was sent nothing sealed"
    );

    // A deniable box opens as one, and is reported as the recipient's word,
    // the whole of its text, which runs past plain evidence's characters.
    let long = "x".repeat(8000);
    let m = message(&bob, 2, &alice, &long);
    let deniable = seal(
        &m,
        &bob.dev,
        &DeviceCert::parse(&alice.cert).unwrap().device_enc,
        true,
    )
    .unwrap();
    ok(&mut b, "msg", sealed_msg(a_uid, &deniable, &alice.cert)).await;
    let ev = a
        .event_where("msg", |d| d.get("sealed").is_some())
        .await
        .unwrap()
        .data;
    let Opened::Deniable { message: got, .. } = opened(&ev, &alice, &bob) else {
        panic!("not deniable");
    };
    let bob_fp = fingerprint(&bob).to_string();
    let report =
        json!({ "user": { "fingerprint": bob_fp }, "reason": "rude", "evidence": got.text });
    ok(&mut a, "report", report).await;
    // Its plaintext has no signature to be checked as one.
    let plaintext = hl_identity::cbor::encode(&got.unsigned());
    let report = json!({ "reason": "rude", "signed": b64(&plaintext) });
    assert_eq!(code(&mut a, "report", report).await, "bad_signature");
    // A signed box's map is the sender's to be held to, however long.
    let whole = message(&bob, 3, &alice, &long).sign(&bob.dev).unwrap();
    ok(
        &mut a,
        "report",
        json!({ "reason": "rude", "signed": b64(&whole) }),
    )
    .await;

    // Nothing sealed is kept: not in the inbox, not in any file.
    let inbox = ok(&mut a, "inbox", json!({})).await;
    let kept: Vec<&Value> = inbox["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| &m["text"])
        .collect();
    assert_eq!(kept, [&json!("fence")], "{inbox}");
    for b in [&sealed, &deniable] {
        assert!(!stored(dir.path(), &b[40..72]));
    }
}

#[tokio::test]
async fn a_sealed_message_that_does_not_check_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob, erin) = (
        person(1, 1, "alice"),
        person(2, 2, "bob"),
        person(3, 3, "erin"),
    );
    let (mut a, _) = login_as(server.ng, &alice, json!({ "sealed": true })).await;
    let (mut b, _) = login_as(server.ng, &bob, json!({ "sealed": true })).await;
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let _classic = hxd_testclient::legacy::Client::login_at(
        server.legacy,
        &hxd_testclient::legacy::Login::account("eve", "eve", "pw"),
    )
    .await
    .unwrap();
    let (e, hello) = login_as(server.ng, &erin, json!({ "sealed": true })).await;
    let (a_uid, b_uid, e_uid) = (a.uid.unwrap(), b.uid.unwrap(), e.uid.unwrap());
    let (d_uid, eve_uid) = (
        uid_of(&hello["users"], "dave"),
        uid_of(&hello["users"], "eve"),
    );
    let alice_cert = DeviceCert::parse(&alice.cert).unwrap();
    let good = seal_to(
        &message(&bob, 1, &alice, "hi"),
        &bob.dev,
        &alice_cert,
        false,
    )
    .unwrap();

    // The shape of the request.
    let mut cut = good.clone();
    cut.pop();
    let mut form = good.clone();
    form[0] = 0x03;
    for (why, params) in [
        (
            "a size no box comes in",
            sealed_msg(a_uid, &cut, &alice.cert),
        ),
        (
            "another leading byte",
            sealed_msg(a_uid, &form, &alice.cert),
        ),
        ("no cert", json!({ "to": a_uid, "sealed": b64(&good) })),
        (
            "a guid",
            json!({ "to": a_uid, "sealed": b64(&good), "cert": key_hash(&alice.cert),
            "guid": "5f5e1000-1234-4abc-89ab-000000000001" }),
        ),
        (
            "text",
            json!({ "to": a_uid, "sealed": b64(&good), "cert": key_hash(&alice.cert), "text": "hi" }),
        ),
        (
            "to_login",
            json!({ "to_login": "alice", "sealed": b64(&good), "cert": key_hash(&alice.cert) }),
        ),
    ] {
        assert_eq!(code(&mut b, "msg", params).await, "bad_request", "{why}");
    }
    // A deniable box under a key not the sender's own.
    let mut swapped = seal(
        &message(&bob, 2, &alice, "hi"),
        &bob.dev,
        &alice_cert.device_enc,
        true,
    )
    .unwrap();
    swapped[1..33].copy_from_slice(&erin.dev.public_enc());
    assert_eq!(
        code(&mut b, "msg", sealed_msg(a_uid, &swapped, &alice.cert)).await,
        "bad_request"
    );
    // A sender that did not say `sealed`.
    assert_eq!(
        code(&mut d, "msg", sealed_msg(a_uid, &good, &alice.cert)).await,
        "bad_request"
    );

    // The target.
    assert_eq!(
        code(&mut b, "msg", sealed_msg(a_uid, &good, &erin.cert)).await,
        "cert_changed"
    );
    assert_eq!(
        code(&mut b, "msg", sealed_msg(d_uid, &good, &alice.cert)).await,
        "not_sealed"
    );
    assert_eq!(
        code(&mut b, "msg", sealed_msg(eve_uid, &good, &alice.cert)).await,
        "not_sealed",
        "classic"
    );
    ok(&mut a, "block", json!({ "login": "bob" })).await;
    assert_eq!(
        code(&mut b, "msg", sealed_msg(a_uid, &good, &alice.cert)).await,
        "blocked"
    );
    assert_eq!(
        code(&mut b, "device_cert", json!({ "uid": a_uid })).await,
        "blocked"
    );
    ok(&mut a, "unblock", json!({ "login": "bob" })).await;
    // Never queued: with no session there is nobody to hold it for.
    e.logout().await.unwrap();
    let to_erin = seal_to(
        &message(&bob, 3, &erin, "hi"),
        &bob.dev,
        &DeviceCert::parse(&erin.cert).unwrap(),
        false,
    )
    .unwrap();
    assert_eq!(
        code(&mut b, "msg", sealed_msg(e_uid, &to_erin, &erin.cert)).await,
        "no_such_user"
    );
    let (mut e, _) = login_as(server.ng, &erin, json!({ "sealed": true })).await;
    let inbox = ok(&mut e, "inbox", json!({})).await;
    assert!(inbox["messages"].as_array().unwrap().is_empty(), "{inbox}");
    assert!(!stored(dir.path(), &to_erin[40..72]));

    // `device_cert`: only a session that can open them asks, and only of
    // one that can.
    assert_eq!(
        code(&mut d, "device_cert", json!({ "uid": a_uid })).await,
        "not_sealed"
    );
    assert_eq!(
        code(&mut b, "device_cert", json!({ "uid": d_uid })).await,
        "not_sealed"
    );
    assert_eq!(
        code(&mut b, "device_cert", json!({ "uid": 60000 })).await,
        "no_such_user"
    );
    let (mut quiet, _) = login_as(server.ng, &person(1, 21, "alice"), json!({})).await;
    let quiet_uid = quiet.uid.unwrap();
    assert_eq!(
        code(&mut b, "device_cert", json!({ "uid": quiet_uid })).await,
        "not_sealed"
    );
    assert_eq!(
        code(&mut quiet, "device_cert", json!({ "uid": b_uid })).await,
        "not_sealed"
    );
    // And is rationed on top of the request limit.
    let mut asked = 0;
    let text = loop {
        match ask(&mut b, "device_cert", json!({ "uid": a_uid })).await {
            Ok(_) => asked += 1,
            Err((code, text)) => {
                assert_eq!(code, "rate_limited");
                break text;
            }
        }
        assert!(asked < 40, "never rationed");
    };
    assert_eq!(text, "You have asked for many certificates lately.");
    assert!(asked >= 15, "rationed after {asked}");

    // A certificate past its expiry can no longer be sealed to.
    server
        .clock
        .advance(Duration::from_secs(cert::RECOMMENDED_LIFETIME + 1));
    assert_eq!(
        code(&mut e, "msg", sealed_msg(a_uid, &good, &alice.cert)).await,
        "not_sealed"
    );
    assert_eq!(
        code(&mut e, "device_cert", json!({ "uid": a_uid })).await,
        "not_sealed"
    );
}

#[tokio::test]
async fn a_held_sealed_message_waits_for_its_resume_and_no_longer() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob, erin) = (
        person(1, 1, "alice"),
        person(2, 2, "bob"),
        person(3, 3, "erin"),
    );
    let (a, _) = login_as(server.ng, &alice, json!({ "sealed": true })).await;
    let (mut b, _) = login_as(server.ng, &bob, json!({ "sealed": true })).await;
    let (mut e, _) = login_as(server.ng, &erin, json!({ "sealed": true })).await;
    let a_uid = a.uid.unwrap();
    let to_alice = DeviceCert::parse(&alice.cert).unwrap();
    let box_of = |from: &Person, n: u8, text: &str| {
        seal_to(&message(from, n, &alice, text), &from.dev, &to_alice, false).unwrap()
    };

    // Held while she is away, and handed over at her resume.
    let (session, seq) = away(a).await;
    detached(&mut b, &alice).await;
    let first = box_of(&bob, 1, "while you were out");
    ok(&mut b, "msg", sealed_msg(a_uid, &first, &alice.cert)).await;
    let (mut a, back) = resume(server.ng, session, seq, true).await;
    assert_eq!(back["sealed"], true);
    let ev = a
        .event_where("msg", |d| d.get("sealed").is_some())
        .await
        .unwrap()
        .data;
    let Opened::Verified { message: got, .. } = opened(&ev, &alice, &bob) else {
        panic!("not verified");
    };
    assert_eq!(got.message.text, "while you were out");

    // One sender holds so much and no more, and leaves room for others.
    let (session, seq) = away(a).await;
    detached(&mut b, &alice).await;
    let long = "x".repeat(8000);
    let held: Vec<Vec<u8>> = (2..5).map(|n| box_of(&bob, n, &long)).collect();
    for sealed in &held {
        assert_eq!(sealed.len(), 17_152);
        ok(&mut b, "msg", sealed_msg(a_uid, sealed, &alice.cert)).await;
    }
    let past = box_of(&bob, 5, &long);
    assert_eq!(
        code(&mut b, "msg", sealed_msg(a_uid, &past, &alice.cert)).await,
        "mailbox_full"
    );
    // And everyone together is held to what the session holds in all.
    let others: Vec<Vec<u8>> = (1..4).map(|n| box_of(&erin, n, &long)).collect();
    for sealed in &others[..2] {
        ok(&mut e, "msg", sealed_msg(a_uid, sealed, &alice.cert)).await;
    }
    assert_eq!(
        code(&mut e, "msg", sealed_msg(a_uid, &others[2], &alice.cert)).await,
        "mailbox_full"
    );

    // A resume that does not say `sealed` gets the placeholders in their
    // places, and everyone sees the mark go.
    let fp = fingerprint(&alice).to_string();
    let (mut a, back) = resume(server.ng, session, seq, false).await;
    assert!(back.get("sealed").is_none());
    let mut lost = 0;
    while lost < 5 {
        let ev = a.event("msg").await.unwrap().data;
        assert!(ev.get("sealed").is_none(), "{ev}");
        assert_eq!(ev["sealed_lost"], true);
        lost += 1;
    }
    b.event_where("user_changed", |e| {
        e["user"]["identity"]["fingerprint"] == fp && e["user"]["identity"].get("sealed").is_none()
    })
    .await
    .unwrap();
    assert_eq!(
        code(&mut b, "msg", sealed_msg(a_uid, &past, &alice.cert)).await,
        "not_sealed"
    );
    for sealed in held.iter().chain(&others).chain([&first, &past]) {
        assert!(!stored(dir.path(), &sealed[40..72]));
    }

    // And one that says it again regains it.
    let (session, seq) = away(a).await;
    let (_a, back) = resume(server.ng, session, seq, true).await;
    assert_eq!(back["sealed"], true);
    b.event_where("user_changed", |e| {
        e["user"]["identity"]["fingerprint"] == fp && e["user"]["identity"]["sealed"] == true
    })
    .await
    .unwrap();
}
