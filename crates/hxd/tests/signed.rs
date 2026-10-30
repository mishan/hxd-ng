//! Signed lines, private messages and articles, and rooms that require
//! signing, on the ng wire (`docs/e2e-messages.md` §4.6–§4.12): real
//! servers on loopback with an identity, one SQLite file for the log, the
//! inbox, the news and the moderation trail, users who log in with a
//! device key and sign with it through hl-identity's own API, and a
//! classic client beside them.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hl_identity::message::{
    Article, ChatLine, Object, Parent, PrivateMessage, Signed, CHAT_DOMAIN,
};
use hl_identity::{cbor, cert, Card, DeviceCert, DeviceKey, IdentityKey, LoginProof, ServerKey};
use hxd_core::{Core, HistoryPolicy, ModerationPolicy, NewsPolicy, RoomPolicy, SystemPolicy};
use hxd_ng_session::{IdentityConfig, IdentityState, NgConfig, NgCtx, Registry};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::ng::Client;
use hxd_testclient::Error;
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const SERVER_SEED: [u8; 32] = [0x55; 32];
const HDR_CHAT: u32 = 0x6a;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    store: Arc<SqliteStore>,
    system: u16,
    stop: [tokio::task::AbortHandle; 2],
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

/// Its certificate issued a day ago, so a line can claim an hour ago.
fn person(seed: u8, name: &str) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[seed + 100; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let cert = DeviceCert::for_device(&id, &dev, now() - 86_400, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(&id);
    Person {
        id,
        dev,
        card,
        cert,
    }
}

fn fingerprint(p: &Person) -> hl_identity::Fingerprint {
    hl_identity::Fingerprint::of(&p.id.public())
}

async fn start(dir: &Path) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let member = "read_chat = true\nsend_chat = true\nsend_msgs = true\nread_chat_history = true\n\
                  read_news = true\npost_news = true\n";
    let account = |login: &str, extra: &str| {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{member}{extra}"),
        )
        .unwrap();
    };
    for (seed, login) in [(1, "alice"), (2, "bob"), (3, "erin")] {
        let fp = fingerprint(&person(seed, login));
        account(login, &format!("[identity]\nfingerprint = \"{fp}\"\n"));
    }
    account("carol", "disconnect_users = true\ndelete_articles = true\n");
    account("dave", "");
    account("eve", "");
    account("boss", "[extra]\nmanage_rooms = true\n");

    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = Core::new()
        .with_inbox(
            store.clone(),
            auth.clone(),
            hxd_core::InboxPolicy::default(),
        )
        .with_history(
            store.clone(),
            HistoryPolicy {
                max_lines: 10_000,
                max_days: 30,
                max_page: 200,
                replay: 0,
            },
        )
        .with_moderation(store.clone(), ModerationPolicy::default())
        .with_news(store.clone(), NewsPolicy::default())
        .with_system(SystemPolicy::default())
        .with_rooms(
            Arc::new(hxd::rooms::FileRooms::new(&dir.join("rooms.toml"))),
            RoomPolicy {
                signed: true,
                ..RoomPolicy::default()
            },
        )
        .unwrap();
    let core = Arc::new(core);
    core.start_system_session().unwrap();
    let system = core.system_uid().unwrap();
    let auth: Arc<dyn hxd_core::AuthBackend> = auth;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "signed".into(),
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
        ServerKey::from_seed(&SERVER_SEED),
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
            server_name: "signed".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 2,
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
    let stop = [
        tokio::spawn(hxd_session::serve(l1, legacy_ctx)).abort_handle(),
        tokio::spawn(hxd_ng_session::serve(l2, ng_ctx)).abort_handle(),
    ];
    Server {
        legacy,
        ng,
        store,
        system,
        stop,
    }
}

/// A server started again on the same database, once every connection to
/// the first has gone.
async fn restart(server: Server, dir: &Path) -> Server {
    server.stop.iter().for_each(tokio::task::AbortHandle::abort);
    timeout(Duration::from_secs(5), async {
        while Arc::strong_count(&server.store) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first server let go of its store");
    drop(server);
    start(dir).await
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

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn refused(c: &mut Client, req: &str, params: Value) -> (String, String) {
    match c.request(req, params).await {
        Err(Error::Refused { code, text }) => (code, text),
        other => panic!("{req} was not refused: {other:?}"),
    }
}

fn guid(n: u8) -> String {
    format!("{n:02x}0e1000-1234-4abc-89ab-000000000000")
}

fn id_of(guid: &str) -> [u8; 16] {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    let mut id = [0; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    id
}

fn line(p: &Person, guid: &str, room: u64, text: &str) -> ChatLine {
    ChatLine {
        id: id_of(guid),
        sent: now(),
        server: ServerKey::from_seed(&SERVER_SEED).public(),
        room,
        cert: p.cert.clone(),
        text: text.into(),
        act: false,
    }
}

/// What a client sends: the detached form, base64url.
fn detached<T: Object>(whole: &[u8], at: u64) -> String {
    b64(&Signed::<T>::parse(whole, at).unwrap().detached().unwrap())
}

fn signed_line(p: &Person, l: &ChatLine) -> String {
    detached::<ChatLine>(&l.sign(&p.dev).unwrap(), l.sent)
}

/// A line signed without hl-identity's own refusal to sign under a
/// certificate that does not allow messages.
fn signed_regardless(p: &Person, l: &ChatLine) -> String {
    use ed25519_dalek::Signer;
    let unsigned = l.unsigned();
    let body = cbor::encode(&unsigned);
    let key = ed25519_dalek::SigningKey::from_bytes(&p.dev.seed());
    let sig = key.sign(&[CHAT_DOMAIN.as_bytes(), &[0], &body].concat());
    let cbor::Value::Map(mut entries) = unsigned else {
        unreachable!()
    };
    entries.retain(|(k, _)| !matches!(k, cbor::Value::Text(t) if t == "text"));
    entries.push((
        cbor::Value::Text("sig".into()),
        cbor::Value::Bytes(sig.to_bytes().to_vec()),
    ));
    b64(&cbor::encode(&cbor::Value::Map(entries)))
}

fn message(p: &Person, guid: &str, to: &Person, text: &str) -> String {
    let m = whole_message(p, guid, to, text);
    detached::<PrivateMessage>(&m, now())
}

fn whole_message(p: &Person, guid: &str, to: &Person, text: &str) -> Vec<u8> {
    PrivateMessage {
        id: id_of(guid),
        sent: now(),
        to: fingerprint(to),
        cert: p.cert.clone(),
        text: text.into(),
        quote: None,
        auto: false,
    }
    .sign(&p.dev)
    .unwrap()
}

fn history_lines(page: &Value) -> Vec<Value> {
    page["lines"].as_array().unwrap().clone()
}

#[tokio::test]
async fn a_signed_line_is_heard_and_kept_with_its_signature() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob) = (person(1, "alice"), person(2, "bob"));
    let (mut a, hello) = login_as(server.ng, &alice, json!({ "signs": "default" })).await;
    assert!(hello["caps"].as_array().unwrap().contains(&json!("signed")));
    assert_eq!(hello["signs"], "default");
    let (mut b, hello) = login_as(server.ng, &bob, json!({ "signs": "able" })).await;
    let me = |users: &Value, fp: &str| {
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["identity"]["fingerprint"] == fp)
            .unwrap()["identity"]
            .clone()
    };
    let (fa, fb) = (
        fingerprint(&alice).to_string(),
        fingerprint(&bob).to_string(),
    );
    assert_eq!(me(&hello["users"], &fa)["signs"], true, "default is shown");
    assert!(
        me(&hello["users"], &fb).get("signs").is_none(),
        "able is not"
    );
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let mut classic = hxd_testclient::legacy::Client::login_at(
        server.legacy,
        &hxd_testclient::legacy::Login::account("eve", "eve", "pw"),
    )
    .await
    .unwrap();

    let g = guid(1);
    let signed = signed_line(&alice, &line(&alice, &g, 0, "hi\nthere"));
    let sent = ok(
        &mut a,
        "chat",
        json!({ "text": "hi\nthere", "guid": g, "signed": signed }),
    )
    .await;
    let id = sent["id"].as_u64().unwrap();
    let heard = b.event_where("chat", |d| d["id"] == id).await.unwrap().data;
    assert_eq!(heard["text"], "hi\nthere");
    assert_eq!(heard["signed"], signed, "exactly as it was sent");
    let seen = d.event_where("chat", |d| d["id"] == id).await.unwrap().data;
    assert_eq!(seen["signed"], signed, "an unsigned reader is shown it too");
    // A classic reader hears the text exactly as it hears the same line
    // unsigned, and nothing of the signature.
    ok(&mut a, "chat", json!({ "text": "hi\nthere" })).await;
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let frame = classic
            .rx
            .recv_where(|f| {
                f.ty == HDR_CHAT
                    && f.bytes(tag::BODY)
                        .is_some_and(|b| b.windows(5).any(|w| w == b"there"))
            })
            .await
            .unwrap();
        bodies.push(frame.bytes(tag::BODY).unwrap());
    }
    assert_eq!(bodies[0], bodies[1]);

    // Signed again with the same content, later: the same line.
    let again = signed_line(
        &alice,
        &ChatLine {
            sent: now() - 30,
            ..line(&alice, &g, 0, "hi\nthere")
        },
    );
    let repeat = ok(
        &mut a,
        "chat",
        json!({ "text": "hi\nthere", "guid": g, "signed": again }),
    )
    .await;
    assert_eq!(repeat["id"], id, "answered as the line it repeats");
    // Other content under the same id: refused here, and in a room too.
    let other = signed_line(&alice, &line(&alice, &g, 0, "bye"));
    let (code, _) = refused(
        &mut a,
        "chat",
        json!({ "text": "bye", "guid": g, "signed": other }),
    )
    .await;
    assert_eq!(code, "bad_signature");
    let (mut boss, _) = Client::account(server.ng, "boss", "pw", "boss")
        .await
        .unwrap();
    let room = ok(&mut boss, "room_create", json!({ "name": "den" })).await["room"]["id"]
        .as_u64()
        .unwrap();
    ok(&mut a, "room_join", json!({ "room": room })).await;
    ok(&mut b, "room_join", json!({ "room": room })).await;
    let moved = signed_line(&alice, &line(&alice, &g, room, "hi\nthere"));
    let (code, _) = refused(
        &mut a,
        "chat",
        json!({ "text": "hi\nthere", "room": room, "guid": g, "signed": moved }),
    )
    .await;
    assert_eq!(code, "bad_signature", "one id is one line, in one room");
    // A fresh line in the room is its own.
    let g2 = guid(2);
    let in_room = signed_line(&alice, &line(&alice, &g2, room, "in here"));
    ok(
        &mut a,
        "chat",
        json!({ "text": "in here", "room": room, "guid": g2, "signed": in_room }),
    )
    .await;
    let page = ok(&mut b, "history", json!({ "room": room })).await;
    assert_eq!(history_lines(&page)[0]["signed"], in_room);

    let page = ok(&mut d, "history", json!({})).await;
    let lines = history_lines(&page);
    assert_eq!(lines.len(), 2, "the repeat was not logged: {page}");
    assert_eq!(lines[0]["signed"], signed);
    assert_eq!(lines[0]["text"], "hi\nthere");
    assert!(lines[1].get("signed").is_none());

    // A server started again on the same database serves it as it was,
    // once every connection to the first has gone.
    for c in [a, b, d, boss] {
        c.logout().await.unwrap();
    }
    drop(classic);
    let server = restart(server, dir.path()).await;
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let page = ok(&mut d, "history", json!({})).await;
    assert_eq!(history_lines(&page)[0]["signed"], signed, "after a restart");
}

#[tokio::test]
async fn a_signed_line_that_does_not_check_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob) = (person(1, "alice"), person(2, "bob"));
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let elsewhere = ServerKey::from_seed(&[0x66; 32]).public();
    let mut no_messages = DeviceCert::for_device(
        &alice.id,
        &alice.dev,
        now() - 60,
        cert::RECOMMENDED_LIFETIME,
    )
    .unwrap();
    no_messages.caps = Some(cert::caps::LOGIN);
    let no_messages = no_messages.sign(&alice.id);
    let other_device = DeviceKey::from_seed(&[0x77; 32]);
    let other_device = Person {
        cert: DeviceCert::for_device(
            &alice.id,
            &other_device,
            now() - 60,
            cert::RECOMMENDED_LIFETIME,
        )
        .unwrap()
        .sign(&alice.id),
        dev: other_device,
        id: IdentityKey::from_seed(&[1; 32]),
        card: Vec::new(),
    };
    let g = guid(9);
    let base = line(&alice, &g, 0, "hello");
    let signed = |l: ChatLine| signed_line(&alice, &l);
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "another room",
            json!({ "text": "hello", "guid": g, "signed": signed(ChatLine { room: 5, ..base.clone() }) }),
            "bad_signature",
        ),
        (
            "another server",
            json!({ "text": "hello", "guid": g,
                    "signed": signed(ChatLine { server: elsewhere, ..base.clone() }) }),
            "bad_signature",
        ),
        (
            "a guid that is not its id",
            json!({ "text": "hello", "guid": guid(10), "signed": signed(base.clone()) }),
            "bad_signature",
        ),
        (
            "signed an hour ago",
            json!({ "text": "hello", "guid": g,
                    "signed": signed(ChatLine { sent: now() - 3600, ..base.clone() }) }),
            "bad_signature",
        ),
        (
            "a certificate that does not allow messages",
            json!({ "text": "hello", "guid": g,
                    "signed": signed_regardless(&alice, &ChatLine { cert: no_messages, ..base.clone() }) }),
            "bad_signature",
        ),
        (
            "a second device of the same identity",
            json!({ "text": "hello", "guid": g,
                    "signed": signed_line(&other_device, &line(&other_device, &g, 0, "hello")) }),
            "bad_signature",
        ),
        (
            "another identity's certificate",
            json!({ "text": "hello", "guid": g,
                    "signed": signed_line(&bob, &line(&bob, &g, 0, "hello")) }),
            "bad_signature",
        ),
        (
            "an action signed as a line",
            json!({ "text": "hello", "style": "action", "guid": g, "signed": signed(base.clone()) }),
            "bad_signature",
        ),
        (
            "other text than it signed",
            json!({ "text": "hullo", "guid": g, "signed": signed(base.clone()) }),
            "bad_signature",
        ),
        (
            "a raw CR",
            json!({ "text": "hi\rthere", "guid": g, "signed": signed(base.clone()) }),
            "bad_request",
        ),
        (
            "over the limit",
            json!({ "text": "x".repeat(4097), "guid": g, "signed": signed(base.clone()) }),
            "bad_request",
        ),
        (
            "no guid",
            json!({ "text": "hello", "signed": signed(base.clone()) }),
            "bad_request",
        ),
    ];
    for (case, params, want) in cases {
        let (code, text) = refused(&mut a, "chat", params).await;
        assert_eq!(code, want, "{case}: {text}");
        match case {
            "signed an hour ago" => assert_eq!(text, "signed too long ago; sign it again"),
            "a second device of the same identity" => {
                assert_eq!(text, "Signed by another device.")
            }
            _ => {}
        }
    }
    let page = ok(&mut a, "history", json!({})).await;
    assert!(
        history_lines(&page).is_empty(),
        "nothing was logged: {page}"
    );
    // A guid an unsigned line was sent under says something else.
    let g = guid(12);
    ok(&mut a, "chat", json!({ "text": "hello", "guid": g })).await;
    let after = signed_line(&alice, &line(&alice, &g, 0, "hello"));
    let (code, _) = refused(
        &mut a,
        "chat",
        json!({ "text": "hello", "guid": g, "signed": after }),
    )
    .await;
    assert_eq!(
        code, "bad_signature",
        "signed under an unsigned line's guid"
    );
    // A session that proved no device has nothing to sign with.
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let g = guid(14);
    let theirs = signed_line(&alice, &line(&alice, &g, 0, "hello"));
    let (code, text) = refused(
        &mut d,
        "chat",
        json!({ "text": "hello", "guid": g, "signed": theirs }),
    )
    .await;
    assert_eq!(
        (code.as_str(), text.as_str()),
        (
            "bad_signature",
            "This session proved no device key to sign with."
        )
    );
    let tcp = TcpStream::connect(server.ng).await.unwrap();
    let mut c = Client::over(Box::new(tcp), &format!("ws://{}/ng", server.ng))
        .await
        .unwrap();
    let (code, _) = refused(&mut c, "login", json!({ "signs": "always" })).await;
    assert_eq!(code, "bad_request", "an unknown `signs`");
}

#[tokio::test]
async fn a_signed_message_is_delivered_kept_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob) = (person(1, "alice"), person(2, "bob"));
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let (mut b, _) = login_as(server.ng, &bob, json!({})).await;
    let bob_uid = b.uid.unwrap();

    let g = guid(3);
    let signed = message(&alice, &g, &bob, "psst");
    ok(
        &mut a,
        "msg",
        json!({ "to": bob_uid, "text": "psst", "guid": g, "signed": signed }),
    )
    .await;
    let got = b
        .event_where("msg", |d| d["text"] == "psst")
        .await
        .unwrap()
        .data;
    assert_eq!(got["signed"], signed);
    let inbox = ok(&mut b, "inbox", json!({})).await;
    assert_eq!(inbox["messages"][0]["signed"], signed, "{inbox}");
    // The same id with other words is refused, and to someone else too.
    let other = message(&alice, &g, &bob, "psst!");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to": bob_uid, "text": "psst!", "guid": g, "signed": other }),
    )
    .await;
    assert_eq!(code, "bad_signature");
    let to_self = message(&alice, &guid(4), &alice, "hi");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to_login": "bob", "text": "hi", "guid": guid(4), "signed": to_self }),
    )
    .await;
    assert_eq!(code, "bad_signature", "signed to another identity");
    let dave = message(&alice, &guid(5), &bob, "hi");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to_login": "dave", "text": "hi", "guid": guid(5), "signed": dave }),
    )
    .await;
    assert_eq!(code, "bad_request", "dave proved no identity");
    let erin = person(3, "erin");
    let elsewhere = message(&alice, &g, &erin, "psst");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to_login": "erin", "text": "psst", "guid": g, "signed": elsewhere }),
    )
    .await;
    assert_eq!(code, "bad_signature", "one id, sent to two people");
    let g8 = guid(8);
    ok(
        &mut a,
        "msg",
        json!({ "to": bob_uid, "text": "plain", "guid": g8 }),
    )
    .await;
    let after = message(&alice, &g8, &bob, "plain");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to": bob_uid, "text": "plain", "guid": g8, "signed": after }),
    )
    .await;
    assert_eq!(
        code, "bad_signature",
        "signed under an unsigned message's guid"
    );
    let system = message(&alice, &guid(9), &bob, "/help");
    let (code, _) = refused(
        &mut a,
        "msg",
        json!({ "to_login": "server", "text": "/help", "guid": guid(9), "signed": system }),
    )
    .await;
    assert_eq!(code, "bad_request", "the system account has no identity");
    // Reported from the inbox, the report carries the signature; pasted,
    // it names whoever signed it.
    let id = inbox["messages"][0]["id"].clone();
    ok(&mut b, "report", json!({ "msg": id, "reason": "creepy" })).await;
    let pasted = message(&alice, &guid(6), &bob, "pasted");
    ok(
        &mut b,
        "report",
        json!({ "reason": "this too", "evidence": "pasted", "signed": pasted }),
    )
    .await;
    // Each from a reporter of its own: a second report about one person
    // by the same reporter is the first one.
    let said = signed_line(&alice, &line(&alice, &guid(13), 0, "said here"));
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    ok(
        &mut d,
        "report",
        json!({ "reason": "a line", "evidence": "said here", "signed": said }),
    )
    .await;
    let (mut e, _) = login_as(server.ng, &erin, json!({})).await;
    let whole = b64(&whole_message(&alice, &guid(15), &erin, "opened"));
    ok(
        &mut e,
        "report",
        json!({ "user": { "login": "alice" }, "reason": "whole", "signed": whole }),
    )
    .await;
    let (code, _) = refused(
        &mut b,
        "report",
        json!({ "user": { "login": "dave" }, "reason": "x", "evidence": "pasted",
                "signed": pasted }),
    )
    .await;
    assert_eq!(code, "bad_signature", "signed by someone else than named");
    let (code, _) = refused(
        &mut b,
        "report",
        json!({ "reason": "x", "evidence": "not what was signed", "signed": pasted }),
    )
    .await;
    assert_eq!(code, "bad_signature");
    let (mut carol, _) = Client::account(server.ng, "carol", "pw", "carol")
        .await
        .unwrap();
    let reports = ok(&mut carol, "reports", json!({})).await;
    let reports = reports["reports"].as_array().unwrap();
    let of_msg = reports
        .iter()
        .find(|r| r["target"]["kind"] == "msg")
        .unwrap();
    assert_eq!(of_msg["signed"], signed);
    assert_eq!(of_msg["evidence"], "psst");
    let of_paste = reports.iter().find(|r| r["reason"] == "this too").unwrap();
    assert_eq!(of_paste["signed"], pasted);
    assert_eq!(of_paste["verified"], false);
    assert_eq!(
        of_paste["target"]["from"]["fingerprint"],
        fingerprint(&alice).to_string()
    );
    let of_line = reports.iter().find(|r| r["reason"] == "a line").unwrap();
    assert_eq!(
        (&of_line["signed"], &of_line["evidence"]),
        (&json!(said), &json!("said here"))
    );
    let of_whole = reports.iter().find(|r| r["reason"] == "whole").unwrap();
    assert_eq!(
        (&of_whole["signed"], &of_whole["evidence"]),
        (&json!(whole), &json!("opened"))
    );

    // To an account with no session, it waits in the inbox with it.
    b.logout().await.unwrap();
    let g = guid(7);
    let later = message(&alice, &g, &bob, "later");
    let queued = ok(
        &mut a,
        "msg",
        json!({ "to_login": "bob", "text": "later", "guid": g, "signed": later }),
    )
    .await;
    assert_eq!(queued["queued"], true);
    let (mut b, _) = login_as(server.ng, &bob, json!({})).await;
    let got = b
        .event_where("msg", |d| d["text"] == "later")
        .await
        .unwrap()
        .data;
    assert_eq!(got["signed"], later);
}

#[tokio::test]
async fn a_redaction_moves_the_signature_into_the_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let alice = person(1, "alice");
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let (mut carol, _) = Client::account(server.ng, "carol", "pw", "carol")
        .await
        .unwrap();
    let g = guid(8);
    let signed = signed_line(&alice, &line(&alice, &g, 0, "regret"));
    let id = ok(
        &mut a,
        "chat",
        json!({ "text": "regret", "guid": g, "signed": signed }),
    )
    .await["id"]
        .clone();
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    ok(&mut d, "report", json!({ "line": id, "reason": "rude" })).await;
    let reports = ok(&mut carol, "reports", json!({})).await;
    let target = &reports["reports"][0]["target"];
    assert_eq!(target["text"], "regret", "{reports}");
    assert_eq!(target["signed"], signed);

    ok(&mut carol, "redact", json!({ "id": id, "reason": "rude" })).await;
    let page = ok(&mut carol, "history", json!({})).await;
    let tombstone = &history_lines(&page)[0];
    assert_eq!(tombstone["deleted"], true);
    assert!(
        tombstone.get("signed").is_none(),
        "a tombstone carries none: {tombstone}"
    );
    let log = ok(&mut carol, "moderation_log", json!({})).await;
    let redact = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "redact")
        .unwrap();
    assert_eq!(redact["signed"], signed);
    // The id stays the line's: said again, even in other words, it is
    // answered as the line, since nothing it said is kept to hold it to.
    let reworded = signed_line(&alice, &line(&alice, &g, 0, "no regrets"));
    let again = ok(
        &mut a,
        "chat",
        json!({ "text": "no regrets", "guid": g, "signed": reworded }),
    )
    .await;
    assert_eq!(again["id"], id);
}

/// A resume that leaves out `signs` and `sealed` takes both off the row
/// in one change, replayed rather than resynced whether it takes over a
/// live connection or comes back to a detached session.
#[tokio::test]
async fn a_resume_that_does_not_say_it_signs_loses_the_mark() {
    for (takeover, login) in [
        (true, json!({ "signs": "default" })),
        (false, json!({ "signs": "default", "sealed": true })),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let server = start(dir.path()).await;
        let alice = person(1, "alice");
        let (mut a, _) = login_as(server.ng, &alice, login).await;
        let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
            .await
            .unwrap();
        let fp = fingerprint(&alice).to_string();
        let alices = |e: &Value| e["user"]["identity"]["fingerprint"] == fp;
        a.event_where("user_joined", |e| e["user"]["nick"] == "dave")
            .await
            .unwrap();
        let (session, seq) = (a.session.clone().unwrap(), a.rx.last_seq);
        let _old = if takeover {
            Some(a)
        } else {
            a.close().await.unwrap();
            let detached = d
                .event_where("user_changed", |e| {
                    alices(e) && e["user"]["status"] == "detached"
                })
                .await
                .unwrap();
            assert_eq!(detached.data["user"]["identity"]["signs"], true);
            None
        };
        let (mut resumed, how) = Client::resume(server.ng, session, seq, Vec::new())
            .await
            .unwrap();
        assert!(
            matches!(how, hxd_testclient::ng::Resumed::Replayed(_)),
            "takeover {takeover}: {how:?}"
        );
        ok(&mut resumed, "nick", json!({ "icon": 77 })).await;
        let mut told = Vec::new();
        loop {
            let e = d.event_where("user_changed", alices).await.unwrap().data;
            if e["user"]["icon"] == 77 {
                break;
            }
            told.push(e);
        }
        assert_eq!(told.len(), 1, "takeover {takeover}: {told:?}");
        let identity = &told[0]["user"]["identity"];
        assert!(
            identity.get("signs").is_none() && identity.get("sealed").is_none(),
            "takeover {takeover}: {identity}"
        );
        assert_eq!(told[0]["user"]["status"], "active");
    }
}

#[tokio::test]
async fn the_signs_request_changes_the_mark_until_a_resume_says_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let alice = person(1, "alice");
    // Saying nothing at login does not keep a device that may sign from it.
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let fp = fingerprint(&alice).to_string();
    for (signs, shown) in [("default", true), ("able", false), ("default", true)] {
        assert_eq!(
            ok(&mut a, "signs", json!({ "signs": signs })).await,
            json!({})
        );
        let changed = d
            .event_where("user_changed", |e| {
                e["user"]["identity"]["fingerprint"] == fp
            })
            .await
            .unwrap();
        assert_eq!(
            changed.data["user"]["identity"].get("signs").is_some(),
            shown,
            "{signs}: {}",
            changed.data
        );
    }
    let (code, _) = refused(&mut d, "signs", json!({ "signs": "default" })).await;
    assert_eq!(code, "bad_request", "a session with no device");
    for params in [json!({ "signs": "always" }), json!({})] {
        let (code, _) = refused(&mut a, "signs", params.clone()).await;
        assert_eq!(code, "bad_request", "{params}");
    }

    let (session, seq) = (a.session.clone().unwrap(), a.rx.last_seq);
    a.close().await.unwrap();
    let (_a, _) = Client::resume(server.ng, session, seq, Vec::new())
        .await
        .unwrap();
    d.event_where("user_changed", |e| {
        e["user"]["identity"]["fingerprint"] == fp && e["user"]["identity"].get("signs").is_none()
    })
    .await
    .unwrap();
}

const GENERAL: [u8; 16] = [0x42; 16];

/// A category the tests post into, with a guid they sign for.
fn general(server: &Server) -> u64 {
    use hxd_core::news::{NewNode, NewsStore, NodeKind};
    server
        .store
        .create_node(
            &NewNode {
                parent: None,
                kind: NodeKind::Category,
                name: "General".into(),
                guid: GENERAL,
                at: std::time::SystemTime::now(),
            },
            16,
        )
        .unwrap()
        .id
}

fn article(p: &Person, id: u8, subject: &str, body: &str, parent: Option<Parent>) -> Article {
    Article {
        id: [id; 16],
        sent: now(),
        server: ServerKey::from_seed(&SERVER_SEED).public(),
        category: GENERAL,
        parent,
        cert: p.cert.clone(),
        subject: subject.into(),
        body: body.into(),
        mime: "text/plain".into(),
    }
}

fn signed_article(p: &Person, a: &Article) -> String {
    detached::<Article>(&a.sign(&p.dev).unwrap(), a.sent)
}

/// `news_post`'s params for `a`, signed by `p`.
fn post_of(category: u64, p: &Person, a: &Article) -> Value {
    let mut params = json!({
        "category": category, "subject": a.subject, "body": a.body, "mime": a.mime,
        "signed": signed_article(p, a),
    });
    if let Some(parent) = a.parent {
        params["parent"] = json!(parent.article);
    }
    params
}

#[tokio::test]
async fn a_signed_article_is_posted_served_and_kept_with_its_signature() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let cat = general(&server);
    let alice = person(1, "alice");
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let tree = ok(&mut a, "news_tree", json!({})).await;
    assert_eq!(tree["nodes"][0]["guid"], b64(&GENERAL), "{tree}");

    let starter = article(&alice, 1, "Signed news", "line one\nline two", None);
    let params = post_of(cat, &alice, &starter);
    let signed = params["signed"].clone();
    let id = ok(&mut a, "news_post", params).await["id"]
        .as_u64()
        .unwrap();
    let got = ok(&mut a, "news_article", json!({ "id": id })).await;
    assert_eq!(got["article"]["signed"], signed);
    assert_eq!(got["article"]["body"], "line one\nline two");
    let threads = ok(&mut a, "news_threads", json!({ "category": cat })).await;
    assert_eq!(threads["threads"][0]["article"]["signed"], signed);
    let thread = ok(&mut a, "news_thread", json!({ "root": id })).await;
    assert_eq!(thread["articles"][0]["signed"], signed);

    // Signed again, later, it is the same post; other words under its id
    // are not.
    let again = Article {
        sent: now() - 30,
        ..starter.clone()
    };
    let retry = ok(&mut a, "news_post", post_of(cat, &alice, &again)).await;
    assert_eq!(retry["id"], id, "answered as the article it repeats");
    let other = Article {
        subject: "Other news".into(),
        ..starter.clone()
    };
    let (code, _) = refused(&mut a, "news_post", post_of(cat, &alice, &other)).await;
    assert_eq!(code, "bad_signature", "an equivocation");

    // A reply names a signed parent by its id and signer.
    let parent = Parent {
        article: u64::from(id as u32),
        signed: Some(([1; 16], fingerprint(&alice))),
    };
    let reply = article(&alice, 2, "Re: Signed news", "a reply", Some(parent));
    let reply = ok(&mut a, "news_post", post_of(cat, &alice, &reply)).await["id"]
        .as_u64()
        .unwrap();
    let thread = ok(&mut a, "news_thread", json!({ "root": id })).await;
    assert_eq!(thread["articles"][1]["id"], reply);
    assert!(thread["articles"][1]["signed"].is_string());

    // A period client reads the text, as it reads any article.
    let mut classic = hxd_testclient::legacy::Client::login_at(
        server.legacy,
        &hxd_testclient::legacy::Login::account("eve", "eve", "pw"),
    )
    .await
    .unwrap();
    let mut path = 1u16.to_be_bytes().to_vec();
    path.extend_from_slice(&[0, 0, 7]);
    path.extend_from_slice(b"General");
    let read = classic
        .call(
            0x190,
            &[
                (tag::NEWSPATH, path),
                (tag::THREADID, (id as u32).to_be_bytes().to_vec()),
                (tag::NEWSTYPE, b"text/plain".to_vec()),
            ],
        )
        .await
        .unwrap();
    assert!(!read.is_error());
    assert_eq!(read.bytes(tag::NEWSDATA).unwrap(), b"line one\rline two");
    assert_eq!(read.bytes(tag::NEWSSUBJECT).unwrap(), b"Signed news");

    drop(classic);
    a.logout().await.unwrap();
    let server = restart(server, dir.path()).await;
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let got = ok(&mut a, "news_article", json!({ "id": id })).await;
    assert_eq!(got["article"]["signed"], signed, "after a restart");
    let retry = ok(&mut a, "news_post", post_of(cat, &alice, &again)).await;
    assert_eq!(retry["id"], id, "the index outlives the server");

    // Deleted by a moderator, it loses its signature to the evidence.
    let (mut carol, _) = Client::account(server.ng, "carol", "pw", "carol")
        .await
        .unwrap();
    ok(
        &mut carol,
        "news_delete",
        json!({ "id": reply, "reason": "x" }),
    )
    .await;
    let gone = ok(&mut a, "news_article", json!({ "id": reply })).await;
    assert!(gone["article"].get("signed").is_none(), "{gone}");
    let log = ok(&mut carol, "moderation_log", json!({})).await;
    let delete = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "news_delete")
        .unwrap();
    assert!(delete["signed"].is_string(), "{delete}");
}

#[tokio::test]
async fn a_signed_article_that_does_not_check_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let cat = general(&server);
    let (alice, bob) = (person(1, "alice"), person(2, "bob"));
    let (mut a, _) = login_as(server.ng, &alice, json!({})).await;
    let signed_starter = ok(
        &mut a,
        "news_post",
        post_of(cat, &alice, &article(&alice, 1, "Signed", "s", None)),
    )
    .await["id"]
        .as_u64()
        .unwrap();
    let unsigned_starter = ok(
        &mut a,
        "news_post",
        json!({ "category": cat, "subject": "Unsigned", "body": "u" }),
    )
    .await["id"]
        .as_u64()
        .unwrap();
    let base = article(&alice, 9, "Hello", "world", None);
    let post = |a: Article| post_of(cat, &alice, &a);
    let reply_to = |article: u64, signed| {
        post(Article {
            parent: Some(Parent { article, signed }),
            ..base.clone()
        })
    };
    let alices = Some(([1; 16], fingerprint(&alice)));
    let mut no_parent = reply_to(signed_starter, alices);
    no_parent.as_object_mut().unwrap().remove("parent");
    let mut no_mime = post(base.clone());
    no_mime.as_object_mut().unwrap().remove("mime");
    let mut other_mime = post(Article {
        mime: "text/markdown".into(),
        ..base.clone()
    });
    other_mime["mime"] = json!("text/plain");
    let with = |key: &str, value: Value| {
        let mut params = post(base.clone());
        params[key] = value;
        params
    };
    let cases: Vec<(&str, Value, &str, Option<&str>)> = vec![
        (
            "another category",
            post(Article {
                category: [0x43; 16],
                ..base.clone()
            }),
            "bad_signature",
            Some("Signed for another category."),
        ),
        (
            "another server",
            post(Article {
                server: ServerKey::from_seed(&[0x66; 32]).public(),
                ..base.clone()
            }),
            "bad_signature",
            Some("Signed for another server."),
        ),
        (
            "a signed parent named as unsigned",
            reply_to(signed_starter, None),
            "bad_signature",
            Some("Signed as a reply to another article."),
        ),
        (
            "an unsigned parent named as signed",
            reply_to(unsigned_starter, alices),
            "bad_signature",
            Some("Signed as a reply to another article."),
        ),
        (
            "a reply posted as a thread",
            no_parent,
            "bad_signature",
            Some("Signed as a reply to another article."),
        ),
        (
            "signed an hour ago",
            post(Article {
                sent: now() - 3600,
                ..base.clone()
            }),
            "bad_signature",
            Some("signed too long ago; sign it again"),
        ),
        (
            "another identity's certificate",
            post_of(cat, &bob, &article(&bob, 9, "Hello", "world", None)),
            "bad_signature",
            Some("Signed by another identity."),
        ),
        ("no mime", no_mime, "bad_request", None),
        ("another mime", other_mime, "bad_signature", None),
        (
            "a subject with a raw CR",
            with("subject", json!("Hel\rlo")),
            "bad_request",
            None,
        ),
        (
            "a subject the server would trim",
            post(Article {
                subject: "Hello\t".into(),
                ..base.clone()
            }),
            "bad_request",
            None,
        ),
        (
            "a body over the limit",
            with("body", json!("x".repeat(65_536))),
            "bad_request",
            None,
        ),
        (
            "other words than it signed",
            with("body", json!("word")),
            "bad_signature",
            None,
        ),
    ];
    for (case, params, want, text) in cases {
        let (code, said) = refused(&mut a, "news_post", params).await;
        assert_eq!(code, want, "{case}: {said}");
        if let Some(text) = text {
            assert_eq!(said, text, "{case}");
        }
    }
    let threads = ok(&mut a, "news_threads", json!({ "category": cat })).await;
    assert_eq!(
        threads["threads"].as_array().unwrap().len(),
        2,
        "nothing else was posted: {threads}"
    );
}

/// `text` to the system account from a classic client, and its answer.
async fn command(c: &mut hxd_testclient::legacy::Client, system: u16, text: &str) -> String {
    use hxproto::messages::ClientHdr;
    let trans = c
        .send(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, system.to_be_bytes().to_vec()),
                (tag::BODY, text.as_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    assert!(!c.reply(trans).await.unwrap().is_error());
    let answer = c
        .recv_where(|f| f.ty == 0x68 && f.uint(tag::UID) == Some(u32::from(system)))
        .await
        .unwrap();
    String::from_utf8_lossy(&answer.bytes(tag::BODY).unwrap()).into_owned()
}

#[tokio::test]
async fn a_room_that_requires_signing_takes_signed_lines_alone() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let (alice, bob) = (person(1, "alice"), person(2, "bob"));
    let (mut boss, _) = Client::account(server.ng, "boss", "pw", "boss")
        .await
        .unwrap();
    let den = ok(
        &mut boss,
        "room_create",
        json!({ "name": "den", "signed": true }),
    )
    .await["room"]
        .clone();
    assert_eq!(den["signed"], true, "{den}");
    let den = den["id"].as_u64().unwrap();
    let (code, _) = refused(
        &mut boss,
        "room_edit",
        json!({ "room": den, "signed": false }),
    )
    .await;
    assert_eq!(code, "bad_request", "the mark never changes");
    let stage = ok(
        &mut boss,
        "room_create",
        json!({ "name": "stage", "signed": true, "post": ["alice"] }),
    )
    .await["room"]["id"]
        .as_u64()
        .unwrap();
    let plain = ok(&mut boss, "room_create", json!({ "name": "hall" })).await["room"].clone();
    assert!(plain.get("signed").is_none(), "{plain}");

    let (mut a, _) = login_as(server.ng, &alice, json!({ "signs": "able" })).await;
    let (mut b, _) = login_as(server.ng, &bob, json!({})).await;
    let (mut d, _) = Client::account(server.ng, "dave", "pw", "dave")
        .await
        .unwrap();
    let joined = ok(&mut a, "room_join", json!({ "room": den })).await;
    assert_eq!(
        (&joined["signed"], &joined["may_post"]),
        (&json!(true), &json!(true))
    );
    for (c, who) in [
        (&mut b, "a session that did not say it signs"),
        (&mut d, "one with no device"),
    ] {
        let joined = ok(c, "room_join", json!({ "room": den })).await;
        assert_eq!(joined["may_post"], false, "{who}");
        let listed = ok(c, "rooms", json!({})).await;
        let row = listed["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == den)
            .unwrap()
            .clone();
        assert_eq!(
            (&row["signed"], &row["may_post"]),
            (&json!(true), &json!(false)),
            "{who}"
        );
        // The gates let it post, so it is told what is missing.
        let (code, _) = refused(c, "chat", json!({ "text": "hi", "room": den })).await;
        assert_eq!(code, "signature_required", "{who}");
    }
    let (code, _) = refused(&mut a, "chat", json!({ "text": "hi", "room": den })).await;
    assert_eq!(code, "signature_required", "unsigned, from one that signs");
    ok(&mut d, "room_join", json!({ "room": stage })).await;
    let (code, _) = refused(&mut d, "chat", json!({ "text": "hi", "room": stage })).await;
    assert_eq!(code, "read_only", "the gates come first");
    let g = guid(20);
    let signed = signed_line(&alice, &line(&alice, &g, den, "signed here"));
    ok(
        &mut a,
        "chat",
        json!({ "text": "signed here", "room": den, "guid": g, "signed": signed }),
    )
    .await;

    // A period client reads it as read-only, and is told once why its
    // lines go nowhere.
    let mut classic = hxd_testclient::legacy::Client::login_at(
        server.legacy,
        &hxd_testclient::legacy::Login::account("eve", "eve", "pw"),
    )
    .await
    .unwrap();
    let rooms = command(&mut classic, server.system, "/rooms").await;
    let line_of = |name: &str| {
        rooms
            .split('\r')
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("{name} in {rooms:?}"))
            .to_string()
    };
    assert!(
        line_of("#den ").ends_with("here) (signed lines only)"),
        "{rooms:?}"
    );
    assert!(line_of("#hall ").ends_with("here)"), "{rooms:?}");
    let cid = |id: u64| (tag::CHAT_ID, (id as u32).to_be_bytes().to_vec());
    classic.call(0x73, &[cid(den)]).await.unwrap();
    for text in [&b"first"[..], b"second"] {
        classic
            .send(0x69, &[(tag::BODY, text.to_vec()), cid(den)])
            .await
            .unwrap();
    }
    classic.ping().await.unwrap();
    let notices: Vec<String> = classic
        .rx
        .take_backlog()
        .iter()
        .filter(|f| f.ty == HDR_CHAT && f.uint(tag::CHAT_ID) == Some(den as u32))
        .map(|f| String::from_utf8_lossy(&f.bytes(tag::BODY).unwrap()).into_owned())
        .collect();
    assert_eq!(notices.len(), 2, "{notices:?}");
    assert!(notices[0].ends_with("this room is public, logged and read-only"));
    assert_eq!(
        notices[1],
        "\r *** this room takes signed lines only, which this client cannot send"
    );
    let page = ok(&mut a, "history", json!({ "room": den })).await;
    let texts: Vec<Value> = history_lines(&page)
        .iter()
        .map(|l| l["text"].clone())
        .collect();
    assert_eq!(texts, [json!("signed here")], "nothing unsigned was logged");

    // A resume that says it signs may post, and is told so.
    ok(&mut b, "rooms", json!({})).await;
    let (session, seq) = (b.session.clone().unwrap(), b.rx.last_seq);
    b.close().await.unwrap();
    let mut b = Client::connect(server.ng).await.unwrap();
    b.rx.last_seq = seq;
    ok(
        &mut b,
        "resume",
        json!({ "session": session.0, "token": session.1, "last_seq": seq, "signs": "able" }),
    )
    .await;
    b.event_where("room_changed", |d| {
        d["room"]["id"] == den && d["room"]["may_post"] == true
    })
    .await
    .unwrap();
}
