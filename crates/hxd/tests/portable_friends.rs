//! Portable friendships on the ng wire (`docs/hotline-ng.md` §7.5,
//! `docs/proposals/portable-friends.md`): real servers on loopback, each
//! with an identity and a SQLite store, and people whose devices sign
//! offers, acceptances and withdrawals with hl-identity's own API. A
//! friendship made on one server is in place on the next with no new
//! request, a withdrawal on one ends it on the other, a revoked device's
//! presentations go with it, a rotation is followed, and a client that
//! never asks, and a period client beside it all, see nothing new.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hl_identity::friendship::Pair;
use hl_identity::{
    cert, Acceptance, Card, DeviceCert, DeviceKey, Fingerprint, Friendship, IdentityKey,
    LoginProof, Offer, Rotation, ServerKey, Withdrawal,
};
use hxd_core::{Core, MessagingPolicy, Revocations};
use hxd_ng_session::{IdentityConfig, IdentityState, NgConfig, NgCtx, Registry};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_store_sqlite::{SqliteStore, Synchronous};
use hxd_testclient::legacy::{self, push, Login};
use hxd_testclient::ng::Client;
use hxd_testclient::Error;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DAY: u64 = 24 * 3600;

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
}

/// An identity with two devices, each certified.
struct Person {
    id: IdentityKey,
    devices: Vec<(DeviceKey, Vec<u8>)>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn person(seed: u8) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let devices = (0..2)
        .map(|n| {
            let dev = DeviceKey::from_seed(&[seed.wrapping_mul(16).wrapping_add(n + 1); 32]);
            let cert = DeviceCert::for_device(&id, &dev, now() - 3600, cert::RECOMMENDED_LIFETIME)
                .unwrap()
                .sign(&id);
            (dev, cert)
        })
        .collect();
    Person { id, devices }
}

fn fp(p: &Person) -> Fingerprint {
    Fingerprint::of(&p.id.public())
}

/// A server whose `alice` and `bob` link these identities, with
/// `erin` a password account beside them. With `anchors`, it keeps
/// successor commitments, and so applies rotations; `messaging` is
/// `[messaging] enabled`.
async fn start(dir: &Path, alice: &Person, bob: &Person, anchors: bool, messaging: bool) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let member = "read_chat = true\nsend_chat = true\nsend_msgs = true\nmessaging = true\n";
    for (login, link) in [
        ("alice", Some(fp(alice))),
        ("bob", Some(fp(bob))),
        ("erin", None),
    ] {
        let link = link.map_or_else(String::new, |f| {
            format!("[identity]\nfingerprint = \"{f}\"\n")
        });
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{member}{link}"),
        )
        .unwrap();
    }
    let store = Arc::new(SqliteStore::open(dir.join("hx.db"), Synchronous::Normal).unwrap());
    let auth = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let core = Arc::new(
        Core::new()
            .with_inbox(
                store.clone(),
                auth.clone(),
                hxd_core::InboxPolicy::default(),
            )
            .with_relationships(store)
            .with_messaging(MessagingPolicy {
                enabled: messaging,
                presence_debounce: Duration::from_millis(50),
                ..MessagingPolicy::default()
            }),
    );
    tokio::spawn(hxd::presence_flusher(core.clone()));
    let auth: Arc<dyn hxd_core::AuthBackend> = auth;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig::default()),
        files: None,
        banner: None,
    };
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (classic, ng) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    let identity = IdentityState::new(
        ServerKey::from_seed(&[0x55; 32]),
        IdentityConfig {
            hosts: vec![ng.to_string()],
            anchors: anchors.then(|| dir.join("successors")),
            ..Default::default()
        },
        auth.clone(),
        core.clone(),
    );
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "portable".into(),
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(60),
            max_detached_per_addr: 8,
            caps: vec!["inbox".into()],
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
    Server { classic, ng, core }
}

/// One HTTP/1.1 request, closed after its answer: the JSON body.
async fn http_json(addr: SocketAddr, path: &str, body: &[u8]) -> Value {
    http_as(addr, path, body, None).await
}

async fn http_as(addr: SocketAddr, path: &str, body: &[u8], bearer: Option<&str>) -> Value {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = bearer.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}\
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

/// The challenge binding with `who`'s device `dev` and `card`, then a
/// login that speaks the friend family and asks for its portable part.
async fn device_login(
    s: &Server,
    who: &Person,
    dev: usize,
    card: &[u8],
    extra: Value,
) -> Result<(Client, Value), Value> {
    let params = json!({ "messaging": true, "friendships": true });
    device_login_as(s, who, dev, card, extra, params).await
}

/// A transport token from the challenge binding.
async fn token(
    s: &Server,
    who: &Person,
    dev: usize,
    card: &[u8],
    extra: Value,
) -> Result<String, Value> {
    let ng = s.ng;
    let ch = http_json(ng, "/identity/challenge", b"").await;
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let (dk, cert) = &who.devices[dev];
    let proof = LoginProof::sign(dk, &challenge, &key, &ng.to_string(), now()).unwrap();
    let mut body = json!({ "card": b64(card), "device_cert": b64(cert), "proof": b64(&proof) });
    for (k, v) in extra.as_object().into_iter().flatten() {
        body[k] = v.clone();
    }
    let auth = http_json(ng, "/identity/auth", body.to_string().as_bytes()).await;
    auth["token"].as_str().map(str::to_owned).ok_or(auth)
}

async fn device_login_as(
    s: &Server,
    who: &Person,
    dev: usize,
    card: &[u8],
    extra: Value,
    params: Value,
) -> Result<(Client, Value), Value> {
    let ng = s.ng;
    let token = token(s, who, dev, card, extra).await?;
    let tcp = TcpStream::connect(ng).await.unwrap();
    let mut c = Client::over(Box::new(tcp), &format!("ws://{ng}/ng?token={token}"))
        .await
        .unwrap();
    let hello = c.login(params).await.unwrap();
    Ok((c, hello))
}

fn card(who: &Person, name: &str) -> Vec<u8> {
    Card::new(&who.id, name, now())
        .sign(&who.id, vec![])
        .unwrap()
}

async fn device(s: &Server, who: &Person, dev: usize, name: &str) -> Client {
    let (c, hello) = device_login(s, who, dev, &card(who, name), json!({}))
        .await
        .expect("admitted");
    assert!(
        hello["caps"]
            .as_array()
            .unwrap()
            .contains(&json!("friendships")),
        "{hello}"
    );
    c
}

/// A password login that speaks the friend family and never asks for
/// its portable part.
async fn password(s: &Server, login: &str) -> (Client, Value) {
    let mut c = Client::connect(s.ng).await.unwrap();
    let hello = c
        .login(json!({ "login": login, "password": "pw", "messaging": true, "friendships": true }))
        .await
        .unwrap();
    (c, hello)
}

/// A request, waited past the request limit for, so a test's pace is not
/// what it checks.
async fn ask(c: &mut Client, req: &str, params: Value) -> Result<Value, String> {
    loop {
        match c.request(req, params.clone()).await {
            Ok(ok) => return Ok(ok),
            Err(Error::Refused { code, .. }) if code == "rate_limited" => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            Err(Error::Refused { code, .. }) => return Err(code),
            Err(e) => panic!("{req}: {e:?}"),
        }
    }
}

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    ask(c, req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e}"))
}

async fn event(c: &mut Client, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
    c.event_where(ev, pred)
        .await
        .unwrap_or_else(|e| panic!("no {ev}: {e:?}"))
        .data
}

fn offer(from: &Person, dev: usize, to: &Person, time: u64) -> Vec<u8> {
    let (key, cert) = &from.devices[dev];
    Offer {
        from: from.id.public(),
        to: fp(to),
        time,
        expires: time + DAY,
        id: [time as u8; 16],
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn accept(offer: &[u8], by: &Person, dev: usize, time: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    let acceptance = Acceptance {
        offer: Sha256::digest(offer).into(),
        from: by.id.public(),
        time,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap();
    Friendship::encode(offer, &acceptance)
}

fn withdraw(by: &Person, dev: usize, other: &Person, before: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    Withdrawal {
        from: by.id.public(),
        pair: Pair::new(fp(by), fp(other)).hash(),
        party: None,
        before,
        time: now(),
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn hash(f: &[u8]) -> String {
    b64(&Sha256::digest(f))
}

fn is_entry(d: &Value, login: &str, state: &str) -> bool {
    d["friend"]["login"] == login && d["friend"]["state"] == state
}

/// Alice and Bob made friends on `s` a minute ago, each from the given
/// sessions: the friendship's bytes.
async fn befriend(
    alice_c: &mut Client,
    bob_c: &mut Client,
    alice: &Person,
    bob: &Person,
) -> Vec<u8> {
    let o = offer(alice, 0, bob, now() - 60);
    let asked = ok(
        alice_c,
        "friend_add",
        json!({ "login": "bob", "offer": b64(&o) }),
    )
    .await;
    assert_eq!(asked["state"], "pending_out");
    let req = event(bob_c, "friend_request", |d| d["login"] == "alice").await;
    assert_eq!(req["offer"], b64(&o), "the offer, to a device that asked");
    let f = accept(&o, bob, 0, now() - 60);
    let done = ok(
        bob_c,
        "friend_respond",
        json!({ "login": "alice", "accept": true, "friendship": b64(&f) }),
    )
    .await;
    assert_eq!(done["state"], "accepted");
    let entry = event(alice_c, "friend", |d| is_entry(d, "bob", "accepted")).await;
    assert_eq!(entry["friend"]["friendships"], json!([hash(&f)]));
    f
}

async fn present(c: &mut Client, withdrawals: &[&[u8]], friendships: &[&[u8]]) -> Value {
    let w: Vec<String> = withdrawals.iter().map(|b| b64(b)).collect();
    let f: Vec<String> = friendships.iter().map(|b| b64(b)).collect();
    ok(
        c,
        "friendships_present",
        json!({ "withdrawals": w, "friendships": f }),
    )
    .await
}

#[tokio::test]
async fn a_friendship_made_on_one_server_is_in_place_on_the_next() {
    let (alice, bob) = (person(1), person(2));
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let s1 = start(d1.path(), &alice, &bob, false, true).await;
    let s2 = start(d2.path(), &alice, &bob, false, true).await;
    let mut erin = legacy::Client::login_at(s1.classic, &Login::account("erin", "erin", "pw"))
        .await
        .unwrap();
    erin.user_list().await.unwrap();
    let (mut plain_bob, hello) = password(&s1, "bob").await;
    assert!(
        !hello["caps"]
            .as_array()
            .unwrap()
            .contains(&json!("friendships")),
        "never granted to a session that proved no device"
    );
    ok(&mut plain_bob, "friends", json!({})).await;

    let mut alice1 = device(&s1, &alice, 0, "alice").await;
    let mut bob1 = device(&s1, &bob, 0, "bob").await;
    let found = ok(&mut alice1, "find_user", json!({ "login": "bob" })).await;
    assert_eq!(found["user"]["fingerprint"], fp(&bob).to_string());
    let f = befriend(&mut alice1, &mut bob1, &alice, &bob).await;
    let req = event(&mut plain_bob, "friend_request", |d| d["login"] == "alice").await;
    assert!(req.get("offer").is_none(), "a plain request: {req}");
    let entry = event(&mut plain_bob, "friend", |d| {
        is_entry(d, "alice", "accepted")
    })
    .await;
    assert!(entry["friend"].get("friendships").is_none(), "{entry}");
    let found = ok(&mut plain_bob, "find_user", json!({ "login": "alice" })).await;
    assert!(found["user"].get("fingerprint").is_none(), "{found}");

    // The second server, where neither has been: no request, and friends
    // once both have presented it.
    let mut alice2 = device(&s2, &alice, 1, "alice").await;
    let mut bob2 = device(&s2, &bob, 1, "bob").await;
    let found = ok(
        &mut alice2,
        "find_user",
        json!({ "fingerprint": fp(&bob).to_string() }),
    )
    .await;
    assert_eq!(found["user"]["login"], "bob");
    let first = present(&mut alice2, &[], &[&f]).await;
    assert_eq!(
        first["friendships"],
        json!([{ "hash": hash(&f), "result": "ok" }])
    );
    present(&mut bob2, &[], &[&f]).await;
    let entry = event(&mut alice2, "friend", |d| is_entry(d, "bob", "accepted")).await;
    assert_eq!(entry["friend"]["friendships"], json!([hash(&f)]));
    let listed = ok(&mut bob2, "friends", json!({})).await;
    assert_eq!(listed["friends"][0]["friendships"], json!([hash(&f)]));
    let fetched = ok(
        &mut bob2,
        "friendships_fetch",
        json!({ "hashes": [hash(&f), b64(&[7; 32])] }),
    )
    .await;
    assert_eq!(
        fetched["friendships"],
        json!([{ "hash": hash(&f), "friendship": b64(&f) }, { "hash": b64(&[7; 32]) }]),
        "a hash no friend's entry carried tells nothing"
    );

    erin.chat(b"still here").await.unwrap();
    erin.recv_where(|f| f.ty == push::CHAT).await.unwrap();
    let stray: Vec<u32> = erin
        .rx
        .take_backlog()
        .iter()
        .map(|f| f.ty)
        .filter(|ty| ![push::CHAT, push::USER_CHANGE, push::SELFINFO].contains(ty))
        .collect();
    assert!(
        stray.is_empty(),
        "a period client hears none of it: {stray:x?}"
    );
}

#[tokio::test]
async fn a_withdrawal_on_one_server_ends_the_friendship_on_the_other() {
    let (alice, bob) = (person(1), person(2));
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let s1 = start(d1.path(), &alice, &bob, false, true).await;
    let s2 = start(d2.path(), &alice, &bob, false, true).await;
    let mut alice1 = device(&s1, &alice, 0, "alice").await;
    let mut bob1 = device(&s1, &bob, 0, "bob").await;
    let f = befriend(&mut alice1, &mut bob1, &alice, &bob).await;
    let mut alice2 = device(&s2, &alice, 1, "alice").await;
    let mut bob2 = device(&s2, &bob, 1, "bob").await;
    present(&mut alice2, &[], &[&f]).await;
    present(&mut bob2, &[], &[&f]).await;
    event(&mut bob2, "friend", |d| is_entry(d, "alice", "accepted")).await;

    let before = now();
    let w = withdraw(&alice, 1, &bob, before);
    ok(
        &mut alice2,
        "friend_remove",
        json!({ "login": "bob", "withdraw": b64(&w) }),
    )
    .await;
    let gone = event(&mut bob2, "friend", |d| is_entry(d, "alice", "removed")).await;
    assert_eq!(gone["friend"]["withdraw"], b64(&w));

    // Alice's other device brings the same cutoff, signed afresh, to the
    // first server, before reading its roster there.
    let again = withdraw(&alice, 0, &bob, before);
    let taken = present(&mut alice1, &[&again], &[]).await;
    assert_eq!(taken["withdrawals"][0]["result"], "ok");
    let gone = event(&mut bob1, "friend", |d| is_entry(d, "alice", "removed")).await;
    assert_eq!(gone["friend"]["withdraw"], b64(&again));
    let refused = present(&mut bob1, &[], &[&f]).await;
    assert_eq!(refused["friendships"][0]["result"], "withdrawn");
    assert_eq!(refused["friendships"][0]["withdraw"], b64(&again));
}

#[tokio::test]
async fn a_revoked_device_takes_its_presentations_with_it() {
    let (alice, bob) = (person(1), person(2));
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path(), &alice, &bob, false, true).await;
    let mut alice1 = device(&s, &alice, 0, "alice").await;
    let mut bob1 = device(&s, &bob, 0, "bob").await;
    let f = befriend(&mut alice1, &mut bob1, &alice, &bob).await;

    s.core.set_revocations(Revocations {
        devices: [Fingerprint::of(&alice.devices[0].0.public()).0].into(),
        ..Default::default()
    });
    let gone = event(&mut bob1, "friend", |d| is_entry(d, "alice", "removed")).await;
    assert!(gone["friend"].get("withdraw").is_none(), "{gone}");
    assert!(
        device_login(&s, &alice, 0, &card(&alice, "alice"), json!({}))
            .await
            .is_err(),
        "the stolen device acts no more"
    );

    let mut alice2 = device(&s, &alice, 1, "alice").await;
    let back = present(&mut alice2, &[], &[&f]).await;
    assert_eq!(back["friendships"][0]["result"], "ok");
    event(&mut bob1, "friend", |d| is_entry(d, "alice", "accepted")).await;
}

#[tokio::test]
async fn the_gate_refuses_what_a_proved_device_of_the_account_did_not_sign() {
    let (alice, bob) = (person(1), person(2));
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path(), &alice, &bob, false, true).await;
    let mut alice0 = device(&s, &alice, 0, "alice").await;
    let (mut by_password, _) = password(&s, "alice").await;
    let t = now();
    for (case, by_device, o, code) in [
        (
            "a password session",
            false,
            offer(&alice, 0, &bob, t),
            "access_denied",
        ),
        (
            "another device's signature",
            true,
            offer(&alice, 1, &bob, t),
            "bad_signature",
        ),
        (
            "an hour old",
            true,
            offer(&alice, 0, &bob, t - 3600),
            "stale",
        ),
    ] {
        let c = if by_device {
            &mut alice0
        } else {
            &mut by_password
        };
        let got = ask(c, "friend_add", json!({ "login": "bob", "offer": b64(&o) })).await;
        assert_eq!(got, Err(code.to_string()), "{case}");
    }
}

#[tokio::test]
async fn a_rotation_is_followed_and_its_friendships_move_to_the_successor() {
    let (alice, bob, successor) = (person(1), person(2), person(3));
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path(), &alice, &bob, true, true).await;
    // Alice's card commits to her successor, so this server anchors it.
    let mut committed = Card::new(&alice.id, "alice", now());
    committed.successor = Some(fp(&successor).0);
    let committed = committed.sign(&alice.id, vec![]).unwrap();
    let (mut alice0, _) = device_login(&s, &alice, 0, &committed, json!({}))
        .await
        .unwrap();
    let mut bob0 = device(&s, &bob, 0, "bob").await;
    let old = befriend(&mut alice0, &mut bob0, &alice, &bob).await;

    let record = Rotation {
        identity: alice.id.public(),
        successor: successor.id.public(),
        time: now(),
    }
    .sign(&alice.id, &successor.id)
    .unwrap();
    let (mut next, _) = device_login(
        &s,
        &successor,
        0,
        &card(&successor, "alice"),
        json!({ "rotation": b64(&record) }),
    )
    .await
    .expect("the successor admitted");
    let fetched = ok(
        &mut bob0,
        "friendships_fetch",
        json!({ "fingerprints": [fp(&successor).to_string()] }),
    )
    .await;
    assert_eq!(
        fetched["rotations"],
        json!([{ "fingerprint": fp(&successor).to_string(), "records": [b64(&record)] }])
    );

    // The successor offers afresh; Bob's client, having checked the
    // rotation, accepts, and the friendship stands throughout.
    let o = offer(&successor, 0, &bob, now());
    let upgraded = ok(
        &mut next,
        "friend_add",
        json!({ "login": "bob", "offer": b64(&o) }),
    )
    .await;
    assert_eq!(upgraded["state"], "accepted", "an upgrade offer");
    let req = event(&mut bob0, "friend_request", |d| d["offer"] == b64(&o)).await;
    assert_eq!(req["login"], "alice");
    let f = accept(&o, &bob, 0, now());
    ok(
        &mut bob0,
        "friend_respond",
        json!({ "login": "alice", "accept": true, "friendship": b64(&f) }),
    )
    .await;
    let entry = event(&mut next, "friend", |d| {
        is_entry(d, "bob", "accepted") && d["friend"]["friendships"] == json!([hash(&f)])
    })
    .await;
    assert_ne!(entry["friend"]["friendships"], json!([hash(&old)]));
}

#[tokio::test]
async fn an_unlinked_identity_makes_no_more_friendship_acts() {
    let (alice, bob) = (person(1), person(2));
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path(), &alice, &bob, false, true).await;
    let mut alice0 = device(&s, &alice, 0, "alice").await;
    let mut bob0 = device(&s, &bob, 0, "bob").await;
    let f = befriend(&mut alice0, &mut bob0, &alice, &bob).await;
    let t = token(&s, &alice, 1, &card(&alice, "alice"), json!({}))
        .await
        .unwrap();
    let unlinked = http_as(s.ng, "/identity/unlink", b"", Some(&t)).await;
    assert_eq!(unlinked["unlinked"], "alice", "{unlinked}");
    let refused = ask(
        &mut alice0,
        "friendships_present",
        json!({ "friendships": [b64(&f)] }),
    )
    .await;
    assert_eq!(refused, Err("access_denied".to_string()));
}

#[tokio::test]
async fn a_block_stands_whatever_becomes_of_its_withdrawal() {
    let (alice, bob) = (person(1), person(2));
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path(), &alice, &bob, false, true).await;
    let mut alice0 = device(&s, &alice, 0, "alice").await;
    let mut bob0 = device(&s, &bob, 0, "bob").await;
    befriend(&mut alice0, &mut bob0, &alice, &bob).await;
    let old = now() - 3600;
    let (key, cert) = &alice.devices[0];
    let stale = Withdrawal {
        from: alice.id.public(),
        pair: Pair::new(fp(&alice), fp(&bob)).hash(),
        party: None,
        before: old,
        time: old,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap();
    let blocked = ask(
        &mut alice0,
        "block",
        json!({ "login": "bob", "withdraw": b64(&stale) }),
    )
    .await;
    assert_eq!(blocked, Err("stale".to_string()));
    let blocks = ok(&mut alice0, "blocks", json!({})).await;
    assert_eq!(blocks["blocked"][0]["login"], "bob", "{blocks}");
    event(&mut bob0, "friend", |d| is_entry(d, "alice", "removed")).await;
    let malformed = ask(
        &mut alice0,
        "block",
        json!({ "uid": 1, "withdraw": b64(&stale) }),
    )
    .await;
    assert_eq!(malformed, Err("bad_request".to_string()));
}

#[tokio::test]
async fn a_login_that_does_not_ask_is_answered_as_before() {
    let (alice, bob) = (person(1), person(2));
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let off = start(d1.path(), &alice, &bob, false, false).await;
    let (_, hello) = device_login(&off, &alice, 0, &card(&alice, "alice"), json!({}))
        .await
        .unwrap();
    let caps = hello["caps"].as_array().unwrap();
    assert!(
        !caps.contains(&json!("friendships")) && !caps.contains(&json!("messaging")),
        "messaging off: {hello}"
    );
    assert!(hello.get("messaging").is_none(), "{hello}");

    let on = start(d2.path(), &alice, &bob, false, true).await;
    let (mut quiet, hello) = device_login_as(
        &on,
        &alice,
        0,
        &card(&alice, "alice"),
        json!({}),
        json!({ "messaging": true }),
    )
    .await
    .unwrap();
    assert!(!hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("friendships")));
    let found = ok(&mut quiet, "find_user", json!({ "login": "bob" })).await;
    assert_eq!(found["user"], json!({ "login": "bob", "name": "bob" }));
    let refused = ask(&mut quiet, "friend_remove", json!({})).await;
    assert_eq!(refused, Err("bad_request".to_string()));
}
