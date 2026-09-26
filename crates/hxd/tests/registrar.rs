//! The registrar end to end (`docs/identity-registrar.md`): a server
//! built from a real `[registrar]` section, the `/registrar` routes and
//! discovery over real sockets, the operator's commands acting on the
//! running server's store, and `hlid` driven as a user would drive it.
//!
//! The registrar's store is SQLite, so a build without the `inbox`
//! feature has no registrar, and these have nothing to run against.
#![cfg(feature = "inbox")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hl_identity::{
    cert, Attestation, Card, DeviceCert, DeviceKey, IdentityKey, ListKind, LoginProof, Record,
    RegisterRequest, RegistrarKeys, Rotation, SignedList, Stats,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HOST: &str = "127.0.0.1";

struct Server {
    ng: SocketAddr,
    config: hxd::Config,
    config_path: PathBuf,
    registrar: Arc<hxd_registrar::Registrar>,
}

/// A server built the way `hxd` builds one, from a config file with an
/// `[identity]` and a `[registrar]`, every path inside `dir`.
async fn start(dir: &Path, registrar_extra: &str) -> Server {
    let d = dir.display();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [identity]\nkey = \"{d}/server.key\"\nsuccessors = \"{d}/successors\"\nenroll = false\n\
         [registrar]\nhost = \"{HOST}\"\nkey = \"{d}/registrar.key\"\n\
         store = \"{d}/registrar.db\"\ninvites = \"{d}/invites\"\n{registrar_extra}\n"
    );
    let config_path = dir.join("hxd-ng.toml");
    std::fs::write(&config_path, &text).unwrap();
    let config = hxd::Config::load(&config_path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let registrar = ng_ctx.registrar.clone().expect("[registrar] builds one");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = listener.local_addr().unwrap();
    tokio::spawn(hxd_ng_session::serve(listener, ng_ctx));
    Server {
        ng,
        config,
        config_path,
        registrar,
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {:?}", String::from_utf8_lossy(&self.body)))
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn http_as(
    addr: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().into(), v.trim().into()))
        })
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

async fn get(s: &Server, path: &str) -> Reply {
    http_as(s.ng, &s.ng.to_string(), "GET", path, &[], b"").await
}

async fn post(s: &Server, path: &str, body: Value) -> Reply {
    http_as(
        s.ng,
        &s.ng.to_string(),
        "POST",
        path,
        &[("Content-Type", "application/json")],
        body.to_string().as_bytes(),
    )
    .await
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn commitment(k: &IdentityKey) -> [u8; 32] {
    k.fingerprint().0
}

/// A request with a time of its own. Two requests signed in one second
/// are otherwise the same bytes, and the second is a replay — answered
/// with the first one's reply, which is not what a test sending a second
/// request means.
fn request(id: &IdentityKey, handle: &str) -> RegisterRequest {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    RegisterRequest {
        identity: id.public(),
        registrar: HOST.into(),
        handle: handle.into(),
        time: now() + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 100,
        successor: None,
        proof: None,
    }
}

async fn register(s: &Server, req: RegisterRequest, id: &IdentityKey) -> Reply {
    post(
        s,
        "/registrar/register",
        json!({ "request": b64(&req.sign(id).unwrap()) }),
    )
    .await
}

fn keys(s: &Server) -> Vec<[u8; 32]> {
    vec![s.registrar.public_key()]
}

/// A per-identity list, verified, with every record in it verified.
async fn records_of(s: &Server, id: &IdentityKey) -> Vec<Record> {
    let r = get(s, &format!("/registrar/records/{}", id.fingerprint())).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("Content-Type"), Some("application/cbor"));
    assert_eq!(r.header("Cache-Control"), Some("max-age=3600"));
    let k = keys(s);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let list = SignedList::parse(&r.body, ListKind::Records, rk).unwrap();
    assert_eq!(list.fingerprint, Some(id.fingerprint().0));
    list.entries
        .iter()
        .map(|(_, b)| Record::parse(b, Some(rk)).unwrap())
        .collect()
}

#[tokio::test]
async fn discovery_names_the_registrar_under_its_own_host_only() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let doc = get(&s, "/.well-known/hotline").await.json();
    let block = &doc["registrar"];
    assert_eq!(block["host"], HOST);
    assert_eq!(
        unb64(block["key"].as_str().unwrap()),
        s.registrar.public_key()
    );
    assert_eq!(block["signup"], "open");
    assert_eq!(block["proof"], Value::Null);
    assert_eq!(block["level"], 0);
    assert_eq!(block["handle"], json!({ "min": 3, "max": 32 }));
    assert_eq!(block["endpoints"]["register"], "/registrar/register");
    assert!(
        block["endpoints"].get("envelopes").is_none(),
        "no key backup here"
    );
    // The registrar key is not the server key (§3).
    assert_ne!(block["key"], doc["server_key"]);

    // Asked for under another name, the block is withheld: a verifier
    // trusts the key it finds under the name it asked.
    let other = http_as(s.ng, "localhost", "GET", "/.well-known/hotline", &[], b"").await;
    assert_eq!(other.json()["registrar"], Value::Null);

    // The key file is the one `hxd` made on its first start.
    assert!(dir.path().join("registrar.key").is_file());
}

#[tokio::test]
async fn a_handle_is_registered_looked_up_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);

    let r = register(&s, request(&alice, "alice"), &alice).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let reply = r.json();
    assert_eq!(reply["handle"], "alice@127.0.0.1");
    assert_eq!(reply["reissued"], false);
    let att = Attestation::parse(&unb64(reply["attestation"].as_str().unwrap())).unwrap();
    att.verify_registrar(&s.registrar.public_key(), now(), 60)
        .unwrap();
    assert_eq!(att.identity, alice.public());

    // Taken, reserved, malformed: the codes of §6.5, as JSON.
    let bob = IdentityKey::from_seed(&[2; 32]);
    for (handle, status, code) in [
        ("alice", 409, "handle_taken"),
        ("admin", 409, "handle_reserved"),
        ("Bob", 409, "handle_invalid"),
    ] {
        let r = register(&s, request(&bob, handle), &bob).await;
        assert_eq!(r.status, status, "{handle}");
        assert_eq!(r.json()["error"], code, "{handle}");
    }
    let mut elsewhere = request(&bob, "bobby");
    elsewhere.registrar = "other.example".into();
    assert_eq!(
        register(&s, elsewhere, &bob).await.json()["error"],
        "bad_request"
    );
    assert_eq!(
        post(&s, "/registrar/register", json!({ "request": 7 }))
            .await
            .status,
        400
    );

    let found = get(&s, "/registrar/lookup/alice").await;
    assert_eq!(found.status, 200);
    assert_eq!(found.json()["fingerprint"], alice.fingerprint().to_string());
    // One name whatever its case (§5.1).
    let found = get(&s, "/registrar/lookup/Alice").await;
    assert_eq!(found.status, 200);
    assert_eq!(found.json()["fingerprint"], alice.fingerprint().to_string());
    assert_eq!(
        get(&s, "/registrar/lookup/nobody").await.json()["error"],
        "not_found"
    );
    let by_key = get(
        &s,
        &format!("/registrar/lookup?identity={}", alice.fingerprint()),
    )
    .await;
    assert_eq!(by_key.json()["handles"], json!(["alice"]));

    // The log carries it, and the stats count it; both verify.
    let k = keys(&s);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let log = get(&s, "/registrar/log").await;
    let log = SignedList::parse(&log.body, ListKind::Log, rk).unwrap();
    assert_eq!(log.entries.len(), 1);
    assert_eq!(
        Attestation::parse(&log.entries[0].1).unwrap().handle,
        "alice"
    );
    let stats = Stats::parse(&get(&s, "/registrar/stats").await.body, rk).unwrap();
    assert_eq!((stats.identities, stats.issued_total), (1, 1));
    assert_eq!(stats.log_seq, log.entries[0].0);

    // And `hxd registrar inspect` reads it all back the way an operator
    // deciding whether to trust this registrar would.
    let base = format!("http://{}", s.ng);
    let report = tokio::task::spawn_blocking(move || hxd::registrar::inspect(&base))
        .await
        .unwrap()
        .unwrap();
    assert!(report.contains("registrar 127.0.0.1"), "{report}");
    assert!(report.contains("agrees with the stats"), "{report}");
    assert!(report.contains("1 new, 0 reissued"), "{report}");
}

#[tokio::test]
async fn a_rotation_is_published_under_both_keys() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let old = IdentityKey::from_seed(&[1; 32]);
    let new = IdentityKey::from_seed(&[2; 32]);
    let thief = IdentityKey::from_seed(&[6; 32]);
    let mut req = request(&old, "alice");
    req.successor = Some(commitment(&new));
    assert_eq!(register(&s, req, &old).await.status, 200);

    let rotate = |to: &IdentityKey| {
        Rotation {
            identity: old.public(),
            successor: to.public(),
            time: now(),
        }
        .sign(&old, to)
        .unwrap()
    };
    let r = post(
        &s,
        "/registrar/records",
        json!({ "record": b64(&rotate(&thief)) }),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["error"], "successor_mismatch");

    let r = post(
        &s,
        "/registrar/records",
        json!({ "record": b64(&rotate(&new)) }),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["published"], true);

    assert!(records_of(&s, &new)
        .await
        .iter()
        .any(|r| matches!(r, Record::Rotate(_))));
    let under_old = records_of(&s, &old).await;
    assert!(under_old.iter().any(|r| matches!(r, Record::Rotate(_))));
    assert!(under_old
        .iter()
        .any(|r| matches!(r, Record::RevokeAttestation(a) if a.handle == "alice")));

    // The predecessor is told where it went; the successor's request is
    // a reissue with the old age.
    let r = register(&s, request(&old, "alice"), &old).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["successor"], new.fingerprint().to_string());
    let r = register(&s, request(&new, "alice"), &new).await.json();
    assert_eq!(r["reissued"], true);

    // An unknown key has a signed, empty list — not a 404.
    assert!(records_of(&s, &IdentityKey::from_seed(&[9; 32]))
        .await
        .is_empty());
    // A record about an identity this registrar never attested.
    let stranger = IdentityKey::from_seed(&[8; 32]);
    let rec = hl_identity::IdentityRevocation {
        identity: stranger.public(),
        time: now(),
        reason: None,
    }
    .sign(&stranger)
    .unwrap();
    let r = post(&s, "/registrar/records", json!({ "record": b64(&rec) })).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (404, json!("not_registered"))
    );

    // The full list, as a delta.
    let k = keys(&s);
    let full = get(&s, "/registrar/records?since=0").await;
    let full = SignedList::parse(
        &full.body,
        ListKind::Records,
        RegistrarKeys {
            host: HOST,
            keys: &k,
        },
    )
    .unwrap();
    assert_eq!(full.since, Some(0));
    assert!(full.fingerprint.is_none());
    assert_eq!(
        full.entries.len(),
        2,
        "the rotation and one attestation revocation"
    );
}

/// The server key a challenge reply names.
fn s_key(ch: &Value) -> [u8; 32] {
    unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap()
}

/// Authenticate as a device, and return the transport token.
async fn token(s: &Server, id: &IdentityKey, dev: &DeviceKey, card: &[u8]) -> String {
    let cert = DeviceCert::for_device(id, dev, now() - 5, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(id);
    let ch = post(s, "/identity/challenge", Value::Null).await.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let proof = LoginProof::sign(dev, &challenge, &s_key(&ch), now());
    let r = post(
        s,
        "/identity/auth",
        json!({ "card": b64(card), "device_cert": b64(&cert), "proof": b64(&proof) }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_card_put_here_must_keep_the_registrars_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let dev = DeviceKey::from_seed(&[101; 32]);
    let next = IdentityKey::from_seed(&[2; 32]);
    let mut req = request(&alice, "alice");
    req.successor = Some(commitment(&next));
    assert_eq!(register(&s, req, &alice).await.status, 200);

    // Logging in with a card is caching it, so a card that drops the
    // commitment is refused there as well as at `PUT`.
    let plain_card = Card::new(&alice, "Alice", now())
        .sign(&alice, vec![])
        .unwrap();
    let cert = DeviceCert::for_device(&alice, &dev, now() - 5, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(&alice);
    let ch = post(&s, "/identity/challenge", Value::Null).await.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let proof = LoginProof::sign(&dev, &challenge, &s_key(&ch), now());
    let r = post(
        &s,
        "/identity/auth",
        json!({ "card": b64(&plain_card), "device_cert": b64(&cert), "proof": b64(&proof) }),
    )
    .await;
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["error"], "bad_card");
    let fp = alice.fingerprint().to_string();
    assert_eq!(get(&s, &format!("/identity/card/{fp}")).await.status, 404);

    let mut first = Card::new(&alice, "Alice", now());
    first.successor = Some(commitment(&next));
    let t = token(&s, &alice, &dev, &first.sign(&alice, vec![]).unwrap()).await;
    let put = |card: Vec<u8>, t: String| {
        let addr = s.ng;
        async move {
            http_as(
                addr,
                &addr.to_string(),
                "PUT",
                "/identity/card",
                &[
                    ("Authorization", &format!("Bearer {t}")),
                    ("Content-Type", "application/cbor"),
                ],
                &card,
            )
            .await
        }
    };
    // Dropping the commitment is changing it.
    let mut dropped = Card::new(&alice, "Alice", now() + 1);
    dropped.successor = None;
    let r = put(dropped.sign(&alice, vec![]).unwrap(), t.clone()).await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["error"], "successor_mismatch");

    let mut kept = Card::new(&alice, "Alice", now() + 2);
    kept.successor = Some(commitment(&next));
    let r = put(kept.sign(&alice, vec![]).unwrap(), t).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // A card makes the first commitment for an identity that registered
    // without one, and the registrar holds it from then on.
    let bob = IdentityKey::from_seed(&[3; 32]);
    let bob_dev = DeviceKey::from_seed(&[103; 32]);
    assert_eq!(register(&s, request(&bob, "bobby"), &bob).await.status, 200);
    let mut committed = Card::new(&bob, "Bob", now());
    committed.successor = Some([4; 32]);
    let committed = committed.sign(&bob, vec![]).unwrap();
    let t = token(&s, &bob, &bob_dev, &committed).await;
    let r = put(committed, t).await;
    assert_eq!(r.status, 200);
    let r = register(&s, request(&bob, "bobby"), &bob).await;
    assert_eq!(r.json()["error"], "successor_mismatch");
}

#[tokio::test]
async fn invites_come_from_the_file_and_from_the_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("invites"),
        "# handed out at the meetup\nAAAA-BBBB\n",
    )
    .unwrap();
    let s = start(dir.path(), "").await;
    let doc = get(&s, "/.well-known/hotline").await.json();
    assert_eq!(doc["registrar"]["signup"], "proof");
    assert_eq!(doc["registrar"]["proof"], "invite");
    assert_eq!(doc["registrar"]["level"], 2);

    let alice = IdentityKey::from_seed(&[1; 32]);
    let r = register(&s, request(&alice, "alice"), &alice).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (403, json!("proof_required"))
    );
    let with = |id: &IdentityKey, handle: &str, code: &str| {
        let mut r = request(id, handle);
        r.proof = Some(code.into());
        r
    };
    assert_eq!(
        register(&s, with(&alice, "alice", "aaaabbbb"), &alice)
            .await
            .status,
        200
    );
    let bob = IdentityKey::from_seed(&[2; 32]);
    let r = register(&s, with(&bob, "bobby", "AAAA-BBBB"), &bob).await;
    assert_eq!(r.json()["error"], "proof_invalid");

    // A code minted by the operator's command works on the running
    // server at once: they share the store.
    let codes = hxd::registrar::invites_add(&s.config, 1).unwrap();
    assert!(std::fs::read_to_string(dir.path().join("invites"))
        .unwrap()
        .contains(&codes[0]));
    assert_eq!(
        register(&s, with(&bob, "bobby", &codes[0]), &bob)
            .await
            .status,
        200
    );

    // A login created after start is reserved once SIGHUP re-reads.
    std::fs::write(
        dir.path().join("accounts").join("carol.toml"),
        "name = \"Carol\"\npassword = \"pw\"\n",
    )
    .unwrap();
    let carol = IdentityKey::from_seed(&[3; 32]);
    let more = hxd::registrar::invites_add(&s.config, 1).unwrap();
    hxd::registrar::reload(&s.registrar, &s.config_path).unwrap();
    let r = register(&s, with(&carol, "carol", &more[0]), &carol).await;
    assert_eq!(r.json()["error"], "handle_reserved");
}

#[tokio::test]
async fn the_operators_commands_act_on_the_running_registrar() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let fp = alice.fingerprint().to_string();

    hxd::registrar::freeze(&s.config, &fp, false).unwrap();
    let r = register(&s, request(&alice, "alice"), &alice).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (403, json!("frozen"))
    );
    hxd::registrar::freeze(&s.config, &fp, true).unwrap();
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let freezes: Vec<bool> = records_of(&s, &alice)
        .await
        .into_iter()
        .filter_map(|r| match r {
            Record::Freeze(f) => Some(f.frozen),
            _ => None,
        })
        .collect();
    assert_eq!(freezes, vec![true, false]);

    hxd::registrar::revoke(&s.config, "alice", "abuse").unwrap();
    let r = register(&s, request(&alice, "alice"), &alice).await;
    assert_eq!(r.json()["error"], "handle_held");
    assert!(hxd::registrar::revoke(&s.config, "alice", "because").is_err());

    // Recovery to a new key, age kept.
    let bob = IdentityKey::from_seed(&[2; 32]);
    assert_eq!(register(&s, request(&bob, "bobby"), &bob).await.status, 200);
    let bob2 = IdentityKey::from_seed(&[12; 32]);
    hxd::registrar::recover(&s.config, "bobby", &bob2.fingerprint().to_string(), true).unwrap();
    let r = register(&s, request(&bob2, "bobby"), &bob2).await.json();
    assert_eq!(r["reissued"], true);

    // The commands never mint a key of their own.
    let mut elsewhere = hxd::Config::load(&s.config_path).unwrap();
    elsewhere.registrar.as_mut().unwrap().key = dir.path().join("missing.key");
    let err = hxd::registrar::freeze(&elsewhere, &fp, false).unwrap_err();
    assert!(err.contains("start the server once"), "{err}");
    assert!(!dir.path().join("missing.key").exists());
}

#[test]
fn a_registrar_section_is_checked_before_anything_starts() {
    let bad = |section: &str, needle: &str| {
        let text = format!("[ng]\n[identity]\n[registrar]\n{section}\n");
        let config: hxd::Config = toml::from_str(&text).unwrap();
        let err = hxd::check_config(&config).unwrap_err();
        assert!(err.contains(needle), "{section}: {err}");
    };
    bad("host = \"hl.example:443\"", "no port");
    bad("host = \"HL.example\"", "lowercase");
    bad(
        "host = \"hl.example\"\nsignup = \"open\"\nproof = \"invite\"",
        "signup = proof",
    );
    bad("host = \"hl.example\"\nproof = \"none\"", "needs a proof");
    bad("host = \"hl.example\"\nproof = \"email\"", "invites only");
    bad("host = \"hl.example\"\nlevel = 3", "at most 2");
    bad(
        "host = \"hl.example\"\nsignup = \"open\"\nlevel = 1",
        "at most 0",
    );
    bad(
        "host = \"hl.example\"\nhandle_min = 5\nhandle_max = 4",
        "handle_min",
    );
    bad("host = \"hl.example\"\nenvelopes = true", "not built");
    bad(
        "host = \"hl.example\"\n[registrar.rate]\nregistrations_per_hour = 0",
        "at least 1",
    );

    let config: hxd::Config = toml::from_str("[ng]\n[registrar]\nhost = \"hl.example\"\n").unwrap();
    assert!(hxd::check_config(&config)
        .unwrap_err()
        .contains("needs [identity]"));
}

// --- `hlid` against a real registrar ------------------------------------

/// The `hlid` binary, built fresh for the reason `identity.rs` gives.
fn hlid_binary() -> PathBuf {
    let ok = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "hlid"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("cargo build -p hlid")
        .success();
    assert!(ok, "cargo build -p hlid failed");
    let mut dir = std::env::current_exe().unwrap();
    dir.pop();
    dir.pop();
    let bin = dir.join(if cfg!(windows) { "hlid.exe" } else { "hlid" });
    assert!(bin.exists(), "no hlid binary at {}", bin.display());
    bin
}

async fn hlid(bin: &Path, home: &Path, args: &[&str]) -> (bool, String, String) {
    let (bin, home) = (bin.to_owned(), home.to_owned());
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(bin)
            .env("HLID_HOME", home)
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn hlid_registers_revokes_and_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let bin = hlid_binary();
    let home = dir.path().join("hlid");
    let url = format!("http://{}", s.ng);
    let (ok, _, err) = hlid(&bin, &home, &["init", "--name", "Alice"]).await;
    assert!(ok, "{err}");

    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[
            "register",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--successor-commit",
        ],
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("registered alice@127.0.0.1"), "{out}");
    assert!(out.contains("card published"), "{out}{err}");
    assert!(home.join("successor.key").is_file());

    // The card now carries the attestation and the commitment, and the
    // registrar serves it.
    let card = Card::parse(&std::fs::read(home.join("card.bin")).unwrap()).unwrap();
    assert_eq!(card.attestations.len(), 1);
    assert_eq!(card.attestations[0].full_handle(), "alice@127.0.0.1");
    let successor_seed: [u8; 32] = {
        let text = std::fs::read_to_string(home.join("successor.key")).unwrap();
        let t = text.trim();
        (0..32)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    let successor = IdentityKey::from_seed(&successor_seed);
    assert_eq!(card.successor, Some(commitment(&successor)));
    let served = get(
        &s,
        &format!(
            "/identity/card/{}",
            hl_identity::Fingerprint::of(&card.identity)
        ),
    )
    .await;
    assert_eq!(served.status, 200);
    assert_eq!(Card::parse(&served.body).unwrap().attestations.len(), 1);

    // Registering again is a reissue, and the card keeps one attestation
    // for the name, not two. A second later, so it is a new request and
    // not the first one's replay.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[
            "register",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--no-put",
        ],
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("reissued"), "{out}");
    let card = Card::parse(&std::fs::read(home.join("card.bin")).unwrap()).unwrap();
    assert_eq!(card.attestations.len(), 1);

    // Revoke a second device by its certificate, signed by this
    // machine's device (its `init` certificate carries `manage`).
    let other = dir.path().join("other.key");
    let other_cert = dir.path().join("other.cert");
    assert!(
        hlid(&bin, &home, &["keygen", "device", other.to_str().unwrap()])
            .await
            .0
    );
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &[
            "cert",
            "--device",
            other.to_str().unwrap(),
            "-o",
            other_cert.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ok, "{err}");
    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[
            "revoke",
            "--registrar",
            &url,
            "--device-cert",
            other_cert.to_str().unwrap(),
            "--reason",
            "lost",
            "--by-device",
        ],
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("revoke_device published"), "{out}");
    let other_dev = DeviceCert::parse(&std::fs::read(&other_cert).unwrap()).unwrap();
    let alice_id = IdentityKey::from_seed(&{
        let text = std::fs::read_to_string(home.join("identity.key")).unwrap();
        let t = text.trim().to_owned();
        let v: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        <[u8; 32]>::try_from(v).unwrap()
    });
    assert!(records_of(&s, &alice_id).await.iter().any(|r| matches!(
        r,
        Record::RevokeDevice(d) if d.device == other_dev.device && d.until == other_dev.expires
    )));

    // Revoking the identity asks first.
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &["revoke", "--registrar", &url, "--identity-revoke"],
    )
    .await;
    assert!(!ok);
    assert!(err.contains("--yes"), "{err}");

    // Rotate to the committed successor; it then holds the name, with
    // its age.
    let succ_key = home.join("successor.key");
    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[
            "rotate",
            "--registrar",
            &url,
            "--to",
            succ_key.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("rotate published"), "{out}");
    // The next step it prints is what the successor runs, as printed.
    let steps: Vec<Vec<String>> = out
        .lines()
        .filter_map(|l| l.strip_prefix("  hlid "))
        .map(|l| {
            assert!(!l.contains('\''), "a step this test cannot split: {l}");
            l.split_whitespace().map(str::to_owned).collect()
        })
        .collect();
    assert_eq!(steps.len(), 2, "{out}");
    assert_eq!(steps[0][0], "card", "{out}");
    assert!(steps[1].iter().any(|w| w == "alice"), "{out}");
    let mut last = String::new();
    for step in &steps {
        let words: Vec<&str> = step.iter().map(String::as_str).collect();
        let (ok, out, err) = hlid(&bin, &home, &words).await;
        assert!(ok, "hlid {}: {err}", step.join(" "));
        last = out;
    }
    let out = last;
    let succ_card = home.join("successor-card.bin");
    assert!(out.contains("reissued alice@127.0.0.1"), "{out}");
    let a = &Card::parse(&std::fs::read(&succ_card).unwrap())
        .unwrap()
        .attestations[0];
    assert_eq!(a.registered, card.attestations[0].registered);
}
