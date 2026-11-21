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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hl_identity::envelope::{Kdf, Keys, Kind, Secret};
use hl_identity::{
    cert, Attestation, Card, DeviceCert, DeviceEpoch, DeviceKey, DeviceProof, DeviceRevocation,
    EnvelopePut, IdentityKey, KeyEnvelope, ListKind, LoginProof, Record, RegisterRequest,
    RegistrarKeys, Rotation, ServerChallenge, SignedList, Stats,
};
use hxd_testclient::device::{get_device_challenge, prove_device};
use hxd_testclient::legacy::{Client, Login};
use hxproto::messages::{tag, ClientHdr};
use hxproto::messaging::CAP_DEVICE_PROOF;
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
    clock: hxd_core::clock::Clock,
}

/// A server built the way `hxd` builds one, from a config file with an
/// `[identity]` and a `[registrar]`, every path inside `dir`.
async fn start(dir: &Path, registrar_extra: &str) -> Server {
    let d = dir.display();
    // Bound first, so that `hosts` can name the address the tests reach
    // it by: without a name, no `v = 2` proof logs in.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = listener.local_addr().unwrap();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [identity]\nkey = \"{d}/server.key\"\nsuccessors = \"{d}/successors\"\nenroll = false\n\
         hosts = [\"{ng}\"]\n\
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
    let clock = ng_ctx.core.clock().clone();
    tokio::spawn(hxd_ng_session::serve(listener, ng_ctx));
    Server {
        ng,
        config,
        config_path,
        registrar,
        clock,
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
            next: None,
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

#[tokio::test]
async fn a_reset_is_published_and_answered_where_the_identity_stands() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let t = now();
    let reset = |epoch: u64, time: u64| {
        DeviceEpoch {
            identity: alice.public(),
            epoch,
            time,
        }
        .sign(&alice)
        .unwrap()
    };
    let post_record = |bytes: Vec<u8>| {
        let s = &s;
        async move { post(s, "/registrar/records", json!({ "record": b64(&bytes) })).await }
    };

    let one = reset(1, t);
    let hash_one = b64(&Sha256::digest(&one));
    let r = post_record(one.clone()).await;
    assert_eq!(r.status, 200);
    let done = r.json();
    assert_eq!(
        (&done["published"], &done["epoch"], &done["hash"]),
        (&json!(true), &json!(1), &json!(hash_one))
    );
    assert!(done["seq"].as_u64().is_some());
    for retry in [one.clone(), reset(1, t + 1)] {
        let r = post_record(retry).await;
        assert_eq!((r.status, r.json()), (200, done.clone()));
    }
    let r = post_record(reset(18, t + 1)).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (400, json!("bad_request"))
    );

    // A device certified before the reset revokes nothing after it.
    let old = DeviceKey::from_seed(&[2; 32]);
    let cert = DeviceCert::for_device(&alice, &old, t - 10, 86_400)
        .unwrap()
        .sign(&alice);
    let revoke = DeviceRevocation {
        identity: alice.public(),
        device: [9; 32],
        time: t,
        until: t + 86_400,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign_as_device(&old, cert)
    .unwrap();
    let r = post_record(revoke).await;
    assert_eq!(r.status, 401);
    assert_eq!(
        r.json(),
        json!({ "error": "bad_signature", "text": "the signer's device was reset" })
    );

    let two = reset(2, t + 2);
    let r = post_record(two.clone()).await.json();
    assert_eq!(
        (&r["epoch"], &r["hash"]),
        (&json!(2), &json!(b64(&Sha256::digest(&two))))
    );
    let epochs = |records: Vec<Record>| -> Vec<u64> {
        records
            .into_iter()
            .filter_map(|r| match r {
                Record::DeviceEpoch(e) => Some(e.epoch),
                _ => None,
            })
            .collect()
    };
    assert_eq!(epochs(records_of(&s, &alice).await), vec![1, 2]);
    let k = keys(&s);
    let rk = RegistrarKeys {
        host: HOST,
        keys: &k,
    };
    let full = get(&s, "/registrar/records?since=0").await;
    let full = SignedList::parse(&full.body, ListKind::Records, rk).unwrap();
    let full = full
        .entries
        .iter()
        .map(|(_, b)| Record::parse(b, Some(rk)).unwrap())
        .collect();
    assert_eq!(epochs(full), vec![2]);
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
    let proof = LoginProof::sign(dev, &challenge, &s_key(&ch), &s.ng.to_string(), now()).unwrap();
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
async fn a_card_a_held_rotation_would_not_take_is_refused_and_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"\nrotation_delay = 86400").await;
    let (old, new, next, thief) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
        IdentityKey::from_seed(&[3; 32]),
        IdentityKey::from_seed(&[6; 32]),
    );
    let dev = DeviceKey::from_seed(&[102; 32]);
    let mut req = request(&old, "alice");
    req.successor = Some(commitment(&new));
    assert_eq!(register(&s, req, &old).await.status, 200);
    assert_eq!(register(&s, request(&new, "bobby"), &new).await.status, 200);
    let rotated = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: now(),
        next: Some(commitment(&next)),
    }
    .sign(&old, &new)
    .unwrap();
    let r = post(&s, "/registrar/records", json!({ "record": b64(&rotated) }))
        .await
        .json();
    assert_eq!(r["published"], false, "{r}");

    let card = |successor: Option<&IdentityKey>, at| {
        let mut card = Card::new(&new, "Bob", at);
        card.successor = successor.map(commitment);
        card.sign(&new, vec![]).unwrap()
    };
    let plain = card(None, now());
    let t = token(&s, &new, &dev, &plain).await;
    let put = |card: Vec<u8>| {
        let (addr, t) = (s.ng, t.clone());
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
    let served = format!("/identity/card/{}", new.fingerprint());
    // Naming another successor than the rotation's `next`: refused, and
    // the card served is still the one before.
    let stolen = card(Some(&thief), now() + 1);
    let r = put(stolen.clone()).await;
    assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    let body = r.json();
    assert_eq!(body["error"], "rotation_pending");
    assert!(body["pending_until"].as_u64().is_some(), "{body}");
    // Put by another identity's session, it is refused as another's card
    // is, saying nothing of how this one stands.
    let mut old_card = Card::new(&old, "Alice", now());
    old_card.successor = Some(commitment(&new));
    let old_card = old_card.sign(&old, vec![]).unwrap();
    let theirs = token(&s, &old, &DeviceKey::from_seed(&[101; 32]), &old_card).await;
    let r = http_as(
        s.ng,
        &s.ng.to_string(),
        "PUT",
        "/identity/card",
        &[
            ("Authorization", &format!("Bearer {theirs}")),
            ("Content-Type", "application/cbor"),
        ],
        &stolen,
    )
    .await;
    assert_eq!(
        r.json()["error"],
        "bad_card",
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    // Shown at sign-in, it is a card the registrar will not take.
    let r = auth_at(s.ng, &new, &dev, &stolen).await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (401, json!("bad_card"))
    );
    assert_eq!(get(&s, &served).await.body, plain);
    // Naming `next` is taken.
    let named = card(Some(&next), now() + 2);
    assert_eq!(put(named.clone()).await.status, 200);
    assert_eq!(get(&s, &served).await.body, named);
}

#[tokio::test]
async fn a_cached_card_the_successors_new_commitment_contradicts_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (next, thief) = (
        IdentityKey::from_seed(&[3; 32]),
        IdentityKey::from_seed(&[6; 32]),
    );
    // Each a rotation from `old` to `new`, whose card names `named`.
    for (n, named) in [(10, Some(&thief)), (20, None)] {
        let (old, new) = (
            IdentityKey::from_seed(&[n; 32]),
            IdentityKey::from_seed(&[n + 1; 32]),
        );
        // Shown at sign-in by a key the registrar does not know, the card
        // is cached and any commitment it names left untaken.
        let mut card = Card::new(&new, "Bob", now());
        card.successor = named.map(commitment);
        let card = card.sign(&new, vec![]).unwrap();
        token(&s, &new, &DeviceKey::from_seed(&[n + 2; 32]), &card).await;
        let path = format!("/identity/card/{}", new.fingerprint());
        assert_eq!(get(&s, &path).await.body, card);

        let mut req = request(&old, &format!("user{n}"));
        req.successor = Some(commitment(&new));
        assert_eq!(register(&s, req, &old).await.status, 200);
        let rotated = Rotation {
            identity: old.public(),
            successor: new.public(),
            time: now(),
            next: Some(commitment(&next)),
        }
        .sign(&old, &new)
        .unwrap();
        let r = post(&s, "/registrar/records", json!({ "record": b64(&rotated) }))
            .await
            .json();
        assert_eq!(r["published"], true, "{r}");
        assert_eq!(get(&s, &path).await.status, 404, "{named:?}");
    }
}

#[tokio::test]
async fn a_card_the_registrar_cannot_check_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let card = Card::new(&alice, "Alice", now())
        .sign(&alice, vec![])
        .unwrap();
    let t = token(&s, &alice, &DeviceKey::from_seed(&[101; 32]), &card).await;
    let path = format!("/identity/card/{}", alice.fingerprint());
    assert_eq!(get(&s, &path).await.status, 200);
    // The registrar's store failing under it.
    rusqlite::Connection::open(dir.path().join("registrar.db"))
        .unwrap()
        .execute_batch("DROP TABLE registrar_identity")
        .unwrap();
    assert_eq!(get(&s, &path).await.status, 503);
    let newer = Card::new(&alice, "Alice", now() + 1)
        .sign(&alice, vec![])
        .unwrap();
    let r = http_as(
        s.ng,
        &s.ng.to_string(),
        "PUT",
        "/identity/card",
        &[
            ("Authorization", &format!("Bearer {t}")),
            ("Content-Type", "application/cbor"),
        ],
        &newer,
    )
    .await;
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
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
    let proof = LoginProof::sign(&dev, &challenge, &s_key(&ch), &s.ng.to_string(), now()).unwrap();
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

/// Register alice committed to `next`, sign in with a card carrying the
/// commitment, and put a newer one: the card the registrar keeps.
async fn committed_card(s: &Server, alice: &IdentityKey, next: &IdentityKey) -> Vec<u8> {
    let mut req = request(alice, "alice");
    req.successor = Some(commitment(next));
    assert_eq!(register(s, req, alice).await.status, 200);
    let card = |at| {
        let mut card = Card::new(alice, "Alice", at);
        card.successor = Some(commitment(next));
        card.sign(alice, vec![]).unwrap()
    };
    let t = token(s, alice, &DeviceKey::from_seed(&[101; 32]), &card(now())).await;
    let newer = card(now() + 1);
    let r = http_as(
        s.ng,
        &s.ng.to_string(),
        "PUT",
        "/identity/card",
        &[
            ("Authorization", &format!("Bearer {t}")),
            ("Content-Type", "application/cbor"),
        ],
        &newer,
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    newer
}

/// `PUT /identity/card` with a transport token.
async fn put_card(s: &Server, token: &str, card: &[u8]) -> Reply {
    http_as(
        s.ng,
        &s.ng.to_string(),
        "PUT",
        "/identity/card",
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/cbor"),
        ],
        card,
    )
    .await
}

#[tokio::test]
async fn a_card_put_again_after_the_store_failed_to_keep_it_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    committed_card(&s, &alice, &next).await;
    let t = token(
        &s,
        &alice,
        &DeviceKey::from_seed(&[102; 32]),
        &committed(&alice, &next, now() + 1),
    )
    .await;
    let db = rusqlite::Connection::open(dir.path().join("registrar.db")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER full BEFORE UPDATE OF card ON registrar_identity
         BEGIN SELECT RAISE(ABORT, 'disk full'); END",
    )
    .unwrap();
    let card = committed(&alice, &next, now() + 2);
    assert_eq!(put_card(&s, &t, &card).await.status, 503);
    db.execute_batch("DROP TRIGGER full").unwrap();
    // The same card again, now cached here already.
    assert_eq!(put_card(&s, &t, &card).await.status, 200);
    let kept: Vec<u8> = db
        .query_row(
            "SELECT card FROM registrar_identity WHERE key = ?1",
            [&alice.public()[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, card);
}

#[tokio::test]
async fn an_older_card_put_makes_no_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let at = now();
    let plain = Card::new(&alice, "Alice", at).sign(&alice, vec![]).unwrap();
    let t = token(&s, &alice, &DeviceKey::from_seed(&[101; 32]), &plain).await;
    let r = put_card(&s, &t, &committed(&alice, &next, at - 1)).await;
    assert_eq!(
        r.json()["updated"],
        false,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert!(found["successor"].is_null(), "{found}");
}

/// A card of `alice` dated `at`, committed to `next`.
fn committed(alice: &IdentityKey, next: &IdentityKey, at: u64) -> Vec<u8> {
    let mut card = Card::new(alice, "Alice", at);
    card.successor = Some(commitment(next));
    card.sign(alice, vec![]).unwrap()
}

#[tokio::test]
async fn a_card_served_in_place_of_one_as_new_is_not_answered_304() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let at = now();
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let plain = Card::new(&alice, "Alice", at).sign(&alice, vec![]).unwrap();
    token(&s, &alice, &DeviceKey::from_seed(&[101; 32]), &plain).await;
    let path = format!("/identity/card/{}", alice.fingerprint());
    let first = get(&s, &path).await;
    assert_eq!(first.body, plain);
    let etag = first.header("etag").unwrap().to_owned();
    // The commitment made, the cached card is refused and one as new
    // carrying it is kept and served in its place.
    let mut req = request(&alice, "alice");
    req.successor = Some(commitment(&next));
    assert_eq!(register(&s, req, &alice).await.status, 200);
    let kept = committed(&alice, &next, at);
    token(&s, &alice, &DeviceKey::from_seed(&[102; 32]), &kept).await;
    let r = http_as(
        s.ng,
        &s.ng.to_string(),
        "GET",
        &path,
        &[("If-None-Match", &etag)],
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, kept);
}

#[tokio::test]
async fn a_card_carrying_the_commitment_is_served_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let kept = committed_card(&s, &alice, &next).await;
    drop(s);

    // A second server on the same files, its card cache empty.
    let s = start(dir.path(), "signup = \"open\"").await;
    let r = get(&s, &format!("/identity/card/{}", alice.fingerprint())).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, kept);
    let card = Card::parse(&r.body).unwrap();
    assert_eq!(card.successor, Some(commitment(&next)));
}

#[tokio::test]
async fn a_kept_card_the_registrar_would_now_refuse_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    committed_card(&s, &alice, &next).await;
    drop(s);
    let db = rusqlite::Connection::open(dir.path().join("registrar.db")).unwrap();
    let kept: bool = db
        .query_row(
            "SELECT card IS NOT NULL FROM registrar_identity WHERE key = ?1",
            [&alice.public()[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert!(kept);
    // The store holding another commitment than the kept card's.
    db.execute(
        "UPDATE registrar_identity SET commitment = ?1",
        [&[4u8; 32][..]],
    )
    .unwrap();

    let s = start(dir.path(), "signup = \"open\"").await;
    let path = format!("/identity/card/{}", alice.fingerprint());
    assert_eq!(get(&s, &path).await.status, 404);
}

#[tokio::test]
async fn no_card_is_served_for_an_identity_revoked_or_rotated_away() {
    for rotated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path(), "signup = \"open\"").await;
        let (alice, next) = (
            IdentityKey::from_seed(&[1; 32]),
            IdentityKey::from_seed(&[2; 32]),
        );
        committed_card(&s, &alice, &next).await;
        let path = format!("/identity/card/{}", alice.fingerprint());
        assert_eq!(get(&s, &path).await.status, 200);
        let record = if rotated {
            Rotation {
                identity: alice.public(),
                successor: next.public(),
                time: now(),
                next: None,
            }
            .sign(&alice, &next)
            .unwrap()
        } else {
            hl_identity::IdentityRevocation {
                identity: alice.public(),
                time: now(),
                reason: None,
            }
            .sign(&alice)
            .unwrap()
        };
        let r = post(&s, "/registrar/records", json!({ "record": b64(&record) })).await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(get(&s, &path).await.status, 404, "rotated: {rotated}");
        drop(s);

        let s = start(dir.path(), "signup = \"open\"").await;
        assert_eq!(get(&s, &path).await.status, 404, "rotated: {rotated}");
    }
}

#[tokio::test]
async fn no_card_is_served_once_a_held_rotation_comes_due() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"\nrotation_delay = 86400").await;
    let (alice, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    committed_card(&s, &alice, &next).await;
    let rotated = Rotation {
        identity: alice.public(),
        successor: next.public(),
        time: now(),
        next: None,
    }
    .sign(&alice, &next)
    .unwrap();
    let r = post(&s, "/registrar/records", json!({ "record": b64(&rotated) }))
        .await
        .json();
    assert_eq!(r["published"], false, "{r}");
    let path = format!("/identity/card/{}", alice.fingerprint());
    assert_eq!(get(&s, &path).await.status, 200, "while it is held");
    // Past its delay, with nothing else asking the registrar to publish.
    s.clock.advance(Duration::from_secs(86_401));
    assert_eq!(get(&s, &path).await.status, 404);
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

#[tokio::test]
async fn a_lookup_names_the_commitment_the_registrar_kept_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let (alice, next, bob) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
        IdentityKey::from_seed(&[3; 32]),
    );
    let mut req = request(&alice, "alice");
    req.successor = Some(commitment(&next));
    assert_eq!(register(&s, req, &alice).await.status, 200);
    assert_eq!(register(&s, request(&bob, "bobby"), &bob).await.status, 200);
    drop(s);

    // A second server on the same files, with a store of its own.
    let s = start(dir.path(), "signup = \"open\"").await;
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert_eq!(found["fingerprint"], alice.fingerprint().to_string());
    assert_eq!(found["successor"], next.fingerprint().to_string());
    let found = get(&s, "/registrar/lookup/bobby").await.json();
    assert!(found["successor"].is_null(), "{found}");
}

#[tokio::test]
async fn a_held_rotation_holds_off_another_and_the_operator_publishes_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"\nrotation_delay = 86400").await;
    let (old, new, next) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
        IdentityKey::from_seed(&[3; 32]),
    );
    let mut req = request(&old, "alice");
    req.successor = Some(commitment(&new));
    assert_eq!(register(&s, req, &old).await.status, 200);
    // The rotation names the successor's own commitment.
    let rotated = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: now(),
        next: Some(commitment(&next)),
    }
    .sign(&old, &new)
    .unwrap();
    let r = post(&s, "/registrar/records", json!({ "record": b64(&rotated) }))
        .await
        .json();
    assert_eq!(r["published"], false, "{r}");
    let until = r["pending_until"].clone();

    let other = IdentityKey::from_seed(&[6; 32]);
    let r = post(
        &s,
        "/registrar/records",
        json!({ "record": b64(&rotation(&old, &other)) }),
    )
    .await;
    assert_eq!(r.status, 409);
    let body = r.json();
    assert_eq!(body["error"], "rotation_pending");
    assert_eq!(body["pending_until"], until);

    let (old_fp, new_fp) = (old.fingerprint().to_string(), new.fingerprint().to_string());
    let other = other.fingerprint().to_string();
    let err = hxd::registrar::publish(&s.config, &old_fp, &other).unwrap_err();
    assert!(err.contains(&format!("is to {new_fp}, not")), "{err}");
    hxd::registrar::publish(&s.config, &old_fp, &new_fp).unwrap();
    assert!(records_of(&s, &new)
        .await
        .iter()
        .any(|r| matches!(r, Record::Rotate(_))));
    // The old key, rotated away, writes nothing more.
    let revoke = hl_identity::IdentityRevocation {
        identity: old.public(),
        time: now(),
        reason: None,
    }
    .sign(&old)
    .unwrap();
    let r = post(&s, "/registrar/records", json!({ "record": b64(&revoke) })).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["successor"], new.fingerprint().to_string());
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert_eq!(found["fingerprint"], new_fp);
    assert_eq!(found["successor"], next.fingerprint().to_string());
    let err = hxd::registrar::publish(&s.config, &old_fp, &new_fp).unwrap_err();
    assert!(err.contains("no rotation pending"), "{err}");
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
    bad(
        "host = \"hl.example\"\nenvelopes = true\nenvelope_max = 2048",
        "envelope_max",
    );
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
    let out = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "hlid", "--message-format=json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("cargo build -p hlid");
    assert!(out.status.success(), "cargo build -p hlid failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["target"]["name"] == "hlid")
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .expect("cargo named no hlid executable")
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

#[tokio::test]
async fn hlid_rotate_signs_the_successors_commitment_and_the_successor_is_held_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let bin = hlid_binary();
    let home = dir.path().join("hlid");
    let url = format!("http://{}", s.ng);
    assert!(hlid(&bin, &home, &["init", "--name", "Alice"]).await.0);
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &[
            "register",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--successor-commit",
            "--no-put",
        ],
    )
    .await;
    assert!(ok, "{err}");

    let succ = home.join("successor.key");
    let succ = succ.to_str().unwrap();
    // A next key where a printed step or a key already lives would be
    // written over, so it is refused before anything is made or posted.
    let card = home.join("successor-card.bin");
    let seed = std::fs::read(succ).unwrap();
    let rotate = ["rotate", "--registrar", &url, "--to", succ, "--next-key"];
    for next in [
        card.clone(),
        home.join(".").join("successor-card.bin"),
        PathBuf::from(succ),
        home.join("identity.key"),
    ] {
        let next = next.to_str().unwrap();
        let (ok, _, err) = hlid(&bin, &home, &[&rotate[..], &[next]].concat()).await;
        assert!(!ok, "{next}");
        assert!(err.contains("--next-key"), "{err}");
    }
    assert!(!card.exists());
    let old = IdentityKey::from_seed(&hex32(&home.join("identity.key")));
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert_eq!(found["fingerprint"], old.fingerprint().to_string());
    // Nor does `hlid card` write over a key.
    let card_over = ["card", "--identity", succ, "--name", "A", "-o", succ];
    assert!(!hlid(&bin, &home, &card_over).await.0);
    assert_eq!(std::fs::read(succ).unwrap(), seed);

    let (ok, out, err) = hlid(&bin, &home, &["rotate", "--registrar", &url, "--to", succ]).await;
    assert!(ok, "{err}");
    assert!(out.contains("rotate published"), "{out}");
    let new = IdentityKey::from_seed(&hex32(Path::new(succ)));
    let signed_next = records_of(&s, &new)
        .await
        .iter()
        .find_map(|r| match r {
            Record::Rotate(r) => Some(r.next),
            _ => None,
        })
        .expect("a rotation under the successor");
    assert!(signed_next.is_some(), "the rotation carries no next");
    let next_key = home.join("successor.next.key");
    let next = IdentityKey::from_seed(&hex32(&next_key));
    assert_eq!(signed_next, Some(commitment(&next)));
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert_eq!(found["fingerprint"], new.fingerprint().to_string());
    assert_eq!(found["successor"], next.fingerprint().to_string());

    // A thief holding the successor's key alone rotates it nowhere else.
    let other = dir.path().join("other.key");
    let other = other.to_str().unwrap();
    assert!(hlid(&bin, &home, &["keygen", "identity", other]).await.0);
    let rotate = ["rotate", "--registrar", &url, "--identity", succ, "--to"];
    let (ok, _, err) = hlid(&bin, &home, &[&rotate[..], &[other]].concat()).await;
    assert!(!ok);
    assert!(err.contains("successor_mismatch"), "{err}");
    let next_key = next_key.to_str().unwrap();
    let (ok, out, err) = hlid(&bin, &home, &[&rotate[..], &[next_key]].concat()).await;
    assert!(ok, "{err}");
    assert!(out.contains("rotate published"), "{out}");
}

/// `-o` may be a pipe (`-o /dev/stdout | base64`), which the check for a
/// key already there must not open for reading.
#[cfg(unix)]
#[test]
fn hlid_card_writes_to_a_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let bin = hlid_binary();
    let home = dir.path().join("hlid");
    let hlid = || {
        let mut c = std::process::Command::new(&bin);
        c.env("HLID_HOME", &home);
        c
    };
    let init = hlid().args(["init", "--name", "Alice"]).status();
    assert!(init.unwrap().success());
    let fifo = dir.path().join("out");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    assert!(made.unwrap().success());
    let drain = std::thread::spawn({
        let fifo = fifo.clone();
        move || std::fs::read(fifo).unwrap()
    });
    let mut child = hlid()
        .args(["card", "--name", "Alice", "-o"])
        .arg(&fifo)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let Some(status) = child.try_wait().unwrap() else {
        child.kill().unwrap();
        // A writer lets the reader's open return, so the test ends.
        drop(std::fs::OpenOptions::new().write(true).open(&fifo));
        panic!("hlid card -o <pipe> did not finish");
    };
    assert!(status.success());
    Card::parse(&drain.join().unwrap()).unwrap();
}

#[tokio::test]
async fn hlid_rotate_to_a_successor_holding_a_commitment_names_that_one() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "signup = \"open\"").await;
    let bin = hlid_binary();
    let url = format!("http://{}", s.ng);
    let (home, succ_home) = (dir.path().join("hlid"), dir.path().join("successor"));
    let succ = succ_home.join("identity.key");
    let (succ, held) = (succ.to_str().unwrap(), succ_home.join("successor.key"));
    for (home, name, handle, key) in [
        (&succ_home, "Bob", "bobby", None),
        (&home, "Alice", "alice", Some(succ)),
    ] {
        assert!(hlid(&bin, home, &["init", "--name", name]).await.0);
        let mut args = vec!["register", "--registrar", url.as_str(), "--handle", handle];
        args.extend(["--successor-commit", "--no-put"]);
        args.extend(key.iter().flat_map(|k| ["--successor-key", *k]));
        let (ok, _, err) = hlid(&bin, home, &args).await;
        assert!(ok, "{err}");
    }
    let new = IdentityKey::from_seed(&hex32(Path::new(succ)));
    let c = IdentityKey::from_seed(&hex32(&held));

    let rotate = ["rotate", "--registrar", &url, "--to", succ, "--next-key"];
    let fresh = dir.path().join("fresh.key");
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &[&rotate[..], &[fresh.to_str().unwrap()]].concat(),
    )
    .await;
    assert!(!ok);
    assert!(err.contains("successor_mismatch"), "{err}");
    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[&rotate[..], &[held.to_str().unwrap()]].concat(),
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("rotate published"), "{out}");
    let found = get(&s, "/registrar/lookup/alice").await.json();
    assert_eq!(found["fingerprint"], new.fingerprint().to_string());
    assert_eq!(found["successor"], c.fingerprint().to_string());
}

/// How a verifier trusts the registrar.
enum Trust {
    /// On the key in its config.
    Key,
    /// On the key the registrar's discovery document publishes.
    Discovery,
}

/// A server that trusts the registrar `r` and reaches it at `url`,
/// every path inside `dir`.
async fn verifier(
    dir: &Path,
    r: &Server,
    trust: Trust,
    url: &str,
    extra: &str,
) -> (SocketAddr, Arc<hxd_ng_session::IdentityState>) {
    let (ng, identity, _) = verifier_serving(dir, r, trust, url, extra, None).await;
    (ng, identity)
}

/// [`verifier`], serving the classic wire on `classic` too, and its core.
async fn verifier_serving(
    dir: &Path,
    r: &Server,
    trust: Trust,
    url: &str,
    extra: &str,
    classic: Option<tokio::net::TcpListener>,
) -> (
    SocketAddr,
    Arc<hxd_ng_session::IdentityState>,
    Arc<hxd_core::Core>,
) {
    let d = dir.display();
    let trust = match trust {
        Trust::Key => format!(
            "[identity.registrar_keys]\n\"{HOST}\" = \"{}\"\n",
            b64(&r.registrar.public_key())
        ),
        Trust::Discovery => String::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = listener.local_addr().unwrap();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [inbox]\ndb = \"{d}/server.db\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [identity]\nkey = \"{d}/server.key\"\nsuccessors = \"{d}/successors\"\nenroll = false\n\
         hosts = [\"{ng}\"]\n\
         revocation_max_age = 1\ntrusted_registrars = [\"{HOST}\"]\n{extra}\n\
         {trust}\
         [identity.registrar_urls]\n\"{HOST}\" = \"{url}\"\n"
    );
    let config_path = dir.join("hxd-ng.toml");
    std::fs::write(&config_path, &text).unwrap();
    let config = hxd::Config::load(&config_path).unwrap();
    hxd::check_config(&config).unwrap();
    let push = hxd::push::build(&config).unwrap();
    let mut ctx = hxd::build_ctx(&config, None, None, push.as_ref(), None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, push.as_ref())
        .unwrap()
        .unwrap();
    let identity = ng_ctx.identity.clone().unwrap();
    let core = ng_ctx.core.clone();
    if let Some(classic) = classic {
        ctx.device_proof = hxd::device::prover(Some(&ng_ctx));
        tokio::spawn(hxd_session::serve(classic, ctx));
    }
    tokio::spawn(hxd_ng_session::serve(listener, ng_ctx));
    (ng, identity, core)
}

/// `/identity/auth` at `at` as `dev` of `id`, showing `card`.
async fn auth_at(at: SocketAddr, id: &IdentityKey, dev: &DeviceKey, card: &[u8]) -> Reply {
    auth_with(at, id, dev, card, json!({})).await
}

/// [`auth_at`], with `extra`'s fields added to the request.
async fn auth_with(
    at: SocketAddr,
    id: &IdentityKey,
    dev: &DeviceKey,
    card: &[u8],
    extra: Value,
) -> Reply {
    auth_cert(at, dev, card, &cert_in(id, dev, 0), extra).await
}

/// `dev`'s certificate from `id`, issued in device epoch `epoch`.
fn cert_in(id: &IdentityKey, dev: &DeviceKey, epoch: u64) -> Vec<u8> {
    let mut cert = DeviceCert::for_device(id, dev, now() - 5, cert::RECOMMENDED_LIFETIME).unwrap();
    cert.epoch = epoch;
    cert.sign(id)
}

/// [`auth_with`], showing `cert`.
async fn auth_cert(
    at: SocketAddr,
    dev: &DeviceKey,
    card: &[u8],
    cert: &[u8],
    extra: Value,
) -> Reply {
    let json_post = |path: &'static str, body: Value| async move {
        http_as(
            at,
            &at.to_string(),
            "POST",
            path,
            &[("Content-Type", "application/json")],
            body.to_string().as_bytes(),
        )
        .await
    };
    let ch = json_post("/identity/challenge", Value::Null).await.json();
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let proof = LoginProof::sign(dev, &challenge, &s_key(&ch), &at.to_string(), now()).unwrap();
    let mut body = json!({ "card": b64(card), "device_cert": b64(cert), "proof": b64(&proof) });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json_post("/identity/auth", body).await
}

/// `id` registered at `r` as `handle`, and its card carrying the
/// attestation.
async fn attested(r: &Server, id: &IdentityKey, handle: &str) -> Vec<u8> {
    let reply = register(r, request(id, handle), id).await.json();
    let att = unb64(reply["attestation"].as_str().unwrap());
    let att = hl_identity::cbor::decode_canonical(&att).unwrap();
    Card::new(id, handle, now()).sign(id, vec![att]).unwrap()
}

/// [`attested`], for an identity that commits to `next` as its successor
/// on its card, and at the registrar too when `there`.
async fn attested_committing(
    r: &Server,
    id: &IdentityKey,
    handle: &str,
    next: &IdentityKey,
    there: bool,
) -> Vec<u8> {
    let mut req = request(id, handle);
    req.successor = there.then(|| commitment(next));
    let reply = register(r, req, id).await.json();
    let att = unb64(reply["attestation"].as_str().unwrap());
    let att = hl_identity::cbor::decode_canonical(&att).unwrap();
    let mut card = Card::new(id, handle, now());
    card.successor = Some(commitment(next));
    card.sign(id, vec![att]).unwrap()
}

/// `from`'s rotation to `to`, signed by both.
fn rotation(from: &IdentityKey, to: &IdentityKey) -> Vec<u8> {
    Rotation {
        identity: from.public(),
        successor: to.public(),
        time: now(),
        next: None,
    }
    .sign(from, to)
    .unwrap()
}

/// A list fetched is current for `revocation_max_age`, a second here.
async fn next_list() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

#[tokio::test]
async fn a_verifying_server_applies_what_the_registrar_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let v = verifier(&there, &r, Trust::Key, &format!("http://{}", r.ng), "")
        .await
        .0;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    let fp = alice.fingerprint().to_string();
    let refused = |reply: &Reply| (reply.status, reply.json()["error"].clone());

    let ok = auth_at(v, &alice, &phone, &card).await;
    assert_eq!(ok.status, 200, "{}", String::from_utf8_lossy(&ok.body));
    assert_eq!(ok.json()["handle"], "alice@127.0.0.1");

    // A device revoked at the registrar is refused here; her others not.
    let revocation = hl_identity::DeviceRevocation {
        identity: alice.public(),
        device: phone.public(),
        time: now(),
        until: now() + 3600,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&alice)
    .unwrap();
    let posted = post(
        &r,
        "/registrar/records",
        json!({ "record": b64(&revocation) }),
    )
    .await;
    assert_eq!(
        posted.status,
        200,
        "{}",
        String::from_utf8_lossy(&posted.body)
    );
    next_list().await;
    assert_eq!(
        refused(&auth_at(v, &alice, &phone, &card).await),
        (403, json!("revoked"))
    );
    assert_eq!(auth_at(v, &alice, &laptop, &card).await.status, 200);

    // Frozen, she is denied; lifted, she is back.
    hxd::registrar::freeze(&r.config, &fp, false).unwrap();
    next_list().await;
    assert_eq!(
        refused(&auth_at(v, &alice, &laptop, &card).await),
        (403, json!("denied"))
    );
    hxd::registrar::freeze(&r.config, &fp, true).unwrap();
    next_list().await;
    assert_eq!(auth_at(v, &alice, &laptop, &card).await.status, 200);

    // Her handle revoked, the attestation on her card counts for nothing.
    hxd::registrar::revoke(&r.config, "alice", "abuse").unwrap();
    next_list().await;
    let unattested = auth_at(v, &alice, &laptop, &card).await.json();
    assert_eq!(unattested["handle"], Value::Null, "{unattested}");
    assert_eq!(unattested["outcome"], "unattested_guest");

    // And revoked outright, she is refused.
    let gone = hl_identity::IdentityRevocation {
        identity: alice.public(),
        time: now(),
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    let posted = post(&r, "/registrar/records", json!({ "record": b64(&gone) })).await;
    assert_eq!(posted.status, 200);
    next_list().await;
    assert_eq!(
        refused(&auth_at(v, &alice, &laptop, &card).await),
        (403, json!("revoked"))
    );
}

#[tokio::test]
async fn records_are_kept_for_when_the_registrar_cannot_be_reached() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let alice = IdentityKey::from_seed(&[1; 32]);
    let bob = IdentityKey::from_seed(&[2; 32]);
    let dev = DeviceKey::from_seed(&[101; 32]);
    let (alice_card, bob_card) = (
        attested(&r, &alice, "alice").await,
        attested(&r, &bob, "bobby").await,
    );
    let gone = hl_identity::IdentityRevocation {
        identity: alice.public(),
        time: now(),
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    assert_eq!(
        post(&r, "/registrar/records", json!({ "record": b64(&gone) }))
            .await
            .status,
        200
    );

    // Trusted on its discovery document: the key, and the lists, fetched.
    let live = format!("http://{}", r.ng);
    let v = verifier(&there, &r, Trust::Discovery, &live, "").await.0;
    assert_eq!(auth_at(v, &alice, &dev, &alice_card).await.status, 403);
    assert_eq!(
        auth_at(v, &bob, &dev, &bob_card).await.json()["handle"],
        "bobby@127.0.0.1"
    );

    // A server on the same database whose registrar does not answer still
    // has the lists, past their lifetime, and the keys they verified
    // under, and by default uses both.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nowhere = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    next_list().await;
    let cached = verifier(
        &there,
        &r,
        Trust::Discovery,
        &nowhere,
        "registrar_timeout = 1",
    )
    .await
    .0;
    let reply = auth_at(cached, &alice, &dev, &alice_card).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("revoked"))
    );
    let reply = auth_at(cached, &bob, &dev, &bob_card).await.json();
    assert_eq!(reply["handle"], "bobby@127.0.0.1", "{reply}");

    // Configured to take a registrar it cannot reach as no registrar, it
    // admits the identity without its handle, and still applies the
    // revocation it holds.
    let guest = verifier(
        &there,
        &r,
        Trust::Discovery,
        &nowhere,
        "registrar_timeout = 1\nrevocation_stale = \"guest\"",
    )
    .await
    .0;
    let reply = auth_at(guest, &alice, &dev, &alice_card).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("revoked"))
    );
    let reply = auth_at(guest, &bob, &dev, &bob_card).await;
    assert_eq!(
        (reply.status, reply.json()["handle"].clone()),
        (200, Value::Null)
    );

    // Configured to refuse what it cannot check, it refuses a stranger to
    // the cache.
    let carol = IdentityKey::from_seed(&[3; 32]);
    let carol_card = attested(&r, &carol, "carol").await;
    let strict = verifier(
        &there,
        &r,
        Trust::Key,
        &nowhere,
        "registrar_timeout = 1\nrevocation_stale = \"deny\"",
    )
    .await
    .0;
    let reply = auth_at(strict, &carol, &dev, &carol_card).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("denied"))
    );

    // An identity whose list is held is no stranger to it, though its
    // card drops the attestation.
    let bare = Card::new(&bob, "bobby", now()).sign(&bob, vec![]).unwrap();
    let own = DeviceKey::from_seed(&[102; 32]);
    let reply = auth_at(strict, &bob, &own, &bare).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("denied"))
    );
}

/// A registrar with open signup, in `dir`.
async fn open_registrar(dir: &Path) -> Server {
    let at = dir.join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    start(&at, "signup = \"open\"").await
}

/// A server trusting `r` and reaching it at `url`, on both wires, whose
/// accounts `alice` and `bob` are linked to those identities, seeds 1
/// and 2, with `extra` after its `[identity]` keys: the ng port, the
/// classic port, the identity state and the core.
async fn linked_verifier(
    dir: &Path,
    r: &Server,
    trust: Trust,
    url: &str,
    extra: &str,
) -> (
    SocketAddr,
    SocketAddr,
    Arc<hxd_ng_session::IdentityState>,
    Arc<hxd_core::Core>,
) {
    let accounts = dir.join("verifier/accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, seed) in [("alice", 1), ("bob", 2)] {
        let fp = IdentityKey::from_seed(&[seed; 32]).fingerprint();
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[identity]\nfingerprint = \"{fp}\"\n"),
        )
        .unwrap();
    }
    let classic = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain = classic.local_addr().unwrap();
    let (ng, identity, core) = verifier_serving(
        &dir.join("verifier"),
        r,
        trust,
        url,
        &format!("classic_hosts = [\"{plain}\"]\n{extra}"),
        Some(classic),
    )
    .await;
    (ng, plain, identity, core)
}

/// Alice's phone, seed 101, admitted on her attested card at a fresh
/// linked verifier, so that her list is held there, and then revoked at
/// her registrar: the registrar, the ng port, the classic port and the
/// card.
async fn phone_revoked(dir: &Path) -> (Server, SocketAddr, SocketAddr, Vec<u8>) {
    let r = open_registrar(dir).await;
    let (v, plain, _, _) =
        linked_verifier(dir, &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let (alice, phone) = (
        IdentityKey::from_seed(&[1; 32]),
        DeviceKey::from_seed(&[101; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    assert_eq!(
        auth_at(v, &alice, &phone, &card).await.json()["outcome"],
        "linked"
    );
    revoke_device(&r, &alice, &phone).await;
    (r, v, plain, card)
}

/// `device` of `id` revoked at `r`, and the verifier's list due again.
async fn revoke_device(r: &Server, id: &IdentityKey, device: &DeviceKey) {
    post_device_revocation(r, id, device).await;
    next_list().await;
}

/// `device` of `id` revoked at `r`.
async fn post_device_revocation(r: &Server, id: &IdentityKey, device: &DeviceKey) {
    let revocation = hl_identity::DeviceRevocation {
        identity: id.public(),
        device: device.public(),
        time: now(),
        until: now() + 3600,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(id)
    .unwrap();
    let posted = post(
        r,
        "/registrar/records",
        json!({ "record": b64(&revocation) }),
    )
    .await;
    assert_eq!(posted.status, 200);
}

/// `id`'s card with no attestation, from before its attested one: a
/// thief's, as cards are public.
fn bare(id: &IdentityKey) -> Vec<u8> {
    Card::new(id, "old", now() - 60).sign(id, vec![]).unwrap()
}

/// [`bare`], attested at the registrar under a key it no longer
/// publishes.
fn retired(id: &IdentityKey) -> Vec<u8> {
    let key = hl_identity::ServerKey::from_seed(&[9; 32]);
    let att = Attestation {
        identity: id.public(),
        registrar: HOST.into(),
        registrar_key: key.public(),
        handle: "old".into(),
        registered: now() - 120,
        issued: now() - 120,
        expires: now() + 3600,
        level: None,
    };
    Card::new(id, "old", now() - 60)
        .sign(id, vec![att.signed_value(&key)])
        .unwrap()
}

/// Prove Device at `plain` logged in as `account`, `dev` of `id` showing
/// `card`: `Ok`, or the refusal's text.
async fn prove_at(
    plain: SocketAddr,
    account: &str,
    id: &IdentityKey,
    dev: &DeviceKey,
    card: &[u8],
) -> Result<(), String> {
    prove_in(plain, account, id, dev, 0, card).await.1
}

/// [`prove_at`], with a certificate issued in device epoch `epoch`, and
/// the connection it was proved on.
async fn prove_in(
    plain: SocketAddr,
    account: &str,
    id: &IdentityKey,
    dev: &DeviceKey,
    epoch: u64,
    card: &[u8],
) -> (Client, Result<(), String>) {
    let login = Login {
        caps: Some(CAP_DEVICE_PROOF as u32),
        ..Login::account(account, account, "pw")
    };
    let mut c = Client::connect(plain).await.unwrap();
    c.login_unannounced(&login).await.unwrap();
    let host = plain.to_string();
    let reply = c
        .ask(ClientHdr::GetDeviceChallenge, &get_device_challenge(&host))
        .await
        .unwrap();
    let ch = ServerChallenge::parse_trtp(&reply.bytes(tag::SERVER_CHALLENGE).unwrap()).unwrap();
    let proof = DeviceProof::sign(dev, &ch.challenge, &ch.server_key, &host, now(), None).unwrap();
    let cert = cert_in(id, dev, epoch);
    let reply = c
        .ask(
            ClientHdr::ProveDevice,
            &prove_device(&proof, &cert, Some(card)),
        )
        .await
        .unwrap();
    let proved = match reply.is_error() {
        true => Err(reply.error_text().unwrap()),
        false => Ok(()),
    };
    (c, proved)
}

#[tokio::test]
async fn a_linked_identitys_bare_card_is_held_to_its_registrars_records_on_ng() {
    let (alice, bob) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    let linked = |reply: Reply| (reply.status, reply.json()["outcome"].clone());

    // Her phone revoked at her registrar, a card naming none, or naming
    // a key it no longer publishes, is no way around it.
    for old in [bare(&alice), retired(&alice)] {
        let dir = tempfile::tempdir().unwrap();
        let (_r, v, _, _) = phone_revoked(dir.path()).await;
        let reply = auth_at(v, &alice, &phone, &old).await;
        assert_eq!(
            (reply.status, reply.json()["error"].clone()),
            (403, json!("revoked"))
        );
    }

    // Her laptop is still let in, with either card.
    let dir = tempfile::tempdir().unwrap();
    let (_r, v, _, card) = phone_revoked(dir.path()).await;
    for card in [bare(&alice), card] {
        assert_eq!(
            linked(auth_at(v, &alice, &laptop, &card).await),
            (200, json!("linked"))
        );
    }

    // Linked by hand, never attested: nothing to ask, and let in.
    assert_eq!(
        linked(auth_at(v, &bob, &phone, &bare(&bob)).await),
        (200, json!("linked"))
    );
}

#[tokio::test]
async fn a_linked_identitys_bare_card_is_held_to_its_registrars_records_on_classic() {
    let (alice, bob) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    for old in [bare(&alice), retired(&alice)] {
        let dir = tempfile::tempdir().unwrap();
        let (_r, _, plain, _) = phone_revoked(dir.path()).await;
        assert_eq!(
            prove_at(plain, "alice", &alice, &phone, &old).await,
            Err("The device could not be proved.".into())
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let (_r, _, plain, card) = phone_revoked(dir.path()).await;
    for card in [bare(&alice), card] {
        prove_at(plain, "alice", &alice, &laptop, &card)
            .await
            .unwrap();
    }
    prove_at(plain, "bob", &bob, &phone, &bare(&bob))
        .await
        .unwrap();
}

/// Carries every connection to `listener` on to `to`, but answers a
/// request for the discovery document 503 while `down` is set, counting
/// each in `refused`.
fn without_discovery(
    listener: tokio::net::TcpListener,
    to: SocketAddr,
    down: Arc<AtomicBool>,
    refused: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        loop {
            let (mut a, _) = listener.accept().await.unwrap();
            let (down, refused) = (down.clone(), refused.clone());
            tokio::spawn(async move {
                // The request line whole, however the reads split it.
                let (mut head, mut buf) = (Vec::new(), [0; 1024]);
                while !head.windows(2).any(|w| w == b"\r\n") && head.len() < 4096 {
                    match a.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                if down.load(Ordering::SeqCst) && head.starts_with(b"GET /.well-known/") {
                    refused.fetch_add(1, Ordering::SeqCst);
                    let _ = a
                        .write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    return;
                }
                let mut b = TcpStream::connect(to).await.unwrap();
                b.write_all(&head).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
            });
        }
    });
}

#[tokio::test]
async fn a_held_list_is_fetched_for_a_retired_key_while_discovery_fails() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let (down, refused) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
    );
    without_discovery(proxy, r.ng, down.clone(), refused.clone());
    let (v, _, identity, _) = linked_verifier(dir.path(), &r, Trust::Discovery, &url, "").await;
    let (alice, phone) = (
        IdentityKey::from_seed(&[1; 32]),
        DeviceKey::from_seed(&[101; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    assert_eq!(
        auth_at(v, &alice, &phone, &card).await.json()["outcome"],
        "linked"
    );

    // Her registrar's discovery document fails while its records still
    // serve, and what the verifier read of it is past the minute after
    // which a key it does not know sends it to ask again.
    down.store(true, Ordering::SeqCst);
    identity.clock().advance(Duration::from_secs(61));
    revoke_device(&r, &alice, &phone).await;
    let reply = auth_at(v, &alice, &phone, &retired(&alice)).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("revoked"))
    );
    assert!(
        refused.load(Ordering::SeqCst) > 0,
        "discovery was asked for"
    );
}

/// An ng session at `at` for `id`'s device, logged in with the token its
/// `/identity/auth` gave.
async fn session_at(at: SocketAddr, id: &IdentityKey, card: &[u8]) -> hxd_testclient::ng::Client {
    session_as(at, id, &DeviceKey::from_seed(&[101; 32]), card).await
}

/// [`session_at`], as `dev`.
async fn session_as(
    at: SocketAddr,
    id: &IdentityKey,
    dev: &DeviceKey,
    card: &[u8],
) -> hxd_testclient::ng::Client {
    session_in(at, dev, &cert_in(id, dev, 0), card, json!({})).await
}

/// [`session_as`], showing `cert` and logging in with `params`.
async fn session_in(
    at: SocketAddr,
    dev: &DeviceKey,
    cert: &[u8],
    card: &[u8],
    params: Value,
) -> hxd_testclient::ng::Client {
    let token = auth_cert(at, dev, card, cert, json!({})).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let tcp = TcpStream::connect(at).await.unwrap();
    let url = format!("ws://{at}/ng?token={token}");
    let mut c = hxd_testclient::ng::Client::over(Box::new(tcp), &url)
        .await
        .unwrap();
    c.login(params).await.unwrap();
    c
}

#[tokio::test]
async fn a_key_its_registrar_revokes_loses_its_session_here_and_a_banned_registrar_its_identities()
{
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, identity) = verifier(&there, &r, Trust::Key, &live, "").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let bob = IdentityKey::from_seed(&[2; 32]);
    let dev = DeviceKey::from_seed(&[101; 32]);
    let alice_card = attested(&r, &alice, "alice").await;
    let mut alice_here = session_at(v, &alice, &alice_card).await;
    let mut bob_here = session_at(v, &bob, &attested(&r, &bob, "bobby").await).await;
    let mallory = IdentityKey::from_seed(&[4; 32]);
    let mut mallory_here = session_at(v, &mallory, &attested(&r, &mallory, "mallory").await).await;

    // Nothing against anyone yet: a sweep ends nothing.
    assert!(identity.sweep_records().await.is_empty());

    // Mallory revokes "a device" with the key every session here happens
    // to use. A device revocation is its identity's own: it ends hers and
    // touches nobody else's.
    let theirs = hl_identity::DeviceRevocation {
        identity: mallory.public(),
        device: dev.public(),
        time: now(),
        until: now() + 3600,
        reason: None,
        signer: None,
        signer_cert: None,
    }
    .sign(&mallory)
    .unwrap();
    assert_eq!(
        post(&r, "/registrar/records", json!({ "record": b64(&theirs) }))
            .await
            .status,
        200
    );

    // Alice shows a card that names no registrar, and is then revoked at
    // hers: the sweep asks the registrar that attested her when she was
    // admitted, not the one her card names now.
    let token = auth_at(v, &alice, &dev, &alice_card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let bare = Card::new(&alice, "Alice", now() + 5)
        .sign(&alice, vec![])
        .unwrap();
    let put = http_as(
        v,
        &v.to_string(),
        "PUT",
        "/identity/card",
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/cbor"),
        ],
        &bare,
    )
    .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    let gone = hl_identity::IdentityRevocation {
        identity: alice.public(),
        time: now(),
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    assert_eq!(
        post(&r, "/registrar/records", json!({ "record": b64(&gone) }))
            .await
            .status,
        200
    );
    next_list().await;
    let ended = identity.sweep_records().await;
    assert_eq!(ended.len(), 2, "{ended:?}");
    alice_here.event("kicked").await.unwrap();
    mallory_here.event("kicked").await.unwrap();
    bob_here.request("ping", json!({})).await.unwrap();

    // A registrar banned here refuses every identity it attested.
    let banned = dir.path().join("banning");
    std::fs::create_dir_all(&banned).unwrap();
    let (strict, _) = verifier(
        &banned,
        &r,
        Trust::Key,
        &live,
        "banned_registrars = [\"127.0.0.1\"]",
    )
    .await;
    let card = attested(&r, &IdentityKey::from_seed(&[3; 32]), "carol").await;
    let reply = auth_at(strict, &IdentityKey::from_seed(&[3; 32]), &dev, &card).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("denied"))
    );
}

/// `id` resets its devices to `epoch` at `r`.
async fn post_reset(r: &Server, id: &IdentityKey, epoch: u64) {
    let reset = DeviceEpoch {
        identity: id.public(),
        epoch,
        time: now(),
    }
    .sign(id)
    .unwrap();
    let posted = post(r, "/registrar/records", json!({ "record": b64(&reset) })).await;
    assert_eq!(
        posted.status,
        200,
        "{}",
        String::from_utf8_lossy(&posted.body)
    );
}

/// What `/identity/auth` answered: its status, error and `epoch`.
fn refusal(reply: &Reply) -> (u16, Value, Value) {
    let body = reply.json();
    (reply.status, body["error"].clone(), body["epoch"].clone())
}

#[tokio::test]
async fn a_reset_refuses_the_certificates_below_its_floor_and_admits_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let (v, _, identity, _) =
        linked_verifier(dir.path(), &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let (phone, laptop, tablet) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
        DeviceKey::from_seed(&[103; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    let linked = |reply: Reply| (reply.status, reply.json()["outcome"].clone());

    // No reset: whatever epoch a certificate was issued in, it logs in.
    for (dev, epoch) in [(&phone, 0), (&laptop, 5)] {
        let reply = auth_cert(v, dev, &card, &cert_in(&alice, dev, epoch), json!({})).await;
        assert_eq!(linked(reply), (200, json!("linked")), "epoch {epoch}");
    }
    let token = auth_at(v, &alice, &phone, &card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(identity.identity_for_device(&phone.public()).is_some());
    let upgraded = auth_at(v, &alice, &phone, &card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let tcp = TcpStream::connect(v).await.unwrap();
    let mut upgraded =
        hxd_testclient::ng::Client::over(Box::new(tcp), &format!("ws://{v}/ng?token={upgraded}"))
            .await
            .unwrap();
    let mut current = session_in(v, &laptop, &cert_in(&alice, &laptop, 5), &card, json!({})).await;

    post_reset(&r, &alice, 1).await;
    next_list().await;
    assert!(identity.sweep_records().await.is_empty(), "epoch 5 stays");
    current.request("ping", json!({})).await.unwrap();

    // The phone's token, minted before the reset, no longer redeems, and
    // the phone on file is not let back in by its certificate.
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{v}/ng?token={token}"))
            .await
            .is_err(),
        "the upgrade is refused"
    );
    assert!(identity.identity_for_device(&phone.public()).is_none());
    // A socket that upgraded before the reset logs in no more.
    let login = upgraded.request_frame("login", json!({})).await.unwrap();
    assert_eq!(
        (&login["error"]["code"], &login["error"]["epoch"]),
        (&json!("revoked"), &json!(1)),
        "{login}"
    );

    // At auth it is told the floor; a device certified at it, or above,
    // is let in.
    assert_eq!(
        refusal(&auth_at(v, &alice, &phone, &card).await),
        (403, json!("revoked"), json!(1))
    );
    for (dev, epoch) in [(&tablet, 1), (&laptop, 5)] {
        let reply = auth_cert(v, dev, &card, &cert_in(&alice, dev, epoch), json!({})).await;
        assert_eq!(linked(reply), (200, json!("linked")), "epoch {epoch}");
    }

    // Reset again before the sweep has installed it: told the floor the
    // lists just fetched say, not the one installed.
    post_reset(&r, &alice, 3).await;
    next_list().await;
    assert_eq!(
        refusal(&auth_at(v, &alice, &phone, &card).await),
        (403, json!("revoked"), json!(3))
    );
}

#[tokio::test]
async fn a_reset_ends_the_sessions_below_its_floor_on_both_wires() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let (v, plain, identity, core) =
        linked_verifier(dir.path(), &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let (alice, bob) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let dev = |seed| DeviceKey::from_seed(&[seed; 32]);
    let card = attested(&r, &alice, "alice").await;
    let sealed = json!({ "sealed": true });

    let mut phone = session_in(
        v,
        &dev(101),
        &cert_in(&alice, &dev(101), 0),
        &card,
        sealed.clone(),
    )
    .await;
    let away = session_in(
        v,
        &dev(102),
        &cert_in(&alice, &dev(102), 0),
        &card,
        json!({}),
    )
    .await;
    let session = away.session.clone().unwrap();
    drop(away);
    timeout(Duration::from_secs(5), async {
        while core.census().detached == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the session never detached");
    let (mut classic, proved) = prove_in(plain, "alice", &alice, &dev(103), 0, &card).await;
    proved.unwrap();
    let mut laptop = session_in(
        v,
        &dev(104),
        &cert_in(&alice, &dev(104), 1),
        &card,
        json!({}),
    )
    .await;
    let (mut desktop, proved) = prove_in(plain, "alice", &alice, &dev(105), 1, &card).await;
    proved.unwrap();
    let mut b = session_in(
        v,
        &dev(201),
        &cert_in(&bob, &dev(201), 0),
        &bare(&bob),
        sealed,
    )
    .await;
    let of_phone = json!({ "uid": phone.uid.unwrap() });
    b.request("device_cert", of_phone.clone()).await.unwrap();

    post_reset(&r, &alice, 1).await;
    next_list().await;
    let ended = identity.sweep_records().await;
    assert_eq!(ended.len(), 3, "{ended:?}");
    phone.event("kicked").await.unwrap();
    let closed = loop {
        if let Err(e) = classic.recv().await {
            break e;
        }
    };
    assert!(
        matches!(closed, hxd_testclient::Error::Closed),
        "{closed:?}"
    );
    assert!(
        b.request("device_cert", of_phone).await.is_err(),
        "the phone's ended session is sealed to no more"
    );
    let mut c = hxd_testclient::ng::Client::connect(v).await.unwrap();
    let resumed = c
        .request_frame(
            "resume",
            json!({ "session": session.0, "token": session.1, "last_seq": 0 }),
        )
        .await
        .unwrap();
    assert_eq!(
        (&resumed["error"]["code"], &resumed["error"]["epoch"]),
        (&json!("revoked"), &json!(1)),
        "{resumed}"
    );

    // The devices certified at the floor stay, and a device below it is
    // refused Prove Device as any device is.
    laptop.request("ping", json!({})).await.unwrap();
    desktop.ping().await.unwrap();
    assert_eq!(
        prove_in(plain, "alice", &alice, &dev(106), 0, &card)
            .await
            .1,
        Err("The device could not be proved.".into())
    );
    prove_in(plain, "alice", &alice, &dev(106), 1, &card)
        .await
        .1
        .unwrap();
}

#[tokio::test]
async fn a_reset_held_is_applied_while_its_registrar_cannot_be_reached() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let alice = IdentityKey::from_seed(&[1; 32]);
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    post_reset(&r, &alice, 1).await;
    let v = verifier(&there, &r, Trust::Key, &format!("http://{}", r.ng), "")
        .await
        .0;
    assert_eq!(
        refusal(&auth_at(v, &alice, &phone, &card).await),
        (403, json!("revoked"), json!(1))
    );

    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nowhere = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    next_list().await;
    // The floor held is told before what the stale lists' policy says.
    for stale in ["cached", "guest", "deny"] {
        let extra = format!("registrar_timeout = 1\nrevocation_stale = \"{stale}\"");
        let v = verifier(&there, &r, Trust::Key, &nowhere, &extra).await.0;
        assert_eq!(
            refusal(&auth_at(v, &alice, &phone, &card).await),
            (403, json!("revoked"), json!(1)),
            "{stale}"
        );
        if stale == "cached" {
            let reply = auth_cert(v, &laptop, &card, &cert_in(&alice, &laptop, 1), json!({})).await;
            assert_eq!(
                reply.status,
                200,
                "{}",
                String::from_utf8_lossy(&reply.body)
            );
        }
    }
}

#[tokio::test]
async fn a_floor_installed_is_told_whatever_the_lists_held_say() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let to = Arc::new(std::sync::Mutex::new(r.ng));
    forward(proxy, to.clone());
    let (v, _, identity, _) = linked_verifier(
        dir.path(),
        &r,
        Trust::Key,
        &url,
        "revocation_stale = \"deny\"",
    )
    .await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    let mut laptop_here =
        session_in(v, &laptop, &cert_in(&alice, &laptop, 1), &card, json!({})).await;
    post_reset(&r, &alice, 1).await;
    next_list().await;
    assert!(identity.sweep_records().await.is_empty());
    laptop_here.request("ping", json!({})).await.unwrap();

    // Her registrar gone and the lists past their lifetime, a stranger
    // to them would be denied; the floor installed is told as it is.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    *to.lock().unwrap() = closed.local_addr().unwrap();
    drop(closed);
    next_list().await;
    assert_eq!(
        refusal(&auth_at(v, &alice, &phone, &card).await),
        (403, json!("revoked"), json!(1))
    );
}

#[tokio::test]
async fn a_floor_auth_fetches_is_applied_before_any_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let (v, _, _, _) = linked_verifier(
        dir.path(),
        &r,
        Trust::Key,
        &format!("http://{}", r.ng),
        "banned_registrars = [\"banned.example\"]",
    )
    .await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let dev = |seed| DeviceKey::from_seed(&[seed; 32]);
    let (phone, tablet, watch) = (dev(101), dev(103), dev(104));
    let reply = register(&r, request(&alice, "alice"), &alice).await.json();
    let att = unb64(reply["attestation"].as_str().unwrap());
    let att = hl_identity::cbor::decode_canonical(&att).unwrap();
    let card = Card::new(&alice, "alice", now())
        .sign(&alice, vec![att.clone()])
        .unwrap();
    let token = auth_at(v, &alice, &phone, &card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    // Her card beside an attestation from a registrar banned here, which
    // policy would refuse `denied`.
    let key = hl_identity::ServerKey::from_seed(&[9; 32]);
    let other = Attestation {
        identity: alice.public(),
        registrar: "banned.example".into(),
        registrar_key: key.public(),
        handle: "alice".into(),
        registered: now() - 120,
        issued: now() - 120,
        expires: now() + 3600,
        level: None,
    };
    let banned = Card::new(&alice, "alice", now())
        .sign(&alice, vec![att, other.signed_value(&key)])
        .unwrap();

    let mut desk = session_in(
        v,
        &dev(102),
        &cert_in(&alice, &dev(102), 0),
        &card,
        json!({}),
    )
    .await;

    // The first auth to fetch the reset is of a device the lists revoke
    // too: told so, not denied, and the floor it fetched goes into force
    // at once, for the other devices' tokens and sessions.
    post_reset(&r, &alice, 1).await;
    post_device_revocation(&r, &alice, &tablet).await;
    next_list().await;
    assert_eq!(
        refusal(&auth_at(v, &alice, &tablet, &banned).await),
        (403, json!("revoked"), Value::Null)
    );
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{v}/ng?token={token}"))
            .await
            .is_err(),
        "a token below the floor that auth fetched no longer redeems"
    );
    desk.event("kicked").await.unwrap();
    assert_eq!(
        refusal(&auth_at(v, &alice, &watch, &banned).await),
        (403, json!("revoked"), json!(1))
    );
}

#[tokio::test]
async fn a_token_below_a_floor_fetched_at_auth_does_not_outlive_the_next_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let (v, _, identity, _) =
        linked_verifier(dir.path(), &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let (phone, tablet) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[103; 32]),
    );
    let card = attested(&r, &alice, "alice").await;
    let token = auth_at(v, &alice, &phone, &card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    post_reset(&r, &alice, 1).await;
    next_list().await;
    assert_eq!(
        refusal(&auth_at(v, &alice, &tablet, &card).await),
        (403, json!("revoked"), json!(1))
    );
    // With no session of hers to keep it, the sweep installs lists that
    // say nothing of her.
    identity.sweep_records().await;
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{v}/ng?token={token}"))
            .await
            .is_err(),
        "the token went with the floor's fetch"
    );
}

#[tokio::test]
async fn a_floor_fetched_beside_a_revoked_device_is_installed_and_spares_one_renewed() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let (v, _, identity, core) =
        linked_verifier(dir.path(), &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let dev = |seed| DeviceKey::from_seed(&[seed; 32]);
    let (phone, tablet, laptop) = (dev(101), dev(103), dev(102));
    let card = attested(&r, &alice, "alice").await;
    let token = auth_at(v, &alice, &phone, &card).await.json()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    core.set_revocations(hxd_core::Revocations {
        devices: [hl_identity::Fingerprint::of(&tablet.public()).0].into(),
        ..Default::default()
    });
    post_reset(&r, &alice, 1).await;
    next_list().await;

    // A device revoked here is told so, and the floor its auth fetched
    // still goes into force.
    assert_eq!(
        refusal(&auth_at(v, &alice, &tablet, &card).await),
        (403, json!("revoked"), Value::Null)
    );
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{v}/ng?token={token}"))
            .await
            .is_err(),
        "a token below the floor no longer redeems"
    );

    // Another identity's certificate for the same key, on file, is not
    // hers to forget.
    let bob = IdentityKey::from_seed(&[2; 32]);
    let shared = dev(105);
    assert_eq!(auth_at(v, &bob, &shared, &bare(&bob)).await.status, 200);
    assert_eq!(
        refusal(&auth_at(v, &alice, &shared, &card).await),
        (403, json!("revoked"), json!(1))
    );
    let on_file = identity.identity_for_device(&shared.public()).unwrap();
    assert_eq!(on_file.identity, bob.public());

    // A device renewed at the floor keeps its place on file when its old
    // certificate is refused.
    let renewed = auth_cert(v, &laptop, &card, &cert_in(&alice, &laptop, 1), json!({})).await;
    assert_eq!(renewed.status, 200);
    assert_eq!(
        refusal(&auth_at(v, &alice, &laptop, &card).await),
        (403, json!("revoked"), json!(1))
    );
    assert!(identity.identity_for_device(&laptop.public()).is_some());
}

#[tokio::test]
async fn a_rotation_listed_beside_a_floor_is_told_as_a_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let r = open_registrar(dir.path()).await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let (old, new) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let mut req = request(&old, "alice");
    req.successor = Some(commitment(&new));
    let reply = register(&r, req, &old).await.json();
    let att = unb64(reply["attestation"].as_str().unwrap());
    let att = hl_identity::cbor::decode_canonical(&att).unwrap();
    let committing = |atts| {
        let mut card = Card::new(&old, "alice", now());
        card.successor = Some(commitment(&new));
        card.sign(&old, atts).unwrap()
    };
    let card = committing(vec![att.clone()]);
    // Beside an attestation from a registrar banned here.
    let key = hl_identity::ServerKey::from_seed(&[9; 32]);
    let other = Attestation {
        identity: old.public(),
        registrar: "banned.example".into(),
        registrar_key: key.public(),
        handle: "alice".into(),
        registered: now() - 120,
        issued: now() - 120,
        expires: now() + 3600,
        level: None,
    };
    let banned = committing(vec![att, other.signed_value(&key)]);
    post_reset(&r, &old, 1).await;
    let posted = post(
        &r,
        "/registrar/records",
        json!({ "record": b64(&rotation(&old, &new)) }),
    )
    .await;
    assert_eq!(posted.json()["published"], true);
    let v = verifier(
        &there,
        &r,
        Trust::Key,
        &format!("http://{}", r.ng),
        "banned_registrars = [\"banned.example\"]",
    )
    .await
    .0;
    // Refused for the banned registrar, the floor is told first.
    assert_eq!(
        refusal(&auth_at(v, &old, &DeviceKey::from_seed(&[101; 32]), &banned).await),
        (403, json!("revoked"), json!(1))
    );
    let reply = auth_at(v, &old, &DeviceKey::from_seed(&[101; 32]), &card).await;
    assert_eq!(
        (
            reply.status,
            reply.json()["error"].clone(),
            reply.json()["successor"].clone()
        ),
        (403, json!("rotated"), json!(new.fingerprint().to_string()))
    );

    // Lists held past their lifetime, the registrar gone, and the
    // rotation not taken here yet: still a rotation, not `denied`.
    std::fs::remove_file(there.join("successors")).unwrap();
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nowhere = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    next_list().await;
    let extra = "registrar_timeout = 1\nrevocation_stale = \"deny\"";
    let v = verifier(&there, &r, Trust::Key, &nowhere, extra).await.0;
    let reply = auth_at(v, &old, &DeviceKey::from_seed(&[101; 32]), &card).await;
    assert_eq!(
        (
            reply.status,
            reply.json()["error"].clone(),
            reply.json()["successor"].clone()
        ),
        (403, json!("rotated"), json!(new.fingerprint().to_string()))
    );
}

/// Carries every connection to `listener` to wherever `to` says now.
fn forward(listener: tokio::net::TcpListener, to: Arc<std::sync::Mutex<SocketAddr>>) {
    tokio::spawn(async move {
        loop {
            let (mut a, _) = listener.accept().await.unwrap();
            let to = *to.lock().unwrap();
            tokio::spawn(async move {
                // One that cannot be reached is a connection dropped.
                let Ok(mut b) = TcpStream::connect(to).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
            });
        }
    });
}

#[tokio::test]
async fn a_session_its_registrar_freezes_resumes_as_expired_and_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let (v, identity) = verifier(&there, &r, Trust::Key, &format!("http://{}", r.ng), "").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let card = attested(&r, &alice, "alice").await;
    let mut here = session_at(v, &alice, &card).await;
    let session = here.session.clone().unwrap();

    hxd::registrar::freeze(&r.config, &alice.fingerprint().to_string(), false).unwrap();
    next_list().await;
    assert_eq!(identity.sweep_records().await.len(), 1);
    here.event("kicked").await.unwrap();
    // A freeze can be lifted: its resume is not told the key is revoked,
    // and the auth that follows says what it is.
    let mut c = hxd_testclient::ng::Client::connect(v).await.unwrap();
    let resumed = c
        .request(
            "resume",
            json!({ "session": session.0, "token": session.1, "last_seq": 0 }),
        )
        .await;
    assert!(
        matches!(&resumed, Err(hxd_testclient::Error::Refused { code, .. }) if code == "session_expired"),
        "{resumed:?}"
    );
    let reply = auth_at(v, &alice, &DeviceKey::from_seed(&[101; 32]), &card).await;
    assert_eq!(
        (reply.status, reply.json()["error"].clone()),
        (403, json!("denied"))
    );
}

#[tokio::test]
async fn a_key_admitted_while_its_registrar_was_down_is_still_swept() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let alice = IdentityKey::from_seed(&[1; 32]);
    let card = attested(&r, &alice, "alice").await;

    // Admitted on nothing held: the registrar does not answer.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let (v, identity) = verifier(
        &there,
        &r,
        Trust::Key,
        &format!("http://{addr}"),
        "registrar_timeout = 1",
    )
    .await;
    let mut alice_here = session_at(v, &alice, &card).await;

    // It answers again, and she is revoked there.
    forward(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        Arc::new(std::sync::Mutex::new(r.ng)),
    );
    let gone = hl_identity::IdentityRevocation {
        identity: alice.public(),
        time: now(),
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    assert_eq!(
        post(&r, "/registrar/records", json!({ "record": b64(&gone) }))
            .await
            .status,
        200
    );
    next_list().await;
    assert_eq!(identity.sweep_records().await.len(), 1);
    alice_here.event("kicked").await.unwrap();
}

/// After a restart, with its registrar out of reach, a trusted list held
/// damaged proves nothing either way: every device of its identity is
/// refused `denied`, whatever `revocation_stale` says, until the list is
/// fetched whole again, at the first login after the registrar answers,
/// or within the minute for one trusted on its discovery document.
#[tokio::test]
async fn a_list_held_damaged_refuses_its_identity_until_it_is_fetched_whole() {
    for discovery in [false, true] {
        let trust = || match discovery {
            false => Trust::Key,
            true => Trust::Discovery,
        };
        let dir = tempfile::tempdir().unwrap();
        let r = open_registrar(dir.path()).await;
        let there = dir.path().join("verifier");
        std::fs::create_dir_all(&there).unwrap();
        let alice = IdentityKey::from_seed(&[1; 32]);
        let (phone, laptop) = (
            DeviceKey::from_seed(&[101; 32]),
            DeviceKey::from_seed(&[102; 32]),
        );
        let card = attested(&r, &alice, "alice").await;
        let refused = |reply: &Reply| (reply.status, reply.json()["error"].clone());
        let live = format!("http://{}", r.ng);
        let v = verifier(&there, &r, trust(), &live, "").await.0;
        post_device_revocation(&r, &alice, &phone).await;
        assert_eq!(
            refused(&auth_at(v, &alice, &phone, &card).await),
            (403, json!("revoked"))
        );

        let db = rusqlite::Connection::open(there.join("server.db")).unwrap();
        let mut list: Vec<u8> = db
            .query_row("SELECT list FROM identity_records", [], |r| r.get(0))
            .unwrap();
        *list.last_mut().unwrap() ^= 1;
        db.execute("UPDATE identity_records SET list = ?1", [list])
            .unwrap();
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let (restarted, identity) = verifier(
            &there,
            &r,
            trust(),
            &format!("http://{addr}"),
            "registrar_timeout = 1",
        )
        .await;
        for dev in [&phone, &laptop] {
            assert_eq!(
                refused(&auth_at(restarted, &alice, dev, &card).await),
                (403, json!("denied")),
                "discovery: {discovery}"
            );
        }

        forward(
            tokio::net::TcpListener::bind(addr).await.unwrap(),
            Arc::new(std::sync::Mutex::new(r.ng)),
        );
        if discovery {
            identity.clock().advance(Duration::from_secs(60));
        }
        assert_eq!(
            refused(&auth_at(restarted, &alice, &phone, &card).await),
            (403, json!("revoked")),
            "discovery: {discovery}"
        );
        let reply = auth_at(restarted, &alice, &laptop, &card).await;
        assert_eq!(reply.json()["handle"], "alice@127.0.0.1", "{discovery}");
    }
}

/// Alice's account at a linked verifier with push registrations, for the
/// sweep of identities with no session here.
#[cfg(feature = "push")]
struct Away {
    dir: tempfile::TempDir,
    r: Server,
    v: SocketAddr,
    identity: Arc<hxd_ng_session::IdentityState>,
    core: Arc<hxd_core::Core>,
    alice: IdentityKey,
    card: Vec<u8>,
    /// The verifier reaches the registrar only while this is false.
    down: Arc<AtomicBool>,
}

#[cfg(feature = "push")]
impl Away {
    async fn start() -> Away {
        let dir = tempfile::tempdir().unwrap();
        let r = open_registrar(dir.path()).await;
        let push = format!(
            "[push]\ncontact = \"mailto:a@example.org\"\nvapid_key = \"{}\"",
            dir.path().join("vapid.key").display()
        );
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", proxy.local_addr().unwrap());
        let down = Arc::new(AtomicBool::new(false));
        let (to, cut) = (r.ng, down.clone());
        tokio::spawn(async move {
            loop {
                let (mut a, _) = proxy.accept().await.unwrap();
                if cut.load(Ordering::SeqCst) {
                    continue;
                }
                tokio::spawn(async move {
                    let mut b = TcpStream::connect(to).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                });
            }
        });
        let (v, _, identity, core) = linked_verifier(dir.path(), &r, Trust::Key, &url, &push).await;
        let alice = IdentityKey::from_seed(&[1; 32]);
        let card = attested(&r, &alice, "alice").await;
        Away {
            dir,
            r,
            v,
            identity,
            core,
            alice,
            card,
            down,
        }
    }

    /// `dev` logs in, registers for push and logs out.
    async fn register(&self, dev: &DeviceKey) {
        let mut c = session_as(self.v, &self.alice, dev, &self.card).await;
        let subscription = json!({
            "endpoint": format!("https://push.example.net/v/{}", devid(dev)),
            "p256dh": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
            "auth": "BTBZMqHH6r4Tts7J_aSIgg",
        });
        c.request("push_register", subscription).await.unwrap();
        c.request("logout", json!({})).await.unwrap();
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.path().join("verifier/server.db")).unwrap()
    }

    /// The devids of the rows the store holds.
    fn rows(&self) -> Vec<String> {
        let db = self.db();
        let mut rows = db
            .prepare("SELECT devid FROM push_device ORDER BY devid")
            .unwrap();
        let devids = rows.query_map([], |r| r.get(0)).unwrap();
        devids.map(Result::unwrap).collect()
    }

    /// The devids of the rows a gateway is handed to deliver to.
    fn delivered(&self) -> Vec<String> {
        let mailbox = hxd_core::inbox::Mailbox::identified("alice", self.alice.fingerprint().0);
        let store = self.core.push_store().unwrap();
        let mut ids: Vec<String> = store
            .devices(&mailbox, std::time::SystemTime::now())
            .unwrap()
            .into_iter()
            .map(|d| d.devid.as_str().to_owned())
            .collect();
        ids.sort();
        ids
    }

    /// The store's deletes fail until [`Self::release`].
    fn hold(&self) {
        self.db()
            .execute_batch(
                "CREATE TRIGGER held BEFORE DELETE ON push_device \
                 BEGIN SELECT RAISE(ABORT, 'held'); END",
            )
            .unwrap();
    }

    fn release(&self) {
        self.db().execute_batch("DROP TRIGGER held").unwrap();
    }
}

/// The id a device's push registration is filed under.
#[cfg(feature = "push")]
fn devid(dev: &DeviceKey) -> String {
    hxd_core::push::DeviceId::of_device(&hl_identity::Fingerprint::of(&dev.public()).0)
        .as_str()
        .to_owned()
}

/// A device revoked at its registrar while its identity has no session
/// here loses its push registration: once the identity's lists are next
/// refreshed, which for one away is every ten minutes, and hidden while
/// a delete the store failed waits, between those refreshes too.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_device_revoked_while_its_identity_is_away_loses_its_push_registration() {
    let a = Away::start().await;
    let (r, alice, identity) = (&a.r, &a.alice, &a.identity);
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    a.register(&phone).await;
    a.register(&laptop).await;
    let mut both = vec![devid(&phone), devid(&laptop)];
    both.sort();
    assert_eq!(a.rows(), both);
    let clock = identity.clock();
    // Seen away: what is held is read, and the first refresh is within
    // the ten minutes.
    identity.sweep_records().await;

    // The phone is revoked, and the store fails its delete.
    post_device_revocation(r, alice, &phone).await;
    a.hold();
    clock.advance(Duration::from_secs(602));
    identity.sweep_records().await;
    assert_eq!(a.rows(), both, "the delete failed");
    assert_eq!(a.delivered(), [devid(&laptop)], "and the row is hidden");
    // A sweep that refreshes nothing of hers keeps it hidden.
    clock.advance(Duration::from_secs(2));
    identity.sweep_records().await;
    assert_eq!(a.delivered(), [devid(&laptop)], "still hidden");
    a.release();
    identity.sweep_records().await;
    assert_eq!(a.rows(), [devid(&laptop)], "the phone's registration went");
    // A row of the phone's written since, as a claim of a login's rows
    // can, is hidden by what was last found against her alone.
    let phones = format!(
        "INSERT INTO push_device (owner, owner_fp, devid, endpoint, p256dh, auth, \
         registered_at) VALUES ('alice', '{}', '{}', 'https://push.example.net/v/again', \
         zeroblob(65), zeroblob(16), 1)",
        hxd_core::push::DeviceId::of_device(&alice.fingerprint().0).as_str(),
        devid(&phone)
    );
    a.db().execute_batch(&phones).unwrap();
    identity.sweep_records().await;
    assert_eq!(a.delivered(), [devid(&laptop)], "a row written since");
    a.db()
        .execute_batch(&format!(
            "DELETE FROM push_device WHERE devid = '{}'",
            devid(&phone)
        ))
        .unwrap();

    post_device_revocation(r, alice, &laptop).await;
    clock.advance(Duration::from_secs(2));
    identity.sweep_records().await;
    assert_eq!(a.rows(), [devid(&laptop)], "not refreshed again yet");
    clock.advance(Duration::from_secs(600));
    identity.sweep_records().await;
    assert!(a.rows().is_empty(), "and then refreshed");
}

/// A list read in part says nothing of what it left out: with the
/// registrar out of reach and the list held damaged, what was found
/// before still hides a row the revoked device has again, as a claim of
/// a login's rows can give it, while its identity is here, once it
/// leaves, and when its lists are next refreshed.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_list_read_in_part_keeps_what_was_found_before() {
    let a = Away::start().await;
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    a.register(&phone).await;
    let mut here = session_as(a.v, &a.alice, &laptop, &a.card).await;
    let clock = a.identity.clock();
    post_device_revocation(&a.r, &a.alice, &phone).await;
    clock.advance(Duration::from_secs(2));
    a.identity.sweep_records().await;
    assert!(a.rows().is_empty(), "the phone's registration went");

    a.down.store(true, Ordering::SeqCst);
    let db = a.db();
    let mut list: Vec<u8> = db
        .query_row("SELECT list FROM identity_records", [], |r| r.get(0))
        .unwrap();
    *list.last_mut().unwrap() ^= 1;
    db.execute("UPDATE identity_records SET list = ?1", [list])
        .unwrap();
    let again = format!(
        "INSERT INTO push_device (owner, owner_fp, devid, endpoint, p256dh, auth, \
         registered_at) VALUES ('alice', '{}', '{}', 'https://push.example.net/v/again', \
         zeroblob(65), zeroblob(16), 1)",
        hxd_core::push::DeviceId::of_device(&a.alice.fingerprint().0).as_str(),
        devid(&phone)
    );
    db.execute_batch(&again).unwrap();
    clock.advance(Duration::from_secs(2));
    a.identity.sweep_records().await;
    assert!(a.delivered().is_empty(), "here: still hidden");

    here.request("logout", json!({})).await.unwrap();
    a.identity.sweep_records().await;
    assert!(a.delivered().is_empty(), "seen away: still hidden");
    clock.advance(Duration::from_secs(602));
    a.identity.sweep_records().await;
    assert!(a.delivered().is_empty(), "refreshed: still hidden");
}

/// A refusal outlives its identity's last push registration until a
/// whole read clears it: with the registrar out of reach and the lists
/// held damaged or unreadable, the revoked device is still refused, and
/// so registers nothing.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_refusal_outlives_its_identitys_last_push_registration() {
    for unreadable in [false, true] {
        let a = Away::start().await;
        let (phone, laptop) = (
            DeviceKey::from_seed(&[101; 32]),
            DeviceKey::from_seed(&[102; 32]),
        );
        a.register(&phone).await;
        let mut here = session_as(a.v, &a.alice, &laptop, &a.card).await;
        post_device_revocation(&a.r, &a.alice, &phone).await;
        let clock = a.identity.clock();
        clock.advance(Duration::from_secs(2));
        a.identity.sweep_records().await;
        assert!(a.rows().is_empty(), "the phone's registration went");
        // With it went the last of hers, and she is seen away.
        here.request("logout", json!({})).await.unwrap();
        a.identity.sweep_records().await;

        a.down.store(true, Ordering::SeqCst);
        let db = a.db();
        if unreadable {
            db.execute_batch("ALTER TABLE identity_records RENAME TO elsewhere")
                .unwrap();
        } else {
            let mut list: Vec<u8> = db
                .query_row("SELECT list FROM identity_records", [], |r| r.get(0))
                .unwrap();
            *list.last_mut().unwrap() ^= 1;
            db.execute("UPDATE identity_records SET list = ?1", [list])
                .unwrap();
        }
        clock.advance(Duration::from_secs(2));
        a.identity.sweep_records().await;
        let reply = auth_at(a.v, &a.alice, &phone, &a.card).await;
        assert_eq!(
            (reply.status, reply.json()["error"].clone()),
            (403, json!("revoked")),
            "unreadable: {unreadable}"
        );
    }
}

/// A refusal kept for an identity with no push registration is read
/// again on the same cadence, and a whole read that no longer finds it
/// lets it go: a freeze lifted while its identity was away refuses
/// nothing once the identity's lists are next refreshed.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_refusal_kept_without_push_registrations_is_lifted_by_a_whole_read() {
    let a = Away::start().await;
    let laptop = DeviceKey::from_seed(&[102; 32]);
    let fp = a.alice.fingerprint();
    let laptop_cert = hxd_core::CertRef {
        identity: fp.0,
        device: hl_identity::Fingerprint::of(&laptop.public()).0,
        epoch: 0,
    };
    let _here = session_as(a.v, &a.alice, &laptop, &a.card).await;
    hxd::registrar::freeze(&a.r.config, &fp.to_string(), false).unwrap();
    let clock = a.identity.clock();
    clock.advance(Duration::from_secs(2));
    a.identity.sweep_records().await;
    assert!(a.core.key_refusal(&laptop_cert).is_some(), "frozen");
    // Its session ended, so she is seen away.
    a.identity.sweep_records().await;
    assert!(a.core.key_refusal(&laptop_cert).is_some(), "kept");

    hxd::registrar::freeze(&a.r.config, &fp.to_string(), true).unwrap();
    clock.advance(Duration::from_secs(2));
    a.identity.sweep_records().await;
    assert!(
        a.core.key_refusal(&laptop_cert).is_some(),
        "kept until read again"
    );
    clock.advance(Duration::from_secs(602));
    a.identity.sweep_records().await;
    assert_eq!(a.core.key_refusal(&laptop_cert), None, "and lifted");
}

/// What a held list refuses is applied as soon as its identity is seen
/// away, before anything is fetched for it: as after a restart, a device
/// revoked in a list held here loses its registration at the first sweep.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_device_a_held_list_revokes_loses_its_push_registration_once_seen_away() {
    let a = Away::start().await;
    let (phone, laptop) = (
        DeviceKey::from_seed(&[101; 32]),
        DeviceKey::from_seed(&[102; 32]),
    );
    a.register(&phone).await;
    post_device_revocation(&a.r, &a.alice, &phone).await;
    // The laptop's admission fetches the list, past its lifetime, and
    // holds it; no sweep has applied it.
    a.identity.clock().advance(Duration::from_secs(2));
    let mut c = session_as(a.v, &a.alice, &laptop, &a.card).await;
    c.request("logout", json!({})).await.unwrap();
    assert_eq!(a.rows(), [devid(&phone)]);
    a.identity.sweep_records().await;
    assert!(a.rows().is_empty(), "the phone's registration went");
}

/// A frozen identity's rows are taken as a revoked one's, and while a
/// delete the store failed waits they stay hidden between refreshes: a
/// freeze is lifted only by lists read again.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_frozen_identity_away_keeps_its_rows_hidden_between_refreshes() {
    let a = Away::start().await;
    let phone = DeviceKey::from_seed(&[101; 32]);
    a.register(&phone).await;
    let clock = a.identity.clock();
    a.identity.sweep_records().await;
    assert_eq!(a.delivered(), [devid(&phone)]);

    hxd::registrar::freeze(&a.r.config, &a.alice.fingerprint().to_string(), false).unwrap();
    a.hold();
    clock.advance(Duration::from_secs(602));
    a.identity.sweep_records().await;
    assert_eq!(a.rows(), [devid(&phone)], "the delete failed");
    assert!(a.delivered().is_empty(), "and the row is hidden");
    clock.advance(Duration::from_secs(2));
    a.identity.sweep_records().await;
    assert!(a.delivered().is_empty(), "still hidden");
    a.release();
    a.identity.sweep_records().await;
    assert!(a.rows().is_empty(), "and then taken");
}

#[tokio::test]
async fn a_registrar_that_moves_to_a_new_key_is_followed_within_the_minute() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| {
        let p = dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    };
    let before = start(&path("before"), "signup = \"open\"").await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let carol = IdentityKey::from_seed(&[3; 32]);
    let dev = DeviceKey::from_seed(&[101; 32]);
    let alice_card = attested(&before, &alice, "alice").await;

    // The registrar is reached at one address whichever key it has.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let to = Arc::new(std::sync::Mutex::new(before.ng));
    forward(listener, to.clone());
    let (v, identity) = verifier(&path("verifier"), &before, Trust::Discovery, &url, "").await;
    let clock = identity.clock().clone();
    assert_eq!(
        auth_at(v, &alice, &dev, &alice_card).await.json()["handle"],
        "alice@127.0.0.1"
    );

    // It moves to a new key, keeping the old one for two minutes.
    let rotated = start(
        &path("rotated"),
        &format!(
            "signup = \"open\"\nretiring = [{{ key = \"{}\", until = {} }}]",
            b64(&before.registrar.public_key()),
            now() + 120
        ),
    )
    .await;
    *to.lock().unwrap() = rotated.ng;
    let carol_card = attested(&rotated, &carol, "carol").await;

    // A key not heard of sends this server back to the registrar at most
    // once a minute, since anyone can name one.
    let reply = auth_at(v, &carol, &dev, &carol_card).await;
    assert_eq!(
        (reply.status, reply.json()["handle"].clone()),
        (200, Value::Null)
    );
    clock.advance(Duration::from_secs(61));
    assert_eq!(
        auth_at(v, &carol, &dev, &carol_card).await.json()["handle"],
        "carol@127.0.0.1"
    );
    assert_eq!(
        auth_at(v, &alice, &dev, &alice_card).await.json()["handle"],
        "alice@127.0.0.1"
    );

    // Past the old key's deadline, what it signed is no attestation.
    clock.advance(Duration::from_secs(70));
    let reply = auth_at(v, &alice, &dev, &alice_card).await;
    assert_eq!(
        (reply.status, reply.json()["handle"].clone()),
        (200, Value::Null)
    );
    assert_eq!(
        auth_at(v, &carol, &dev, &carol_card).await.json()["handle"],
        "carol@127.0.0.1"
    );
}

#[tokio::test]
async fn a_rotation_its_registrar_publishes_moves_the_identity_here() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, _) = verifier(&there, &r, Trust::Key, &live, "new_accounts = \"create\"").await;
    let (old, new) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let dev = DeviceKey::from_seed(&[101; 32]);
    let old_card = attested_committing(&r, &old, "alice", &new, true).await;
    let account = auth_at(v, &old, &dev, &old_card).await.json()["account"].clone();
    assert!(account.is_string(), "{account}");
    let mut old_here = session_at(v, &old, &old_card).await;

    let posted = post(
        &r,
        "/registrar/records",
        json!({ "record": b64(&rotation(&old, &new)) }),
    )
    .await;
    assert_eq!(posted.json()["published"], true);
    let new_card = attested(&r, &new, "alice").await;
    next_list().await;

    // The successor's admission is where the rotation is learned: it
    // takes the predecessor's account, ends its session, and the
    // predecessor is told where the identity went.
    let reply = auth_at(v, &new, &dev, &new_card).await.json();
    assert_eq!(
        (reply["handle"].clone(), reply["account"].clone()),
        (json!("alice@127.0.0.1"), account)
    );
    old_here.event("kicked").await.unwrap();
    let reply = auth_at(v, &old, &dev, &old_card).await;
    assert_eq!(
        (
            reply.status,
            reply.json()["error"].clone(),
            reply.json()["successor"].clone()
        ),
        (403, json!("rotated"), json!(new.fingerprint().to_string()))
    );
}

#[tokio::test]
async fn a_rotation_shown_at_auth_is_taken_only_to_the_anchored_key() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, _) = verifier(&there, &r, Trust::Key, &live, "").await;
    let old = IdentityKey::from_seed(&[1; 32]);
    let new = IdentityKey::from_seed(&[2; 32]);
    let thief = IdentityKey::from_seed(&[6; 32]);
    let dev = DeviceKey::from_seed(&[101; 32]);
    let old_card = attested_committing(&r, &old, "alice", &new, false).await;
    // Admitted with standing, so its commitment is anchored here.
    assert_eq!(auth_at(v, &old, &dev, &old_card).await.status, 200);

    // A thief with the old key gets a registrar that never held the
    // commitment to publish a rotation to their own key. The anchor
    // here outranks it: the old key is not told of any successor.
    let posted = post(
        &r,
        "/registrar/records",
        json!({ "record": b64(&rotation(&old, &thief)) }),
    )
    .await;
    assert_eq!(posted.json()["published"], true);
    next_list().await;
    assert_eq!(auth_at(v, &old, &dev, &old_card).await.status, 200);

    // A rotation signed with the old key to any other key is ignored:
    // that key is admitted as itself, and the old one still is.
    let card = |id: &IdentityKey| Card::new(id, "x", now()).sign(id, vec![]).unwrap();
    let extra = json!({ "rotation": b64(&rotation(&old, &thief)) });
    assert_eq!(
        auth_with(v, &thief, &dev, &card(&thief), extra)
            .await
            .status,
        200
    );
    assert_eq!(auth_at(v, &old, &dev, &old_card).await.status, 200);

    // To the anchored key it is taken.
    let extra = json!({ "rotation": b64(&rotation(&old, &new)) });
    assert_eq!(
        auth_with(v, &new, &dev, &card(&new), extra).await.status,
        200
    );
    let reply = auth_at(v, &old, &dev, &old_card).await;
    assert_eq!(
        (reply.status, reply.json()["successor"].clone()),
        (403, json!(new.fingerprint().to_string()))
    );
}

#[tokio::test]
async fn a_registrars_rotation_into_a_key_anchored_elsewhere_refuses_the_old_key_and_moves_nothing()
{
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, identity) = verifier(&there, &r, Trust::Key, &live, "").await;
    let [old, new, other] = [1, 2, 3].map(|s| IdentityKey::from_seed(&[s; 32]));
    std::fs::write(
        there.join("accounts/alice.toml"),
        format!(
            "name = \"alice\"\npassword = \"pw\"\n[identity]\nfingerprint = \"{}\"\n",
            old.fingerprint()
        ),
    )
    .unwrap();
    let dev = DeviceKey::from_seed(&[101; 32]);
    let old_card = attested_committing(&r, &old, "alice", &new, false).await;
    let account = auth_at(v, &old, &dev, &old_card).await.json()["account"].clone();
    assert_eq!(account, "alice");
    let mut old_here = session_at(v, &old, &old_card).await;

    // The successor key, attested and linking no account, is anchored
    // here to a key its rotation will not name. Shown at `auth`, the
    // rotation is ignored, as one replayed by whoever holds that key
    // alone would be.
    let new_card = attested_committing(&r, &new, "bob", &other, false).await;
    let reply = auth_at(v, &new, &dev, &new_card).await;
    assert_eq!(
        (reply.status, reply.json().get("account").cloned()),
        (200, Some(Value::Null))
    );
    let shown = json!({ "rotation": b64(&rotation(&old, &new)) });
    assert_eq!(auth_with(v, &new, &dev, &new_card, shown).await.status, 200);
    assert_eq!(auth_at(v, &old, &dev, &old_card).await.status, 200);

    // Its registrar publishes it: the old key is refused, and its
    // account stays where it was, though nothing stops it moving.
    let posted = post(
        &r,
        "/registrar/records",
        json!({ "record": b64(&rotation(&old, &new)) }),
    )
    .await;
    assert_eq!(posted.json()["published"], true);
    next_list().await;
    identity.sweep_records().await;
    old_here.event("kicked").await.unwrap();
    let reply = auth_at(v, &old, &dev, &old_card).await;
    assert_eq!(
        (
            reply.status,
            reply.json()["error"].clone(),
            reply.json()["successor"].clone()
        ),
        (403, json!("rotated"), json!(new.fingerprint().to_string()))
    );
    let reply = auth_at(v, &new, &dev, &new_card).await;
    assert_eq!(
        (reply.status, reply.json().get("account").cloned()),
        (200, Some(Value::Null))
    );
    let alice = std::fs::read_to_string(there.join("accounts/alice.toml")).unwrap();
    assert!(alice.contains(&old.fingerprint().to_string()), "{alice}");
    let file = std::fs::read_to_string(there.join("successors")).unwrap();
    assert!(
        file.contains(&format!(
            "{} => {} held",
            old.fingerprint(),
            new.fingerprint()
        )),
        "{file}"
    );
}

#[tokio::test]
async fn a_successor_rotates_on_only_to_its_rotations_next() {
    for with_next in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("registrar");
        std::fs::create_dir_all(&at).unwrap();
        let r = start(&at, "signup = \"open\"").await;
        let there = dir.path().join("verifier");
        std::fs::create_dir_all(&there).unwrap();
        let live = format!("http://{}", r.ng);
        let (v, _) = verifier(&there, &r, Trust::Key, &live, "new_accounts = \"create\"").await;
        let [old, new, next, thief] = [1, 2, 3, 6].map(|s| IdentityKey::from_seed(&[s; 32]));
        let dev = DeviceKey::from_seed(&[101; 32]);
        let old_card = attested_committing(&r, &old, "alice", &new, false).await;
        let account = auth_at(v, &old, &dev, &old_card).await.json()["account"].clone();
        assert!(account.is_string(), "{account}");
        let card = |id: &IdentityKey, successor: Option<&IdentityKey>| {
            let mut c = Card::new(id, "x", now());
            c.successor = successor.map(commitment);
            c.sign(id, vec![]).unwrap()
        };
        let rotate = |from: &IdentityKey, to: &IdentityKey, next: Option<&IdentityKey>| {
            let r = Rotation {
                identity: from.public(),
                successor: to.public(),
                time: now(),
                next: next.map(commitment),
            };
            json!({ "rotation": b64(&r.sign(from, to).unwrap()) })
        };

        // A thief holding the successor key alone signs in first,
        // replaying the owner's rotation on a card that commits to the
        // thief's own key. The rotation stands; the card's commitment
        // is anchored by neither, and with a `next` the card is refused.
        let owners = rotate(&old, &new, with_next.then_some(&next));
        let shown = auth_with(v, &new, &dev, &card(&new, Some(&thief)), owners).await;
        assert_eq!(
            shown.status,
            if with_next { 401 } else { 200 },
            "{with_next}"
        );
        assert_eq!(auth_at(v, &old, &dev, &old_card).await.status, 403);
        let stolen = rotate(&new, &thief, None);
        let taken = auth_with(v, &thief, &dev, &card(&thief, None), stolen).await;
        assert_ne!(taken.json()["account"], account, "{with_next}");
        let owner = auth_at(v, &new, &dev, &card(&new, with_next.then_some(&next))).await;
        assert_eq!(
            (owner.status, owner.json()["account"].clone()),
            (200, account.clone()),
            "{with_next}: the account stays with the owner"
        );

        // The owner's own rotation onward is taken at auth only to the
        // `next` its predecessor signed; without one, only a registrar's
        // records could move it.
        let onward = rotate(&new, &next, None);
        let moved = auth_with(v, &next, &dev, &card(&next, None), onward).await;
        assert_eq!(moved.json()["account"] == account, with_next, "{with_next}");
        let after = auth_at(v, &new, &dev, &card(&new, with_next.then_some(&next))).await;
        assert_eq!(
            after.status,
            if with_next { 403 } else { 200 },
            "{with_next}"
        );
    }
}

#[tokio::test]
async fn a_successor_takes_no_next_from_a_second_predecessor() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, _) = verifier(&there, &r, Trust::Key, &live, "new_accounts = \"create\"").await;
    let [old, new, own, thief] = [1, 2, 4, 6].map(|s| IdentityKey::from_seed(&[s; 32]));
    let dev = DeviceKey::from_seed(&[101; 32]);
    let old_card = attested_committing(&r, &old, "alice", &new, false).await;
    let account = auth_at(v, &old, &dev, &old_card).await.json()["account"].clone();
    assert!(account.is_string(), "{account}");
    let card = |id: &IdentityKey, name: &str, successor: Option<&IdentityKey>| {
        let mut c = Card::new(id, name, now());
        c.successor = successor.map(commitment);
        c.sign(id, vec![]).unwrap()
    };
    let rotate = |from: &IdentityKey, to: &IdentityKey, next: Option<&IdentityKey>| {
        let r = Rotation {
            identity: from.public(),
            successor: to.public(),
            time: now(),
            next: next.map(commitment),
        };
        json!({ "rotation": b64(&r.sign(from, to).unwrap()) })
    };
    let owners = rotate(&old, &new, None);
    let shown = auth_with(v, &new, &dev, &card(&new, "x", None), owners).await;
    assert_eq!(shown.json()["account"], account);

    // Whoever holds the successor key alone makes an identity of its own
    // committed to it, rotates that one onto the successor with a `next`
    // of their choosing, and then the successor onto that.
    let own_card = attested_committing(&r, &own, "mallory", &new, false).await;
    let mine = auth_at(v, &own, &dev, &own_card).await;
    assert!(mine.json()["account"].is_string(), "{}", mine.json());
    let second = rotate(&own, &new, Some(&thief));
    auth_with(v, &new, &dev, &card(&new, "x", None), second).await;
    let stolen = rotate(&new, &thief, None);
    let taken = auth_with(v, &thief, &dev, &card(&thief, "t", None), stolen).await;
    assert_ne!(taken.json()["account"], account);
    let owner = auth_at(v, &new, &dev, &card(&new, "x", None)).await;
    assert_eq!(
        (owner.status, owner.json()["account"].clone()),
        (200, account),
        "the account stays with the owner"
    );
}

#[tokio::test]
async fn a_key_nobody_answers_for_waits_before_it_may_chat() {
    let dir = tempfile::tempdir().unwrap();
    let at = dir.path().join("registrar");
    std::fs::create_dir_all(&at).unwrap();
    let r = start(&at, "signup = \"open\"").await;
    let there = dir.path().join("verifier");
    std::fs::create_dir_all(&there).unwrap();
    let live = format!("http://{}", r.ng);
    let (v, identity) = verifier(&there, &r, Trust::Key, &live, "").await;

    // No attestation and no account: admitted, and quiet for a while.
    let stranger = IdentityKey::from_seed(&[7; 32]);
    let card = Card::new(&stranger, "Stranger", now())
        .sign(&stranger, vec![])
        .unwrap();
    let mut c = session_at(v, &stranger, &card).await;
    let id = c.tx.send("chat", json!({ "text": "hello" })).await.unwrap();
    let reply = loop {
        if let hxd_testclient::ng::Incoming::Reply(r) = c.next().await.unwrap() {
            if r["reply"] == id {
                break r;
            }
        }
    };
    let wait = reply["error"]["retry_after"].as_u64().unwrap();
    assert_eq!(reply["error"]["code"], "rate_limited");
    assert!((1..=120).contains(&wait), "{reply}");

    // An attested key is not held to it.
    let alice = IdentityKey::from_seed(&[1; 32]);
    let mut a = session_at(v, &alice, &attested(&r, &alice, "alice").await).await;
    a.chat("hi").await.unwrap();

    identity.clock().advance(Duration::from_secs(wait));
    c.chat("hello").await.unwrap();
}

// --- key backup (§9) -------------------------------------------------------

/// A registrar keeping envelopes, its decoy secret inside `dir`.
async fn start_backups(dir: &Path) -> Server {
    let secret = dir.join("envelope.secret");
    start(
        dir,
        &format!(
            "signup = \"open\"\nenvelopes = true\nenvelope_secret = \"{}\"",
            secret.display()
        ),
    )
    .await
}

async fn send_put(s: &Server, put: &[u8]) -> Reply {
    http_as(
        s.ng,
        &s.ng.to_string(),
        "PUT",
        "/registrar/envelopes",
        &[("Content-Type", "application/json")],
        json!({ "request": b64(put) }).to_string().as_bytes(),
    )
    .await
}

/// Seal `who` under `secret` and put it, as the server's clock has it.
async fn back_up(s: &Server, who: &IdentityKey, secret: &Secret<'_>) -> Keys {
    let (env, keys) = KeyEnvelope::seal(who, secret).unwrap();
    let put = EnvelopePut::store(who, HOST, s.clock.unix(), &env, &keys).unwrap();
    let r = send_put(s, &put).await;
    assert_eq!((r.status, r.json()), (200, json!({ "stored": true })));
    keys
}

async fn salt(s: &Server, handle: &str, kind: u8) -> Kdf {
    let r = post(
        s,
        "/registrar/envelopes/params",
        json!({ "handle": handle, "kind": kind }),
    )
    .await;
    assert_eq!(r.status, 200);
    Kdf::parse(&unb64(r.json()["kdf"].as_str().unwrap())).unwrap()
}

async fn fetch(s: &Server, handle: &str, kind: u8, auth: &[u8; 32]) -> Reply {
    post(
        s,
        "/registrar/envelopes/fetch",
        json!({ "handle": handle, "kind": kind, "auth": b64(auth) }),
    )
    .await
}

fn hex32(path: &Path) -> [u8; 32] {
    let text = std::fs::read_to_string(path).unwrap();
    let t = text.trim();
    (0..32)
        .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// The envelope the registrar's own file holds, read beside the server.
fn stored(dir: &Path, who: &IdentityKey, kind: u8) -> Option<hxd_registrar::EnvelopeRow> {
    use hxd_registrar::RegistrarStore;
    hxd_store_sqlite::SqliteRegistrarStore::open(
        dir.join("registrar.db"),
        hxd_store_sqlite::Synchronous::Normal,
    )
    .unwrap()
    .envelope(&who.public(), kind)
    .unwrap()
}

#[tokio::test]
async fn an_envelope_is_found_by_its_salt_fetched_and_opened_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let doc = get(&s, "/.well-known/hotline").await.json();
    assert_eq!(
        doc["registrar"]["endpoints"]["envelopes"],
        "/registrar/envelopes"
    );
    let alice = IdentityKey::from_seed(&[1; 32]);
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let secret = Secret::Passphrase("correct horse battery");
    back_up(&s, &alice, &secret).await;

    // As a device with nothing but the handle and the passphrase.
    let keys = Keys::derive(&secret, salt(&s, "Alice", 1).await).unwrap();
    let r = fetch(&s, "alice", 1, keys.auth()).await;
    assert_eq!(r.status, 200);
    let body = r.json();
    let identity: [u8; 32] = unb64(body["identity"].as_str().unwrap())
        .try_into()
        .unwrap();
    let env = KeyEnvelope::parse(&unb64(body["envelope"].as_str().unwrap())).unwrap();
    assert_eq!(env.open(&identity, &keys).unwrap().public(), alice.public());
}

#[tokio::test]
async fn every_fetch_miss_answers_alike_and_every_salt_without_an_envelope_is_a_decoy() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let (alice, bob) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    for (who, handle) in [(&alice, "alice"), (&bob, "bobby")] {
        assert_eq!(register(&s, request(who, handle), who).await.status, 200);
    }
    let keys = back_up(&s, &alice, &Secret::Passphrase("correct horse")).await;
    let bobs = back_up(&s, &bob, &Secret::Passphrase("battery staple")).await;
    hxd::registrar::freeze(&s.config, &bob.fingerprint().to_string(), false).unwrap();

    let mut answers = Vec::new();
    for (handle, kind, auth) in [
        ("carol", 1, keys.auth()),
        ("alice", 2, keys.auth()),
        ("alice", 1, &[0; 32]),
        ("bobby", 1, bobs.auth()),
    ] {
        let r = fetch(&s, handle, kind, auth).await;
        // Everything but the time it was sent.
        let headers: Vec<_> = r
            .headers
            .into_iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("date"))
            .collect();
        answers.push((r.status, headers, r.body));
    }
    assert_eq!(answers[0].0, 404);
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");

    let secret = hex32(&dir.path().join("envelope.secret"));
    for (handle, kind, k) in [
        ("carol", 1, Kind::Passphrase),
        ("alice", 2, Kind::RecoveryCode),
        ("bobby", 1, Kind::Passphrase),
    ] {
        let decoy = Kdf::decoy(&secret, handle, k);
        assert_eq!(salt(&s, handle, kind).await, decoy, "{handle}");
        assert_eq!(salt(&s, handle, kind).await, decoy, "{handle}, asked again");
    }
}

#[tokio::test]
async fn a_handle_guessed_at_is_locked_out_until_the_clock_moves_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    assert_eq!(
        register(&s, request(&alice, "alice"), &alice).await.status,
        200
    );
    let keys = back_up(&s, &alice, &Secret::Passphrase("correct horse")).await;
    for i in 0..10 {
        assert_eq!(
            fetch(&s, "alice", 1, &[i; 32]).await.status,
            404,
            "guess {i}"
        );
    }
    let r = fetch(&s, "alice", 1, keys.auth()).await;
    assert_eq!(
        (r.status, r.json()["error"].clone(), r.header("Retry-After")),
        (429, json!("rate_limited"), Some("3600"))
    );
    s.clock.advance(Duration::from_secs(3600));
    assert_eq!(fetch(&s, "alice", 1, keys.auth()).await.status, 200);

    // Locked again, for twice as long, until the operator forgets the
    // counts. The guess that locks it is told so in its own reply.
    let mut last = None;
    for i in 0..10 {
        last = Some(fetch(&s, "alice", 1, &[i; 32]).await);
    }
    let last = last.unwrap();
    assert_eq!(
        (last.status, last.header("Retry-After")),
        (429, Some("7200"))
    );
    hxd::registrar::unlock(&s.config, "alice", Some("passphrase")).unwrap();
    assert_eq!(fetch(&s, "alice", 1, keys.auth()).await.status, 200);
}

#[tokio::test]
async fn a_put_is_refused_for_another_registrar_and_for_an_identity_that_may_not() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let (alice, frozen, stranger) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
        IdentityKey::from_seed(&[3; 32]),
    );
    for (who, handle) in [(&alice, "alice"), (&frozen, "frozen")] {
        assert_eq!(register(&s, request(who, handle), who).await.status, 200);
    }
    hxd::registrar::freeze(&s.config, &frozen.fingerprint().to_string(), false).unwrap();
    for (who, host, status, error) in [
        (&alice, "elsewhere.example", 400, "bad_request"),
        (&frozen, HOST, 403, "frozen"),
        (&stranger, HOST, 404, "not_registered"),
    ] {
        let (env, keys) = KeyEnvelope::seal(who, &Secret::Passphrase("p")).unwrap();
        let put = EnvelopePut::store(who, host, s.clock.unix(), &env, &keys).unwrap();
        let r = send_put(&s, &put).await;
        assert_eq!(
            (r.status, r.json()["error"].clone()),
            (status, json!(error))
        );
        assert_eq!(stored(dir.path(), who, 1), None);
    }
}

#[tokio::test]
async fn revocation_and_rotation_take_the_envelopes_with_them() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let (alice, bob, bob2) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
        IdentityKey::from_seed(&[12; 32]),
    );
    for (who, handle) in [(&alice, "alice"), (&bob, "bobby")] {
        assert_eq!(register(&s, request(who, handle), who).await.status, 200);
        back_up(&s, who, &Secret::Passphrase("p")).await;
        assert!(stored(dir.path(), who, 1).is_some());
    }
    let revoke = hl_identity::IdentityRevocation {
        identity: alice.public(),
        time: now(),
        reason: None,
    }
    .sign(&alice)
    .unwrap();
    let rotate = Rotation {
        identity: bob.public(),
        successor: bob2.public(),
        time: now(),
        next: None,
    }
    .sign(&bob, &bob2)
    .unwrap();
    for record in [revoke, rotate] {
        let r = post(&s, "/registrar/records", json!({ "record": b64(&record) })).await;
        assert_eq!(r.json()["published"], true);
    }
    for who in [&alice, &bob] {
        assert_eq!(stored(dir.path(), who, 1), None);
    }
}

#[tokio::test]
async fn hlid_backs_up_and_restores_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let bin = hlid_binary();
    let home = dir.path().join("hlid");
    let url = format!("http://{}", s.ng);
    let pass = dir.path().join("passphrase");
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    let pass = pass.to_str().unwrap();
    let (ok, _, err) = hlid(&bin, &home, &["init", "--name", "Alice"]).await;
    assert!(ok, "{err}");
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &["register", "--registrar", &url, "--handle", "alice"],
    )
    .await;
    assert!(ok, "{err}");
    let (ok, _, err) = hlid(
        &bin,
        &home,
        &["backup", "--registrar", &url, "--password-file", pass],
    )
    .await;
    assert!(ok, "{err}");
    let (ok, out, err) = hlid(&bin, &home, &["backup", "--registrar", &url, "--recovery"]).await;
    assert!(ok, "{err}");
    let code = out
        .lines()
        .find_map(|l| l.strip_prefix("recovery code: "))
        .unwrap_or_else(|| panic!("no code shown: {out}"));
    let code_file = dir.path().join("code");
    std::fs::write(&code_file, code).unwrap();
    let original = hex32(&home.join("identity.key"));

    for (name, secret, recovery) in [
        ("by-passphrase", pass, false),
        ("by-code", code_file.to_str().unwrap(), true),
    ] {
        let restored = dir.path().join(name);
        let mut args = vec![
            "restore",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--password-file",
            secret,
        ];
        if recovery {
            args.push("--recovery");
        }
        let (ok, out, err) = hlid(&bin, &restored, &args).await;
        assert!(ok, "{name}: {err}");
        assert!(out.contains("with the card the registrar keeps"), "{out}");
        assert_eq!(hex32(&restored.join("identity.key")), original, "{name}");
        let card = Card::parse(&std::fs::read(restored.join("card.bin")).unwrap()).unwrap();
        assert_eq!(card.attestations[0].full_handle(), "alice@127.0.0.1");
        let cert = DeviceCert::parse(&std::fs::read(restored.join("cert.bin")).unwrap()).unwrap();
        assert_eq!(cert.identity, IdentityKey::from_seed(&original).public());
    }

    // A passphrase on the command line is one `ps` shows.
    let (ok, _, err) = hlid(
        &bin,
        &dir.path().join("in-ps"),
        &[
            "restore",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--password",
            "correct horse battery staple",
        ],
    )
    .await;
    assert!(!ok && err.contains("`ps`"), "{err}");

    // A put in the second of the last one is signed again once the
    // second turns: the second put lands in the first one's second.
    let start = now();
    while now() == start {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let id = IdentityKey::from_seed(&original);
    let put = EnvelopePut::delete(&id, HOST, Kind::Passphrase, now()).unwrap();
    assert_eq!(send_put(&s, &put).await.status, 200);
    let (ok, _, err) = hlid(&bin, &home, &["backup", "--registrar", &url, "--delete"]).await;
    assert!(ok, "{err}");
    let (ok, _, err) = hlid(
        &bin,
        &dir.path().join("too-late"),
        &[
            "restore",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--password-file",
            pass,
        ],
    )
    .await;
    assert!(!ok);
    assert!(err.contains("no passphrase envelope for alice"), "{err}");
}

#[tokio::test]
async fn a_restore_whose_card_cannot_be_fetched_stops_rather_than_make_one() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("envelope.secret");
    // One card fetch a minute from here, and this address not exempt.
    let s = start(
        dir.path(),
        &format!(
            "signup = \"open\"\nenvelopes = true\nenvelope_secret = \"{}\"\n\
             [limits]\nexempt = []\navatar_fetches_per_minute = 1",
            secret.display()
        ),
    )
    .await;
    let alice = IdentityKey::from_seed(&[1; 32]);
    let mut req = request(&alice, "alice");
    req.successor = Some(commitment(&IdentityKey::from_seed(&[2; 32])));
    assert_eq!(register(&s, req, &alice).await.status, 200);
    back_up(&s, &alice, &Secret::Passphrase("correct horse battery")).await;
    let card = format!("/identity/card/{}", alice.fingerprint());
    assert_eq!(get(&s, &card).await.status, 404);
    assert_eq!(get(&s, &card).await.status, 429);
    let pass = dir.path().join("passphrase");
    std::fs::write(&pass, "correct horse battery\n").unwrap();
    let home = dir.path().join("restored");
    let url = format!("http://{}", s.ng);
    let (ok, _, err) = hlid(
        &hlid_binary(),
        &home,
        &[
            "restore",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--password-file",
            pass.to_str().unwrap(),
        ],
    )
    .await;
    assert!(!ok);
    assert!(err.contains("answered 429"), "{err}");
}

#[tokio::test]
async fn a_restore_with_no_card_to_take_says_the_successor_must_commit_again() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_backups(dir.path()).await;
    let bin = hlid_binary();
    let url = format!("http://{}", s.ng);
    // Registered with a commitment, and never a card put at the registrar.
    let (alice, successor) = (
        IdentityKey::from_seed(&[1; 32]),
        IdentityKey::from_seed(&[2; 32]),
    );
    let mut req = request(&alice, "alice");
    req.successor = Some(commitment(&successor));
    assert_eq!(register(&s, req, &alice).await.status, 200);
    back_up(&s, &alice, &Secret::Passphrase("correct horse battery")).await;
    let pass = dir.path().join("passphrase");
    std::fs::write(&pass, "correct horse battery\n").unwrap();
    let home = dir.path().join("restored");

    let (ok, out, err) = hlid(
        &bin,
        &home,
        &[
            "restore",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--password-file",
            pass.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ok, "{err}");
    assert!(out.contains("--successor-key"), "{out}");

    let register_again = |extra: Vec<String>| {
        let mut args = vec![
            "register",
            "--registrar",
            &url,
            "--handle",
            "alice",
            "--no-put",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        args.extend(extra);
        args
    };
    let args = register_again(vec![]);
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, err) = hlid(&bin, &home, &words).await;
    assert!(!ok && err.contains("successor_mismatch"), "{err}");

    let key = dir.path().join("successor.key");
    let hex: String = successor
        .seed()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(&key, hex).unwrap();
    let args = register_again(vec![
        "--successor-commit".into(),
        "--successor-key".into(),
        key.to_str().unwrap().into(),
    ]);
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, out, err) = hlid(&bin, &home, &words).await;
    assert!(ok, "{err}");
    assert!(out.contains("reissued alice@127.0.0.1"), "{out}");
}
