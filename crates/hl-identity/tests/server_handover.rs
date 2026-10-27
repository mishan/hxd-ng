//! `docs/server-handover-vectors.json`, the server key handover's
//! vectors (`docs/server-key-handover.md` §10). The generator below
//! signs every object without this crate's signers and writes each
//! outcome as the spec states it, never as this crate decides it. The
//! checks hold the crate to the file: objects re-sign to the exact bytes
//! and parse back to their fields, rejects fail with the named error, and
//! every client case decides as the file says.
//!
//! Regenerate with
//! `cargo test -p hl-identity --test server_handover -- --ignored generate`.

use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::handover::{self, Followed, Pinned, Verdict, Warning};
use hl_identity::message::SKEW;
use hl_identity::{proof, Handover, ServerChallenge, ServerKey};
use serde::Serialize;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../docs/server-handover-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/server-handover-vectors.json"
);

const T0: u64 = 1_757_116_800;
const DAY: u64 = 86_400;
const NOW: u64 = T0 + 30 * DAY;
const HOST: &str = "hl.example:5700";
const NONCE: [u8; 32] = [0xc4; 32];
const LONG: usize = handover::MAX_CHAIN + 1;

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string of odd length: {s:?}");
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("not hex: {pair:?}"))
        })
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn str_of<'a>(j: &'a Json, k: &str) -> &'a str {
    j[k].as_str()
        .unwrap_or_else(|| panic!("missing string {k}"))
}

fn opt32(j: &Json) -> Option<[u8; 32]> {
    j.as_str().map(unhex32)
}

// --- the generator -------------------------------------------------------

/// `server` is `identity-test-vectors.json`'s server key; `k1` on and
/// `stray` are keys beyond it.
fn seed_of(name: &str) -> [u8; 32] {
    match name {
        "server" => [0x04; 32],
        "stray" => [0x30; 32],
        k => [0x10 + k[1..].parse::<u8>().unwrap(); 32],
    }
}

fn k(i: usize) -> String {
    match i {
        0 => "server".into(),
        i => format!("k{i}"),
    }
}

fn pk(name: &str) -> [u8; 32] {
    SigningKey::from_bytes(&seed_of(name))
        .verifying_key()
        .to_bytes()
}

fn commit(name: &str) -> [u8; 32] {
    Sha256::digest(pk(name)).into()
}

fn bytes(b: &[u8]) -> Option<Value> {
    Some(Value::Bytes(b.to_vec()))
}

/// The file's shape for a signed object, signed by `signer`.
fn entry(domain: &str, fields: Json, unsigned: Value, signer: &str) -> Json {
    let body = cbor::encode(&unsigned);
    let mut input = domain.as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(&body);
    let sig = SigningKey::from_bytes(&seed_of(signer))
        .sign(&input)
        .to_bytes();
    let Value::Map(mut entries) = unsigned else {
        unreachable!()
    };
    entries.push((Value::Text("sig".into()), Value::Bytes(sig.to_vec())));
    json!({
        "domain": domain,
        "signer": signer,
        "fields": fields,
        "unsigned_hex": hex(&body),
        "signature_input_hex": hex(&input),
        "signature_hex": hex(&sig),
        "signed_hex": hex(&cbor::encode(&Value::Map(entries))),
    })
}

fn handover_entry(
    old: &str,
    new: &str,
    next: Option<&str>,
    time: u64,
    v: u64,
    signer: &str,
) -> Json {
    let next = next.map(commit);
    let mut fields = json!({ "v": v, "old": hex(&pk(old)), "new": hex(&pk(new)), "time": time });
    if let Some(n) = next {
        fields["next"] = json!(hex(&n));
    }
    let unsigned = map(vec![
        ("v", Some(Value::Uint(v))),
        ("old", bytes(&pk(old))),
        ("new", bytes(&pk(new))),
        ("next", next.as_ref().and_then(|n| bytes(n))),
        ("time", Some(Value::Uint(time))),
    ]);
    entry(handover::DOMAIN, fields, unsigned, signer)
}

fn ho(old: &str, new: &str, next: Option<&str>, time: u64) -> Json {
    handover_entry(old, new, next, time, 1, old)
}

fn challenge_entry(key: &str, next: Option<&str>) -> Json {
    let next = next.map(commit);
    let expires = NOW + 60;
    let mut fields = json!({
        "v": 1, "challenge": hex(&NONCE), "server_key": hex(&pk(key)),
        "host": HOST, "expires": expires,
    });
    if let Some(n) = next {
        fields["next"] = json!(hex(&n));
    }
    let unsigned = map(vec![
        ("v", Some(Value::Uint(1))),
        ("challenge", bytes(&NONCE)),
        ("server_key", bytes(&pk(key))),
        ("host", Some(Value::Text(HOST.into()))),
        ("expires", Some(Value::Uint(expires))),
        ("next", next.as_ref().and_then(|n| bytes(n))),
    ]);
    entry(proof::SERVER_DOMAIN, fields, unsigned, key)
}

fn t(i: u64) -> u64 {
    T0 + i * DAY
}

fn long_name(i: usize) -> String {
    format!("h{i}_{}", i + 1)
}

/// A commitment to `key`, in the file's form.
fn c(key: &str) -> Json {
    json!(hex(&commit(key)))
}

fn warn(reason: &str) -> Json {
    json!({ "outcome": "warn", "reason": reason })
}

/// A client case: a `check` by a client with no records, from `HOST`,
/// unless `case` says otherwise.
fn case(mut case: Json) -> Json {
    let defaults = json!({
        "kind": "check", "followed": [], "dismissed": [], "host": HOST,
    });
    for (k, v) in defaults.as_object().unwrap() {
        if case.get(k).is_none() {
            case[k] = v.clone();
        }
    }
    case
}

#[test]
#[ignore = "writes docs/server-handover-vectors.json"]
fn generate() {
    let mut keys = serde_json::Map::new();
    for name in (0..=LONG + 1).map(k).chain(["stray".into()]) {
        let e = json!({ "seed_hex": hex(&seed_of(&name)), "public_hex": hex(&pk(&name)) });
        keys.insert(name, e);
    }

    let mut handovers = serde_json::Map::new();
    for i in 0..LONG {
        let e = ho(&k(i), &k(i + 1), Some(&k(i + 2)), t(i as u64 + 1));
        handovers.insert(long_name(i), e);
    }
    for (name, e) in [
        ("h0_1_end", ho("server", "k1", None, t(1))),
        ("h1_2_end", ho("k1", "k2", None, t(2))),
        (
            "h1_2_by_new",
            handover_entry("k1", "k2", Some("k3"), t(2), 1, "k2"),
        ),
        ("h0_stray", ho("server", "stray", Some("k2"), t(1))),
        ("h0_1_later", ho("server", "k1", Some("k2"), t(1) + 1)),
        (
            "h0_1_future",
            ho("server", "k1", Some("k2"), NOW + SKEW + 1),
        ),
        ("h1_2_same_time", ho("k1", "k2", Some("k3"), t(1))),
        ("h1_2_back", ho("k1", "k2", Some("k1"), t(2))),
        ("h2_1", ho("k2", "k1", Some("k3"), t(3))),
        ("h0_1_edge", ho("server", "k1", Some("k2"), NOW + SKEW)),
        ("h1_3", ho("k1", "k3", Some("k4"), t(2))),
        ("hstray_2", ho("stray", "k2", Some("k3"), t(2))),
    ] {
        handovers.insert(name.into(), e);
    }
    handovers["h0_1"]["note"] = json!(
        "A handover with `next` (§3): the file's server key hands over to k1 and commits to k2."
    );

    let mut challenges = serde_json::Map::new();
    for (name, key, next) in [
        ("c1", "k1", Some("k2")),
        ("c1_k3", "k1", Some("k3")),
        ("c2", "k2", Some("k3")),
        ("c2_end", "k2", None),
        ("c2_stray", "k2", Some("stray")),
        ("c16", "k16", Some("k17")),
        ("c17", "k17", Some("k18")),
        ("c_stray", "stray", Some("k2")),
    ] {
        challenges.insert(name.into(), challenge_entry(key, next));
    }
    challenges["c2"]["note"] = json!(
        "A server challenge carrying `next` (§2), signed with it, beside hotline-ng-auth.md §6.2's own vector."
    );

    let long: Vec<String> = (0..LONG).map(long_name).collect();
    let two = ["h0_1", "h1_2"];
    let fork = |name: &str| json!({ "outcome": "warn", "reason": "Fork", "handover": name });
    let keep = json!({ "outcome": "keep" });
    let client: Vec<Json> = [
        json!({
            "name": "a chain of two, followed from the pinned key",
            "pinned": "server", "commitment": c("k1"), "chain": two, "challenge": "c2",
            "expect": { "outcome": "follow", "key": "k2", "commitment": c("k3"), "followed": two },
        }),
        json!({
            "name": "the same chain served from before the pin, followed from the pinned key",
            "pinned": "k1", "commitment": c("k2"), "followed": ["h0_1"], "chain": two, "challenge": "c2",
            "expect": { "outcome": "follow", "key": "k2", "commitment": c("k3"), "followed": ["h1_2"] },
        }),
        json!({
            "name": "the last handover and the new challenge both lack next: accepted",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "h1_2_end"], "challenge": "c2_end",
            "expect": { "outcome": "follow", "key": "k2", "commitment": null, "followed": ["h0_1", "h1_2_end"] },
        }),
        json!({
            "name": "a first pin takes the served chain as aliases",
            "kind": "pin", "chain": two, "challenge": "c2",
            "expect": { "outcome": "pin", "commitment": c("k3"), "aliases": two },
        }),
        json!({
            "name": "a first pin of a chain that fails its checks gives no aliases",
            "kind": "pin", "chain": ["h1_2", "h0_1"], "challenge": "c2",
            "expect": { "outcome": "pin", "commitment": c("k3"), "aliases": [] },
        }),
        json!({
            "name": "a first pin of more than 16 handovers gives no aliases",
            "kind": "pin", "chain": long, "challenge": "c17",
            "expect": { "outcome": "pin", "commitment": c("k18"), "aliases": [] },
        }),
        json!({
            "name": "exactly 16 handovers, followed",
            "pinned": "server", "commitment": c("k1"), "chain": long[..16], "challenge": "c16",
            "expect": { "outcome": "follow", "key": "k16", "commitment": c("k17"), "followed": long[..16] },
        }),
        json!({
            "name": "a handover whose time is exactly now plus S, followed",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1_edge"], "challenge": "c1",
            "expect": { "outcome": "follow", "key": "k1", "commitment": c("k2"), "followed": ["h0_1_edge"] },
        }),
        json!({
            "name": "a handover to a key the commitment does not name",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_stray"], "challenge": "c_stray",
            "expect": warn("Chain(Commitment)"),
        }),
        json!({
            "name": "re-pin after a commitment warning: the replaced key gets no alias",
            "kind": "repin", "chain": ["h0_stray"], "challenge": "c_stray",
            "expect": { "outcome": "pin", "commitment": c("k2"), "aliases": [] },
        }),
        json!({
            "name": "re-pin after a second key-change warning: a key given up at the first one, signing a handover it never made, gets no alias",
            "kind": "repin", "chain": ["h0_1_later", "h1_2"], "challenge": "c2",
            "expect": { "outcome": "pin", "commitment": c("k3"), "aliases": [] },
        }),
        json!({
            "name": "re-pin of a chain that forks against a record warns in turn",
            "kind": "repin", "followed": ["h0_1"], "chain": ["h0_stray"], "challenge": "c_stray",
            "expect": fork("h0_stray"),
        }),
        json!({
            "name": "a key change with no commitment remembered",
            "pinned": "server", "commitment": null, "chain": two, "challenge": "c2",
            "expect": warn("Chain(Commitment)"),
        }),
        json!({
            "name": "a followed handover no later than a record the client holds",
            "pinned": "k1", "commitment": c("k2"), "followed": ["h0_1"], "chain": ["h1_2_same_time"], "challenge": "c2",
            "expect": warn("Chain(Time)"),
        }),
        json!({
            "name": "a mid-chain new that does not match the previous next",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "h1_3"], "challenge": "c2",
            "expect": warn("Chain(Link)"),
        }),
        json!({
            "name": "an old that is not the previous new",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "hstray_2"], "challenge": "c2",
            "expect": warn("Chain(Link)"),
        }),
        json!({
            "name": "same key: none remembered, one seen, no warning",
            "pinned": "k2", "commitment": null, "chain": two, "challenge": "c2", "expect": keep,
        }),
        json!({
            "name": "same key: the remembered commitment seen",
            "pinned": "k2", "commitment": c("k3"), "chain": two, "challenge": "c2", "expect": keep,
        }),
        json!({
            "name": "same key: one remembered, another seen, warns",
            "pinned": "k2", "commitment": c("k3"), "chain": two, "challenge": "c2_stray",
            "expect": warn("Recommitted"),
        }),
        json!({
            "name": "same key: one remembered, none seen, warns",
            "pinned": "k2", "commitment": c("k3"), "chain": two, "challenge": "c2_end",
            "expect": warn("Recommitted"),
        }),
        json!({
            "name": "a handover signed by new rather than old",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "h1_2_by_new"], "challenge": "c2",
            "expect": warn("Chain(Bad(BadSignature))"),
        }),
        json!({
            "name": "a first new that does not match the commitment",
            "pinned": "server", "commitment": c("stray"), "chain": two, "challenge": "c2",
            "expect": warn("Chain(Commitment)"),
        }),
        json!({
            "name": "a handover after one with no next",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1_end", "h1_2"], "challenge": "c2",
            "expect": warn("Chain(Link)"),
        }),
        json!({
            "name": "a last new that is not the challenge's server_key, both next absent",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1_end"], "challenge": "c2_end",
            "expect": warn("Chain(ServerKey)"),
        }),
        json!({
            "name": "a chain whose last new is not the server_key",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1"], "challenge": "c2",
            "expect": warn("Chain(ServerKey)"),
        }),
        json!({
            "name": "a fork from one old to two keys",
            "pinned": "k1", "commitment": c("k2"), "followed": ["h0_1"], "chain": ["h0_stray"], "challenge": "c1",
            "expect": fork("h0_stray"),
        }),
        json!({
            "name": "a fork the user accepted does not warn again",
            "pinned": "k1", "commitment": c("k2"), "followed": ["h0_1"], "dismissed": ["h0_stray"],
            "chain": ["h0_stray"], "challenge": "c1", "expect": keep,
        }),
        json!({
            "name": "a fork with the same old and new at another time",
            "pinned": "k2", "commitment": c("k3"), "followed": two, "chain": ["h0_1_later", "h1_2"], "challenge": "c2",
            "expect": fork("h0_1_later"),
        }),
        json!({
            "name": "a handover whose time is past now plus S",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1_future"], "challenge": "c1",
            "expect": warn("Chain(Time)"),
        }),
        json!({
            "name": "a chain whose times are equal",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "h1_2_same_time"], "challenge": "c2",
            "expect": warn("Chain(Time)"),
        }),
        json!({
            "name": "a list of more than 16 handovers",
            "pinned": "server", "commitment": c("k1"), "chain": long, "challenge": "c17",
            "expect": warn("Chain(TooLong)"),
        }),
        json!({
            "name": "a list of more than 16 handovers at the same key is not verified, and forks nothing",
            "pinned": "k17", "commitment": c("k18"), "followed": ["h0_1_later"], "chain": long, "challenge": "c17",
            "expect": keep,
        }),
        json!({
            "name": "a chain that repeats a key",
            "pinned": "server", "commitment": c("k1"), "chain": ["h0_1", "h1_2_back", "h2_1"], "challenge": "c1_k3",
            "expect": warn("Chain(RepeatedKey)"),
        }),
        json!({
            "name": "a new key whose challenge next differs from the last followed handover's",
            "pinned": "server", "commitment": c("k1"), "chain": two, "challenge": "c2_stray",
            "expect": warn("Chain(Next)"),
        }),
        json!({
            "name": "the new key's challenge signed for another host",
            "pinned": "server", "commitment": c("k1"), "chain": two, "challenge": "c2", "host": "other.example",
            "expect": warn("HostMismatch"),
        }),
        json!({
            "name": "a pinned key older than the 16 kept",
            "pinned": "server", "commitment": c("k1"), "chain": long[1..], "challenge": "c17",
            "expect": warn("Chain(NotServed)"),
        }),
    ]
    .into_iter()
    .map(case)
    .collect();

    let alias = |name: &str, server: &str, sent: u64, expect: bool| json!({ "name": name, "alias": "h0_1", "server": server, "sent": sent, "expect": expect });
    let scope = vec![
        alias(
            "sent at the handover's time + S: in scope",
            "server",
            t(1) + SKEW,
            true,
        ),
        alias(
            "sent at time + S + 1: signed for elsewhere",
            "server",
            t(1) + SKEW + 1,
            false,
        ),
        alias("another server: not this alias", "k1", t(1), false),
    ];

    let base: Vec<u8> = unhex(str_of(&handovers["h0_1"], "signed_hex"));
    let not_canonical = {
        // `v` again, as a two-byte uint where one byte is canonical.
        let at = base
            .windows(3)
            .position(|w| w == [0x61, 0x76, 0x01])
            .unwrap();
        let mut b = base[..at + 2].to_vec();
        b.extend_from_slice(&[0x18, 0x01]);
        b.extend_from_slice(&base[at + 3..]);
        b
    };
    let reject = |name: &str, bytes: &str, error: &str| json!({ "name": name, "hex": bytes, "error": error });
    let rejects = vec![
        reject(
            "signed by new rather than old",
            str_of(&handovers["h1_2_by_new"], "signed_hex"),
            "BadSignature",
        ),
        reject(
            "new equal to old",
            str_of(
                &handover_entry("server", "server", Some("k1"), t(1), 1, "server"),
                "signed_hex",
            ),
            "BadField(\"new\")",
        ),
        reject(
            "a non-deterministic encoding",
            &hex(&not_canonical),
            "Cbor(NotCanonical)",
        ),
        reject(
            "v other than 1",
            str_of(
                &handover_entry("server", "k1", Some("k2"), t(1), 2, "server"),
                "signed_hex",
            ),
            "UnsupportedVersion(2)",
        ),
    ];
    let short_next = {
        let unsigned = map(vec![
            ("v", Some(Value::Uint(1))),
            ("challenge", bytes(&NONCE)),
            ("server_key", bytes(&pk("k1"))),
            ("host", Some(Value::Text(HOST.into()))),
            ("expires", Some(Value::Uint(NOW + 60))),
            ("next", bytes(&commit("k2")[..31])),
        ]);
        entry(proof::SERVER_DOMAIN, json!({}), unsigned, "k1")
    };
    let challenge_rejects = vec![reject(
        "a next that is not 32 bytes",
        str_of(&short_next, "signed_hex"),
        "BadField(\"next\")",
    )];

    let doc = json!({
        "notes": [
            "The server key handover's vectors (server-key-handover.md §10), in identity-test-vectors.json's shape: byte strings are lowercase hex, signature_input_hex = domain || 0x00 || unsigned_hex, and signed_hex is the deterministic CBOR of the unsigned map plus `sig`. Each object names its `signer`.",
            "`server` is identity-test-vectors.json's server key; the others are beyond it. `now` is the client's clock and `skew` is S. Every challenge is for `host`, with `challenge` and `expires` as its fields give them.",
            "`handover_rejects` and `challenge_rejects` must fail to parse with `error`.",
            "Each `client` case names handovers and a challenge by their keys here. A `check` is a later fetch of discovery (§5.2-§5.4) by a client pinned at `pinned`, remembering `commitment`, holding a fork record of each handover in `followed` (its old, the SHA-256 of its bytes, its time and its next), and having accepted the fork warning of each in `dismissed`; a `pin` is a first pin (§5.1), and a `repin` a pin again after a warning, which takes no aliases (§5.3). `chain` is server_handovers as served. A client checks `challenge` for `host` first (hotline-ng-auth.md §6.2), and one that fails warns with that error. `expect` is what it does: keep its pin, follow to `key` taking `commitment` and adding `followed` to its records, pin taking `commitment` and adding `aliases`, or warn, naming the conflicting `handover` of a fork. Everything in `expect` binds but a warning's `reason`, which names the check of this implementation that failed.",
            "Each `scope` case asks whether a line or article whose in.server is `server` and whose `sent` is given is in scope under the alias the handover `alias` keeps (§5.5).",
        ],
        "now": NOW,
        "skew": SKEW,
        "host": HOST,
        "keys": keys,
        "handovers": handovers,
        "challenges": challenges,
        "handover_rejects": rejects,
        "challenge_rejects": challenge_rejects,
        "client": client,
        "scope": scope,
    });
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut out,
        serde_json::ser::PrettyFormatter::with_indent(b" "),
    );
    doc.serialize(&mut ser).unwrap();
    out.push(b'\n');
    std::fs::write(PATH, out).unwrap();
}

// --- the checks ----------------------------------------------------------

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

fn key(v: &Json, name: &str) -> ServerKey {
    let k = &v["keys"][name];
    let key = ServerKey::from_seed(&unhex32(str_of(k, "seed_hex")));
    assert_eq!(key.public(), unhex32(str_of(k, "public_hex")), "{name}");
    key
}

fn signed_of(v: &Json, kind: &str, name: &str) -> Vec<u8> {
    unhex(str_of(&v[kind][name], "signed_hex"))
}

/// Every published field of a signed object, not only `signed_hex`.
fn check_signed(v: &Json, e: &Json) {
    let domain = str_of(e, "domain");
    let unsigned = unhex(str_of(e, "unsigned_hex"));
    let mut input = domain.as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(&unsigned);
    assert_eq!(unhex(str_of(e, "signature_input_hex")), input, "{domain}");
    let value = cbor::decode_canonical(&unhex(str_of(e, "signed_hex"))).unwrap();
    assert_eq!(cbor::encode(&value.without("sig")), unsigned, "{domain}");
    let sig = unhex(str_of(e, "signature_hex"));
    assert_eq!(value.get("sig"), Some(&Value::Bytes(sig.clone())));
    let signer = key(v, str_of(e, "signer")).public();
    hl_identity::keys::verify_domain(&signer, domain, &unsigned, &sig.try_into().unwrap()).unwrap();
}

#[test]
fn handover_objects() {
    let v = vectors();
    for (name, e) in v["handovers"].as_object().unwrap() {
        check_signed(&v, e);
        assert_eq!(str_of(e, "domain"), handover::DOMAIN);
        let f = &e["fields"];
        let h = Handover {
            old: unhex32(str_of(f, "old")),
            new: unhex32(str_of(f, "new")),
            next: opt32(&f["next"]),
            time: f["time"].as_u64().unwrap(),
        };
        let signed = signed_of(&v, "handovers", name);
        let signer = key(&v, str_of(e, "signer"));
        if signer.public() == h.old {
            assert_eq!(h.sign(&signer).unwrap(), signed, "{name}");
            assert_eq!(Handover::parse(&signed).unwrap(), h, "{name}");
        } else {
            assert_eq!(
                Handover::parse(&signed),
                Err(hl_identity::Error::BadSignature)
            );
        }
    }
}

#[test]
fn challenge_objects() {
    let v = vectors();
    for (name, e) in v["challenges"].as_object().unwrap() {
        check_signed(&v, e);
        assert_eq!(str_of(e, "domain"), proof::SERVER_DOMAIN);
        let f = &e["fields"];
        let signed = signed_of(&v, "challenges", name);
        let next = opt32(&f["next"]);
        let expires = f["expires"].as_u64().unwrap();
        let challenge = unhex32(str_of(f, "challenge"));
        assert_eq!(
            ServerChallenge::sign(
                &key(&v, str_of(e, "signer")),
                &challenge,
                str_of(f, "host"),
                expires,
                next.as_ref()
            )
            .unwrap(),
            signed,
            "{name}"
        );
        let c = ServerChallenge::parse(&signed).unwrap();
        assert_eq!(c.server_key, unhex32(str_of(f, "server_key")));
        assert_eq!((c.challenge, c.expires, c.next), (challenge, expires, next));
    }
}

#[test]
fn rejects() {
    let v = vectors();
    for r in v["handover_rejects"].as_array().unwrap() {
        let err = Handover::parse(&unhex(str_of(r, "hex"))).unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            str_of(r, "error"),
            "{}",
            str_of(r, "name")
        );
    }
    for r in v["challenge_rejects"].as_array().unwrap() {
        let err = ServerChallenge::parse(&unhex(str_of(r, "hex"))).unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            str_of(r, "error"),
            "{}",
            str_of(r, "name")
        );
    }
}

fn record(v: &Json, name: &str) -> Followed {
    let bytes = signed_of(v, "handovers", name);
    let h = Handover::parse(&bytes).unwrap();
    Followed {
        old: h.old,
        sha256: Sha256::digest(&bytes).into(),
        time: h.time,
        next: h.next,
    }
}

fn names(j: &Json) -> Vec<&str> {
    j.as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect()
}

fn records(v: &Json, j: &Json) -> Vec<Followed> {
    names(j).into_iter().map(|n| record(v, n)).collect()
}

fn hash_of(v: &Json, name: &str) -> [u8; 32] {
    Sha256::digest(signed_of(v, "handovers", name)).into()
}

/// What a case decided, in the file's form, so that `expect` is compared
/// whole.
fn decide(v: &Json, case: &Json) -> Json {
    let now = v["now"].as_u64().unwrap();
    let chain: Vec<Vec<u8>> = names(&case["chain"])
        .into_iter()
        .map(|n| signed_of(v, "handovers", n))
        .collect();
    let challenge =
        ServerChallenge::parse(&signed_of(v, "challenges", str_of(case, "challenge"))).unwrap();
    if let Err(e) = challenge.check(
        &challenge.challenge,
        &challenge.server_key,
        str_of(case, "host"),
        now,
        v["skew"].as_u64().unwrap(),
    ) {
        return warn(&format!("{e:?}"));
    }
    let followed = records(v, &case["followed"]);
    let dismissed: Vec<[u8; 32]> = names(&case["dismissed"])
        .into_iter()
        .map(|n| hash_of(v, n))
        .collect();
    let key_name = |key: &[u8; 32]| -> String {
        let keys = v["keys"].as_object().unwrap();
        let (name, _) = keys
            .iter()
            .find(|(_, k)| unhex32(str_of(k, "public_hex")) == *key)
            .unwrap();
        name.clone()
    };
    let named = |sha256: &[u8; 32]| -> String {
        let (name, _) = v["handovers"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(name, _)| hash_of(v, name) == *sha256)
            .expect("a handover in the file");
        name.clone()
    };
    let handover_names = |got: &[Followed]| -> Vec<String> {
        got.iter()
            .map(|f| {
                let name = named(&f.sha256);
                assert_eq!(record(v, &name), *f);
                name
            })
            .collect()
    };
    let fork = |sha256: &[u8; 32]| json!({ "outcome": "warn", "reason": "Fork", "handover": named(sha256) });
    let hex32 = |c: Option<[u8; 32]>| c.map(|c| hex(&c));
    let pinned_as = |aliases: &[Followed]| {
        json!({
            "outcome": "pin",
            "commitment": hex32(challenge.next),
            "aliases": handover_names(aliases),
        })
    };
    match str_of(case, "kind") {
        "pin" => {
            assert!(
                followed.is_empty() && dismissed.is_empty(),
                "a first pin holds no records"
            );
            return pinned_as(&handover::pin(&chain, &challenge, now));
        }
        "repin" => {
            return match handover::repin(&chain, &followed, &dismissed) {
                Ok(()) => pinned_as(&[]),
                Err(Warning::Fork { sha256 }) => fork(&sha256),
                Err(w) => panic!("a re-pin warns only of a fork: {w:?}"),
            };
        }
        _ => {}
    }
    let pinned = Pinned {
        key: unhex32(str_of(&v["keys"][str_of(case, "pinned")], "public_hex")),
        commitment: opt32(&case["commitment"]),
        followed: &followed,
        dismissed: &dismissed,
    };
    match handover::check(&pinned, &chain, &challenge, now) {
        Verdict::Keep => json!({ "outcome": "keep" }),
        Verdict::Follow {
            key,
            commitment,
            followed,
        } => json!({
            "outcome": "follow",
            "key": key_name(&key),
            "commitment": hex32(commitment),
            "followed": handover_names(&followed),
        }),
        Verdict::Warn(Warning::Fork { sha256 }) => fork(&sha256),
        Verdict::Warn(w) => warn(&format!("{w:?}")),
    }
}

#[test]
fn client_cases() {
    let v = vectors();
    for case in v["client"].as_array().unwrap() {
        assert_eq!(decide(&v, case), case["expect"], "{}", str_of(case, "name"));
    }
}

#[test]
fn scope_cases() {
    let v = vectors();
    for case in v["scope"].as_array().unwrap() {
        let alias = record(&v, str_of(case, "alias"));
        let server = unhex32(str_of(&v["keys"][str_of(case, "server")], "public_hex"));
        assert_eq!(
            alias.covers(&server, case["sent"].as_u64().unwrap()),
            case["expect"].as_bool().unwrap(),
            "{}",
            str_of(case, "name")
        );
    }
}
