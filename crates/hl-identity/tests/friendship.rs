//! The friendship objects' vectors in `docs/identity-test-vectors.json`
//! (`docs/proposals/friendship-objects.md` §6). The generator below
//! signs every object without this crate's signers, writes each outcome
//! as the spec states it, never as this crate decides it, and adds them
//! to the file beside what is already there, which it leaves as it was.
//! The checks hold the crate to the file: objects re-sign to the exact
//! bytes and parse back to their fields, rejects fail at the stated step,
//! and every read decides as the file says.
//!
//! Regenerate with
//! `cargo test -p hl-identity --test friendship -- --ignored generate`.

use std::collections::HashMap;
use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::friendship::{self, Held, Refused};
use hl_identity::registrar::ROTATE_DOMAIN;
use hl_identity::{
    cert, Acceptance, DeviceCert, DeviceKey, Fingerprint, Friendship, IdentityKey, Offer, Pair,
    Rotation, Withdrawal,
};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../docs/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/identity-test-vectors.json"
);

const DAY: u64 = 86_400;
const SKEW: u64 = 600;
/// message_cert's window.
const ISSUED: u64 = 1_757_116_800;
const EXPIRES: u64 = 1_764_892_800;
/// The offer.
const T0: u64 = 1_757_117_000;
/// The withdrawals' cutoff.
const BEFORE: u64 = T0 + 3600;
/// `rotate`'s time, and `rotate_successor`'s.
const ROTATED: u64 = 1_757_203_240;
const ROTATED_AGAIN: u64 = ROTATED + DAY;
const NOW: u64 = 1_757_376_000;

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

fn u64_of(j: &Json, k: &str) -> u64 {
    j[k].as_u64().unwrap_or_else(|| panic!("missing u64 {k}"))
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

// --- the generator -------------------------------------------------------

fn seed(name: &str) -> [u8; 32] {
    let b = match name {
        "identity" => 0x01,
        "device" => 0x02,
        "successor" => 0x04,
        "other" => 0x07,
        "other_device" => 0x08,
        "successor_successor" => 0x09,
        other => panic!("no seed for {other}"),
    };
    [b; 32]
}

fn pk(name: &str) -> [u8; 32] {
    SigningKey::from_bytes(&seed(name))
        .verifying_key()
        .to_bytes()
}

fn fp(name: &str) -> [u8; 32] {
    sha(&pk(name))
}

#[derive(Clone)]
enum F {
    U(u64),
    B(Vec<u8>),
}

type Fields = Vec<(&'static str, F)>;

fn set(mut fields: Fields, key: &'static str, to: F) -> Fields {
    fields.retain(|(k, _)| *k != key);
    fields.push((key, to));
    fields
}

fn input(domain: &str, body: &[u8]) -> Vec<u8> {
    [domain.as_bytes(), &[0], body].concat()
}

fn sig(signer: &str, input: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&seed(signer)).sign(input).to_bytes()
}

fn unsigned(fields: &Fields) -> Value {
    map(fields
        .iter()
        .map(|(k, f)| {
            let v = match f {
                F::U(n) => Value::Uint(*n),
                F::B(b) => Value::Bytes(b.clone()),
            };
            (*k, Some(v))
        })
        .collect())
}

fn with_entries(v: Value, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let Value::Map(mut entries) = v else {
        unreachable!()
    };
    for (k, b) in extra {
        entries.push((Value::Text((*k).into()), Value::Bytes(b.to_vec())));
    }
    cbor::encode(&Value::Map(entries))
}

fn fields_json(fields: &Fields) -> Json {
    Json::Object(
        fields
            .iter()
            .map(|(k, f)| {
                let v = match f {
                    F::U(n) => json!(n),
                    F::B(b) => json!(hex(b)),
                };
                (k.to_string(), v)
            })
            .collect(),
    )
}

/// The file's shape for a signed object, and its bytes.
fn signed(domain: &str, fields: &Fields, signer: &str) -> (Json, Vec<u8>) {
    let v = unsigned(fields);
    let body = cbor::encode(&v);
    let input = input(domain, &body);
    let s = sig(signer, &input);
    let bytes = with_entries(v, &[("sig", &s)]);
    let e = json!({
        "domain": domain,
        "signer": signer,
        "fields": fields_json(fields),
        "unsigned_hex": hex(&body),
        "signature_input_hex": hex(&input),
        "signature_hex": hex(&s),
        "signed_hex": hex(&bytes),
    });
    (e, bytes)
}

fn raw(domain: &str, fields: &Fields, signer: &str) -> Vec<u8> {
    signed(domain, fields, signer).1
}

const OFFER: &str = "hl-identity/friend-offer/v1";
const ACCEPT: &str = "hl-identity/friend-accept/v1";
const WITHDRAW: &str = "hl-identity/friend-withdraw/v1";
const PAIR: &str = "hl-identity/friend-pair/v1";
const CERT: &str = "hl-identity/device-cert/v1";

fn cert_f(identity: &str, device: &str, issued: u64, expires: u64, caps: u64) -> Fields {
    let enc = DeviceKey::from_seed(&seed(device)).public_enc();
    vec![
        ("v", F::U(1)),
        ("identity", F::B(pk(identity).to_vec())),
        ("device", F::B(pk(device).to_vec())),
        ("device_enc", F::B(enc.to_vec())),
        ("issued", F::U(issued)),
        ("expires", F::U(expires)),
        ("caps", F::U(caps)),
    ]
}

fn offer_f(time: u64, expires: u64, id: u8, cert: &[u8]) -> Fields {
    vec![
        ("v", F::U(1)),
        ("from", F::B(pk("identity").to_vec())),
        ("to", F::B(fp("other").to_vec())),
        ("time", F::U(time)),
        ("expires", F::U(expires)),
        ("id", F::B(vec![id; 16])),
        ("cert", F::B(cert.to_vec())),
    ]
}

fn accept_f(offer: &[u8], from: &str, time: u64, cert: &[u8]) -> Fields {
    vec![
        ("v", F::U(1)),
        ("offer", F::B(sha(offer).to_vec())),
        ("from", F::B(pk(from).to_vec())),
        ("time", F::U(time)),
        ("cert", F::B(cert.to_vec())),
    ]
}

fn pair_input(a: &str, b: &str) -> Vec<u8> {
    let (x, y) = (fp(a), fp(b));
    let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
    [PAIR.as_bytes(), &[0], &lo, &hi].concat()
}

fn pair_hash(a: &str, b: &str) -> [u8; 32] {
    sha(&pair_input(a, b))
}

fn withdraw_f(
    from: &str,
    pair: [u8; 32],
    party: Option<&str>,
    before: u64,
    time: u64,
    cert: &[u8],
) -> Fields {
    let mut f = vec![
        ("v", F::U(1)),
        ("from", F::B(pk(from).to_vec())),
        ("pair", F::B(pair.to_vec())),
        ("before", F::U(before)),
        ("time", F::U(time)),
        ("cert", F::B(cert.to_vec())),
    ];
    if let Some(p) = party {
        f.push(("party", F::B(fp(p).to_vec())));
    }
    f
}

fn array(items: &[&[u8]]) -> Vec<u8> {
    cbor::encode(&Value::Array(
        items.iter().map(|b| Value::Bytes(b.to_vec())).collect(),
    ))
}

#[derive(Default)]
struct Objects {
    json: serde_json::Map<String, Json>,
    bytes: HashMap<String, Vec<u8>>,
}

impl Objects {
    fn add(
        &mut self,
        name: &str,
        kind: &str,
        domain: &str,
        fields: Fields,
        signer: &str,
    ) -> Vec<u8> {
        let (mut e, b) = signed(domain, &fields, signer);
        e["object"] = json!(kind);
        self.json.insert(name.into(), e);
        self.bytes.insert(name.into(), b.clone());
        b
    }

    fn friendship(&mut self, name: &str, offer: &str, acceptance: &str) -> Vec<u8> {
        let a = array(&[&self.bytes[offer], &self.bytes[acceptance]]);
        self.json.insert(
            name.into(),
            json!({
                "object": "friendship",
                "offer": offer,
                "acceptance": acceptance,
                "array_hex": hex(&a),
                "hash_hex": hex(&sha(&a)),
            }),
        );
        a
    }
}

fn refusal(step: u8, error: &str) -> (Json, Option<&str>) {
    (json!(step), Some(error))
}

fn accepted() -> (Json, Option<&'static str>) {
    (json!("accepted"), None)
}

fn reject(name: &str, object: &str, bytes: &[u8], step: u8, error: &str) -> Json {
    json!({ "name": name, "object": object, "hex": hex(bytes), "step": step, "error": error })
}

/// A read against pair(identity, other), at the file's `now`, with no
/// rotation applied and nothing held, unless `edit` says otherwise.
fn read(
    name: &str,
    object: &str,
    vector: &str,
    (expect, error): (Json, Option<&str>),
    edit: impl FnOnce(&mut Json),
) -> Json {
    let mut r = json!({
        "name": name,
        "object": object,
        "vector": vector,
        "pair": [hex(&fp("identity")), hex(&fp("other"))],
        "rotations": [],
        "withdrawals": [],
        "expect": expect,
    });
    if let Some(e) = error {
        r["error"] = json!(e);
    }
    edit(&mut r);
    r
}

/// A rotation record in `rotate`'s shape, `sig` by `from` and `ack` by
/// `to`.
fn rotation(from: &str, to: &str, time: u64, note: &str) -> Json {
    let fields: Fields = vec![
        ("v", F::U(1)),
        ("identity", F::B(pk(from).to_vec())),
        ("successor", F::B(pk(to).to_vec())),
        ("time", F::U(time)),
    ];
    let rot = unsigned(&fields);
    let body = cbor::encode(&rot);
    let sig_input = input(ROTATE_DOMAIN, &body);
    let ack_input = input(&format!("{ROTATE_DOMAIN}/ack"), &body);
    let (s, a) = (sig(from, &sig_input), sig(to, &ack_input));
    json!({
        "ack_hex": hex(&a),
        "ack_input_hex": hex(&ack_input),
        "domain": ROTATE_DOMAIN,
        "fields": fields_json(&fields),
        "note": note,
        "signature_hex": hex(&s),
        "signature_input_hex": hex(&sig_input),
        "signed_hex": hex(&with_entries(rot, &[("sig", &s), ("ack", &a)])),
        "unsigned_hex": hex(&body),
    })
}

fn held(names: &'static [&'static str]) -> impl FnOnce(&mut Json) {
    move |r| r["withdrawals"] = json!(names)
}

fn rotated(names: &'static [&'static str]) -> impl FnOnce(&mut Json) {
    move |r| r["rotations"] = json!(names)
}

#[test]
#[ignore = "writes docs/identity-test-vectors.json"]
fn generate() {
    let text = std::fs::read_to_string(PATH).unwrap();
    let mut file: J = serde_json::from_str(&text).unwrap();
    assert_eq!(
        render(&file),
        text,
        "the file is written as this generator writes it"
    );
    let old: Json = serde_json::from_str(&text).unwrap();
    let message_cert = unhex(str_of(&old["message_cert"], "signed_hex"));
    assert_eq!(
        message_cert,
        raw(
            CERT,
            &cert_f("identity", "device", ISSUED, EXPIRES, 3),
            "identity"
        ),
        "message_cert is keys.identity's certificate of keys.device"
    );
    assert_eq!(u64_of(&old["rotate"]["fields"], "time"), ROTATED);
    assert_eq!(
        str_of(&old["rotate"]["fields"], "successor"),
        hex(&pk("successor"))
    );

    let mut o = Objects::default();
    let cert_other = o.add(
        "cert_other",
        "device_cert",
        CERT,
        cert_f("other", "other_device", ISSUED, EXPIRES, 3),
        "other",
    );
    let cert_successor = o.add(
        "cert_successor",
        "device_cert",
        CERT,
        cert_f("successor", "device", ISSUED, EXPIRES, 3),
        "successor",
    );
    let cert_successor_successor = o.add(
        "cert_successor_successor",
        "device_cert",
        CERT,
        cert_f("successor_successor", "device", ISSUED, EXPIRES, 3),
        "successor_successor",
    );
    let cert_short = o.add(
        "cert_short",
        "device_cert",
        CERT,
        cert_f("identity", "device", ISSUED, ISSUED + DAY, 3),
        "identity",
    );

    let offer_fields = offer_f(T0, T0 + 7 * DAY, 0x51, &message_cert);
    let offer = o.add("offer", "offer", OFFER, offer_fields.clone(), "device");
    let accept_fields = accept_f(&offer, "other", T0 + 60, &cert_other);
    let acceptance = o.add(
        "acceptance",
        "acceptance",
        ACCEPT,
        accept_fields.clone(),
        "other_device",
    );
    let friendship = o.friendship("friendship", "offer", "acceptance");
    let offer_again = o.add(
        "offer_again",
        "offer",
        OFFER,
        offer_f(BEFORE + 600, BEFORE + 600 + 7 * DAY, 0x52, &message_cert),
        "device",
    );
    o.add(
        "acceptance_again",
        "acceptance",
        ACCEPT,
        accept_f(&offer_again, "other", BEFORE + 660, &cert_other),
        "other_device",
    );
    o.friendship("friendship_again", "offer_again", "acceptance_again");
    o.add(
        "acceptance_later",
        "acceptance",
        ACCEPT,
        accept_f(&offer, "other", BEFORE + 300, &cert_other),
        "other_device",
    );
    o.friendship("friendship_reaccepted", "offer", "acceptance_later");

    let pair = pair_hash("identity", "other");
    let by_offerer = withdraw_f("identity", pair, None, BEFORE, BEFORE + 60, &message_cert);
    o.add(
        "withdrawal_by_offerer",
        "withdrawal",
        WITHDRAW,
        by_offerer.clone(),
        "device",
    );
    o.add(
        "withdrawal_by_offeree",
        "withdrawal",
        WITHDRAW,
        withdraw_f(
            "other",
            pair,
            Some("identity"),
            BEFORE,
            BEFORE + 120,
            &cert_other,
        ),
        "other_device",
    );
    o.add(
        "withdrawal_offeree_own",
        "withdrawal",
        WITHDRAW,
        withdraw_f("other", pair, None, BEFORE, BEFORE + 180, &cert_other),
        "other_device",
    );
    for (name, from, party, before, time, cert, signer) in [
        (
            "withdrawal_at_offer",
            "identity",
            None,
            T0,
            T0,
            &message_cert,
            "device",
        ),
        (
            "withdrawal_party_outside",
            "identity",
            Some("successor_successor"),
            BEFORE,
            BEFORE + 240,
            &message_cert,
            "device",
        ),
        (
            "withdrawal_short_cert",
            "identity",
            None,
            BEFORE,
            BEFORE + 300,
            &cert_short,
            "device",
        ),
        (
            "withdrawal_successor",
            "successor",
            Some("identity"),
            BEFORE,
            ROTATED + 600,
            &cert_successor,
            "device",
        ),
        (
            "withdrawal_successor_late",
            "successor",
            Some("identity"),
            ROTATED + 1,
            ROTATED + 600,
            &cert_successor,
            "device",
        ),
        (
            "withdrawal_successor_at_rotation",
            "successor",
            Some("identity"),
            ROTATED,
            ROTATED + 600,
            &cert_successor,
            "device",
        ),
        (
            "withdrawal_successor_own",
            "successor",
            None,
            BEFORE,
            ROTATED + 600,
            &cert_successor,
            "device",
        ),
        (
            "withdrawal_offeree_late",
            "other",
            Some("identity"),
            ROTATED + 1,
            ROTATED + 600,
            &cert_other,
            "other_device",
        ),
        (
            "withdrawal_successor_successor",
            "successor_successor",
            Some("identity"),
            BEFORE,
            ROTATED_AGAIN + 600,
            &cert_successor_successor,
            "device",
        ),
    ] {
        o.add(
            name,
            "withdrawal",
            WITHDRAW,
            withdraw_f(from, pair, party, before, time, cert),
            signer,
        );
    }
    let notes = [
        ("offer", "keys.identity offers keys.other a friendship, under message_cert."),
        ("acceptance", "keys.other accepts `offer`, under cert_other."),
        ("withdrawal_by_offerer", "keys.identity on its own account, `party` absent: ends `friendship`, whose offer predates `before`, and leaves `friendship_again` standing."),
        ("withdrawal_by_offeree", "keys.other spreading withdrawal_by_offerer, naming keys.identity as `party`: ends what it ends."),
        ("withdrawal_offeree_own", "keys.other on its own account: ends `friendship`, whose acceptance predates `before`, and leaves `friendship_reaccepted`, the same offer accepted again after it, standing."),
    ];
    for (name, note) in notes {
        o.json[name]["note"] = json!(note);
    }

    let rotate_successor = rotation(
        "successor",
        "successor_successor",
        ROTATED_AGAIN,
        "keys.successor rotating on to keys.successor_successor, as `rotate` takes keys.identity to keys.successor: `sig` by the first and `ack` by the second.",
    );
    let rotate_back = rotation(
        "successor",
        "identity",
        ROTATED_AGAIN,
        "keys.successor rotating back to keys.identity: with `rotate`, a chain that loops.",
    );
    let rotate_fork = rotation(
        "identity",
        "successor_successor",
        ROTATED,
        "keys.identity rotating to keys.successor_successor: with `rotate`, a chain that forks.",
    );

    let pairs: Vec<Json> = [
        ("the offerer's fingerprint the lesser", "identity", "other"),
        ("the offerer's fingerprint the greater", "other", "identity"),
    ]
    .into_iter()
    .map(|(name, offerer, offeree)| {
        json!({
            "name": name,
            "offerer_fingerprint_hex": hex(&fp(offerer)),
            "offeree_fingerprint_hex": hex(&fp(offeree)),
            "input_hex": hex(&pair_input(offerer, offeree)),
            "pair_hex": hex(&pair_hash(offerer, offeree)),
        })
    })
    .collect();

    // Certificates the rejects carry.
    let login_only = |id: &str, dev: &str| raw(CERT, &cert_f(id, dev, ISSUED, EXPIRES, 1), id);
    let big = |id: &str, dev: &str| {
        let f = set(
            cert_f(id, dev, ISSUED, EXPIRES, 3),
            "pad",
            F::B(vec![0; 300]),
        );
        raw(CERT, &f, id)
    };
    let pad = F::B(vec![0; 1024]);

    let mut rejects = Vec::new();
    for (name, bytes, step, error) in [
        (
            "an offer signed under the acceptance's domain",
            raw(ACCEPT, &offer_fields, "device"),
            5,
            "BadSignature",
        ),
        (
            "an offer signed under hl-identity/message/v1",
            raw("hl-identity/message/v1", &offer_fields, "device"),
            5,
            "BadSignature",
        ),
        (
            "an offer over 1 KiB",
            raw(
                OFFER,
                &set(offer_fields.clone(), "pad", pad.clone()),
                "device",
            ),
            1,
            "TooLarge",
        ),
        (
            "an offer whose v is 2",
            raw(OFFER, &set(offer_fields.clone(), "v", F::U(2)), "device"),
            1,
            "UnsupportedVersion(2)",
        ),
        (
            "an offer whose to is its own from's fingerprint",
            raw(
                OFFER,
                &set(offer_fields.clone(), "to", F::B(fp("identity").to_vec())),
                "device",
            ),
            1,
            "BadField(\"to\")",
        ),
        (
            "an offer whose expires is more than 30 days after its time",
            raw(
                OFFER,
                &set(offer_fields.clone(), "expires", F::U(T0 + 30 * DAY + 1)),
                "device",
            ),
            1,
            "BadField(\"expires\")",
        ),
        (
            "an offer whose expires is its time",
            raw(
                OFFER,
                &set(offer_fields.clone(), "expires", F::U(T0)),
                "device",
            ),
            1,
            "BadField(\"expires\")",
        ),
        (
            "an offer whose certificate is for another identity",
            raw(
                OFFER,
                &set(offer_fields.clone(), "cert", F::B(cert_other.clone())),
                "other_device",
            ),
            4,
            "KeyMismatch",
        ),
        (
            "an offer whose certificate lacks bit 1",
            raw(
                OFFER,
                &set(
                    offer_fields.clone(),
                    "cert",
                    F::B(login_only("identity", "device")),
                ),
                "device",
            ),
            4,
            "CapabilityMissing",
        ),
        (
            "an offer whose certificate is over 512 bytes",
            raw(
                OFFER,
                &set(
                    offer_fields.clone(),
                    "cert",
                    F::B(big("identity", "device")),
                ),
                "device",
            ),
            4,
            "BadField(\"cert\")",
        ),
    ] {
        rejects.push(reject(name, "offer", &bytes, step, error));
    }

    let with_accept = |f: Fields| array(&[&offer, &raw(ACCEPT, &f, "other_device")]);
    let brief = raw(
        OFFER,
        &offer_f(T0, T0 + 3600, 0x53, &message_cert),
        "device",
    );
    let forged = raw(
        OFFER,
        &set(
            offer_fields.clone(),
            "cert",
            F::B(raw(
                CERT,
                &cert_f("identity", "device", ISSUED, EXPIRES, 3),
                "other",
            )),
        ),
        "device",
    );
    let maps = cbor::encode(&Value::Array(vec![
        cbor::decode_canonical(&offer).unwrap(),
        cbor::decode_canonical(&acceptance).unwrap(),
    ]));
    for (name, bytes, step, error) in [
        (
            "an acceptance over 1 KiB",
            with_accept(set(accept_fields.clone(), "pad", pad.clone())),
            1,
            "TooLarge",
        ),
        (
            "an acceptance whose v is 2",
            with_accept(set(accept_fields.clone(), "v", F::U(2))),
            1,
            "UnsupportedVersion(2)",
        ),
        (
            "an acceptance whose offer is another offer's hash",
            with_accept(set(
                accept_fields.clone(),
                "offer",
                F::B(sha(&offer_again).to_vec()),
            )),
            2,
            "BadField(\"offer\")",
        ),
        (
            "an acceptance whose from is not the offer's to",
            array(&[
                &offer,
                &raw(
                    ACCEPT,
                    &accept_f(&offer, "successor", T0 + 60, &cert_successor),
                    "device",
                ),
            ]),
            2,
            "KeyMismatch",
        ),
        (
            "an acceptance dated before the offer's time",
            with_accept(set(accept_fields.clone(), "time", F::U(T0 - 1))),
            3,
            "BadField(\"time\")",
        ),
        (
            "an acceptance dated after the offer's expires",
            array(&[
                &brief,
                &raw(
                    ACCEPT,
                    &accept_f(&brief, "other", T0 + 3601, &cert_other),
                    "other_device",
                ),
            ]),
            3,
            "BadField(\"time\")",
        ),
        (
            "the array reversed",
            array(&[&acceptance, &offer]),
            1,
            "MissingField(\"to\")",
        ),
        (
            "the array with a third element",
            array(&[&offer, &acceptance, &acceptance]),
            1,
            "BadField(\"friendship\")",
        ),
        (
            "the array holding maps in place of byte strings",
            maps,
            1,
            "BadField(\"friendship\")",
        ),
        (
            "the array of indefinite length",
            [&[0x9f][..], &friendship[1..], &[0xff]].concat(),
            1,
            "Cbor(Unsupported(159))",
        ),
        (
            "the array with a head not in its shortest form",
            [&[0x98, 0x02][..], &friendship[1..]].concat(),
            1,
            "Cbor(NotCanonical)",
        ),
        (
            "a friendship whose certificate carries a bad identity signature",
            array(&[
                &forged,
                &raw(
                    ACCEPT,
                    &accept_f(&forged, "other", T0 + 60, &cert_other),
                    "other_device",
                ),
            ]),
            5,
            "BadSignature",
        ),
        (
            "an acceptance whose certificate is for another identity",
            array(&[
                &offer,
                &raw(
                    ACCEPT,
                    &set(accept_fields.clone(), "cert", F::B(message_cert.clone())),
                    "device",
                ),
            ]),
            4,
            "KeyMismatch",
        ),
        (
            "an acceptance whose certificate lacks bit 1",
            with_accept(set(
                accept_fields.clone(),
                "cert",
                F::B(login_only("other", "other_device")),
            )),
            4,
            "CapabilityMissing",
        ),
        (
            "an acceptance whose certificate is over 512 bytes",
            with_accept(set(
                accept_fields.clone(),
                "cert",
                F::B(big("other", "other_device")),
            )),
            4,
            "BadField(\"cert\")",
        ),
    ] {
        rejects.push(reject(name, "friendship", &bytes, step, error));
    }

    // Two byte strings at the bound and one byte more: refused by size
    // before it is decoded, where decoding would say Trailing.
    let over = [
        &[0x82, 0x59, 0x04, 0x00][..],
        &[0; 1024],
        &[0x59, 0x04, 0x00],
        &[0; 1024],
        &[0],
    ]
    .concat();
    rejects.push(reject(
        "a friendship over 2,055 bytes",
        "friendship",
        &over,
        1,
        "TooLarge",
    ));

    let w = |f: Fields| raw(WITHDRAW, &f, "device");
    for (name, bytes, step, error) in [
        (
            "a withdrawal signed under hl-identity/vouch-withdraw/v1",
            raw("hl-identity/vouch-withdraw/v1", &by_offerer, "device"),
            6,
            "BadSignature",
        ),
        (
            "a withdrawal over 1 KiB",
            w(set(by_offerer.clone(), "pad", pad.clone())),
            1,
            "TooLarge",
        ),
        (
            "a withdrawal whose v is 2",
            w(set(by_offerer.clone(), "v", F::U(2))),
            1,
            "UnsupportedVersion(2)",
        ),
        (
            "a withdrawal whose before is after its time",
            w(set(by_offerer.clone(), "before", F::U(BEFORE + 61))),
            2,
            "BadField(\"before\")",
        ),
        (
            "a withdrawal whose party is its own from's fingerprint",
            w(set(
                by_offerer.clone(),
                "party",
                F::B(fp("identity").to_vec()),
            )),
            1,
            "BadField(\"party\")",
        ),
        (
            "a withdrawal whose certificate is for another identity",
            raw(
                WITHDRAW,
                &set(by_offerer.clone(), "cert", F::B(cert_other.clone())),
                "other_device",
            ),
            5,
            "KeyMismatch",
        ),
        (
            "a withdrawal whose certificate lacks bit 1",
            w(set(
                by_offerer.clone(),
                "cert",
                F::B(login_only("identity", "device")),
            )),
            5,
            "CapabilityMissing",
        ),
        (
            "a withdrawal whose certificate is over 512 bytes",
            w(set(
                by_offerer.clone(),
                "cert",
                F::B(big("identity", "device")),
            )),
            5,
            "BadField(\"cert\")",
        ),
    ] {
        rejects.push(reject(name, "withdrawal", &bytes, step, error));
    }

    let reads = vec![
        read("the offer", "offer", "offer", accepted(), |_| {}),
        read("the friendship", "friendship", "friendship", accepted(), |_| {}),
        read("the offer, dated past now + S", "offer", "offer", refusal(3, "ClockSkew"), |r| r["now"] = json!(T0 - SKEW - 1)),
        read("the friendship, its acceptance dated past now + S", "friendship", "friendship", refusal(3, "ClockSkew"), |r| r["now"] = json!(T0 + 60 - SKEW - 1)),
        read("the offer, pending, which its offerer's withdrawal ends", "offer", "offer", refusal(6, "Withdrawn"), held(&["withdrawal_by_offerer"])),
        read("the offer, pending, which the offeree's own withdrawal leaves open", "offer", "offer", accepted(), held(&["withdrawal_offeree_own"])),
        read("the friendship, which the offerer's withdrawal ends", "friendship", "friendship", refusal(6, "Withdrawn"), held(&["withdrawal_by_offerer"])),
        read("a friendship from a later offer, which the offerer's withdrawal leaves standing", "friendship", "friendship_again", accepted(), held(&["withdrawal_by_offerer"])),
        read("the friendship, which the offeree's spread of the offerer's withdrawal ends", "friendship", "friendship", refusal(6, "Withdrawn"), held(&["withdrawal_by_offeree"])),
        read("a friendship from a later offer, which the spread leaves standing", "friendship", "friendship_again", accepted(), held(&["withdrawal_by_offeree"])),
        read("the friendship, which the offeree's own withdrawal ends", "friendship", "friendship", refusal(6, "Withdrawn"), held(&["withdrawal_offeree_own"])),
        read("the offer accepted again after the offeree's own withdrawal, standing", "friendship", "friendship_reaccepted", accepted(), held(&["withdrawal_offeree_own"])),
        read("the offerer's withdrawal", "withdrawal", "withdrawal_by_offerer", accepted(), |_| {}),
        read("the offeree's withdrawal naming the offerer", "withdrawal", "withdrawal_by_offeree", accepted(), |_| {}),
        read("the offeree's own withdrawal", "withdrawal", "withdrawal_offeree_own", accepted(), |_| {}),
        read("a withdrawal dated past now + S", "withdrawal", "withdrawal_by_offerer", refusal(2, "ClockSkew"), |r| r["now"] = json!(BEFORE + 60 - SKEW - 1)),
        read("a withdrawal whose pair is another pair's hash", "withdrawal", "withdrawal_by_offerer", refusal(3, "KeyMismatch"), |r| r["pair"] = json!([hex(&fp("identity")), hex(&fp("successor"))])),
        read("a withdrawal whose from is outside the pair: a successor where no rotation is applied", "withdrawal", "withdrawal_successor", refusal(4, "KeyMismatch"), |_| {}),
        read("a withdrawal whose party is outside the pair", "withdrawal", "withdrawal_party_outside", refusal(4, "BadField(\"party\")"), |_| {}),
        read("across one rotation, the successor's withdrawal naming its predecessor", "withdrawal", "withdrawal_successor", accepted(), rotated(&["rotate"])),
        read("across one rotation, a successor's withdrawal whose before is after the rotation", "withdrawal", "withdrawal_successor_late", refusal(4, "BadField(\"before\")"), rotated(&["rotate"])),
        read("across one rotation, the predecessor's withdrawal", "withdrawal", "withdrawal_by_offerer", refusal(4, "KeyMismatch"), rotated(&["rotate"])),
        read("across two rotations, the middle key's withdrawal naming the first", "withdrawal", "withdrawal_successor", refusal(4, "KeyMismatch"), rotated(&["rotate", "rotate_successor"])),
        read("across two rotations, the last key's withdrawal naming the first", "withdrawal", "withdrawal_successor_successor", accepted(), rotated(&["rotate", "rotate_successor"])),
        read("across one rotation, a successor's withdrawal whose before is the rotation's time", "withdrawal", "withdrawal_successor_at_rotation", accepted(), rotated(&["rotate"])),
        read("across one rotation, a successor's withdrawal on its own account", "withdrawal", "withdrawal_successor_own", refusal(4, "BadField(\"party\")"), rotated(&["rotate"])),
        read("across one rotation, the unrotated party's withdrawal naming the rotated one", "withdrawal", "withdrawal_by_offeree", accepted(), rotated(&["rotate"])),
        read("across one rotation, the unrotated party's withdrawal naming the rotated one with before after the rotation", "withdrawal", "withdrawal_offeree_late", refusal(4, "BadField(\"before\")"), rotated(&["rotate"])),
        read("the same rotation applied twice, which is not a fork", "withdrawal", "withdrawal_successor", accepted(), rotated(&["rotate", "rotate"])),
        read("rotations that fork, leaving no last key", "withdrawal", "withdrawal_successor", refusal(4, "KeyMismatch"), rotated(&["rotate", "rotate_fork"])),
        read("rotations that loop, leaving no last key", "withdrawal", "withdrawal_successor", refusal(4, "KeyMismatch"), rotated(&["rotate", "rotate_back"])),
        read("a withdrawal applied before a rotation still ends its friendship once the rotation is applied", "friendship", "friendship", refusal(6, "Withdrawn"), |r| {
            r["rotations"] = json!(["rotate"]);
            r["withdrawals"] = json!(["withdrawal_by_offerer"]);
            r["note"] = json!("A rule for the caller: a withdrawal held is not checked again when a rotation is applied later. The objects' checks take no rotations for an offer or a friendship, so this case passes by construction; it is here for implementations that would re-check what they hold.");
        }),
        read("a half dated exactly before, which stands", "friendship", "friendship", accepted(), held(&["withdrawal_at_offer"])),
        read("a withdrawal whose before equals its time", "withdrawal", "withdrawal_at_offer", accepted(), |_| {}),
        read("a withdrawal whose certificate expired by now but was valid at its time", "withdrawal", "withdrawal_short_cert", accepted(), |_| {}),
    ];

    let mut window = Vec::new();
    for (name, issued, expires, expect) in [
        ("issued at time + S", T0 + SKEW, T0 + DAY, accepted()),
        (
            "issued at time + S + 1",
            T0 + SKEW + 1,
            T0 + DAY,
            refusal(4, "NotYetValid"),
        ),
        ("time at expires + S", T0 - DAY, T0 - SKEW, accepted()),
        (
            "time at expires + S + 1",
            T0 - DAY,
            T0 - SKEW - 1,
            refusal(4, "Expired"),
        ),
        ("expires equal to issued", T0, T0, refusal(4, "NotYetValid")),
    ] {
        let cert = raw(
            CERT,
            &cert_f("identity", "device", issued, expires, 3),
            "identity",
        );
        let bytes = raw(OFFER, &offer_f(T0, T0 + 7 * DAY, 0x51, &cert), "device");
        let mut c = json!({
            "name": name, "issued": issued, "expires": expires, "time": T0,
            "signed_hex": hex(&bytes), "expect": expect.0,
        });
        if let Some(e) = expect.1 {
            c["error"] = json!(e);
        }
        window.push(c);
    }

    let friends = json!({
        "now": NOW,
        "skew": SKEW,
        "notes": [
            "Friendship objects (proposals/friendship-objects.md). `now` is the checker's clock and `skew` is S.",
            "friend_objects are signed as the objects above are, each naming its `object` (offer, acceptance, withdrawal or device_cert) and its `signer` in `keys`. keys.identity, keys.successor and keys.successor_successor sign with keys.device, under message_cert, cert_successor and cert_successor_successor; keys.other with keys.other_device, under cert_other. A friendship is the array of its offer's and its acceptance's bytes, `array_hex`, named by `hash_hex`, its SHA-256. `rotate` takes keys.identity to keys.successor, and `rotate_successor` keys.successor on to keys.successor_successor.",
            "friend_pairs: `pair_hex` = SHA-256(input_hex), input_hex = \"hl-identity/friend-pair/v1\" || 0x00 || the lesser fingerprint || the greater, however the two are ordered.",
            "friend_rejects must be refused at `step`, checked at `now` with nothing held: an offer alone (§3: step 1 without the array, then 3 to 6), a friendship whole, and a withdrawal by the steps that need no pair (§4: 1, 2, 5 and 6). `error` names this implementation's error; the step binds.",
            "friend_reads check `vector` at `now`, the case's own when it gives one, against the pair's two fingerprints `pair`, the rotation records applied (`rotations`, by name), and the withdrawals held (`withdrawals`, by name, each checked whole against `pair` with no rotation applied, as when it was taken). An offer or a friendship is checked by §3, a withdrawal by all six steps of §4; rotations enter only a withdrawal's step 4, never a withdrawal already held. `expect` is accepted or the step it fails at; `error` as above. A case may carry a `note`.",
            "friend_cert_window: offers like `offer`, each under a certificate of its own, checked at `now`. A certificate is valid at t when `expires` is after `issued`, `issued` <= t + S and t <= `expires` + S.",
        ],
    });

    let keys = json!({
        "other_device": {
            "fingerprint": Fingerprint(fp("other_device")).to_string(),
            "public_enc_hex": hex(&DeviceKey::from_seed(&seed("other_device")).public_enc()),
            "public_hex": hex(&pk("other_device")),
            "seed_hex": hex(&seed("other_device")),
        },
        "successor_successor": {
            "fingerprint": Fingerprint(fp("successor_successor")).to_string(),
            "public_hex": hex(&pk("successor_successor")),
            "seed_hex": hex(&seed("successor_successor")),
        },
    });

    let top = obj_mut(&mut file);
    {
        let (_, k) = top.iter_mut().find(|(k, _)| k == "keys").unwrap();
        let k = obj_mut(k);
        for (name, e) in keys.as_object().unwrap() {
            upsert(k, name, from_json(e), true);
        }
    }
    for (name, e) in [
        ("rotate_successor", rotate_successor),
        ("rotate_back", rotate_back),
        ("rotate_fork", rotate_fork),
        ("friends", friends),
        ("friend_objects", Json::Object(o.json)),
        ("friend_pairs", json!(pairs)),
        ("friend_rejects", json!(rejects)),
        ("friend_reads", json!(reads)),
        ("friend_cert_window", json!(window)),
    ] {
        upsert(top, name, from_json(&e), false);
    }
    std::fs::write(PATH, render(&file)).unwrap();
}

// --- the file as it is written ---------------------------------------------

/// JSON with its objects in the order the file has them, so that adding
/// to the file leaves the rest of it byte for byte as it was.
#[derive(Debug, Clone, PartialEq)]
enum J {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl<'de> Deserialize<'de> for J {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<J, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = J;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unsigned numbers")
            }
            fn visit_unit<E: de::Error>(self) -> Result<J, E> {
                Ok(J::Null)
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<J, E> {
                Ok(J::Bool(b))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<J, E> {
                Ok(J::Num(n))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<J, E> {
                Ok(J::Str(s.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut items = Vec::new();
                while let Some(x) = a.next_element()? {
                    items.push(x);
                }
                Ok(J::Arr(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut entries = Vec::new();
                while let Some(e) = a.next_entry()? {
                    entries.push(e);
                }
                Ok(J::Obj(entries))
            }
        }
        d.deserialize_any(V)
    }
}

/// New entries come from `serde_json`, whose objects are sorted.
fn from_json(j: &Json) -> J {
    match j {
        Json::Null => J::Null,
        Json::Bool(b) => J::Bool(*b),
        Json::Number(n) => J::Num(n.as_u64().expect("unsigned")),
        Json::String(s) => J::Str(s.clone()),
        Json::Array(a) => J::Arr(a.iter().map(from_json).collect()),
        Json::Object(m) => J::Obj(m.iter().map(|(k, v)| (k.clone(), from_json(v))).collect()),
    }
}

fn obj_mut(j: &mut J) -> &mut Vec<(String, J)> {
    match j {
        J::Obj(entries) => entries,
        other => panic!("not an object: {other:?}"),
    }
}

/// Replace `key` where it is, or add it: in key order if `sorted`, else
/// last.
fn upsert(entries: &mut Vec<(String, J)>, key: &str, value: J, sorted: bool) {
    if let Some(e) = entries.iter_mut().find(|(k, _)| k == key) {
        e.1 = value;
        return;
    }
    let at = if sorted {
        entries
            .iter()
            .position(|(k, _)| k.as_str() > key)
            .unwrap_or(entries.len())
    } else {
        entries.len()
    };
    entries.insert(at, (key.into(), value));
}

/// The file's layout: one space of indent per level, and every character
/// outside printable ASCII escaped.
fn render(j: &J) -> String {
    let mut out = String::new();
    write(j, 0, &mut out);
    out.push('\n');
    out
}

fn write(j: &J, depth: usize, out: &mut String) {
    let newline = |depth: usize, out: &mut String| {
        out.push('\n');
        out.push_str(&" ".repeat(depth));
    };
    match j {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Str(s) => escape(s, out),
        J::Arr(items) if items.is_empty() => out.push_str("[]"),
        J::Obj(entries) if entries.is_empty() => out.push_str("{}"),
        J::Arr(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(depth + 1, out);
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.push(']');
        }
        J::Obj(entries) => {
            out.push('{');
            for (i, (k, x)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(depth + 1, out);
                escape(k, out);
                out.push_str(": ");
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.push('}');
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}

// --- the checks ------------------------------------------------------------

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

fn seed_of(v: &Json, name: &str) -> [u8; 32] {
    unhex32(str_of(&v["keys"][name], "seed_hex"))
}

fn now_of(v: &Json) -> u64 {
    u64_of(&v["friends"], "now")
}

fn object_bytes(v: &Json, name: &str) -> Vec<u8> {
    let e = &v["friend_objects"][name];
    match str_of(e, "object") {
        "friendship" => unhex(str_of(e, "array_hex")),
        _ => unhex(str_of(e, "signed_hex")),
    }
}

/// Every published field of a signed object, not only `signed_hex`.
fn check_signed(v: &Json, e: &Json) {
    let domain = str_of(e, "domain");
    let unsigned = unhex(str_of(e, "unsigned_hex"));
    assert_eq!(
        unhex(str_of(e, "signature_input_hex")),
        input(domain, &unsigned)
    );
    let value = cbor::decode_canonical(&unhex(str_of(e, "signed_hex"))).unwrap();
    assert_eq!(cbor::encode(&value.without("sig")), unsigned, "{domain}");
    let sig = unhex(str_of(e, "signature_hex"));
    assert_eq!(value.get("sig"), Some(&Value::Bytes(sig.clone())));
    let signer = unhex32(str_of(&v["keys"][str_of(e, "signer")], "public_hex"));
    hl_identity::keys::verify_domain(&signer, domain, &unsigned, &sig.try_into().unwrap()).unwrap();
}

fn outcome<T>(r: Result<T, Refused>) -> (Json, Option<String>) {
    match r {
        Ok(_) => (json!("accepted"), None),
        Err(r) => (json!(r.step), Some(format!("{:?}", r.error))),
    }
}

fn expected(c: &Json) -> (Json, Option<String>) {
    (c["expect"].clone(), c["error"].as_str().map(str::to_owned))
}

fn fingerprint(j: &Json) -> Fingerprint {
    Fingerprint(unhex32(j.as_str().unwrap()))
}

#[test]
fn friend_keys() {
    let v = vectors();
    let k = &v["keys"];
    let dev = DeviceKey::from_seed(&seed_of(&v, "other_device"));
    assert_eq!(hex(&dev.public()), str_of(&k["other_device"], "public_hex"));
    assert_eq!(
        hex(&dev.public_enc()),
        str_of(&k["other_device"], "public_enc_hex")
    );
    assert_eq!(
        dev.fingerprint().to_string(),
        str_of(&k["other_device"], "fingerprint")
    );
    let id = IdentityKey::from_seed(&seed_of(&v, "successor_successor"));
    assert_eq!(
        hex(&id.public()),
        str_of(&k["successor_successor"], "public_hex")
    );
    assert_eq!(
        id.fingerprint().to_string(),
        str_of(&k["successor_successor"], "fingerprint")
    );
}

#[test]
fn friend_objects() {
    let v = vectors();
    let now = now_of(&v);
    for (name, e) in v["friend_objects"].as_object().unwrap() {
        let f = &e["fields"];
        let b32 = |k: &str| unhex32(str_of(f, k));
        let device = || DeviceKey::from_seed(&seed_of(&v, str_of(e, "signer")));
        let kind = str_of(e, "object");
        if kind != "friendship" {
            check_signed(&v, e);
        }
        let bytes = object_bytes(&v, name);
        match kind {
            "device_cert" => {
                assert_eq!(str_of(e, "domain"), cert::DOMAIN);
                let c = DeviceCert {
                    identity: b32("identity"),
                    device: b32("device"),
                    device_enc: b32("device_enc"),
                    issued: u64_of(f, "issued"),
                    expires: u64_of(f, "expires"),
                    caps: f["caps"].as_u64(),
                    name: None,
                };
                let id = IdentityKey::from_seed(&seed_of(&v, str_of(e, "signer")));
                assert_eq!(c.sign(&id), bytes, "{name}");
                assert_eq!(DeviceCert::parse(&bytes).unwrap(), c, "{name}");
            }
            "offer" => {
                assert_eq!(str_of(e, "domain"), friendship::OFFER_DOMAIN);
                let o = Offer {
                    from: b32("from"),
                    to: Fingerprint(b32("to")),
                    time: u64_of(f, "time"),
                    expires: u64_of(f, "expires"),
                    id: unhex(str_of(f, "id")).try_into().unwrap(),
                    cert: unhex(str_of(f, "cert")),
                };
                assert_eq!(o.sign(&device()).unwrap(), bytes, "{name}");
                assert_eq!(Offer::check(&bytes, now, &[]).unwrap(), o, "{name}");
            }
            "acceptance" => {
                assert_eq!(str_of(e, "domain"), friendship::ACCEPT_DOMAIN);
                let a = Acceptance {
                    offer: b32("offer"),
                    from: b32("from"),
                    time: u64_of(f, "time"),
                    cert: unhex(str_of(f, "cert")),
                };
                assert_eq!(a.sign(&device()).unwrap(), bytes, "{name}");
            }
            "withdrawal" => {
                assert_eq!(str_of(e, "domain"), friendship::WITHDRAW_DOMAIN);
                let w = Withdrawal {
                    from: b32("from"),
                    pair: b32("pair"),
                    party: f["party"].as_str().map(|p| Fingerprint(unhex32(p))),
                    before: u64_of(f, "before"),
                    time: u64_of(f, "time"),
                    cert: unhex(str_of(f, "cert")),
                };
                assert_eq!(w.sign(&device()).unwrap(), bytes, "{name}");
                assert_eq!(
                    Withdrawal::parse(&bytes, now).unwrap().withdrawal(),
                    &w,
                    "{name}"
                );
            }
            "friendship" => {
                let offer = object_bytes(&v, str_of(e, "offer"));
                let acceptance = object_bytes(&v, str_of(e, "acceptance"));
                assert_eq!(Friendship::encode(&offer, &acceptance), bytes, "{name}");
                let hash = unhex32(str_of(e, "hash_hex"));
                assert_eq!(sha(&bytes), hash, "{name}");
                let checked = Friendship::check(&bytes, now, &[]).unwrap();
                assert_eq!(checked.hash, hash, "{name}");
                assert_eq!(checked.offer, Offer::check(&offer, now, &[]).unwrap());
            }
            other => panic!("unknown object kind {other}"),
        }
    }
}

#[test]
fn rotation_vectors() {
    let v = vectors();
    for (name, from, to) in [
        ("rotate_successor", "successor", "successor_successor"),
        ("rotate_back", "successor", "identity"),
        ("rotate_fork", "identity", "successor_successor"),
    ] {
        let e = &v[name];
        let f = &e["fields"];
        let r = Rotation {
            identity: unhex32(str_of(f, "identity")),
            successor: unhex32(str_of(f, "successor")),
            time: u64_of(f, "time"),
        };
        let signed = unhex(str_of(e, "signed_hex"));
        let pred = IdentityKey::from_seed(&seed_of(&v, from));
        let succ = IdentityKey::from_seed(&seed_of(&v, to));
        assert_eq!(r.sign(&pred, &succ).unwrap(), signed, "{name}");
        assert_eq!(Rotation::parse(&signed).unwrap(), r, "{name}");
        let unsigned = unhex(str_of(e, "unsigned_hex"));
        assert_eq!(
            unhex(str_of(e, "signature_input_hex")),
            input(ROTATE_DOMAIN, &unsigned)
        );
        assert_eq!(
            unhex(str_of(e, "ack_input_hex")),
            input(&format!("{ROTATE_DOMAIN}/ack"), &unsigned)
        );
        let value = cbor::decode_canonical(&signed).unwrap();
        assert_eq!(cbor::encode(&value.without("sig").without("ack")), unsigned);
        assert_eq!(
            value.get("sig"),
            Some(&Value::Bytes(unhex(str_of(e, "signature_hex"))))
        );
        assert_eq!(
            value.get("ack"),
            Some(&Value::Bytes(unhex(str_of(e, "ack_hex"))))
        );
    }
}

#[test]
fn friend_pairs() {
    let v = vectors();
    for p in v["friend_pairs"].as_array().unwrap() {
        let a = fingerprint(&p["offerer_fingerprint_hex"]);
        let b = fingerprint(&p["offeree_fingerprint_hex"]);
        let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        let input_hex = unhex(str_of(p, "input_hex"));
        assert_eq!(input_hex, [PAIR.as_bytes(), &[0], &lo.0, &hi.0].concat());
        let pair = unhex32(str_of(p, "pair_hex"));
        assert_eq!(sha(&input_hex), pair);
        assert_eq!(Pair::new(a, b).hash(), pair, "{}", str_of(p, "name"));
    }
    assert_eq!(friendship::PAIR_DOMAIN, PAIR);
}

#[test]
fn friend_rejects() {
    let v = vectors();
    let now = now_of(&v);
    for r in v["friend_rejects"].as_array().unwrap() {
        let bytes = unhex(str_of(r, "hex"));
        let got = match str_of(r, "object") {
            "offer" => outcome(Offer::check(&bytes, now, &[])),
            "friendship" => outcome(Friendship::check(&bytes, now, &[])),
            "withdrawal" => outcome(Withdrawal::parse(&bytes, now)),
            other => panic!("unknown object kind {other}"),
        };
        let want = (r["step"].clone(), r["error"].as_str().map(str::to_owned));
        assert_eq!(got, want, "reject `{}`", str_of(r, "name"));
    }
}

#[test]
fn friend_reads() {
    let v = vectors();
    for c in v["friend_reads"].as_array().unwrap() {
        let now = c["now"].as_u64().unwrap_or(now_of(&v));
        let p = c["pair"].as_array().unwrap();
        let pair = Pair::new(fingerprint(&p[0]), fingerprint(&p[1]));
        let names = |k: &str| {
            c[k].as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let rotations: Vec<Rotation> = names("rotations")
            .iter()
            .map(|n| Rotation::parse(&unhex(str_of(&v[n.as_str()], "signed_hex"))).unwrap())
            .collect();
        let held: Vec<Held> = names("withdrawals")
            .iter()
            .map(|n| Withdrawal::check(&object_bytes(&v, n), now, &pair, &[]).unwrap())
            .collect();
        let bytes = object_bytes(&v, str_of(c, "vector"));
        let got = match str_of(c, "object") {
            "offer" => outcome(Offer::check(&bytes, now, &held)),
            "friendship" => outcome(Friendship::check(&bytes, now, &held)),
            "withdrawal" => outcome(Withdrawal::check(&bytes, now, &pair, &rotations)),
            other => panic!("unknown object kind {other}"),
        };
        assert_eq!(got, expected(c), "{}", str_of(c, "name"));
    }
}

#[test]
fn friend_cert_window() {
    let v = vectors();
    let now = now_of(&v);
    for c in v["friend_cert_window"].as_array().unwrap() {
        let bytes = unhex(str_of(c, "signed_hex"));
        let checked = Offer::check(&bytes, now, &[]);
        if let Ok(offer) = &checked {
            let cert = DeviceCert::parse(&offer.cert).unwrap();
            assert_eq!(
                (cert.issued, cert.expires),
                (u64_of(c, "issued"), u64_of(c, "expires"))
            );
            assert_eq!(offer.time, u64_of(c, "time"));
        }
        assert_eq!(outcome(checked), expected(c), "{}", str_of(c, "name"));
    }
}
