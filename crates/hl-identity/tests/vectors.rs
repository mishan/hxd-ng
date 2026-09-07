//! `docs/identity-test-vectors.json` is the contract with other
//! implementations. This test holds this crate to it: keys derive as
//! stated, every object re-signs to the exact bytes, every object parses
//! back to the stated fields, the composed login verifies, and every
//! reject fails with the named error.

use hl_identity::{
    attestation, card, cert, proof, Attestation, Card, DeviceCert, DeviceKey, IdentityKey,
    LoginContext, LoginProof, ServerKey,
};
use serde_json::Value as Json;

const VECTORS: &str = include_str!("../../../docs/identity-test-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
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

struct Keys {
    id: IdentityKey,
    dev: DeviceKey,
    reg: ServerKey,
    srv: ServerKey,
}

fn keys(v: &Json) -> Keys {
    let k = &v["keys"];
    let id = IdentityKey::from_seed(&unhex32(str_of(&k["identity"], "seed_hex")));
    let dev = DeviceKey::from_seed(&unhex32(str_of(&k["device"], "seed_hex")));
    let reg = ServerKey::from_seed(&unhex32(str_of(&k["registrar"], "seed_hex")));
    let srv = ServerKey::from_seed(&unhex32(str_of(&k["server"], "seed_hex")));

    assert_eq!(id.public(), unhex32(str_of(&k["identity"], "public_hex")));
    assert_eq!(
        id.fingerprint().to_string(),
        str_of(&k["identity"], "fingerprint")
    );
    assert_eq!(dev.public(), unhex32(str_of(&k["device"], "public_hex")));
    assert_eq!(
        dev.public_enc(),
        unhex32(str_of(&k["device"], "public_enc_hex"))
    );
    assert_eq!(
        dev.fingerprint().to_string(),
        str_of(&k["device"], "fingerprint")
    );
    assert_eq!(reg.public(), unhex32(str_of(&k["registrar"], "public_hex")));
    assert_eq!(srv.public(), unhex32(str_of(&k["server"], "public_hex")));
    Keys { id, dev, reg, srv }
}

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn device_cert_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["device_cert"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), cert::DOMAIN);

    let dc = DeviceCert {
        identity: unhex32(str_of(f, "identity")),
        device: unhex32(str_of(f, "device")),
        device_enc: unhex32(str_of(f, "device_enc")),
        issued: u64_of(f, "issued"),
        expires: u64_of(f, "expires"),
        caps: f["caps"].as_u64(),
        name: f["name"].as_str().map(str::to_owned),
    };
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        dc.sign(&k.id),
        signed,
        "device cert re-signs to the vector bytes"
    );
    assert_eq!(DeviceCert::parse(&signed).unwrap(), dc);
}

#[test]
fn attestation_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["attestation"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), attestation::DOMAIN);

    let a = Attestation {
        identity: unhex32(str_of(f, "identity")),
        registrar: str_of(f, "registrar").to_owned(),
        registrar_key: unhex32(str_of(f, "registrar_key")),
        handle: str_of(f, "handle").to_owned(),
        registered: u64_of(f, "registered"),
        issued: u64_of(f, "issued"),
        expires: u64_of(f, "expires"),
        level: f["level"].as_u64(),
    };
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(a.sign(&k.reg), signed);
    let back = Attestation::parse(&signed).unwrap();
    assert_eq!(back, a);
    assert!(back
        .verify_registrar(&k.reg.public(), u64_of(&v["login"], "now"), 300)
        .is_ok());
}

#[test]
fn card_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["card"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), card::DOMAIN);

    let att = Attestation::parse(&unhex(str_of(&v["attestation"], "signed_hex"))).unwrap();
    let mut c = Card::new(&k.id, str_of(f, "name"), u64_of(f, "updated"));
    c.icon = f["icon"].as_u64();
    c.profile = f["profile"].as_str().map(str::to_owned);
    c.links = f["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        c.sign(&k.id, vec![att.signed_value(&k.reg)]).unwrap(),
        signed
    );

    let back = Card::parse(&signed).unwrap();
    assert_eq!(back.identity, unhex32(str_of(f, "identity")));
    assert_eq!(back.name, c.name);
    assert_eq!(back.attestations, vec![att]);
    // The optional fields are part of the contract too; asserting only
    // the name let a card round-trip while silently dropping them.
    assert_eq!(back.updated, u64_of(f, "updated"));
    assert_eq!(back.icon, f["icon"].as_u64());
    assert_eq!(back.profile.as_deref(), f["profile"].as_str());
    assert_eq!(back.links, c.links);
    assert_eq!(back.successor, None);
}

#[test]
fn card_successor_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["card_successor"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), card::DOMAIN);

    let mut c = Card::new(&k.id, str_of(f, "name"), u64_of(f, "updated"));
    c.successor = Some(unhex32(str_of(f, "successor")));
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(c.sign(&k.id, vec![]).unwrap(), signed);

    let back = Card::parse(&signed).unwrap();
    assert_eq!(back.successor, Some(unhex32(str_of(f, "successor"))));
    assert_eq!(back.identity, unhex32(str_of(f, "identity")));
}

#[test]
fn login_proof_vector_and_composed_login() {
    let v = vectors();
    let k = keys(&v);
    let lp = &v["login_proof"];
    let e = &lp["object"];
    assert_eq!(str_of(e, "domain"), proof::DOMAIN);
    let challenge = unhex32(str_of(lp, "challenge_hex"));
    let server_key = unhex32(str_of(lp, "server_key_hex"));
    let time = u64_of(&e["fields"], "time");
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        LoginProof::sign(&k.dev, &challenge, &server_key, time),
        signed
    );
    let p = LoginProof::parse(&signed).unwrap();
    assert_eq!(p.device, k.dev.public());

    let login = &v["login"];
    let ctx = LoginContext {
        challenge: &challenge,
        server_key: &k.srv.public(),
        now: u64_of(login, "now"),
        skew: u64_of(login, "skew"),
    };
    let ok = hl_identity::verify_login(
        &unhex(str_of(&v["card"], "signed_hex")),
        &unhex(str_of(&v["device_cert"], "signed_hex")),
        &signed,
        ctx,
    )
    .unwrap();
    assert_eq!(
        ok.fingerprint().to_string(),
        str_of(login, "identity_fingerprint")
    );
    assert_eq!(
        ok.card.attestations[0].full_handle(),
        str_of(login, "handle")
    );
}

#[test]
fn rejects() {
    let v = vectors();
    for r in v["rejects"].as_array().unwrap() {
        let bytes = unhex(str_of(r, "hex"));
        let err = match str_of(r, "object") {
            "device_cert" => DeviceCert::parse(&bytes).unwrap_err(),
            "attestation" => Attestation::parse(&bytes).unwrap_err(),
            "card" => Card::parse(&bytes).unwrap_err(),
            "login_proof" => LoginProof::parse(&bytes).unwrap_err(),
            other => panic!("unknown object kind {other}"),
        };
        assert_eq!(
            format!("{err:?}"),
            str_of(r, "error"),
            "reject `{}`",
            str_of(r, "name")
        );
    }
}
