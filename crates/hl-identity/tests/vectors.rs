//! `docs/identity-test-vectors.json` is the contract with other
//! implementations. This test holds this crate to it: keys derive as
//! stated, every object re-signs to the exact bytes, every object parses
//! back to the stated fields, the composed login verifies, and every
//! reject fails with the named error.

use hl_identity::{
    attestation, card, cert, enroll, proof, Attestation, Bundle, Card, DeviceCert, DeviceKey,
    EnrollRequest, IdentityKey, LoginContext, LoginProof, ServerKey, SessionClaim,
};
use serde_json::Value as Json;

const VECTORS: &str = include_str!("../../../docs/identity-test-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    // Over bytes rather than `&str` slices: a non-ASCII character in a
    // vector file would panic on a character boundary instead of saying
    // what was wrong with the file.
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

/// Hold a published object to *every* field the file states about it, not
/// just `signed_hex`.
///
/// `unsigned_hex`, `signature_hex` and `signature_input_hex` are what
/// another implementation reads to find out where its own bytes diverge —
/// they are the debugging surface of the whole vector file. Asserting
/// only the signed form let all three drift or rot while the suite stayed
/// green, which is the one failure a contract file must not have.
fn check_signed(e: &Json, domain: &str, public: &[u8; 32], signed: &[u8]) {
    let unsigned = unhex(str_of(e, "unsigned_hex"));
    let sig = unhex(str_of(e, "signature_hex"));
    let input = unhex(str_of(e, "signature_input_hex"));

    // The signature input is the domain, a NUL, and the unsigned bytes.
    let mut expect = domain.as_bytes().to_vec();
    expect.push(0);
    expect.extend_from_slice(&unsigned);
    assert_eq!(input, expect, "{domain}: signature_input_hex");

    // The unsigned form is the signed one minus `sig`.
    let value = hl_identity::cbor::decode_canonical(signed).expect("signed_hex is canonical");
    assert_eq!(
        hl_identity::cbor::encode(&value.without("sig")),
        unsigned,
        "{domain}: unsigned_hex"
    );

    // And the signature in the object is the one the file publishes, and
    // it verifies over the input the file publishes.
    match value.get("sig") {
        Some(hl_identity::cbor::Value::Bytes(b)) => {
            assert_eq!(b.as_slice(), sig.as_slice(), "{domain}: signature_hex")
        }
        other => panic!("{domain}: no sig in the signed object: {other:?}"),
    }
    let sig: [u8; 64] = sig.try_into().expect("64-byte signature");
    hl_identity::keys::verify_domain(public, domain, &unsigned, &sig)
        .unwrap_or_else(|e| panic!("{domain}: published signature does not verify: {e}"));
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
    check_signed(e, cert::DOMAIN, &k.id.public(), &signed);
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
    check_signed(e, attestation::DOMAIN, &k.reg.public(), &signed);
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
    check_signed(e, card::DOMAIN, &k.id.public(), &signed);
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
    check_signed(e, card::DOMAIN, &k.id.public(), &signed);
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
    check_signed(e, proof::DOMAIN, &k.dev.public(), &signed);

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

#[test]
fn enroll_request_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["enroll_request"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), enroll::DOMAIN);

    // `prev` is the device certificate published above rather than a
    // second copy of one: a renewal is about a certificate that already
    // exists, and a vector that invented its own would not say that.
    let prev = unhex(str_of(&v["device_cert"], "signed_hex"));
    let secret: [u8; enroll::PAIRING_SECRET_BYTES] = unhex(str_of(e, "pairing_secret_hex"))
        .try_into()
        .expect("16-byte pairing secret");

    let r = EnrollRequest {
        device: unhex32(str_of(f, "device")),
        device_enc: unhex32(str_of(f, "device_enc")),
        name: f["name"].as_str().map(str::to_owned),
        caps: f["caps"].as_u64(),
        days: f["days"].as_u64(),
        time: u64_of(f, "time"),
        prev: Some(prev.clone()),
        pair: Some(unhex32(str_of(f, "pair"))),
    };
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        r.sign(&k.dev),
        signed,
        "enrollment request re-signs to the vector bytes"
    );
    let back = EnrollRequest::parse(&signed).unwrap();
    assert_eq!(back, r);

    // Signed by the device key, not the identity key: this is the one
    // object in the file whose signer is the subject.
    check_signed(e, enroll::DOMAIN, &k.dev.public(), &signed);

    // The two derived fields the file publishes, recomputed rather than
    // trusted: the pairing tag and the certificate `prev` resolves to.
    assert_eq!(
        enroll::pair_tag(&secret, &k.dev.public()),
        unhex32(str_of(f, "pair")),
        "pair is HMAC-SHA-256(pairing secret, device)"
    );
    assert!(back.pair_matches(&secret));
    assert_eq!(
        back.prev_cert().expect("prev is present").unwrap(),
        DeviceCert::parse(&prev).unwrap()
    );
}

#[test]
fn enroll_session_claim_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["enroll_session_claim"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), enroll::CLAIM_DOMAIN);

    // The session is published as a hash *and* as the secret it came
    // from, so a reimplementation can check it derived the key the same
    // way rather than copying the digest across.
    let session = enroll::session_key(str_of(e, "session_secret"));
    assert_eq!(
        session,
        unhex32(str_of(f, "session")),
        "session is SHA-256 of the session secret"
    );

    let claim = SessionClaim::new(unhex32(str_of(f, "identity")), session);
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        claim.sign(&k.id),
        signed,
        "session claim re-signs to the vector bytes"
    );
    assert_eq!(SessionClaim::parse(&signed, &session).unwrap(), claim);

    // Signed by the identity key, and only good for this session.
    check_signed(e, enroll::CLAIM_DOMAIN, &k.id.public(), &signed);
    assert!(SessionClaim::parse(&signed, &enroll::session_key("another")).is_err());
}

#[test]
fn bundle_vector() {
    let v = vectors();
    let e = &v["bundle"];

    let cert = unhex(str_of(&v["device_cert"], "signed_hex"));
    let card = unhex(str_of(&v["card"], "signed_hex"));
    let b = Bundle {
        cert: cert.clone(),
        card: card.clone(),
    };

    let encoded = unhex(str_of(e, "encoded_hex"));
    assert_eq!(b.encode(), encoded, "bundle re-encodes to the vector bytes");
    assert_eq!(Bundle::parse(&encoded).unwrap(), b);

    // Unsigned, so the thing to pin is that opening it does the check
    // the format exists for: both members verify, and the card belongs
    // to the identity the certificate names.
    let (opened_cert, opened_card) = Bundle::parse(&encoded).unwrap().open().unwrap();
    assert_eq!(opened_cert, DeviceCert::parse(&cert).unwrap());
    assert_eq!(opened_card.identity, opened_cert.identity);
}
