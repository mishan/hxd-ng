//! `docs/identity-test-vectors.json` is the contract with other
//! implementations. This test holds this crate to it: keys derive as
//! stated, every object re-signs to the exact bytes, every object parses
//! back to the stated fields, the composed login verifies, and every
//! reject fails with the named error.

use hl_identity::message::{
    Article, ChatLine, ChatScope, Context, Form, NewsScope, Object, Outcome, Parent,
    PrivateMessage, Sender, Signed,
};
use hl_identity::registrar::{
    FREEZE_DOMAIN, RECORDS_DOMAIN, REGISTER_DOMAIN, REVOKE_ATTESTATION_DOMAIN,
    REVOKE_DEVICE_DOMAIN, REVOKE_IDENTITY_DOMAIN, ROTATE_DOMAIN,
};
use hl_identity::sealed::{self, Opened, Opening, Replay};
use hl_identity::{
    attestation, card, cert, enroll, message, proof, Attestation, AttestationRevocation, Bundle,
    Card, DeviceCert, DeviceKey, DeviceProof, DeviceRevocation, EnrollRequest, Fingerprint, Freeze,
    IdentityKey, IdentityRevocation, ListKind, LoginContext, LoginProof, Record, RegisterRequest,
    RegistrarKeys, Rotation, ServerChallenge, ServerKey, SessionClaim, SignedList,
};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

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
        LoginProof::sign_v1(&k.dev, &challenge, &server_key, time),
        signed
    );
    let p = LoginProof::parse(&signed).unwrap();
    assert_eq!(p.device, k.dev.public());
    check_signed(e, proof::DOMAIN, &k.dev.public(), &signed);

    let login = &v["login"];
    let ctx = LoginContext {
        challenge: &challenge,
        server_key: &k.srv.public(),
        host: None,
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
fn login_proof_v2_vector_binds_the_host() {
    let v = vectors();
    let k = keys(&v);
    let lp = &v["login_proof_v2"];
    let e = &lp["object"];
    assert_eq!(str_of(e, "domain"), proof::DOMAIN);
    assert_eq!(u64_of(&e["fields"], "v"), proof::HOST_VERSION);
    let challenge = unhex32(str_of(lp, "challenge_hex"));
    let server_key = unhex32(str_of(lp, "server_key_hex"));
    let host = str_of(lp, "host");
    let time = u64_of(&e["fields"], "time");
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        LoginProof::sign(&k.dev, &challenge, &server_key, host, time).unwrap(),
        signed
    );
    assert_eq!(
        LoginProof::parse(&signed).unwrap().host.as_deref(),
        Some(host)
    );
    check_signed(e, proof::DOMAIN, &k.dev.public(), &signed);

    let login = &v["login"];
    let verify = |host| {
        hl_identity::verify_login(
            &unhex(str_of(&v["card"], "signed_hex")),
            &unhex(str_of(&v["device_cert"], "signed_hex")),
            &signed,
            LoginContext {
                challenge: &challenge,
                server_key: &k.srv.public(),
                host,
                now: u64_of(login, "now"),
                skew: u64_of(login, "skew"),
            },
        )
        .map(|ok| ok.fingerprint().to_string())
    };
    assert_eq!(
        verify(Some(host)).as_deref(),
        Ok(str_of(login, "identity_fingerprint"))
    );
    assert_eq!(
        verify(Some("relay.example")),
        Err(hl_identity::Error::HostMismatch)
    );
}

#[test]
fn server_challenge_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["server_challenge"]["object"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), proof::SERVER_DOMAIN);
    let challenge = unhex32(str_of(f, "challenge"));
    let host = str_of(f, "host");
    let expires = u64_of(f, "expires");
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        ServerChallenge::sign(&k.srv, &challenge, host, expires, None).unwrap(),
        signed
    );
    let c = ServerChallenge::parse(&signed).unwrap();
    assert_eq!(c.server_key, unhex32(str_of(f, "server_key")));
    assert_eq!(
        (c.challenge, c.host.as_str(), c.expires),
        (challenge, host, expires)
    );
    assert!(c
        .check(&challenge, &k.srv.public(), host, expires, 0)
        .is_ok());
    check_signed(e, proof::SERVER_DOMAIN, &k.srv.public(), &signed);
}

#[test]
fn server_challenge_trtp_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["server_challenge_trtp"]["object"];
    let f = &e["fields"];
    assert_eq!(str_of(e, "domain"), proof::TRTP_SERVER_DOMAIN);
    let challenge = unhex32(str_of(f, "challenge"));
    let host = str_of(f, "host");
    let expires = u64_of(f, "expires");
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        ServerChallenge::sign_trtp(&k.srv, &challenge, host, expires, None).unwrap(),
        signed
    );
    let c = ServerChallenge::parse_trtp(&signed).unwrap();
    assert_eq!(
        (c.challenge, c.server_key, c.host.as_str(), c.expires),
        (challenge, k.srv.public(), host, expires)
    );
    assert_eq!(
        ServerChallenge::parse(&signed),
        Err(hl_identity::Error::BadSignature)
    );
    check_signed(e, proof::TRTP_SERVER_DOMAIN, &k.srv.public(), &signed);
}

#[test]
fn device_proof_vector_binds_the_connection() {
    let v = vectors();
    let k = keys(&v);
    let dp = &v["device_proof"];
    let e = &dp["object"];
    assert_eq!(str_of(e, "domain"), proof::DEVICE_DOMAIN);
    let challenge = unhex32(str_of(dp, "challenge_hex"));
    let server_key = unhex32(str_of(dp, "server_key_hex"));
    let exporter = unhex32(str_of(dp, "exporter_hex"));
    let host = str_of(dp, "host");
    let time = u64_of(&e["fields"], "time");
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(
        DeviceProof::sign(&k.dev, &challenge, &server_key, host, time, Some(&exporter)).unwrap(),
        signed
    );
    let p = DeviceProof::parse(&signed).unwrap();
    assert_eq!(
        p.check(&challenge, &server_key, host, Some(&exporter), time, 0),
        Ok(())
    );
    assert_eq!(
        p.check(&challenge, &server_key, host, None, time, 0),
        Err(hl_identity::Error::ChallengeMismatch)
    );
    assert_eq!(
        LoginProof::parse(&signed),
        Err(hl_identity::Error::BadSignature)
    );
    check_signed(e, proof::DEVICE_DOMAIN, &k.dev.public(), &signed);
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
            "server_challenge" => ServerChallenge::parse(&bytes).unwrap_err(),
            "revoke_device" => DeviceRevocation::parse(&bytes).unwrap_err(),
            "rotate" => Rotation::parse(&bytes).unwrap_err(),
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

// --- The registrar's objects (identity-registrar.md §15) -----------------

fn key_of(v: &Json, name: &str) -> IdentityKey {
    let k = &v["keys"][name];
    let key = IdentityKey::from_seed(&unhex32(str_of(k, "seed_hex")));
    assert_eq!(
        key.public(),
        unhex32(str_of(k, "public_hex")),
        "keys.{name}"
    );
    assert_eq!(
        key.fingerprint().to_string(),
        str_of(k, "fingerprint"),
        "keys.{name}"
    );
    key
}

fn opt32(f: &Json, k: &str) -> Option<[u8; 32]> {
    f[k].as_str().map(unhex32)
}

#[test]
fn register_vectors() {
    let v = vectors();
    let k = keys(&v);
    let succ = key_of(&v, "successor");
    for name in ["register", "register_reissue"] {
        let e = &v[name];
        let f = &e["fields"];
        assert_eq!(str_of(e, "domain"), REGISTER_DOMAIN);
        let r = RegisterRequest {
            identity: unhex32(str_of(f, "identity")),
            registrar: str_of(f, "registrar").to_owned(),
            handle: str_of(f, "handle").to_owned(),
            time: u64_of(f, "time"),
            successor: opt32(f, "successor"),
            proof: f["proof"].as_str().map(str::to_owned),
        };
        let signed = unhex(str_of(e, "signed_hex"));
        assert_eq!(
            r.sign(&k.id).unwrap(),
            signed,
            "{name} re-signs to the vector bytes"
        );
        assert_eq!(RegisterRequest::parse(&signed).unwrap(), r);
        assert_eq!(
            r.successor,
            Some(succ.fingerprint().0),
            "{name} commits to keys.successor"
        );
        check_signed(e, REGISTER_DOMAIN, &k.id.public(), &signed);
    }
}

#[test]
fn record_vectors() {
    let v = vectors();
    let k = keys(&v);
    let succ = key_of(&v, "successor");
    let other = key_of(&v, "other");
    let lost = unhex32(str_of(&v["keys"]["lost_device"], "public_hex"));
    let reg_keys = [k.reg.public()];
    let rk = RegistrarKeys {
        host: "hl.example",
        keys: &reg_keys,
    };
    let parse = |name: &str| {
        let e = &v[name];
        let signed = unhex(str_of(e, "signed_hex"));
        let rec = Record::parse(&signed, Some(rk)).unwrap_or_else(|e| panic!("{name}: {e}"));
        (e, signed, rec)
    };

    let (e, signed, rec) = parse("revoke_device");
    let f = &e["fields"];
    let r = DeviceRevocation {
        identity: k.id.public(),
        device: lost,
        time: u64_of(f, "time"),
        until: u64_of(f, "until"),
        reason: f["reason"].as_u64(),
        signer: None,
        signer_cert: None,
    };
    assert_eq!(r.sign(&k.id).unwrap(), signed);
    assert_eq!(rec, Record::RevokeDevice(r));
    check_signed(e, REVOKE_DEVICE_DOMAIN, &k.id.public(), &signed);

    // Signed by the device, so the signature checks against `signer`.
    let (e, signed, rec) = parse("revoke_device_by_device");
    let f = &e["fields"];
    let cert = unhex(str_of(f, "signer_cert"));
    let r = DeviceRevocation {
        identity: k.id.public(),
        device: lost,
        time: u64_of(f, "time"),
        until: u64_of(f, "until"),
        reason: f["reason"].as_u64(),
        signer: None,
        signer_cert: None,
    };
    assert_eq!(r.sign_as_device(&k.dev, cert).unwrap(), signed);
    let Record::RevokeDevice(back) = rec else {
        panic!("not a device revocation")
    };
    assert_eq!(back.signer, Some(k.dev.public()));
    check_signed(e, REVOKE_DEVICE_DOMAIN, &k.dev.public(), &signed);

    let (e, signed, rec) = parse("revoke_identity");
    let f = &e["fields"];
    let r = IdentityRevocation {
        identity: other.public(),
        time: u64_of(f, "time"),
        reason: f["reason"].as_u64(),
    };
    assert_eq!(r.sign(&other).unwrap(), signed);
    assert_eq!(rec, Record::RevokeIdentity(r));
    check_signed(e, REVOKE_IDENTITY_DOMAIN, &other.public(), &signed);

    // Two signatures over one input, under two domains.
    let (e, signed, rec) = parse("rotate");
    let f = &e["fields"];
    let r = Rotation {
        identity: k.id.public(),
        successor: succ.public(),
        time: u64_of(f, "time"),
    };
    assert_eq!(r.sign(&k.id, &succ).unwrap(), signed);
    assert_eq!(rec, Record::Rotate(r));
    let value = hl_identity::cbor::decode_canonical(&signed).unwrap();
    let unsigned = unhex(str_of(e, "unsigned_hex"));
    assert_eq!(
        hl_identity::cbor::encode(&value.without("sig").without("ack")),
        unsigned
    );
    let mut sig_input = ROTATE_DOMAIN.as_bytes().to_vec();
    sig_input.push(0);
    sig_input.extend_from_slice(&unsigned);
    assert_eq!(unhex(str_of(e, "signature_input_hex")), sig_input);
    let mut ack_input = format!("{ROTATE_DOMAIN}/ack").into_bytes();
    ack_input.push(0);
    ack_input.extend_from_slice(&unsigned);
    assert_eq!(unhex(str_of(e, "ack_input_hex")), ack_input);
    let sig: [u8; 64] = unhex(str_of(e, "signature_hex")).try_into().unwrap();
    let ack: [u8; 64] = unhex(str_of(e, "ack_hex")).try_into().unwrap();
    hl_identity::keys::verify_domain(&k.id.public(), ROTATE_DOMAIN, &unsigned, &sig).unwrap();
    hl_identity::keys::verify_domain(
        &succ.public(),
        &format!("{ROTATE_DOMAIN}/ack"),
        &unsigned,
        &ack,
    )
    .unwrap();

    let (e, signed, rec) = parse("freeze");
    let f = &e["fields"];
    let r = Freeze {
        identity: k.id.public(),
        registrar: str_of(f, "registrar").to_owned(),
        frozen: f["frozen"].as_bool().unwrap(),
        time: u64_of(f, "time"),
    };
    assert_eq!(r.sign(&k.reg), signed);
    assert_eq!(rec, Record::Freeze(r));
    check_signed(e, FREEZE_DOMAIN, &k.reg.public(), &signed);

    let (e, signed, rec) = parse("revoke_attestation");
    let f = &e["fields"];
    let r = AttestationRevocation {
        identity: k.id.public(),
        registrar: str_of(f, "registrar").to_owned(),
        handle: str_of(f, "handle").to_owned(),
        time: u64_of(f, "time"),
        reason: f["reason"].as_u64(),
    };
    assert_eq!(r.sign(&k.reg), signed);
    assert_eq!(rec, Record::RevokeAttestation(r));
    check_signed(e, REVOKE_ATTESTATION_DOMAIN, &k.reg.public(), &signed);
}

#[test]
fn record_list_vectors() {
    let v = vectors();
    let k = keys(&v);
    let other = key_of(&v, "other");
    let reg_keys = [k.reg.public()];
    let rk = RegistrarKeys {
        host: "hl.example",
        keys: &reg_keys,
    };

    let e = &v["records"];
    let signed = unhex(str_of(e, "signed_hex"));
    let list = SignedList::parse(&signed, ListKind::Records, rk).unwrap();
    assert_eq!(list.fingerprint, Some(k.id.fingerprint().0));
    assert_eq!(list.sign(ListKind::Records, &k.reg), signed);
    check_signed(e, RECORDS_DOMAIN, &k.reg.public(), &signed);
    // Every entry is the vector of the same name, byte for byte.
    let named = [
        "revoke_device",
        "revoke_device_by_device",
        "rotate",
        "freeze",
        "revoke_attestation",
    ];
    assert_eq!(list.entries.len(), named.len());
    for ((_, bytes), name) in list.entries.iter().zip(named) {
        assert_eq!(bytes, &unhex(str_of(&v[name], "signed_hex")), "{name}");
        assert!(Record::parse(bytes, Some(rk)).is_ok(), "{name}");
    }

    let e = &v["records_empty"];
    let signed = unhex(str_of(e, "signed_hex"));
    let list = SignedList::parse(&signed, ListKind::Records, rk).unwrap();
    assert_eq!(list.fingerprint, Some(other.fingerprint().0));
    assert!(list.entries.is_empty());
    check_signed(e, RECORDS_DOMAIN, &k.reg.public(), &signed);
}

// --- Signed messages (e2e-messages.md §13) --------------------------------

fn texts_of_if_any(e: &Json) -> Vec<String> {
    if e["texts"].is_array() {
        texts_of(e)
    } else {
        Vec::new()
    }
}

fn texts_of(e: &Json) -> Vec<String> {
    e["texts"]
        .as_array()
        .unwrap_or_else(|| panic!("missing texts"))
        .iter()
        .map(|t| t.as_str().unwrap().to_owned())
        .collect()
}

/// A vector's texts as its object takes them, which fails here if the
/// file gives the wrong number.
fn texts_as<'a, T: Object>(texts: &'a [String]) -> T::Texts<'a>
where
    T::Texts<'a>: TryFrom<Vec<&'a str>>,
{
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    texts
        .try_into()
        .ok()
        .expect("as many texts as the object has text keys")
}

fn opt16(f: &Json, k: &str) -> Option<[u8; 16]> {
    f[k].as_str().map(|s| unhex(s).try_into().unwrap())
}

fn at_of(v: &Json) -> u64 {
    u64_of(&v["messages"], "at")
}

/// Every form of one signed object, held to the file byte for byte:
/// the struct re-signs to `signed_hex`, it parses back to the struct,
/// its detached and link forms are the published ones, and each
/// reassembles to the whole map.
fn check_message<T: Object + PartialEq + std::fmt::Debug>(v: &Json, name: &str, built: T)
where
    for<'a> T::Texts<'a>: TryFrom<Vec<&'a str>>,
{
    let k = keys(v);
    let e = &v[name];
    let at = at_of(v);
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(str_of(e, "domain"), T::DOMAIN, "{name}");
    assert_eq!(built.sign(&k.dev).unwrap(), signed, "{name} re-signs");
    check_signed(e, T::DOMAIN, &k.dev.public(), &signed);

    let whole = Signed::<T>::parse(&signed, at).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(whole.message, built, "{name}");
    assert_eq!(whole.signer(), k.id.fingerprint(), "{name}");

    let texts = texts_of(e);
    let texts = texts_as::<T>(&texts);
    let detached = unhex(str_of(e, "detached_hex"));
    assert_eq!(whole.detached().unwrap(), detached, "{name} detached");
    let back = Signed::<T>::parse_detached(&detached, texts, at).unwrap();
    assert_eq!(back.whole(), signed, "{name} reassembled");

    if let Some(link) = e["link_hex"].as_str() {
        let link = unhex(link);
        assert_eq!(whole.link().unwrap(), link, "{name} link form");
        let cert = unhex(str_of(&v["message_cert"], "signed_hex"));
        let back = Signed::<T>::parse_link(&link, texts, &cert, at).unwrap();
        assert_eq!(back.whole(), signed, "{name} restored from its link form");
    }
}

fn chat_line_of(f: &Json) -> ChatLine {
    ChatLine {
        id: opt16(f, "id").unwrap(),
        sent: u64_of(f, "sent"),
        server: unhex32(str_of(&f["in"], "server")),
        room: u64_of(&f["in"], "room"),
        cert: unhex(str_of(f, "cert")),
        text: str_of(f, "text").to_owned(),
        act: f["act"].as_bool().unwrap_or(false),
    }
}

fn private_message_of(f: &Json) -> PrivateMessage {
    PrivateMessage {
        id: opt16(f, "id").unwrap(),
        sent: u64_of(f, "sent"),
        to: Fingerprint(unhex32(str_of(f, "to"))),
        cert: unhex(str_of(f, "cert")),
        text: str_of(f, "text").to_owned(),
        quote: f["quote"].as_str().map(str::to_owned),
        auto: f["auto"].as_bool().unwrap_or(false),
    }
}

fn parent_of(p: &Json) -> Option<Parent> {
    if p.is_null() {
        return None;
    }
    Some(Parent {
        article: u64_of(p, "article"),
        signed: opt16(p, "id").map(|id| (id, Fingerprint(unhex32(str_of(p, "by"))))),
    })
}

fn article_of(f: &Json) -> Article {
    Article {
        id: opt16(f, "id").unwrap(),
        sent: u64_of(f, "sent"),
        server: unhex32(str_of(&f["in"], "server")),
        category: opt16(&f["in"], "category").unwrap(),
        parent: parent_of(&f["parent"]),
        cert: unhex(str_of(f, "cert")),
        subject: str_of(f, "subject").to_owned(),
        body: str_of(f, "body").to_owned(),
        mime: str_of(f, "mime").to_owned(),
    }
}

#[test]
fn message_cert_vector() {
    let v = vectors();
    let k = keys(&v);
    let e = &v["message_cert"];
    let f = &e["fields"];
    let dc = DeviceCert {
        identity: unhex32(str_of(f, "identity")),
        device: unhex32(str_of(f, "device")),
        device_enc: unhex32(str_of(f, "device_enc")),
        issued: u64_of(f, "issued"),
        expires: u64_of(f, "expires"),
        caps: f["caps"].as_u64(),
        name: None,
    };
    let signed = unhex(str_of(e, "signed_hex"));
    assert_eq!(dc.sign(&k.id), signed);
    assert!(signed.len() <= message::CERT_MAX_BYTES);
    check_signed(e, cert::DOMAIN, &k.id.public(), &signed);
}

#[test]
fn message_vectors() {
    let v = vectors();
    assert_eq!(u64_of(&v["messages"], "skew"), message::SKEW);
    for name in ["chat_lobby", "chat_room", "chat_action"] {
        check_message(&v, name, chat_line_of(&v[name]["fields"]));
    }
    for name in ["private_message", "private_message_auto"] {
        check_message(&v, name, private_message_of(&v[name]["fields"]));
    }
    for name in ["article_signed_parent", "article_unsigned_parent"] {
        check_message(&v, name, article_of(&v[name]["fields"]));
    }
}

#[test]
fn canonical_text_vectors() {
    let v = vectors();
    for c in v["canonical_text"].as_array().unwrap() {
        assert_eq!(
            message::canonicalize(str_of(c, "input")),
            str_of(c, "canonical"),
            "{}",
            str_of(c, "name")
        );
    }
}

fn read_as<T: Object>(v: &Json, r: &Json, scope: &T::Scope) -> Outcome
where
    for<'a> T::Texts<'a>: TryFrom<Vec<&'a str>>,
{
    let e = &v[str_of(r, "vector")];
    let k = keys(v);
    let sender = match str_of(r, "sender") {
        "named" => Sender::Named(k.id.fingerprint()),
        "other" => Sender::Named(key_of(v, "other").fingerprint()),
        "certificate" => Sender::Certificate,
        "unknown" => Sender::Unknown,
        other => panic!("unknown sender {other}"),
    };
    let texts = texts_of(e);
    let texts = texts_as::<T>(&texts);
    let cert = r["cert"]
        .as_str()
        .map(|c| unhex(str_of(&v[c], "signed_hex")));
    let (whole, detached, link) = (
        unhex(str_of(e, "signed_hex")),
        unhex(str_of(e, "detached_hex")),
        e["link_hex"].as_str().map(unhex),
    );
    let form = match str_of(r, "form") {
        "whole" => Form::Whole(&whole),
        "detached" => Form::Detached {
            bytes: &detached,
            texts,
        },
        "link" => Form::Link {
            bytes: link.as_deref().unwrap(),
            texts,
            cert: cert.as_deref(),
        },
        other => panic!("unknown form {other}"),
    };
    let ctx = Context {
        at: r["at"].as_u64().unwrap_or_else(|| at_of(v)),
        sender,
        scope,
    };
    Signed::<T>::read(form, &ctx)
}

#[test]
fn message_read_vectors() {
    let v = vectors();
    let signer = key_of(&v, "identity").fingerprint();
    for r in v["message_reads"].as_array().unwrap() {
        let name = str_of(r, "name");
        let vector = str_of(r, "vector");
        let s = &r["scope"];
        let outcome = if vector.starts_with("chat_") {
            let scope = ChatScope {
                server: s["server"].as_str().map(unhex32),
                room: u64_of(s, "room"),
            };
            read_as::<ChatLine>(&v, r, &scope)
        } else if vector.starts_with("private_message") {
            let reader = r["reader"]
                .as_str()
                .map(|fp| Fingerprint::parse(fp).unwrap());
            read_as::<PrivateMessage>(&v, r, &reader)
        } else {
            let scope = NewsScope {
                server: unhex32(str_of(s, "server")),
                category: opt16(s, "category").unwrap(),
                parent: parent_of(&s["parent"]),
            };
            read_as::<Article>(&v, r, &scope)
        };
        let apart = r["sent_apart"].as_bool().unwrap_or(false);
        let state = match &outcome {
            Outcome::Verified {
                signer: s,
                sent_apart,
            } if *s == signer && *sent_apart == apart => "verified",
            Outcome::Elsewhere {
                signer: s,
                sent_apart,
            } if *s == signer && *sent_apart == apart => "elsewhere",
            Outcome::Unverified { .. } => "unverified",
            Outcome::Invalid(_) => "invalid",
            other => panic!("{name}: another signer or sent_apart: {other:?}"),
        };
        assert_eq!(state, str_of(r, "expect"), "{name}: {outcome:?}");
    }
}

#[test]
fn message_cert_window_vectors() {
    let v = vectors();
    for c in v["cert_window"]["cases"].as_array().unwrap() {
        let got = Signed::<ChatLine>::parse(&unhex(str_of(c, "signed_hex")), u64_of(c, "sent"))
            .map(|s| (s.cert.issued, s.cert.expires));
        let want = match str_of(c, "expect") {
            "ok" => Ok((u64_of(c, "issued"), u64_of(c, "expires"))),
            error => Err(error.to_owned()),
        };
        assert_eq!(
            got.map_err(|e| format!("{e:?}")),
            want,
            "{}",
            str_of(c, "name")
        );
    }
}

#[test]
fn mixed_order_key_vectors() {
    let v = vectors();
    let m = &v["mixed_order_key"];
    let device = unhex32(str_of(m, "device_hex"));
    let at = at_of(&v);
    let ok = Signed::<ChatLine>::parse(&unhex(str_of(&m["accepted"], "signed_hex")), at).unwrap();
    assert_eq!(ok.cert.device, device);
    assert_eq!(
        ok.cert,
        DeviceCert::parse(&unhex(str_of(&m["accepted"], "cert_hex"))).unwrap()
    );
    let bad = &m["rejected"];
    assert_eq!(
        DeviceCert::parse(&unhex(str_of(bad, "cert_hex")))
            .unwrap()
            .device,
        device
    );
    assert_eq!(
        format!(
            "{:?}",
            Signed::<ChatLine>::parse(&unhex(str_of(bad, "signed_hex")), at).unwrap_err()
        ),
        str_of(bad, "error")
    );
}

fn parse_message<T: Object>(r: &Json, bytes: &[u8], at: u64) -> Result<(), hl_identity::Error>
where
    for<'a> T::Texts<'a>: TryFrom<Vec<&'a str>>,
{
    let texts = texts_of_if_any(r);
    match str_of(r, "form") {
        "whole" => Signed::<T>::parse(bytes, at),
        "detached" => Signed::<T>::parse_detached(bytes, texts_as::<T>(&texts), at),
        "link" => Signed::<T>::parse_link(
            bytes,
            texts_as::<T>(&texts),
            &unhex(str_of(r, "cert_hex")),
            at,
        ),
        other => panic!("unknown form {other}"),
    }
    .map(drop)
}

#[test]
fn message_rejects() {
    let v = vectors();
    let at = at_of(&v);
    for r in v["message_rejects"].as_array().unwrap() {
        let bytes = unhex(str_of(r, "hex"));
        let result = match (str_of(r, "object"), str_of(r, "form")) {
            ("chat_line", _) => parse_message::<ChatLine>(r, &bytes, at),
            ("private_message", _) => parse_message::<PrivateMessage>(r, &bytes, at),
            ("article", _) => parse_message::<Article>(r, &bytes, at),
            ("padded_plaintext", form) => message::unpad(&bytes, form == "deniable").map(drop),
            (other, _) => panic!("unknown object kind {other}"),
        };
        assert_eq!(
            result.map_err(|e| format!("{e:?}")),
            Err(str_of(r, "error").to_owned()),
            "reject `{}`",
            str_of(r, "name")
        );
    }
}

// --- Sealed messages (e2e-messages.md §3.7–§3.11) -------------------------

/// HPKE's one draw per box, the ikm its ephemeral key is derived from,
/// fixed as a vector fixes it.
struct Ikm(Option<Vec<u8>>);

impl RngCore for Ikm {
    fn next_u32(&mut self) -> u32 {
        unreachable!("HPKE draws its ephemeral key with fill_bytes")
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("HPKE draws its ephemeral key with fill_bytes")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0.take().expect("one ephemeral key per box"));
    }
}

impl CryptoRng for Ikm {}

fn derive(ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
    (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
}

/// The CFRG's vectors for RFC 9180, from `test-vectors.json` in
/// github.com/cfrg/draft-irtf-cfrg-hpke at commit
/// 5f503c564da00b0687b3de75f1dfbdfc4079ad31, cut to §3.8's suite in base
/// and auth mode and to each one's first encryption, the only one a
/// single-shot seal makes: so the HPKE a sealed message rests on is the
/// standard's, whatever version of the crate is pinned.
#[test]
fn rfc9180_vectors() {
    let v: Json = serde_json::from_str(include_str!("rfc9180-vectors.json")).unwrap();
    let entries = v.as_array().unwrap();
    let modes: Vec<u64> = entries.iter().map(|e| u64_of(e, "mode")).collect();
    assert_eq!(modes, [0, 2]);
    for e in entries {
        let mode = u64_of(e, "mode");
        let suite = (
            u64_of(e, "kem_id"),
            u64_of(e, "kdf_id"),
            u64_of(e, "aead_id"),
        );
        assert_eq!(suite, (0x20, 1, 2), "mode {mode}");
        let hex = |k| unhex(str_of(e, k));
        assert_eq!(
            derive(&hex("ikmR")),
            (hex("skRm"), hex("pkRm")),
            "mode {mode}"
        );
        assert_eq!(
            derive(&hex("ikmE")),
            (hex("skEm"), hex("pkEm")),
            "mode {mode}"
        );
        let pk_r = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&hex("pkRm")).unwrap();
        let sk_r = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&hex("skRm")).unwrap();
        let (seal_mode, open_mode) = match mode {
            0 => (OpModeS::Base, OpModeR::Base),
            2 => {
                assert_eq!(derive(&hex("ikmS")), (hex("skSm"), hex("pkSm")));
                let pk_s = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&hex("pkSm")).unwrap();
                let sk_s = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&hex("skSm")).unwrap();
                (OpModeS::Auth((sk_s, pk_s.clone())), OpModeR::Auth(pk_s))
            }
            other => panic!("mode {other} is not one this suite uses"),
        };
        let c = &e["encryptions"][0];
        let (info, aad, pt) = (hex("info"), unhex(str_of(c, "aad")), unhex(str_of(c, "pt")));
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
            &seal_mode,
            &pk_r,
            &info,
            &pt,
            &aad,
            &mut Ikm(Some(hex("ikmE"))),
        )
        .unwrap();
        assert_eq!(enc.to_bytes().to_vec(), hex("enc"), "mode {mode}");
        assert_eq!(ct, unhex(str_of(c, "ct")), "mode {mode}");
        let opened = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &open_mode, &sk_r, &enc, &info, &ct, &aad,
        )
        .unwrap();
        assert_eq!(opened, pt, "mode {mode}");
    }
}

/// A replay memory that starts empty, as each vector is read with.
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

    fn accept(&mut self, signer: Fingerprint, id: [u8; 16], _until: u64) -> bool {
        if self.accepted(&signer, &id) {
            return false;
        }
        self.accepted.push((signer, id));
        true
    }
}

/// The recipient's device and what its reader knows.
fn sealed_reader(v: &Json) -> (DeviceKey, [u8; 32], Opening) {
    let s = &v["sealed"];
    let r = &s["recipient"];
    let seed = unhex32(str_of(r, "seed_hex"));
    let reader = DeviceKey::from_seed(&seed);
    assert_eq!(reader.public_enc(), unhex32(str_of(r, "public_enc_hex")));
    let ctx = Opening {
        now: u64_of(s, "now"),
        at: u64_of(s, "at"),
        reader: Fingerprint::parse(str_of(r, "identity_fingerprint")).unwrap(),
        sender: Sender::Named(key_of(v, "identity").fingerprint()),
    };
    (reader, seed, ctx)
}

#[test]
fn sealed_vectors() {
    let v = vectors();
    let k = keys(&v);
    let s = &v["sealed"];
    assert_eq!(str_of(s, "signed_info").as_bytes(), sealed::SIGNED_INFO);
    assert_eq!(str_of(s, "deniable_info").as_bytes(), sealed::DENIABLE_INFO);
    assert_eq!(u64_of(s, "hold"), sealed::HOLD);
    let (reader, seed, ctx) = sealed_reader(&v);
    let mut x25519 = Sha256::new();
    x25519.update(b"hl-identity/device-enc/v1");
    x25519.update(seed);
    let sk_r = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&x25519.finalize()).unwrap();

    let pm = &v["private_message"];
    let message = private_message_of(&pm["fields"]);
    let (signed, unsigned) = (
        unhex(str_of(pm, "signed_hex")),
        unhex(str_of(pm, "unsigned_hex")),
    );
    for (name, deniable) in [("sealed_message", false), ("deniable_box", true)] {
        let e = &v[name];
        let hex = |k| unhex(str_of(e, k));
        let bytes = hex("sealed_hex");
        let ikm: [u8; 32] = hex("ikm_e_hex").try_into().unwrap();
        let again =
            sealed::seal_from_ikm(&message, &k.dev, &reader.public_enc(), deniable, &ikm).unwrap();
        assert_eq!(again, bytes, "{name} seals again");
        assert_eq!(
            derive(&ikm),
            (hex("ephemeral_secret_hex"), hex("enc_hex")),
            "{name}"
        );

        let (info, plaintext, rest) = if deniable {
            assert_eq!(hex("plaintext_hex"), unsigned, "{name}");
            assert_eq!(hex("sender_enc_hex"), k.dev.public_enc(), "{name}");
            assert_eq!(bytes[1..33], k.dev.public_enc(), "{name} pkS");
            (sealed::DENIABLE_INFO, &unsigned, &bytes[33..])
        } else {
            assert_eq!(str_of(e, "plaintext_of"), "private_message");
            (sealed::SIGNED_INFO, &signed, &bytes[1..])
        };
        let padded = hex("padded_hex");
        assert_eq!(message::pad(plaintext, deniable).unwrap(), padded, "{name}");
        assert_eq!(rest[..32], hex("enc_hex"), "{name} enc");
        assert_eq!(
            bytes.len(),
            padded.len() + if deniable { 32 } else { 0 } + sealed::OVERHEAD
        );
        let mode = match deniable {
            false => OpModeR::Base,
            true => OpModeR::Auth(
                <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&k.dev.public_enc()).unwrap(),
            ),
        };
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&rest[..32]).unwrap();
        let opened = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &mode,
            &sk_r,
            &enc,
            info,
            &rest[32..],
            &bytes[..1],
        )
        .unwrap();
        assert_eq!(opened, padded, "{name} padded plaintext");

        match sealed::open(&bytes, &reader, &ctx, &mut Memory::default()) {
            Opened::Verified { message: m, .. } if !deniable => assert_eq!(m.whole(), signed),
            Opened::Deniable { message: m, .. } if deniable => assert_eq!(m, message),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn sealed_rejects() {
    let v = vectors();
    let (reader, _, ctx) = sealed_reader(&v);
    for r in v["sealed_rejects"].as_array().unwrap() {
        let name = str_of(r, "name");
        let got = sealed::open(
            &unhex(str_of(r, "hex")),
            &reader,
            &ctx,
            &mut Memory::default(),
        );
        let (state, error) = match got {
            Opened::Unopened(e) => ("unopened", e),
            Opened::Invalid { error, .. } => ("invalid", error),
            Opened::Dropped(e) => ("dropped", e),
            other => panic!("reject `{name}` was shown: {other:?}"),
        };
        assert_eq!(
            (state, format!("{error:?}")),
            (str_of(r, "expect"), str_of(r, "error").to_owned()),
            "reject `{name}`"
        );
    }
}
