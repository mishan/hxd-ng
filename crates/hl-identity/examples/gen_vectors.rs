//! Regenerate `docs/identity-test-vectors.json`.
//!
//!     cargo run -p hl-identity --example gen_vectors > docs/identity-test-vectors.json
//!
//! Every input is a fixed seed and Ed25519 is deterministic, so the output
//! is stable across runs and machines; a change in the file is a change in
//! the encoding, which is the point of checking it in.

use hl_identity::cbor::{self, Value};
use hl_identity::{
    caps, cert, Attestation, Card, DeviceCert, DeviceKey, IdentityKey, LoginProof, ServerKey,
};
use serde_json::{json, Value as Json};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The exact bytes an Ed25519 signature is computed over.
fn sig_input(domain: &str, unsigned: &[u8]) -> Vec<u8> {
    let mut m = domain.as_bytes().to_vec();
    m.push(0);
    m.extend_from_slice(unsigned);
    m
}

/// Split a signed object into (unsigned bytes, signature).
fn split(signed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let v = cbor::decode_canonical(signed).unwrap();
    let sig = match v.get("sig") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => unreachable!(),
    };
    (cbor::encode(&v.without("sig")), sig)
}

fn signed_entry(domain: &str, signed: &[u8], fields: Json) -> Json {
    let (unsigned, sig) = split(signed);
    json!({
        "domain": domain,
        "fields": fields,
        "unsigned_hex": hex(&unsigned),
        "signature_input_hex": hex(&sig_input(domain, &unsigned)),
        "signature_hex": hex(&sig),
        "signed_hex": hex(signed),
    })
}

fn main() {
    const T0: u64 = 1_757_116_800; // 2025-09-06T00:00:00Z

    let id = IdentityKey::from_seed(&[0x01; 32]);
    let dev = DeviceKey::from_seed(&[0x02; 32]);
    let reg = ServerKey::from_seed(&[0x03; 32]);
    let srv = ServerKey::from_seed(&[0x04; 32]);

    let mut dc = DeviceCert::for_device(&id, &dev, T0, cert::RECOMMENDED_LIFETIME);
    dc.caps = Some(caps::WEB);
    dc.name = Some("browser".into());
    let dc_bytes = dc.sign(&id);

    let att = Attestation {
        identity: id.public(),
        registrar: "hl.example".into(),
        registrar_key: reg.public(),
        handle: "misha".into(),
        registered: T0 - 365 * 86_400,
        issued: T0,
        expires: T0 + hl_identity::attestation::RECOMMENDED_LIFETIME,
        level: Some(2),
    };
    let att_bytes = att.sign(&reg);

    let mut card = Card::new(&id, "Misha", T0 + 60);
    card.icon = Some(128);
    card.profile = Some("hxd-ng test vector".into());
    card.links = vec!["https://example.com/misha".into()];
    let card_bytes = card.sign(&id, vec![att.signed_value(&reg)]).unwrap();

    let challenge = [0xc4u8; 32];
    let proof_bytes = LoginProof::sign(&dev, &challenge, &srv.public(), T0 + 120);

    // Negative vectors: each is a byte string and the error name
    // `parse` returns for it. Built by mutating the good objects.
    let mut rejects = Vec::new();
    {
        // Non-shortest integer head inside an otherwise-correct proof:
        // re-encode `time` with a 64-bit argument.
        let v = cbor::decode_canonical(&proof_bytes).unwrap();
        let mut b = cbor::encode(&v);
        // Locate the `time` key (text "time" = 0x64 't' 'i' 'm' 'e'); its
        // value's uint32 head follows immediately.
        let key = [0x64, b't', b'i', b'm', b'e'];
        let t_pos = b.windows(key.len()).position(|w| w == key).unwrap() + key.len();
        assert_eq!(b[t_pos], 0x1a);
        let t = u32::from_be_bytes(b[t_pos + 1..t_pos + 5].try_into().unwrap()) as u64;
        b.splice(t_pos..t_pos + 5, [0x1b].into_iter().chain(t.to_be_bytes()));
        rejects.push(
            json!({ "name": "non-shortest integer head", "object": "login_proof",
                             "hex": hex(&b), "error": "Cbor(NotCanonical)" }),
        );
    }
    {
        let mut b = dc_bytes.clone();
        let at = b.windows(32).position(|w| w == dc.device_enc).unwrap();
        b[at] ^= 0x01;
        rejects.push(
            json!({ "name": "one bit flipped in device_enc", "object": "device_cert",
                             "hex": hex(&b), "error": "BadSignature" }),
        );
    }
    {
        // Version 2 of a device cert, correctly signed.
        let Value::Map(entries) = cbor::decode_canonical(&dc_bytes).unwrap().without("sig") else {
            unreachable!()
        };
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(k, v)| {
                if matches!(&k, Value::Text(t) if t == "v") {
                    (k, Value::Uint(2))
                } else {
                    (k, v)
                }
            })
            .collect();
        let unsigned = cbor::encode(&Value::Map(entries.clone()));
        let sig = ed25519_sign(&id, cert::DOMAIN, &unsigned);
        let mut with_sig = entries;
        with_sig.push((Value::Text("sig".into()), Value::Bytes(sig)));
        rejects.push(json!({ "name": "unsupported version 2", "object": "device_cert",
                             "hex": hex(&cbor::encode(&Value::Map(with_sig))), "error": "UnsupportedVersion(2)" }));
    }
    {
        // Attestation whose registrar host isn't lowercase, signed fine.
        let a = Attestation {
            registrar: "HL.example".into(),
            ..att.clone()
        };
        rejects.push(
            json!({ "name": "uppercase registrar host", "object": "attestation",
                             "hex": hex(&a.sign(&reg)), "error": "BadField(\"registrar\")" }),
        );
    }
    {
        rejects.push(json!({ "name": "trailing byte", "object": "login_proof",
                             "hex": hex(&[proof_bytes.clone(), vec![0x00]].concat()), "error": "Cbor(Trailing)" }));
    }

    let out = json!({
        "version": hl_identity::VERSION,
        "notes": [
            "All byte strings are lowercase hex.",
            "Seeds are the 32-byte Ed25519 private key seeds (RFC 8032). Device X25519 secret = SHA-256(\"hl-identity/device-enc/v1\" || seed).",
            "signature_input_hex = domain || 0x00 || unsigned_hex; signature_hex = Ed25519(seed, signature_input).",
            "signed_hex is the deterministic CBOR of the unsigned map plus a `sig` entry, keys sorted by encoded bytes.",
            "Fingerprint = SHA-256(public key), shown as lowercase Crockford base32, 52 digits.",
            "`rejects` entries must fail to parse with the named error; implementations that don't distinguish error kinds should at least fail.",
        ],
        "keys": {
            "identity":  { "seed_hex": hex(&*id.seed()),  "public_hex": hex(&id.public()),  "fingerprint": id.fingerprint().to_string() },
            "device":    { "seed_hex": hex(&*dev.seed()), "public_hex": hex(&dev.public()), "public_enc_hex": hex(&dev.public_enc()), "fingerprint": dev.fingerprint().to_string() },
            "registrar": { "seed_hex": hex(&*reg.seed()), "public_hex": hex(&reg.public()) },
            "server":    { "seed_hex": hex(&*srv.seed()), "public_hex": hex(&srv.public()) },
        },
        "device_cert": signed_entry(cert::DOMAIN, &dc_bytes, json!({
            "v": 1, "identity": hex(&dc.identity), "device": hex(&dc.device), "device_enc": hex(&dc.device_enc),
            "issued": dc.issued, "expires": dc.expires, "caps": dc.caps, "name": dc.name,
        })),
        "attestation": signed_entry(hl_identity::attestation::DOMAIN, &att_bytes, json!({
            "v": 1, "identity": hex(&att.identity), "registrar": att.registrar, "registrar_key": hex(&att.registrar_key),
            "handle": att.handle, "registered": att.registered, "issued": att.issued, "expires": att.expires, "level": att.level,
        })),
        "card": signed_entry(hl_identity::card::DOMAIN, &card_bytes, json!({
            "v": 1, "identity": hex(&card.identity), "updated": card.updated, "name": card.name, "icon": card.icon,
            "profile": card.profile, "links": card.links, "attestations": "[the signed attestation above, embedded as a map]",
        })),
        "login_proof": {
            "challenge_hex": hex(&challenge),
            "server_key_hex": hex(&srv.public()),
            "object": signed_entry(hl_identity::proof::DOMAIN, &proof_bytes, json!({
                "v": 1, "challenge": hex(&challenge), "server_key": hex(&srv.public()), "device": hex(&dev.public()), "time": T0 + 120,
            })),
        },
        "login": {
            "now": T0 + 130,
            "skew": 300,
            "expect": "ok",
            "identity_fingerprint": id.fingerprint().to_string(),
            "handle": "misha@hl.example",
        },
        "rejects": rejects,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

/// The example needs raw domain signing for the version-2 vector; the
/// crate keeps that private, so do it here with the same construction.
fn ed25519_sign(id: &IdentityKey, domain: &str, unsigned: &[u8]) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&id.seed());
    key.sign(&sig_input(domain, unsigned)).to_bytes().to_vec()
}
