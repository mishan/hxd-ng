//! Talking to a registrar (`docs/identity-registrar.md` §11's user
//! tools): register a handle, revoke a device or the identity, rotate to
//! a successor key.
//!
//! `--registrar` is a host, reached over HTTPS as every verifier reaches
//! it, or a full `http(s)://` URL for a test rig. Either way the
//! registrar's key comes from its discovery document, and nothing it
//! hands back is believed until it verifies against that key.
//!
//! Every record is parsed back with the same verifier the registrar and
//! the servers use before it is sent (§12): a record this tool would
//! post is one they would accept.

use std::path::Path;

use hl_identity::registrar::{device_reason, identity_reason};
use hl_identity::{
    cbor, Attestation, Card, DeviceCert, DeviceKey, DeviceRevocation, Fingerprint, IdentityKey,
    IdentityRevocation, Record, RegisterRequest, Rotation,
};
use serde_json::{json, Value};

use crate::{
    b64, now, parse, read_file, read_seed, refuse_unreadable, unb64, Args, CARD_FILE, IDENTITY_KEY,
    R,
};

/// Where a successor key goes when `hlid register --successor-commit`
/// makes one: beside the identity key, and like it never overwritten.
const SUCCESSOR_KEY: &str = "successor.key";

/// A registrar as discovery describes it.
struct Registrar {
    base: String,
    host: String,
    key: [u8; 32],
    retiring: Vec<[u8; 32]>,
    register: String,
    records: String,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build()
}

fn key32(v: &Value, what: &str) -> R<[u8; 32]> {
    unb64(v.as_str().ok_or(format!("discovery: no {what}"))?)?
        .try_into()
        .map_err(|_| format!("discovery: {what} is not 32 bytes"))
}

fn discover(a: &Args) -> R<Registrar> {
    let target = a.one("registrar")?;
    let base = if target.contains("://") {
        target.trim_end_matches('/').to_owned()
    } else {
        format!("https://{target}")
    };
    let doc: Value = agent()
        .get(&format!("{base}/.well-known/hotline"))
        .call()
        .map_err(|e| format!("{base}: {e}"))?
        .into_json()
        .map_err(|e| format!("{base}: discovery is not JSON: {e}"))?;
    let block = &doc["registrar"];
    if block.is_null() {
        return Err(format!(
            "{base} is not a registrar (its discovery document has no registrar block)"
        ));
    }
    let endpoint = |name: &str| {
        block["endpoints"][name]
            .as_str()
            .map(|p| format!("{base}{p}"))
            .ok_or(format!("discovery: no {name} endpoint"))
    };
    Ok(Registrar {
        host: block["host"]
            .as_str()
            .ok_or("discovery: no registrar host")?
            .to_owned(),
        key: key32(&block["key"], "registrar key")?,
        retiring: block["retiring"]
            .as_array()
            .map(|r| {
                r.iter()
                    .filter_map(|k| key32(&k["key"], "key").ok())
                    .collect()
            })
            .unwrap_or_default(),
        register: endpoint("register")?,
        records: endpoint("records")?,
        base,
    })
}

/// POST `{ field: b64 }` and return the JSON reply, or the registrar's
/// refusal as a sentence.
fn post(url: &str, field: &str, bytes: &[u8]) -> R<Value> {
    match agent().post(url).send_json(json!({ field: b64(bytes) })) {
        Ok(resp) => resp.into_json().map_err(|e| format!("{url}: {e}")),
        Err(ureq::Error::Status(code, resp)) => {
            let body: Value = resp.into_json().unwrap_or(Value::Null);
            Err(format!(
                "refused ({code} {}): {}",
                body["error"].as_str().unwrap_or("?"),
                body["text"].as_str().unwrap_or("")
            ))
        }
        Err(e) => Err(format!("{url}: {e}")),
    }
}

fn identity(a: &Args) -> R<IdentityKey> {
    Ok(IdentityKey::from_seed(&read_seed(
        &a.file("identity", IDENTITY_KEY)?,
    )?))
}

// --- register ----------------------------------------------------------

/// `hlid register --registrar HOST --handle NAME [--proof CODE]
/// [--successor-commit]`: ask for an attestation (§6.1), check it, put
/// it in the card, re-sign the card, and hand the card to the registrar,
/// which is its home of record (§6.4).
pub(crate) fn register_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = discover(&a)?;
    let id = identity(&a)?;
    let card_path = a.file("card", CARD_FILE)?;
    let card_bytes = read_file(&card_path)?;
    let card = Card::parse(&card_bytes).map_err(|e| format!("{}: {e}", card_path.display()))?;
    if card.identity != id.public() {
        return Err(format!(
            "{} is another identity's card",
            card_path.display()
        ));
    }

    // The commitment is immutable once a registrar holds it (§5.4), so
    // a card that already carries one is where it comes from; a request
    // that dropped it would be refused.
    let successor = match (card.successor, a.has("successor-commit")) {
        (Some(c), _) => Some(c),
        (None, false) => None,
        (None, true) => Some(successor_commitment(&a)?),
    };
    let request = RegisterRequest {
        identity: id.public(),
        registrar: reg.host.clone(),
        handle: a.one("handle")?.to_owned(),
        time: now(),
        successor,
        proof: a.opt("proof").map(str::to_owned),
    }
    .sign(&id)
    .map_err(|e| refuse_unreadable("registration request", e))?;
    let reply = post(&reg.register, "request", &request)?;

    let att_bytes = unb64(
        reply["attestation"]
            .as_str()
            .ok_or("reply has no attestation")?,
    )?;
    let att = Attestation::parse(&att_bytes).map_err(|e| format!("attestation: {e}"))?;
    let keys: Vec<[u8; 32]> = std::iter::once(reg.key)
        .chain(reg.retiring.iter().copied())
        .collect();
    if att.identity != id.public()
        || att.registrar != reg.host
        || !keys.contains(&att.registrar_key)
    {
        return Err("the registrar answered with an attestation that is not this one".into());
    }

    // Replace any attestation for the same name at the same registrar;
    // keep every other, as signed.
    let mut kept: Vec<cbor::Value> = match cbor::decode_canonical(&card_bytes)
        .map_err(|e| e.to_string())?
        .get("attestations")
    {
        Some(cbor::Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    kept.retain(|v| {
        !(matches!(v.get("registrar"), Some(cbor::Value::Text(h)) if *h == att.registrar)
            && matches!(v.get("handle"), Some(cbor::Value::Text(h)) if *h == att.handle))
    });
    kept.push(cbor::decode_canonical(&att_bytes).map_err(|e| e.to_string())?);
    let mut next = card.clone();
    next.updated = now().max(card.updated + 1);
    next.successor = successor;
    let signed = next
        .sign(&id, kept)
        .map_err(|e| refuse_unreadable("card", e))?;
    Card::parse(&signed).map_err(|e| refuse_unreadable("card", e))?;
    std::fs::write(&card_path, &signed).map_err(|e| format!("{}: {e}", card_path.display()))?;

    println!(
        "{} {} (registered {}, expires {}); card updated at {}",
        if reply["reissued"].as_bool() == Some(true) {
            "reissued"
        } else {
            "registered"
        },
        att.full_handle(),
        att.registered,
        att.expires,
        card_path.display()
    );
    if a.has("no-put") {
        return Ok(());
    }
    // The registrar serves the card; a server that has only a handle does
    // `lookup` and then `card` (§6.4). Putting it takes a device that can
    // manage the identity, as every card PUT does.
    match crate::put_card(&reg.base, &a, &signed) {
        Ok(()) => println!("card published at {}", reg.base),
        Err(e) => eprintln!(
            "hlid: the card was not published at the registrar ({e}); \
             it will be at your next login there"
        ),
    }
    Ok(())
}

/// Make — or reuse — the successor key, and commit to it. The key is
/// the whole point of the commitment, so it is written before the
/// commitment is ever sent: a commitment to a key that was lost with the
/// terminal would lock the identity out of rotating at all.
fn successor_commitment(a: &Args) -> R<[u8; 32]> {
    let path = match a.opt("successor-key") {
        Some(p) => std::path::PathBuf::from(p),
        None => crate::hlid_home()?.join(SUCCESSOR_KEY),
    };
    let key = if path.is_file() {
        IdentityKey::from_seed(&read_seed(&path)?)
    } else {
        let key = IdentityKey::generate();
        crate::write_private(&path, &crate::hex(&*key.seed()))?;
        eprintln!(
            "wrote a successor identity key to {} — keep it apart from the identity key; \
             it is the only key this identity can rotate to",
            path.display()
        );
        key
    };
    Ok(Fingerprint::of(&key.public()).0)
}

// --- revoke --------------------------------------------------------------

fn post_record(reg: &Registrar, bytes: &[u8]) -> R<()> {
    // The same verifier the registrar and every server run (§12).
    let rec = Record::parse(bytes, None).map_err(|e| refuse_unreadable("record", e))?;
    let reply = post(&reg.records, "record", bytes)?;
    match reply["published"].as_bool() {
        Some(true) => println!(
            "{} published at {} (seq {})",
            rec.kind(),
            reg.host,
            reply["seq"]
        ),
        _ => println!(
            "{} accepted at {}, and held until {} before it is published",
            rec.kind(),
            reg.host,
            reply["pending_until"]
        ),
    }
    Ok(())
}

/// `hlid revoke --registrar HOST (--device-cert FILE | --device-pub HEX)
/// [--reason lost|stolen|retired] [--by-device]` or `hlid revoke
/// --registrar HOST --identity-revoke --yes`.
pub(crate) fn revoke_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = discover(&a)?;
    if a.has("identity-revoke") {
        if !a.has("yes") {
            return Err(
                "revoking the identity is permanent and names no successor; \
                        to hand over to a new key, use `hlid rotate`. Add --yes if you mean it"
                    .into(),
            );
        }
        let id = identity(&a)?;
        let bytes = IdentityRevocation {
            identity: id.public(),
            time: now(),
            reason: Some(match a.opt("reason") {
                None | Some("retired") => identity_reason::RETIRED,
                Some("compromised") => identity_reason::COMPROMISED,
                Some(other) => return Err(format!("--reason {other:?}: retired or compromised")),
            }),
        }
        .sign(&id)
        .map_err(|e| refuse_unreadable("identity revocation", e))?;
        return post_record(&reg, &bytes);
    }

    // The device being revoked: its certificate when the user has it,
    // which also says how long the revocation must be published; else
    // its public key, published for the default two years.
    let (device, until) = match (a.opt("device-cert"), a.opt("device-pub")) {
        (Some(path), None) => {
            let c = DeviceCert::parse(&read_file(Path::new(path))?)
                .map_err(|e| format!("{path}: {e}"))?;
            (c.device, Some(c.expires))
        }
        (None, Some(hex)) => (
            crate::unhex(hex)?
                .try_into()
                .map_err(|_| "--device-pub: 32 bytes of hex".to_string())?,
            None,
        ),
        _ => {
            return Err(
                "name the device with --device-cert FILE or --device-pub HEX \
                 (or revoke the identity with --identity-revoke)"
                    .into(),
            )
        }
    };
    let time = now();
    let reason = match a.opt("reason") {
        None => None,
        Some("lost") => Some(device_reason::LOST),
        Some("stolen") => Some(device_reason::STOLEN),
        Some("retired") => Some(device_reason::RETIRED),
        Some(other) => return Err(format!("--reason {other:?}: lost, stolen or retired")),
    };
    let signer_identity: [u8; 32];
    let bytes = if a.has("by-device") {
        // Signed by this machine's device, whose certificate must carry
        // `manage` — which a web client's never does (§4.4).
        let dev = DeviceKey::from_seed(&read_seed(&a.file("device", "device.key")?)?);
        let cert = read_file(&a.file("cert", "cert.bin")?)?;
        let parsed = DeviceCert::parse(&cert).map_err(|e| format!("certificate: {e}"))?;
        signer_identity = parsed.identity;
        DeviceRevocation {
            identity: parsed.identity,
            device,
            time,
            until: until
                .unwrap_or(DeviceRevocation::default_until(time))
                .max(time),
            reason,
            signer: None,
            signer_cert: None,
        }
        .sign_as_device(&dev, cert)
    } else {
        let id = identity(&a)?;
        signer_identity = id.public();
        DeviceRevocation {
            identity: id.public(),
            device,
            time,
            until: until
                .unwrap_or(DeviceRevocation::default_until(time))
                .max(time),
            reason,
            signer: None,
            signer_cert: None,
        }
        .sign(&id)
    }
    .map_err(|e| refuse_unreadable("device revocation", e))?;
    eprintln!(
        "revoking device {} of identity {}",
        Fingerprint::of(&device),
        Fingerprint::of(&signer_identity)
    );
    post_record(&reg, &bytes)
}

// --- rotate --------------------------------------------------------------

/// `hlid rotate --registrar HOST --to SUCCESSOR_KEY`: hand the identity
/// over to the successor (§4.6). Both keys sign; the registrar publishes
/// the rotation only if it is to the committed key, if one was.
pub(crate) fn rotate_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = discover(&a)?;
    let old = identity(&a)?;
    let new = IdentityKey::from_seed(&read_seed(Path::new(a.one("to")?))?);
    let bytes = Rotation {
        identity: old.public(),
        successor: new.public(),
        time: now(),
    }
    .sign(&old, &new)
    .map_err(|e| refuse_unreadable("rotation", e))?;
    post_record(&reg, &bytes)?;

    // The successor has no card, and `register` puts the attestation
    // into one of the registering identity's own, so the next step is
    // two commands: a card, then a reissue per handle. The old card,
    // when it is where it usually is, fills in the name and the handles.
    let to = a.one("to")?;
    let old_card = a
        .file("card", CARD_FILE)
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| Card::parse(&b).ok())
        .filter(|c| c.identity == old.public());
    let name = old_card.as_ref().map_or("NAME", |c| c.name.as_str());
    let mut handles: Vec<&str> = old_card
        .iter()
        .flat_map(|c| &c.attestations)
        .filter(|att| att.registrar == reg.host)
        .map(|att| att.handle.as_str())
        .collect();
    if handles.is_empty() {
        handles.push("HANDLE");
    }
    let card = Path::new(to).with_file_name("successor-card.bin");
    let card = card.to_string_lossy();
    println!(
        "next: the successor {} needs a card of its own, and then each handle again \
         (a reissue, which keeps its age):",
        Fingerprint::of(&new.public())
    );
    println!(
        "  hlid card --identity {} --name {} -o {}",
        shell_word(to),
        shell_word(name),
        shell_word(&card)
    );
    for h in handles {
        println!(
            "  hlid register --registrar {} --identity {} --card {} --handle {} --no-put",
            shell_word(a.one("registrar")?),
            shell_word(to),
            shell_word(&card),
            shell_word(h)
        );
    }
    println!(
        "the card is published at the registrar once a device certified by the successor \
         logs in there"
    );
    Ok(())
}

/// A word as a POSIX shell reads it back: bare when that is safe, else
/// single-quoted.
fn shell_word(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./_-".contains(&b));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// For `hlid inspect`: a registration request or a user-signed record,
/// described.
pub(crate) fn describe(bytes: &[u8]) -> Option<Value> {
    if let Ok(r) = RegisterRequest::parse(bytes) {
        return Some(json!({
            "type": "register_request",
            "identity_fingerprint": Fingerprint::of(&r.identity).to_string(),
            "registrar": r.registrar, "handle": r.handle, "time": r.time,
            "successor": r.successor.map(|s| crate::hex(&s)),
            "proof": r.proof.is_some(),
        }));
    }
    let rec = Record::parse(bytes, None).ok()?;
    let mut v = json!({
        "type": rec.kind(),
        "identity_fingerprint": Fingerprint::of(rec.identity()).to_string(),
        "time": rec.time(),
    });
    match &rec {
        Record::RevokeDevice(r) => {
            v["device"] = json!(Fingerprint::of(&r.device).to_string());
            v["until"] = json!(r.until);
            v["reason"] = json!(r.reason);
            v["signed_by_device"] = json!(r.signer.map(|s| Fingerprint::of(&s).to_string()));
        }
        Record::RevokeIdentity(r) => v["reason"] = json!(r.reason),
        Record::Rotate(r) => {
            v["successor_fingerprint"] = json!(Fingerprint::of(&r.successor).to_string())
        }
        Record::Freeze(_) | Record::RevokeAttestation(_) => {}
    }
    Some(v)
}
