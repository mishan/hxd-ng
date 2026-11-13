//! Talking to a registrar (`docs/identity-registrar.md` §11's user
//! tools): register a handle, revoke a device or the identity, rotate to
//! a successor key, and keep the identity key there sealed (§9).
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

use hl_identity::envelope::{Kdf, Keys, Kind, Secret};
use hl_identity::registrar::{device_reason, identity_reason};
use hl_identity::{
    cbor, Attestation, Card, DeviceCert, DeviceKey, DeviceRevocation, EnvelopePut, Fingerprint,
    IdentityKey, IdentityRevocation, KeyEnvelope, Record, RecoveryCode, RegisterRequest, Rotation,
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
    envelopes: Option<String>,
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
        envelopes: endpoint("envelopes").ok(),
        base,
    })
}

/// Send a JSON body and return the JSON reply, or the registrar's
/// refusal: its code, and a sentence.
fn send(req: ureq::Request, body: Value) -> Result<Value, (String, String)> {
    let url = req.url().to_owned();
    match req.send_json(body) {
        Ok(resp) => resp
            .into_json()
            .map_err(|e| (String::new(), format!("{url}: {e}"))),
        Err(ureq::Error::Status(code, resp)) => {
            let body: Value = resp.into_json().unwrap_or(Value::Null);
            let error = body["error"].as_str().unwrap_or("?").to_owned();
            let sentence = format!(
                "refused ({code} {error}): {}",
                body["text"].as_str().unwrap_or("")
            );
            Err((error, sentence))
        }
        Err(e) => Err((String::new(), format!("{url}: {e}"))),
    }
}

/// POST `{ field: b64 }`.
fn post(url: &str, field: &str, bytes: &[u8]) -> R<Value> {
    send(agent().post(url), json!({ field: b64(bytes) })).map_err(|(_, e)| e)
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

// --- backup and restore ----------------------------------------------------

fn envelopes(reg: &Registrar) -> R<&str> {
    reg.envelopes
        .as_deref()
        .ok_or_else(|| format!("{} keeps no key backups", reg.host))
}

fn kind(a: &Args) -> Kind {
    match a.has("recovery") {
        true => Kind::RecoveryCode,
        false => Kind::Passphrase,
    }
}

/// Never from `--password`: a passphrase in `ps` is one anybody on the
/// machine can fetch the identity key with.
fn read_secret(a: &Args, what: &str) -> R<String> {
    if a.has("password") {
        return Err(format!(
            "--password would put {what} where `ps` shows it; use --password-file or \
             --password-stdin"
        ));
    }
    a.password()?
        .ok_or_else(|| format!("{what} is read from --password-file or --password-stdin"))
}

/// `hlid backup --registrar HOST [--recovery] [--delete]`: seal the
/// identity key and put the envelope at the registrar (§9.2), under a
/// passphrase, or under a recovery code made here and shown once.
pub(crate) fn backup_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = discover(&a)?;
    let url = envelopes(&reg)?.to_owned();
    let id = identity(&a)?;
    let kind = kind(&a);
    if a.has("delete") {
        put_envelope(&url, |time| EnvelopePut::delete(&id, &reg.host, kind, time))?;
        println!("the {} envelope is deleted at {}", noun(kind), reg.host);
        return Ok(());
    }
    let code = RecoveryCode::generate();
    let passphrase;
    let secret = match kind {
        Kind::RecoveryCode => Secret::RecoveryCode(&code),
        Kind::Passphrase => {
            passphrase = read_secret(&a, "the passphrase")?;
            if passphrase.chars().count() < 12 {
                eprintln!(
                    "hlid: a short passphrase is a weak one, and whoever holds the envelope \
                     can guess at it offline"
                );
            }
            Secret::Passphrase(&passphrase)
        }
    };
    let (envelope, keys) = KeyEnvelope::seal(&id, &secret).map_err(|e| format!("sealing: {e}"))?;
    put_envelope(&url, |time| {
        EnvelopePut::store(&id, &reg.host, time, &envelope, &keys)
    })?;
    println!(
        "the identity key is kept at {}, sealed under {}",
        reg.host,
        match kind {
            Kind::RecoveryCode => "a recovery code",
            Kind::Passphrase => "your passphrase",
        }
    );
    if kind == Kind::RecoveryCode {
        println!(
            "recovery code: {}\n\
             write it down; it is shown this once and kept nowhere, and it replaces \
             any code made before",
            code.display().as_str()
        );
    }
    Ok(())
}

/// A put must be later than the last of its kind, to the second, so one
/// refused as no newer is signed again once the second has turned.
fn put_envelope(url: &str, sign: impl Fn(u64) -> Result<Vec<u8>, hl_identity::Error>) -> R<()> {
    let send_at = |time| -> Result<Value, (String, String)> {
        let put = sign(time).map_err(|e| (String::new(), refuse_unreadable("envelope put", e)))?;
        send(agent().put(url), json!({ "request": b64(&put) }))
    };
    let first = now();
    match send_at(first) {
        Err((code, _)) if code == "bad_time" => {
            let wait = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| 1_000_000_000 - d.subsec_nanos())
                .unwrap_or(0);
            std::thread::sleep(std::time::Duration::from_nanos(wait.into()));
            send_at(now().max(first + 1)).map_err(|(_, e)| e)?;
        }
        other => {
            other.map_err(|(_, e)| e)?;
        }
    }
    Ok(())
}

fn noun(kind: Kind) -> &'static str {
    match kind {
        Kind::Passphrase => "passphrase",
        Kind::RecoveryCode => "recovery code",
    }
}

/// `hlid restore --registrar HOST --handle NAME [--recovery]`: the salt,
/// the keys derived from it, the envelope they fetch, and the identity
/// it opens to, laid out in `$HLID_HOME` as `hlid init` lays one out —
/// with a new device, and the card the registrar keeps when it has one.
pub(crate) fn restore_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = discover(&a)?;
    let url = envelopes(&reg)?.to_owned();
    let handle = a.one("handle")?;
    let kind = kind(&a);
    let typed = read_secret(&a, &format!("the {}", noun(kind)))?;
    let code;
    let secret = match kind {
        Kind::RecoveryCode => {
            code = RecoveryCode::parse(&typed)
                .ok_or("a recovery code is 20 characters, as four groups of five")?;
            Secret::RecoveryCode(&code)
        }
        Kind::Passphrase => Secret::Passphrase(&typed),
    };
    // Before the fetch, which the handle's counts are charged for.
    let home = crate::hlid_home()?;
    crate::laid_out_already(&home)?;

    let reply = send(
        agent().post(&format!("{url}/params")),
        json!({ "handle": handle, "kind": kind as u8 }),
    )
    .map_err(|(_, e)| e)?;
    let kdf = Kdf::parse(&unb64(reply["kdf"].as_str().ok_or("reply has no kdf")?)?)
        .map_err(|e| format!("the registrar's salt: {e}"))?;
    let keys = Keys::derive(&secret, kdf).map_err(|e| format!("deriving: {e}"))?;
    let reply = match send(
        agent().post(&format!("{url}/fetch")),
        json!({ "handle": handle, "kind": kind as u8, "auth": b64(keys.auth()) }),
    ) {
        Ok(reply) => reply,
        Err((code, _)) if code == "not_found" => {
            return Err(format!(
                "{} has no {} envelope for {handle} that this {} opens",
                reg.host,
                noun(kind),
                noun(kind)
            ))
        }
        Err((_, e)) => return Err(e),
    };
    let identity: [u8; 32] = unb64(reply["identity"].as_str().ok_or("reply has no identity")?)?
        .try_into()
        .map_err(|_| "the reply's identity is not 32 bytes".to_string())?;
    let envelope = KeyEnvelope::parse(&unb64(
        reply["envelope"].as_str().ok_or("reply has no envelope")?,
    )?)
    .map_err(|e| format!("the envelope: {e}"))?;
    let id = envelope
        .open(&identity, &keys)
        .map_err(|e| format!("the envelope did not open: {e}"))?;

    let card = agent()
        .get(&format!("{}/identity/card/{}", reg.base, id.fingerprint()))
        .call()
        .ok()
        .and_then(|resp| {
            let mut body = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(resp.into_reader(), 64 * 1024),
                &mut body,
            )
            .ok()?;
            Some(body)
        })
        .filter(|b| Card::parse(b).is_ok_and(|c| c.identity == id.public()));
    crate::lay_out(
        &home,
        &id,
        card.as_deref(),
        a.opt("name").unwrap_or(handle),
        &a,
    )?;
    println!(
        "identity {} restored to {}{}",
        id.fingerprint(),
        home.display(),
        if card.is_some() {
            ", with the card the registrar keeps"
        } else {
            ", with a new card"
        }
    );
    Ok(())
}
