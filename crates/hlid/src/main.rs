//! `hlid` — the Hotline identity tool.
//!
//! Everything a user or operator needs to exercise
//! `docs/hotline-ng-identity.md` from a shell:
//!
//! ```text
//! hlid keygen identity|device|server PATH     make a key (32-byte seed, hex, mode 0600)
//! hlid cert    --identity K --device K [--days N] [--caps all|web|LIST] [--name S] -o FILE
//! hlid card    --identity K --name S [--icon N] [--profile S] [--link URL]... [--attestation FILE]... -o FILE
//! hlid attest  --registrar-key K --registrar HOST --identity K|--identity-pub HEX --handle S
//!              [--registered UNIX] [--days N] [--level N] -o FILE
//! hlid inspect FILE                           print any signed object
//! hlid auth    --server URL --device K --card FILE --cert FILE [--login L --password P]
//!              challenge binding → token; with credentials, links the account (§8.2)
//! hlid link    --server URL --device K --card FILE --cert FILE --login L --password P
//! hlid unlink  --server URL --device K --card FILE --cert FILE
//! hlid tunnel  --server URL --device K --card FILE --cert FILE [--listen ADDR]
//!              local TCP port for a classic client, TRTP over WebSocket upstream
//! ```
//!
//! Key files are the raw seed in hex. That is the prototype's storage;
//! the registrar spec's password-wrapped envelope replaces it, and the
//! seed format is what that envelope will wrap, so nothing here is
//! thrown away.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use hl_identity::{
    attestation, caps, cbor, cert, Attestation, Card, DeviceCert, DeviceKey, Fingerprint,
    IdentityKey, LoginProof, ServerKey,
};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let r = match cmd.as_str() {
        "keygen" => keygen(&args[1..]),
        "cert" => make_cert(&args[1..]),
        "card" => make_card(&args[1..]),
        "attest" => make_attestation(&args[1..]),
        "inspect" => inspect(&args[1..]),
        "auth" => auth_cmd(&args[1..]),
        "link" => link_cmd(&args[1..]),
        "unlink" => unlink_cmd(&args[1..]),
        "tunnel" => tunnel_cmd(&args[1..]),
        _ => usage(),
    };
    if let Err(e) = r {
        eprintln!("hlid: {e}");
        exit(1);
    }
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  hlid keygen identity|device|server PATH\n  hlid cert --identity K --device K [--days N] [--caps all|web|LIST] [--name S] -o FILE\n  hlid card --identity K --name S [--icon N] [--profile S] [--link URL]... [--attestation FILE]... -o FILE\n  hlid attest --registrar-key K --registrar HOST (--identity K | --identity-pub HEX) --handle S [--registered UNIX] [--days N] [--level N] -o FILE\n  hlid inspect FILE\n  hlid auth --server URL --device K --card FILE --cert FILE [--login L --password P]\n  hlid link --server URL --device K --card FILE --cert FILE --login L --password P\n  hlid unlink --server URL --device K --card FILE --cert FILE\n  hlid tunnel --server URL --device K --card FILE --cert FILE [--listen 127.0.0.1:5500]"
    );
    exit(2)
}

type R<T> = Result<T, String>;

// --- Argument parsing: `--key value` pairs, repeated keys collected ------

struct Args {
    flags: HashMap<String, Vec<String>>,
}

fn parse(args: &[String]) -> Args {
    let mut flags: HashMap<String, Vec<String>> = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = match args[i].strip_prefix("--") {
            Some(k) => k,
            None if args[i] == "-o" => "o",
            None => {
                eprintln!("hlid: unexpected argument {:?}", args[i]);
                exit(2);
            }
        };
        let v = args.get(i + 1).cloned().unwrap_or_default();
        flags.entry(key.to_owned()).or_default().push(v);
        i += 2;
    }
    Args { flags }
}

impl Args {
    fn one(&self, k: &str) -> R<&str> {
        self.flags
            .get(k)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| format!("--{k} is required"))
    }
    fn opt(&self, k: &str) -> Option<&str> {
        self.flags
            .get(k)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    fn many(&self, k: &str) -> Vec<&str> {
        self.flags
            .get(k)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
    fn u64(&self, k: &str, default: u64) -> R<u64> {
        match self.opt(k) {
            Some(s) => s.parse().map_err(|_| format!("--{k}: not a number")),
            None => Ok(default),
        }
    }
}

// --- Files ---------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> R<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "not hex".to_string()))
        .collect()
}

fn read_seed(path: &str) -> R<[u8; 32]> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    unhex(&text)?
        .try_into()
        .map_err(|_| format!("{path}: seed must be 32 bytes"))
}

fn write_private(path: &Path, text: &str) -> R<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{text}").map_err(|e| e.to_string())
}

fn write_out(a: &Args, bytes: &[u8]) -> R<()> {
    let path = a.one("o")?;
    std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}"))?;
    eprintln!("wrote {} bytes to {path}", bytes.len());
    Ok(())
}

fn read_file(path: &str) -> R<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> R<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "not base64url".to_string())
}

// --- Commands ------------------------------------------------------------

fn keygen(args: &[String]) -> R<()> {
    let [kind, path] = args else { usage() };
    let path = PathBuf::from(path);
    let mut seed = [0u8; 32];
    getrandom_seed(&mut seed);
    write_private(&path, &hex(&seed))?;
    match kind.as_str() {
        "identity" => {
            let k = IdentityKey::from_seed(&seed);
            println!(
                "identity key written to {}\npublic:      {}\nfingerprint: {}",
                path.display(),
                hex(&k.public()),
                k.fingerprint()
            );
        }
        "device" => {
            let k = DeviceKey::from_seed(&seed);
            println!(
                "device key written to {}\npublic:      {}\npublic_enc:  {}\nfingerprint: {}",
                path.display(),
                hex(&k.public()),
                hex(&k.public_enc()),
                k.fingerprint()
            );
        }
        "server" => {
            let k = ServerKey::from_seed(&seed);
            println!("server key written to {}\npublic:      {}\npublic (b64url, for registrar_keys): {}", path.display(), hex(&k.public()), b64(&k.public()));
        }
        _ => usage(),
    }
    Ok(())
}

fn getrandom_seed(seed: &mut [u8; 32]) {
    // Borrow the crate's generator through a throwaway key rather than
    // add a second randomness dependency here.
    *seed = *IdentityKey::generate().seed();
}

fn make_cert(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = IdentityKey::from_seed(&read_seed(a.one("identity")?)?);
    let dev = DeviceKey::from_seed(&read_seed(a.one("device")?)?);
    let days = a.u64("days", cert::RECOMMENDED_LIFETIME / 86_400)?;
    let mut c = DeviceCert::for_device(&id, &dev, now(), days * 86_400);
    c.caps = match a.opt("caps") {
        None | Some("all") => None,
        Some("web") => Some(caps::WEB),
        Some(list) => Some(
            list.split(',')
                .map(|s| match s.trim() {
                    "login" => Ok(caps::LOGIN),
                    "message" => Ok(caps::MESSAGE),
                    "vouch" => Ok(caps::VOUCH),
                    "manage" => Ok(caps::MANAGE),
                    other => Err(format!("unknown capability {other:?}")),
                })
                .collect::<R<Vec<u64>>>()?
                .into_iter()
                .fold(0, |acc, b| acc | b),
        ),
    };
    c.name = a.opt("name").map(str::to_owned);
    write_out(&a, &c.sign(&id))
}

fn make_card(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = IdentityKey::from_seed(&read_seed(a.one("identity")?)?);
    let mut card = Card::new(&id, a.one("name")?, now());
    card.icon = match a.opt("icon") {
        Some(s) => Some(s.parse().map_err(|_| "--icon: not a number".to_string())?),
        None => None,
    };
    card.profile = a.opt("profile").map(str::to_owned);
    card.links = a.many("link").into_iter().map(str::to_owned).collect();
    let atts = a
        .many("attestation")
        .into_iter()
        .map(|p| {
            let bytes = read_file(p)?;
            Attestation::parse(&bytes).map_err(|e| format!("{p}: {e}"))?;
            cbor::decode_canonical(&bytes).map_err(|e| format!("{p}: {e}"))
        })
        .collect::<R<Vec<_>>>()?;
    write_out(&a, &card.sign(&id, atts).map_err(|e| e.to_string())?)
}

fn make_attestation(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = ServerKey::from_seed(&read_seed(a.one("registrar-key")?)?);
    let identity: [u8; 32] = match (a.opt("identity"), a.opt("identity-pub")) {
        (Some(seed), _) => IdentityKey::from_seed(&read_seed(seed)?).public(),
        (None, Some(pubhex)) => unhex(pubhex)?
            .try_into()
            .map_err(|_| "--identity-pub: 32 bytes".to_string())?,
        (None, None) => return Err("--identity or --identity-pub is required".into()),
    };
    let t = now();
    let att = Attestation {
        identity,
        registrar: a.one("registrar")?.to_lowercase(),
        registrar_key: reg.public(),
        handle: a.one("handle")?.to_owned(),
        registered: a.u64("registered", t)?,
        issued: t,
        expires: t + a.u64("days", attestation::RECOMMENDED_LIFETIME / 86_400)? * 86_400,
        level: match a.opt("level") {
            Some(s) => Some(s.parse().map_err(|_| "--level: not a number".to_string())?),
            None => None,
        },
    };
    write_out(&a, &att.sign(&reg))
}

fn inspect(args: &[String]) -> R<()> {
    let [path] = args else { usage() };
    let bytes = read_file(path)?;
    let doc = if let Ok(c) = DeviceCert::parse(&bytes) {
        json!({
            "type": "device_cert",
            "identity": hex(&c.identity), "identity_fingerprint": Fingerprint::of(&c.identity).to_string(),
            "device": hex(&c.device), "device_enc": hex(&c.device_enc),
            "issued": c.issued, "expires": c.expires, "caps": c.caps, "name": c.name,
        })
    } else if let Ok(c) = Card::parse(&bytes) {
        json!({
            "type": "card",
            "identity": hex(&c.identity), "identity_fingerprint": Fingerprint::of(&c.identity).to_string(),
            "updated": c.updated, "name": c.name, "icon": c.icon, "profile": c.profile, "links": c.links,
            "attestations": c.attestations.iter().map(|a| json!({
                "handle": a.full_handle(), "registered": a.registered, "issued": a.issued, "expires": a.expires,
                "level": a.level, "registrar_key": hex(&a.registrar_key),
            })).collect::<Vec<_>>(),
            "vouches": c.vouches.len(),
        })
    } else if let Ok(a) = Attestation::parse(&bytes) {
        json!({
            "type": "attestation",
            "identity": hex(&a.identity), "identity_fingerprint": Fingerprint::of(&a.identity).to_string(),
            "handle": a.full_handle(), "registrar_key": hex(&a.registrar_key),
            "registered": a.registered, "issued": a.issued, "expires": a.expires, "level": a.level,
        })
    } else if let Ok(p) = LoginProof::parse(&bytes) {
        json!({
            "type": "login_proof",
            "device": hex(&p.device), "challenge": hex(&p.challenge), "server_key": hex(&p.server_key), "time": p.time,
        })
    } else {
        // Say which parser got furthest: the first error that isn't "wrong
        // object" is the useful one.
        let errs = [
            ("device_cert", DeviceCert::parse(&bytes).err()),
            ("card", Card::parse(&bytes).err()),
            ("attestation", Attestation::parse(&bytes).err()),
            ("login_proof", LoginProof::parse(&bytes).err()),
        ];
        let mut msg = String::from("not a recognised identity object:");
        for (k, e) in errs {
            if let Some(e) = e {
                msg.push_str(&format!("\n  as {k}: {e}"));
            }
        }
        return Err(msg);
    };
    // `println!` panics on a closed pipe (`hlid inspect x | head`); a
    // write error on stdout is just the reader going away.
    let _ = writeln!(
        std::io::stdout(),
        "{}",
        serde_json::to_string_pretty(&doc).unwrap()
    );
    Ok(())
}

// --- Talking to a server -------------------------------------------------

struct Credentials {
    device: DeviceKey,
    card: Vec<u8>,
    cert: Vec<u8>,
}

fn credentials(a: &Args) -> R<Credentials> {
    Ok(Credentials {
        device: DeviceKey::from_seed(&read_seed(a.one("device")?)?),
        card: read_file(a.one("card")?)?,
        cert: read_file(a.one("cert")?)?,
    })
}

/// `http(s)://host[:port]` → the same with no trailing slash.
fn server_base(a: &Args) -> R<String> {
    let s = a.one("server")?.trim_end_matches('/').to_owned();
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return Err("--server must start with http:// or https://".into());
    }
    Ok(s)
}

/// The challenge binding (§5.2) against a server. Blocking; small.
fn authenticate(base: &str, c: &Credentials) -> R<Value> {
    authenticate_with(base, c, None)
}

/// Same, optionally with classic credentials to link in the same step
/// (§5.4, §8.2).
fn authenticate_with(base: &str, c: &Credentials, classic: Option<(&str, &str)>) -> R<Value> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let ch: Value = agent
        .post(&format!("{base}/identity/challenge"))
        .call()
        .map_err(|e| format!("challenge: {e}"))?
        .into_json()
        .map_err(|e| format!("challenge: {e}"))?;
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap_or(""))?
        .try_into()
        .map_err(|_| "challenge: bad length".to_string())?;
    let server_key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap_or(""))?
        .try_into()
        .map_err(|_| "server_key: bad length".to_string())?;
    let proof = LoginProof::sign(&c.device, &challenge, &server_key, now());
    let mut body =
        json!({ "card": b64(&c.card), "device_cert": b64(&c.cert), "proof": b64(&proof) });
    if let Some((login, password)) = classic {
        body["login"] = json!(login);
        body["password"] = json!(password);
    }
    match agent.post(&format!("{base}/identity/auth")).send_json(body) {
        Ok(resp) => resp.into_json().map_err(|e| format!("auth: {e}")),
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            Err(format!("auth refused ({code}): {text}"))
        }
        Err(e) => Err(format!("auth: {e}")),
    }
}

fn auth_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let base = server_base(&a)?;
    let c = credentials(&a)?;
    let classic = a.opt("login").zip(a.opt("password"));
    let reply = authenticate_with(&base, &c, classic)?;
    println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    Ok(())
}

/// A token-authenticated POST to an identity endpoint.
fn post_with_token(base: &str, c: &Credentials, path: &str, body: Value) -> R<Value> {
    let token = authenticate(base, c)?;
    let token = token["token"].as_str().ok_or("auth reply had no token")?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let req = agent
        .post(&format!("{base}{path}"))
        .set("Authorization", &format!("Bearer {token}"));
    let result = if body.is_null() {
        req.call()
    } else {
        req.send_json(body)
    };
    match result {
        Ok(resp) => resp.into_json().map_err(|e| format!("{path}: {e}")),
        Err(ureq::Error::Status(code, resp)) => Err(format!(
            "{path} refused ({code}): {}",
            resp.into_string().unwrap_or_default()
        )),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

fn link_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let base = server_base(&a)?;
    let c = credentials(&a)?;
    let body = json!({ "login": a.one("login")?, "password": a.one("password")? });
    let reply = post_with_token(&base, &c, "/identity/link", body)?;
    println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    Ok(())
}

fn unlink_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let base = server_base(&a)?;
    let c = credentials(&a)?;
    let reply = post_with_token(&base, &c, "/identity/unlink", Value::Null)?;
    println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    Ok(())
}

fn tunnel_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let base = server_base(&a)?;
    let c = credentials(&a)?;
    let listen = a.opt("listen").unwrap_or("127.0.0.1:5500").to_owned();
    if !listen.starts_with("127.")
        && !listen.starts_with("[::1]")
        && !listen.starts_with("localhost")
    {
        // §11.1: the local hop is cleartext, so it stays on loopback
        // unless the user says otherwise on purpose.
        if a.opt("allow-remote-listen").is_none() {
            return Err(format!(
                "{listen} is not loopback; pass --allow-remote-listen 1 if you mean it"
            ));
        }
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .map_err(|e| format!("{listen}: {e}"))?;
        // Check credentials once up front so a typo fails now, not on the
        // first connection.
        let probe = tokio::task::spawn_blocking({
            let base = base.clone();
            let creds = Credentials {
                device: DeviceKey::from_seed(&c.device.seed()),
                card: c.card.clone(),
                cert: c.cert.clone(),
            };
            move || authenticate(&base, &creds)
        })
        .await
        .map_err(|e| e.to_string())??;
        eprintln!(
            "authenticated to {base} as {} ({}); tunnelling {listen} → {base}/trtp",
            probe["fingerprint"].as_str().unwrap_or("?"),
            probe["outcome"].as_str().unwrap_or("?")
        );
        let ws_base = format!("ws{}", &base[4..]); // http → ws, https → wss
        let c = std::sync::Arc::new(c);
        loop {
            let (sock, peer) = listener.accept().await.map_err(|e| e.to_string())?;
            let (base, ws_base, c) = (base.clone(), ws_base.clone(), c.clone());
            tokio::spawn(async move {
                if let Err(e) = tunnel_one(sock, &base, &ws_base, &c).await {
                    eprintln!("tunnel {peer}: {e}");
                }
            });
        }
    })
}

/// One legacy connection: fresh token, WebSocket to /trtp, pump both ways.
async fn tunnel_one(
    sock: tokio::net::TcpStream,
    base: &str,
    ws_base: &str,
    c: &Credentials,
) -> R<()> {
    let _ = sock.set_nodelay(true);
    let token = {
        let base = base.to_owned();
        let creds = Credentials {
            device: DeviceKey::from_seed(&c.device.seed()),
            card: c.card.clone(),
            cert: c.cert.clone(),
        };
        tokio::task::spawn_blocking(move || authenticate(&base, &creds))
            .await
            .map_err(|e| e.to_string())??
    };
    let token = token["token"]
        .as_str()
        .ok_or("auth reply had no token")?
        .to_owned();
    let mut req = format!("{ws_base}/trtp")
        .into_client_request()
        .map_err(|e| e.to_string())?;
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .map_err(|e| format!("upstream: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut rd, mut wr) = sock.into_split();

    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut rd, &mut buf)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                let _ = ws_tx.close().await;
                return Ok::<(), String>(());
            }
            ws_tx
                .send(Message::Binary(buf[..n].to_vec()))
                .await
                .map_err(|e| e.to_string())?;
        }
    };
    let down = async {
        while let Some(m) = ws_rx.next().await {
            match m.map_err(|e| e.to_string())? {
                Message::Binary(b) => tokio::io::AsyncWriteExt::write_all(&mut wr, &b)
                    .await
                    .map_err(|e| e.to_string())?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut wr).await;
        Ok::<(), String>(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}
