//! `hlid` — the Hotline identity tool.
//!
//! Everything a user or operator needs to exercise
//! `docs/hotline-ng-identity.md` from a shell:
//!
//! ```text
//! hlid init    --name S [--days N] [--device-name S]
//!              identity key, device key, certificate and card in one step
//! hlid enroll  --server URL [--caps web|LIST] [--days N]
//!              show a pairing code, wait for one device, prompt, certify
//! hlid keygen  identity|device|server PATH    make a key (32-byte seed, hex, mode 0600)
//! hlid cert    [--identity K] (--device K | --device-pub HEX --device-enc-pub HEX)
//!              [--days N] [--caps all|web|LIST] [--name S] [--bundle] -o FILE
//! hlid card    [--identity K] --name S [--icon N] [--profile S] [--link URL]...
//!              [--attestation FILE]... [--successor HEX|--successor-key FILE] -o FILE
//! hlid attest  --registrar-key K --registrar HOST --identity K|--identity-pub HEX --handle S
//!              [--registered UNIX] [--days N] [--level N] -o FILE
//! hlid inspect FILE                           print any signed object
//! hlid auth    --server URL [--device K] [--card FILE] [--cert FILE] [--login L]
//!              [--password P | --password-file F | --password-stdin] [--no-create]
//!              challenge binding → token; with credentials, links the account (§8.2)
//! hlid link    --server URL [--device K] [--card FILE] [--cert FILE] --login L --password P
//! hlid unlink  --server URL [--device K] [--card FILE] [--cert FILE]
//! hlid tunnel  --server URL [--device K] [--card FILE] [--cert FILE] [--listen ADDR]
//!              [--allow-remote-listen] [--create]
//!              local TCP port for a classic client, TRTP over WebSocket upstream
//! ```
//!
//! `--password` puts a secret on the command line, where anyone on the
//! machine can read it out of `ps`. `--password-file` and
//! `--password-stdin` don't; prefer them, and prompt-based entry lands
//! with the registrar spec's password-wrapped key envelope.
//!
//! `--identity`, `--device`, `--cert` and `--card` fall back to fixed
//! names in `$HLID_HOME` (default `~/.hlid`), which is what `hlid init`
//! fills. That exists so a command a web client prints for the user to
//! run can be exact: the browser cannot know where this machine keeps its
//! identity key, and a pre-filled path that guesses is right only for
//! whoever followed one particular tutorial.
//!
//! Key files are the raw seed in hex. That is the prototype's storage;
//! the registrar spec's password-wrapped envelope replaces it, and the
//! seed format is what that envelope will wrap, so nothing here is
//! thrown away.

mod enroll;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use hl_identity::{
    attestation, caps, cbor, cert, Attestation, Bundle, Card, DeviceCert, DeviceKey, Fingerprint,
    IdentityKey, LoginProof, PublicKey, ServerKey,
};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let r = match cmd.as_str() {
        "init" => init(&args[1..]),
        "enroll" => enroll::enroll_cmd(&args[1..]),
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
    eprintln!(concat!(
        "usage:\n",
        "  hlid init --name S [--days N] [--device-name S]\n",
        "  hlid enroll --server URL [--caps web|LIST] [--days N] [--identity K] [--card FILE] [--web URL] [--show-url]\n",
        "  hlid keygen identity|device|server PATH\n",
        "  hlid cert [--identity K] (--device K | --device-pub HEX --device-enc-pub HEX) [--days N] [--caps all|web|LIST] [--name S] [--bundle [--card FILE]] -o FILE\n",
        "  hlid card [--identity K] --name S [--icon N] [--profile S] [--link URL]... [--attestation FILE]...\n",
        "       [--successor HEX | --successor-key FILE] -o FILE\n",
        "  hlid attest --registrar-key K --registrar HOST (--identity K | --identity-pub HEX) --handle S [--registered UNIX] [--days N] [--level N] -o FILE\n",
        "  hlid inspect FILE\n",
        "  hlid auth --server URL [--device K] [--card FILE] [--cert FILE] [--login L] [--password P | --password-file F | --password-stdin] [--no-create]\n",
        "  hlid link --server URL [--device K] [--card FILE] [--cert FILE] --login L [--password P | --password-file F | --password-stdin]\n",
        "  hlid unlink --server URL [--device K] [--card FILE] [--cert FILE]\n",
        "  hlid tunnel --server URL [--device K] [--card FILE] [--cert FILE] [--listen 127.0.0.1:5500] [--allow-remote-listen] [--create]\n",
        "\n",
        "`hlid init` writes identity.key, device.key, cert.bin and card.bin into\n",
        "$HLID_HOME (default ~/.hlid), and --identity, --device, --cert and --card\n",
        "fall back to them, so a command printed by a web client for you to run\n",
        "can be exact without guessing where you keep your key. `attest` is the\n",
        "exception: a registrar attests somebody else, so its flags stay explicit.\n",
        "\n",
        "`hlid enroll` replaces the paste: it opens a session at the server's\n",
        "enrollment mailbox, shows a code to type into the browser, and asks\n",
        "before it certifies anything. --caps defaults to `web` — login and\n",
        "message, never vouch or manage — and nothing a request asks for can\n",
        "widen that. When the server advertises a web client on its own origin\n",
        "it also draws a QR code, and says which origin the scan will open: the\n",
        "link carries the pairing secret, so a client hosted somewhere else has\n",
        "to be named by you with --web rather than by the server. --show-url\n",
        "prints the link beneath the code, which puts that secret in your\n",
        "scrollback.\n",
        "\n",
        "--bundle writes the certificate and the identity's card as one object\n",
        "instead of the certificate alone — the same thing enrollment carries, so\n",
        "a browser has one blob to paste and one format to verify.\n",
        "\n",
        "--device-pub/--device-enc-pub certify a device this tool never held the\n",
        "private key for — a browser's non-extractable WebCrypto key, in\n",
        "particular. They do not fall back to the default directory: the point of\n",
        "them is that the device is somewhere else.\n",
        "\n",
        "Password options: --password puts the secret in `ps` output; prefer\n",
        "--password-file or --password-stdin.",
    ));
    exit(2)
}

pub(crate) type R<T> = Result<T, String>;

// --- Argument parsing: `--key value` pairs, repeated keys collected ------

pub(crate) struct Args {
    flags: HashMap<String, Vec<String>>,
}

/// Flags that stand alone; everything else takes a value. Without this
/// list a bare `--allow-remote-listen` swallowed the next argument, so it
/// needed a dummy value nothing documented.
const BARE: &[&str] = &[
    "allow-remote-listen",
    "bundle",
    "show-url",
    "password-stdin",
    "no-create",
    "create",
];

pub(crate) fn parse(args: &[String]) -> Args {
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
        if BARE.contains(&key) {
            flags.entry(key.to_owned()).or_default().push(String::new());
            i += 1;
            continue;
        }
        let Some(v) = args.get(i + 1).cloned() else {
            eprintln!("hlid: --{key} needs a value");
            exit(2);
        };
        flags.entry(key.to_owned()).or_default().push(v);
        i += 2;
    }
    Args { flags }
}

impl Args {
    pub(crate) fn one(&self, k: &str) -> R<&str> {
        self.flags
            .get(k)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| format!("--{k} is required"))
    }
    pub(crate) fn opt(&self, k: &str) -> Option<&str> {
        self.flags
            .get(k)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    pub(crate) fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
    /// A password from the least-bad source the user offered.
    /// `--password` is accepted because scripts exist, but it is visible
    /// in `ps` to everyone on the machine, so the other two come first.
    fn password(&self) -> R<Option<String>> {
        if self.has("password-stdin") {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
                .map_err(|e| format!("--password-stdin: {e}"))?;
            return Ok(Some(s.trim_end_matches(['\r', '\n']).to_owned()));
        }
        if let Some(path) = self.opt("password-file") {
            let s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            return Ok(Some(s.trim_end_matches(['\r', '\n']).to_owned()));
        }
        if let Some(p) = self.opt("password") {
            eprintln!(
                "hlid: --password is visible to other users via `ps`; \
                 prefer --password-file or --password-stdin"
            );
            return Ok(Some(p.to_owned()));
        }
        Ok(None)
    }
    fn many(&self, k: &str) -> Vec<&str> {
        self.flags
            .get(k)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
    /// A file this tool keeps for the user: the flag when it was given,
    /// else the default directory's name for it — but only when that is
    /// actually there, so that "you have no identity key" and "the one
    /// you named is missing" stay different errors. `None` means
    /// neither, which some callers read as "not asked for" rather than
    /// as a failure.
    pub(crate) fn file_opt(&self, flag: &str, name: &str) -> Option<PathBuf> {
        if let Some(p) = self.opt(flag) {
            return Some(PathBuf::from(p));
        }
        let p = hlid_home().ok()?.join(name);
        // `is_file`, not `exists`: a directory of that name would be
        // taken as the default and then fail on read with "Is a
        // directory", which is exactly the unhelpful error the fallback
        // exists to avoid.
        p.is_file().then_some(p)
    }

    pub(crate) fn file(&self, flag: &str, name: &str) -> R<PathBuf> {
        if let Some(p) = self.file_opt(flag, name) {
            return Ok(p);
        }
        // Two different failures, and splicing one into the other's
        // sentence made nonsense of both: with no home directory there
        // is no "{name} in {home}" to talk about, so say that instead.
        let home = hlid_home()?;
        Err(format!(
            "--{flag} is required, and there is no {name} in {} to fall back to (`hlid init` writes one)",
            home.display()
        ))
    }

    pub(crate) fn u64(&self, k: &str, default: u64) -> R<u64> {
        match self.opt(k) {
            Some(s) => s.parse().map_err(|_| format!("--{k}: not a number")),
            None => Ok(default),
        }
    }
}

// --- Files ---------------------------------------------------------------

/// Days as seconds, refusing a number that cannot be one. `days * 86_400`
/// wraps silently in release for anything past ~2^44, which would produce
/// a signed object with an expiry in the past.
pub(crate) fn seconds(days: u64) -> R<u64> {
    if days == 0 {
        // Issued and expiring at the same second: every verifier refuses
        // it, so writing it only wastes the user's next command.
        return Err("--days: must be at least 1".into());
    }
    days.checked_mul(86_400)
        .filter(|_| days <= 36_500)
        .ok_or_else(|| "--days: must be 36500 or fewer (100 years)".to_string())
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Hex to bytes, over bytes rather than characters: `&s[i..i + 2]` on a
/// `&str` panics when the split lands inside a multi-byte character, so
/// a key file with an accent in it aborted the tool instead of failing.
fn unhex(s: &str) -> R<Vec<u8>> {
    let s = s.trim().as_bytes();
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    fn digit(b: u8) -> R<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("not hex".to_string()),
        }
    }
    s.chunks(2)
        .map(|p| Ok(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

/// `$HLID_HOME`, else `~/.hlid`. The directory exists so that a command
/// printed for a user to run can be exact: hx-ng's identity panel shows
/// `hlid cert --device-pub …` and has no way to know where this machine
/// keeps its identity key, so a pre-filled `--identity ~/.hlid/identity.key`
/// is right only for whoever followed one particular tutorial. A
/// pre-filled command that is wrong is worse than no command at all.
pub(crate) fn hlid_home() -> R<PathBuf> {
    if let Some(h) = std::env::var_os("HLID_HOME") {
        return Ok(PathBuf::from(h));
    }
    let home = std::env::var_os("HOME").ok_or(
        "neither $HLID_HOME nor $HOME is set, so there is no default \
         directory to look in; name the file explicitly",
    )?;
    Ok(PathBuf::from(home).join(".hlid"))
}

/// The fixed names inside it: what `hlid init` writes, and what the
/// corresponding flags fall back to when they are omitted.
pub(crate) const IDENTITY_KEY: &str = "identity.key";
const DEVICE_KEY: &str = "device.key";
const CERT_FILE: &str = "cert.bin";
pub(crate) const CARD_FILE: &str = "card.bin";

pub(crate) fn read_seed(path: &Path) -> R<[u8; 32]> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    unhex(&text)?
        .try_into()
        .map_err(|_| format!("{}: seed must be 32 bytes", path.display()))
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

/// An object this build would refuse to read is not one to write. The
/// checks live in `hl-identity`'s parsers, so this is the one place that
/// has to know they exist: `--level 7`, an attestation about someone
/// else, a name with an invisible character in it.
pub(crate) fn refuse_unreadable(kind: &str, e: hl_identity::Error) -> String {
    format!("refusing to write a {kind} this build would reject: {e}")
}

pub(crate) fn read_file(path: &Path) -> R<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Write a signed object. Not `write_private`: these are public material
/// that other people are meant to be given, and `create_new` would make
/// re-running `hlid cert` after a certificate expires an error.
fn write_file(path: &Path, bytes: &[u8]) -> R<()> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn unb64(s: &str) -> R<Vec<u8>> {
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

/// `hlid init --name S`: nothing to an identity in one command.
///
/// Four objects, written into the default directory under the names
/// every other command falls back to: an identity key, a device key for
/// this machine, an unrestricted certificate for that device, and a
/// card. That is the whole of what a person needs before they can
/// certify a browser, and doing it in one step is the difference
/// between hx-ng's panel saying "run this" and it saying "first,
/// read the identity spec".
fn init(args: &[String]) -> R<()> {
    let a = parse(args);
    let name = a.one("name")?;
    let home = hlid_home()?;
    create_private_dir(&home)?;

    // Check all four before writing any: a second `init` over a live
    // identity that failed half way would leave the directory holding a
    // device key certified by nothing, which is harder to explain than
    // refusing outright.
    for f in [IDENTITY_KEY, DEVICE_KEY, CERT_FILE, CARD_FILE] {
        let p = home.join(f);
        if p.exists() {
            return Err(format!(
                "{} already exists; hlid init will not write over an identity",
                p.display()
            ));
        }
    }

    let mut id_seed = [0u8; 32];
    getrandom_seed(&mut id_seed);
    write_private(&home.join(IDENTITY_KEY), &hex(&id_seed))?;
    let id = IdentityKey::from_seed(&id_seed);

    let mut dev_seed = [0u8; 32];
    getrandom_seed(&mut dev_seed);
    write_private(&home.join(DEVICE_KEY), &hex(&dev_seed))?;
    let dev = DeviceKey::from_seed(&dev_seed);

    // Unrestricted caps: this device sits on the same machine as the
    // identity key, so a capability bit withheld from it protects
    // nothing — anything it is not allowed to do can be done by reading
    // the key file next to it. Restricted certificates are for the
    // devices this one goes on to certify.
    let days = a.u64("days", cert::RECOMMENDED_LIFETIME / 86_400)?;
    let mut c = DeviceCert::for_keys(&id, dev.public(), dev.public_enc(), now(), seconds(days)?)
        .map_err(|e| format!("--days: {e}"))?;
    c.name = Some(a.opt("device-name").unwrap_or("this machine").to_owned());
    let cert_bytes = c.sign(&id);
    DeviceCert::parse(&cert_bytes).map_err(|e| refuse_unreadable("device certificate", e))?;
    write_file(&home.join(CERT_FILE), &cert_bytes)?;

    let card_bytes = Card::new(&id, name, now())
        .sign(&id, Vec::new())
        .map_err(|e| e.to_string())?;
    Card::parse(&card_bytes).map_err(|e| refuse_unreadable("card", e))?;
    write_file(&home.join(CARD_FILE), &card_bytes)?;

    println!(
        "identity written to {}\n\
         name:        {name}\n\
         fingerprint: {}\n\
         \n\
         Every other hlid command falls back to these files, so --identity,\n\
         --device, --cert and --card can be left off from here on.",
        home.display(),
        id.fingerprint()
    );
    Ok(())
}

/// The directory holds private keys, so it is created 0700 rather than
/// left to the umask. Existing is not an error — a user may well have
/// made it themselves — but its mode is then theirs, not ours.
fn create_private_dir(path: &Path) -> R<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn getrandom_seed(seed: &mut [u8; 32]) {
    // Borrow the crate's generator through a throwaway key rather than
    // add a second randomness dependency here.
    *seed = *IdentityKey::generate().seed();
}

fn make_cert(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = IdentityKey::from_seed(&read_seed(&a.file("identity", IDENTITY_KEY)?)?);
    // `--device` names a seed file this tool holds; `--device-pub` +
    // `--device-enc-pub` certify a device whose private keys never left
    // wherever they were generated — a browser's non-extractable
    // `CryptoKey`s, which can only ever export their public halves
    // (hx-ng's `docs/identity-keys.md` §9).
    //
    // Only the seed form falls back to the default directory. The public
    // keys are the explicit request; silently certifying this machine's
    // own device key because `--device-enc-pub` was left off a command
    // pasted from a browser would hand back a certificate for the wrong
    // device, which the browser would reject with nothing to say about
    // why.
    let (device, device_enc): (PublicKey, [u8; 32]) =
        if a.has("device-pub") || a.has("device-enc-pub") {
            if a.has("device") {
                return Err("--device and --device-pub/--device-enc-pub are alternatives".into());
            }
            (
                unhex(a.one("device-pub")?)?
                    .try_into()
                    .map_err(|_| "--device-pub: 32 bytes".to_string())?,
                unhex(a.one("device-enc-pub")?)?
                    .try_into()
                    .map_err(|_| "--device-enc-pub: 32 bytes".to_string())?,
            )
        } else {
            let path = a.file_opt("device", DEVICE_KEY).ok_or_else(|| {
                let home = hlid_home().map_or_else(|e| e, |h| h.display().to_string());
                format!(
                    "--device or --device-pub (with --device-enc-pub) is required, \
                 and there is no {DEVICE_KEY} in {home} to fall back to"
                )
            })?;
            let dev = DeviceKey::from_seed(&read_seed(&path)?);
            (dev.public(), dev.public_enc())
        };
    let days = a.u64("days", cert::RECOMMENDED_LIFETIME / 86_400)?;
    let mut c = DeviceCert::for_keys(&id, device, device_enc, now(), seconds(days)?)
        .map_err(|e| format!("--days: {e}"))?;
    c.caps = parse_caps(a.opt("caps"))?;
    c.name = a.opt("name").map(str::to_owned);
    let bytes = c.sign(&id);
    DeviceCert::parse(&bytes).map_err(|e| refuse_unreadable("device certificate", e))?;

    // `--bundle` writes the §5.4 object instead of a bare certificate:
    // the same bytes the enrollment mailbox carries, so a browser handed
    // one by a pairing code and a browser handed one by a paste verify
    // the same thing. Without it the user pastes a certificate and,
    // separately, a card, and the browser tells the two apart by shape.
    if !a.has("bundle") {
        return write_out(&a, &bytes);
    }
    let card_path = a.file("card", CARD_FILE)?;
    let card = read_file(&card_path)?;
    let parsed = Card::parse(&card).map_err(|e| format!("{}: {e}", card_path.display()))?;
    // A bundle whose halves name different identities is not one, and
    // finding that out here beats finding it out in a browser that can
    // only say the paste was wrong.
    if parsed.identity != id.public() {
        return Err(format!(
            "{} is the card of {}, not of the identity signing this certificate ({})",
            card_path.display(),
            Fingerprint::of(&parsed.identity),
            id.fingerprint()
        ));
    }
    let encoded = Bundle { cert: bytes, card }.encode();
    Bundle::parse(&encoded).map_err(|e| refuse_unreadable("bundle", e))?;
    write_out(&a, &encoded)
}

/// `--caps`: `all` (or absent) for unrestricted, `web` for what a
/// browser should get, or a comma-separated list. `None` on the way out
/// means unrestricted, which is what an absent `caps` means on the wire.
pub(crate) fn parse_caps(spec: Option<&str>) -> R<Option<u64>> {
    Ok(match spec {
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
    })
}

/// Capability bits as the words `--caps` takes, for a prompt that has to
/// show what is being asked for and what will be granted.
pub(crate) fn caps_words(caps: Option<u64>) -> String {
    let Some(bits) = caps else {
        return "everything".into();
    };
    if bits == 0 {
        return "nothing".into();
    }
    let named = [
        (caps::LOGIN, "login"),
        (caps::MESSAGE, "message"),
        (caps::VOUCH, "vouch"),
        (caps::MANAGE, "manage"),
    ];
    let mut out: Vec<&str> = named
        .iter()
        .filter(|(b, _)| bits & b == *b)
        .map(|(_, n)| *n)
        .collect();
    // A bit this build has no word for still has to appear, or a prompt
    // would understate what it is about to grant.
    // Fold with OR, not sum: these happen to be disjoint powers of two,
    // and a sum would quietly stop meaning "the union" the day one of
    // them is not.
    let known: u64 = named.iter().fold(0, |acc, (b, _)| acc | b);
    let unknown = bits & !known;
    let extra;
    if unknown != 0 {
        extra = format!("+{unknown:#x}");
        out.push(&extra);
    }
    out.join(", ")
}

fn make_card(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = IdentityKey::from_seed(&read_seed(&a.file("identity", IDENTITY_KEY)?)?);
    let mut card = Card::new(&id, a.one("name")?, now());
    card.icon = match a.opt("icon") {
        Some(s) => Some(s.parse().map_err(|_| "--icon: not a number".to_string())?),
        None => None,
    };
    card.profile = a.opt("profile").map(str::to_owned);
    card.links = a.many("link").into_iter().map(str::to_owned).collect();
    // §3.4: a one-way commitment to the identity that may succeed this
    // one. `--successor-key` takes the successor's *key file* and hashes
    // its public half, which is what a user actually has to hand.
    card.successor = match (a.opt("successor"), a.opt("successor-key")) {
        (Some(_), Some(_)) => return Err("--successor and --successor-key are alternatives".into()),
        (Some(h), None) => Some(
            unhex(h)?
                .try_into()
                .map_err(|_| "--successor: 32 bytes of hex".to_string())?,
        ),
        (None, Some(path)) => {
            let key = IdentityKey::from_seed(&read_seed(Path::new(path))?);
            Some(Fingerprint::of(&key.public()).0)
        }
        (None, None) => None,
    };
    let atts = a
        .many("attestation")
        .into_iter()
        .map(|p| {
            let bytes = read_file(Path::new(p))?;
            Attestation::parse(&bytes).map_err(|e| format!("{p}: {e}"))?;
            cbor::decode_canonical(&bytes).map_err(|e| format!("{p}: {e}"))
        })
        .collect::<R<Vec<_>>>()?;
    let bytes = card.sign(&id, atts).map_err(|e| e.to_string())?;
    Card::parse(&bytes).map_err(|e| refuse_unreadable("card", e))?;
    write_out(&a, &bytes)
}

fn make_attestation(args: &[String]) -> R<()> {
    let a = parse(args);
    let reg = ServerKey::from_seed(&read_seed(Path::new(a.one("registrar-key")?))?);
    // No default-directory fallback here, unlike `cert` and `card`:
    // `attest` is run by a registrar about somebody else, so falling back
    // to the caller's own identity would be attesting the wrong person.
    let identity: [u8; 32] = match (a.opt("identity"), a.opt("identity-pub")) {
        (Some(seed), _) => IdentityKey::from_seed(&read_seed(Path::new(seed))?).public(),
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
        expires: t
            .checked_add(seconds(
                a.u64("days", attestation::RECOMMENDED_LIFETIME / 86_400)?,
            )?)
            .ok_or("--days: the expiry does not fit")?,
        level: match a.opt("level") {
            Some(s) => Some(s.parse().map_err(|_| "--level: not a number".to_string())?),
            None => None,
        },
    };
    let bytes = att.sign(&reg);
    Attestation::parse(&bytes).map_err(|e| refuse_unreadable("attestation", e))?;
    write_out(&a, &bytes)
}

fn inspect(args: &[String]) -> R<()> {
    let [path] = args else { usage() };
    let bytes = read_file(Path::new(path))?;
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
            "successor": c.successor.as_ref().map(|s| hex(s)),
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
    } else if let Ok(b) = Bundle::parse(&bytes) {
        // Unsigned, so unlike the others this reports what its members
        // say *and* whether they hold together — that check is the only
        // interesting thing about the wrapper.
        let opened = b.open();
        json!({
            "type": "bundle",
            "cert": DeviceCert::parse(&b.cert).ok().map(|c| json!({
                "identity_fingerprint": Fingerprint::of(&c.identity).to_string(),
                "device": hex(&c.device), "device_enc": hex(&c.device_enc),
                "issued": c.issued, "expires": c.expires, "caps": c.caps, "name": c.name,
            })),
            "card": Card::parse(&b.card).ok().map(|c| json!({
                "identity_fingerprint": Fingerprint::of(&c.identity).to_string(),
                "name": c.name, "updated": c.updated,
            })),
            "ok": opened.is_ok(),
            "error": opened.err().map(|e| e.to_string()),
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
            ("bundle", Bundle::parse(&bytes).err()),
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
    /// What the tunnel says about the hop behind it (spec §5.2
    /// `downstream`): `cleartext` when listening off loopback.
    downstream: &'static str,
    /// §8.2 `create`: may the server make an account for this identity
    /// on a `new_accounts = create` server? Off by default here — the
    /// token these paths fetch is for `link` or `unlink`, and an account
    /// created first makes the link that follows `already_linked`.
    create: bool,
}

impl Credentials {
    /// A copy for a task that needs its own (the device key is a seed,
    /// so this is a re-derivation rather than a clone of secret state).
    fn dup(&self) -> Credentials {
        Credentials {
            device: DeviceKey::from_seed(&self.device.seed()),
            card: self.card.clone(),
            cert: self.cert.clone(),
            downstream: self.downstream,
            create: self.create,
        }
    }
}

fn credentials(a: &Args) -> R<Credentials> {
    Ok(Credentials {
        device: DeviceKey::from_seed(&read_seed(&a.file("device", DEVICE_KEY)?)?),
        card: read_file(&a.file("card", CARD_FILE)?)?,
        cert: read_file(&a.file("cert", CERT_FILE)?)?,
        downstream: "local",
        create: false,
    })
}

/// `http(s)://host[:port]` → the same with no trailing slash.
pub(crate) fn server_base(a: &Args) -> R<String> {
    let s = a.one("server")?.trim_end_matches('/').to_owned();
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return Err("--server must start with http:// or https://".into());
    }
    Ok(s)
}

/// The challenge binding (§5.2) against a server. Blocking; small.
fn authenticate(base: &str, c: &Credentials) -> R<Value> {
    // `create` is off unless the caller asked for it — see the field.
    authenticate_with(base, c, None, c.create)
}

/// Same, optionally with classic credentials to link in the same step
/// (§5.4, §8.2). `create` is §8.2's opt-out.
fn authenticate_with(
    base: &str,
    c: &Credentials,
    classic: Option<(&str, &str)>,
    create: bool,
) -> R<Value> {
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
    let mut body = json!({
        "card": b64(&c.card),
        "device_cert": b64(&c.cert),
        "proof": b64(&proof),
        "downstream": c.downstream,
        "create": create,
    });
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
    let password = a.password()?;
    // A login with no password used to be dropped on the floor. It is
    // always a mistake — say so rather than authenticating as nobody.
    let classic = match (a.opt("login"), password.as_deref()) {
        (Some(l), Some(p)) => Some((l, p)),
        (Some(_), None) => {
            return Err(
                "--login needs a password (--password-file, --password-stdin \
                        or --password)"
                    .into(),
            )
        }
        (None, Some(_)) => return Err("--password without --login".into()),
        (None, None) => None,
    };
    let reply = authenticate_with(&base, &c, classic, !a.has("no-create"))?;
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
    let password = a
        .password()?
        .ok_or("a password is required (--password-file, --password-stdin or --password)")?;
    let body = json!({ "login": a.one("login")?, "password": password });
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
    let mut c = credentials(&a)?;
    c.create = a.has("create");
    let listen = a.opt("listen").unwrap_or("127.0.0.1:5500").to_owned();
    if !listen.starts_with("127.")
        && !listen.starts_with("[::1]")
        && !listen.starts_with("localhost")
    {
        // §11.1: the local hop is cleartext, so it stays on loopback
        // unless the user says otherwise on purpose.
        if !a.has("allow-remote-listen") {
            return Err(format!(
                "{listen} is not loopback; pass --allow-remote-listen if you mean it"
            ));
        }
        // And tell the server so, so the session is marked cleartext and
        // other users get the PM warning (spec §5.2 `downstream`).
        c.downstream = "cleartext";
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .map_err(|e| format!("{listen}: {e}"))?;
        // Check credentials once up front so a typo fails now, not on the
        // first connection.
        let probe = tokio::task::spawn_blocking({
            let (base, creds) = (base.clone(), c.dup());
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
        let (base, creds) = (base.to_owned(), c.dup());
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
