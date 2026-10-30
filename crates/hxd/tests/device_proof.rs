//! Device proof on the classic wire (`docs/proposals/portable-friends.md`
//! §3): a server built from a real config, with an ng port and its
//! identity, and classic clients that hold their own device keys and
//! sign with hl-identity's own API, on the plain port, on TLS 1.3 with
//! its exporter and on TLS 1.2, and under HOPE.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hl_identity::{
    caps, cert, Card, DeviceCert, DeviceKey, DeviceProof, Fingerprint, IdentityKey, ServerChallenge,
};
use hxd_core::AuthBackend;
use hxd_testclient::device::{get_device_challenge, prove_device};
use hxd_testclient::legacy::{Client, Frame, Login};
use hxd_testclient::ng;
use hxhope::client::Offer;
use hxhope::Cipher;
use hxproto::messages::{tag, ClientHdr};
use hxproto::messaging::CAP_DEVICE_PROOF;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const LABEL: &[u8] = b"EXPERIMENTAL-hl-identity-device-proof";
const SKEWED: &str =
    "This device's clock is too far from the server's to prove it. Set the clock and try again.";
const NOT_PROVED: &str = "The device could not be proved.";
const NO_CHALLENGE: &str = "This server gives no device challenge for that address.";
const TOO_MANY: &str = "Too many device challenges. Try again shortly.";

struct Server {
    plain: SocketAddr,
    tls: SocketAddr,
    ng: SocketAddr,
    cert: CertificateDer<'static>,
    accounts: PathBuf,
}

/// A user with an identity, a device and a certificate for it.
struct Person {
    id: IdentityKey,
    dev: DeviceKey,
    card: Vec<u8>,
    cert: Vec<u8>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `caps` is the certificate's mask, `None` for all of them.
fn person_with(seed: u8, name: &str, caps: Option<u64>) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[seed + 100; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let mut c =
        DeviceCert::for_device(&id, &dev, now() - 3600, cert::RECOMMENDED_LIFETIME).unwrap();
    c.caps = caps;
    Person {
        cert: c.sign(&id),
        id,
        dev,
        card,
    }
}

fn person(seed: u8, name: &str) -> Person {
    person_with(seed, name, None)
}

fn fingerprint(p: &Person) -> Fingerprint {
    Fingerprint::of(&p.id.public())
}

/// Linked to its account here.
fn alice() -> Person {
    person(1, "alice")
}
/// Its account links nothing.
fn bob() -> Person {
    person(2, "bob")
}
/// Its account links it, with identity login off.
fn carol() -> Person {
    person(3, "carol")
}
/// Its device is revoked here.
fn erin() -> Person {
    person(5, "erin")
}
/// Linked, and not on the allow list.
fn frank() -> Person {
    person(6, "frank")
}
/// Nobody's here.
fn mallory() -> Person {
    person(7, "mallory")
}
/// Its account links nothing either.
fn gus() -> Person {
    person(9, "gus")
}

/// A server whose `[identity]` section has `identity` beside what every
/// one here has, `{plain}` and `{tls}` in it the classic listeners.
async fn start(dir: &Path, identity: &str) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let account = |login: &str, more: &str| {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                 send_chat = true\n{more}"
            ),
        )
        .unwrap();
    };
    let linked = |p: &Person| format!("[identity]\nfingerprint = \"{}\"\n", fingerprint(p));
    // Held to no rate, so that its cases are not paced.
    account(
        "alice",
        &format!("{}[extra]\ncan_spam = true\n", linked(&alice())),
    );
    account("bob", "");
    account("gus", "");
    account("lou", "[identity]\nlogin = false\n");
    account("carol", &format!("{}login = false\n", linked(&carol())));
    account("dave", "[identity]\nallow_self_link = false\n");
    account("erin", &linked(&erin()));
    account("frank", &linked(&frank()));

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), issued.signing_key.serialize_pem()).unwrap();

    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (p, t, n) = (
        plain.local_addr().unwrap(),
        tls.local_addr().unwrap(),
        ngl.local_addr().unwrap(),
    );
    let allowed: Vec<String> = [alice(), bob(), carol(), erin(), mallory(), gus()]
        .iter()
        .map(|p| format!("\"{}\"", fingerprint(p)))
        .collect();
    let revoked = Fingerprint::of(&erin().dev.public());
    let identity = identity
        .replace("{plain}", &p.to_string())
        .replace("{tls}", &t.to_string());
    // A case logs one account in more often than a person would.
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [limits]\nconnections_per_account = 0\nreconnect_seconds = 0\n\
         [ng]\nbind = \"{n}\"\n\
         [tls]\nbind = \"{t}\"\ncert = \"{d}/cert.pem\"\nkey = \"{d}/key.pem\"\n\
         [identity]\nkey = \"{d}/identity.key\"\nnext_key = \"{d}/identity.next\"\n\
         handovers = \"{d}/identity.handovers\"\nsuccessors = \"{d}/identity.successors\"\n\
         hosts = [\"{n}\"]\nallow_list = [{}]\nrevoked_devices = [\"{revoked}\"]\n{identity}\n",
        allowed.join(", "),
        d = dir.display(),
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    // As the binary builds them.
    let mut ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None).unwrap();
    ctx.device_proof = hxd::device::prover(ng_ctx.as_ref());
    let legacy_tls = hxd::tls::build(&config).unwrap().unwrap().tls;
    tokio::spawn(hxd_session::serve_tls(tls, ctx.clone(), legacy_tls));
    tokio::spawn(hxd_session::serve(plain, ctx));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx.unwrap()));
    Server {
        plain: p,
        tls: t,
        ng: n,
        cert: CertificateDer::from(issued.cert.der().to_vec()),
        accounts,
    }
}

/// Where a classic client connects, and whether its proof carries the
/// connection's exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Port {
    Plain,
    Tls13,
    Tls12,
}

impl Port {
    fn addr(self, s: &Server) -> SocketAddr {
        match self {
            Port::Plain => s.plain,
            Port::Tls13 | Port::Tls12 => s.tls,
        }
    }

    async fn connect(self, s: &Server) -> (Client, Option<[u8; 32]>) {
        match self {
            Port::Plain => (Client::connect(s.plain).await.unwrap(), None),
            Port::Tls13 | Port::Tls12 => {
                let mut roots = RootCertStore::empty();
                roots.add(s.cert.clone()).unwrap();
                let versions: &[_] = match self {
                    Port::Tls13 => &[&tokio_rustls::rustls::version::TLS13],
                    _ => &[&tokio_rustls::rustls::version::TLS12],
                };
                let config =
                    ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                        .with_protocol_versions(versions)
                        .unwrap()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                let (c, exporter) =
                    Client::connect_tls_exporting(s.tls, "localhost", Arc::new(config), LABEL)
                        .await
                        .unwrap();
                assert_eq!(exporter.is_some(), self == Port::Tls13);
                (c, exporter)
            }
        }
    }
}

fn login(account: &str) -> Login {
    Login {
        caps: Some(CAP_DEVICE_PROOF as u16),
        ..Login::account(account, account, "pw")
    }
}

/// A connection on `port` logged in as `account`, not yet joined.
async fn unannounced(s: &Server, port: Port, account: &str) -> (Client, Option<[u8; 32]>) {
    let (mut c, exporter) = port.connect(s).await;
    let reply = c.login_unannounced(&login(account)).await.unwrap();
    let caps = reply.uint(tag::CAPABILITIES).unwrap_or(0);
    assert_ne!(u64::from(caps) & CAP_DEVICE_PROOF, 0, "bit 14 confirmed");
    (c, exporter)
}

/// Get Device Challenge for `host`: the challenge, or the refusal's text.
async fn challenge(c: &mut Client, host: SocketAddr) -> Result<ServerChallenge, String> {
    let reply = c
        .ask(
            ClientHdr::GetDeviceChallenge,
            &get_device_challenge(&host.to_string()),
        )
        .await
        .unwrap();
    if reply.is_error() {
        assert_eq!(hxd_testclient::messaging::reason(&reply), None);
        return Err(reply.error_text().unwrap());
    }
    let c = ServerChallenge::parse_trtp(&reply.bytes(tag::SERVER_CHALLENGE).unwrap()).unwrap();
    assert_eq!(c.host, host.to_string());
    Ok(c)
}

/// `p`'s device's answer to `c`, signed at `time`.
fn answer(p: &Person, c: &ServerChallenge, exporter: Option<&[u8; 32]>, time: u64) -> Vec<u8> {
    DeviceProof::sign(&p.dev, &c.challenge, &c.server_key, &c.host, time, exporter).unwrap()
}

/// Prove Device: `Ok` for the empty reply, or the refusal's text.
async fn prove(c: &mut Client, p: &Person, proof: &[u8], card: bool) -> Result<(), String> {
    let chunks = prove_device(proof, &p.cert, card.then_some(p.card.as_slice()));
    let reply = c.ask(ClientHdr::ProveDevice, &chunks).await.unwrap();
    if reply.is_error() {
        assert_eq!(hxd_testclient::messaging::reason(&reply), None);
        return Err(reply.error_text().unwrap());
    }
    assert_eq!(reply.chunks().count(), 0, "an empty reply");
    Ok(())
}

/// Both transactions, for the listener `c` is on.
async fn challenge_and_prove(
    s: &Server,
    c: &mut Client,
    port: Port,
    exporter: Option<[u8; 32]>,
    p: &Person,
    card: bool,
) -> Result<(), String> {
    let ch = challenge(c, port.addr(s)).await.unwrap();
    prove(c, p, &answer(p, &ch, exporter.as_ref(), now()), card).await
}

fn linked_to(s: &Server, account: &str) -> Option<[u8; 32]> {
    hxd_auth_file::FileAuth::new(s.accounts.clone())
        .lookup(account)
        .unwrap()
        .identity
        .fingerprint
}

fn shown(event: &ng::Event) -> &serde_json::Value {
    &event.data["user"]["identity"]["fingerprint"]
}

#[tokio::test]
async fn a_proved_device_is_on_the_user_list_from_its_announcement_on_every_port() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\", \"{tls}\"]").await;
    let (mut watcher, _) = ng::Client::guest(s.ng, "watcher").await.unwrap();
    let fp = fingerprint(&alice()).to_string();
    for port in [Port::Plain, Port::Tls13, Port::Tls12] {
        let (mut c, exporter) = unannounced(&s, port, "alice").await;
        challenge_and_prove(&s, &mut c, port, exporter, &alice(), true)
            .await
            .unwrap_or_else(|e| panic!("{port:?}: {e}"));
        c.join(&login("alice")).await.unwrap();
        let uid = c.uid.unwrap();
        let joined = watcher
            .event_where("user_joined", |d| d["user"]["uid"] == uid)
            .await
            .unwrap();
        assert_eq!(shown(&joined), &fp, "{port:?}");
    }

    // Proved after joining, it holds, and the users here are told.
    let mut c = Client::login_at(s.plain, &login("alice")).await.unwrap();
    let uid = c.uid.unwrap();
    let joined = watcher
        .event_where("user_joined", |d| d["user"]["uid"] == uid)
        .await
        .unwrap();
    assert!(shown(&joined).is_null());
    // Without the card, which the server holds now.
    challenge_and_prove(&s, &mut c, Port::Plain, None, &alice(), false)
        .await
        .unwrap();
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == uid)
        .await
        .unwrap();
    assert_eq!(shown(&changed), &fp);
}

/// What a case does after its connection's own challenge, to be refused.
#[derive(Debug)]
enum Misstep {
    /// Answers another session's challenge.
    OthersChallenge,
    /// Answers its challenge again after a refused answer spent it.
    Spent,
    /// Answers the challenge a second request replaced.
    Replaced,
    /// Signs for another host than the challenge was given for.
    OtherHost,
    /// Signs `exporter` rather than the connection's.
    Exporter(Option<[u8; 32]>),
    /// Signs another TLS 1.3 connection's exporter.
    OtherConnection,
}

#[tokio::test]
async fn a_proof_answers_its_own_challenge_for_its_listener_on_its_connection() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\", \"{tls}\"]").await;
    let unknown: SocketAddr = "127.0.0.1:1".parse().unwrap();
    for (name, port, host) in [
        ("a host this server is not", Port::Plain, unknown),
        ("the TLS port's host on the plain port", Port::Plain, s.tls),
        (
            "the plain port's host on the TLS port",
            Port::Tls13,
            s.plain,
        ),
    ] {
        let (mut c, _) = unannounced(&s, port, "alice").await;
        assert_eq!(
            challenge(&mut c, host).await.unwrap_err(),
            NO_CHALLENGE,
            "{name}"
        );
    }

    let a = alice();
    for (port, misstep) in [
        (Port::Plain, Misstep::OthersChallenge),
        (Port::Plain, Misstep::Spent),
        (Port::Plain, Misstep::Replaced),
        (Port::Plain, Misstep::OtherHost),
        (Port::Tls13, Misstep::Exporter(None)),
        (Port::Plain, Misstep::Exporter(Some([7; 32]))),
        (Port::Tls12, Misstep::Exporter(Some([7; 32]))),
        (Port::Tls13, Misstep::OtherConnection),
    ] {
        let (mut c, exporter) = unannounced(&s, port, "alice").await;
        let mine = challenge(&mut c, port.addr(&s)).await.unwrap();
        let (mut other, other_exporter) = unannounced(&s, port, "alice").await;
        let theirs = challenge(&mut other, port.addr(&s)).await.unwrap();
        let proof = match misstep {
            Misstep::OthersChallenge => answer(&a, &theirs, exporter.as_ref(), now()),
            Misstep::Spent => {
                let wrong = answer(&mallory(), &mine, exporter.as_ref(), now());
                assert_eq!(
                    prove(&mut c, &a, &wrong, true).await,
                    Err(NOT_PROVED.into())
                );
                answer(&a, &mine, exporter.as_ref(), now())
            }
            Misstep::Replaced => {
                challenge(&mut c, port.addr(&s)).await.unwrap();
                answer(&a, &mine, exporter.as_ref(), now())
            }
            Misstep::OtherHost => {
                let host = s.tls.to_string();
                DeviceProof::sign(
                    &a.dev,
                    &mine.challenge,
                    &mine.server_key,
                    &host,
                    now(),
                    None,
                )
                .unwrap()
            }
            Misstep::Exporter(e) => answer(&a, &mine, e.as_ref(), now()),
            Misstep::OtherConnection => answer(&a, &mine, other_exporter.as_ref(), now()),
        };
        assert_eq!(
            prove(&mut c, &a, &proof, true).await,
            Err(NOT_PROVED.into()),
            "{port:?} {misstep:?}"
        );
        // The other session's challenge is its own still.
        let proof = answer(&a, &theirs, other_exporter.as_ref(), now());
        prove(&mut other, &a, &proof, true)
            .await
            .unwrap_or_else(|e| panic!("{port:?} {misstep:?}: {e}"));
    }
}

#[tokio::test]
async fn a_refusal_says_why_only_of_a_clock() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\"]").await;
    for (name, account, p, time, want) in [
        (
            "a clock an hour slow",
            "alice",
            alice(),
            now() - 3600,
            SKEWED,
        ),
        ("a device revoked here", "erin", erin(), now(), NOT_PROVED),
        (
            "an identity the allow list leaves out",
            "frank",
            frank(),
            now(),
            NOT_PROVED,
        ),
        (
            "another identity than the account's",
            "alice",
            mallory(),
            now(),
            NOT_PROVED,
        ),
        (
            "an account with identity login off",
            "carol",
            carol(),
            now(),
            NOT_PROVED,
        ),
    ] {
        let (mut c, _) = unannounced(&s, Port::Plain, account).await;
        let ch = challenge(&mut c, s.plain).await.unwrap();
        let proof = answer(&p, &ch, None, time);
        assert_eq!(
            prove(&mut c, &p, &proof, true).await,
            Err(want.into()),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_session_proves_one_device_once() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\"]").await;
    let (mut c, _) = unannounced(&s, Port::Plain, "alice").await;
    challenge_and_prove(&s, &mut c, Port::Plain, None, &alice(), true)
        .await
        .unwrap();
    assert_eq!(
        challenge_and_prove(&s, &mut c, Port::Plain, None, &alice(), true).await,
        Err(NOT_PROVED.into())
    );
}

/// How a classic session reaches the plain or the TLS port.
#[derive(Debug, Clone, Copy)]
enum Session {
    On(Port),
    /// HOPE on the plain port, with a cipher or with none.
    Hope(bool),
}

impl Session {
    /// Logged in as `account` and joined, with the exporter its proof signs.
    async fn open(self, s: &Server, account: &str) -> (Client, Option<[u8; 32]>, Port) {
        match self {
            Session::On(port) => {
                let (mut c, exporter) = port.connect(s).await;
                c.login(&login(account)).await.unwrap();
                (c, exporter, port)
            }
            Session::Hope(cipher) => {
                let offer = Offer {
                    ciphers: if cipher {
                        vec![Cipher::Blowfish]
                    } else {
                        vec![]
                    },
                    ..Offer::new(*b"TEST")
                };
                let mut c = Client::connect(s.plain).await.unwrap();
                let (_, agreed) = c.login_hope(&offer, &login(account)).await.unwrap();
                assert_eq!(agreed.cipher.is_some(), cipher);
                (c, None, Port::Plain)
            }
        }
    }
}

#[tokio::test]
async fn classic_proof_encrypted_takes_tls_and_a_hope_cipher_alone() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(
        dir.path(),
        "classic_hosts = [\"{plain}\", \"{tls}\"]\nclassic_proof = \"encrypted\"",
    )
    .await;
    for (session, want) in [
        (Session::On(Port::Plain), Err(NOT_PROVED.into())),
        (Session::Hope(false), Err(NOT_PROVED.into())),
        (Session::Hope(true), Ok(())),
        (Session::On(Port::Tls13), Ok(())),
        (Session::On(Port::Tls12), Ok(())),
    ] {
        let (mut c, exporter, port) = session.open(&s, "alice").await;
        let proved = challenge_and_prove(&s, &mut c, port, exporter, &alice(), true).await;
        assert_eq!(proved, want, "{session:?}");
    }
}

#[tokio::test]
async fn a_proof_with_the_card_links_an_account_on_an_encrypted_session() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\", \"{tls}\"]").await;
    let unmanaging = person_with(2, "bob", Some(caps::LOGIN | caps::MESSAGE));
    // A guest account with a password, which still names no account.
    std::fs::write(
        s.accounts.join("guest.toml"),
        "name = \"guest\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let tls = Session::On(Port::Tls13);
    for (name, session, account, p, card) in [
        (
            "on the plain port",
            Session::On(Port::Plain),
            "gus",
            gus(),
            true,
        ),
        (
            "under HOPE with no cipher",
            Session::Hope(false),
            "gus",
            gus(),
            true,
        ),
        ("without the card", tls, "gus", gus(), false),
        ("on TLS 1.2", Session::On(Port::Tls12), "bob", bob(), true),
        ("as guest", tls, "guest", mallory(), true),
        ("where identity login is off", tls, "lou", mallory(), true),
        (
            "from a certificate that may not manage",
            tls,
            "bob",
            unmanaging,
            true,
        ),
        (
            "of an identity another account links",
            tls,
            "bob",
            alice(),
            true,
        ),
        (
            "to an account that refuses it",
            tls,
            "dave",
            mallory(),
            true,
        ),
    ] {
        let (mut c, exporter, port) = session.open(&s, account).await;
        let proved = challenge_and_prove(&s, &mut c, port, exporter, &p, card).await;
        assert_eq!(proved, Err(NOT_PROVED.into()), "{name}");
        assert_eq!(linked_to(&s, account), None, "{name}");
    }
    for (session, account, p) in [
        (Session::On(Port::Tls13), "bob", bob()),
        (Session::Hope(true), "gus", gus()),
    ] {
        let (mut c, exporter, port) = session.open(&s, account).await;
        challenge_and_prove(&s, &mut c, port, exporter, &p, true)
            .await
            .unwrap_or_else(|e| panic!("{account}: {e}"));
        assert_eq!(linked_to(&s, account), Some(fingerprint(&p).0));
    }
}

#[tokio::test]
async fn a_client_that_never_asks_is_answered_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let on = start(dir.path(), "classic_hosts = [\"{plain}\"]").await;
    let dir = tempfile::tempdir().unwrap();
    let off = start(dir.path(), "").await;
    for (name, s, caps) in [
        ("without bit 14", &on, None),
        (
            "to a server with no classic host",
            &off,
            Some(CAP_DEVICE_PROOF as u16),
        ),
    ] {
        let login = Login {
            caps,
            ..Login::account("alice", "alice", "pw")
        };
        let mut c = Client::connect(s.plain).await.unwrap();
        let reply = c.login(&login).await.unwrap();
        let echoed = reply.uint(tag::CAPABILITIES).unwrap_or(0);
        assert_eq!(u64::from(echoed) & CAP_DEVICE_PROOF, 0, "{name}");
        let host = s.plain.to_string();
        let refused: Frame = c
            .ask(ClientHdr::GetDeviceChallenge, &get_device_challenge(&host))
            .await
            .unwrap();
        assert_eq!(
            refused.error_text().as_deref(),
            Some("Not implemented."),
            "{name}"
        );
    }
}

#[tokio::test]
async fn an_account_asks_so_many_whatever_it_reconnects() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "classic_hosts = [\"{plain}\"]").await;
    for _ in 0..2 {
        let (mut c, _) = unannounced(&s, Port::Plain, "bob").await;
        for _ in 0..5 {
            challenge(&mut c, s.plain).await.unwrap();
        }
    }
    let (mut c, _) = unannounced(&s, Port::Plain, "bob").await;
    assert_eq!(challenge(&mut c, s.plain).await.unwrap_err(), TOO_MANY);
    let (mut c, _) = unannounced(&s, Port::Plain, "gus").await;
    challenge(&mut c, s.plain).await.unwrap();
}
