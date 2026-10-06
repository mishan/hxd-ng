//! Server linking (`docs/server-link.md`) between real servers in process:
//! each with a TLS port and a `[link]` section, one dialing the other by
//! key mode.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hxd_testclient::legacy::{self, Login};

struct Server {
    legacy: SocketAddr,
    hub: hxd_link::Hub,
    config: std::path::PathBuf,
}

fn public(seed: u8) -> String {
    B64.encode(hxd_link::LinkKey::from_seed(&[seed; 32]).public())
}

/// A server whose link key is `seed` repeated, with `peers` as its
/// `[[link.peer]]` entries. Its TLS listener is `tls`, bound by the
/// caller so a peer's config can name it first.
async fn start(
    dir: &Path,
    seed: u8,
    tag: &str,
    peers: &str,
    tls: tokio::net::TcpListener,
) -> Server {
    let d = dir.display();
    let seed_hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("link.key"), seed_hex).unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), issued.signing_key.serialize_pem()).unwrap();
    let text = format!(
        "[server]\nname = \"{tag} server\"\n[paths]\naccounts = \"{d}/accounts\"\n\
         [tls]\ncert = \"{d}/cert.pem\"\nkey = \"{d}/key.pem\"\n\
         [link]\ntag = \"{tag}\"\nkey = \"{d}/link.key\"\n{peers}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let hub = hxd::link::build(&config, ctx.core.queue_budget().clone())
        .unwrap()
        .unwrap();
    let certs = Arc::new(
        hxd_session::LegacyTls::load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap(),
    );
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        hub: hub.clone(),
        config: path,
    };
    tokio::spawn(hxd_session::serve(legacy, ctx.clone()));
    tokio::spawn(hxd_session::serve_tls_with_peers(
        tls,
        ctx,
        certs,
        Some(Arc::new(hub.clone()) as Arc<dyn hxd_session::PeerAcceptor>),
    ));
    hub.spawn_dialers();
    server
}

async fn bind() -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
}

fn up(hub: &hxd_link::Hub, seed: u8) -> bool {
    let id = hxd_link::LinkKey::from_seed(&[seed; 32]).server_id();
    hub.status().iter().any(|s| s.server == id)
}

/// Whether `hub` links to the server whose key is `seed` within `within`.
async fn comes_up(hub: &hxd_link::Hub, seed: u8, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while !up(hub, seed) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// Two servers, `a` accepting `b`, with the key each holds for the other.
async fn pair(a_holds: u8, b_holds: u8) -> (Server, Server, [tempfile::TempDir; 2]) {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a_tls = bind().await;
    let a_addr = a_tls.local_addr().unwrap();
    let a = start(
        da.path(),
        1,
        "aa",
        &format!(
            "[[link.peer]]\nname = \"bb\"\naccept = true\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-bb\"\n",
            public(a_holds)
        ),
        a_tls,
    )
    .await;
    let b = start(
        db.path(),
        2,
        "bb",
        &format!(
            "[[link.peer]]\nname = \"aa\"\ndial = \"{a_addr}\"\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-bb\"\n",
            public(b_holds)
        ),
        bind().await,
    )
    .await;
    (a, b, [da, db])
}

#[tokio::test]
async fn two_servers_link_by_their_keys() {
    let (a, b, _dirs) = pair(2, 1).await;
    assert!(
        comes_up(&a.hub, 2, Duration::from_secs(10)).await,
        "{:?}",
        a.hub.status()
    );
    assert!(
        comes_up(&b.hub, 1, Duration::from_secs(10)).await,
        "{:?}",
        b.hub.status()
    );
}

#[tokio::test]
async fn a_link_with_a_key_either_side_did_not_configure_never_comes_up() {
    // `a` holds a stranger's key for `b`, then `b` a stranger's for `a`:
    // the acceptor refuses the login, then the dialer refuses the reply.
    for (a_holds, b_holds) in [(3, 1), (2, 3)] {
        let (a, b, _dirs) = pair(a_holds, b_holds).await;
        // Long past the moment a good pair links (the test above).
        assert!(
            !comes_up(&b.hub, 1, Duration::from_secs(2)).await,
            "{a_holds} {b_holds}"
        );
        assert!(!up(&a.hub, 2), "{a_holds} {b_holds}");
    }
}

/// Wait for the link to `seed` to go down.
async fn goes_down(hub: &hxd_link::Hub, seed: u8) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while up(hub, seed) {
        assert!(tokio::time::Instant::now() < deadline, "{:?}", hub.status());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn removing_a_peer_on_reload_unlinks_it_for_good() {
    let (a, b, _dirs) = pair(2, 1).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let text = std::fs::read_to_string(&a.config).unwrap();
    std::fs::write(&a.config, &text[..text.find("[[link.peer]]").unwrap()]).unwrap();
    assert_eq!(hxd::link::reload(&a.hub, &a.config), Ok(0));
    goes_down(&b.hub, 1).await;
    // With the entry back, only a dialer that stopped on `Unlinked`
    // explains the link staying down.
    std::fs::write(&a.config, &text).unwrap();
    assert_eq!(hxd::link::reload(&a.hub, &a.config), Ok(1));
    assert!(!comes_up(&b.hub, 1, Duration::from_secs(3)).await);
}

#[tokio::test]
async fn a_key_changed_on_reload_closes_the_link() {
    let (a, b, _dirs) = pair(2, 1).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let text = std::fs::read_to_string(&a.config).unwrap();
    std::fs::write(&a.config, text.replace(&public(2), &public(3))).unwrap();
    assert_eq!(hxd::link::reload(&a.hub, &a.config), Ok(1));
    goes_down(&a.hub, 2).await;
    // The dialer tries again, and is refused under the new key.
    assert!(!comes_up(&b.hub, 1, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_link_login_on_the_plain_port_is_refused() {
    let (a, _b, _dirs) = pair(2, 1).await;
    let mut login = Login::account("link", "link-bb", "");
    login.caps = Some(1 << 11 | 1 << 1);
    match legacy::Client::login_at(a.legacy, &login).await {
        Err(hxd_testclient::Error::Refused { text, .. }) => {
            assert_eq!(text, "This port does not accept server links.")
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_key_proof_without_bit_11_is_refused() {
    let (a, _b, _dirs) = pair(2, 1).await;
    let mut c = legacy::Client::connect(a.legacy).await.unwrap();
    let reply = c
        .call(
            hxproto::messages::ClientHdr::Login.as_u32(),
            &[
                (hxproto::messages::tag::NAME, b"guest".to_vec()),
                (0x0640, vec![9; 32]),
                (0x0641, vec![9; 64]),
            ],
        )
        .await;
    match reply {
        Err(hxd_testclient::Error::Refused { text, .. }) => assert_eq!(text, "Login failed."),
        other => panic!("{:?}", other.map(|_| ())),
    }
}
