//! Server linking (`docs/server-link.md`) between real servers in process:
//! each with a TLS port and a `[link]` section, one dialing the other by
//! key mode.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hl_identity::message::{link_cert_sha256, ChatLine, Object, PrivateMessage, Signed};
use hl_identity::sealed::{open, seal_to, Opened, Opening, Replay};
use hl_identity::{cert, Card, DeviceCert, DeviceKey, Fingerprint, IdentityKey, LoginProof};
use hl_identity::{message::Sender, ServerKey};
use hxd_testclient::legacy::{self, push, Login, UserRow};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    hub: hxd_link::Hub,
    core: Arc<hxd_core::Core>,
    config: std::path::PathBuf,
}

fn public(seed: u8) -> String {
    B64.encode(hxd_link::LinkKey::from_seed(&[seed; 32]).public())
}

/// The seed of the discovery key of the server whose link key is `seed`
/// repeated: its signed lines' scope.
fn identity_seed(seed: u8) -> [u8; 32] {
    [seed + 0x40; 32]
}

fn discovery_key(seed: u8) -> [u8; 32] {
    ServerKey::from_seed(&identity_seed(seed)).public()
}

/// A server whose link key is `seed` repeated, with `link` as more keys
/// of its `[link]` section and `peers` as its `[[link.peer]]` entries. Its
/// TLS listener is `tls`, bound by the caller so a peer's config can name
/// it first.
async fn start(
    dir: &Path,
    seed: u8,
    tag: &str,
    link: &str,
    peers: &str,
    tls: tokio::net::TcpListener,
) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    // Every act on another user, so that a refusal for a ghost is the
    // ghost's and never a missing privilege's.
    std::fs::write(
        accounts.join("admin.toml"),
        "name = \"Admin\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\nget_user_info = true\ndisconnect_users = true\ncreate_pchats = true\n",
    )
    .unwrap();
    // The people who log in with their keys, on whichever server a test
    // puts them.
    for (n, login) in [(1, "alice"), (2, "bob"), (3, "carol")] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"pw\"\n[access]\nread_chat = true\n\
                 send_chat = true\nsend_msgs = true\nread_chat_history = true\n\
                 [identity]\nfingerprint = \"{}\"\n",
                fingerprint(&person(n))
            ),
        )
        .unwrap();
    }
    let hex = |seed: [u8; 32]| seed.iter().map(|b| format!("{b:02x}")).collect::<String>();
    std::fs::write(dir.join("link.key"), hex([seed; 32])).unwrap();
    std::fs::write(dir.join("identity.key"), hex(identity_seed(seed))).unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), issued.signing_key.serialize_pem()).unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = ngl.local_addr().unwrap();
    let text = format!(
        "[server]\nname = \"{tag} server\"\n[paths]\naccounts = \"{d}/accounts\"\n\
         [inbox]\ndb = \"{d}/hx.db\"\n[history]\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [identity]\nkey = \"{d}/identity.key\"\nsuccessors = \"\"\nhosts = [\"{ng}\"]\n\
         [limits]\nspam_points = 0\nchat_lines = 0\nng_requests = 0\n\
         [tls]\ncert = \"{d}/cert.pem\"\nkey = \"{d}/key.pem\"\n\
         [link]\ntag = \"{tag}\"\nkey = \"{d}/link.key\"\n{link}\n{peers}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let hub = hxd::link::build(&config, ctx.core.clone())
        .unwrap()
        .unwrap();
    let certs = Arc::new(
        hxd_session::LegacyTls::load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap(),
    );
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng,
        hub: hub.clone(),
        core: ctx.core.clone(),
        config: path,
    };
    tokio::spawn(hxd_session::serve(legacy, ctx.clone()));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx));
    tokio::spawn(hxd_session::serve_tls_with_peers(
        tls,
        ctx,
        certs,
        Some(Arc::new(hub.clone()) as Arc<dyn hxd_session::PeerAcceptor>),
    ));
    hub.start();
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

/// Wait for the link to `seed` to go down.
async fn goes_down(hub: &hxd_link::Hub, seed: u8) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while up(hub, seed) {
        assert!(tokio::time::Instant::now() < deadline, "{:?}", hub.status());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Two servers, `a` (tag `aa`) accepting `b` (tag `bb`), with the key
/// each holds for the other, more `[link]` keys for `a`, and more keys for
/// `a`'s entry for `b` and `b`'s for `a`.
async fn pair_with(
    a_holds: u8,
    b_holds: u8,
    a_link: &str,
    a_offers: &str,
    a_extra: &str,
    b_extra: &str,
) -> (Server, Server, [tempfile::TempDir; 2]) {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a_tls = bind().await;
    let a_addr = a_tls.local_addr().unwrap();
    let a = start(
        da.path(),
        1,
        "aa",
        a_link,
        &format!(
            "[[link.peer]]\nname = \"bb\"\naccept = true\nprotection = \"key\"\n\
             key = \"ed25519:{}\"\naccount = \"link-bb\"\nfeatures = {a_offers}\n{a_extra}\n",
            public(a_holds)
        ),
        a_tls,
    )
    .await;
    let b = start(
        db.path(),
        2,
        "bb",
        "",
        &format!(
            "[[link.peer]]\nname = \"aa\"\ndial = \"{a_addr}\"\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-bb\"\nfeatures = {EVERY_FEATURE}\n{b_extra}\n",
            public(b_holds)
        ),
        bind().await,
    )
    .await;
    (a, b, [da, db])
}

/// Every link feature this server implements, as `[[link.peer]]` names
/// them.
const EVERY_FEATURE: &str = r#"["chat", "msgs", "info"]"#;

async fn pair(a_holds: u8, b_holds: u8) -> (Server, Server, [tempfile::TempDir; 2]) {
    pair_with(a_holds, b_holds, "", EVERY_FEATURE, "", "").await
}

/// Two servers linked, waited for.
async fn linked(a_link: &str) -> (Server, Server, [tempfile::TempDir; 2]) {
    linked_offering(a_link, EVERY_FEATURE).await
}

/// Two servers linked, `a` offering only `a_offers`.
async fn linked_offering(a_link: &str, a_offers: &str) -> (Server, Server, [tempfile::TempDir; 2]) {
    let servers = pair_with(2, 1, a_link, a_offers, "", "").await;
    assert!(comes_up(&servers.0.hub, 2, Duration::from_secs(10)).await);
    assert!(comes_up(&servers.1.hub, 1, Duration::from_secs(10)).await);
    servers
}

/// The row named `nick` in `c`'s user list, once it appears.
async fn row(c: &mut legacy::Client, nick: &str) -> UserRow {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let rows = c.user_list().await.unwrap();
        if let Some(r) = rows.into_iter().find(|r| r.nick == nick.as_bytes()) {
            return r;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{nick} never listed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    // `a` holds a stranger's key for `b`, then `b` a stranger's for `a`.
    // The acceptor refuses both: the first proof is not by the key it
    // holds, and the second names a key that is not its own. The dialer's
    // own check of a reply is the unit tests' (`hxd-link`'s `dial.rs`).
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
    goes_down(&b.hub, 1).await;
    // The dialer tries again, and is refused under the new key.
    assert!(!comes_up(&b.hub, 1, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_suspended_peer_stays_unlinked_until_resumed() {
    let (a, b, _dirs) = linked("").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let _bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let ghost = row(&mut ann, "bob").await;
    let config = hxd::Config::load(&b.config).unwrap();
    let section = config.link.as_ref().unwrap();
    let status = tokio::spawn(hxd::link::write_status(
        b.hub.clone(),
        hxd::link::status_path(section),
    ));

    hxd::link::set_suspended(&config, "aa", true).unwrap();
    assert_eq!(hxd::link::reload(&b.hub, &b.config), Ok(1));
    goes_down(&a.hub, 2).await;
    // Gone at once, not after the grace an interruption is given.
    ann.rx
        .recv_where(|f| f.ty == push::USER_PART && f.uint(tag::UID) == Some(ghost.uid.into()))
        .await
        .unwrap();
    assert!(!comes_up(&a.hub, 2, Duration::from_secs(2)).await);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let shown = hxd::link::status(&config).unwrap();
        if shown.lines().any(|l| l == "aa (dials): suspended") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{shown}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    hxd::link::set_suspended(&config, "aa", false).unwrap();
    assert_eq!(hxd::link::reload(&b.hub, &b.config), Ok(1));
    assert!(comes_up(&a.hub, 2, Duration::from_secs(10)).await);
    row(&mut ann, "bob").await;
    status.abort();
}

#[tokio::test]
async fn reset_id_waits_for_a_stopped_server_and_keeps_the_old_key() {
    let (_a, b, dirs) = pair(2, 1).await;
    let config = hxd::Config::load(&b.config).unwrap();
    let path = hxd::link::status_path(config.link.as_ref().unwrap());
    let status = tokio::spawn(hxd::link::write_status(b.hub.clone(), path.clone()));
    while !path.exists() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hxd::link::reset_id(&config)
        .unwrap_err()
        .contains("running"));

    status.abort();
    std::fs::remove_file(&path).unwrap();
    let key = dirs[1].path().join("link.key");
    let before = std::fs::read_to_string(&key).unwrap();
    let said = hxd::link::reset_id(&config).unwrap();
    assert!(!said.contains(&public(2)), "{said}");
    assert_ne!(std::fs::read_to_string(&key).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(dirs[1].path().join("link.key.old")).unwrap(),
        before
    );
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
            ClientHdr::Login.as_u32(),
            &[
                (tag::NAME, b"guest".to_vec()),
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

#[tokio::test]
async fn users_cross_the_link_both_ways_on_both_wires_and_leave() {
    let (a, b, _dirs) = linked("").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();

    // Each sees the other as a user, greyed out for private chat, which
    // never crosses, and never as an admin.
    let ghost = row(&mut ann, "bob").await;
    assert_eq!(ghost.color, 8);
    assert_eq!(row(&mut bob, "ann").await.color, 8);

    // An ng client is told where the ghost is from.
    let (_watcher, hello) = ng::Client::guest(a.ng, "watcher").await.unwrap();
    let users = hello["users"].as_array().unwrap();
    let seen = users.iter().find(|u| u["nick"] == "bob").unwrap();
    assert_eq!(
        seen["remote"],
        json!({ "server": "bb server", "tag": "bb", "tagged": false })
    );
    assert_eq!(seen["transport"], "unknown");
    assert_eq!(a.hub.status()[0].ghosts, 1);

    // When Bob leaves his server, he leaves Ann's list.
    drop(bob);
    let part = ann
        .rx
        .recv_where(|f| f.ty == push::USER_PART && f.uint(tag::UID) == Some(ghost.uid.into()))
        .await;
    assert!(part.is_ok(), "{part:?}");
}

#[tokio::test]
async fn show_tags_puts_the_home_servers_tag_in_every_ghosts_name() {
    let (a, b, _dirs) = linked("show_tags = true").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("roberta-long"))
        .await
        .unwrap();
    let ghost = row(&mut ann, "roberta-long@bb").await.uid;
    // In chat too, where the name is cut so the 13 columns keep the tag.
    row(&mut bob, "ann").await;
    bob.chat(b"hi").await.unwrap();
    let line = heard(&mut ann, ghost).await;
    assert_eq!(line, b"\rroberta-lo@bb:  hi");

    // History names it as the live ng event does, the tag in `remote`.
    let (mut ngc, _) = ng::Client::account(a.ng, "admin", "pw", "ngc")
        .await
        .unwrap();
    let page = ngc.request("history", json!({})).await.unwrap();
    let hi = page["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["text"] == "hi")
        .unwrap();
    assert_eq!(hi["from"]["nick"], "roberta-long");
    assert_eq!(hi["from"]["remote"]["tagged"], true);
}

/// The next public chat line `c` hears from `uid`.
async fn heard(c: &mut legacy::Client, uid: u16) -> Vec<u8> {
    c.rx.recv_where(|f| f.ty == push::CHAT && f.uint(tag::UID) == Some(uid.into()))
        .await
        .unwrap()
        .bytes(tag::BODY)
        .unwrap()
}

#[tokio::test]
async fn public_chat_crosses_the_link_both_ways_on_both_wires() {
    let (a, b, _dirs) = linked("").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let (mut ngc, _) = ng::Client::guest(b.ng, "ngc").await.unwrap();
    let ann_there = row(&mut bob, "ann").await.uid;
    let ngc_here = row(&mut ann, "ngc").await.uid;

    // Formatted where it is heard, as a local line is, on both wires.
    ann.chat(b"hello from aa").await.unwrap();
    assert_eq!(
        heard(&mut bob, ann_there).await,
        b"\r          ann:  hello from aa"
    );
    let event = ngc
        .event_where("chat", |d| d["from"]["uid"] == ann_there)
        .await
        .unwrap();
    assert_eq!(event.data["text"], "hello from aa");

    // An ng client's lines cross line by line, and an emote as one.
    ngc.request("chat", json!({ "text": "two\nlines", "style": "action" }))
        .await
        .unwrap();
    assert_eq!(
        heard(&mut ann, ngc_here).await,
        b"\r *** ngc two\r *** ngc lines"
    );

    // Lines keep their order across the link.
    for n in 0..20 {
        bob.chat(format!("line {n}").as_bytes()).await.unwrap();
    }
    let bob_here = row(&mut ann, "bob").await.uid;
    for n in 0..20 {
        let want = format!("\r          bob:  line {n}");
        assert_eq!(heard(&mut ann, bob_here).await, want.as_bytes());
    }
}

#[tokio::test]
async fn an_ng_block_of_a_ghost_refuses_its_messages_until_unblocked() {
    let (a, b, _dirs) = linked("").await;
    let (mut ann, _) = ng::Client::guest(a.ng, "ann").await.unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let mut watcher = legacy::Client::login_at(a.legacy, &Login::guest("watcher"))
        .await
        .unwrap();
    let bob_here = row(&mut watcher, "bob").await.uid;
    let ann_there = row(&mut bob, "ann").await.uid;
    let send = |text: &'static str| {
        vec![
            (tag::UID, ann_there.to_be_bytes().to_vec()),
            (tag::BODY, text.as_bytes().to_vec()),
        ]
    };

    ann.request("block", json!({ "uid": bob_here }))
        .await
        .unwrap();
    match bob.call(ClientHdr::Msg.as_u32(), &send("blocked")).await {
        Err(hxd_testclient::Error::Refused { text, .. }) => {
            assert_eq!(text, "That user does not accept private messages.")
        }
        other => panic!("{:?}", other.map(|_| ())),
    }

    ann.request("unblock", json!({ "uid": bob_here }))
        .await
        .unwrap();
    bob.call(ClientHdr::Msg.as_u32(), &send("heard"))
        .await
        .unwrap();
    let got = ann
        .event_where("msg", |d| d["from"]["nick"] == "bob")
        .await
        .unwrap();
    assert_eq!(got.data["text"], "heard");
}

#[tokio::test]
async fn a_peer_trying_the_user_transport_draft_is_told_how_each_user_connects() {
    const DRAFT: &str = "drafts = [\"user_transport\"]";
    // `b` trying the draft with `a`, then not: `a` says the same either
    // way, and `b` reads it only when it tries the draft too.
    for (b_extra, plain, sealed, guest) in [
        (DRAFT, "cleartext", "encrypted", "cleartext"),
        ("", "unknown", "unknown", "unknown"),
    ] {
        let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, DRAFT, b_extra).await;
        assert!(comes_up(&a.hub, 2, Duration::from_secs(10)).await);
        assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
        // On `a`: a classic client in the clear, one under HOPE's Blowfish
        // with a password and one without, whose keys anyone watching
        // could derive, and an ng client whose TLS is a proxy's that `a`
        // cannot see.
        let _plain = legacy::Client::login_at(a.legacy, &Login::guest("plain"))
            .await
            .unwrap();
        let offer = hxhope::client::Offer {
            ciphers: vec![hxhope::Cipher::Blowfish],
            ..hxhope::client::Offer::new(*b"TEST")
        };
        let mut sealed_c = legacy::Client::connect(a.legacy).await.unwrap();
        sealed_c
            .login_hope(&offer, &Login::account("sealed", "admin", "pw"))
            .await
            .unwrap();
        let mut guest_c = legacy::Client::connect(a.legacy).await.unwrap();
        guest_c
            .login_hope(&offer, &Login::guest("hopeguest"))
            .await
            .unwrap();
        let (_ngu, _) = ng::Client::guest(a.ng, "ngu").await.unwrap();

        let mut watcher = legacy::Client::login_at(b.legacy, &Login::guest("watcher"))
            .await
            .unwrap();
        for nick in ["plain", "Admin", "hopeguest", "ngu"] {
            row(&mut watcher, nick).await;
        }
        let (_ngc, hello) = ng::Client::guest(b.ng, "ngc").await.unwrap();
        let transport = |nick: &str| {
            hello["users"]
                .as_array()
                .unwrap()
                .iter()
                .find(|u| u["nick"] == nick)
                .map(|u| u["transport"].clone())
        };
        assert_eq!(transport("plain"), Some(json!(plain)), "{b_extra}");
        assert_eq!(transport("Admin"), Some(json!(sealed)), "{b_extra}");
        assert_eq!(transport("hopeguest"), Some(json!(guest)), "{b_extra}");
        assert_eq!(transport("ngu"), Some(json!("unknown")), "{b_extra}");
    }
}

#[tokio::test]
async fn private_messages_and_user_info_cross_the_link() {
    let (a, b, _dirs) = linked("").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let (mut ngc, _) = ng::Client::guest(b.ng, "ngc").await.unwrap();
    let (bob_here, ann_there) = (
        row(&mut ann, "bob").await.uid,
        row(&mut bob, "ann").await.uid,
    );
    let ngc_here = row(&mut ann, "ngc").await.uid;

    // Ann's message reaches Bob as from her ghost there, and his answer
    // comes back the same way.
    let sent = ann
        .call(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, bob_here.to_be_bytes().to_vec()),
                (tag::BODY, b"hi bob".to_vec()),
            ],
        )
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    let got = bob
        .rx
        .recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(ann_there.into()))
        .await
        .unwrap();
    assert_eq!(got.bytes(tag::BODY).unwrap(), b"hi bob");
    bob.call(
        ClientHdr::Msg.as_u32(),
        &[
            (tag::UID, ann_there.to_be_bytes().to_vec()),
            (tag::BODY, b"hi ann".to_vec()),
        ],
    )
    .await
    .unwrap();
    let got = ann
        .rx
        .recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(bob_here.into()))
        .await
        .unwrap();
    assert_eq!(got.bytes(tag::BODY).unwrap(), b"hi ann");

    // An ng client's message too, its LF carried as a line break.
    let sent = ngc
        .request("msg", json!({ "to": ann_there, "text": "two\nlines" }))
        .await
        .unwrap();
    assert_eq!(sent["queued"], false);
    let got = ann
        .rx
        .recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(ngc_here.into()))
        .await
        .unwrap();
    assert_eq!(got.bytes(tag::BODY).unwrap(), b"two\rlines");

    // User info names the ghost's server, then what that server shows
    // anyone: never a login or an address.
    let info = ann
        .call(
            ClientHdr::UserGetInfo.as_u32(),
            &[(tag::UID, bob_here.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let text = String::from_utf8(info.bytes(tag::BODY).unwrap()).unwrap();
    assert!(text.starts_with("  server: bb server\r"), "{text:?}");
    assert!(text.contains("name: bob\r"), "{text:?}");
    assert!(
        !text.contains("login") && !text.contains("address"),
        "{text:?}"
    );
}

#[tokio::test]
async fn a_link_without_messages_refuses_them_and_names_the_server_for_info() {
    let (a, b, _dirs) = linked_offering("", r#"["chat"]"#).await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let _bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let ghost = row(&mut ann, "bob").await;
    assert_eq!(ghost.color, 4 | 8, "greyed out for messages too");
    let sent = ann
        .call(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, ghost.uid.to_be_bytes().to_vec()),
                (tag::BODY, b"hi".to_vec()),
            ],
        )
        .await;
    assert!(
        matches!(&sent, Err(hxd_testclient::Error::Refused { text, .. }) if text.contains("private messages")),
        "{sent:?}"
    );
    let (mut ngc, _) = ng::Client::guest(a.ng, "ngc").await.unwrap();
    let sent = ngc
        .request("msg", json!({ "to": ghost.uid, "text": "hi" }))
        .await;
    assert!(
        matches!(&sent, Err(hxd_testclient::Error::Refused { code, .. }) if code == "not_delivered"),
        "{sent:?}"
    );
    let info = ann
        .call(
            ClientHdr::UserGetInfo.as_u32(),
            &[(tag::UID, ghost.uid.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    assert_eq!(info.bytes(tag::BODY).unwrap(), b"  server: bb server\r");
}

#[tokio::test]
async fn a_kick_hides_a_ghost_at_its_kicker_and_a_ban_is_placed_by_its_home_server() {
    let (a, b, dirs) = linked("").await;
    // An account of eve's own, as a ban is placed on a person's account.
    std::fs::write(
        dirs[1].path().join("accounts/eve.toml"),
        "name = \"eve\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let mut admin = legacy::Client::login_at(a.legacy, &Login::account("ann", "admin", "pw"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let mut eve = legacy::Client::login_at(b.legacy, &Login::account("eve", "eve", "pw"))
        .await
        .unwrap();
    let kick = |uid: u16, ban: bool| {
        let mut chunks = vec![(tag::UID, uid.to_be_bytes().to_vec())];
        if ban {
            chunks.push((tag::BAN, vec![0, 1]));
        }
        chunks
    };

    // A kick: gone from the kicker's server, told why, and still on its
    // own.
    let bob_here = row(&mut admin, "bob").await.uid;
    let kicked = admin
        .call(ClientHdr::UserKick.as_u32(), &kick(bob_here, false))
        .await;
    assert!(kicked.is_ok(), "{kicked:?}");
    assert!(admin
        .user_list()
        .await
        .unwrap()
        .iter()
        .all(|r| r.uid != bob_here));
    let told = bob.rx.recv_where(|f| f.ty == 0x163).await.unwrap();
    let text = String::from_utf8(told.bytes(tag::BODY).unwrap()).unwrap();
    assert!(text.contains("aa server (aa)"), "{text:?}");
    assert!(bob.user_list().await.is_ok(), "still connected at home");

    // A ban: placed by the home server as its own operator would, so the
    // user is thrown off there and refused there.
    let eve_here = row(&mut admin, "eve").await.uid;
    let banned = admin
        .call(ClientHdr::UserKick.as_u32(), &kick(eve_here, true))
        .await;
    assert!(banned.is_ok(), "{banned:?}");
    let told = eve.rx.recv_where(|f| f.ty == 0x163).await.unwrap();
    let text = String::from_utf8(told.bytes(tag::BODY).unwrap()).unwrap();
    assert!(
        text.contains("banned from the network by aa server (aa)"),
        "{text:?}"
    );
    let again = legacy::Client::login_at(b.legacy, &Login::account("eve", "eve", "pw")).await;
    assert!(
        matches!(&again, Err(hxd_testclient::Error::Refused { text, .. }) if text.contains("aa")),
        "{:?}",
        again.map(|_| ())
    );

    // The ban is the kicker's server's to list, and to lift, by asking
    // the user's home server, which lets them back in.
    let config = hxd::Config::load(&a.config).unwrap();
    // Kept once the answer has come, a moment after the reply.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !hxd::moderation::ban_list(&config, false)
        .unwrap()
        .contains("n#1 eve on bb")
    {
        assert!(tokio::time::Instant::now() < deadline, "never recorded");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    hxd::moderation::ban_lift_network(&config, 1).unwrap();
    let hub = a.hub.clone();
    tokio::task::spawn_blocking(move || hub.send_unbans())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let back = legacy::Client::login_at(b.legacy, &Login::account("eve", "eve", "pw")).await;
        if back.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            back.map(|_| ())
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // And the record is marked lifted once the answer is kept.
    while hxd::moderation::ban_list(&config, false)
        .unwrap()
        .contains("n#1")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "never marked lifted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // On the ng wire, the reply says what was done where.
    let _carol = legacy::Client::login_at(b.legacy, &Login::guest("carol"))
        .await
        .unwrap();
    let carol = row(&mut admin, "carol").await.uid;
    let (mut ngc, _) = ng::Client::account(a.ng, "admin", "pw", "ngc")
        .await
        .unwrap();
    let hidden = ngc.request("kick", json!({ "uid": carol })).await.unwrap();
    assert_eq!(
        hidden,
        json!({ "hidden_here": true, "network": true, "banned": false })
    );
}

#[tokio::test]
async fn a_kick_with_purge_takes_a_ghosts_lines_here_and_spares_a_namesake() {
    let (a, b, _dirs) = linked("").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let mut local_bob = legacy::Client::login_at(a.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    row(&mut bob, "ann").await;
    // The other bob, beside the local one.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let ghost = loop {
        let rows = ann.user_list().await.unwrap();
        if let Some(r) = rows
            .iter()
            .find(|r| r.nick == b"bob" && Some(r.uid) != local_bob.uid)
        {
            break r.uid;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the other bob never listed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    bob.chat(b"spam").await.unwrap();
    heard(&mut ann, ghost).await;
    local_bob.chat(b"mine").await.unwrap();
    heard(&mut ann, local_bob.uid.unwrap()).await;

    let (mut ngc, _) = ng::Client::account(a.ng, "admin", "pw", "ngc")
        .await
        .unwrap();
    // History tells the namesakes apart as the live event does.
    let page = ngc.request("history", json!({})).await.unwrap();
    let from = |want: &str| {
        let lines = page["lines"].as_array().unwrap();
        lines.iter().find(|l| l["text"] == want).unwrap()["from"].clone()
    };
    assert_eq!(
        from("spam")["remote"],
        json!({ "server": "bb server", "tag": "bb", "tagged": false })
    );
    assert!(from("mine").get("remote").is_none());
    let kicked = ngc
        .request(
            "kick",
            json!({ "uid": ghost, "purge": 3600, "reason": "spam" }),
        )
        .await
        .unwrap();
    assert_eq!(kicked["hidden_here"], true);
    let page = ngc.request("history", json!({})).await.unwrap();
    let lines = page["lines"].as_array().unwrap();
    let text = |want: &str| lines.iter().any(|l| l["text"] == want);
    assert!(!text("spam"), "{lines:?}");
    assert!(
        lines.iter().any(|l| l["deleted"] == true),
        "a tombstone in its place"
    );
    assert!(text("mine"), "the local bob's line stands");
}

#[tokio::test]
async fn a_peer_shut_down_is_held_for_the_grace_period_and_then_let_go() {
    let (a, b, _dirs) = linked("grace = 2").await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let _bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let bob = row(&mut ann, "bob").await.uid;
    let is_part =
        move |f: &legacy::Frame| f.ty == push::USER_PART && f.uint(tag::UID) == Some(bob.into());

    // A stopping server closes for a Shutdown, and dials nobody after.
    b.hub.shutdown().await;
    goes_down(&a.hub, 2).await;
    let early = tokio::time::timeout(Duration::from_secs(1), ann.rx.recv_where(is_part)).await;
    assert!(early.is_err(), "held through the grace: {early:?}");
    assert_eq!(row(&mut ann, "bob").await.uid, bob);
    // Not back within it: an honest netsplit.
    let late = tokio::time::timeout(Duration::from_secs(5), ann.rx.recv_where(is_part)).await;
    assert!(matches!(late, Ok(Ok(_))), "{late:?}");
}

/// Three servers in a chain, `aa` and `cc` each dialing `bb`, every link
/// with every feature and transit, so `bb` relays between them.
async fn chain() -> (Server, Server, Server, [tempfile::TempDir; 3]) {
    chain_offering(r#"["chat", "msgs", "info", "transit"]"#).await
}

/// [`chain`], `cc`'s link to `bb` offering only `cc_offers`.
async fn chain_offering(cc_offers: &str) -> (Server, Server, Server, [tempfile::TempDir; 3]) {
    chain_trying(cc_offers, "", "").await
}

/// [`chain_offering`], `aa`'s link trying `drafts` as well and `cc`'s
/// `cc_drafts`.
async fn chain_trying(
    cc_offers: &str,
    drafts: &str,
    cc_drafts: &str,
) -> (Server, Server, Server, [tempfile::TempDir; 3]) {
    const TRANSIT: &str = r#"["chat", "msgs", "info", "transit"]"#;
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let b_tls = bind().await;
    let b_addr = b_tls.local_addr().unwrap();
    let accept = |name: &str, seed: u8, drafts: &str| {
        format!(
            "[[link.peer]]\nname = \"{name}\"\naccept = true\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = {TRANSIT}\n{drafts}\n",
            public(seed)
        )
    };
    let dial = |name: &str, drafts: &str| {
        format!(
            "[[link.peer]]\nname = \"bb\"\ndial = \"{b_addr}\"\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = {TRANSIT}\n{drafts}\n",
            public(2)
        )
    };
    let peers = accept("aa", 1, drafts) + &accept("cc", 3, cc_drafts);
    let b = start(dirs[1].path(), 2, "bb", "", &peers, b_tls).await;
    let a_peer = dial("aa", drafts);
    let a = start(dirs[0].path(), 1, "aa", "", &a_peer, bind().await).await;
    let c_peer = dial("cc", cc_drafts).replace(
        &format!("features = {TRANSIT}"),
        &format!("features = {cc_offers}"),
    );
    let c = start(dirs[2].path(), 3, "cc", "", &c_peer, bind().await).await;
    assert!(comes_up(&a.hub, 2, Duration::from_secs(10)).await);
    assert!(comes_up(&c.hub, 2, Duration::from_secs(10)).await);
    (a, b, c, dirs)
}

#[tokio::test]
async fn a_server_in_the_middle_relays_users_chat_and_messages_between_its_links() {
    let (a, _b, c, _dirs) = chain().await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut cat = legacy::Client::login_at(c.legacy, &Login::guest("cat"))
        .await
        .unwrap();
    // Each sees the other, two links away, as from the far end's server.
    let cat_here = row(&mut ann, "cat").await.uid;
    let ann_there = row(&mut cat, "ann").await.uid;
    let (_watcher, hello) = ng::Client::guest(a.ng, "watcher").await.unwrap();
    let users = hello["users"].as_array().unwrap();
    let seen = users.iter().find(|u| u["nick"] == "cat").unwrap();
    assert_eq!(seen["remote"]["tag"], "cc");

    // A line crosses both links, formatted where it is heard.
    cat.chat(b"hi from cc").await.unwrap();
    assert_eq!(
        heard(&mut ann, cat_here).await,
        b"\r          cat:  hi from cc"
    );

    // A message crosses both, and the answer comes back.
    let sent = ann
        .call(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, cat_here.to_be_bytes().to_vec()),
                (tag::BODY, b"hi cat".to_vec()),
            ],
        )
        .await;
    assert!(sent.is_ok(), "{sent:?}");
    let got = cat
        .rx
        .recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(ann_there.into()))
        .await
        .unwrap();
    assert_eq!(got.bytes(tag::BODY).unwrap(), b"hi cat");

    // User info names the far server.
    let info = ann
        .call(
            ClientHdr::UserGetInfo.as_u32(),
            &[(tag::UID, cat_here.to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let text = String::from_utf8(info.bytes(tag::BODY).unwrap()).unwrap();
    assert!(text.starts_with("  server: cc server\r"), "{text:?}");
    assert!(text.contains("name: cat\r"), "{text:?}");

    // And when cat leaves cc, ann hears it two links away.
    drop(cat);
    let part = ann
        .rx
        .recv_where(|f| f.ty == push::USER_PART && f.uint(tag::UID) == Some(cat_here.into()))
        .await;
    assert!(part.is_ok(), "{part:?}");
}

#[tokio::test]
async fn a_kick_two_links_away_is_carried_out_by_the_users_home() {
    let (a, _b, c, _dirs) = chain().await;
    let mut admin = legacy::Client::login_at(a.legacy, &Login::account("ann", "admin", "pw"))
        .await
        .unwrap();
    let mut cat = legacy::Client::login_at(c.legacy, &Login::guest("cat"))
        .await
        .unwrap();
    let cat_here = row(&mut admin, "cat").await.uid;
    let kicked = admin
        .call(
            ClientHdr::UserKick.as_u32(),
            &[(tag::UID, cat_here.to_be_bytes().to_vec())],
        )
        .await;
    assert!(kicked.is_ok(), "{kicked:?}");
    let told = cat.rx.recv_where(|f| f.ty == 0x163).await.unwrap();
    let text = String::from_utf8(told.bytes(tag::BODY).unwrap()).unwrap();
    assert!(text.contains("aa server (aa)"), "{text:?}");
}

#[tokio::test]
async fn a_ban_two_links_away_is_placed_and_enforced_by_the_users_home() {
    let (a, _b, c, dirs) = chain().await;
    std::fs::write(
        dirs[2].path().join("accounts/cat.toml"),
        "name = \"cat\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let mut admin = legacy::Client::login_at(a.legacy, &Login::account("ann", "admin", "pw"))
        .await
        .unwrap();
    let mut cat = legacy::Client::login_at(c.legacy, &Login::account("cat", "cat", "pw"))
        .await
        .unwrap();
    let cat_here = row(&mut admin, "cat").await.uid;
    let banned = admin
        .call(
            ClientHdr::UserKick.as_u32(),
            &[
                (tag::UID, cat_here.to_be_bytes().to_vec()),
                (tag::BAN, vec![0, 1]),
            ],
        )
        .await;
    assert!(banned.is_ok(), "{banned:?}");
    let told = cat.rx.recv_where(|f| f.ty == 0x163).await.unwrap();
    let text = String::from_utf8(told.bytes(tag::BODY).unwrap()).unwrap();
    assert!(
        text.contains("banned from the network by aa server (aa)"),
        "{text:?}"
    );
    let again = legacy::Client::login_at(c.legacy, &Login::account("cat", "cat", "pw")).await;
    assert!(again.is_err(), "refused at home");
}

#[tokio::test]
async fn a_link_without_transit_is_not_joined_to_the_others() {
    let (a, b, c, _dirs) = chain_offering(r#"["chat", "msgs", "info"]"#).await;
    let mut ann = legacy::Client::login_at(a.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bea = legacy::Client::login_at(b.legacy, &Login::guest("bea"))
        .await
        .unwrap();
    let _cat = legacy::Client::login_at(c.legacy, &Login::guest("cat"))
        .await
        .unwrap();
    // bb shows cat, but does not pass cat on to aa.
    row(&mut bea, "cat").await;
    row(&mut ann, "bea").await;
    let rows = ann.user_list().await.unwrap();
    assert!(
        rows.iter().all(|r| r.nick != b"cat"),
        "cat crossed a link without transit"
    );
}

#[tokio::test]
async fn no_act_on_another_user_reaches_a_ghost() {
    let (a, b, _dirs) = linked("").await;
    let mut admin = legacy::Client::login_at(a.legacy, &Login::account("admin", "admin", "pw"))
        .await
        .unwrap();
    let carol = legacy::Client::login_at(a.legacy, &Login::guest("carol"))
        .await
        .unwrap();
    let _bob = legacy::Client::login_at(b.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let ghost = row(&mut admin, "bob").await.uid;
    // Nobody's uid: a ghost must be refused exactly as a user who is not
    // there would be.
    let nobody: u16 = 0x7ff0;

    // A private chat of the admin's, with a local user in it, for the
    // invitation.
    let made = admin
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, carol.uid.unwrap().to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let chat = (tag::CHAT_ID, made.bytes(tag::CHAT_ID).unwrap());

    for ty in hxd_session::NAMES_A_USER {
        // Carried to the ghost's server, or a kick carried out here, as
        // their own tests show.
        if matches!(
            ty,
            ClientHdr::Msg | ClientHdr::UserGetInfo | ClientHdr::UserKick
        ) {
            continue;
        }
        let request = |to: u16| {
            let uid = (tag::UID, to.to_be_bytes().to_vec());
            match ty {
                ClientHdr::Msg => vec![uid, (tag::BODY, b"hello".to_vec())],
                ClientHdr::UserGetInfo | ClientHdr::UserKick | ClientHdr::ChatCreate => vec![uid],
                ClientHdr::ChatInvite => vec![chat.clone(), uid],
                other => panic!("{other:?} names a user and has no case here"),
            }
        };
        let answer = admin.call(ty.as_u32(), &request(ghost)).await;
        let absent = admin.call(ty.as_u32(), &request(nobody)).await;
        assert!(
            matches!(&answer, Err(hxd_testclient::Error::Refused { .. })),
            "{ty:?}: {answer:?}"
        );
        assert_eq!(
            format!("{answer:?}"),
            format!("{absent:?}"),
            "{ty:?}: a ghost refused unlike a user who is not there"
        );
    }
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

/// Alice, bob or carol, by seed, as the accounts every server has name
/// them.
fn person(seed: u8) -> Person {
    let name = ["alice", "bob", "carol"][usize::from(seed) - 1];
    let id = IdentityKey::from_seed(&[seed; 32]);
    let dev = DeviceKey::from_seed(&[seed + 100; 32]);
    let card = Card::new(&id, name, now()).sign(&id, vec![]).unwrap();
    let cert = DeviceCert::for_device(&id, &dev, now() - 3600, cert::RECOMMENDED_LIFETIME)
        .unwrap()
        .sign(&id);
    Person {
        id,
        dev,
        card,
        cert,
    }
}

fn fingerprint(p: &Person) -> Fingerprint {
    Fingerprint::of(&p.id.public())
}

fn unb64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

/// One HTTP/1.1 request, closed after its answer: the JSON body.
async fn http_json(addr: SocketAddr, path: &str) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: 0\r\n\r\n"
    );
    s.write_all(head.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    serde_json::from_slice(&raw[split + 4..]).unwrap()
}

/// `p` logged in to `server`'s ng port with their key, saying it signs
/// every lobby line and can open sealed messages, and its login reply.
async fn keyed(server: &Server, p: &Person) -> (ng::Client, Value) {
    keyed_saying(server, p, json!({ "signs": "default", "sealed": true })).await
}

async fn keyed_saying(server: &Server, p: &Person, login: Value) -> (ng::Client, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = server.ng;
    let ch = http_json(addr, "/identity/challenge").await;
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let proof = LoginProof::sign(&p.dev, &challenge, &key, &addr.to_string(), now()).unwrap();
    let body = json!({ "card": B64.encode(&p.card), "device_cert": B64.encode(&p.cert),
                       "proof": B64.encode(&proof) })
    .to_string();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /identity/auth HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let auth: Value = serde_json::from_slice(&raw[split + 4..]).unwrap();
    let token = auth["token"].as_str().expect("a transport token");
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut c = ng::Client::over(Box::new(tcp), &format!("ws://{addr}/ng?token={token}"))
        .await
        .unwrap();
    let hello = c.login(login).await.unwrap();
    assert!(hello["caps"].as_array().unwrap().contains(&json!("signed")));
    (c, hello)
}

/// The row of a ghost `is` picks out, from `hello` or once `c` hears of
/// it.
async fn ghost_row(c: &mut ng::Client, hello: &Value, is: impl Fn(&Value) -> bool) -> Value {
    let is = |u: &Value| u.get("remote").is_some() && is(u);
    if let Some(u) = hello["users"].as_array().unwrap().iter().find(|u| is(u)) {
        return u.clone();
    }
    c.event_where("user_joined", |d| is(&d["user"]))
        .await
        .unwrap()
        .data["user"]
        .clone()
}

/// The ghost of the user whose identity is `p`'s.
async fn identity_row(c: &mut ng::Client, hello: &Value, p: &Person) -> Value {
    let fp = fingerprint(p).to_string();
    ghost_row(c, hello, |u| u["identity"]["fingerprint"] == fp).await
}

/// The `n`th guid a test signs under, and the id it spells.
fn guid(n: u8) -> (String, [u8; 16]) {
    let guid = format!("{n:02x}0e1000-1234-4abc-89ab-000000000000");
    let id = [
        n, 0x0e, 0x10, 0, 0x12, 0x34, 0x4a, 0xbc, 0x89, 0xab, 0, 0, 0, 0, 0, 0,
    ];
    (guid, id)
}

/// A signed private message of `from`'s to `to`, as `msg` sends it.
fn signed_msg(from: &Person, n: u8, to: &Person, text: &str) -> (String, String) {
    let (guid, id) = guid(n);
    let m = PrivateMessage {
        id,
        sent: now(),
        to: fingerprint(to),
        cert: from.cert.clone(),
        text: text.into(),
        quote: None,
        auto: false,
    };
    let detached = Signed::<PrivateMessage>::parse(&m.sign(&from.dev).unwrap(), now())
        .unwrap()
        .detached()
        .unwrap();
    (guid, B64.encode(detached))
}

/// A signed lobby line of `p`'s on the server whose link key is `home`.
fn signed_line(p: &Person, home: u8, n: u8, text: &str) -> (String, String) {
    let (guid, id) = guid(n);
    let line = ChatLine {
        id,
        sent: now(),
        server: discovery_key(home),
        room: 0,
        cert: p.cert.clone(),
        text: text.into(),
        act: false,
    };
    let whole = line.sign(&p.dev).unwrap();
    let detached = Signed::<ChatLine>::parse(&whole, now())
        .unwrap()
        .detached()
        .unwrap();
    (guid, B64.encode(detached))
}

/// A form as a `chat` event or a history line serves it: whole, which
/// verifies under the scope `home` names, or its link form, which names
/// its certificate by hash alone.
fn whole(signed: &Value, text: &str, home: u8) -> bool {
    let form = unb64(signed.as_str().unwrap());
    if link_cert_sha256(&form).is_ok() {
        return false;
    }
    let line = Signed::<ChatLine>::parse_detached(&form, [text], now()).unwrap();
    assert_eq!(
        (line.message.server, line.message.room),
        (discovery_key(home), 0)
    );
    true
}

/// `reader` hears `sender`'s signed lines from the server whose link key
/// is `home`: the first in its link form, verifiable once its server has
/// fetched the certificate, and history serving it whole by then; the
/// next whole as it is heard. Either way with its text canonical and its
/// home server's key beside it.
async fn signed_lines_cross(
    sender: &mut ng::Client,
    p: &Person,
    home: u8,
    reader: &mut ng::Client,
    first: u8,
) {
    let key = B64.encode(discovery_key(home));
    let text: &str = &format!("signed {first}\nacross");
    let (guid, signed) = signed_line(p, home, first, text);
    sender
        .request(
            "chat",
            json!({ "text": text, "guid": guid, "signed": signed }),
        )
        .await
        .unwrap();
    let heard = reader
        .event_where("chat", |d| d["text"] == text)
        .await
        .unwrap()
        .data;
    assert_eq!(heard["from"]["remote"]["server_key"], key);
    assert!(!whole(&heard["signed"], text, home), "{heard}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let page = reader.request("history", json!({})).await.unwrap();
        let logged = page["lines"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["text"] == text)
            .cloned()
            .unwrap();
        assert_eq!(logged["from"]["remote"]["server_key"], key);
        if whole(&logged["signed"], text, home) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never whole: {logged}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let text: &str = &format!("signed {}", first + 1);
    let (guid, signed) = signed_line(p, home, first + 1, text);
    sender
        .request(
            "chat",
            json!({ "text": text, "guid": guid, "signed": signed }),
        )
        .await
        .unwrap();
    let heard = reader
        .event_where("chat", |d| d["text"] == text)
        .await
        .unwrap()
        .data;
    assert!(whole(&heard["signed"], text, home), "{heard}");
}

const USER_KEYS: &str = "drafts = [\"user_keys\"]";

#[tokio::test]
async fn a_signed_lobby_line_crosses_both_ways_and_verifies_where_it_is_heard() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, USER_KEYS, USER_KEYS).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (alice, bob) = (person(1), person(2));
    let (mut on_a, a_hello) = keyed(&a, &alice).await;
    let (mut on_b, b_hello) = keyed(&b, &bob).await;
    // Each ghost carries the identity its home server says it proved, and
    // that server's key.
    let row = identity_row(&mut on_b, &b_hello, &alice).await;
    assert_eq!(row["remote"]["server_key"], B64.encode(discovery_key(1)));
    identity_row(&mut on_a, &a_hello, &bob).await;
    signed_lines_cross(&mut on_a, &alice, 1, &mut on_b, 1).await;
    signed_lines_cross(&mut on_b, &bob, 2, &mut on_a, 3).await;

    // A line of a ghost's, pasted, stands under its home server's key,
    // which this server showed; under a key it never knew, it does not.
    let (_, signed) = signed_line(&alice, 1, 9, "pasted");
    on_b.request(
        "report",
        json!({ "reason": "x", "evidence": "pasted", "signed": signed }),
    )
    .await
    .unwrap();
    let (_, elsewhere) = signed_line(&alice, 9, 10, "pasted");
    let refused = on_b
        .request(
            "report",
            json!({ "reason": "x", "evidence": "pasted", "signed": elsewhere }),
        )
        .await;
    assert!(
        matches!(&refused, Err(hxd_testclient::Error::Refused { code, .. }) if code == "bad_signature"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_ghost_says_it_signs_while_its_user_signs_every_lobby_line() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, USER_KEYS, USER_KEYS).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (alice, bob) = (person(1), person(2));
    let (mut on_a, _) = keyed_saying(&a, &alice, json!({ "signs": "able" })).await;
    let (mut on_b, b_hello) = keyed(&b, &bob).await;
    let row = identity_row(&mut on_b, &b_hello, &alice).await;
    assert!(row["identity"].get("signs").is_none(), "{row}");
    let fp = fingerprint(&alice).to_string();
    let alices = |d: &Value| d["user"]["identity"]["fingerprint"] == fp;

    // Signing a line is a choice made for that line, not every one.
    let (guid, signed) = signed_line(&alice, 1, 1, "once");
    on_a.request(
        "chat",
        json!({ "text": "once", "guid": guid, "signed": signed }),
    )
    .await
    .unwrap();
    on_b.event_where("chat", |d| d["text"] == "once")
        .await
        .unwrap();
    on_a.request("nick", json!({ "icon": 77 })).await.unwrap();
    let changed = on_b.event_where("user_changed", alices).await.unwrap().data;
    assert_eq!(changed["user"]["icon"], 77, "{changed}");
    assert!(
        changed["user"]["identity"].get("signs").is_none(),
        "{changed}"
    );

    for (signs, shown) in [("default", true), ("able", false), ("default", true)] {
        on_a.request("signs", json!({ "signs": signs }))
            .await
            .unwrap();
        let changed = on_b.event_where("user_changed", alices).await.unwrap().data;
        assert_eq!(
            changed["user"]["identity"].get("signs").is_some(),
            shown,
            "{signs}: {changed}"
        );
    }

    // A resume that leaves it out takes it off over the link too.
    let (session, seq) = (on_a.session.clone().unwrap(), on_a.rx.last_seq);
    on_a.close().await.unwrap();
    let (_on_a, _) = ng::Client::resume(a.ng, session, seq, Vec::new())
        .await
        .unwrap();
    on_b.event_where("user_changed", |d| {
        alices(d) && d["user"]["identity"].get("signs").is_none()
    })
    .await
    .unwrap();
}

/// What a peer says of its users' keys is read only where this server
/// tries the draft with it too.
#[tokio::test]
async fn a_ghosts_keys_are_not_read_from_a_peer_not_tried_with() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, USER_KEYS, "").await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (_on_a, _) = keyed(&a, &person(1)).await;
    let (mut on_b, b_hello) = keyed(&b, &person(2)).await;
    let row = ghost_row(&mut on_b, &b_hello, |u| u["nick"] == "alice").await;
    assert!(row.get("identity").is_none(), "{row}");
}

#[tokio::test]
async fn a_server_in_the_middle_passes_signed_lines_and_their_fetches_on() {
    let (a, _b, c, _dirs) = chain_trying(
        r#"["chat", "msgs", "info", "transit"]"#,
        USER_KEYS,
        USER_KEYS,
    )
    .await;
    let (alice, carol) = (person(1), person(3));
    let (mut on_a, _) = keyed(&a, &alice).await;
    let (mut on_c, c_hello) = keyed(&c, &carol).await;
    let row = identity_row(&mut on_c, &c_hello, &alice).await;
    assert_eq!(row["identity"]["signs"], true, "key flags passed on: {row}");
    signed_lines_cross(&mut on_a, &alice, 1, &mut on_c, 1).await;
}

/// A signed line never crosses without its signature (§4.11), so a peer
/// that does not try the draft is sent one with it, which it shows
/// unverified, in its link form; it is told nothing of anyone's keys, and
/// neither a signed message nor a certificate crosses to it.
#[tokio::test]
async fn a_peer_not_trying_the_draft_hears_a_signed_line_with_its_signature() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, "", "").await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (alice, bob) = (person(1), person(2));
    let (mut on_a, a_hello) = keyed(&a, &alice).await;
    let (mut on_b, b_hello) = keyed(&b, &bob).await;
    let (guid, signed) = signed_line(&alice, 1, 1, "signed");
    on_a.request(
        "chat",
        json!({ "text": "signed", "guid": guid, "signed": signed }),
    )
    .await
    .unwrap();
    let heard = on_b
        .event_where("chat", |d| d["text"] == "signed")
        .await
        .unwrap()
        .data;
    let form = unb64(heard["signed"].as_str().unwrap());
    assert!(link_cert_sha256(&form).is_ok(), "{heard}");
    assert!(
        heard["from"]["remote"].get("server_key").is_none(),
        "{heard}"
    );
    let alice_there = ghost_row(&mut on_b, &b_hello, |u| u["nick"] == "alice").await;
    assert!(alice_there.get("identity").is_none(), "{alice_there}");

    let bob_here = ghost_row(&mut on_a, &a_hello, |u| u["nick"] == "bob").await["uid"].clone();
    let (guid, signed) = signed_msg(&alice, 2, &bob, "hi");
    for (req, params, code) in [
        (
            "msg",
            json!({ "to": bob_here, "text": "hi", "guid": guid, "signed": signed }),
            "bad_request",
        ),
        ("device_cert", json!({ "uid": bob_here }), "not_delivered"),
    ] {
        match on_a.request(req, params).await {
            Err(hxd_testclient::Error::Refused { code: got, .. }) => assert_eq!(got, code, "{req}"),
            other => panic!("{req}: {other:?}"),
        }
    }
}

/// A replay memory that starts empty.
#[derive(Default)]
struct Memory(Vec<(Fingerprint, [u8; 16])>);

impl Replay for Memory {
    fn latest(&mut self, now: u64) -> u64 {
        now
    }

    fn accepted(&self, signer: &Fingerprint, id: &[u8; 16]) -> bool {
        self.0.contains(&(*signer, *id))
    }

    fn accept(&mut self, signer: Fingerprint, id: [u8; 16], _: u64) -> bool {
        let new = !self.accepted(&signer, &id);
        self.0.push((signer, id));
        new
    }
}

/// What `msg` names a box's key by.
fn key_hash(cert: &[u8]) -> String {
    B64.encode(Sha256::digest(DeviceCert::parse(cert).unwrap().device_enc))
}

#[tokio::test]
async fn private_messages_cross_signed_and_sealed_to_a_ghosts_device() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, USER_KEYS, USER_KEYS).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (alice, bob, carol) = (person(1), person(2), person(3));
    let (mut on_a, a_hello) = keyed(&a, &alice).await;
    let (mut on_b, _) = keyed(&b, &bob).await;
    let bob_here = identity_row(&mut on_a, &a_hello, &bob).await["uid"].clone();

    // Signed: heard in its link form until bob's server holds alice's
    // certificate, which it fetches from hers, and whole from then on.
    let mut n = 1;
    loop {
        let text = format!("signed {n}");
        let (guid, signed) = signed_msg(&alice, n, &bob, &text);
        on_a.request(
            "msg",
            json!({ "to": bob_here, "text": text, "guid": guid, "signed": signed }),
        )
        .await
        .unwrap();
        let got = on_b
            .event_where("msg", |d| d["text"] == text.as_str())
            .await
            .unwrap()
            .data;
        let form = unb64(got["signed"].as_str().unwrap());
        if link_cert_sha256(&form).is_err() {
            let m =
                Signed::<PrivateMessage>::parse_detached(&form, [text.as_str()], now()).unwrap();
            assert_eq!(m.message.to, fingerprint(&bob));
            break;
        }
        assert!(n < 100, "never whole");
        n += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Signed to someone else, it is not sent at all.
    let (guid, signed) = signed_msg(&alice, 200, &carol, "elsewhere");
    let refused = on_a
        .request(
            "msg",
            json!({ "to": bob_here, "text": "elsewhere", "guid": guid, "signed": signed }),
        )
        .await;
    assert!(
        matches!(&refused, Err(hxd_testclient::Error::Refused { code, .. }) if code == "bad_signature"),
        "{refused:?}"
    );

    // Sealed: to the certificate bob's server hands over the link, opened
    // by his device alone; and one sealed to another key is refused there.
    let got = on_a
        .request("device_cert", json!({ "uid": bob_here }))
        .await
        .unwrap();
    assert_eq!(unb64(got["cert"].as_str().unwrap()), bob.cert);
    let m = PrivateMessage {
        id: [7; 16],
        sent: now(),
        to: fingerprint(&bob),
        cert: alice.cert.clone(),
        text: "only you".into(),
        quote: None,
        auto: false,
    };
    let sealed = seal_to(
        &m,
        &alice.dev,
        &DeviceCert::parse(&bob.cert).unwrap(),
        false,
    )
    .unwrap();
    let sent = on_a
        .request(
            "msg",
            json!({ "to": bob_here, "sealed": B64.encode(&sealed), "cert": key_hash(&bob.cert) }),
        )
        .await
        .unwrap();
    assert_eq!(sent, json!({ "queued": false }));
    let ev = on_b
        .event_where("msg", |d| d.get("sealed").is_some())
        .await
        .unwrap()
        .data;
    assert_eq!(ev["text"], "[Encrypted message]");
    assert_eq!(ev["from"]["fingerprint"], fingerprint(&alice).to_string());
    let opening = Opening {
        now: now(),
        at: ev["at"].as_u64().unwrap(),
        reader: fingerprint(&bob),
        sender: Sender::Named(fingerprint(&alice)),
    };
    let opened = open(
        &unb64(ev["sealed"].as_str().unwrap()),
        &bob.dev,
        &opening,
        &mut Memory::default(),
    );
    let Opened::Verified { message, .. } = opened else {
        panic!("not verified: {opened:?}");
    };
    assert_eq!(message.message.text, "only you");
    let wrong = on_a
        .request(
            "msg",
            json!({ "to": bob_here, "sealed": B64.encode(&sealed), "cert": key_hash(&carol.cert) }),
        )
        .await;
    assert!(
        matches!(&wrong, Err(hxd_testclient::Error::Refused { code, .. }) if code == "cert_changed"),
        "{wrong:?}"
    );
}

/// A sealed message whose sender's fingerprint its recipient's home
/// server is not shown is refused there, before the key it was sealed to
/// is looked at, since fetching the certificate again would not help:
/// `cc` reads no fingerprints from `bb`, which it does not try the draft
/// with.
#[tokio::test]
async fn a_sealed_message_from_a_sender_unkeyed_where_it_arrives_is_refused() {
    let (a, _b, c, _dirs) =
        chain_trying(r#"["chat", "msgs", "info", "transit"]"#, USER_KEYS, "").await;
    let (alice, carol) = (person(1), person(3));
    let (mut on_a, a_hello) = keyed(&a, &alice).await;
    let (_on_c, _) = keyed(&c, &carol).await;
    let carol_here = ghost_row(&mut on_a, &a_hello, |u| u["nick"] == "carol").await["uid"].clone();
    let m = PrivateMessage {
        id: [8; 16],
        sent: now(),
        to: fingerprint(&carol),
        cert: alice.cert.clone(),
        text: "only you".into(),
        quote: None,
        auto: false,
    };
    let carols = DeviceCert::parse(&carol.cert).unwrap();
    let sealed = seal_to(&m, &alice.dev, &carols, false).unwrap();
    // Named by a key not carol's, which alone would be `cert_changed`.
    let refused = on_a
        .request(
            "msg",
            json!({ "to": carol_here, "sealed": B64.encode(&sealed), "cert": key_hash(&alice.cert) }),
        )
        .await;
    let unkeyed = hxd_core::server_link::PeerRefusal::SenderUnkeyed.text();
    assert!(
        matches!(&refused, Err(hxd_testclient::Error::Refused { code, text })
            if code == "not_sealed" && text == unkeyed),
        "{refused:?}"
    );
}

/// A certificate that expires takes `sealed` and `signs` with it: from
/// its session's row here, and from its ghost's key flags over the link;
/// and neither `signs` nor a resume gives them back.
#[tokio::test]
async fn an_expired_certificate_takes_its_sessions_key_flags_with_it() {
    let (a, b, _dirs) = pair_with(2, 1, "", EVERY_FEATURE, USER_KEYS, USER_KEYS).await;
    assert!(comes_up(&b.hub, 1, Duration::from_secs(10)).await);
    let (alice, bob, carol) = (person(1), person(2), person(3));
    let (mut on_a, _) = keyed(&a, &alice).await;
    let (mut carol_on_a, carol_hello) = keyed(&a, &carol).await;
    let (mut on_b, b_hello) = keyed(&b, &bob).await;
    let fp = fingerprint(&alice).to_string();
    let local = carol_hello["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["identity"]["fingerprint"] == fp)
        .cloned()
        .unwrap();
    assert_eq!(
        (&local["identity"]["sealed"], &local["identity"]["signs"]),
        (&json!(true), &json!(true)),
        "{local}"
    );
    let ghost = identity_row(&mut on_b, &b_hello, &alice).await;
    assert_eq!(ghost["identity"]["signs"], true, "{ghost}");

    a.core
        .clock()
        .advance(Duration::from_secs(cert::RECOMMENDED_LIFETIME));
    a.core.expire_device_keys();
    let alices_without = |flag: &'static str| {
        let fp = fp.clone();
        move |d: &Value| {
            let id = &d["user"]["identity"];
            id["fingerprint"] == fp && id.get(flag).is_none()
        }
    };
    let local = carol_on_a
        .event_where("user_changed", alices_without("sealed"))
        .await
        .unwrap()
        .data;
    assert!(local["user"]["identity"].get("signs").is_none(), "{local}");
    on_b.event_where("user_changed", alices_without("signs"))
        .await
        .unwrap();

    let refused = on_a.request("signs", json!({ "signs": "default" })).await;
    assert!(
        matches!(&refused, Err(hxd_testclient::Error::Refused { code, .. }) if code == "bad_request"),
        "{refused:?}"
    );
    let (session, seq) = (on_a.session.clone().unwrap(), on_a.rx.last_seq);
    on_a.close().await.unwrap();
    let mut again = ng::Client::connect(a.ng).await.unwrap();
    again.rx.last_seq = seq;
    let resumed = again
        .request(
            "resume",
            json!({ "session": session.0, "token": session.1, "last_seq": seq,
                    "sealed": true, "signs": "default" }),
        )
        .await
        .unwrap();
    let (r, id) = (&resumed, &resumed["self"]["identity"]);
    let flags = [&r["sealed"], &r["signs"], &id["sealed"], &id["signs"]];
    assert!(flags.iter().all(|v| v.is_null()), "{resumed}");
}
