//! Server linking (`docs/server-link.md`) between real servers in process:
//! each with a TLS port and a `[link]` section, one dialing the other by
//! key mode.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hxd_testclient::legacy::{self, push, Login, UserRow};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::json;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    hub: hxd_link::Hub,
    config: std::path::PathBuf,
}

fn public(seed: u8) -> String {
    B64.encode(hxd_link::LinkKey::from_seed(&[seed; 32]).public())
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
    let seed_hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("link.key"), seed_hex).unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), issued.signing_key.serialize_pem()).unwrap();
    let text = format!(
        "[server]\nname = \"{tag} server\"\n[paths]\naccounts = \"{d}/accounts\"\n\
         [inbox]\ndb = \"{d}/hx.db\"\n[history]\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
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
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
        hub: hub.clone(),
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
    const TRANSIT: &str = r#"["chat", "msgs", "info", "transit"]"#;
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let b_tls = bind().await;
    let b_addr = b_tls.local_addr().unwrap();
    let accept = |name: &str, seed: u8| {
        format!(
            "[[link.peer]]\nname = \"{name}\"\naccept = true\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = {TRANSIT}\n",
            public(seed)
        )
    };
    let dial = |name: &str| {
        format!(
            "[[link.peer]]\nname = \"bb\"\ndial = \"{b_addr}\"\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = {TRANSIT}\n",
            public(2)
        )
    };
    let peers = accept("aa", 1) + &accept("cc", 3);
    let b = start(dirs[1].path(), 2, "bb", "", &peers, b_tls).await;
    let a = start(dirs[0].path(), 1, "aa", "", &dial("aa"), bind().await).await;
    let c_peer = dial("cc").replace(
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
