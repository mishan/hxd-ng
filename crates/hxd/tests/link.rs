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
/// each holds for the other and more `[link]` keys for `a`.
async fn pair_with(
    a_holds: u8,
    b_holds: u8,
    a_link: &str,
    a_offers: &str,
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
             key = \"ed25519:{}\"\naccount = \"link-bb\"\nfeatures = {a_offers}\n",
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
             key = \"{}\"\naccount = \"link-bb\"\nfeatures = {EVERY_FEATURE}\n",
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
    pair_with(a_holds, b_holds, "", EVERY_FEATURE).await
}

/// Two servers linked, waited for.
async fn linked(a_link: &str) -> (Server, Server, [tempfile::TempDir; 2]) {
    linked_offering(a_link, EVERY_FEATURE).await
}

/// Two servers linked, `a` offering only `a_offers`.
async fn linked_offering(a_link: &str, a_offers: &str) -> (Server, Server, [tempfile::TempDir; 2]) {
    let servers = pair_with(2, 1, a_link, a_offers).await;
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

    // The same on the ng wire, from an account that may do each.
    let (mut ngc, _) = ng::Client::account(a.ng, "admin", "pw", "ngc")
        .await
        .unwrap();
    for method in ["block"] {
        let to = |uid: u16| json!({ "uid": uid });
        let answer = ngc.request(method, to(ghost)).await;
        let absent = ngc.request(method, to(nobody)).await;
        assert!(
            matches!(&answer, Err(hxd_testclient::Error::Refused { code, .. }) if code != "access_denied"),
            "{method}: {answer:?}"
        );
        assert_eq!(
            format!("{answer:?}"),
            format!("{absent:?}"),
            "{method}: a ghost refused unlike a user who is not there"
        );
    }
}
