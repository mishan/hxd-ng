//! Pronouns on the classic wire, on a server built from a real config:
//! set with the system account's `/pronouns`, kept in the account file's
//! `[profile]`, and shown as a `pronouns:` line in Get User Info's text
//! wherever the reader's encoding keeps them, with nothing else sent for
//! a change.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hxd_core::access::{bit, AccessBits};
use hxd_testclient::legacy::{push, xor, Client, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::json;

const UTF8: u32 = 1 << 1;
const ACCOUNT_MODIFY: u32 = 0x0161;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
    accounts: PathBuf,
}

impl Server {
    fn system(&self) -> u16 {
        self.core.system_uid().unwrap()
    }

    fn file(&self, login: &str) -> String {
        std::fs::read_to_string(self.accounts.join(format!("{login}.toml"))).unwrap()
    }
}

/// A server with `server` as more of its `[server]` keys and `limits` as
/// its `[limits]`, and these accounts: `alice` and `dave`, people; `bob`,
/// a person whose file turns pronouns off; `admin`, who may edit
/// accounts; and `carol`, whose file says what the server would never
/// have written.
async fn start(dir: &Path, server: &str, limits: &str) -> Server {
    let d = dir.display();
    let path = dir.join("hxd-ng.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\n{server}\n[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n\
             [system]\n[limits]\n{limits}\n"
        ),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    ctx.core.start_system_session().unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let accounts = dir.join("accounts");
    let basic = "[access]\nsend_msgs = true\nget_user_info = true\nread_users = true\n";
    for (login, more) in [
        ("alice", ""),
        ("dave", ""),
        ("bob", "[extra]\npronouns = false\n"),
        (
            "admin",
            "modify_users = true\ndisconnect_users = true\n[profile]\npronouns = \"they/them\"\n",
        ),
        (
            "carol",
            "[profile]\npronouns = \"she/her\\r   login: admin\"\n",
        ),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("# {login}'s account\nname = \"{login}\"\npassword = \"pw\"\n{basic}{more}"),
        )
        .unwrap();
    }
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
        core: ctx.core.clone(),
        accounts,
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx));
    server
}

/// A server as an operator leaves it, but for the flood limit: the tests
/// that make many changes would otherwise be kicked for them.
async fn started(dir: &Path) -> Server {
    start(dir, "", "spam_points = 0").await
}

async fn login(server: &Server, login: &str, caps: Option<u32>) -> Client {
    let mut l = Login::account(login, login, "pw");
    l.caps = caps;
    Client::login_at(server.legacy, &l).await.unwrap()
}

/// Send `text` to the system account, and its answer.
async fn command(c: &mut Client, system: u16, text: &[u8]) -> Vec<u8> {
    let trans = c
        .send(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, system.to_be_bytes().to_vec()),
                (tag::BODY, text.to_vec()),
            ],
        )
        .await
        .unwrap();
    assert!(!c.reply(trans).await.unwrap().is_error());
    c.recv_where(|f| f.ty == push::MSG && f.uint(tag::UID) == Some(u32::from(system)))
        .await
        .unwrap()
        .bytes(tag::BODY)
        .unwrap()
}

async fn said(c: &mut Client, system: u16, text: &str) -> String {
    String::from_utf8_lossy(&command(c, system, text.as_bytes()).await).into_owned()
}

/// What `c` reads in Get User Info of `uid`, as sent.
async fn info(c: &mut Client, uid: u16) -> Vec<u8> {
    c.call(
        ClientHdr::UserGetInfo.as_u32(),
        &[(tag::UID, uid.to_be_bytes().to_vec())],
    )
    .await
    .unwrap()
    .bytes(tag::BODY)
    .unwrap()
}

/// What `c` has been sent that it has not read, once everything sent
/// before now has arrived.
async fn unread(c: &mut Client) -> Vec<u32> {
    c.ping().await.unwrap();
    c.rx.take_backlog().iter().map(|f| f.ty).collect()
}

/// `text` as far as `  online:`, which moves as the session ages, and
/// whether what follows is that line, as it always was.
fn before_online(text: &[u8]) -> &[u8] {
    let at = text.windows(9).position(|w| w == b"  online:").unwrap();
    assert!(text.ends_with(b"s\r"), "{text:?}");
    &text[..at]
}

#[tokio::test]
async fn get_user_info_is_as_it_was_where_no_pronouns_are_shown() {
    // Someone with none; someone whose file says what the server would
    // never have written, who logs in all the same; and someone with
    // some, on a server that shows none.
    for (server, target) in [("", "dave"), ("", "carol"), ("pronouns = false", "admin")] {
        let td = tempfile::tempdir().unwrap();
        let s = start(td.path(), server, "spam_points = 0").await;
        let mut alice = login(&s, "alice", None).await;
        let mut shown = login(&s, target, None).await;
        let uid = shown.uid.unwrap();
        let want = format!("    name: {target}\r   login: -\r address: -\r");
        assert_eq!(
            before_online(&info(&mut alice, uid).await),
            want.as_bytes(),
            "{server:?} {target}"
        );
        if !server.is_empty() {
            assert_eq!(
                said(&mut alice, s.system(), "/pronouns she/her").await,
                "error: this server does not show pronouns"
            );
            assert_eq!(said(&mut shown, s.system(), "/pronouns").await, "ok: none");
        }
    }
}

#[tokio::test]
async fn pronouns_set_with_the_system_account_show_where_the_encoding_keeps_them() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let mut alice = login(&s, "alice", None).await;
    let mut dave = login(&s, "dave", Some(UTF8)).await;
    let mut bob = login(&s, "bob", None).await;
    let (alice_uid, dave_uid) = (alice.uid.unwrap(), dave.uid.unwrap());
    unread(&mut alice).await;
    unread(&mut bob).await;

    // In Mac Roman, as a period client types it: 0x8e is e acute.
    assert_eq!(
        command(&mut alice, s.system(), b"/pronouns \x8el/ella").await,
        b"ok: your pronouns are \x8el/ella"
    );
    // Nothing else is sent for it, to the setter or to anyone.
    assert!(unread(&mut alice).await.is_empty());
    assert!(unread(&mut bob).await.is_empty());
    assert_eq!(
        command(&mut alice, s.system(), b"/pronouns").await,
        b"ok: \x8el/ella"
    );
    let text = s.file("alice");
    assert!(text.starts_with("# alice's account\n"), "{text}");
    assert!(
        text.contains("[profile]\npronouns = \"\u{e9}l/ella\""),
        "{text}"
    );
    assert!(info(&mut bob, alice_uid)
        .await
        .starts_with(b"    name: alice\rpronouns: \x8el/ella\r   login: -\r"));
    assert!(info(&mut dave, alice_uid)
        .await
        .starts_with("    name: alice\npronouns: \u{e9}l/ella\n   login: -\n".as_bytes()));

    // What Mac Roman has no letters for is left out there, not shown as
    // question marks.
    let cjk = "\u{5f7c}/\u{5979}";
    assert_eq!(
        said(&mut dave, s.system(), &format!("/pronouns {cjk}")).await,
        format!("ok: your pronouns are {cjk}")
    );
    assert!(info(&mut dave, dave_uid)
        .await
        .starts_with(format!("    name: dave\npronouns: {cjk}\n").as_bytes()));
    assert!(info(&mut bob, dave_uid)
        .await
        .starts_with(b"    name: dave\r   login: -\r"));

    s.core.clock().advance(hxd_core::pronouns::INTERVAL);
    assert_eq!(
        said(&mut alice, s.system(), "/pronouns clear").await,
        "ok: cleared"
    );
    assert!(info(&mut bob, alice_uid)
        .await
        .starts_with(b"    name: alice\r   login: -\r"));
    assert!(!s.file("alice").contains("profile"));
}

#[tokio::test]
async fn a_value_is_refused_whole_and_only_a_change_made_waits_its_turn() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let mut alice = login(&s, "alice", None).await;
    let before = s.file("alice");
    let long = format!(
        "/pronouns {}",
        "a".repeat(hxd_core::pronouns::MAX_CHARS + 1)
    );
    for text in [
        "/pronouns she/her\r   login: admin",
        "/pronouns she\nher",
        "/pronouns she  her",
        &long,
    ] {
        let answer = said(&mut alice, s.system(), text).await;
        assert!(
            answer.starts_with("error: pronouns are 1 to 32 characters"),
            "{text:?}: {answer}"
        );
    }
    assert_eq!(s.file("alice"), before);

    // A line ending after the value is the message's, not the value's.
    // And none of the refusals spent the account's turn.
    assert_eq!(
        said(&mut alice, s.system(), "/pronouns they/them\r").await,
        "ok: your pronouns are they/them"
    );
    let answer = said(&mut alice, s.system(), "/pronouns she/they").await;
    assert!(
        answer.starts_with("error: slow down; try again in"),
        "{answer}"
    );
    s.core.clock().advance(hxd_core::pronouns::INTERVAL);
    assert_eq!(
        said(&mut alice, s.system(), "/pronouns she/they").await,
        "ok: your pronouns are she/they"
    );

    // A shared login keeps nobody's, and an account may be told it
    // keeps none.
    let mut guest = Client::login_at(s.legacy, &Login::guest("guest"))
        .await
        .unwrap();
    let mut bob = login(&s, "bob", None).await;
    for c in [&mut guest, &mut bob] {
        assert_eq!(
            said(c, s.system(), "/pronouns she/her").await,
            "error: your account may not set pronouns"
        );
    }
    assert!(!s.file("bob").contains("profile"));
}

#[tokio::test]
async fn a_set_costs_what_a_user_change_costs() {
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), "", "spam_points = 50").await;
    let mut alice = login(&s, "alice", None).await;
    // Three messages are six points; a set is a User Change's twenty
    // more, so a second one reaches fifty.
    for _ in 0..3 {
        said(&mut alice, s.system(), "/pronouns").await;
    }
    said(&mut alice, s.system(), "/pronouns she/her").await;
    alice
        .send(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, s.system().to_be_bytes().to_vec()),
                (tag::BODY, b"/pronouns they/them".to_vec()),
            ],
        )
        .await
        .unwrap();
    // Kicked for it: the connection closes.
    loop {
        match alice.recv().await {
            Err(hxd_testclient::Error::Closed | hxd_testclient::Error::Io(_)) => break,
            Ok(_) => {}
            Err(e) => panic!("{e}"),
        }
    }
}

#[tokio::test]
async fn account_editors_leave_the_users_pronouns_as_they_are() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let mut alice = login(&s, "alice", None).await;
    let mut admin = login(&s, "admin", None).await;
    let alice_uid = alice.uid.unwrap();
    said(&mut alice, s.system(), "/pronouns she/her").await;

    // The 1.5 user editor, saving what it opened.
    let bits = [bit::SEND_MSGS, bit::GET_USER_INFO, bit::READ_USERS]
        .into_iter()
        .fold(AccessBits::empty(), AccessBits::with);
    admin
        .call(
            ACCOUNT_MODIFY,
            &[
                (tag::LOGIN, xor(b"alice")),
                (tag::PASSWORD, vec![0]),
                (tag::NAME, b"Alice".to_vec()),
                (tag::ACCESS, bits.to_wire().to_vec()),
            ],
        )
        .await
        .unwrap();
    // The ng editor.
    let (mut editor, _) = ng::Client::account(s.ng, "admin", "pw", "editor")
        .await
        .unwrap();
    editor
        .request("account_update", json!({ "login": "alice", "name": "Al" }))
        .await
        .unwrap();
    let text = s.file("alice");
    assert!(text.contains("name = \"Al\""), "{text}");
    assert!(text.contains("[profile]\npronouns = \"she/her\""), "{text}");
    assert!(info(&mut admin, alice_uid)
        .await
        .windows(18)
        .any(|w| w == b"pronouns: she/her\r"));
}
