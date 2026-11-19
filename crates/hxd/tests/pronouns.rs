//! Pronouns on both wires, on a server built from a real config: set
//! with the system account's `/pronouns` or the ng `pronouns` request,
//! kept in the account file's `[profile]`, shown to a classic client as a
//! `pronouns:` line in Get User Info's text wherever its encoding keeps
//! them, with nothing else sent for a change, and to an ng client on the
//! `user` object, a change told as `user_changed`.

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
             [roles]\nfile = \"{d}/roles.toml\"\n[system]\n[limits]\n{limits}\n"
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
            assert_eq!(
                said(&mut shown, s.system(), "/pronouns").await,
                "ok: this server shows no pronouns; /pronouns clear removes any your account keeps"
            );
            let help = said(&mut shown, s.system(), "/help").await;
            assert!(help.contains("/pronouns clear - remove"), "{help}");
            // What is kept may still be taken down.
            assert_eq!(
                said(&mut shown, s.system(), "/pronouns clear").await,
                "ok: cleared"
            );
            assert!(!s.file("admin").contains("profile"));
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

    // Space before the value and a line ending after it are the
    // message's, not the value's, as for every command.
    // And none of the refusals spent the account's turn.
    assert_eq!(
        said(&mut alice, s.system(), "/pronouns \tthey/them\r").await,
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
    // The guest's is shared even behind a password.
    let path = s.accounts.join("guest.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("password = \"pw\"\n{text}")).unwrap();
    let mut shared = login(&s, "guest", None).await;
    for c in [&mut guest, &mut bob, &mut shared] {
        assert_eq!(
            said(c, s.system(), "/pronouns she/her").await,
            "error: your account may not set pronouns"
        );
    }
    assert!(!s.file("bob").contains("profile"));

    // What the server would not have written, and so does not show, is
    // still the user's to take down.
    let mut carol = login(&s, "carol", None).await;
    assert_eq!(
        said(&mut carol, s.system(), "/pronouns clear").await,
        "ok: cleared"
    );
    assert!(!s.file("carol").contains("profile"));
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

    // The ng request is a User Change too: the third reaches sixty.
    let (mut dave, _) = ng_login(&s, "dave").await;
    let mut codes = Vec::new();
    for p in ["she/her", "they/them", "xe/xem"] {
        let frame = dave
            .request_frame("pronouns", json!({ "pronouns": p }))
            .await
            .unwrap();
        codes.push(frame["error"]["code"].as_str().unwrap_or("ok").to_owned());
    }
    assert_eq!(codes, ["ok", "rate_limited", "flooding"]);
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

/// An ng session of `login`, and its login reply.
async fn ng_login(server: &Server, login: &str) -> (ng::Client, serde_json::Value) {
    ng::Client::account(server.ng, login, "pw", login)
        .await
        .unwrap()
}

#[tokio::test]
async fn pronouns_set_on_either_wire_show_on_the_other() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let mut bob = login(&s, "bob", None).await;
    let mut dave = login(&s, "dave", None).await;
    let _admin = login(&s, "admin", None).await;
    let _carol = login(&s, "carol", None).await;
    let (mut alice, _) = ng_login(&s, "alice").await;
    let (mut watcher, hello) = ng_login(&s, "bob").await;
    let alice_uid = alice.uid.unwrap();
    let dave_uid = u64::from(dave.uid.unwrap());

    // What an account's file holds is on its row from the start, and a
    // row with none says nothing.
    let users = hello["users"].as_array().unwrap();
    let row = |nick: &str| users.iter().find(|u| u["nick"] == nick).unwrap().clone();
    assert_eq!(row("admin")["pronouns"], "they/them");
    assert!(row("dave").get("pronouns").is_none());
    // Nor a value the server would not have written.
    assert!(row("carol").get("pronouns").is_none());
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "pronouns"));

    // Set on ng: a change to the row, to the ng wire alone, and no
    // account change for the setter.
    unread(&mut bob).await;
    alice
        .request("pronouns", json!({ "pronouns": "she/her" }))
        .await
        .unwrap();
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == alice_uid)
        .await
        .unwrap();
    assert_eq!(changed.data["user"]["pronouns"], "she/her");
    alice
        .event_where("user_changed", |d| d["user"]["uid"] == alice_uid)
        .await
        .unwrap();
    assert!(!alice
        .rx
        .take_backlog()
        .iter()
        .any(|e| e.ev == "account_changed"));
    assert!(unread(&mut bob).await.is_empty());
    let text = info(&mut bob, alice_uid as u16).await;
    assert!(
        text.starts_with(b"    name: alice\rpronouns: she/her\r"),
        "{text:?}"
    );

    // Set on classic: the same `user_changed`, then cleared from ng.
    said(&mut dave, s.system(), "/pronouns he/him").await;
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == dave_uid)
        .await
        .unwrap();
    assert_eq!(changed.data["user"]["pronouns"], "he/him");
    // One `user_changed` a change: alice's was told once before dave's.
    let told = |c: &mut ng::Client, uid: u64| {
        c.rx.take_backlog()
            .iter()
            .filter(|e| e.ev == "user_changed" && e.data["user"]["uid"] == uid)
            .count()
    };
    assert_eq!(told(&mut watcher, alice_uid), 0);
    s.core.clock().advance(hxd_core::pronouns::INTERVAL);
    alice
        .request("pronouns", json!({ "pronouns": null }))
        .await
        .unwrap();
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == alice_uid)
        .await
        .unwrap();
    assert!(changed.data["user"].get("pronouns").is_none());

    // An operator's edit, applied by a reload, is told the same way.
    unread(&mut dave).await;
    let path = s.accounts.join("dave.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("he/him", "xe/xem")).unwrap();
    s.core.reload_accounts();
    let changed = watcher
        .event_where("user_changed", |d| {
            d["user"]["uid"] == dave_uid && d["user"]["pronouns"] == "xe/xem"
        })
        .await
        .unwrap();
    assert_eq!(changed.data["user"]["nick"], "dave");
    // A row's change alone: dave's own session is told no account
    // change.
    assert!(!unread(&mut dave).await.contains(&push::SELFINFO));
    let synced = watcher.sync().await.unwrap();
    assert_eq!(told(&mut watcher, dave_uid), 0);
    let users = synced["users"].as_array().unwrap();
    let carol = users.iter().find(|u| u["nick"] == "carol").unwrap();
    assert!(carol.get("pronouns").is_none(), "{carol}");
    // Every event an ng session was sent took the next seq.
    for c in [&alice, &watcher] {
        assert!(c.rx.seq_faults.is_empty(), "{:?}", c.rx.seq_faults);
    }
}

#[tokio::test]
async fn the_pronouns_request_is_refused_as_the_command_is() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let (mut alice, _) = ng_login(&s, "alice").await;
    let (mut bob, _) = ng_login(&s, "bob").await;
    let (mut guest, _) = ng::Client::guest(s.ng, "guest").await.unwrap();
    let refused = |r: hxd_testclient::Result<serde_json::Value>| match r {
        Err(hxd_testclient::Error::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    };
    for c in [&mut guest, &mut bob] {
        let r = c
            .request("pronouns", json!({ "pronouns": "she/her" }))
            .await;
        assert_eq!(refused(r), "access_denied");
    }
    for params in [
        json!({ "pronouns": "she  her" }),
        json!({ "pronouns": "she/her\r   login: admin" }),
        json!({ "pronouns": "a".repeat(hxd_core::pronouns::MAX_CHARS + 1) }),
        json!({ "pronouns": 3 }),
        json!({}),
    ] {
        let r = alice.request("pronouns", params.clone()).await;
        assert_eq!(refused(r), "bad_request", "{params}");
    }
    alice
        .request("pronouns", json!({ "pronouns": "she/her" }))
        .await
        .unwrap();
    let frame = alice
        .request_frame("pronouns", json!({ "pronouns": "she/they" }))
        .await
        .unwrap();
    assert_eq!(frame["error"]["code"], "rate_limited", "{frame}");
    assert!(
        frame["error"]["retry_after"].as_u64().unwrap() <= 10,
        "{frame}"
    );

    // A server that shows none offers none to set.
    let td = tempfile::tempdir().unwrap();
    let s = start(td.path(), "pronouns = false", "spam_points = 0").await;
    let (mut alice, hello) = ng_login(&s, "alice").await;
    assert!(!hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "pronouns"));
    let r = alice
        .request("pronouns", json!({ "pronouns": "she/her" }))
        .await;
    assert_eq!(refused(r), "not_available");
}

#[tokio::test]
async fn a_reload_that_recolors_a_role_with_the_pronouns_still_tells_self_info() {
    let td = tempfile::tempdir().unwrap();
    let s = started(td.path()).await;
    let roles = td.path().join("roles.toml");
    std::fs::write(&roles, "[role.crew]\ncolor = 0x112233\n").unwrap();
    let path = s.accounts.join("dave.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("roles = [\"crew\"]\n{text}")).unwrap();
    s.core.reload_accounts();
    let mut dave = login(&s, "dave", None).await;
    unread(&mut dave).await;

    // The role's color is a classic client's to redraw, whatever else
    // the reload changed.
    std::fs::write(&roles, "[role.crew]\ncolor = 0x445566\n").unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}[profile]\npronouns = \"xe/xem\"\n")).unwrap();
    s.core.reload_accounts();
    assert!(unread(&mut dave).await.contains(&push::SELFINFO));
}
