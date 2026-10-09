//! Account administration on both wires and from the command line,
//! against one accounts directory: the 1.5 user editor's New, Delete,
//! Open and Set User, the ng `accounts` family, and `hxd account`, with
//! a change reaching the account's sessions on both wires while they are
//! logged in — at once from a wire, on SIGHUP from the command line.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::access::bit;
use hxd_core::{AccessBits, Core};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::{Caps, ServerConfig, ServerCtx};
use hxd_testclient::legacy::{self, push, xor, Login};
use hxd_testclient::{ng, Error};
use hxproto::messages::{tag, ClientHdr};
use serde_json::json;
use tokio::net::TcpListener;

const ACCOUNT_CREATE: u32 = 0x015e;
const ACCOUNT_DELETE: u32 = 0x015f;
const ACCOUNT_READ: u32 = 0x0160;
const ACCOUNT_MODIFY: u32 = 0x0161;

const USERS: &str = "create_users = true\ndelete_users = true\nread_users = true\n\
    modify_users = true\n";

/// `admin` holds every bit here, and 41, which has no name; `deputy`
/// edits users but may not disconnect them; `lim` may disconnect but not
/// moderate; `editor` may only read and modify.
const ACCOUNTS: &[(&str, &str)] = &[
    (
        "admin",
        "read_chat = true\nsend_chat = true\nget_user_info = true\nuse_any_name = true\n\
         disconnect_users = true\ncreate_users = true\ndelete_users = true\n\
         read_users = true\nmodify_users = true\nraw_bits = [41]\n",
    ),
    ("deputy", USERS),
    // May disconnect, but the operator kept moderation from it, which the
    // kick bit would otherwise bring.
    (
        "lim",
        "read_users = true\ncreate_users = true\nmodify_users = true\ndelete_users = true\n\
         disconnect_users = true\n[extra]\nmoderate = false\n",
    ),
    ("editor", "read_users = true\nmodify_users = true\n"),
];

struct Running {
    legacy: SocketAddr,
    ng: SocketAddr,
    accounts: tempfile::TempDir,
}

impl Running {
    fn file(&self, login: &str) -> std::path::PathBuf {
        self.accounts.path().join(format!("{login}.toml"))
    }
}

async fn start() -> Running {
    let accounts = tempfile::tempdir().unwrap();
    std::fs::write(
        accounts.path().join("guest.toml"),
        "name = \"guest\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    for (login, access) in ACCOUNTS {
        write(
            accounts.path(),
            login,
            &format!("password = \"pw\"\n[access]\n{access}"),
        );
    }
    let files = Arc::new(hxd_auth_file::FileAuth::new(accounts.path()));
    let core = Arc::new(Core::new().with_admin(files.clone()));
    let auth: Arc<dyn hxd_core::AuthBackend> = files;
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "accounts".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: Caps::empty(),
            hope: None,
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            stamp_queued: true,
            news: Default::default(),
        }),
        files: None,
        banner: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "accounts".into(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: None,
        banner: None,
        metrics: None,
    };
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        accounts,
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    running
}

fn write(dir: &Path, login: &str, text: &str) {
    std::fs::write(dir.join(format!("{login}.toml")), text).unwrap();
}

async fn classic(server: &Running, login: &str, password: &str) -> legacy::Client {
    legacy::Client::login_at(server.legacy, &Login::account(login, login, password))
        .await
        .unwrap()
}

fn access(bits: &[u8]) -> AccessBits {
    bits.iter().fold(AccessBits::empty(), |a, b| a.with(*b))
}

/// Set User's or New User's fields. `password` is as typed; `None` sends
/// the single NUL that keeps the password the account has.
fn user(login: &str, password: Option<&str>, name: &str, bits: AccessBits) -> Vec<(u16, Vec<u8>)> {
    vec![
        (tag::LOGIN, xor(login.as_bytes())),
        (
            tag::PASSWORD,
            password.map_or(vec![0], |p| xor(p.as_bytes())),
        ),
        (tag::NAME, name.as_bytes().to_vec()),
        (tag::ACCESS, bits.to_wire().to_vec()),
    ]
}

fn refused(result: hxd_testclient::Result<legacy::Frame>) -> String {
    match result {
        Err(Error::Refused { text, .. }) => text,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn an_administrator_makes_reads_edits_and_deletes_an_account() {
    let server = start().await;
    let mut admin = classic(&server, "admin", "pw").await;
    let chatter = access(&[bit::READ_CHAT, bit::SEND_CHAT]);

    admin
        .call(ACCOUNT_CREATE, &user("Bob", Some("secret"), "Bob", chatter))
        .await
        .unwrap();
    assert_eq!(
        refused(
            admin
                .call(ACCOUNT_CREATE, &user("bob", Some("x"), "Bob", chatter))
                .await
        ),
        "That account already exists."
    );

    // Open User names its login in the clear, and its reply never
    // carries the password.
    let read = admin
        .call(ACCOUNT_READ, &[(tag::LOGIN, b"bob".to_vec())])
        .await
        .unwrap();
    assert_eq!(read.bytes(tag::NAME).unwrap(), b"Bob");
    assert_eq!(read.bytes(tag::LOGIN).unwrap(), xor(b"bob"));
    assert_eq!(read.bytes(tag::PASSWORD).unwrap(), [0]);
    // History was not named, so it follows read-chat.
    let read_access = access(&[bit::READ_CHAT, bit::SEND_CHAT, bit::CHAT_HISTORY]);
    assert_eq!(read.bytes(tag::ACCESS).unwrap(), read_access.to_wire());

    // Saving what was opened keeps the password; a new one replaces it.
    admin
        .call(ACCOUNT_MODIFY, &user("bob", None, "Robert", read_access))
        .await
        .unwrap();
    classic(&server, "bob", "secret").await;
    admin
        .call(
            ACCOUNT_MODIFY,
            &user("bob", Some("newer"), "Robert", read_access),
        )
        .await
        .unwrap();
    assert!(
        legacy::Client::login_at(server.legacy, &Login::account("b", "bob", "secret"))
            .await
            .is_err()
    );

    // Deleting the account disconnects whoever is logged in as it.
    let mut bob = classic(&server, "bob", "newer").await;
    admin
        .call(ACCOUNT_DELETE, &[(tag::LOGIN, xor(b"bob"))])
        .await
        .unwrap();
    let closed = loop {
        if let Err(e) = bob.recv().await {
            break e;
        }
    };
    assert!(matches!(closed, Error::Closed), "{closed:?}");
    assert!(!server.file("bob").exists());
    assert_eq!(
        refused(
            admin
                .call(ACCOUNT_DELETE, &[(tag::LOGIN, xor(b"bob"))])
                .await
        ),
        "There is no such account."
    );
}

#[tokio::test]
async fn an_edit_keeps_what_the_editor_does_not_show() {
    let server = start().await;
    write(
        server.accounts.path(),
        "carol",
        "# Carol runs the file area.\nname = \"Carol\"\npassword = \"pw\" # rotated in May\n\n\
         [access]\nread_chat = true\nsend_chat = false # muted\n\n\
         [extra]\ncan_detach = false\n",
    );
    let mut admin = classic(&server, "admin", "pw").await;
    let edited = access(&[bit::READ_CHAT, bit::SEND_CHAT, bit::CHAT_HISTORY]);
    admin
        .call(ACCOUNT_MODIFY, &user("carol", None, "Carol", edited))
        .await
        .unwrap();
    let text = std::fs::read_to_string(server.file("carol")).unwrap();
    for kept in [
        "# Carol runs the file area.",
        "password = \"pw\" # rotated in May",
        "send_chat = true # muted",
        "[extra]\ncan_detach = false",
    ] {
        assert!(text.contains(kept), "{kept:?} lost from:\n{text}");
    }
}

#[tokio::test]
async fn each_act_needs_its_bit_and_nobody_grants_what_they_do_not_hold() {
    let server = start().await;
    write(
        server.accounts.path(),
        "plain",
        "password = \"pw\"\n[access]\nread_chat = true\n",
    );
    let mut guest = legacy::Client::login_at(server.legacy, &Login::guest("g"))
        .await
        .unwrap();
    let plain = access(&[bit::READ_CHAT]);
    let not_allowed = "You are not allowed to do that.";
    for (ty, fields) in [
        (ACCOUNT_CREATE, user("new", Some("pw"), "New", plain)),
        (ACCOUNT_MODIFY, user("plain", None, "Plain", plain)),
        (ACCOUNT_READ, vec![(tag::LOGIN, b"plain".to_vec())]),
        (ACCOUNT_DELETE, vec![(tag::LOGIN, xor(b"plain"))]),
    ] {
        assert_eq!(
            refused(guest.call(ty, &fields).await),
            not_allowed,
            "{ty:#x}"
        );
    }

    // Set User makes a new account, as GtkHx asks it to, only for a
    // session that may make one.
    let mut editor = classic(&server, "editor", "pw").await;
    assert_eq!(
        refused(
            editor
                .call(ACCOUNT_MODIFY, &user("new", Some("pw"), "New", plain))
                .await
        ),
        not_allowed
    );
    let mut deputy = classic(&server, "deputy", "pw").await;
    deputy
        .call(
            ACCOUNT_MODIFY,
            &user("new", Some("pw"), "New", AccessBits::empty()),
        )
        .await
        .unwrap();
    assert!(server.file("new").exists());

    // The deputy cannot disconnect anyone, so may not make an account
    // that can, nor change or delete one, nor give away a bit it lacks.
    let outranked = "That account may do, or would be allowed to do, something you may not.";
    let kicker = access(&[bit::DISCONNECT_USERS]);
    for (ty, fields) in [
        (ACCOUNT_CREATE, user("kicker", Some("pw"), "K", kicker)),
        (ACCOUNT_MODIFY, user("new", None, "New", kicker)),
        (
            ACCOUNT_MODIFY,
            user("admin", None, "Admin", AccessBits::empty()),
        ),
        (ACCOUNT_DELETE, vec![(tag::LOGIN, xor(b"admin"))]),
    ] {
        assert_eq!(
            refused(deputy.call(ty, &fields).await),
            outranked,
            "{ty:#x}"
        );
    }
    assert!(!server.file("kicker").exists());
    assert!(server.file("admin").exists());

    // Nor is what an account file grants beside the bitmap given away, or
    // taken over: an account that may kick moderates unless it says not,
    // and `lim`'s says not.
    write(
        server.accounts.path(),
        "warden",
        "password = \"pw\"\n[extra]\nmoderate = true\n",
    );
    let mut lim = classic(&server, "lim", "pw").await;
    for (ty, fields) in [
        (ACCOUNT_CREATE, user("alt", Some("pw"), "Alt", kicker)),
        (
            ACCOUNT_MODIFY,
            user("warden", Some("mine"), "W", AccessBits::empty()),
        ),
        (ACCOUNT_DELETE, vec![(tag::LOGIN, xor(b"warden"))]),
    ] {
        assert_eq!(refused(lim.call(ty, &fields).await), outranked, "{ty:#x}");
    }
    assert!(!server.file("alt").exists());

    // An account deleting itself is not disconnected for it, and edits
    // nothing more: its file is what it is measured against.
    deputy
        .call(ACCOUNT_DELETE, &[(tag::LOGIN, xor(b"deputy"))])
        .await
        .unwrap();
    deputy.ping().await.unwrap();
    assert_eq!(
        refused(
            deputy
                .call(ACCOUNT_CREATE, &user("late", Some("pw"), "L", plain))
                .await
        ),
        not_allowed
    );

    // Having no password is not a privilege to keep from others: an
    // administrator without one may still give an account one.
    write(
        server.accounts.path(),
        "root",
        &format!("[access]\nread_chat = true\n{USERS}"),
    );
    let mut root = classic(&server, "root", "").await;
    root.call(ACCOUNT_CREATE, &user("pal", Some("pw"), "Pal", plain))
        .await
        .unwrap();
    classic(&server, "pal", "pw").await;
}

#[tokio::test]
async fn the_classic_editor_changes_only_what_it_can_say() {
    let server = start().await;
    write(
        server.accounts.path(),
        "dora",
        "password = \"pw\"\n[access]\nread_chat = true\nread_chat_history = false\n",
    );
    write(
        server.accounts.path(),
        "erin",
        "password = \"pw\"\n[access]\nread_chat = true\n",
    );
    let mut admin = classic(&server, "admin", "pw").await;
    let read = |login: &'static str| (tag::LOGIN, login.as_bytes().to_vec());

    // A period editor saves what it opened, less the password field it
    // leaves out once its box is emptied: the password goes, and history,
    // which it cannot show, stays as the account had it.
    let opened = admin.call(ACCOUNT_READ, &[read("dora")]).await.unwrap();
    let mut fields = user("dora", None, "Dora", AccessBits::empty());
    fields.retain(|(t, _)| *t != tag::PASSWORD);
    fields.retain(|(t, _)| *t != tag::ACCESS);
    fields.push((tag::ACCESS, opened.bytes(tag::ACCESS).unwrap()));
    admin.call(ACCOUNT_MODIFY, &fields).await.unwrap();
    classic(&server, "dora", "").await;
    let text = std::fs::read_to_string(server.file("dora")).unwrap();
    assert!(text.contains("read_chat_history = false"), "{text}");

    // History granted by number is the file's too.
    write(
        server.accounts.path(),
        "fay",
        "password = \"pw\"\n[access]\nraw_bits = [56]\n",
    );
    let opened = admin.call(ACCOUNT_READ, &[read("fay")]).await.unwrap();
    let mut fields = user("fay", None, "Fay", AccessBits::empty());
    fields.retain(|(t, _)| *t != tag::ACCESS);
    fields.push((tag::ACCESS, opened.bytes(tag::ACCESS).unwrap()));
    admin.call(ACCOUNT_MODIFY, &fields).await.unwrap();
    let opened = admin.call(ACCOUNT_READ, &[read("fay")]).await.unwrap();
    assert_eq!(
        opened.bytes(tag::ACCESS).unwrap(),
        access(&[bit::CHAT_HISTORY]).to_wire()
    );

    // Taking read-chat away takes the history that followed it.
    admin
        .call(
            ACCOUNT_MODIFY,
            &user("erin", None, "Erin", AccessBits::empty()),
        )
        .await
        .unwrap();
    let opened = admin.call(ACCOUNT_READ, &[read("erin")]).await.unwrap();
    assert_eq!(
        opened.bytes(tag::ACCESS).unwrap(),
        AccessBits::empty().to_wire()
    );
}

#[tokio::test]
async fn a_change_reaches_the_account_on_both_wires_at_once() {
    let server = start().await;
    write(
        server.accounts.path(),
        "dana",
        "name = \"Dana\"\npassword = \"pw\"\n[access]\nread_chat = true\nsend_chat = true\n\
         get_user_info = true\nread_users = true\n",
    );
    let mut admin = classic(&server, "admin", "pw").await;
    let mut classic_dana = classic(&server, "dana", "pw").await;
    let (mut modern_dana, _) = ng::Client::account(server.ng, "dana", "pw", "dana-ng")
        .await
        .unwrap();
    let dana_uid = classic_dana.uid.unwrap();

    // Read-chat only, and no longer choosing a name: both of Dana's
    // sessions are renamed to the account's.
    let now = access(&[bit::READ_CHAT, bit::CHAT_HISTORY]);
    admin
        .call(ACCOUNT_MODIFY, &user("dana", None, "Dana", now))
        .await
        .unwrap();

    let told = classic_dana
        .recv_where(|f| {
            f.ty == push::SELFINFO && f.bytes(tag::ACCESS) == Some(now.to_wire().to_vec())
        })
        .await;
    assert!(told.is_ok(), "{told:?}");
    let renamed = admin
        .recv_where(|f| {
            f.ty == push::USER_CHANGE
                && f.uint(tag::UID) == Some(u32::from(dana_uid))
                && f.bytes(tag::NAME).as_deref() == Some(b"Dana")
        })
        .await;
    assert!(renamed.is_ok(), "{renamed:?}");
    // Each wire refuses what the account no longer allows, whether the
    // check is the frontend's own or the domain's.
    let admin_uid = admin.uid.unwrap();
    assert!(refused(
        classic_dana
            .call(
                ClientHdr::UserGetInfo.as_u32(),
                &[(tag::UID, admin_uid.to_be_bytes().to_vec())],
            )
            .await
    )
    .contains("not allowed"));
    assert_eq!(
        refused(
            classic_dana
                .call(ACCOUNT_READ, &[(tag::LOGIN, b"admin".to_vec())])
                .await
        ),
        "You are not allowed to do that."
    );
    // Given the kick bit, Dana wears the administrator's color for all.
    admin
        .call(
            ACCOUNT_MODIFY,
            &user("dana", None, "Dana", now.with(bit::DISCONNECT_USERS)),
        )
        .await
        .unwrap();
    let colored = admin
        .recv_where(|f| {
            f.ty == push::USER_CHANGE
                && f.uint(tag::UID) == Some(u32::from(dana_uid))
                && f.uint(tag::COLOUR).is_some_and(|c| c & 2 != 0)
        })
        .await;
    assert!(colored.is_ok(), "{colored:?}");
    match modern_dana.chat("still here?").await {
        Err(Error::Refused { code, .. }) => assert_eq!(code, "access_denied"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refused_ng(result: hxd_testclient::Result<serde_json::Value>) -> String {
    match result {
        Err(Error::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn an_ng_administrator_keeps_accounts_and_its_target_hears() {
    let server = start().await;
    let (mut admin, hello) = ng::Client::account(server.ng, "admin", "pw", "root")
        .await
        .unwrap();
    assert!(hello["caps"]
        .as_array()
        .unwrap()
        .contains(&json!("accounts")));
    assert!(hello["accounts"]["access"]
        .as_array()
        .unwrap()
        .contains(&json!("modify_users")));

    let made = admin
        .request(
            "account_create",
            json!({ "login": "Eve", "name": "Eve", "password": "pw",
                    "access": ["read_chat", "send_chat"], "raw_bits": [41] }),
        )
        .await
        .unwrap();
    // Exactly what was asked: history named off, since read-chat alone
    // would otherwise carry it.
    assert_eq!(
        made["account"],
        json!({ "login": "eve", "name": "Eve", "password": true,
                "access": ["read_chat", "send_chat"], "raw_bits": [41] })
    );
    assert_eq!(
        refused_ng(
            admin
                .request("account_create", json!({ "login": "eve" }))
                .await
        ),
        "already_exists"
    );
    let listed = admin.request("account_list", json!({})).await.unwrap();
    assert!(listed["accounts"]
        .as_array()
        .unwrap()
        .contains(&json!({ "login": "eve", "name": "Eve" })));

    // Eve, logged in, hears what she may now do.
    let (mut eve, eve_hello) = ng::Client::account(server.ng, "eve", "pw", "eve")
        .await
        .unwrap();
    admin
        .request(
            "account_update",
            json!({ "login": "eve", "access": ["read_chat"], "raw_bits": [41] }),
        )
        .await
        .unwrap();
    let told = eve.event("account_changed").await.unwrap();
    assert_eq!(
        told.data,
        json!({ "access": ["read_chat"], "raw_bits": [41] })
    );
    assert_eq!(refused_ng(eve.chat("hi").await), "access_denied");

    // A change made while Eve is away, past what a resume can replay, is
    // in the `sync` that recovers from it.
    drop(eve);
    let chatter = json!({ "access": ["read_chat", "send_chat"], "raw_bits": [41] });
    let mut update = chatter.clone();
    update["login"] = json!("eve");
    admin.request("account_update", update).await.unwrap();
    let mut eve = ng::Client::connect(server.ng).await.unwrap();
    let resume = json!({
        "session": eve_hello["session"],
        "token": eve_hello["token"],
        "last_seq": 0,
    });
    assert_eq!(
        refused_ng(eve.request("resume", resume).await),
        "resync_required"
    );
    let synced = eve.request("sync", json!({})).await.unwrap();
    assert_eq!(synced["accounts"], chatter);

    // A password cleared, and a field this server does not know ignored.
    let cleared = admin
        .request(
            "account_update",
            json!({ "login": "eve", "password": "", "identity": "not ours to set" }),
        )
        .await
        .unwrap();
    assert_eq!(cleared["account"]["password"], json!(false));

    // Update never makes an account, and every refusal has its code.
    for (req, params, code) in [
        (
            "account_update",
            json!({ "login": "nobody", "name": "N" }),
            "no_such_account",
        ),
        (
            "account_update",
            json!({ "login": "eve", "access": ["flying"] }),
            "bad_request",
        ),
        (
            "account_update",
            json!({ "login": "eve", "raw_bits": [41] }),
            "bad_request",
        ),
        (
            "account_update",
            json!({ "login": "eve", "password": "x".repeat(32) }),
            "bad_request",
        ),
        (
            "account_create",
            json!({ "login": "../etc" }),
            "invalid_login",
        ),
        (
            "account_get",
            json!({ "login": "nobody" }),
            "no_such_account",
        ),
    ] {
        assert_eq!(
            refused_ng(admin.request(req, params.clone()).await),
            code,
            "{req} {params}"
        );
    }
    assert!(!server.file("nobody").exists());

    // A session that may only modify is held to what it holds.
    let (mut editor, _) = ng::Client::account(server.ng, "editor", "pw", "ed")
        .await
        .unwrap();
    assert_eq!(
        refused_ng(
            editor
                .request("account_update", json!({ "login": "eve", "access": [] }))
                .await
        ),
        "outranked"
    );
    assert_eq!(
        refused_ng(
            editor
                .request("account_delete", json!({ "login": "eve" }))
                .await
        ),
        "access_denied"
    );

    admin
        .request("account_delete", json!({ "login": "eve" }))
        .await
        .unwrap();
    assert!(eve.event("kicked").await.is_ok());
    assert!(!server.file("eve").exists());
}

#[tokio::test]
async fn the_command_line_keeps_accounts_and_a_reload_reaches_their_sessions() {
    let td = tempfile::tempdir().unwrap();
    let d = td.path().display();
    let path = td.path().join("hxd-ng.toml");
    std::fs::write(&path, format!("[paths]\naccounts = \"{d}/accounts\"\n")).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let core = ctx.core.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hxd_session::serve(listener, ctx));

    let secret = td.path().join("secret");
    std::fs::write(&secret, "first\n").unwrap();
    let password = hxd::accounts::Password::File(secret.clone());
    let added = hxd::accounts::add(
        &config,
        "frank",
        Some("Frank".into()),
        Some("guest"),
        None,
        &password,
    )
    .unwrap();
    assert!(added.contains("password: set"), "{added}");
    assert!(hxd::accounts::list(&config).unwrap().contains("frank"));
    assert!(hxd::accounts::add(&config, "frank", None, None, None, &password).is_err());

    std::fs::write(&secret, "second").unwrap();
    hxd::accounts::passwd(&config, "frank", &password).unwrap();
    let mut frank = legacy::Client::login_at(addr, &Login::account("f", "frank", "second"))
        .await
        .unwrap();

    // An edit made beside the running server reaches Frank on SIGHUP.
    let shown = hxd::accounts::set_access(
        &config,
        "frank",
        &["send_chat=off".into(), "read_chat_history=off".into()],
    )
    .unwrap();
    assert!(!shown.contains("send_chat"), "{shown}");
    assert!(!shown.contains("read_chat_history"), "{shown}");
    assert!(hxd::accounts::set_access(&config, "frank", &["flying=on".into()]).is_err());
    assert_eq!(core.reload_accounts(), (1, 0));
    let told = frank
        .recv_where(|f| {
            f.ty == push::SELFINFO
                && f.bytes(tag::ACCESS).is_some_and(|a| {
                    !AccessBits::from_wire(a.try_into().unwrap()).has(bit::SEND_CHAT)
                })
        })
        .await;
    assert!(told.is_ok(), "{told:?}");
    // History that follows read-chat goes with it.
    std::fs::write(
        td.path().join("accounts/gus.toml"),
        "password = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let shown = hxd::accounts::set_access(&config, "gus", &["read_chat=off".into()]).unwrap();
    assert!(!shown.contains("read_chat"), "{shown}");
    // History set apart from read-chat stays apart unless named.
    std::fs::write(
        td.path().join("accounts/hal.toml"),
        "password = \"pw\"\n[access]\nread_chat = false\nread_chat_history = false\n",
    )
    .unwrap();
    let shown = hxd::accounts::set_access(&config, "hal", &["read_chat=on".into()]).unwrap();
    assert!(
        shown.contains("read_chat") && !shown.contains("read_chat_history"),
        "{shown}"
    );

    // An account with an identity is purged by its fingerprint, which
    // nothing can say once its file is gone.
    let fp = "6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0";
    std::fs::write(
        td.path().join("accounts/ida.toml"),
        format!("password = \"pw\"\n[identity]\nfingerprint = \"{fp}\"\n"),
    )
    .unwrap();
    let said = hxd::accounts::remove(&config, "ida").unwrap();
    assert!(
        said.contains(&format!("hxd inbox purge ida --fingerprint {fp}")),
        "{said}"
    );

    hxd::accounts::remove(&config, "frank").unwrap();
    assert_eq!(core.reload_accounts(), (0, 1));
    let closed = loop {
        if let Err(e) = frank.recv().await {
            break e;
        }
    };
    assert!(matches!(closed, Error::Closed), "{closed:?}");
}
