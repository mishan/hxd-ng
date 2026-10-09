//! HOPE, the secure login, on the classic wire (`docs/hope.md`): a server
//! built from a real config, and a client that speaks HOPE through
//! hx-libs' `hxhope`, as GtkHx does.

use std::net::SocketAddr;
use std::path::Path;

use hxd_testclient::legacy::{Client, Login};
use hxd_testclient::{ng, Error};
use hxhope::client::Offer;
use hxhope::{Cipher, Compression};

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

/// A server with `more` appended to its config, and accounts `alice`
/// (password `s3cret`) and `cafe` (password `café`).
async fn start(dir: &Path, more: &str) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, password) in [("alice", "s3cret"), ("cafe", "caf\u{e9}")] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"{password}\"\n[access]\nsend_chat = true\nread_chat = true\n"),
        )
        .unwrap();
    }
    let text =
        format!("[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n{more}\n");
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx));
    server
}

fn offer(ciphers: &[Cipher], compressions: &[Compression]) -> Offer {
    Offer {
        ciphers: ciphers.to_vec(),
        compressions: compressions.to_vec(),
        ..Offer::new(*b"TEST")
    }
}

async fn hope(
    addr: SocketAddr,
    offer: &Offer,
    login: &Login,
) -> Result<(Client, hxhope::Negotiated), Error> {
    let mut c = Client::connect(addr).await?;
    let (_, agreed) = c.login_hope(offer, login).await?;
    Ok((c, agreed))
}

fn refused(r: Result<(Client, hxhope::Negotiated), Error>) -> String {
    match r {
        Err(Error::Refused { text, .. }) => text,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("logged in"),
    }
}

#[tokio::test]
async fn a_hope_login_runs_through_what_it_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "").await;
    let mut clients = Vec::new();
    for compression in [None, Some(Compression::Gzip), Some(Compression::Lz4)] {
        let mut login = Login::account("a", "alice", "s3cret");
        login.caps = Some(1 << 1);
        let (mut c, agreed) = hope(
            s.legacy,
            &offer(
                &[Cipher::Blowfish],
                &compression.into_iter().collect::<Vec<_>>(),
            ),
            &login,
        )
        .await
        .unwrap();
        assert_eq!(
            (agreed.cipher, agreed.compression),
            (Some(Cipher::Blowfish), compression)
        );
        // Both ways through the transport: a request and its reply,
        // pushes, and a chat line heard back.
        let rows = c.user_list().await.unwrap();
        assert!(rows.iter().any(|r| r.nick == b"alice"), "{compression:?}");
        c.chat(b"through the cipher").await.unwrap();
        c.recv_where(|f| {
            f.bytes(hxproto::messages::tag::BODY)
                .is_some_and(|b| b.ends_with(b"through the cipher"))
        })
        .await
        .unwrap();
        clients.push(c);
    }
    // An ng client sees a classic user under a HOPE cipher as encrypted.
    let (_ngc, hello) = ng::Client::guest(s.ng, "ngc").await.unwrap();
    let alice = hello["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "alice")
        .unwrap()
        .clone();
    assert_eq!(alice["transport"], "encrypted");
}

#[tokio::test]
async fn hope_checks_the_password_as_the_client_typed_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "").await;
    let o = offer(&[Cipher::Blowfish], &[]);
    // The guest, by the empty login, and an account named in lower case.
    hope(s.legacy, &o, &Login::guest("guest")).await.unwrap();
    hope(s.legacy, &o, &Login::account("a", "alice", "s3cret"))
        .await
        .unwrap();
    // A UTF-8 password from a client that negotiated UTF-8.
    let mut cafe = Login::account("c", "cafe", "caf\u{e9}");
    cafe.caps = Some(1 << 1);
    hope(s.legacy, &o, &cafe).await.unwrap();
    // A wrong password, and a login no account has: the transport never
    // starts, and the refusal is not one the client can read through it.
    for login in [
        Login::account("a", "alice", "wrong"),
        Login::account("n", "nobody", "s3cret"),
    ] {
        assert!(hope(s.legacy, &o, &login).await.is_err());
    }
}

#[tokio::test]
async fn wrong_hope_passwords_count_as_any_others_do() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(
        dir.path(),
        "[limits]\nexempt = []\nlogin_failures = 2\nlogin_failure_seconds = 600\n",
    )
    .await;
    let o = offer(&[Cipher::Blowfish], &[]);
    for _ in 0..2 {
        assert!(hope(s.legacy, &o, &Login::account("a", "alice", "wrong"))
            .await
            .is_err());
    }
    // The address is out of guesses at alice, on the plain login as on HOPE.
    match Client::login_at(s.legacy, &Login::account("a", "alice", "s3cret")).await {
        Err(Error::Refused { text, .. }) => {
            assert!(text.starts_with("Too many failed logins."), "{text}")
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_client_with_no_cipher_in_common_is_refused_only_if_the_server_requires_one() {
    let dir = tempfile::tempdir().unwrap();
    let open = start(dir.path(), "").await;
    let none = offer(&[], &[]);
    let (_c, agreed) = hope(open.legacy, &none, &Login::account("a", "alice", "s3cret"))
        .await
        .unwrap();
    assert_eq!(agreed.cipher, None);

    let dir = tempfile::tempdir().unwrap();
    let strict = start(dir.path(), "[hope]\nrequire_cipher = true\n").await;
    assert_eq!(
        refused(
            hope(
                strict.legacy,
                &none,
                &Login::account("a", "alice", "s3cret")
            )
            .await
        ),
        "Secure login failed: nothing in common."
    );
    hope(
        strict.legacy,
        &offer(&[Cipher::Blowfish], &[]),
        &Login::account("a", "alice", "s3cret"),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hope_turned_off_is_refused_and_a_plain_login_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "[hope]\nenabled = false\n").await;
    assert_eq!(
        refused(
            hope(
                s.legacy,
                &offer(&[Cipher::Blowfish], &[]),
                &Login::account("a", "alice", "s3cret")
            )
            .await
        ),
        "Secure login (HOPE) is not offered here."
    );
    Client::login_at(s.legacy, &Login::account("a", "alice", "s3cret"))
        .await
        .unwrap();
}
