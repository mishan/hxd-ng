//! HOPE, the secure login, on the classic wire (`docs/hope.md`): a server
//! built from a real config, and a client that speaks HOPE through
//! hx-libs' `hxhope`, as GtkHx does.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hxd_testclient::legacy::{Client, Login};
use hxd_testclient::{ng, Error};
use hxhope::client::Offer;
use hxhope::{Cipher, Compression};

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
    transfer: SocketAddr,
}

/// A password Mac Roman cannot write: "parol'1" in Cyrillic.
const CYRILLIC: &str = "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}1";
/// The banner every server here holds, for a transfer to fetch.
const BANNER: &[u8] = b"GIF89a sealed or not";
/// A file in every server's area, larger than a sealed record so its body
/// spans several.
const NOTES: &[u8] = &[b'n'; 150_000];

/// A server with `more` appended to its config, and accounts `alice`
/// (password `s3cret`) and `cafe` (password `café`).
async fn start(dir: &Path, more: &str) -> Server {
    let d = dir.display();
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, password) in [
        ("alice", "s3cret"),
        ("cafe", "caf\u{e9}"),
        ("ivan", CYRILLIC),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "name = \"{login}\"\npassword = \"{password}\"\n[access]\nsend_chat = true\n\
                 read_chat = true\ndownload_files = true\nupload_files = true\n\
                 upload_anywhere = true\n"
            ),
        )
        .unwrap();
    }
    // An agreement, since a 1.5 client is offered the banner once it
    // agrees to one.
    std::fs::write(dir.join("agreement.txt"), "Be kind.").unwrap();
    std::fs::write(dir.join("banner.gif"), BANNER).unwrap();
    std::fs::create_dir(dir.join("files")).unwrap();
    std::fs::write(dir.join("files").join("notes.txt"), NOTES).unwrap();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\nagreement = \"{d}/agreement.txt\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [files]\nroot = \"{d}/files\"\nbind = \"127.0.0.1:0\"\n\
         [banner]\nfile = \"{d}/banner.gif\"\n{more}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    // As the binary builds them.
    let files = hxd::files::build(&config).unwrap();
    let htxf = hxd::files::htxf(&config, files.as_ref()).unwrap().unwrap();
    let banner = hxd::banner::build(&config, Some(&htxf.registry)).unwrap();
    let ctx = hxd::build_ctx(&config, None, files.as_ref(), None, banner).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, files.as_ref(), None)
        .unwrap()
        .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transfer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
        transfer: transfer.local_addr().unwrap(),
    };
    tokio::spawn(hxd_files::serve_htxf(
        transfer,
        htxf.registry,
        ctx.core.clone(),
        htxf.timeouts,
    ));
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
        // Compression is not offered, whatever the client asks for.
        assert_eq!(
            (agreed.cipher, agreed.compression),
            (Some(Cipher::Blowfish), None)
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

    // The guest's empty password makes keys anyone who watched the
    // handshake has: a cipher on them is not encryption.
    let (_guest, _) = hope(
        s.legacy,
        &offer(&[Cipher::Blowfish], &[]),
        &Login::guest("visitor"),
    )
    .await
    .unwrap();
    let (_ngc, hello) = ng::Client::guest(s.ng, "ngc2").await.unwrap();
    let guest = hello["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["nick"] == "visitor")
        .unwrap()
        .clone();
    assert_eq!(guest["transport"], "cleartext");
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
    // One Mac Roman cannot write logs in under UTF-8 alone: written in
    // Mac Roman it would be question marks, which anyone could type.
    let mut ivan = Login::account("i", "ivan", CYRILLIC);
    ivan.caps = Some(1 << 1);
    hope(s.legacy, &o, &ivan).await.unwrap();
    assert!(hope(s.legacy, &o, &Login::account("i", "ivan", "??????1"))
        .await
        .is_err());
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
    // The guest is no guess, by HOPE as by the plain login.
    hope(s.legacy, &o, &Login::guest("g")).await.unwrap();
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

#[tokio::test]
async fn a_guest_account_with_a_password_is_throttled_by_hope_as_any_other() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(
        dir.path(),
        "[limits]\nexempt = []\nlogin_failures = 2\nlogin_failure_seconds = 600\n",
    )
    .await;
    std::fs::write(
        dir.path().join("accounts/guest.toml"),
        "name = \"guest\"\npassword = \"gpw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    let o = offer(&[Cipher::Blowfish], &[]);
    let guest = |password: &str| Login {
        password: password.into(),
        ..Login::guest("g")
    };
    hope(s.legacy, &o, &guest("gpw")).await.unwrap();
    for _ in 0..2 {
        assert!(hope(s.legacy, &o, &guest("wrong")).await.is_err());
    }
    // Locked out: the right password is refused too.
    assert!(hope(s.legacy, &o, &guest("gpw")).await.is_err());
}

#[tokio::test]
async fn a_frame_sent_in_the_clear_after_step_2_is_refused_not_run() {
    use hxd_testclient::legacy::{pack, read_frame};
    use hxproto::messages::{tag, ClientHdr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "").await;
    let mut stream = tokio::net::TcpStream::connect(s.legacy).await.unwrap();
    stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.unwrap();
    stream.read_exact(&mut [0; 8]).await.unwrap();
    let o = offer(&[Cipher::Blowfish], &[]);
    stream
        .write_all(&hxhope::client::step1(&o, 1).unwrap())
        .await
        .unwrap();
    let answer = read_frame(&mut stream).await.unwrap();
    let answer = pack(
        answer.ty,
        answer.trans,
        answer.flag,
        &answer
            .chunks()
            .map(|c| (c.tag, c.data.to_vec()))
            .collect::<Vec<_>>(),
    );
    let who = hxhope::client::Login {
        login: b"alice",
        password: b"s3cret",
        name: b"a",
        icon: 1,
        version: 150,
        caps: 0,
    };
    let est = hxhope::client::step2(&o, &answer, &who, 2, Box::new(|_: &mut [u8]| {})).unwrap();
    // Step 2 and, behind it without waiting, a request in the clear: what
    // someone on the path could add to a real client's login.
    let mut both = est.step2;
    both.extend(pack(ClientHdr::UserGetList.as_u32(), 3, 0, &[]));
    stream.write_all(&both).await.unwrap();
    let refusal = read_frame(&mut stream).await.unwrap();
    assert_eq!(refusal.trans, 2);
    assert_eq!(
        refusal.bytes(tag::TASK_ERROR).as_deref(),
        Some(&b"Login failed."[..])
    );
}

/// The banner over HTXF: the reference asked for on the control
/// connection, the handshake in the clear, and what comes back.
async fn banner(c: &mut Client, transfer: SocketAddr) -> (u32, Vec<u8>) {
    use hxproto::messages::{tag, ClientHdr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let reply = c
        .call(ClientHdr::DownloadBanner.as_u32(), &[])
        .await
        .unwrap();
    let reference = reply.uint(tag::HTXF_REF).unwrap();
    let size = reply.uint(tag::HTXF_SIZE).unwrap();
    let preamble = hxfiles_xfer::htxf::Preamble {
        reference,
        transfer_len: u64::from(size),
        type_code: 2,
        flags: 0,
        resume_digest: None,
    };
    let mut stream = tokio::net::TcpStream::connect(transfer).await.unwrap();
    stream.write_all(&preamble.encode().unwrap()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    (reference, bytes)
}

#[tokio::test]
async fn chacha20_poly1305_seals_the_session_and_its_transfers() {
    use hxcrypto::aead::{AeadState, AEAD_LENGTH_PREFIX, AEAD_TAG_SIZE};
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "").await;
    let (mut c, agreed) = hope(
        s.legacy,
        &offer(&[Cipher::ChaCha20Poly1305, Cipher::Blowfish], &[]),
        &Login::account("a", "alice", "s3cret"),
    )
    .await
    .unwrap();
    assert_eq!(agreed.cipher, Some(Cipher::ChaCha20Poly1305));
    assert!(!c.user_list().await.unwrap().is_empty());

    // The banner arrives in records only this transfer's keys open.
    let (reference, wire) = banner(&mut c, s.transfer).await;
    let (_, mut to_client) = agreed.transfer_keys.unwrap().transfer(reference);
    let mut got = Vec::new();
    let mut rest = &wire[..];
    while !rest.is_empty() {
        let size = AeadState::peek_frame_size(rest).unwrap();
        let mut plain = vec![0; size - AEAD_LENGTH_PREFIX - AEAD_TAG_SIZE];
        to_client.open(&rest[..size], &mut plain).unwrap();
        got.extend(plain);
        rest = &rest[size..];
    }
    assert_eq!(got, BANNER);

    // A Blowfish session's transfers stay in the clear, as on mhxd.
    let (mut b, _) = hope(
        s.legacy,
        &offer(&[Cipher::Blowfish], &[]),
        &Login::account("b", "alice", "s3cret"),
    )
    .await
    .unwrap();
    assert_eq!(banner(&mut b, s.transfer).await.1, BANNER);
}

/// A ChaCha20-Poly1305 session's download and upload, sealed in records
/// as GtkHx seals them: the handshake in the clear, then each direction
/// under its own key from the session's and the reference.
#[tokio::test]
async fn a_chacha20_poly1305_download_and_upload_are_sealed() {
    use hxcrypto::aead::{AeadState, AEAD_LENGTH_PREFIX, AEAD_TAG_SIZE};
    use hxproto::messages::tag;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const FILE_GET: u32 = 0x00ca;
    const FILE_PUT: u32 = 0x00cb;
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), "").await;
    let (mut c, agreed) = hope(
        s.legacy,
        &offer(&[Cipher::ChaCha20Poly1305], &[]),
        &Login::account("a", "alice", "s3cret"),
    )
    .await
    .unwrap();
    let keys = agreed.transfer_keys.unwrap();
    let preamble = |reference, transfer_len| {
        hxfiles_xfer::htxf::Preamble {
            reference,
            transfer_len,
            type_code: 0,
            flags: 0,
            resume_digest: None,
        }
        .encode()
        .unwrap()
    };

    let get = c
        .call(FILE_GET, &[(tag::FILE_NAME, b"notes.txt".to_vec())])
        .await
        .unwrap();
    let reference = get.uint(tag::HTXF_REF).unwrap();
    let size = get.uint(tag::HTXF_SIZE).unwrap() as usize;
    let mut stream = tokio::net::TcpStream::connect(s.transfer).await.unwrap();
    stream.write_all(&preamble(reference, 0)).await.unwrap();
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let (_, mut to_client) = keys.transfer(reference);
    let (mut object, mut rest) = (Vec::new(), &wire[..]);
    while !rest.is_empty() {
        let size = AeadState::peek_frame_size(rest).unwrap();
        let mut plain = vec![0; size - AEAD_LENGTH_PREFIX - AEAD_TAG_SIZE];
        to_client.open(&rest[..size], &mut plain).unwrap();
        object.extend(plain);
        rest = &rest[size..];
    }
    assert_eq!(object.len(), size);
    assert!(object.windows(NOTES.len()).any(|w| w == NOTES));

    let put = c
        .call(FILE_PUT, &[(tag::FILE_NAME, b"up.txt".to_vec())])
        .await
        .unwrap();
    let reference = put.uint(tag::HTXF_REF).unwrap();
    let data = vec![b'u'; 150_000];
    let encoded = hxfiles_xfer::ffo::encode(
        &hxfiles_xfer::ffo::Metadata {
            name: b"up.txt",
            type_code: *b"TEXT",
            creator: *b"ttxt",
            comment: b"",
            create_time: 0,
            modify_time: 0,
        },
        hxfiles_xfer::ffo::Forks {
            data_len: data.len() as u64,
            data_offset: 0,
            resource_len: 0,
            resource_offset: 0,
        },
        false,
    )
    .unwrap();
    let mut object = encoded.prefix;
    object[22..24].copy_from_slice(&2u16.to_be_bytes());
    object.extend_from_slice(&data);
    let (mut to_server, _) = keys.transfer(reference);
    let mut stream = tokio::net::TcpStream::connect(s.transfer).await.unwrap();
    stream
        .write_all(&preamble(reference, object.len() as u64))
        .await
        .unwrap();
    // 60 KiB a record, as GtkHx's upload loop sends them.
    for piece in object.chunks(0xf000) {
        let mut record = vec![0; AEAD_LENGTH_PREFIX + piece.len() + AEAD_TAG_SIZE];
        to_server.seal(piece, &mut record).unwrap();
        stream.write_all(&record).await.unwrap();
    }
    let mut ignored = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut ignored))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("files/up.txt")).unwrap(),
        data
    );
}
