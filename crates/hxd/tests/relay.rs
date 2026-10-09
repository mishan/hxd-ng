//! A classic server behind `hlrelay` (`docs/hotline-ng-auth.md` §10.2):
//! a client that reaches it only over WebSockets logs in, chats with a
//! client on the TCP port, and downloads a file over `/htxf` — with the
//! server none the wiser. The server here is hxd-ng's legacy frontend on
//! its own, with no ng listener: the relay is what a server that has
//! never heard of Hotline-ng gets in front of it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::Core;
use hxd_files::{
    DownloadTokens, EntryLimits, FileService, HtxfTimeouts, LocalFileSource, LocalLimits,
    TransferRegistry,
};
use hxd_session::{ServerConfig, ServerCtx};
use hxd_testclient::legacy::{push, Client, Login};
use hxfiles_xfer::htxf;
use hxproto::messages::tag;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const FILE_GET: u32 = 0x00ca;
const WAIT: Duration = Duration::from_secs(5);

struct Running {
    legacy: SocketAddr,
    relay: SocketAddr,
    _files: tempfile::TempDir,
    _accounts: tempfile::TempDir,
}

async fn start() -> Running {
    let accounts = tempfile::tempdir().unwrap();
    std::fs::write(
        accounts.path().join("guest.toml"),
        "name = \"guest\"\n[access]\nread_chat = true\nsend_chat = true\n\
         download_files = true\nuse_any_name = true\n",
    )
    .unwrap();
    let files = tempfile::tempdir().unwrap();
    std::fs::write(files.path().join("hello.txt"), b"hello through the relay").unwrap();

    let limits = EntryLimits {
        total: 64,
        per_session: 16,
        per_account: 64,
    };
    let source = Arc::new(LocalFileSource::open(files.path(), LocalLimits::default()).unwrap());
    let service = Arc::new(FileService::new(
        source.clone(),
        Some(source),
        Arc::new(TransferRegistry::new(Duration::from_secs(30), limits)),
        Arc::new(DownloadTokens::new(Duration::from_secs(30), limits)),
        WAIT,
    ));
    let core = Arc::new(Core::new());
    let ctx = ServerCtx {
        core: core.clone(),
        auth: Arc::new(hxd_auth_file::FileAuth::new(accounts.path())),
        cfg: Arc::new(ServerConfig {
            name: "behind a relay".into(),
            version: 185,
            agreement: None,
            login_timeout: WAIT,
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: hxd_session::Caps::empty(),
            hope: None,
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            news: Default::default(),
        }),
        files: Some(service.clone()),
        banner: None,
    };
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transfer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        relay: relay.local_addr().unwrap(),
        _files: files,
        _accounts: accounts,
    };
    let mut cfg = hlrelay::Config::new(running.legacy.to_string());
    cfg.transfer = Some(transfer.local_addr().unwrap().to_string());
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_files::serve_htxf(
        transfer,
        service.transfers.clone(),
        core,
        HtxfTimeouts {
            handshake: WAIT,
            idle: WAIT,
        },
    ));
    tokio::spawn(hlrelay::serve(relay, cfg));
    running
}

/// A classic client whose only way in is the relay's `/trtp`.
async fn relayed(relay: SocketAddr, nick: &str) -> Client {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{relay}/trtp"))
        .await
        .unwrap();
    let mut c = Client::over(Box::new(hl_tunnel::WsByteStream::new(ws)))
        .await
        .unwrap();
    c.login(&Login::guest(nick)).await.unwrap();
    c
}

fn chat_text(f: &hxd_testclient::legacy::Frame) -> String {
    String::from_utf8_lossy(&f.bytes(tag::BODY).unwrap_or_default()).into_owned()
}

#[tokio::test]
async fn a_relayed_client_is_an_ordinary_client() {
    let server = start().await;
    let mut web = relayed(server.relay, "web").await;
    let mut tcp = Client::login_at(server.legacy, &Login::guest("tcp"))
        .await
        .unwrap();

    // Each sees the other.
    let nicks: Vec<_> = tcp
        .user_list()
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.nick)
        .collect();
    assert!(nicks.iter().any(|n| n == b"web"), "{nicks:?}");

    // Chat crosses in both directions.
    web.chat(b"from the browser").await.unwrap();
    let heard = timeout(
        WAIT,
        tcp.recv_where(|f| f.ty == push::CHAT && chat_text(f).contains("from the browser")),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(chat_text(&heard).contains("web"));
    tcp.chat(b"from a desktop").await.unwrap();
    timeout(
        WAIT,
        web.recv_where(|f| f.ty == push::CHAT && chat_text(f).contains("from a desktop")),
    )
    .await
    .unwrap()
    .unwrap();

    // Closing the socket ends the session, as closing TCP does.
    web.shutdown().await.unwrap();
    timeout(WAIT, tcp.recv_type(push::USER_PART))
        .await
        .expect("the relayed user parts")
        .unwrap();
}

#[tokio::test]
async fn a_relayed_client_downloads_over_htxf() {
    let server = start().await;
    let mut web = relayed(server.relay, "web").await;
    let get = web
        .call(FILE_GET, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await
        .unwrap();
    let reference = get.uint(tag::HTXF_REF).unwrap();
    let size = get.uint(tag::HTXF_SIZE).unwrap() as usize;

    // The transfer's own socket, as a classic client opens its own
    // connection to the port after the server's.
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/htxf", server.relay))
        .await
        .unwrap();
    let mut xfer = hl_tunnel::WsByteStream::new(ws);
    let preamble = htxf::Preamble {
        reference,
        transfer_len: 0,
        type_code: 0,
        flags: 0,
        resume_digest: None,
    };
    xfer.write_all(&preamble.encode().unwrap()).await.unwrap();
    xfer.flush().await.unwrap();
    let mut got = Vec::new();
    timeout(WAIT, xfer.read_to_end(&mut got))
        .await
        .expect("the server ends the transfer")
        .unwrap();
    assert_eq!(got.len(), size);
    assert!(got.windows(23).any(|w| w == b"hello through the relay"));
}
