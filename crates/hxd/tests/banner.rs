//! The server banner over the legacy wire: the push that follows a 1.5+
//! client's agreement, and a banner held here fetched over HTXF the way
//! GtkHx and mhxd's own client fetch one. And the same banner on the ng
//! wire: the login reply's `banner` block and `GET /banner`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::Core;
use hxd_files::{EntryLimits, HtxfTimeouts, TransferRegistry};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{Banner, ServerConfig, ServerCtx};
use hxfiles_xfer::htxf;
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const TASK: u32 = 0x0001_0000;
const LOGIN: u32 = 0x6b;
const AGREEMENT: u32 = 0x6d;
const AGREEMENT_AGREE: u32 = 0x79;
const BANNER: u32 = 0x7a;
const DOWNLOAD_BANNER: u32 = 0xd4;
const PING: u32 = 0x1f4;
/// `HTXF_TYPE_BANNER`, which a banner fetch names in its handshake.
const HTXF_TYPE_BANNER: u16 = 2;

struct Running {
    legacy: SocketAddr,
    /// The same server, reached as through the `/trtp` tunnel.
    tunnelled: SocketAddr,
    htxf: SocketAddr,
    ng: SocketAddr,
    core: Arc<Core>,
    /// The banner, and the file it was read from, for a SIGHUP's worth
    /// of rewriting.
    banner: Option<(Arc<Banner>, std::path::PathBuf)>,
    temp: tempfile::TempDir,
}

enum Shown<'a> {
    Nothing,
    Url(&'a str),
    File(&'a [u8], Option<&'a str>),
}

async fn start(shown: Shown<'_>) -> Running {
    let temp = tempfile::tempdir().unwrap();
    let accounts = temp.path().join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let transfers = Arc::new(TransferRegistry::new(
        Duration::from_secs(30),
        EntryLimits {
            total: 16,
            per_session: 4,
            per_account: 16,
        },
    ));
    let path = temp.path().join("banner");
    let banner = match shown {
        Shown::Nothing => None,
        Shown::Url(url) => Some(Banner::url(url.into())),
        Shown::File(bytes, url) => {
            std::fs::write(&path, bytes).unwrap();
            Some(Banner::file(&path, url.map(String::from), transfers.clone()).unwrap())
        }
    }
    .map(Arc::new);
    let core = Arc::new(Core::new());
    let ctx = ServerCtx {
        core: core.clone(),
        auth: Arc::new(hxd_auth_file::FileAuth::new(&accounts)),
        cfg: Arc::new(ServerConfig {
            name: "banner".into(),
            ..Default::default()
        }),
        files: None,
        banner: banner.clone(),
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth: ctx.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "banner".into(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: None,
        banner: ctx.banner.clone().map(|b| {
            Arc::new(hxd::banner::NgBanner(b)) as Arc<dyn hxd_ng_session::banner::BannerSource>
        }),
    };
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transfer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        tunnelled: tunnel.local_addr().unwrap(),
        htxf: transfer.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        core: core.clone(),
        banner: banner.map(|b| (b, path)),
        temp,
    };
    // `run_session` is what the ng frontend hands a tunnelled stream to:
    // the protocol is the same, and the peer is not the client's address.
    let tunnel_ctx = ctx.clone();
    tokio::spawn(async move {
        while let Ok((stream, peer)) = tunnel.accept().await {
            tokio::spawn(hxd_session::run_session(
                stream,
                peer,
                tunnel_ctx.clone(),
                Default::default(),
                Default::default(),
            ));
        }
    });
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    tokio::spawn(hxd_files::serve_htxf(
        transfer,
        transfers,
        core,
        HtxfTimeouts {
            handshake: Duration::from_secs(5),
            idle: Duration::from_secs(5),
        },
    ));
    running
}

struct Client {
    stream: TcpStream,
    trans: u32,
}

impl Client {
    /// A 1.5+ guest, logged in and at the agreement, not yet agreeing.
    async fn login(address: SocketAddr, version: u16) -> Client {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"TRTPHOTL\0\x01\0\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut client = Client { stream, trans: 0 };
        let trans = client
            .send(LOGIN, &[(tag::VERSION, version.to_be_bytes().to_vec())])
            .await;
        let reply = client.task(trans).await;
        assert_eq!(reply.flag & 1, 0, "login succeeds");
        client
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        self.stream
            .write_all(&pack_frame(ty, self.trans, 0, chunks))
            .await
            .unwrap();
        self.trans
    }

    async fn recv(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while a frame was expected")
    }

    /// Everything the server sends until the reply to `trans`, and that
    /// reply.
    async fn until_task(&mut self, trans: u32) -> (Vec<Frame>, Frame) {
        let mut before = Vec::new();
        loop {
            let frame = self.recv().await;
            if frame.ty == TASK && frame.trans == trans {
                return (before, frame);
            }
            before.push(frame);
        }
    }

    async fn task(&mut self, trans: u32) -> Frame {
        self.until_task(trans).await.1
    }

    /// Agree, then ping: every banner the agreement earns has arrived by
    /// the time the ping is answered, since a session answers in order.
    async fn agree(&mut self) -> Vec<Frame> {
        let agreed = self
            .send(AGREEMENT_AGREE, &[(tag::NAME, b"viewer".to_vec())])
            .await;
        let (mut pushed, ack) = self.until_task(agreed).await;
        assert_eq!(ack.flag & 1, 0);
        let ping = self.send(PING, &[]).await;
        pushed.extend(self.until_task(ping).await.0);
        pushed.into_iter().filter(|f| f.ty == BANNER).collect()
    }
}

fn field(frame: &Frame, wanted: u16) -> Option<Vec<u8>> {
    frame
        .chunks()
        .find(|chunk| chunk.tag == wanted)
        .map(|chunk| chunk.data.to_vec())
}

fn uint(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |n, b| (n << 8) | u32::from(*b))
}

/// Redeem a reference as GtkHx does: the banner type in the handshake,
/// and the size the reply stated.
async fn fetch(address: SocketAddr, reference: u32, size: u32) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let preamble = htxf::Preamble {
        reference,
        transfer_len: u64::from(size),
        type_code: HTXF_TYPE_BANNER,
        flags: 0,
        resume_digest: None,
    };
    stream.write_all(&preamble.encode().unwrap()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

fn gif(len: usize) -> Vec<u8> {
    let mut bytes = b"GIF89a".to_vec();
    bytes.extend((0..len - 6).map(|i| i as u8));
    bytes
}

#[tokio::test]
async fn a_banner_held_here_follows_the_agreement_and_downloads_once() {
    let image = gif(4000);
    let server = start(Shown::File(&image, Some("https://hl.example/"))).await;
    let mut client = Client::login(server.legacy, 190).await;
    let banners = client.agree().await;
    assert_eq!(banners.len(), 1, "one banner after the agreement");
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"GIFf");
    assert_eq!(
        field(&banners[0], tag::BANNER_URL).unwrap(),
        b"https://hl.example/"
    );

    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    let reply = client.task(trans).await;
    assert_eq!(reply.flag & 1, 0);
    // Two bytes, as mhxd sends it, for a banner that fits in them.
    let size = field(&reply, tag::HTXF_SIZE).unwrap();
    assert_eq!(size, (image.len() as u16).to_be_bytes());
    let reference = uint(&field(&reply, tag::HTXF_REF).unwrap());
    assert_eq!(fetch(server.htxf, reference, uint(&size)).await, image);
    // Spent by the fetch.
    assert!(fetch(server.htxf, reference, uint(&size)).await.is_empty());

    // Once per login: a second request is refused, and agreeing again
    // does not send the banner again.
    let again = client.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(client.task(again).await.flag & 1, 1);
    assert!(client.agree().await.is_empty());

    // A new login is a new banner.
    let mut next = Client::login(server.legacy, 190).await;
    assert_eq!(next.agree().await.len(), 1);
    let trans = next.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(next.task(trans).await.flag & 1, 0);
}

#[tokio::test]
async fn a_banner_past_64k_states_its_size_in_four_bytes() {
    let image = gif(100_000);
    let server = start(Shown::File(&image, None)).await;
    let mut client = Client::login(server.legacy, 151).await;
    let banners = client.agree().await;
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"GIFf");
    assert!(field(&banners[0], tag::BANNER_URL).is_none());

    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    let reply = client.task(trans).await;
    let size = field(&reply, tag::HTXF_SIZE).unwrap();
    assert_eq!(size, 100_000u32.to_be_bytes());
    let reference = uint(&field(&reply, tag::HTXF_REF).unwrap());
    // mhxd's client puts 0 in the handshake's size, as for a file.
    assert_eq!(fetch(server.htxf, reference, 0).await, image);
}

#[tokio::test]
async fn a_banner_reference_ends_with_its_session() {
    let image = gif(64);
    let server = start(Shown::File(&image, None)).await;
    let mut client = Client::login(server.legacy, 190).await;
    client.agree().await;
    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    let reply = client.task(trans).await;
    let reference = uint(&field(&reply, tag::HTXF_REF).unwrap());
    // The owner leaves; the reference goes with the session.
    drop(client);
    timeout(Duration::from_secs(5), async {
        while !server.core.snapshot().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the session ends with its connection");
    assert!(fetch(server.htxf, reference, 64).await.is_empty());
}

#[tokio::test]
async fn a_url_banner_is_fetched_by_the_client_itself() {
    let server = start(Shown::Url("https://hl.example/banner.jpg")).await;
    let mut client = Client::login(server.legacy, 190).await;
    let banners = client.agree().await;
    assert_eq!(banners.len(), 1);
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"URL ");
    assert_eq!(
        field(&banners[0], tag::BANNER_URL).unwrap(),
        b"https://hl.example/banner.jpg"
    );
    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(client.task(trans).await.flag & 1, 1, "nothing to download");
}

#[tokio::test]
async fn no_banner_is_no_push_and_nothing_to_download() {
    let server = start(Shown::Nothing).await;
    let mut client = Client::login(server.legacy, 190).await;
    assert!(client.agree().await.is_empty());
    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(client.task(trans).await.flag & 1, 1);
}

#[tokio::test]
async fn a_client_that_never_agrees_is_never_sent_one() {
    let image = gif(64);
    let server = start(Shown::File(&image, None)).await;
    // 1.2 logs in and is done: no agreement, and so no banner.
    let mut client = Client::login(server.legacy, 0).await;
    let ping = client.send(PING, &[]).await;
    let (pushed, _) = client.until_task(ping).await;
    assert!(pushed.iter().all(|f| f.ty != BANNER && f.ty != AGREEMENT));
    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(client.task(trans).await.flag & 1, 1);
}

#[tokio::test]
async fn a_reload_between_the_push_and_the_download_serves_what_was_pushed() {
    let image = gif(300);
    let server = start(Shown::File(&image, None)).await;
    let mut client = Client::login(server.legacy, 190).await;
    let banners = client.agree().await;
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"GIFf");

    // The operator swaps in a JPEG and reloads.
    let path = server.temp.path().join("banner");
    std::fs::write(&path, [0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]).unwrap();
    server.banner.as_ref().unwrap().0.reload().unwrap();

    let trans = client.send(DOWNLOAD_BANNER, &[]).await;
    let reply = client.task(trans).await;
    let size = uint(&field(&reply, tag::HTXF_SIZE).unwrap());
    let reference = uint(&field(&reply, tag::HTXF_REF).unwrap());
    assert_eq!(
        fetch(server.htxf, reference, size).await,
        image,
        "the GIF it was told of"
    );

    // The next login is told of the JPEG.
    let mut next = Client::login(server.legacy, 190).await;
    assert_eq!(
        field(&next.agree().await[0], tag::BANNER_TYPE).unwrap(),
        b"JPEG"
    );
}

#[tokio::test]
async fn a_tunnelled_client_is_told_of_the_banner_as_anyone_is() {
    // It fetches a held one through `/htxf` (identity.rs covers that).
    let image = gif(64);
    let server = start(Shown::File(&image, Some("https://hl.example/"))).await;
    let mut tunnelled = Client::login(server.tunnelled, 190).await;
    let banners = tunnelled.agree().await;
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"GIFf");
    let trans = tunnelled.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(tunnelled.task(trans).await.flag & 1, 0);
}

// --- The ng wire ----------------------------------------------------------

/// A guest login on the ng wire: the reply's `ok`, and the bearer for HTTP.
async fn ng_login(address: SocketAddr) -> (Value, String) {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
        .await
        .unwrap();
    let login = json!({ "id": 1, "req": "login" }).to_string();
    ws.send(Message::Text(login)).await.unwrap();
    loop {
        let msg = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("ng timed out")
            .expect("ng closed")
            .unwrap();
        let Message::Text(text) = msg else { continue };
        let value: Value = serde_json::from_str(&text).unwrap();
        if value["reply"] == 1 {
            let ok = value["ok"].clone();
            assert!(!ok.is_null(), "{value}");
            let bearer = format!(
                "Bearer {}.{}",
                ok["session"].as_str().unwrap(),
                ok["token"].as_str().unwrap()
            );
            // The session lives as long as its socket does.
            tokio::spawn(async move { while ws.next().await.is_some() {} });
            return (ok, bearer);
        }
    }
}

/// `GET path` with these headers: the status, the headers and the body.
async fn get(address: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (u16, String, Vec<u8>) {
    request(address, "GET", path, headers).await
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, head, raw[split + 4..].to_vec())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

#[tokio::test]
async fn ng_is_told_of_a_banner_held_here_and_fetches_it_with_its_bearer() {
    let image = gif(300);
    let server = start(Shown::File(&image, Some("https://hl.example/"))).await;
    let (ok, bearer) = ng_login(server.ng).await;
    assert!(ok["caps"].as_array().unwrap().contains(&json!("banner")));
    assert_eq!(
        ok["banner"],
        json!({ "url": "/banner", "type": "image/gif", "link": "https://hl.example/" })
    );

    let (status, _, _) = get(server.ng, "/banner", &[]).await;
    assert_eq!(status, 401, "a bearer is required");

    let (status, head, body) = get(server.ng, "/banner", &[("Authorization", &bearer)]).await;
    assert_eq!(status, 200);
    assert_eq!(body, image);
    assert_eq!(header(&head, "content-type"), Some("image/gif"));
    assert_eq!(header(&head, "cache-control"), Some("private, no-cache"));
    // Unlike the legacy download, as often as a client likes, and
    // revalidated from the digest.
    let etag = header(&head, "etag").unwrap().to_owned();
    let (status, _, body) = get(
        server.ng,
        "/banner",
        &[("Authorization", &bearer), ("If-None-Match", &etag)],
    )
    .await;
    assert_eq!((status, body.len()), (304, 0));
}

#[tokio::test]
async fn ng_is_sent_a_url_banner_to_fetch_itself() {
    let server = start(Shown::Url("https://hl.example/banner.jpg")).await;
    let (ok, bearer) = ng_login(server.ng).await;
    assert!(ok["caps"].as_array().unwrap().contains(&json!("banner")));
    assert_eq!(
        ok["banner"],
        json!({ "url": "https://hl.example/banner.jpg" })
    );
    let (status, _, _) = get(server.ng, "/banner", &[("Authorization", &bearer)]).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn ng_without_a_banner_has_no_capability_and_no_block() {
    let server = start(Shown::Nothing).await;
    let (ok, bearer) = ng_login(server.ng).await;
    assert!(!ok["caps"].as_array().unwrap().contains(&json!("banner")));
    assert!(ok.get("banner").is_none());
    let (status, _, _) = get(server.ng, "/banner", &[("Authorization", &bearer)]).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn ng_is_not_sent_a_link_the_banner_does_not_have() {
    let image = gif(64);
    let server = start(Shown::File(&image, None)).await;
    let (ok, _) = ng_login(server.ng).await;
    assert_eq!(
        ok["banner"],
        json!({ "url": "/banner", "type": "image/gif" })
    );
}

#[tokio::test]
async fn a_sighup_reaches_the_next_ng_fetch() {
    let server = start(Shown::File(&gif(64), None)).await;
    let (_, bearer) = ng_login(server.ng).await;
    let auth = ("Authorization", bearer.as_str());
    let (_, head, _) = get(server.ng, "/banner", &[auth]).await;
    let old = header(&head, "etag").unwrap().to_owned();

    let (banner, path) = server.banner.as_ref().unwrap();
    let jpeg = [0xff, 0xd8, 0xff, 0xe0, 1, 2, 3];
    std::fs::write(path, jpeg).unwrap();
    banner.reload().unwrap();

    // The tag the client holds is stale now: the whole new file, typed.
    let (status, head, body) = get(server.ng, "/banner", &[auth, ("If-None-Match", &old)]).await;
    assert_eq!((status, body.as_slice()), (200, &jpeg[..]));
    assert_eq!(header(&head, "content-type"), Some("image/jpeg"));
    let new = header(&head, "etag").unwrap().to_owned();
    assert_ne!(new, old);
    // And a proxy that weakened the new one still gets its 304.
    let weak = format!("W/{new}");
    let (status, head, _) = get(server.ng, "/banner", &[auth, ("If-None-Match", &weak)]).await;
    assert_eq!(status, 304);
    assert_eq!(header(&head, "etag"), Some(new.as_str()));
    assert_eq!(header(&head, "cache-control"), Some("private, no-cache"));
}

#[tokio::test]
async fn a_page_elsewhere_may_fetch_the_banner() {
    let server = start(Shown::File(&gif(64), None)).await;
    let (_, bearer) = ng_login(server.ng).await;
    let origin = ("Origin", "https://web.example");
    let (status, head, _) = get(server.ng, "/banner", &[origin, ("Authorization", &bearer)]).await;
    assert_eq!(status, 200);
    assert!(
        header(&head, "access-control-allow-origin").is_some(),
        "{head}"
    );
    // A stale or forged bearer is refused as a missing one is.
    let (status, _, body) = get(
        server.ng,
        "/banner",
        &[origin, ("Authorization", "Bearer s_0.nope")],
    )
    .await;
    assert_eq!(status, 401);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"]["code"], "not_logged_in");
}

#[tokio::test]
async fn a_browser_preflight_for_the_banner_is_answered() {
    // A page sends this before any fetch that carries `Authorization`;
    // without an answer, it never sends the fetch.
    let server = start(Shown::File(&gif(64), None)).await;
    let (status, head, _) = request(
        server.ng,
        "OPTIONS",
        "/banner",
        &[
            ("Origin", "https://web.example"),
            ("Access-Control-Request-Method", "GET"),
            (
                "Access-Control-Request-Headers",
                "authorization, if-none-match",
            ),
        ],
    )
    .await;
    assert_eq!(status, 204);
    assert!(header(&head, "access-control-allow-methods")
        .unwrap()
        .contains("get"));
    let allowed = header(&head, "access-control-allow-headers").unwrap();
    assert!(
        allowed.contains("authorization") && allowed.contains("if-none-match"),
        "{allowed}"
    );
}

#[tokio::test]
async fn the_binary_gives_the_ng_frontend_the_same_banner() {
    // Built as `hxd` builds a server from its config, not by hand: the
    // wiring between the two frontends is what this is about.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let text = format!(
        "[server]\nbind = \"127.0.0.1:0\"\n[paths]\naccounts = \"{d}/accounts\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n\
         [banner]\nurl = \"https://hl.example/banner.jpg\"\n"
    );
    let path = dir.path().join("hxd-ng.toml");
    std::fs::write(&path, text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let banner = hxd::banner::build(&config, None).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, banner).unwrap();
    let ng = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(hxd_ng_session::serve(listener, ng));
    let (ok, _) = ng_login(address).await;
    assert_eq!(
        ok["banner"],
        json!({ "url": "https://hl.example/banner.jpg" })
    );
}
