//! The server banner over the legacy wire: the push that follows a 1.5+
//! client's agreement, and a banner held here fetched over HTXF the way
//! GtkHx and mhxd's own client fetch one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::Core;
use hxd_files::{EntryLimits, HtxfTimeouts, TransferRegistry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{Banner, ServerConfig, ServerCtx};
use hxfiles_xfer::htxf;
use hxproto::messages::tag;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

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
    core: Arc<Core>,
    banner: Option<Arc<Banner>>,
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
    let banner = match shown {
        Shown::Nothing => None,
        Shown::Url(url) => Some(Banner::url(url.into())),
        Shown::File(bytes, url) => {
            let path = temp.path().join("banner");
            std::fs::write(&path, bytes).unwrap();
            Some(Banner::file(&path, url.map(String::from), transfers.clone()).unwrap())
        }
    };
    let core = Arc::new(Core::new());
    let ctx = ServerCtx {
        core: core.clone(),
        auth: Arc::new(hxd_auth_file::FileAuth::new(&accounts)),
        cfg: Arc::new(ServerConfig {
            name: "banner".into(),
            ..Default::default()
        }),
        files: None,
        banner: banner.map(Arc::new),
    };
    let banner = ctx.banner.clone();
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transfer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        tunnelled: tunnel.local_addr().unwrap(),
        htxf: transfer.local_addr().unwrap(),
        core: core.clone(),
        banner,
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
    server.banner.as_ref().unwrap().reload().unwrap();

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
async fn a_tunnelled_client_is_not_told_of_a_banner_it_cannot_fetch() {
    let image = gif(64);
    let server = start(Shown::File(&image, Some("https://hl.example/"))).await;
    let mut tunnelled = Client::login(server.tunnelled, 190).await;
    assert!(tunnelled.agree().await.is_empty());
    let trans = tunnelled.send(DOWNLOAD_BANNER, &[]).await;
    assert_eq!(tunnelled.task(trans).await.flag & 1, 1);

    // A banner fetched from its URL needs no transfer port.
    let server = start(Shown::Url("https://hl.example/b.jpg")).await;
    let mut tunnelled = Client::login(server.tunnelled, 190).await;
    let banners = tunnelled.agree().await;
    assert_eq!(field(&banners[0], tag::BANNER_TYPE).unwrap(), b"URL ");
}
