//! The legacy wire over TLS: a scripted 1.5 client that handshakes at
//! byte zero on the TLS port and then speaks the same protocol the
//! plaintext port carries, beside a plaintext client on one server — and
//! a download on the TLS transfer port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::Core;
use hxd_files::{
    DownloadTokens, EntryLimits, FileService, HtxfSlots, HtxfTimeouts, LocalFileSource,
    LocalLimits, TransferRegistry,
};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{cap, Caps, LegacyTls, ServerConfig, ServerCtx};
use hxfiles_xfer::htxf;
use hxproto::messages::tag;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const TASK: u32 = 0x0001_0000;
const LOGIN: u32 = 0x006b;
const CHAT_SEND: u32 = 0x0069;
const CHAT: u32 = 0x006a;
const SELFINFO: u32 = 0x0162;
const GET_USER_LIST: u32 = 0x012c;
const FILE_GET: u32 = 0x00ca;

/// Color bit 4: the link is cleartext.
const CLEARTEXT: u16 = 16;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Io for S {}

struct Running {
    plain: SocketAddr,
    tls: SocketAddr,
    tls_htxf: SocketAddr,
    /// The certificate, for the client's trust store.
    cert: CertificateDer<'static>,
    _temp: tempfile::TempDir,
}

async fn start(login_timeout: Duration) -> Running {
    let temp = tempfile::tempdir().unwrap();
    let accounts = temp.path().join("accounts");
    std::fs::create_dir(&accounts).unwrap();
    std::fs::write(
        accounts.join("guest.toml"),
        "name = \"guest\"\n[access]\nread_chat = true\nsend_chat = true\n\
         download_files = true\nuse_any_name = true\n",
    )
    .unwrap();
    let root = temp.path().join("files");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("sealed.txt"), b"over the wire, under wraps").unwrap();

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert_path, key_path) = (temp.path().join("cert.pem"), temp.path().join("key.pem"));
    std::fs::write(&cert_path, issued.cert.pem()).unwrap();
    std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();
    let tls = Arc::new(LegacyTls::load(&cert_path, &key_path).unwrap());

    let limits = EntryLimits {
        total: 64,
        per_session: 16,
        per_account: 64,
    };
    let source = Arc::new(LocalFileSource::open(&root, LocalLimits::default()).unwrap());
    let service = Arc::new(FileService::new(
        source.clone(),
        Some(source),
        Arc::new(TransferRegistry::new(Duration::from_secs(30), limits)),
        Arc::new(DownloadTokens::new(Duration::from_secs(30), limits)),
        Duration::from_secs(5),
    ));
    let core = Arc::new(Core::new());
    let ctx = ServerCtx {
        core: core.clone(),
        auth: Arc::new(hxd_auth_file::FileAuth::new(&accounts)),
        cfg: Arc::new(ServerConfig {
            name: "tls".into(),
            version: 185,
            agreement: None,
            login_timeout,
            ban_time: Duration::from_secs(60),
            stamp_queued: true,
            caps: Caps::empty().with(cap::LARGE_FILES),
            mark_cleartext: true,
            trtp_login: hxd_session::TrtpLogin::Verify,
            news: Default::default(),
        }),
        files: Some(service.clone()),
    };

    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let htxf = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        plain: plain.local_addr().unwrap(),
        tls: secure.local_addr().unwrap(),
        tls_htxf: htxf.local_addr().unwrap(),
        cert: issued.cert.der().clone(),
        _temp: temp,
    };
    tokio::spawn(hxd_session::serve(plain, ctx.clone()));
    tokio::spawn(hxd_session::serve_tls(secure, ctx, tls.clone()));
    tokio::spawn(hxd_files::serve_htxf_with(
        htxf,
        HtxfSlots::default(),
        move |stream| tls.acceptor().accept(stream),
        service.transfers.clone(),
        core,
        HtxfTimeouts {
            handshake: Duration::from_secs(5),
            idle: Duration::from_secs(5),
        },
    ));
    running
}

/// A client that trusts exactly the server's certificate.
fn connector(cert: &CertificateDer<'static>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn tls_stream(server: &Running, addr: SocketAddr) -> impl Io {
    let tcp = TcpStream::connect(addr).await.unwrap();
    connector(&server.cert)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the TLS handshake completes")
}

struct Client {
    stream: Box<dyn Io>,
    trans: u32,
    uid: u16,
}

impl Client {
    async fn plain(server: &Running, nick: &str) -> Client {
        let stream = TcpStream::connect(server.plain).await.unwrap();
        Client::login(Box::new(stream), nick).await
    }

    async fn tls(server: &Running, nick: &str) -> Client {
        let stream = tls_stream(server, server.tls).await;
        Client::login(Box::new(stream), nick).await
    }

    /// The magic exchange and a guest login as a 1.5 client makes it,
    /// through the self-info push that says the session is announced.
    async fn login(mut stream: Box<dyn Io>, nick: &str) -> Client {
        stream.write_all(b"TRTPHOTL\0\x01\0\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, b"TRTP\0\0\0\0", "server magic");
        let mut c = Client {
            stream,
            trans: 0,
            uid: 0,
        };
        let t = c
            .send(
                LOGIN,
                &[
                    (tag::NAME, nick.as_bytes().to_vec()),
                    (tag::ICON, 1u16.to_be_bytes().to_vec()),
                    (tag::VERSION, 150u16.to_be_bytes().to_vec()),
                ],
            )
            .await;
        let reply = c.task(t).await;
        assert_eq!(reply.flag & 1, 0, "login succeeds");
        c.uid = reply
            .chunks()
            .find(|ch| ch.tag == tag::UID)
            .map(|ch| ch.as_uint() as u16)
            .unwrap();
        c.recv_type(SELFINFO).await;
        c
    }

    async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> u32 {
        self.trans += 1;
        let bytes = pack_frame(ty, self.trans, 0, chunks);
        self.stream.write_all(&bytes).await.unwrap();
        self.stream.flush().await.unwrap();
        self.trans
    }

    async fn recv(&mut self) -> Frame {
        timeout(Duration::from_secs(5), read_frame(&mut self.stream))
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while a frame was expected")
    }

    async fn recv_type(&mut self, ty: u32) -> Frame {
        for _ in 0..16 {
            let f = self.recv().await;
            if f.ty == ty {
                return f;
            }
        }
        panic!("frame type {ty:#x} never arrived");
    }

    async fn task(&mut self, trans: u32) -> Frame {
        for _ in 0..16 {
            let f = self.recv().await;
            if f.ty == TASK && f.trans == trans {
                return f;
            }
        }
        panic!("the reply to {trans} never arrived");
    }

    async fn request(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Frame {
        let t = self.send(ty, chunks).await;
        self.task(t).await
    }

    /// Wait for a chat line whose body is `line`, however many others
    /// arrive first — a sender hears its own echo too.
    async fn hear(&mut self, line: &[u8]) {
        for _ in 0..16 {
            let f = self.recv_type(CHAT).await;
            if field(&f, tag::BODY).as_deref() == Some(line) {
                return;
            }
        }
        panic!("never heard {:?}", String::from_utf8_lossy(line));
    }
}

fn field(f: &Frame, want: u16) -> Option<Vec<u8>> {
    f.chunks().find(|c| c.tag == want).map(|c| c.data.to_vec())
}

/// Each user-list row's uid and color.
fn colors(list: &Frame) -> Vec<(u16, u16)> {
    list.chunks()
        .filter(|c| c.tag == tag::USER_LIST)
        .map(|c| {
            let d = c.data;
            (
                u16::from_be_bytes([d[0], d[1]]),
                u16::from_be_bytes([d[4], d[5]]),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_tls_client_and_a_plaintext_one_share_one_room() {
    let server = start(Duration::from_secs(5)).await;
    let mut sealed = Client::tls(&server, "sealed").await;
    let mut open = Client::plain(&server, "open").await;

    // Only the plaintext session wears the cleartext mark.
    let list = open.request(GET_USER_LIST, &[]).await;
    let rows = colors(&list);
    let color = |uid| rows.iter().find(|(u, _)| *u == uid).unwrap().1;
    assert_eq!(color(sealed.uid) & CLEARTEXT, 0, "{rows:?}");
    assert_eq!(color(open.uid) & CLEARTEXT, CLEARTEXT, "{rows:?}");

    // Chat crosses both ways, formatted as on any other port.
    open.send(CHAT_SEND, &[(tag::BODY, b"anyone listening?".to_vec())])
        .await;
    sealed.hear(b"\r         open:  anyone listening?").await;
    sealed
        .send(CHAT_SEND, &[(tag::BODY, b"only you".to_vec())])
        .await;
    open.hear(b"\r       sealed:  only you").await;
}

#[tokio::test]
async fn the_tls_port_says_nothing_to_a_plaintext_client() {
    let server = start(Duration::from_secs(5)).await;
    let mut stream = TcpStream::connect(server.tls).await.unwrap();
    stream.write_all(b"TRTPHOTL\0\x01\0\x02").await.unwrap();
    let mut reply = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut reply))
        .await
        .expect("the server hangs up");
    assert!(
        !reply.starts_with(b"TRTP"),
        "no Hotline bytes before a handshake"
    );
    // And the port is still serving.
    Client::tls(&server, "after").await;
}

#[tokio::test]
async fn a_stalled_handshake_is_dropped_at_the_login_timeout() {
    let server = start(Duration::from_millis(500)).await;
    let mut stream = TcpStream::connect(server.tls).await.unwrap();
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the server hangs up on a client that never says hello");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test]
async fn a_download_crosses_the_tls_transfer_port() {
    let server = start(Duration::from_secs(5)).await;
    let mut client = Client::tls(&server, "fetcher").await;
    let get = client
        .request(FILE_GET, &[(tag::FILE_NAME, b"sealed.txt".to_vec())])
        .await;
    assert_eq!(get.flag & 1, 0, "the download is granted");
    let reference = u32::from_be_bytes(field(&get, tag::HTXF_REF).unwrap().try_into().unwrap());

    // A plaintext handshake on the TLS transfer port gets nothing.
    let preamble = htxf::Preamble {
        reference,
        transfer_len: 0,
        type_code: 0,
        flags: 0,
        resume_digest: None,
    };
    let mut plain = TcpStream::connect(server.tls_htxf).await.unwrap();
    plain.write_all(&preamble.encode().unwrap()).await.unwrap();
    let mut refused = Vec::new();
    let _ = timeout(Duration::from_secs(5), plain.read_to_end(&mut refused))
        .await
        .expect("the server hangs up");
    assert!(!refused.windows(5).any(|w| w == b"wraps"));

    // The same reference over TLS delivers the file.
    let mut stream = tls_stream(&server, server.tls_htxf).await;
    stream.write_all(&preamble.encode().unwrap()).await.unwrap();
    stream.flush().await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("the transfer finishes");
    assert!(
        bytes
            .windows(26)
            .any(|w| w == b"over the wire, under wraps"),
        "the file arrives"
    );
}
