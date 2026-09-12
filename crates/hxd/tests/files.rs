//! Read-only Files across both frontends and the HTXF data channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::Core;
use hxd_files::{
    DownloadTokens, FileService, HttpManifestSource, ManifestLimits, TransferRegistry,
};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{cap, Caps, ServerConfig, ServerCtx};
use hxfiles_xfer::htxf;
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const TASK: u32 = 0x0001_0000;
const LOGIN: u32 = 0x006b;
const FILE_LIST: u32 = 0x00c8;
const FILE_GET: u32 = 0x00ca;
const LIST_ENTRY: u16 = 0x00c8;
const HUGE_SIZE: u64 = u32::MAX as u64 + 6;

struct Running {
    legacy: SocketAddr,
    ng: SocketAddr,
    htxf: SocketAddr,
}

async fn start() -> Running {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = origin.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while request.len() < 16 * 1024 {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let first = request.lines().next().unwrap_or_default();
                let range = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("range")
                            .then(|| value.trim().strip_prefix("bytes="))
                            .flatten()
                    })
                    .and_then(|value| value.strip_suffix('-'))
                    .and_then(|value| value.parse::<u64>().ok());
                let (size, full) = if first.contains("/hello.txt ") {
                    (11, b"hello world".as_slice())
                } else {
                    (HUGE_SIZE, &[][..])
                };
                let (status, body, content_range) = match range {
                    Some(6) if size == 11 => (
                        "206 Partial Content",
                        b"world".as_slice(),
                        Some("bytes 6-10/11".to_string()),
                    ),
                    Some(start) if size == HUGE_SIZE && start == HUGE_SIZE - 5 => (
                        "206 Partial Content",
                        b"world".as_slice(),
                        Some(format!("bytes {start}-{}/{}", HUGE_SIZE - 1, HUGE_SIZE)),
                    ),
                    None if size == 11 => ("200 OK", full, None),
                    _ => ("416 Range Not Satisfiable", &[][..], None),
                };
                let mut response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(value) = content_range {
                    response.push_str(&format!("Content-Range: {value}\r\n"));
                }
                response.push_str("\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            });
        }
    });

    let manifest = format!(
        r#"{{"version":1,"files":[
          {{"path":"hello.txt","size":"11","media_type":"text/plain","ranges":true}},
          {{"path":"huge.bin","size":"{HUGE_SIZE}","ranges":true}}
        ]}}"#
    );
    let source = HttpManifestSource::from_json(
        &format!("http://{origin_addr}/"),
        manifest.as_bytes(),
        ManifestLimits::default(),
    )
    .unwrap();
    let service = Arc::new(FileService::new(
        Arc::new(source),
        Arc::new(TransferRegistry::new(Duration::from_secs(30))),
        Arc::new(DownloadTokens::new(Duration::from_secs(30))),
    ));

    let temp = tempfile::tempdir().unwrap();
    let accounts = temp.path().join("accounts");
    std::fs::create_dir(&accounts).unwrap();
    std::fs::write(
        accounts.join("guest.toml"),
        "name = \"guest\"\n[access]\ndownload_files = true\nread_chat = true\nuse_any_name = true\n",
    )
    .unwrap();
    // FileAuth reads on demand, so the temporary directory must outlive the
    // spawned servers. The test process owns this small fixture thereafter.
    let accounts = temp.keep().join("accounts");
    let core = Arc::new(Core::new());
    let auth: Arc<dyn hxd_core::AuthBackend> = Arc::new(hxd_auth_file::FileAuth::new(&accounts));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "files".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: Caps::empty().with(cap::LARGE_FILES),
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            stamp_queued: true,
        }),
        files: Some(service.clone()),
    };
    let ng_ctx = NgCtx {
        core: core.clone(),
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "files".into(),
            caps: vec!["files".into()],
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: Some(service.clone()),
    };
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transfer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        htxf: transfer.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    tokio::spawn(hxd_files::serve_htxf(
        transfer,
        service.transfers.clone(),
        core,
        Duration::from_secs(5),
    ));
    running
}

struct Legacy {
    stream: TcpStream,
    trans: u32,
}

impl Legacy {
    async fn login(address: SocketAddr, large: bool) -> Self {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"TRTPHOTL\0\x01\0\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut chunks = vec![(tag::VERSION, 195u16.to_be_bytes().to_vec())];
        if large {
            chunks.push((
                tag::CAPABILITIES,
                Caps::empty().with(cap::LARGE_FILES).to_wire(),
            ));
        }
        stream
            .write_all(&pack_frame(LOGIN, 1, 0, &chunks))
            .await
            .unwrap();
        let mut client = Legacy { stream, trans: 1 };
        client.task(1).await;
        client
    }

    async fn request(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Frame {
        self.trans += 1;
        let trans = self.trans;
        self.stream
            .write_all(&pack_frame(ty, trans, 0, chunks))
            .await
            .unwrap();
        self.task(trans).await
    }

    async fn task(&mut self, trans: u32) -> Frame {
        loop {
            let frame = timeout(Duration::from_secs(5), read_frame(&mut self.stream))
                .await
                .unwrap()
                .unwrap();
            if frame.ty == TASK && frame.trans == trans {
                return frame;
            }
        }
    }
}

#[tokio::test]
async fn classic_hides_oversized_files_while_large_file_resume_is_exact() {
    let server = start().await;
    let mut classic = Legacy::login(server.legacy, false).await;
    let listing = classic.request(FILE_LIST, &[]).await;
    let names: Vec<_> = listing
        .chunks()
        .filter(|chunk| chunk.tag == LIST_ENTRY)
        .map(|chunk| chunk.data[20..].to_vec())
        .collect();
    assert_eq!(names, [b"hello.txt".to_vec()]);
    assert!(listing.chunks().all(|chunk| chunk.tag != tag::FILESIZE64));
    let ordinary = classic
        .request(FILE_GET, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    assert!(ordinary.chunks().all(|chunk| chunk.tag != tag::XFERSIZE64));
    let reference = ordinary
        .chunks()
        .find(|chunk| chunk.tag == tag::HTXF_REF)
        .unwrap()
        .as_uint();
    let transfer_len = ordinary
        .chunks()
        .find(|chunk| chunk.tag == tag::HTXF_SIZE)
        .unwrap()
        .as_uint() as u64;
    let mut transfer = TcpStream::connect(server.htxf).await.unwrap();
    transfer
        .write_all(
            &htxf::Preamble {
                reference,
                transfer_len,
                type_code: 1,
                flags: 0,
                resume_digest: None,
            }
            .encode()
            .unwrap(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    transfer.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.windows(11).any(|window| window == b"hello world"));

    let guessed = classic
        .request(FILE_GET, &[(tag::FILE_NAME, b"huge.bin".to_vec())])
        .await;
    assert_ne!(
        guessed.flag & 1,
        0,
        "an invisible large file stays inaccessible"
    );

    let mut capable = Legacy::login(server.legacy, true).await;
    let listing = capable.request(FILE_LIST, &[]).await;
    let chunks: Vec<_> = listing.chunks().collect();
    let huge = chunks
        .windows(2)
        .find(|pair| pair[0].tag == LIST_ENTRY && pair[0].data[20..] == *b"huge.bin")
        .expect("large entry and adjacent companion");
    assert_eq!(huge[1].tag, tag::FILESIZE64);
    assert_eq!(
        u64::from_be_bytes(huge[1].data.try_into().unwrap()),
        HUGE_SIZE
    );

    let offset = HUGE_SIZE - 5;
    let get = capable
        .request(
            FILE_GET,
            &[
                (tag::FILE_NAME, b"huge.bin".to_vec()),
                (tag::OFFSET64, offset.to_be_bytes().to_vec()),
            ],
        )
        .await;
    assert_eq!(get.flag & 1, 0);
    let reference = get
        .chunks()
        .find(|chunk| chunk.tag == tag::HTXF_REF)
        .unwrap()
        .as_uint();
    let transfer_len = get
        .chunks()
        .find(|chunk| chunk.tag == tag::XFERSIZE64)
        .map(|chunk| u64::from_be_bytes(chunk.data.try_into().unwrap()))
        .unwrap();
    assert_eq!(
        get.chunks()
            .find(|chunk| chunk.tag == tag::OFFSET64)
            .map(|chunk| u64::from_be_bytes(chunk.data.try_into().unwrap())),
        Some(offset)
    );
    let mut transfer = TcpStream::connect(server.htxf).await.unwrap();
    transfer
        .write_all(
            &htxf::Preamble {
                reference,
                transfer_len,
                type_code: 1,
                flags: htxf::FLAG_LARGE_FILE,
                resume_digest: None,
            }
            .encode()
            .unwrap(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    transfer.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.windows(5).any(|window| window == b"world"));
    assert_eq!(&bytes[bytes.len() - 16..bytes.len() - 12], b"MACR");
}

#[tokio::test]
async fn ng_lists_decimal_sizes_and_proxies_full_and_ranged_downloads() {
    let server = start().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/", server.ng))
        .await
        .unwrap();
    ws.send(Message::Text(
        json!({"id":1,"req":"login","params":{"nick":"reader"}}).to_string(),
    ))
    .await
    .unwrap();
    reply(&mut ws, 1).await;
    ws.send(Message::Text(
        json!({"id":2,"req":"files_list","params":{}}).to_string(),
    ))
    .await
    .unwrap();
    let listed = reply(&mut ws, 2).await;
    assert_eq!(listed["ok"]["entries"][1]["size"], HUGE_SIZE.to_string());
    ws.send(Message::Text(
        json!({"id":3,"req":"files_download","params":{"path":"hello.txt"}}).to_string(),
    ))
    .await
    .unwrap();
    let prepared = reply(&mut ws, 3).await;
    assert_eq!(prepared["ok"]["size"], "11");
    let path = prepared["ok"]["url"].as_str().unwrap();
    let full = http_get(server.ng, path, None).await;
    assert!(full.starts_with("HTTP/1.1 200 OK"));
    assert!(full.ends_with("hello world"));
    let ranged = http_get(server.ng, path, Some("bytes=6-")).await;
    assert!(ranged.starts_with("HTTP/1.1 206 Partial Content"));
    assert!(ranged.contains("content-range: bytes 6-10/11"));
    assert!(ranged.ends_with("world"));
    let malformed = http_get(server.ng, path, Some("bytes=-5")).await;
    assert!(malformed.starts_with("HTTP/1.1 416 Range Not Satisfiable"));

    ws.send(Message::Text(
        json!({"id":4,"req":"logout","params":{}}).to_string(),
    ))
    .await
    .unwrap();
    reply(&mut ws, 4).await;
    let stale = http_get(server.ng, path, None).await;
    assert!(stale.starts_with("HTTP/1.1 404 Not Found"));
}

async fn reply(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    id: u64,
) -> Value {
    loop {
        let message = timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = message {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["reply"] == id {
                return value;
            }
        }
    }
}

async fn http_get(address: SocketAddr, path: &str, range: Option<&str>) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let range = range.map_or(String::new(), |value| format!("Range: {value}\r\n"));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n{range}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}
