//! Read-only Files across both frontends and the HTXF data channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hxd_core::Core;
use hxd_files::{
    DownloadTokens, EntryLimits, FileService, HttpManifestSource, HtxfTimeouts, ManifestLimits,
    TransferRegistry,
};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::frame::{pack_frame, read_frame, Frame};
use hxd_session::{cap, Caps, ServerConfig, ServerCtx};
use hxfiles_xfer::{htxf, rflt};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

const TASK: u32 = 0x0001_0000;
const LOGIN: u32 = 0x006b;
const FILE_LIST: u32 = 0x00c8;
const FILE_GET_INFO: u32 = 0x00ce;
const FILE_GET: u32 = 0x00ca;
const LIST_ENTRY: u16 = 0x00c8;
const HUGE_SIZE: u64 = u32::MAX as u64 + 6;

struct Running {
    legacy: SocketAddr,
    ng: SocketAddr,
    htxf: SocketAddr,
    _temp: tempfile::TempDir,
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
                let (size, full) = if first.contains("/hello.txt ") || first.contains("/fixed.txt ")
                {
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
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let Some(value) = content_range {
                    response.push_str(&format!("Content-Range: {value}\r\n"));
                }
                response.push_str("\r\n");
                // The server may hang up once it has what it asked for.
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });

    let manifest = format!(
        r#"{{"version":1,"files":[
          {{"path":"hello.txt","size":"11","media_type":"text/plain","ranges":true}},
          {{"path":"fixed.txt","size":"11","ranges":false}},
          {{"path":"huge.bin","size":"{HUGE_SIZE}","ranges":true}},
          {{"path":"docs/guide.txt","size":"5","comment":"inside a folder"}}
        ]}}"#
    );
    let source = HttpManifestSource::from_json(
        &format!("http://{origin_addr}/"),
        manifest.as_bytes(),
        ManifestLimits::default(),
    )
    .unwrap();
    let limits = EntryLimits {
        total: 64,
        per_session: 16,
        per_account: 64,
    };
    let idle = Duration::from_secs(5);
    let service = Arc::new(FileService::new(
        Arc::new(source),
        Arc::new(TransferRegistry::new(Duration::from_secs(30), limits)),
        Arc::new(DownloadTokens::new(Duration::from_secs(30), limits)),
        idle,
    ));

    let temp = tempfile::tempdir().unwrap();
    let accounts = temp.path().join("accounts");
    std::fs::create_dir(&accounts).unwrap();
    std::fs::write(
        accounts.join("guest.toml"),
        "name = \"guest\"\n[access]\ndownload_files = true\nread_chat = true\nuse_any_name = true\n",
    )
    .unwrap();
    // An account that may look but not download.
    std::fs::write(
        accounts.join("browser.toml"),
        "name = \"Browser\"\npassword = \"pw\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    // Accounts that may download, but not list, and not get info.
    for (login, extra) in [("nolist", "file_list"), ("noinfo", "file_getinfo")] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!(
                "password = \"pw\"\n[access]\ndownload_files = true\nread_chat = true\n\
                 [extra]\n{extra} = false\n"
            ),
        )
        .unwrap();
    }
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
        _temp: temp,
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    tokio::spawn(hxd_files::serve_htxf(
        transfer,
        service.transfers.clone(),
        core,
        HtxfTimeouts {
            handshake: Duration::from_secs(5),
            idle,
        },
    ));
    running
}

struct Legacy {
    stream: TcpStream,
    trans: u32,
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| !byte).collect()
}

impl Legacy {
    async fn login(address: SocketAddr, large: bool) -> Self {
        let mut chunks = vec![(tag::VERSION, 195u16.to_be_bytes().to_vec())];
        if large {
            chunks.push((
                tag::CAPABILITIES,
                Caps::empty().with(cap::LARGE_FILES).to_wire(),
            ));
        }
        Self::connect(address, chunks).await
    }

    async fn login_as(address: SocketAddr, login: &str, password: &str) -> Self {
        Self::connect(
            address,
            vec![
                (tag::VERSION, 195u16.to_be_bytes().to_vec()),
                (tag::LOGIN, xor(login.as_bytes())),
                (tag::PASSWORD, xor(password.as_bytes())),
            ],
        )
        .await
    }

    async fn connect(address: SocketAddr, chunks: Vec<(u16, Vec<u8>)>) -> Self {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"TRTPHOTL\0\x01\0\x02").await.unwrap();
        let mut magic = [0; 8];
        stream.read_exact(&mut magic).await.unwrap();
        stream
            .write_all(&pack_frame(LOGIN, 1, 0, &chunks))
            .await
            .unwrap();
        let mut client = Legacy { stream, trans: 1 };
        let reply = client.task(1).await;
        assert_eq!(reply.flag & 1, 0, "login succeeds");
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

fn field(frame: &Frame, wanted: u16) -> Option<Vec<u8>> {
    frame
        .chunks()
        .find(|chunk| chunk.tag == wanted)
        .map(|chunk| chunk.data.to_vec())
}

fn listed_names(listing: &Frame) -> Vec<Vec<u8>> {
    listing
        .chunks()
        .filter(|chunk| chunk.tag == LIST_ENTRY)
        .map(|chunk| chunk.data[20..].to_vec())
        .collect()
}

/// A DIR field naming one folder below the root.
fn dir(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 1, 0, 0, name.len() as u8];
    out.extend_from_slice(name);
    out
}

/// Opens a transfer connection, sends the handshake, and reads until the
/// server closes it.
async fn transfer(address: SocketAddr, preamble: htxf::Preamble) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&preamble.encode().unwrap()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

/// The handshake a classic client sends for a download: the protocol puts
/// 0 in its Data size.
fn classic_download(reference: u32) -> htxf::Preamble {
    htxf::Preamble {
        reference,
        transfer_len: 0,
        type_code: 0,
        flags: 0,
        resume_digest: None,
    }
}

#[tokio::test]
async fn classic_hides_oversized_files_while_large_file_resume_is_exact() {
    let server = start().await;
    let mut classic = Legacy::login(server.legacy, false).await;
    let listing = classic.request(FILE_LIST, &[]).await;
    assert_eq!(
        listed_names(&listing),
        [
            b"docs".to_vec(),
            b"fixed.txt".to_vec(),
            b"hello.txt".to_vec()
        ]
    );
    assert!(listing.chunks().all(|chunk| chunk.tag != tag::FILESIZE64));
    let ordinary = classic
        .request(FILE_GET, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    assert!(ordinary.chunks().all(|chunk| chunk.tag != tag::XFERSIZE64));
    let reference =
        u32::from_be_bytes(field(&ordinary, tag::HTXF_REF).unwrap().try_into().unwrap());
    let transfer_len = u32::from_be_bytes(
        field(&ordinary, tag::HTXF_SIZE)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let bytes = transfer(server.htxf, classic_download(reference)).await;
    assert!(bytes.windows(11).any(|window| window == b"hello world"));
    assert_eq!(bytes.len(), transfer_len as usize);

    // A reference is single-use.
    assert!(transfer(server.htxf, classic_download(reference))
        .await
        .is_empty());

    // mhxd's own client echoes the transfer size in the handshake instead.
    let again = classic
        .request(FILE_GET, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    let reference = u32::from_be_bytes(field(&again, tag::HTXF_REF).unwrap().try_into().unwrap());
    let bytes = transfer(
        server.htxf,
        htxf::Preamble {
            transfer_len: u64::from(transfer_len),
            ..classic_download(reference)
        },
    )
    .await;
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

    let info = capable
        .request(FILE_GET_INFO, &[(tag::FILE_NAME, b"huge.bin".to_vec())])
        .await;
    let info_chunks: Vec<_> = info.chunks().collect();
    let sizes = info_chunks
        .windows(2)
        .find(|pair| pair[0].tag == tag::FILE_SIZE)
        .expect("clamped file size and adjacent exact companion");
    assert_eq!(sizes[0].as_uint(), u32::MAX);
    assert_eq!(sizes[1].tag, tag::FILESIZE64);
    assert_eq!(
        u64::from_be_bytes(sizes[1].data.try_into().unwrap()),
        HUGE_SIZE
    );

    // Resuming at the very end is a finished download asking again: the
    // transfer carries the headers and nothing else.
    let eof_resume = capable
        .request(
            FILE_GET,
            &[
                (tag::FILE_NAME, b"huge.bin".to_vec()),
                (tag::OFFSET64, HUGE_SIZE.to_be_bytes().to_vec()),
            ],
        )
        .await;
    assert_eq!(eof_resume.flag & 1, 0);
    let reference = u32::from_be_bytes(
        field(&eof_resume, tag::HTXF_REF)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let headers_only = u64::from_be_bytes(
        field(&eof_resume, tag::XFERSIZE64)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let bytes = transfer(
        server.htxf,
        htxf::Preamble {
            flags: htxf::FLAG_LARGE_FILE,
            ..classic_download(reference)
        },
    )
    .await;
    assert_eq!(bytes.len() as u64, headers_only);
    assert_eq!(&bytes[bytes.len() - 16..bytes.len() - 12], b"MACR");

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
    let reference = u32::from_be_bytes(field(&get, tag::HTXF_REF).unwrap().try_into().unwrap());
    assert_eq!(
        field(&get, tag::OFFSET64).map(|data| u64::from_be_bytes(data.try_into().unwrap())),
        Some(offset)
    );
    let bytes = transfer(
        server.htxf,
        htxf::Preamble {
            flags: htxf::FLAG_LARGE_FILE,
            ..classic_download(reference)
        },
    )
    .await;
    assert!(bytes.windows(5).any(|window| window == b"world"));
    assert_eq!(&bytes[bytes.len() - 16..bytes.len() - 12], b"MACR");
}

#[tokio::test]
async fn classic_resume_folders_and_get_info_follow_the_reference() {
    let server = start().await;
    let mut classic = Legacy::login(server.legacy, false).await;

    let resume = rflt::encode(rflt::Resume {
        data: 6,
        resource: 0,
    })
    .to_vec();
    let get = classic
        .request(
            FILE_GET,
            &[
                (tag::FILE_NAME, b"hello.txt".to_vec()),
                (tag::RFLT, resume.clone()),
            ],
        )
        .await;
    assert_eq!(get.flag & 1, 0);
    let reference = u32::from_be_bytes(field(&get, tag::HTXF_REF).unwrap().try_into().unwrap());
    let bytes = transfer(server.htxf, classic_download(reference)).await;
    // The name rides in the INFO fork, so look for the whole file instead.
    assert!(bytes.windows(5).any(|window| window == b"world"));
    assert!(!bytes.windows(11).any(|window| window == b"hello world"));

    let refused = classic
        .request(
            FILE_GET,
            &[(tag::FILE_NAME, b"fixed.txt".to_vec()), (tag::RFLT, resume)],
        )
        .await;
    assert_ne!(
        refused.flag & 1,
        0,
        "a file that cannot start mid-way refuses the resume in its reply"
    );

    let listing = classic.request(FILE_LIST, &[]).await;
    let folder = listing
        .chunks()
        .find(|chunk| chunk.tag == LIST_ENTRY && chunk.data[20..] == *b"docs")
        .expect("the folder is listed");
    assert_eq!(&folder.data[..4], b"fldr");
    assert_eq!(
        u32::from_be_bytes(folder.data[8..12].try_into().unwrap()),
        1,
        "a folder's size is its child count"
    );
    let inside = classic
        .request(FILE_LIST, &[(tag::DIR, dir(b"docs"))])
        .await;
    assert_eq!(listed_names(&inside), [b"guide.txt".to_vec()]);
    let nested = classic
        .request(
            FILE_GET_INFO,
            &[
                (tag::FILE_NAME, b"guide.txt".to_vec()),
                (tag::DIR, dir(b"docs")),
            ],
        )
        .await;
    assert_eq!(
        field(&nested, tag::FILE_COMMENT).as_deref(),
        Some(b"inside a folder".as_slice())
    );

    let folder_info = classic
        .request(FILE_GET_INFO, &[(tag::FILE_NAME, b"docs".to_vec())])
        .await;
    assert_eq!(folder_info.flag & 1, 0, "Get Info answers for a folder");
    assert_eq!(
        field(&folder_info, tag::FILE_TYPE).as_deref(),
        Some(b"fldr".as_slice())
    );
    assert_eq!(
        field(&folder_info, tag::FILE_CREATOR).as_deref(),
        Some(b"n/a ".as_slice())
    );
    assert_eq!(
        field(&folder_info, tag::FILE_ICON).as_deref(),
        Some(b"fldr".as_slice())
    );
    assert_eq!(
        field(&folder_info, tag::FILE_SIZE).as_deref(),
        Some(1u32.to_be_bytes().as_slice())
    );

    let file_info = classic
        .request(FILE_GET_INFO, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    assert_eq!(
        field(&file_info, tag::FILE_ICON).as_deref(),
        Some(b"TEXT".as_slice())
    );
    assert!(
        file_info.chunks().all(|chunk| chunk.tag != tag::FILESIZE64),
        "a classic client gets no 64-bit companion"
    );
}

#[tokio::test]
async fn browsing_needs_no_access_bit_but_downloading_does() {
    let server = start().await;
    let mut browser = Legacy::login_as(server.legacy, "browser", "pw").await;
    let listing = browser.request(FILE_LIST, &[]).await;
    assert_eq!(listing.flag & 1, 0);
    assert!(!listed_names(&listing).is_empty());
    let info = browser
        .request(FILE_GET_INFO, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    assert_eq!(info.flag & 1, 0);
    let get = browser
        .request(FILE_GET, &[(tag::FILE_NAME, b"hello.txt".to_vec())])
        .await;
    assert_ne!(get.flag & 1, 0);

    let mut ws = ng_login(
        server.ng,
        json!({"login": "browser", "password": "pw", "nick": "Browser"}),
    )
    .await;
    let listed = ng_request(&mut ws, 2, "files_list", json!({})).await;
    assert!(listed["ok"]["entries"].is_array());
    let info = ng_request(&mut ws, 3, "files_info", json!({"path": "hello.txt"})).await;
    assert_eq!(info["ok"]["size"], "11");
    let download = ng_request(&mut ws, 4, "files_download", json!({"path": "hello.txt"})).await;
    assert_eq!(download["error"]["code"], "access_denied");
}

#[tokio::test]
async fn listing_and_get_info_are_separate_extras() {
    let server = start().await;
    let hello = [(tag::FILE_NAME, b"hello.txt".to_vec())];

    let mut nolist = Legacy::login_as(server.legacy, "nolist", "pw").await;
    assert_ne!(nolist.request(FILE_LIST, &[]).await.flag & 1, 0);
    assert_eq!(nolist.request(FILE_GET_INFO, &hello).await.flag & 1, 0);
    let mut noinfo = Legacy::login_as(server.legacy, "noinfo", "pw").await;
    assert_eq!(noinfo.request(FILE_LIST, &[]).await.flag & 1, 0);
    assert_ne!(noinfo.request(FILE_GET_INFO, &hello).await.flag & 1, 0);
    assert_eq!(
        noinfo.request(FILE_GET, &hello).await.flag & 1,
        0,
        "downloading is its own question"
    );

    for (login, list, info) in [("nolist", false, true), ("noinfo", true, false)] {
        let mut ws = ng_login(
            server.ng,
            json!({"login": login, "password": "pw", "nick": login}),
        )
        .await;
        let listed = ng_request(&mut ws, 2, "files_list", json!({})).await;
        assert_eq!(listed.get("ok").is_some(), list, "{login}: {listed}");
        let answer = ng_request(&mut ws, 3, "files_info", json!({"path": "hello.txt"})).await;
        assert_eq!(answer.get("ok").is_some(), info, "{login}: {answer}");
    }

    // The roster does not carry the extras, so a resumed session reads
    // them again from its account.
    let url = format!("ws://{}/", server.ng);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let login = ng_request(
        &mut ws,
        1,
        "login",
        json!({"login": "nolist", "password": "pw", "nick": "nolist"}),
    )
    .await;
    let (session, token) = (
        login["ok"]["session"].as_str().unwrap().to_owned(),
        login["ok"]["token"].as_str().unwrap().to_owned(),
    );
    drop(ws);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let resumed = ng_request(
        &mut ws,
        1,
        "resume",
        json!({"session": session, "token": token, "last_seq": 0}),
    )
    .await;
    assert!(resumed.get("ok").is_some(), "{resumed}");
    let listed = ng_request(&mut ws, 2, "files_list", json!({})).await;
    assert_eq!(listed["error"]["code"], "access_denied");
    let answer = ng_request(&mut ws, 3, "files_info", json!({"path": "hello.txt"})).await;
    assert!(answer.get("ok").is_some(), "{answer}");
}

#[tokio::test]
async fn ng_lists_decimal_sizes_and_proxies_full_and_ranged_downloads() {
    let server = start().await;
    let mut ws = ng_login(server.ng, json!({"nick": "reader"})).await;
    let listed = ng_request(&mut ws, 2, "files_list", json!({})).await;
    let entries = listed["ok"]["entries"].as_array().unwrap();
    let huge = entries
        .iter()
        .find(|entry| entry["name"] == "huge.bin")
        .unwrap();
    assert_eq!(huge["size"], HUGE_SIZE.to_string());
    let docs = entries
        .iter()
        .find(|entry| entry["name"] == "docs")
        .unwrap();
    assert_eq!(docs["kind"], "folder");
    assert_eq!(docs["size"], "1");

    let prepared = ng_request(&mut ws, 3, "files_download", json!({"path": "hello.txt"})).await;
    assert_eq!(prepared["ok"]["size"], "11");
    let path = prepared["ok"]["url"].as_str().unwrap();
    let full = http_get(server.ng, path, None).await;
    assert!(full.starts_with("HTTP/1.1 200 OK"));
    assert!(full.contains("accept-ranges: bytes"));
    assert!(full.contains(
        "content-disposition: attachment; filename=\"hello.txt\"; filename*=UTF-8''hello.txt"
    ));
    assert!(full.ends_with("hello world"));

    let open_ended = http_get(server.ng, path, Some("bytes=6-")).await;
    assert!(open_ended.starts_with("HTTP/1.1 206 Partial Content"));
    assert!(open_ended.contains("content-range: bytes 6-10/11"));
    assert!(open_ended.ends_with("\r\n\r\nworld"));
    let suffix = http_get(server.ng, path, Some("bytes=-5")).await;
    assert!(suffix.starts_with("HTTP/1.1 206 Partial Content"));
    assert!(suffix.contains("content-range: bytes 6-10/11"));
    assert!(suffix.ends_with("\r\n\r\nworld"));
    let bounded = http_get(server.ng, path, Some("bytes=0-4")).await;
    assert!(bounded.starts_with("HTTP/1.1 206 Partial Content"));
    assert!(bounded.contains("content-range: bytes 0-4/11"));
    assert!(bounded.contains("content-length: 5"));
    assert!(bounded.ends_with("\r\n\r\nhello"));
    let past_the_end = http_get(server.ng, path, Some("bytes=11-")).await;
    assert!(past_the_end.starts_with("HTTP/1.1 416 Range Not Satisfiable"));
    assert!(past_the_end.contains("content-range: bytes */11"));

    // Anything else is ignored, and the whole file comes back.
    for headers in [
        "Range: bytes=0-\r\nRange: bytes=6-\r\n",
        "Range: bytes=0-1,4-5\r\n",
        "Range: bytes=+5-\r\n",
        "Range: pages=1-\r\n",
    ] {
        let ignored = http_get_headers(server.ng, path, headers).await;
        assert!(ignored.starts_with("HTTP/1.1 200 OK"), "{headers}");
        assert!(ignored.ends_with("hello world"), "{headers}");
    }

    let fixed = ng_request(&mut ws, 4, "files_download", json!({"path": "fixed.txt"})).await;
    let fixed_path = fixed["ok"]["url"].as_str().unwrap();
    let fixed_full = http_get(server.ng, fixed_path, None).await;
    assert!(!fixed_full.contains("accept-ranges:"));
    let fixed_range = http_get(server.ng, fixed_path, Some("bytes=6-")).await;
    assert!(
        fixed_range.starts_with("HTTP/1.1 200 OK"),
        "a file without ranges ignores the header"
    );
    assert!(fixed_range.ends_with("hello world"));

    ng_request(&mut ws, 5, "logout", json!({})).await;
    let stale = http_get(server.ng, path, None).await;
    assert!(stale.starts_with("HTTP/1.1 404 Not Found"));
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ng_login(address: SocketAddr, params: Value) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{address}/"))
        .await
        .unwrap();
    let login = ng_request(&mut ws, 1, "login", params).await;
    assert!(login.get("ok").is_some(), "{login}");
    ws
}

async fn ng_request(ws: &mut Ws, id: u64, req: &str, params: Value) -> Value {
    ws.send(Message::Text(
        json!({"id": id, "req": req, "params": params}).to_string(),
    ))
    .await
    .unwrap();
    reply(ws, id).await
}

async fn reply(ws: &mut Ws, id: u64) -> Value {
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
    let range = range.map_or(String::new(), |value| format!("Range: {value}\r\n"));
    http_get_headers(address, path, &range).await
}

async fn http_get_headers(address: SocketAddr, path: &str, headers: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n{headers}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}
