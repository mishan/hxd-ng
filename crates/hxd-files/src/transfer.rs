use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FileBody, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::{ffo, htxf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{PreparedTransfer, TransferRegistry};

/// How much of a body is read and written at a time.
const CHUNK: usize = 64 * 1024;

pub struct LegacyTransfer {
    pub principal: FilePrincipal,
    pub account: String,
    /// The control connection's address when the transfer must come from
    /// it; see [`PreparedTransfer::peer`].
    pub peer: Option<IpAddr>,
    pub path: FilePath,
    pub offset: u64,
    pub large: bool,
    pub wire_name: Vec<u8>,
    pub type_code: [u8; 4],
    pub creator: [u8; 4],
    pub wire_comment: Vec<u8>,
}

pub async fn prepare_legacy(
    registry: &TransferRegistry,
    source: Arc<dyn FileSource>,
    request: LegacyTransfer,
) -> Result<(u32, u64), FileError> {
    let info = source.info(&request.path).await?;
    let encoded = ffo::encode(
        &ffo::Metadata {
            name: &request.wire_name,
            type_code: request.type_code,
            creator: request.creator,
            comment: &request.wire_comment,
            create_time: info.created.unwrap_or(0),
            modify_time: info.modified.unwrap_or(0),
        },
        ffo::Forks {
            data_len: info.size,
            data_offset: request.offset,
            resource_len: 0,
            resource_offset: 0,
        },
        request.large,
    )
    .map_err(|e| match e {
        ffo::Error::Range(_) => FileError::RangeInvalid,
        ffo::Error::SizeOverflow => FileError::TooLarge,
        _ => FileError::Unavailable(format!("FILP metadata: {e}")),
    })?;
    let size = encoded.transfer_len;
    let reference = registry.issue(PreparedTransfer {
        principal: request.principal,
        account: request.account,
        peer: request.peer,
        path: request.path,
        source,
        offset: request.offset,
        large: request.large,
        encoded,
        expires: std::time::Instant::now(),
    })?;
    Ok((reference, size))
}

/// Timeouts for the HTXF listener.
#[derive(Debug, Clone, Copy)]
pub struct HtxfTimeouts {
    /// How long a connection has to present its handshake.
    pub handshake: Duration,
    /// How long a transfer may make no progress in either direction.
    pub idle: Duration,
}

pub async fn serve_htxf(
    listener: TcpListener,
    registry: Arc<TransferRegistry>,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
) -> std::io::Result<()> {
    let mut accept_backoff = Duration::from_millis(10);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                accept_backoff = Duration::from_millis(10);
                accepted
            }
            Err(error) => {
                warn!(%error, "HTXF accept failed; retrying");
                tokio::time::sleep(accept_backoff).await;
                accept_backoff = (accept_backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let registry = registry.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_one(stream, peer, &registry, core, timeouts).await {
                debug!(%peer, %error, "HTXF transfer refused");
            }
        });
    }
}

async fn serve_one(
    mut stream: TcpStream,
    peer: SocketAddr,
    registry: &TransferRegistry,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
) -> Result<(), FileError> {
    let mut base = [0; htxf::BASE_LEN];
    tokio::time::timeout(timeouts.handshake, stream.read_exact(&mut base))
        .await
        .map_err(|_| FileError::Unavailable("HTXF handshake timed out".into()))?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    if base[..4] != htxf::MAGIC {
        return Err(FileError::InvalidPath);
    }
    let flags = u16::from_be_bytes([base[14], base[15]]);
    let full_len = htxf::encoded_len(flags).map_err(|_| FileError::InvalidPath)?;
    let mut bytes = Vec::with_capacity(full_len);
    bytes.extend_from_slice(&base);
    bytes.resize(full_len, 0);
    if full_len > htxf::BASE_LEN {
        tokio::time::timeout(
            timeouts.handshake,
            stream.read_exact(&mut bytes[htxf::BASE_LEN..]),
        )
        .await
        .map_err(|_| FileError::Unavailable("HTXF extension timed out".into()))?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    }
    let (preamble, used) = htxf::parse(&bytes).map_err(|_| FileError::InvalidPath)?;
    if used != bytes.len() {
        return Err(FileError::InvalidPath);
    }
    let transfer = registry.claim(&core, &preamble, peer.ip())?;
    // A resume at the very end of the file has nothing left to fetch, and
    // gets the headers alone, as mhxd sends them.
    let body = if transfer.encoded.data_remaining == 0 {
        None
    } else {
        let body = transfer
            .source
            .open(&transfer.path, transfer.offset)
            .await?;
        if body.len != transfer.encoded.data_remaining {
            return Err(FileError::OriginChanged);
        }
        Some(body)
    };
    let alive = Liveness::new(core, transfer.principal);
    write_idle(&mut stream, &transfer.encoded.prefix, timeouts.idle).await?;
    if let Some(body) = body {
        let expected = body.len;
        deliver(body, &mut stream, expected, timeouts.idle, &alive).await?;
    }
    write_idle(
        &mut stream,
        &transfer.encoded.resource_header,
        timeouts.idle,
    )
    .await?;
    tokio::time::timeout(timeouts.idle, stream.shutdown())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}

/// Whether the session a transfer was issued to is still the one on the
/// roster. A transfer outlives neither a kick nor a logout: mhxd ends a
/// user's transfers with their control connection.
#[derive(Clone)]
pub struct Liveness {
    core: Arc<Core>,
    principal: FilePrincipal,
}

impl Liveness {
    pub fn new(core: Arc<Core>, principal: FilePrincipal) -> Self {
        Liveness { core, principal }
    }

    fn check(&self) -> Result<(), FileError> {
        if self.core.session_serial(self.principal.uid) == Some(self.principal.serial) {
            Ok(())
        } else {
            Err(FileError::Unavailable("the session ended".into()))
        }
    }
}

/// Copies exactly `len` bytes of `body` to `writer`.
///
/// Either side stalling for `idle` ends the copy, and so does the session
/// ending. A source that holds a permit while its body is open, as the
/// HTTP origin does, only gives it back when the body is dropped, so a
/// receiver that stops reading must not be waited on indefinitely.
async fn deliver<W: AsyncWrite + Unpin>(
    body: FileBody,
    writer: &mut W,
    len: u64,
    idle: Duration,
    alive: &Liveness,
) -> Result<(), FileError> {
    let mut reader = body.reader.take(len);
    let mut buffer = vec![0; CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        alive.check()?;
        let read = read_idle(&mut reader, &mut buffer, idle).await?;
        if read == 0 {
            warn!(remaining, len, "source ended before its stated length");
            return Err(FileError::OriginChanged);
        }
        remaining -= read as u64;
        write_idle(writer, &buffer[..read], idle).await?;
    }
    Ok(())
}

/// Streams `len` bytes of `body` into a channel for a response written
/// elsewhere, such as an HTTP body.
///
/// The consumer is not polled by this side, so it is watched through the
/// channel instead: when a chunk sits unaccepted for `idle`, or the
/// session ends, the pump drops the body and the stream ends short. The
/// consumer sees an error item or an early end, never a silent stall.
pub fn pump(
    body: FileBody,
    len: u64,
    idle: Duration,
    alive: Liveness,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(2);
    tokio::spawn(async move {
        let mut reader = body.reader.take(len);
        let mut remaining = len;
        while remaining > 0 {
            if let Err(error) = alive.check() {
                let _ = tx.try_send(Err(std::io::Error::other(error)));
                return;
            }
            let mut buffer = vec![0; CHUNK.min(usize::try_from(remaining).unwrap_or(CHUNK))];
            let read = match read_idle(&mut reader, &mut buffer, idle).await {
                Ok(0) => {
                    let _ = tx.try_send(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    return;
                }
                Ok(read) => read,
                Err(error) => {
                    let _ = tx.try_send(Err(std::io::Error::other(error)));
                    return;
                }
            };
            buffer.truncate(read);
            remaining -= read as u64;
            if tx.send_timeout(Ok(buffer), idle).await.is_err() {
                debug!("download receiver stalled or left; abandoning the body");
                return;
            }
        }
    });
    rx
}

async fn read_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    idle: Duration,
) -> Result<usize, FileError> {
    tokio::time::timeout(idle, reader.read(buffer))
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

async fn write_idle<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    idle: Duration,
) -> Result<(), FileError> {
    tokio::time::timeout(idle, writer.write_all(bytes))
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

fn stalled() -> FileError {
    FileError::Unavailable("transfer stalled".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::{AccessBits, AttachInfo, Transport};

    fn attach(core: &Core) -> FilePrincipal {
        let (uid, _events) = core
            .attach(AttachInfo {
                nick: "reader".into(),
                icon: 0,
                admin: false,
                access: AccessBits::empty(),
                login: "reader".into(),
                addr: None,
                can_detach: false,
                transport: Transport::default(),
                has_inbox: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
            })
            .unwrap();
        FilePrincipal {
            uid,
            serial: core.session_serial(uid).unwrap(),
        }
    }

    /// A body that reports when it is dropped, standing in for a source
    /// whose permit lives as long as its reader.
    struct Tracked {
        inner: std::io::Cursor<Vec<u8>>,
        _dropped: tokio::sync::oneshot::Sender<()>,
    }

    impl AsyncRead for Tracked {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    fn tracked(len: usize) -> (FileBody, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = FileBody {
            len: len as u64,
            reader: Box::pin(Tracked {
                inner: std::io::Cursor::new(vec![7; len]),
                _dropped: tx,
            }),
        };
        (body, rx)
    }

    #[tokio::test]
    async fn a_receiver_that_stops_reading_releases_the_body() {
        let core = Arc::new(Core::new());
        let alive = Liveness::new(core.clone(), attach(&core));
        let len = 4 * CHUNK;
        let (body, dropped) = tracked(len);
        // The receiving half is held and never read, so the writer fills
        // the pipe and then waits.
        let (mut writer, _receiver) = tokio::io::duplex(1024);
        let error = deliver(
            body,
            &mut writer,
            len as u64,
            Duration::from_millis(50),
            &alive,
        )
        .await
        .unwrap_err();
        assert_eq!(error, stalled());
        dropped.await.expect_err("the body was dropped");

        let (body, dropped) = tracked(len);
        let mut chunks = pump(body, len as u64, Duration::from_millis(50), alive);
        tokio::time::sleep(Duration::from_millis(200)).await;
        dropped.await.expect_err("the pump dropped the body");
        let mut received = 0;
        while let Some(chunk) = chunks.recv().await {
            received += chunk.unwrap().len();
        }
        assert!(received < len, "the stream ends short rather than hanging");
    }

    #[tokio::test]
    async fn a_transfer_ends_with_its_session() {
        let core = Arc::new(Core::new());
        let principal = attach(&core);
        let alive = Liveness::new(core.clone(), principal);
        core.end_session(principal.uid);

        let (body, _) = tracked(CHUNK);
        let (mut writer, _receiver) = tokio::io::duplex(4 * CHUNK);
        assert!(deliver(
            body,
            &mut writer,
            CHUNK as u64,
            Duration::from_secs(5),
            &alive
        )
        .await
        .is_err());

        let (body, _) = tracked(CHUNK);
        let mut chunks = pump(body, CHUNK as u64, Duration::from_secs(5), alive);
        assert!(chunks.recv().await.unwrap().is_err());
        assert!(chunks.recv().await.is_none());
    }
}
