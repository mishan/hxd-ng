use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FileBody, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::{ffo, htxf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, warn};

use crate::{
    LocalFileSource, PreparedDownload, PreparedTransfer, PreparedUpload, TransferRegistry,
    UploadQuote,
};

/// How much of a body is read and written at a time.
const CHUNK: usize = 64 * 1024;

pub struct LegacyTransfer {
    pub principal: FilePrincipal,
    pub account: String,
    /// The control connection's address when the transfer must come from
    /// it; see [`PreparedDownload::peer`].
    pub peer: Option<IpAddr>,
    pub path: FilePath,
    pub offset: u64,
    pub resource_offset: u64,
    pub large: bool,
    pub wire_name: Vec<u8>,
    pub type_code: [u8; 4],
    pub creator: [u8; 4],
    pub wire_comment: Vec<u8>,
}

pub struct UploadTransfer {
    pub principal: FilePrincipal,
    /// As for [`LegacyTransfer::peer`].
    pub peer: Option<IpAddr>,
    pub path: FilePath,
    pub owner: String,
    /// The declared HTXF payload size. A request may leave it out, as
    /// mhxd's own client always does; the handshake then states it.
    pub transfer_len: Option<u64>,
    pub large: bool,
    pub resume_requested: bool,
    /// The uploader's text is UTF-8 (`CAPABILITY_TEXT_ENCODING`). The
    /// comment is stored as Mac Roman whichever wire it came from, since
    /// that is what the sidecar holds and what every reader decodes.
    pub comment_utf8: bool,
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
            resource_len: info.resource_size,
            resource_offset: request.resource_offset,
        },
        request.large,
    )
    .map_err(|e| match e {
        ffo::Error::Range(_) => FileError::RangeInvalid,
        ffo::Error::SizeOverflow => FileError::TooLarge,
        _ => FileError::Unavailable(format!("FILP metadata: {e}")),
    })?;
    let size = encoded.transfer_len;
    let reference = registry.issue(PreparedTransfer::Download(PreparedDownload {
        principal: request.principal,
        account: request.account,
        peer: request.peer,
        path: request.path,
        source,
        offset: request.offset,
        resource_offset: request.resource_offset,
        large: request.large,
        encoded,
    }))?;
    Ok((reference, size))
}

pub async fn prepare_upload(
    registry: &TransferRegistry,
    source: Arc<LocalFileSource>,
    request: UploadTransfer,
) -> Result<(u32, Option<UploadQuote>), FileError> {
    let quote_source = source.clone();
    let owner = request.owner.clone();
    let path = request.path.clone();
    let transfer_len = request.transfer_len;
    let large = request.large;
    let resume_requested = request.resume_requested;
    let quote = tokio::task::spawn_blocking(move || {
        quote_source.prepare_upload(&owner, &path, transfer_len, large, resume_requested)
    })
    .await
    .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))??;
    let resumed = quote.as_ref().map_or(0, |value| {
        value.data_offset.saturating_add(value.resource_offset)
    });
    if request.transfer_len.is_some_and(|total| resumed > total) {
        return Err(FileError::RangeInvalid);
    }
    if !request.large
        && quote.as_ref().is_some_and(|value| {
            value.data_offset > u64::from(u32::MAX) || value.resource_offset > u64::from(u32::MAX)
        })
    {
        return Err(FileError::TooLarge);
    }
    let reference = registry.issue(PreparedTransfer::Upload(PreparedUpload {
        principal: request.principal,
        peer: request.peer,
        path: request.path,
        source,
        owner: request.owner,
        transfer_len: request.transfer_len,
        large: request.large,
        quote: quote.clone(),
        comment_utf8: request.comment_utf8,
    }))?;
    Ok((reference, quote))
}

/// Timeouts for the HTXF listener.
#[derive(Debug, Clone, Copy)]
pub struct HtxfTimeouts {
    /// How long a connection has to present its handshake.
    pub handshake: Duration,
    /// How long a download may make no progress toward its receiver.
    pub idle: Duration,
}

/// A byte stream HTXF can run over: a TCP socket, or a TLS session on one.
pub trait HtxfStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> HtxfStream for S {}

/// The transfer connections one server holds at once, across every HTXF
/// listener it runs: a TLS transfer port is more of the same capacity,
/// not another helping of it.
#[derive(Clone)]
pub struct HtxfSlots(Arc<Semaphore>);

impl Default for HtxfSlots {
    fn default() -> Self {
        const MAX_HTXF_CONNECTIONS: usize = 256;
        Self(Arc::new(Semaphore::new(MAX_HTXF_CONNECTIONS)))
    }
}

/// The plaintext transfer listener, with capacity of its own.
pub async fn serve_htxf(
    listener: TcpListener,
    registry: Arc<TransferRegistry>,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
) -> std::io::Result<()> {
    serve_htxf_with(
        listener,
        HtxfSlots::default(),
        |stream| std::future::ready(Ok(stream)),
        registry,
        core,
        timeouts,
    )
    .await
}

/// A transfer listener whose accepted sockets pass through `wrap` before
/// the handshake is read — a TLS accept, for the TLS transfer port.
/// `wrap` runs on the connection's own task, inside the handshake
/// timeout, so a client that stalls in it holds one slot and no more.
pub async fn serve_htxf_with<W, F, S>(
    listener: TcpListener,
    slots: HtxfSlots,
    wrap: W,
    registry: Arc<TransferRegistry>,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
) -> std::io::Result<()>
where
    W: Fn(TcpStream) -> F,
    F: Future<Output = std::io::Result<S>> + Send + 'static,
    S: HtxfStream,
{
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
        // A banned address takes no slot, and so no TLS handshake either:
        // the pool is shared, and its idle connections would crowd out
        // everyone else's transfers on both ports.
        if core.is_banned(peer.ip()) {
            debug!(%peer, "HTXF connection refused from a banned address");
            continue;
        }
        let permit = match slots.0.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(%peer, "HTXF connection refused while transfer capacity is full");
                continue;
            }
        };
        let registry = registry.clone();
        let core = core.clone();
        let wrapped = wrap(stream);
        tokio::spawn(async move {
            let _permit = permit;
            let stream = match tokio::time::timeout(timeouts.handshake, wrapped).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    debug!(%peer, %error, "HTXF connection refused before its handshake");
                    return;
                }
                Err(_) => {
                    debug!(%peer, "HTXF connection timed out before its handshake");
                    return;
                }
            };
            if let Err(error) = serve_one(stream, peer, &registry, core, timeouts).await {
                debug!(%peer, %error, "HTXF transfer refused");
            }
        });
    }
}

async fn serve_one<S: HtxfStream>(
    mut stream: S,
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
    match transfer {
        PreparedTransfer::Download(transfer) => {
            let alive = Liveness::new(core, transfer.principal);
            serve_download(stream, transfer, &alive, timeouts.idle).await
        }
        PreparedTransfer::Upload(transfer) => {
            let alive = Liveness::new(core, transfer.principal);
            let timeout = transfer.source.limits().upload_timeout;
            tokio::time::timeout(timeout, serve_upload(stream, transfer, preamble, &alive))
                .await
                .map_err(|_| FileError::Unavailable("upload exceeded its time limit".into()))?
        }
    }
}

async fn serve_download<S: HtxfStream>(
    mut stream: S,
    transfer: PreparedDownload,
    alive: &Liveness,
    idle: Duration,
) -> Result<(), FileError> {
    // A resume at the very end of a fork has nothing left to fetch from
    // it, and the transfer carries that fork's header alone, as mhxd
    // sends it.
    let data = if transfer.encoded.data_remaining == 0 {
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
    write_idle(&mut stream, &transfer.encoded.prefix, idle).await?;
    if let Some(body) = data {
        let expected = body.len;
        deliver(body, &mut stream, expected, idle, alive).await?;
    }
    write_idle(&mut stream, &transfer.encoded.resource_header, idle).await?;
    if transfer.encoded.resource_remaining != 0 {
        let resource = transfer
            .source
            .open_resource(&transfer.path, transfer.resource_offset)
            .await?;
        if resource.len != transfer.encoded.resource_remaining {
            return Err(FileError::OriginChanged);
        }
        let expected = resource.len;
        deliver(resource, &mut stream, expected, idle, alive).await?;
    }
    tokio::time::timeout(idle, stream.shutdown())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}

async fn serve_upload<S: HtxfStream>(
    mut stream: S,
    transfer: PreparedUpload,
    preamble: htxf::Preamble,
    alive: &Liveness,
) -> Result<(), FileError> {
    // Local I/O permits are taken around each piece of disk work rather
    // than for the whole upload: a client trickling bytes must not hold
    // capacity that listings and downloads share.
    let fresh = transfer.quote.is_none();
    let owner = transfer.owner.clone();
    let path = transfer.path.clone();
    // The claim resolves a length the request left out.
    let reserve = transfer
        .transfer_len
        .ok_or_else(|| FileError::Unavailable("upload length was not resolved".into()))?;
    let quote = transfer.quote.clone();
    let files = on_disk(&transfer.source, move |source| {
        let files = source.begin_upload(&owner, &path, fresh, reserve)?;
        if let Some(quote) = quote {
            source.recheck_resume(&files, &quote)?;
        }
        Ok(files)
    })
    .await?;
    let result = if transfer.large {
        receive_large(&mut stream, &transfer, &preamble, &files, alive).await
    } else {
        receive_legacy(&mut stream, &transfer, &preamble, &files, alive).await
    };
    // Nothing is published for a session that ended while its bytes were
    // arriving.
    let result = result.and_then(|hfs| alive.check().map(|()| hfs));
    let path = transfer.path.clone();
    on_disk(&transfer.source, move |source| match result {
        Ok(hfs) => source.publish_upload(&path, &files, &hfs),
        // Dropped here, off the runtime: a partial left empty is removed as
        // it goes.
        Err(error) => {
            drop(files);
            Err(error)
        }
    })
    .await
}

/// Runs local disk work on the blocking pool, under an I/O permit.
async fn on_disk<T: Send + 'static>(
    source: &Arc<LocalFileSource>,
    work: impl FnOnce(&LocalFileSource) -> Result<T, FileError> + Send + 'static,
) -> Result<T, FileError> {
    let _permit = source.acquire_io_permit().await?;
    let source = source.clone();
    tokio::task::spawn_blocking(move || work(&source))
        .await
        .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))?
}

async fn receive_large<S: HtxfStream>(
    stream: &mut S,
    transfer: &PreparedUpload,
    preamble: &htxf::Preamble,
    files: &crate::local::UploadFiles,
    alive: &Liveness,
) -> Result<hxhfs::HfsInfo, FileError> {
    let offset = transfer.quote.as_ref().map_or(0, |quote| quote.data_offset);
    let final_len = offset
        .checked_add(preamble.transfer_len)
        .ok_or(FileError::TooLarge)?;
    if final_len > transfer.source.limits().max_file_size {
        return Err(FileError::TooLarge);
    }
    let mut output = tokio::fs::File::from_std(
        files
            .data
            .try_clone()
            .map_err(|error| unavailable("clone partial data fork", error))?,
    );
    output
        .seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|error| unavailable("seek partial data fork", error))?;
    copy_exact(
        stream,
        &mut output,
        preamble.transfer_len,
        &transfer.source,
        alive,
    )
    .await?;
    let _permit = transfer.source.acquire_io_permit().await?;
    output
        .sync_all()
        .await
        .map_err(|error| unavailable("sync uploaded data", error))?;
    Ok(hxhfs::HfsInfo::default())
}

async fn receive_legacy<S: HtxfStream>(
    stream: &mut S,
    transfer: &PreparedUpload,
    preamble: &htxf::Preamble,
    files: &crate::local::UploadFiles,
    alive: &Liveness,
) -> Result<hxhfs::HfsInfo, FileError> {
    let source = &transfer.source;
    let timeout = source.limits().io_timeout;
    // Everything the object says about its own size is spent against the
    // length the handshake declared before a byte of it is written, so a
    // fork header cannot claim more than was reserved for it.
    let mut budget = preamble.transfer_len;
    let mut fixed = [0; ffo::FFO_HEADER_LEN + ffo::FORK_HEADER_LEN];
    spend(&mut budget, fixed.len() as u64)?;
    read_exact_timeout(stream, &mut fixed, timeout).await?;
    // The fork count is not consulted, as mhxd does not consult it: the
    // fork headers say what follows, and the declared length says where
    // the object ends.
    if &fixed[..4] != b"FILP" || fixed[4..6] != 1u16.to_be_bytes() || fixed[6..22] != [0; 16] {
        return Err(FileError::InvalidPath);
    }
    let info_header =
        ffo::parse_fork_header(&fixed[24..], false).map_err(|_| FileError::InvalidPath)?;
    let max_info = ffo::INFO_FIXED_LEN + ffo::MAX_NAME_LEN + ffo::MAX_COMMENT_LEN;
    if &info_header.tag != b"INFO"
        || info_header.length < ffo::INFO_FIXED_LEN as u64
        || info_header.length > max_info as u64
    {
        return Err(FileError::InvalidPath);
    }
    spend(&mut budget, info_header.length)?;
    let mut info = vec![0; info_header.length as usize];
    read_exact_timeout(stream, &mut info, timeout).await?;
    let mut parsed = ffo::parse_info(&info).map_err(|_| FileError::InvalidPath)?;
    // Unmappable characters become `?`, as on every other Mac Roman
    // path; stored raw, a UTF-8 comment would read back as mojibake.
    if transfer.comment_utf8 {
        parsed.comment = hxproto::text::from_utf8(&String::from_utf8_lossy(&parsed.comment));
    }
    let mut data_header = [0; ffo::FORK_HEADER_LEN];
    spend(&mut budget, data_header.len() as u64)?;
    read_exact_timeout(stream, &mut data_header, timeout).await?;
    let data_header =
        ffo::parse_fork_header(&data_header, false).map_err(|_| FileError::InvalidPath)?;
    if &data_header.tag != b"DATA" {
        return Err(FileError::InvalidPath);
    }
    spend(&mut budget, data_header.length)?;
    let data_offset = transfer.quote.as_ref().map_or(0, |quote| quote.data_offset);
    let data_len = data_offset
        .checked_add(data_header.length)
        .ok_or(FileError::TooLarge)?;
    if data_len > transfer.source.limits().max_file_size {
        return Err(FileError::TooLarge);
    }
    let mut data = tokio::fs::File::from_std(
        files
            .data
            .try_clone()
            .map_err(|error| unavailable("clone partial data fork", error))?,
    );
    data.seek(std::io::SeekFrom::Start(data_offset))
        .await
        .map_err(|error| unavailable("seek partial data fork", error))?;
    copy_exact(stream, &mut data, data_header.length, source, alive).await?;

    // The protocol's object has two forks, and mhxd's client sends no MACR
    // header for an empty resource fork, so one is read only while declared
    // bytes remain, which is when mhxd reads it.
    let resource_length = if budget == 0 {
        0
    } else {
        let mut resource_header = [0; ffo::FORK_HEADER_LEN];
        spend(&mut budget, resource_header.len() as u64)?;
        read_exact_timeout(stream, &mut resource_header, timeout).await?;
        let resource_header =
            ffo::parse_fork_header(&resource_header, false).map_err(|_| FileError::InvalidPath)?;
        if &resource_header.tag != b"MACR" {
            return Err(FileError::InvalidPath);
        }
        spend(&mut budget, resource_header.length)?;
        resource_header.length
    };
    if budget != 0 {
        return Err(FileError::InvalidPath);
    }
    let resource_offset = transfer
        .quote
        .as_ref()
        .map_or(0, |quote| quote.resource_offset);
    let resource_len = resource_offset
        .checked_add(resource_length)
        .ok_or(FileError::TooLarge)?;
    if data_len.saturating_add(resource_len) > source.limits().max_file_size {
        return Err(FileError::TooLarge);
    }
    if resource_length != 0 {
        let mut resource = tokio::fs::File::from_std(
            files
                .resource
                .try_clone()
                .map_err(|error| unavailable("clone partial resource fork", error))?,
        );
        resource
            .seek(std::io::SeekFrom::Start(resource_offset))
            .await
            .map_err(|error| unavailable("seek partial resource fork", error))?;
        copy_exact(stream, &mut resource, resource_length, source, alive).await?;
        let _permit = source.acquire_io_permit().await?;
        resource
            .sync_all()
            .await
            .map_err(|error| unavailable("sync uploaded resource fork", error))?;
    }
    let _permit = source.acquire_io_permit().await?;
    data.sync_all()
        .await
        .map_err(|error| unavailable("sync uploaded data fork", error))?;
    let mut type_creator = [0; 8];
    type_creator.copy_from_slice(&parsed.type_creator);
    Ok(hxhfs::HfsInfo {
        type_creator,
        create_time: parsed.create_time.to_be_bytes(),
        modify_time: parsed.modify_time.to_be_bytes(),
        rsrclen: resource_len,
        comment: parsed.comment,
    })
}

async fn read_exact_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    bytes: &mut [u8],
    timeout: Duration,
) -> Result<(), FileError> {
    tokio::time::timeout(timeout, reader.read_exact(bytes))
        .await
        .map_err(|_| FileError::Unavailable("upload stalled".into()))?
        .map(|_| ())
        .map_err(|error| unavailable("read upload", error))
}

/// Takes `amount` from what the handshake declared is left to arrive.
fn spend(budget: &mut u64, amount: u64) -> Result<(), FileError> {
    *budget = budget.checked_sub(amount).ok_or(FileError::InvalidPath)?;
    Ok(())
}

/// Copies exactly `remaining` bytes of an upload into its partial. Each disk
/// write takes an I/O permit of its own, and the session is checked between
/// chunks: an upload ends with a kick, as a download does.
///
/// Whatever arrived is flushed before this returns, on the way out of a
/// failure as much as a success: `tokio::fs::File` buffers a write and
/// dropping one does not push it to the file, so an upload that ends early
/// would otherwise leave a partial the next resume quote measures as
/// shorter than it is — or as empty, which discards it.
async fn copy_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    remaining: u64,
    source: &LocalFileSource,
    alive: &Liveness,
) -> Result<(), FileError> {
    let result = copy_chunks(reader, writer, remaining, source, alive).await;
    if let Ok(_permit) = source.acquire_io_permit().await {
        let flushed = tokio::time::timeout(source.limits().io_timeout, writer.flush())
            .await
            .map_err(|_| FileError::Unavailable("local file write stalled".into()))
            .and_then(|write| write.map_err(|error| unavailable("flush partial upload", error)));
        result.and(flushed)
    } else {
        result
    }
}

async fn copy_chunks<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    mut remaining: u64,
    source: &LocalFileSource,
    alive: &Liveness,
) -> Result<(), FileError> {
    let timeout = source.limits().io_timeout;
    let mut buffer = vec![0; CHUNK];
    while remaining != 0 {
        alive.check()?;
        let want = remaining.min(buffer.len() as u64) as usize;
        let read = tokio::time::timeout(timeout, reader.read(&mut buffer[..want]))
            .await
            .map_err(|_| FileError::Unavailable("upload stalled".into()))?
            .map_err(|error| unavailable("read upload", error))?;
        if read == 0 {
            return Err(FileError::OriginChanged);
        }
        let _permit = source.acquire_io_permit().await?;
        tokio::time::timeout(timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| FileError::Unavailable("local file write stalled".into()))?
            .map_err(|error| unavailable("write partial upload", error))?;
        remaining -= read as u64;
    }
    Ok(())
}

fn unavailable(context: &str, error: std::io::Error) -> FileError {
    FileError::Unavailable(format!("{context}: {error}"))
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
                attach_news: false,
                moderate: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
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
