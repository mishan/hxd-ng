use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FileBody, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::{ffo, folder, htxf, rflt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, warn};

use crate::local::PartialKey;
use crate::{
    FolderItem, LocalFileSource, PreparedDownload, PreparedFolder, PreparedFolderUpload,
    PreparedTransfer, PreparedUpload, TransferRegistry, UploadQuote,
};

/// How much of a body is read and written at a time.
const CHUNK: usize = 64 * 1024;

pub struct LegacyTransfer {
    pub principal: FilePrincipal,
    pub account: String,
    /// The control connection's address when the transfer must come from
    /// it; see [`PreparedDownload::peer`].
    pub peer: Option<IpAddr>,
    /// See [`PreparedDownload::hope`].
    pub hope: Option<crate::SealKeys>,
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
    /// See [`PreparedDownload::hope`].
    pub hope: Option<crate::SealKeys>,
    pub path: FilePath,
    pub owner: String,
    /// The declared HTXF payload size. A request may leave it out, as
    /// mhxd's own client always does; the handshake then states it.
    pub transfer_len: Option<u64>,
    pub large: bool,
    pub resume_requested: bool,
    /// The uploader may not see into the folder it uploads to: a drop box,
    /// for an account without `view_drop_boxes`. Such an upload is never
    /// offered a resume and is never refused for a name that is taken; it
    /// is published under a free one instead, so that it learns nothing of
    /// what the folder holds.
    pub blind: bool,
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
        hope: request.hope,
        path: request.path,
        source,
        offset: request.offset,
        resource_offset: request.resource_offset,
        large: request.large,
        encoded,
    }))?;
    Ok((reference, size))
}

pub struct FolderTransfer {
    pub principal: FilePrincipal,
    pub account: String,
    /// As for [`LegacyTransfer::peer`].
    pub peer: Option<IpAddr>,
    /// See [`PreparedDownload::hope`].
    pub hope: Option<crate::SealKeys>,
    pub large: bool,
    pub items: Vec<FolderItem>,
}

/// Issues a folder download: its reference, and the size its files'
/// objects come to, which is what the reply announces.
pub fn prepare_folder(
    registry: &TransferRegistry,
    source: Arc<dyn FileSource>,
    request: FolderTransfer,
) -> Result<(u32, u64), FileError> {
    let mut size = 0u64;
    let mut fits = true;
    for item in &request.items {
        // A header the wire cannot carry is refused now, not partway.
        folder::Item {
            folder: item.file.is_none(),
            path: item.path.clone(),
        }
        .encode()
        .map_err(|_| FileError::TooDeep)?;
        if let Some(file) = &item.file {
            let len = file.encode(0, 0, request.large)?.transfer_len;
            fits &= len <= u64::from(u32::MAX);
            size = size.checked_add(len).ok_or(FileError::TooLarge)?;
        }
    }
    let reference = registry.issue(PreparedTransfer::Folder(PreparedFolder {
        principal: request.principal,
        account: request.account,
        peer: request.peer,
        hope: request.hope,
        source,
        large: request.large,
        fits,
        items: request.items.into(),
    }))?;
    Ok((reference, size))
}

pub async fn prepare_upload(
    registry: &TransferRegistry,
    source: Arc<LocalFileSource>,
    request: UploadTransfer,
) -> Result<(u32, Option<UploadQuote>), FileError> {
    let quote = check_upload(&source, &request).await?;
    let reference = registry.issue(PreparedTransfer::Upload(PreparedUpload {
        principal: request.principal,
        peer: request.peer,
        hope: request.hope,
        path: request.path,
        source,
        owner: request.owner,
        transfer_len: request.transfer_len,
        large: request.large,
        quote: quote.clone(),
        blind: request.blind,
        comment_utf8: request.comment_utf8,
    }))?;
    Ok((reference, quote))
}

/// What the local area says to an upload of `request`: refused (the name
/// is taken, the quotas are spent), or allowed, with the partial it may
/// resume.
async fn check_upload(
    source: &Arc<LocalFileSource>,
    request: &UploadTransfer,
) -> Result<Option<UploadQuote>, FileError> {
    let quote_source = source.clone();
    let key = partial_key(&request.owner, &request.path, request.blind)?;
    let path = request.path.clone();
    let transfer_len = request.transfer_len;
    let large = request.large;
    let resume_requested = request.resume_requested;
    let quote = crate::spawn_blocking("files", move || {
        quote_source.prepare_upload(&key, &path, transfer_len, large, resume_requested)
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
    Ok(quote)
}

fn partial_key(owner: &str, path: &FilePath, blind: bool) -> Result<PartialKey, FileError> {
    if blind {
        PartialKey::blind(owner)
    } else {
        Ok(PartialKey::resumable(owner, path))
    }
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
            if let Err(error) = serve_one(stream, peer, &registry, core, timeouts, None).await {
                debug!(%peer, %error, "HTXF transfer refused");
            }
        });
    }
}

/// One transfer arriving through the `/htxf` tunnel (`hotline-ng-auth.md`
/// §7.4) rather than on a transfer port. `identity` is the one the
/// tunnel's socket proved, and the reference must have been issued to a
/// session with that same identity: a tunnelled session's reference is
/// bound to no address, since its peer is whoever terminated the
/// WebSocket, and this is what binds it instead.
pub async fn serve_tunnelled<S: HtxfStream>(
    stream: S,
    peer: SocketAddr,
    registry: &TransferRegistry,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
    identity: [u8; 32],
) -> Result<(), FileError> {
    serve_one(stream, peer, registry, core, timeouts, Some(identity)).await
}

async fn serve_one<S: HtxfStream>(
    mut stream: S,
    peer: SocketAddr,
    registry: &TransferRegistry,
    core: Arc<Core>,
    timeouts: HtxfTimeouts,
    identity: Option<[u8; 32]>,
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
    // Claimed first, so a presentation under the wrong identity spends the
    // reference as a wrong address does.
    if let Some(identity) = identity {
        let owner = core
            .user(transfer.principal().uid)
            .and_then(|u| u.transport.identity)
            .map(|tag| tag.fingerprint);
        if owner != Some(identity) {
            return Err(FileError::NotFound);
        }
    }
    let mut stream: Box<dyn HtxfStream> = match transfer.hope() {
        Some(seal) => Box::new(crate::sealed::Sealed::new(
            stream,
            &seal.keys,
            preamble.reference,
        )),
        None => Box::new(stream),
    };
    match transfer {
        PreparedTransfer::Download(transfer) => {
            let alive = Liveness::new(core, transfer.principal);
            serve_download(stream, transfer, &alive, timeouts.idle).await
        }
        PreparedTransfer::Folder(transfer) => {
            let alive = Liveness::new(core, transfer.principal);
            serve_folder(stream, transfer, &alive, timeouts.idle).await
        }
        PreparedTransfer::FolderUpload(transfer) => {
            let alive = Liveness::new(core, transfer.principal);
            serve_folder_upload(stream, transfer, &alive, timeouts.idle).await
        }
        // No `Liveness` check: a banner is at most 1 MiB, already in memory,
        // and finishes within `idle`; a kick mid-banner costs nothing worth
        // interrupting it for.
        PreparedTransfer::Banner(banner) => {
            write_idle(&mut stream, &banner.bytes, timeouts.idle).await?;
            tokio::time::timeout(timeouts.idle, stream.shutdown())
                .await
                .map_err(|_| stalled())?
                .map_err(|e| FileError::Unavailable(e.to_string()))
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
    let _open = hxd_core::instrument::transfer_open("download");
    send_object(
        &mut stream,
        transfer.source.as_ref(),
        &transfer.path,
        &transfer.encoded,
        (transfer.offset, transfer.resource_offset),
        alive,
        idle,
    )
    .await?;
    tokio::time::timeout(idle, stream.shutdown())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}

/// One flattened file object: `encoded`'s framing around the forks of
/// `path`, read from `offsets` (data, resource).
async fn send_object<S: AsyncWrite + Unpin>(
    stream: &mut S,
    source: &dyn FileSource,
    path: &FilePath,
    encoded: &ffo::Encoded,
    offsets: (u64, u64),
    alive: &Liveness,
    idle: Duration,
) -> Result<(), FileError> {
    // A resume at the very end of a fork has nothing left to fetch from
    // it, and the transfer carries that fork's header alone, as mhxd
    // sends it.
    let data = if encoded.data_remaining == 0 {
        None
    } else {
        let body = source.open(path, offsets.0).await?;
        if body.len != encoded.data_remaining {
            return Err(FileError::OriginChanged);
        }
        Some(body)
    };
    write_idle(stream, &encoded.prefix, idle).await?;
    if let Some(body) = data {
        let expected = body.len;
        deliver(body, stream, expected, idle, alive).await?;
    }
    write_idle(stream, &encoded.resource_header, idle).await?;
    if encoded.resource_remaining != 0 {
        let resource = source.open_resource(path, offsets.1).await?;
        if resource.len != encoded.resource_remaining {
            return Err(FileError::OriginChanged);
        }
        let expected = resource.len;
        deliver(resource, stream, expected, idle, alive).await?;
    }
    Ok(())
}

/// A folder download's dialog (Hotline.md, Download Folder): the client
/// asks for each item's header with NEXT, then for a file's object with
/// SEND or RESUME, and the server closes once NEXT finds nothing left.
async fn serve_folder<S: HtxfStream>(
    mut stream: S,
    transfer: PreparedFolder,
    alive: &Liveness,
    idle: Duration,
) -> Result<(), FileError> {
    let _open = hxd_core::instrument::transfer_open("download");
    let protocol = |what: &str| FileError::Unavailable(format!("folder download: {what}"));
    let mut items = transfer.items.iter();
    let mut current: Option<&FolderItem> = None;
    loop {
        // TLS, a sealed transfer and the tunnel may hold what was written
        // until they are flushed, and the client answers only what it has.
        flush_idle(&mut stream, idle).await?;
        let Some(action) = read_action(&mut stream, idle).await? else {
            break;
        };
        alive.check()?;
        match action {
            folder::ACTION_NEXT => {
                let Some(item) = items.next() else {
                    break;
                };
                current = Some(item);
                let header = folder::Item {
                    folder: item.file.is_none(),
                    path: item.path.clone(),
                }
                .encode()
                .map_err(|e| protocol(&e.to_string()))?;
                write_idle(&mut stream, &header, idle).await?;
            }
            folder::ACTION_SEND | folder::ACTION_RESUME => {
                // Once per item: a client wanting it again asks again.
                let file = current
                    .take()
                    .and_then(|item| item.file.as_ref())
                    .ok_or_else(|| protocol("a send names no file"))?;
                let resume = if action == folder::ACTION_RESUME {
                    let mut len = [0; 2];
                    read_exact_idle(&mut stream, &mut len, idle).await?;
                    let len = usize::from(u16::from_be_bytes(len));
                    if len > folder::MAX_RESUME_LEN {
                        return Err(protocol("an oversized resume"));
                    }
                    let mut record = vec![0; len];
                    read_exact_idle(&mut stream, &mut record, idle).await?;
                    rflt::parse_compatible(&record)
                } else {
                    rflt::Resume::default()
                };
                let offsets = (u64::from(resume.data), u64::from(resume.resource));
                if offsets.0 != 0
                    && offsets.0 < file.data_len
                    && !transfer.source.supports_ranges(&file.path)
                {
                    return Err(protocol("a resume this file cannot make"));
                }
                let encoded = file.encode(offsets.0, offsets.1, transfer.large)?;
                // Advisory past 32 bits (Capabilities-Large-File, "Per-item
                // transfer size"): the receiver reads the object's own
                // fork headers.
                let size = u32::try_from(encoded.transfer_len).unwrap_or(0);
                write_idle(&mut stream, &size.to_be_bytes(), idle).await?;
                send_object(
                    &mut stream,
                    transfer.source.as_ref(),
                    &file.path,
                    &encoded,
                    offsets,
                    alive,
                    idle,
                )
                .await?;
            }
            _ => return Err(protocol("an unknown action")),
        }
    }
    tokio::time::timeout(idle, stream.shutdown())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

/// A folder upload's dialog (Hotline.md, Upload Folder): the server asks
/// for each item with NEXT and answers a file's header with SEND, or with
/// RESUME from the end of one already there, which it keeps; the client
/// closes after its last item.
async fn serve_folder_upload<S: HtxfStream>(
    mut stream: S,
    transfer: PreparedFolderUpload,
    alive: &Liveness,
    idle: Duration,
) -> Result<(), FileError> {
    let _open = hxd_core::instrument::transfer_open("upload");
    let protocol = |what: &str| FileError::Unavailable(format!("folder upload: {what}"));
    let source = &transfer.source;
    let root = if transfer.merge {
        transfer.root.clone()
    } else {
        alive.folder_reserve()?;
        source
            .make_upload_folder(&transfer.root, transfer.blind)
            .await
            .inspect_err(|_| alive.folder_refund())?
    };
    let mut items = 0;
    loop {
        write_idle(&mut stream, &folder::ACTION_NEXT.to_be_bytes(), idle).await?;
        flush_idle(&mut stream, idle).await?;
        let mut len = [0; 2];
        if read_idle(&mut stream, &mut len[..1], idle).await? == 0 {
            break;
        }
        read_exact_idle(&mut stream, &mut len[1..], idle).await?;
        let mut header = vec![0; usize::from(u16::from_be_bytes(len))];
        read_exact_idle(&mut stream, &mut header, idle).await?;
        let item = folder::Item::parse(&header).map_err(|e| protocol(&e.to_string()))?;
        alive.check()?;
        items += 1;
        if items > transfer.max_items {
            return Err(protocol("more items than [files] max_folder_items"));
        }
        // Refused before a name is decoded: a header can name thousands.
        if root.components().len() + item.path.len() > source.limits().max_depth {
            return Err(FileError::TooDeep);
        }
        if item.path.iter().any(|name| name.len() > 128) {
            return Err(FileError::InvalidPath);
        }
        let path = FilePath::from_components(
            root.components()
                .map(str::to_owned)
                .chain(item.path.iter().map(|name| (transfer.decode)(name))),
        )?;
        // Added to, a folder that holds a drop box would answer for what is
        // in it: whether an item is there, and how long. Decided on the
        // spelling, as listing would hide it, not on what exists.
        if transfer.merge && !transfer.sees_drop_boxes && path.is_drop_box() {
            return Err(FileError::NotFound);
        }
        if item.folder {
            // Adding to a folder, one already there costs nothing, so a
            // resume after the budget ran out goes on to its files.
            if transfer.merge {
                match source.info(&path).await {
                    Ok(info) if info.kind == hxd_core::FileKind::Folder => continue,
                    Ok(_) => return Err(FileError::AlreadyExists),
                    Err(FileError::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            alive.folder_reserve()?;
            source
                .make_folder(&path)
                .await
                .inspect_err(|_| alive.folder_refund())?;
            continue;
        }
        let there = if transfer.merge {
            match source.info(&path).await {
                Ok(info) => Some(info),
                Err(FileError::NotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let mut size = [0; 4];
        if let Some(info) = there {
            // Resumed from its end, the client sends the object's headers
            // alone, and what is there is kept: a client that cannot be
            // told to skip an item can still be spared sending it. Any
            // longer copy's tail is read and dropped.
            if info.kind != hxd_core::FileKind::File {
                return Err(FileError::AlreadyExists);
            }
            let end = |len: u64| u32::try_from(len).map_err(|_| FileError::TooLarge);
            let record = rflt::encode(rflt::Resume {
                data: end(info.size)?,
                resource: end(info.resource_size)?,
            });
            let mut action = folder::ACTION_RESUME.to_be_bytes().to_vec();
            action.extend_from_slice(&(record.len() as u16).to_be_bytes());
            action.extend_from_slice(&record);
            write_idle(&mut stream, &action, idle).await?;
            flush_idle(&mut stream, idle).await?;
            read_exact_idle(&mut stream, &mut size, idle).await?;
            let size = u64::from(u32::from_be_bytes(size));
            if size > source.limits().max_file_size.saturating_add(1_024) {
                return Err(FileError::TooLarge);
            }
            let mut left = size;
            let mut buffer = vec![0; CHUNK.min(size as usize)];
            while left > 0 {
                let at = buffer.len().min(left as usize);
                read_exact_idle(&mut stream, &mut buffer[..at], idle).await?;
                left -= at as u64;
            }
            continue;
        }
        write_idle(&mut stream, &folder::ACTION_SEND.to_be_bytes(), idle).await?;
        flush_idle(&mut stream, idle).await?;
        read_exact_idle(&mut stream, &mut size, idle).await?;
        let transfer_len = u64::from(u32::from_be_bytes(size));
        let request = UploadTransfer {
            principal: transfer.principal,
            peer: transfer.peer,
            hope: transfer.hope.clone(),
            path,
            owner: transfer.owner.clone(),
            transfer_len: Some(transfer_len),
            large: false,
            resume_requested: false,
            blind: false,
            comment_utf8: transfer.comment_utf8,
        };
        check_upload(source, &request).await?;
        let upload = PreparedUpload {
            principal: request.principal,
            peer: request.peer,
            hope: request.hope,
            path: request.path,
            source: source.clone(),
            owner: request.owner,
            transfer_len: request.transfer_len,
            large: false,
            quote: None,
            blind: false,
            comment_utf8: request.comment_utf8,
        };
        let preamble = htxf::Preamble {
            reference: 0,
            transfer_len,
            type_code: 0,
            flags: 0,
            resume_digest: None,
        };
        // Each file is held to the time one uploaded alone would be.
        tokio::time::timeout(
            source.limits().upload_timeout,
            receive_upload(&mut stream, &upload, &preamble, alive),
        )
        .await
        .map_err(|_| FileError::Unavailable("upload exceeded its time limit".into()))??;
    }
    tokio::time::timeout(idle, stream.shutdown())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

/// The receiver's next action, or `None` when it has closed between them.
async fn read_action<S: AsyncRead + Unpin>(
    stream: &mut S,
    idle: Duration,
) -> Result<Option<u16>, FileError> {
    let mut action = [0; 2];
    if read_idle(stream, &mut action[..1], idle).await? == 0 {
        return Ok(None);
    }
    read_exact_idle(stream, &mut action[1..], idle).await?;
    Ok(Some(u16::from_be_bytes(action)))
}

async fn flush_idle<S: AsyncWrite + Unpin>(
    stream: &mut S,
    idle: Duration,
) -> Result<(), FileError> {
    tokio::time::timeout(idle, stream.flush())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

async fn read_exact_idle<S: AsyncRead + Unpin>(
    stream: &mut S,
    bytes: &mut [u8],
    idle: Duration,
) -> Result<(), FileError> {
    tokio::time::timeout(idle, stream.read_exact(bytes))
        .await
        .map_err(|_| stalled())?
        .map(|_| ())
        .map_err(|e| FileError::Unavailable(e.to_string()))
}

async fn serve_upload<S: HtxfStream>(
    mut stream: S,
    transfer: PreparedUpload,
    preamble: htxf::Preamble,
    alive: &Liveness,
) -> Result<(), FileError> {
    let _open = hxd_core::instrument::transfer_open("upload");
    receive_upload(&mut stream, &transfer, &preamble, alive).await
}

/// One uploaded object, received into a partial and published.
async fn receive_upload<S: HtxfStream>(
    stream: &mut S,
    transfer: &PreparedUpload,
    preamble: &htxf::Preamble,
    alive: &Liveness,
) -> Result<(), FileError> {
    // Local I/O permits are taken around each piece of disk work rather
    // than for the whole upload: a client trickling bytes must not hold
    // capacity that listings and downloads share.
    let fresh = transfer.quote.is_none();
    let key = partial_key(&transfer.owner, &transfer.path, transfer.blind)?;
    let path = transfer.path.clone();
    // The claim resolves a length the request left out.
    let reserve = transfer
        .transfer_len
        .ok_or_else(|| FileError::Unavailable("upload length was not resolved".into()))?;
    let quote = transfer.quote.clone();
    let files = on_disk(&transfer.source, move |source| {
        let files = source.begin_upload(&key, &path, fresh, reserve)?;
        if let Some(quote) = quote {
            source.recheck_resume(&files, &quote)?;
        }
        Ok(files)
    })
    .await?;
    let result = if transfer.large {
        receive_large(stream, transfer, preamble, &files, alive).await
    } else {
        receive_legacy(stream, transfer, preamble, &files, alive).await
    };
    // Nothing is published for a session that ended while its bytes were
    // arriving.
    let result = result.and_then(|hfs| alive.check().map(|()| hfs));
    let path = transfer.path.clone();
    let tree = transfer.source.lock_tree().await;
    on_disk(&transfer.source, move |source| match result {
        Ok(hfs) => source
            .publish_upload(&tree, &path, &files, &hfs)
            .map(|_| ()),
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
    crate::spawn_blocking("files", move || work(&source))
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

    /// One folder from what the session's account may make (`[limits]
    /// folders`): a folder upload that runs past it ends, keeping what
    /// arrived for a resume to finish.
    fn folder_reserve(&self) -> Result<(), FileError> {
        self.core
            .folder_reserve(self.principal.uid)
            .map_err(|_| FileError::Unavailable("made folders faster than allowed".into()))
    }

    fn folder_refund(&self) {
        self.core.folder_refund(self.principal.uid);
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
                set_avatar: false,
                moderate: false,
                can_spam: false,
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

    #[tokio::test]
    async fn a_folder_download_flushes_before_it_waits_for_the_client() {
        // A sealed transfer or the tunnel holds a write until it is flushed,
        // as a buffered writer does; the client answers only what arrived.
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), "ab").unwrap();
        let source = Arc::new(LocalFileSource::open(temp.path(), Default::default()).unwrap());
        let core = Arc::new(Core::new());
        let principal = attach(&core);
        let file = crate::FolderFile {
            path: FilePath::root().join("a.txt").unwrap(),
            wire_name: b"a.txt".to_vec(),
            type_code: *b"TEXT",
            creator: *b"ttxt",
            wire_comment: Vec::new(),
            created: 0,
            modified: 0,
            data_len: 2,
            resource_len: 0,
        };
        let folder = PreparedFolder {
            principal,
            account: "reader".into(),
            peer: None,
            hope: None,
            source,
            large: false,
            fits: true,
            items: vec![FolderItem {
                path: vec![b"a.txt".to_vec()],
                file: Some(file),
            }]
            .into(),
        };
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let alive = Liveness::new(core.clone(), principal);
        let idle = Duration::from_secs(5);
        let served = tokio::spawn(async move {
            serve_folder(tokio::io::BufWriter::new(near), folder, &alive, idle).await
        });
        let wait = Duration::from_secs(2);
        for action in [folder::ACTION_NEXT, folder::ACTION_SEND] {
            far.write_all(&action.to_be_bytes()).await.unwrap();
            let mut answer = [0; 2];
            tokio::time::timeout(wait, far.read_exact(&mut answer))
                .await
                .expect("the answer is flushed before the server waits")
                .unwrap();
        }
        far.write_all(&folder::ACTION_NEXT.to_be_bytes())
            .await
            .unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(wait, far.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.windows(2).any(|w| w == b"ab"));
        served.await.unwrap().unwrap();
    }
}
