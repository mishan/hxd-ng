use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::{ffo, htxf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::{
    LocalFileSource, PreparedDownload, PreparedTransfer, PreparedUpload, TransferRegistry,
    UploadQuote,
};

pub struct LegacyTransfer {
    pub principal: FilePrincipal,
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
    pub path: FilePath,
    pub owner: String,
    pub transfer_len: u64,
    pub large: bool,
    pub resume_requested: bool,
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
    if quote.as_ref().is_some_and(|value| {
        value.data_offset.saturating_add(value.resource_offset) > request.transfer_len
    }) {
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
        path: request.path,
        source,
        owner: request.owner,
        transfer_len: request.transfer_len,
        large: request.large,
        quote: quote.clone(),
    }))?;
    Ok((reference, quote))
}

pub async fn serve_htxf(
    listener: TcpListener,
    registry: Arc<TransferRegistry>,
    core: Arc<Core>,
    handshake_timeout: Duration,
) -> std::io::Result<()> {
    const MAX_HTXF_CONNECTIONS: usize = 256;
    let connection_slots = Arc::new(Semaphore::new(MAX_HTXF_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match connection_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(%peer, "HTXF connection refused while transfer capacity is full");
                continue;
            }
        };
        let registry = registry.clone();
        let core = core.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_one(stream, &registry, &core, handshake_timeout).await {
                debug!(%peer, %error, "HTXF transfer refused");
            }
        });
    }
}

async fn serve_one(
    mut stream: TcpStream,
    registry: &TransferRegistry,
    core: &Core,
    handshake_timeout: Duration,
) -> Result<(), FileError> {
    let mut base = [0; htxf::BASE_LEN];
    tokio::time::timeout(handshake_timeout, stream.read_exact(&mut base))
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
            handshake_timeout,
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
    let transfer = registry.claim(core, &preamble)?;
    match transfer {
        PreparedTransfer::Download(transfer) => serve_download(stream, transfer).await,
        PreparedTransfer::Upload(transfer) => {
            let timeout = transfer.source.limits().upload_timeout;
            tokio::time::timeout(timeout, serve_upload(stream, transfer, preamble))
                .await
                .map_err(|_| FileError::Unavailable("upload exceeded its time limit".into()))?
        }
    }
}

async fn serve_download(
    mut stream: TcpStream,
    transfer: PreparedDownload,
) -> Result<(), FileError> {
    let body = transfer
        .source
        .open(&transfer.path, transfer.offset)
        .await?;
    if body.len != transfer.encoded.data_remaining {
        return Err(FileError::OriginChanged);
    }
    stream
        .write_all(&transfer.encoded.prefix)
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    let expected = body.len;
    let mut reader = body.reader.take(expected);
    let copied = tokio::io::copy(&mut reader, &mut stream)
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    if copied != expected {
        warn!(copied, expected, "origin ended before its manifest length");
        return Err(FileError::OriginChanged);
    }
    drop(reader);
    stream
        .write_all(&transfer.encoded.resource_header)
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    if transfer.encoded.resource_remaining != 0 {
        let resource = transfer
            .source
            .open_resource(&transfer.path, transfer.resource_offset)
            .await?;
        if resource.len != transfer.encoded.resource_remaining {
            return Err(FileError::OriginChanged);
        }
        let expected = resource.len;
        let mut reader = resource.reader.take(expected);
        let copied = tokio::io::copy(&mut reader, &mut stream)
            .await
            .map_err(|e| FileError::Unavailable(e.to_string()))?;
        if copied != expected {
            return Err(FileError::OriginChanged);
        }
    }
    stream
        .shutdown()
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}

async fn serve_upload(
    mut stream: TcpStream,
    transfer: PreparedUpload,
    preamble: htxf::Preamble,
) -> Result<(), FileError> {
    let _permit = transfer.source.acquire_io_permit().await?;
    let fresh = transfer.quote.is_none();
    let begin_source = transfer.source.clone();
    let owner = transfer.owner.clone();
    let path = transfer.path.clone();
    let reserve = transfer.transfer_len;
    let mut files = tokio::task::spawn_blocking(move || {
        begin_source.begin_upload(&owner, &path, fresh, reserve)
    })
    .await
    .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))??;
    if let Some(quote) = transfer.quote.clone() {
        let check_source = transfer.source.clone();
        files = tokio::task::spawn_blocking(move || {
            check_source.recheck_resume(&files, &quote)?;
            Ok::<_, FileError>(files)
        })
        .await
        .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))??;
    }
    let result = if transfer.large {
        receive_large(&mut stream, &transfer, &preamble, &files).await
    } else {
        receive_legacy(&mut stream, &transfer, &preamble, &files).await
    };
    match result {
        Ok(hfs) => {
            let publish_source = transfer.source.clone();
            let path = transfer.path.clone();
            tokio::task::spawn_blocking(move || publish_source.publish_upload(&path, &files, &hfs))
                .await
                .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))?
        }
        Err(error) => Err(error),
    }
}

async fn receive_large(
    stream: &mut TcpStream,
    transfer: &PreparedUpload,
    preamble: &htxf::Preamble,
    files: &crate::local::UploadFiles,
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
        transfer.source.limits().io_timeout,
    )
    .await?;
    output
        .sync_all()
        .await
        .map_err(|error| unavailable("sync uploaded data", error))?;
    Ok(hxhfs::HfsInfo::default())
}

async fn receive_legacy(
    stream: &mut TcpStream,
    transfer: &PreparedUpload,
    preamble: &htxf::Preamble,
    files: &crate::local::UploadFiles,
) -> Result<hxhfs::HfsInfo, FileError> {
    let timeout = transfer.source.limits().io_timeout;
    let mut fixed = [0; ffo::FFO_HEADER_LEN + ffo::FORK_HEADER_LEN];
    read_exact_timeout(stream, &mut fixed, timeout).await?;
    if &fixed[..4] != b"FILP" || fixed[4..6] != 1u16.to_be_bytes() || fixed[6..22] != [0; 16] {
        return Err(FileError::InvalidPath);
    }
    let fork_count = u16::from_be_bytes(fixed[22..24].try_into().expect("two bytes"));
    if !matches!(fork_count, 2 | 3) {
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
    let mut info = vec![0; info_header.length as usize];
    read_exact_timeout(stream, &mut info, timeout).await?;
    let parsed = ffo::parse_info(&info).map_err(|_| FileError::InvalidPath)?;
    let mut data_header = [0; ffo::FORK_HEADER_LEN];
    read_exact_timeout(stream, &mut data_header, timeout).await?;
    let data_header =
        ffo::parse_fork_header(&data_header, false).map_err(|_| FileError::InvalidPath)?;
    if &data_header.tag != b"DATA" {
        return Err(FileError::InvalidPath);
    }
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
    copy_exact(stream, &mut data, data_header.length, timeout).await?;

    let consumed =
        fixed.len() as u64 + info.len() as u64 + ffo::FORK_HEADER_LEN as u64 + data_header.length;
    let mut resource_header = [0; ffo::FORK_HEADER_LEN];
    read_exact_timeout(stream, &mut resource_header, timeout).await?;
    let resource_header =
        ffo::parse_fork_header(&resource_header, false).map_err(|_| FileError::InvalidPath)?;
    if &resource_header.tag != b"MACR" || (fork_count == 3) != (resource_header.length != 0) {
        return Err(FileError::InvalidPath);
    }
    let resource_offset = transfer
        .quote
        .as_ref()
        .map_or(0, |quote| quote.resource_offset);
    let resource_len = resource_offset
        .checked_add(resource_header.length)
        .ok_or(FileError::TooLarge)?;
    if data_len.saturating_add(resource_len) > transfer.source.limits().max_file_size {
        return Err(FileError::TooLarge);
    }
    if resource_header.length != 0 {
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
        copy_exact(stream, &mut resource, resource_header.length, timeout).await?;
        resource
            .sync_all()
            .await
            .map_err(|error| unavailable("sync uploaded resource fork", error))?;
    }
    let consumed = consumed
        .checked_add(ffo::FORK_HEADER_LEN as u64)
        .and_then(|value| value.checked_add(resource_header.length))
        .ok_or(FileError::TooLarge)?;
    if consumed != preamble.transfer_len {
        return Err(FileError::InvalidPath);
    }
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

async fn copy_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    mut remaining: u64,
    timeout: Duration,
) -> Result<(), FileError> {
    let mut buffer = [0; 64 * 1024];
    while remaining != 0 {
        let want = remaining.min(buffer.len() as u64) as usize;
        let read = tokio::time::timeout(timeout, reader.read(&mut buffer[..want]))
            .await
            .map_err(|_| FileError::Unavailable("upload stalled".into()))?
            .map_err(|error| unavailable("read upload", error))?;
        if read == 0 {
            return Err(FileError::OriginChanged);
        }
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
