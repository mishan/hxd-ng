use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::{ffo, htxf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::{PreparedTransfer, TransferRegistry};

pub struct LegacyTransfer {
    pub principal: FilePrincipal,
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
        path: request.path,
        source,
        offset: request.offset,
        large: request.large,
        encoded,
        expires: std::time::Instant::now(),
    })?;
    Ok((reference, size))
}

pub async fn serve_htxf(
    listener: TcpListener,
    registry: Arc<TransferRegistry>,
    core: Arc<Core>,
    handshake_timeout: Duration,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let registry = registry.clone();
        let core = core.clone();
        tokio::spawn(async move {
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
    stream
        .write_all(&transfer.encoded.resource_header)
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    stream
        .shutdown()
        .await
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}
