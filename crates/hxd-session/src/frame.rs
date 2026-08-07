//! Transaction framing over a byte stream.
//!
//! The 22-byte header layout (`type`/`trans`/`flag`/`len`/`len2`/`hc`) and
//! all chunk encoding come from `hotline-proto` — the same code gtkhx frames
//! with, so the two ends can never disagree by drift.
//!
//! The read side frames by **`len2` (DataSize), not `len` (TotalSize)** —
//! the distinction only matters for fragmenting senders, but it cost gtkhx a
//! real desync to learn, so the server starts on the right field. No known
//! client fragments requests; a frame whose `len` disagrees with `len2` is
//! rejected rather than half-understood.

use hotline_proto::build::pack_header;
use hotline_proto::wire::ChunkIter;
use hotline_proto::{HL_DATA_HDR_LEN, HL_HDR_LEN};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Hard cap on a transaction's data size — mhxd's `MAX_HOTLINE_PACKET_LEN`.
/// Anything larger is a hostile or broken client.
pub const MAX_FRAME_DATA: u32 = 0x40000;

/// A received transaction. `buf` holds header + body contiguously so
/// `hotline-proto`'s [`ChunkIter`] can walk it in place.
#[derive(Debug)]
pub struct Frame {
    pub ty: u32,
    pub trans: u32,
    pub flag: u32,
    pub hc: u16,
    buf: Vec<u8>,
}

impl Frame {
    /// Iterate the data chunks.
    pub fn chunks(&self) -> ChunkIter<'_> {
        ChunkIter::over_message(&self.buf, self.buf.len())
    }
}

/// Why a read failed.
#[derive(Debug)]
pub enum ReadError {
    /// Clean EOF at a frame boundary — the peer hung up.
    Eof,
    Io(std::io::Error),
    /// The header violates the protocol (oversized, len/len2 mismatch).
    Malformed(String),
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadError::Eof
        } else {
            ReadError::Io(e)
        }
    }
}

/// Read one transaction.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, ReadError> {
    let mut hdr = [0u8; HL_HDR_LEN];
    // Distinguish "EOF before any byte" (clean close) from a torn header.
    if r.read(&mut hdr[..1]).await? == 0 {
        return Err(ReadError::Eof);
    }
    r.read_exact(&mut hdr[1..]).await?;

    let ty = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
    let trans = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
    let flag = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
    let len = u32::from_be_bytes(hdr[12..16].try_into().unwrap());
    let len2 = u32::from_be_bytes(hdr[16..20].try_into().unwrap());
    let hc = u16::from_be_bytes(hdr[20..22].try_into().unwrap());

    if len2 > MAX_FRAME_DATA {
        return Err(ReadError::Malformed(format!(
            "data size {len2:#x} exceeds cap {MAX_FRAME_DATA:#x}"
        )));
    }
    if len != len2 {
        // Clients never fragment; see module docs.
        return Err(ReadError::Malformed(format!(
            "fragmented frame from client (len {len:#x} != len2 {len2:#x})"
        )));
    }

    // len2 counts the body plus the 2-byte `hc` that physically sits at the
    // header's tail; body bytes still to read = len2 - 2.
    let body_len = len2.saturating_sub(2) as usize;
    let mut buf = Vec::with_capacity(HL_HDR_LEN + body_len);
    buf.extend_from_slice(&hdr);
    buf.resize(HL_HDR_LEN + body_len, 0);
    r.read_exact(&mut buf[HL_HDR_LEN..]).await?;

    Ok(Frame {
        ty,
        trans,
        flag,
        hc,
        buf,
    })
}

/// Pack a full outgoing transaction. No chunk-count limit (a user-list
/// reply carries one chunk per user), hence not `pack_message` — but the
/// header bytes come from the same `pack_header` gtkhx uses.
pub fn pack_frame(ty: u32, trans: u32, flag: u32, chunks: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let body_len: usize = chunks.iter().map(|(_, d)| HL_DATA_HDR_LEN + d.len()).sum();
    let mut out = vec![0u8; HL_HDR_LEN];
    pack_header(
        &mut out,
        ty,
        trans,
        flag,
        chunks.len() as u16,
        body_len as u32,
    );
    for (tag, data) in chunks {
        assert!(
            data.len() <= u16::MAX as usize,
            "chunk payload exceeds u16 length"
        );
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrips_through_pack_and_read() {
        let bytes = pack_frame(
            0x0000_006b,
            7,
            0,
            &[(0x0066, b"misha".to_vec()), (0x0068, vec![0x00, 0x91])],
        );
        let mut cur = bytes.as_slice();
        let f = read_frame(&mut cur).await.unwrap();
        assert_eq!((f.ty, f.trans, f.flag, f.hc), (0x6b, 7, 0, 2));
        let chunks: Vec<_> = f.chunks().collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].tag, 0x0066);
        assert_eq!(chunks[0].data, b"misha");
        assert_eq!(chunks[1].as_uint(), 0x91);
    }

    #[tokio::test]
    async fn empty_body_frame_is_fine() {
        let bytes = pack_frame(0x0001_0000, 3, 0, &[]);
        // len/len2 must be 2 (just the hc tail) for an empty reply.
        assert_eq!(&bytes[12..16], &[0, 0, 0, 2]);
        let mut cur = bytes.as_slice();
        let f = read_frame(&mut cur).await.unwrap();
        assert_eq!(f.chunks().count(), 0);
    }

    #[tokio::test]
    async fn oversized_and_fragmented_frames_are_rejected() {
        let mut bytes = pack_frame(0x69, 1, 0, &[]);
        bytes[16..20].copy_from_slice(&(MAX_FRAME_DATA + 1).to_be_bytes());
        let mut cur = bytes.as_slice();
        assert!(matches!(
            read_frame(&mut cur).await,
            Err(ReadError::Malformed(_))
        ));

        let mut bytes = pack_frame(0x69, 1, 0, &[]);
        bytes[12..16].copy_from_slice(&99u32.to_be_bytes());
        let mut cur = bytes.as_slice();
        assert!(matches!(
            read_frame(&mut cur).await,
            Err(ReadError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn clean_eof_vs_torn_header() {
        let mut cur: &[u8] = &[];
        assert!(matches!(read_frame(&mut cur).await, Err(ReadError::Eof)));
        let mut cur: &[u8] = &[0x00, 0x01];
        assert!(matches!(read_frame(&mut cur).await, Err(ReadError::Eof)));
    }
}
