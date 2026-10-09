//! A file transfer of a session that agreed HOPE's ChaCha20-Poly1305
//! (`docs/hope.md` §5): past the HTXF preamble, everything both ways is
//! in sealed records, under keys derived from the session's and the
//! transfer's reference, as GtkHx's client seals them.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use hxcrypto::aead::{AeadState, AEAD_LENGTH_PREFIX, AEAD_TAG_SIZE};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most plaintext one incoming record may carry. The format allows
/// 16 MiB, which a transfer would hold in memory before it could check
/// the record; GtkHx seals 60 KiB at a time.
const MAX_RECORD: usize = 1 << 20;

pub(crate) struct Sealed<S> {
    inner: S,
    seal: AeadState,
    open: AeadState,
    /// The record being read, its length prefix first, sized once for the
    /// whole of it, and how much of it has arrived.
    framed: Vec<u8>,
    filled: usize,
    /// Opened and not yet read.
    plain: Vec<u8>,
    at: usize,
    /// Sealed and not yet written.
    pending: Vec<u8>,
    sent: usize,
}

impl<S> Sealed<S> {
    pub(crate) fn new(inner: S, keys: &hxhope::TransferKeys, reference: u32) -> Self {
        let (to_server, to_client) = keys.transfer(reference);
        Sealed {
            inner,
            seal: to_client,
            open: to_server,
            framed: Vec::new(),
            filled: 0,
            plain: Vec::new(),
            at: 0,
            pending: Vec::new(),
            sent: 0,
        }
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("sealed transfer: {what}"),
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for Sealed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.at < this.plain.len() {
                let n = (this.plain.len() - this.at).min(buf.remaining());
                buf.put_slice(&this.plain[this.at..this.at + n]);
                this.at += n;
                return Poll::Ready(Ok(()));
            }
            let need = if this.filled < AEAD_LENGTH_PREFIX {
                AEAD_LENGTH_PREFIX
            } else {
                let size = AeadState::peek_frame_size(&this.framed[..this.filled])
                    .ok_or_else(|| invalid("a record of impossible length"))?;
                if size
                    .checked_sub(AEAD_LENGTH_PREFIX + AEAD_TAG_SIZE)
                    .is_none_or(|plain| plain > MAX_RECORD)
                {
                    return Poll::Ready(Err(invalid("a record too large")));
                }
                size
            };
            if this.filled == need && need > AEAD_LENGTH_PREFIX {
                this.plain
                    .resize(need - AEAD_LENGTH_PREFIX - AEAD_TAG_SIZE, 0);
                this.open
                    .open(&this.framed[..need], &mut this.plain)
                    .ok_or_else(|| invalid("a record that does not authenticate"))?;
                (this.filled, this.at) = (0, 0);
                continue;
            }
            // Grown once a record, not once a read: a record trickled in a
            // byte at a time must not cost a megabyte's fill each time.
            if this.framed.len() < need {
                this.framed.resize(need, 0);
            }
            let start = this.filled;
            let mut into = ReadBuf::new(&mut this.framed[start..need]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut into))?;
            let n = into.filled().len();
            this.filled += n;
            if n == 0 {
                return Poll::Ready(match start {
                    0 => Ok(()),
                    _ => Err(io::ErrorKind::UnexpectedEof.into()),
                });
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> Sealed<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Sealed<S> {
    /// One record per call, of what fits in one: taken at once, and
    /// written by the next call or flush if the socket is full.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_RECORD);
        this.pending
            .resize(AEAD_LENGTH_PREFIX + n + AEAD_TAG_SIZE, 0);
        this.seal
            .seal(&buf[..n], &mut this.pending)
            .ok_or_else(|| invalid("a record that does not seal"))?;
        if let Poll::Ready(Err(e)) = this.drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Both ends' transfer keys, from a ChaCha20-Poly1305 HOPE login run
    /// between hxhope's client and server.
    fn keys() -> (hxhope::TransferKeys, hxhope::TransferKeys) {
        use hxhope::{client, server, Cipher, Mac};
        let offer = client::Offer {
            ciphers: vec![Cipher::ChaCha20Poly1305],
            ..client::Offer::new(*b"TEST")
        };
        let policy = server::Policy {
            macs: Mac::ALL.to_vec(),
            ciphers: vec![Cipher::ChaCha20Poly1305],
            compressions: vec![],
            require_cipher: true,
        };
        let who = client::Login {
            login: b"",
            password: b"pw",
            name: b"",
            icon: 0,
            version: 0,
            caps: 0,
        };
        let step1 = client::step1(&offer, 1).unwrap();
        let (srv, reply) = server::answer(&policy, &step1, [7; 64], 1).unwrap();
        let est = client::step2(&offer, &reply, &who, 2, Box::new(|_: &mut [u8]| {})).unwrap();
        let step2 = srv.step2(&est.step2).unwrap();
        let (_, agreed) = srv
            .accept(&step2, b"pw", Box::new(|_: &mut [u8]| {}))
            .unwrap();
        (
            est.negotiated.transfer_keys.unwrap(),
            agreed.transfer_keys.unwrap(),
        )
    }

    /// `plain` sealed as a client seals it, one record per piece.
    fn sealed_by_client(state: &mut AeadState, pieces: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for piece in pieces {
            let mut record = vec![0; AEAD_LENGTH_PREFIX + piece.len() + AEAD_TAG_SIZE];
            state.seal(piece, &mut record).unwrap();
            wire.extend(record);
        }
        wire
    }

    #[tokio::test]
    async fn a_transfer_is_sealed_both_ways_under_its_own_keys() {
        let (client, server) = keys();
        let (near, mut far) = tokio::io::duplex(1 << 20);
        let mut sealed = Sealed::new(near, &server, 42);
        let (mut to_server, mut to_client) = client.transfer(42);

        // An upload, cut anywhere on the wire, read whole.
        let wire = sealed_by_client(&mut to_server, &[b"one ", b"", b"two"]);
        for piece in wire.chunks(5) {
            far.write_all(piece).await.unwrap();
        }
        let mut got = vec![0; 7];
        sealed.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"one two");

        // A download, opened with the client's key for its direction.
        sealed.write_all(b"hello").await.unwrap();
        sealed.flush().await.unwrap();
        let mut record = vec![0; AEAD_LENGTH_PREFIX + 5 + AEAD_TAG_SIZE];
        far.read_exact(&mut record).await.unwrap();
        let mut plain = [0; 5];
        to_client.open(&record, &mut plain).unwrap();
        assert_eq!(&plain, b"hello");

        // Another transfer's keys open nothing of this one's.
        let (mut other, _) = client.transfer(43);
        let wire = sealed_by_client(&mut other, &[b"x"]);
        far.write_all(&wire).await.unwrap();
        assert!(sealed.read(&mut [0; 1]).await.is_err());
    }

    #[tokio::test]
    async fn a_record_past_the_cap_or_cut_short_is_refused() {
        let (_, server) = keys();
        let (near, mut far) = tokio::io::duplex(64);
        let mut sealed = Sealed::new(near, &server, 1);
        let too_large = (AEAD_LENGTH_PREFIX + MAX_RECORD + 1 + AEAD_TAG_SIZE) as u32;
        far.write_all(&too_large.to_be_bytes()).await.unwrap();
        assert!(sealed.read(&mut [0; 1]).await.is_err());

        let (near, mut far) = tokio::io::duplex(64);
        let mut sealed = Sealed::new(near, &server, 1);
        far.write_all(&[0, 0, 0, 40, 1, 2]).await.unwrap();
        drop(far);
        let cut = sealed.read(&mut [0; 1]).await.unwrap_err();
        assert_eq!(cut.kind(), io::ErrorKind::UnexpectedEof);
    }
}
