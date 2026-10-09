//! HOPE, the secure login, on the classic wire (`docs/hope.md`): the
//! adaptors a connection's socket halves run through, which pass bytes as
//! they are until a HOPE login agrees a transport, and the handshake's
//! two steps.
//!
//! The halves go into the slots the moment the password verifies, before
//! the reply to step 2 is queued, so that reply and everything after it
//! is encoded. Nothing queued earlier is still waiting by then: the only
//! frame before it is the reply to step 1, which the client has read, or
//! it would not have sent step 2. The reader's slot is filled at the same
//! moment, and the client sends nothing encoded until it has the reply.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::encoding::TextEncoding;

/// Where a connection's transport goes once a HOPE login agrees one.
#[derive(Clone, Default)]
pub(crate) struct Slots {
    send: Arc<Mutex<Option<hxhope::Sender>>>,
    recv: Arc<Mutex<Option<hxhope::Receiver>>>,
}

impl Slots {
    pub(crate) fn install(&self, transport: hxhope::Transport) {
        let (send, recv) = transport.split();
        *self.recv.lock().unwrap() = Some(recv);
        *self.send.lock().unwrap() = Some(send);
    }

    pub(crate) fn reader<R>(&self, inner: R) -> HopeRead<R> {
        HopeRead {
            inner,
            slot: self.recv.clone(),
            plain: Vec::new(),
            at: 0,
            raw: vec![0; 16 << 10].into_boxed_slice(),
        }
    }

    pub(crate) fn writer<W>(&self, inner: W) -> HopeWrite<W> {
        HopeWrite {
            inner,
            slot: self.send.clone(),
            pending: Vec::new(),
            at: 0,
        }
    }
}

fn broken(e: hxhope::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

pub(crate) struct HopeRead<R> {
    inner: R,
    slot: Arc<Mutex<Option<hxhope::Receiver>>>,
    /// Decoded and not yet read.
    plain: Vec<u8>,
    at: usize,
    raw: Box<[u8]>,
}

impl<R: AsyncRead + Unpin> AsyncRead for HopeRead<R> {
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
                if this.at == this.plain.len() {
                    this.plain.clear();
                    this.at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.slot.lock().unwrap().is_none() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut raw = ReadBuf::new(&mut this.raw);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut raw))?;
            if raw.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            let mut slot = this.slot.lock().unwrap();
            let recv = slot.as_mut().expect("a slot is never emptied");
            recv.decode(raw.filled(), &mut this.plain).map_err(broken)?;
        }
    }
}

pub(crate) struct HopeWrite<W> {
    inner: W,
    slot: Arc<Mutex<Option<hxhope::Sender>>>,
    /// Encoded and not yet written.
    pending: Vec<u8>,
    at: usize,
}

impl<W: AsyncWrite + Unpin> HopeWrite<W> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.at < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.at..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.at += n;
        }
        self.pending.clear();
        self.at = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HopeWrite<W> {
    /// Under a transport, `buf` is encoded whole, as one unit, and taken
    /// at once: the writer hands over whole transactions, which is what a
    /// Blowfish transport's rekey markers are placed by.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        let encoded = match this.slot.lock().unwrap().as_mut() {
            None => None,
            Some(send) => Some(send.encode(buf).map_err(broken)?),
        };
        let Some(encoded) = encoded else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };
        this.pending = encoded;
        // Taken whether or not it all went: what is left goes at the next
        // write or flush.
        if let Poll::Ready(Err(e)) = this.drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
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

/// A HOPE login past step 2: what checks its password, and what the check
/// agrees.
pub(crate) struct Handshake {
    server: hxhope::server::Server,
    step2: hxhope::server::Step2,
    agreed: Mutex<Option<(hxhope::Transport, hxhope::Negotiated)>>,
}

impl Handshake {
    pub(crate) fn new(server: hxhope::server::Server, step2: hxhope::server::Step2) -> Self {
        Handshake {
            server,
            step2,
            agreed: Mutex::new(None),
        }
    }

    /// Which of `logins` step 2 names, as the client would have typed it
    /// in `enc`: `Some("")` for the guest, `None` for none of them.
    pub(crate) fn resolve(&self, logins: &[String], enc: TextEncoding) -> Option<String> {
        if self.step2.names(&self.server, b"") {
            return Some(String::new());
        }
        logins
            .iter()
            .find(|l| self.step2.names(&self.server, &enc.encode(l)))
            .cloned()
    }

    /// Whether step 2's MAC is of `stored`, the account's password as the
    /// client would have typed it in `enc`; if so, the transport it
    /// agrees is kept for [`Handshake::agreed`].
    pub(crate) fn check(&self, stored: &str, enc: TextEncoding) -> bool {
        let random: hxhope::Random = Box::new(|b: &mut [u8]| {
            getrandom::getrandom(b).expect("the OS CSPRNG");
        });
        match self
            .server
            .clone()
            .accept(&self.step2, &enc.encode(stored), random)
        {
            Ok(agreed) => {
                *self.agreed.lock().unwrap() = Some(agreed);
                true
            }
            Err(_) => false,
        }
    }

    pub(crate) fn agreed(&self) -> Option<(hxhope::Transport, hxhope::Negotiated)> {
        self.agreed.lock().unwrap().take()
    }
}
