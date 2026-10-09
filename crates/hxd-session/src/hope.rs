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
//! moment, and the client sends nothing encoded until it has the reply;
//! one that does is dropped as malformed, as on mhxd.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::encoding::TextEncoding;

/// Where a connection's transport goes once a HOPE login agrees one.
#[derive(Clone, Default)]
pub(crate) struct Slots {
    send: Arc<Mutex<Option<hxhope::Sender>>>,
    recv: Arc<Mutex<Option<hxhope::Receiver>>>,
    /// Bytes read as they are, before a transport.
    passed: Arc<AtomicUsize>,
}

impl Slots {
    /// Install `transport` if exactly `read` bytes came before it: the
    /// two steps of the handshake. Anything more was sent after step 2
    /// without waiting for its reply, in the clear, and someone on the
    /// path could have put it there; it is refused, not run as the
    /// session's.
    pub(crate) fn install(&self, transport: hxhope::Transport, read: usize) -> bool {
        let mut recv = self.recv.lock().unwrap();
        if self.passed.load(Ordering::Acquire) != read {
            return false;
        }
        let (send, received) = transport.split();
        *recv = Some(received);
        *self.send.lock().unwrap() = Some(send);
        true
    }

    pub(crate) fn reader<R>(&self, inner: R) -> HopeRead<R> {
        HopeRead {
            inner,
            slot: self.recv.clone(),
            passed: self.passed.clone(),
            plain: Vec::new(),
            at: 0,
            raw: Vec::new(),
        }
    }

    pub(crate) fn writer<W>(&self, inner: W) -> HopeWrite<W> {
        HopeWrite {
            inner,
            slot: self.send.clone(),
            pending: Vec::new(),
            sent: 0,
            owed: 0,
            credited: 0,
        }
    }
}

fn broken(e: hxhope::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// What the transport would not encode, which no retry can send.
#[derive(Debug)]
pub(crate) struct Unencodable(hxhope::Error);

impl std::fmt::Display for Unencodable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Unencodable {}

/// Past this, a drained plaintext buffer is let go rather than kept: one
/// read can decompress to megabytes, and a connection should not hold
/// them for its life.
const KEEP: usize = 64 << 10;

pub(crate) struct HopeRead<R> {
    inner: R,
    slot: Arc<Mutex<Option<hxhope::Receiver>>>,
    passed: Arc<AtomicUsize>,
    /// Decoded and not yet read.
    plain: Vec<u8>,
    at: usize,
    /// Allocated with the transport: a connection with none needs none.
    raw: Vec<u8>,
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
                    if this.plain.capacity() > KEEP {
                        this.plain = Vec::new();
                    } else {
                        this.plain.clear();
                    }
                    this.at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            {
                // Held across the read, so a transport cannot be installed
                // between finding none and reading what it would decode.
                let slot = this.slot.lock().unwrap();
                if slot.is_none() {
                    let before = buf.filled().len();
                    let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
                    this.passed
                        .fetch_add(buf.filled().len() - before, Ordering::Release);
                    return polled;
                }
            }
            if this.raw.is_empty() {
                this.raw.resize(16 << 10, 0);
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
    /// The encoding of the plaintext being written, and how much of it
    /// has gone.
    pending: Vec<u8>,
    sent: usize,
    /// That plaintext's length, and how much of it has been reported
    /// written: in proportion to what has gone, so a caller timing its
    /// writes by their progress sees progress as the socket takes the
    /// encoding.
    owed: usize,
    credited: usize,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HopeWrite<W> {
    /// Under a transport, a `buf` the writer has not been handed before
    /// is encoded whole, as one unit: the writer hands over whole
    /// transactions, several at a time, which is what a Blowfish
    /// transport's rekey markers are placed by. The calls that follow it,
    /// with what is left of `buf`, write its encoding.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.owed == 0 {
            let encoded = match this.slot.lock().unwrap().as_mut() {
                None => None,
                Some(send) => Some(
                    send.encode(buf)
                        .map_err(|e| io::Error::other(Unencodable(e)))?,
                ),
            };
            let Some(encoded) = encoded else {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            };
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            (this.pending, this.sent, this.owed, this.credited) = (encoded, 0, buf.len(), 0);
        }
        loop {
            let target = if this.sent == this.pending.len() {
                this.owed
            } else {
                let share = this.sent as u128 * this.owed as u128 / this.pending.len() as u128;
                (share as usize).min(this.owed - 1)
            };
            if target > this.credited {
                let n = target - this.credited;
                this.credited = target;
                if this.credited == this.owed {
                    this.pending.clear();
                    (this.sent, this.owed, this.credited) = (0, 0, 0);
                }
                return Poll::Ready(Ok(n));
            }
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.sent += n;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// What a HOPE login agreed, once its password checked.
pub(crate) struct Agreed {
    pub(crate) transport: hxhope::Transport,
    pub(crate) negotiated: hxhope::Negotiated,
    /// The password was empty, so the keys are anyone's who watched the
    /// handshake, whatever cipher runs on them.
    pub(crate) keyless: bool,
}

/// A HOPE login past step 2: what checks its password, and what the check
/// agrees.
pub(crate) struct Handshake {
    server: hxhope::server::Server,
    step2: hxhope::server::Step2,
    agreed: Mutex<Option<Agreed>>,
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
    /// agrees is kept for [`Handshake::agreed`]. A password `enc` cannot
    /// write is refused: written, its characters would be `?`, and a
    /// Cyrillic password would open to as many question marks.
    pub(crate) fn check(&self, stored: &str, enc: TextEncoding) -> bool {
        let typed = enc.encode(stored);
        if enc.decode(&typed) != stored {
            return false;
        }
        let random: hxhope::Random = Box::new(|b: &mut [u8]| {
            getrandom::getrandom(b).expect("the OS CSPRNG");
        });
        match self.server.clone().accept(&self.step2, &typed, random) {
            Ok((transport, negotiated)) => {
                *self.agreed.lock().unwrap() = Some(Agreed {
                    transport,
                    negotiated,
                    keyless: stored.is_empty(),
                });
                true
            }
            Err(_) => false,
        }
    }

    /// Whether step 2's password is empty: no guess, whichever account
    /// it names, as on the plain login.
    pub(crate) fn empty_password(&self) -> bool {
        let none: hxhope::Random = Box::new(|_: &mut [u8]| {});
        self.server.clone().accept(&self.step2, b"", none).is_ok()
    }

    pub(crate) fn agreed(&self) -> Option<Agreed> {
        self.agreed.lock().unwrap().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Both ends' transports, from a Blowfish HOPE login run between
    /// hxhope's client and server.
    fn transports() -> (hxhope::Transport, hxhope::Transport) {
        use hxhope::{client, server, Cipher, Mac};
        let offer = client::Offer {
            ciphers: vec![Cipher::Blowfish],
            ..client::Offer::new(*b"TEST")
        };
        let policy = server::Policy {
            macs: Mac::ALL.to_vec(),
            ciphers: vec![Cipher::Blowfish],
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
        let (srv, reply) = server::answer(&policy, &step1, [3; 64], 1).unwrap();
        let est = client::step2(&offer, &reply, &who, 2, Box::new(|_: &mut [u8]| {})).unwrap();
        let step2 = srv.step2(&est.step2).unwrap();
        let (server, _) = srv
            .accept(&step2, b"pw", Box::new(|_: &mut [u8]| {}))
            .unwrap();
        (est.transport, server)
    }

    fn frames(n: u32) -> Vec<u8> {
        (0..n)
            .flat_map(|i| crate::frame::pack_frame(105, i, 0, &[(101, vec![i as u8; 900])]))
            .collect()
    }

    #[tokio::test]
    async fn a_write_under_a_transport_reports_progress_as_its_encoding_goes() {
        let (mut client, server) = transports();
        let slots = Slots::default();
        let (near, mut far) = tokio::io::duplex(1024);
        let mut wr = slots.writer(near);
        assert!(slots.install(server, 0));
        let sent = frames(40);
        // The socket takes a kilobyte at a time, so the first write is
        // reported short, as a plain socket's would be.
        let first = wr.write(&sent).await.unwrap();
        assert!(first > 0 && first < sent.len(), "{first}");
        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            far.read_to_end(&mut wire).await.unwrap();
            wire
        });
        wr.write_all(&sent[first..]).await.unwrap();
        wr.shutdown().await.unwrap();
        drop(wr);
        let mut got = Vec::new();
        client.decode(&reader.await.unwrap(), &mut got).unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn reads_pass_through_until_a_transport_is_installed_after_them() {
        let (mut client, server) = transports();
        let slots = Slots::default();
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut rd = slots.reader(near);
        far.write_all(b"plain").await.unwrap();
        let mut got = [0; 5];
        rd.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"plain");
        // Installed only after exactly what the handshake was read.
        let (_, spare) = transports();
        assert!(!slots.install(spare, 4));
        assert!(slots.install(server, 5));
        let sent = frames(3);
        far.write_all(&client.encode(&sent).unwrap()).await.unwrap();
        let mut got = vec![0; sent.len()];
        rd.read_exact(&mut got).await.unwrap();
        assert_eq!(got, sent);
    }
}
