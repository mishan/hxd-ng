//! The classic frontend's side of server linking (`docs/server-link.md`
//! §7.1): a login that sets capability bit 11 is a linked server, not a
//! user, and is handed to whatever implements [`PeerAcceptor`] before any
//! password is checked. This crate never holds a server key and knows
//! nothing of the link wire; it frames bytes and hands them over.

use hxd_core::server_link::{PeerRefusal, PEER_WAIT};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use hxd_core::ConnPermit;
use tokio::sync::mpsc::Receiver;

use crate::frame::Frame;
use crate::session::{enqueue, reader_task, writer_task, Backlog, Outbound, Tx, WRITER_FLUSH};

/// The TLS exporter a key-mode link proves its key over (RFC 8446
/// section 7.5), with an empty context. Here because it is this crate
/// that holds the TLS session; `hxd-link` signs over the value.
pub const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-hotline-link-key-proof";
pub const EXPORTER_LEN: usize = 32;

/// The login fields of a key-mode link (the extension's "The Key Proof").
pub mod field {
    pub const SERVER_KEY: u16 = 0x0640;
    pub const KEY_PROOF: u16 = 0x0641;
}

/// A link login, as far as the classic frontend read it.
pub struct LinkLogin {
    pub login: String,
    pub server_key: Option<[u8; 32]>,
    pub proof: Option<[u8; 64]>,
    /// The session's exporter value: present only on the TLS port, and
    /// only when TLS 1.3 was negotiated.
    pub exporter: Option<[u8; EXPORTER_LEN]>,
    /// Whether the login also asked for Text-Encoding (bit 1): every
    /// string on a link is UTF-8, so a link without it is refused.
    pub text_encoding: bool,
    pub addr: IpAddr,
}

/// A login the acceptor confirmed: the login reply to send, and whatever
/// it needs to take the link over.
pub struct LinkGrant {
    pub reply: Vec<(u16, Vec<u8>)>,
    pub state: Box<dyn std::any::Any + Send>,
}

/// A link session's connection, once the login reply has gone.
pub struct LinkIo {
    pub frames: Receiver<Frame>,
    pub out: LinkOut,
    /// The connection's place among its address's connections, held for
    /// as long as the link lasts. A link this server dialed has none.
    pub place: Option<ConnPermit>,
    pub peer: SocketAddr,
}

pub trait PeerAcceptor: Send + Sync + 'static {
    /// Confirm a link login or refuse it, with the text a refused login is
    /// given. Called before any password check, and never counted as a
    /// failed login.
    fn authorize(&self, login: LinkLogin) -> Result<LinkGrant, &'static str>;

    /// Run the link until it ends, returning why.
    fn accept(
        &self,
        grant: LinkGrant,
        io: LinkIo,
    ) -> Pin<Box<dyn Future<Output = &'static str> + Send + 'static>>;
}

/// What a TLS connection brings to a link login.
#[derive(Clone)]
pub(crate) struct LinkPort {
    pub(crate) acceptor: Arc<dyn PeerAcceptor>,
    pub(crate) exporter: Option<[u8; EXPORTER_LEN]>,
}

/// The writing half of a link session, over the connection's own writer,
/// with its bound: a link that stops reading is dropped like any client.
pub struct LinkOut(pub(crate) Tx);

impl LinkOut {
    /// A request this side originates, with its own task id.
    pub fn request(&self, ty: u32, trans: u32, chunks: Vec<(u16, Vec<u8>)>) {
        enqueue(&self.0, Outbound::Request { ty, trans, chunks });
    }

    /// A notification: task id 0, no reply.
    pub fn notify(&self, ty: u32, chunks: Vec<(u16, Vec<u8>)>) {
        enqueue(&self.0, Outbound::Notify { ty, chunks });
    }

    pub fn reply(&self, trans: u32, error: bool, chunks: Vec<(u16, Vec<u8>)>) {
        enqueue(
            &self.0,
            Outbound::Reply {
                trans,
                error,
                chunks,
            },
        );
    }

    /// Whether the peer has stopped keeping up, past which nothing more is
    /// queued.
    pub fn is_lagging(&self) -> bool {
        self.0.backlog.lagging.load(Ordering::Acquire)
    }

    /// Resolves once the peer has stopped keeping up.
    pub async fn lagged(&self) {
        loop {
            let woken = self.0.backlog.lagged.notified();
            if self.is_lagging() {
                return;
            }
            woken.await;
        }
    }
}

/// Frame a link this server dialed over the same reader and writer, held
/// to the same bound, as an accepted one. The dialer does the TRTP
/// handshake and the login itself, then hands the stream over.
pub fn dialed<S>(
    stream: S,
    peer: SocketAddr,
    budget: &Arc<hxd_core::QueueBudget>,
) -> (LinkIo, DialedLink)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(stream);
    let (out, out_rx) = tokio::sync::mpsc::unbounded_channel();
    let tx = Tx {
        out,
        backlog: Arc::new(Backlog::new(budget.share())),
    };
    let backlog = tx.backlog.clone();
    let writer = tokio::spawn(writer_task(wr, out_rx, backlog.clone()));
    let (frames_tx, frames) = tokio::sync::mpsc::channel(32);
    let reader = tokio::spawn(reader_task(rd, frames_tx));
    let io = LinkIo {
        frames,
        out: LinkOut(tx),
        place: None,
        peer,
    };
    (
        io,
        DialedLink {
            reader,
            writer,
            backlog,
        },
    )
}

/// The tasks behind a dialed link, ended once the link is.
pub struct DialedLink {
    reader: tokio::task::JoinHandle<&'static str>,
    writer: tokio::task::JoinHandle<()>,
    backlog: Arc<Backlog>,
}

impl DialedLink {
    /// What is queued is written, for a moment at most, as for an accepted
    /// connection, and not at all to a peer that stopped reading. The
    /// `LinkIo` must be gone, or the writer never ends.
    pub async fn close(self) {
        self.reader.abort();
        if self.backlog.lagging.load(Ordering::Acquire) {
            self.backlog.stop.notify_one();
        }
        if tokio::time::timeout(WRITER_FLUSH, self.writer)
            .await
            .is_err()
        {
            self.backlog.stop.notify_one();
        }
    }
}

/// The answer to an act on a user of another server, or `Unreachable`
/// once [`PEER_WAIT`] has passed without one.
pub async fn peer_answer<T>(
    answer: tokio::sync::oneshot::Receiver<Result<T, PeerRefusal>>,
) -> Result<T, PeerRefusal> {
    match tokio::time::timeout(PEER_WAIT, answer).await {
        Ok(Ok(result)) => result,
        _ => Err(PeerRefusal::Unreachable),
    }
}
