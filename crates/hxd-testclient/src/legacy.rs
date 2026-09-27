//! The classic wire: TRTP handshake, 22-byte-header transactions, the
//! 1.2/1.5 login and agreement, over plain TCP or TLS.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxproto::build::pack_header;
use hxproto::messages::{tag, ClientHdr};
use hxproto::parse::decode_header_full;
use hxproto::wire::{Chunk, ChunkIter};
use hxproto::{HL_DATA_HDR_LEN, HL_HDR_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::{Error, Result, DEFAULT_TIMEOUT};

/// A task reply's type. Replies echo the request's `trans`.
pub const TASK: u32 = 0x0001_0000;

/// Server pushes a client script usually waits for.
pub mod push {
    pub const CHAT: u32 = 0x6a;
    pub const MSG: u32 = 0x68;
    pub const AGREEMENT: u32 = 0x6d;
    pub const USER_CHANGE: u32 = 0x12d;
    pub const USER_PART: u32 = 0x12e;
    pub const SELFINFO: u32 = 0x162;
    pub const DISCONNECT_MSG: u32 = 0x6f;
}

/// The largest frame this client accepts: the server's own cap, with
/// room to spare. Anything bigger is a desync, not a message.
const MAX_FRAME: u32 = 1 << 24;

/// Anything the client can speak over.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One received transaction. `buf` holds the header and the body, so the
/// chunks are walked in place.
#[derive(Debug, Clone)]
pub struct Frame {
    pub ty: u32,
    pub trans: u32,
    pub flag: u32,
    pub hc: u16,
    buf: Vec<u8>,
}

impl Frame {
    pub fn chunks(&self) -> ChunkIter<'_> {
        ChunkIter::over_message(&self.buf, self.buf.len())
    }

    /// The first chunk tagged `tag`.
    pub fn chunk(&self, want: u16) -> Option<Chunk<'_>> {
        self.chunks().find(|c| c.tag == want)
    }

    pub fn bytes(&self, want: u16) -> Option<Vec<u8>> {
        self.chunk(want).map(|c| c.data.to_vec())
    }

    pub fn uint(&self, want: u16) -> Option<u32> {
        self.chunk(want).map(|c| c.as_uint())
    }

    /// Every chunk tagged `tag`, in order (user list rows, say).
    pub fn all(&self, want: u16) -> Vec<Vec<u8>> {
        self.chunks()
            .filter(|c| c.tag == want)
            .map(|c| c.data.to_vec())
            .collect()
    }

    pub fn is_error(&self) -> bool {
        self.flag & 1 != 0
    }

    /// The task error's text, lossily.
    pub fn error_text(&self) -> Option<String> {
        self.chunk(tag::TASK_ERROR)
            .map(|c| String::from_utf8_lossy(c.data).into_owned())
    }

    /// Its size on the wire.
    pub fn wire_len(&self) -> usize {
        self.buf.len()
    }
}

/// Pack one transaction.
pub fn pack(ty: u32, trans: u32, flag: u32, chunks: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let body: usize = chunks.iter().map(|(_, d)| HL_DATA_HDR_LEN + d.len()).sum();
    let mut out = vec![0u8; HL_HDR_LEN];
    pack_header(&mut out, ty, trans, flag, chunks.len() as u16, body as u32);
    for (t, data) in chunks {
        assert!(data.len() <= u16::MAX as usize, "chunk exceeds u16 length");
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// Read one transaction, framed by `len2` as every Hotline reader must.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut hdr = [0u8; HL_HDR_LEN];
    r.read_exact(&mut hdr).await?;
    let h = decode_header_full(&hdr, MAX_FRAME).expect("a full header was read");
    if h.wire_len > MAX_FRAME {
        return Err(Error::Protocol(format!("frame of {} bytes", h.wire_len)));
    }
    let mut buf = Vec::with_capacity(HL_HDR_LEN + h.body_len as usize);
    buf.extend_from_slice(&hdr);
    buf.resize(HL_HDR_LEN + h.body_len as usize, 0);
    r.read_exact(&mut buf[HL_HDR_LEN..]).await?;
    Ok(Frame {
        ty: h.type_,
        trans: h.trans,
        flag: h.flag,
        hc: h.hc,
        buf,
    })
}

/// A whole frame off the front of `buf[*pos..]`, if one is there,
/// advancing `pos` past it. The buffer is compacted only when a frame is
/// incomplete or all of it is consumed, so cutting a run of small frames
/// out of one large read costs each frame's bytes and no more.
fn cut_frame(buf: &mut Vec<u8>, pos: &mut usize) -> Result<Option<Frame>> {
    let unread = &buf[*pos..];
    let Some(h) = decode_header_full(unread, MAX_FRAME) else {
        buf.drain(..*pos);
        *pos = 0;
        return Ok(None);
    };
    if h.wire_len > MAX_FRAME {
        return Err(Error::Protocol(format!("frame of {} bytes", h.wire_len)));
    }
    let len = HL_HDR_LEN + h.body_len as usize;
    if unread.len() < len {
        buf.drain(..*pos);
        *pos = 0;
        return Ok(None);
    }
    let frame = unread[..len].to_vec();
    *pos += len;
    if *pos == buf.len() {
        buf.clear();
        *pos = 0;
    }
    Ok(Some(Frame {
        ty: h.type_,
        trans: h.trans,
        flag: h.flag,
        hc: h.hc,
        buf: frame,
    }))
}

/// The "obfuscation" classic clients apply to a login and password.
pub fn xor(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

/// What a login sends. `Login::guest("nick")` is the common case.
#[derive(Debug, Clone)]
pub struct Login {
    pub nick: String,
    pub icon: u16,
    /// Empty for the guest account.
    pub login: String,
    pub password: String,
    /// The client version. 150 and up is offered the agreement, and this
    /// client agrees to it; 0 sends none, as a 1.2 client does.
    pub version: u16,
    /// Capability bits to offer, if any.
    pub caps: Option<u16>,
}

impl Login {
    pub fn guest(nick: &str) -> Self {
        Login {
            nick: nick.into(),
            icon: 1,
            login: String::new(),
            password: String::new(),
            version: 150,
            caps: None,
        }
    }

    pub fn account(nick: &str, login: &str, password: &str) -> Self {
        Login {
            login: login.into(),
            password: password.into(),
            ..Login::guest(nick)
        }
    }

    fn chunks(&self) -> Vec<(u16, Vec<u8>)> {
        let mut c = vec![
            (tag::NAME, self.nick.as_bytes().to_vec()),
            (tag::ICON, self.icon.to_be_bytes().to_vec()),
        ];
        if !self.login.is_empty() {
            c.push((tag::LOGIN, xor(self.login.as_bytes())));
            c.push((tag::PASSWORD, xor(self.password.as_bytes())));
        }
        if self.version != 0 {
            c.push((tag::VERSION, self.version.to_be_bytes().to_vec()));
        }
        if let Some(caps) = self.caps {
            c.push((tag::CAPABILITIES, caps.to_be_bytes().to_vec()));
        }
        c
    }
}

/// A user-list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub uid: u16,
    pub icon: u16,
    pub color: u16,
    pub nick: Vec<u8>,
}

impl UserRow {
    pub fn parse(data: &[u8]) -> Option<UserRow> {
        let u16at = |i: usize| Some(u16::from_be_bytes([*data.get(i)?, *data.get(i + 1)?]));
        let len = u16at(6)? as usize;
        Some(UserRow {
            uid: u16at(0)?,
            icon: u16at(2)?,
            color: u16at(4)?,
            nick: data.get(8..8 + len)?.to_vec(),
        })
    }
}

/// The sending half of a connection.
pub struct Sender {
    wr: WriteHalf<Box<dyn Io>>,
    trans: u32,
    /// How long one write may take: a server that has stopped reading
    /// must not hold a sender forever.
    pub timeout: Duration,
}

impl Sender {
    /// Send a transaction; returns its `trans`.
    pub async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Result<u32> {
        self.trans = self.trans.wrapping_add(1);
        let bytes = pack(ty, self.trans, 0, chunks);
        self.send_raw(&bytes).await?;
        Ok(self.trans)
    }

    /// Send raw bytes: a malformed frame, a half header.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let write = async {
            self.wr.write_all(bytes).await?;
            self.wr.flush().await
        };
        timeout(self.timeout, write)
            .await
            .map_err(|_| Error::Timeout)??;
        Ok(())
    }

    /// Send a public chat line. The classic wire does not answer one.
    pub async fn chat(&mut self, text: &[u8]) -> Result<()> {
        self.send(ClientHdr::Chat.as_u32(), &[(tag::BODY, text.to_vec())])
            .await
            .map(|_| ())
    }

    /// Close the write side, which the server reads as EOF.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.wr.shutdown().await?;
        Ok(())
    }
}

/// The receiving half of a connection. Frames that arrived while it
/// waited for something else are kept, oldest first, and handed out
/// before anything is read.
///
/// Reading is cancel-safe: bytes go into `buf` as they arrive and a frame
/// is cut from it only once whole, so a timeout or a `select!` that drops
/// a read halfway loses nothing and cannot desync the stream.
pub struct Receiver {
    rd: ReadHalf<Box<dyn Io>>,
    buf: Vec<u8>,
    /// Where the unread part of `buf` starts.
    pos: usize,
    backlog: VecDeque<Frame>,
    pub timeout: Duration,
}

impl Receiver {
    /// The next frame, from the backlog or the socket.
    pub async fn recv(&mut self) -> Result<Frame> {
        if let Some(f) = self.backlog.pop_front() {
            return Ok(f);
        }
        self.read().await
    }

    /// The next frame with no timeout at all: for a reader that waits as
    /// long as the run does.
    pub async fn recv_forever(&mut self) -> Result<Frame> {
        if let Some(f) = self.backlog.pop_front() {
            return Ok(f);
        }
        self.read_whole().await
    }

    async fn read(&mut self) -> Result<Frame> {
        timeout(self.timeout, self.read_whole())
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// The next frame off the socket, by `deadline`.
    async fn read_by(&mut self, deadline: tokio::time::Instant) -> Result<Frame> {
        tokio::time::timeout_at(deadline, self.read_whole())
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn read_whole(&mut self) -> Result<Frame> {
        loop {
            if let Some(f) = cut_frame(&mut self.buf, &mut self.pos)? {
                return Ok(f);
            }
            let mut chunk = [0u8; 16 * 1024];
            let n = self.rd.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// The first frame matching `pred`, backlog first; everything else
    /// stays in the backlog in order. The timeout is for the whole wait,
    /// so steady unrelated traffic cannot stretch it.
    pub async fn recv_where(&mut self, pred: impl Fn(&Frame) -> bool) -> Result<Frame> {
        if let Some(i) = self.backlog.iter().position(&pred) {
            return Ok(self.backlog.remove(i).expect("position is in range"));
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let f = self.read_by(deadline).await?;
            if pred(&f) {
                return Ok(f);
            }
            self.backlog.push_back(f);
        }
    }

    /// The first frame of type `ty`.
    pub async fn recv_type(&mut self, ty: u32) -> Result<Frame> {
        self.recv_where(|f| f.ty == ty).await
    }

    /// The reply to `trans`, as it arrived: an error reply is `Ok` here.
    pub async fn reply(&mut self, trans: u32) -> Result<Frame> {
        self.recv_where(|f| f.ty == TASK && f.trans == trans).await
    }

    pub fn take_backlog(&mut self) -> Vec<Frame> {
        self.backlog.drain(..).collect()
    }
}

/// A scripted classic client: a [`Sender`] and a [`Receiver`] over one
/// connection, which [`Client::split`] hands out separately.
pub struct Client {
    pub tx: Sender,
    pub rx: Receiver,
    /// The uid the server gave this session, once logged in.
    pub uid: Option<u16>,
}

impl Client {
    /// Connect over TCP and exchange the TRTP magic.
    pub async fn connect(addr: SocketAddr) -> Result<Client> {
        let stream = timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)??;
        stream.set_nodelay(true)?;
        Client::over(Box::new(stream)).await
    }

    /// Connect over TLS, then exchange the magic inside it.
    pub async fn connect_tls(
        addr: SocketAddr,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Client> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::Protocol(format!("server name: {e}")))?;
        let tls = timeout(DEFAULT_TIMEOUT, async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            TlsConnector::from(config).connect(name, tcp).await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Client::over(Box::new(tls)).await
    }

    /// Exchange the magic over a stream the caller opened.
    pub async fn over(mut stream: Box<dyn Io>) -> Result<Client> {
        stream.write_all(b"TRTPHOTL\x00\x01\x00\x02").await?;
        stream.flush().await?;
        let mut reply = [0u8; 8];
        timeout(DEFAULT_TIMEOUT, stream.read_exact(&mut reply))
            .await
            .map_err(|_| Error::Timeout)??;
        if &reply != b"TRTP\x00\x00\x00\x00" {
            return Err(Error::Protocol(format!("server magic {reply:02x?}")));
        }
        let (rd, wr) = tokio::io::split(stream);
        Ok(Client {
            tx: Sender {
                wr,
                trans: 0,
                timeout: DEFAULT_TIMEOUT,
            },
            rx: Receiver {
                rd,
                buf: Vec::new(),
                pos: 0,
                backlog: VecDeque::new(),
                timeout: DEFAULT_TIMEOUT,
            },
            uid: None,
        })
    }

    /// Connect and log in.
    pub async fn login_at(addr: SocketAddr, login: &Login) -> Result<Client> {
        let mut c = Client::connect(addr).await?;
        c.login(login).await?;
        Ok(c)
    }

    /// Log in: the login task, then — for a 1.5 client — the agreement,
    /// agreed to when the server has one. Returns the login reply. What
    /// else arrives (self-info, joins) stays in the backlog.
    pub async fn login(&mut self, login: &Login) -> Result<Frame> {
        let reply = self
            .call(ClientHdr::Login.as_u32(), &login.chunks())
            .await?;
        self.uid = reply.uint(tag::UID).map(|u| u as u16);
        if login.version >= 150 {
            let agreement = self.rx.recv_type(push::AGREEMENT).await?;
            if agreement.chunk(tag::NOAGREEMENT).is_none() {
                self.call(
                    ClientHdr::AgreementAgree.as_u32(),
                    &[
                        (tag::NAME, login.nick.as_bytes().to_vec()),
                        (tag::ICON, login.icon.to_be_bytes().to_vec()),
                    ],
                )
                .await?;
            }
        }
        Ok(reply)
    }

    pub async fn send(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Result<u32> {
        self.tx.send(ty, chunks).await
    }

    pub async fn recv(&mut self) -> Result<Frame> {
        self.rx.recv().await
    }

    pub async fn recv_type(&mut self, ty: u32) -> Result<Frame> {
        self.rx.recv_type(ty).await
    }

    pub async fn recv_where(&mut self, pred: impl Fn(&Frame) -> bool) -> Result<Frame> {
        self.rx.recv_where(pred).await
    }

    pub async fn reply(&mut self, trans: u32) -> Result<Frame> {
        self.rx.reply(trans).await
    }

    /// Send and wait for the reply; an error reply is `Err(Refused)`.
    pub async fn call(&mut self, ty: u32, chunks: &[(u16, Vec<u8>)]) -> Result<Frame> {
        let trans = self.tx.send(ty, chunks).await?;
        let reply = self.rx.reply(trans).await?;
        if reply.is_error() {
            return Err(Error::Refused {
                code: String::new(),
                text: reply.error_text().unwrap_or_default(),
            });
        }
        Ok(reply)
    }

    pub async fn chat(&mut self, text: &[u8]) -> Result<()> {
        self.tx.chat(text).await
    }

    /// The user list, as rows.
    pub async fn user_list(&mut self) -> Result<Vec<UserRow>> {
        let reply = self.call(ClientHdr::UserGetList.as_u32(), &[]).await?;
        Ok(reply
            .all(tag::USER_LIST)
            .iter()
            .filter_map(|d| UserRow::parse(d))
            .collect())
    }

    /// A ping, answered.
    pub async fn ping(&mut self) -> Result<()> {
        self.call(ClientHdr::Ping.as_u32(), &[]).await.map(|_| ())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.tx.shutdown().await
    }

    pub fn split(self) -> (Sender, Receiver) {
        (self.tx, self.rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packed_frame_reads_back() {
        let bytes = pack(0x69, 7, 0, &[(tag::BODY, b"hi".to_vec())]);
        let f = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(read_frame(&mut bytes.as_slice()))
            .unwrap();
        assert_eq!((f.ty, f.trans, f.flag, f.hc), (0x69, 7, 0, 1));
        assert_eq!(f.bytes(tag::BODY).unwrap(), b"hi");
    }

    #[test]
    fn a_frame_is_cut_only_once_whole() {
        let one = pack(0x6a, 1, 0, &[(tag::BODY, b"first".to_vec())]);
        let two = pack(0x6a, 2, 0, &[(tag::BODY, b"second".to_vec())]);
        let mut buf = one[..10].to_vec();
        let mut pos = 0;
        assert!(cut_frame(&mut buf, &mut pos).unwrap().is_none());
        buf.extend_from_slice(&one[10..]);
        buf.extend_from_slice(&two[..5]);
        let f = cut_frame(&mut buf, &mut pos).unwrap().unwrap();
        assert_eq!(f.trans, 1);
        assert_eq!(f.bytes(tag::BODY).unwrap(), b"first");
        assert!(cut_frame(&mut buf, &mut pos).unwrap().is_none());
        assert_eq!((&buf[pos..], pos), (&two[..5], 0));
        buf.extend_from_slice(&two[5..]);
        let f = cut_frame(&mut buf, &mut pos).unwrap().unwrap();
        assert_eq!(f.trans, 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_user_row_parses_and_a_short_one_does_not() {
        let row = [0, 5, 0, 2, 0, 0, 0, 3, b'b', b'o', b'b'];
        assert_eq!(
            UserRow::parse(&row),
            Some(UserRow {
                uid: 5,
                icon: 2,
                color: 0,
                nick: b"bob".to_vec()
            })
        );
        assert_eq!(UserRow::parse(&row[..9]), None);
    }
}
