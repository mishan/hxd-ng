//! The per-connection session actor.
//!
//! Three tasks per connection: a **reader** that frames the socket and
//! feeds a channel, a **writer** that owns the write half and stamps the
//! push transaction counter in one place, and the **session loop** that
//! selects over incoming frames and domain events. The split keeps
//! `read_frame` cancel-safety out of the picture (the reader never races a
//! select) and gives moderation a clean lever: a kick event just breaks the
//! session loop.
//!
//! The protocol flow (magic exchange, login chunk-walk, the version-driven
//! agreement dance, chat formatting, private-chat lifecycle) mirrors mhxd's
//! `rcv.c` / `chat.c` / `protocol/hotline.c`, the behavioral reference for
//! what 1.2 and 1.5 clients expect. Deviations are deliberate and
//! commented.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use hxd_core::access::bit;
use hxd_core::instrument::{self, Dir, Kind};
use hxd_core::video::VideoKind;
use hxd_core::voice::VoiceError;
use hxd_core::{
    Account, AttachInfo, AuthBackend, AuthError, ChatError, Core, Event, FileEntry, FileKind,
    FilePrincipal, LinkAuthority, LinkOutcome, Proof, SeqEvent, SessionStatus, Transport, Uid,
    UserInfo,
};
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use hxproto::text;
use hxproto::HL_DATA_HDR_LEN;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;
use tracing::{debug, info, warn, Instrument};

use crate::banner::Banner;
use crate::caps::{cap, Caps};
use crate::encoding::TextEncoding;
use crate::files;
use crate::frame::{pack_frame, read_frame, Frame, ReadError, MAX_FRAME_DATA};
use crate::media;
use crate::news::{self, LegacyNews};
use crate::video;
use crate::voice;

/// Server → client transaction opcodes not covered by
/// `hxproto::messages::ServerHdr` (which only carries what the gtkhx
/// client routes on). Values from `hotline.h`.
mod hdr {
    pub const TASK: u32 = 0x0001_0000;
    pub const AGREEMENT: u32 = 0x0000_006d;
    pub const BANNER: u32 = 0x0000_007a;
    pub const USER_CHANGE: u32 = 0x0000_012d;
    pub const USER_PART: u32 = 0x0000_012e;
    pub const USER_SELFINFO: u32 = 0x0000_0162;
    pub const CHAT: u32 = 0x0000_006a;
    pub const MSG: u32 = 0x0000_0068;
    pub const MSG_BROADCAST: u32 = 0x0000_0163;
    pub const CHAT_INVITE: u32 = 0x0000_0071;
    pub const CHAT_USER_CHANGE: u32 = 0x0000_0075;
    pub const CHAT_USER_PART: u32 = 0x0000_0076;
    pub const CHAT_SUBJECT: u32 = 0x0000_0077;
    pub const ICON_CHANGE: u32 = 0x0000_0748;
}

/// fogWraith's GIF Icons extension (`docs/avatars.md` §3): client
/// opcodes hxproto routes no enum for.
mod gif_icons {
    pub const GET_LIST: u32 = 0x0000_0745;
    pub const SET: u32 = 0x0000_0746;
    pub const GET: u32 = 0x0000_0747;
}

/// Data tags hxproto has no constants for (the gtkhx client ignores
/// or hand-rolls them).
const TAG_BANNERID: u16 = 0x00a1;
/// `HTLC_DATA_CHAT_AWAY` — away-toggle rider on a chat send. Parsed and
/// ignored until away state exists.
const TAG_CHAT_AWAY: u16 = 0x0ea1;

/// The client hello: `"TRTPHOTL" 0x0001 0x0002`.
const CLIENT_MAGIC: [u8; 12] = *b"TRTPHOTL\x00\x01\x00\x02";
/// The server's answer: `"TRTP"` + a zero error code.
const SERVER_MAGIC: [u8; 8] = *b"TRTP\x00\x00\x00\x00";

/// Longest accepted chat/message payload, matching the reference server's
/// buffer cap.
const MAX_CHAT_INPUT: usize = 4096;

/// Server-wide configuration the sessions need.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Advertised server name (UTF-8; converted to Mac Roman on the wire).
    pub name: String,
    /// Advertised server version. `0` mimics a 1.0/1.2-era server: no
    /// version/name chunks in the login reply, no agreement flow.
    pub version: u16,
    /// Agreement text (UTF-8), shown unless the account opts out.
    pub agreement: Option<String>,
    /// How long a connection may exist before completing its login.
    pub login_timeout: Duration,
    /// How long a kick-with-ban keeps the address banned.
    pub ban_time: Duration,
    /// The `DATA_CAPABILITIES` bits this server can actually honor. A
    /// session negotiates the intersection of these and what the client
    /// offered; the binary derives them from what is wired and
    /// configured, so a bit is never advertised by a build that can't
    /// serve it.
    pub caps: Caps,
    /// Set the cleartext marker bit in user flags for unencrypted
    /// sessions (`docs/hotline-ng-auth.md` §8). Off by default: see
    /// [`wire_color`].
    pub mark_cleartext: bool,
    /// How a tunnelled session's classic login reconciles with the
    /// socket's transport identity (`docs/hotline-ng-identity.md` §8.3).
    pub trtp_login: TrtpLogin,
    /// Mark a private message that waited in the inbox with the time it
    /// was sent. A message that arrives three days late and looks like it
    /// arrived this second is a worse experience than a slightly ugly
    /// one; an operator who disagrees turns it off.
    pub stamp_queued: bool,
    /// How `[news]` reaches this wire: the 1.5 listing's cap and the 1.2
    /// flat category (`docs/news.md` §12). Read only when the core has
    /// news at all.
    pub news: LegacyNews,
}

/// See [`ServerConfig::trtp_login`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrtpLogin {
    /// Classic credentials are checked as on the TCP port; a named
    /// account must be the linked one or self-linkable (then it gets
    /// linked). Identity adds marking and admission, never replaces a
    /// password.
    #[default]
    Verify,
    /// A linked account is used and the classic credentials ignored.
    Trust,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            name: "hxd-ng".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(10),
            ban_time: Duration::from_secs(1800),
            caps: Caps::empty(),
            mark_cleartext: false,
            trtp_login: TrtpLogin::Verify,
            stamp_queued: true,
            news: LegacyNews::default(),
        }
    }
}

/// Everything a session needs from the server. Cheap to clone.
#[derive(Clone)]
pub struct ServerCtx {
    pub core: Arc<Core>,
    pub auth: Arc<dyn AuthBackend>,
    pub cfg: Arc<ServerConfig>,
    pub files: Option<Arc<hxd_files::FileService>>,
    /// The banner every 1.5+ client is shown after its agreement. Absent =
    /// none, and no `HTLS_HDR_BANNER` is ever sent.
    pub banner: Option<Arc<Banner>>,
}

/// The next connection, however long that takes. An accept error —
/// descriptors exhausted, most often, which anyone able to open enough
/// idle connections can cause — is waited out rather than returned: a
/// returned error ends the process, taking every session with it.
async fn accept(listener: &TcpListener, backoff: &mut Duration) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => {
                *backoff = Duration::from_millis(10);
                return accepted;
            }
            Err(e) => {
                warn!("accept failed; retrying: {e}");
                tokio::time::sleep(*backoff).await;
                *backoff = (*backoff * 2).min(Duration::from_secs(1));
            }
        }
    }
}

/// Accept loop: one [`run_session`] task per connection. Plain TCP, so
/// the transport is cleartext and carries no identity. Never returns.
pub async fn serve(listener: TcpListener, ctx: ServerCtx) {
    let mut backoff = Duration::from_millis(10);
    loop {
        let (stream, peer) = accept(&listener, &mut backoff).await;
        let _ = stream.set_nodelay(true);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!("session", %peer);
            run_connection(
                stream,
                peer,
                ctx,
                Transport::default(),
                LinkAuthority::default(),
                true,
            )
            .instrument(span)
            .await;
        });
    }
}

/// TLS handshakes in progress at once. Past it a new connection is
/// closed unanswered: a handshake costs the server real work, and a
/// client that opens connections and never finishes one should run out
/// of room here rather than run the process out of descriptors.
const MAX_TLS_HANDSHAKES: usize = 256;

/// Accept loop for the TLS port: the same sessions as [`serve`], each
/// behind a handshake that must finish within the login timeout. The
/// handshake runs on the connection's own task, so a client that stalls
/// in it holds up nobody else's accept. A session here is encrypted and
/// carries no identity — a client certificate is not asked for. Never
/// returns.
pub async fn serve_tls(listener: TcpListener, ctx: ServerCtx, tls: Arc<crate::LegacyTls>) {
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_TLS_HANDSHAKES));
    let mut backoff = Duration::from_millis(10);
    loop {
        let (stream, peer) = accept(&listener, &mut backoff).await;
        // A banned address costs no handshake.
        if ctx.core.is_banned(peer.ip()) {
            info!(%peer, "refusing banned address");
            instrument::disconnect(WIRE, "banned");
            continue;
        }
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            debug!(%peer, "TLS handshakes at capacity; closing");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let ctx = ctx.clone();
        let acceptor = tls.acceptor();
        tokio::spawn(async move {
            let span = tracing::info_span!("session", %peer, tls = true);
            let handshake = timeout(ctx.cfg.login_timeout, acceptor.accept(stream)).await;
            drop(permit);
            let stream = match handshake {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    debug!(parent: &span, "TLS handshake failed: {e}");
                    return;
                }
                Err(_) => {
                    debug!(parent: &span, "TLS handshake timed out");
                    return;
                }
            };
            let transport = Transport {
                encrypted: true,
                ..Transport::default()
            };
            run_connection(stream, peer, ctx, transport, LinkAuthority::default(), true)
                .instrument(span)
                .await;
        });
    }
}

/// One outbound frame, typed by who stamps the transaction id.
enum Outbound {
    /// Reply to a client request: `trans` echoes the request.
    Reply {
        trans: u32,
        error: bool,
        chunks: Vec<(u16, Vec<u8>)>,
    },
    /// Server-initiated push: the writer stamps its own counter.
    Push {
        ty: u32,
        chunks: Vec<(u16, Vec<u8>)>,
    },
    /// Server-initiated notification stamped with **task id 0**.
    ///
    /// The base protocol's pushes count their own transactions (mhxd's
    /// convention, which this frontend follows everywhere else), but the
    /// voice extension's transaction-semantics section says its three
    /// server-initiated notifications use task id 0 with the reply flag
    /// unset. GtkHx dispatches them by type and doesn't care either way;
    /// Janus sends 0; so we send 0, and only there.
    Notify {
        ty: u32,
        chunks: Vec<(u16, Vec<u8>)>,
    },
}

impl Outbound {
    /// What this frame will take on the wire, near enough: the header,
    /// and each chunk's four bytes of tag and length plus its data. For
    /// the write-queue gauges, which only need to be the same number on
    /// the way in and on the way out.
    fn wire_len(&self) -> usize {
        let chunks = match self {
            Outbound::Reply { chunks, .. }
            | Outbound::Push { chunks, .. }
            | Outbound::Notify { chunks, .. } => chunks,
        };
        hxproto::HL_HDR_LEN + chunks.iter().map(|(_, d)| 4 + d.len()).sum::<usize>()
    }
}

type Tx = UnboundedSender<Outbound>;

/// Queue a frame for the writer. Every frame goes through here, so the
/// write-queue gauges count what the writer later takes off them.
fn enqueue(tx: &Tx, out: Outbound) {
    let len = out.wire_len() as i64;
    instrument::write_queued(WIRE, 1, len);
    if tx.send(out).is_err() {
        instrument::write_queued(WIRE, -1, -len);
    }
}

/// This frontend's name in the metrics.
const WIRE: &str = "legacy";

/// Inbound transaction types the session answers: what an inbound frame
/// may be labeled as (`hxd_core::instrument`). Anything else, whatever a
/// client sends, is `other`, so a client cannot mint series.
const HANDLED: &[ClientHdr] = &[
    ClientHdr::AgreementAgree,
    ClientHdr::Chat,
    ClientHdr::ChatCreate,
    ClientHdr::ChatDecline,
    ClientHdr::ChatInvite,
    ClientHdr::ChatJoin,
    ClientHdr::ChatPart,
    ClientHdr::ChatSubject,
    ClientHdr::DownloadBanner,
    ClientHdr::FileGet,
    ClientHdr::FileGetInfo,
    ClientHdr::FileList,
    ClientHdr::FilePut,
    ClientHdr::GetChatHistory,
    ClientHdr::Login,
    ClientHdr::Msg,
    ClientHdr::MsgBroadcast,
    ClientHdr::Ping,
    ClientHdr::UserChange,
    ClientHdr::UserGetInfo,
    ClientHdr::UserGetList,
    ClientHdr::UserKick,
    ClientHdr::VideoStart,
    ClientHdr::VideoState,
    ClientHdr::VideoStop,
    ClientHdr::VideoSubscribe,
    ClientHdr::VoiceIce,
    ClientHdr::VoiceJoin,
    ClientHdr::VoiceLeave,
    ClientHdr::VoiceMute,
    ClientHdr::VoiceSdpAnswer,
];

/// An inbound frame's type as a metric label.
fn type_label(ty: u32) -> Kind<'static> {
    let known = HANDLED.iter().any(|h| h.as_u32() == ty)
        || news::handles(ty)
        || ty == media::trans::UPLOAD_MEDIA
        || ty == media::trans::DOWNLOAD_MEDIA
        || matches!(ty, gif_icons::GET_LIST | gif_icons::GET | gif_icons::SET);
    if known {
        Kind::Type(ty)
    } else {
        Kind::Name("other")
    }
}

async fn writer_task<W: AsyncWrite + Unpin>(mut wr: W, mut rx: UnboundedReceiver<Outbound>) {
    // Server pushes count their own transactions, starting at 1 (mhxd's
    // convention; clients ignore the value everywhere but task replies).
    let mut push_trans: u32 = 1;
    while let Some(out) = rx.recv().await {
        instrument::queue_depth(WIRE, rx.len());
        let queued = out.wire_len() as i64;
        let label = match &out {
            Outbound::Reply { .. } => Kind::Name("reply"),
            // The server's own push types: a set the code fixes.
            Outbound::Push { ty, .. } | Outbound::Notify { ty, .. } => Kind::Type(*ty),
        };
        let bytes = match out {
            Outbound::Reply {
                trans,
                error,
                chunks,
            } => {
                trace_out(hdr::TASK, trans, error as u32, &chunks);
                pack_frame(hdr::TASK, trans, error as u32, &chunks)
            }
            Outbound::Push { ty, chunks } => {
                let trans = push_trans;
                push_trans = push_trans.wrapping_add(1);
                trace_out(ty, trans, 0, &chunks);
                pack_frame(ty, trans, 0, &chunks)
            }
            Outbound::Notify { ty, chunks } => {
                trace_out(ty, 0, 0, &chunks);
                pack_frame(ty, 0, 0, &chunks)
            }
        };
        let took = instrument::Timer::start();
        let written = wr.write_all(&bytes).await.is_ok() && wr.flush().await.is_ok();
        instrument::socket_write(WIRE, took);
        instrument::write_queued(WIRE, -1, -queued);
        if !written {
            break; // Reader will observe the dead socket and clean up.
        }
        instrument::frame(WIRE, Dir::Out, label, bytes.len());
    }
    // What was queued and will now never be written leaves the gauges
    // with the connection.
    rx.close();
    while let Ok(out) = rx.try_recv() {
        instrument::write_queued(WIRE, -1, -(out.wire_len() as i64));
    }
    let _ = wr.shutdown().await;
}

/// Reader task: frames the socket into a bounded channel (backpressure for
/// a flooding client). Exits on EOF, error, or a malformed frame.
/// Returns why it stopped, which is why the connection did when it was
/// the reader that ended it.
async fn reader_task<R: AsyncRead + Unpin>(mut rd: R, frames: Sender<Frame>) -> &'static str {
    loop {
        match read_frame(&mut rd).await {
            Ok(f) => {
                instrument::frame(WIRE, Dir::In, type_label(f.ty), f.wire_len());
                if frames.send(f).await.is_err() {
                    return "closed"; // Session loop is gone.
                }
            }
            Err(ReadError::Eof) => return "eof",
            Err(ReadError::Io(e)) => {
                debug!("read error: {e}");
                return "io_error";
            }
            Err(ReadError::Malformed(why)) => {
                warn!("malformed frame: {why}");
                return "malformed";
            }
        }
    }
}

fn trace_out(ty: u32, trans: u32, flag: u32, chunks: &[(u16, Vec<u8>)]) {
    if tracing::enabled!(target: "proto", tracing::Level::DEBUG) {
        let tags: Vec<String> = chunks
            .iter()
            .map(|(t, d)| format!("{t:#06x}/{}", d.len()))
            .collect();
        debug!(target: "proto", "out type={ty:#x} trans={trans} flag={flag} hc={} [{}]",
            chunks.len(), tags.join(" "));
    }
}

fn trace_in(f: &Frame) {
    if tracing::enabled!(target: "proto", tracing::Level::DEBUG) {
        let tags: Vec<String> = f
            .chunks()
            .map(|c| format!("{:#06x}/{}", c.tag, c.data.len()))
            .collect();
        debug!(target: "proto", "in  type={:#x} trans={} flag={} hc={} [{}]",
            f.ty, f.trans, f.flag, f.hc, tags.join(" "));
    }
}

fn reply(tx: &Tx, trans: u32, chunks: Vec<(u16, Vec<u8>)>) {
    enqueue(
        tx,
        Outbound::Reply {
            trans,
            error: false,
            chunks,
        },
    );
}

/// Task error texts are the server's own words and ASCII, which is the
/// same bytes in Mac Roman and in UTF-8 — so one conversion serves every
/// connection whatever it negotiated. The assertion keeps it that way: a
/// text that needed the connection's encoding would have to be passed it.
fn reply_error(tx: &Tx, trans: u32, msg: &str) {
    debug_assert!(msg.is_ascii(), "task error text must be ASCII: {msg:?}");
    enqueue(
        tx,
        Outbound::Reply {
            trans,
            error: true,
            chunks: vec![(tag::TASK_ERROR, text::from_utf8(msg))],
        },
    );
}

/// A task error carrying extra fields beside its text — the shape the
/// inline-media extension's optional error code needs
/// (`docs/inline-media.md` §7.2).
fn reply_error_with(tx: &Tx, trans: u32, msg: &str, extra: Vec<(u16, Vec<u8>)>) {
    debug_assert!(msg.is_ascii(), "task error text must be ASCII: {msg:?}");
    let mut chunks = vec![(tag::TASK_ERROR, text::from_utf8(msg))];
    chunks.extend(extra);
    enqueue(
        tx,
        Outbound::Reply {
            trans,
            error: true,
            chunks,
        },
    );
}

fn push(tx: &Tx, ty: u32, chunks: Vec<(u16, Vec<u8>)>) {
    enqueue(tx, Outbound::Push { ty, chunks });
}

/// A server-initiated notification with task id 0 — see
/// [`Outbound::Notify`]. The voice extension's 602/604/605 and the video
/// extension's 611 use it.
fn notify(tx: &Tx, ty: u32, chunks: Vec<(u16, Vec<u8>)>) {
    enqueue(tx, Outbound::Notify { ty, chunks });
}

/// The domain is UTF-8; this edge speaks the connection's encoding. On
/// Mac Roman egress is lossy (`?` for unmappable), and either way a nick
/// is cut to the wire's 31 bytes *after* conversion, at a character
/// boundary.
fn wire_nick(enc: TextEncoding, nick: &str) -> Vec<u8> {
    enc.encode_capped(nick, 31)
}

/// A chat subject, cut to the wire's 255 bytes after conversion. Inbound
/// the cap is 255 characters, which UTF-8 can carry in up to four times
/// the bytes, and a subject can come from an ng client with no cap of
/// this wire's at all; a classic client reads the field as the 255 its
/// own sends are held to.
fn wire_subject(enc: TextEncoding, subject: &str) -> Vec<u8> {
    enc.encode_capped(subject, 255)
}

/// The legacy color field is a bitfield in practice: bit 1 away, bit 2
/// admin. The domain stores `admin` + status; the wire form is derived
/// here and only here.
///
/// Bit 4 (value 16) marks a session whose link is cleartext
/// (`docs/hotline-ng-auth.md` §8): a plain TCP legacy session. Old
/// clients ignore flag bits they don't know, but the reference server
/// never set one, so this is a deliberate deviation behind
/// `ServerConfig::mark_cleartext` (default off) until it has been seen
/// against every 1.x client we care about.
fn wire_color(u: &UserInfo, mark_cleartext: bool) -> u16 {
    (if u.admin { 2 } else { 0 })
        | (if u.status == SessionStatus::Active {
            0
        } else {
            1
        })
        | (if mark_cleartext && !u.transport.encrypted {
            16
        } else {
            0
        })
}

/// The `HTLS_DATA_USER_LIST` payload: uid, icon, color, nlen (all u16 BE),
/// then the name bytes. `struct hl_userlist_hdr` minus the chunk header.
fn userlist_payload(u: &UserInfo, mark_cleartext: bool, enc: TextEncoding) -> Vec<u8> {
    let nick = wire_nick(enc, &u.nick);
    let mut v = Vec::with_capacity(8 + nick.len());
    v.extend_from_slice(&u.uid.to_be_bytes());
    v.extend_from_slice(&u.icon.to_be_bytes());
    v.extend_from_slice(&wire_color(u, mark_cleartext).to_be_bytes());
    v.extend_from_slice(&(nick.len() as u16).to_be_bytes());
    v.extend_from_slice(&nick);
    v
}

fn user_change_chunks(
    u: &UserInfo,
    mark_cleartext: bool,
    enc: TextEncoding,
) -> Vec<(u16, Vec<u8>)> {
    vec![
        (tag::UID, u.uid.to_be_bytes().to_vec()),
        (tag::ICON, u.icon.to_be_bytes().to_vec()),
        (
            tag::COLOUR,
            wire_color(u, mark_cleartext).to_be_bytes().to_vec(),
        ),
        (tag::NAME, wire_nick(enc, &u.nick)),
    ]
}

/// The legacy XOR-0xff de-obfuscation of LOGIN/PASSWORD chunk payloads
/// (`hl_decode` in the C tree).
fn hl_decode(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| !b).collect()
}

/// The `CHAT_ID` of a voice transaction. Absent means the public chat,
/// which is also what `0` means — every voice transaction carries the
/// field, and a client that omits it is asking about the lobby.
fn voice_cid(f: &Frame) -> u32 {
    f.chunks()
        .find(|c| c.tag == tag::CHAT_ID)
        .map_or(0, |c| c.as_uint())
}

/// The `DATA_VIDEO_KIND` of a video transaction, where it is required.
/// `None` covers both a missing field and a kind this revision doesn't
/// define — kind `0` is invalid on purpose, so a zeroed field is caught
/// rather than read as a camera.
///
/// The field is a UInt16, but `as_uint` widens a four-byte chunk to
/// `u32`; the conversion is checked so that a client sending a wide value
/// is refused rather than truncated into a kind it didn't name.
fn video_kind(f: &Frame) -> Option<VideoKind> {
    f.chunks()
        .find(|c| c.tag == tag::VIDEO_KIND)
        .and_then(|c| u16::try_from(c.as_uint()).ok())
        .and_then(VideoKind::from_wire)
}

fn err_text(e: ChatError) -> &'static str {
    match e {
        ChatError::NoSuchUser => "That user is not connected.",
        ChatError::NoSuchChat => "That chat does not exist.",
        ChatError::NotAMember => "You are not in that chat.",
        ChatError::AlreadyThere => "Already there.",
        ChatError::WrongPassword => "Wrong chat password.",
        ChatError::MailboxFull => "That user's mailbox is full.",
        ChatError::Blocked => "That user is not accepting messages from you.",
        ChatError::NoInbox => "This account has no message inbox.",
        // Not theirs, expired, or revoked — one answer for all three, so
        // a send cannot be used to test whether a handle exists.
        ChatError::NoSuchMedia => "Media rejected",
        ChatError::ServerError => "Server error.",
    }
}

/// `YYYY-MM-DD HH:MM UTC`, for the queued-message stamp and the
/// operator's moderation listings.
///
/// UTC, and said so in the text: the server knows nothing about where the
/// reader is, and the legacy wire has no way for a client to tell it. A
/// stamp in an unstated zone would be worse than one in a stated one.
pub fn stamp(t: SystemTime) -> String {
    let c = civil(t);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

/// A UTC calendar date and time.
pub(crate) struct Civil {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    /// 0 is Sunday.
    pub weekday: i64,
}

/// `t` on the UTC calendar. Hand-rolled rather than pulling in a calendar
/// crate for a line of presentation — this is Howard Hinnant's
/// `civil_from_days`, which is exact for every date this server will ever
/// format. A clock before the epoch reads as the epoch rather than
/// wrapping.
pub(crate) fn civil(t: SystemTime) -> Civil {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        // 1970-01-01 was a Thursday.
        weekday: (days + 4).rem_euclid(7),
    }
}

// --- Chat line formatting ----------------------------------------------
//
// Hotline chat is server-formatted: the server composes the display line
// and clients render it verbatim. These mirror the reference server's
// default formats — `"\r%13.13s:  %s"` and `"\r *** %s %s"` — byte for
// byte, name field right-aligned in 13 columns and truncated to 13.
//
// The leading `\r` is the line's framing, not a line ending in the text,
// so it stays `\r` on a UTF-8 connection too: it is what every client
// splits a chat push on, and the Text-Encoding spec's LF rule is about
// the text a line carries. That text never contains a break — it is
// split on CR and LF and each piece attributed on its own.

fn format_chat_line(out: &mut Vec<u8>, enc: TextEncoding, nick: &[u8], line: &[u8], style: u16) {
    out.push(b'\r');
    if style == 1 {
        out.extend_from_slice(b" *** ");
        out.extend_from_slice(nick);
        out.push(b' ');
    } else {
        out.extend(enc.name_column(nick));
        out.extend_from_slice(b":  ");
    }
    out.extend_from_slice(line);
}

/// Split multi-line input and format each line, mirroring the reference
/// server's `cr_strtok_r` loop: empty segments (consecutive or trailing
/// `\r`/`\n`, including CRLF pairs) are skipped rather than rendered as
/// blank attributed lines. Input that is *only* delimiters (or empty)
/// still formats one empty line — the reference's "no token found" path.
fn format_chat(enc: TextEncoding, nick: &[u8], text: &[u8], style: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 32);
    let mut wrote = false;
    for line in text.split(|b| *b == b'\r' || *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        format_chat_line(&mut out, enc, nick, line, style);
        wrote = true;
    }
    if !wrote {
        format_chat_line(&mut out, enc, nick, b"", style);
    }
    out
}

/// Render one stored line for the legacy compatibility replay: a
/// timestamp, then the attribution, then the text.
///
/// Like [`format_chat`], the body is split on CR/LF and each segment is
/// attributed again. Appending it verbatim would let a line that
/// contains a carriage return replay as an unattributed line in every
/// non-capable client's scrollback — a forgery live delivery does not
/// allow, and the store keeps the body as it was said. The split is on
/// the encoded bytes so nothing the encoding produces can slip through
/// either.
fn format_replay(line: &hxd_core::LogLine, enc: TextEncoding) -> Vec<u8> {
    let seconds = line
        .at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let day = seconds % 86_400;
    let prefix = format!(
        "\r[{hour:02}:{minute:02}] ",
        hour = day / 3600,
        minute = day / 60 % 60
    );
    let mut attribution = enc.encode(&prefix);
    if line.flags.contains(hxd_core::LineFlags::ACTION) {
        attribution.extend_from_slice(b"*** ");
        attribution.extend(wire_nick(enc, &line.from_nick));
        attribution.push(b' ');
    } else {
        attribution.extend(wire_nick(enc, &line.from_nick));
        attribution.extend_from_slice(b":  ");
    }
    let body = enc.encode(&line.text);
    let mut out = Vec::with_capacity(body.len() + attribution.len());
    let mut wrote = false;
    for segment in body.split(|b| *b == b'\r' || *b == b'\n') {
        if segment.is_empty() {
            continue;
        }
        out.extend_from_slice(&attribution);
        out.extend_from_slice(segment);
        wrote = true;
    }
    // A tombstone, or a body that is only delimiters: one empty line,
    // the same "no token found" path `format_chat` takes.
    if !wrote {
        out.extend_from_slice(&attribution);
    }
    out
}

/// Trim a page of history entries to what one transaction can carry,
/// returning what fits and whether anything was dropped.
///
/// The spec bounds a single entry — its lengths are u16 — but says
/// nothing about the reply, and a full page of long lines overruns
/// [`MAX_FRAME_DATA`]. A client clamps an oversized header rather than
/// refusing it, so the reply would arrive truncated and the rest of the
/// connection mis-framed. Dropping whole entries keeps the framing
/// honest.
///
/// Entries arrive and leave oldest-first, and are dropped from the end
/// the client is paging *away* from: an `after` query continues from the
/// newest id it was handed, so the newest go; every other query
/// continues from the oldest, so the oldest go. What is left is still
/// contiguous with the cursor the client will send next, and the caller
/// turns a drop into `has_more`, which means "more in the direction of
/// the query".
fn fit_history_entries(mut entries: Vec<Vec<u8>>, paging_newer: bool) -> (Vec<Vec<u8>>, bool) {
    // CHANNEL_ID and HAS_MORE ride along in the same transaction, and
    // the chunk count sits inside the counted data size.
    const FIXED: usize = 2 * HL_DATA_HDR_LEN + 4 + 1 + size_of::<u16>();
    let budget = MAX_FRAME_DATA as usize - FIXED;
    let cost = |entry: &Vec<u8>| HL_DATA_HDR_LEN + entry.len();
    if entries.iter().map(cost).sum::<usize>() <= budget {
        return (entries, false);
    }
    // One entry is at most `u16::MAX` plus its chunk header, which is
    // far inside the budget, so at least one always survives and the
    // client's cursor always advances.
    let mut used = 0;
    let mut kept = 0;
    let ordered: Box<dyn Iterator<Item = &Vec<u8>>> = if paging_newer {
        Box::new(entries.iter())
    } else {
        Box::new(entries.iter().rev())
    };
    for entry in ordered {
        if used + cost(entry) > budget {
            break;
        }
        used += cost(entry);
        kept += 1;
    }
    if paging_newer {
        entries.truncate(kept);
    } else {
        entries.drain(..entries.len() - kept);
    }
    (entries, true)
}

/// What the login chunk-walk yielded.
#[derive(Default)]
struct LoginRequest {
    login: Vec<u8>,
    password: Vec<u8>,
    nick: Option<Vec<u8>>,
    icon: u16,
    clientversion: u16,
    /// The extensions the client says it implements (`0x01F0`).
    caps: Caps,
    /// A 1-byte all-zero LOGIN chunk: the HOPE session-key probe.
    hope_probe: bool,
}

fn parse_login(f: &Frame) -> LoginRequest {
    let mut req = LoginRequest::default();
    for c in f.chunks() {
        match c.tag {
            tag::NAME => req.nick = Some(c.data.to_vec()),
            tag::ICON => req.icon = c.as_uint() as u16,
            tag::VERSION => req.clientversion = c.as_uint() as u16,
            tag::CAPABILITIES => req.caps = Caps::from_wire(c.data),
            tag::LOGIN => {
                if c.data.len() == 1 && c.data[0] == 0 {
                    req.hope_probe = true;
                } else {
                    req.login = hl_decode(c.data);
                }
            }
            // A single NUL byte is "no password" on the wire.
            tag::PASSWORD if !(c.data.len() == 1 && c.data[0] == 0) => {
                req.password = hl_decode(c.data);
            }
            _ => {}
        }
    }
    req
}

/// Per-session protocol state after a successful login.
struct Session {
    uid: Uid,
    account: Account,
    /// Visible on the roster yet? False while a 1.5 client is still inside
    /// the agreement dance.
    announced: bool,
    /// The extensions negotiated at LOGIN — what the client offered
    /// intersected with what this server supports. Extension traffic is
    /// gated on these: a client that didn't negotiate a capability must
    /// never be sent its transactions.
    caps: Caps,
    /// Every text field in and out, from bit 1 of `caps`. Fixed at login:
    /// the spec negotiates it once, and a connection whose encoding could
    /// change would have text in flight in the old one.
    enc: TextEncoding,
    history_replayed: bool,
    /// Download budget for 751, refilled continuously. Per connection
    /// rather than per account, because it bounds this socket's writes:
    /// an image is the largest thing this wire hands back outside a file
    /// transfer, and a client in a loop is the case it exists for.
    media_tokens: f64,
    media_refill: Instant,
    /// The sliced download in progress: the handle, and the next part
    /// index that continues it. One image costs one token however many
    /// 751s carry it — see `allow_download`.
    media_stream: Option<(hxd_core::media::Handle, u16)>,
    /// Where this session's file transfers must connect from: the control
    /// connection's own address, when that is a direct TCP connection. A
    /// tunnelled session's peer is whoever terminated its WebSocket, so it
    /// binds nothing.
    transfer_addr: Option<IpAddr>,
    /// This session has used the GIF Icons extension, so it is sent Icon
    /// Change. The extension has no capability bit; a client that never
    /// asked is not handed a transaction it may not know.
    gif_icons: bool,
    /// Whether this session has been sent the banner, which happens once.
    banner_sent: bool,
    /// The image this session was told of and may still download: once,
    /// as on mhxd, which is all a client showing it needs. Kept rather
    /// than read again, so the bytes are the ones the push described.
    banner_image: Option<crate::banner::Image>,
}

impl Session {
    fn can(&self, b: u8) -> bool {
        self.account.access.has(b)
    }

    /// Take a download token, refilling at `per_minute`. A burst of the
    /// full minute's worth is allowed and then the rate is the rate,
    /// which is what a client fetching every image in a busy room needs
    /// and a client in a loop does not get more of.
    ///
    /// **One image, one token**, however many parts it is sliced into.
    /// The ng wire hands an image back in a single `GET` and charges
    /// once for it, and `download_per_minute` is one knob with one
    /// meaning — charging per 751 part would quietly give a legacy
    /// client a fraction of the advertised budget, the fraction being
    /// whatever chunk size this server happens to advertise.
    ///
    /// So a part that *continues* the download just paid for is free,
    /// and anything else — a new handle, a restart, a part already
    /// served — is a fresh download and costs. Sequential fetching is
    /// therefore one token per image and re-asking for the same part in
    /// a loop is one token per request, which is the client this bound
    /// exists for.
    fn allow_download(
        &mut self,
        per_minute: u32,
        of: Option<hxd_core::media::Handle>,
        index: u16,
    ) -> bool {
        if let (Some(handle), Some((streaming, next))) = (of, self.media_stream) {
            if handle == streaming && index == next {
                self.media_stream = Some((handle, index.saturating_add(1)));
                return true;
            }
        }
        if !self.take_download_token(per_minute) {
            return false;
        }
        self.media_stream = of.map(|h| (h, index.saturating_add(1)));
        true
    }

    fn take_download_token(&mut self, per_minute: u32) -> bool {
        let cap = per_minute.max(1) as f64;
        let now = Instant::now();
        self.media_tokens = (self.media_tokens
            + now.duration_since(self.media_refill).as_secs_f64() * cap / 60.0)
            .min(cap);
        self.media_refill = now;
        if self.media_tokens < 1.0 {
            return false;
        }
        self.media_tokens -= 1.0;
        true
    }

    /// Did this session negotiate capability bit `n`?
    fn has_cap(&self, n: u8) -> bool {
        self.caps.has(n)
    }
}

/// Run one legacy session over any byte stream: a TCP socket from
/// [`serve`], or a TRTP-over-WebSocket tunnel handed over by the ng
/// frontend (`docs/hotline-ng-auth.md` §7.3). `transport` says what
/// the caller knows about the link — encrypted or not, and the transport
/// identity if the caller authenticated one — and is carried to the
/// roster untouched. The protocol inside doesn't know which it got.
pub async fn run_session<S>(
    stream: S,
    peer: SocketAddr,
    ctx: ServerCtx,
    transport: Transport,
    link: LinkAuthority,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_connection(stream, peer, ctx, transport, link, false).await
}

/// [`run_session`], told whether `peer` is the client's own TCP address.
/// Only then can a file transfer be required to come from it.
async fn run_connection<S>(
    stream: S,
    peer: SocketAddr,
    ctx: ServerCtx,
    transport: Transport,
    link: LinkAuthority,
    direct: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if ctx.core.is_banned(peer.ip()) {
        info!("refusing banned address");
        instrument::disconnect(WIRE, "banned");
        return;
    }
    let (mut rd, wr): (ReadHalf<S>, WriteHalf<S>) = tokio::io::split(stream);

    // --- Magic exchange -------------------------------------------------
    // Read exactly the 12 client-hello bytes; anything the client pipelined
    // behind them (old hx logs in without waiting) stays in the socket
    // buffer and is handled by the normal frame loop.
    let began = instrument::Timer::start();
    let mut magic = [0u8; 12];
    match timeout(ctx.cfg.login_timeout, rd.read_exact(&mut magic)).await {
        Ok(Ok(_)) => {}
        _ => {
            instrument::disconnect(WIRE, "handshake");
            return;
        }
    }
    if magic != CLIENT_MAGIC {
        debug!("bad client magic, dropping");
        instrument::disconnect(WIRE, "handshake");
        return;
    }

    let (tx, out_rx) = mpsc::unbounded_channel();
    let mut wr_for_magic = wr;
    // TCP needs no flush; a tunnelled stream buffers frames until one
    // (`WsByteStream`), so flush after every write on the generic path.
    if wr_for_magic.write_all(&SERVER_MAGIC).await.is_err() || wr_for_magic.flush().await.is_err() {
        instrument::disconnect(WIRE, "handshake");
        return;
    }
    let writer = tokio::spawn(writer_task(wr_for_magic, out_rx));
    let (frames_tx, mut frames) = mpsc::channel(32);
    let mut reader = tokio::spawn(reader_task(rd, frames_tx));

    // --- Login, then the session loop -----------------------------------
    let identified = transport.identity.is_some();
    let outcome = login_phase(&mut frames, &tx, &ctx, peer, transport, link).await;
    let ended = if let Some((mut sess, mut events)) = outcome {
        let auth = if identified {
            "identity"
        } else if names_guest(&sess.account.login) {
            "guest"
        } else {
            "password"
        };
        instrument::login(WIRE, auth, began);
        sess.transfer_addr = direct.then(|| peer.ip());
        let uid = sess.uid;
        info!(uid, login = %sess.account.login, "logged in");
        let ended = session_loop(&mut frames, &mut events, &tx, &ctx, &mut sess).await;
        ctx.core.end_session(uid);
        info!(uid, "disconnected");
        ended
    } else {
        Some("login")
    };
    // `None` is the session loop saying the reader ended it, and the
    // reader knows why.
    let reason = match ended {
        Some(reason) => reason,
        None => (&mut reader).await.unwrap_or("closed"),
    };
    instrument::disconnect(WIRE, reason);
    reader.abort();
    drop(tx);
    let _ = writer.await;
}

/// Does this login name the guest account? Empty is guest by convention
/// (`AuthBackend::authenticate`), and so is the name itself.
fn names_guest(login: &str) -> bool {
    login.is_empty() || login.eq_ignore_ascii_case("guest")
}

/// The classic login, reconciled with the socket's transport identity
/// when it has one (`docs/hotline-ng-identity.md` §8.3). Without an
/// identity this is just `authenticate`.
fn reconcile_login(
    auth: &dyn AuthBackend,
    core: &Core,
    login: &str,
    password: &[u8],
    identity_fp: Option<[u8; 32]>,
    policy: TrtpLogin,
    link: LinkAuthority,
) -> Result<Account, AuthError> {
    // Whatever this login resolves to, an account that links an identity
    // has its mail claimed onto the fingerprint before it is handed a
    // session. `claim` is idempotent and does nothing on a mailbox that
    // has already moved; running it here closes the two windows a
    // link-time-only claim leaves — a `msg_login` that read the
    // directory before the link was written, and an account linked from
    // another device while a session of it was already up, both of which
    // leave rows on the bare login that nobody would look at again.
    let claim = |a: &Account| {
        if let Some(f) = a.identity.fingerprint {
            let moved = core.inbox_claim(&a.login, &f);
            if moved > 0 {
                info!(login = %a.login, moved, "inbox claimed at login");
            }
        }
    };
    let Some(fp) = identity_fp else {
        // No transport identity — and the claim still belongs here. The
        // obligation is the *account's*, not the socket's: someone who
        // linked once through ng and thereafter logs in from GtkHx with
        // their password has a fingerprint-keyed mailbox, and the rows
        // those two windows leave on the bare login would sit there
        // unread forever if the only claim were on the identity paths.
        let account = auth.authenticate(login, Proof::Plain(password))?;
        claim(&account);
        return Ok(account);
    };
    // Unfiltered: "no account links this identity" and "one does but the
    // operator turned identity login off" are different answers, and
    // §8.1 gives them different outcomes. Collapsing them here turned the
    // second into a silent guest session, where the ng path denies it.
    let linked = auth.find_by_fingerprint(&fp)?;
    let identity_admits = linked.as_ref().is_some_and(|a| a.identity.identity_login);
    if policy == TrtpLogin::Trust && identity_admits {
        let a = linked.expect("identity_admits implies a linked account");
        debug!(login = %a.login, "trtp_login = trust: using the linked account");
        claim(&a);
        return Ok(a);
    }
    let account = match auth.authenticate(login, Proof::Plain(password)) {
        Ok(a) => Some(a),
        // Deleting `guest.toml` is the documented way to turn guests
        // off, and it used to refuse a linked identity's guest login on
        // this wire while the JSON wire admitted the same identity on
        // the link alone. Naming no account is a question about the
        // identity; only a linked account that may log in answers it.
        Err(AuthError::NoSuchAccount) if names_guest(login) && identity_admits => None,
        Err(e) => return Err(e),
    };
    if account.as_ref().is_none_or(|a| a.login == "guest") {
        // §8.1: naming no account on an identity socket associates by
        // identity. A link the operator has disabled is a refusal, not a
        // fallback to guest — the account said no, and handing out a
        // guest session instead is answering a different question.
        return match linked {
            Some(a) if identity_admits => {
                claim(&a);
                Ok(a)
            }
            Some(a) => {
                info!(login = %a.login, "identity_login is off for the linked account");
                Err(AuthError::BadProof)
            }
            // §8.1 `deny`, decided on this wire as it is on the JSON one:
            // nothing links this identity, so there is no guest to fall
            // back to. The token that opened the socket may have been
            // minted while an account still linked it — it lives a
            // minute — so this is re-decided here rather than trusted
            // from the upgrade.
            None if !link.unlinked_ok => {
                info!("new_accounts = deny: an identity with no linked account");
                Err(AuthError::BadProof)
            }
            None => account.ok_or(AuthError::NoSuchAccount),
        };
    }
    let account = account.expect("a named account was authenticated");
    match account.identity.fingerprint {
        Some(f) if f == fp => {
            claim(&account);
            Ok(account)
        }
        Some(_) => {
            info!(login = %account.login, "tunnelled login names an account linked to another identity");
            Err(AuthError::BadProof)
        }
        // Self-linking here writes an association exactly as
        // `/identity/link` does, so it needs the same `manage`
        // capability (identity spec §8.2) — and it goes through the
        // backend's exclusive op, so two tunnelled logins by one
        // identity can't both decide the identity is free.
        None if account.identity.allow_self_link && link.may_link => {
            match auth.link_identity(&account.login, &fp)? {
                LinkOutcome::Linked(a) => {
                    info!(login = %a.login, "identity linked by tunnelled login");
                    // §4 of docs/private-messages.md: a link that doesn't
                    // claim strands the account's existing mail.
                    let moved = core.inbox_claim(&a.login, &fp);
                    if moved > 0 {
                        info!(login = %a.login, moved, "inbox claimed by the new identity link");
                    }
                    Ok(a)
                }
                LinkOutcome::Already(a) => Ok(a),
                // The identity already links someone else's account, or
                // this one refused. §8.3 `verify` allows exactly two
                // shapes — the account linked to this identity, or an
                // unlinked self-linkable one — so this is neither.
                LinkOutcome::Taken(_) | LinkOutcome::Refused(_) => {
                    info!(login = %account.login, "tunnelled login names an account this identity may not have");
                    Err(AuthError::BadProof)
                }
            }
        }
        // Unlinked, and either not self-linkable or this socket's
        // certificate lacks `manage`. §8.3 `verify`: an identity socket
        // may land on the account linked to it, or on an unlinked
        // account it is allowed to link — nothing else. Admitting it
        // anyway would put an account that refused association on the
        // roster as identity-bound, which is the state `allow_self_link
        // = false` exists to prevent. The password still works on the
        // plain TCP port, which is where an account that wants nothing
        // to do with identities belongs.
        None => {
            info!(login = %account.login, "tunnelled login names an account that refuses self-linking");
            Err(AuthError::BadProof)
        }
    }
}

/// Wait for the LOGIN transaction and run the login flow. `None` = close.
async fn login_phase(
    frames: &mut Receiver<Frame>,
    tx: &Tx,
    ctx: &ServerCtx,
    peer: SocketAddr,
    transport: Transport,
    link: LinkAuthority,
) -> Option<(Session, UnboundedReceiver<SeqEvent>)> {
    let f = match timeout(ctx.cfg.login_timeout, frames.recv()).await {
        Ok(Some(f)) => f,
        _ => return None, // timeout or reader gone
    };
    trace_in(&f);
    if f.ty != ClientHdr::Login.as_u32() {
        reply_error(tx, f.trans, "Please log in first.");
        return None;
    }

    let req = parse_login(&f);
    if req.hope_probe {
        // HOPE arrives with the secure-login work; refuse it cleanly
        // rather than desync. When it lands it stays refused on the TLS
        // port (`transport.encrypted`): the same protection twice buys
        // nothing, and GtkHx refuses the combination from its side too.
        reply_error(tx, f.trans, "Secure login (HOPE) is not supported yet.");
        return None;
    }

    // The encoding comes from the same frame as the credentials, so it is
    // settled before anything in that frame is read as text. Bit 1 needs
    // nothing wired to be honored, but it is still only honored when the
    // server lists it: the echo below is what tells the client which
    // encoding it got, and the two must agree.
    let enc = TextEncoding::negotiated(req.caps.intersect(ctx.cfg.caps));

    // Authenticate on the blocking pool — backends do file I/O. Login and
    // password are canonicalized to UTF-8 from the connection's encoding
    // before the backend sees them, so an accented password typed on a
    // legacy client matches the UTF-8 account file, and matches it
    // whichever encoding the client negotiated. (HOPE proofs will need
    // this same canonical form.) The wire's cap of 31 applies in
    // characters, which is bytes for Mac Roman as it always was, so a
    // password cuts at the same place whichever encoding sent it.
    let auth = ctx.auth.clone();
    let core = ctx.core.clone();
    let login_str = enc.decode_chars(&req.login, 31);
    let password = enc.decode_chars(&req.password, 31).into_bytes();
    let identity_fp = transport.identity.as_ref().map(|t| t.fingerprint);
    let policy = ctx.cfg.trtp_login;
    let verdict = tokio::task::spawn_blocking(instrument::blocking("login", move || {
        reconcile_login(
            &*auth,
            &core,
            &login_str,
            &password,
            identity_fp,
            policy,
            link,
        )
    }))
    .await
    .ok()?;

    let account = match verdict {
        Ok(a) => a,
        Err(e @ (AuthError::NoSuchAccount | AuthError::BadProof)) => {
            info!(login = %String::from_utf8_lossy(&req.login), "login refused: {e}");
            // The reference server closes with an empty error reply; give
            // the human a reason too — clients render the text.
            reply_error(tx, f.trans, "Login failed.");
            return None;
        }
        Err(AuthError::Backend(e)) => {
            warn!("auth backend failure: {e}");
            reply_error(tx, f.trans, "Server error.");
            return None;
        }
    };

    // Resolve the visible name: the account must grant use_any_name for
    // the client's own nick to stick; otherwise the account name rules.
    let got_name = req.nick.is_some();
    let nick = match (&req.nick, account.access.has(bit::USE_ANY_NAME)) {
        (Some(n), true) => enc.decode_chars(n, 31),
        _ => account.name.clone(),
    };

    // The capability negotiation happens *before* the attach, because
    // one of its bits is something the domain needs: the authorization
    // set for an image is captured during fan-out, and fan-out has to
    // know which recipients can carry the reference at all
    // (`docs/inline-media.md` §5.2).
    let mut caps = req.caps.intersect(ctx.cfg.caps);
    // Bit 10 depends on bit 2. A client that asked for video without
    // voice gets neither the bit nor a video transaction that works,
    // because there is no voice room for video to live in — and echoing
    // a bit whose transactions would all fail is the one thing the
    // capability handshake must never do.
    if caps.has(cap::VIDEO) && !caps.has(cap::VOICE) {
        caps = Caps::from_bits(caps.bits() & !(1u64 << cap::VIDEO));
    }
    // Bit 3 the same way: without a configured pipeline there are no
    // handles to issue and 750 would answer nothing but errors.
    if caps.has(cap::INLINE_MEDIA) && !ctx.core.media_enabled() {
        caps = Caps::from_bits(caps.bits() & !(1u64 << cap::INLINE_MEDIA));
    }
    let transport = Transport {
        inline_media: caps.has(cap::INLINE_MEDIA),
        ..transport
    };

    let attach = AttachInfo {
        nick,
        icon: req.icon,
        admin: account.access.has(bit::DISCONNECT_USERS),
        access: account.access,
        login: account.login.clone(),
        addr: Some(peer.ip()),
        can_detach: account.can_detach,
        has_inbox: account.has_inbox,
        attach_news: account.attach_news,
        moderate: account.moderate,
        is_person: account.is_person(),
        // This wire has no `msg_read` and never will — a private message
        // is a window that opens and nothing comes back — so handing one
        // over is as much as it will ever say about reading it
        // (`docs/private-messages.md` §11).
        reads_on_delivery: true,
        // The account's link first, the socket's identity only where
        // there is none — see `AttachInfo::identity`. On this wire the
        // socket's identity arrives through the TRTP tunnel.
        identity: account
            .identity
            .fingerprint
            .or_else(|| transport.identity.as_ref().map(|t| t.fingerprint)),
        system: false,
        transport,
    };
    // A key revoked after the tunnel authenticated: `attach` refuses it,
    // and asking first only buys the right words.
    let revoked = attach
        .transport
        .identity
        .as_ref()
        .is_some_and(|t| ctx.core.is_revoked(&t.fingerprint, &t.device));
    let attached = if revoked {
        None
    } else {
        ctx.core.attach(attach)
    };
    let Some((uid, events)) = attached else {
        reply_error(
            tx,
            f.trans,
            if revoked {
                "This key is revoked on this server."
            } else {
                "Server full."
            },
        );
        return None;
    };

    // Login reply. A version-0 server sends only the uid (and a 1.0/1.2
    // client wouldn't know what to do with more).
    let mut login_reply = if ctx.cfg.version == 0 {
        vec![(tag::UID, uid.to_be_bytes().to_vec())]
    } else {
        vec![
            (tag::UID, uid.to_be_bytes().to_vec()),
            (tag::VERSION, ctx.cfg.version.to_be_bytes().to_vec()),
            (TAG_BANNERID, 0u16.to_be_bytes().to_vec()),
            (tag::SERVERNAME, enc.encode(&ctx.cfg.name)),
        ]
    };
    // The capability echo: the bits we agreed to (settled above, before
    // the attach), and nothing when we agreed to none — the spec's "omit
    // it and the session is standard mode". It rides even a version-0
    // reply: only a modern client asks the question, and one that asked
    // deserves the answer.
    if !caps.is_empty() {
        login_reply.push((tag::CAPABILITIES, caps.to_wire()));
    }
    // The ceilings, one field per kind, so the client can configure its
    // encoders before the first join rather than discovering them by
    // rejection.
    if caps.has(cap::VIDEO) {
        login_reply.extend(video::limits_chunks(&ctx.core.video_config()));
    }
    // The six advisory limits, which the spec makes a MUST beside a
    // confirmed bit 3: a client configures its own pre-flight from them
    // instead of discovering them by rejection.
    if caps.has(cap::INLINE_MEDIA) {
        if let Some(cfg) = ctx.core.media_config() {
            login_reply.extend(media::limits_chunks(cfg));
        }
    }
    if caps.has(cap::CHAT_HISTORY) {
        if let Some(history) = ctx.core.history_policy() {
            if history.max_lines != 0 {
                login_reply.push((
                    tag::HISTORY_MAX_MSGS,
                    history.max_lines.to_be_bytes().to_vec(),
                ));
            }
            if history.max_days != 0 {
                login_reply.push((
                    tag::HISTORY_MAX_DAYS,
                    history.max_days.to_be_bytes().to_vec(),
                ));
            }
        }
    }
    reply(tx, f.trans, login_reply);

    // Agreement dance (1.5 flow).
    let mut agreement_sent = false;
    if !account.access.has(bit::DONT_SHOW_AGREEMENT) {
        if let Some(text_utf8) = &ctx.cfg.agreement {
            push(tx, hdr::AGREEMENT, vec![(tag::BODY, enc.body(text_utf8))]);
            agreement_sent = true;
        }
    }
    if req.clientversion >= 150 && !agreement_sent {
        push(
            tx,
            hdr::AGREEMENT,
            vec![(tag::NOAGREEMENT, vec![0x00, 0x01])],
        );
    }

    let mut sess = Session {
        uid,
        account,
        announced: false,
        caps,
        enc,
        history_replayed: false,
        media_tokens: ctx
            .core
            .media_config()
            .map(|c| c.download_per_minute as f64)
            .unwrap_or(0.0),
        media_refill: Instant::now(),
        media_stream: None,
        transfer_addr: None,
        gif_icons: false,
        banner_sent: false,
        banner_image: None,
    };

    // A 1.5+ client that sent no name finishes its login via
    // AGREEMENTAGREE or USER_CHANGE; everyone else is done now.
    if req.clientversion < 150 || got_name {
        complete_login(tx, ctx, &mut sess).await;
    }
    Some((sess, events))
}

/// Run a domain call that touches the message store off the reactor.
///
/// `Core` is synchronous all the way down (`hxd_core::inbox` explains
/// why), so a flush or a `msg` is rusqlite with a five-second busy
/// timeout and `synchronous = FULL` fsyncs. On a tokio worker one slow
/// disk stalls every session that worker carries. This file already does
/// exactly this for `authenticate`.
pub(crate) async fn off_reactor<T: Send + 'static>(
    core: &Arc<hxd_core::Core>,
    f: impl FnOnce(&hxd_core::Core) -> T + Send + 'static,
) -> Option<T> {
    let core = core.clone();
    tokio::task::spawn_blocking(instrument::blocking(WIRE, move || f(&core)))
        .await
        .ok()
}

/// The "loginupdate" moment: hand the client its self-info and make it
/// visible (which broadcasts the join to everyone else).
async fn complete_login(tx: &Tx, ctx: &ServerCtx, sess: &mut Session) {
    if sess.announced {
        return;
    }
    if ctx.cfg.version != 0 {
        if let Some(me) = ctx.core.user(sess.uid) {
            // Real access bits — not the reference server's all-ones fake.
            // Clients use these to grey out what the account can't do,
            // which only works if they're true.
            push(
                tx,
                hdr::USER_SELFINFO,
                vec![
                    (tag::ACCESS, sess.account.access.to_wire().to_vec()),
                    (
                        tag::USER_LIST,
                        userlist_payload(&me, ctx.cfg.mark_cleartext, sess.enc),
                    ),
                ],
            );
        }
    }
    // The owner's avatar, before anyone is told the session exists. A
    // store read, so off the reactor — and only on a server with avatars,
    // so one without has nothing between the login and the join.
    if ctx.core.avatar_policy().is_some() {
        let uid = sess.uid;
        off_reactor(&ctx.core, move |c| c.restore_avatar(uid)).await;
    }
    ctx.core.announce(sess.uid);
    sess.announced = true;
    // Mail waiting from before this login, now that the roster is
    // coherent. On this wire each one opens a window, which is why the
    // domain caps a single flush and leaves the rest for next time.
    //
    // Whether this counts as reading them is the session's own property
    // (`AttachInfo::reads_on_delivery`), so it applies to a message that
    // arrives live just as much as to one waiting here.
    let uid = sess.uid;
    off_reactor(&ctx.core, move |c| c.flush_inbox(uid)).await;
}

/// A private message from the system account, or — on a server with
/// none — in the shape mhxd uses for its own server messages: the
/// recipient's own uid, which a 1.x client renders through the PM path.
fn system_msg(tx: &Tx, ctx: &ServerCtx, sess: &Session, text: &str) {
    let (uid, nick) = match (ctx.core.system_uid(), ctx.core.system_nick()) {
        (Some(uid), Some(nick)) => (uid, nick),
        _ => (sess.uid, "Server".to_string()),
    };
    push(
        tx,
        hdr::MSG,
        vec![
            (tag::UID, uid.to_be_bytes().to_vec()),
            (tag::BODY, sess.enc.body(text)),
            (tag::NAME, wire_nick(sess.enc, &nick)),
        ],
    );
}

/// Encode one domain event onto the wire. Returns `false` when the session
/// must end (kicked).
async fn deliver_event(tx: &Tx, ctx: &ServerCtx, sess: &Session, ev: Event) -> bool {
    match ev {
        Event::Changed(u) => {
            push(
                tx,
                hdr::USER_CHANGE,
                user_change_chunks(&u, ctx.cfg.mark_cleartext, sess.enc),
            );
        }
        Event::Joined(u) => {
            push(
                tx,
                hdr::USER_CHANGE,
                user_change_chunks(&u, ctx.cfg.mark_cleartext, sess.enc),
            );
            // A user list row cannot carry a picture, and a GIF-icon client
            // fetches one only on Icon Change: someone who joins already
            // wearing an avatar is announced as a change, as they were on
            // mhxd, where the client set it again after every login.
            if sess.gif_icons && u.avatar.is_some() {
                push(
                    tx,
                    hdr::ICON_CHANGE,
                    vec![(tag::UID, u.uid.to_be_bytes().to_vec())],
                );
            }
        }
        Event::Parted(uid) => {
            push(
                tx,
                hdr::USER_PART,
                vec![(tag::UID, uid.to_be_bytes().to_vec())],
            );
        }
        Event::AvatarChanged(u) => {
            if sess.gif_icons {
                push(
                    tx,
                    hdr::ICON_CHANGE,
                    vec![(tag::UID, u.uid.to_be_bytes().to_vec())],
                );
            }
        }
        Event::Chat {
            cid,
            from,
            text,
            style,
            media,
            ..
        } => {
            // Format at the edge, in the connection's encoding, so the
            // 13-column name alignment stays correct for its renderer.
            let line = format_chat(
                sess.enc,
                &wire_nick(sess.enc, &from.nick),
                &sess.enc.encode(&text),
                style,
            );
            let mut chunks = vec![(tag::BODY, line)];
            if cid != 0 {
                chunks.push((tag::CHAT_ID, cid.to_be_bytes().to_vec()));
            }
            chunks.push((tag::UID, from.uid.to_be_bytes().to_vec()));
            // Per connection, not per event: the same relayed line is
            // two different frames for a capable and a classic client in
            // one room, and neither knows about the other. A client that
            // did not negotiate the bit sees the text and nothing else,
            // which is the spec's own fallback.
            if let Some(media) = media.filter(|_| sess.caps.has(cap::INLINE_MEDIA)) {
                chunks.extend(media::companion_chunks(&media));
            }
            push(tx, hdr::CHAT, chunks);
        }
        Event::Notice { cid, from, text } => {
            // The legacy rendering of a server notice: `\r<text>`.
            let mut line = Vec::with_capacity(text.len() + 3);
            line.push(b'\r');
            line.push(b'<');
            line.extend_from_slice(&sess.enc.encode(&text));
            line.push(b'>');
            let mut chunks = vec![(tag::BODY, line)];
            if cid != 0 {
                chunks.push((tag::CHAT_ID, cid.to_be_bytes().to_vec()));
            }
            chunks.push((tag::UID, from.to_be_bytes().to_vec()));
            push(tx, hdr::CHAT, chunks);
        }
        Event::ChatSubject { cid, subject } => {
            push(
                tx,
                hdr::CHAT_SUBJECT,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::CHAT_SUBJECT, wire_subject(sess.enc, &subject)),
                ],
            );
        }
        Event::ChatPassword { cid, password } => {
            push(
                tx,
                hdr::CHAT_SUBJECT,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::PASSWORD, sess.enc.encode(&password)),
                ],
            );
        }
        Event::ChatInvite {
            cid,
            from,
            from_nick,
        } => {
            push(
                tx,
                hdr::CHAT_INVITE,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::UID, from.to_be_bytes().to_vec()),
                    (tag::NAME, wire_nick(sess.enc, &from_nick)),
                ],
            );
        }
        Event::ChatUserJoined { cid, user } => {
            push(
                tx,
                hdr::CHAT_USER_CHANGE,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::UID, user.uid.to_be_bytes().to_vec()),
                    (tag::ICON, user.icon.to_be_bytes().to_vec()),
                    (
                        tag::COLOUR,
                        wire_color(&user, ctx.cfg.mark_cleartext)
                            .to_be_bytes()
                            .to_vec(),
                    ),
                    (tag::NAME, wire_nick(sess.enc, &user.nick)),
                ],
            );
        }
        Event::ChatUserParted { cid, uid } => {
            push(
                tx,
                hdr::CHAT_USER_PART,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::UID, uid.to_be_bytes().to_vec()),
                ],
            );
        }
        Event::Msg {
            from,
            from_nick,
            text,
            sent_at,
            queued,
            media,
            ..
        } => {
            let body = if queued && ctx.cfg.stamp_queued {
                format!("[queued {}]\r{text}", stamp(sent_at))
            } else {
                text
            };
            // `from` is 0 when a queued message's sender has no session
            // now — and a 104 with UID 0 is not a private message to a
            // 1.x client. GtkHx dispatches on the uid (`is_pm = uid > 0`,
            // `rcv.c`), so a uid-0 frame lands in the chat pane as a
            // broadcast line with the `[queued …]` stamp inline: no PM
            // window, nothing to reply to. Send the recipient's own uid
            // instead, which is the shape mhxd uses for its own server
            // messages and which renders through the PM path with the
            // wire NAME — the sender's — as the name. Replying goes to
            // yourself rather than to nobody, which is the better of the
            // two answers a wire with no "from an absent user" has.
            let uid = if from == 0 { sess.uid } else { from };
            let mut chunks = vec![
                (tag::UID, uid.to_be_bytes().to_vec()),
                (tag::BODY, sess.enc.body(&body)),
                (tag::NAME, wire_nick(sess.enc, &from_nick)),
            ];
            if let Some(media) = media.filter(|_| sess.caps.has(cap::INLINE_MEDIA)) {
                chunks.extend(media::companion_chunks(&media));
            }
            push(tx, hdr::MSG, chunks);
        }
        Event::Broadcast {
            from,
            from_nick,
            text,
        } => {
            push(
                tx,
                hdr::MSG_BROADCAST,
                vec![
                    (tag::UID, from.to_be_bytes().to_vec()),
                    (tag::BODY, sess.enc.body(&text)),
                    (tag::NAME, wire_nick(sess.enc, &from_nick)),
                ],
            );
        }
        // Voice notifications: task id 0, per the extension spec's
        // transaction semantics. Only a session that negotiated the
        // capability and then joined can be here at all.
        Event::VoiceOffer { cid, sdp } => {
            // A chunk's length is 16 bits, and `pack_frame` asserts it.
            // The SFU caps its own offers well under that, so this is
            // the belt to that braces: an offer that somehow outgrew the
            // wire is dropped and logged rather than turned into a
            // panic in this connection's writer.
            if sdp.len() > u16::MAX as usize {
                warn!(cid, len = sdp.len(), "voice offer too large for the wire");
                return true;
            }
            notify(
                tx,
                ServerHdr::VoiceSdpOffer as u32,
                vec![voice::chat_id(cid), (tag::VOICE_SDP, sdp.into_bytes())],
            );
        }
        Event::VoiceIce { cid, candidate } => {
            notify(
                tx,
                ServerHdr::VoiceIce as u32,
                vec![
                    voice::chat_id(cid),
                    (tag::VOICE_ICE, voice::ice_payload(&candidate)),
                ],
            );
        }
        Event::VoiceStatus { cid, participants } => {
            notify(
                tx,
                ServerHdr::VoiceRoomStatus as u32,
                vec![
                    voice::chat_id(cid),
                    (
                        tag::VOICE_PARTICIPANTS,
                        voice::participants_payload(&participants),
                    ),
                ],
            );
        }

        // Video's one notification. Dropped for a session that didn't
        // negotiate `CAPABILITY_VIDEO`: the domain sends the event to
        // everyone in the room on purpose, because whether a wire can
        // say "a camera is on" is the frontend's business, and this wire
        // can only say it to a client that asked for the extension.
        // Unlike the ng wire there is no seq accounting to keep here, so
        // dropping it really is dropping it.
        Event::VideoStatus { cid, publications } => {
            if !sess.has_cap(cap::VIDEO) {
                return true;
            }
            notify(
                tx,
                ServerHdr::VideoStatus as u32,
                vec![
                    video::chat_id(cid),
                    (
                        tag::VIDEO_PUBLISHERS,
                        video::publishers_payload(&publications),
                    ),
                    (tag::VIDEO_CODEC, ctx.core.video_codec().as_bytes().to_vec()),
                ],
            );
        }

        // Nothing to send. A 106 was pushed and this wire has no
        // transaction to unsend it, so a rendered line keeps its image
        // until the window scrolls; what the revocation does reach is
        // the next 751, which now answers "not found"
        // (moderation.md §6).
        Event::MediaRevoked { .. } => {}
        // The same limit, for a line: a 106 was sent and there is no
        // transaction to unsend it (moderation.md §6). History (700)
        // shows the tombstone, which is what a capable client reads.
        Event::ChatRedacted { .. } => {}
        // A report reaches a legacy moderator as a private message from
        // the system account (moderation.md §4.5): a window that opens,
        // and nothing a period client has to understand beyond that.
        Event::Report(report) => {
            if ctx.core.moderation_policy().notify_legacy {
                system_msg(tx, ctx, sess, &report.summary());
            }
        }
        // The reporter hears how it ended; the moderators, who acted or
        // saw it acted on, need no window for it on this wire.
        Event::ReportClosed {
            id,
            outcome,
            yours: true,
        } => {
            system_msg(
                tx,
                ctx,
                sess,
                &format!("[report #{id}] closed: {}", outcome.name()),
            );
        }
        Event::ReportClosed { yours: false, .. } => {}
        // A post into the flat category grows a 1.2 client's pane, whichever
        // wire it came from (`docs/news.md` §12.5): mhxd's push, carrying
        // the one new entry for the client to prepend. Every reader gets
        // it, the poster included, as on mhxd — this wire has no way to
        // tell a 1.2 client from a 1.5 one, and GtkHx prepends it too.
        Event::NewsPosted { id, category, .. } => {
            let who = news::Asker {
                uid: sess.uid,
                enc: sess.enc,
            };
            if let Some(entry) = news::flat_push(&ctx.core, &ctx.cfg.news, who, id, category).await
            {
                push(
                    tx,
                    ServerHdr::NewsFilePost.as_u32(),
                    vec![(tag::NEWS, entry)],
                );
            }
        }
        // Nothing to say. A 1.5 client refetches a listing when it opens
        // one, and the period wire has no push for a threaded change.
        //
        // `NewsNotify` is a notice for one person: a legacy account is
        // notified through a system mailbox with a `stop` reply, which is
        // a feature of its own (`docs/news.md` §10.11).
        Event::NewsDeleted { .. }
        | Event::NewsNode(_)
        | Event::NewsNodeDeleted { .. }
        | Event::NewsNotify(_) => {}
        Event::Kicked => return false,
    }
    true
}

async fn session_loop(
    frames: &mut Receiver<Frame>,
    events: &mut UnboundedReceiver<SeqEvent>,
    tx: &Tx,
    ctx: &ServerCtx,
    sess: &mut Session,
) -> Option<&'static str> {
    loop {
        tokio::select! {
            maybe = frames.recv() => match maybe {
                Some(f) => {
                    trace_in(&f);
                    dispatch(&f, tx, ctx, sess).await;
                }
                None => return None, // Reader exited: EOF, error, or bad frame.
            },
            maybe = events.recv() => match maybe {
                Some(se) => {
                    if !deliver_event(tx, ctx, sess, se.event).await {
                        info!(uid = sess.uid, "kicked");
                        return Some("kicked");
                    }
                }
                None => return Some("replaced"), // Detached elsewhere; shouldn't happen.
            },
        }
    }
}

async fn dispatch(f: &Frame, tx: &Tx, ctx: &ServerCtx, sess: &mut Session) {
    match f.ty {
        t if t == ClientHdr::Ping.as_u32() => reply(tx, f.trans, vec![]),

        t if t == ClientHdr::UserGetList.as_u32() => {
            let mut chunks: Vec<(u16, Vec<u8>)> = ctx
                .core
                .snapshot()
                .iter()
                .map(|u| {
                    (
                        tag::USER_LIST,
                        userlist_payload(u, ctx.cfg.mark_cleartext, sess.enc),
                    )
                })
                .collect();
            chunks.push((
                tag::CHAT_SUBJECT,
                wire_subject(sess.enc, &ctx.core.public_subject()),
            ));
            reply(tx, f.trans, chunks);
            // Optional compatibility replay, only for clients that did
            // not negotiate history and only after their first user list.
            if !sess.history_replayed
                && !sess.has_cap(cap::CHAT_HISTORY)
                && sess.can(bit::CHAT_HISTORY)
            {
                sess.history_replayed = true;
                if let Some(policy) = ctx.core.history_policy() {
                    if policy.replay > 0 {
                        let uid = sess.uid;
                        let query = hxd_core::HistoryQuery {
                            channel: 0,
                            before: None,
                            after: None,
                            limit: policy.replay.min(policy.max_page),
                        };
                        if let Some(Ok(page)) =
                            off_reactor(&ctx.core, move |c| c.history(uid, query)).await
                        {
                            for line in page.lines {
                                push(
                                    tx,
                                    hdr::CHAT,
                                    vec![(tag::BODY, format_replay(&line, sess.enc))],
                                );
                            }
                        }
                    }
                }
            }
        }

        t if t == ClientHdr::UserChange.as_u32() => {
            let (mut nick, mut icon) = (None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::NAME if sess.can(bit::USE_ANY_NAME) => {
                        nick = Some(sess.enc.decode_chars(c.data, 31));
                    }
                    tag::ICON => icon = Some(c.as_uint() as u16),
                    _ => {}
                }
            }
            ctx.core.update(sess.uid, nick, icon);
            if !sess.announced {
                complete_login(tx, ctx, sess).await;
            }
            // No reply — USER_CHANGE is fire-and-forget on the wire.
        }

        t if t == ClientHdr::AgreementAgree.as_u32() => {
            let (mut nick, mut icon) = (None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::NAME if sess.can(bit::USE_ANY_NAME) => {
                        nick = Some(sess.enc.decode_chars(c.data, 31));
                    }
                    tag::ICON => {
                        let v = c.as_uint() as u16;
                        if v != 0 {
                            icon = Some(v);
                        }
                    }
                    _ => {}
                }
            }
            reply(tx, f.trans, vec![]); // ack first, like the reference
            ctx.core.update(sess.uid, nick, icon);
            if !sess.announced {
                complete_login(tx, ctx, sess).await;
            }
            // The banner follows the agreement, as on mhxd: only a 1.5+
            // client agrees, and only one of those knows what a banner
            // is. Once per session, however often the client agrees.
            if let Some(banner) = ctx.banner.as_ref().filter(|_| !sess.banner_sent) {
                sess.banner_sent = true;
                // A tunnelled session fetches a held banner through the
                // tunnel's `/htxf` (`hotline-ng-auth.md` §7.4), which
                // `hlid tunnel` serves on its own port + 1, where a classic
                // client looks.
                let offer = banner.offer();
                sess.banner_image = offer.image;
                push(tx, hdr::BANNER, offer.chunks);
            }
        }

        // No access bit, as on mhxd: the banner is the server's own
        // decoration, shown to every account that was sent it.
        t if t == ClientHdr::DownloadBanner.as_u32() => {
            let transfers = ctx.banner.as_ref().and_then(|banner| banner.transfers());
            let (Some(image), Some(transfers)) = (sess.banner_image.clone(), transfers) else {
                // mhxd leaves this unanswered; a task error is kinder to a
                // client waiting on its reply.
                reply_error(tx, f.trans, "There is no banner to download.");
                return;
            };
            let Some(serial) = ctx.core.session_serial(sess.uid) else {
                reply_error(tx, f.trans, "Session ended.");
                return;
            };
            let size = image.bytes.len() as u32;
            let issued = transfers.issue(hxd_files::PreparedTransfer::Banner(
                hxd_files::PreparedBanner {
                    principal: FilePrincipal {
                        uid: sess.uid,
                        serial,
                    },
                    account: sess.account.login.clone(),
                    peer: sess.transfer_addr,
                    bytes: image.bytes,
                },
            ));
            let reference = match issued {
                Ok(reference) => reference,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            sess.banner_image = None;
            // mhxd sends the size in two bytes, truncating any banner past
            // 64 KiB. Those bytes exactly whenever they are right, and four
            // when they would not be: a client reads the field as an
            // integer of either width.
            let size = match u16::try_from(size) {
                Ok(short) => short.to_be_bytes().to_vec(),
                Err(_) => size.to_be_bytes().to_vec(),
            };
            reply(
                tx,
                f.trans,
                vec![
                    (tag::HTXF_SIZE, size),
                    (tag::HTXF_REF, reference.to_be_bytes().to_vec()),
                ],
            );
        }

        // --- Read-only Files -----------------------------------------
        // Listing and Get Info have no access bit; the bitmap defines none
        // for them. As on mhxd they are the server-local `file_list` and
        // `file_getinfo` extras, which every account has unless its file
        // turns them off (accounts.c), so a user who may not download can
        // still browse.
        t if t == ClientHdr::FileList.as_u32() => {
            if !sess.account.file_list {
                reply_error(tx, f.trans, "You are not allowed to list files.");
                return;
            }
            let Some(service) = ctx.files.as_ref() else {
                reply_error(tx, f.trans, "Files are not available on this server.");
                return;
            };
            let dir = f.chunks().find(|chunk| chunk.tag == tag::DIR);
            let large = sess.has_cap(cap::LARGE_FILES);
            let path = match files::resolve_dir(
                service.source.as_ref(),
                dir.as_ref().map(|chunk| chunk.data),
                large,
                sess.enc,
            )
            .await
            {
                Ok(path) => path,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            // mhxd shows a drop box's contents only to accounts that may
            // view drop boxes (files.c, check_dropbox).
            if path.is_drop_box() && !sess.can(bit::VIEW_DROP_BOXES) {
                reply_error(tx, f.trans, "You are not allowed to view drop boxes.");
                return;
            }
            let entries = match files::list(service.source.as_ref(), &path, large, sess.enc).await {
                Ok(entries) => entries,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            let mut chunks = Vec::with_capacity(entries.len() * if large { 2 } else { 1 });
            // DataSize includes the two-byte chunk count as well as every
            // chunk header and payload.
            let mut wire_len = 2usize;
            for entry in entries {
                let payload = files::list_payload(&entry);
                wire_len = wire_len.saturating_add(4 + payload.len());
                chunks.push((files::LIST_TAG, payload));
                if large {
                    wire_len = wire_len.saturating_add(12);
                    chunks.push((tag::FILESIZE64, entry.entry.size.to_be_bytes().to_vec()));
                }
            }
            if wire_len > MAX_FRAME_DATA as usize {
                reply_error(tx, f.trans, "This folder has too many entries.");
            } else {
                reply(tx, f.trans, chunks);
            }
        }

        t if t == ClientHdr::FileGetInfo.as_u32() => {
            if !sess.account.file_getinfo {
                reply_error(tx, f.trans, "You are not allowed to get file info.");
                return;
            }
            let Some(service) = ctx.files.as_ref() else {
                reply_error(tx, f.trans, "Files are not available on this server.");
                return;
            };
            let name = f.chunks().find(|chunk| chunk.tag == tag::FILE_NAME);
            let dir = f.chunks().find(|chunk| chunk.tag == tag::DIR);
            let Some(name) = name else {
                reply_error(tx, f.trans, "No file name was supplied.");
                return;
            };
            let large = sess.has_cap(cap::LARGE_FILES);
            let (_path, info, wire_name) = match files::resolve_entry(
                service.source.as_ref(),
                dir.as_ref().map(|chunk| chunk.data),
                name.data,
                large,
                sess.enc,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            let entry = FileEntry {
                name: info.path.name().unwrap_or_default().to_owned(),
                kind: info.kind,
                size: info.size,
                media_type: info.media_type.clone(),
                modified: info.modified,
            };
            let (inferred_type, inferred_creator) = files::type_creator(&entry);
            let type_code = info.type_code.unwrap_or(inferred_type);
            // Get Info shows a folder's creator as "n/a ", as mhxd answers
            // it; listings keep the creator they have always carried.
            let creator = if info.kind == FileKind::Folder {
                *b"n/a "
            } else {
                info.creator_code.unwrap_or(inferred_creator)
            };
            let mut chunks = vec![
                (tag::FILE_NAME, wire_name),
                (tag::FILE_TYPE, type_code.to_vec()),
                (tag::FILE_CREATOR, creator.to_vec()),
                // Field 213, the type code the Get Info window draws its
                // icon from.
                (tag::FILE_ICON, type_code.to_vec()),
                (
                    tag::FILE_SIZE,
                    (info.size.min(u32::MAX as u64) as u32)
                        .to_be_bytes()
                        .to_vec(),
                ),
            ];
            if large {
                chunks.push((tag::FILESIZE64, info.size.to_be_bytes().to_vec()));
            }
            chunks.push((tag::FILE_DATE_CREATE, files::date(info.created)));
            chunks.push((tag::FILE_DATE_MODIFY, files::date(info.modified)));
            chunks.push((
                tag::FILE_COMMENT,
                sess.enc
                    .body_capped(info.comment.as_deref().unwrap_or_default(), 255),
            ));
            reply(tx, f.trans, chunks);
        }

        t if t == ClientHdr::FileGet.as_u32() => {
            if !sess.can(bit::DOWNLOAD_FILES) {
                reply_error(tx, f.trans, "You are not allowed to download files.");
                return;
            }
            let Some(service) = ctx.files.as_ref() else {
                reply_error(tx, f.trans, "Files are not available on this server.");
                return;
            };
            let name = f.chunks().find(|chunk| chunk.tag == tag::FILE_NAME);
            let dir = f.chunks().find(|chunk| chunk.tag == tag::DIR);
            let Some(name) = name else {
                reply_error(tx, f.trans, "No file name was supplied.");
                return;
            };
            let large = sess.has_cap(cap::LARGE_FILES);
            let (path, info, wire_name) = match files::resolve_file(
                service.source.as_ref(),
                dir.as_ref().map(|chunk| chunk.data),
                name.data,
                large,
                sess.enc,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            if info.kind != FileKind::File {
                reply_error(tx, f.trans, "That path is not a file.");
                return;
            }
            let resume = f
                .chunks()
                .find(|chunk| chunk.tag == tag::RFLT)
                .map(|chunk| hxfiles_xfer::rflt::parse_compatible(chunk.data))
                .unwrap_or_default();
            let mut offset = u64::from(resume.data);
            let resource_offset = u64::from(resume.resource);
            if let Some(chunk) = f.chunks().find(|chunk| chunk.tag == tag::OFFSET64) {
                if !large || chunk.data.len() != 8 {
                    reply_error(tx, f.trans, "Malformed file resume offset.");
                    return;
                }
                offset = u64::from_be_bytes(chunk.data.try_into().expect("eight bytes"));
            }
            // Offsets at the very end are a finished download asking again;
            // they get a transfer of headers alone, as mhxd sends it.
            if offset > info.size {
                reply_error(tx, f.trans, "Resume offset is beyond the file.");
                return;
            }
            if resource_offset > info.resource_size {
                reply_error(
                    tx,
                    f.trans,
                    "Resource-fork resume offset is beyond the file.",
                );
                return;
            }
            // A resume from inside the file needs a source that can start
            // there. Refused here, the client gets a task error; issued a
            // reference, it would only see its transfer socket close.
            if offset != 0 && offset < info.size && !service.source.supports_ranges(&path) {
                reply_error(tx, f.trans, "This file cannot be resumed.");
                return;
            }
            let Some(serial) = ctx.core.session_serial(sess.uid) else {
                reply_error(tx, f.trans, "Session ended.");
                return;
            };
            let entry = FileEntry {
                name: info.path.name().unwrap_or_default().to_owned(),
                kind: info.kind,
                size: info.size,
                media_type: info.media_type.clone(),
                modified: info.modified,
            };
            let (inferred_type, inferred_creator) = files::type_creator(&entry);
            let type_code = info.type_code.unwrap_or(inferred_type);
            let creator = info.creator_code.unwrap_or(inferred_creator);
            let comment = sess
                .enc
                .body_capped(info.comment.as_deref().unwrap_or_default(), 255);
            let prepared = hxd_files::prepare_legacy(
                &service.transfers,
                service.source.clone(),
                hxd_files::LegacyTransfer {
                    principal: FilePrincipal {
                        uid: sess.uid,
                        serial,
                    },
                    account: sess.account.login.clone(),
                    peer: sess.transfer_addr,
                    path,
                    offset,
                    resource_offset,
                    large,
                    wire_name,
                    type_code,
                    creator,
                    wire_comment: comment,
                },
            )
            .await;
            let (reference, transfer_size) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            let mut chunks = vec![
                (tag::HTXF_REF, reference.to_be_bytes().to_vec()),
                (
                    tag::HTXF_SIZE,
                    (transfer_size.min(u32::MAX as u64) as u32)
                        .to_be_bytes()
                        .to_vec(),
                ),
            ];
            if large {
                chunks.push((tag::XFERSIZE64, transfer_size.to_be_bytes().to_vec()));
                chunks.push((
                    tag::FILE_SIZE,
                    (info.size.min(u32::MAX as u64) as u32)
                        .to_be_bytes()
                        .to_vec(),
                ));
                chunks.push((tag::FILESIZE64, info.size.to_be_bytes().to_vec()));
                chunks.push((tag::OFFSET64, offset.to_be_bytes().to_vec()));
            }
            reply(tx, f.trans, chunks);
        }

        t if t == ClientHdr::FilePut.as_u32() => {
            if !sess.can(bit::UPLOAD_FILES) {
                reply_error(tx, f.trans, "You are not allowed to upload files.");
                return;
            }
            let Some(service) = ctx.files.as_ref() else {
                reply_error(tx, f.trans, "Files are not available on this server.");
                return;
            };
            let Some(source) = service.uploads.as_ref() else {
                reply_error(tx, f.trans, "This file area is read-only.");
                return;
            };
            let Some(name) = f.chunks().find(|chunk| chunk.tag == tag::FILE_NAME) else {
                reply_error(tx, f.trans, "No file name was supplied.");
                return;
            };
            let dir = f.chunks().find(|chunk| chunk.tag == tag::DIR);
            let large = sess.has_cap(cap::LARGE_FILES);
            let path = match files::resolve_upload(
                service.source.as_ref(),
                dir.as_ref().map(|chunk| chunk.data),
                name.data,
                large,
                sess.enc,
            )
            .await
            {
                Ok(path) => path,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            // mhxd lets an account without upload-anywhere upload into any
            // folder whose path names an upload folder or a drop box
            // (files.c, rcv_file_put).
            if !sess.can(bit::UPLOAD_ANYWHERE)
                && !path
                    .parent()
                    .is_some_and(|folder| folder.is_upload_folder())
            {
                reply_error(tx, f.trans, "You are not allowed to upload files here.");
                return;
            }
            // A resume needs the client to ask for one. mhxd writes an upload
            // in place, so an interrupted one is listed and a client offers
            // to resume what it sees; here a partial stays unlisted until it
            // completes, so nobody is served half a file, and a client that
            // offers resume only for a listed file starts over instead.
            //
            // mhxd reads these fields as integers of whatever width they
            // come in, and a zero option asks for no resume.
            let resume_requested = match f.chunks().find(|chunk| chunk.tag == tag::FILE_PREVIEW) {
                None => false,
                Some(chunk) => match files::wire_uint(chunk.data) {
                    Some(option) => option != 0,
                    None => {
                        reply_error(tx, f.trans, "Malformed upload resume option.");
                        return;
                    }
                },
            };
            let legacy_size = match f.chunks().find(|chunk| chunk.tag == tag::HTXF_SIZE) {
                None => None,
                Some(chunk) => match files::wire_uint(chunk.data).map(u32::try_from) {
                    Some(Ok(size)) => Some(size),
                    _ => {
                        reply_error(tx, f.trans, "Malformed upload size.");
                        return;
                    }
                },
            };
            let wide_size = match f.chunks().find(|chunk| chunk.tag == tag::XFERSIZE64) {
                None => None,
                Some(_) if !large => {
                    reply_error(tx, f.trans, "64-bit upload size was not negotiated.");
                    return;
                }
                Some(chunk) if chunk.data.len() == 8 => Some(u64::from_be_bytes(
                    chunk.data.try_into().expect("eight bytes"),
                )),
                Some(_) => {
                    reply_error(tx, f.trans, "Malformed 64-bit upload size.");
                    return;
                }
            };
            let transfer_len = match (legacy_size, wide_size) {
                (Some(legacy), Some(wide)) => {
                    if legacy != wide.min(u64::from(u32::MAX)) as u32 {
                        reply_error(tx, f.trans, "Upload sizes disagree.");
                        return;
                    }
                    Some(wide)
                }
                // XFERSIZE64 is a SHOULD. Without it the 32-bit size stands,
                // unless it is clamped and so is not the length.
                (Some(legacy), None) if !large || legacy != u32::MAX => Some(u64::from(legacy)),
                (Some(_), None) => {
                    reply_error(tx, f.trans, "Large uploads require a 64-bit size.");
                    return;
                }
                (None, Some(wide)) => Some(wide),
                // The size is optional (Hotline.md, Upload File): mhxd's own
                // client never sends it, and a Large File resume request
                // leaves it out. The handshake states it instead.
                (None, None) => None,
            };
            let Some(serial) = ctx.core.session_serial(sess.uid) else {
                reply_error(tx, f.trans, "Session ended.");
                return;
            };
            let prepared = hxd_files::prepare_upload(
                &service.transfers,
                source.clone(),
                hxd_files::UploadTransfer {
                    principal: FilePrincipal {
                        uid: sess.uid,
                        serial,
                    },
                    peer: sess.transfer_addr,
                    path,
                    owner: sess.account.login.clone(),
                    transfer_len,
                    large,
                    resume_requested,
                    comment_utf8: sess.enc == TextEncoding::Utf8,
                },
            )
            .await;
            let (reference, quote) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    reply_error(tx, f.trans, file_error_text(&error));
                    return;
                }
            };
            let resumed = quote.as_ref().map_or(0, |value| {
                value.data_offset.saturating_add(value.resource_offset)
            });
            let mut chunks = vec![(tag::HTXF_REF, reference.to_be_bytes().to_vec())];
            // Without a declared size there is no remainder to echo, as in
            // mhxd's reply; the client works it out from the quoted offset.
            if let Some(transfer_len) = transfer_len {
                let Some(remaining) = transfer_len.checked_sub(resumed) else {
                    reply_error(tx, f.trans, "Stored partial exceeds the upload size.");
                    return;
                };
                chunks.push((
                    tag::HTXF_SIZE,
                    (remaining.min(u64::from(u32::MAX)) as u32)
                        .to_be_bytes()
                        .to_vec(),
                ));
                if large {
                    chunks.push((tag::XFERSIZE64, remaining.to_be_bytes().to_vec()));
                }
            }
            if let Some(quote) = quote {
                if quote.data_offset > u64::from(u32::MAX)
                    || quote.resource_offset > u64::from(u32::MAX)
                {
                    if !large {
                        reply_error(tx, f.trans, "Stored partial needs Large File support.");
                        return;
                    }
                } else {
                    let rflt = hxfiles_xfer::rflt::encode(hxfiles_xfer::rflt::Resume {
                        data: quote.data_offset as u32,
                        resource: quote.resource_offset as u32,
                    });
                    chunks.push((tag::RFLT, rflt.to_vec()));
                }
                if large {
                    chunks.push((tag::OFFSET64, quote.data_offset.to_be_bytes().to_vec()));
                    if let Some(digest) = quote.digest {
                        chunks.push((tag::PARTIAL_DIGEST, digest.to_vec()));
                    }
                }
            }
            reply(tx, f.trans, chunks);
        }

        // --- Chat -----------------------------------------------------
        t if t == ClientHdr::Chat.as_u32() => {
            let (mut cid, mut style, mut body) = (0u32, 0u16, String::new());
            let (mut handle, mut declared) = (None, false);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::STYLE => style = c.as_uint() as u16,
                    tag::BODY => body = sess.enc.decode_capped(c.data, MAX_CHAT_INPUT),
                    tag::CHAT_MEDIA_ID => handle = media::parse_handle(c.data),
                    tag::CHAT_MEDIA_TYPE => declared = true,
                    TAG_CHAT_AWAY => {} // No away state yet; rider ignored.
                    _ => {}
                }
            }
            // The reference server drops unpermitted chat silently (no
            // task reply exists for a notification-style send).
            if !sess.can(bit::SEND_CHAT) {
                debug!(uid = sess.uid, "chat dropped: no send_chat access");
                return;
            }
            // "Servers MUST drop these fields from any inbound
            // transaction whose sender did not negotiate the
            // capability" — the text still goes through as plain chat.
            let media = match (handle, declared) {
                _ if !sess.has_cap(cap::INLINE_MEDIA) => None,
                // The two travel together or not at all. One without
                // the other is a malformed send, and this transaction
                // has no task reply to refuse it with, so it goes the
                // way an unpermitted chat goes.
                (Some(_), false) | (None, true) => {
                    debug!(uid = sess.uid, "chat dropped: media fields are unpaired");
                    return;
                }
                (handle, _) => handle,
            };
            if cid == 0 {
                let from = sess.uid;
                match off_reactor(&ctx.core, move |c| c.chat_public(from, body, style, media)).await
                {
                    Some(Err(ChatError::NoSuchMedia)) => {
                        debug!(
                            uid = sess.uid,
                            "chat dropped: media handle is not this sender's"
                        )
                    }
                    Some(Err(e)) => warn!(uid = sess.uid, "public chat store failed: {e:?}"),
                    _ => {}
                }
            } else if let Err(e) = ctx.core.chat_private(cid, sess.uid, body, style, media) {
                debug!(uid = sess.uid, cid, "private chat dropped: {e:?}");
            }
        }

        t if t == ClientHdr::GetChatHistory.as_u32() => {
            if !sess.has_cap(cap::CHAT_HISTORY) {
                reply_error(tx, f.trans, "Chat history was not negotiated.");
                return;
            }
            if !sess.can(bit::CHAT_HISTORY) {
                reply_error(tx, f.trans, "You are not allowed to read chat history.");
                return;
            }
            if !ctx.core.allow_history_request(sess.uid).unwrap_or(false) {
                reply_error(tx, f.trans, "Slow down.");
                return;
            }

            let (mut channel, mut before, mut after, mut limit) = (None, None, None, None);
            let mut malformed = false;
            for chunk in f.chunks() {
                match chunk.tag {
                    tag::CHANNEL_ID if chunk.data.len() == 4 => {
                        channel = Some(u32::from_be_bytes(chunk.data.try_into().unwrap()))
                    }
                    tag::HISTORY_BEFORE if chunk.data.len() == 8 => {
                        let id = u64::from_be_bytes(chunk.data.try_into().unwrap());
                        before = (id != 0).then_some(id);
                    }
                    tag::HISTORY_AFTER if chunk.data.len() == 8 => {
                        let id = u64::from_be_bytes(chunk.data.try_into().unwrap());
                        after = (id != 0).then_some(id);
                    }
                    tag::HISTORY_LIMIT if chunk.data.len() == 2 => {
                        limit = Some(u16::from_be_bytes(chunk.data.try_into().unwrap()))
                    }
                    tag::CHANNEL_ID
                    | tag::HISTORY_BEFORE
                    | tag::HISTORY_AFTER
                    | tag::HISTORY_LIMIT => malformed = true,
                    _ => {}
                }
            }
            if malformed || channel.is_none() {
                reply_error(tx, f.trans, "Malformed chat history request.");
                return;
            }
            if channel != Some(0) {
                reply_error(tx, f.trans, "No such channel.");
                return;
            }
            // The capability and the log come from the same config, but
            // `ServerConfig` is public and nothing makes the two agree,
            // so answer the way the ng wire does rather than panic.
            let Some(policy) = ctx.core.history_policy() else {
                reply_error(tx, f.trans, "Chat history is not available.");
                return;
            };
            let requested = limit.filter(|n| *n != 0).map_or(50, usize::from);
            let query = hxd_core::HistoryQuery {
                channel: 0,
                before,
                after,
                limit: requested.min(policy.max_page),
            };
            let uid = sess.uid;
            match off_reactor(&ctx.core, move |c| c.history(uid, query)).await {
                Some(Ok(page)) => {
                    let mut entries = Vec::with_capacity(page.lines.len());
                    for line in page.lines {
                        let deleted = line.flags.contains(hxd_core::LineFlags::DELETED);
                        let nick = if deleted {
                            Vec::new()
                        } else {
                            sess.enc.encode(&line.from_nick)
                        };
                        let body = if deleted {
                            Vec::new()
                        } else {
                            sess.enc.encode(&line.text)
                        };
                        let timestamp = line
                            .at
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64);
                        let Some(entry) = hxproto::build::build_history_entry(
                            line.id,
                            timestamp,
                            line.flags.bits(),
                            line.icon,
                            &nick,
                            &body,
                            &[],
                        ) else {
                            warn!(id = line.id, "chat history entry exceeds the wire chunk");
                            reply_error(tx, f.trans, "Server error.");
                            return;
                        };
                        entries.push(entry);
                    }
                    let (entries, trimmed) = fit_history_entries(entries, after.is_some());
                    let mut chunks = Vec::with_capacity(entries.len() + 2);
                    chunks.push((tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec()));
                    chunks.extend(entries.into_iter().map(|e| (tag::HISTORY_ENTRY, e)));
                    let has_more = page.has_more || trimmed;
                    chunks.push((tag::HISTORY_HAS_MORE, vec![u8::from(has_more)]));
                    reply(tx, f.trans, chunks);
                }
                Some(Err(e)) => {
                    warn!(uid = sess.uid, "chat history query failed: {e:?}");
                    reply_error(tx, f.trans, "Server error.");
                }
                None => reply_error(tx, f.trans, "Server error."),
            }
        }

        t if t == ClientHdr::ChatSubject.as_u32() => {
            let (mut cid, mut subject, mut password) = (0u32, None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::CHAT_SUBJECT => subject = Some(sess.enc.decode_chars(c.data, 255)),
                    tag::PASSWORD => password = Some(sess.enc.decode_chars(c.data, 31)),
                    _ => {}
                }
            }
            // Public-subject policy: the account file's [extra]
            // set_subject flag (default: tracks the admin bit) — the
            // reference server's config-granted privilege, done properly.
            if cid == 0 && !sess.account.set_subject {
                debug!(uid = sess.uid, "public subject refused");
                return;
            }
            if let Some(s) = subject {
                if let Err(e) = ctx.core.chat_subject(cid, sess.uid, s) {
                    debug!(uid = sess.uid, cid, "subject refused: {e:?}");
                }
            }
            if cid != 0 {
                if let Some(p) = password {
                    let _ = ctx.core.chat_password(cid, sess.uid, p);
                }
            }
            // No task reply — the reference server never acks this opcode,
            // and clients are built around that.
        }

        // --- Private chats --------------------------------------------
        t if t == ClientHdr::ChatCreate.as_u32() => {
            if !sess.can(bit::CREATE_PCHATS) {
                reply_error(tx, f.trans, "You are not allowed to create private chats.");
                return;
            }
            let Some(invitee) = f
                .chunks()
                .find(|c| c.tag == tag::UID)
                .map(|c| c.as_uint() as Uid)
            else {
                reply_error(tx, f.trans, "Invite whom?");
                return;
            };
            match ctx.core.chat_create(sess.uid, invitee) {
                Ok((cid, me)) => reply(
                    tx,
                    f.trans,
                    vec![
                        (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                        (tag::UID, me.uid.to_be_bytes().to_vec()),
                        (tag::ICON, me.icon.to_be_bytes().to_vec()),
                        (
                            tag::COLOUR,
                            wire_color(&me, ctx.cfg.mark_cleartext)
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (tag::NAME, wire_nick(sess.enc, &me.nick)),
                    ],
                ),
                Err(e) => reply_error(tx, f.trans, err_text(e)),
            }
        }

        t if t == ClientHdr::ChatInvite.as_u32() => {
            let (mut cid, mut target) = (0u32, 0 as Uid);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::UID => target = c.as_uint() as Uid,
                    _ => {}
                }
            }
            match ctx.core.chat_invite(cid, sess.uid, target) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, err_text(e)),
            }
        }

        t if t == ClientHdr::ChatDecline.as_u32() => {
            if let Some(cid) = f
                .chunks()
                .find(|c| c.tag == tag::CHAT_ID)
                .map(|c| c.as_uint())
            {
                ctx.core.chat_decline(cid, sess.uid);
            }
            // No reply, like the reference.
        }

        t if t == ClientHdr::ChatJoin.as_u32() => {
            let (mut cid, mut password) = (0u32, String::new());
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::PASSWORD => password = sess.enc.decode_chars(c.data, 31),
                    _ => {}
                }
            }
            match ctx.core.chat_join(cid, sess.uid, &password) {
                Ok((rows, subject)) => {
                    let mut chunks: Vec<(u16, Vec<u8>)> = rows
                        .iter()
                        .map(|u| {
                            (
                                tag::USER_LIST,
                                userlist_payload(u, ctx.cfg.mark_cleartext, sess.enc),
                            )
                        })
                        .collect();
                    chunks.push((tag::CHAT_SUBJECT, wire_subject(sess.enc, &subject)));
                    reply(tx, f.trans, chunks);
                }
                Err(e) => reply_error(tx, f.trans, err_text(e)),
            }
        }

        t if t == ClientHdr::ChatPart.as_u32() => {
            if let Some(cid) = f
                .chunks()
                .find(|c| c.tag == tag::CHAT_ID)
                .map(|c| c.as_uint())
            {
                ctx.core.chat_part(cid, sess.uid);
            }
            // No reply, like the reference.
        }

        // --- Messaging ------------------------------------------------
        t if t == ClientHdr::Msg.as_u32() => {
            let (mut to, mut body) = (0 as Uid, String::new());
            let (mut handle, mut declared) = (None, false);
            for c in f.chunks() {
                match c.tag {
                    tag::UID => to = c.as_uint() as Uid,
                    tag::BODY => body = sess.enc.decode_capped(c.data, MAX_CHAT_INPUT),
                    tag::CHAT_MEDIA_ID => handle = media::parse_handle(c.data),
                    tag::CHAT_MEDIA_TYPE => declared = true,
                    _ => {}
                }
            }
            // A message to the system account is a command line, not a
            // private message, and `/block` or `/stop` needs no right to
            // message anyone (`docs/system-account.md` §3). The commands
            // that do reach a person, `/msg`, check the bit themselves.
            if !sess.can(bit::SEND_MSGS) && ctx.core.system_uid() != Some(to) {
                reply_error(tx, f.trans, "You are not allowed to send private messages.");
                return;
            }
            // Same rule as chat: dropped outright from a sender that did
            // not negotiate the bit. This transaction *does* have a task
            // reply, so an unpaired field is refused rather than
            // silently dropped.
            let media = match (handle, declared) {
                _ if !sess.has_cap(cap::INLINE_MEDIA) => None,
                (Some(_), false) | (None, true) => {
                    reply_error(tx, f.trans, "Media rejected");
                    return;
                }
                (handle, _) => handle,
            };
            // A message with an image may have no text at all: the image
            // is the message. Without one the old rule stands.
            if to == 0 || (body.is_empty() && media.is_none()) {
                reply_error(tx, f.trans, "Empty message or no recipient.");
                return;
            }
            // No guid: the legacy wire has no way to carry one, so every
            // send from it is its own message and a retry is a resend.
            let from = sess.uid;
            match off_reactor(&ctx.core, move |c| c.msg(from, to, body, None, media)).await {
                Some(Ok(_)) => reply(tx, f.trans, vec![]),
                Some(Err(e)) => reply_error(tx, f.trans, err_text(e)),
                None => reply_error(tx, f.trans, "Server error."),
            }
        }

        t if t == ClientHdr::MsgBroadcast.as_u32() => {
            if !sess.can(bit::CAN_BROADCAST) {
                reply_error(tx, f.trans, "You are not allowed to broadcast.");
                return;
            }
            let body = f
                .chunks()
                .find(|c| c.tag == tag::BODY)
                .map(|c| sess.enc.decode_capped(c.data, MAX_CHAT_INPUT))
                .unwrap_or_default();
            if body.is_empty() {
                reply_error(tx, f.trans, "Empty broadcast.");
                return;
            }
            let _ = ctx.core.broadcast(sess.uid, body);
            // The reference server never acks a broadcast, leaving the
            // sender's task dangling; we ack, which clients accept.
            reply(tx, f.trans, vec![]);
        }

        // --- User info & moderation -----------------------------------
        t if t == ClientHdr::UserGetInfo.as_u32() => {
            let target = f
                .chunks()
                .find(|c| c.tag == tag::UID)
                .map(|c| c.as_uint() as Uid)
                .unwrap_or(0);
            // Self-info is always allowed (the reference server's
            // options.self_info default); other users need the bit.
            if target != sess.uid && !sess.can(bit::GET_USER_INFO) {
                reply_error(tx, f.trans, "You are not allowed to get user information.");
                return;
            }
            let Some(d) = ctx.core.user_details(target) else {
                reply_error(tx, f.trans, "That user is not connected.");
                return;
            };
            let secs = d.connected_at.elapsed().as_secs();
            let info = format!(
                "    name: {}\r   login: {}\r address: {}\r  online: {}h {}m {}s\r",
                d.info.nick,
                d.login,
                d.addr.map_or_else(|| "-".into(), |a| a.to_string()),
                secs / 3600,
                (secs % 3600) / 60,
                secs % 60,
            );
            reply(
                tx,
                f.trans,
                vec![
                    (tag::BODY, sess.enc.body(&info)),
                    (tag::NAME, wire_nick(sess.enc, &d.info.nick)),
                ],
            );
        }

        t if t == ClientHdr::UserKick.as_u32() => {
            if !sess.can(bit::DISCONNECT_USERS) {
                reply_error(tx, f.trans, "You are not allowed to disconnect users.");
                return;
            }
            let (mut target, mut ban) = (0 as Uid, false);
            for c in f.chunks() {
                match c.tag {
                    tag::UID => target = c.as_uint() as Uid,
                    tag::BAN => ban = c.as_uint() != 0,
                    _ => {}
                }
            }
            if ctx
                .core
                .access_of(target)
                .is_some_and(|a| a.has(bit::CANT_BE_DISCONNECTED))
            {
                reply_error(tx, f.trans, "That user cannot be disconnected.");
                return;
            }
            let ban_for = ban.then_some(ctx.cfg.ban_time);
            // `[moderation] kick_purges` makes a kick take the target's
            // recent output with it, as the ng `kick { purge }` does —
            // and only for a kicker who may purge, since that is the
            // question the ng request asks too (moderation.md §6). Off
            // by default: a kick over this wire has meant one thing for
            // twenty-five years. Before the kick, while the target's
            // session still says who they are.
            let window = ctx.core.moderation_policy().kick_purges;
            if !window.is_zero() && ctx.core.is_moderator(sess.uid) {
                let who = hxd_core::PersonRef::Uid(target);
                let by = hxd_core::Actor::Session(sess.uid);
                let why = if ban { "banned" } else { "kicked" };
                let core = ctx.core.clone();
                let purged =
                    tokio::task::spawn_blocking(instrument::blocking("purge", move || {
                        core.purge_sender(by, &who, window, why)
                    }))
                    .await;
                if let Ok(Err(e)) = purged {
                    debug!(target, "kick purge skipped: {e:?}");
                }
            }
            match ctx.core.kick(target, ban_for) {
                Ok(nick) => {
                    reply(tx, f.trans, vec![]);
                    // The public-chat announcement, in the reference
                    // server's wording (each frontend adds its own framing
                    // — this edge renders it as `\r<text>`).
                    let by = ctx.core.user(sess.uid).map(|u| u.nick).unwrap_or_default();
                    let verb = if ban { "banned" } else { "kicked" };
                    ctx.core
                        .chat_notice(0, sess.uid, format!("{nick} has been {verb} by {by}"));
                }
                Err(e) => reply_error(tx, f.trans, err_text(e)),
            }
        }

        // --- Voice (fogWraith Capabilities-Voice.md) ------------------
        //
        // A client that didn't negotiate CAPABILITY_VOICE never sends
        // these, and never receives one: the gate is the first line of
        // every arm, and a task error is a base-protocol reply rather
        // than a voice transaction, so answering one doesn't break that
        // rule.
        // --- Inline media (docs/inline-media.md §7.2, §7.3) ----------
        t if t == media::trans::UPLOAD_MEDIA => {
            if !sess.has_cap(cap::INLINE_MEDIA) {
                reply_error(tx, f.trans, "Inline media was not negotiated.");
                return;
            }
            let (mut payload, mut declared, mut token) = (Vec::new(), None, None);
            let (mut index, mut count, mut last) = (0u16, None, false);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_MEDIA_PAYLOAD => payload = c.data.to_vec(),
                    tag::CHAT_MEDIA_DECLARED_TYPE => {
                        declared = Some(String::from_utf8_lossy(c.data).into_owned())
                    }
                    tag::CHAT_MEDIA_UPLOAD_TOKEN => token = media::parse_handle(c.data),
                    tag::CHAT_MEDIA_PART_INDEX => index = media::uint(c.data) as u16,
                    tag::CHAT_MEDIA_PART_COUNT => count = Some(media::uint(c.data) as u16),
                    tag::CHAT_MEDIA_PART_FINAL => last = media::flag(c.data),
                    _ => {}
                }
            }
            let uid = sess.uid;
            // The pipeline decodes and re-encodes an image, so it runs on
            // a blocking thread — and the awaiting side gives up before
            // the client does. A decode that outlives the budget is
            // abandoned to finish on its thread while its sender is told
            // to try again: a Rust decoder cannot be killed from
            // outside, and the dimension and allocation caps are what
            // bound the work in the first place.
            let budget = ctx
                .core
                .media_config()
                .map(|c| c.codec.permit_wait * 2)
                .unwrap_or(Duration::from_secs(4));
            let outcome = tokio::time::timeout(
                budget,
                off_reactor(&ctx.core, move |c| {
                    c.media_upload_part(
                        uid,
                        hxd_core::media::UploadPart {
                            payload: &payload,
                            declared: declared.as_deref(),
                            token,
                            index,
                            count,
                            last,
                        },
                    )
                }),
            )
            .await;
            match outcome {
                Ok(Some(Ok(hxd_core::media::UploadOutcome::Done(reference)))) => {
                    reply(tx, f.trans, media::upload_reply_chunks(&reference))
                }
                // An intermediate reply carries the token and nothing
                // else. Echoing it on every part (rather than only the
                // first) is what the spec calls safe and what GtkHx
                // tolerates.
                Ok(Some(Ok(hxd_core::media::UploadOutcome::Token(token)))) => reply(
                    tx,
                    f.trans,
                    vec![(tag::CHAT_MEDIA_UPLOAD_TOKEN, token.to_vec())],
                ),
                Ok(Some(Err(reject))) => {
                    debug!(target: "media", uid, code = reject.code(), "upload refused");
                    reply_error_with(tx, f.trans, reject.text(), media::error_chunks(reject))
                }
                Ok(None) | Err(_) => {
                    let busy = hxd_core::media::MediaReject::Busy;
                    reply_error_with(tx, f.trans, busy.text(), media::error_chunks(busy))
                }
            }
        }

        t if t == media::trans::DOWNLOAD_MEDIA => {
            if !sess.has_cap(cap::INLINE_MEDIA) {
                reply_error(tx, f.trans, "Inline media was not negotiated.");
                return;
            }
            let (mut handle, mut index) = (None, 0u16);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_MEDIA_ID => handle = media::parse_handle(c.data),
                    tag::CHAT_MEDIA_PART_INDEX => index = media::uint(c.data) as u16,
                    _ => {}
                }
            }
            let per_minute = ctx
                .core
                .media_config()
                .map(|c| c.download_per_minute)
                .unwrap_or(0);
            if !sess.allow_download(per_minute, handle, index) {
                let slow = hxd_core::media::MediaReject::RateLimited;
                reply_error_with(tx, f.trans, slow.text(), media::error_chunks(slow));
                return;
            }
            // Authorization is re-checked on every part, because a set
            // can only shrink: a session kicked between parts is exactly
            // the one that should stop receiving.
            let fetched = handle.and_then(|h| ctx.core.media_fetch(sess.uid, &h));
            match fetched.and_then(|f2| {
                media::download_chunks(&f2.bytes, f2.mime.mime(), index).map(|(c, _)| c)
            }) {
                Some(chunks) => reply(tx, f.trans, chunks),
                // "Not found", "expired", "revoked", "not yours" and "a
                // part past the end" are one answer, so none of them can
                // be told from the others.
                None => {
                    let no = hxd_core::media::MediaReject::NotAuthorized;
                    reply_error_with(tx, f.trans, "Media not found", media::error_chunks(no))
                }
            }
        }

        t if t == ClientHdr::VoiceJoin.as_u32() => {
            if !sess.has_cap(cap::VOICE) {
                reply_error(tx, f.trans, "Voice chat is not available on this server.");
                return;
            }
            // The privilege check lives here, with its wording, and says
            // only that the user may join voice *somewhere*. Which room
            // is the domain's membership check.
            if !sess.can(bit::VOICE_CHAT) {
                reply_error(tx, f.trans, "You are not allowed to join voice chat.");
                return;
            }
            let cid = voice_cid(f);
            match ctx.core.voice_join(sess.uid, cid) {
                Ok(join) => reply(
                    tx,
                    f.trans,
                    vec![
                        voice::chat_id(cid),
                        (tag::VOICE_SDP, join.sdp.into_bytes()),
                        (tag::VOICE_CODEC, join.codec.as_bytes().to_vec()),
                        (
                            tag::VOICE_PARTICIPANTS,
                            voice::participants_payload(&join.participants),
                        ),
                    ],
                ),
                Err(e) => reply_error(tx, f.trans, voice::err_text(e)),
            }
        }

        t if t == ClientHdr::VoiceLeave.as_u32() => {
            if !sess.has_cap(cap::VOICE) {
                reply_error(tx, f.trans, "Voice chat is not available on this server.");
                return;
            }
            match ctx.core.voice_leave(sess.uid, voice_cid(f)) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, voice::err_text(e)),
            }
        }

        t if t == ClientHdr::VoiceSdpAnswer.as_u32() => {
            if !sess.has_cap(cap::VOICE) {
                reply_error(tx, f.trans, "Voice chat is not available on this server.");
                return;
            }
            let (mut cid, mut sdp) = (0u32, Ok(String::new()));
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    // SDP is UTF-8 by the spec and never Mac Roman: it is
                    // a media-plane blob that happens to travel on this
                    // wire, not text anyone reads. So it is validated
                    // rather than converted: a lossy decode would put
                    // U+FFFD into a fingerprint or an ICE password and
                    // hand the media layer an answer that is subtly not
                    // the one the client sent. A client that can't send
                    // us UTF-8 gets told its answer was rejected, which
                    // is what happened.
                    tag::VOICE_SDP => sdp = std::str::from_utf8(c.data).map(str::to_string),
                    _ => {}
                }
            }
            let Ok(sdp) = sdp else {
                debug!(uid = sess.uid, cid, "voice answer is not valid UTF-8");
                reply_error(tx, f.trans, voice::err_text(VoiceError::BadAnswer));
                return;
            };
            match ctx.core.voice_answer(sess.uid, cid, sdp) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, voice::err_text(e)),
            }
        }

        t if t == ClientHdr::VoiceIce.as_u32() => {
            // A notification in both directions: no reply exists, so a
            // candidate we can't use is dropped rather than answered.
            if !sess.has_cap(cap::VOICE) {
                return;
            }
            let (mut cid, mut candidate) = (0u32, None);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::VOICE_ICE => candidate = voice::parse_ice(c.data),
                    _ => {}
                }
            }
            match candidate {
                // The refusal is discarded, not ignored: this
                // transaction has no reply to put it in. A candidate for
                // a room the user isn't in is dropped, which is what the
                // domain did with it anyway.
                Some(c) => {
                    if let Err(e) = ctx.core.voice_ice(sess.uid, cid, c) {
                        debug!(uid = sess.uid, cid, "ICE candidate dropped: {e:?}");
                    }
                }
                None => debug!(uid = sess.uid, cid, "unparseable ICE candidate dropped"),
            }
        }

        t if t == ClientHdr::VoiceMute.as_u32() => {
            if !sess.has_cap(cap::VOICE) {
                reply_error(tx, f.trans, "Voice chat is not available on this server.");
                return;
            }
            let (mut cid, mut muted) = (0u32, false);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::VOICE_MUTED => muted = c.as_uint() != 0,
                    _ => {}
                }
            }
            match ctx.core.voice_mute(sess.uid, cid, muted) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, voice::err_text(e)),
            }
        }

        // --- Video (docs/capabilities-video.md) -----------------------
        //
        // Video is layered on voice, so every transaction here needs both
        // capabilities and a voice session; the domain enforces the
        // second, this frontend the first. SDP and ICE are not repeated:
        // a video renegotiation is a 602/603 on the same peer connection,
        // handled above without knowing video exists.
        t if t == ClientHdr::VideoStart.as_u32() => {
            if !sess.has_cap(cap::VIDEO) {
                reply_error(tx, f.trans, "Video is not available on this server.");
                return;
            }
            let cid = voice_cid(f);
            let Some(kind) = video_kind(f) else {
                // Kind 0 is deliberately invalid and a reserved kind is a
                // later revision's, so neither is guessed at.
                reply_error(tx, f.trans, "That is not a video stream kind.");
                return;
            };
            // Camera and screen are separate trust decisions and neither
            // bit implies the other: an operator may reasonably let
            // someone show their face and not their desktop.
            let allowed = match kind {
                VideoKind::Camera => sess.can(bit::VIDEO_CHAT),
                VideoKind::Screen => sess.can(bit::SCREEN_SHARE),
            };
            if !allowed {
                reply_error(
                    tx,
                    f.trans,
                    match kind {
                        VideoKind::Camera => "You are not allowed to share video.",
                        VideoKind::Screen => "You are not allowed to share your screen.",
                    },
                );
                return;
            }
            match ctx.core.video_start(sess.uid, cid, kind) {
                // No SDP here, deliberately: a renegotiation may already
                // be outstanding toward this peer, and the offer follows
                // as a 602 when serialisation allows. A client must not
                // wait for it to consider the start to have succeeded.
                Ok(codec) => reply(
                    tx,
                    f.trans,
                    vec![
                        video::chat_id(cid),
                        video::kind_chunk(kind),
                        (tag::VIDEO_CODEC, codec.as_bytes().to_vec()),
                    ],
                ),
                Err(e) => reply_error(tx, f.trans, video::err_text(e)),
            }
        }

        t if t == ClientHdr::VideoStop.as_u32() => {
            if !sess.has_cap(cap::VIDEO) {
                reply_error(tx, f.trans, "Video is not available on this server.");
                return;
            }
            // The kind is optional here and only here: omitting it stops
            // everything this client is publishing in the room.
            let kind = f
                .chunks()
                .find(|c| c.tag == tag::VIDEO_KIND)
                .map(|c| VideoKind::from_wire(u16::try_from(c.as_uint()).ok()?));
            let kind = match kind {
                Some(None) => {
                    reply_error(tx, f.trans, "That is not a video stream kind.");
                    return;
                }
                Some(Some(k)) => Some(k),
                None => None,
            };
            match ctx.core.video_stop(sess.uid, voice_cid(f), kind) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, video::err_text(e)),
            }
        }

        t if t == ClientHdr::VideoState.as_u32() => {
            if !sess.has_cap(cap::VIDEO) {
                reply_error(tx, f.trans, "Video is not available on this server.");
                return;
            }
            let Some(kind) = video_kind(f) else {
                reply_error(tx, f.trans, "That is not a video stream kind.");
                return;
            };
            let paused = f
                .chunks()
                .find(|c| c.tag == tag::VIDEO_PAUSED)
                .is_some_and(|c| c.as_uint() != 0);
            match ctx.core.video_state(sess.uid, voice_cid(f), kind, paused) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, video::err_text(e)),
            }
        }

        t if t == ClientHdr::VideoSubscribe.as_u32() => {
            if !sess.has_cap(cap::VIDEO) {
                reply_error(tx, f.trans, "Video is not available on this server.");
                return;
            }
            // No privilege check: receiving video needs nothing beyond
            // being in the room. The bits govern publishing.
            //
            // An absent field is an empty set, which is how a client
            // turns everything off in one request — and the state it
            // started in.
            let streams = f
                .chunks()
                .find(|c| c.tag == tag::VIDEO_SUBSCRIPTIONS)
                .map(|c| video::parse_subscriptions(c.data))
                .unwrap_or_default();
            match ctx.core.video_subscribe(sess.uid, voice_cid(f), &streams) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, video::err_text(e)),
            }
        }

        // News, both eras of it (`docs/news.md` §12). The domain decides
        // who may do what; every answer is store I/O, so it happens off
        // the reactor.
        t if news::handles(t) => {
            let who = news::Asker {
                uid: sess.uid,
                enc: sess.enc,
            };
            let fields = f.chunks().map(|c| (c.tag, c.data.to_vec())).collect();
            match news::transaction(&ctx.core, &ctx.cfg.news, who, t, fields).await {
                Ok(chunks) => reply(tx, f.trans, chunks),
                Err(msg) => reply_error(tx, f.trans, msg),
            }
        }

        t if t == ClientHdr::Login.as_u32() => {
            reply_error(tx, f.trans, "Already logged in.");
        }

        // --- GIF Icons (`docs/avatars.md` §3) --------------------------
        // Without `[avatars]` these fall through to the unknown-transaction
        // error below, which is how a probing client learns the server has
        // no support.
        gif_icons::GET_LIST if ctx.core.avatar_policy().is_some() => {
            sess.gif_icons = true;
            let (entries, left_out) = icon_list(&ctx.core.avatars());
            reply(tx, f.trans, entries);
            // What did not fit is announced as changed, which is what makes
            // a GIF-icon client fetch a user's icon on its own.
            for uid in left_out {
                push(
                    tx,
                    hdr::ICON_CHANGE,
                    vec![(tag::UID, uid.to_be_bytes().to_vec())],
                );
            }
        }

        gif_icons::GET if ctx.core.avatar_policy().is_some() => {
            sess.gif_icons = true;
            let Some(uid) = f
                .chunks()
                .find(|c| c.tag == tag::UID)
                .and_then(|c| u16::try_from(c.as_uint()).ok())
                .filter(|uid| ctx.core.user_details(*uid).is_some())
            else {
                reply_error(tx, f.trans, "No such user.");
                return;
            };
            let gif = ctx
                .core
                .avatar_of(uid)
                .and_then(|a| a.legacy_gif)
                .map(|g| g.to_vec())
                .unwrap_or_default();
            reply(
                tx,
                f.trans,
                vec![(tag::ICON_GIF, gif), (tag::UID, uid.to_be_bytes().to_vec())],
            );
        }

        gif_icons::SET if ctx.core.avatar_policy().is_some() => {
            sess.gif_icons = true;
            let gif = f
                .chunks()
                .find(|c| c.tag == tag::ICON_GIF)
                .map(|c| c.data.to_vec())
                .unwrap_or_default();
            // The extension's own rule, and the first thing this server
            // checks: anything else is refused before it reaches the codec.
            if !gif.is_empty() && !hxproto::gif_icons::is_gif(&gif) {
                reply_error(tx, f.trans, "An icon must be a GIF.");
                return;
            }
            let uid = sess.uid;
            let outcome = off_reactor(&ctx.core, move |c| {
                if gif.is_empty() {
                    c.clear_avatar(uid).map(|_| ())
                } else {
                    c.set_avatar(uid, &gif).map(|_| ())
                }
            })
            .await;
            match outcome {
                Some(Ok(())) => reply(tx, f.trans, vec![]),
                Some(Err(e)) => reply_error(tx, f.trans, e.text()),
                None => reply_error(tx, f.trans, hxd_core::media::MediaReject::Busy.text()),
            }
        }

        other => {
            debug!("unimplemented transaction {other:#x}");
            reply_error(tx, f.trans, "Not implemented.");
        }
    }
}

/// The most a Get Icon List reply carries. GtkHx and mhxd's own client
/// both accept a transaction of up to 1 MiB (`MAX_HOTLINE_PACKET_LEN` on
/// the client side, `0x100000`), which holds a large roster's icons.
const ICON_LIST_BUDGET: usize = 0x10_0000;

/// The Get Icon List reply: one packed entry per user with a legacy GIF,
/// in uid order, until the next would pass [`ICON_LIST_BUDGET`] — and the
/// uids that did not fit, which the caller announces one by one instead
/// (`docs/avatars.md` §3).
fn icon_list(avatars: &[(Uid, hxd_core::Avatar)]) -> (Vec<(u16, Vec<u8>)>, Vec<Uid>) {
    let mut budget = ICON_LIST_BUDGET - 2;
    let mut chunks = Vec::new();
    let mut left_out = Vec::new();
    for (uid, avatar) in avatars {
        let Some(gif) = &avatar.legacy_gif else {
            continue;
        };
        // A GIF too long for the entry's two-byte length: the config's
        // ceiling keeps this from happening, and it is skipped if it does.
        let Ok(len) = u16::try_from(gif.len() + 4) else {
            continue;
        };
        let cost = 4 + usize::from(len);
        if cost > budget {
            left_out.push(*uid);
            continue;
        }
        budget -= cost;
        let mut entry = Vec::with_capacity(usize::from(len));
        entry.extend_from_slice(&uid.to_be_bytes());
        entry.extend_from_slice(&(gif.len() as u16).to_be_bytes());
        entry.extend_from_slice(gif);
        chunks.push((tag::ICON_LIST, entry));
    }
    (chunks, left_out)
}

fn file_error_text(error: &hxd_core::FileError) -> &'static str {
    match error {
        hxd_core::FileError::InvalidPath => "Malformed file path.",
        hxd_core::FileError::NotFound => "File not found.",
        hxd_core::FileError::NotFolder => "That path is not a folder.",
        hxd_core::FileError::NotFile => "That path is not a file.",
        hxd_core::FileError::AlreadyExists => "A file already exists at that path.",
        hxd_core::FileError::RangeUnsupported => "This file cannot be resumed.",
        hxd_core::FileError::RangeInvalid => "Invalid file range.",
        hxd_core::FileError::OriginChanged => "The file changed at its origin.",
        hxd_core::FileError::TooLarge => "This file needs Large File support.",
        hxd_core::FileError::Busy => "The file service is busy.",
        hxd_core::FileError::Unavailable(_) => "The file service is unavailable.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn avatar(uid: u8, gif_len: usize) -> (Uid, hxd_core::Avatar) {
        let mut a = hxd_core::avatar::conformance::avatar(uid, hxd_core::media::MediaType::Gif);
        a.legacy_gif = Some(vec![uid; gif_len].into());
        (u16::from(uid), a)
    }

    #[test]
    fn the_icon_list_fits_one_transaction_and_names_what_did_not() {
        // 40 GIFs at the 32 KiB default pass 1 MiB: some must be left out,
        // and every one is either listed or named.
        let all: Vec<_> = (1..=40).map(|n| avatar(n, 32 * 1024)).collect();
        let (entries, left_out) = icon_list(&all);
        let total: usize = 2 + entries.iter().map(|(_, e)| 4 + e.len()).sum::<usize>();
        assert!(total <= ICON_LIST_BUDGET, "{total}");
        assert!(!left_out.is_empty());
        assert_eq!(entries.len() + left_out.len(), all.len());
        let (first, rest) = entries[0].1.split_at(4);
        assert_eq!(first, [0, 1, 0x80, 0x00], "uid 1, length 32768");
        assert_eq!(rest.len(), 32 * 1024);

        // A user with no legacy rendition is neither listed nor named.
        let mut none = avatar(9, 10);
        none.1.legacy_gif = None;
        assert_eq!(icon_list(&[none]), (vec![], vec![]));

        // The largest GIF an entry can carry fits its two-byte field.
        let (entries, left_out) = icon_list(&[avatar(3, 65_531)]);
        assert!(left_out.is_empty());
        assert_eq!(entries[0].1.len(), 65_535);
    }

    #[test]
    fn the_queued_stamp_reads_as_a_date_a_person_recognises() {
        assert_eq!(stamp(at(0)), "1970-01-01 00:00 UTC");
        assert_eq!(stamp(at(1_788_704_520)), "2026-09-06 14:22 UTC");
        // Leap day, and the year boundary either side of it — the two
        // places a hand-rolled calendar goes wrong.
        assert_eq!(stamp(at(1_709_164_800)), "2024-02-29 00:00 UTC");
        assert_eq!(stamp(at(1_735_689_540)), "2024-12-31 23:59 UTC");
        assert_eq!(stamp(at(1_735_689_600)), "2025-01-01 00:00 UTC");
        // 2000 was a leap year and 1900 was not; the algorithm has to
        // know the difference.
        assert_eq!(stamp(at(951_782_400)), "2000-02-29 00:00 UTC");
        // A clock before the epoch stamps the epoch rather than wrapping.
        assert_eq!(
            stamp(SystemTime::UNIX_EPOCH - Duration::from_secs(60)),
            "1970-01-01 00:00 UTC"
        );
    }

    /// Every type `dispatch` answers by name is in `HANDLED`. Read from
    /// this file's source, so that a transaction added to `dispatch`
    /// without a label fails here rather than counting as `other`.
    #[test]
    fn every_dispatched_type_has_a_label() {
        let src = include_str!("session.rs");
        let start = src.find("async fn dispatch(").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        let mut seen = 0;
        for line in body.lines() {
            let Some(rest) = line.strip_prefix("        t if t == ClientHdr::") else {
                continue;
            };
            let name = &rest[..rest.find('.').unwrap()];
            let listed = format!("    ClientHdr::{name},");
            assert!(
                src.contains(&listed),
                "{name} is dispatched but not in HANDLED"
            );
            seen += 1;
        }
        assert!(seen > 10, "the dispatcher's arms were not found");
        assert!(matches!(
            type_label(ClientHdr::Chat.as_u32()),
            Kind::Type(_)
        ));
        assert!(matches!(type_label(gif_icons::GET), Kind::Type(_)));
        assert!(matches!(type_label(0x7ff), Kind::Name("other")));
    }
}
