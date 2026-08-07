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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hotline_proto::messages::{tag, ClientHdr};
use hotline_proto::text;
use hxd_core::access::bit;
use hxd_core::{
    Account, AttachInfo, AuthBackend, AuthError, ChatError, Core, Event, Proof, SessionStatus, Uid,
    UserInfo,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;
use tracing::{debug, info, warn, Instrument};

use crate::frame::{pack_frame, read_frame, Frame, ReadError};

/// Server → client transaction opcodes not covered by
/// `hotline_proto::messages::ServerHdr` (which only carries what the gtkhx
/// client routes on). Values from `hotline.h`.
mod hdr {
    pub const TASK: u32 = 0x0001_0000;
    pub const AGREEMENT: u32 = 0x0000_006d;
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
}

/// Data tags hotline-proto has no constants for (the gtkhx client ignores
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            name: "hxd-ng".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(10),
            ban_time: Duration::from_secs(1800),
        }
    }
}

/// Everything a session needs from the server. Cheap to clone.
#[derive(Clone)]
pub struct ServerCtx {
    pub core: Arc<Core>,
    pub auth: Arc<dyn AuthBackend>,
    pub cfg: Arc<ServerConfig>,
}

/// Accept loop: one [`run_session`] task per connection.
pub async fn serve(listener: TcpListener, ctx: ServerCtx) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!("session", %peer);
            run_session(stream, peer, ctx).instrument(span).await;
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
}

type Tx = UnboundedSender<Outbound>;

async fn writer_task(mut wr: OwnedWriteHalf, mut rx: UnboundedReceiver<Outbound>) {
    // Server pushes count their own transactions, starting at 1 (mhxd's
    // convention; clients ignore the value everywhere but task replies).
    let mut push_trans: u32 = 1;
    while let Some(out) = rx.recv().await {
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
        };
        if wr.write_all(&bytes).await.is_err() {
            break; // Reader will observe the dead socket and clean up.
        }
    }
    let _ = wr.shutdown().await;
}

/// Reader task: frames the socket into a bounded channel (backpressure for
/// a flooding client). Exits on EOF, error, or a malformed frame.
async fn reader_task(mut rd: OwnedReadHalf, frames: Sender<Frame>) {
    loop {
        match read_frame(&mut rd).await {
            Ok(f) => {
                if frames.send(f).await.is_err() {
                    return; // Session loop is gone.
                }
            }
            Err(ReadError::Eof) => return,
            Err(ReadError::Io(e)) => {
                debug!("read error: {e}");
                return;
            }
            Err(ReadError::Malformed(why)) => {
                warn!("malformed frame: {why}");
                return;
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
    let _ = tx.send(Outbound::Reply {
        trans,
        error: false,
        chunks,
    });
}

fn reply_error(tx: &Tx, trans: u32, msg: &str) {
    let _ = tx.send(Outbound::Reply {
        trans,
        error: true,
        chunks: vec![(tag::TASK_ERROR, text::from_utf8(msg))],
    });
}

fn push(tx: &Tx, ty: u32, chunks: Vec<(u16, Vec<u8>)>) {
    let _ = tx.send(Outbound::Push { ty, chunks });
}

/// The domain is UTF-8; this edge speaks Mac Roman. Egress conversion is
/// lossy (`?` for unmappable) and nicks are truncated to the wire's 31
/// bytes *after* conversion (Mac Roman is single-byte, so no split risk).
fn mac_nick(nick: &str) -> Vec<u8> {
    let mut v = text::from_utf8(nick);
    v.truncate(31);
    v
}

/// The legacy color field is a bitfield in practice: bit 1 away, bit 2
/// admin. The domain stores `admin` + status; the wire form is derived
/// here and only here.
fn wire_color(u: &UserInfo) -> u16 {
    (if u.admin { 2 } else { 0 })
        | (if u.status == SessionStatus::Active {
            0
        } else {
            1
        })
}

/// The `HTLS_DATA_USER_LIST` payload: uid, icon, color, nlen (all u16 BE),
/// then the name bytes. `struct hl_userlist_hdr` minus the chunk header.
fn userlist_payload(u: &UserInfo) -> Vec<u8> {
    let nick = mac_nick(&u.nick);
    let mut v = Vec::with_capacity(8 + nick.len());
    v.extend_from_slice(&u.uid.to_be_bytes());
    v.extend_from_slice(&u.icon.to_be_bytes());
    v.extend_from_slice(&wire_color(u).to_be_bytes());
    v.extend_from_slice(&(nick.len() as u16).to_be_bytes());
    v.extend_from_slice(&nick);
    v
}

fn user_change_chunks(u: &UserInfo) -> Vec<(u16, Vec<u8>)> {
    vec![
        (tag::UID, u.uid.to_be_bytes().to_vec()),
        (tag::ICON, u.icon.to_be_bytes().to_vec()),
        (tag::COLOUR, wire_color(u).to_be_bytes().to_vec()),
        (tag::NAME, mac_nick(&u.nick)),
    ]
}

/// The legacy XOR-0xff de-obfuscation of LOGIN/PASSWORD chunk payloads
/// (`hl_decode` in the C tree).
fn hl_decode(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| !b).collect()
}

fn cap31(data: &[u8]) -> &[u8] {
    &data[..data.len().min(31)]
}

fn err_text(e: ChatError) -> &'static str {
    match e {
        ChatError::NoSuchUser => "That user is not connected.",
        ChatError::NoSuchChat => "That chat does not exist.",
        ChatError::NotAMember => "You are not in that chat.",
        ChatError::AlreadyThere => "Already there.",
        ChatError::WrongPassword => "Wrong chat password.",
    }
}

// --- Chat line formatting ----------------------------------------------
//
// Hotline chat is server-formatted: the server composes the display line
// and clients render it verbatim. These mirror the reference server's
// default formats — `"\r%13.13s:  %s"` and `"\r *** %s %s"` — byte for
// byte, name field right-aligned in 13 columns and truncated to 13.

fn format_chat_line(out: &mut Vec<u8>, nick: &[u8], line: &[u8], style: u16) {
    out.push(b'\r');
    if style == 1 {
        out.extend_from_slice(b" *** ");
        out.extend_from_slice(nick);
        out.push(b' ');
    } else {
        let shown = &nick[..nick.len().min(13)];
        for _ in shown.len()..13 {
            out.push(b' ');
        }
        out.extend_from_slice(shown);
        out.extend_from_slice(b":  ");
    }
    out.extend_from_slice(line);
}

/// Split multi-line input and format each line, mirroring the reference
/// server's `cr_strtok_r` loop: empty segments (consecutive or trailing
/// `\r`/`\n`, including CRLF pairs) are skipped rather than rendered as
/// blank attributed lines. Input that is *only* delimiters (or empty)
/// still formats one empty line — the reference's "no token found" path.
fn format_chat(nick: &[u8], text: &[u8], style: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 32);
    let mut wrote = false;
    for line in text.split(|b| *b == b'\r' || *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        format_chat_line(&mut out, nick, line, style);
        wrote = true;
    }
    if !wrote {
        format_chat_line(&mut out, nick, b"", style);
    }
    out
}

/// What the login chunk-walk yielded.
#[derive(Default)]
struct LoginRequest {
    login: Vec<u8>,
    password: Vec<u8>,
    nick: Option<Vec<u8>>,
    icon: u16,
    clientversion: u16,
    /// A 1-byte all-zero LOGIN chunk: the HOPE session-key probe.
    hope_probe: bool,
}

fn parse_login(f: &Frame) -> LoginRequest {
    let mut req = LoginRequest::default();
    for c in f.chunks() {
        match c.tag {
            tag::NAME => req.nick = Some(cap31(c.data).to_vec()),
            tag::ICON => req.icon = c.as_uint() as u16,
            tag::VERSION => req.clientversion = c.as_uint() as u16,
            tag::LOGIN => {
                if c.data.len() == 1 && c.data[0] == 0 {
                    req.hope_probe = true;
                } else {
                    req.login = hl_decode(cap31(c.data));
                }
            }
            // A single NUL byte is "no password" on the wire.
            tag::PASSWORD if !(c.data.len() == 1 && c.data[0] == 0) => {
                req.password = hl_decode(cap31(c.data));
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
}

impl Session {
    fn can(&self, b: u8) -> bool {
        self.account.access.has(b)
    }
}

pub async fn run_session(stream: TcpStream, peer: SocketAddr, ctx: ServerCtx) {
    if ctx.core.is_banned(peer.ip()) {
        info!("refusing banned address");
        return;
    }
    let _ = stream.set_nodelay(true);
    let (mut rd, wr) = stream.into_split();

    // --- Magic exchange -------------------------------------------------
    // Read exactly the 12 client-hello bytes; anything the client pipelined
    // behind them (old hx logs in without waiting) stays in the socket
    // buffer and is handled by the normal frame loop.
    let mut magic = [0u8; 12];
    match timeout(ctx.cfg.login_timeout, rd.read_exact(&mut magic)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    if magic != CLIENT_MAGIC {
        debug!("bad client magic, dropping");
        return;
    }

    let (tx, out_rx) = mpsc::unbounded_channel();
    let mut wr_for_magic = wr;
    if wr_for_magic.write_all(&SERVER_MAGIC).await.is_err() {
        return;
    }
    let writer = tokio::spawn(writer_task(wr_for_magic, out_rx));
    let (frames_tx, mut frames) = mpsc::channel(32);
    let reader = tokio::spawn(reader_task(rd, frames_tx));

    // --- Login, then the session loop -----------------------------------
    let outcome = login_phase(&mut frames, &tx, &ctx, peer).await;
    if let Some((mut sess, mut events)) = outcome {
        let uid = sess.uid;
        info!(uid, login = %sess.account.login, "logged in");
        session_loop(&mut frames, &mut events, &tx, &ctx, &mut sess).await;
        ctx.core.detach(uid);
        info!(uid, "disconnected");
    }
    reader.abort();
    drop(tx);
    let _ = writer.await;
}

/// Wait for the LOGIN transaction and run the login flow. `None` = close.
async fn login_phase(
    frames: &mut Receiver<Frame>,
    tx: &Tx,
    ctx: &ServerCtx,
    peer: SocketAddr,
) -> Option<(Session, UnboundedReceiver<Event>)> {
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
        // rather than desync.
        reply_error(tx, f.trans, "Secure login (HOPE) is not supported yet.");
        return None;
    }

    // Authenticate on the blocking pool — backends do file I/O. Login and
    // password are canonicalized Mac Roman → UTF-8 before the backend sees
    // them, so an accented password typed on a legacy client matches the
    // UTF-8 account file. (HOPE proofs will need this same canonical form.)
    let auth = ctx.auth.clone();
    let login_str = text::to_utf8(&req.login);
    let password = text::to_utf8(&req.password).into_bytes();
    let verdict =
        tokio::task::spawn_blocking(move || auth.authenticate(&login_str, Proof::Plain(&password)))
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
        (Some(n), true) => text::to_utf8(n),
        _ => account.name.clone(),
    };

    let attach = AttachInfo {
        nick,
        icon: req.icon,
        admin: account.access.has(bit::DISCONNECT_USERS),
        access: account.access,
        login: account.login.clone(),
        addr: Some(peer.ip()),
    };
    let Some((uid, events)) = ctx.core.attach(attach) else {
        reply_error(tx, f.trans, "Server full.");
        return None;
    };

    // Login reply. A version-0 server sends only the uid (and a 1.0/1.2
    // client wouldn't know what to do with more).
    if ctx.cfg.version == 0 {
        reply(tx, f.trans, vec![(tag::UID, uid.to_be_bytes().to_vec())]);
    } else {
        reply(
            tx,
            f.trans,
            vec![
                (tag::UID, uid.to_be_bytes().to_vec()),
                (tag::VERSION, ctx.cfg.version.to_be_bytes().to_vec()),
                (TAG_BANNERID, 0u16.to_be_bytes().to_vec()),
                (tag::SERVERNAME, text::from_utf8(&ctx.cfg.name)),
            ],
        );
    }

    // Agreement dance (1.5 flow).
    let mut agreement_sent = false;
    if !account.access.has(bit::DONT_SHOW_AGREEMENT) {
        if let Some(text_utf8) = &ctx.cfg.agreement {
            let mut mac = text::from_utf8(text_utf8);
            for b in &mut mac {
                if *b == b'\n' {
                    *b = b'\r'; // The wire wants classic Mac line endings.
                }
            }
            push(tx, hdr::AGREEMENT, vec![(tag::BODY, mac)]);
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
    };

    // A 1.5+ client that sent no name finishes its login via
    // AGREEMENTAGREE or USER_CHANGE; everyone else is done now.
    if req.clientversion < 150 || got_name {
        complete_login(tx, ctx, &mut sess);
    }
    Some((sess, events))
}

/// The "loginupdate" moment: hand the client its self-info and make it
/// visible (which broadcasts the join to everyone else).
fn complete_login(tx: &Tx, ctx: &ServerCtx, sess: &mut Session) {
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
                    (tag::USER_LIST, userlist_payload(&me)),
                ],
            );
        }
    }
    ctx.core.announce(sess.uid);
    sess.announced = true;
}

/// Encode one domain event onto the wire. Returns `false` when the session
/// must end (kicked).
fn deliver_event(tx: &Tx, ev: Event) -> bool {
    match ev {
        Event::Joined(u) | Event::Changed(u) => {
            push(tx, hdr::USER_CHANGE, user_change_chunks(&u));
        }
        Event::Parted(uid) => {
            push(
                tx,
                hdr::USER_PART,
                vec![(tag::UID, uid.to_be_bytes().to_vec())],
            );
        }
        Event::Chat {
            cid,
            from,
            text,
            style,
        } => {
            // Format at the edge, in Mac Roman, so the 13-column name
            // alignment stays byte-correct for legacy renderers.
            let line = format_chat(&mac_nick(&from.nick), &text::from_utf8(&text), style);
            let mut chunks = vec![(tag::BODY, line)];
            if cid != 0 {
                chunks.push((tag::CHAT_ID, cid.to_be_bytes().to_vec()));
            }
            chunks.push((tag::UID, from.uid.to_be_bytes().to_vec()));
            push(tx, hdr::CHAT, chunks);
        }
        Event::Notice { cid, from, text } => {
            // The legacy rendering of a server notice: `\r<text>`.
            let mut line = Vec::with_capacity(text.len() + 3);
            line.push(b'\r');
            line.push(b'<');
            line.extend_from_slice(&text::from_utf8(&text));
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
                    (tag::CHAT_SUBJECT, text::from_utf8(&subject)),
                ],
            );
        }
        Event::ChatPassword { cid, password } => {
            push(
                tx,
                hdr::CHAT_SUBJECT,
                vec![
                    (tag::CHAT_ID, cid.to_be_bytes().to_vec()),
                    (tag::PASSWORD, text::from_utf8(&password)),
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
                    (tag::NAME, mac_nick(&from_nick)),
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
                    (tag::COLOUR, wire_color(&user).to_be_bytes().to_vec()),
                    (tag::NAME, mac_nick(&user.nick)),
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
        } => {
            push(
                tx,
                hdr::MSG,
                vec![
                    (tag::UID, from.to_be_bytes().to_vec()),
                    (tag::BODY, text::from_utf8(&text)),
                    (tag::NAME, mac_nick(&from_nick)),
                ],
            );
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
                    (tag::BODY, text::from_utf8(&text)),
                    (tag::NAME, mac_nick(&from_nick)),
                ],
            );
        }
        Event::Kicked => return false,
    }
    true
}

async fn session_loop(
    frames: &mut Receiver<Frame>,
    events: &mut UnboundedReceiver<Event>,
    tx: &Tx,
    ctx: &ServerCtx,
    sess: &mut Session,
) {
    loop {
        tokio::select! {
            maybe = frames.recv() => match maybe {
                Some(f) => {
                    trace_in(&f);
                    dispatch(&f, tx, ctx, sess);
                }
                None => return, // Reader exited: EOF, error, or bad frame.
            },
            maybe = events.recv() => match maybe {
                Some(ev) => {
                    if !deliver_event(tx, ev) {
                        info!(uid = sess.uid, "kicked");
                        return;
                    }
                }
                None => return, // Detached elsewhere; shouldn't happen.
            },
        }
    }
}

fn dispatch(f: &Frame, tx: &Tx, ctx: &ServerCtx, sess: &mut Session) {
    match f.ty {
        t if t == ClientHdr::Ping.as_u32() => reply(tx, f.trans, vec![]),

        t if t == ClientHdr::UserGetList.as_u32() => {
            let mut chunks: Vec<(u16, Vec<u8>)> = ctx
                .core
                .snapshot()
                .iter()
                .map(|u| (tag::USER_LIST, userlist_payload(u)))
                .collect();
            chunks.push((
                tag::CHAT_SUBJECT,
                text::from_utf8(&ctx.core.public_subject()),
            ));
            reply(tx, f.trans, chunks);
        }

        t if t == ClientHdr::UserChange.as_u32() => {
            let (mut nick, mut icon) = (None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::NAME if sess.can(bit::USE_ANY_NAME) => {
                        nick = Some(text::to_utf8(cap31(c.data)));
                    }
                    tag::ICON => icon = Some(c.as_uint() as u16),
                    _ => {}
                }
            }
            ctx.core.update(sess.uid, nick, icon);
            if !sess.announced {
                complete_login(tx, ctx, sess);
            }
            // No reply — USER_CHANGE is fire-and-forget on the wire.
        }

        t if t == ClientHdr::AgreementAgree.as_u32() => {
            let (mut nick, mut icon) = (None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::NAME if sess.can(bit::USE_ANY_NAME) => {
                        nick = Some(text::to_utf8(cap31(c.data)));
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
                complete_login(tx, ctx, sess);
            }
        }

        // --- Chat -----------------------------------------------------
        t if t == ClientHdr::Chat.as_u32() => {
            let (mut cid, mut style, mut body) = (0u32, 0u16, String::new());
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::STYLE => style = c.as_uint() as u16,
                    tag::BODY => body = text::to_utf8(&c.data[..c.data.len().min(MAX_CHAT_INPUT)]),
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
            if cid == 0 {
                ctx.core.chat_public(sess.uid, body, style);
            } else if let Err(e) = ctx.core.chat_private(cid, sess.uid, body, style) {
                debug!(uid = sess.uid, cid, "private chat dropped: {e:?}");
            }
        }

        t if t == ClientHdr::ChatSubject.as_u32() => {
            let (mut cid, mut subject, mut password) = (0u32, None, None);
            for c in f.chunks() {
                match c.tag {
                    tag::CHAT_ID => cid = c.as_uint(),
                    tag::CHAT_SUBJECT => {
                        subject = Some(text::to_utf8(&c.data[..c.data.len().min(255)]))
                    }
                    tag::PASSWORD => password = Some(text::to_utf8(cap31(c.data))),
                    _ => {}
                }
            }
            // Public-subject policy: the reference server gates this on a
            // config list (access_extra.set_subject, default nobody); we
            // approximate with the disconnect_users (admin) bit until
            // account files grow an extras section.
            if cid == 0 && !sess.can(bit::DISCONNECT_USERS) {
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
                        (tag::COLOUR, wire_color(&me).to_be_bytes().to_vec()),
                        (tag::NAME, mac_nick(&me.nick)),
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
                    tag::PASSWORD => password = text::to_utf8(cap31(c.data)),
                    _ => {}
                }
            }
            match ctx.core.chat_join(cid, sess.uid, &password) {
                Ok((rows, subject)) => {
                    let mut chunks: Vec<(u16, Vec<u8>)> = rows
                        .iter()
                        .map(|u| (tag::USER_LIST, userlist_payload(u)))
                        .collect();
                    chunks.push((tag::CHAT_SUBJECT, text::from_utf8(&subject)));
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
            if !sess.can(bit::SEND_MSGS) {
                reply_error(tx, f.trans, "You are not allowed to send private messages.");
                return;
            }
            let (mut to, mut body) = (0 as Uid, String::new());
            for c in f.chunks() {
                match c.tag {
                    tag::UID => to = c.as_uint() as Uid,
                    tag::BODY => body = text::to_utf8(&c.data[..c.data.len().min(MAX_CHAT_INPUT)]),
                    _ => {}
                }
            }
            if to == 0 || body.is_empty() {
                reply_error(tx, f.trans, "Empty message or no recipient.");
                return;
            }
            match ctx.core.msg(sess.uid, to, body) {
                Ok(()) => reply(tx, f.trans, vec![]),
                Err(e) => reply_error(tx, f.trans, err_text(e)),
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
                .map(|c| text::to_utf8(&c.data[..c.data.len().min(MAX_CHAT_INPUT)]))
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
                    (tag::BODY, text::from_utf8(&info)),
                    (tag::NAME, mac_nick(&d.info.nick)),
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

        t if t == ClientHdr::Login.as_u32() => {
            reply_error(tx, f.trans, "Already logged in.");
        }

        other => {
            debug!("unimplemented transaction {other:#x}");
            reply_error(tx, f.trans, "Not implemented.");
        }
    }
}
