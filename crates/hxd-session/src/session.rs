//! The per-connection session actor.
//!
//! One tokio task reads and dispatches frames; a second owns the write half
//! and serializes every outbound frame through a mailbox, stamping the
//! server-push transaction counter in exactly one place. Domain events
//! arrive on the session's roster channel and are encoded here — the domain
//! layer never sees wire bytes.
//!
//! The protocol flow (magic exchange, login chunk-walk, the version-driven
//! agreement dance, user-list shape) mirrors mhxd's `rcv.c` /
//! `protocol/hotline.c`, which is the behavioral reference for what 1.2 and
//! 1.5 clients expect. Deviations are deliberate and commented.

use std::sync::Arc;
use std::time::Duration;

use hotline_proto::messages::{tag, ClientHdr};
use hotline_proto::text;
use hxd_core::access::bit;
use hxd_core::{Account, AuthBackend, AuthError, Core, Event, Proof, Uid, UserInfo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
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
}

/// `HTLS_DATA_BANNERID` — hotline-proto has no constant for it (the gtkhx
/// client ignores the chunk).
const TAG_BANNERID: u16 = 0x00a1;

/// The client hello: `"TRTPHOTL" 0x0001 0x0002`.
const CLIENT_MAGIC: [u8; 12] = *b"TRTPHOTL\x00\x01\x00\x02";
/// The server's answer: `"TRTP"` + a zero error code.
const SERVER_MAGIC: [u8; 8] = *b"TRTP\x00\x00\x00\x00";

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
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            name: "hxd-ng".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(10),
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
            run_session(stream, ctx).instrument(span).await;
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

/// The `HTLS_DATA_USER_LIST` payload: uid, icon, color, nlen (all u16 BE),
/// then the name bytes. `struct hl_userlist_hdr` minus the chunk header.
fn userlist_payload(u: &UserInfo) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + u.nick.len());
    v.extend_from_slice(&u.uid.to_be_bytes());
    v.extend_from_slice(&u.icon.to_be_bytes());
    v.extend_from_slice(&u.color.to_be_bytes());
    v.extend_from_slice(&(u.nick.len() as u16).to_be_bytes());
    v.extend_from_slice(&u.nick);
    v
}

fn user_change_chunks(u: &UserInfo) -> Vec<(u16, Vec<u8>)> {
    vec![
        (tag::UID, u.uid.to_be_bytes().to_vec()),
        (tag::ICON, u.icon.to_be_bytes().to_vec()),
        (tag::COLOUR, u.color.to_be_bytes().to_vec()),
        (tag::NAME, u.nick.clone()),
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

pub async fn run_session(stream: TcpStream, ctx: ServerCtx) {
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

    let (tx, rx) = mpsc::unbounded_channel();
    let mut wr_for_magic = wr;
    if wr_for_magic.write_all(&SERVER_MAGIC).await.is_err() {
        return;
    }
    let writer = tokio::spawn(writer_task(wr_for_magic, rx));

    // --- Login, then the frame loop -------------------------------------
    let sess = match login_phase(&mut rd, &tx, &ctx).await {
        Some(sess) => sess,
        None => {
            drop(tx);
            let _ = writer.await;
            return;
        }
    };
    let uid = sess.uid;
    info!(uid, login = %sess.account.login, "logged in");

    frame_loop(&mut rd, &tx, &ctx, sess).await;

    ctx.core.detach(uid);
    info!(uid, "disconnected");
    drop(tx);
    let _ = writer.await;
}

/// Wait for the LOGIN transaction and run the login flow. `None` = close.
async fn login_phase(rd: &mut OwnedReadHalf, tx: &Tx, ctx: &ServerCtx) -> Option<Session> {
    let f = match timeout(ctx.cfg.login_timeout, read_frame(rd)).await {
        Ok(Ok(f)) => f,
        Ok(Err(ReadError::Malformed(why))) => {
            warn!("malformed frame before login: {why}");
            return None;
        }
        _ => return None, // timeout, EOF, io error
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

    // Authenticate on the blocking pool — backends do file I/O.
    let auth = ctx.auth.clone();
    let login_str = String::from_utf8_lossy(&req.login).into_owned();
    let password = req.password.clone();
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
        (Some(n), true) => n.clone(),
        _ => text::from_utf8(&account.name),
    };
    let color = if account.access.has(bit::DISCONNECT_USERS) {
        2
    } else {
        0
    };

    let Some((uid, events)) = ctx.core.attach(nick, req.icon, color, account.access) else {
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

    // Start the event pump now that the roster feeds us.
    spawn_event_pump(events, tx.clone());

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
    Some(sess)
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

fn spawn_event_pump(mut events: UnboundedReceiver<Event>, tx: Tx) {
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                Event::Joined(u) | Event::Changed(u) => {
                    push(&tx, hdr::USER_CHANGE, user_change_chunks(&u));
                }
                Event::Parted(uid) => {
                    push(
                        &tx,
                        hdr::USER_PART,
                        vec![(tag::UID, uid.to_be_bytes().to_vec())],
                    );
                }
            }
        }
    });
}

async fn frame_loop(rd: &mut OwnedReadHalf, tx: &Tx, ctx: &ServerCtx, mut sess: Session) {
    loop {
        let f = match read_frame(rd).await {
            Ok(f) => f,
            Err(ReadError::Eof) => return,
            Err(ReadError::Io(e)) => {
                debug!("read error: {e}");
                return;
            }
            Err(ReadError::Malformed(why)) => {
                warn!("malformed frame: {why}");
                return;
            }
        };
        trace_in(&f);

        match f.ty {
            t if t == ClientHdr::Ping.as_u32() => reply(tx, f.trans, vec![]),
            t if t == ClientHdr::UserGetList.as_u32() => {
                let mut chunks: Vec<(u16, Vec<u8>)> = ctx
                    .core
                    .snapshot()
                    .iter()
                    .map(|u| (tag::USER_LIST, userlist_payload(u)))
                    .collect();
                // The reference server always appends the public-chat
                // subject; empty until the chat phase gives it content.
                chunks.push((tag::CHAT_SUBJECT, Vec::new()));
                reply(tx, f.trans, chunks);
            }
            t if t == ClientHdr::UserChange.as_u32() => {
                let (mut nick, mut icon) = (None, None);
                for c in f.chunks() {
                    match c.tag {
                        tag::NAME if sess.account.access.has(bit::USE_ANY_NAME) => {
                            nick = Some(cap31(c.data).to_vec());
                        }
                        tag::ICON => icon = Some(c.as_uint() as u16),
                        _ => {}
                    }
                }
                ctx.core.update(sess.uid, nick, icon);
                if !sess.announced {
                    complete_login(tx, ctx, &mut sess);
                }
                // No reply — USER_CHANGE is fire-and-forget on the wire.
            }
            t if t == ClientHdr::AgreementAgree.as_u32() => {
                let (mut nick, mut icon) = (None, None);
                for c in f.chunks() {
                    match c.tag {
                        tag::NAME if sess.account.access.has(bit::USE_ANY_NAME) => {
                            nick = Some(cap31(c.data).to_vec());
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
                    complete_login(tx, ctx, &mut sess);
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
}
