//! One WebSocket connection: handshake (login / resume), then a select
//! loop over incoming requests and outgoing domain events.
//!
//! Requests are handled inline, in order, replies written directly — the
//! spec promises in-order replies and this is the cheapest way to keep the
//! promise. Domain events arrive on the session's outbox channel already
//! seq-stamped; this layer only encodes them.

use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use hxd_core::access::bit;
use hxd_core::inbox::MessageGuid;
use hxd_core::video::VideoKind;
use hxd_core::voice::IceCandidate;
use hxd_core::{
    AccessBits, AttachInfo, AuthError, ChatError, MsgOutcome, Proof, Resume, SeqEvent, Uid,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use crate::identity::{AuthRefused, Outcome, TransportIdentity};
use crate::proto::{
    blocked_json, event_json, history_line_json, parse_streams, participants_json, reply_err,
    reply_ok, stored_msg_json, user_json, video_err, video_limits_json, voice_err, BlockParams,
    ChatParams, HistoryParams, InboxParams, LoginParams, MsgParams, MsgReadParams, NickParams,
    ReqEnvelope, ResumeParams, VideoStartParams, VideoStateParams, VideoStopParams,
    VideoSubscribeParams, VoiceAnswerParams, VoiceIceParams, VoiceMuteParams, VoiceRoomParams,
};
use crate::NgCtx;

/// How often a quiet connection is pinged, and how long it may stay
/// silent before the ping is treated as unanswered. The deadline is
/// three periods so that one lost ping, or one tick delayed behind a
/// slow handler, is not a disconnection.
const PING_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
const PONG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// The socket after the HTTP layer upgraded it.
type Ws = WebSocketStream<TokioIo<Upgraded>>;

/// Per-connection state once a session is attached.
struct SessState {
    uid: Uid,
    session_id: String,
    access: AccessBits,
}

/// Why the connection loop ended, deciding the session's fate.
enum Exit {
    /// Socket died or closed without logout → detach if permitted.
    ConnectionLost,
    /// Clean logout or kick → session already ended; registry cleaned.
    SessionOver,
    /// The outbox channel closed under us: another connection took the
    /// session over (or it ended elsewhere). Not ours anymore.
    Replaced,
}

/// Run the JSON protocol on an upgraded socket. `identity` is the
/// transport identity the HTTP layer authenticated, if any
/// (`docs/hotline-ng-auth.md` §7.2); the ban check happened before
/// the upgrade.
pub(crate) async fn run(ws: Ws, peer: SocketAddr, ctx: NgCtx, identity: Option<TransportIdentity>) {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // --- Handshake: the first request must be login or resume. ----------
    let first = match timeout(ctx.cfg.login_timeout, next_request(&mut ws_rx)).await {
        Ok(Some(req)) => req,
        _ => return,
    };

    let (state, mut events) = match first.req.as_str() {
        "login" => match handle_login(&ctx, peer, &first, identity.as_ref(), &mut ws_tx).await {
            Some(v) => v,
            None => return,
        },
        "resume" => match handle_resume(&ctx, &first, &mut ws_tx).await {
            Some(v) => v,
            None => return,
        },
        _ => {
            let _ = send_frame(
                &mut ws_tx,
                Message::Text(reply_err(
                    first.id,
                    "not_logged_in",
                    "Log in or resume first.",
                )),
            )
            .await;
            return;
        }
    };
    info!(uid = state.uid, session = %state.session_id, "ng session attached");

    // --- Main loop -------------------------------------------------------
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // Consume the immediate first tick.

    // A ping with no deadline behind it asks a question and accepts no
    // answer: a peer that stops reading — a NAT that dropped the
    // mapping, a laptop in a bag — leaves the session attached until TCP
    // gives up, which can be many minutes and on some paths never. Any
    // inbound frame counts as an answer, pongs included (tungstenite
    // hands them up), so a client that talks at all never sees this.
    let mut heard = tokio::time::Instant::now();

    let exit = loop {
        tokio::select! {
            // Biased, events first: a reply must never overtake an event
            // the session was handed before the request arrived. Without
            // it the two branches race for one sink, and a `sync` reply
            // could go out ahead of an event whose seq that reply says
            // the client is already past — which a client doing the
            // natural "drop anything at or below my seq" would then
            // discard, losing a message the store has marked delivered.
            //
            // A link slower than a room can keep this arm ready and delay
            // requests (including the ping tick). Each write is bounded by
            // the pong deadline, though, so a dead peer still ends after at
            // most the buffered backlog plus that deadline.
            biased;
            ev = events.recv() => match ev {
                Some(se) => {
                    let kicked = matches!(se.event, hxd_core::Event::Kicked);
                    if !send_frame(&mut ws_tx, Message::Text(event_json(&se))).await {
                        break Exit::ConnectionLost;
                    }
                    if kicked {
                        end_kicked(&ctx, &state, &mut ws_tx).await;
                        break Exit::SessionOver;
                    }
                }
                None => break Exit::Replaced,
            },
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    heard = tokio::time::Instant::now();
                    let Ok(req) = serde_json::from_str::<ReqEnvelope>(&text) else {
                        debug!("unparseable request frame");
                        break Exit::ConnectionLost;
                    };
                    // `sync` is the one request that needs the event
                    // channel itself; see `handle_sync`.
                    let flow = if req.req == "sync" {
                        handle_sync(&ctx, &state, &req, &mut ws_tx, &mut events).await
                    } else {
                        dispatch(&ctx, &state, &req, &mut ws_tx).await
                    };
                    match flow {
                        Flow::Continue => {}
                        Flow::LoggedOut => break Exit::SessionOver,
                        Flow::Dead => break Exit::ConnectionLost,
                        Flow::Replaced => break Exit::Replaced,
                    }
                }
                Some(Ok(Message::Close(_))) | None => break Exit::ConnectionLost,
                // A pong (or anything else) is the peer answering the
                // keep-alive; nothing to do with it but note that it
                // came.
                Some(Ok(_)) => heard = tokio::time::Instant::now(),
                Some(Err(e)) => {
                    debug!("ws error: {e}");
                    break Exit::ConnectionLost;
                }
            },
            _ = ping.tick() => {
                if heard.elapsed() >= PONG_DEADLINE {
                    info!(uid = state.uid, "ng connection silent past the pong deadline");
                    break Exit::ConnectionLost;
                }
                if !send_frame(&mut ws_tx, Message::Ping(Vec::new())).await {
                    break Exit::ConnectionLost;
                }
            }
        }
    };

    match exit {
        Exit::ConnectionLost => {
            let survived = ctx
                .core
                .connection_lost(state.uid, ctx.cfg.max_detached_per_addr);
            if survived {
                info!(uid = state.uid, "ng session detached");
            } else {
                ctx.registry.remove(&state.session_id);
                info!(uid = state.uid, "ng session ended (no detach)");
            }
        }
        Exit::SessionOver => {
            info!(uid = state.uid, "ng session ended");
        }
        Exit::Replaced => {
            info!(uid = state.uid, "ng connection replaced by a newer one");
            let _ = send_frame(
                &mut ws_tx,
                Message::Close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "replaced".into(),
                })),
            )
            .await;
        }
    }
}

/// Read frames until a parseable request arrives (or the stream ends).
async fn next_request(ws_rx: &mut futures_util::stream::SplitStream<Ws>) -> Option<ReqEnvelope> {
    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(text)) => match serde_json::from_str(&text) {
                Ok(req) => return Some(req),
                Err(e) => {
                    debug!("bad handshake frame: {e}");
                    return None;
                }
            },
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
    None
}

type WsTx = futures_util::stream::SplitSink<Ws, Message>;

/// Why a login did not happen. The backend's own answer, or the identity
/// policy's — which §8.1 calls `denied` and which is not a failed login:
/// an identity socket sends no credentials, so there was nothing to get
/// wrong.
enum Refused {
    Auth(AuthError),
    Denied,
    Backend,
}

async fn handle_login(
    ctx: &NgCtx,
    peer: SocketAddr,
    req: &ReqEnvelope,
    identity: Option<&TransportIdentity>,
    ws_tx: &mut WsTx,
) -> Option<(SessState, UnboundedReceiver<SeqEvent>)> {
    // Absent params is a guest login; *malformed* params is an error, like
    // every other handler — never mistake a client bug for a guest.
    let p: LoginParams = if req.params.is_null() {
        LoginParams::default()
    } else {
        match serde_json::from_value(req.params.clone()) {
            Ok(p) => p,
            Err(_) => {
                let _ = send_frame(
                    ws_tx,
                    Message::Text(reply_err(req.id, "bad_request", "Malformed login.")),
                )
                .await;
                return None;
            }
        }
    };

    // An authenticated socket ignores credentials (§6.2, §8.1): the
    // linked account if there is one (re-read now, so a link made since
    // the token was issued counts), else guest. A socket the identity
    // layer refused never got a token or a certificate admission, so it
    // can't reach here — `new_accounts = deny` is decided there, on
    // every admitting path.
    let auth = ctx.auth.clone();
    let identity_state = ctx.identity.clone();
    let (login, password) = match identity {
        Some(_) => (String::new(), String::new()),
        None => (p.login.clone(), p.password.clone()),
    };
    let ident = identity.cloned();
    let core = ctx.core.clone();
    let verdict = tokio::task::spawn_blocking(move || {
        let account = if let (Some(i), Some(st)) = (ident.as_ref(), identity_state.as_ref()) {
            match st.account_for(i) {
                Ok(Some(account)) => Ok(account),
                Ok(None) => auth
                    .authenticate(&login, Proof::Plain(password.as_bytes()))
                    .map_err(Refused::Auth),
                // §8.1's own word for this outcome, rather than "login
                // failed": nothing about a login failed — this socket
                // sent no credentials — the server's policy refused the
                // identity, and a client that is told the wrong one
                // will retry with a password it does not need.
                Err(AuthRefused::Backend) => Err(Refused::Backend),
                Err(_) => Err(Refused::Denied),
            }
        } else {
            auth.authenticate(&login, Proof::Plain(password.as_bytes()))
                .map_err(Refused::Auth)
        };
        // A linked account's mail is claimed onto the fingerprint before
        // the session starts. `claim` is idempotent, and doing it only
        // at link time left two windows open: a `msg_login` that read
        // the directory before the link was written, and an account
        // linked from another device while a session of it was up. Rows
        // left on the bare login are invisible after the next login.
        if let Ok(a) = &account {
            if let Some(fp) = a.identity.fingerprint {
                let moved = core.inbox_claim(&a.login, &fp);
                if moved > 0 {
                    info!(login = %a.login, moved, "inbox claimed at login");
                }
            }
        }
        account
    })
    .await
    .ok()?;

    let account = match verdict {
        Ok(a) => a,
        Err(Refused::Denied) => {
            info!("ng login denied by policy");
            let _ = send_frame(
                ws_tx,
                Message::Text(reply_err(
                    req.id,
                    "denied",
                    "This identity may not log in here.",
                )),
            )
            .await;
            return None;
        }
        Err(Refused::Backend) => {
            warn!("identity account lookup failed");
            let _ = send_frame(
                ws_tx,
                Message::Text(reply_err(req.id, "server_error", "Server error.")),
            )
            .await;
            return None;
        }
        Err(Refused::Auth(e @ (AuthError::NoSuchAccount | AuthError::BadProof))) => {
            info!(login = %p.login, "ng login refused: {e}");
            let _ = send_frame(
                ws_tx,
                Message::Text(reply_err(req.id, "login_failed", "Login failed.")),
            )
            .await;
            return None;
        }
        Err(Refused::Auth(AuthError::Backend(e))) => {
            warn!("auth backend failure: {e}");
            let _ = send_frame(
                ws_tx,
                Message::Text(reply_err(req.id, "server_error", "Server error.")),
            )
            .await;
            return None;
        }
    };

    let mut nick = match (&p.nick, account.access.has(bit::USE_ANY_NAME)) {
        (Some(n), true) if !n.is_empty() => n.clone(),
        _ => account.name.clone(),
    };
    // The legacy wire truncates a nick to 31 Mac Roman bytes after
    // conversion, and this one is copied into every stored message's
    // `sender_nick` — up to `max_queued` rows per recipient — so it is
    // bounded here rather than only where it is rendered. In characters,
    // because that is what one Mac Roman byte is worth (§8).
    nick.truncate_to_chars(NICK_MAX_CHARS);
    let attach = AttachInfo {
        nick,
        icon: p.icon.unwrap_or(128),
        admin: account.access.has(bit::DISCONNECT_USERS),
        access: account.access,
        login: account.login.clone(),
        addr: Some(peer.ip()),
        can_detach: account.can_detach,
        // The plaintext listener is loopback-only and WSS is mandatory in
        // production (`docs/hotline-ng.md` §9), so ng sockets are
        // encrypted by construction — unless the client told us at
        // `/identity/auth` that it forwards over a cleartext hop (§5.2
        // `downstream`). A client may make itself look less safe than it
        // is, never more, and the `/trtp` path already honoured this.
        transport: hxd_core::Transport {
            encrypted: !identity.is_some_and(|i| i.downstream_cleartext),
            identity: identity.map(TransportIdentity::tag),
        },
        has_inbox: account.has_inbox,
        // ng has `msg_read`; a client says for itself when it has read
        // something, and delivery is not that.
        reads_on_delivery: false,
        // The account's link first, the socket's identity only where
        // there is none — see `AttachInfo::identity`. A mailbox belongs
        // to the account, so it is the same mailbox whether its owner
        // arrived with a password or with their key; the transport's
        // fingerprint stands in only for an identity user admitted as a
        // guest, which gives that session something to be blocked by
        // without giving it a mailbox it must not have.
        identity: account
            .identity
            .fingerprint
            .or_else(|| identity.map(|i| i.fingerprint.0)),
    };
    let Some((uid, events)) = ctx.core.attach(attach) else {
        let _ = send_frame(
            ws_tx,
            Message::Text(reply_err(req.id, "server_full", "Server full.")),
        )
        .await;
        return None;
    };
    // ng has no agreement dance: announce immediately (the snapshot below
    // then includes self).
    ctx.core.announce(uid);

    let Some((session_id, token)) = ctx.registry.issue(&ctx.core, uid) else {
        ctx.core.end_session(uid);
        return None;
    };

    let Some(me) = ctx.core.user(uid) else {
        ctx.core.end_session(uid);
        ctx.registry.remove(&session_id);
        return None;
    };
    let users: Vec<_> = ctx.core.snapshot().iter().map(user_json).collect();
    let detach = if account.can_detach {
        json!({ "grace": ctx.cfg.grace.as_secs() })
    } else {
        serde_json::Value::Null
    };
    let mut server = json!({
        "name": ctx.cfg.server_name,
        "subject": ctx.core.public_subject(),
    });
    if let Some(agreement) = &ctx.cfg.agreement {
        server["agreement"] = json!(agreement);
    }
    let mut me_json = user_json(&me);
    if let Some(i) = identity {
        // `age` and `outcome` are for the user themself, never the roster.
        // The outcome reflects the account this session actually landed
        // on, which can differ from the token's if a link was made in
        // between.
        let outcome = if account.identity.fingerprint == Some(i.fingerprint.0) {
            if i.outcome == Outcome::Created {
                "created"
            } else {
                "linked"
            }
        } else {
            i.outcome.as_str()
        };
        me_json["identity"] = json!({
            "fingerprint": i.fingerprint.to_string(),
            "handle": i.handle,
            "age": i.age,
            "outcome": outcome,
            "account": if account.login == "guest" { Value::Null } else { json!(account.login) },
        });
    }
    // `identity` is a property of the server, not of the config's
    // extension list: it's on whenever the identity endpoints are.
    let mut caps = ctx.cfg.caps.clone();
    if ctx.identity.is_some() && !caps.iter().any(|c| c == "identity") {
        caps.push("identity".into());
    }
    let mut ok = json!({
        "session": session_id,
        "token": token,
        "self": me_json,
        "server": server,
        "users": users,
        "detach": detach,
        // Always present, empty when this build offers no extensions:
        // absent and empty mean the same thing, and one shape is one
        // less case for a client to get wrong.
        "caps": caps,
        "seq": 0,
    });
    // The ceilings, so a client configures its encoders before the first
    // join rather than discovering them by rejection. Present only when
    // video is — `"video"` never appears in `caps` without `"voice"`,
    // and this object never appears without `"video"`.
    if ctx.core.video_enabled() {
        ok["video"] = video_limits_json(&ctx.core.video_config());
    }
    // What is waiting, so a client can render a badge before any of it
    // arrives. Absent on a server with no inbox, like the video block.
    if ctx.core.inbox_enabled() {
        let counts = off_reactor(&ctx.core, move |c| c.inbox_counts(uid))
            .await
            // `None` is the blocking task itself failing — a panic in
            // the store. Same empty badge, and worth the same line in
            // the log as a store error, or a panicked count is the one
            // failure here nothing records.
            .unwrap_or_else(|| {
                warn!(
                    uid,
                    "inbox counts panicked at login; reporting an empty badge"
                );
                Ok(Default::default())
            })
            .unwrap_or_else(|e| {
                // A store that would not answer becomes an empty badge:
                // there is no shape in the login reply for "unknown",
                // and refusing the login over a count would be worse.
                // But an empty badge on a full mailbox is a lie, so it
                // is said here as well as in the domain's own log.
                warn!(
                    uid,
                    "inbox counts unavailable at login: {e:?}; reporting an empty badge"
                );
                Default::default()
            });
        ok["inbox"] = json!({ "unread": counts.unread, "total": counts.total });
    }
    if let Some(history) = ctx.core.history_policy() {
        ok["history"] = json!({
            "max_lines": history.max_lines,
            "max_days": history.max_days,
        });
    }
    if !send_frame(ws_tx, Message::Text(reply_ok(req.id, ok))).await {
        // The client never learned it was logged in; a ghost session with
        // no transport (and a leaked token) must not linger.
        ctx.core.end_session(uid);
        ctx.registry.remove(&session_id);
        return None;
    }
    info!(uid, login = %account.login, "ng logged in");
    // Mail from before this login, after the client has the roster it
    // needs to make sense of who sent it.
    off_reactor(&ctx.core, move |c| c.flush_inbox(uid)).await;

    Some((
        SessState {
            uid,
            session_id,
            access: account.access,
        },
        events,
    ))
}

async fn handle_resume(
    ctx: &NgCtx,
    req: &ReqEnvelope,
    ws_tx: &mut WsTx,
) -> Option<(SessState, UnboundedReceiver<SeqEvent>)> {
    let Ok(p) = serde_json::from_value::<ResumeParams>(req.params.clone()) else {
        let _ = send_frame(
            ws_tx,
            Message::Text(reply_err(req.id, "bad_request", "Malformed resume.")),
        )
        .await;
        return None;
    };
    let Some(uid) = ctx.registry.validate(&ctx.core, &p.session, &p.token) else {
        let _ = send_frame(
            ws_tx,
            Message::Text(reply_err(
                req.id,
                "session_expired",
                "Session expired; log in again.",
            )),
        )
        .await;
        return None;
    };

    let (events, replay) = match ctx.core.resume(uid, p.last_seq) {
        Resume::Replayed(rx, replay) => (rx, Some(replay)),
        Resume::ResyncRequired(rx) => (rx, None),
        Resume::Gone => {
            ctx.registry.remove(&p.session);
            let _ = send_frame(
                ws_tx,
                Message::Text(reply_err(
                    req.id,
                    "session_expired",
                    "Session expired; log in again.",
                )),
            )
            .await;
            return None;
        }
    };
    let access = ctx.core.access_of(uid).unwrap_or_default();
    let state = SessState {
        uid,
        session_id: p.session.clone(),
        access,
    };

    // From here the session is attached: any send failure means the new
    // transport died mid-handshake, and the session must go back through
    // the connection-lost policy (detach or end) rather than sit live
    // with a dropped receiver.
    let lost = |ctx: &NgCtx| {
        if !ctx.core.connection_lost(uid, ctx.cfg.max_detached_per_addr) {
            ctx.registry.remove(&p.session);
        }
    };
    match replay {
        Some(replay) => {
            let Some(me) = ctx.core.user(uid) else {
                lost(ctx);
                return None;
            };
            let ok = json!({ "replay": replay.len(), "self": user_json(&me) });
            if !send_frame(ws_tx, Message::Text(reply_ok(req.id, ok))).await {
                lost(ctx);
                return None;
            }
            for se in &replay {
                if !send_frame(ws_tx, Message::Text(event_json(se))).await {
                    lost(ctx);
                    return None;
                }
            }
            info!(uid, replayed = replay.len(), "ng resumed");
        }
        None => {
            // The session is attached and live, but the gap is gone —
            // the client follows with `sync` on this same connection.
            let err = reply_err(
                req.id,
                "resync_required",
                "Event gap unrecoverable; sync required.",
            );
            if !send_frame(ws_tx, Message::Text(err)).await {
                lost(ctx);
                return None;
            }
            info!(uid, "ng resumed with resync required");
            // **No flush here.** The client has been told to `sync`, and
            // the seq that reply reports is past whatever this flush
            // would emit — so the events would be marked delivered and
            // then skipped, which is the one way a stored message can be
            // lost outright. `sync` flushes, after its own reply.
            return Some((state, events));
        }
    }
    // Anything that arrived while this session had no connection at all
    // is in the inbox, not the replay buffer — one message, one place.
    off_reactor(&ctx.core, move |c| c.flush_inbox(uid)).await;
    Some((state, events))
}

/// Run a domain call that touches the message store off the reactor.
///
/// `Core` is synchronous all the way down (`hxd_core::inbox` explains
/// why), so `msg`, `msg_login`, `flush_inbox` and every `inbox_*` call is
/// rusqlite with a five-second busy timeout and `synchronous = FULL`
/// fsyncs — plus, for `msg_login`, the accounts-directory read behind
/// `inbox_account`. On a tokio worker one slow disk, or an external
/// `sqlite3` holding a write lock, stalls every session that worker is
/// carrying. This file already does exactly this for `authenticate`.
async fn off_reactor<T: Send + 'static>(
    core: &std::sync::Arc<hxd_core::Core>,
    f: impl FnOnce(&hxd_core::Core) -> T + Send + 'static,
) -> Option<T> {
    let core = core.clone();
    tokio::task::spawn_blocking(move || f(&core)).await.ok()
}

/// Send one frame and continue, for the handful of places that answer
/// before the dispatch table's single exit.
async fn finish(ws_tx: &mut WsTx, out: String) -> Flow {
    if !send_frame(ws_tx, Message::Text(out)).await {
        return Flow::Dead;
    }
    Flow::Continue
}

enum Flow {
    Continue,
    LoggedOut,
    Dead,
    Replaced,
}

/// Write one frame, giving up if the socket will not take it.
///
/// A send that never completes is the same peer the pong deadline is
/// about — one that stopped reading — and without a bound on it that
/// deadline never runs: the loop is parked inside `send`, and the arm
/// that would notice the silence does not get a turn. In a busy room
/// that is the ordinary shape of the failure, not an exotic one: the
/// kernel buffer fills, the next event blocks, and the session lives
/// until TCP gives up. Same window as a missed pong, for the same peer.
///
/// `false` means the connection is gone, which every caller already
/// treats as the end of it.
async fn send_frame(ws_tx: &mut WsTx, msg: Message) -> bool {
    match timeout(PONG_DEADLINE, ws_tx.send(msg)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            debug!("ng send failed: {e}");
            false
        }
        Err(_) => {
            info!("ng send blocked past the pong deadline");
            false
        }
    }
}

/// End a session the domain kicked: the event has already gone out, and
/// this is the teardown that follows it.
async fn end_kicked(ctx: &NgCtx, state: &SessState, ws_tx: &mut WsTx) {
    ctx.core.end_session(state.uid);
    ctx.registry.remove(&state.session_id);
    let _ = send_frame(
        ws_tx,
        Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "kicked".into(),
        })),
    )
    .await;
}

/// `sync` (`docs/hotline-ng.md` §6): the roster snapshot and the seq the
/// client continues from, then the mail it missed.
///
/// It lives here rather than in `dispatch` because it is the one request
/// that has to reach the event channel. The `seq` this reply reports is
/// what the client will treat as "everything up to here is accounted
/// for", so nothing at or below it may arrive afterwards — and events
/// already handed to this session were sitting in the channel, behind a
/// reply that shares their sink. Snapshotting the seq and then draining
/// everything at or below it makes the promise true rather than likely;
/// whatever is stamped after the snapshot gets a later seq by construction.
async fn handle_sync(
    ctx: &NgCtx,
    state: &SessState,
    req: &ReqEnvelope,
    ws_tx: &mut WsTx,
    events: &mut UnboundedReceiver<SeqEvent>,
) -> Flow {
    // `Outbox::push` assigns the seq and sends the event while holding the
    // same roster lock `current_seq` takes. Therefore every event at or
    // below this snapshot is already in `events`, and every later enqueue
    // has a higher seq. Moving that send outside the lock would reopen MS9.
    let mut seq = ctx.core.current_seq(state.uid).unwrap_or(0);
    let mut kicked = false;
    loop {
        match events.try_recv() {
            Ok(se) => {
                seq = seq.max(se.seq);
                kicked |= matches!(se.event, hxd_core::Event::Kicked);
                if !send_frame(ws_tx, Message::Text(event_json(&se))).await {
                    return Flow::Dead;
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return Flow::Replaced;
            }
        }
    }
    if kicked {
        end_kicked(ctx, state, ws_tx).await;
        return Flow::LoggedOut;
    }
    let users: Vec<_> = ctx.core.snapshot().iter().map(user_json).collect();
    let out = reply_ok(
        req.id,
        json!({
            "server": {
                "name": ctx.cfg.server_name,
                "subject": ctx.core.public_subject(),
            },
            "users": users,
            "seq": seq,
        }),
    );
    if !send_frame(ws_tx, Message::Text(out)).await {
        return Flow::Dead;
    }
    // After the seq this reply reports, so the mail arrives as events
    // the client has not already been told it is past.
    let uid = state.uid;
    off_reactor(&ctx.core, move |c| c.flush_inbox(uid)).await;
    Flow::Continue
}

async fn dispatch(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope, ws_tx: &mut WsTx) -> Flow {
    let send = |s: String| Message::Text(s);
    let out = match req.req.as_str() {
        "ping" => reply_ok(req.id, json!({})),

        "chat" => match serde_json::from_value::<ChatParams>(req.params.clone()) {
            Ok(p) if !state.access.has(bit::SEND_CHAT) => {
                let _ = p;
                reply_err(req.id, "access_denied", "You are not allowed to send chat.")
            }
            Ok(p) => {
                let style = if p.style.as_deref() == Some("action") {
                    1
                } else {
                    0
                };
                let mut text = p.text;
                text.truncate_to_char_boundary(4096);
                let uid = state.uid;
                match off_reactor(&ctx.core, move |c| c.chat_public(uid, text, style)).await {
                    Some(Ok(_)) => reply_ok(req.id, json!({})),
                    _ => reply_err(req.id, "server_error", "Server error."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed chat."),
        },

        "history" => {
            let Some(policy) = ctx.core.history_policy() else {
                return finish(
                    ws_tx,
                    reply_err(req.id, "not_available", "Chat history is not available."),
                )
                .await;
            };
            if !state.access.has(bit::CHAT_HISTORY) {
                reply_err(
                    req.id,
                    "access_denied",
                    "You are not allowed to read chat history.",
                )
            } else if !ctx.core.allow_history_request(state.uid).unwrap_or(false) {
                reply_err(req.id, "rate_limited", "Slow down.")
            } else {
                let parsed = if req.params.is_null() {
                    Ok(HistoryParams::default())
                } else {
                    serde_json::from_value::<HistoryParams>(req.params.clone())
                };
                match parsed {
                    Ok(p) if p.limit.is_none_or(|n| n != 0) => {
                        let query = hxd_core::HistoryQuery {
                            channel: 0,
                            before: p.before.filter(|id| *id != 0),
                            after: p.after.filter(|id| *id != 0),
                            limit: p.limit.unwrap_or(50).min(policy.max_page),
                        };
                        let uid = state.uid;
                        match off_reactor(&ctx.core, move |c| c.history(uid, query)).await {
                            Some(Ok(page)) => reply_ok(
                                req.id,
                                json!({
                                    "lines": page.lines.iter().map(history_line_json).collect::<Vec<_>>(),
                                    "has_more": page.has_more,
                                }),
                            ),
                            _ => reply_err(req.id, "server_error", "Server error."),
                        }
                    }
                    _ => reply_err(req.id, "bad_request", "Malformed history request."),
                }
            }
        }

        "nick" => match serde_json::from_value::<NickParams>(req.params.clone()) {
            Ok(p) => {
                let nick = p
                    .nick
                    .filter(|_| state.access.has(bit::USE_ANY_NAME))
                    .filter(|n| !n.is_empty())
                    .map(|mut n| {
                        n.truncate_to_chars(NICK_MAX_CHARS);
                        n
                    });
                ctx.core.update(state.uid, nick, p.icon);
                reply_ok(req.id, json!({}))
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed nick."),
        },

        "msg" => match serde_json::from_value::<MsgParams>(req.params.clone()) {
            Ok(_) if !state.access.has(bit::SEND_MSGS) => reply_err(
                req.id,
                "access_denied",
                "You are not allowed to send private messages.",
            ),
            Ok(p) => {
                let mut text = p.text;
                text.truncate_to_char_boundary(4096);
                // The legacy wire refuses an empty message and so does
                // this one: it would take a queue slot, notify, and
                // render as a bare `[queued …]` stamp with nothing
                // under it.
                if text.is_empty() {
                    return finish(
                        ws_tx,
                        reply_err(req.id, "bad_request", "A message needs text."),
                    )
                    .await;
                }
                // Parsed, not stored as it arrived: this indexes a
                // column, and an index over arbitrary client text is a
                // place to put anything.
                let guid = match p.guid.as_deref().map(MessageGuid::parse) {
                    None => None,
                    Some(Some(g)) => Some(g),
                    Some(None) => {
                        return finish(
                            ws_tx,
                            reply_err(req.id, "bad_request", "`guid` is not a UUID."),
                        )
                        .await
                    }
                };
                let from = state.uid;
                let outcome = match (p.to, p.to_login.clone()) {
                    (Some(uid), None) => {
                        off_reactor(&ctx.core, move |c| c.msg(from, uid, text, guid)).await
                    }
                    (None, Some(login)) => {
                        off_reactor(&ctx.core, move |c| c.msg_login(from, &login, text, guid)).await
                    }
                    // A client that sent both meant something, and
                    // guessing which is how a message reaches the wrong
                    // person.
                    _ => {
                        return finish(
                            ws_tx,
                            reply_err(
                                req.id,
                                "bad_request",
                                "Name exactly one of `to` and `to_login`.",
                            ),
                        )
                        .await
                    }
                };
                let Some(outcome) = outcome else {
                    return finish(ws_tx, reply_err(req.id, "server_error", "Server error.")).await;
                };
                // One mapping for both ways of addressing, so a code
                // cannot be added to one and forgotten on the other.
                match outcome {
                    // The reply says whether it waited, and nothing else:
                    // the message id is the *recipient's* handle for
                    // marking read, and handing a monotonic id to the
                    // sender would tell them how much mail this server
                    // carries.
                    Ok(MsgOutcome::Delivered) => reply_ok(req.id, json!({ "queued": false })),
                    Ok(MsgOutcome::Queued(_)) => reply_ok(req.id, json!({ "queued": true })),
                    Err(ChatError::MailboxFull) => {
                        reply_err(req.id, "mailbox_full", "That user's mailbox is full.")
                    }
                    Err(ChatError::Blocked) => reply_err(
                        req.id,
                        "blocked",
                        "That user is not accepting messages from you.",
                    ),
                    // A store that would not answer is our failure, not
                    // the sender's — telling them their correspondent
                    // does not exist because the disk is full is a lie
                    // they will act on.
                    Err(ChatError::ServerError) => {
                        reply_err(req.id, "server_error", "Server error.")
                    }
                    // One answer for "no such user", "no such account" and
                    // "that account takes no offline messages", so none of
                    // them can be told apart from outside.
                    Err(_) => reply_err(req.id, "no_such_user", "No such user."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed msg."),
        },

        // --- The inbox (docs/private-messages.md §6) -------------------
        //
        // The pull side of the same mail the `msg` event pushes: what a
        // client that woke to a push, or resynced, or simply opened,
        // reads to find out where it is.
        // `params` may be omitted entirely: both fields are optional, so
        // "the first page" needs nothing said. Serde will not deserialise
        // a null into a struct, hence the explicit default.
        "inbox" => match if req.params.is_null() {
            Ok(InboxParams::default())
        } else {
            serde_json::from_value::<InboxParams>(req.params.clone())
        } {
            Ok(p) => {
                let limit = p.limit.unwrap_or(50).clamp(1, 200);
                let (uid, before) = (state.uid, p.before);
                let listed = off_reactor(&ctx.core, move |c| {
                    c.inbox_list(uid, before, limit).map(|m| {
                        let counts = c.inbox_counts(uid).unwrap_or_else(|e| {
                            warn!(uid, "inbox counts unavailable: {e:?}; reporting zeros");
                            Default::default()
                        });
                        (m, counts)
                    })
                })
                .await;
                let Some(listed) = listed else {
                    return finish(ws_tx, reply_err(req.id, "server_error", "Server error.")).await;
                };
                match listed {
                    Ok((messages, counts)) => reply_ok(
                        req.id,
                        json!({
                            "messages": messages
                                .iter()
                                .map(stored_msg_json)
                                .collect::<Vec<_>>(),
                            "unread": counts.unread,
                            "total": counts.total,
                        }),
                    ),
                    Err(ChatError::ServerError) => {
                        reply_err(req.id, "server_error", "Server error.")
                    }
                    Err(_) => reply_err(req.id, "no_inbox", "This account has no inbox."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed inbox."),
        },

        // Blocking: a minimum viable fogWraith Block User (806), here
        // because account addressing means anyone can put mail in anyone's
        // queue and a queue has a cap. See docs/private-messages.md §9.
        "block" | "unblock" => match serde_json::from_value::<BlockParams>(req.params.clone()) {
            Ok(p) => {
                let on = req.req == "block";
                let me = state.uid;
                let named = [p.uid.is_some(), p.login.is_some(), p.fingerprint.is_some()]
                    .iter()
                    .filter(|x| **x)
                    .count();
                let fingerprint = p
                    .fingerprint
                    .as_deref()
                    .and_then(hl_identity::Fingerprint::parse);
                let done = match (p.uid, p.login.clone(), fingerprint) {
                    _ if named != 1 => {
                        return finish(
                            ws_tx,
                            reply_err(
                                req.id,
                                "bad_request",
                                "Name exactly one of `uid`, `login` and `fingerprint`.",
                            ),
                        )
                        .await
                    }
                    (Some(uid), _, _) => {
                        off_reactor(&ctx.core, move |c| c.inbox_block_uid(me, uid, on)).await
                    }
                    (_, Some(login), _) => {
                        off_reactor(&ctx.core, move |c| c.inbox_block(me, &login, on)).await
                    }
                    // A fingerprint names a block, not a person: the
                    // guest who left has no roster row and no login of
                    // their own, so `blocks` reports the fingerprint and
                    // `unblock` takes it back. Blocking still needs
                    // someone you can see.
                    (_, _, Some(fp)) if !on => {
                        off_reactor(&ctx.core, move |c| c.inbox_unblock_fingerprint(me, &fp.0))
                            .await
                    }
                    (_, _, Some(_)) => {
                        return finish(
                            ws_tx,
                            reply_err(
                                req.id,
                                "bad_request",
                                "Block by `uid` or `login`; `fingerprint` unblocks.",
                            ),
                        )
                        .await
                    }
                    (None, None, None) => {
                        return finish(
                            ws_tx,
                            reply_err(req.id, "bad_request", "Malformed fingerprint."),
                        )
                        .await
                    }
                };
                match done {
                    None | Some(Err(ChatError::ServerError)) => {
                        reply_err(req.id, "server_error", "Server error.")
                    }
                    Some(Ok(())) => reply_ok(req.id, json!({})),
                    // A session with no mailbox of its own has nowhere to
                    // keep a block, and that is a different thing from
                    // the target not existing — the same `no_inbox` the
                    // other inbox requests answer.
                    Some(Err(ChatError::NoInbox)) => {
                        reply_err(req.id, "no_inbox", "This account has no inbox.")
                    }
                    // Otherwise the same one answer msg_login gives, so
                    // this cannot be used to find out which accounts
                    // exist either.
                    Some(Err(_)) => reply_err(req.id, "no_such_user", "No such user."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed block."),
        },

        "blocks" => {
            let uid = state.uid;
            match off_reactor(&ctx.core, move |c| c.inbox_blocked(uid)).await {
                None | Some(Err(ChatError::ServerError)) => {
                    reply_err(req.id, "server_error", "Server error.")
                }
                Some(Ok(who)) => reply_ok(
                    req.id,
                    json!({
                        "blocked": who.iter().map(blocked_json).collect::<Vec<_>>(),
                    }),
                ),
                Some(Err(_)) => reply_err(req.id, "no_inbox", "This account has no inbox."),
            }
        }

        "msg_read" => match serde_json::from_value::<MsgReadParams>(req.params.clone()) {
            // A cursor in the caller's own mailbox: the domain scopes
            // it by account, so no `up_to` can mark another account's
            // mail read.
            Ok(p) => {
                let (uid, up_to) = (state.uid, p.up_to);
                match off_reactor(&ctx.core, move |c| c.inbox_mark_read(uid, up_to)).await {
                    None | Some(Err(ChatError::ServerError)) => {
                        reply_err(req.id, "server_error", "Server error.")
                    }
                    Some(Ok(counts)) => reply_ok(
                        req.id,
                        json!({ "unread": counts.unread, "total": counts.total }),
                    ),
                    Some(Err(_)) => reply_err(req.id, "no_inbox", "This account has no inbox."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed msg_read."),
        },

        // --- Voice (docs/voice.md §8) ---------------------------------
        //
        // The same six messages the legacy wire carries as 600–606. No
        // capability gate here: the ng handshake has no per-session
        // negotiation, and its `caps` list is a hint for feature
        // detection rather than a switch — a client that calls these on a
        // server without an SFU gets `voice_disabled` from the domain.
        "voice_join" => match serde_json::from_value::<VoiceRoomParams>(req.params.clone()) {
            Ok(_) if !state.access.has(bit::VOICE_CHAT) => reply_err(
                req.id,
                "access_denied",
                "You are not allowed to join voice chat.",
            ),
            Ok(p) => match ctx.core.voice_join(state.uid, p.cid) {
                Ok(join) => reply_ok(
                    req.id,
                    json!({
                        "cid": p.cid,
                        "sdp": join.sdp,
                        "codec": join.codec,
                        "participants": participants_json(&join.participants),
                    }),
                ),
                Err(e) => {
                    let (code, text) = voice_err(e);
                    reply_err(req.id, code, text)
                }
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed voice_join."),
        },

        "voice_leave" => match serde_json::from_value::<VoiceRoomParams>(req.params.clone()) {
            Ok(p) => match ctx.core.voice_leave(state.uid, p.cid) {
                Ok(()) => reply_ok(req.id, json!({})),
                Err(e) => {
                    let (code, text) = voice_err(e);
                    reply_err(req.id, code, text)
                }
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed voice_leave."),
        },

        "voice_answer" => match serde_json::from_value::<VoiceAnswerParams>(req.params.clone()) {
            Ok(p) => match ctx.core.voice_answer(state.uid, p.cid, p.sdp) {
                Ok(()) => reply_ok(req.id, json!({})),
                Err(e) => {
                    let (code, text) = voice_err(e);
                    reply_err(req.id, code, text)
                }
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed voice_answer."),
        },

        "voice_ice" => match serde_json::from_value::<VoiceIceParams>(req.params.clone()) {
            Ok(p) => {
                // `null` is end-of-candidates, which the domain carries
                // as a candidate with an empty string.
                let candidate = p.candidate.map(IceCandidate::from).unwrap_or_default();
                // Every request on this wire gets an answer, so a
                // candidate for a room the caller isn't in is refused
                // rather than acknowledged — `docs/voice.md` §8, and the
                // same shape as voice_leave, voice_answer and
                // voice_mute. The legacy wire, which has no reply here,
                // drops it instead.
                match ctx.core.voice_ice(state.uid, p.cid, candidate) {
                    Ok(()) => reply_ok(req.id, json!({})),
                    Err(e) => {
                        let (code, text) = voice_err(e);
                        reply_err(req.id, code, text)
                    }
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed voice_ice."),
        },

        "voice_mute" => match serde_json::from_value::<VoiceMuteParams>(req.params.clone()) {
            Ok(p) => match ctx.core.voice_mute(state.uid, p.cid, p.muted) {
                Ok(()) => reply_ok(req.id, json!({})),
                Err(e) => {
                    let (code, text) = voice_err(e);
                    reply_err(req.id, code, text)
                }
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed voice_mute."),
        },

        // --- Video (docs/capabilities-video.md §"Hotline-ng Binding") -
        //
        // Layered on voice exactly as on the classic wire: the same peer
        // connection, the same SFU, the same room, and `voice_offer` /
        // `voice_answer` / `voice_ice` carrying every SDP and ICE
        // exchange without changing shape. No capability gate, for the
        // same reason voice has none here.
        "video_start" => match serde_json::from_value::<VideoStartParams>(req.params.clone()) {
            Ok(p) => match VideoKind::from_name(&p.kind) {
                None => reply_err(req.id, "bad_request", "Unknown video stream kind."),
                // Camera and screen are separate trust decisions; neither
                // bit implies the other.
                Some(kind)
                    if !state.access.has(match kind {
                        VideoKind::Camera => bit::VIDEO_CHAT,
                        VideoKind::Screen => bit::SCREEN_SHARE,
                    }) =>
                {
                    reply_err(
                        req.id,
                        "access_denied",
                        match kind {
                            VideoKind::Camera => "You are not allowed to share video.",
                            VideoKind::Screen => "You are not allowed to share your screen.",
                        },
                    )
                }
                Some(kind) => match ctx.core.video_start(state.uid, p.cid, kind) {
                    // No SDP in the reply: the offer follows as a
                    // `voice_offer` when serialisation allows, and a
                    // client must not wait for it to consider the start
                    // to have succeeded.
                    Ok(codec) => reply_ok(req.id, json!({ "codec": codec })),
                    Err(e) => {
                        let (code, text) = video_err(e);
                        reply_err(req.id, code, text)
                    }
                },
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed video_start."),
        },

        "video_stop" => match serde_json::from_value::<VideoStopParams>(req.params.clone()) {
            // An absent kind stops everything this session is publishing
            // in the room; a kind we don't know is a mistake rather than
            // a wildcard, so it must not fall through to the wildcard.
            Ok(p)
                if p.kind
                    .as_deref()
                    .is_some_and(|k| VideoKind::from_name(k).is_none()) =>
            {
                reply_err(req.id, "bad_request", "Unknown video stream kind.")
            }
            Ok(p) => {
                let kind = p.kind.as_deref().and_then(VideoKind::from_name);
                match ctx.core.video_stop(state.uid, p.cid, kind) {
                    Ok(()) => reply_ok(req.id, json!({})),
                    Err(e) => {
                        let (code, text) = video_err(e);
                        reply_err(req.id, code, text)
                    }
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed video_stop."),
        },

        "video_state" => match serde_json::from_value::<VideoStateParams>(req.params.clone()) {
            Ok(p) => match VideoKind::from_name(&p.kind) {
                None => reply_err(req.id, "bad_request", "Unknown video stream kind."),
                Some(kind) => match ctx.core.video_state(state.uid, p.cid, kind, p.paused) {
                    Ok(()) => reply_ok(req.id, json!({})),
                    Err(e) => {
                        let (code, text) = video_err(e);
                        reply_err(req.id, code, text)
                    }
                },
            },
            Err(_) => reply_err(req.id, "bad_request", "Malformed video_state."),
        },

        "video_subscribe" => {
            match serde_json::from_value::<VideoSubscribeParams>(req.params.clone()) {
                // Receiving needs no privilege bit beyond being in the
                // room; the bits govern publishing. An absent or empty
                // array is "no video at all", which is where every
                // session starts.
                Ok(p) => {
                    let streams = parse_streams(&p.streams);
                    match ctx.core.video_subscribe(state.uid, p.cid, &streams) {
                        Ok(()) => reply_ok(req.id, json!({})),
                        Err(e) => {
                            let (code, text) = video_err(e);
                            reply_err(req.id, code, text)
                        }
                    }
                }
                Err(_) => reply_err(req.id, "bad_request", "Malformed video_subscribe."),
            }
        }

        "logout" => {
            ctx.core.end_session(state.uid);
            ctx.registry.remove(&state.session_id);
            // `LoggedOut`, not `Dead`, if the acknowledgement does not go
            // out: the session is over either way, and `Dead` routes the
            // exit through `connection_lost` on a uid `end_session` has
            // just released — a call that means nothing here and, if the
            // uid had been handed to someone else in the meantime, would
            // mean it about them.
            if !send_frame(ws_tx, send(reply_ok(req.id, json!({})))).await {
                return Flow::LoggedOut;
            }
            let _ = send_frame(
                ws_tx,
                Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "logout".into(),
                })),
            )
            .await;
            return Flow::LoggedOut;
        }

        "login" | "resume" => reply_err(req.id, "bad_request", "Already logged in."),

        _ => reply_err(req.id, "unknown_method", "Unknown request."),
    };
    finish(ws_tx, out).await
}

/// What a nick may weigh, in *characters*. The legacy wire's field is 31
/// bytes of Mac Roman and every character converts to exactly one of
/// those (or to `?`), so 31 characters is that same bound one step
/// earlier — a truncation the ng client can see coming rather than one
/// that happens on the way out to a 1.x client.
///
/// Counting UTF-8 bytes here instead cut a 28-character accented nick
/// that a 1.x client would have carried whole, and cut it for every
/// viewer including the ng ones.
const NICK_MAX_CHARS: usize = 31;

/// `String::truncate` panics off char boundaries; caps shouldn't.
trait TruncateToCharBoundary {
    /// Truncate to at most `max` *bytes*, at a character boundary.
    fn truncate_to_char_boundary(&mut self, max: usize);
    /// Truncate to at most `max` *characters*.
    fn truncate_to_chars(&mut self, max: usize);
}

impl TruncateToCharBoundary for String {
    fn truncate_to_char_boundary(&mut self, max: usize) {
        if self.len() <= max {
            return;
        }
        let mut end = max;
        while end > 0 && !self.is_char_boundary(end) {
            end -= 1;
        }
        self.truncate(end);
    }

    fn truncate_to_chars(&mut self, max: usize) {
        if let Some((end, _)) = self.char_indices().nth(max) {
            self.truncate(end);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nick_is_bounded_in_characters_not_utf8_bytes() {
        // 28 accented characters: 56 UTF-8 bytes, 28 Mac Roman bytes.
        // The wire's field holds it whole, so the ng side must not cut
        // it — which counting bytes did, for every viewer at once.
        let mut nick = "é".repeat(28);
        nick.truncate_to_chars(NICK_MAX_CHARS);
        assert_eq!(nick.chars().count(), 28);

        // And a nick that really is too long is cut to the bound.
        let mut nick = "é".repeat(40);
        nick.truncate_to_chars(NICK_MAX_CHARS);
        assert_eq!(nick.chars().count(), NICK_MAX_CHARS);

        // The byte-counting form is still what chat text uses.
        let mut text = "é".repeat(10);
        text.truncate_to_char_boundary(5);
        assert_eq!(text, "éé");
    }
}
