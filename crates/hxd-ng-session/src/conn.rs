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
use hxd_core::video::VideoKind;
use hxd_core::voice::IceCandidate;
use hxd_core::{AccessBits, AttachInfo, AuthError, Proof, Resume, SeqEvent, Uid};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use crate::proto::{
    event_json, parse_streams, participants_json, reply_err, reply_ok, user_json, video_err,
    video_limits_json, voice_err, ChatParams, LoginParams, MsgParams, NickParams, ReqEnvelope,
    ResumeParams, VideoStartParams, VideoStateParams, VideoStopParams, VideoSubscribeParams,
    VoiceAnswerParams, VoiceIceParams, VoiceMuteParams, VoiceRoomParams,
};
use crate::NgCtx;

type Ws = WebSocketStream<TcpStream>;

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

pub(crate) async fn run(stream: TcpStream, peer: SocketAddr, ctx: NgCtx) {
    if ctx.core.is_banned(peer.ip()) {
        info!("refusing banned address");
        return;
    }
    let config = WebSocketConfig {
        max_message_size: Some(256 * 1024),
        max_frame_size: Some(256 * 1024),
        ..Default::default()
    };
    let ws = match timeout(
        ctx.cfg.login_timeout,
        tokio_tungstenite::accept_async_with_config(stream, Some(config)),
    )
    .await
    {
        Ok(Ok(ws)) => ws,
        _ => return,
    };
    let (mut ws_tx, mut ws_rx) = ws.split();

    // --- Handshake: the first request must be login or resume. ----------
    let first = match timeout(ctx.cfg.login_timeout, next_request(&mut ws_rx)).await {
        Ok(Some(req)) => req,
        _ => return,
    };

    let (state, mut events) = match first.req.as_str() {
        "login" => match handle_login(&ctx, peer, &first, &mut ws_tx).await {
            Some(v) => v,
            None => return,
        },
        "resume" => match handle_resume(&ctx, &first, &mut ws_tx).await {
            Some(v) => v,
            None => return,
        },
        _ => {
            let _ = ws_tx
                .send(Message::Text(reply_err(
                    first.id,
                    "not_logged_in",
                    "Log in or resume first.",
                )))
                .await;
            return;
        }
    };
    info!(uid = state.uid, session = %state.session_id, "ng session attached");

    // --- Main loop -------------------------------------------------------
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // Consume the immediate first tick.

    let exit = loop {
        tokio::select! {
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    let Ok(req) = serde_json::from_str::<ReqEnvelope>(&text) else {
                        debug!("unparseable request frame");
                        break Exit::ConnectionLost;
                    };
                    match dispatch(&ctx, &state, &req, &mut ws_tx).await {
                        Flow::Continue => {}
                        Flow::LoggedOut => break Exit::SessionOver,
                        Flow::Dead => break Exit::ConnectionLost,
                    }
                }
                Some(Ok(Message::Close(_))) | None => break Exit::ConnectionLost,
                Some(Ok(_)) => {} // ping/pong/binary — ignored
                Some(Err(e)) => {
                    debug!("ws error: {e}");
                    break Exit::ConnectionLost;
                }
            },
            ev = events.recv() => match ev {
                Some(se) => {
                    let kicked = matches!(se.event, hxd_core::Event::Kicked);
                    if ws_tx.send(Message::Text(event_json(&se))).await.is_err() {
                        break Exit::ConnectionLost;
                    }
                    if kicked {
                        ctx.core.end_session(state.uid);
                        ctx.registry.remove(&state.session_id);
                        let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: "kicked".into(),
                        }))).await;
                        break Exit::SessionOver;
                    }
                }
                None => break Exit::Replaced,
            },
            _ = ping.tick() => {
                if ws_tx.send(Message::Ping(Vec::new())).await.is_err() {
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
            let _ = ws_tx
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "replaced".into(),
                })))
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

async fn handle_login(
    ctx: &NgCtx,
    peer: SocketAddr,
    req: &ReqEnvelope,
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
                let _ = ws_tx
                    .send(Message::Text(reply_err(
                        req.id,
                        "bad_request",
                        "Malformed login.",
                    )))
                    .await;
                return None;
            }
        }
    };

    let auth = ctx.auth.clone();
    let (login, password) = (p.login.clone(), p.password.clone());
    let verdict = tokio::task::spawn_blocking(move || {
        auth.authenticate(&login, Proof::Plain(password.as_bytes()))
    })
    .await
    .ok()?;

    let account = match verdict {
        Ok(a) => a,
        Err(e @ (AuthError::NoSuchAccount | AuthError::BadProof)) => {
            info!(login = %p.login, "ng login refused: {e}");
            let _ = ws_tx
                .send(Message::Text(reply_err(
                    req.id,
                    "login_failed",
                    "Login failed.",
                )))
                .await;
            return None;
        }
        Err(AuthError::Backend(e)) => {
            warn!("auth backend failure: {e}");
            let _ = ws_tx
                .send(Message::Text(reply_err(
                    req.id,
                    "server_error",
                    "Server error.",
                )))
                .await;
            return None;
        }
    };

    let nick = match (&p.nick, account.access.has(bit::USE_ANY_NAME)) {
        (Some(n), true) if !n.is_empty() => n.clone(),
        _ => account.name.clone(),
    };
    let attach = AttachInfo {
        nick,
        icon: p.icon.unwrap_or(128),
        admin: account.access.has(bit::DISCONNECT_USERS),
        access: account.access,
        login: account.login.clone(),
        addr: Some(peer.ip()),
        can_detach: account.can_detach,
    };
    let Some((uid, events)) = ctx.core.attach(attach) else {
        let _ = ws_tx
            .send(Message::Text(reply_err(
                req.id,
                "server_full",
                "Server full.",
            )))
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
    let mut ok = json!({
        "session": session_id,
        "token": token,
        "self": user_json(&me),
        "server": server,
        "users": users,
        "detach": detach,
        // Always present, empty when this build offers no extensions:
        // absent and empty mean the same thing, and one shape is one
        // less case for a client to get wrong.
        "caps": ctx.cfg.caps,
        "seq": 0,
    });
    // The ceilings, so a client configures its encoders before the first
    // join rather than discovering them by rejection. Present only when
    // video is — `"video"` never appears in `caps` without `"voice"`,
    // and this object never appears without `"video"`.
    if ctx.core.video_enabled() {
        ok["video"] = video_limits_json(&ctx.core.video_config());
    }
    if ws_tx
        .send(Message::Text(reply_ok(req.id, ok)))
        .await
        .is_err()
    {
        // The client never learned it was logged in; a ghost session with
        // no transport (and a leaked token) must not linger.
        ctx.core.end_session(uid);
        ctx.registry.remove(&session_id);
        return None;
    }
    info!(uid, login = %account.login, "ng logged in");

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
        let _ = ws_tx
            .send(Message::Text(reply_err(
                req.id,
                "bad_request",
                "Malformed resume.",
            )))
            .await;
        return None;
    };
    let Some(uid) = ctx.registry.validate(&ctx.core, &p.session, &p.token) else {
        let _ = ws_tx
            .send(Message::Text(reply_err(
                req.id,
                "session_expired",
                "Session expired; log in again.",
            )))
            .await;
        return None;
    };

    let (events, replay) = match ctx.core.resume(uid, p.last_seq) {
        Resume::Replayed(rx, replay) => (rx, Some(replay)),
        Resume::ResyncRequired(rx) => (rx, None),
        Resume::Gone => {
            ctx.registry.remove(&p.session);
            let _ = ws_tx
                .send(Message::Text(reply_err(
                    req.id,
                    "session_expired",
                    "Session expired; log in again.",
                )))
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
            if ws_tx
                .send(Message::Text(reply_ok(req.id, ok)))
                .await
                .is_err()
            {
                lost(ctx);
                return None;
            }
            for se in &replay {
                if ws_tx.send(Message::Text(event_json(se))).await.is_err() {
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
            if ws_tx.send(Message::Text(err)).await.is_err() {
                lost(ctx);
                return None;
            }
            info!(uid, "ng resumed with resync required");
        }
    }
    Some((state, events))
}

enum Flow {
    Continue,
    LoggedOut,
    Dead,
}

async fn dispatch(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope, ws_tx: &mut WsTx) -> Flow {
    let send = |s: String| Message::Text(s);
    let out = match req.req.as_str() {
        "ping" => reply_ok(req.id, json!({})),

        "sync" => {
            let users: Vec<_> = ctx.core.snapshot().iter().map(user_json).collect();
            reply_ok(
                req.id,
                json!({
                    "server": {
                        "name": ctx.cfg.server_name,
                        "subject": ctx.core.public_subject(),
                    },
                    "users": users,
                    "seq": ctx.core.current_seq(state.uid).unwrap_or(0),
                }),
            )
        }

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
                ctx.core.chat_public(state.uid, text, style);
                reply_ok(req.id, json!({}))
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed chat."),
        },

        "nick" => match serde_json::from_value::<NickParams>(req.params.clone()) {
            Ok(p) => {
                let nick = p
                    .nick
                    .filter(|_| state.access.has(bit::USE_ANY_NAME))
                    .filter(|n| !n.is_empty());
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
                match ctx.core.msg(state.uid, p.to, text) {
                    Ok(()) => reply_ok(req.id, json!({})),
                    Err(_) => reply_err(req.id, "bad_request", "That user is not connected."),
                }
            }
            Err(_) => reply_err(req.id, "bad_request", "Malformed msg."),
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
            let _ = ws_tx.send(send(reply_ok(req.id, json!({})))).await;
            let _ = ws_tx
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "logout".into(),
                })))
                .await;
            return Flow::LoggedOut;
        }

        "login" | "resume" => reply_err(req.id, "bad_request", "Already logged in."),

        _ => reply_err(req.id, "unknown_method", "Unknown request."),
    };
    if ws_tx.send(send(out)).await.is_err() {
        return Flow::Dead;
    }
    Flow::Continue
}

/// `String::truncate` panics off char boundaries; chat caps shouldn't.
trait TruncateToCharBoundary {
    fn truncate_to_char_boundary(&mut self, max: usize);
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
}
