//! Sealed private messages on the ng wire (`docs/e2e-messages.md`
//! §4.1–§4.5): `sealed` at login and resume, `device_cert`, and `msg`
//! carrying a box. The server checks what the wire shows, a box's size,
//! its leading byte and a deniable box's sender key, and never what it
//! holds, which it has no key to read.

use hl_identity::sealed::{check_len, sender_enc};
use hxd_core::{SealedDevice, SealedError};
use serde::Deserialize;
use serde_json::json;

use crate::conn::{off_reactor, retry_secs, SessState};
use crate::proto::{b64url, reply_err, reply_err_retry, reply_ok, MsgParams};
use crate::push::DeviceOnSocket;
use crate::NgCtx;

/// What a session that said `sealed` can open them with: the device it
/// proved, if its certificate allows it (§4.1).
pub(crate) fn device(device: Option<&DeviceOnSocket>, asked: bool) -> Option<SealedDevice> {
    device.filter(|_| asked)?.sealable.clone()
}

fn refused(id: u64, e: SealedError) -> String {
    match e {
        SealedError::SelfNotSealed => reply_err(
            id,
            "not_sealed",
            "This session did not say it can open sealed messages.",
        ),
        SealedError::NotSealed => {
            reply_err(id, "not_sealed", "That user cannot open sealed messages.")
        }
        SealedError::CertChanged => reply_err(
            id,
            "cert_changed",
            "That user's device key has changed; fetch its certificate and seal again.",
        ),
        SealedError::NoSuchUser => reply_err(id, "no_such_user", "No such user."),
        SealedError::Blocked => reply_err(
            id,
            "blocked",
            "That user is not accepting messages from you.",
        ),
        SealedError::HeldFull => reply_err(
            id,
            "mailbox_full",
            "That user is holding as many sealed messages as it may.",
        ),
        SealedError::RateLimited(wait) => reply_err_retry(
            id,
            "rate_limited",
            "You have asked for many certificates lately.",
            retry_secs(wait),
        ),
        SealedError::ServerError => reply_err(id, "server_error", "Server error."),
    }
}

/// Nothing sealed crosses a link yet (§5), so no ghost can be one to
/// seal to.
fn across_link(id: u64) -> String {
    reply_err(
        id,
        "not_sealed",
        "Sealed messages do not cross links to other servers yet.",
    )
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

#[derive(Deserialize)]
struct DeviceCertParams {
    uid: u16,
}

/// `device_cert` (§4.2).
pub(crate) async fn device_cert(
    ctx: &NgCtx,
    state: &SessState,
    id: u64,
    params: &serde_json::Value,
) -> String {
    let Ok(p) = serde_json::from_value::<DeviceCertParams>(params.clone()) else {
        return reply_err(id, "bad_request", "Malformed device_cert.");
    };
    if ctx.core.is_ghost(p.uid) {
        return across_link(id);
    }
    let asker = state.uid;
    match off_reactor(&ctx.core, move |c| c.device_cert(asker, p.uid)).await {
        Some(Ok(cert)) => reply_ok(id, json!({ "cert": b64url(&cert) })),
        Some(Err(e)) => refused(id, e),
        None => reply_err(id, "server_error", "Server error."),
    }
}

/// `msg` with `sealed` (§4.3): to one session, never stored, so always
/// `queued: false`.
pub(crate) async fn msg(ctx: &NgCtx, state: &SessState, id: u64, p: MsgParams) -> String {
    let bad = |text: &str| reply_err(id, "bad_request", text);
    let (Some(sealed), Some(cert)) = (p.sealed, p.cert) else {
        return bad("`sealed` and `cert` go together.");
    };
    if p.to_login.is_some()
        || p.text.is_some()
        || p.signed.is_some()
        || p.media.is_some()
        || p.guid.is_some()
    {
        return bad("A sealed message carries `to`, `sealed` and `cert` alone.");
    }
    let Some(to) = p.to else {
        return bad("A sealed message is to a session, by `to`.");
    };
    let Some(sealed) =
        unb64(&sealed).filter(|b| b.first().is_some_and(|f| check_len(*f, b.len()).is_ok()))
    else {
        return bad("`sealed` is not a sealed message of one of its sizes.");
    };
    let Some(sealed_to) = unb64(&cert).and_then(|c| <[u8; 32]>::try_from(c).ok()) else {
        return bad("`cert` is the SHA-256 of a `device_enc` key.");
    };
    if let Some(pk_s) = sender_enc(&sealed) {
        let own = state
            .device
            .as_ref()
            .and_then(|d| d.sealable.as_ref())
            .map(|d| d.enc);
        if own != Some(pk_s) {
            return bad("A deniable box is sealed under this session's own `device_enc` key.");
        }
    }
    if ctx.core.is_ghost(to) {
        return across_link(id);
    }
    let from = state.uid;
    match off_reactor(&ctx.core, move |c| {
        c.msg_sealed(from, to, sealed, sealed_to)
    })
    .await
    {
        Some(Ok(())) => reply_ok(id, json!({ "queued": false })),
        // The sender's own session not saying `sealed` is its client's
        // bug, not news about the target (§4.3).
        Some(Err(SealedError::SelfNotSealed)) => {
            bad("This session did not say it can open sealed messages.")
        }
        Some(Err(e)) => refused(id, e),
        None => reply_err(id, "server_error", "Server error."),
    }
}
