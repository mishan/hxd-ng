//! Device registration on the ng wire (`docs/webpush-gateway.md` §7,
//! push-notifications.md §8).
//!
//! Two requests, and the login reply's `push` block. Everything about
//! *where* a push goes is the gateway's and everything about *whose* it
//! is is the domain's; what is decided here is the one thing neither can
//! see, which is what this socket's device certificate says it may do.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hxd_core::push::{DeviceId, PushError, Registration};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, SessState};
use crate::proto::{reply_err, reply_ok, ReqEnvelope};
use crate::NgCtx;

/// What the server tells a client about push at login: the key to
/// subscribe against, what kinds of registration it takes, and how much
/// of a message will leave the server. Built by the binary, which is
/// where the gateway is.
#[derive(Debug, Clone)]
pub struct PushInfo {
    /// The server's VAPID public key, base64url.
    pub vapid: String,
    /// `"full"`, `"sender"` or `"generic"`, so a client can tell its
    /// user what they are agreeing to before it asks the browser.
    pub content: String,
}

/// The `push` block, for a session that has a mailbox to push about. A
/// guest is never offered it, as news offers `subscribe` only to an
/// account.
pub fn login_json(ctx: &NgCtx, has_inbox: bool) -> Option<Value> {
    let info = ctx.push.as_ref()?;
    has_inbox.then(|| {
        json!({
            "vapid": info.vapid,
            // What `push_register` accepts here (push-notifications.md
            // §8.1): `unifiedpush` is Web Push under another name on the
            // client's side of the distributor, and both are taken.
            "types": ["webpush", "unifiedpush"],
            "content": info.content,
        })
    })
}

#[derive(Deserialize)]
struct RegisterParams {
    #[serde(rename = "type")]
    kind: Option<String>,
    endpoint: String,
    p256dh: String,
    auth: String,
    devid: Option<String>,
}

#[derive(Deserialize, Default)]
struct UnregisterParams {
    devid: Option<String>,
    #[serde(default)]
    all: bool,
}

pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    match req.req.as_str() {
        "push_register" => register(ctx, state, req).await,
        "push_unregister" => unregister(ctx, state, req).await,
        _ => reply_err(req.id, "bad_request", "No such request."),
    }
}

async fn register(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let bad = |text: &str| reply_err(req.id, "bad_request", text);
    if ctx.push.is_none() {
        return not_available(req.id);
    }
    let Ok(p) = serde_json::from_value::<RegisterParams>(req.params.clone()) else {
        return bad("Malformed registration.");
    };
    // Only Web Push, and `unifiedpush` is Web Push with another name on
    // the client's side of the distributor. A vendor type would need
    // credentials this server has none of and cannot be given
    // (push-notifications.md §8.2), so it is refused rather than stored
    // and never used.
    match p.kind.as_deref() {
        None | Some("webpush") | Some("unifiedpush") => {}
        Some(_) => return bad("This server sends Web Push."),
    }
    let (Some(p256dh), Some(auth)) = (key::<65>(&p.p256dh), key::<16>(&p.auth)) else {
        return bad("That subscription's keys are not a subscription's keys.");
    };
    // The device names itself where it can (push-notifications.md §5.1):
    // on an identity session the certificate's fingerprint is the id,
    // and a client-supplied one is ignored rather than refused, because
    // a client that sends one is not doing anything wrong.
    let (devid, expires) = match state.device.as_ref() {
        Some(device) => {
            if !device.may_message {
                return reply_err(
                    req.id,
                    "no_capability",
                    "This device's certificate is not trusted with messages.",
                );
            }
            (device.devid.clone(), device.expires)
        }
        None => match p.devid.as_deref().map(DeviceId::parse) {
            // Spelled like a device fingerprint is an identity device's
            // id, and only its own certificate names it. A password
            // login on a linked account shares that mailbox, and taking
            // the phone's row would replace its endpoint and strip the
            // expiry that stops a lost phone buzzing
            // (`docs/webpush-gateway.md` §7).
            Some(Some(devid)) if devid.is_device_fingerprint() => {
                return bad("That device id belongs to an identity device.")
            }
            Some(Some(devid)) => (devid, None),
            Some(None) => return bad("That is not a device id."),
            None => return bad("A device id is required on a password session."),
        },
    };
    let registration = Registration {
        devid: devid.clone(),
        endpoint: p.endpoint,
        p256dh,
        auth,
        expires,
    };
    let uid = state.uid;
    match off_reactor(&ctx.core, move |c| c.push_register(uid, registration)).await {
        Some(Ok(_)) => reply_ok(req.id, json!({ "devid": devid.as_str() })),
        Some(Err(e)) => refused(req.id, e),
        None => reply_err(req.id, "server_error", "Server error."),
    }
}

async fn unregister(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    if ctx.push.is_none() {
        return not_available(req.id);
    }
    let params = if req.params.is_null() {
        Ok(UnregisterParams::default())
    } else {
        serde_json::from_value::<UnregisterParams>(req.params.clone())
    };
    let Ok(p) = params else {
        return reply_err(req.id, "bad_request", "Malformed request.");
    };
    // Omitting `devid` means *this* device, never every device: the
    // request a client sends most is "turn notifications off here", and
    // it must not be one missing field away from silencing every device
    // the account owns. Logging out everywhere is `all: true`, said on
    // purpose (push-notifications.md §8).
    let asked = match p.devid.as_deref().map(DeviceId::parse) {
        Some(None) => return reply_err(req.id, "bad_request", "That is not a device id."),
        Some(Some(devid)) => Some(devid),
        None => None,
    };
    let mine = state.device.as_ref().map(|d| d.devid.clone());
    let target = match (p.all, asked) {
        (true, _) => None,
        (false, Some(devid)) => Some(devid),
        (false, None) => match mine {
            Some(devid) => Some(devid),
            None => {
                return reply_err(
                    req.id,
                    "bad_request",
                    "Name the device to forget, or ask for `all`.",
                )
            }
        },
    };
    // Another device, or all of them, is account management, and a web
    // client's certificate that omits `manage` may turn its own
    // notifications off and not silence the owner's phone (§5.1 there).
    let someone_elses = target.as_ref() != state.device.as_ref().map(|d| &d.devid);
    if someone_elses {
        if let Some(device) = state.device.as_ref() {
            if !device.may_manage {
                return reply_err(
                    req.id,
                    "no_capability",
                    "This device may not manage the account's other devices.",
                );
            }
        }
    }
    let uid = state.uid;
    match off_reactor(&ctx.core, move |c| c.push_unregister(uid, target)).await {
        Some(Ok(())) => reply_ok(req.id, json!({})),
        Some(Err(e)) => refused(req.id, e),
        None => reply_err(req.id, "server_error", "Server error."),
    }
}

fn not_available(id: u64) -> String {
    reply_err(id, "not_available", "This server sends no notifications.")
}

fn refused(id: u64, e: PushError) -> String {
    let (code, text) = match e {
        PushError::NotAvailable => ("not_available", "This server sends no notifications."),
        PushError::NoMailbox => (
            "no_mailbox",
            "A guest has no mailbox, so there is nothing to be notified about.",
        ),
        PushError::NoSession => ("server_error", "Server error."),
        PushError::BadSubscription(text) => ("bad_request", text),
        PushError::TooManyDevices => (
            "too_many_devices",
            "This account has as many devices as it may; unregister one first.",
        ),
        PushError::StoreFailed => ("server_error", "Server error."),
    };
    reply_err(id, code, text)
}

/// A base64url subscription key of exactly `N` bytes. Exactly, because
/// these are fixed-width by construction and something else is not a
/// short key but a different kind of value.
fn key<const N: usize>(s: &str) -> Option<[u8; N]> {
    B64.decode(s)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(s).ok())?
        .try_into()
        .ok()
}

/// What the session's device certificate says, for the two requests that
/// are about a device rather than an account. Taken at login and kept
/// with the session (`crate::registry`), so a resume cannot change it.
#[derive(Debug, Clone)]
pub struct DeviceOnSocket {
    pub(crate) devid: DeviceId,
    /// A push is a message delivered to this device, so registering
    /// needs the certificate's `message` bit.
    pub(crate) may_message: bool,
    /// Unregistering another device is account management.
    pub(crate) may_manage: bool,
    pub(crate) expires: Option<SystemTime>,
}

impl DeviceOnSocket {
    pub(crate) fn of(identity: &crate::identity::TransportIdentity) -> Self {
        DeviceOnSocket {
            devid: DeviceId::of_device(&hl_identity::Fingerprint::of(&identity.device).0),
            may_message: identity.allows(hl_identity::caps::MESSAGE),
            may_manage: identity.allows(hl_identity::caps::MANAGE),
            expires: UNIX_EPOCH.checked_add(Duration::from_secs(identity.device_expires)),
        }
    }
}
