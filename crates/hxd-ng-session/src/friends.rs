//! The friend family on the ng wire (`docs/hotline-ng.md` §7.5): its
//! requests, its login block, and the objects its events carry.
//!
//! A translation, as rooms' is: who may ask whom, what a request becomes
//! and which sessions are told are `hxd_core::messaging`'s.

use std::time::{Duration, SystemTime};

use hxd_core::inbox::{Mailbox, MessageGuid};
use hxd_core::messaging::{
    Cleared, Fetched, PresentResult, Presented, RequestAction, RequestsListing,
};
use hxd_core::relationships::Profile;
use hxd_core::{
    Core, FoundUser, FriendEntry, Im, MessagingError, OwnPresence, Presence, PresenceUpdate,
};
use hxd_core::{RosterState, Uid};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use tracing::warn;

use crate::conn::{off_reactor, SessState, TruncateToCharBoundary, NICK_MAX_CHARS};
use crate::proto::{b64url, reply_err, reply_ok, unix, ReqEnvelope};
use crate::NgCtx;

/// A status text is told to every friend, so it is held to the subject's
/// bound (§8).
const STATUS_MAX_CHARS: usize = 255;

/// A note is held to a private message's bound (§8).
const NOTE_MAX_BYTES: usize = 4096;

pub(crate) fn handles(req: &str) -> bool {
    matches!(
        req,
        "friends"
            | "friend_add"
            | "friend_respond"
            | "friend_remove"
            | "friend_alias"
            | "presence"
            | "find_user"
            | "user_profile"
            | "receipt"
            | "typing"
            | "requests"
            | "request_answer"
            | "requests_clear"
            | "friendships_present"
            | "friendships_fetch"
    )
}

/// What the friendship objects a request carries add to its price
/// (`docs/hotline-ng.md` §7.5): each costs the signatures it is checked
/// with, and a presentation or a fetch is paced an object at a time.
pub(crate) fn object_weight(req: &ReqEnvelope) -> u32 {
    let p = &req.params;
    let n = |key: &str| {
        p.get(key)
            .and_then(Value::as_array)
            .map_or(0, |a| u32::try_from(a.len()).unwrap_or(u32::MAX))
    };
    let has = |key: &str| u32::from(p.get(key).is_some());
    match req.req.as_str() {
        "friendships_present" => {
            4u32.saturating_mul(n("friendships").saturating_add(n("withdrawals")))
        }
        "friendships_fetch" => n("hashes").saturating_add(n("fingerprints")),
        "friend_add" | "friend_remove" | "block" => 2 * (has("offer") + has("withdraw")),
        "friend_respond" => 4 * has("friendship"),
        _ => 0,
    }
}

/// The login and sync replies' `messaging` (§7.5), where the server has
/// it: a store read, so called off the reactor.
pub(crate) fn login_json(core: &Core, uid: Uid) -> Option<Value> {
    if !core.messaging_enabled() {
        return None;
    }
    let p = core.messaging_policy();
    let takes_part = core.takes_part(uid);
    let mut v = json!({
        "takes_part": takes_part,
        "max_roster": p.max_roster,
        "max_message_bytes": p.max_message_bytes,
        "request_messages": p.request_messages,
    });
    if !takes_part {
        return Some(v);
    }
    // A store that will not answer leaves what a new login starts with,
    // since the block's fields are promised wherever it takes part.
    let own = core.own_presence(uid).unwrap_or_else(|e| {
        warn!(uid, "messaging: reading the account's own presence: {e:?}");
        OwnPresence {
            state: Presence::Online,
            status_text: None,
            discoverable: false,
            takes_requests: false,
        }
    });
    v["state"] = json!(presence_name(own.state));
    if let Some(text) = own.status_text {
        v["status_text"] = json!(text);
    }
    v["discoverable"] = json!(own.discoverable);
    v["takes_requests"] = json!(own.takes_requests);
    Some(v)
}

fn fingerprint(fp: &[u8; 32]) -> String {
    hl_identity::Fingerprint(*fp).to_string()
}

/// `{ login, fingerprint? }`, the way every object here names an account.
pub(crate) fn named(login: &str, fp: Option<&[u8; 32]>) -> Value {
    let mut v = json!({ "login": login });
    if let Some(fp) = fp {
        v["fingerprint"] = json!(fingerprint(fp));
    }
    v
}

fn mailbox_json(m: &Mailbox) -> Value {
    named(&m.login, m.fingerprint.as_ref())
}

fn state_name(s: RosterState) -> &'static str {
    match s {
        RosterState::Removed => "removed",
        RosterState::PendingOut => "pending_out",
        RosterState::PendingIn => "pending_in",
        RosterState::Accepted => "accepted",
        RosterState::Blocked => "blocked",
    }
}

/// `invisible` only ever reaches the account itself: the domain tells
/// its friends it is offline.
fn presence_name(p: Presence) -> &'static str {
    match p {
        Presence::Offline => "offline",
        Presence::Invisible => "invisible",
        Presence::Online => "online",
        Presence::Away => "away",
        Presence::Busy => "busy",
    }
}

pub(crate) fn friend_json(e: &FriendEntry) -> Value {
    let mut v = named(&e.login, e.fingerprint.as_ref());
    v["state"] = json!(state_name(e.state));
    if let Some(alias) = &e.alias {
        v["alias"] = json!(alias);
    }
    if e.state == RosterState::Accepted {
        v["presence"] = json!(presence_name(e.presence));
        if let Some(text) = &e.status_text {
            v["status_text"] = json!(text);
        }
    }
    if let Some(note) = e
        .note
        .as_ref()
        .filter(|_| e.state == RosterState::PendingIn)
    {
        v["note"] = json!(note);
    }
    // The domain fills these in for a friendships session alone.
    if !e.friendships.is_empty() {
        v["friendships"] = json!(e.friendships.iter().map(|h| b64url(h)).collect::<Vec<_>>());
    }
    if let Some(offer) = &e.offer {
        v["offer"] = json!(b64url(offer));
    }
    if let Some(withdraw) = &e.withdraw {
        v["withdraw"] = json!(b64url(withdraw));
    }
    v
}

pub(crate) fn presence_json(
    login: &str,
    fp: Option<&[u8; 32]>,
    state: Presence,
    status_text: Option<&str>,
) -> Value {
    let mut v = named(login, fp);
    v["state"] = json!(presence_name(state));
    if let Some(text) = status_text {
        v["status_text"] = json!(text);
    }
    v
}

pub(crate) fn im_json(m: &Im) -> Value {
    let mut from = named(&m.from_login, m.from_fingerprint.as_ref());
    from["nick"] = json!(m.from_nick);
    let mut v = json!({
        "from": from,
        "text": m.text,
        "at": unix(m.sent_at),
        "guid": m.guid.as_str(),
        "queued": m.queued,
    });
    if let Some(id) = m.id {
        v["id"] = json!(id);
    }
    if let Some(signed) = &m.signed {
        v["signed"] = json!(b64url(signed));
    }
    if m.approval {
        v["approval"] = json!(true);
    }
    v
}

fn profile_json(p: &Profile) -> Value {
    let mut v = json!({ "languages": p.languages });
    for (key, field) in [
        ("nickname", &p.nickname),
        ("first_name", &p.first_name),
        ("last_name", &p.last_name),
        ("email", &p.email),
        ("country", &p.country),
        ("postcode", &p.postcode),
    ] {
        if let Some(s) = field {
            v[key] = json!(s);
        }
    }
    if p.gender != 0 {
        v["gender"] = json!(p.gender);
    }
    let b = p.birthdate;
    if b.year != 0 || b.month != 0 || b.day != 0 {
        let mut d = json!({});
        for (key, n) in [
            ("year", b.year),
            ("month", b.month.into()),
            ("day", b.day.into()),
        ] {
            if n != 0 {
                d[key] = json!(n);
            }
        }
        v["birthdate"] = d;
    }
    v
}

fn user_json(u: &FoundUser) -> Value {
    let mut v = json!({ "login": u.login, "name": u.name });
    // Only ever filled in for a friendships session.
    if let Some(fp) = &u.fingerprint {
        v["fingerprint"] = json!(fingerprint(fp));
    }
    if let Some((state, text)) = &u.presence {
        v["presence"] = json!(presence_name(*state));
        if let Some(text) = text {
            v["status_text"] = json!(text);
        }
    }
    if let Some(p) = &u.profile {
        v["profile"] = profile_json(p);
    }
    v
}

fn listing_json(l: &RequestsListing) -> Value {
    let requests: Vec<Value> = l
        .requests
        .iter()
        .map(|g| {
            let mut v = mailbox_json(&g.from);
            v["messages"] = g
                .messages
                .iter()
                .map(|m| {
                    let mut msg = json!({
                        "id": m.id,
                        "text": m.body,
                        "at": unix(m.sent_at),
                    });
                    // Every request is stored with one.
                    msg["guid"] = json!(m.guid.as_ref().map(MessageGuid::as_str));
                    if let Some(signed) = &m.signed {
                        msg["signed"] = json!(b64url(&signed.form));
                    }
                    msg
                })
                .collect();
            v
        })
        .collect();
    let approvals: Vec<Value> = l.approvals.iter().map(mailbox_json).collect();
    json!({ "requests": requests, "approvals": approvals, "dropped": l.dropped })
}

fn results_json(results: &[PresentResult]) -> Vec<Value> {
    results
        .iter()
        .map(|r| {
            let (result, withdraw) = match &r.outcome {
                Presented::Ok => ("ok", None),
                Presented::AccountNotFound => ("no_such_user", None),
                Presented::RosterFull => ("roster_full", None),
                Presented::BadSignature => ("bad_signature", None),
                Presented::Withdrawn(w) => ("withdrawn", w.as_ref()),
                Presented::Stale => ("stale", None),
            };
            let mut v = json!({ "hash": b64url(&r.hash), "result": result });
            if let Some(w) = withdraw {
                v["withdraw"] = json!(b64url(w));
            }
            v
        })
        .collect()
}

fn fetched_json(f: &Fetched) -> Value {
    let friendships: Vec<Value> = f
        .friendships
        .iter()
        .map(|(h, bytes)| {
            let mut v = json!({ "hash": b64url(h) });
            if let Some(b) = bytes {
                v["friendship"] = json!(b64url(b));
            }
            v
        })
        .collect();
    let rotations: Vec<Value> = f
        .rotations
        .iter()
        .map(|(fp, records)| {
            json!({
                "fingerprint": fingerprint(fp),
                "records": records.iter().map(|r| b64url(r)).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "friendships": friendships, "rotations": rotations })
}

fn messaging_err(id: u64, e: MessagingError) -> String {
    let (code, text) = match e {
        MessagingError::NotEnabled => (
            "access_denied",
            "Your account does not take part in instant messaging.",
        ),
        MessagingError::AccountNotFound => ("no_such_user", "No such user."),
        MessagingError::Blocked => ("blocked", "You have blocked that user."),
        MessagingError::AlreadyFriends => ("already_friends", "That user is your friend already."),
        MessagingError::RequestPending => (
            "request_pending",
            "A friend request between you is waiting already.",
        ),
        MessagingError::NotFriends => ("not_friends", "That user is not your friend."),
        MessagingError::RosterFull => ("roster_full", "Your roster is full."),
        MessagingError::RateLimited => (
            "quota_exceeded",
            "You have asked as many new people today as this server allows.",
        ),
        MessagingError::MessageTooLong => ("bad_request", "Too long."),
        MessagingError::QueueFull => ("mailbox_full", "That user's mailbox is full."),
        MessagingError::SignedElsewhere | MessagingError::Equivocation => {
            ("bad_signature", "That signature does not fit this message.")
        }
        MessagingError::RequestFull => (
            "request_full",
            "You have sent that user as many requests as you may.",
        ),
        MessagingError::NoSuchRequest => ("no_such_request", "No such request."),
        MessagingError::NotDeviceProved => (
            "access_denied",
            "This session has not proved a device that may make friendships.",
        ),
        MessagingError::BadSignature => (
            "bad_signature",
            "That friendship object does not verify, or is not this session's own.",
        ),
        MessagingError::Withdrawn => (
            "withdrawn",
            "A withdrawal held here ends it; sign again in ten minutes.",
        ),
        MessagingError::TooMany => (
            "bad_request",
            "At most 32 objects, and one withdrawal for a pair.",
        ),
        MessagingError::Stale => (
            "stale",
            "Its time is not within ten minutes of the server's clock.",
        ),
        MessagingError::ServerError => ("server_error", "Server error."),
    };
    reply_err(id, code, text)
}

/// `null` clears, a value sets, and absent leaves as it was.
fn set_or_clear<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct AddParams {
    login: String,
    note: Option<String>,
    offer: Option<String>,
}

#[derive(Deserialize)]
struct RespondParams {
    login: String,
    accept: bool,
    friendship: Option<String>,
}

#[derive(Deserialize)]
struct RemoveParams {
    login: Option<String>,
    fingerprint: Option<String>,
    withdraw: Option<String>,
    offer: Option<String>,
}

#[derive(Deserialize)]
struct FindParams {
    login: Option<String>,
    fingerprint: Option<String>,
}

#[derive(Deserialize, Default)]
struct PresentParams {
    #[serde(default)]
    withdrawals: Vec<String>,
    #[serde(default)]
    friendships: Vec<String>,
}

#[derive(Deserialize, Default)]
struct FetchParams {
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default)]
    fingerprints: Vec<String>,
}

#[derive(Deserialize)]
struct AliasParams {
    login: String,
    alias: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum StateParam {
    Online,
    Away,
    Busy,
    Invisible,
}

#[derive(Deserialize, Default)]
struct PresenceParams {
    state: Option<StateParam>,
    #[serde(default, deserialize_with = "set_or_clear")]
    status_text: Option<Option<String>>,
    discoverable: Option<bool>,
    takes_requests: Option<bool>,
}

#[derive(Deserialize)]
struct ReceiptParams {
    login: String,
    guid: String,
    #[serde(default)]
    read: bool,
}

#[derive(Deserialize)]
struct TypingParams {
    login: String,
    typing: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionParam {
    Approve,
    Delete,
    End,
}

#[derive(Deserialize)]
struct AnswerParams {
    login: String,
    action: ActionParam,
}

#[derive(Deserialize, Default)]
struct ClearParams {
    since: Option<u64>,
    before: Option<u64>,
}

/// Who a request names: an account by login, or by the fingerprint it
/// links.
enum Named {
    Login(String),
    Key([u8; 32]),
}

/// What Remove Friend carries beside whom it names.
enum Removal {
    Plain,
    Withdraw(Vec<u8>),
    CancelOffer(Vec<u8>),
}

/// A request of the family, parsed.
enum Op {
    Friends,
    Add(String, Option<String>, Option<Vec<u8>>),
    Respond(String, bool, Option<Vec<u8>>),
    Remove(Named, Removal),
    Alias(String, Option<String>),
    Presence(PresenceUpdate),
    Find(Named, bool),
    Present(Vec<Vec<u8>>, Vec<Vec<u8>>),
    Fetch(Vec<[u8; 32]>, Vec<[u8; 32]>),
    Receipt(String, MessageGuid, bool),
    Typing(String, bool),
    Requests,
    Answer(String, RequestAction),
    Clear(Option<SystemTime>, Option<SystemTime>),
}

/// A friendship object, as base64url.
fn object(s: &str) -> Result<Vec<u8>, &'static str> {
    crate::identity::unb64(s).ok_or("A friendship object is not base64url.")
}

fn hash(s: &str) -> Result<[u8; 32], &'static str> {
    object(s)?.try_into().map_err(|_| "A hash is not 32 bytes.")
}

fn key(s: &str) -> Result<[u8; 32], &'static str> {
    hl_identity::Fingerprint::parse(s)
        .map(|f| f.0)
        .ok_or("Malformed fingerprint.")
}

/// Exactly one of `login` and `fingerprint`; neither is the malformed
/// request it always was.
fn named_one(login: Option<String>, fp: Option<String>) -> Result<Named, &'static str> {
    match (login, fp) {
        (Some(l), None) => Ok(Named::Login(l)),
        (None, Some(f)) => key(&f).map(Named::Key),
        (None, None) => Err("Malformed request."),
        (Some(_), Some(_)) => Err("Name exactly one of `login` and `fingerprint`."),
    }
}

fn parse(req: &ReqEnvelope) -> Result<Op, &'static str> {
    let p = &req.params;
    let bad = "Malformed request.";
    // A time past what `SystemTime` holds is malformed, never a panic.
    let at = |s: Option<u64>| {
        s.map(|s| {
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(s))
                .ok_or(bad)
        })
        .transpose()
    };
    Ok(match req.req.as_str() {
        "friends" => Op::Friends,
        "requests" => Op::Requests,
        "friend_add" => {
            let p: AddParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let note = p.note.map(|mut n| {
                n.truncate_to_char_boundary(NOTE_MAX_BYTES);
                n
            });
            let offer = p.offer.as_deref().map(object).transpose()?;
            Op::Add(p.login, note, offer)
        }
        "friend_respond" => {
            let p: RespondParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let friendship = p.friendship.as_deref().map(object).transpose()?;
            Op::Respond(p.login, p.accept, friendship)
        }
        "friend_remove" => {
            let p: RemoveParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let removal = match (p.withdraw, p.offer) {
                (None, None) => Removal::Plain,
                (Some(w), None) => Removal::Withdraw(object(&w)?),
                (None, Some(o)) if p.login.is_some() => Removal::CancelOffer(object(&o)?),
                _ => return Err(bad),
            };
            Op::Remove(named_one(p.login, p.fingerprint)?, removal)
        }
        "friendships_present" => {
            let p: PresentParams = crate::conn::params_or_default(p).map_err(|_| bad)?;
            let ws = p
                .withdrawals
                .iter()
                .map(|w| object(w))
                .collect::<Result<_, _>>()?;
            let fs = p
                .friendships
                .iter()
                .map(|f| object(f))
                .collect::<Result<_, _>>()?;
            Op::Present(ws, fs)
        }
        "friendships_fetch" => {
            let p: FetchParams = crate::conn::params_or_default(p).map_err(|_| bad)?;
            let hashes = p.hashes.iter().map(|h| hash(h)).collect::<Result<_, _>>()?;
            let fps = p
                .fingerprints
                .iter()
                .map(|f| key(f))
                .collect::<Result<_, _>>()?;
            Op::Fetch(hashes, fps)
        }
        "friend_alias" => {
            let p: AliasParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let alias = p.alias.filter(|a| !a.is_empty()).map(|mut a| {
                a.truncate_to_chars(NICK_MAX_CHARS);
                a
            });
            Op::Alias(p.login, alias)
        }
        "presence" => {
            let p: PresenceParams = crate::conn::params_or_default(p).map_err(|_| bad)?;
            Op::Presence(PresenceUpdate {
                state: p.state.map(|s| match s {
                    StateParam::Online => Presence::Online,
                    StateParam::Away => Presence::Away,
                    StateParam::Busy => Presence::Busy,
                    StateParam::Invisible => Presence::Invisible,
                }),
                status_text: p.status_text.map(|t| {
                    t.filter(|t| !t.is_empty()).map(|mut t| {
                        t.truncate_to_chars(STATUS_MAX_CHARS);
                        t
                    })
                }),
                discoverable: p.discoverable,
                takes_requests: p.takes_requests,
            })
        }
        "find_user" | "user_profile" => {
            let p: FindParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            Op::Find(
                named_one(p.login, p.fingerprint)?,
                req.req == "user_profile",
            )
        }
        "receipt" => {
            let p: ReceiptParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let guid = MessageGuid::parse(&p.guid).ok_or("`guid` is not a UUID.")?;
            Op::Receipt(p.login, guid, p.read)
        }
        "typing" => {
            let p: TypingParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            Op::Typing(p.login, p.typing)
        }
        "request_answer" => {
            let p: AnswerParams = serde_json::from_value(p.clone()).map_err(|_| bad)?;
            let action = match p.action {
                ActionParam::Approve => RequestAction::Approve,
                ActionParam::Delete => RequestAction::Delete,
                ActionParam::End => RequestAction::End,
            };
            Op::Answer(p.login, action)
        }
        _ => {
            let p: ClearParams = crate::conn::params_or_default(p).map_err(|_| bad)?;
            Op::Clear(at(p.since)?, at(p.before)?)
        }
    })
}

/// What one request of the family answers, done off the reactor: each is
/// a store read or write.
fn act(core: &Core, uid: Uid, op: Op) -> Result<Value, MessagingError> {
    let done = |r: Result<(), MessagingError>| r.map(|()| json!({}));
    let state = |s: RosterState| json!({ "state": state_name(s) });
    match op {
        Op::Friends => core
            .friends_roster(uid)
            .map(|rows| json!({ "friends": rows.iter().map(friend_json).collect::<Vec<_>>() })),
        Op::Add(login, note, offer) => core.friend_ask(uid, &login, note, offer).map(state),
        Op::Respond(login, accept, friendship) => core
            .friend_answer(uid, &login, accept, friendship)
            .map(state),
        Op::Remove(Named::Key(fp), Removal::Withdraw(w)) => {
            done(core.friend_remove_by_key(uid, &fp, Some(w)))
        }
        Op::Remove(Named::Key(fp), _) => done(core.friend_remove_by_key(uid, &fp, None)),
        Op::Remove(Named::Login(login), Removal::Plain) => done(core.friend_remove(uid, &login)),
        Op::Remove(Named::Login(login), Removal::Withdraw(w)) => {
            done(core.friend_unfriend(uid, &login, Some(w)))
        }
        Op::Remove(Named::Login(login), Removal::CancelOffer(o)) => {
            done(core.friend_cancel_offer(uid, &login, &o))
        }
        Op::Present(withdrawals, friendships) => core
            .friendships_present(uid, withdrawals, friendships)
            .map(|(w, f)| json!({ "withdrawals": results_json(&w), "friendships": results_json(&f) })),
        Op::Fetch(hashes, fps) => core.friendships_fetch(uid, &hashes, &fps).map(|f| fetched_json(&f)),
        Op::Alias(login, alias) => done(core.friend_alias(uid, &login, alias.as_deref())),
        Op::Presence(update) => done(core.set_presence(uid, update)),
        Op::Find(Named::Login(login), profile) => {
            let found = if profile {
                core.messaging_user_info(uid, &login)
            } else {
                core.find_user(uid, &login)
            };
            found.map(|u| json!({ "user": user_json(&u) }))
        }
        Op::Find(Named::Key(fp), profile) => core
            .find_user_by_key(uid, &fp, profile)
            .map(|u| json!({ "user": user_json(&u) })),
        Op::Receipt(login, guid, read) => done(core.im_ack(uid, &login, &guid, read)),
        Op::Typing(login, typing) => done(core.im_typing(uid, &login, typing)),
        Op::Requests => {
            let mut listed = listing_json(&core.requests_list(uid)?);
            listed["takes_requests"] = json!(core.own_presence(uid)?.takes_requests);
            Ok(listed)
        }
        Op::Answer(login, action) => done(core.request_answer(uid, &login, action)),
        Op::Clear(since, before) => core.requests_clear(uid, since, before).map(
            |Cleared { declined, deleted }| json!({ "declined": declined, "deleted": deleted }),
        ),
    }
}

/// Answer one request of the family.
pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let id = req.id;
    let op = match parse(req) {
        Ok(op) => op,
        Err(text) => return reply_err(id, "bad_request", text),
    };
    let uid = state.uid;
    match off_reactor(&ctx.core, move |c| act(c, uid, op)).await {
        Some(Ok(ok)) => reply_ok(id, ok),
        Some(Err(e)) => messaging_err(id, e),
        None => reply_err(id, "server_error", "Server error."),
    }
}

/// `block` with a `withdraw` (§7.5): the withdrawal taken, then the block
/// made, as Block User (806) carrying one does. The block stands whatever
/// becomes of the withdrawal, whose refusal is the answer, for the client
/// to sign afresh for its other servers.
pub(crate) async fn block(ctx: &NgCtx, uid: Uid, id: u64, login: String, withdraw: &str) -> String {
    let w = match object(withdraw) {
        Ok(w) => w,
        Err(text) => return reply_err(id, "bad_request", text),
    };
    let done = off_reactor(&ctx.core, move |c| {
        let taken = c.block_withdrawing(uid, &login, w);
        c.inbox_block(uid, &login, true)?;
        Ok(taken)
    })
    .await;
    match done {
        Some(Ok(Ok(()))) => reply_ok(id, json!({})),
        Some(Ok(Err(e))) => messaging_err(id, e),
        Some(Err(hxd_core::ChatError::NoInbox)) => {
            reply_err(id, "no_inbox", "This account has no inbox.")
        }
        Some(Err(hxd_core::ChatError::ServerError)) | None => {
            reply_err(id, "server_error", "Server error.")
        }
        Some(Err(_)) => reply_err(id, "no_such_user", "No such user."),
    }
}
