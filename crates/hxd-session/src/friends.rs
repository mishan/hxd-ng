//! The friend family on the classic wire (`docs/instant-messaging.md`
//! §7): fogWraith's instant messaging extension except its file transfer,
//! calls, directory search, profile writes and buddy icons, and the
//! message requests draft.
//!
//! A translation, as the ng frontend's is: who may ask whom, what a
//! message becomes and which sessions are told are
//! `hxd_core::messaging`'s. Only a session that negotiated capability
//! bit 6 is answered here, or sent anything; every other is answered as
//! before the family existed. Portable friendships
//! (`docs/proposals/portable-friends.md`) are read from and told to a
//! session that negotiated bit 15 alone, whose friendship acts the
//! domain gates on the device it proved.

use std::time::{Duration, SystemTime};

use hxd_core::inbox::{Mailbox, MessageGuid};
use hxd_core::messaging::{Fetched, PresentResult, Presented, RequestAction, RequestsListing};
use hxd_core::relationships::Profile;
use hxd_core::{
    ChatError, Core, Event, FoundUser, FriendEntry, MessagingError, MsgOutcome, Presence,
    PresenceUpdate, RosterState, Uid,
};
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use hxproto::messaging::{
    AckType, PresenceState, ReasonCode, RequestAction as WireAction, RosterState as WireState,
    TypingState, HASH_LEN, MAX_FRIENDSHIP_LEN, MAX_FRIENDSHIP_OBJECTS, MAX_OFFER_LEN,
};

use crate::encoding::TextEncoding;
use crate::frame::{Frame, MAX_FRAME_DATA};

type Chunks = Vec<(u16, Vec<u8>)>;

/// A status text is told to every friend, so it is held to the subject's
/// bound, as on the ng wire.
const STATUS_MAX_CHARS: usize = 255;
/// A friend request's note is held to a private message's bound.
const NOTE_MAX_BYTES: usize = 4096;
/// An alias is a nick.
const ALIAS_MAX_CHARS: usize = 31;

const HANDLED: &[ClientHdr] = &[
    ClientHdr::GetRoster,
    ClientHdr::AddFriend,
    ClientHdr::RemoveFriend,
    ClientHdr::FriendResponse,
    ClientHdr::BlockUser,
    ClientHdr::UnblockUser,
    ClientHdr::SetPresence,
    ClientHdr::ImSend,
    ClientHdr::ImAck,
    ClientHdr::ImTyping,
    ClientHdr::FindUser,
    ClientHdr::SetFriendNickname,
    ClientHdr::GetProfile,
    ClientHdr::GetMessageRequests,
    ClientHdr::AnswerMessageRequest,
    ClientHdr::ClearMessageRequests,
    ClientHdr::PresentFriendships,
    ClientHdr::GetFriendships,
];

fn handled(ty: u32) -> Option<ClientHdr> {
    HANDLED.iter().copied().find(|h| h.as_u32() == ty)
}

/// Is `ty` a transaction of the family this wire answers?
pub(crate) fn handles(ty: u32) -> bool {
    handled(ty).is_some()
}

/// Is `ty` one answered only for a session that negotiated bit 15?
pub(crate) fn friendships_only(ty: u32) -> bool {
    ty == ClientHdr::PresentFriendships.as_u32() || ty == ClientHdr::GetFriendships.as_u32()
}

/// Whether `ty` has a reply: IM Typing (813) is a notification both ways.
pub(crate) fn answers(ty: u32) -> bool {
    ty != ClientHdr::ImTyping.as_u32()
}

/// The spam points each costs a session that negotiated bit 6. mhxd's
/// table predates the extension and would charge its catch-all 10 for
/// each, at which the receipts a client sends for a roster read's
/// backlog are a ban. So each is priced as its nearest classic
/// counterpart: a roster read as Get User List (300), a friend request
/// as Invite to Chat (113), an answer, a removal, an alias or a clearing
/// as Decline Chat (114), presence as the agreement's SetInfo (121), and
/// a listing of requests at the catch-all, the store read it is.
/// Receipts and typing come as fast as messages are read and typed, so
/// they cost mhxd's least. Discovery costs more than Get User Info's
/// (303) 1: the extension asks that it be rate-limited against
/// enumeration, and this budget is the only one this wire has. A message
/// names a Login as Find User does, and so does a block or an unblock,
/// answered alike whether or not the Login exists but looked up all the
/// same, so they cost as much, as the requests draft counts a send
/// toward Find User's rate. Present Friendships and Get Friendships cost
/// none: they are paced by their own rate (`Core::friendships_spend`),
/// never kicked for (`docs/proposals/portable-friends.md` §4.3).
pub(crate) fn price(ty: u32) -> Option<u32> {
    let points = match handled(ty)? {
        ClientHdr::PresentFriendships | ClientHdr::GetFriendships => 0,
        ClientHdr::GetRoster => 20,
        ClientHdr::GetMessageRequests => 10,
        ClientHdr::AddFriend => 8,
        ClientHdr::SetPresence
        | ClientHdr::FindUser
        | ClientHdr::GetProfile
        | ClientHdr::ImSend
        | ClientHdr::BlockUser
        | ClientHdr::UnblockUser => 4,
        ClientHdr::RemoveFriend
        | ClientHdr::FriendResponse
        | ClientHdr::SetFriendNickname
        | ClientHdr::AnswerMessageRequest
        | ClientHdr::ClearMessageRequests => 2,
        ClientHdr::ImAck | ClientHdr::ImTyping => 1,
        _ => return None,
    };
    Some(points)
}

/// The Server Limits Advertisement a login reply carries beside a
/// confirmed bit 6, with the requests draft's message bound, since this
/// server takes requests wherever messaging is on.
pub(crate) fn limits(core: &Core, enc: TextEncoding) -> Chunks {
    let p = core.messaging_policy();
    // The domain bounds a message's UTF-8, of which one Mac Roman byte can
    // become three, and an advertisement may be tighter than the bound
    // but never looser.
    let message_bytes = match enc {
        TextEncoding::Utf8 => p.max_message_bytes,
        TextEncoding::MacRoman => p.max_message_bytes / 3,
    };
    [
        (tag::MAX_MESSAGE_BYTES, message_bytes),
        (tag::MAX_ROSTER_SIZE, p.max_roster),
        (tag::MAX_OFFLINE_QUEUE, core.inbox_policy().max_queued),
        (tag::MAX_REQUEST_MESSAGES, p.request_messages),
    ]
    .into_iter()
    .map(|(t, n)| (t, u32_bytes(n.max(1))))
    .collect()
}

/// Who a request names: an account by Login, or, on a session that
/// negotiated bit 15, by the fingerprint it links.
pub(crate) enum Named {
    Login(String),
    Key([u8; 32]),
}

/// What Remove Friend (803) carries beside whom it names.
pub(crate) enum Removal {
    Plain,
    Withdraw(Vec<u8>),
    CancelOffer(Vec<u8>),
}

/// A request of the family, parsed.
pub(crate) enum Op {
    Roster,
    Add(String, Option<String>, Option<Vec<u8>>),
    Remove(Named, Removal),
    Respond(String, bool, Option<Vec<u8>>),
    Block(String, bool, Option<Vec<u8>>),
    Presence(PresenceUpdate),
    Send(String, MessageGuid, String),
    Ack(String, MessageGuid, bool),
    Typing(String, bool),
    Find(Named, bool),
    Alias(String, Option<String>),
    Requests(usize),
    Answer(Named, RequestAction),
    Clear(Option<SystemTime>, Option<SystemTime>),
    Present(Vec<Vec<u8>>, Vec<Vec<u8>>),
    Fetch(Vec<[u8; 32]>, Vec<[u8; 32]>),
}

/// What a request is answered.
pub(crate) enum Answer {
    /// The reply, and the notifications that follow it.
    Reply {
        chunks: Chunks,
        then: Vec<(u32, Chunks)>,
    },
    /// A failure: its text, and its reason code where one fits.
    Refused {
        text: &'static str,
        reason: Option<ReasonCode>,
    },
    /// Nothing: a notification has no reply.
    Silent,
}

impl Answer {
    fn ok(chunks: Chunks) -> Answer {
        Answer::Reply {
            chunks,
            then: Vec::new(),
        }
    }

    /// The reason code a failure carries, as fields.
    pub(crate) fn reason_chunks(reason: Option<ReasonCode>) -> Chunks {
        reason.map_or_else(Vec::new, |r| vec![reason_chunk(r)])
    }
}

const MALFORMED: &str = "Malformed request.";

/// Read `f`, a transaction [`handles`] says is the family's, with what
/// only bit 15 adds read where `friendships` says the session negotiated
/// it, and ignored, as any field unknown to the extension is, where not.
pub(crate) fn parse(f: &Frame, enc: TextEncoding, friendships: bool) -> Result<Op, &'static str> {
    let field = |t: u16| f.chunks().find(|c| c.tag == t).map(|c| c.data.to_vec());
    // A friendship object, within its field's bound.
    let object = |t: u16, max: usize| {
        field(t)
            .filter(|_| friendships)
            .map(|o| {
                (!o.is_empty() && o.len() <= max)
                    .then_some(o)
                    .ok_or(MALFORMED)
            })
            .transpose()
    };
    let key = || -> Result<Option<[u8; 32]>, &'static str> {
        field(tag::FRIEND_IDENTITY)
            .filter(|_| friendships)
            .map(|k| <[u8; 32]>::try_from(k.as_slice()).map_err(|_| MALFORMED))
            .transpose()
    };
    let uint = |t: u16| f.chunks().find(|c| c.tag == t).map(|c| c.as_uint());
    let login = || {
        field(tag::FRIEND_LOGIN)
            .filter(|l| !l.is_empty())
            .map(|l| enc.decode(&l))
            .ok_or(MALFORMED)
    };
    let guid = || {
        field(tag::MESSAGE_GUID)
            .and_then(|g| guid_of(&g))
            .ok_or(MALFORMED)
    };
    let at = |t: u16| -> Result<Option<SystemTime>, &'static str> {
        field(t)
            .map(|d| {
                // A time past what `SystemTime` holds is malformed, never
                // a panic.
                <[u8; 8]>::try_from(d.as_slice())
                    .ok()
                    .and_then(|b| {
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_secs(u64::from_be_bytes(b)))
                    })
                    .ok_or(MALFORMED)
            })
            .transpose()
    };
    Ok(match handled(f.ty).ok_or(MALFORMED)? {
        ClientHdr::GetRoster => Op::Roster,
        ClientHdr::AddFriend => {
            let note = field(tag::REQUEST_NOTE).map(|n| {
                let mut n = enc.decode(&n);
                cut(&mut n, NOTE_MAX_BYTES);
                n
            });
            Op::Add(login()?, note, object(tag::FRIEND_OFFER, MAX_OFFER_LEN)?)
        }
        ClientHdr::RemoveFriend => {
            let removal = match (
                object(tag::FRIEND_WITHDRAW, MAX_OFFER_LEN)?,
                object(tag::FRIEND_OFFER, MAX_OFFER_LEN)?,
            ) {
                (None, None) => Removal::Plain,
                (Some(w), None) => Removal::Withdraw(w),
                (None, Some(o)) => Removal::CancelOffer(o),
                (Some(_), Some(_)) => return Err(MALFORMED),
            };
            let named = match (field(tag::FRIEND_LOGIN), key()?) {
                (Some(_), Some(_)) => return Err(MALFORMED),
                (None, Some(k)) if !matches!(removal, Removal::CancelOffer(_)) => Named::Key(k),
                _ => Named::Login(login()?),
            };
            Op::Remove(named, removal)
        }
        ClientHdr::FriendResponse => {
            let accept = uint(tag::ROSTER_STATE) == Some(WireState::Accepted.wire().into());
            let friendship = object(tag::FRIENDSHIP, MAX_FRIENDSHIP_LEN)?;
            if friendship.is_some() && !accept {
                return Err(MALFORMED);
            }
            Op::Respond(login()?, accept, friendship)
        }
        ClientHdr::BlockUser => {
            Op::Block(login()?, true, object(tag::FRIEND_WITHDRAW, MAX_OFFER_LEN)?)
        }
        ClientHdr::UnblockUser => Op::Block(login()?, false, None),
        ClientHdr::SetPresence => {
            // Absent changes the settings alone: a state would end an
            // Invisible set from another client.
            let state = match uint(tag::PRESENCE_STATE)
                .map(|v| u16::try_from(v).ok().and_then(PresenceState::from_wire))
            {
                None => None,
                Some(Some(PresenceState::Online)) => Some(Presence::Online),
                Some(Some(PresenceState::Away)) => Some(Presence::Away),
                Some(Some(PresenceState::Invisible)) => Some(Presence::Invisible),
                Some(Some(PresenceState::Busy)) => Some(Presence::Busy),
                // Never a state a client sets for itself.
                Some(_) => return Err(MALFORMED),
            };
            // Present and empty, or only whitespace, clears the text;
            // absent leaves it as it was.
            let status_text = field(tag::PRESENCE_STATUS_TEXT).map(|t| {
                let t: String = enc.decode(&t).chars().take(STATUS_MAX_CHARS).collect();
                (!t.trim().is_empty()).then_some(t)
            });
            Op::Presence(PresenceUpdate {
                state,
                status_text,
                discoverable: uint(tag::DISCOVERABLE).map(|v| v != 0),
                takes_requests: uint(tag::TAKES_REQUESTS).map(|v| v != 0),
            })
        }
        ClientHdr::ImSend => {
            let body = field(tag::MESSAGE_BODY)
                .filter(|b| !b.is_empty())
                .ok_or(MALFORMED)?;
            Op::Send(login()?, guid()?, enc.decode(&body))
        }
        ClientHdr::ImAck => {
            let read = match uint(tag::ACK_TYPE)
                .and_then(|v| AckType::from_wire(u16::try_from(v).ok()?))
            {
                Some(AckType::Delivered) => false,
                Some(AckType::Read) => true,
                _ => return Err(MALFORMED),
            };
            Op::Ack(login()?, guid()?, read)
        }
        ClientHdr::ImTyping => Op::Typing(
            login()?,
            uint(tag::TYPING_STATE) == Some(TypingState::Started.wire().into()),
        ),
        ClientHdr::FindUser => match (field(tag::FRIEND_LOGIN), key()?) {
            (None, Some(k)) => Op::Find(Named::Key(k), false),
            (Some(_), Some(_)) => return Err(MALFORMED),
            _ => Op::Find(Named::Login(login()?), false),
        },
        ClientHdr::GetProfile => Op::Find(Named::Login(login()?), true),
        ClientHdr::SetFriendNickname => {
            let alias = field(tag::FRIEND_NICKNAME).ok_or(MALFORMED)?;
            let alias = enc.decode_chars(&alias, ALIAS_MAX_CHARS);
            Op::Alias(login()?, (!alias.is_empty()).then_some(alias))
        }
        ClientHdr::GetMessageRequests => {
            let from = match field(tag::REQUEST_CURSOR) {
                None => 0,
                Some(c) => <[u8; 4]>::try_from(c.as_slice())
                    .map(|b| u32::from_be_bytes(b) as usize)
                    .map_err(|_| MALFORMED)?,
            };
            Op::Requests(from)
        }
        ClientHdr::AnswerMessageRequest => {
            let action = match uint(tag::REQUEST_ACTION)
                .and_then(|v| WireAction::from_wire(u16::try_from(v).ok()?))
            {
                Some(WireAction::Approve) => RequestAction::Approve,
                Some(WireAction::Delete) => RequestAction::Delete,
                Some(WireAction::EndApproval) => RequestAction::End,
                _ => return Err(MALFORMED),
            };
            // An identity guest is named by its fingerprint alone (§4.5).
            let named = match (field(tag::FRIEND_LOGIN), key()?) {
                (None, Some(k)) => Named::Key(k),
                (Some(_), Some(_)) => return Err(MALFORMED),
                _ => Named::Login(login()?),
            };
            Op::Answer(named, action)
        }
        ClientHdr::ClearMessageRequests => Op::Clear(at(tag::SPAN_SINCE)?, at(tag::SPAN_BEFORE)?),
        ClientHdr::PresentFriendships => {
            let (mut withdrawals, mut presented) = (Vec::new(), Vec::new());
            for c in f.chunks() {
                let (to, max) = match c.tag {
                    tag::FRIEND_WITHDRAW => (&mut withdrawals, MAX_OFFER_LEN),
                    tag::FRIENDSHIP => (&mut presented, MAX_FRIENDSHIP_LEN),
                    _ => continue,
                };
                if c.data.is_empty() || c.data.len() > max {
                    return Err(MALFORMED);
                }
                to.push(c.data.to_vec());
            }
            Op::Present(withdrawals, presented)
        }
        ClientHdr::GetFriendships => {
            let (mut hashes, mut keys) = (Vec::new(), Vec::new());
            for c in f.chunks() {
                let to = match c.tag {
                    tag::FRIENDSHIP_HASH => &mut hashes,
                    tag::FRIEND_IDENTITY => &mut keys,
                    _ => continue,
                };
                to.push(<[u8; HASH_LEN]>::try_from(c.data).map_err(|_| MALFORMED)?);
            }
            Op::Fetch(hashes, keys)
        }
        _ => return Err(MALFORMED),
    })
}

/// Answer one request, off the reactor: each is a store read or write.
/// `friendships` is whether the session negotiated bit 15.
pub(crate) fn act(core: &Core, uid: Uid, enc: TextEncoding, friendships: bool, op: Op) -> Answer {
    let done = |r: Result<(), MessagingError>| match r {
        Ok(()) => Answer::ok(vec![reason_chunk(ReasonCode::Ok)]),
        Err(e) => refusal(e),
    };
    let state = |r: Result<RosterState, MessagingError>| match r {
        Ok(state) => Answer::ok(vec![
            reason_chunk(ReasonCode::Ok),
            (tag::ROSTER_STATE, u16_bytes(roster_state(state).wire())),
        ]),
        Err(e) => refusal(e),
    };
    if let Some((base, per_object)) = weight(&op) {
        let objects = match &op {
            Op::Present(w, f) => w.len() + f.len(),
            Op::Fetch(h, k) => h.len() + k.len(),
            _ => 1,
        };
        if objects > MAX_FRIENDSHIP_OBJECTS {
            return refusal(MessagingError::TooMany);
        }
        // The objects are charged only to a session the domain's gate
        // would let act, so that one that proved no device spends none of
        // its account's or its address's rate on what is refused; the
        // request's own weight, always.
        let may_act = core
            .user(uid)
            .is_some_and(|u| u.transport.friendships && u.transport.identity.is_some());
        let weight = base + if may_act { per_object } else { 0 };
        // A removal or a block is never held up by pacing (§4.3): its
        // withdrawal is charged, and taken, whatever is left.
        let removes = matches!(op, Op::Remove(..) | Op::Block(..));
        if removes {
            core.friendships_charge(uid, weight);
        } else if weight > 0 && core.friendships_spend(uid, weight).is_err() {
            return refusal(MessagingError::RateLimited);
        }
    }
    match op {
        Op::Roster => match core.friends_roster(uid) {
            Ok(rows) => {
                // As many entries as fit a frame, and the rest as Roster
                // Entries after it, which the extension allows.
                let mut entries: Vec<Chunks> = rows
                    .iter()
                    .map(|e| entry_chunks(e, enc, friendships))
                    .collect();
                let (listed, _) = page(&entries, 0, PAGE_BUDGET);
                let rest = entries.split_off(listed);
                let mut then: Vec<(u32, Chunks)> = rest
                    .into_iter()
                    .map(|c| (ServerHdr::RosterEntry.as_u32(), c))
                    .collect();
                // A request waiting is told as its Friend Request too, and
                // so is an upgrade offer waiting on a friend, which an entry
                // has no field for.
                then.extend(
                    rows.iter()
                        .filter(|e| {
                            e.state == RosterState::PendingIn
                                || (e.state == RosterState::Accepted && e.offer.is_some())
                        })
                        .map(|e| {
                            let request = Request {
                                login: &e.login,
                                fingerprint: e.fingerprint.as_ref(),
                                note: e.note.as_deref(),
                                offer: e.offer.as_deref(),
                            };
                            request.frame(enc, friendships)
                        }),
                );
                Answer::Reply {
                    chunks: entries.into_iter().flatten().collect(),
                    then,
                }
            }
            Err(e) => refusal(e),
        },
        Op::Add(login, note, offer) => state(core.friend_ask(uid, &login, note, offer)),
        Op::Remove(Named::Key(fp), removal) => {
            let withdraw = match removal {
                Removal::Withdraw(w) => Some(w),
                _ => None,
            };
            done(core.friend_remove_by_key(uid, &fp, withdraw))
        }
        Op::Remove(Named::Login(login), Removal::Plain) => done(core.friend_remove(uid, &login)),
        Op::Remove(Named::Login(login), Removal::Withdraw(w)) => {
            done(core.friend_unfriend(uid, &login, Some(w)))
        }
        Op::Remove(Named::Login(login), Removal::CancelOffer(o)) => {
            done(core.friend_cancel_offer(uid, &login, &o))
        }
        Op::Respond(login, accept, friendship) => done(
            core.friend_answer(uid, &login, accept, friendship)
                .map(|_| ()),
        ),
        // The block stands whatever becomes of the withdrawal before it,
        // whose refusal is the answer, for the client to sign afresh for
        // its other servers (§4.3).
        Op::Block(login, on, withdraw) => {
            let taken = withdraw.map_or(Ok(()), |w| core.block_withdrawing(uid, &login, w));
            match core.inbox_block(uid, &login, on) {
                // A Login nobody holds is answered as any other, so that a
                // block never confirms that a Login exists.
                Ok(()) | Err(ChatError::NoSuchUser) => done(taken),
                Err(ChatError::NoInbox) => Answer::Refused {
                    text: "This account has no inbox.",
                    reason: None,
                },
                Err(_) => refusal(MessagingError::ServerError),
            }
        }
        Op::Presence(update) => done(core.set_presence(uid, update)),
        Op::Send(login, guid, text) => match core.im_send_login(uid, &login, text, Some(guid)) {
            Ok(outcome) => {
                let reason = match outcome {
                    MsgOutcome::Delivered(_) => ReasonCode::Ok,
                    MsgOutcome::Queued(_) => ReasonCode::OfflineQueued,
                    MsgOutcome::Requested => ReasonCode::Requested,
                };
                Answer::ok(vec![reason_chunk(reason)])
            }
            Err(e) => refusal(e),
        },
        Op::Ack(login, guid, read) => done(core.im_ack(uid, &login, &guid, read)),
        Op::Typing(login, typing) => {
            // A notification: what the domain refuses is dropped unsaid.
            let _ = core.im_typing(uid, &login, typing);
            Answer::Silent
        }
        Op::Find(named, profile) => {
            let found = match named {
                Named::Login(login) if profile => core.messaging_user_info(uid, &login),
                Named::Login(login) => core.find_user(uid, &login),
                Named::Key(fp) => core.find_user_by_key(uid, &fp, profile),
            };
            match found {
                Ok(u) => Answer::ok(found_chunks(&u, profile, enc)),
                Err(e) => refusal(e),
            }
        }
        Op::Alias(login, alias) => done(core.friend_alias(uid, &login, alias.as_deref())),
        Op::Requests(from) => {
            let listed = core.requests_list_page(uid, from == 0).and_then(|l| {
                let takes = core.own_presence(uid)?.takes_requests;
                Ok((l, takes))
            });
            match listed {
                Ok((l, takes)) => Answer::ok(listing_chunks(&l, takes, from, enc, friendships)),
                Err(e) => refusal(e),
            }
        }
        Op::Answer(Named::Login(login), action) => done(core.request_answer(uid, &login, action)),
        Op::Answer(Named::Key(fp), action) => done(core.request_answer_by_key(uid, &fp, action)),
        Op::Clear(since, before) => match core.requests_clear(uid, since, before) {
            Ok(c) => Answer::ok(vec![
                reason_chunk(ReasonCode::Ok),
                (tag::REQUEST_COUNT, u32_bytes(c.deleted)),
                (tag::FRIEND_REQUEST_COUNT, u32_bytes(c.declined)),
            ]),
            Err(e) => refusal(e),
        },
        Op::Present(withdrawals, presented) => {
            match core.friendships_present(uid, withdrawals, presented) {
                Ok((taken, presented)) => Answer::ok(
                    taken
                        .iter()
                        .chain(&presented)
                        .flat_map(outcome_chunks)
                        .collect(),
                ),
                Err(e) => refusal(e),
            }
        }
        Op::Fetch(hashes, keys) => match core.friendships_fetch(uid, &hashes, &keys) {
            Ok(f) => Answer::ok(fetched_chunks(&f)),
            Err(e) => refusal(e),
        },
    }
}

/// What a request carrying friendship objects weighs against
/// `Core::friendships_spend`, as the ng wire's request limit weighs it
/// (`docs/hotline-ng.md` §7.5): each object the signatures it is checked
/// with, and Present Friendships and Get Friendships their own requests'
/// weights besides, which the classic wire's spam points do not price:
/// the request's own weight, and its objects'.
fn weight(op: &Op) -> Option<(u32, u32)> {
    let n = |len: usize| u32::try_from(len).unwrap_or(u32::MAX);
    match op {
        Op::Add(_, _, Some(_))
        | Op::Remove(_, Removal::Withdraw(_) | Removal::CancelOffer(_))
        | Op::Block(_, true, Some(_)) => Some((0, 2)),
        Op::Respond(_, _, Some(_)) => Some((0, 4)),
        Op::Present(w, f) => Some((1, 4 * n(w.len() + f.len()))),
        Op::Fetch(h, k) => Some((4, n(h.len() + k.len()))),
        _ => None,
    }
}

/// One group of a Present Friendships (833) reply: the object's hash, its
/// reason code, and for `Withdrawn` the withdrawal where there is one.
fn outcome_chunks(r: &PresentResult) -> Chunks {
    let (reason, withdraw) = match &r.outcome {
        Presented::Ok => (ReasonCode::Ok, None),
        Presented::AccountNotFound => (ReasonCode::AccountNotFound, None),
        Presented::RosterFull => (ReasonCode::RosterFull, None),
        Presented::BadSignature => (ReasonCode::BadSignature, None),
        Presented::Withdrawn(w) => (ReasonCode::Withdrawn, w.as_ref()),
        Presented::Stale => (ReasonCode::Stale, None),
    };
    let mut c = vec![
        (tag::FRIENDSHIP_HASH, r.hash.to_vec()),
        reason_chunk(reason),
    ];
    if let Some(w) = withdraw {
        c.push((tag::FRIEND_WITHDRAW, w.clone()));
    }
    c
}

/// A Get Friendships (834) reply: a group for each hash, with its
/// friendship where the caller may have it, and for each fingerprint,
/// with its rotation records in chain order; as many groups as fit a
/// frame, the questions after them left unanswered for the client to
/// ask again.
fn fetched_chunks(f: &Fetched) -> Chunks {
    let mut groups: Vec<Chunks> = Vec::new();
    for (hash, friendship) in &f.friendships {
        let mut c = vec![(tag::FRIENDSHIP_HASH, hash.to_vec())];
        if let Some(b) = friendship {
            c.push((tag::FRIENDSHIP, b.clone()));
        }
        groups.push(c);
    }
    for (fp, records) in &f.rotations {
        let mut c = vec![(tag::FRIEND_IDENTITY, fp.to_vec())];
        c.extend(records.iter().map(|r| (tag::IDENTITY_ROTATION, r.clone())));
        groups.push(c);
    }
    let (end, _) = page(&groups, 0, PAGE_BUDGET);
    groups.into_iter().take(end).flatten().collect()
}

/// A refusal by the extension's reason codes, and the requests draft's
/// where it gives its own.
fn refusal(e: MessagingError) -> Answer {
    let (text, reason) = match e {
        MessagingError::NotEnabled => (
            "Your account does not take part in instant messaging.",
            None,
        ),
        MessagingError::AccountNotFound => ("No such user.", Some(ReasonCode::AccountNotFound)),
        // The extension's `Blocked` is the target's block of the caller,
        // which is told as a missing account; the caller's own has no
        // code of its own, so it goes with its words alone.
        MessagingError::Blocked => ("You have blocked that user.", None),
        MessagingError::AlreadyFriends => (
            "That user is your friend already.",
            Some(ReasonCode::AlreadyFriends),
        ),
        MessagingError::RequestPending => (
            "A friend request between you is waiting already.",
            Some(ReasonCode::RequestPending),
        ),
        MessagingError::NotFriends => (
            "That user is not your friend.",
            Some(ReasonCode::NotFriends),
        ),
        MessagingError::RosterFull => ("Your roster is full.", Some(ReasonCode::RosterFull)),
        MessagingError::RateLimited => (
            "You have sent as much as this server allows for now.",
            Some(ReasonCode::RateLimited),
        ),
        MessagingError::MessageTooLong => ("That is too long.", Some(ReasonCode::MessageTooLong)),
        MessagingError::QueueFull => ("That user's mailbox is full.", Some(ReasonCode::QueueFull)),
        MessagingError::RequestFull => (
            "You have sent that user as many requests as you may.",
            Some(ReasonCode::QueueFull),
        ),
        MessagingError::NoSuchRequest => ("No such request.", Some(ReasonCode::AccountNotFound)),
        // A friendship act from a session that proved no device of the
        // account's identity: the extension has no code for it.
        MessagingError::NotDeviceProved => (
            "This session has not proved a device that may make friendships.",
            None,
        ),
        MessagingError::BadSignature => (
            "That friendship object does not verify, or is not this session's own.",
            Some(ReasonCode::BadSignature),
        ),
        MessagingError::Withdrawn => (
            "A withdrawal held here ends it. Sign again in ten minutes.",
            Some(ReasonCode::Withdrawn),
        ),
        MessagingError::Stale => (
            "Its time is not within ten minutes of the server's clock.",
            Some(ReasonCode::Stale),
        ),
        MessagingError::TooMany => ("At most 32 objects, and one withdrawal for a pair.", None),
        // Signed messages are not negotiated on this wire, so neither of
        // these can be asked for here.
        MessagingError::SignedElsewhere
        | MessagingError::Equivocation
        | MessagingError::ServerError => ("Server error.", None),
    };
    Answer::Refused { text, reason }
}

/// The notification a domain event is on this wire, for one of the
/// family's.
pub(crate) fn event(ev: &Event, enc: TextEncoding, friendships: bool) -> Option<(u32, Chunks)> {
    Some(match ev {
        Event::FriendEntry(e) => (
            ServerHdr::RosterEntry.as_u32(),
            entry_chunks(e, enc, friendships),
        ),
        Event::FriendRequest {
            login,
            fingerprint,
            note,
            offer,
        } => Request {
            login,
            fingerprint: fingerprint.as_ref(),
            note: note.as_deref(),
            offer: offer.as_deref(),
        }
        .frame(enc, friendships),
        Event::Presence {
            login,
            state,
            status_text,
            ..
        } => {
            let mut c = vec![
                (tag::FRIEND_LOGIN, enc.encode(login)),
                (
                    tag::PRESENCE_STATE,
                    u16_bytes(presence_state(*state).wire()),
                ),
            ];
            if let Some(t) = status_text {
                c.push((tag::PRESENCE_STATUS_TEXT, enc.encode(t)));
            }
            (ServerHdr::PresenceChanged.as_u32(), c)
        }
        Event::Im(im) => (
            ServerHdr::ImDeliver.as_u32(),
            vec![
                (tag::MESSAGE_GUID, guid_bytes(&im.guid).to_vec()),
                (tag::FRIEND_LOGIN, enc.encode(&im.from_login)),
                (tag::MESSAGE_BODY, enc.body(&im.text)),
                (
                    tag::MESSAGE_TIMESTAMP,
                    unix(im.sent_at).to_be_bytes().to_vec(),
                ),
            ],
        ),
        Event::Receipt {
            login, guid, read, ..
        } => {
            let ack = if *read {
                AckType::Read
            } else {
                AckType::Delivered
            };
            (
                ServerHdr::ImAck.as_u32(),
                vec![
                    (tag::MESSAGE_GUID, guid_bytes(guid).to_vec()),
                    (tag::ACK_TYPE, u16_bytes(ack.wire())),
                    (tag::FRIEND_LOGIN, enc.encode(login)),
                ],
            )
        }
        Event::Typing { login, typing, .. } => {
            let state = if *typing {
                TypingState::Started
            } else {
                TypingState::Stopped
            };
            (
                ServerHdr::ImTyping.as_u32(),
                vec![
                    (tag::FRIEND_LOGIN, enc.encode(login)),
                    (tag::TYPING_STATE, u16_bytes(state.wire())),
                ],
            )
        }
        Event::RequestsChanged { count } => (
            ServerHdr::MessageRequestsChanged.as_u32(),
            vec![(tag::REQUEST_COUNT, u32_bytes(*count))],
        ),
        _ => return None,
    })
}

/// One roster entry, whole, as Get Roster (800) lists it and a Roster
/// Entry (801) carries it: one routine for both, so the two are the same
/// bytes, as the extension asks. A friend's presence only while it is
/// shown, and its status text whenever it keeps one. What the domain
/// fills in for a session that negotiated bit 15 alone, a friend's hashes
/// and the withdrawal that removed one, wherever it is there, and to
/// such a session the fingerprint the account links.
fn entry_chunks(e: &FriendEntry, enc: TextEncoding, friendships: bool) -> Chunks {
    let mut c = vec![(tag::FRIEND_LOGIN, enc.encode(&e.login))];
    if e.state == RosterState::Removed {
        c.push((tag::ROSTER_STATE, u16_bytes(WireState::Removed.wire())));
        if let Some(w) = &e.withdraw {
            c.push((tag::FRIEND_WITHDRAW, w.clone()));
        }
        return c;
    }
    if let Some(fp) = e.fingerprint.filter(|_| friendships) {
        c.push((tag::FRIEND_IDENTITY, fp.to_vec()));
    }
    c.extend(
        e.friendships
            .iter()
            .take(2)
            .map(|h| (tag::FRIENDSHIP_HASH, h.to_vec())),
    );
    if let Some(alias) = &e.alias {
        c.push((tag::FRIEND_NICKNAME, enc.encode(alias)));
    }
    c.push((tag::ROSTER_STATE, u16_bytes(roster_state(e.state).wire())));
    if e.state == RosterState::Accepted {
        if e.presence != Presence::Offline {
            c.push((
                tag::PRESENCE_STATE,
                u16_bytes(presence_state(e.presence).wire()),
            ));
        }
        if let Some(t) = &e.status_text {
            c.push((tag::PRESENCE_STATUS_TEXT, enc.encode(t)));
        }
    }
    c
}

/// A Friend Request (804): a request waiting, or an upgrade offer.
struct Request<'a> {
    login: &'a str,
    fingerprint: Option<&'a [u8; 32]>,
    note: Option<&'a str>,
    offer: Option<&'a [u8]>,
}

impl Request<'_> {
    /// With the sender's fingerprint to a session that negotiated bit
    /// 15, and its offer, which the domain sends no other.
    fn frame(&self, enc: TextEncoding, friendships: bool) -> (u32, Chunks) {
        let mut c = vec![(tag::FRIEND_LOGIN, enc.encode(self.login))];
        if let Some(n) = self.note {
            c.push((tag::REQUEST_NOTE, enc.body(n)));
        }
        if let Some(fp) = self.fingerprint.filter(|_| friendships) {
            c.push((tag::FRIEND_IDENTITY, fp.to_vec()));
        }
        if let Some(o) = self.offer {
            c.push((tag::FRIEND_OFFER, o.to_vec()));
        }
        (ServerHdr::FriendRequest.as_u32(), c)
    }
}

/// Find User (822) and Get User Info (825): the public card, and for 825
/// the profile where the caller may read it or `NotFriends` where not;
/// and the fingerprint the account links, which the domain fills in for
/// a session that negotiated bit 15 alone.
fn found_chunks(u: &FoundUser, profile: bool, enc: TextEncoding) -> Chunks {
    let shown = u.profile.as_ref().filter(|_| profile);
    let reason = if profile && shown.is_none() {
        ReasonCode::NotFriends
    } else {
        ReasonCode::Ok
    };
    let mut c = vec![
        reason_chunk(reason),
        (tag::FRIEND_LOGIN, enc.encode(&u.login)),
        (tag::NAME, enc.encode(&u.name)),
    ];
    if let Some(fp) = &u.fingerprint {
        c.push((tag::FRIEND_IDENTITY, fp.to_vec()));
    }
    if let Some(p) = shown {
        c.extend(profile_chunks(p, enc));
    }
    c
}

fn profile_chunks(p: &Profile, enc: TextEncoding) -> Chunks {
    let mut c = Chunks::new();
    for (t, v) in [
        (tag::PROFILE_NICKNAME, &p.nickname),
        (tag::PROFILE_FIRST_NAME, &p.first_name),
        (tag::PROFILE_LAST_NAME, &p.last_name),
        (tag::PROFILE_EMAIL, &p.email),
    ] {
        if let Some(v) = v {
            c.push((t, enc.encode(v)));
        }
    }
    if p.gender != 0 {
        c.push((tag::PROFILE_GENDER, u16_bytes(p.gender)));
    }
    let b = p.birthdate;
    if b.year != 0 || b.month != 0 || b.day != 0 {
        let y = b.year.to_be_bytes();
        c.push((tag::PROFILE_BIRTHDATE, vec![y[0], y[1], b.month, b.day]));
    }
    for (t, v) in [
        (tag::PROFILE_COUNTRY, &p.country),
        (tag::PROFILE_POSTCODE, &p.postcode),
    ] {
        if let Some(v) = v {
            c.push((t, enc.encode(v)));
        }
    }
    for l in &p.languages {
        c.push((tag::PROFILE_LANGUAGE, enc.encode(l)));
    }
    c
}

/// Get Message Requests (829): from the `from`th group of senders then
/// approvals, as many as fit a frame, with what the first page alone
/// carries before them and the cursor where there is more. A listing is
/// read whole each time, so a cursor is a group's place in it.
fn listing_chunks(
    l: &RequestsListing,
    takes: bool,
    from: usize,
    enc: TextEncoding,
    friendships: bool,
) -> Chunks {
    let mut groups: Vec<Chunks> = Vec::new();
    for g in &l.requests {
        let mut c = named_group(&g.from, enc, friendships);
        let mut size = REQUEST_GROUP_FIELDS;
        for m in &g.messages {
            // Every request is stored with a guid.
            let Some(guid) = &m.guid else {
                continue;
            };
            // A group stored under larger limits than today's is listed
            // as far as a page holds it: approving it delivers it all.
            let body = enc.body(&m.body);
            size += REQUEST_MESSAGE_FIELDS + body.len();
            if body.len() > usize::from(u16::MAX) || size > PAGE_BUDGET {
                break;
            }
            c.push((tag::MESSAGE_GUID, guid_bytes(guid).to_vec()));
            c.push((tag::MESSAGE_BODY, body));
            c.push((
                tag::MESSAGE_TIMESTAMP,
                unix(m.sent_at).to_be_bytes().to_vec(),
            ));
        }
        groups.push(c);
    }
    for a in &l.approvals {
        let mut c = named_group(a, enc, friendships);
        c.push((tag::ROSTER_STATE, u16_bytes(WireState::Accepted.wire())));
        groups.push(c);
    }
    let (end, next) = page(&groups, from, PAGE_BUDGET);
    let mut out = Chunks::new();
    if from == 0 {
        out.push((tag::TAKES_REQUESTS, u16_bytes(u16::from(takes))));
        out.push((
            tag::REQUEST_COUNT,
            u32_bytes(usize::try_from(l.dropped).unwrap_or(usize::MAX)),
        ));
    }
    if let Some(next) = next {
        out.push((tag::REQUEST_CURSOR, u32_bytes(next)));
    }
    out.extend(groups.into_iter().take(end).skip(from).flatten());
    out
}

/// A group's head: its Login, and to a bit-15 session an identity
/// guest's fingerprint, its one name apart from the other guests'
/// (§4.5).
fn named_group(from: &Mailbox, enc: TextEncoding, friendships: bool) -> Chunks {
    let mut c = vec![(tag::FRIEND_LOGIN, enc.encode(&from.login))];
    if let Some(fp) = from
        .fingerprint
        .filter(|_| friendships && from.login == "guest")
    {
        c.push((tag::FRIEND_IDENTITY, fp.to_vec()));
    }
    c
}

/// The fields a reply of groups may hold: a frame, with room for what
/// goes before the groups.
const PAGE_BUDGET: usize = MAX_FRAME_DATA as usize - 64;

/// What one waiting message adds to its group of Get Message Requests
/// beside its body: its guid's and timestamp's fields, and its body's
/// header.
const REQUEST_MESSAGE_FIELDS: usize = (4 + 16) + (4 + 8) + 4;

/// What a group adds before its messages: its Login's field, a Login
/// being a nick's length, within which an identity guest's `guest` and
/// fingerprint fit too.
const REQUEST_GROUP_FIELDS: usize = 4 + 3 * ALIAS_MAX_CHARS;

/// Does one sender's group of Get Message Requests always fit a page, as
/// a page always holds at least one group whatever its size? A body is
/// at most `max_message_bytes` on either encoding, since a Mac Roman
/// body is never longer than its UTF-8.
pub fn request_group_fits(request_messages: usize, max_message_bytes: usize) -> bool {
    max_message_bytes
        .checked_add(REQUEST_MESSAGE_FIELDS)
        .and_then(|m| m.checked_mul(request_messages))
        .and_then(|g| g.checked_add(REQUEST_GROUP_FIELDS))
        .is_some_and(|g| g <= PAGE_BUDGET)
}

/// Where the groups from `from` that fit `budget` bytes of fields end, at
/// least one however large, and that place again where any are left.
fn page(groups: &[Chunks], from: usize, budget: usize) -> (usize, Option<usize>) {
    let mut used = 0;
    for (i, g) in groups.iter().enumerate().skip(from) {
        let size: usize = g.iter().map(|(_, d)| 4 + d.len()).sum();
        if i > from && used + size > budget {
            return (i, Some(i));
        }
        used += size;
    }
    (groups.len(), None)
}

fn roster_state(s: RosterState) -> WireState {
    match s {
        RosterState::Removed => WireState::Removed,
        RosterState::PendingOut => WireState::PendingOut,
        RosterState::PendingIn => WireState::PendingIn,
        RosterState::Accepted => WireState::Accepted,
        RosterState::Blocked => WireState::Blocked,
    }
}

fn presence_state(p: Presence) -> PresenceState {
    match p {
        Presence::Offline => PresenceState::Offline,
        Presence::Online => PresenceState::Online,
        Presence::Away => PresenceState::Away,
        Presence::Invisible => PresenceState::Invisible,
        Presence::Busy => PresenceState::Busy,
    }
}

fn reason_chunk(r: ReasonCode) -> (u16, Vec<u8>) {
    (tag::REASON_CODE, u16_bytes(r.wire()))
}

fn u16_bytes(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn u32_bytes(n: usize) -> Vec<u8> {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes().to_vec()
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A 16-byte `DATA_MESSAGE_GUID` as the domain keeps one.
fn guid_of(b: &[u8]) -> Option<MessageGuid> {
    if b.len() != 16 {
        return None;
    }
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    MessageGuid::parse(&hex)
}

fn guid_bytes(g: &MessageGuid) -> [u8; 16] {
    let hex: Vec<u8> = g.as_str().bytes().filter(|c| *c != b'-').collect();
    let mut out = [0u8; 16];
    for (o, pair) in out.iter_mut().zip(hex.chunks(2)) {
        *o = std::str::from_utf8(pair)
            .ok()
            .and_then(|p| u8::from_str_radix(p, 16).ok())
            .unwrap_or(0);
    }
    out
}

/// Cut `s` to at most `max` bytes, at a character boundary.
fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut n = max;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::inbox::StoredMessage;
    use hxd_core::messaging::RequestGroup;
    use hxproto::messaging::{parse_entry, parse_message_requests};

    fn message(chunks: &Chunks) -> Vec<u8> {
        let mut v = vec![0u8; hxproto::HL_HDR_LEN];
        for (t, d) in chunks {
            v.extend_from_slice(&t.to_be_bytes());
            v.extend_from_slice(&(d.len() as u16).to_be_bytes());
            v.extend_from_slice(d);
        }
        v
    }

    fn friend(state: RosterState, presence: Presence) -> FriendEntry {
        FriendEntry {
            login: "bob".into(),
            fingerprint: None,
            state,
            alias: Some("Bobby".into()),
            presence,
            status_text: Some("out".into()),
            note: None,
            friendships: Vec::new(),
            offer: None,
            withdraw: None,
        }
    }

    #[test]
    fn an_entry_carries_what_its_state_shows() {
        type Shown<'a> = (Option<&'a [u8]>, Option<u16>, Option<u16>, Option<&'a [u8]>);
        let cases: [(FriendEntry, Shown); 4] = [
            (
                friend(RosterState::Accepted, Presence::Busy),
                (Some(b"Bobby"), Some(3), Some(4), Some(b"out")),
            ),
            // Offline is told by the absence of a presence, and the
            // account's text still shown.
            (
                friend(RosterState::Accepted, Presence::Offline),
                (Some(b"Bobby"), Some(3), None, Some(b"out")),
            ),
            (
                friend(RosterState::Blocked, Presence::Offline),
                (Some(b"Bobby"), Some(4), None, None),
            ),
            // A removal is its login and its state alone.
            (
                friend(RosterState::Removed, Presence::Offline),
                (None, Some(0), None, None),
            ),
        ];
        for (e, want) in cases {
            let m = message(&entry_chunks(&e, TextEncoding::MacRoman, false));
            let got = parse_entry(&m, m.len()).unwrap();
            assert_eq!(got.login, b"bob");
            assert_eq!(
                (got.nickname, got.state, got.presence, got.status_text),
                want,
                "{:?}",
                e.state
            );
        }
    }

    #[test]
    fn get_friendships_answers_what_fits_a_frame() {
        let records = vec![vec![7u8; 512]; 16];
        let fetched = Fetched {
            friendships: vec![([1; 32], Some(vec![2; 2080]))],
            rotations: (0..32u8).map(|n| ([n; 32], records.clone())).collect(),
        };
        let m = message(&fetched_chunks(&fetched));
        assert!(m.len() <= MAX_FRAME_DATA as usize + hxproto::HL_HDR_LEN);
        let answered = hxproto::messaging::parse_friendships(&m, m.len())
            .unwrap()
            .answers()
            .count();
        assert!((2..33).contains(&answered), "{answered} of 33, in order");
    }

    #[test]
    fn a_guid_survives_the_wire() {
        let g = MessageGuid::parse("0123abcd-4567-4890-8bcd-ef0123456789").unwrap();
        assert_eq!(guid_of(&guid_bytes(&g)), Some(g));
        assert_eq!(guid_of(&[0u8; 15]), None);
    }

    fn sender(n: usize) -> Mailbox {
        Mailbox {
            login: format!("s{n}"),
            fingerprint: None,
        }
    }

    fn msg(n: u8) -> StoredMessage {
        StoredMessage {
            id: n.into(),
            reference: [n; 16],
            cursor: n.into(),
            recipient: sender(99),
            sender: Some(sender(n.into())),
            sender_nick: String::new(),
            body: "x".repeat(60_000),
            sent_at: SystemTime::UNIX_EPOCH,
            guid: MessageGuid::parse(&format!("{n:032x}")),
            kind: Default::default(),
            media: None,
            signed: None,
            friendship: None,
            delivered_at: None,
            read_at: None,
        }
    }

    #[test]
    fn a_listing_pages_by_the_frame_and_resumes_at_its_cursor() {
        let listing = RequestsListing {
            requests: (0..6)
                .map(|n| RequestGroup {
                    from: sender(n),
                    messages: vec![msg(n as u8)],
                })
                .collect(),
            approvals: vec![sender(9)],
            dropped: 2,
        };
        let mut from = 0;
        let mut seen = Vec::new();
        loop {
            let m = message(&listing_chunks(
                &listing,
                true,
                from,
                TextEncoding::Utf8,
                false,
            ));
            assert!(m.len() <= MAX_FRAME_DATA as usize + hxproto::HL_HDR_LEN);
            let page = parse_message_requests(&m, m.len()).unwrap();
            let first = from == 0;
            assert_eq!(page.dropped, first.then_some(2));
            assert_eq!(page.takes_requests, first.then_some(true));
            seen.extend(page.groups().map(|g| (g.login.to_vec(), g.is_approval())));
            match page.cursor {
                Some(c) => from = u32::from_be_bytes(c.try_into().unwrap()) as usize,
                None => break,
            }
        }
        let want: Vec<(Vec<u8>, bool)> = (0..6)
            .map(|n| (format!("s{n}").into_bytes(), false))
            .chain([(b"s9".to_vec(), true)])
            .collect();
        assert_eq!(seen, want);
    }

    #[test]
    fn a_group_larger_than_a_frame_is_listed_as_far_as_one_holds() {
        let listing = RequestsListing {
            requests: vec![RequestGroup {
                from: sender(1),
                messages: (10..16).map(msg).collect(),
            }],
            approvals: vec![],
            dropped: 0,
        };
        let m = message(&listing_chunks(
            &listing,
            true,
            0,
            TextEncoding::Utf8,
            false,
        ));
        assert!(m.len() <= MAX_FRAME_DATA as usize + hxproto::HL_HDR_LEN);
        let page = parse_message_requests(&m, m.len()).unwrap();
        assert_eq!(page.cursor, None);
        let groups: Vec<_> = page.groups().collect();
        assert_eq!(groups.len(), 1);
        let listed = groups[0].messages().count();
        assert!((1..6).contains(&listed), "{listed} of 6");
    }
}
