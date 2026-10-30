//! The instant messaging extension on the classic wire, as a client
//! speaks it: requests built by `hxproto`'s builders, the ones GtkHx
//! sends, and replies read with its parsers, so a test of the server is
//! never the server's encoder agreeing with itself.

use hxproto::build::HxChunk;
use hxproto::messages::{tag, ClientHdr};
use hxproto::messaging::{self as m, ReasonCode, SCRATCH_LEN};

use crate::legacy::{Client, Frame};
use crate::Result;

pub type Chunks = Vec<(u16, Vec<u8>)>;

/// What a builder filled, owned. Panics where it refused the request,
/// which is a test asking for something the wire cannot say.
pub fn built(fill: impl FnOnce(&mut [HxChunk], &mut [u8]) -> usize) -> Chunks {
    let mut chunks = [HxChunk::EMPTY; m::MAX_FRIENDSHIP_OBJECTS];
    let mut scratch = [0u8; SCRATCH_LEN];
    let n = fill(&mut chunks, &mut scratch);
    assert!(n > 0, "the builder refused the request");
    chunks[..n]
        .iter()
        .map(|c| {
            let data = if c.len == 0 {
                Vec::new()
            } else {
                // SAFETY: the builder pointed `data` at `len` bytes of an
                // input the caller still holds, or of `scratch`, alive here.
                unsafe { std::slice::from_raw_parts(c.data, c.len.into()) }.to_vec()
            };
            (c.tag, data)
        })
        .collect()
}

pub fn add_friend(login: &[u8], note: Option<&[u8]>) -> Chunks {
    built(|c, s| m::build_add_friend_chunks(login, note, None, c, s))
}

pub fn remove_friend(login: &[u8]) -> Chunks {
    built(|c, s| m::build_remove_friend_chunks(m::Who::Login(login), None, None, c, s))
}

pub fn friend_response(login: &[u8], accept: bool) -> Chunks {
    built(|c, s| m::build_friend_response_chunks(login, accept, None, c, s))
}

pub fn block(login: &[u8]) -> Chunks {
    built(|c, s| m::build_block_user_chunks(login, None, c, s))
}

/// Add Friend (802) carrying an offer.
pub fn add_friend_offering(login: &[u8], offer: &[u8]) -> Chunks {
    built(|c, s| m::build_add_friend_chunks(login, None, Some(offer), c, s))
}

/// Remove Friend (803) naming `who`, carrying an upgrade offer to cancel
/// or a withdrawal.
pub fn remove_friend_with(
    who: m::Who<'_>,
    offer: Option<&[u8]>,
    withdrawal: Option<&[u8]>,
) -> Chunks {
    built(|c, s| m::build_remove_friend_chunks(who, offer, withdrawal, c, s))
}

/// Friend Response (805) accepting with a friendship.
pub fn friend_response_with(login: &[u8], friendship: &[u8]) -> Chunks {
    built(|c, s| m::build_friend_response_chunks(login, true, Some(friendship), c, s))
}

/// Block User (806) carrying a withdrawal.
pub fn block_withdrawing(login: &[u8], withdrawal: &[u8]) -> Chunks {
    built(|c, s| m::build_block_user_chunks(login, Some(withdrawal), c, s))
}

pub fn present_friendships(objects: &[m::Presentation<'_>]) -> Chunks {
    built(|c, s| m::build_present_friendships_chunks(objects, c, s))
}

pub fn get_friendships(asked: &[m::FriendshipQuery<'_>]) -> Chunks {
    built(|c, s| m::build_get_friendships_chunks(asked, c, s))
}

/// Unblock User (807) and Get User Info (825).
pub fn login_only(login: &[u8]) -> Chunks {
    built(|c, s| m::build_login_only_chunks(login, c, s))
}

pub fn set_presence(p: &m::Presence<'_>) -> Chunks {
    built(|c, s| m::build_set_presence_chunks(p, c, s))
}

pub fn im_send(to: &[u8], guid: &[u8; 16], body: &[u8]) -> Chunks {
    let send = m::ImSend {
        to,
        guid,
        content: m::ImContent::Plain(body),
    };
    built(|c, s| m::build_im_send_chunks(&send, c, s))
}

pub fn im_ack(guid: &[u8; 16], ack: m::AckType, sender: &[u8]) -> Chunks {
    built(|c, s| m::build_im_ack_chunks(guid, ack, sender, c, s))
}

pub fn im_typing(login: &[u8], state: m::TypingState) -> Chunks {
    built(|c, s| m::build_im_typing_chunks(login, state, c, s))
}

pub fn find_user(login: &[u8]) -> Chunks {
    find_user_by(m::Who::Login(login))
}

pub fn find_user_by(who: m::Who<'_>) -> Chunks {
    built(|c, s| m::build_find_user_chunks(who, c, s))
}

pub fn set_friend_nickname(login: &[u8], nickname: &[u8]) -> Chunks {
    built(|c, s| m::build_set_friend_nickname_chunks(login, nickname, c, s))
}

/// Get Message Requests (829): the first page goes bare.
pub fn get_message_requests(cursor: Option<&[u8]>) -> Chunks {
    match cursor {
        None => Vec::new(),
        Some(cur) => built(|c, s| m::build_get_message_requests_chunks(cur, c, s)),
    }
}

pub fn answer_message_request(login: &[u8], action: m::RequestAction) -> Chunks {
    built(|c, s| m::build_answer_message_request_chunks(login, action, c, s))
}

/// Clear Message Requests (831): everything goes bare.
pub fn clear_message_requests(since: Option<u64>, before: Option<u64>) -> Chunks {
    if since.is_none() && before.is_none() {
        return Vec::new();
    }
    built(|c, s| m::build_clear_message_requests_chunks(since, before, c, s))
}

/// A reply's `DATA_REASON_CODE`, where it carries one.
pub fn reason(f: &Frame) -> Option<ReasonCode> {
    let r = f.chunk(tag::REASON_CODE)?;
    ReasonCode::from_wire(u16::try_from(r.as_uint()).ok()?)
}

impl Client {
    /// Send one of the extension's requests and wait for its reply, an
    /// error reply included.
    pub async fn ask(&mut self, hdr: ClientHdr, chunks: &[(u16, Vec<u8>)]) -> Result<Frame> {
        let trans = self.send(hdr.as_u32(), chunks).await?;
        self.reply(trans).await
    }
}
