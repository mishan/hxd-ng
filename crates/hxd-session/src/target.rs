//! A target as the Replies draft packs it, which its companions share:
//! what a reply answers (`crate::replies`) and what a reaction is on
//! (`crate::reactions`). Each reads its own field with these parts, since
//! the kinds each takes differ.

use hxd_core::reply::{guid_bytes, guid_of};
use hxd_core::Reply;

pub(crate) const LINE: u8 = 1;
pub(crate) const IM: u8 = 2;
pub(crate) const EPHEMERAL: u8 = 4;
pub(crate) const PM: u8 = 5;

/// A private message reference's flag for one the server stores.
pub(crate) const STORED: u8 = 1;

/// A line target's fields past its kind: the channel or chat, and the id.
pub(crate) fn line(rest: &[u8]) -> Option<(u32, u64)> {
    let (chat, id) = <&[u8; 12]>::try_from(rest).ok()?.split_at(4);
    Some((
        u32::from_be_bytes(chat.try_into().ok()?),
        u64::from_be_bytes(id.try_into().ok()?),
    ))
}

/// An instant message target's fields past its kind: the guid, then the
/// sender's login.
pub(crate) fn im(rest: &[u8]) -> Option<Reply> {
    let (guid, rest) = rest.split_first_chunk::<16>()?;
    let (&len, login) = rest.split_first()?;
    if login.len() != usize::from(len) {
        return None;
    }
    let login = String::from_utf8(login.to_vec()).ok()?;
    Reply::im(login, guid_of(guid)?)
}

/// `target` as this wire names it to a reader: a lobby line kind 1 on
/// channel 0 and a room's kind 4 under its chat id, however it was
/// asked, since a session names a channel one way, and a line nobody
/// keeps kind 4 under its chat's. A signed target has no form here.
pub(crate) fn pack(target: &Reply) -> Option<Vec<u8>> {
    let line =
        |kind, chat: &u32, id: &u64| [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat();
    Some(match target {
        Reply::Line { room, id } => line(if *room == 0 { LINE } else { EPHEMERAL }, room, id),
        Reply::Ephemeral { chat, id } => line(EPHEMERAL, chat, id),
        Reply::Im(t) => [
            &[IM][..],
            &guid_bytes(t.guid()),
            &[t.login().len() as u8],
            t.login().as_bytes(),
        ]
        .concat(),
        Reply::Pm(r) => [&[PM][..], &crate::reactions::pm_id(r)].concat(),
        Reply::Signed { .. } => return None,
    })
}
