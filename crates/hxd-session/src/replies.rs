//! Replies on the classic wire (the Replies draft, `docs/replies.md`):
//! capability bit 18, `DATA_REPLY_TO` on a line of chat, kept and relayed
//! as sent to the sessions that negotiated it, on Chat Message (106) and
//! in Get Chat History (700) as the entry's sub-field, and 700 by line id
//! for the lines a page's replies answer.
//!
//! The server never looks a target up: every reference is parsed, held
//! to the conversation it is said in by the core's own scope rule, and
//! dropped from the line where it breaks it, since 105 has no reply to
//! refuse it with.
//!
//! The draft's numbers are kept here, as Structured Chat's are in
//! [`crate::structured`], until they are allocated.

use hxd_core::Reply;

use crate::frame::Frame;
use crate::target::{line, EPHEMERAL, LINE};

/// A line's history id, repeated in a 700 that asks for lines by id.
pub const DATA_LINE_ID: u16 = 0x0f20;
/// What a line or message answers, as a packed target.
pub const DATA_REPLY_TO: u16 = 0x0f21;
/// The login reply's: the kinds of target this server keeps, `1 << kind`.
pub const DATA_REPLY_TARGETS: u16 = 0x0f22;

/// An entry's sub-field: the line's `DATA_REPLY_TO` as kept.
pub const REPLY_TO: u16 = 0x0020;

pub const TARGETS_LINES: u16 = 1 << LINE;
pub const TARGETS_EPHEMERAL: u16 = 1 << EPHEMERAL;

/// The longest `DATA_REPLY_TO` the draft allows.
const MAX_PACKED: usize = 128;

/// The most lines one 700 may ask for by id.
const MAX_IDS: usize = 50;

/// The kinds of target a session may name, fixed at its login: kept
/// lines where lines are kept, and lines nobody keeps, a private chat's,
/// a notice's and the unkept lobby's or a room's, always.
pub(crate) fn targets(lines_kept: bool) -> u16 {
    TARGETS_EPHEMERAL | if lines_kept { TARGETS_LINES } else { 0 }
}

/// Where a line is said: the lobby, a room or a private chat by its id.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Said {
    Lobby,
    Room(u32),
    Chat(u32),
}

/// The reference `f` carries, from a session that may name `offered`:
/// `Ok(None)` for none, `Err` with why it is dropped.
pub(crate) fn reply_to(f: &Frame, offered: u16, said: Said) -> Result<Option<Reply>, &'static str> {
    let mut sent = f.chunks().filter(|c| c.tag == DATA_REPLY_TO);
    match (sent.next(), sent.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err("more than one"),
        (Some(c), None) => parse(c.data, offered, said).map(Some),
    }
}

/// The lines a 700 asks for by id, none for a page; `None` past
/// [`MAX_IDS`] or for an id that is not 8 bytes.
pub(crate) fn line_ids(f: &Frame) -> Option<Vec<u64>> {
    let ids: Option<Vec<u64>> = (f.chunks().filter(|c| c.tag == DATA_LINE_ID))
        .map(|c| c.data.try_into().ok().map(u64::from_be_bytes))
        .collect();
    ids.filter(|ids| ids.len() <= MAX_IDS)
}

/// `DATA_REPLY_TO` as sent, said where `said` is. Kind 1 names a kept
/// lobby line on channel 0; kind 4 an unkept line under its chat's id,
/// or in a room where lines are kept, which `offered` says by holding
/// kind 1, the room's kept line, as the room is addressed by its chat id
/// on this wire.
pub(crate) fn parse(b: &[u8], offered: u16, said: Said) -> Result<Reply, &'static str> {
    if b.len() > MAX_PACKED {
        return Err("past the bound");
    }
    let (&kind, rest) = b.split_first().ok_or("empty")?;
    if kind >= 16 || offered & 1 << kind == 0 {
        return Err("a kind not offered");
    }
    if !matches!(kind, LINE | EPHEMERAL) {
        return Err("a kind a line does not take");
    }
    let (chat, id) = line(rest).ok_or("malformed")?;
    if id == 0 {
        return Err("line id 0");
    }
    let (here, room) = match said {
        Said::Lobby => (0, false),
        Said::Room(r) => (r, true),
        Said::Chat(c) => (c, false),
    };
    let re = match kind {
        LINE if here == 0 => Reply::Line { room: chat, id },
        LINE => return Err("kind 1 off the lobby"),
        _ if room && chat == here && offered & TARGETS_LINES != 0 => Reply::Line { room: here, id },
        _ => Reply::Ephemeral { chat, id },
    };
    re.in_room(here).then_some(re).ok_or("out of scope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{IM, PM, STORED};
    use hxproto::messages::tag;

    fn line_bytes(kind: u8, chat: u32, id: u64) -> Vec<u8> {
        [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
    }

    type Parsed = Result<Reply, &'static str>;

    fn no(why: &'static str) -> Parsed {
        Err(why)
    }

    /// Every structural drop, and every kind each place takes, with
    /// lines kept and without.
    #[test]
    fn a_reference_is_taken_only_as_the_draft_allows_where_it_is_said() {
        let (kept, unkept, all) = (targets(true), targets(false), u16::MAX);
        let line = |room, id| Ok(Reply::Line { room, id });
        let eph = |chat, id| Ok(Reply::Ephemeral { chat, id });
        let l = |kind, chat| line_bytes(kind, chat, 9);
        let im = [&[IM][..], &[7; 16], &[3], b"bob"].concat();
        let pm = [&[PM, STORED][..], &[3; 16]].concat();
        let signed = [&[3][..], &[0; 80]].concat();
        let (lb, room, chat) = (Said::Lobby, Said::Room(5), Said::Chat(7));
        let (scope, offer) = ("out of scope", "a kind not offered");
        let kind = "a kind a line does not take";
        let off = "kind 1 off the lobby";
        for (case, bytes, offered, said, want) in [
            ("a lobby line", l(1, 0), kept, lb, line(0, 9)),
            ("a lobby notice", l(4, 0), kept, lb, eph(0, 9)),
            ("the unkept lobby", l(4, 0), unkept, lb, eph(0, 9)),
            ("kind 1 unkept", l(1, 0), unkept, lb, no(offer)),
            ("kind 1 on a room", l(1, 5), kept, lb, no(scope)),
            ("kind 4 off chat 0", l(4, 5), kept, lb, no(scope)),
            ("a kept room", l(4, 5), kept, room, line(5, 9)),
            ("an unkept room", l(4, 5), unkept, room, eph(5, 9)),
            ("another room", l(4, 6), kept, room, no(scope)),
            ("another, unkept", l(4, 6), unkept, room, no(scope)),
            ("the lobby from a room", l(4, 0), kept, room, no(scope)),
            ("kind 1 in a room", l(1, 5), kept, room, no(off)),
            ("kind 1 on 0 in a room", l(1, 0), kept, room, no(off)),
            ("a private chat", l(4, 7), kept, chat, eph(7, 9)),
            ("another chat", l(4, 8), kept, chat, no(scope)),
            ("a room from a chat", l(4, 5), kept, chat, no(scope)),
            ("kind 1 in a chat", l(1, 7), kept, chat, no(off)),
            ("id 0", line_bytes(1, 0, 0), kept, lb, no("line id 0")),
            (
                "ephemeral id 0",
                line_bytes(4, 7, 0),
                kept,
                chat,
                no("line id 0"),
            ),
            ("signed", signed.clone(), kept, lb, no(offer)),
            ("signed, offered", signed, all, lb, no(kind)),
            ("an IM", im.clone(), kept, lb, no(offer)),
            ("an IM, offered", im, all, lb, no(kind)),
            ("a PM", pm.clone(), kept, lb, no(offer)),
            ("a PM, offered", pm, all, lb, no(kind)),
            ("an unknown kind", l(9, 0), all, lb, no(kind)),
            ("a kind past the mask", l(200, 0), all, lb, no(offer)),
            ("short", l(1, 0)[..12].to_vec(), kept, lb, no("malformed")),
            (
                "long",
                [l(1, 0), vec![0]].concat(),
                kept,
                lb,
                no("malformed"),
            ),
            (
                "128 bytes",
                [l(1, 0), vec![0; 115]].concat(),
                kept,
                lb,
                no("malformed"),
            ),
            (
                "past 128",
                [l(1, 0), vec![0; 116]].concat(),
                kept,
                lb,
                no("past the bound"),
            ),
            ("empty", vec![], kept, lb, no("empty")),
        ] {
            assert_eq!(parse(&bytes, offered, said), want, "{case}");
        }
    }

    #[tokio::test]
    async fn a_frame_carries_one_reference_or_none() {
        let field = |id: u64| (DATA_REPLY_TO, line_bytes(1, 0, id));
        let body = (tag::BODY, b"yes".to_vec());
        for (case, fields, want) in [
            ("none", vec![body.clone()], Ok(None)),
            (
                "one",
                vec![field(9), body.clone()],
                Ok(Some(Reply::Line { room: 0, id: 9 })),
            ),
            ("two", vec![field(9), body, field(10)], Err("more than one")),
            (
                "a bad one",
                vec![(DATA_REPLY_TO, vec![1])],
                Err("malformed"),
            ),
        ] {
            let packed = crate::frame::pack_frame(105, 1, 0, &fields);
            let f = crate::frame::read_frame(&mut packed.as_slice())
                .await
                .unwrap();
            assert_eq!(reply_to(&f, targets(true), Said::Lobby), want, "{case}");
        }
    }

    #[tokio::test]
    async fn a_700_asks_for_at_most_50_lines_of_8_byte_ids() {
        let id = |n: u64| (DATA_LINE_ID, n.to_be_bytes().to_vec());
        let channel = (tag::CHANNEL_ID, vec![0; 4]);
        for (case, ids, want) in [
            ("none", vec![], Some(vec![])),
            ("one", vec![id(7)], Some(vec![7])),
            ("50", (1..=50).map(id).collect(), Some((1..=50).collect())),
            ("51", (1..=51).map(id).collect(), None),
            ("7 bytes", vec![id(7), (DATA_LINE_ID, vec![0; 7])], None),
        ] {
            let fields = [vec![channel.clone()], ids].concat();
            let packed = crate::frame::pack_frame(700, 1, 0, &fields);
            let f = crate::frame::read_frame(&mut packed.as_slice())
                .await
                .unwrap();
            assert_eq!(line_ids(&f), want, "{case}");
        }
    }

    /// A target goes back to a reader as this wire addresses its chat.
    #[test]
    fn a_kept_reference_is_named_back_as_its_chat_is_addressed() {
        for (re, want) in [
            (Reply::Line { room: 0, id: 9 }, line_bytes(1, 0, 9)),
            (Reply::Line { room: 5, id: 9 }, line_bytes(4, 5, 9)),
            (Reply::Ephemeral { chat: 0, id: 9 }, line_bytes(4, 0, 9)),
            (Reply::Ephemeral { chat: 5, id: 9 }, line_bytes(4, 5, 9)),
        ] {
            assert_eq!(crate::target::pack(&re), Some(want), "{re:?}");
        }
    }
}
