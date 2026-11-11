//! Reactions on the classic wire (the Reactions draft): capability bit
//! 19, Send Reaction (710) and Get Reactions (712) on the lines of the
//! log, Reaction Changed (711) for every change the core tells a session
//! that negotiated it, a line's reactions on its 700 entry, and Set
//! Notifications (717) answered with no type.
//!
//! Only a session that negotiated bit 19, beside bits 1 and 17, is
//! answered here or sent any of it; to every other these transactions do
//! not exist. Who may react, the caps, the rate, the batches and who is
//! told are `hxd_core::reaction`'s: this is a translation of its calls.
//!
//! The draft's numbers are kept here, as Structured Chat's are in
//! [`crate::structured`], until they are allocated.

use std::time::Instant;

use hxd_core::reply::{guid_bytes, guid_of};
use hxd_core::{Asked, ReactError, ReactionChange, ReactionKey, ReactionPolicy, Reply};

use crate::encoding::TextEncoding;
use crate::frame::Frame;
use crate::friends::PAGE_BUDGET;
use crate::structured::{
    INVALID_TARGET, NOT_ALLOWED, NO_SUCH_TARGET, RATE_LIMITED, TOO_MANY_TARGETS,
};

type Chunks = Vec<(u16, Vec<u8>)>;

pub const SEND: u32 = 710;
pub const CHANGED: u32 = 711;
pub const GET: u32 = 712;
/// The Replies draft's Set Notifications, which a session with bit 19
/// may send too.
pub const SET_NOTIFICATIONS: u32 = 717;

pub const DATA_TARGET: u16 = 0x0f24;
pub const DATA_REACTION_KEY: u16 = 0x0f25;
pub const DATA_REACTION_ACTION: u16 = 0x0f26;
pub const DATA_REACTION_COUNT: u16 = 0x0f27;
pub const DATA_REACTION_SUMMARY: u16 = 0x0f29;
pub const DATA_REACTION_TARGETS: u16 = 0x0f2b;
pub const DATA_MAX_REACTION_KEYS: u16 = 0x0f2c;
pub const DATA_MAX_REACTIONS_PER_USER: u16 = 0x0f2d;
pub const DATA_REACTION_MINE: u16 = 0x0f31;
/// The Replies draft's: the notification types a session asks for, and
/// is granted.
pub const DATA_NOTIFY_TYPES: u16 = 0x0f2e;

/// A 700 entry's sub-fields: the line's `DATA_REACTION_SUMMARY`, and the
/// reader's `DATA_REACTION_MINE`.
pub const REACTIONS: u16 = 0x0021;
pub const REACTIONS_MINE: u16 = 0x0023;

/// The most targets one 712 names.
const MAX_TARGETS: usize = 50;

/// `DATA_FRIEND_LOGIN`, the instant messaging extension's: an instant
/// message's other party, and in a change group its reactor.
const DATA_FRIEND_LOGIN: u16 = hxproto::messages::tag::FRIEND_LOGIN;

/// The draft's reason codes, in Structured Chat's `DATA_CHAT_REASON`.
pub const INVALID_KEY: u16 = 3;
pub const TOO_MANY_KEYS: u16 = 4;
pub const TOO_MANY_OF_YOURS: u16 = 5;

pub const ADD: u16 = 1;
pub const REMOVE: u16 = 2;
pub const CLEAR: u16 = 3;
pub const SUMMARY: u16 = 4;

const LINE: u8 = 1;
const IM: u8 = 2;
const EPHEMERAL: u8 = 4;
const PM: u8 = 5;

/// A private message reference's flag for one the server stores.
const STORED: u8 = 1;

/// `DATA_REACTION_TARGETS`' bits: `1 << kind`, and bit 6 for stored
/// private messages.
pub const TARGETS_LINES: u16 = 1 << LINE;
pub const TARGETS_EPHEMERAL: u16 = 1 << EPHEMERAL;
pub const TARGETS_STORED_PMS: u16 = 1 << 6;

/// What a moderator's clear is recorded with: 710 carries no reason, and
/// the trail takes no clear without one.
pub const CLEAR_REASON: &str = "Cleared on the classic wire.";

/// Is `ty` one of the requests a session with bit 19 may send?
pub(crate) fn handles(ty: u32) -> bool {
    matches!(ty, SEND | GET | SET_NOTIFICATIONS)
}

/// What each costs a session that negotiated bit 19: a reaction what a
/// line or a message does, a 712 more the more targets it names, as the
/// draft asks, and a 717 what any small request does.
pub(crate) fn price(f: &Frame) -> Option<u32> {
    match f.ty {
        SEND => Some(2),
        GET => Some(get_price(
            f.chunks().filter(|c| c.tag == DATA_TARGET).count(),
        )),
        SET_NOTIFICATIONS => Some(1),
        _ => None,
    }
}

fn get_price(targets: usize) -> u32 {
    1 + targets.div_ceil(10) as u32
}

/// What 717, and a login that asks, is answered: no type, since this
/// server sends no notification.
pub(crate) fn notify_types() -> (u16, Vec<u8>) {
    (DATA_NOTIFY_TYPES, 0u32.to_be_bytes().to_vec())
}

/// The kinds of target this session may name, fixed at its login: lines
/// always, and a room's, which this wire shows as a private chat, as
/// kind 4 under its chat id where there are rooms.
pub(crate) fn targets(rooms: bool) -> u16 {
    TARGETS_LINES | if rooms { TARGETS_EPHEMERAL } else { 0 }
}

/// The login reply's fields beside a confirmed bit 19.
pub(crate) fn login_fields(policy: &ReactionPolicy, targets: u16) -> Chunks {
    vec![
        (DATA_REACTION_TARGETS, targets.to_be_bytes().to_vec()),
        (
            DATA_MAX_REACTION_KEYS,
            (policy.max_keys as u32).to_be_bytes().to_vec(),
        ),
        (
            DATA_MAX_REACTIONS_PER_USER,
            (policy.max_per_user as u32).to_be_bytes().to_vec(),
        ),
    ]
}

/// A target as the wire named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// One the core can look for.
    Named(Reply),
    /// Kind 4 on chat 0: an ephemeral public line, which this server
    /// neither numbers nor keeps.
    Unheld,
}

/// `DATA_TARGET` as sent, of a kind in `offered`, or `None`: the draft's
/// `InvalidTarget`. Kind 1 names a lobby line on channel 0, and is taken
/// on a room's id as that room's line; kind 4 names a room's line under
/// the chat id it is shown by.
pub(crate) fn parse_target(b: &[u8], offered: u16) -> Option<Target> {
    let (&kind, rest) = b.split_first()?;
    let bit = match (kind, rest.first()) {
        (PM, Some(&flags)) if flags & STORED != 0 => TARGETS_STORED_PMS,
        (PM, _) => return None,
        (kind, _) if kind < 16 => 1 << kind,
        _ => return None,
    };
    if offered & bit == 0 {
        return None;
    }
    let line = |rest: &[u8]| {
        let (chat, id) = <&[u8; 12]>::try_from(rest).ok()?.split_at(4);
        Some((
            u32::from_be_bytes(chat.try_into().ok()?),
            u64::from_be_bytes(id.try_into().ok()?),
        ))
    };
    match kind {
        LINE => line(rest).map(|(room, id)| Target::Named(Reply::Line { room, id })),
        EPHEMERAL => line(rest).map(|(chat, id)| match chat {
            0 => Target::Unheld,
            room => Target::Named(Reply::Line { room, id }),
        }),
        IM => {
            let (guid, rest) = rest.split_first_chunk::<16>()?;
            let (&len, login) = rest.split_first()?;
            if login.len() != usize::from(len) {
                return None;
            }
            let login = String::from_utf8(login.to_vec()).ok()?;
            Reply::im(login, guid_of(guid)?).map(Target::Named)
        }
        PM => <[u8; 17]>::try_from(rest)
            .ok()
            .map(|r| Target::Named(Reply::Pm(r[1..].try_into().expect("16 bytes")))),
        _ => None,
    }
}

/// `target` as this wire names it to a reader: a lobby line kind 1 on
/// channel 0 and a room's kind 4 under its chat id, however it was
/// asked, since a session names a channel one way. A signed target has
/// no form here.
pub(crate) fn pack_target(target: &Reply) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match target {
        Reply::Line { room, id } => {
            out.push(if *room == 0 { LINE } else { EPHEMERAL });
            out.extend_from_slice(&room.to_be_bytes());
            out.extend_from_slice(&id.to_be_bytes());
        }
        Reply::Im(t) => {
            out.push(IM);
            out.extend_from_slice(&guid_bytes(t.guid()));
            out.push(t.login().len() as u8);
            out.extend_from_slice(t.login().as_bytes());
        }
        Reply::Pm(r) => {
            out.extend_from_slice(&[PM, STORED]);
            out.extend_from_slice(r);
        }
        Reply::Signed { .. } => return None,
    }
    Some(out)
}

/// `DATA_REACTION_KEY` as sent: one emoji, or from a session that
/// negotiated bit 20 one of the server's by id. What one emoji is, is
/// the core's to say.
pub(crate) fn parse_key(b: &[u8], emoji: bool) -> Option<ReactionKey> {
    match b.split_first()? {
        // Bounded as sent, which the core's spelling of a key may shorten.
        (1, text) if text.len() <= hxd_core::reaction::MAX_KEY_BYTES => {
            ReactionKey::emoji(std::str::from_utf8(text).ok()?)
        }
        (2, id) if emoji => Some(ReactionKey::Custom(hxd_core::emoji::EmojiId(
            u32::from_be_bytes(id.try_into().ok()?),
        ))),
        _ => None,
    }
}

/// `DATA_REACTION_SUMMARY`: `u16 n`, then `n` entries of `u32 count`,
/// `u16 key_len` and the packed key, in the order the keys came.
pub(crate) fn summary(keys: &[(ReactionKey, u32)]) -> Vec<u8> {
    let mut out = (keys.len() as u16).to_be_bytes().to_vec();
    for (key, count) in keys {
        let key = key.pack();
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(&key);
    }
    out
}

/// `DATA_REACTION_MINE`: `u8 n`, then the reader's indexes into the
/// summary.
pub(crate) fn mine(indexes: &[u8]) -> Vec<u8> {
    [&[indexes.len() as u8][..], indexes].concat()
}

/// What Send Reaction (710) asks, once its fields are read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Send {
    /// One key added to, or taken from, a line.
    Line {
        room: u32,
        id: u64,
        key: ReactionKey,
        add: bool,
    },
    /// Every reaction on a line taken by a moderator.
    Clear { room: u32, id: u64 },
    /// Kind 4 on chat 0, well formed, a clear or not, answered by the
    /// frontend once it has said who may react or clear.
    Unheld { clearing: bool },
}

/// Why a 710 or a 712 was refused as malformed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Malformed {
    Target,
    Key,
    /// No action the draft defines, for which it has no code.
    Action,
    /// More targets than a 712 takes, a key beside more than one, or a
    /// reply past one frame.
    TooManyTargets,
}

/// A [`Malformed`] request's text and reason code.
pub(crate) fn malformed(m: Malformed) -> (&'static str, Option<u16>) {
    match m {
        Malformed::Target => (
            "That is not a target this server takes.",
            Some(INVALID_TARGET),
        ),
        Malformed::Key => ("That is not a reaction.", Some(INVALID_KEY)),
        Malformed::Action => ("Malformed request.", None),
        Malformed::TooManyTargets => ("Too many targets for one request.", Some(TOO_MANY_TARGETS)),
    }
}

/// 710's fields, from a session that may name `offered`, and with
/// `emoji`, the server's emoji: the target first, then the action,
/// then the key, which a clear does not take.
pub(crate) fn parse_send<'a>(
    fields: impl Iterator<Item = (u16, &'a [u8])> + Clone,
    offered: u16,
    emoji: bool,
) -> Result<Send, Malformed> {
    let field = |tag| fields.clone().find(|(t, _)| *t == tag).map(|(_, d)| d);
    let target = field(DATA_TARGET)
        .and_then(|b| parse_target(b, offered))
        .ok_or(Malformed::Target)?;
    let line = match target {
        Target::Named(Reply::Line { room, id }) => Some((room, id)),
        Target::Unheld => None,
        Target::Named(_) => return Err(Malformed::Target),
    };
    let action = field(DATA_REACTION_ACTION)
        .filter(|d| matches!(d.len(), 2 | 4))
        .map(|d| d.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)));
    let add = match action {
        Some(3) => {
            return Ok(match line {
                Some((room, id)) => Send::Clear { room, id },
                None => Send::Unheld { clearing: true },
            })
        }
        Some(1) => true,
        Some(2) => false,
        _ => return Err(Malformed::Action),
    };
    let key = field(DATA_REACTION_KEY)
        .and_then(|k| parse_key(k, emoji))
        .ok_or(Malformed::Key)?;
    Ok(match line {
        Some((room, id)) => Send::Line { room, id, key, add },
        None => Send::Unheld { clearing: false },
    })
}

/// 712's fields: 1 to [`MAX_TARGETS`] targets, counted before any is
/// read, of the kinds kept to be read again, and a key beside one alone.
/// A line nobody keeps is left out, as the core leaves out one it does
/// not hold.
pub(crate) fn parse_get<'a>(
    fields: impl Iterator<Item = (u16, &'a [u8])> + Clone,
    offered: u16,
    emoji: bool,
) -> Result<(Vec<Reply>, Option<ReactionKey>), Malformed> {
    let sent = || fields.clone().filter(|(t, _)| *t == DATA_TARGET);
    let n = sent().count();
    if n == 0 {
        return Err(Malformed::Target);
    }
    if n > MAX_TARGETS {
        return Err(Malformed::TooManyTargets);
    }
    let mut targets = Vec::with_capacity(n);
    for (_, b) in sent() {
        match parse_target(b, offered) {
            Some(Target::Named(Reply::Im(_))) | None => return Err(Malformed::Target),
            Some(Target::Named(t)) => targets.push(t),
            Some(Target::Unheld) => {}
        }
    }
    let key = match fields.clone().find(|(t, _)| *t == DATA_REACTION_KEY) {
        None => None,
        Some(_) if n != 1 => return Err(Malformed::TooManyTargets),
        Some((_, k)) => Some(parse_key(k, emoji).ok_or(Malformed::Key)?),
    };
    Ok((targets, key))
}

/// 712's reply: a group for each target answered, in the order asked,
/// and with a key who holds it, by the nick each reacted under. `None`
/// past what one frame carries, which only targets at the largest caps
/// reach.
pub(crate) fn asked(answers: &[Asked], enc: TextEncoding) -> Option<Chunks> {
    let mut out = Chunks::new();
    for a in answers {
        let Some(target) = pack_target(&a.target) else {
            continue;
        };
        out.push((DATA_TARGET, target));
        out.push((DATA_REACTION_SUMMARY, summary(&a.shown.keys)));
        if !a.shown.mine.is_empty() {
            out.push((DATA_REACTION_MINE, mine(&a.shown.mine)));
        }
        let from = a.from.iter().flatten();
        out.extend(from.map(|nick| {
            (
                hxproto::messages::tag::NAME,
                crate::session::wire_nick(enc, nick),
            )
        }));
    }
    (group_len(&out) <= PAGE_BUDGET).then_some(out)
}

/// A refusal's text and reason code: none where the draft has none.
pub(crate) fn refusal(e: Option<ReactError>, clearing: bool) -> (&'static str, Option<u16>) {
    let not_allowed = if clearing {
        "You may not clear reactions."
    } else {
        "You may not react to that."
    };
    match e {
        Some(ReactError::NoSuchTarget) => ("No such line or message.", Some(NO_SUCH_TARGET)),
        Some(ReactError::NotAllowed | ReactError::Protected) => (not_allowed, Some(NOT_ALLOWED)),
        Some(ReactError::TooManyKeys) => (
            "That line has as many kinds of reaction as it may.",
            Some(TOO_MANY_KEYS),
        ),
        Some(ReactError::TooManyOfYours) => (
            "You have as many reactions there as you may.",
            Some(TOO_MANY_OF_YOURS),
        ),
        Some(ReactError::RateLimited(_)) => ("Slow down.", Some(RATE_LIMITED)),
        Some(ReactError::NoSuchEmoji) => ("No such emoji.", Some(crate::emoji::NO_SUCH_EMOJI)),
        Some(ReactError::OutOfScope | ReactError::NotAvailable) => (
            "That is not a target this server takes.",
            Some(INVALID_TARGET),
        ),
        Some(ReactError::BadRequest(_) | ReactError::ServerError) | None => ("Server error.", None),
    }
}

/// How many bytes of line summaries a session may be sent in a burst,
/// and how fast it earns them back: a purge owes every room it touched
/// at once, each room's summaries whole, and together they would pass
/// what one connection may have queued.
const SUMMARY_BURST: f64 = (1 << 20) as f64;
const SUMMARY_PER_SECOND: f64 = (256 << 10) as f64;

/// One session's allowance of line summaries. A summary past it is not
/// sent, the line left to be read again, as one outside the live window
/// is.
#[derive(Debug)]
pub(crate) struct SummaryBudget {
    bytes: f64,
    at: Instant,
}

impl SummaryBudget {
    pub(crate) fn new(now: Instant) -> Self {
        SummaryBudget {
            bytes: SUMMARY_BURST,
            at: now,
        }
    }

    fn take(&mut self, n: usize, now: Instant) -> bool {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() * SUMMARY_PER_SECOND;
        self.bytes = (self.bytes + earned).min(SUMMARY_BURST);
        self.at = now;
        if self.bytes < n as f64 {
            return false;
        }
        self.bytes -= n as f64;
        true
    }
}

fn group_len(group: &Chunks) -> usize {
    group.iter().map(|(_, d)| 4 + d.len()).sum()
}

/// One [`ReactionChange`] as its group, or `None` where this session is
/// sent nothing of it: a signed target, a stored message's to a messenger
/// session, which holds no reference to match it by, and a line's summary
/// past `budget`.
fn group(
    change: &ReactionChange,
    enc: TextEncoding,
    messenger: bool,
    budget: &mut SummaryBudget,
    now: Instant,
) -> Option<Chunks> {
    let target = match change {
        ReactionChange::Summary { target, .. }
        | ReactionChange::Clear { target }
        | ReactionChange::Changed { target, .. } => target,
    };
    if messenger && matches!(target, Reply::Pm(_)) {
        return None;
    }
    let action = |a: u16| (DATA_REACTION_ACTION, a.to_be_bytes().to_vec());
    let mut g = vec![(DATA_TARGET, pack_target(target)?)];
    match change {
        ReactionChange::Summary { keys, mine: m, .. } => {
            g.push(action(SUMMARY));
            g.push((DATA_REACTION_SUMMARY, summary(keys)));
            if !m.is_empty() {
                g.push((DATA_REACTION_MINE, mine(m)));
            }
            if matches!(target, Reply::Line { .. }) && !budget.take(group_len(&g), now) {
                hxd_core::instrument::reaction_summary_skipped("legacy");
                return None;
            }
        }
        ReactionChange::Clear { .. } => g.push(action(CLEAR)),
        ReactionChange::Changed { key, add, from, .. } => {
            g.push(action(if *add { ADD } else { REMOVE }));
            g.push((DATA_REACTION_KEY, key.pack()));
            g.push((DATA_FRIEND_LOGIN, enc.encode(from)));
        }
    }
    Some(g)
}

/// One `Event::ReactionsChanged` as Reaction Changed (711) frames, its
/// groups in the event's order, split between groups where a frame
/// would pass [`PAGE_BUDGET`].
pub(crate) fn changed(
    changes: &[ReactionChange],
    enc: TextEncoding,
    messenger: bool,
    budget: &mut SummaryBudget,
    now: Instant,
) -> Vec<Chunks> {
    let mut frames: Vec<Chunks> = Vec::new();
    let mut used = PAGE_BUDGET;
    for g in changes
        .iter()
        .filter_map(|c| group(c, enc, messenger, budget, now))
    {
        let len = group_len(&g);
        if used + len > PAGE_BUDGET {
            frames.push(Vec::new());
            used = 0;
        }
        used += len;
        frames.last_mut().expect("a frame").extend(g);
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use hxd_core::emoji::EmojiId;

    const ALL: u16 = TARGETS_LINES | 1 << IM | TARGETS_EPHEMERAL | TARGETS_STORED_PMS;

    fn line_bytes(kind: u8, chat: u32, id: u64) -> Vec<u8> {
        [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
    }

    fn guid() -> hxd_core::inbox::MessageGuid {
        guid_of(&[7; 16]).unwrap()
    }

    fn im_bytes(login: &[u8], len: u8) -> Vec<u8> {
        [&[IM][..], &[7; 16], &[len], login].concat()
    }

    fn thumbs() -> ReactionKey {
        ReactionKey::emoji("👍").unwrap()
    }

    #[test]
    fn targets_are_read_as_the_draft_lays_them_out() {
        let line = |room, id| Some(Target::Named(Reply::Line { room, id }));
        let long_login = vec![b'a'; hxd_core::reply::MAX_PACKED - 17];
        for (case, bytes, offered, want) in [
            ("a lobby line", line_bytes(1, 0, 9), ALL, line(0, 9)),
            ("kind 1 on a room", line_bytes(1, 5, 9), ALL, line(5, 9)),
            ("kind 4 on a room", line_bytes(4, 5, 9), ALL, line(5, 9)),
            (
                "kind 4 on chat 0",
                line_bytes(4, 0, 9),
                ALL,
                Some(Target::Unheld),
            ),
            (
                "an instant message",
                im_bytes(b"bob", 3),
                ALL,
                Some(Target::Named(Reply::im("bob".into(), guid()).unwrap())),
            ),
            ("an empty login", im_bytes(b"", 0), ALL, None),
            (
                "a login past the bound",
                im_bytes(&long_login, long_login.len() as u8),
                ALL,
                None,
            ),
            ("a login cut short", im_bytes(b"bo", 3), ALL, None),
            ("a login that is not UTF-8", im_bytes(b"\xff", 1), ALL, None),
            (
                "a stored message",
                [&[PM, STORED][..], &[3; 16]].concat(),
                ALL,
                Some(Target::Named(Reply::Pm([3; 16]))),
            ),
            (
                "an unstored message",
                [&[PM, 0][..], &[3; 16]].concat(),
                ALL,
                None,
            ),
            ("a message cut short", vec![PM, STORED, 3], ALL, None),
            ("signed", [&[3][..], &[0; 80]].concat(), u16::MAX, None),
            ("an unknown kind", line_bytes(9, 0, 9), u16::MAX, None),
            (
                "a kind past the field",
                line_bytes(200, 0, 9),
                u16::MAX,
                None,
            ),
            ("short", line_bytes(1, 0, 9)[..12].to_vec(), ALL, None),
            ("long", [line_bytes(1, 0, 9), vec![0]].concat(), ALL, None),
            ("empty", vec![], ALL, None),
            (
                "lines not offered",
                line_bytes(1, 0, 9),
                TARGETS_EPHEMERAL,
                None,
            ),
            (
                "kind 4 not offered",
                line_bytes(4, 5, 9),
                TARGETS_LINES,
                None,
            ),
            (
                "an IM not offered",
                im_bytes(b"bob", 3),
                TARGETS_LINES,
                None,
            ),
            (
                "a stored message not offered",
                [&[PM, STORED][..], &[3; 16]].concat(),
                TARGETS_LINES | 1 << PM,
                None,
            ),
        ] {
            assert_eq!(parse_target(&bytes, offered), want, "{case}");
        }
    }

    /// A target goes back to a reader as this wire names its channel,
    /// whichever kind it was asked in.
    #[test]
    fn a_target_is_named_back_by_how_its_channel_is_addressed() {
        let back = |b: Vec<u8>| match parse_target(&b, ALL) {
            Some(Target::Named(r)) => pack_target(&r),
            other => panic!("{other:?}"),
        };
        assert_eq!(back(line_bytes(1, 0, 9)), Some(line_bytes(1, 0, 9)));
        assert_eq!(back(line_bytes(1, 5, 9)), Some(line_bytes(4, 5, 9)));
        assert_eq!(back(line_bytes(4, 5, 9)), Some(line_bytes(4, 5, 9)));
        assert_eq!(back(im_bytes(b"bob", 3)), Some(im_bytes(b"bob", 3)));
        let pm = [&[PM, STORED][..], &[3; 16]].concat();
        assert_eq!(back(pm.clone()), Some(pm));
        let signed = Reply::Signed {
            signer: [0; 32],
            id: [0; 16],
            hash: [0; 32],
        };
        assert_eq!(pack_target(&signed), None);
    }

    #[test]
    fn keys_are_read_as_the_draft_lays_them_out() {
        let party = "🎉".as_bytes();
        // One ZWJ sequence of 64 bytes.
        let longest = format!("😀\u{200d}{}", ["😀\u{fe0f}"; 6].join("\u{200d}"));
        assert_eq!(longest.len(), 64);
        // One of 65, which the core spells shorter without its U+FE0Fs.
        let past = ["😀\u{fe0f}"; 4].join("\u{200d}") + &"\u{200d}😀".repeat(4);
        assert_eq!(past.len(), 65);
        assert!(ReactionKey::emoji(&past).is_some());
        let emoji = |s: &str| ReactionKey::emoji(s);
        for (case, bytes, server_emoji, want) in [
            ("one emoji", [&[1][..], party].concat(), false, emoji("🎉")),
            ("empty", vec![1], false, None),
            ("one byte", vec![1, b'a'], false, None),
            ("no kind", vec![], false, None),
            (
                "64 bytes",
                [&[1][..], longest.as_bytes()].concat(),
                false,
                emoji(&longest),
            ),
            (
                "65 bytes",
                [&[1][..], past.as_bytes()].concat(),
                false,
                None,
            ),
            ("not UTF-8", vec![1, 0xff], false, None),
            (
                "a server's",
                vec![2, 0, 0, 1, 2],
                true,
                Some(ReactionKey::Custom(EmojiId(0x102))),
            ),
            (
                "a server's without bit 20",
                vec![2, 0, 0, 1, 2],
                false,
                None,
            ),
            ("a server's cut short", vec![2, 0, 0, 1], true, None),
            ("a server's too long", vec![2, 0, 0, 1, 2, 3], true, None),
            ("an unknown kind", [&[3][..], party].concat(), true, None),
        ] {
            assert_eq!(parse_key(&bytes, server_emoji), want, "{case}");
        }
        assert!(emoji(&longest).is_some(), "the 64-byte case is one emoji");
    }

    #[test]
    fn a_summary_and_mine_are_packed_as_the_draft_lays_them_out() {
        let keys = [
            (thumbs(), 3),
            (ReactionKey::Custom(EmojiId(0x0102_0304)), 1),
        ];
        let want = [
            &[0, 2][..],
            &[0, 0, 0, 3],
            &[0, 5],
            &[1],
            "👍".as_bytes(),
            &[0, 0, 0, 1],
            &[0, 5],
            &[2, 1, 2, 3, 4],
        ]
        .concat();
        assert_eq!(summary(&keys), want);
        assert_eq!(summary(&[]), [0, 0]);
        assert_eq!(mine(&[0, 1]), [2, 0, 1]);
    }

    fn line_summary(id: u64, keys: usize, mine: Vec<u8>) -> ReactionChange {
        let keys: Vec<_> = (0..keys)
            .map(|i| (ReactionKey::Custom(EmojiId(i as u32)), 1))
            .collect();
        ReactionChange::Summary {
            target: Reply::Line { room: 0, id },
            keys: Arc::from(keys),
            mine,
        }
    }

    fn sent(changes: &[ReactionChange], messenger: bool) -> Vec<Chunks> {
        let now = Instant::now();
        changed(
            changes,
            TextEncoding::Utf8,
            messenger,
            &mut SummaryBudget::new(now),
            now,
        )
    }

    fn action(a: u16) -> (u16, Vec<u8>) {
        (DATA_REACTION_ACTION, a.to_be_bytes().to_vec())
    }

    #[test]
    fn each_change_is_its_group() {
        let im = Reply::im("bob".into(), guid()).unwrap();
        let changes = [
            line_summary(9, 1, vec![0]),
            line_summary(10, 0, vec![]),
            ReactionChange::Clear {
                target: Reply::Line { room: 5, id: 9 },
            },
            ReactionChange::Changed {
                target: im,
                key: thumbs(),
                add: false,
                from: "alice".into(),
            },
            ReactionChange::Summary {
                target: Reply::Pm([3; 16]),
                keys: Arc::from(vec![(thumbs(), 1)]),
                mine: vec![],
            },
        ];
        let custom = [&[0, 1][..], &[0, 0, 0, 1], &[0, 5], &[2, 0, 0, 0, 0]].concat();
        let pm = [&[PM, STORED][..], &[3; 16]].concat();
        let want = vec![
            (DATA_TARGET, line_bytes(1, 0, 9)),
            action(SUMMARY),
            (DATA_REACTION_SUMMARY, custom),
            (DATA_REACTION_MINE, vec![1, 0]),
            (DATA_TARGET, line_bytes(1, 0, 10)),
            action(SUMMARY),
            (DATA_REACTION_SUMMARY, vec![0, 0]),
            (DATA_TARGET, line_bytes(4, 5, 9)),
            action(CLEAR),
            (DATA_TARGET, im_bytes(b"bob", 3)),
            action(REMOVE),
            (DATA_REACTION_KEY, thumbs().pack()),
            (DATA_FRIEND_LOGIN, b"alice".to_vec()),
            (DATA_TARGET, pm.clone()),
            action(SUMMARY),
            (DATA_REACTION_SUMMARY, summary(&[(thumbs(), 1)])),
        ];
        assert_eq!(sent(&changes, false), std::slice::from_ref(&want));
        // A messenger session holds no message reference to match by.
        let without_pm = want[..want.len() - 3].to_vec();
        assert_eq!(sent(&changes, true), [without_pm]);
    }

    /// The worst group the core can send: every key a line may carry, at
    /// the longest a key is, and the reader holding the most it may.
    fn worst(id: u64) -> ReactionChange {
        ReactionChange::Summary {
            target: Reply::Line { room: 7, id },
            keys: worst_keys(),
            mine: vec![0; 255],
        }
    }

    fn worst_keys() -> Arc<[(ReactionKey, u32)]> {
        let key = ReactionKey::Emoji("x".repeat(hxd_core::reaction::MAX_KEY_BYTES));
        vec![(key, u32::MAX); hxd_core::reaction::MAX_KEYS_CEILING].into()
    }

    #[test]
    fn a_711_is_split_between_groups_at_the_frame_budget() {
        let groups: Vec<_> = (0..30).map(worst).collect();
        let now = Instant::now();
        let frames = changed(
            &groups,
            TextEncoding::Utf8,
            false,
            &mut SummaryBudget::new(now),
            now,
        );
        assert!(frames.len() > 1);
        let mut ids = Vec::new();
        for f in &frames {
            assert!(group_len(f) <= PAGE_BUDGET);
            assert_eq!(f[0].0, DATA_TARGET, "a frame starts a group");
            ids.extend(
                f.iter()
                    .filter(|(t, _)| *t == DATA_TARGET)
                    .map(|(_, d)| u64::from_be_bytes(d[5..].try_into().unwrap())),
            );
        }
        assert_eq!(ids, (0..30).collect::<Vec<_>>(), "every group, in order");
        let one = sent(&[worst(0)], false);
        assert_eq!(one.len(), 1);
    }

    /// Line summaries are sent within a byte allowance earned back over
    /// time; what nothing else would tell the client is always sent.
    #[test]
    fn line_summaries_past_the_budget_are_skipped_and_nothing_else_is() {
        let start = Instant::now();
        let mut budget = SummaryBudget::new(start);
        let worst_len = group_len(&sent(&[worst(0)], false)[0]);
        let fit = (SUMMARY_BURST as usize) / worst_len;
        let lines: Vec<_> = (0..fit as u64 + 1).map(worst).collect();
        let count = |frames: &[Chunks]| {
            frames
                .iter()
                .flatten()
                .filter(|(t, _)| *t == DATA_TARGET)
                .count()
        };
        let go = |budget: &mut SummaryBudget, changes: &[ReactionChange], at| {
            changed(changes, TextEncoding::Utf8, false, budget, at)
        };
        assert_eq!(count(&go(&mut budget, &lines, start)), fit);
        let always = [
            ReactionChange::Clear {
                target: Reply::Line { room: 0, id: 1 },
            },
            ReactionChange::Changed {
                target: Reply::im("bob".into(), guid()).unwrap(),
                key: thumbs(),
                add: true,
                from: "alice".into(),
            },
            ReactionChange::Summary {
                target: Reply::Pm([3; 16]),
                keys: worst_keys(),
                mine: vec![],
            },
        ];
        assert_eq!(count(&go(&mut budget, &always, start)), always.len());
        assert_eq!(count(&go(&mut budget, &lines[..1], start)), 0, "spent");
        let refilled = start + Duration::from_secs_f64(worst_len as f64 / SUMMARY_PER_SECOND);
        assert_eq!(count(&go(&mut budget, &lines[..2], refilled)), 1);
        let later = refilled + Duration::from_secs(3600);
        assert_eq!(
            count(&go(&mut budget, &lines, later)),
            fit,
            "no more than the burst"
        );
    }

    #[test]
    fn the_targets_offered_follow_the_rooms() {
        assert_eq!(targets(false), 0x0002);
        assert_eq!(targets(true), 0x0012);
    }

    #[test]
    fn a_710_is_read_target_action_then_key() {
        let lobby = line_bytes(1, 0, 9);
        let key = thumbs().pack();
        let act = |a: u16| a.to_be_bytes().to_vec();
        let wide = 1u32.to_be_bytes().to_vec();
        let line = |add| {
            Ok(Send::Line {
                room: 0,
                id: 9,
                key: thumbs(),
                add,
            })
        };
        for (case, fields, want) in [
            (
                "add",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, act(1)),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                line(true),
            ),
            (
                "remove, its action in four bytes",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, 2u32.to_be_bytes().to_vec()),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                line(false),
            ),
            (
                "a clear takes no key",
                vec![
                    (DATA_TARGET, line_bytes(4, 5, 9)),
                    (DATA_REACTION_ACTION, act(3)),
                    (DATA_REACTION_KEY, vec![9]),
                ],
                Ok(Send::Clear { room: 5, id: 9 }),
            ),
            (
                "kind 4 on chat 0",
                vec![
                    (DATA_TARGET, line_bytes(4, 0, 9)),
                    (DATA_REACTION_ACTION, act(1)),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Ok(Send::Unheld { clearing: false }),
            ),
            (
                "a clear on kind 4 chat 0",
                vec![
                    (DATA_TARGET, line_bytes(4, 0, 9)),
                    (DATA_REACTION_ACTION, act(3)),
                ],
                Ok(Send::Unheld { clearing: true }),
            ),
            (
                "kind 4 on chat 0 with a bad key",
                vec![
                    (DATA_TARGET, line_bytes(4, 0, 9)),
                    (DATA_REACTION_ACTION, act(1)),
                    (DATA_REACTION_KEY, vec![1]),
                ],
                Err(Malformed::Key),
            ),
            (
                "no target",
                vec![
                    (DATA_REACTION_ACTION, act(1)),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Err(Malformed::Target),
            ),
            (
                "a bad target before a bad action",
                vec![(DATA_TARGET, vec![3]), (DATA_REACTION_ACTION, act(9))],
                Err(Malformed::Target),
            ),
            (
                "a target this wire does not act on yet",
                vec![
                    (DATA_TARGET, im_bytes(b"bob", 3)),
                    (DATA_REACTION_ACTION, act(3)),
                ],
                Err(Malformed::Target),
            ),
            (
                "no action",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Err(Malformed::Action),
            ),
            (
                "action 0",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, act(0)),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Err(Malformed::Action),
            ),
            (
                "action 4",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, act(4)),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Err(Malformed::Action),
            ),
            (
                "an action in three bytes",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, wide[1..].to_vec()),
                    (DATA_REACTION_KEY, key.clone()),
                ],
                Err(Malformed::Action),
            ),
            (
                "a bad action before a bad key",
                vec![
                    (DATA_TARGET, lobby.clone()),
                    (DATA_REACTION_ACTION, act(7)),
                    (DATA_REACTION_KEY, vec![]),
                ],
                Err(Malformed::Action),
            ),
            (
                "no key",
                vec![(DATA_TARGET, lobby.clone()), (DATA_REACTION_ACTION, act(1))],
                Err(Malformed::Key),
            ),
        ] {
            let it = fields.iter().map(|(t, d)| (*t, d.as_slice()));
            assert_eq!(parse_send(it, ALL, false), want, "{case}");
        }
    }

    #[test]
    fn a_712_takes_one_to_fifty_kept_targets_and_a_key_beside_one() {
        let lobby = line_bytes(1, 0, 9);
        let key = thumbs().pack();
        let line = |room, id| Reply::Line { room, id };
        let targets = |list: &[Vec<u8>]| -> Vec<(u16, Vec<u8>)> {
            list.iter().map(|t| (DATA_TARGET, t.clone())).collect()
        };
        let with_key = |mut f: Vec<(u16, Vec<u8>)>, k: Vec<u8>| {
            f.push((DATA_REACTION_KEY, k));
            f
        };
        let fifty = vec![lobby.clone(); 50];
        let alone = targets(std::slice::from_ref(&lobby));
        for (case, fields, want) in [
            (
                "a line in each kind, and one nobody keeps left out",
                targets(&[
                    line_bytes(4, 5, 9),
                    line_bytes(4, 0, 9),
                    line_bytes(1, 5, 9),
                    lobby.clone(),
                ]),
                Ok((vec![line(5, 9), line(5, 9), line(0, 9)], None)),
            ),
            ("fifty", targets(&fifty), Ok((vec![line(0, 9); 50], None))),
            (
                "a key beside one",
                with_key(alone.clone(), key.clone()),
                Ok((vec![line(0, 9)], Some(thumbs()))),
            ),
            (
                "none",
                vec![(DATA_REACTION_KEY, key.clone())],
                Err(Malformed::Target),
            ),
            (
                "fifty-one, counted before any is read",
                targets(&[fifty.clone(), vec![vec![3]]].concat()),
                Err(Malformed::TooManyTargets),
            ),
            (
                "a key beside two",
                with_key(targets(&[lobby.clone(), lobby.clone()]), key.clone()),
                Err(Malformed::TooManyTargets),
            ),
            (
                "an instant message, kept nowhere",
                targets(&[lobby.clone(), im_bytes(b"bob", 3)]),
                Err(Malformed::Target),
            ),
            (
                "one malformed",
                targets(&[lobby.clone(), vec![1, 0]]),
                Err(Malformed::Target),
            ),
            (
                "a key that is no emoji",
                with_key(alone.clone(), vec![1, b'a']),
                Err(Malformed::Key),
            ),
            (
                "a server's without bit 20",
                with_key(alone.clone(), vec![2, 0, 0, 0, 1]),
                Err(Malformed::Key),
            ),
        ] {
            let it = fields.iter().map(|(t, d)| (*t, d.as_slice()));
            assert_eq!(parse_get(it, ALL, false), want, "{case}");
        }
    }

    #[test]
    fn a_712_is_priced_one_and_one_for_each_ten_targets() {
        for (targets, points) in [(1, 2), (10, 2), (11, 3), (50, 6)] {
            assert_eq!(get_price(targets), points, "{targets}");
        }
    }

    fn answer(target: Reply, keys: Vec<(ReactionKey, u32)>, mine: Vec<u8>) -> Asked {
        Asked {
            target,
            shown: hxd_core::Reactions { keys, mine },
            from: None,
        }
    }

    /// Each answer is its group, its target named as this wire names its
    /// channel, with who holds the key by nick, cut as a user list cuts
    /// one.
    #[test]
    fn a_712_reply_is_a_group_for_each_answer() {
        let long = "n".repeat(40);
        let answers = [
            answer(Reply::Line { room: 5, id: 9 }, vec![(thumbs(), 2)], vec![0]),
            answer(
                Reply::Signed {
                    signer: [0; 32],
                    id: [0; 16],
                    hash: [0; 32],
                },
                vec![],
                vec![],
            ),
            Asked {
                from: Some(vec!["bobby".into(), long.clone()]),
                ..answer(Reply::Line { room: 0, id: 3 }, vec![(thumbs(), 2)], vec![])
            },
            answer(Reply::Line { room: 0, id: 4 }, vec![], vec![]),
        ];
        let name = |n: &[u8]| (hxproto::messages::tag::NAME, n.to_vec());
        let want = vec![
            (DATA_TARGET, line_bytes(4, 5, 9)),
            (DATA_REACTION_SUMMARY, summary(&[(thumbs(), 2)])),
            (DATA_REACTION_MINE, vec![1, 0]),
            (DATA_TARGET, line_bytes(1, 0, 3)),
            (DATA_REACTION_SUMMARY, summary(&[(thumbs(), 2)])),
            name(b"bobby"),
            name(&long.as_bytes()[..31]),
            (DATA_TARGET, line_bytes(1, 0, 4)),
            (DATA_REACTION_SUMMARY, vec![0, 0]),
        ];
        assert_eq!(asked(&answers, TextEncoding::Utf8), Some(want));
    }

    /// A reply that fills a frame is sent, and one a byte past it is not.
    #[test]
    fn a_712_reply_is_held_to_one_frame() {
        let mut answers: Vec<Asked> = (0..14)
            .map(|id| {
                answer(
                    Reply::Line { room: 7, id },
                    worst_keys().to_vec(),
                    vec![0; 255],
                )
            })
            .collect();
        let used = group_len(&asked(&answers, TextEncoding::Utf8).unwrap());
        // A target, and a summary of one key of `n` bytes.
        let rest = PAGE_BUDGET - used - (4 + 13) - (4 + 2 + 4 + 2 + 1);
        let last = |n: usize| {
            let key = ReactionKey::Emoji("x".repeat(n));
            answer(Reply::Line { room: 7, id: 99 }, vec![(key, 1)], vec![])
        };
        answers.push(last(rest));
        let full = asked(&answers, TextEncoding::Utf8).expect("a full frame");
        assert_eq!(group_len(&full), PAGE_BUDGET);
        *answers.last_mut().unwrap() = last(rest + 1);
        assert_eq!(asked(&answers, TextEncoding::Utf8), None);
    }

    #[test]
    fn each_refusal_has_its_code() {
        use ReactError::*;
        for (e, clearing, want) in [
            (Some(NoSuchTarget), false, Some(1)),
            (Some(NotAllowed), false, Some(2)),
            (Some(Protected), true, Some(2)),
            (Some(TooManyKeys), false, Some(4)),
            (Some(TooManyOfYours), false, Some(5)),
            (Some(RateLimited(Duration::from_secs(1))), false, Some(6)),
            (Some(NoSuchEmoji), false, Some(7)),
            (Some(OutOfScope), false, Some(12)),
            (Some(NotAvailable), false, Some(12)),
            (Some(BadRequest("x")), true, None),
            (Some(ServerError), false, None),
            (None, false, None),
        ] {
            let (text, code) = refusal(e, clearing);
            assert_eq!(code, want, "{e:?}");
            assert!(text.is_ascii());
        }
        assert_ne!(
            refusal(Some(NotAllowed), true).0,
            refusal(Some(NotAllowed), false).0
        );
    }
}
