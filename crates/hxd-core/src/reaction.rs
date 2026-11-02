//! Reactions (`docs/hotline-ng.md` §7.3): an emoji an account attaches to
//! a public line, counted on the line and kept beside it in the log.
//!
//! A reaction is an **account's**, by the mailbox rule, never a session's
//! or a nick's: every session of an account shares one set, and a
//! reaction survives a nick change, a reconnect and a link of the
//! account's identity. So only an account that is one person reacts —
//! never a guest, whose login everybody shares.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use crate::access::bit;
use crate::history::LineId;
use crate::inbox::{Mailbox, StoreError};
use crate::roster::{reads_public_chat, RosterInner, Uid, UserSession};
use crate::Core;

/// The most bytes one key's text may take: the longest emoji sequences
/// already run past 32 (a kiss with two skin tones is 35).
pub const MAX_KEY_BYTES: usize = 64;

/// The most distinct keys a target may carry, whatever a configuration
/// says: a reader's own keys are indexes into a line's, one byte each on
/// the classic wire.
pub const MAX_KEYS_CEILING: usize = 255;

/// Lines one op tombstones at most.
const GONE_CHUNK: usize = 256;

/// What may be reacted with. Packed as the stores keep it, a kind byte
/// and the kind's bytes, so that a server's own emoji (kind 2, by id)
/// can join without a migration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReactionKey {
    /// One emoji, as UTF-8 in its fully-qualified form
    /// ([`ReactionKey::emoji`]), compared byte for byte.
    Emoji(String),
}

const EMOJI: u8 = 1;

impl ReactionKey {
    /// An emoji key, or `None` for anything that is not exactly one
    /// emoji within [`MAX_KEY_BYTES`]. Spelled as [`qualified`] has it,
    /// so the two spellings of one emoji are one key.
    pub fn emoji(s: &str) -> Option<Self> {
        let s = qualified(s)?;
        (s.len() <= MAX_KEY_BYTES && is_one_emoji(&s)).then_some(ReactionKey::Emoji(s))
    }

    pub fn pack(&self) -> Vec<u8> {
        match self {
            ReactionKey::Emoji(s) => [&[EMOJI][..], s.as_bytes()].concat(),
        }
    }

    /// [`ReactionKey::pack`]'s bytes back, or `None` for bytes it never
    /// wrote. Not checked again as [`ReactionKey::emoji`] checks: a key
    /// stored under looser rules than a later build's still counts
    /// against the caps, so it must still be shown and removable.
    pub fn unpack(b: &[u8]) -> Option<Self> {
        match b.split_first()? {
            (&EMOJI, rest) => Some(ReactionKey::Emoji(String::from_utf8(rest.to_vec()).ok()?)),
            _ => None,
        }
    }
}

/// `Extended_Pictographic` (Unicode's emoji-data.txt), reserved ranges
/// included, so an emoji newer than this table is still one.
const PICTOGRAPHIC: &[(u32, u32)] = &[
    (0x00A9, 0x00A9),
    (0x00AE, 0x00AE),
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2194, 0x2199),
    (0x21A9, 0x21AA),
    (0x231A, 0x231B),
    (0x2328, 0x2328),
    (0x2388, 0x2388),
    (0x23CF, 0x23CF),
    (0x23E9, 0x23F3),
    (0x23F8, 0x23FA),
    (0x24C2, 0x24C2),
    (0x25AA, 0x25AB),
    (0x25B6, 0x25B6),
    (0x25C0, 0x25C0),
    (0x25FB, 0x25FE),
    (0x2600, 0x2605),
    (0x2607, 0x2612),
    (0x2614, 0x2685),
    (0x2690, 0x2705),
    (0x2708, 0x2712),
    (0x2714, 0x2714),
    (0x2716, 0x2716),
    (0x271D, 0x271D),
    (0x2721, 0x2721),
    (0x2728, 0x2728),
    (0x2733, 0x2734),
    (0x2744, 0x2744),
    (0x2747, 0x2747),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2763, 0x2767),
    (0x2795, 0x2797),
    (0x27A1, 0x27A1),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2934, 0x2935),
    (0x2B05, 0x2B07),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
    (0x1F000, 0x1F0FF),
    (0x1F10D, 0x1F10F),
    (0x1F12F, 0x1F12F),
    (0x1F16C, 0x1F171),
    (0x1F17E, 0x1F17F),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F1AD, 0x1F1E5),
    (0x1F201, 0x1F20F),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F232, 0x1F23A),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F3FA),
    (0x1F400, 0x1F53D),
    (0x1F546, 0x1F64F),
    (0x1F680, 0x1F6FF),
    (0x1F774, 0x1F77F),
    (0x1F7D5, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8FF),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1FAFF),
    (0x1FC00, 0x1FFFD),
];

/// `Emoji_Presentation` (emoji-data.txt): what is drawn as an emoji
/// without U+FE0F after it.
const PRESENTATION: &[(u32, u32)] = &[
    (0x231A, 0x231B),
    (0x23E9, 0x23EC),
    (0x23F0, 0x23F0),
    (0x23F3, 0x23F3),
    (0x25FD, 0x25FE),
    (0x2614, 0x2615),
    (0x2648, 0x2653),
    (0x267F, 0x267F),
    (0x2693, 0x2693),
    (0x26A1, 0x26A1),
    (0x26AA, 0x26AB),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26CE, 0x26CE),
    (0x26D4, 0x26D4),
    (0x26EA, 0x26EA),
    (0x26F2, 0x26F3),
    (0x26F5, 0x26F5),
    (0x26FA, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2705, 0x2705),
    (0x270A, 0x270B),
    (0x2728, 0x2728),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2795, 0x2797),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x1F004, 0x1F004),
    (0x1F0CF, 0x1F0CF),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F1E6, 0x1F1FF),
    (0x1F201, 0x1F201),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F232, 0x1F236),
    (0x1F238, 0x1F23A),
    (0x1F250, 0x1F251),
    (0x1F300, 0x1F320),
    (0x1F32D, 0x1F335),
    (0x1F337, 0x1F37C),
    (0x1F37E, 0x1F393),
    (0x1F3A0, 0x1F3CA),
    (0x1F3CF, 0x1F3D3),
    (0x1F3E0, 0x1F3F0),
    (0x1F3F4, 0x1F3F4),
    (0x1F3F8, 0x1F43E),
    (0x1F440, 0x1F440),
    (0x1F442, 0x1F4FC),
    (0x1F4FF, 0x1F53D),
    (0x1F54B, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F57A, 0x1F57A),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A4),
    (0x1F5FB, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CC, 0x1F6CC),
    (0x1F6D0, 0x1F6D2),
    (0x1F6D5, 0x1F6D7),
    (0x1F6DC, 0x1F6DF),
    (0x1F6EB, 0x1F6EC),
    (0x1F6F4, 0x1F6FC),
    (0x1F7E0, 0x1F7EB),
    (0x1F7F0, 0x1F7F0),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1F9FF),
    (0x1FA70, 0x1FA7C),
    (0x1FA80, 0x1FA89),
    (0x1FA8F, 0x1FAC6),
    (0x1FACE, 0x1FADC),
    (0x1FADF, 0x1FAE9),
    (0x1FAF0, 0x1FAF8),
];

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let c = u32::from(c);
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn pictographic(c: char) -> bool {
    in_table(PICTOGRAPHIC, c)
}

const ZWJ: char = '\u{200D}';
const VS15: char = '\u{FE0E}';
const VS16: char = '\u{FE0F}';
const KEYCAP: char = '\u{20E3}';
const BLACK_FLAG: char = '\u{1F3F4}';
const CANCEL_TAG: char = '\u{E007F}';

fn regional(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

fn skin_tone(c: char) -> bool {
    ('\u{1F3FB}'..='\u{1F3FF}').contains(&c)
}

/// `s` in the one spelling a key is kept in, UTS #51's fully-qualified
/// form, whatever a client sent: every U+FE0F taken out, then one put
/// back after a keycap's base and after each pictograph that is not
/// drawn as an emoji by itself and has no skin tone after it, so that
/// U+2764 and U+2764 U+FE0F are one key. `None` for a text-style
/// selector (U+FE0E), which asks for the emoji not to be one.
fn qualified(s: &str) -> Option<String> {
    if s.contains(VS15) {
        return None;
    }
    let bare: Vec<char> = s.chars().filter(|&c| c != VS16).collect();
    let mut out = String::with_capacity(s.len() + 4);
    match bare.as_slice() {
        [k, KEYCAP] if keycap_base(*k) => out.extend([*k, VS16, KEYCAP]),
        _ => {
            for (i, &c) in bare.iter().enumerate() {
                out.push(c);
                let next = bare.get(i + 1).copied();
                if pictographic(c)
                    && !in_table(PRESENTATION, c)
                    && !next.is_some_and(skin_tone)
                    && (i == 0 || bare[i - 1] == ZWJ)
                {
                    out.push(VS16);
                }
            }
        }
    }
    Some(out)
}

fn keycap_base(c: char) -> bool {
    c.is_ascii_digit() || c == '#' || c == '*'
}

/// Is `s`, as [`qualified`] spells it, one emoji, by the shapes UTS #51
/// gives its sequences: a flag, a keycap, a subdivision flag's tag
/// sequence, or pictographs joined by ZWJ, each with at most U+FE0F or a
/// skin tone? Each is one grapheme cluster by UAX #29 (GB9, GB11,
/// GB12–13), and nothing else is let through: no text, control, space,
/// private-use character or separator matches any of them. Some that
/// match are in no emoji set, a skin tone on a pictograph that takes
/// none, any two regional indicators, any tag sequence, and are kept as
/// sent: one grapheme is what a client can draw.
fn is_one_emoji(s: &str) -> bool {
    let c: Vec<char> = s.chars().collect();
    match c.as_slice() {
        [a, b] if regional(*a) && regional(*b) => true,
        [k, rest @ ..] if keycap_base(*k) => matches!(rest, [VS16, KEYCAP]),
        [BLACK_FLAG, tags @ .., CANCEL_TAG] if !tags.is_empty() => {
            tags.iter().all(|t| ('\u{E0020}'..='\u{E007E}').contains(t))
        }
        _ => c.split(|&x| x == ZWJ).all(element),
    }
}

/// One pictograph of a ZWJ sequence, with U+FE0F or a skin tone after
/// it.
fn element(e: &[char]) -> bool {
    match e {
        [p, more @ ..] if pictographic(*p) => match more {
            [] => true,
            [m] => *m == VS16 || skin_tone(*m),
            _ => false,
        },
        _ => false,
    }
}

/// `[reactions]`, as the domain takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactionPolicy {
    /// Distinct keys one line may carry, at most [`MAX_KEYS_CEILING`].
    pub max_keys: usize,
    /// Keys one account may hold on one line.
    pub max_per_user: usize,
    /// One account's reactions at once, earned back at `per_second`.
    pub burst: u32,
    pub per_second: u32,
    /// May a reader who may not post in a room react there?
    pub read_only_rooms: bool,
}

impl Default for ReactionPolicy {
    fn default() -> Self {
        ReactionPolicy {
            max_keys: 20,
            max_per_user: 5,
            burst: 10,
            per_second: 1,
            read_only_rooms: true,
        }
    }
}

/// What the desk ([`desk`]) keeps beside the log for its ops: nothing
/// yet, reactions living in the log alone.
#[derive(Default)]
pub(crate) struct Live {}

/// Could `sess` have read line `line` of `room`: one it can read, already
/// relayed, and either heard live or readable in history.
fn could_have_read(r: &RosterInner, sess: &UserSession, room: u32, line: LineId) -> bool {
    let readable = match room {
        0 => reads_public_chat(sess),
        _ => r
            .rooms
            .get(&room)
            .is_some_and(|e| crate::rooms::sees(sess, &e.room)),
    };
    let relayed = r.last_ids.get(&room).is_some_and(|&last| line <= last);
    let heard = sess.heard_from.get(&room).is_some_and(|&from| line > from);
    readable && relayed && (heard || sess.access.has(bit::CHAT_HISTORY))
}

/// A line's reactions as a reader is shown them: its keys with their
/// counts in the order they were first added, the part every reader
/// shares, and the indexes into `keys` this reader's account holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reactions {
    pub keys: Vec<(ReactionKey, u32)>,
    pub mine: Vec<u8>,
}

/// One account adding or removing one key on one line, held to the
/// policy's caps where it adds.
#[derive(Debug)]
pub struct ReactAct<'a> {
    pub channel: u32,
    pub line: LineId,
    pub who: &'a Mailbox,
    /// The reactor's nick at the time, kept for saying who reacted.
    pub nick: &'a str,
    pub key: &'a ReactionKey,
    pub add: bool,
    pub at: SystemTime,
    pub max_keys: usize,
    pub max_per_user: usize,
}

/// What a store made of a [`ReactAct`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reacted {
    /// Applied, or nothing to change: the key's count now.
    Count(u32),
    /// No such line in that channel, or a tombstone.
    NoSuchLine,
    TooManyKeys,
    TooManyOfYours,
}

/// The mailbox rule as one value, which a store can index and compare:
/// an identified account by its key alone, any other by its login.
pub fn reactor_key(who: &Mailbox) -> String {
    match who.fingerprint {
        Some(fp) => format!("f:{}", hex(&fp)),
        None => format!("l:{}", who.login),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Why a reaction was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactError {
    /// The server does not take reactions on this kind of target.
    NotAvailable,
    /// This session may not react: a guest or other shared account, no
    /// `send_chat`, an archived room, or a read-only room the policy
    /// keeps closed.
    NotAllowed,
    /// A line that does not exist, is a tombstone, is another room's,
    /// cannot be read, or has not been relayed yet: all one answer.
    NoSuchTarget,
    TooManyReactions,
    RateLimited(Duration),
    ServerError,
}

impl Core {
    /// Take reactions under `policy`, on the lines of the log.
    pub fn with_reactions(mut self, mut policy: ReactionPolicy) -> Self {
        policy.max_keys = policy.max_keys.min(MAX_KEYS_CEILING);
        self.reactions = Some(policy);
        self
    }

    /// The policy, where lines can take reactions: the log keeps them.
    pub fn reaction_policy(&self) -> Option<ReactionPolicy> {
        self.reactions.filter(|_| self.history.is_some())
    }

    /// `uid`'s account adds (`add`) or removes `key` on line `line` of
    /// `room`, 0 the lobby, answering the key's count after.
    ///
    /// The line must be one the session can read and one already relayed,
    /// so nothing about a line is known before the line is; one older
    /// than what it heard live needs history's bit, since it can only
    /// have been read there. Each of those is [`ReactError::NoSuchTarget`]
    /// alike. Rated per account before any of them is asked.
    pub fn react(
        &self,
        uid: Uid,
        room: u32,
        line: LineId,
        key: &ReactionKey,
        add: bool,
    ) -> Result<u32, ReactError> {
        let policy = self.reaction_policy().ok_or(ReactError::NotAvailable)?;
        let (who, nick, target) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(ReactError::NotAllowed)?;
            if !sess.is_person
                || sess.info.system
                || sess.info.transport.messenger_session
                || !sess.access.has(bit::SEND_CHAT)
            {
                return Err(ReactError::NotAllowed);
            }
            let entry = r.rooms.get(&room);
            let target = if !could_have_read(&r, sess, room, line) {
                Err(ReactError::NoSuchTarget)
            } else if entry.is_some_and(|e| {
                // An archive is read by its managers and moderators alone,
                // and changes no more.
                e.room.archived_at.is_some()
                    || (!policy.read_only_rooms && !crate::rooms::gates_post(sess, &e.room))
            }) {
                Err(ReactError::NotAllowed)
            } else {
                Ok(())
            };
            (sess.mailbox(), sess.info.nick.clone(), target)
        };
        self.react_rate(uid, policy)?;
        target?;
        let act = desk::Act {
            channel: room,
            line,
            who,
            nick,
            key: key.clone(),
            add,
            at: self.clock.wall(),
            max_keys: policy.max_keys,
            max_per_user: policy.max_per_user,
        };
        match self.desk_react(act) {
            Ok(Reacted::Count(n)) => Ok(n),
            Ok(Reacted::NoSuchLine) => Err(ReactError::NoSuchTarget),
            Ok(Reacted::TooManyKeys | Reacted::TooManyOfYours) => Err(ReactError::TooManyReactions),
            Err(e) => {
                tracing::warn!("chat log would not take a reaction: {e}");
                Err(ReactError::ServerError)
            }
        }
    }

    /// Spend one of `uid`'s account's reactions.
    pub(crate) fn react_rate(&self, uid: Uid, policy: ReactionPolicy) -> Result<(), ReactError> {
        if let Some(rate) = self.post_key(uid) {
            let per = Duration::from_secs_f64(
                f64::from(policy.burst) / f64::from(policy.per_second.max(1)),
            );
            self.react_rates
                .reserve(rate, (policy.burst, per), Instant::now())
                .map_err(ReactError::RateLimited)?;
        }
        Ok(())
    }

    /// The reactions on `ids`, as `uid` is shown them, for a page of
    /// history it has already been let read: lines with none are left
    /// out. A session of no one account holds none of them.
    pub fn line_reactions(
        &self,
        uid: Uid,
        ids: &[LineId],
    ) -> Result<HashMap<LineId, Reactions>, StoreError> {
        let Some(log) = self.history.as_ref().filter(|_| self.reactions.is_some()) else {
            return Ok(HashMap::new());
        };
        let reader = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .filter(|s| s.is_person)
                .map(|s| s.mailbox())
        };
        log.reactions(ids, reader.as_ref())
    }

    /// Take `who`'s reactions of the last `within`: a purge's, and an
    /// account's deletion's, so a later holder of the login inherits
    /// none.
    pub(crate) fn forget_reactions(&self, who: &Mailbox, within: Duration) {
        if self.history.is_none() {
            return;
        }
        let since = (self.clock.wall())
            .checked_sub(within)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let who = who.clone();
        self.desk(move |c, _| {
            let log = c.history.as_ref().expect("asked above");
            if let Err(e) = log.forget_reactions(&who, since) {
                tracing::warn!("chat log would not forget {}'s reactions: {e}", who.login)
            }
        });
    }

    /// Tombstone `ids` with their reactions: the desk's half of a
    /// redaction or a purge, which waits on it under the room's serial
    /// before it tells anyone of the redaction. Answers the lines
    /// tombstoned.
    pub(crate) fn lines_gone(
        &self,
        ids: Vec<LineId>,
        by: String,
        at: SystemTime,
    ) -> Result<Vec<LineId>, StoreError> {
        let mut gone = Vec::with_capacity(ids.len());
        // An op a chunk, so a purge of a flood keeps the desk, which
        // other rooms' serials may be waiting on, for a moment at a time.
        for chunk in ids.chunks(GONE_CHUNK) {
            let chunk = chunk.to_vec();
            let by = by.clone();
            let done = self.desk_caught(move |c, _| c.chunk_gone(chunk, &by, at));
            gone.extend(
                done.unwrap_or_else(|| Err(StoreError::new("a reaction desk op panicked")))?,
            );
        }
        Ok(gone)
    }

    fn chunk_gone(
        &self,
        ids: Vec<LineId>,
        by: &str,
        at: SystemTime,
    ) -> Result<Vec<LineId>, StoreError> {
        let log = (self.history.as_ref()).ok_or_else(|| StoreError::new("no chat log"))?;
        log.tombstone_all(&ids, by, at)
    }

    /// Retire the log's lines past `keep`, and their reactions with them:
    /// at the desk, so no reaction is applied to a line between the
    /// two. One statement for the store, an hour's worth at most.
    pub(crate) fn prune_log(
        &self,
        keep: crate::history::Retention,
        now: SystemTime,
    ) -> Result<usize, StoreError> {
        let done = self.desk_caught(move |c, _| match c.history.as_ref() {
            Some(log) => log.prune(&keep, now),
            None => Ok(0),
        });
        done.unwrap_or_else(|| Err(StoreError::new("a reaction desk op panicked")))
    }

    /// Delete a deleted room's lines, and their reactions with them, at
    /// the desk; its caller holds the room's serial.
    pub(crate) fn delete_channel_lines(&self, room: u32) -> Result<usize, StoreError> {
        let done = self.desk_caught(move |c, _| match c.history.as_ref() {
            Some(log) => log.delete_channel(room),
            None => Ok(0),
        });
        done.unwrap_or_else(|| Err(StoreError::new("a reaction desk op panicked")))
    }

    /// `from`'s reactions are `to`'s now: an account linked an identity.
    pub(crate) fn rekey_reactions(&self, from: &Mailbox, to: &Mailbox) {
        if let Err(e) = self.rekey_all_reactions(from, to) {
            tracing::warn!("chat log would not move {}'s reactions: {e}", from.login);
        }
    }

    /// The same, answering a store's error for a caller that retries.
    pub(crate) fn rekey_all_reactions(
        &self,
        from: &Mailbox,
        to: &Mailbox,
    ) -> Result<(), StoreError> {
        let (from, to) = (from.clone(), to.clone());
        self.desk(move |c, _| {
            if let Some(log) = c.history.as_ref() {
                log.rekey_reactions(&from, &to)?;
            }
            Ok(())
        })
    }
}

mod desk;
pub(crate) use desk::Desk;

#[cfg(test)]
mod edges;
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::history::{ChatLog, HistoryPolicy, MemoryLog};
    use crate::roster::AttachInfo;
    use crate::{AccessBits, Events, Transport};

    pub(super) fn server(policy: ReactionPolicy) -> (Arc<Core>, Arc<MemoryLog>) {
        let log = Arc::new(MemoryLog::default());
        let core = Core::new()
            .with_history(log.clone(), HistoryPolicy::default())
            .with_reactions(policy);
        (Arc::new(core), log)
    }

    pub(super) fn bits(of: &[u8]) -> AccessBits {
        of.iter().fold(AccessBits::empty(), |a, b| a.with(*b))
    }

    /// One person's session, holding `access`.
    fn person(core: &Core, login: &str, access: AccessBits, person: bool) -> Uid {
        let (uid, _rx) = core
            .attach(AttachInfo {
                account: None,
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access,
                login: login.to_string(),
                addr: None,
                can_detach: false,
                transport: Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: person,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        uid
    }

    pub(super) fn thumbs() -> ReactionKey {
        ReactionKey::emoji("👍").unwrap()
    }

    pub(super) fn party() -> ReactionKey {
        ReactionKey::emoji("🎉").unwrap()
    }

    /// A person's session that reads and may chat, hearing reactions as
    /// `transport` says, a moderator with `moderate`.
    pub(super) fn hearing(
        core: &Core,
        login: &str,
        transport: Transport,
        moderate: bool,
    ) -> (Uid, Events) {
        use bit::{READ_CHAT, SEND_CHAT};
        let (uid, rx) = core
            .attach(AttachInfo {
                account: None,
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: bits(&[READ_CHAT, SEND_CHAT]),
                login: login.to_string(),
                addr: None,
                can_detach: false,
                transport,
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    pub(super) fn ng() -> Transport {
        Transport {
            reactions: true,
            redactions: true,
            ..Transport::default()
        }
    }

    pub(super) fn said(core: &Core, uid: Uid, text: &str) -> LineId {
        core.chat_public(uid, text.into(), 0, None)
            .unwrap()
            .unwrap()
    }

    /// Only a line already relayed, readable, and heard live or read in
    /// history may be reacted to, by an account that is one person and
    /// may chat; everything else about the target is one answer.
    #[test]
    fn a_reaction_needs_a_person_who_may_chat_and_a_line_it_could_have_read() {
        use bit::{CHAT_HISTORY, READ_CHAT, SEND_CHAT};
        let (core, log) = server(ReactionPolicy::default());
        let chatter = bits(&[READ_CHAT, SEND_CHAT]);
        let alice = person(&core, "alice", chatter, true);
        let said = core
            .chat_public(alice, "hi".into(), 0, None)
            .unwrap()
            .unwrap();
        let logged = log.append(&crate::history::NewLine {
            channel: 0,
            ghost: None,
            from_nick: "x".into(),
            from_login: None,
            from_fingerprint: None,
            icon: 0,
            text: "not relayed".into(),
            flags: Default::default(),
            at: SystemTime::now(),
            guid: None,
            signed: None,
            home_key: None,
            home: None,
            re: None,
        });
        let late = person(&core, "late", chatter, true);
        let reader = person(&core, "reader", chatter.with(CHAT_HISTORY), true);
        let guest = person(&core, "guest", chatter, false);
        let mute = person(&core, "mute", bits(&[READ_CHAT, CHAT_HISTORY]), true);
        let blind = person(&core, "blind", bits(&[SEND_CHAT, CHAT_HISTORY]), true);
        for (case, uid, line, want) in [
            ("heard live", alice, said, Ok(1)),
            ("read in history", reader, said, Ok(2)),
            (
                "logged, not relayed",
                reader,
                logged.unwrap(),
                Err(ReactError::NoSuchTarget),
            ),
            (
                "never logged",
                reader,
                said + 100,
                Err(ReactError::NoSuchTarget),
            ),
            (
                "before it came, no history",
                late,
                said,
                Err(ReactError::NoSuchTarget),
            ),
            (
                "cannot read chat",
                blind,
                said,
                Err(ReactError::NoSuchTarget),
            ),
            ("a guest", guest, said, Err(ReactError::NotAllowed)),
            ("may not chat", mute, said, Err(ReactError::NotAllowed)),
        ] {
            assert_eq!(core.react(uid, 0, line, &thumbs(), true), want, "{case}");
        }
        let shown = core.line_reactions(alice, &[said]).unwrap();
        assert_eq!(shown[&said].keys, [(thumbs(), 2)]);
        assert_eq!(shown[&said].mine, [0]);
        assert!(core.line_reactions(guest, &[said]).unwrap()[&said]
            .mine
            .is_empty());
    }

    /// The log's lines are relayed lines after a restart too, on a server
    /// with no rooms to read the log's channels for it.
    #[test]
    fn a_line_from_before_a_restart_takes_reactions() {
        use bit::{CHAT_HISTORY, READ_CHAT, SEND_CHAT};
        let chatter = bits(&[READ_CHAT, SEND_CHAT]);
        let log = Arc::new(MemoryLog::default());
        let said = {
            let core = Core::new().with_history(log.clone(), HistoryPolicy::default());
            let alice = person(&core, "alice", chatter, true);
            core.chat_public(alice, "hi".into(), 0, None)
                .unwrap()
                .unwrap()
        };
        let core = Core::new()
            .with_history(log, HistoryPolicy::default())
            .with_reactions(ReactionPolicy::default());
        let reader = person(&core, "reader", chatter.with(CHAT_HISTORY), true);
        assert_eq!(core.react(reader, 0, said, &thumbs(), true), Ok(1));
    }

    /// A burst, then a steady rate, per account across its sessions,
    /// asked before the target is: a guess at a line costs as much as a
    /// reaction.
    #[test]
    fn an_account_reacts_a_burst_and_then_waits() {
        use bit::{READ_CHAT, SEND_CHAT};
        let (core, _log) = server(ReactionPolicy {
            burst: 2,
            per_second: 1,
            ..ReactionPolicy::default()
        });
        let chatter = bits(&[READ_CHAT, SEND_CHAT]);
        let one = person(&core, "alice", chatter, true);
        let two = person(&core, "alice", chatter, true);
        let bob = person(&core, "bob", chatter, true);
        let said = core
            .chat_public(one, "hi".into(), 0, None)
            .unwrap()
            .unwrap();
        assert_eq!(core.react(one, 0, said, &thumbs(), true), Ok(1));
        assert_eq!(
            core.react(two, 0, said + 100, &thumbs(), true),
            Err(ReactError::NoSuchTarget)
        );
        assert!(matches!(
            core.react(two, 0, said, &thumbs(), false),
            Err(ReactError::RateLimited(wait)) if wait <= Duration::from_secs(1)
        ));
        assert_eq!(core.react(bob, 0, said, &thumbs(), true), Ok(2));
    }

    #[test]
    fn one_emoji_is_a_key_and_nothing_else_is() {
        for ok in [
            "👍",
            "❤",
            "❤\u{FE0F}",
            "🇺🇦",
            "#\u{FE0F}\u{20E3}",
            "7\u{20E3}",
            "👍🏽",
            "👨\u{200D}👩\u{200D}👧\u{200D}👦",
            "🏳\u{FE0F}\u{200D}🌈",
            // A kiss with two skin tones, the longest RGI sequence.
            "👨🏻\u{200D}❤\u{FE0F}\u{200D}💋\u{200D}👨🏻",
            // Scotland's flag, a tag sequence.
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
            // Unassigned in a reserved block: an emoji newer than us.
            "\u{1FAFF}",
        ] {
            assert!(ReactionKey::emoji(ok).is_some(), "{ok:?}");
        }
        for bad in [
            "",
            "a",
            "ok",
            "👍👍",
            "👍 ",
            " ",
            "\u{2028}",
            "\u{0007}",
            "\u{E000}",
            "\u{200D}",
            "👍\u{200D}",
            "🏽",
            "🇺",
            "#",
            "e\u{301}",
            "👍\u{301}",
            "🏴\u{E007F}",
        ] {
            assert!(ReactionKey::emoji(bad).is_none(), "{bad:?}");
        }
        let long = format!("👍{}", "\u{200D}👍".repeat(9));
        assert!(long.len() > MAX_KEY_BYTES);
        assert!(ReactionKey::emoji(&long).is_none());
    }

    #[test]
    /// A key stored under rules a later build tightened still reads
    /// back, so it can be shown and taken away.
    fn a_key_packs_and_back_and_a_kept_one_reads_back_as_kept() {
        let key = ReactionKey::emoji("🎉").unwrap();
        assert_eq!(ReactionKey::unpack(&key.pack()), Some(key));
        assert_eq!(
            ReactionKey::unpack(b"\x01ok"),
            Some(ReactionKey::Emoji("ok".into()))
        );
        for bad in [&[][..], &[2, 0, 0, 0, 1], &[1, 0xff]] {
            assert_eq!(ReactionKey::unpack(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_spelling_of_an_emoji_is_kept_as_its_qualified_one() {
        for (sent, kept) in [
            ("❤", "❤\u{FE0F}"),
            ("❤\u{FE0F}", "❤\u{FE0F}"),
            ("👍\u{FE0F}", "👍"),
            ("👍\u{FE0F}🏽", "👍🏽"),
            ("©", "©\u{FE0F}"),
            ("7\u{20E3}", "7\u{FE0F}\u{20E3}"),
            ("#\u{FE0F}\u{20E3}", "#\u{FE0F}\u{20E3}"),
            ("🏃\u{200D}♀", "🏃\u{200D}♀\u{FE0F}"),
            ("🏃🏽\u{200D}♂\u{FE0F}", "🏃🏽\u{200D}♂\u{FE0F}"),
            ("❤\u{200D}🔥", "❤\u{FE0F}\u{200D}🔥"),
            ("👁\u{200D}🗨", "👁\u{FE0F}\u{200D}🗨\u{FE0F}"),
            ("🏳\u{FE0F}\u{200D}🌈", "🏳\u{FE0F}\u{200D}🌈"),
            // One grapheme in no emoji set is kept as sent.
            ("❤🏽", "❤🏽"),
            ("🇿🇿", "🇿🇿"),
        ] {
            let want = Some(ReactionKey::Emoji(kept.into()));
            assert_eq!(ReactionKey::emoji(sent), want, "{sent:?}");
        }
        for text_style in ["❤\u{FE0E}", "👍\u{FE0E}", "7\u{FE0E}\u{20E3}"] {
            assert_eq!(ReactionKey::emoji(text_style), None, "{text_style:?}");
        }
    }
}
