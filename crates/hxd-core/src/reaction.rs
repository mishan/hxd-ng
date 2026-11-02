//! Reactions (`docs/hotline-ng.md` §7.3): an emoji an account attaches to
//! a public line, counted on the line and kept beside it in the log.
//!
//! A reaction is an **account's**, by the mailbox rule, never a session's
//! or a nick's: every session of an account shares one set, and a
//! reaction survives a nick change, a reconnect and a link of the
//! account's identity. So only an account that is one person reacts —
//! never a guest, whose login everybody shares.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::access::bit;
use crate::history::LineId;
use crate::inbox::{Mailbox, StoreError};
use crate::messaging::Key;
use crate::moderation::{Act, ActKind, Actor};
use crate::reply::Reply;
use crate::roster::{reads_public_chat, Event, RosterInner, Uid, UserSession};
use crate::Core;

/// The most bytes one key's text may take: the longest emoji sequences
/// already run past 32 (a kiss with two skin tones is 35).
pub const MAX_KEY_BYTES: usize = 64;

/// The most distinct keys a target may carry, whatever a configuration
/// says: a reader's own keys are indexes into a line's, one byte each on
/// the classic wire.
pub const MAX_KEYS_CEILING: usize = 255;

/// The most lines a room's live window may hold: one batch reads every
/// one of them in a statement.
pub const MAX_LIVE_WINDOW: usize = 500;

/// Instant-message reactions kept for one party while it has no session
/// to hear them; past it, the reactor holding the most gives up its
/// oldest.
pub const IM_WAITING: usize = 100;

/// Instant-message reactions kept for everyone at once; past it, the
/// oldest anywhere goes.
pub const IM_WAITING_ALL: usize = 50_000;

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
    /// Each room's most recent lines whose changes are announced as they
    /// happen, at most [`MAX_LIVE_WINDOW`]; older lines' are read when
    /// they are shown.
    pub live_window: usize,
    /// How long a room's changes are gathered into one announcement: no
    /// session hears more than one a room in it.
    pub batch: Duration,
    /// How long an instant-message reaction waits for a party with no
    /// session: the inbox's unread retention, as the messages it is on.
    pub im_keep: Duration,
}

impl Default for ReactionPolicy {
    fn default() -> Self {
        ReactionPolicy {
            max_keys: 20,
            max_per_user: 5,
            burst: 10,
            per_second: 1,
            read_only_rooms: true,
            live_window: 200,
            batch: Duration::from_secs(1),
            im_keep: Duration::from_secs(30 * 24 * 3600),
        }
    }
}

/// One change a [`Event::ReactionsChanged`] carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactionChange {
    /// A line's reactions as they stand when it is sent: its keys, which
    /// every reader shares, and the indexes into them this reader's
    /// account holds.
    Summary {
        target: Reply,
        keys: Arc<[(ReactionKey, u32)]>,
        mine: Vec<u8>,
    },
    /// Every reaction on a line is gone: a moderator cleared it, or it
    /// was redacted.
    Clear { target: Reply },
    /// `from`'s account added (`add`) or removed `key` on an instant
    /// message, told to the conversation's other party alone.
    Changed {
        target: Reply,
        key: ReactionKey,
        add: bool,
        from: String,
    },
}

impl ReactionChange {
    /// For [`Event::weight`]: a summary as if its keys were its own,
    /// though every reader's copy shares them.
    pub(crate) fn weight(&self) -> usize {
        let key = |k: &ReactionKey| match k {
            ReactionKey::Emoji(e) => e.len(),
        };
        std::mem::size_of::<Self>()
            + match self {
                ReactionChange::Summary { keys, mine, .. } => {
                    keys.iter()
                        .map(|(k, _)| std::mem::size_of::<(ReactionKey, u32)>() + key(k))
                        .sum::<usize>()
                        + mine.len()
                }
                ReactionChange::Clear { .. } => 0,
                ReactionChange::Changed {
                    target,
                    key: k,
                    from,
                    ..
                } => target.pack().len() + key(k) + from.len(),
            }
    }
}

/// What a live line owes its room's next batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owe {
    /// Its reactions changed: a summary, read when the batch goes.
    Summary,
    /// A moderator cleared them.
    Clear,
    /// It was redacted, taking them: told as a clear, to a wire that
    /// shows redactions.
    Gone,
}

struct Owed {
    due: Instant,
    lines: BTreeMap<LineId, Owe>,
}

/// An instant-message reaction kept for a party with no session.
struct Waiting {
    from: Mailbox,
    change: ReactionChange,
    at: Instant,
}

/// What reactions are announced from, in the roster: which lines are
/// live, what has changed on them since their room's last batch, and the
/// instant-message reactions waiting for their party.
///
/// Bounded by the rooms rather than by anyone's backlog: a room holds at
/// most its live window's lines, owed or not, however many react and
/// however slowly anyone reads, and a session is sent one event a room a
/// batch, which its own queue and the server's budget weigh as any other.
#[derive(Default)]
pub(crate) struct Live {
    /// Lines a room keeps live; 0, a server without reactions, none.
    window: usize,
    batch: Duration,
    /// Each room's live lines, oldest first, and the same by line.
    recent: HashMap<u32, VecDeque<LineId>>,
    room_of: HashMap<LineId, u32>,
    owed: HashMap<u32, Owed>,
    wake: Arc<tokio::sync::Notify>,
    waiting: HashMap<Key, VecDeque<Waiting>>,
}

impl Live {
    /// `id` was relayed in `room`: live until the window has moved past
    /// it.
    pub(crate) fn relayed(&mut self, room: u32, id: LineId) {
        if self.window == 0 {
            return;
        }
        let ring = self.recent.entry(room).or_default();
        ring.push_back(id);
        self.room_of.insert(id, room);
        while ring.len() > self.window {
            if let Some(old) = ring.pop_front() {
                self.room_of.remove(&old);
            }
        }
    }

    /// Owe `line`'s room `what` in its next batch, if the line is live.
    /// A redaction stands whatever comes after it; otherwise the last
    /// change says what is sent, a summary being the line as it is then.
    pub(crate) fn owe(&mut self, line: LineId, what: Owe, now: Instant) {
        let Some(&room) = self.room_of.get(&line) else {
            return;
        };
        // A batch is taken whole before it is sent, so a change after it
        // is due a whole batch after the last one went.
        let owed = self.owed.entry(room).or_insert_with(|| {
            self.wake.notify_one();
            Owed {
                due: now + self.batch,
                lines: BTreeMap::new(),
            }
        });
        let was = owed.lines.insert(line, what);
        if was == Some(Owe::Gone) {
            owed.lines.insert(line, Owe::Gone);
        }
    }

    pub(crate) fn is_live(&self, line: LineId) -> bool {
        self.room_of.contains_key(&line)
    }

    /// A room deleted or archived keeps no live lines: nothing more is
    /// told of them.
    pub(crate) fn forget_room(&mut self, room: u32) {
        for id in self.recent.remove(&room).into_iter().flatten() {
            self.room_of.remove(&id);
        }
        self.owed.remove(&room);
    }

    /// Give up the instant-message reactions older than `keep`.
    fn prune(&mut self, now: Instant, keep: Duration) {
        self.waiting.retain(|_, queue| {
            queue.retain(|w| now.duration_since(w.at) < keep);
            !queue.is_empty()
        });
    }

    /// Keep `change` for `to`, from `from`, in place of one it replaces:
    /// the latest of each reactor's key on each message, within
    /// [`IM_WAITING`] and the policy's age.
    fn keep(&mut self, to: Key, w: Waiting, keep: Duration) {
        let queue = self.waiting.entry(to).or_default();
        let same = |a: &ReactionChange, b: &ReactionChange| match (a, b) {
            (
                ReactionChange::Changed {
                    target: t1,
                    key: k1,
                    ..
                },
                ReactionChange::Changed {
                    target: t2,
                    key: k2,
                    ..
                },
            ) => t1 == t2 && k1 == k2,
            _ => false,
        };
        queue.retain(|q| {
            !(Key::of(&q.from) == Key::of(&w.from) && same(&q.change, &w.change))
                && w.at.duration_since(q.at) < keep
        });
        queue.push_back(w);
        if queue.len() > IM_WAITING {
            // The reactor holding the most gives up its oldest, so one
            // cannot crowd the others out.
            let mut held: HashMap<Key, usize> = HashMap::new();
            for q in queue.iter() {
                *held.entry(Key::of(&q.from)).or_default() += 1;
            }
            let most = held.values().max().copied();
            if let Some(i) = queue
                .iter()
                .position(|q| held.get(&Key::of(&q.from)).copied() == most)
            {
                queue.remove(i);
            }
        }
        while self.waiting.values().map(VecDeque::len).sum::<usize>() > IM_WAITING_ALL {
            let oldest = (self.waiting.iter())
                .filter_map(|(k, q)| q.front().map(|w| (w.at, k.clone())))
                .min_by_key(|(at, _)| *at);
            let Some((_, k)) = oldest else { break };
            if let Some(q) = self.waiting.get_mut(&k) {
                q.pop_front();
                if q.is_empty() {
                    self.waiting.remove(&k);
                }
            }
        }
    }
}

/// Does `s` hear `room`'s reactions as they change: a session that
/// declared them, reading the lobby, or a member of the room able to
/// see it.
fn hears(r: &RosterInner, room: u32, uid: Uid, s: &UserSession) -> bool {
    s.info.transport.reactions
        && match room {
            0 => s.visible && reads_public_chat(s),
            _ => r
                .rooms
                .get(&room)
                .is_some_and(|e| e.members.contains(&uid) && crate::rooms::sees(s, &e.room)),
        }
}

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
    /// Applied: the key's count now.
    Count(u32),
    /// Nothing to change, a key the account held added or one it did
    /// not removed: the key's count, which nobody need be told.
    Held(u32),
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

/// Does this messenger session hear instant-message reactions: one that
/// declared them and is attached, and under an approval one that
/// understands requests, as a receipt is told.
fn im_hears(s: &UserSession, approval: bool) -> bool {
    s.info.transport.reactions
        && crate::roster::is_live(s)
        && (!approval || crate::messaging::understands_requests(s))
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
    /// An instant message named neither the caller nor the party it
    /// names as the other.
    OutOfScope,
    ServerError,
}

impl Core {
    /// Take reactions under `policy`, on the lines of the log.
    pub fn with_reactions(mut self, mut policy: ReactionPolicy) -> Self {
        policy.max_keys = policy.max_keys.min(MAX_KEYS_CEILING);
        policy.live_window = policy.live_window.min(MAX_LIVE_WINDOW);
        policy.batch = policy.batch.max(Duration::from_secs(1));
        {
            let mut r = self.roster.lock().unwrap();
            r.live.window = policy.live_window;
            r.live.batch = policy.batch;
        }
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
        let log = self.history.as_ref().ok_or(ReactError::NotAvailable)?;
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
            let who = Mailbox {
                login: sess.login.clone(),
                fingerprint: sess.identity,
            };
            (who, sess.info.nick.clone(), target)
        };
        self.react_rate(uid, policy)?;
        target?;
        let act = ReactAct {
            channel: room,
            line,
            who: &who,
            nick: &nick,
            key,
            add,
            at: self.clock.wall(),
            max_keys: policy.max_keys,
            max_per_user: policy.max_per_user,
        };
        match log.react(&act) {
            Ok(Reacted::Count(n)) => {
                let now = self.clock.now();
                self.roster
                    .lock()
                    .unwrap()
                    .live
                    .owe(line, Owe::Summary, now);
                Ok(n)
            }
            Ok(Reacted::Held(n)) => Ok(n),
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
            r.users.get(&uid).filter(|s| s.is_person).map(|s| Mailbox {
                login: s.login.clone(),
                fingerprint: s.identity,
            })
        };
        log.reactions(ids, reader.as_ref())
    }

    /// Take `who`'s reactions of the last `within`: a purge's, and an
    /// account's deletion's, so a later holder of the login inherits
    /// none. The live lines among those they were on are announced in
    /// their rooms' next batches, one event a room however many lines.
    pub(crate) fn forget_reactions(&self, who: &Mailbox, within: Duration) {
        let Some(log) = self.history.as_ref() else {
            return;
        };
        let since = self
            .clock
            .wall()
            .checked_sub(within)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        match log.forget_reactions(who, since) {
            Ok(lines) => {
                let now = self.clock.now();
                let mut r = self.roster.lock().unwrap();
                for line in lines {
                    r.live.owe(line, Owe::Summary, now);
                }
            }
            Err(e) => tracing::warn!("chat log would not forget {}'s reactions: {e}", who.login),
        }
    }

    /// Of `ids`, about to be redacted, the live ones that carry
    /// reactions, to be told as cleared once they are
    /// ([`Core::reactions_gone`]).
    pub(crate) fn reacted_live(&self, ids: &[LineId]) -> Vec<LineId> {
        let Some(log) = self.history.as_ref().filter(|_| self.reactions.is_some()) else {
            return Vec::new();
        };
        let live: Vec<LineId> = {
            let r = self.roster.lock().unwrap();
            ids.iter()
                .copied()
                .filter(|id| r.live.is_live(*id))
                .collect()
        };
        if live.is_empty() {
            return live;
        }
        match log.reactions(&live, None) {
            Ok(shown) => live
                .into_iter()
                .filter(|id| shown.contains_key(id))
                .collect(),
            Err(e) => {
                tracing::warn!("chat log would not read reactions: {e}");
                Vec::new()
            }
        }
    }

    /// `ids` were redacted, and their reactions with them.
    pub(crate) fn reactions_gone(&self, ids: &[LineId]) {
        let now = self.clock.now();
        let mut r = self.roster.lock().unwrap();
        for &id in ids {
            r.live.owe(id, Owe::Gone, now);
        }
    }

    /// A moderator's clear: every reaction on line `line` of `room` taken,
    /// recorded in the moderation trail with what was there, and
    /// announced as cleared. Who may is who may redact, the moderate
    /// permission, and the line is one they could have read, as for a
    /// reaction.
    pub fn react_clear(&self, uid: Uid, room: u32, line: LineId) -> Result<(), ReactError> {
        self.reaction_policy().ok_or(ReactError::NotAvailable)?;
        let log = self.history.as_ref().ok_or(ReactError::NotAvailable)?;
        let store = self.moderation.as_ref().ok_or(ReactError::NotAllowed)?;
        let acting = self
            .acting(Actor::Session(uid))
            .map_err(|_| ReactError::NotAllowed)?;
        {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(ReactError::NotAllowed)?;
            if !could_have_read(&r, sess, room, line) {
                return Err(ReactError::NoSuchTarget);
            }
        }
        let failed = |e: StoreError| {
            tracing::warn!("chat log would not clear reactions: {e}");
            ReactError::ServerError
        };
        let was = log.reactions(&[line], None).map_err(failed)?;
        match log.clear_reactions(room, line).map_err(failed)? {
            None => return Err(ReactError::NoSuchTarget),
            Some(0) => return Ok(()),
            Some(_) => {}
        }
        let mut act = Act::new(ActKind::ClearReactions, &acting, String::new());
        act.line = Some(line);
        act.room = (room != 0).then_some(room);
        act.evidence = was.get(&line).map(|shown| {
            let keys = shown.keys.iter().map(|(k, n)| match k {
                ReactionKey::Emoji(e) => format!("{e} {n}"),
            });
            format!("#{line}: {}", keys.collect::<Vec<_>>().join(", "))
        });
        if let Err(e) = store.record(&act) {
            tracing::warn!("moderation: a reactions clear would not record: {e}");
        }
        let now = self.clock.now();
        self.roster.lock().unwrap().live.owe(line, Owe::Clear, now);
        Ok(())
    }

    /// Send each room whose batch is due what changed on its live lines,
    /// and answer when the next is due. The domain schedules nothing, so
    /// the binary runs this from a task woken by [`Core::reactions_wake`]
    /// and by the deadline it returns, as presence's.
    pub fn reactions_flush(&self, now: Instant) -> Option<Instant> {
        let due: Vec<(u32, BTreeMap<LineId, Owe>)> = {
            let mut r = self.roster.lock().unwrap();
            let rooms: Vec<u32> = (r.live.owed.iter())
                .filter(|(_, o)| o.due <= now)
                .map(|(room, _)| *room)
                .collect();
            rooms
                .into_iter()
                .filter_map(|room| {
                    let mut owed = r.live.owed.remove(&room)?;
                    owed.lines.retain(|id, _| r.live.is_live(*id));
                    Some((room, owed.lines))
                })
                .collect()
        };
        for (room, lines) in due {
            self.announce_reactions(room, lines);
        }
        let r = self.roster.lock().unwrap();
        r.live.owed.values().map(|o| o.due).min()
    }

    /// Give up the instant-message reactions that have waited too long:
    /// the binary's flusher runs this now and then, so that ones never
    /// handed over do not stay.
    pub fn reactions_prune(&self) {
        let keep = self.reactions.map_or(Duration::ZERO, |p| p.im_keep);
        let now = self.clock.now();
        self.roster.lock().unwrap().live.prune(now, keep);
    }

    /// Notified when a room first owes a batch.
    pub fn reactions_wake(&self) -> Arc<tokio::sync::Notify> {
        self.roster.lock().unwrap().live.wake.clone()
    }

    /// One room's batch, to every session that hears the room, of the
    /// lines it could have read: each summary read once, shared, and
    /// every reader's own keys from one read of who reacted to them.
    /// Under the room's serial, as a redaction is, so a summary read
    /// before one is not sent after it.
    fn announce_reactions(&self, room: u32, lines: BTreeMap<LineId, Owe>) {
        let Some(log) = self.history.as_ref() else {
            return;
        };
        let channel = (room != 0).then(|| self.room_channel(room));
        let _serial = channel
            .as_ref()
            .map_or(&self.log_serial, |c| &c.serial)
            .lock()
            .unwrap();
        let (readers, by_key) = {
            let r = self.roster.lock().unwrap();
            let mut by_key: HashMap<String, usize> = HashMap::new();
            let readers: Vec<(Uid, Option<usize>)> = (r.users.iter())
                .filter(|(uid, s)| hears(&r, room, **uid, s))
                .map(|(uid, s)| {
                    let account = s.is_person.then(|| {
                        let next = by_key.len();
                        *by_key.entry(reactor_key(&s.mailbox())).or_insert(next)
                    });
                    (*uid, account)
                })
                .collect();
            (readers, by_key)
        };
        if readers.is_empty() {
            return;
        }
        let asked: Vec<LineId> = (lines.iter())
            .filter(|(_, w)| **w == Owe::Summary)
            .map(|(id, _)| *id)
            .collect();
        let read = || -> Result<_, StoreError> {
            if asked.is_empty() {
                return Ok((HashMap::new(), Vec::new()));
            }
            let shown = log.reactions(&asked, None)?;
            let held = match by_key.is_empty() {
                true => Vec::new(),
                false => log.reactors_on(&asked)?,
            };
            Ok((shown, held))
        };
        let (mut shown, held) = match read() {
            Ok(read) => read,
            Err(e) => {
                tracing::warn!("chat log would not read reactions: {e}");
                return;
            }
        };
        let keys: HashMap<LineId, Arc<[(ReactionKey, u32)]>> = (asked.iter())
            .map(|id| {
                let keys = shown.remove(id).map(|s| s.keys).unwrap_or_default();
                (*id, keys.into())
            })
            .collect();
        let mut mine: HashMap<(usize, LineId), Vec<u8>> = HashMap::new();
        for (line, reactor, key) in held {
            let Some(&account) = by_key.get(&reactor) else {
                continue;
            };
            let at = keys
                .get(&line)
                .and_then(|k| k.iter().position(|(k, _)| *k == key));
            if let Some(i) = at.and_then(|i| u8::try_from(i).ok()) {
                mine.entry((account, line)).or_default().push(i);
            }
        }
        for m in mine.values_mut() {
            m.sort_unstable();
        }
        let mut r = self.roster.lock().unwrap();
        for (uid, account) in readers {
            let Some(s) = r.users.get(&uid).filter(|s| hears(&r, room, uid, s)) else {
                continue;
            };
            let redactions = s.info.transport.redactions;
            // A line it never heard, nor may read in history, is not one
            // to tell it of.
            let changes: Vec<ReactionChange> = (lines.iter())
                .filter(|(&id, _)| could_have_read(&r, s, room, id))
                .filter_map(|(&id, what)| {
                    let target = Reply::Line { room, id };
                    match what {
                        Owe::Summary => Some(ReactionChange::Summary {
                            target,
                            keys: keys[&id].clone(),
                            mine: account
                                .and_then(|a| mine.get(&(a, id)).cloned())
                                .unwrap_or_default(),
                        }),
                        Owe::Clear => Some(ReactionChange::Clear { target }),
                        Owe::Gone => redactions.then_some(ReactionChange::Clear { target }),
                    }
                })
                .collect();
            if !changes.is_empty() {
                r.send_to(uid, Event::ReactionsChanged(changes));
            }
        }
    }

    /// Relay `change` from `from` to `to`'s sessions that hear reactions,
    /// those that understand requests alone under an `approval`, or keep
    /// it for them when there are none.
    pub(crate) fn im_reaction(
        &self,
        from: &Mailbox,
        to: &Mailbox,
        approval: bool,
        change: ReactionChange,
    ) {
        let keep = self.reactions.map_or(Duration::ZERO, |p| p.im_keep);
        let now = self.clock.now();
        let mut r = self.roster.lock().unwrap();
        let told: Vec<Uid> = (r.messengers(&Key::of(to)).into_iter())
            .filter(|u| r.users.get(u).is_some_and(|s| im_hears(s, approval)))
            .collect();
        if told.is_empty() {
            let w = Waiting {
                from: from.clone(),
                change,
                at: now,
            };
            r.live.keep(Key::of(to), w, keep);
            return;
        }
        for uid in told {
            r.send_to(uid, Event::ReactionsChanged(vec![change.clone()]));
        }
    }

    /// Hand `uid`, at its roster read, the instant-message reactions kept
    /// for its account: one event a conversation, still fresh, and by
    /// how the two may message now, which `relation` says of each
    /// reactor as `im_relation` does. A conversation they may no longer
    /// have is given up; one under an approval waits for a session that
    /// understands requests.
    pub(crate) fn im_reactions_drain(
        &self,
        uid: Uid,
        me: &Mailbox,
        relation: impl Fn(&Mailbox) -> Option<bool>,
    ) {
        let keep = self.reactions.map_or(Duration::ZERO, |p| p.im_keep);
        let now = self.clock.now();
        let (understands, queue) = {
            let mut r = self.roster.lock().unwrap();
            let Some((hears, understands)) = r
                .users
                .get(&uid)
                .map(|s| (im_hears(s, false), im_hears(s, true)))
            else {
                return;
            };
            if !hears {
                return;
            }
            let Some(queue) = r.live.waiting.remove(&Key::of(me)) else {
                return;
            };
            (understands, queue)
        };
        let mut conversations: Vec<(Mailbox, Vec<Waiting>)> = Vec::new();
        for w in queue
            .into_iter()
            .filter(|w| now.duration_since(w.at) < keep)
        {
            match (conversations.iter_mut()).find(|(m, _)| Key::of(m) == Key::of(&w.from)) {
                Some((_, kept)) => kept.push(w),
                None => conversations.push((w.from.clone(), vec![w])),
            }
        }
        let judged: Vec<_> = (conversations.into_iter())
            .map(|(from, kept)| (relation(&from), kept))
            .collect();
        let mut r = self.roster.lock().unwrap();
        let mut back: Vec<Waiting> = Vec::new();
        for (relation, kept) in judged {
            match relation {
                None => {}
                Some(true) if !understands => back.extend(kept),
                Some(_) => {
                    let changes = kept.into_iter().map(|w| w.change).collect();
                    r.send_to(uid, Event::ReactionsChanged(changes));
                }
            }
        }
        if !back.is_empty() {
            back.sort_by_key(|w| w.at);
            let queue = r.live.waiting.entry(Key::of(me)).or_default();
            for w in back.into_iter().rev() {
                queue.push_front(w);
            }
        }
    }

    /// `from`'s reactions are `to`'s now: an account linked an identity.
    /// A live line that lost one, held under both, is told as it now
    /// stands.
    pub(crate) fn rekey_reactions(&self, from: &Mailbox, to: &Mailbox) {
        match self
            .history
            .as_ref()
            .map(|log| log.rekey_reactions(from, to))
        {
            Some(Ok(lost)) => {
                let now = self.clock.now();
                let mut r = self.roster.lock().unwrap();
                for line in lost {
                    r.live.owe(line, Owe::Summary, now);
                }
            }
            Some(Err(e)) => {
                tracing::warn!("chat log would not move {}'s reactions: {e}", from.login)
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::history::{ChatLog, HistoryPolicy, MemoryLog};
    use crate::roster::{drain, AttachInfo};
    use crate::{AccessBits, Events, Transport};

    fn server(policy: ReactionPolicy) -> (Arc<Core>, Arc<MemoryLog>) {
        let log = Arc::new(MemoryLog::default());
        let core = Core::new()
            .with_history(log.clone(), HistoryPolicy::default())
            .with_reactions(policy);
        (Arc::new(core), log)
    }

    fn bits(of: &[u8]) -> AccessBits {
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

    fn thumbs() -> ReactionKey {
        ReactionKey::emoji("👍").unwrap()
    }

    fn party() -> ReactionKey {
        ReactionKey::emoji("🎉").unwrap()
    }

    /// A person's session that reads and may chat, hearing reactions as
    /// `transport` says, a moderator with `moderate`.
    fn hearing(core: &Core, login: &str, transport: Transport, moderate: bool) -> (Uid, Events) {
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

    fn ng() -> Transport {
        Transport {
            reactions: true,
            redactions: true,
            ..Transport::default()
        }
    }

    /// The batches `rx` was sent, each as its groups' lines and what
    /// each says: `Some((keys, mine))` for a summary, `None` for a
    /// clear.
    type Group = (LineId, Option<(Vec<(ReactionKey, u32)>, Vec<u8>)>);

    fn batches(rx: &mut Events) -> Vec<Vec<Group>> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::ReactionsChanged(changes) => Some(
                    changes
                        .into_iter()
                        .map(|c| match c {
                            ReactionChange::Summary {
                                target: Reply::Line { id, .. },
                                keys,
                                mine,
                            } => (id, Some((keys.to_vec(), mine))),
                            ReactionChange::Clear {
                                target: Reply::Line { id, .. },
                            } => (id, None),
                            other => panic!("not a line's: {other:?}"),
                        })
                        .collect(),
                ),
                _ => None,
            })
            .collect()
    }

    fn said(core: &Core, uid: Uid, text: &str) -> LineId {
        core.chat_public(uid, text.into(), 0, None)
            .unwrap()
            .unwrap()
    }

    /// A room's changes over a batch go out together once it is due, as
    /// one event to each session that declared reactions and reads the
    /// room, each with its own account's keys, and the next waits a whole
    /// batch after it. A change that changes nothing is not told.
    #[test]
    fn a_batch_goes_once_a_window_to_the_readers_that_declared_reactions() {
        let (core, _log) = server(ReactionPolicy::default());
        let (alice, mut ra) = hearing(&core, "alice", ng(), false);
        let (bob, mut rb) = hearing(&core, "bob", ng(), false);
        let (_, mut plain) = hearing(&core, "dave", Transport::default(), false);
        let (blind, mut rblind) = hearing(&core, "blind", ng(), false);
        core.roster
            .lock()
            .unwrap()
            .users
            .get_mut(&blind)
            .unwrap()
            .access = bits(&[bit::SEND_CHAT]);
        let one = said(&core, alice, "one");
        let two = said(&core, alice, "two");
        for rx in [&mut ra, &mut rb, &mut plain, &mut rblind] {
            drain(rx);
        }
        let t0 = core.clock.now();
        core.react(bob, 0, one, &thumbs(), true).unwrap();
        core.react(alice, 0, one, &party(), true).unwrap();
        core.react(alice, 0, two, &thumbs(), true).unwrap();
        let due = core.reactions_flush(t0).expect("a batch is owed");
        assert!(due >= t0 + Duration::from_secs(1));
        assert!(batches(&mut ra).is_empty(), "not before its window closes");

        core.clock.advance(due - t0);
        assert_eq!(core.reactions_flush(core.clock.now()), None);
        let keys = vec![(thumbs(), 1), (party(), 1)];
        assert_eq!(
            batches(&mut ra),
            [vec![
                (one, Some((keys.clone(), vec![1]))),
                (two, Some((vec![(thumbs(), 1)], vec![0])))
            ]]
        );
        assert_eq!(
            batches(&mut rb),
            [vec![
                (one, Some((keys, vec![0]))),
                (two, Some((vec![(thumbs(), 1)], vec![])))
            ]]
        );
        assert!(batches(&mut plain).is_empty(), "never declared reactions");
        assert!(batches(&mut rblind).is_empty(), "does not read the lobby");

        assert_eq!(core.react(bob, 0, one, &thumbs(), true), Ok(1));
        let sent = core.clock.now();
        assert_eq!(core.reactions_flush(sent), None, "nothing changed");
        core.react(bob, 0, one, &thumbs(), false).unwrap();
        let next = core.reactions_flush(sent).expect("owed again");
        assert!(next >= sent + Duration::from_secs(1), "a whole batch later");
        assert_eq!(
            core.reactions_flush(next - Duration::from_millis(1)),
            Some(next)
        );
        assert!(batches(&mut ra).is_empty());
        core.reactions_flush(next);
        assert_eq!(
            batches(&mut ra),
            [vec![(one, Some((vec![(party(), 1)], vec![0])))]]
        );
    }

    /// A line is told only to a reader that could have read it: one that
    /// heard it live, or may read history. One that came after it hears
    /// nothing of it, and so learns nothing of a line it never saw.
    #[test]
    fn a_reader_is_told_of_the_lines_it_could_have_read_alone() {
        let (core, _log) = server(ReactionPolicy::default());
        let (alice, mut ra) = hearing(&core, "alice", ng(), false);
        let before = said(&core, alice, "before");
        let (_, mut late) = hearing(&core, "late", ng(), false);
        let (reader, mut rh) = hearing(&core, "reader", ng(), false);
        (core.roster.lock().unwrap().users.get_mut(&reader).unwrap()).access =
            bits(&[bit::READ_CHAT, bit::CHAT_HISTORY]);
        let after = said(&core, alice, "after");
        for rx in [&mut ra, &mut late, &mut rh] {
            drain(rx);
        }
        for line in [before, after] {
            core.react(alice, 0, line, &thumbs(), true).unwrap();
        }
        let due = core.reactions_flush(core.clock.now()).unwrap();
        core.reactions_flush(due);
        let lines =
            |rx: &mut Events| -> Vec<LineId> { batches(rx).concat().iter().map(|g| g.0).collect() };
        assert_eq!(lines(&mut ra), [before, after]);
        assert_eq!(lines(&mut rh), [before, after], "it may read history");
        assert_eq!(lines(&mut late), [after]);
    }

    /// Only a room's most recent lines are told as they change; an older
    /// one's reactions are read when it is shown.
    #[test]
    fn only_the_live_window_is_announced() {
        let (core, _log) = server(ReactionPolicy {
            live_window: 2,
            ..ReactionPolicy::default()
        });
        let (alice, mut ra) = hearing(&core, "alice", ng(), false);
        let old = said(&core, alice, "old");
        let lines = [said(&core, alice, "a"), said(&core, alice, "b")];
        drain(&mut ra);
        assert_eq!(core.react(alice, 0, old, &thumbs(), true), Ok(1));
        assert_eq!(core.reactions_flush(core.clock.now()), None, "owes nothing");
        for line in lines {
            core.react(alice, 0, line, &thumbs(), true).unwrap();
        }
        let due = core.reactions_flush(core.clock.now()).unwrap();
        core.reactions_flush(due);
        let told: Vec<LineId> = batches(&mut ra).concat().iter().map(|g| g.0).collect();
        assert_eq!(told, lines);
    }

    /// What a redaction and a purge take is told in the next batch: a
    /// redacted line as cleared, to a wire that shows redactions, and a
    /// line a purge took someone's from as it now stands. A moderator's
    /// clear is told as cleared, and kept in the trail with what was
    /// there; nobody else may clear.
    #[test]
    fn a_redaction_a_purge_and_a_clear_are_told_in_the_next_batch() {
        let (core, _log) = {
            let log = Arc::new(MemoryLog::default());
            let core = Core::new()
                .with_history(log.clone(), HistoryPolicy::default())
                .with_reactions(ReactionPolicy::default())
                .with_moderation(
                    Arc::new(crate::MemoryModeration::default()),
                    crate::ModerationPolicy::default(),
                );
            (Arc::new(core), log)
        };
        let (alice, mut ra) = hearing(&core, "alice", ng(), false);
        let (bob, _) = hearing(&core, "bob", ng(), false);
        let (carol, _) = hearing(&core, "carol", ng(), true);
        let blind = Transport {
            redactions: false,
            ..ng()
        };
        let (_, mut rblind) = hearing(&core, "erin", blind, false);
        let [gone, kept, cleared] = ["gone", "kept", "cleared"].map(|t| said(&core, alice, t));
        for line in [gone, kept, cleared] {
            core.react(bob, 0, line, &thumbs(), true).unwrap();
        }
        core.react(alice, 0, kept, &party(), true).unwrap();
        let mut now = core.clock.now();
        let flush = |now: &mut Instant| {
            *now += Duration::from_secs(5);
            core.reactions_flush(*now);
        };
        flush(&mut now);
        drain(&mut ra);
        drain(&mut rblind);

        core.redact_line(Actor::Session(carol), gone, "no").unwrap();
        core.purge_sender(
            Actor::Session(carol),
            &crate::moderation::PersonRef::Login("bob".into()),
            Duration::from_secs(3600),
            "ballot stuffing",
        )
        .unwrap();
        flush(&mut now);
        assert_eq!(
            batches(&mut ra),
            [vec![
                (gone, None),
                (kept, Some((vec![(party(), 1)], vec![0]))),
                (cleared, Some((vec![], vec![]))),
            ]]
        );
        assert_eq!(
            batches(&mut rblind),
            [vec![
                (kept, Some((vec![(party(), 1)], vec![]))),
                (cleared, Some((vec![], vec![]))),
            ]]
        );

        assert_eq!(
            core.react_clear(alice, 0, kept),
            Err(ReactError::NotAllowed)
        );
        assert_eq!(core.react_clear(carol, 0, kept), Ok(()));
        assert_eq!(
            core.react_clear(carol, 0, gone),
            Err(ReactError::NoSuchTarget)
        );
        flush(&mut now);
        assert_eq!(batches(&mut ra), [vec![(kept, None)]]);
        let acts = core.moderation.as_ref().unwrap().acts(None, 10).unwrap();
        let act = acts
            .iter()
            .find(|a| a.kind == crate::ActKind::ClearReactions)
            .expect("the clear is in the trail");
        assert_eq!(
            (act.line, act.actor.as_str(), act.evidence.as_deref()),
            (Some(kept), "carol", Some(format!("#{kept}: 🎉 1").as_str()))
        );
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
