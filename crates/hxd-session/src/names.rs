//! A name as the classic wire shows it. That wire marks a bot by
//! `[server] bot_suffix` after its nick and, under `[link] show_tags`, a
//! linked server's user by `@tag`, and a classic client has nothing else
//! to tell them by, so no name may end in either by itself. What is judged
//! is what the reader is sent: written in its encoding, cut to the field,
//! and without what draws as nothing. A rule on the stored nick would miss
//! a cut, a NUL or a `?` that makes one.

use hxd_core::Core;

use crate::encoding::TextEncoding;

/// How one connection writes names: its encoding, and this server's
/// markers.
#[derive(Clone, Copy)]
pub(crate) struct Names<'a> {
    pub(crate) enc: TextEncoding,
    bot_suffix: &'a str,
    tags: bool,
}

/// A nick's room on the wire, in bytes.
const NICK: usize = 31;
/// Public chat's name column (`EncodingExt::name_column`).
const COLUMN: usize = 13;

impl<'a> Names<'a> {
    pub(crate) fn of(enc: TextEncoding, core: &'a Core) -> Self {
        Names {
            enc,
            bot_suffix: core.bot_suffix(),
            tags: core.tagged_names(),
        }
    }

    /// Names with no marker to keep off: a server that shows none.
    #[cfg(test)]
    pub(crate) fn plain(enc: TextEncoding) -> Names<'static> {
        Names::with(enc, "", false)
    }

    #[cfg(test)]
    pub(crate) fn with(enc: TextEncoding, bot_suffix: &'static str, tags: bool) -> Names<'static> {
        Names {
            enc,
            bot_suffix,
            tags,
        }
    }

    /// What a bot is shown with, if this server shows one.
    pub(crate) fn bot_marker(&self) -> Option<&'a str> {
        (!self.bot_suffix.is_empty()).then_some(self.bot_suffix)
    }

    /// `nick` and the `marker` that follows it, in a nick's 31 bytes: the
    /// marker whole, and the name in what it leaves.
    pub(crate) fn nick(&self, nick: &str, marker: Option<&str>) -> Vec<u8> {
        let marker = marker.map_or_else(Vec::new, |m| self.enc.encode_capped(m, NICK));
        let room = NICK - marker.len();
        let mut out = self.enc.encode(&self.shown(nick, usize::MAX, room));
        out.extend(marker);
        out
    }

    /// A name where a field holds one at length, as a news article's
    /// poster: `bytes` of it, and no marker of the server's.
    pub(crate) fn field(&self, nick: &str, bytes: usize) -> Vec<u8> {
        self.enc.encode(&self.shown(nick, usize::MAX, bytes))
    }

    /// A name as it is set into text shared by every connection, as the
    /// 1.2 news view: judged as UTF-8 writes it and as Mac Roman does,
    /// whose `?` for what it cannot write could make a tag. Mac Roman
    /// writes one byte a character, so the two are cut at the same place.
    pub(crate) fn text(&self, nick: &str) -> String {
        let as_in = |enc| Names { enc, ..*self };
        let mut name = as_in(TextEncoding::Utf8).shown(nick, usize::MAX, usize::MAX);
        loop {
            let mac = TextEncoding::MacRoman;
            let seen = as_in(mac).unmarked(&mac.decode(&mac.encode(&name)));
            let kept: String = name.chars().take(seen.chars().count()).collect();
            if kept == name {
                return name;
            }
            name = as_in(TextEncoding::Utf8).shown(&kept, usize::MAX, usize::MAX);
        }
    }

    /// The same in public chat's 13 columns, so the column never cuts the
    /// marker.
    pub(crate) fn column(&self, nick: &str, marker: Option<&str>) -> Vec<u8> {
        let marker_bytes = marker.map_or_else(Vec::new, |m| self.enc.encode_capped(m, NICK));
        let columns = COLUMN.saturating_sub(marker.map_or(0, |m| m.chars().count()));
        let mut out = self
            .enc
            .encode(&self.shown(nick, columns, NICK - marker_bytes.len()));
        out.extend(marker_bytes);
        out
    }

    /// What a reader is shown of `nick` in `columns` and `bytes`: what
    /// draws as nothing gone, as the encoding writes it, any marker at its
    /// end taken off for as long as one is left, cut to fit, and the same
    /// again.
    fn shown(&self, nick: &str, columns: usize, bytes: usize) -> String {
        // A server with no marker shows a name as it always did, joiners
        // and direction marks included.
        if self.bot_suffix.is_empty() && !self.tags {
            return self.cut(&self.enc.decode(&self.enc.encode(nick)), columns, bytes);
        }
        let drawn: String = nick.chars().filter(|c| !invisible(*c)).collect();
        // Before the cut, so the cut does not leave part of one, and after.
        let written = self.unmarked(&self.enc.decode(&self.enc.encode(&drawn)));
        let unmarked = self.unmarked(&self.cut(&written, columns, bytes));
        if unmarked.is_empty() {
            "?".into()
        } else {
            unmarked
        }
    }

    /// `name` in `columns` and `bytes`, whichever is less, as the
    /// encoding counts them.
    fn cut(&self, name: &str, columns: usize, bytes: usize) -> String {
        let mut cut = String::new();
        let mut used = 0;
        for c in name.chars().take(columns) {
            let width = match self.enc {
                TextEncoding::MacRoman => 1,
                TextEncoding::Utf8 => c.len_utf8(),
            };
            if used + width > bytes {
                break;
            }
            used += width;
            cut.push(c);
        }
        cut
    }

    fn unmarked(&self, name: &str) -> String {
        let suffix = self.bot_suffix.trim();
        let mut name = name.trim_end();
        loop {
            let before = name;
            if let Some(rest) = strip_suffix(name, suffix) {
                name = rest.trim_end();
            }
            if self.tags {
                if let Some((rest, tag)) = name.rsplit_once('@') {
                    // A bare `@` too, which a marker after it would make
                    // a tag of.
                    if tag.len() <= 8 && tag.bytes().all(|b| b.is_ascii_graphic()) {
                        name = rest.trim_end();
                    }
                }
            }
            if name == before {
                return name.to_owned();
            }
        }
    }
}

/// `name` without `suffix` at its end, matched without regard to ASCII
/// case: where the suffix begins with a letter or digit, only as a word of
/// its own, so a suffix of `bot` leaves `Talbot` its name.
fn strip_suffix<'n>(name: &'n str, suffix: &str) -> Option<&'n str> {
    if suffix.is_empty() || name.len() < suffix.len() {
        return None;
    }
    let at = name.len() - suffix.len();
    if !name.is_char_boundary(at) || !name[at..].eq_ignore_ascii_case(suffix) {
        return None;
    }
    let rest = &name[..at];
    let wordlike = suffix.starts_with(|c: char| c.is_alphanumeric());
    (!wordlike || rest.is_empty() || rest.ends_with(char::is_whitespace)).then_some(rest)
}

/// A character a classic client draws as nothing: a control, NUL among
/// them, or one Unicode says is ignored where it is not understood
/// (Default_Ignorable_Code_Point), which shapes, joins or directs the
/// text around it, selects a variant, or fills a blank.
fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{61c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fff8}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(enc: TextEncoding, tags: bool) -> Names<'static> {
        Names {
            enc,
            bot_suffix: " [bot]",
            tags,
        }
    }

    /// Whatever a name holds, what is sent ends in no marker the server
    /// did not put there.
    #[test]
    fn no_name_ends_in_a_marker_by_itself() {
        let long = "\u{e9}".repeat(11);
        for (nick, tags, list, chat) in [
            ("alice", true, "alice", "alice"),
            ("alice [bot]", false, "alice", "alice"),
            ("alice [BOT]", false, "alice", "alice"),
            ("alice[bot]", false, "alice", "alice"),
            ("alice [bot] [bot]", false, "alice", "alice"),
            ("abcdefg [bot]zzz", false, "abcdefg [bot]zzz", "abcdefg"),
            ("alice [bot]\0x", false, "alice [bot]x", "alice [bot]x"),
            ("alice [bot]\u{1}", false, "alice", "alice"),
            ("alice [bot]\u{200b}", false, "alice", "alice"),
            ("alice [b\u{200b}ot]", false, "alice", "alice"),
            ("alice [bot]\u{fe0f}", false, "alice", "alice"),
            ("alice [bot]\u{e0020}", false, "alice", "alice"),
            ("alice\u{3164}[bot]", false, "alice", "alice"),
            ("alice@bb", false, "alice@bb", "alice@bb"),
            ("alice@bb", true, "alice", "alice"),
            ("a@b@c", true, "a", "a"),
            ("alice@", true, "alice", "alice"),
            ("alice@", false, "alice@", "alice@"),
            ("alice@ninechars", true, "alice@ninechars", "alice"),
            ("abcd@bbbbbbbbZZ", true, "abcd@bbbbbbbbZZ", "abcd"),
            ("[bot]", false, "?", "?"),
            ("Talbot", false, "Talbot", "Talbot"),
        ] {
            let n = names(TextEncoding::Utf8, tags);
            let sent = |b: Vec<u8>| String::from_utf8(b).unwrap();
            assert_eq!(sent(n.nick(nick, None)), list, "{nick:?}");
            assert_eq!(sent(n.column(nick, None)).trim_start(), chat, "{nick:?}");
        }
        // Cut to 31 bytes, a tag too long to be one is one.
        let n = names(TextEncoding::Utf8, true);
        let nick = format!("{long}@abcdefghij");
        assert_eq!(n.nick(&nick, None), long.as_bytes());
        // Mac Roman writes what it cannot as `?`, which a tag may be.
        let n = names(TextEncoding::MacRoman, true);
        assert_eq!(n.nick("alice@\u{4e2d}\u{6587}", None), b"alice");
        // Text every connection shares is judged as Mac Roman writes it
        // too, and cut where both agree.
        let n = names(TextEncoding::Utf8, true);
        assert_eq!(n.text("Bob@\u{4e2d}"), "Bob");
        assert_eq!(n.text("Bob \u{4e2d}"), "Bob \u{4e2d}");
        // A bot named with a bare `@` reads as no tag beside the marker.
        assert_eq!(n.nick("Alice@", Some("!")), b"Alice!");
        // The server's own marker is kept whole, after the name's own
        // is taken off.
        let n = names(TextEncoding::Utf8, true);
        assert_eq!(n.nick("alice [bot]", Some(" [bot]")), b"alice [bot]");
        assert_eq!(n.column("roberta-long", Some("@bb")), b"roberta-lo@bb");
        assert_eq!(n.nick(&"r".repeat(40), Some("@bb")).len(), NICK);
    }

    /// With no marker to keep off, a name goes as it always did.
    #[test]
    fn a_server_with_no_marker_shows_a_name_as_set() {
        let n = Names::plain(TextEncoding::Utf8);
        let dev = "\u{1f469}\u{200d}\u{1f4bb} dev [bot]@bb";
        assert_eq!(n.nick(dev, None), dev.as_bytes());
        assert_eq!(n.nick(&"r".repeat(40), None).len(), NICK);
    }

    #[test]
    fn a_wordlike_suffix_comes_off_only_as_a_word() {
        let n = Names {
            enc: TextEncoding::Utf8,
            bot_suffix: " bot",
            tags: false,
        };
        for (nick, want) in [
            ("Talbot", "Talbot"),
            ("robot", "robot"),
            ("Tal bot", "Tal"),
            ("bot", "?"),
        ] {
            assert_eq!(n.nick(nick, None), want.as_bytes(), "{nick:?}");
        }
    }
}
