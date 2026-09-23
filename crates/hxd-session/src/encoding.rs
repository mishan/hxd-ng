//! The text encoding of one legacy connection: Mac Roman, or UTF-8 when
//! the client negotiated `CAPABILITY_TEXT_ENCODING` (bit 1 of
//! `DATA_CAPABILITIES`). Source: fogWraith
//! `Docs/Protocol/Capabilities-Text-Encoding.md`.
//!
//! The domain is UTF-8 either way, so this is only ever a question about
//! bytes at this crate's edge: every text field in and out goes through
//! one of these methods, and the connection's [`TextEncoding`] decides
//! what they do. Mac Roman is what every client that didn't ask gets,
//! and its output is byte for byte what this frontend sent before the
//! extension existed.
//!
//! Two things differ beyond the conversion itself:
//!
//! - **Line endings.** A body leaves as CR for Mac Roman and LF for
//!   UTF-8, whichever the sender's wire gave the domain (the spec's
//!   normalization; see [`TextEncoding::body`]).
//! - **Length caps.** Outbound, the wire's byte limits (31 for a nick,
//!   255 for a subject) stay the same, but a UTF-8 cut must land on a
//!   character boundary or the client receives a broken sequence.
//!   Inbound, a name, password or subject is capped in characters
//!   ([`TextEncoding::decode_chars`]), so the same text means the same
//!   thing from either wire: a password of twenty accented letters is
//!   twenty bytes in Mac Roman and forty in UTF-8, and a byte cap would
//!   let one client in and turn the other away. Mac Roman is one byte
//!   per character, so every cap lands where it always has.

use hxproto::text;

use crate::caps::{cap, Caps};

/// One connection's text encoding, fixed at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextEncoding {
    /// The classic wire, and the fallback for every client that did not
    /// negotiate. Unmappable characters leave as `?`.
    #[default]
    MacRoman,
    /// Negotiated: the client sends and receives UTF-8 in every text
    /// field. The bit means UTF-8 specifically, not "some encoding".
    Utf8,
}

impl TextEncoding {
    /// The encoding a session's negotiated capabilities give it.
    pub const fn negotiated(caps: Caps) -> Self {
        if caps.has(cap::TEXT_ENCODING) {
            TextEncoding::Utf8
        } else {
            TextEncoding::MacRoman
        }
    }

    /// UTF-8 → wire bytes, with no other change.
    pub fn encode(self, s: &str) -> Vec<u8> {
        match self {
            TextEncoding::MacRoman => text::from_utf8(s),
            TextEncoding::Utf8 => s.as_bytes().to_vec(),
        }
    }

    /// [`Self::encode`], cut to at most `max` bytes without splitting a
    /// character.
    pub fn encode_capped(self, s: &str, max: usize) -> Vec<u8> {
        match self {
            TextEncoding::MacRoman => {
                let mut v = text::from_utf8(s);
                v.truncate(max);
                v
            }
            TextEncoding::Utf8 => s.as_bytes()[..floor_char_boundary(s, max)].to_vec(),
        }
    }

    /// A body — a message, an agreement, a comment — with the line
    /// endings this connection uses: CR for Mac Roman, LF for UTF-8.
    ///
    /// The conversion belongs here and not in the stored text: the domain
    /// holds whatever the sender's wire gave it — an ng client's `\n`, a
    /// legacy client's `\r` — and each connection renders that in its own
    /// terms, exactly as with the encoding itself. A 1.x client draws a
    /// bare `\n` as a glyph rather than a line break, so a multi-line
    /// private message from an ng client arrived as one run of text with
    /// a symbol in it, and the queued stamp (which is `\r`) made a body
    /// with both. CRLF collapses to one break either way, or the pair
    /// renders as a blank line.
    pub fn body(self, s: &str) -> Vec<u8> {
        let eol = match self {
            TextEncoding::MacRoman => b'\r',
            TextEncoding::Utf8 => b'\n',
        };
        let bytes = self.encode(s);
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\r' if bytes.get(i + 1) == Some(&b'\n') => {
                    out.push(eol);
                    i += 2;
                }
                b'\r' | b'\n' => {
                    out.push(eol);
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        out
    }

    /// [`Self::body`], cut to at most `max` bytes without splitting a
    /// character. The cut is on the converted bytes, so a CRLF that
    /// collapsed to one byte leaves room for the text after it.
    pub fn body_capped(self, s: &str, max: usize) -> Vec<u8> {
        let mut v = self.body(s);
        if v.len() > max {
            let cut = match self {
                TextEncoding::MacRoman => max,
                TextEncoding::Utf8 => utf8_floor(&v, max),
            };
            v.truncate(cut);
        }
        v
    }

    /// Wire bytes → UTF-8. Mac Roman is injective, so legacy-origin text
    /// round-trips exactly. Bytes that are not UTF-8 from a client that
    /// said they would be become U+FFFD: the spec's best effort, and never
    /// a reason to drop the transaction.
    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            TextEncoding::MacRoman => text::to_utf8(bytes),
            TextEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        }
    }

    /// [`Self::decode`] of at most the first `max` bytes. For UTF-8 a
    /// character the cut split is dropped whole rather than turned into a
    /// replacement character: the client sent a valid string and the
    /// server chose where to end it.
    pub fn decode_capped(self, bytes: &[u8], max: usize) -> String {
        let bytes = &bytes[..bytes.len().min(max)];
        match self {
            TextEncoding::MacRoman => text::to_utf8(bytes),
            TextEncoding::Utf8 => {
                String::from_utf8_lossy(&bytes[..complete_prefix(bytes)]).into_owned()
            }
        }
    }

    /// [`Self::decode`] of at most the first `max` characters: for the
    /// fields whose limit is a length the user sees (a login, a password,
    /// a nick, a subject), which must cut the same text at the same place
    /// whichever encoding carried it. The frame's own cap bounds the
    /// bytes.
    pub fn decode_chars(self, bytes: &[u8], max: usize) -> String {
        match self {
            TextEncoding::MacRoman => text::to_utf8(&bytes[..bytes.len().min(max)]),
            TextEncoding::Utf8 => String::from_utf8_lossy(bytes).chars().take(max).collect(),
        }
    }

    /// The name column of a server-formatted chat line: right-aligned in
    /// 13 columns and cut to 13 (the reference server's `%13.13s`). For
    /// Mac Roman a column is a byte, as it always was; for UTF-8 it is a
    /// character, so a name in any script lines up the way an ASCII one
    /// does rather than being cut mid-sequence.
    pub(crate) fn name_column(self, nick: &[u8]) -> Vec<u8> {
        const WIDTH: usize = 13;
        let shown = match self {
            TextEncoding::MacRoman => &nick[..nick.len().min(WIDTH)],
            TextEncoding::Utf8 => {
                let end = nick
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| !is_continuation(**b))
                    .nth(WIDTH)
                    .map_or(nick.len(), |(i, _)| i);
                &nick[..end]
            }
        };
        let width = match self {
            TextEncoding::MacRoman => shown.len(),
            TextEncoding::Utf8 => shown.iter().filter(|b| !is_continuation(**b)).count(),
        };
        let mut out = vec![b' '; WIDTH.saturating_sub(width)];
        out.extend_from_slice(shown);
        out
    }
}

fn is_continuation(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// The largest index `<= max` that is a character boundary of `s`.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    (0..=max)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0)
}

/// The largest index `<= max` that does not fall inside a UTF-8 sequence
/// of `bytes`, which may not be valid UTF-8 as a whole.
fn utf8_floor(bytes: &[u8], max: usize) -> usize {
    let mut i = max.min(bytes.len());
    while i > 0 && i < bytes.len() && is_continuation(bytes[i]) {
        i -= 1;
    }
    i
}

/// The length of `bytes` without a trailing sequence that is incomplete
/// only because the bytes stop — a cut, not an error. Anything else that
/// is invalid is left for the lossy decode to replace.
fn complete_prefix(bytes: &[u8]) -> usize {
    let mut start = 0;
    loop {
        match std::str::from_utf8(&bytes[start..]) {
            Ok(_) => return bytes.len(),
            // `None` is "the input ended mid-sequence": the tail.
            Err(e) => match e.error_len() {
                None => return start + e.valid_up_to(),
                Some(bad) => start += e.valid_up_to() + bad,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MR: TextEncoding = TextEncoding::MacRoman;
    const U8: TextEncoding = TextEncoding::Utf8;

    #[test]
    fn the_bit_picks_the_encoding() {
        assert_eq!(TextEncoding::negotiated(Caps::empty()), MR);
        assert_eq!(TextEncoding::negotiated(Caps::empty().with(cap::VOICE)), MR);
        assert_eq!(
            TextEncoding::negotiated(Caps::empty().with(cap::TEXT_ENCODING)),
            U8
        );
    }

    #[test]
    fn mac_roman_is_what_it_always_was() {
        assert_eq!(MR.encode("caf\u{e9}"), text::from_utf8("caf\u{e9}"));
        assert_eq!(MR.encode("caf\u{e9}"), b"caf\x8e");
        assert_eq!(MR.decode(b"caf\x8e"), "caf\u{e9}");
        // Unmappable leaves as `?`.
        assert_eq!(MR.encode("\u{3042}"), b"?");
    }

    #[test]
    fn utf8_passes_through() {
        assert_eq!(
            U8.encode("caf\u{e9} \u{3042}"),
            "caf\u{e9} \u{3042}".as_bytes()
        );
        assert_eq!(
            U8.decode("caf\u{e9} \u{3042}".as_bytes()),
            "caf\u{e9} \u{3042}"
        );
        // Not UTF-8 after all: replaced, never refused.
        assert_eq!(U8.decode(b"caf\x8e"), "caf\u{fffd}");
    }

    #[test]
    fn a_body_leaves_with_this_connections_line_ending() {
        assert_eq!(MR.body("one\ntwo"), b"one\rtwo");
        assert_eq!(MR.body("one\r\ntwo"), b"one\rtwo");
        assert_eq!(MR.body("one\rtwo"), b"one\rtwo", "already this wire's");
        assert_eq!(MR.body("a\n\nb\n"), b"a\r\rb\r");
        // The queued stamp is a `\r`; a Mac Roman body keeps it and
        // converts the ellipsis.
        assert_eq!(MR.body("[queued \u{2026}]\rbody\nmore"), {
            let mut want = b"[queued ".to_vec();
            want.extend_from_slice(&text::from_utf8("\u{2026}"));
            want.extend_from_slice(b"]\rbody\rmore");
            want
        });
        assert_eq!(U8.body("one\rtwo"), b"one\ntwo");
        assert_eq!(U8.body("one\r\ntwo"), b"one\ntwo");
        assert_eq!(U8.body("one\ntwo"), b"one\ntwo", "already this wire's");
        assert_eq!(U8.body("a\r\rb\r"), b"a\n\nb\n");
        assert_eq!(
            U8.body("[queued \u{2026}]\rbody"),
            "[queued \u{2026}]\nbody".as_bytes()
        );
    }

    #[test]
    fn caps_never_split_a_character() {
        // Mac Roman: one byte a character, cut where it always was.
        assert_eq!(MR.encode_capped("abcdef", 3), b"abc");
        // "é" is two bytes in UTF-8; a cap landing inside it drops it.
        assert_eq!(U8.encode_capped("ab\u{e9}", 3), b"ab");
        assert_eq!(U8.encode_capped("ab\u{e9}", 4), "ab\u{e9}".as_bytes());
        assert_eq!(U8.encode_capped("\u{3042}", 2), b"");
        assert_eq!(U8.body_capped("ab\u{e9}", 3), b"ab");
        assert_eq!(U8.body_capped("a\r\nb", 3), b"a\nb");
        // Inbound, a cap is the server's choice, not the client's error.
        assert_eq!(U8.decode_capped("ab\u{e9}".as_bytes(), 3), "ab");
        assert_eq!(U8.decode_capped("ab\u{e9}".as_bytes(), 4), "ab\u{e9}");
        assert_eq!(MR.decode_capped(b"abc\x8e", 3), "abc");
        // A genuinely broken byte before the cut is still replaced.
        assert_eq!(U8.decode_capped(b"a\xffb\xc3", 4), "a\u{fffd}b");
    }

    #[test]
    fn a_character_cap_cuts_the_same_text_from_either_wire() {
        let password = "\u{e4}".repeat(20);
        let mac = MR.encode(&password);
        let utf = U8.encode(&password);
        assert_eq!((mac.len(), utf.len()), (20, 40));
        assert_eq!(MR.decode_chars(&mac, 31), password);
        assert_eq!(U8.decode_chars(&utf, 31), password);
        // Past the cap, both keep the same first 31 characters.
        let long = "\u{e4}".repeat(40);
        let want = "\u{e4}".repeat(31);
        assert_eq!(MR.decode_chars(&MR.encode(&long), 31), want);
        assert_eq!(U8.decode_chars(&U8.encode(&long), 31), want);
        assert_eq!(MR.decode_chars(b"abcdef", 3), "abc");
    }

    #[test]
    fn the_name_column_counts_characters_on_utf8() {
        assert_eq!(MR.name_column(b"bob"), b"          bob");
        assert_eq!(MR.name_column(b"abcdefghijklmnop"), b"abcdefghijklm");
        assert_eq!(
            U8.name_column("\u{3042}\u{3044}".as_bytes()),
            ["           ".as_bytes(), "\u{3042}\u{3044}".as_bytes()].concat()
        );
        let long = "\u{e9}".repeat(15);
        assert_eq!(
            U8.name_column(long.as_bytes()),
            "\u{e9}".repeat(13).as_bytes()
        );
    }
}
