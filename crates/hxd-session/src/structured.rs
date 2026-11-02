//! A chat line as a Chat History entry (`docs/chat-history.md` §12): what
//! Get Chat History (700) answers with, and with the Structured Chat
//! draft's capability bit 17, what each Chat Message (106) relaying a
//! line carries beside its formatted text. One encoder for both, so a
//! line seen live and the same line paged back cannot disagree.

use std::time::SystemTime;

use hxproto::build::{build_history_entry, HistorySubfield};

use crate::encoding::TextEncoding;

/// `DATA_CHAT_LINE`: the draft's, and not allocated.
pub const DATA_CHAT_LINE: u16 = 0x0f33;

/// The draft's entry flag for an id from the chat's own count rather than
/// the log's. Never set in a 700 entry.
pub const EPHEMERAL: u16 = 1 << 3;

/// What an entry says of one line.
pub(crate) struct Line<'a> {
    pub id: u64,
    pub at: SystemTime,
    pub flags: u16,
    pub icon: u16,
    /// Already in the session's encoding and cut as it shows names.
    pub nick: &'a [u8],
    pub text: &'a str,
    pub subfields: &'a [(u16, Vec<u8>)],
}

/// The entry for `line`, its text in `enc` with the session's line
/// endings. The text is what can grow past the field's 16-bit length,
/// Mac Roman's three times over as UTF-8, so it is cut at a character
/// boundary where the entry would not fit.
pub(crate) fn entry(enc: TextEncoding, line: &Line<'_>) -> Vec<u8> {
    const FIXED: usize = 24;
    let room = (u16::MAX as usize).saturating_sub(
        FIXED
            + line.nick.len()
            + line
                .subfields
                .iter()
                .map(|(_, d)| 4 + d.len())
                .sum::<usize>(),
    );
    let text = enc.body_capped(line.text, room);
    let subfields: Vec<_> = line
        .subfields
        .iter()
        .map(|(ty, data)| HistorySubfield { ty: *ty, data })
        .collect();
    let at = line
        .at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64);
    build_history_entry(
        line.id, at, line.flags, line.icon, line.nick, &text, &subfields,
    )
    .expect("an entry whose text is cut to its field fits it")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_too_long_for_the_field_is_cut_at_a_character_boundary() {
        // Mac Roman's 0xA5 is U+2022, three bytes as UTF-8.
        let text = "\u{2022}".repeat(30_000);
        let nick = b"alice";
        for enc in [TextEncoding::Utf8, TextEncoding::MacRoman] {
            let line = Line {
                id: 7,
                at: SystemTime::UNIX_EPOCH,
                flags: 0,
                icon: 0,
                nick,
                text: &text,
                subfields: &[],
            };
            let entry = entry(enc, &line);
            let parsed = hxproto::parse::parse_history_entry(&entry).unwrap();
            let want = match enc {
                TextEncoding::Utf8 => (u16::MAX as usize - 24 - nick.len()) / 3 * 3,
                TextEncoding::MacRoman => 30_000,
            };
            assert_eq!(parsed.message.len(), want, "{enc:?}");
            assert!(entry.len() <= u16::MAX as usize);
            if enc == TextEncoding::Utf8 {
                assert!(std::str::from_utf8(parsed.message).is_ok());
            }
        }
    }
}
