//! What may appear in a name this crate carries — a card's display name
//! (§3.4) and an attestation's handle (§3.5).
//!
//! Both are rendered next to each other and next to account logins, so
//! both refuse the characters that render as something other than
//! themselves. `char::is_control` covers `Cc` only; the interesting
//! attacks are all `Cf` — a zero-width space or joiner disappears, and a
//! bidi override reverses what follows it, so `admin\u{200b}@hl.example`
//! and `admin@hl.example` are one string to a reader and two to a
//! server.
//!
//! The table is written out rather than reached for through a Unicode
//! crate: it is short, it doesn't move between Unicode releases in ways
//! that matter here, and this crate has no dependency that carries the
//! character database.

/// A character that renders as nothing, or as something else: controls,
/// `Cf`, and every whitespace character but the plain space. The space
/// itself is a legitimate part of a display name ("Misha Nasledov") and
/// is refused separately where it doesn't belong, as in a handle.
pub(crate) fn is_deceptive(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(c,
            '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}')
}
