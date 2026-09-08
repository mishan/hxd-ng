//! What may appear in a name this crate carries — a card's display name
//! (§3.4) and an attestation's handle (§3.5).
//!
//! Both are rendered next to each other and next to account logins, so
//! both refuse the characters that render as something other than
//! themselves. `char::is_control` covers `Cc` only; the interesting
//! attacks are all invisible — a zero-width space or joiner disappears,
//! a variation selector attaches to nothing, and a bidi override
//! reverses what follows it, so `admin\u{200b}@hl.example` and
//! `admin@hl.example` are one string to a reader and two to a server.
//!
//! The table is written out rather than reached for through a Unicode
//! crate: it is short, it doesn't move between Unicode releases in ways
//! that matter here, and this crate has no dependency that carries the
//! character database.

/// A character that renders as nothing, or as something else: controls,
/// every whitespace character but the plain space, and everything
/// invisible.
///
/// The invisible half is Unicode's `Default_Ignorable_Code_Point`
/// written out — which is the property that means "renders as nothing
/// when unsupported", so it covers the variation selectors (`admin` plus
/// U+FE0F is `admin`), the Hangul fillers, and the combining grapheme
/// joiner, none of which are `Cf` — plus the `Cf` characters outside it
/// and U+2800 BRAILLE PATTERN BLANK, which is a printing character whose
/// glyph is blank.
///
/// The plain space is a legitimate part of a display name ("Alice
/// Anderson") and is refused separately where it doesn't belong, as in a
/// handle.
pub(crate) fn is_deceptive(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(c,
            // Default_Ignorable_Code_Point, in order.
            '\u{00ad}'                      // SOFT HYPHEN
            | '\u{034f}'                    // COMBINING GRAPHEME JOINER
            | '\u{061c}'                    // ARABIC LETTER MARK
            | '\u{115f}'..='\u{1160}'       // HANGUL CHOSEONG/JUNGSEONG FILLER
            | '\u{17b4}'..='\u{17b5}'       // KHMER INHERENT VOWELS
            | '\u{180b}'..='\u{180f}'       // MONGOLIAN selectors and separator
            | '\u{200b}'..='\u{200f}'       // zero-width space .. RLM
            | '\u{202a}'..='\u{202e}'       // bidi embedding and override
            | '\u{2060}'..='\u{206f}'       // word joiner .. deprecated bidi
            | '\u{3164}'                    // HANGUL FILLER
            | '\u{fe00}'..='\u{fe0f}'       // VARIATION SELECTOR-1..16
            | '\u{feff}'                    // ZERO WIDTH NO-BREAK SPACE
            | '\u{ffa0}'                    // HALFWIDTH HANGUL FILLER
            | '\u{fff0}'..='\u{fff8}'       // reserved, ignorable
            | '\u{1bca0}'..='\u{1bca3}'     // SHORTHAND FORMAT
            | '\u{1d173}'..='\u{1d17a}'     // MUSICAL SYMBOL BEGIN/END
            | '\u{e0000}'..='\u{e0fff}'     // tags and VARIATION SELECTOR-17..256
            // `Cf` outside that property: prefixes and marks that take
            // their width from what follows them, and the interlinear
            // annotation characters.
            | '\u{0600}'..='\u{0605}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{fff9}'..='\u{fffb}'
            // Not ignorable, not `Cf`, and blank all the same.
            | '\u{2800}') // BRAILLE PATTERN BLANK
}

#[cfg(test)]
mod tests {
    use super::is_deceptive;

    #[test]
    fn the_table_covers_what_renders_as_nothing() {
        // One from each shape the review found missing.
        for c in [
            '\u{fe0f}',  // VS16: `admin\u{fe0f}` renders as `admin`
            '\u{034f}',  // combining grapheme joiner
            '\u{1160}',  // Hangul junseong filler
            '\u{3164}',  // Hangul filler
            '\u{2800}',  // Braille blank
            '\u{e0100}', // variation selector supplement
            '\u{0600}',  // Arabic number sign
            '\u{070f}',  // Syriac abbreviation mark
            '\u{200b}',  // zero-width space
            '\u{202e}',  // right-to-left override
            '\u{feff}',  // BOM
            '\u{00ad}',  // soft hyphen
            '\u{0009}',  // control
            '\u{00a0}',  // no-break space
        ] {
            assert!(is_deceptive(c), "U+{:04X} must be refused", c as u32);
        }
        // And nothing a name is made of.
        for c in "Alice Anderson Ø é 日本語 ✓".chars() {
            assert!(!is_deceptive(c), "U+{:04X} must be allowed", c as u32);
        }
    }
}
