//! The news search language (`docs/news.md` §6.2).
//!
//! Ours, closed, and never an error. Handing someone's text to FTS5's
//! `MATCH` is how a search box answers `fts5: syntax error near "-"`, so
//! a query is parsed here into terms made of nothing but words, and each
//! store renders those however it searches. Anything the grammar does not
//! know — an FTS5 operator, a stray quote or paren — is only more text,
//! split into words like the rest of it.
//!
//! A word is a run of letters and digits, lowercased: the split the
//! index's `unicode61` tokenizer makes, give or take the corners of
//! Unicode (the index also folds diacritics, which the in-memory store
//! does not). Because a compiled term holds only such words, no store
//! ever has anything to escape.

/// Terms past this many are dropped, so the expression a store builds is
/// bounded before anything sees it.
pub const MAX_TERMS: usize = 16;
/// Each term's text is cut to this many bytes, at a character boundary.
pub const MAX_TERM_BYTES: usize = 64;

/// Where a term must be found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Subject, body or author.
    Any,
    /// `subject:`
    Subject,
    /// `from:` — the author's nick and login.
    Author,
}

/// One thing a hit must contain — or, negated, must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    /// One word, or a phrase: these words, adjacent and in order.
    pub words: Vec<String>,
    pub field: Field,
    pub negated: bool,
    /// The last word matches any word it begins.
    pub prefix: bool,
}

/// A query as the grammar read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledQuery {
    pub terms: Vec<Term>,
}

/// The words of a text: runs of letters and digits, lowercased.
pub fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl CompiledQuery {
    /// Read a query. Never fails: what the grammar does not recognize is
    /// words, and a term with no words in it — `!!!`, a lone `-` — is
    /// dropped rather than left to match nothing and take the rest of the
    /// query down with it.
    ///
    /// | Input | Meaning |
    /// |---|---|
    /// | `phase 4` | both terms, anywhere |
    /// | `"phase 4"` | the phrase |
    /// | `-legacy` | exclude |
    /// | `subject:sizes` | in the subject only |
    /// | `from:alice` | in the author only |
    /// | `sizes*` | prefix |
    pub fn parse(input: &str) -> Self {
        let s = input;
        let b = s.as_bytes();
        let mut terms = Vec::new();
        let mut i = 0;
        while i < b.len() && terms.len() < MAX_TERMS {
            if b[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            let negated = b[i] == b'-' && b.get(i + 1).is_some_and(|c| !c.is_ascii_whitespace());
            if negated {
                i += 1;
            }
            let mut field = Field::Any;
            for (name, f) in [("subject:", Field::Subject), ("from:", Field::Author)] {
                let named = s
                    .get(i..i + name.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(name));
                if named
                    && b.get(i + name.len())
                        .is_some_and(|c| !c.is_ascii_whitespace())
                {
                    field = f;
                    i += name.len();
                    break;
                }
            }
            let (text, prefix) = if b[i] == b'"' {
                // A phrase runs to the closing quote, or to the end when
                // there is none: a stray quote is a mistake, not a reason
                // to refuse.
                let start = i + 1;
                let end = s[start..].find('"').map_or(s.len(), |n| start + n);
                i = (end + 1).min(s.len());
                let prefix = b.get(i) == Some(&b'*');
                if prefix {
                    i += 1;
                }
                (&s[start..end], prefix)
            } else {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                let raw = &s[start..i];
                let bare = raw.trim_end_matches('*');
                (bare, bare.len() < raw.len())
            };
            let words = words(truncate(text, MAX_TERM_BYTES));
            if words.is_empty() {
                continue;
            }
            terms.push(Term {
                words,
                field,
                negated,
                prefix,
            });
        }
        CompiledQuery { terms }
    }

    /// Add "by this author" — the `from` parameter, which is `from:` said
    /// as a field rather than typed.
    pub fn push_author(&mut self, who: &str) {
        let words = words(truncate(who, MAX_TERM_BYTES));
        if !words.is_empty() {
            self.terms.push(Term {
                words,
                field: Field::Author,
                negated: false,
                prefix: false,
            });
        }
    }

    /// True when no term says what to find. Exclusions alone describe
    /// everything but something, which no index answers; the query
    /// matches nothing, and is told so without asking one.
    pub fn matches_nothing(&self) -> bool {
        !self.terms.iter().any(|t| !t.negated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(words: &[&str]) -> Term {
        Term {
            words: words.iter().map(|w| w.to_string()).collect(),
            field: Field::Any,
            negated: false,
            prefix: false,
        }
    }

    fn parsed(q: &str) -> Vec<Term> {
        CompiledQuery::parse(q).terms
    }

    #[test]
    fn each_row_of_the_grammar() {
        assert_eq!(parsed("phase 4"), [term(&["phase"]), term(&["4"])]);
        assert_eq!(parsed("\"Phase 4\""), [term(&["phase", "4"])]);
        assert_eq!(
            parsed("-legacy"),
            [Term {
                negated: true,
                ..term(&["legacy"])
            }]
        );
        assert_eq!(
            parsed("subject:sizes"),
            [Term {
                field: Field::Subject,
                ..term(&["sizes"])
            }]
        );
        assert_eq!(
            parsed("FROM:Alice"),
            [Term {
                field: Field::Author,
                ..term(&["alice"])
            }]
        );
        assert_eq!(
            parsed("sizes*"),
            [Term {
                prefix: true,
                ..term(&["sizes"])
            }]
        );
        assert_eq!(
            parsed("-subject:\"phase 4\"*"),
            [Term {
                field: Field::Subject,
                negated: true,
                prefix: true,
                ..term(&["phase", "4"])
            }]
        );
    }

    #[test]
    fn anything_else_is_words() {
        // FTS5's own operators, a stray quote, parens, a NEAR group:
        // literal text, split the way the index splits it.
        assert_eq!(
            parsed("(phase OR 4) NEAR/2"),
            [
                term(&["phase"]),
                term(&["or"]),
                term(&["4"]),
                term(&["near", "2"]),
            ]
        );
        assert_eq!(
            parsed("\"unterminated phrase"),
            [term(&["unterminated", "phrase"])]
        );
        assert_eq!(parsed("c++ don't"), [term(&["c"]), term(&["don", "t"])]);
        assert_eq!(
            parsed("a*b"),
            [term(&["a", "b"])],
            "only a trailing star is a prefix"
        );
        // What has no words in it is not a term at all.
        assert!(parsed("!!! - * \"\" subject:")
            .iter()
            .all(|t| t.words == ["subject"]));
        assert!(parsed("   ").is_empty());
    }

    #[test]
    fn every_word_is_something_no_store_has_to_escape() {
        for q in [
            "\"\"\"\"",
            "-\"a\"\"b\"",
            "subject:\"",
            "from:\"*\"",
            "💥 ☃ ñ",
            "'; DROP TABLE news_article; --",
            "{subject author}: x",
        ] {
            for t in parsed(q) {
                assert!(!t.words.is_empty(), "{q:?}");
                assert!(
                    t.words.iter().all(|w| w.chars().all(char::is_alphanumeric)),
                    "{q:?} gave {t:?}"
                );
            }
        }
    }

    #[test]
    fn a_query_is_bounded_before_anything_reads_it() {
        let many: String = (0..40).map(|n| format!("w{n} ")).collect();
        assert_eq!(parsed(&many).len(), MAX_TERMS);
        let long = "é".repeat(100);
        let cut = &parsed(&long)[0].words[0];
        assert!(cut.len() <= MAX_TERM_BYTES);
        assert_eq!(
            cut.chars().count(),
            MAX_TERM_BYTES / 2,
            "cut at a character"
        );
    }

    #[test]
    fn exclusions_alone_match_nothing() {
        assert!(CompiledQuery::parse("-phase -legacy").matches_nothing());
        assert!(CompiledQuery::parse("").matches_nothing());
        assert!(!CompiledQuery::parse("-legacy phase").matches_nothing());
        let mut by = CompiledQuery::parse("");
        by.push_author("Alice");
        assert!(!by.matches_nothing(), "\"everything by alice\" is a search");
        assert_eq!(by.terms[0].field, Field::Author);
    }
}
