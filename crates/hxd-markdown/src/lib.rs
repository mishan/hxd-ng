//! Markdown bodies for the news (`docs/news.md` §5): what a markdown
//! article says to a reader who cannot render markdown, and which
//! articles it points at.
//!
//! **Text in, text out, and never HTML.** The server stores the source
//! exactly as typed and hands it to ng clients to draw; what it makes here
//! is the plain-text downgrade a 1.5 client and the search index read
//! (§5.4), and the references a body resolves to (§5.3). Nothing produces
//! markup for a browser to interpret, so the injection surface a
//! markdown-to-HTML server would open does not exist. pulldown-cmark is
//! built without its `html` feature to keep it that way: there is no HTML
//! writer in this binary to call by mistake.
//!
//! **The dialect** is CommonMark with GitHub's tables and strikethrough,
//! minus two things (§5.2). Raw HTML is literal text, in the downgrade as
//! in any client. And an image by URL is never an image: an article's
//! pictures are its attachments, and a body that makes a reader fetch
//! `https://tracker.example/pixel.gif` reports that reader's address to a
//! stranger. Here it becomes a link to where it would have been fetched
//! from, which is exactly what it is.
//!
//! **References** are the `news:` scheme — `[the sizes thread](news:51)` —
//! and the `#51` shorthand, found by `hxd-core`'s scanner in the prose and
//! never in code: an article quoting a shell prompt or a C preprocessor
//! line is not citing anything.
//!
//! Behind `hxd-core`'s [`BodyRenderer`], in its own crate and behind the
//! `markdown` feature — the `hxd-media` shape, for the same reason: a
//! server that wants no parser does not link one.

use hxd_core::news::{scan_refs, ArticleId, BodyRenderer, Rendered};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};

/// The renderer `hxd` gives the domain when `[news] markdown = "render"`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Markdown;

impl BodyRenderer for Markdown {
    fn render(&self, source: &str, limit: usize) -> Rendered {
        render(source, limit)
    }
}

/// How a truncated downgrade ends. Three bytes, and counted inside the
/// limit.
const CUT: &str = "…";

/// A block that puts something at the start of every line inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    /// `> `.
    Quote,
    /// A list item's continuation lines, indented under its marker.
    Item { width: usize },
    /// A code block's lines, indented four spaces with the fences gone.
    Code,
}

/// The plain text as it is written, and the references found on the way.
struct Writer {
    out: String,
    limit: usize,
    cut: bool,
    stack: Vec<Container>,
    /// A list item's marker, waiting for the item's first line.
    marker: Option<String>,
    /// Lists open, innermost last: `None` for bullets, the next number
    /// for an ordered list.
    lists: Vec<Option<u64>>,
    at_line_start: bool,
    /// A blank line is owed before the next block.
    blank: bool,
    /// Inside a link or an image: where it goes, and its text so far.
    link: Option<(String, String)>,
    /// Inside a table row, and whether a cell has been written in it yet.
    cells: Option<bool>,
    /// Prose waiting to be scanned for the `#51` shorthand. Scanned
    /// whenever anything else happens, so a scan never spans code.
    prose: String,
    refs: Vec<ArticleId>,
}

/// Render `source` to plain text of at most `limit` bytes, and find what
/// it references. A downgrade can be longer than its source — every link
/// grows — so it is cut, at a character boundary, with a trailing `…`.
pub fn render(source: &str, limit: usize) -> Rendered {
    let mut w = Writer {
        out: String::new(),
        limit,
        cut: false,
        stack: Vec::new(),
        marker: None,
        lists: Vec::new(),
        at_line_start: true,
        blank: false,
        link: None,
        cells: None,
        prose: String::new(),
        refs: Vec::new(),
    };
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    for event in Parser::new_ext(source, options) {
        w.event(event);
    }
    w.scan_prose();
    let plain = w.out.trim_end().to_string();
    Rendered {
        plain,
        refs: w.refs,
    }
}

/// The article a `news:` destination names, if it names one: digits only,
/// nonzero, and an id the legacy wire can carry.
fn news_target(dest: &str) -> Option<ArticleId> {
    let digits = dest.strip_prefix("news:")?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<ArticleId>().ok().filter(|&id| id != 0)
}

impl Writer {
    fn event(&mut self, event: Event<'_>) {
        if !matches!(event, Event::Text(_)) || self.in_code() {
            self.scan_prose();
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(text) => {
                if !self.in_code() {
                    self.prose.push_str(&text);
                }
                self.text(&text);
            }
            // Kept delimited: a backticked command is not decoration, and
            // a text view reads it better with the ticks than without.
            Event::Code(code) => {
                self.text("`");
                self.text(&code);
                self.text("`");
            }
            // Literal, never interpreted, on the way in and on the way
            // out (§5.2).
            Event::Html(html) | Event::InlineHtml(html) => self.text(&html),
            Event::SoftBreak | Event::HardBreak => self.newline(),
            Event::Rule => {
                self.open_block();
                self.text("---");
                self.close_block();
            }
            Event::TaskListMarker(done) => self.text(if done { "[x] " } else { "[ ] " }),
            Event::FootnoteReference(label) => {
                self.text("[^");
                self.text(&label);
                self.text("]");
            }
            // Math is not enabled; if it ever arrives, the source is the
            // best plain text there is.
            Event::InlineMath(math) | Event::DisplayMath(math) => self.text(&math),
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph | Tag::Heading { .. } | Tag::HtmlBlock => self.open_block(),
            Tag::BlockQuote(_) => {
                self.open_block();
                self.stack.push(Container::Quote);
            }
            Tag::CodeBlock(kind) => {
                self.open_block();
                // An indented block is already indented in the source and
                // arrives without it; a fenced one never had it. Both
                // come out four spaces in, the fences gone.
                let _ = matches!(kind, CodeBlockKind::Fenced(_));
                self.stack.push(Container::Code);
            }
            Tag::List(first) => {
                // A nested list starts on its own line, inside the item.
                if !self.lists.is_empty() {
                    self.newline_if_needed();
                } else {
                    self.open_block();
                }
                self.lists.push(first);
            }
            Tag::Item => {
                self.newline_if_needed();
                if self.blank {
                    self.blank_line();
                    self.blank = false;
                }
                let marker = match self.lists.last_mut() {
                    Some(Some(n)) => {
                        let m = format!("{n}. ");
                        *n = n.saturating_add(1);
                        m
                    }
                    _ => "- ".to_string(),
                };
                self.stack.push(Container::Item {
                    width: marker.chars().count(),
                });
                self.marker = Some(marker);
            }
            Tag::Table(_) => self.open_block(),
            Tag::TableHead | Tag::TableRow => {
                self.newline_if_needed();
                self.cells = Some(false);
            }
            Tag::TableCell => {
                if self.cells == Some(true) {
                    self.text("\t");
                }
                self.cells = Some(true);
            }
            Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                if let Some(id) = news_target(&dest_url) {
                    self.reference(id);
                }
                self.link = Some((dest_url.to_string(), String::new()));
            }
            // Emphasis, strong and strikethrough lose their markers and
            // keep their words; nothing else here is enabled.
            _ => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::HtmlBlock | TagEnd::Table => {
                self.close_block()
            }
            TagEnd::BlockQuote(_) => {
                self.pop(Container::Quote);
                self.close_block();
            }
            TagEnd::CodeBlock => {
                self.pop(Container::Code);
                self.close_block();
            }
            TagEnd::List(_) => {
                self.lists.pop();
                if self.lists.is_empty() {
                    self.close_block();
                }
            }
            TagEnd::Item => {
                self.marker = None;
                self.stack.pop();
                self.newline_if_needed();
            }
            TagEnd::TableHead | TagEnd::TableRow => {
                self.cells = None;
                self.newline_if_needed();
            }
            TagEnd::Link | TagEnd::Image => {
                let Some((dest, text)) = self.link.take() else {
                    return;
                };
                let text = text.trim();
                let shown = match news_target(&dest) {
                    Some(id) => format!("news #{id}"),
                    None => dest.clone(),
                };
                // An autolink's text is its destination; saying it twice
                // helps nobody.
                let same = text == dest || dest.strip_prefix("mailto:") == Some(text);
                if !same && !dest.is_empty() {
                    if text.is_empty() {
                        self.text(&shown);
                    } else {
                        self.text(" (");
                        self.text(&shown);
                        self.text(")");
                    }
                }
            }
            _ => {}
        }
    }

    fn in_code(&self) -> bool {
        self.stack.last() == Some(&Container::Code)
    }

    fn pop(&mut self, want: Container) {
        if let Some(i) = self.stack.iter().rposition(|c| *c == want) {
            self.stack.truncate(i);
        }
    }

    /// Scan what prose has gathered for the shorthand, and let it go.
    fn scan_prose(&mut self) {
        if self.prose.is_empty() {
            return;
        }
        for id in scan_refs(&self.prose) {
            self.reference(id);
        }
        self.prose.clear();
    }

    fn reference(&mut self, id: ArticleId) {
        if !self.refs.contains(&id) {
            self.refs.push(id);
        }
    }

    /// Start a block: on a line of its own, after a blank line when the
    /// block before it asked for one.
    fn open_block(&mut self) {
        self.newline_if_needed();
        if self.blank && !self.out.is_empty() {
            self.blank_line();
        }
        self.blank = false;
    }

    fn close_block(&mut self) {
        self.newline_if_needed();
        self.blank = true;
    }

    fn newline_if_needed(&mut self) {
        if !self.at_line_start {
            self.newline();
        }
    }

    fn newline(&mut self) {
        self.raw("\n");
        self.at_line_start = true;
    }

    /// A blank line inside whatever is open: a quote's is `>`, anything
    /// else's is empty, and none of them carries trailing spaces.
    fn blank_line(&mut self) {
        let prefix: String = self
            .stack
            .iter()
            .map(|c| match c {
                Container::Quote => "> ",
                _ => "",
            })
            .collect();
        let prefix = prefix.trim_end().to_string();
        self.raw(&prefix);
        self.raw("\n");
        self.at_line_start = true;
    }

    /// Text, a line at a time, each line begun with what its containers
    /// put there.
    fn text(&mut self, text: &str) {
        if let Some((_, shown)) = self.link.as_mut() {
            shown.push_str(text);
        }
        let mut lines = text.split('\n').peekable();
        while let Some(line) = lines.next() {
            if !line.is_empty() {
                if self.at_line_start {
                    self.prefix();
                }
                self.raw(line);
                self.at_line_start = false;
            }
            if lines.peek().is_some() {
                self.newline();
            }
        }
    }

    fn prefix(&mut self) {
        let mut prefix = String::new();
        let innermost_item = self
            .stack
            .iter()
            .rposition(|c| matches!(c, Container::Item { .. }));
        for (i, c) in self.stack.iter().enumerate() {
            match c {
                Container::Quote => prefix.push_str("> "),
                Container::Code => prefix.push_str("    "),
                Container::Item { width } => match (&self.marker, Some(i) == innermost_item) {
                    (Some(marker), true) => prefix.push_str(marker),
                    _ => prefix.extend(std::iter::repeat_n(' ', *width)),
                },
            }
        }
        self.marker = None;
        self.raw(&prefix);
    }

    /// The one place bytes are written, and the one place the limit is
    /// kept.
    fn raw(&mut self, s: &str) {
        if self.cut || s.is_empty() {
            return;
        }
        if self.out.len() + s.len() <= self.limit.saturating_sub(CUT.len()) {
            self.out.push_str(s);
            return;
        }
        let room = self.limit.saturating_sub(CUT.len() + self.out.len());
        let mut end = room.min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.out.push_str(&s[..end]);
        if self.out.len() + CUT.len() <= self.limit {
            self.out.push_str(CUT);
        }
        self.cut = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(source: &str) -> String {
        render(source, 65_535).plain
    }

    #[test]
    fn emphasis_loses_its_markers_and_keeps_its_words() {
        assert_eq!(
            plain("some **bold**, some *italic*, some ~~gone~~"),
            "some bold, some italic, some gone"
        );
    }

    #[test]
    fn a_heading_is_its_text_and_a_blank_line() {
        assert_eq!(
            plain("# Phase 4\nNews, finally."),
            "Phase 4\n\nNews, finally."
        );
    }

    #[test]
    fn lists_keep_the_shape_markdown_borrowed_from_plain_text() {
        assert_eq!(plain("* one\n* two"), "- one\n- two");
        assert_eq!(plain("3. three\n4. four"), "3. three\n4. four");
        assert_eq!(
            plain("- outer\n  - inner\n- after"),
            "- outer\n  - inner\n- after"
        );
    }

    #[test]
    fn code_is_indented_four_and_its_fences_go() {
        assert_eq!(
            plain("Run it:\n\n```sh\nhxd --config x\ncargo test\n```\n\nThen wait."),
            "Run it:\n\n    hxd --config x\n    cargo test\n\nThen wait."
        );
        assert_eq!(
            plain("use `hxd news-reindex` then"),
            "use `hxd news-reindex` then"
        );
    }

    #[test]
    fn a_quote_is_quoted_line_by_line() {
        assert_eq!(
            plain("> first\n> second\n>\n> third"),
            "> first\n> second\n>\n> third"
        );
    }

    #[test]
    fn links_say_where_they_go() {
        assert_eq!(
            plain("settled in [the sizes thread](news:51), see [docs](https://hl.example/x)"),
            "settled in the sizes thread (news #51), see docs (https://hl.example/x)"
        );
        assert_eq!(plain("<https://hl.example>"), "https://hl.example");
        assert_eq!(
            plain("a bare #51 stays as typed"),
            "a bare #51 stays as typed"
        );
    }

    #[test]
    fn an_image_by_url_is_a_link_and_never_an_image() {
        assert_eq!(
            plain("![a pixel](https://tracker.example/p.gif)"),
            "a pixel (https://tracker.example/p.gif)"
        );
    }

    #[test]
    fn raw_html_is_literal() {
        assert_eq!(
            plain("<script>alert(1)</script>\n\nand <b>this</b>"),
            "<script>alert(1)</script>\n\nand <b>this</b>"
        );
    }

    #[test]
    fn a_table_is_its_cells() {
        assert_eq!(
            plain("| size | bytes |\n|---|---|\n| full | 412000 |\n| legacy | 60000 |"),
            "size\tbytes\nfull\t412000\nlegacy\t60000"
        );
    }

    #[test]
    fn references_are_links_and_shorthand_in_prose_and_nothing_in_code() {
        let r = render(
            "See [the sizes](news:51) and #47, not `#12` nor\n\n```\n#13\n```\n\nand [again](news:51), #0 or #x.",
            65_535,
        );
        assert_eq!(r.refs, [51, 47], "in order of appearance, once each");
        assert!(render("# 51 is a heading", 100).refs.is_empty());
        assert!(render("[not ours](news:5x) [nor](news:)", 100)
            .refs
            .is_empty());
    }

    #[test]
    fn a_downgrade_that_outgrows_its_limit_is_cut_on_a_character() {
        let long = "[é](https://hl.example/aaaaaaaaaa) ".repeat(50);
        let r = render(&long, 100);
        assert!(r.plain.len() <= 100, "{}", r.plain.len());
        assert!(r.plain.ends_with('…'));
        assert!(std::str::from_utf8(r.plain.as_bytes()).is_ok());
    }

    #[test]
    fn deep_nesting_costs_only_what_the_limit_allows() {
        // A quote opened thousands deep and then continued lazily would
        // repeat its prefix on every line: quadratic output from linear
        // input, were it not for the limit.
        let mut body = ">".repeat(5_000);
        body.push_str(" deep\n");
        body.push_str(&"lazy\n".repeat(5_000));
        let started = std::time::Instant::now();
        let r = render(&body, 65_535);
        assert!(r.plain.len() <= 65_535);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // A run of delimiters with nothing to close it is literal. (Alone
        // on a line it would be a thematic break, which is CommonMark's
        // business, so it sits in prose here.)
        let stars = format!("a {} b", "*".repeat(5_000));
        assert_eq!(plain(&stars), stars);
    }
}
