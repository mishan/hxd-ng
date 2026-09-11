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
//! in any client, and opaque: never prose, so never scanned for a
//! reference. And an image by URL is never an image: an article's
//! pictures are its attachments, and a body that makes a reader fetch
//! `https://tracker.example/pixel.gif` reports that reader's address to a
//! stranger. Here it becomes a link to where it would have been fetched
//! from, which is exactly what it is.
//!
//! **References** are the `news:` scheme — `[the sizes thread](news:51)`,
//! in any case, as a URI scheme is — and the `#51` shorthand, found by
//! `hxd-core`'s scanner in the prose and never in code: an article quoting
//! a shell prompt or a C preprocessor line is not citing anything.
//!
//! Behind `hxd-core`'s [`BodyRenderer`], in its own crate and behind the
//! `markdown` feature — the `hxd-media` shape, for the same reason: a
//! server that wants no parser does not link one.

use hxd_core::news::{scan_refs, ArticleId, BodyRenderer, Rendered};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

/// The renderer `hxd` gives the domain when `[news] markdown = "render"`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Markdown;

impl BodyRenderer for Markdown {
    fn render(&self, source: &str, limit: usize) -> Rendered {
        render(source, limit)
    }

    fn refuses(&self, source: &str) -> Option<&'static str> {
        (nesting_width(source) > MAX_NESTING_WIDTH).then_some("That article nests too deeply.")
    }
}

/// The most columns of list and quote syntax a line may open with
/// (§5.4).
///
/// pulldown-cmark matches every line against every block still open
/// around it, and a list item stays open across a blank line, which
/// costs one byte. So a body that opens thousands of levels and then
/// runs blank lines costs levels times lines — seconds, from one that
/// fits in `max_body`. Every open block takes at least a column of the
/// line that opened it, so capping the columns caps the depth, and the
/// parse with it, at milliseconds. It admits lists far deeper than any
/// client draws.
pub const MAX_NESTING_WIDTH: usize = 64;

/// How far into its line the widest run of list and quote syntax
/// reaches, in columns, over the lines that have any: an upper bound on
/// how deep the body nests. Indentation that continues an open block, a
/// `>`, and a list marker each take at least a column per level, and a
/// block opens only on a line with a marker.
pub fn nesting_width(source: &str) -> usize {
    let mut continuation = 0;
    let mut widest = 0;
    for line in source.split('\n') {
        let width = line_width(line, continuation);
        if width > 0 {
            continuation = width;
            widest = widest.max(width);
        }
    }
    widest
}

/// The container syntax a line opens with, in columns, or nothing when
/// it has no marker: indentation alone deepens nothing, and neither does
/// a thematic break, however many dashes it has. Before the first marker,
/// CommonMark permits at most three columns beyond the active container;
/// any more is an indented code block whose punctuation is literal.
fn line_width(line: &str, continuation: usize) -> usize {
    let b = line.as_bytes();
    if thematic_break(b) {
        return 0;
    }
    let (mut i, mut col, mut marked) = (0, 0, false);
    while let Some(&c) = b.get(i) {
        match c {
            b' ' => {
                col += 1;
                if !marked && col > continuation + 3 {
                    return 0;
                }
            }
            b'\t' => {
                col += 4 - col % 4;
                if !marked && col > continuation + 3 {
                    return 0;
                }
            }
            b'>' => {
                col += 1;
                marked = true;
            }
            b'-' | b'*' | b'+' if spaced(b, i + 1) => {
                col += 1;
                marked = true;
            }
            b'0'..=b'9' => {
                let digits = b[i..].iter().take_while(|d| d.is_ascii_digit()).count();
                let end = i + digits;
                if digits > 9 || !matches!(b.get(end), Some(b'.' | b')')) || !spaced(b, end + 1) {
                    break;
                }
                col += digits + 1;
                marked = true;
                i = end;
            }
            _ => break,
        }
        i += 1;
    }
    if marked {
        col
    } else {
        0
    }
}

/// Whether what ends before `i` is a list marker: one needs a space, a
/// tab or the end of the line after it.
fn spaced(b: &[u8], i: usize) -> bool {
    matches!(b.get(i), None | Some(b' ' | b'\t' | b'\r'))
}

/// `---`, `* * *`, `_ _ _`: three or more of one of them and nothing but
/// spaces besides, which CommonMark reads as a rule before it reads a
/// list, so it opens no block.
fn thematic_break(b: &[u8]) -> bool {
    let mut mark = None;
    let mut n = 0;
    for &c in b {
        match c {
            b' ' | b'\t' | b'\r' => {}
            b'-' | b'*' | b'_' if mark.is_none_or(|m| m == c) => {
                mark = Some(c);
                n += 1;
            }
            _ => return false,
        }
    }
    n >= 3
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

/// A list open around the text.
struct List {
    /// The next number, for an ordered list.
    next: Option<u64>,
    /// Whether an item has begun yet.
    begun: bool,
    /// Its items hold paragraphs, which a loose list's do and a tight
    /// list's never do.
    loose: bool,
}

/// A link or image open around the text.
struct Frame {
    dest: String,
    /// Where its label begins in the output, once it does: one opened at
    /// the start of a line begins after what the line's containers put
    /// there.
    start: Option<usize>,
}

/// The plain text as it is written, and the references found on the way.
struct Writer {
    out: String,
    limit: usize,
    cut: bool,
    /// Whitespace did not fit. It is owed only if something follows it:
    /// a document that ends exactly at the limit is whole, not cut.
    full: bool,
    stack: Vec<Container>,
    /// A list item's marker, waiting for the item's first line.
    marker: Option<String>,
    /// Lists open, innermost last.
    lists: Vec<List>,
    at_line_start: bool,
    /// A blank line is owed before the next block.
    blank: bool,
    /// The links and images open around the text, innermost last. A
    /// stack, because an image may sit inside a link —
    /// `[![alt](img)](news:51)` — and each end closes its own.
    links: Vec<Frame>,
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
        full: false,
        stack: Vec::new(),
        marker: None,
        lists: Vec::new(),
        at_line_start: true,
        blank: false,
        links: Vec::new(),
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

/// The article a `news:` destination names, if it names one: the scheme
/// in any case, as a URI's is, then digits only, nonzero, and an id the
/// legacy wire can carry.
fn news_target(dest: &str) -> Option<ArticleId> {
    let digits = dest
        .get(5..)
        .filter(|_| dest[..5].eq_ignore_ascii_case("news:"))?;
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
            // out (§5.2). And opaque: a tag or an HTML block, by every
            // start condition CommonMark has, is not prose, so a `#51`
            // inside one cites nothing. hx-ng draws it the same way.
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
            Tag::Paragraph => {
                // Only a loose list's items hold paragraphs; a tight
                // list's text sits in the item itself.
                if matches!(self.stack.last(), Some(Container::Item { .. })) {
                    if let Some(list) = self.lists.last_mut() {
                        list.loose = true;
                    }
                }
                self.open_block();
            }
            Tag::Heading { .. } | Tag::HtmlBlock => self.open_block(),
            Tag::BlockQuote(_) => {
                self.open_block();
                self.stack.push(Container::Quote);
            }
            Tag::CodeBlock(_) => {
                self.open_block();
                // An indented block is already indented in the source and
                // arrives without it; a fenced one never had it. Both
                // come out four spaces in, the fences gone.
                self.stack.push(Container::Code);
            }
            Tag::List(first) => {
                // A nested list starts on its own line, inside the item.
                if !self.lists.is_empty() {
                    self.newline_if_needed();
                } else {
                    self.open_block();
                }
                self.lists.push(List {
                    next: first,
                    begun: false,
                    loose: false,
                });
            }
            Tag::Item => {
                // An item whose first thing is a list has not written its
                // own marker yet; it goes on a line of its own, or the
                // nested marker would take its place.
                if self.marker.is_some() {
                    self.bare_marker();
                    self.newline();
                }
                self.newline_if_needed();
                // A quote or a code block ends by asking for a blank line.
                // Between items it is owed only in a loose list: in a
                // tight one it would read as the list coming apart. A
                // first item is not between items, so it asks the list
                // around it.
                let between = match self.lists.as_slice() {
                    [.., list] if list.begun => Some(list),
                    [.., outer, _] => Some(outer),
                    _ => None,
                };
                if self.blank && between.is_some_and(|list| list.loose) {
                    self.blank_line();
                }
                self.blank = false;
                let marker = match self.lists.last_mut() {
                    Some(list) => {
                        list.begun = true;
                        match &mut list.next {
                            Some(n) => {
                                let m = format!("{n}. ");
                                *n = n.saturating_add(1);
                                m
                            }
                            None => "- ".to_string(),
                        }
                    }
                    None => "- ".to_string(),
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
            // The destination's reference is recorded at the end, after
            // the label's prose has been scanned, so references come out
            // in the order they appear in the source.
            Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                let start = (!self.at_line_start).then_some(self.out.len());
                self.links.push(Frame {
                    dest: dest_url.to_string(),
                    start,
                });
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
                // An empty item is still an item: its marker, and nothing
                // after it.
                if self.marker.is_some() {
                    self.bare_marker();
                }
                self.stack.pop();
                self.newline_if_needed();
            }
            TagEnd::TableHead | TagEnd::TableRow => {
                self.cells = None;
                self.newline_if_needed();
            }
            TagEnd::Link | TagEnd::Image => {
                let Some(Frame { dest, start }) = self.links.pop() else {
                    return;
                };
                let target = news_target(&dest);
                if let Some(id) = target {
                    self.reference(id);
                }
                // Past the limit there is nowhere to write, and nothing
                // whole to compare a label against.
                if self.cut {
                    return;
                }
                let shown = match target {
                    Some(id) => format!("news #{id}"),
                    None => dest.clone(),
                };
                // The label is what was written since the link opened,
                // measured rather than copied: a copy into every open
                // frame is quadratic in nested images. A line break in it
                // leaves a newline there, so it is never taken for a
                // destination.
                let start = start.map_or(self.out.len(), |s| s.min(self.out.len()));
                let written = &self.out[start..];
                let label = written.trim();
                let from = start + (written.len() - written.trim_start().len());
                let to = from + label.len();
                // An autolink's text is its destination; saying it twice
                // helps nobody.
                let same = label == dest
                    || dest.strip_prefix("mailto:") == Some(label)
                    || (target.is_some() && label.eq_ignore_ascii_case(&dest));
                if same {
                    // A news link that says only where it goes says it the
                    // way every other one does: `<news:51>` is `news #51`,
                    // as `[the sizes](news:51)` is `the sizes (news #51)`.
                    if target.is_some() {
                        let tail = self.out.split_off(to);
                        self.out.truncate(from);
                        self.raw(&shown);
                        self.raw(&tail);
                    }
                } else if !dest.is_empty() {
                    if label.is_empty() {
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

    /// A blank line inside whatever is open: the quotes' marks and the
    /// indentation before them, and no trailing spaces.
    fn blank_line(&mut self) {
        // As in `text`: a line nothing is written to is not built.
        if self.cut {
            return;
        }
        // Only a quote puts anything visible at the start of a line, so
        // what the containers inside the innermost one would add is
        // spaces the trim takes off anyway, and is never built.
        let depth = self
            .stack
            .iter()
            .rposition(|c| *c == Container::Quote)
            .map_or(0, |i| i + 1);
        let prefix = self.line_prefix(depth, false);
        self.raw(prefix.trim_end());
        self.raw("\n");
        self.at_line_start = true;
    }

    /// Text, a line at a time, each line begun with what its containers
    /// put there.
    fn text(&mut self, text: &str) {
        // Past the limit nothing more is written, so nothing more is
        // built either: the limit bounds the work, not just the output.
        if self.cut {
            return;
        }
        let mut lines = text.split('\n').peekable();
        while let Some(line) = lines.next() {
            let more = lines.peek().is_some();
            if !line.is_empty() {
                if self.at_line_start {
                    self.prefix();
                    self.begin_labels();
                }
                self.raw(line);
                self.at_line_start = false;
            } else if more && self.at_line_start {
                // An empty line inside a code block or an HTML block keeps
                // its quote's `>`, or a legacy reader sees the quote end
                // there and another begin.
                self.blank_line();
                continue;
            }
            if more {
                self.newline();
            }
        }
    }

    /// Links opened at the start of a line begin where their first text
    /// does, after the line's prefix. They are the innermost frames, and
    /// each is set once.
    fn begin_labels(&mut self) {
        let at = self.out.len();
        for frame in self.links.iter_mut().rev() {
            if frame.start.is_some() {
                break;
            }
            frame.start = Some(at);
        }
    }

    fn prefix(&mut self) {
        // As in `text`: a prefix nesting has made long is not built for
        // a line nothing is written to.
        if self.cut {
            self.marker = None;
            return;
        }
        let prefix = self.line_prefix(self.stack.len(), true);
        self.marker = None;
        self.raw(&prefix);
    }

    /// What the outermost `depth` containers begin a line with. An item is
    /// its width in spaces, or the marker it is waiting to write when it
    /// is the innermost and `marker` asks for it.
    fn line_prefix(&self, depth: usize, marker: bool) -> String {
        let mut prefix = String::new();
        let innermost_item = self
            .stack
            .iter()
            .rposition(|c| matches!(c, Container::Item { .. }));
        for (i, c) in self.stack[..depth].iter().enumerate() {
            match c {
                Container::Quote => prefix.push_str("> "),
                Container::Code => prefix.push_str("    "),
                Container::Item { width } => {
                    match (&self.marker, marker && Some(i) == innermost_item) {
                        (Some(marker), true) => prefix.push_str(marker),
                        _ => prefix.extend(std::iter::repeat_n(' ', *width)),
                    }
                }
            }
        }
        prefix
    }

    /// An item's marker alone on its line: `-`, never `- `. Trimmed before
    /// it is written, so a space that is never kept cannot be what takes
    /// the line past the limit.
    fn bare_marker(&mut self) {
        if !self.cut {
            let prefix = self.line_prefix(self.stack.len(), true);
            self.raw(prefix.trim_end_matches(' '));
        }
        self.marker = None;
        self.at_line_start = false;
    }

    /// The one place bytes are written, and the one place the limit is
    /// kept.
    fn raw(&mut self, s: &str) {
        if self.cut || s.is_empty() {
            return;
        }
        // Whatever fits is written whole; room for the ellipsis is made
        // only once something does not fit.
        if !self.full && self.out.len() + s.len() <= self.limit {
            self.out.push_str(s);
            return;
        }
        // Whitespace past the limit is not yet a cut — a block's closing
        // newline, or the end of a code line: it becomes one only if more
        // text follows it.
        let body = s.trim_end();
        if body.is_empty() || (!self.full && self.out.len() + body.len() <= self.limit) {
            self.out.push_str(body);
            self.full = true;
            return;
        }
        let keep = self.limit.saturating_sub(CUT.len());
        if self.full || self.out.len() > keep {
            // Whitespace that did not fit can leave the output short of
            // `keep`; then the cut goes where the output ends.
            let mut end = keep.min(self.out.len());
            while !self.out.is_char_boundary(end) {
                end -= 1;
            }
            self.out.truncate(end);
        } else {
            let mut end = (keep - self.out.len()).min(s.len());
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            self.out.push_str(&s[..end]);
        }
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
    fn an_image_inside_a_link_closes_its_own_frame() {
        let r = render("[![a pixel](https://img.example/p.png)](news:51)", 100);
        assert_eq!(r.plain, "a pixel (https://img.example/p.png) (news #51)");
        assert_eq!(r.refs, [51], "the outer destination is not lost");
    }

    #[test]
    fn references_come_out_in_the_order_they_were_written() {
        assert_eq!(render("[see #2](news:1)", 100).refs, [2, 1]);
    }

    #[test]
    fn the_ellipsis_is_made_room_for_only_when_something_does_not_fit() {
        assert_eq!(render("abc", 3).plain, "abc");
        assert_eq!(render("abcd", 3).plain, "…");
        assert_eq!(render("abcdefgh", 6).plain, "abc…");
    }

    #[test]
    fn an_item_that_opens_with_a_list_keeps_its_marker() {
        assert_eq!(plain("- - inner\n- after"), "-\n  - inner\n- after");
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
        // Lists nested thousands deep reach the limit within their first
        // few hundred lines. What follows is written nowhere, and must
        // not be built either: a prefix rebuilt per item after the cut is
        // seconds of work here where the linear writer takes a blink.
        for (unit, what) in [("- ", "bullets"), ("1. ", "numbers"), ("> - ", "quoted")] {
            let body = format!("{}x", unit.repeat(30_000));
            let started = std::time::Instant::now();
            let r = render(&body, 65_535);
            let took = started.elapsed();
            assert!(r.plain.len() <= 65_535, "{what}");
            assert!(r.plain.ends_with('…'), "{what}");
            assert!(took < std::time::Duration::from_secs(2), "{what}: {took:?}");
        }
    }

    #[test]
    fn nesting_is_measured_in_columns_of_container_syntax() {
        assert_eq!(nesting_width("plain\n\ntext"), 0);
        assert_eq!(nesting_width("        indented, but no marker"), 0);
        assert_eq!(
            nesting_width("-x\n1.5\n#1\n+1"),
            0,
            "none of these is a marker"
        );
        assert_eq!(nesting_width("- a"), 2);
        assert_eq!(
            nesting_width("-"),
            1,
            "an empty item at the end of the line"
        );
        assert_eq!(nesting_width(">quote"), 1);
        assert_eq!(nesting_width("> > - a"), 6);
        assert_eq!(nesting_width("- a\n  - b\n    - c"), 6);
        assert_eq!(nesting_width("\t- a"), 0, "a tab opens indented code");
        assert_eq!(nesting_width("10. a\n1) b"), 4);
        assert_eq!(
            nesting_width("1234567890. a"),
            0,
            "ten digits are not a marker"
        );
    }

    #[test]
    fn a_thematic_break_opens_nothing_however_long() {
        assert_eq!(nesting_width(&"- ".repeat(200)), 0);
        assert_eq!(nesting_width(&"* ".repeat(200)), 0);
        assert_eq!(nesting_width(&"_".repeat(200)), 0);
        // With anything else on the line it is a list after all.
        assert_eq!(nesting_width(&format!("{}a", "- ".repeat(200))), 400);
    }

    #[test]
    fn nesting_deeper_than_a_parse_can_afford_is_refused() {
        let admitted = format!("{}a", "- ".repeat(MAX_NESTING_WIDTH / 2));
        assert_eq!(Markdown.refuses(&admitted), None);
        let deeper = format!("{}a", "- ".repeat(MAX_NESTING_WIDTH / 2 + 1));
        assert_eq!(
            Markdown.refuses(&deeper),
            Some("That article nests too deeply.")
        );
        assert!(Markdown
            .refuses(&format!("{}a", "> ".repeat(MAX_NESTING_WIDTH)))
            .is_some());
        assert_eq!(
            Markdown.refuses("an ordinary\n\n- list\n  - nested\n"),
            None
        );

        let code = format!("{}- literal", " ".repeat(MAX_NESTING_WIDTH + 1));
        assert_eq!(nesting_width(&code), 0);
        assert_eq!(Markdown.refuses(&code), None);
        assert_eq!(nesting_width("- item\n        - literal"), 2);

        let nested = (0..=MAX_NESTING_WIDTH / 2)
            .map(|depth| format!("{}- item", "  ".repeat(depth)))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(Markdown.refuses(&nested).is_some());
    }

    #[test]
    fn what_the_cap_admits_parses_in_linear_time() {
        // The shape that made the parse quadratic: every level the cap
        // admits, then blank lines up to the most a body may hold, each of
        // which the parser matches against every level still open.
        let levels = "- ".repeat(MAX_NESTING_WIDTH / 2);
        let body = format!("{levels}a\n{}", "\n".repeat(65_535 - levels.len() - 2));
        assert_eq!(Markdown.refuses(&body), None);
        let started = std::time::Instant::now();
        render(&body, 4 * 65_535);
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(2), "{took:?}");

        // Uncapped, the same shape costs seconds to parse; refused, it
        // costs one pass over its bytes.
        let deep = format!("{}a\n{}", "- ".repeat(16_384), "\n".repeat(32_767));
        let started = std::time::Instant::now();
        assert!(Markdown.refuses(&deep).is_some());
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_millis(500), "{took:?}");
    }

    #[test]
    fn nested_links_and_images_cost_what_they_write() {
        // Each label is measured in the output when its link closes, not
        // copied into every frame open around it as it is written.
        let n = 20_000;
        for (open, what) in [("![", "images"), ("[", "links")] {
            let body = format!("{}a{}", open.repeat(n), "](u)".repeat(n));
            let started = std::time::Instant::now();
            let r = render(&body, 65_535);
            let took = started.elapsed();
            // Images nest; a link cannot hold one, so the outer brackets
            // of the links are literal and only the innermost is a link.
            assert!(r.plain.contains("a (u)"), "{what}");
            assert!(took < std::time::Duration::from_secs(2), "{what}: {took:?}");
        }
        assert_eq!(plain("![![a](u)](v)"), "a (u) (v)");
    }

    #[test]
    fn a_blank_line_in_quoted_code_is_still_quoted() {
        assert_eq!(plain("> ```\n> a\n>\n> b\n> ```"), ">     a\n>\n>     b");
        assert_eq!(
            plain("- item\n\n  > q\n  >\n  >     code\n  >\n  >     more"),
            "- item\n\n  > q\n  >\n  >     code\n  >\n  >     more",
            "and keeps the indentation in front of its `>`"
        );
    }

    #[test]
    fn a_tight_list_stays_tight_around_a_quote_or_code() {
        assert_eq!(plain("- a\n  > q\n- b"), "- a\n  > q\n- b");
        assert_eq!(plain("- a\n  ```\n  x\n  ```\n- b"), "- a\n      x\n- b");
        assert_eq!(
            plain("- a\n\n  > q\n\n- b"),
            "- a\n\n  > q\n\n- b",
            "a loose one keeps its blank lines"
        );
    }

    #[test]
    fn an_empty_item_keeps_its_marker() {
        assert_eq!(plain("-\n- b"), "-\n- b");
        assert_eq!(plain("1.\n2. b"), "1.\n2. b");
        assert_eq!(plain("- a\n-\n- c"), "- a\n-\n- c");
    }

    #[test]
    fn raw_html_is_never_prose() {
        // Every kind of HTML block CommonMark has, and inline tags: their
        // text is the author's markup, not their words, and a `#51` in it
        // cites nothing. hx-ng's renderer draws raw HTML the same way.
        for body in [
            "<br>\nFixed in #51.",
            "<div>\n#51\n</div>",
            "<!-- #51 -->",
            "<pre>\n#51\n</pre>",
            "<?php #51 ?>",
            "<!X #51>",
            "<![CDATA[ #51 ]]>",
            "see <a title=\"#51\">this</a>",
        ] {
            let r = render(body, 100);
            assert!(r.refs.is_empty(), "{body:?} gave {:?}", r.refs);
            assert!(r.plain.contains("#51"), "kept as written: {:?}", r.plain);
        }
        assert_eq!(
            render("<b>#51</b>", 100).refs,
            [51],
            "the words between tags are prose"
        );
    }

    #[test]
    fn the_news_scheme_is_any_case() {
        let r = render("[x](NEWS:51) and <News:52>", 100);
        assert_eq!(r.refs, [51, 52]);
        assert_eq!(r.plain, "x (news #51) and news #52");
    }

    #[test]
    fn a_news_autolink_says_which_article_as_other_news_links_do() {
        assert_eq!(plain("see <news:51>."), "see news #51.");
        assert_eq!(plain("[news:51](news:51)"), "news #51");
        assert_eq!(plain("> <news:51>"), "> news #51");
        assert_eq!(render("<news:51>", 100).refs, [51]);
        assert_eq!(
            plain("<https://hl.example>"),
            "https://hl.example",
            "and any other autolink is still its destination, once"
        );
    }

    #[test]
    fn a_small_limit_cuts_only_what_does_not_fit() {
        // Whatever the limit, the downgrade keeps within it, comes out
        // whole when it fits, and ends in the ellipsis when it does not.
        // The continuation under a wide marker is whitespace that may not
        // fit while the output is still short of the ellipsis's room.
        for body in [
            "100. a\n\n     b",
            "100. aaaa\n     bbbb\n\n     cccc",
            "100.   -",
            "- - - inner\n- after\n-\n- c",
            "> ```\n> a\n>\n> b\n> ```",
            "    code \n\n    more ",
            "100. <news:51>\n\n     é [x](news:52) ü",
            "| a | b |\n|---|---|\n| c | d |",
        ] {
            let whole = plain(body);
            for limit in 0..=whole.len() + 1 {
                let cut = render(body, limit).plain;
                assert!(cut.len() <= limit, "{body:?} at {limit}: {cut:?}");
                if whole.len() <= limit {
                    assert_eq!(cut, whole, "{body:?} at {limit}");
                } else if limit >= CUT.len() {
                    assert!(cut.ends_with(CUT), "{body:?} at {limit}: {cut:?}");
                }
            }
        }
        // The space after a bare marker, and at the end of a code line,
        // is never kept, so neither is what cuts a downgrade that fits.
        assert_eq!(render("100.   -", 11).plain, "100.\n     -");
        assert_eq!(render("    code ", 8).plain, "    code");
    }
}
