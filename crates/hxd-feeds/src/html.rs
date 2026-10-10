//! A feed's HTML as markdown, or as plain text (`docs/news-feeds.md` §7).
//!
//! The walk is over tokens, never a tree, and what it keeps of the
//! document's structure is a stack it bounds itself: containers past
//! [`MAX_NEST`] are read as if they were not there. Output stops at the
//! caller's limit, so the work is linear in the input and the result is
//! never longer than the limit, an ellipsis included.
//!
//! Nothing here writes HTML. Text is escaped wherever it lands outside a
//! code span or block, which markdown never reads as markup; the only
//! destinations written are `http`, `https` and `mailto` URLs, inside
//! `<…>`, and never one holding a character that could end it.

use html5gum::{DefaultEmitter, HtmlString, Token, Tokenizer};
use std::collections::BTreeMap;
use url::Url;

/// How many lists and quotes are nested before more are ignored.
const MAX_NEST: usize = 16;

const ELLIPSIS: &str = "…";

/// Characters markdown might read as syntax, wherever they fall in a line.
/// Escaping the harmless ones too is what makes this independent of
/// where a text run ends up.
const SIGNIFICANT: &str = "\\`*_{}[]()<>#+-.!|~&=";

/// Elements dropped with everything in them. These are raw text to the
/// tokenizer, so even a self-closed one has content to drop; the
/// [`DROPPED`] ones honor `/>`.
const RAW_DROPPED: &[&[u8]] = &[
    b"script",
    b"style",
    b"iframe",
    b"noscript",
    b"noembed",
    b"noframes",
    b"xmp",
    b"title",
    b"textarea",
];
const DROPPED: &[&[u8]] = &[
    b"object",
    b"form",
    b"svg",
    b"math",
    b"template",
    b"select",
    b"button",
    b"head",
    b"video",
    b"audio",
    b"canvas",
];

const BLOCKS: &[&[u8]] = &[
    b"p",
    b"div",
    b"section",
    b"article",
    b"header",
    b"footer",
    b"main",
    b"aside",
    b"nav",
    b"figure",
    b"figcaption",
    b"table",
    b"tr",
    b"dl",
    b"dt",
    b"dd",
    b"address",
    b"details",
    b"summary",
    b"center",
];

enum Container {
    Quote,
    List {
        ordered: bool,
        next: u32,
        indent: usize,
        marker: Option<String>,
    },
}

/// An `a` whose text is being written; `url` is cleared once the link
/// has been closed early by a block boundary inside it.
struct Link {
    url: Option<String>,
    start: usize,
}

struct Writer<'a> {
    markdown: bool,
    max: usize,
    base: Option<&'a Url>,
    out: String,
    full: bool,
    containers: Vec<Container>,
    /// Containers opened past [`MAX_NEST`], whose ends close nothing.
    ignored: usize,
    /// The paragraph under way, `\n` marking a `br`.
    line: String,
    space: bool,
    heading: usize,
    /// Only the outermost emphasis is marked: nested marks add nothing
    /// a reader sees, and would be a run of asterisks as long as the
    /// nesting is deep.
    emphasis: Option<(usize, &'static str)>,
    emphasis_depth: usize,
    link: Option<Link>,
    code: Option<String>,
    pre: Option<String>,
    pre_depth: usize,
    skip: Option<(Vec<u8>, usize)>,
    /// The last block written began a list item, so a following item
    /// is the same tight list.
    item: bool,
}

/// `html` as markdown (or plain text), at most `max` bytes, with links
/// resolved against `base`.
pub(crate) fn html(input: &str, base: Option<&Url>, markdown: bool, max: usize) -> String {
    let mut w = Writer::new(base, markdown, max);
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true);
    for token in Tokenizer::new_with_emitter(input, emitter) {
        let Ok(token) = token;
        match token {
            Token::StartTag(t) => w.start(&t.name, &t.attributes, t.self_closing),
            Token::EndTag(t) => w.end(&t.name),
            Token::String(s) => w.text(&String::from_utf8_lossy(&s)),
            _ => {}
        }
        if w.over() {
            break;
        }
    }
    w.finish()
}

/// Plain text, as a feed's `text/plain` content: escaped like any text,
/// with its line breaks kept and blank lines between paragraphs.
pub(crate) fn text(input: &str, markdown: bool, max: usize) -> String {
    let mut w = Writer::new(None, markdown, max);
    for paragraph in input.split("\n\n") {
        for line in paragraph.lines() {
            w.text(line);
            w.line.push('\n');
            w.space = false;
        }
        w.flush();
        if w.over() {
            break;
        }
    }
    w.finish()
}

fn attr<S: std::ops::Deref<Target = HtmlString>>(
    attrs: &BTreeMap<HtmlString, S>,
    name: &[u8],
) -> Option<String> {
    attrs
        .get(name)
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// The longest run of backticks in `s`, so a fence can be longer.
fn backticks(s: &str) -> usize {
    s.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

pub(crate) fn floor_boundary(s: &str, at: usize) -> usize {
    let mut at = at.min(s.len());
    while !s.is_char_boundary(at) {
        at -= 1;
    }
    at
}

impl<'a> Writer<'a> {
    fn new(base: Option<&'a Url>, markdown: bool, max: usize) -> Self {
        Writer {
            markdown,
            max,
            base,
            out: String::new(),
            full: false,
            containers: Vec::new(),
            ignored: 0,
            line: String::new(),
            space: false,
            heading: 0,
            emphasis: None,
            emphasis_depth: 0,
            link: None,
            code: None,
            pre: None,
            pre_depth: 0,
            skip: None,
            item: false,
        }
    }

    /// Past the limit, nothing more read can be written.
    fn over(&self) -> bool {
        self.full
            || self.out.len()
                + self.line.len()
                + self.code.as_ref().map_or(0, String::len)
                + self.pre.as_ref().map_or(0, String::len)
                > self.max
    }

    fn finish(mut self) -> String {
        self.end_pre();
        self.flush();
        self.out
    }

    fn resolve(&self, href: &str, schemes: &[&str]) -> Option<String> {
        let url = match self.base {
            Some(base) => base.join(href),
            None => Url::parse(href),
        }
        .ok()?;
        // A `mailto:` path is left as written, and a `<`, `>` or space in
        // it would end the `<…>` the destination is written in.
        let unsafe_char =
            |c: char| matches!(c, '<' | '>' | '\\') || c.is_whitespace() || c.is_control();
        let allowed = schemes.contains(&url.scheme());
        let url = url.to_string();
        (allowed && !url.contains(unsafe_char)).then_some(url)
    }

    fn start<S>(&mut self, name: &[u8], attrs: &BTreeMap<HtmlString, S>, self_closing: bool)
    where
        S: std::ops::Deref<Target = HtmlString>,
    {
        if let Some((skipping, depth)) = &mut self.skip {
            if skipping == name && !self_closing {
                *depth += 1;
            }
            return;
        }
        if RAW_DROPPED.contains(&name) || (DROPPED.contains(&name) && !self_closing) {
            self.skip = Some((name.to_vec(), 1));
            return;
        }
        if self.pre.is_some() {
            if name == b"pre" {
                self.pre_depth += 1;
            } else if name == b"br" {
                self.text("\n");
            }
            return;
        }
        match name {
            b"br" => {
                if self.code.is_none() {
                    self.line.push('\n');
                    self.space = false;
                } else {
                    self.space = true;
                }
            }
            b"hr" => {
                self.flush();
                self.emit("---", "", "");
            }
            b"pre" => {
                self.flush();
                self.pre = Some(String::new());
                self.pre_depth = 1;
            }
            b"code" | b"kbd" | b"samp" | b"tt" if self.code.is_none() => {
                self.pending_space();
                self.code = Some(String::new());
            }
            b"em" | b"i" | b"strong" | b"b" if self.code.is_none() => {
                self.emphasis_depth += 1;
                if self.emphasis_depth == 1 && self.markdown {
                    self.pending_space();
                    let mark = if matches!(name, b"em" | b"i") {
                        "*"
                    } else {
                        "**"
                    };
                    self.emphasis = Some((self.line.len(), mark));
                    self.line.push_str(mark);
                }
            }
            b"a" if self.link.is_none() && self.code.is_none() => {
                self.pending_space();
                let url = attr(attrs, b"href")
                    .and_then(|h| self.resolve(&h, &["http", "https", "mailto"]));
                if url.is_some() && self.markdown {
                    self.line.push('[');
                }
                self.link = Some(Link {
                    url,
                    start: self.line.len(),
                });
            }
            b"img" => {
                let Some(url) =
                    attr(attrs, b"src").and_then(|s| self.resolve(&s, &["http", "https"]))
                else {
                    return;
                };
                let alt = attr(attrs, b"alt").unwrap_or_default();
                let alt = alt.split_whitespace().collect::<Vec<_>>().join(" ");
                if self.code.is_some() || self.link.is_some() {
                    self.text(&alt);
                    return;
                }
                let alt = if alt.is_empty() { "image" } else { &alt };
                self.pending_space();
                if self.markdown {
                    self.line.push('[');
                    self.text(alt);
                    self.line.push_str(&format!("](<{url}>)"));
                } else {
                    self.text(alt);
                    self.line.push_str(&format!(" ({url})"));
                }
            }
            b"h1" | b"h2" | b"h3" | b"h4" | b"h5" | b"h6" => {
                self.flush();
                self.heading = usize::from(name[1] - b'0');
            }
            b"blockquote" => {
                self.flush();
                self.open(Container::Quote);
            }
            b"ul" | b"ol" => {
                self.flush();
                let next = attr(attrs, b"start")
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1)
                    .min(999_999_999);
                self.open(Container::List {
                    ordered: name == b"ol",
                    next,
                    indent: 0,
                    marker: None,
                });
            }
            b"li" => {
                self.flush();
                let list = self.containers.iter_mut().rev().find_map(|c| match c {
                    Container::List {
                        ordered,
                        next,
                        marker,
                        ..
                    } => Some((ordered, next, marker)),
                    Container::Quote => None,
                });
                if let Some((ordered, next, marker)) = list {
                    *marker = Some(if *ordered {
                        *next = next.saturating_add(1);
                        format!("{}. ", *next - 1)
                    } else {
                        "- ".into()
                    });
                }
            }
            b"td" | b"th" => self.space = true,
            _ if BLOCKS.contains(&name) => self.flush(),
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8]) {
        if let Some((skipping, depth)) = &mut self.skip {
            if skipping == name {
                *depth -= 1;
                if *depth == 0 {
                    self.skip = None;
                }
            }
            return;
        }
        if self.pre.is_some() {
            if name == b"pre" {
                self.pre_depth -= 1;
                if self.pre_depth == 0 {
                    self.end_pre();
                }
            }
            return;
        }
        match name {
            b"code" | b"kbd" | b"samp" | b"tt" => self.end_code(),
            b"em" | b"i" | b"strong" | b"b" if self.code.is_none() => {
                self.emphasis_depth = self.emphasis_depth.saturating_sub(1);
                if self.emphasis_depth == 0 {
                    self.end_emphasis();
                }
            }
            b"a" => self.end_link(),
            b"h1" | b"h2" | b"h3" | b"h4" | b"h5" | b"h6" | b"li" => self.flush(),
            b"blockquote" => {
                self.flush();
                self.close(|c| matches!(c, Container::Quote));
            }
            b"ul" | b"ol" => {
                self.flush();
                self.close(|c| matches!(c, Container::List { .. }));
            }
            _ if BLOCKS.contains(&name) => self.flush(),
            _ => {}
        }
    }

    fn open(&mut self, c: Container) {
        if self.containers.len() < MAX_NEST {
            self.containers.push(c);
        } else {
            self.ignored += 1;
        }
    }

    fn close(&mut self, matches: impl Fn(&Container) -> bool) {
        if self.ignored > 0 {
            self.ignored -= 1;
        } else if let Some(i) = self.containers.iter().rposition(matches) {
            self.containers.truncate(i);
        }
    }

    /// Writes the space owed before an inline mark, so the mark sits
    /// against the text it marks.
    fn pending_space(&mut self) {
        if self.space && !self.line.is_empty() && !self.line.ends_with('\n') {
            self.line.push(' ');
        }
        self.space = false;
    }

    fn text(&mut self, s: &str) {
        if self.skip.is_some() {
            return;
        }
        if let Some(pre) = &mut self.pre {
            pre.extend(s.chars().filter(|c| *c == '\n' || !c.is_control()));
            return;
        }
        for c in s.chars() {
            if c.is_whitespace() || c.is_control() {
                self.space = true;
                continue;
            }
            match &mut self.code {
                Some(code) => {
                    if self.space && !code.is_empty() {
                        code.push(' ');
                    }
                    code.push(c);
                }
                None => {
                    self.pending_space();
                    if self.markdown && SIGNIFICANT.contains(c) {
                        self.line.push('\\');
                    }
                    self.line.push(c);
                }
            }
            self.space = false;
        }
    }

    fn end_code(&mut self) {
        let Some(code) = self.code.take() else {
            return;
        };
        if code.is_empty() {
            return;
        }
        if self.markdown {
            let fence = "`".repeat(backticks(&code) + 1);
            let pad = if code.starts_with('`') || code.ends_with('`') {
                " "
            } else {
                ""
            };
            self.line
                .push_str(&format!("{fence}{pad}{code}{pad}{fence}"));
        } else {
            self.line.push_str(&code);
        }
    }

    fn end_emphasis(&mut self) {
        if let Some((start, mark)) = self.emphasis.take() {
            if self.line.len() == start + mark.len() {
                self.line.truncate(start);
            } else {
                self.line.push_str(mark);
            }
        }
    }

    fn end_link(&mut self) {
        let Some(link) = self.link.take() else {
            return;
        };
        let Some(url) = link.url else {
            return;
        };
        let empty = self.line[link.start.min(self.line.len())..]
            .trim()
            .is_empty();
        match (self.markdown, empty) {
            (true, true) => {
                self.line.truncate(link.start - 1);
                self.pending_space();
                self.line.push_str(&format!("<{url}>"));
            }
            (true, false) => self.line.push_str(&format!("](<{url}>)")),
            (false, true) => {
                self.pending_space();
                self.line.push_str(&url);
            }
            (false, false) => {
                if self.line[link.start..].trim() != url {
                    self.line.push_str(&format!(" ({url})"));
                }
            }
        }
    }

    fn end_pre(&mut self) {
        let Some(pre) = self.pre.take() else {
            return;
        };
        let pre = pre.strip_prefix('\n').unwrap_or(&pre).trim_end();
        if pre.is_empty() {
            return;
        }
        let (sep, first) = self.lead();
        let prefix = self.prefix(false);
        let body = pre.replace('\n', &format!("\n{prefix}"));
        if self.markdown {
            let fence = "`".repeat(backticks(pre).max(2) + 1);
            self.emit(
                &format!("{sep}{first}{fence}\n{prefix}"),
                &body,
                &format!("\n{prefix}{fence}"),
            );
        } else {
            self.emit(&format!("{sep}{first}"), &body, "");
        }
        self.item = false;
    }

    /// The separator before a new block and the prefix of its first line.
    fn lead(&mut self) -> (String, String) {
        let item = self.containers.iter().any(|c| {
            matches!(
                c,
                Container::List {
                    marker: Some(_),
                    ..
                }
            )
        });
        let sep = if self.out.is_empty() {
            String::new()
        } else if item && self.item {
            "\n".into()
        } else {
            format!("\n{}\n", self.prefix(false).trim_end())
        };
        self.item = item;
        (sep, self.prefix(true))
    }

    /// The containers' prefix for a line: quote marks and list indents,
    /// or on a block's first line the list markers still owed.
    fn prefix(&mut self, first: bool) -> String {
        let mut p = String::new();
        for c in &mut self.containers {
            match c {
                Container::Quote => p.push_str("> "),
                Container::List { indent, marker, .. } => {
                    if first {
                        if let Some(m) = marker.take() {
                            *indent = m.len();
                            p.push_str(&m);
                            continue;
                        }
                    }
                    p.extend(std::iter::repeat_n(' ', *indent));
                }
            }
        }
        p
    }

    /// Ends the paragraph under way: inline code and a link still open
    /// are closed into it, and it is written as one block.
    fn flush(&mut self) {
        if self.code.is_some() {
            self.end_code();
            self.code = Some(String::new());
        }
        if let Some(link) = &self.link {
            if link.url.is_some() {
                let start = link.start;
                self.end_link();
                self.link = Some(Link { url: None, start });
            }
        }
        self.end_emphasis();
        self.space = false;
        let line = std::mem::take(&mut self.line);
        let heading = std::mem::take(&mut self.heading);
        let lines: Vec<&str> = line
            .split('\n')
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if lines.is_empty() {
            return;
        }
        let (sep, first) = self.lead();
        if heading > 0 && self.markdown {
            let marks = "#".repeat(heading);
            self.emit(&format!("{sep}{first}{marks} "), &lines.join(" "), "");
            return;
        }
        let prefix = self.prefix(false);
        let brk = if self.markdown { "\\\n" } else { "\n" };
        let body = lines.join(&format!("{brk}{prefix}"));
        self.emit(&format!("{sep}{first}"), &body, "");
    }

    /// Appends a block, cutting its body to fit the limit if it must,
    /// with the ellipsis inside whatever closes it.
    fn emit(&mut self, head: &str, body: &str, tail: &str) {
        if self.full {
            return;
        }
        if self.out.len() + head.len() + body.len() + tail.len() <= self.max {
            self.out.push_str(head);
            self.out.push_str(body);
            self.out.push_str(tail);
            return;
        }
        self.full = true;
        let room = self
            .max
            .saturating_sub(self.out.len() + head.len() + tail.len() + ELLIPSIS.len());
        let mut cut = body[..floor_boundary(body, room)].trim_end();
        // An escape cut from its character would show as a backslash.
        if self.markdown && (cut.len() - cut.trim_end_matches('\\').len()) % 2 == 1 {
            cut = &cut[..cut.len() - 1];
        }
        if !cut.is_empty() {
            self.out.push_str(head);
            self.out.push_str(cut);
            self.out.push_str(ELLIPSIS);
            self.out.push_str(tail);
        } else if !self.out.is_empty() && self.out.len() + 2 + ELLIPSIS.len() <= self.max {
            self.out.push_str("\n\n");
            self.out.push_str(ELLIPSIS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulldown_cmark::{Event, Parser, Tag};

    fn md(input: &str) -> String {
        let base = Url::parse("https://example.org/posts/1").unwrap();
        html(input, Some(&base), true, 1 << 20)
    }

    /// What markdown makes of `out`: no HTML, and no link anywhere but
    /// the schemes allowed.
    fn assert_safe(out: &str) {
        for event in Parser::new_ext(
            out,
            pulldown_cmark::Options::ENABLE_TABLES | pulldown_cmark::Options::ENABLE_STRIKETHROUGH,
        ) {
            match event {
                Event::Html(h) | Event::InlineHtml(h) => panic!("HTML {h:?} in {out:?}"),
                Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                    assert!(
                        ["http://", "https://", "mailto:"]
                            .iter()
                            .any(|s| dest_url.starts_with(s)),
                        "{dest_url} in {out:?}"
                    );
                }
                _ => {}
            }
        }
    }

    /// The text markdown renders from `out`.
    fn rendered(out: &str) -> String {
        Parser::new(out)
            .filter_map(|e| match e {
                Event::Text(t) | Event::Code(t) => Some(t.into_string()),
                Event::SoftBreak | Event::HardBreak => Some("\n".into()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn conversions() {
        let cases: &[(&str, &str)] = &[
            ("<p>one</p><p>two</p>", "one\n\ntwo"),
            ("a<br>b<br><br>", "a\\\nb"),
            ("<h2>Title</h2><p>x</p>", "## Title\n\nx"),
            ("<em>a</em> <strong>b</strong>", "*a* **b**"),
            ("x<em> </em>y", "x y"),
            ("<ul><li>a</li><li>b</li></ul>", "- a\n- b"),
            ("<ol start=3><li>a</li><li>b</li></ol>", "3. a\n4. b"),
            (
                "<ul><li>a<ul><li>b</li></ul></li><li>c</li></ul>",
                "- a\n  - b\n- c",
            ),
            ("<blockquote><p>q</p><p>r</p></blockquote>", "> q\n>\n> r"),
            (
                "<pre>\nfn f() {\n  1 < 2\n}</pre>",
                "```\nfn f() {\n  1 < 2\n}\n```",
            ),
            ("<code>a`b</code>", "``a`b``"),
            (
                "<a href=\"/x?a=1\">here</a>",
                "[here](<https://example.org/x?a=1>)",
            ),
            ("<a href=\"https://e.com/\"></a>", "<https://e.com/>"),
            (
                "<a href=\"mailto:a@b.c\">mail</a>",
                "[mail](<mailto:a@b.c>)",
            ),
            ("<a href=\"javascript:alert(1)\">click</a>", "click"),
            ("<a href=\"mailto:x<img src=x onerror=alert(1)>\"></a>", ""),
            ("<a href=\"mailto:a>b\">m</a>", "m"),
            ("<a href=\"data:text/html,x\">d</a>", "d"),
            (
                "<img src=\"i.png\" alt=\"a cat\">",
                "[a cat](<https://example.org/posts/i.png>)",
            ),
            ("<img src=\"javascript:x\" alt=\"no\">", ""),
            (
                "<a href=\"/p\"><img src=\"/i\" alt=\"pic\"></a>",
                "[pic](<https://example.org/p>)",
            ),
            ("a<script>alert('<b>x</b>')</script>b", "ab"),
            ("a<style>p { color: red }</style>b", "ab"),
            ("a<iframe src=x>inside</iframe>b", "ab"),
            ("a<script/>gone</script>b", "ab"),
            ("a<object><p>fallback</p></object>b", "ab"),
            ("a<form><input value=x>text</form>b", "ab"),
            ("a<!-- hidden -->b", "ab"),
            ("<span class=x>kept</span> <blink>too</blink>", "kept too"),
            ("&lt;b&gt; &amp;amp; &eacute;", "\\<b\\> \\&amp; \u{e9}"),
            ("1. not a list", "1\\. not a list"),
            ("# not a heading", "\\# not a heading"),
            (
                "[x](javascript:alert(1)) *y* `z` < >",
                "\\[x\\]\\(javascript:alert\\(1\\)\\) \\*y\\* \\`z\\` \\< \\>",
            ),
        ];
        for (input, want) in cases {
            let out = md(input);
            assert_eq!(&out, want, "from {input:?}");
            assert_safe(&out);
        }
    }

    #[test]
    fn text_that_looks_like_markup_renders_as_itself() {
        for input in [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;",
            "[click](javascript:alert(1))",
            "<p>&lt;div&gt;\n===</p>",
            "<p>| a | b |<br>|---|---|</p>",
            "<p>&amp;lt;b&amp;gt;</p>",
            "<p>   indented code?</p>",
            "<p>~~struck~~ __bold__ ![i](http://e/i)</p>",
        ] {
            let out = md(input);
            assert_safe(&out);
            let plain = html(input, None, false, 1 << 20);
            assert_eq!(
                rendered(&out),
                plain,
                "markdown of {input:?} renders to the same text plain mode writes"
            );
        }
    }

    #[test]
    fn plain_mode() {
        let cases: &[(&str, &str)] = &[
            ("<p>a *b*</p><p>c</p>", "a *b*\n\nc"),
            ("<em>x</em><h1>T</h1>", "x\n\nT"),
            (
                "<a href=\"https://e.com/a\">site</a>",
                "site (https://e.com/a)",
            ),
            (
                "<a href=\"https://e.com/a\">https://e.com/a</a>",
                "https://e.com/a",
            ),
            (
                "<img src=\"https://e.com/i\" alt=\"pic\">",
                "pic (https://e.com/i)",
            ),
            ("<ul><li>a</li><li>b</li></ul>", "- a\n- b"),
            ("<pre>x  y</pre><code>`</code>", "x  y\n\n`"),
            ("a<script>b</script>c", "ac"),
        ];
        for (input, want) in cases {
            assert_eq!(&html(input, None, false, 1 << 20), want, "from {input:?}");
        }
    }

    #[test]
    fn plain_text_content_is_escaped_and_keeps_its_lines() {
        assert_eq!(text("a *b*\nc\n\nd", true, 100), "a \\*b\\*\\\nc\n\nd");
        assert_eq!(text("a *b*\nc\n\nd", false, 100), "a *b*\nc\n\nd");
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let n = 20_000;
        let deep = "<blockquote><ul><li>".repeat(n) + "deep" + &"</li></ul></blockquote>".repeat(n);
        let out = md(&deep);
        assert!(
            out.ends_with("deep"),
            "{}",
            &out[out.len().saturating_sub(80)..]
        );
        assert!(
            out.len() < 200,
            "prefixes are as deep as the cap: {}",
            out.len()
        );
        assert_safe(&out);

        let inline = "<span><em><b>".repeat(n) + "x";
        assert_eq!(md(&inline), "*x*");
        assert_eq!(md(&("<div>".repeat(n) + "x")), "x");
        let anchors = "<a href=\"http://e/\">".repeat(n) + "x";
        assert_eq!(md(&anchors), "[x](<http://e/>)");
    }

    #[test]
    fn the_limit_holds_and_closes_what_it_cuts() {
        let long = format!(
            "<p>{}</p><pre>{}</pre>",
            "word ".repeat(100),
            "code\n".repeat(100)
        );
        for max in [0, 1, 5, 50, 499, 520, 600, 900] {
            let out = html(&long, None, true, max);
            assert!(out.len() <= max, "{max}: {} bytes", out.len());
            assert_safe(&out);
            if out.contains("```") {
                assert!(
                    out.ends_with("```"),
                    "{max}: a cut code block is closed: {out:?}"
                );
            }
        }
        let out = html("<p>héééé</p>", None, true, 5);
        assert_eq!(out, "h…", "cut at a character boundary");
    }
}
