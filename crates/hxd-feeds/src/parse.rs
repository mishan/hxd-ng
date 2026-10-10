//! A feed's bytes as items (`docs/news-feeds.md` §5).

use std::fmt;
use std::time::SystemTime;

use feed_rs::model::{Entry, Text};
use sha2::{Digest, Sha256};
use url::Url;

use crate::html;

/// What [`parse`] makes of each item.
#[derive(Clone, Debug)]
pub struct ParseOptions {
    /// Bodies as markdown, or as plain text.
    pub markdown: bool,
    /// A subject's limit, in bytes.
    pub max_subject: usize,
    /// A body's limit before its link lines, in bytes.
    pub max_body: usize,
    /// The fetch time: an item with no date has it, and none is later.
    pub now: SystemTime,
}

/// A feed, as far as news needs it.
#[derive(Clone, Debug)]
pub struct Feed {
    pub title: Option<String>,
    pub author: Option<String>,
    /// Oldest first.
    pub items: Vec<Item>,
    /// Items with nothing to know them by, which cannot be imported.
    pub skipped: usize,
}

/// One item, ready to be an article.
#[derive(Clone, Debug)]
pub struct Item {
    /// SHA-256 of the item's identity.
    pub key: [u8; 32],
    pub subject: String,
    /// The item's author, else the feed's, else the feed's title.
    pub author: Option<String>,
    pub at: SystemTime,
    pub body: String,
    /// Whether `body` is markdown, as [`ParseOptions::markdown`] asked.
    pub markdown: bool,
}

#[derive(Debug)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// RSS 0.9x–2.0 and RDF, Atom 1.0 or JSON Feed, whichever `bytes` is.
pub fn parse(bytes: &[u8], opts: &ParseOptions) -> Result<Feed, ParseError> {
    // An empty id is how feed-rs is made to say an item has none, rather
    // than inventing one from a hash of whatever else it has.
    let feed = feed_rs::parser::Builder::new()
        .id_generator(|_, _, _| String::new())
        .sanitize_content(false)
        .build()
        .parse(bytes)
        .map_err(|e| ParseError(e.to_string()))?;

    let title = feed.title.as_ref().map(|t| as_text(t, usize::MAX));
    let title = title.filter(|t| !t.is_empty());
    let author = feed
        .authors
        .iter()
        .find_map(|p| p.name.as_deref().map(collapse))
        .filter(|a| !a.is_empty());
    let fallback = author.clone().or_else(|| title.clone());
    // JSON Feed's attachments arrive as links with nothing but their
    // type to tell them from the item's own.
    let json = feed.feed_type == feed_rs::model::FeedType::JSON;

    let mut skipped = 0;
    let mut items: Vec<Item> = feed
        .entries
        .iter()
        .rev()
        .filter_map(|e| {
            let item = item(e, json, fallback.as_deref(), opts);
            skipped += usize::from(item.is_none());
            item
        })
        .collect();
    // Stable, over the feed's order reversed: items a feed lists newest
    // first under one date come out oldest first.
    items.sort_by_key(|i| i.at);
    Ok(Feed {
        title,
        author,
        items,
        skipped,
    })
}

fn http(href: &str) -> Option<Url> {
    Url::parse(href)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

fn item(e: &Entry, json: bool, fallback: Option<&str>, opts: &ParseOptions) -> Option<Item> {
    let (enclosures, links): (Vec<_>, Vec<_>) = e
        .links
        .iter()
        .partition(|l| l.rel.as_deref() == Some("enclosure") || (json && l.media_type.is_some()));
    let link = links
        .iter()
        .filter(|l| matches!(l.rel.as_deref(), None | Some("alternate")))
        .find_map(|l| http(&l.href));
    let enclosures: Vec<Url> = enclosures
        .iter()
        .filter_map(|l| http(&l.href))
        .chain(
            e.media
                .iter()
                .flat_map(|m| &m.content)
                .filter_map(|c| c.url.as_ref().and_then(|u| http(u.as_str()))),
        )
        .fold(Vec::new(), |mut all, u| {
            if !all.contains(&u) {
                all.push(u);
            }
            all
        });

    let identity = Some(e.id.as_str())
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| link.as_ref().map(Url::to_string))
        .or_else(|| enclosures.first().map(Url::to_string))?;

    let subject = e
        .title
        .as_ref()
        .map(|t| as_text(t, opts.max_subject))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(untitled)".into());
    let author = e
        .authors
        .iter()
        .find_map(|p| p.name.as_deref().map(collapse))
        .filter(|a| !a.is_empty())
        .or_else(|| fallback.map(str::to_owned));
    let at = e
        .published
        .or(e.updated)
        .map(SystemTime::from)
        .map_or(opts.now, |at| at.min(opts.now));

    let (content, html_type) = match (&e.content, &e.summary) {
        (Some(c), _) if c.body.as_deref().is_some_and(|b| !b.trim().is_empty()) => (
            c.body.as_deref().unwrap_or_default(),
            c.content_type.essence().to_string() != "text/plain",
        ),
        (_, Some(s)) => (s.content.as_str(), !is_plain(s)),
        _ => ("", false),
    };
    let mut body = if html_type {
        html::html(content, link.as_ref(), opts.markdown, opts.max_body)
    } else {
        html::text(content, opts.markdown, opts.max_body)
    };
    let mut lines = link.iter().map(|u| ("Source", u)).collect::<Vec<_>>();
    lines.extend(enclosures.iter().map(|u| ("Download", u)));
    for (label, url) in lines {
        body.push_str(if body.is_empty() { "" } else { "\n\n" });
        if opts.markdown {
            body.push_str(&format!("{label}: <{url}>"));
        } else {
            body.push_str(&format!("{label}: {url}"));
        }
    }

    Some(Item {
        key: Sha256::digest(identity.as_bytes()).into(),
        subject,
        author,
        at,
        body,
        markdown: opts.markdown,
    })
}

fn is_plain(t: &Text) -> bool {
    t.content_type.essence().to_string() == "text/plain"
}

/// A title as one line of text, markup removed, cut to `max` bytes.
fn as_text(t: &Text, max: usize) -> String {
    let text = if is_plain(t) {
        collapse(&t.content)
    } else {
        collapse(&html::html(
            &t.content,
            None,
            false,
            max.saturating_mul(4).saturating_add(64),
        ))
    };
    text[..html::floor_boundary(&text, max)]
        .trim_end()
        .to_owned()
}

fn collapse(s: &str) -> String {
    s.split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
