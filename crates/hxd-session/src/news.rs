//! The legacy news binding (`docs/news.md` §12): the 1.5 threaded-news
//! transactions, and 1.2 flat news as a rendering of one category.
//!
//! Everything here is a mapping onto the domain the ng wire already
//! speaks. A `NEWSPATH` is resolved to a node by the names this
//! connection was listed — the wire's address for a node, which is why it
//! lives here and not in `hxd-core` (§12.1) — and the rest is ids. Text
//! crosses at this edge through the connection's [`TextEncoding`], as it
//! does everywhere else in the crate.
//!
//! mhxd's `tnews.c` and `rcv.c` are the reference for what a period
//! client sees. Where this deviates on purpose the site says so; the
//! largest deviation is that flat and threaded news here are one store,
//! so a post from any wire grows the 1.2 pane (§12.5).

use std::time::{SystemTime, UNIX_EPOCH};

use hxd_core::access::bit;
use hxd_core::news::MAX_NODE_NAME;
use hxd_core::{
    Article, ArticleId, BodyType, Core, Listed, NewsError, Node, NodeId, NodeKind, PostRequest,
    TextLen, ThreadQuery, Uid,
};
use hxproto::messages::{tag, ClientHdr};
use tracing::warn;

use crate::encoding::{floor_char_boundary, TextEncoding};
use crate::files;
use crate::session::{civil, off_reactor};

/// What a chunk can hold, and so the most any one news text may be on
/// this wire: an article part, a flat-news document, a pushed entry and a
/// `CATLIST` all ride in one chunk with a u16 length.
pub(crate) const CHUNK_MAX: usize = u16::MAX as usize;

/// mhxd's `news_divider`, which is what a 1.2 client has always seen
/// between two entries.
const DIVIDER: &str = "_________________________________________________________";

/// How long a subject derived from a body's first line may run before it
/// is cut at a word, in characters. A subject line, not a paragraph.
const DERIVED_SUBJECT: usize = 60;

/// The most a configured masthead may be, in bytes: `flat_masthead` is
/// refused past it at startup, and a masthead is cut to it all the same.
/// A line or two of welcome is a few hundred bytes; this is generous for
/// that and still leaves the entries almost all of a chunk, which is what
/// the document is for.
pub const MASTHEAD_MAX: usize = 4096;

/// A `CATEGORYITEM`'s `ntype`: a bundle and a category.
const NTYPE_BUNDLE: u16 = 2;
const NTYPE_CATEGORY: u16 = 3;

/// `[news]`'s keys for this wire.
#[derive(Debug, Clone)]
pub struct LegacyNews {
    /// The most articles one 1.5 category listing carries (§12.3).
    pub catlist_max: usize,
    /// The subject of a post, from either period wire, that sends none
    /// and whose body gives none to derive (§12.4, §12.5).
    pub default_subject: String,
    /// The category 1.2 clients read and post into, or `None` for a
    /// server whose 1.2 clients are told its news is threaded (§12.5).
    pub flat: Option<FlatNews>,
}

impl Default for LegacyNews {
    fn default() -> Self {
        LegacyNews {
            catlist_max: 2000,
            default_subject: "(no subject)".into(),
            flat: None,
        }
    }
}

/// `flat_*` (§12.5).
#[derive(Debug, Clone)]
pub struct FlatNews {
    /// The category's names from the root, as `flat_category` spelled
    /// them with `/` between.
    pub category: Vec<String>,
    /// The most entries one document carries; the byte budget usually
    /// decides first.
    pub articles: usize,
    pub reply: FlatReply,
    /// The line above the entries: `None` for the built-in one, `Some("")`
    /// for none at all.
    pub masthead: Option<String>,
}

/// Where a 1.2 post with no `Re:` goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlatReply {
    /// Under the root of the most recent live thread: one conversation,
    /// every 1.2 post at depth 1.
    NewestThread,
    /// A thread of its own, for a flat category that is an announcements
    /// feed.
    NewThread,
}

impl FlatReply {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "newest_thread" => Some(FlatReply::NewestThread),
            "new_thread" => Some(FlatReply::NewThread),
            _ => None,
        }
    }
}

/// Who is asking, as much of the session as a news transaction reads.
#[derive(Clone, Copy)]
pub(crate) struct Asker {
    pub uid: Uid,
    pub enc: TextEncoding,
}

type Chunks = Vec<(u16, Vec<u8>)>;

/// Is `ty` a news transaction this module answers?
pub(crate) fn handles(ty: u32) -> bool {
    [
        ClientHdr::NewsGetFile,
        ClientHdr::NewsPost,
        ClientHdr::NewsListDir,
        ClientHdr::NewsListCategory,
        ClientHdr::GetThread,
        ClientHdr::PostThread,
        ClientHdr::DeleteThread,
        ClientHdr::NewsDelete,
        ClientHdr::NewsMkdir,
        ClientHdr::NewsMkCategory,
    ]
    .iter()
    .any(|h| h.as_u32() == ty)
}

/// Answer one news transaction: the reply's chunks, or a task error's
/// text. `fields` are the request's chunks, copied out of the frame so
/// the work can go to a blocking thread — every answer here is store I/O.
pub(crate) async fn transaction(
    core: &std::sync::Arc<Core>,
    cfg: &LegacyNews,
    who: Asker,
    ty: u32,
    fields: Chunks,
) -> Result<Chunks, &'static str> {
    let cfg = cfg.clone();
    off_reactor(core, move |core| answer(core, &cfg, who, ty, &fields))
        .await
        .unwrap_or(Err("Server error."))
}

fn field(fields: &Chunks, t: u16) -> Option<&[u8]> {
    fields
        .iter()
        .find(|(tag, _)| *tag == t)
        .map(|(_, d)| d.as_slice())
}

fn uint(fields: &Chunks, t: u16) -> Option<u64> {
    field(fields, t).and_then(files::wire_uint)
}

fn answer(
    core: &Core,
    cfg: &LegacyNews,
    who: Asker,
    ty: u32,
    fields: &Chunks,
) -> Result<Chunks, &'static str> {
    if !core.news_enabled() {
        return Err(error_text(&NewsError::Disabled));
    }
    let path = field(fields, tag::NEWSPATH);
    let result = match ty {
        t if t == ClientHdr::NewsGetFile.as_u32() => flat_document(core, cfg, who),
        t if t == ClientHdr::NewsPost.as_u32() => {
            let body = who.enc.decode(field(fields, tag::BODY).unwrap_or_default());
            flat_post(core, cfg, who, &body).map(|()| Vec::new())
        }
        t if t == ClientHdr::NewsListDir.as_u32() => list_dir(core, who, path),
        t if t == ClientHdr::NewsListCategory.as_u32() => list_category(core, cfg, who, path),
        t if t == ClientHdr::GetThread.as_u32() => {
            let id = thread_id(fields)?;
            let mime = field(fields, tag::NEWSTYPE).unwrap_or_default();
            get_thread(core, who, path, id, mime)
        }
        t if t == ClientHdr::PostThread.as_u32() => post_thread(core, cfg, who, path, fields),
        t if t == ClientHdr::DeleteThread.as_u32() => {
            let id = thread_id(fields)?;
            let replies = uint(fields, tag::DELETEREPLIES).is_some_and(|v| v != 0);
            delete_thread(core, who, path, id, replies).map(|()| Vec::new())
        }
        t if t == ClientHdr::NewsDelete.as_u32() => delete_node(core, who, path),
        t if t == ClientHdr::NewsMkdir.as_u32() => make_node(
            core,
            who,
            path,
            NodeKind::Bundle,
            field(fields, tag::FILE_NAME),
        ),
        t if t == ClientHdr::NewsMkCategory.as_u32() => make_node(
            core,
            who,
            path,
            NodeKind::Category,
            field(fields, tag::CATEGORY),
        ),
        _ => return Err("Not implemented."),
    };
    result.map_err(|e| error_text(&e))
}

fn thread_id(fields: &Chunks) -> Result<ArticleId, &'static str> {
    uint(fields, tag::THREADID)
        .and_then(|v| ArticleId::try_from(v).ok())
        .ok_or("No article was named.")
}

/// A task error's words for a news refusal. ASCII, like every task error
/// this crate sends.
pub(crate) fn error_text(e: &NewsError) -> &'static str {
    match e {
        NewsError::Disabled => "News is not available on this server.",
        NewsError::AccessDenied => "You are not allowed to do that.",
        NewsError::NoSuchNode => "No such news bundle or category.",
        NewsError::NoSuchArticle => "No such article.",
        NewsError::NotACategory => "That is not a news category.",
        NewsError::WrongCategory => "That article is in another category.",
        NewsError::TooDeep => "That is nested too deeply.",
        NewsError::NameTaken => "That name is already in use there.",
        NewsError::NotEmpty => "That bundle is not empty.",
        NewsError::BadBodyType => "This server does not take articles of that type.",
        NewsError::BadRequest(why) => why,
        _ => "Server error.",
    }
}

// --- Paths ---------------------------------------------------------------

/// The components of a `NEWSPATH`: the file area's encoding, a count and
/// then per name two zero bytes, a length and the bytes. Absent, or
/// shorter than one component could be, is the root, as mhxd's
/// `cat_to_path` has it — GtkHx sends an empty path for the top.
fn components(path: Option<&[u8]>) -> Result<Vec<Vec<u8>>, NewsError> {
    match path {
        Some(bytes) if bytes.len() >= 5 => {
            files::parse_dir(bytes).map_err(|_| NewsError::BadRequest("Malformed news path."))
        }
        _ => Ok(Vec::new()),
    }
}

/// A node's name as this connection reads it, which is also how it names
/// the node back: a pstring, so 255 bytes after conversion.
fn wire_name(enc: TextEncoding, name: &str) -> Vec<u8> {
    enc.encode_capped(name, 255)
}

/// Walk `path` from the root to the node it names, matching each
/// component against the names this connection was listed. `None` is the
/// root. Two names that convert to the same bytes resolve to the first
/// listed, by name; a Mac Roman client cannot tell them apart any more
/// than it can type them.
fn resolve(core: &Core, who: Asker, path: Option<&[u8]>) -> Result<Option<Node>, NewsError> {
    let mut at: Option<Node> = None;
    for component in components(path)? {
        let parent = at.as_ref().map(|n| n.id);
        if at.as_ref().is_some_and(|n| n.kind == NodeKind::Category) {
            return Err(NewsError::NoSuchNode);
        }
        let found = core
            .news_tree(who.uid, parent, 1)?
            .into_iter()
            .map(|t| t.node)
            .find(|n| wire_name(who.enc, &n.name) == component)
            .ok_or(NewsError::NoSuchNode)?;
        at = Some(found);
    }
    Ok(at)
}

/// The category `path` names, or why it names none.
fn resolve_category(core: &Core, who: Asker, path: Option<&[u8]>) -> Result<NodeId, NewsError> {
    match resolve(core, who, path)? {
        Some(n) if n.kind == NodeKind::Category => Ok(n.id),
        Some(_) => Err(NewsError::NotACategory),
        // The root is a place for bundles and categories, never articles.
        None => Err(NewsError::NotACategory),
    }
}

/// The category `names` spell from the root, by their UTF-8 names: how
/// the operator's `flat_category` is found. `None` when there is none.
fn find_category(core: &Core, uid: Uid, names: &[String]) -> Result<Option<NodeId>, NewsError> {
    let mut at: Option<Node> = None;
    for name in names {
        let parent = at.as_ref().map(|n| n.id);
        match core
            .news_tree(uid, parent, 1)?
            .into_iter()
            .map(|t| t.node)
            .find(|n| &n.name == name)
        {
            Some(n) => at = Some(n),
            None => return Ok(None),
        }
    }
    Ok(at.filter(|n| n.kind == NodeKind::Category).map(|n| n.id))
}

// --- The 1.5 transactions ------------------------------------------------

fn list_dir(core: &Core, who: Asker, path: Option<&[u8]>) -> Result<Chunks, NewsError> {
    let parent = resolve(core, who, path)?;
    // A category has no sub-nodes, and mhxd lists one as an empty
    // folder rather than refusing.
    if parent
        .as_ref()
        .is_some_and(|n| n.kind == NodeKind::Category)
    {
        return Ok(Vec::new());
    }
    Ok(core
        .news_tree(who.uid, parent.map(|n| n.id), 1)?
        .into_iter()
        .map(|t| (tag::CATEGORYITEM, category_item(who.enc, &t.node)))
        .collect())
}

/// One `CATEGORYITEM` (0x0143), the richer of the two listing entries:
/// a category carries its guid and its add and delete serials, which is
/// what lets a client skip refetching one that has not changed (§12.2).
/// mhxd's bundle entry claims four bytes more than it writes; this one
/// is exactly as long as it says.
fn category_item(enc: TextEncoding, node: &Node) -> Vec<u8> {
    let name = wire_name(enc, &node.name);
    let count = u16::try_from(node.children).unwrap_or(u16::MAX);
    let mut v = Vec::with_capacity(29 + name.len());
    match node.kind {
        NodeKind::Bundle => {
            v.extend_from_slice(&NTYPE_BUNDLE.to_be_bytes());
            v.extend_from_slice(&count.to_be_bytes());
        }
        NodeKind::Category => {
            v.extend_from_slice(&NTYPE_CATEGORY.to_be_bytes());
            v.extend_from_slice(&count.to_be_bytes());
            v.extend_from_slice(&node.guid);
            v.extend_from_slice(&node.add_sn.to_be_bytes());
            v.extend_from_slice(&node.delete_sn.to_be_bytes());
        }
    }
    v.push(name.len() as u8);
    v.extend_from_slice(&name);
    v
}

/// An article's date on this wire: the header format the file area
/// sends, seconds since 2000 (`files::date`), which reaches past the
/// 1904 epoch's 2040.
fn wire_date(at: SystemTime) -> Vec<u8> {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_sub(946_684_800);
    files::date(Some(u32::try_from(secs).unwrap_or(u32::MAX)))
}

/// How many bytes `text` is on this connection once it has been through
/// [`wire_text`], from its lengths alone — or `None` when only the text
/// can say, which is a UTF-8 text cut at a character.
fn wire_len(enc: TextEncoding, len: TextLen) -> Option<usize> {
    match enc {
        // One byte a character, `?` included, and a cut to the chunk is
        // a cut to 65 534 characters and a one-byte ellipsis.
        TextEncoding::MacRoman => Some(len.chars.min(CHUNK_MAX)),
        TextEncoding::Utf8 if len.bytes <= CHUNK_MAX => Some(len.bytes),
        TextEncoding::Utf8 => None,
    }
}

/// A text as an article part on this wire: converted, its line endings
/// the connection's, and cut to what a chunk holds at a character with a
/// trailing ellipsis (§12.4). The stored text is never cut; a downgrade
/// can outgrow the body it came from, and search reads all of it.
pub(crate) fn wire_text(enc: TextEncoding, text: &str) -> Vec<u8> {
    fit(enc, enc.body(text), CHUNK_MAX)
}

/// `bytes`, cut to `max` at a character boundary with an ellipsis when
/// they do not fit.
fn fit(enc: TextEncoding, mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    if bytes.len() <= max {
        return bytes;
    }
    let mut ellipsis = enc.encode("\u{2026}");
    // No room for the ellipsis either: the cut alone, so what comes back
    // is never longer than `max`.
    if ellipsis.len() > max {
        ellipsis.clear();
    }
    let room = max - ellipsis.len();
    let cut = match enc {
        TextEncoding::MacRoman => room,
        TextEncoding::Utf8 => {
            let mut cut = room;
            while cut > 0 && bytes[cut] & 0xc0 == 0x80 {
                cut -= 1;
            }
            cut
        }
    };
    bytes.truncate(cut);
    bytes.extend_from_slice(&ellipsis);
    bytes
}

/// `text` trimmed and cut to `max` UTF-8 bytes at a character, which is
/// how the domain measures a subject and a name. The wire's caps count
/// characters, or Mac Roman bytes, and either can be several bytes of
/// UTF-8; what a period client was allowed to send is cut here rather
/// than refused there.
fn within(text: &str, max: usize) -> String {
    let text = text.trim();
    text[..floor_char_boundary(text, max)]
        .trim_end()
        .to_string()
}

/// The domain's `max_subject`. News is on by the time anything asks.
fn max_subject(core: &Core) -> usize {
    core.news_policy()
        .map_or(hxd_core::NewsPolicy::default().max_subject, |p| {
            p.max_subject
        })
}

/// The parts an article lists (§12.3): the plain text every client asks
/// for, and the markdown source beside it when there is a downgrade to
/// tell them apart. A markdown article with no downgrade — posted under
/// `markdown = "source"` — lists its source as `text/plain`, so a period
/// client asking for the only body there is gets bytes and not an error.
/// A tombstone is one empty `text/plain` part.
fn parts(l: &Listed) -> Vec<(&'static str, TextLen, bool)> {
    if l.deleted {
        return vec![("text/plain", TextLen::default(), false)];
    }
    match l.plain_len {
        Some(plain) if l.mime == BodyType::Markdown => vec![
            ("text/plain", plain, true),
            ("text/markdown", l.body_len, false),
        ],
        _ => vec![("text/plain", l.body_len, false)],
    }
}

fn list_category(
    core: &Core,
    cfg: &LegacyNews,
    who: Asker,
    path: Option<&[u8]>,
) -> Result<Chunks, NewsError> {
    let category = resolve_category(core, who, path)?;
    let listed = core.news_listing(who.uid, category, cfg.catlist_max)?;
    // The listing is one chunk, so a category the article cap allows can
    // still be more than this wire can say. The store's rule again, in
    // bytes: whole threads, newest first, while they fit, and a newest
    // thread too long on its own cut in preorder, so no reply is listed
    // without its parent.
    const HEADER: usize = 10;
    let mut posts = Vec::new();
    let mut count = 0u32;
    for thread in listed.chunk_by(|a, b| a.root == b.root) {
        let mut bytes = Vec::new();
        let mut n = 0u32;
        for l in thread {
            let post = catlist_post(core, who, l);
            if HEADER + posts.len() + bytes.len() + post.len() > CHUNK_MAX {
                break;
            }
            bytes.extend(post);
            n += 1;
        }
        let whole = n as usize == thread.len();
        if !whole && count > 0 {
            break;
        }
        posts.extend(bytes);
        count += n;
        if !whole {
            break;
        }
    }
    let mut body = Vec::with_capacity(HEADER + posts.len());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend(posts);
    Ok(vec![(tag::CATLIST, body)])
}

/// One article's entry in a `CATLIST`: mhxd's `hl_news_thread_hdr`, then
/// the subject and poster as pstrings, then each part's MIME type and
/// size.
fn catlist_post(core: &Core, who: Asker, l: &Listed) -> Vec<u8> {
    let (subject, sender) = if l.deleted {
        (Vec::new(), Vec::new())
    } else {
        (
            who.enc.encode_capped(&l.subject, 255),
            who.enc.encode_capped(&l.nick, 255),
        )
    };
    let parts = parts(l);
    let mut v = Vec::with_capacity(24 + subject.len() + sender.len() + parts.len() * 16);
    v.extend_from_slice(&l.id.to_be_bytes());
    v.extend_from_slice(&wire_date(l.at));
    v.extend_from_slice(&l.parent.unwrap_or(0).to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&(parts.len() as u16).to_be_bytes());
    v.push(subject.len() as u8);
    v.extend_from_slice(&subject);
    v.push(sender.len() as u8);
    v.extend_from_slice(&sender);
    for (mime, len, plain) in parts {
        let size = wire_len(who.enc, len).unwrap_or_else(|| {
            // Only a UTF-8 text past the chunk: measure the cut itself.
            core.news_article(who.uid, l.id)
                .map(|a| {
                    let text = if plain {
                        a.plain.as_deref().unwrap_or(&a.body)
                    } else {
                        &a.body
                    };
                    wire_text(who.enc, text).len()
                })
                .unwrap_or(0)
        });
        v.push(mime.len() as u8);
        v.extend_from_slice(mime.as_bytes());
        v.extend_from_slice(&(size as u16).to_be_bytes());
    }
    v
}

/// An article in the category `path` names, live or a tombstone. One in
/// another category is not there, whatever its id.
fn article_in(
    core: &Core,
    who: Asker,
    path: Option<&[u8]>,
    id: ArticleId,
) -> Result<Article, NewsError> {
    let category = resolve_category(core, who, path)?;
    let article = core.news_article(who.uid, id)?;
    if article.category != category {
        return Err(NewsError::NoSuchArticle);
    }
    Ok(article)
}

fn get_thread(
    core: &Core,
    who: Asker,
    path: Option<&[u8]>,
    id: ArticleId,
    mime: &[u8],
) -> Result<Chunks, NewsError> {
    let a = article_in(core, who, path, id)?;
    // The part asked for by its MIME type (§12.3). The markdown source
    // to a client that names it, and the plain text to everyone else —
    // including a client naming a type this server does not list, which
    // is better answered with the body than with an error.
    let (label, text) = if a.deleted {
        ("text/plain", "")
    } else if mime == b"text/markdown" && a.mime == BodyType::Markdown {
        ("text/markdown", a.body.as_str())
    } else {
        ("text/plain", a.plain.as_deref().unwrap_or(&a.body))
    };
    let (subject, poster) = if a.deleted {
        (Vec::new(), Vec::new())
    } else {
        (
            who.enc.encode_capped(&a.subject, 255),
            who.enc.encode_capped(&a.author.nick, 255),
        )
    };
    // mhxd's field order. The neighbors are 0, "none": mhxd's are
    // directory order, which says nothing, and a client that walks them
    // is served better by its own listing.
    Ok(vec![
        (tag::NEWSDATA, wire_text(who.enc, text)),
        (tag::PREVTHREADID, 0u32.to_be_bytes().to_vec()),
        (tag::NEXTTHREADID, 0u32.to_be_bytes().to_vec()),
        (
            tag::PARENTTHREADID,
            a.parent.unwrap_or(0).to_be_bytes().to_vec(),
        ),
        (tag::NEXTSUBTHREADID, 0u32.to_be_bytes().to_vec()),
        (tag::NEWSSUBJECT, subject),
        (tag::NEWSPOSTER, poster),
        (tag::NEWSTYPE, label.as_bytes().to_vec()),
        (tag::NEWSDATE, wire_date(a.at)),
    ])
}

fn post_thread(
    core: &Core,
    cfg: &LegacyNews,
    who: Asker,
    path: Option<&[u8]>,
    fields: &Chunks,
) -> Result<Chunks, NewsError> {
    let category = resolve_category(core, who, path)?;
    // `THREADID` is the parent on a post, and 0 is none: the naming trap
    // `build_news_post_thread_chunks` documents.
    let parent = uint(fields, tag::THREADID)
        .map(|v| ArticleId::try_from(v).map_err(|_| NewsError::NoSuchArticle))
        .transpose()?
        .filter(|&id| id != 0);
    let mime = match field(fields, tag::NEWSTYPE) {
        Some(b"text/markdown") => BodyType::Markdown,
        _ => BodyType::Plain,
    };
    let body = who
        .enc
        .decode(field(fields, tag::NEWSDATA).unwrap_or_default());
    let subject = who
        .enc
        .decode_chars(field(fields, tag::NEWSSUBJECT).unwrap_or_default(), 255);
    // A post is not refused for a subject it did not send: the 1.2 rule,
    // which asks nothing a 1.5 client could not also have left out. A
    // markdown body's subject comes from what it reads as, not from its
    // syntax.
    let subject = if subject.trim().is_empty() {
        let plain = match mime {
            BodyType::Markdown => core.news_downgrade(&body),
            BodyType::Plain => None,
        };
        derived_subject(plain.as_deref().unwrap_or(&body))
            .unwrap_or_else(|| cfg.default_subject.clone())
    } else {
        subject
    };
    core.news_post(
        who.uid,
        PostRequest {
            category,
            parent,
            subject: within(&subject, max_subject(core)),
            body,
            mime,
            attachments: Vec::new(),
        },
    )?;
    Ok(Vec::new())
}

/// Delete an article, and with `replies` everything under it, as mhxd's
/// `DELETEREPLIES` does. Deletion here leaves a tombstone, so what goes
/// is words and not places.
///
/// Replies are anyone's, so asking for them takes `delete_articles`
/// whoever wrote the article itself; without it the request is refused
/// before anything is touched, rather than half done.
fn delete_thread(
    core: &Core,
    who: Asker,
    path: Option<&[u8]>,
    id: ArticleId,
    replies: bool,
) -> Result<(), NewsError> {
    let article = article_in(core, who, path, id)?;
    // A tombstone has nothing left to delete, but its replies do: a 1.5
    // client lists it, and clearing what hangs under it is one request
    // there as anywhere else.
    if article.deleted && !replies {
        return Err(NewsError::NoSuchArticle);
    }
    let mut under = Vec::new();
    if replies {
        if !core
            .access_of(who.uid)
            .is_some_and(|a| a.has(bit::DELETE_ARTICLES))
        {
            return Err(NewsError::AccessDenied);
        }
        let mut after = Some(id);
        let mut snapshot = None;
        'walk: loop {
            let page = core.news_thread(who.uid, article.root, after, snapshot, 200)?;
            snapshot = Some(page.snapshot);
            for a in &page.articles {
                if a.depth <= article.depth {
                    break 'walk;
                }
                if !a.deleted {
                    under.push(a.id);
                }
            }
            match page.articles.last() {
                Some(last) if page.has_more => after = Some(last.id),
                _ => break,
            }
        }
    }
    if !article.deleted {
        core.news_delete(who.uid, id)?;
    }
    for reply in under {
        match core.news_delete(who.uid, reply) {
            // Deleted meanwhile by someone else: gone either way.
            Ok(()) | Err(NewsError::NoSuchArticle) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn delete_node(core: &Core, who: Asker, path: Option<&[u8]>) -> Result<Chunks, NewsError> {
    let node = resolve(core, who, path)?.ok_or(NewsError::NoSuchNode)?;
    core.news_node_delete(who.uid, node.id)?;
    Ok(Vec::new())
}

/// Make a bundle or a category in the bundle `path` names. The new name
/// is a field of its own — `FILE_NAME` for a bundle, `CATEGORY` for a
/// category — as mhxd reads them and GtkHx sends them.
fn make_node(
    core: &Core,
    who: Asker,
    path: Option<&[u8]>,
    kind: NodeKind,
    name: Option<&[u8]>,
) -> Result<Chunks, NewsError> {
    let name = name.ok_or(NewsError::BadRequest("No name was supplied."))?;
    let parent = resolve(core, who, path)?;
    if parent
        .as_ref()
        .is_some_and(|n| n.kind == NodeKind::Category)
    {
        return Err(NewsError::BadRequest("A category holds only articles."));
    }
    core.news_node_create(
        who.uid,
        parent.map(|n| n.id),
        kind,
        &within(&who.enc.decode_chars(name, 255), MAX_NODE_NAME),
    )?;
    Ok(Vec::new())
}

// --- 1.2 flat news -------------------------------------------------------

/// What a 1.2 client is told when this server's news has no flat view.
const THREADED_ONLY: &str = "News on this server is threaded. Reading it needs a Hotline \
     1.5 client or newer.";

/// The flat category's id, or `None` when there is no flat view: none
/// configured, or one configured that does not exist (which the operator
/// hears about).
fn flat_category(core: &Core, cfg: &LegacyNews, uid: Uid) -> Result<Option<NodeId>, NewsError> {
    let Some(flat) = cfg.flat.as_ref() else {
        return Ok(None);
    };
    let found = find_category(core, uid, &flat.category)?;
    if found.is_none() {
        warn!(
            category = flat.category.join("/"),
            "[news] flat_category names no category"
        );
    }
    Ok(found)
}

fn flat_document(core: &Core, cfg: &LegacyNews, who: Asker) -> Result<Chunks, NewsError> {
    let (Some(flat), Some(category)) = (cfg.flat.as_ref(), flat_category(core, cfg, who.uid)?)
    else {
        // Readable, not a task error: a person running a 1.2 client
        // deserves to learn why the pane is empty (§12.5). The error is
        // for a server with no news at all.
        core.news_tree(who.uid, None, 1)?;
        return Ok(vec![(tag::NEWS, who.enc.body(THREADED_ONLY))]);
    };
    let articles = core.news_recent(who.uid, category, flat.articles.saturating_add(1))?;
    Ok(vec![(tag::NEWS, render_document(who.enc, flat, &articles))])
}

/// The flat document (§12.5): a masthead, then entries newest first until
/// `flat_articles` or 65 535 bytes, then — when anything was left out — a
/// line naming the oldest id it carried, so a reader knows the archive
/// goes on.
///
/// `articles` is newest first and may be one longer than `flat.articles`,
/// which is how "more than fits" is known without a count.
pub(crate) fn render_document(enc: TextEncoding, flat: &FlatNews, articles: &[Article]) -> Vec<u8> {
    let masthead = match flat.masthead.as_deref() {
        Some("") => None,
        Some(line) => Some(line.to_string()),
        None => Some(format!(
            "News from \"{}\", newest first. To set a subject or reply to an \
             article, begin a post with Subject: and Re: #<number> lines, as the \
             entries below do.",
            flat.category.join("/")
        )),
    };
    // Cut to its ceiling even though startup refuses a longer one, so no
    // masthead can crowd the entries out of the chunk, or past it.
    let mut out = masthead.map_or_else(Vec::new, |line| {
        let mut out = fit(enc, enc.body(&line), MASTHEAD_MAX);
        out.extend(enc.body(&format!("\n{DIVIDER}\n")));
        out
    });
    // Room for the notice at its longest, so adding it can never push the
    // document past the chunk.
    let reserve = enc.body(&older_notice(ArticleId::MAX)).len();
    let mut oldest = None;
    let mut left_over = articles.len() > flat.articles;
    for (i, a) in articles.iter().take(flat.articles).enumerate() {
        let entry = enc.body(&render_entry(a));
        let room = CHUNK_MAX.saturating_sub(out.len() + reserve);
        if entry.len() > room {
            if i > 0 {
                left_over = true;
                break;
            }
            // The newest entry alone does not fit: the pane shows as much
            // of it as it can rather than nothing but a notice.
            out.extend(fit(enc, entry, room));
        } else {
            out.extend(entry);
        }
        oldest = Some(a.id);
    }
    if let (true, Some(id)) = (left_over, oldest) {
        out.extend(enc.body(&older_notice(id)));
    }
    out
}

fn older_notice(oldest: ArticleId) -> String {
    format!("Older articles go on past #{oldest}, the oldest shown here.\n")
}

/// One entry, as the document shows it and as the push carries it
/// (§12.5): mhxd's frame — who, when, a blank line, the text, the divider
/// — with the id after the date and the two headers a 1.2 user types to
/// set a subject and reply.
pub(crate) fn render_entry(a: &Article) -> String {
    let mut s = String::new();
    if a.deleted {
        s.push_str("From (deleted)");
    } else {
        s.push_str("From ");
        s.push_str(&a.author.nick);
        if let Some(login) = &a.author.login {
            s.push_str(" - ");
            s.push_str(login);
        }
    }
    s.push_str(&format!("\n[{}]  #{}\n", ctime(a.at), a.id));
    if !a.subject.is_empty() {
        s.push_str(&format!("Subject: {}\n", a.subject));
    }
    if let Some(parent) = a.parent {
        s.push_str(&format!("Re: #{parent}\n"));
    }
    s.push('\n');
    // A markdown article contributes its downgrade, never its source: a
    // 1.2 client is the last place to send raw syntax.
    let text = a.plain.as_deref().unwrap_or(&a.body);
    if !text.is_empty() {
        s.push_str(text.trim_end_matches('\n'));
        s.push('\n');
    }
    // A picture this wire cannot fetch is named, so a post does not read
    // as if something were missing from it.
    for image in &a.attachments {
        match &image.name {
            Some(name) => s.push_str(&format!("[image: {name}]\n")),
            None => s.push_str("[image]\n"),
        }
    }
    s.push_str(DIVIDER);
    s.push('\n');
    s
}

/// `Wed Sep  9 12:00:00 2026 UTC`: C's `%c`, which is mhxd's default
/// news time, in UTC and saying so — the server knows nothing about
/// where the reader is.
fn ctime(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let c = civil(t);
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {} UTC",
        DAYS[c.weekday as usize],
        MONTHS[(c.month - 1) as usize],
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.year
    )
}

/// A 1.2 post's leading header block, and the body after it (§12.5).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FlatPost {
    pub subject: Option<String>,
    /// The article named, and the line that named it, which goes back
    /// into the body if the article cannot be replied to.
    pub re: Option<(ArticleId, String)>,
    pub body: String,
}

/// Read `Subject:` and `Re:` off the top of a body. Lines are consumed
/// while they are a header not seen yet — case aside, since `subject:`
/// is what someone will type — and the first that is not is where the
/// body starts, one blank line after the block going with it. A second
/// `Subject:` is body, and so is a header nobody recognizes, which is
/// what keeps the convention from eating prose.
pub(crate) fn parse_flat_post(text: &str) -> FlatPost {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut post = FlatPost {
        subject: None,
        re: None,
        body: String::new(),
    };
    let mut rest = text.as_str();
    let mut any = false;
    loop {
        let (line, after) = match rest.split_once('\n') {
            Some((line, after)) => (line, after),
            None => (rest, ""),
        };
        let header = line.split_once(':').and_then(|(name, value)| {
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "subject" if post.subject.is_none() && !value.is_empty() => {
                    Some((Some(value.to_string()), None))
                }
                "re" if post.re.is_none() => {
                    let digits = value.strip_prefix('#').unwrap_or(value);
                    let id = digits
                        .parse::<ArticleId>()
                        .ok()
                        .filter(|&id| id != 0 && digits.bytes().all(|b| b.is_ascii_digit()))?;
                    Some((None, Some((id, line.to_string()))))
                }
                _ => None,
            }
        });
        match header {
            Some((subject, re)) if !rest.is_empty() => {
                post.subject = subject.or(post.subject);
                post.re = re.or(post.re);
                any = true;
                rest = after;
            }
            _ => break,
        }
    }
    if any {
        if let Some(after) = rest.strip_prefix('\n') {
            rest = after;
        } else if rest.trim().is_empty() {
            rest = "";
        }
    }
    post.body = rest.to_string();
    post
}

/// A subject from a body's first line with anything on it, cut at a word
/// with an ellipsis when it runs long. The line stays in the body: in
/// flat news the body is the whole message.
pub(crate) fn derived_subject(body: &str) -> Option<String> {
    let line = body
        .split(['\r', '\n'])
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    if line.chars().count() <= DERIVED_SUBJECT {
        return Some(line.to_string());
    }
    let cut: String = line.chars().take(DERIVED_SUBJECT).collect();
    let at_word = match cut.rfind(char::is_whitespace) {
        Some(i) if i > 0 => cut[..i].trim_end(),
        _ => cut.as_str(),
    };
    Some(format!("{at_word}\u{2026}"))
}

/// Post from a 1.2 client into the flat category.
///
/// **Never refused for what the wire cannot say.** A post with no
/// `Subject:` gets one from its first line; one with no `Re:` goes where
/// `flat_reply` says; one whose `Re:` names an article that is missing,
/// deleted, in another category or too deep to answer goes there too,
/// with the `Re:` line kept in the body so what the person meant
/// survives in what everyone reads.
fn flat_post(core: &Core, cfg: &LegacyNews, who: Asker, text: &str) -> Result<(), NewsError> {
    let (Some(flat), Some(category)) = (cfg.flat.as_ref(), flat_category(core, cfg, who.uid)?)
    else {
        core.news_tree(who.uid, None, 1)?;
        return Err(NewsError::BadRequest(
            "News on this server is threaded. Posting needs a 1.5 client.",
        ));
    };
    let post = parse_flat_post(text);
    let subject = post
        .subject
        .clone()
        .or_else(|| derived_subject(&post.body))
        .unwrap_or_else(|| cfg.default_subject.clone());
    let subject = within(&subject, max_subject(core));
    let fallback = match flat.reply {
        FlatReply::NewThread => None,
        FlatReply::NewestThread => newest_live_root(core, who.uid, category)?,
    };
    let request = |parent, body: String| PostRequest {
        category,
        parent,
        subject: subject.clone(),
        body,
        mime: BodyType::Plain,
        attachments: Vec::new(),
    };
    let kept = |line: &str| format!("{line}\n{}", post.body);
    let Some((id, line)) = post.re.as_ref() else {
        core.news_post(who.uid, request(fallback, post.body.clone()))?;
        return Ok(());
    };
    let answerable = match core.news_article(who.uid, *id) {
        Ok(a) => a.category == category && !a.deleted,
        Err(NewsError::NoSuchArticle) => false,
        Err(e) => return Err(e),
    };
    if !answerable {
        core.news_post(who.uid, request(fallback, kept(line)))?;
        return Ok(());
    }
    match core.news_post(who.uid, request(Some(*id), post.body.clone())) {
        Err(NewsError::TooDeep) => {
            core.news_post(who.uid, request(fallback, kept(line)))?;
            Ok(())
        }
        other => other.map(|_| ()),
    }
}

/// The root of the newest thread whose starter is still there: where a
/// 1.2 post with no `Re:` goes. Replying to the root rather than to the
/// newest article keeps every such post at depth 1 instead of walking a
/// chain into `max_depth` within weeks.
fn newest_live_root(
    core: &Core,
    uid: Uid,
    category: NodeId,
) -> Result<Option<ArticleId>, NewsError> {
    let limit = core.news_policy().map_or(1, |p| p.max_page).max(1);
    let page = core.news_threads(
        uid,
        ThreadQuery {
            category,
            before: None,
            after: None,
            limit,
        },
    )?;
    Ok(page
        .threads
        .iter()
        .find(|h| !h.article.deleted)
        .map(|h| h.article.id))
}

/// The entry to push when article `id` landed in `category` (§12.5):
/// `Some` when that is the flat category, whichever wire it came from.
/// Rendered exactly as the document renders it, so a client that
/// prepends the push and one that refetches read the same text.
pub(crate) async fn flat_push(
    core: &std::sync::Arc<Core>,
    cfg: &LegacyNews,
    who: Asker,
    id: ArticleId,
    category: NodeId,
) -> Option<Vec<u8>> {
    let names = cfg.flat.as_ref()?.category.clone();
    off_reactor(core, move |core| {
        // Asked of every post by every connection, so a missing category
        // is not warned about here: reading the news says so once.
        if find_category(core, who.uid, &names).ok()?? != category {
            return None;
        }
        let article = core.news_article(who.uid, id).ok()?;
        Some(fit(
            who.enc,
            who.enc.body(&render_entry(&article)),
            CHUNK_MAX,
        ))
    })
    .await
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::{Author, Node};
    use hxproto::parse::{parse_catlist, parse_dirlist, NewsDirKind};
    use std::time::Duration;

    const MR: TextEncoding = TextEncoding::MacRoman;
    const U8: TextEncoding = TextEncoding::Utf8;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn article(id: ArticleId, parent: Option<ArticleId>, subject: &str, body: &str) -> Article {
        Article {
            id,
            category: 1,
            parent,
            root: parent.unwrap_or(id),
            depth: u16::from(parent.is_some()),
            author: Author {
                nick: "Alice".into(),
                login: Some("alice".into()),
                fingerprint: None,
            },
            subject: subject.into(),
            body: body.into(),
            mime: BodyType::Plain,
            plain: None,
            at: at(1_788_955_200),
            deleted: false,
            refs: Vec::new(),
            referenced_by: 0,
            attachments: Vec::new(),
        }
    }

    fn flat(articles: usize) -> FlatNews {
        FlatNews {
            category: vec!["General".into()],
            articles,
            reply: FlatReply::NewestThread,
            masthead: Some(String::new()),
        }
    }

    /// A reply as a whole TASK frame, which is what hxproto's parsers
    /// walk.
    fn message(chunks: &Chunks) -> Vec<u8> {
        crate::frame::pack_frame(0x0001_0000, 1, 0, chunks)
    }

    #[test]
    fn a_header_block_is_consumed_and_stripped() {
        let p = parse_flat_post("Subject: The u16\rRe: #398\r\rThe part size is a u16.\r");
        assert_eq!(p.subject.as_deref(), Some("The u16"));
        assert_eq!(p.re, Some((398, "Re: #398".into())));
        assert_eq!(p.body, "The part size is a u16.\n");
    }

    #[test]
    fn a_header_is_read_whatever_its_case_and_either_id_spelling() {
        let p = parse_flat_post("subject: lower\nre: 398\nbody");
        assert_eq!(p.subject.as_deref(), Some("lower"));
        assert_eq!(p.re.map(|r| r.0), Some(398));
        assert_eq!(p.body, "body");
        assert_eq!(parse_flat_post("RE: #7\n\nx").re.map(|r| r.0), Some(7));
    }

    #[test]
    fn an_unrecognized_first_line_leaves_the_body_whole() {
        let text = "Note: this is broken\nSubject: not a header now\n\nbody";
        let p = parse_flat_post(text);
        assert_eq!((p.subject, p.re), (None, None));
        assert_eq!(p.body, text);
        // Nor is a `Re:` that names nothing a person could mean.
        let text = "Re: your post\nI agree.";
        assert_eq!(parse_flat_post(text).body, text);
    }

    #[test]
    fn a_second_subject_is_body() {
        let p = parse_flat_post("Subject: one\nSubject: two\nbody");
        assert_eq!(p.subject.as_deref(), Some("one"));
        assert_eq!(p.body, "Subject: two\nbody");
    }

    #[test]
    fn only_one_blank_line_goes_with_the_block() {
        let p = parse_flat_post("Subject: s\n\n\nindented");
        assert_eq!(p.body, "\nindented");
        let p = parse_flat_post("plain\n\nprose");
        assert_eq!(p.body, "plain\n\nprose", "no block, nothing consumed");
    }

    #[test]
    fn a_derived_subject_is_the_first_line_cut_at_a_word() {
        assert_eq!(
            derived_subject("\n\n  Hello there  \nmore").as_deref(),
            Some("Hello there")
        );
        let long = "word ".repeat(30);
        let s = derived_subject(&long).unwrap();
        assert!(s.ends_with('\u{2026}'));
        assert!(s.chars().count() <= DERIVED_SUBJECT + 1);
        assert!(!s.contains("wor\u{2026}"), "cut at a word: {s:?}");
        assert_eq!(
            derived_subject("from\ra 1.2 client").as_deref(),
            Some("from")
        );
        assert_eq!(derived_subject(""), None);
        assert_eq!(derived_subject(" \n \n"), None);
    }

    #[test]
    fn an_entry_carries_the_id_and_the_two_headers() {
        let a = article(
            412,
            Some(398),
            "The derivative and the u16",
            "The part size.\n",
        );
        let entry = render_entry(&a);
        assert_eq!(
            entry,
            format!(
                "From Alice - alice\n[Wed Sep  9 12:00:00 2026 UTC]  #412\n\
                 Subject: The derivative and the u16\nRe: #398\n\nThe part size.\n{DIVIDER}\n"
            )
        );
        // What a 1.2 client reads is what it would type back.
        let back = parse_flat_post(entry.split_once("#412\n").unwrap().1);
        assert_eq!(back.subject.as_deref(), Some("The derivative and the u16"));
        assert_eq!(back.re.map(|r| r.0), Some(398));
        // And on the wire it is CR-delimited Mac Roman.
        assert!(!MR.body(&entry).contains(&b'\n'));
    }

    #[test]
    fn an_entry_reads_the_downgrade_and_names_its_pictures() {
        let mut a = article(5, None, "Pics", "**bold** words");
        a.mime = BodyType::Markdown;
        a.plain = Some("bold words".into());
        a.attachments = vec![hxd_core::Attachment {
            id: [0; 16],
            mime: hxd_core::MediaType::Png,
            width: 1,
            height: 1,
            bytes: 1,
            name: Some("screenshot.png".into()),
        }];
        let entry = render_entry(&a);
        assert!(entry.contains("\n\nbold words\n[image: screenshot.png]\n"));
        assert!(!entry.contains("**"));
    }

    #[test]
    fn a_tombstone_keeps_its_header_and_loses_its_words() {
        let mut a = article(9, Some(3), "", "");
        a.deleted = true;
        a.author = Author {
            nick: String::new(),
            login: None,
            fingerprint: None,
        };
        assert_eq!(
            render_entry(&a),
            format!("From (deleted)\n[Wed Sep  9 12:00:00 2026 UTC]  #9\nRe: #3\n\n{DIVIDER}\n")
        );
    }

    #[test]
    fn the_document_stops_at_the_budget_and_says_where() {
        let big = "x".repeat(20_000);
        let articles: Vec<Article> = (1..=5)
            .rev()
            .map(|id| article(id, None, "s", &big))
            .collect();
        let doc = render_document(MR, &flat(100), &articles);
        assert!(doc.len() <= CHUNK_MAX);
        let text = String::from_utf8(doc).unwrap();
        assert!(text.contains("#5\r") && text.contains("#3\r"));
        assert!(!text.contains("#2\r"));
        assert!(text.ends_with("Older articles go on past #3, the oldest shown here.\r"));

        // Under the budget and the count, nothing is said.
        let doc = render_document(MR, &flat(100), &articles[..2]);
        assert!(!String::from_utf8(doc).unwrap().contains("Older"));
        // Over the count, it is.
        let doc = render_document(MR, &flat(1), &articles[..2]);
        let text = String::from_utf8(doc).unwrap();
        assert!(text.contains("#5\r") && !text.contains("#4\r"));
        assert!(text.contains("past #5"));
    }

    #[test]
    fn a_newest_entry_too_big_to_fit_is_cut_not_dropped() {
        let articles = vec![
            article(2, None, "s", &"\u{e9}".repeat(70_000)),
            article(1, None, "s", "small"),
        ];
        for enc in [MR, U8] {
            let doc = render_document(enc, &flat(100), &articles);
            assert!(doc.len() <= CHUNK_MAX);
            let text = enc.decode(&doc);
            assert!(text.contains("#2"));
            assert!(text.contains('\u{2026}'));
            assert!(text.contains("past #2"));
        }
        let doc = render_document(U8, &flat(100), &articles);
        assert!(std::str::from_utf8(&doc).is_ok(), "cut on a character");
    }

    #[test]
    fn the_masthead_is_built_in_chosen_or_absent() {
        let a = [article(1, None, "s", "b")];
        let mut f = flat(10);
        f.masthead = None;
        let text = String::from_utf8(render_document(MR, &f, &a)).unwrap();
        assert!(text.starts_with("News from \"General\""));
        assert!(text.contains("Subject: and Re: #<number>"));
        f.masthead = Some("Welcome.".into());
        let text = String::from_utf8(render_document(MR, &f, &a)).unwrap();
        assert!(text.starts_with(&format!("Welcome.\r{DIVIDER}\rFrom Alice")));
        f.masthead = Some(String::new());
        let text = String::from_utf8(render_document(MR, &f, &a)).unwrap();
        assert!(text.starts_with("From Alice"));
    }

    #[test]
    fn no_masthead_crowds_the_news_out_of_the_chunk() {
        let a = [article(1, None, "s", &"x".repeat(60_000))];
        let mut f = flat(10);
        for enc in [MR, U8] {
            f.masthead = Some("\u{e9}".repeat(70_000));
            let doc = render_document(enc, &f, &a);
            assert!(doc.len() <= CHUNK_MAX, "{}", doc.len());
            let text = enc.decode(&doc);
            assert!(text.contains("]  #1"), "the entry is there");
            let divider = doc
                .windows(DIVIDER.len())
                .position(|w| w == DIVIDER.as_bytes())
                .unwrap();
            assert!(
                divider <= MASTHEAD_MAX + 1,
                "the masthead, cut, and a break"
            );
        }
    }

    #[test]
    fn a_cut_too_small_for_its_ellipsis_is_never_longer_than_asked() {
        for enc in [MR, U8] {
            assert!(fit(enc, b"abcdef".to_vec(), 0).is_empty());
            assert_eq!(fit(enc, b"abcdef".to_vec(), 1).len(), 1);
        }
        assert_eq!(fit(U8, b"abcdef".to_vec(), 2), b"ab");
        assert_eq!(fit(U8, b"abcdef".to_vec(), 4), "a\u{2026}".as_bytes());
    }

    #[test]
    fn a_subject_or_name_is_cut_to_the_domains_bytes_at_a_character() {
        assert_eq!(within("  caf\u{e9}  ", 255), "caf\u{e9}");
        assert_eq!(within(&"\u{e9}".repeat(200), 255), "\u{e9}".repeat(127));
        assert_eq!(within(&"\u{3042}".repeat(100), 255), "\u{3042}".repeat(85));
        assert_eq!(within("ab   cd", 4), "ab");
    }

    #[test]
    fn ctime_is_cs_percent_c_in_utc() {
        assert_eq!(ctime(at(0)), "Thu Jan  1 00:00:00 1970 UTC");
        assert_eq!(
            ctime(at(1_709_164_800 + 3_723)),
            "Thu Feb 29 01:02:03 2024 UTC"
        );
        assert_eq!(ctime(at(1_788_955_200)), "Wed Sep  9 12:00:00 2026 UTC");
    }

    #[test]
    fn a_part_is_cut_to_the_chunk_at_a_character() {
        let long = "\u{3042}".repeat(30_000);
        let wire = wire_text(U8, &long);
        assert!(wire.len() <= CHUNK_MAX);
        assert!(std::str::from_utf8(&wire).unwrap().ends_with('\u{2026}'));
        let wire = wire_text(MR, &"a".repeat(70_000));
        assert_eq!(wire.len(), CHUNK_MAX);
        assert_eq!(*wire.last().unwrap(), 0xc9, "Mac Roman's ellipsis");
        assert_eq!(
            wire_len(MR, TextLen::of(&"a".repeat(70_000))),
            Some(CHUNK_MAX)
        );
        assert_eq!(
            wire_len(U8, TextLen::of(&long)),
            None,
            "only the text knows"
        );
        assert_eq!(wire_len(U8, TextLen::of("\u{e9}")), Some(2));
        assert_eq!(wire_len(MR, TextLen::of("\u{e9}")), Some(1));
    }

    fn node(kind: NodeKind, name: &str) -> Node {
        Node {
            id: 7,
            parent: None,
            kind,
            name: name.into(),
            guid: [0xab; 16],
            add_sn: 5,
            delete_sn: 2,
            children: 3,
            created_at: at(0),
        }
    }

    #[test]
    fn a_directory_listing_parses_as_a_client_parses_it() {
        let chunks = vec![
            (
                tag::CATEGORYITEM,
                category_item(MR, &node(NodeKind::Bundle, "Projects")),
            ),
            (
                tag::CATEGORYITEM,
                category_item(MR, &node(NodeKind::Category, "Caf\u{e9}")),
            ),
        ];
        let bytes = message(&chunks);
        let list = parse_dirlist(&bytes, bytes.len());
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.entries[0].kind, NewsDirKind::Folder);
        assert_eq!(list.entries[0].name, b"Projects");
        assert_eq!(list.entries[1].kind, NewsDirKind::Category);
        assert_eq!(list.entries[1].name, b"Caf\x8e");
        // The category's sync fields sit where mhxd's struct puts them.
        let cat = &chunks[1].1;
        assert_eq!(&cat[0..2], &[0, 3]);
        assert_eq!(&cat[2..4], &[0, 3], "its count");
        assert_eq!(&cat[4..20], &[0xab; 16]);
        assert_eq!(&cat[20..24], &5u32.to_be_bytes());
        assert_eq!(&cat[24..28], &2u32.to_be_bytes());
        assert_eq!(
            chunks[0].1.len(),
            5 + 8,
            "a bundle is exactly as long as it says"
        );
    }

    fn listed(id: ArticleId, parent: Option<ArticleId>) -> Listed {
        Listed {
            id,
            parent,
            root: parent.map_or(id, |_| 1),
            at: at(1_788_955_200),
            subject: format!("subject {id}"),
            nick: "Alice".into(),
            mime: BodyType::Plain,
            deleted: false,
            body_len: TextLen::of("caf\u{e9}"),
            plain_len: None,
        }
    }

    #[test]
    fn a_post_and_its_parts_parse_as_a_client_parses_them() {
        let core = Core::new();
        let who = Asker { uid: 1, enc: MR };
        let mut marked = listed(2, Some(1));
        marked.mime = BodyType::Markdown;
        marked.body_len = TextLen::of("**bold**");
        marked.plain_len = Some(TextLen::of("bold"));
        let mut stone = listed(3, Some(1));
        stone.deleted = true;
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        for l in [listed(1, None), marked, stone] {
            body.extend(catlist_post(&core, who, &l));
        }
        let bytes = message(&vec![(tag::CATLIST, body)]);
        let list = parse_catlist(&bytes, bytes.len()).expect("a client parses it");
        let [plain, marked, stone] = &list.posts[..] else {
            panic!("three posts: {:?}", list.posts);
        };
        assert_eq!((plain.postid, plain.parentid), (1, 0));
        assert_eq!(plain.subject, b"subject 1");
        assert_eq!(plain.sender, b"Alice");
        assert_eq!(plain.parts.len(), 1);
        assert_eq!(plain.parts[0].mime_type, b"text/plain");
        assert_eq!(plain.parts[0].size, 4, "four characters, four bytes");
        assert_eq!(&[plain.date_base_year, plain.date_pad], &[2000, 0]);

        assert_eq!(marked.parentid, 1);
        let parts: Vec<(&[u8], u16)> = marked
            .parts
            .iter()
            .map(|p| (p.mime_type.as_slice(), p.size))
            .collect();
        assert_eq!(parts, [(&b"text/plain"[..], 4), (&b"text/markdown"[..], 8)]);

        assert_eq!(stone.subject, b"");
        assert_eq!(stone.sender, b"");
        assert_eq!(stone.parts.len(), 1);
        assert_eq!(stone.parts[0].size, 0);
    }

    #[test]
    fn a_path_is_the_file_areas_encoding_and_short_is_the_root() {
        assert!(components(None).unwrap().is_empty());
        assert!(components(Some(b"")).unwrap().is_empty());
        assert!(components(Some(b"\0\0")).unwrap().is_empty());
        assert_eq!(
            components(Some(b"\0\x02\0\0\x01a\0\0\x02bc")).unwrap(),
            [b"a".to_vec(), b"bc".to_vec()]
        );
        assert!(components(Some(b"\0\x02\0\0\x01a\0\0")).is_err());
    }

    #[test]
    fn every_news_opcode_is_answered_here() {
        for ty in [
            0x65, 0x67, 0x172, 0x173, 0x17c, 0x17d, 0x17e, 0x190, 0x19a, 0x19b,
        ] {
            assert!(handles(ty), "{ty:#x}");
        }
        assert!(!handles(0x69));
    }
}
