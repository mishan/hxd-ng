//! Threaded news: bundles, categories, articles, and the references
//! between them.
//!
//! Designed in `docs/news.md`. The tree keeps the 1.5 wire's containment
//! rules — a bundle holds bundles and categories, a category holds
//! articles and nothing else, a reply lives in its parent's category —
//! because they cost the ng wire nothing and are what makes the legacy
//! binding a mapping rather than a translation (§2). Threading is a
//! materialized preorder path, so a thread comes back in display order
//! from one range scan (§3.3).
//!
//! **The store decides its own invariants.** Containment, reply depth, a
//! name unique among its siblings, and whether a referenced id names an
//! article are all settled inside the store's write, never by a caller
//! reading first — for the reason [`crate::inbox::MessageStore::push`]
//! gives: a check made outside the transaction is a check a concurrent
//! write can invalidate. So the writing methods answer [`NewsError`]
//! rather than [`StoreError`], and [`conformance`] holds both stores to
//! the same answers.
//!
//! **Wire-free and UTF-8**, like everything else in this crate. A
//! `NEWSPATH` is the legacy wire's address for a node and gets resolved
//! in `hxd-session` (§12.1); the domain names nodes by id.
//!
//! The trait grows with the stages of `docs/news.md` §16. What is here
//! is the tree, plain-text articles, `#51` references and retention;
//! markdown, search, attachments and subscriptions bring their methods
//! with them rather than arriving early as stubs.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tracing::warn;

use crate::access::{bit, AccessBits};
use crate::inbox::{Mailbox, StoreError};
use crate::roster::{Core, Event, Uid, UserSession};

pub mod conformance;
pub mod memory;

pub use memory::MemoryNews;

/// A bundle or a category. A rowid, never reused.
pub type NodeId = u64;

/// An article. **A u32 because the legacy wire says so** (§3.2):
/// `CatPost.postid`, `parentid` and the `THREADID` chunk are all u32, and
/// an id that wire cannot carry is an article nobody on it can reply to.
/// Globally unique and never reused, so an ng client names an article by
/// id alone.
pub type ArticleId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// The SDK's "news folder": holds bundles and categories.
    Bundle,
    /// Holds articles, and only articles.
    Category,
}

impl NodeKind {
    pub fn as_i64(self) -> i64 {
        match self {
            NodeKind::Bundle => 0,
            NodeKind::Category => 1,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(NodeKind::Bundle),
            1 => Some(NodeKind::Category),
            _ => None,
        }
    }

    /// The ng wire's spelling.
    pub fn name(self) -> &'static str {
        match self {
            NodeKind::Bundle => "bundle",
            NodeKind::Category => "category",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "bundle" => Some(NodeKind::Bundle),
            "category" => Some(NodeKind::Category),
            _ => None,
        }
    }
}

/// A bundle or a category, as a listing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    /// `None` for a node at the root of the tree.
    pub parent: Option<NodeId>,
    pub kind: NodeKind,
    /// Unique among its parent's children, because the legacy wire
    /// addresses a node by name and the ng wire is held to the same rule
    /// rather than allowed duplicates it would then have to explain.
    pub name: String,
    /// The 1.5 `CATEGORYITEM` guid: stable for the node's life. Filled
    /// from day one although only the legacy binding reads it, because a
    /// column left empty is a 1.5 client refetching everything forever
    /// (§4).
    pub guid: [u8; 16],
    /// Bumped on every post into a category.
    pub add_sn: u32,
    /// Bumped on every delete from one.
    pub delete_sn: u32,
    /// Sub-nodes for a bundle; live articles for a category.
    pub children: u32,
    pub created_at: SystemTime,
}

/// Who wrote an article, **as they were when they wrote it** (§3.1). A
/// rename two years later does not rewrite history.
///
/// `login` and `fingerprint` are what "is this yours" is decided on — the
/// same two columns, for the same reason, as `chat_line` and `message` —
/// and both are `None` for a guest, whose `guest` login several people
/// share and so names nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub nick: String,
    pub login: Option<String>,
    pub fingerprint: Option<[u8; 32]>,
}

impl Author {
    /// Did the account behind `who` write this? The mailbox rule
    /// ([`Mailbox::matches`]) over the author's two columns, so an
    /// identity-linked account is recognized across a rename and a login
    /// someone else has since taken is not.
    pub fn is(&self, who: &Mailbox) -> bool {
        self.login
            .as_deref()
            .is_some_and(|login| who.matches(login, self.fingerprint.as_ref()))
    }
}

/// How to read an article's body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyType {
    Plain,
    /// Accepted once the markdown stage (§5, W3) lands. The column and the
    /// wire field exist now so that stage is not a migration.
    Markdown,
}

impl BodyType {
    pub fn mime(self) -> &'static str {
        match self {
            BodyType::Plain => "text/plain",
            BodyType::Markdown => "text/markdown",
        }
    }

    pub fn from_mime(s: &str) -> Option<Self> {
        match s {
            "text/plain" => Some(BodyType::Plain),
            "text/markdown" => Some(BodyType::Markdown),
            _ => None,
        }
    }
}

/// One article.
///
/// A tombstone keeps its id, category, parent, place in its thread and
/// time, and loses its subject, body, author and outbound references
/// (§9.2). Its replies stay where they are: dropping it would reparent
/// them onto nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Article {
    pub id: ArticleId,
    pub category: NodeId,
    pub parent: Option<ArticleId>,
    /// Equal to `id` for a thread starter.
    pub root: ArticleId,
    /// 0 for a thread starter.
    pub depth: u16,
    pub author: Author,
    pub subject: String,
    /// Exactly as typed, with its line endings made LF.
    pub body: String,
    pub mime: BodyType,
    pub at: SystemTime,
    pub deleted: bool,
    /// What the body pointed at, resolved when it was posted, reported as
    /// the targets stand now. In order of appearance.
    pub refs: Vec<Reference>,
    /// How many articles point at this one. The list is
    /// [`NewsStore::refs_to`].
    pub referenced_by: u32,
}

/// A resolved reference. Unlike [`Author`] this is *current* state: a
/// reference is a pointer, so it reports its target as it is now (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub id: ArticleId,
    /// Empty when the target is a tombstone.
    pub subject: String,
    pub author_nick: String,
    pub at: SystemTime,
    pub deleted: bool,
}

/// A thread as a listing shows it: the starter, and what happened to it
/// since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadHead {
    /// The starter, body included — a listing that shows a first line
    /// needs it, and a round trip per row is what a phone cannot afford.
    pub article: Article,
    /// Everything under the starter, tombstones included.
    pub replies: u32,
    pub last_at: SystemTime,
    pub last_id: ArticleId,
}

/// A post on its way into the store. Everything about it has been
/// checked except what only the store can check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPost {
    pub category: NodeId,
    pub parent: Option<ArticleId>,
    pub author: Author,
    pub subject: String,
    pub body: String,
    pub mime: BodyType,
    /// Candidate ids from [`scan_refs`], in order of appearance and
    /// deduplicated. The store keeps the ones that name an article.
    pub refs: Vec<ArticleId>,
    pub at: SystemTime,
}

/// What the store made of a post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posted {
    pub id: ArticleId,
    pub root: ArticleId,
}

/// A node on its way into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNode {
    pub parent: Option<NodeId>,
    pub kind: NodeKind,
    pub name: String,
    pub guid: [u8; 16],
    pub at: SystemTime,
}

/// A page of one category's threads. **Newest first**, by starter id.
///
/// `before` pages toward older threads and `after` toward newer ones,
/// both exclusive, exactly as `history` does with lines; with `after`
/// the page is the threads nearest to it, still newest first. `has_more`
/// is about the direction asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadQuery {
    pub category: NodeId,
    pub before: Option<ArticleId>,
    pub after: Option<ArticleId>,
    /// Clamped by the caller; zero is refused.
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPage {
    pub threads: Vec<ThreadHead>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArticlePage {
    /// Preorder: every reply directly under the article it answers,
    /// siblings oldest first.
    pub articles: Vec<Article>,
    pub has_more: bool,
    /// The newest article admitted to this traversal. Echo it on every
    /// later page so replies posted meanwhile do not move behind the
    /// cursor and disappear from the walk.
    pub snapshot: ArticleId,
}

/// A node with the part of the tree under it that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTree {
    pub node: Node,
    /// `Some` for a bundle the requested depth reached into; `None` for
    /// a category, and for a bundle below the requested depth.
    pub children: Option<Vec<NodeTree>>,
}

/// Why a news operation did not happen. Each is a distinct ng error code
/// (§9.2); the mapping lives in the frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewsError {
    /// This server has no news at all — about the server, where
    /// `AccessDenied` is about you.
    Disabled,
    AccessDenied,
    NoSuchNode,
    NoSuchArticle,
    /// Posting into a bundle, or putting a node inside a category.
    NotACategory,
    /// A reply whose parent lives in another category.
    WrongCategory,
    TooDeep,
    NameTaken,
    /// Deleting a bundle that still holds something.
    NotEmpty,
    /// A body type this server does not take.
    BadBodyType,
    /// Malformed input the domain refuses, with what was wrong for a
    /// human.
    BadRequest(&'static str),
    /// The session asking has gone.
    NoSession,
    Store(StoreError),
}

impl From<StoreError> for NewsError {
    fn from(e: StoreError) -> Self {
        NewsError::Store(e)
    }
}

/// The store behind the tree. Synchronous, like [`crate::MessageStore`]
/// and [`crate::ChatLog`], for the reason their docs give: `Core` is sync
/// all the way down, and the frontends call through `off_reactor`.
pub trait NewsStore: Send + Sync + 'static {
    /// The children of `parent` (the root when `None`), by name.
    fn nodes(&self, parent: Option<NodeId>) -> Result<Vec<Node>, StoreError>;

    fn node(&self, id: NodeId) -> Result<Option<Node>, StoreError>;

    /// Create a node. Refuses a missing parent, a category as a parent,
    /// a name its siblings already use, and a node deeper than
    /// `max_depth` levels from the root.
    fn create_node(&self, n: &NewNode, max_depth: u16) -> Result<Node, NewsError>;

    fn rename_node(&self, id: NodeId, name: &str) -> Result<Node, NewsError>;

    /// Delete a node. A category takes its articles with it; a bundle
    /// must be empty — "delete this folder and the four hundred articles
    /// in it" should be four hundred decisions or a refusal, not one
    /// click (§8). Returns how many articles went.
    fn delete_node(&self, id: NodeId) -> Result<u64, NewsError>;

    /// Store a post: into a category, under a parent in the same
    /// category, no deeper than `max_depth`, with at most `max_refs` of
    /// its candidate references kept — only the ones that name an
    /// article, since an id naming nothing is the digits someone typed.
    /// Bumps the category's `add_sn`.
    fn post(&self, p: &NewPost, max_depth: u16, max_refs: usize) -> Result<Posted, NewsError>;

    fn article(&self, id: ArticleId) -> Result<Option<Article>, StoreError>;

    /// One category's threads. `NoSuchNode` or `NotACategory` for a
    /// query that names something else. A thread whose every article is
    /// a tombstone is not listed: there is nothing left in it to read.
    fn threads(&self, q: &ThreadQuery) -> Result<ThreadPage, NewsError>;

    /// A thread in preorder, from the start or from after `after` (an
    /// article in it). The first page chooses a `snapshot`; later pages
    /// echo it so the mutable preorder is stable for the whole walk.
    /// `NoSuchArticle` when `root` is not a thread starter.
    fn thread(
        &self,
        root: ArticleId,
        after: Option<ArticleId>,
        snapshot: Option<ArticleId>,
        limit: usize,
    ) -> Result<ArticlePage, NewsError>;

    /// Clear an article down to its tombstone, drop its outbound
    /// references, and bump its category's `delete_sn`. Returns the
    /// article as it was, or `None` when there was no live article with
    /// that id. `by` is who did it, for the moderation record.
    fn tombstone(
        &self,
        id: ArticleId,
        by: &str,
        at: SystemTime,
    ) -> Result<Option<Article>, StoreError>;

    /// The articles pointing at `id`, newest first. Tombstones are never
    /// among them — a tombstone's references went with its body.
    fn refs_to(&self, id: ArticleId, limit: usize) -> Result<Vec<Reference>, StoreError>;

    /// Retention: remove every thread whose newest article is older than
    /// `max_age`, whole — pruning a starter out from under its live
    /// replies would leave them hanging off nothing. References into what
    /// went go with it. Returns how many articles went.
    fn prune(&self, max_age: Duration, now: SystemTime) -> Result<u64, StoreError>;
}

/// The numbers the domain enforces, filled from `[news]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsPolicy {
    /// The legacy `NEWSDATA` ceiling (§12.4): lower it freely, never
    /// raise it past 65 535.
    pub max_body: usize,
    /// The 1.5 pstring: 255.
    pub max_subject: usize,
    pub max_refs: usize,
    /// Reply nesting.
    pub max_depth: u16,
    /// Bundle nesting.
    pub max_node_depth: u16,
    pub max_page: usize,
    /// May an author delete their own article without `delete_articles`?
    /// A deliberate deviation from period behavior, where it is the bit
    /// or nothing (§8).
    pub self_delete: bool,
    /// Days a thread survives its last post; 0 keeps everything.
    pub retain_days: u32,
}

impl Default for NewsPolicy {
    fn default() -> Self {
        NewsPolicy {
            max_body: 65_535,
            max_subject: 255,
            max_refs: 32,
            max_depth: 32,
            max_node_depth: 16,
            max_page: 200,
            self_delete: true,
            retain_days: 0,
        }
    }
}

/// What a frontend hands [`Core::news_post`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRequest {
    pub category: NodeId,
    pub parent: Option<ArticleId>,
    pub subject: String,
    pub body: String,
    pub mime: BodyType,
}

/// The longest node name, in bytes. The legacy wire carries a name as a
/// pstring of Mac Roman, where every character is one byte, so a UTF-8
/// byte bound is the conservative one.
pub const MAX_NODE_NAME: usize = 255;

/// How many candidate references one body may offer the store. Far past
/// any `max_refs`, and what stops a 64 KiB body of `#1 #2 #3 …` becoming
/// thousands of lookups for a cap of 32.
const MAX_REF_CANDIDATES: usize = 256;

/// The `#51` shorthand, found in a body (§5.3).
///
/// Recognized when the `#` starts the text or follows whitespace or
/// punctuation, and the digits end at the text's end, whitespace or
/// punctuation. Not recognized after `&`, where `&#51;` is an HTML
/// character reference; after another `#`; or glued to a word on either
/// side. An ATX heading never matches, because a heading's `#` is
/// followed by a space and this needs a digit. The neighbors are judged
/// as characters, not bytes, so an em dash, a curly quote or an
/// ideographic space bounds a reference as `-`, `"` and a space do, and a
/// letter from any script glues to it as `a` does.
///
/// Runs on plain bodies, which is what lets a 1.5 client typing `see #51`
/// produce a real link in an ng client. What comes back are candidates —
/// in order of appearance, deduplicated, nonzero — and the store decides
/// which of them name an article.
pub fn scan_refs(body: &str) -> Vec<ArticleId> {
    // Whitespace, or anything printable that is neither a letter, a digit
    // nor `_` — which in ASCII is exactly punctuation.
    fn delimits(c: char) -> bool {
        c.is_whitespace() || !(c.is_alphanumeric() || c == '_' || c.is_control())
    }
    let bytes = body.as_bytes();
    let mut out: Vec<ArticleId> = Vec::new();
    let mut i = 0;
    while i < bytes.len() && out.len() < MAX_REF_CANDIDATES {
        if bytes[i] != b'#' {
            i += 1;
            continue;
        }
        // `#` and the digits are ASCII, so `i` and `end` are always
        // character boundaries and the neighbors decode whole.
        let opens = match body[..i].chars().next_back() {
            None => true,
            Some('&' | '#') => false,
            Some(c) => delimits(c),
        };
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let closes = body[end..].chars().next().is_none_or(delimits);
        if opens && closes && end > start && end - start <= 10 {
            if let Ok(id) = body[start..end].parse::<ArticleId>() {
                if id != 0 && !out.contains(&id) {
                    out.push(id);
                }
            }
        }
        i = end.max(i + 1);
    }
    out
}

/// A subject as the domain keeps it: one line, trimmed. Line breaks and
/// tabs become spaces rather than refusals — a pasted subject with a
/// trailing newline is not a mistake worth bouncing.
fn clean_subject(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// A body as the domain keeps it: exactly as typed, except that its line
/// endings are LF whatever the sender used. The legacy edge converts to
/// CR on the way out (§12.4).
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// A node name, or why it cannot be one.
fn clean_name(s: &str) -> Result<String, NewsError> {
    let name = s.trim();
    if name.is_empty() {
        return Err(NewsError::BadRequest("A name cannot be empty."));
    }
    if name.len() > MAX_NODE_NAME {
        return Err(NewsError::BadRequest("That name is too long."));
    }
    if name.chars().any(char::is_control) {
        return Err(NewsError::BadRequest("A name is one line of text."));
    }
    Ok(name.to_string())
}

/// This session as the author of whatever it is about to write.
fn author_of(sess: &UserSession) -> Author {
    // Only a session with exactly one person behind its account is
    // somebody: neither the shared `guest` login nor a fingerprint it
    // happened to arrive with makes an article *its* to delete later.
    // `is_person` rather than `has_inbox`, which an operator may turn
    // off for an account's mail without meaning its articles too.
    Author {
        nick: sess.info.nick.clone(),
        login: sess.is_person.then(|| sess.login.clone()),
        fingerprint: sess.identity.filter(|_| sess.is_person),
    }
}

/// What one request needs to know about the session making it, copied
/// out so the roster lock is released before the store is touched.
struct Asker {
    access: AccessBits,
    author: Author,
    /// What this session's own articles were recorded under, where it
    /// can own any (see [`author_of`]).
    owner: Option<Mailbox>,
    login: String,
}

fn store_failed(e: NewsError) -> NewsError {
    if let NewsError::Store(err) = &e {
        warn!("news store: {err}");
    }
    e
}

impl Core {
    /// Give the domain a news store. Without one every news request is
    /// answered as a server without the feature answers it.
    pub fn with_news(mut self, store: Arc<dyn NewsStore>, policy: NewsPolicy) -> Self {
        self.news = Some(store);
        self.news_policy = policy;
        self
    }

    pub fn news_enabled(&self) -> bool {
        self.news.is_some()
    }

    pub fn news_policy(&self) -> Option<NewsPolicy> {
        self.news.as_ref().map(|_| self.news_policy)
    }

    /// May this session post? The login reply says so, the way it says
    /// whether a session moderates, so a client can gray out the button
    /// rather than discover the refusal after someone has typed (§9.1).
    pub fn news_may_post(&self, uid: Uid) -> bool {
        self.access_of(uid)
            .is_some_and(|a| a.has(bit::READ_NEWS) && a.has(bit::POST_NEWS))
    }

    fn news_store(&self) -> Result<&Arc<dyn NewsStore>, NewsError> {
        self.news.as_ref().ok_or(NewsError::Disabled)
    }

    /// The asking session, refused unless it may read news at all —
    /// every other news privilege is on top of that one.
    fn news_reader(&self, uid: Uid) -> Result<Asker, NewsError> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid).ok_or(NewsError::NoSession)?;
        if !sess.access.has(bit::READ_NEWS) {
            return Err(NewsError::AccessDenied);
        }
        Ok(Asker {
            access: sess.access,
            author: author_of(sess),
            owner: sess.is_person.then(|| sess.mailbox()),
            login: sess.login.clone(),
        })
    }

    fn news_fan_out(&self, ev: Event) {
        let mut r = self.roster.lock().unwrap();
        r.broadcast_where(&ev, None, |s| s.access.has(bit::READ_NEWS));
    }

    /// The tree under `parent` (the root when `None`), `depth` levels
    /// deep, between 1 and 4.
    pub fn news_tree(
        &self,
        uid: Uid,
        parent: Option<NodeId>,
        depth: u8,
    ) -> Result<Vec<NodeTree>, NewsError> {
        let store = self.news_store()?;
        self.news_reader(uid)?;
        if let Some(id) = parent {
            store.node(id)?.ok_or(NewsError::NoSuchNode)?;
        }
        fn level(
            store: &dyn NewsStore,
            parent: Option<NodeId>,
            depth: u8,
        ) -> Result<Vec<NodeTree>, NewsError> {
            store
                .nodes(parent)?
                .into_iter()
                .map(|node| {
                    let children = match node.kind {
                        NodeKind::Bundle if depth > 1 => {
                            Some(level(store, Some(node.id), depth - 1)?)
                        }
                        _ => None,
                    };
                    Ok(NodeTree { node, children })
                })
                .collect()
        }
        level(&**store, parent, depth.clamp(1, 4)).map_err(store_failed)
    }

    pub fn news_threads(&self, uid: Uid, query: ThreadQuery) -> Result<ThreadPage, NewsError> {
        let store = self.news_store()?;
        self.news_reader(uid)?;
        if query.limit == 0 {
            return Err(NewsError::BadRequest("A page needs a limit of at least 1."));
        }
        store.threads(&query).map_err(store_failed)
    }

    pub fn news_thread(
        &self,
        uid: Uid,
        root: ArticleId,
        after: Option<ArticleId>,
        snapshot: Option<ArticleId>,
        limit: usize,
    ) -> Result<ArticlePage, NewsError> {
        let store = self.news_store()?;
        self.news_reader(uid)?;
        if limit == 0 {
            return Err(NewsError::BadRequest("A page needs a limit of at least 1."));
        }
        store
            .thread(root, after, snapshot, limit)
            .map_err(store_failed)
    }

    pub fn news_article(&self, uid: Uid, id: ArticleId) -> Result<Article, NewsError> {
        let store = self.news_store()?;
        self.news_reader(uid)?;
        store
            .article(id)
            .map_err(|e| store_failed(e.into()))?
            .ok_or(NewsError::NoSuchArticle)
    }

    /// The articles pointing at `id` — backlinks, which the edge table's
    /// second index makes free (§5.3).
    pub fn news_refs(
        &self,
        uid: Uid,
        id: ArticleId,
        limit: usize,
    ) -> Result<Vec<Reference>, NewsError> {
        let store = self.news_store()?;
        self.news_reader(uid)?;
        store
            .article(id)
            .map_err(|e| store_failed(e.into()))?
            .ok_or(NewsError::NoSuchArticle)?;
        store.refs_to(id, limit).map_err(|e| store_failed(e.into()))
    }

    /// Post an article or a reply, and tell every reader their view of
    /// that category is stale.
    pub fn news_post(&self, uid: Uid, req: PostRequest) -> Result<ArticleId, NewsError> {
        let store = self.news_store()?;
        let asker = self.news_reader(uid)?;
        if !asker.access.has(bit::POST_NEWS) {
            return Err(NewsError::AccessDenied);
        }
        // `markdown = "off"` is the only mode this build has: the parser
        // and the plain-text downgrade are the markdown stage's (§5).
        if req.mime != BodyType::Plain {
            return Err(NewsError::BadBodyType);
        }
        let policy = self.news_policy;
        let subject = clean_subject(&req.subject);
        if subject.is_empty() {
            return Err(NewsError::BadRequest("An article needs a subject."));
        }
        if subject.len() > policy.max_subject {
            return Err(NewsError::BadRequest("That subject is too long."));
        }
        // Refused rather than cut: a body the legacy wire cannot carry is
        // one a 1.5 client silently truncates, and saying so up front is
        // better than a lossy conversion at the edge (§12.4).
        let body = normalize_newlines(&req.body);
        if body.len() > policy.max_body {
            return Err(NewsError::BadRequest("That article is too long."));
        }
        let post = NewPost {
            category: req.category,
            parent: req.parent,
            refs: scan_refs(&body),
            author: asker.author,
            subject,
            body,
            mime: req.mime,
            at: SystemTime::now(),
        };
        let posted = store
            .post(&post, policy.max_depth, policy.max_refs)
            .map_err(store_failed)?;
        self.news_fan_out(Event::NewsPosted {
            id: posted.id,
            category: post.category,
            root: posted.root,
            parent: post.parent,
            subject: post.subject,
            from_nick: post.author.nick,
            at: post.at,
        });
        Ok(posted.id)
    }

    /// Delete an article: its author's own (unless `self_delete` is off),
    /// or anyone's with `delete_articles`. What is left is a tombstone.
    ///
    /// Not yet here: §8's moderation ladder, which spares an author
    /// holding `cant_be_disconnected` from anyone without `delete_users`.
    /// It asks about the author's privileges, which an article does not
    /// record, and it lands with the rest of moderation in W8.
    pub fn news_delete(&self, uid: Uid, id: ArticleId) -> Result<(), NewsError> {
        let store = self.news_store()?;
        let asker = self.news_reader(uid)?;
        let article = store
            .article(id)
            .map_err(|e| store_failed(e.into()))?
            .filter(|a| !a.deleted)
            .ok_or(NewsError::NoSuchArticle)?;
        let own = self.news_policy.self_delete
            && asker.owner.as_ref().is_some_and(|m| article.author.is(m));
        if !own && !asker.access.has(bit::DELETE_ARTICLES) {
            return Err(NewsError::AccessDenied);
        }
        // `None` here is a delete that lost a race with another: the
        // article is a tombstone either way, and the other one announced
        // it.
        store
            .tombstone(id, &asker.login, SystemTime::now())
            .map_err(|e| store_failed(e.into()))?
            .ok_or(NewsError::NoSuchArticle)?;
        self.news_fan_out(Event::NewsDeleted {
            id,
            category: article.category,
        });
        Ok(())
    }

    pub fn news_node_create(
        &self,
        uid: Uid,
        parent: Option<NodeId>,
        kind: NodeKind,
        name: &str,
    ) -> Result<Node, NewsError> {
        let store = self.news_store()?;
        let asker = self.news_reader(uid)?;
        if !asker.access.has(create_bit(kind)) {
            return Err(NewsError::AccessDenied);
        }
        let mut guid = [0u8; 16];
        getrandom::getrandom(&mut guid)
            .map_err(|e| NewsError::Store(StoreError::new(format!("no randomness: {e}"))))?;
        let node = store
            .create_node(
                &NewNode {
                    parent,
                    kind,
                    name: clean_name(name)?,
                    guid,
                    at: SystemTime::now(),
                },
                self.news_policy.max_node_depth,
            )
            .map_err(store_failed)?;
        self.news_fan_out(Event::NewsNode(node.clone()));
        Ok(node)
    }

    /// Rename a node. Naming one is part of making one, so it takes the
    /// bit that creates that kind.
    pub fn news_node_rename(&self, uid: Uid, id: NodeId, name: &str) -> Result<Node, NewsError> {
        let store = self.news_store()?;
        let asker = self.news_reader(uid)?;
        let node = store
            .node(id)
            .map_err(|e| store_failed(e.into()))?
            .ok_or(NewsError::NoSuchNode)?;
        if !asker.access.has(create_bit(node.kind)) {
            return Err(NewsError::AccessDenied);
        }
        let node = store
            .rename_node(id, &clean_name(name)?)
            .map_err(store_failed)?;
        self.news_fan_out(Event::NewsNode(node.clone()));
        Ok(node)
    }

    /// Delete a node, answering how many articles went with it.
    pub fn news_node_delete(&self, uid: Uid, id: NodeId) -> Result<u64, NewsError> {
        let store = self.news_store()?;
        let asker = self.news_reader(uid)?;
        let node = store
            .node(id)
            .map_err(|e| store_failed(e.into()))?
            .ok_or(NewsError::NoSuchNode)?;
        let needed = match node.kind {
            NodeKind::Bundle => bit::DELETE_NEWS_BUNDLES,
            NodeKind::Category => bit::DELETE_CATEGORIES,
        };
        if !asker.access.has(needed) {
            return Err(NewsError::AccessDenied);
        }
        let gone = store.delete_node(id).map_err(store_failed)?;
        self.news_fan_out(Event::NewsNodeDeleted { id });
        Ok(gone)
    }

    /// Retention, off the request path like chat history's. Nothing is
    /// announced: a thread old enough to prune is not on anyone's screen
    /// in a way a refetch would not settle.
    pub fn prune_news(&self) -> u64 {
        let (Some(store), days) = (self.news.as_ref(), self.news_policy.retain_days) else {
            return 0;
        };
        if days == 0 {
            return 0;
        }
        let age = Duration::from_secs(u64::from(days) * 24 * 3600);
        store.prune(age, SystemTime::now()).unwrap_or_else(|e| {
            warn!("news retention: {e}");
            0
        })
    }
}

fn create_bit(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Bundle => bit::CREATE_NEWS_BUNDLES,
        NodeKind::Category => bit::CREATE_CATEGORIES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{drain, test_attach, AttachInfo, Transport};

    fn reader() -> AccessBits {
        AccessBits::empty().with(bit::READ_NEWS)
    }

    fn poster() -> AccessBits {
        reader().with(bit::POST_NEWS)
    }

    fn editor() -> AccessBits {
        poster()
            .with(bit::CREATE_CATEGORIES)
            .with(bit::CREATE_NEWS_BUNDLES)
            .with(bit::DELETE_CATEGORIES)
            .with(bit::DELETE_NEWS_BUNDLES)
    }

    fn news_core() -> Core {
        Core::new().with_news(Arc::new(MemoryNews::default()), NewsPolicy::default())
    }

    /// A session with an account behind it, the way a real login gives
    /// one: `is_person` is what makes it somebody.
    fn member(core: &Core, login: &str, access: AccessBits) -> Uid {
        attach_as(core, login, access, true, true)
    }

    fn attach_as(
        core: &Core,
        login: &str,
        access: AccessBits,
        has_inbox: bool,
        is_person: bool,
    ) -> Uid {
        let (uid, _rx) = core
            .attach(AttachInfo {
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access,
                login: login.to_string(),
                addr: None,
                can_detach: false,
                transport: Transport::default(),
                has_inbox,
                is_person,
                reads_on_delivery: false,
                identity: None,
            })
            .unwrap();
        core.announce(uid);
        uid
    }

    fn post(
        core: &Core,
        uid: Uid,
        category: NodeId,
        parent: Option<ArticleId>,
        body: &str,
    ) -> Result<ArticleId, NewsError> {
        core.news_post(
            uid,
            PostRequest {
                category,
                parent,
                subject: "subject".into(),
                body: body.into(),
                mime: BodyType::Plain,
            },
        )
    }

    #[test]
    fn the_shorthand_is_found_where_a_person_would_write_it() {
        assert_eq!(scan_refs("see #51"), [51]);
        assert_eq!(scan_refs("#51 at the start"), [51]);
        assert_eq!(scan_refs("(#51), and #47."), [51, 47]);
        assert_eq!(scan_refs("#51 then #51 again"), [51], "deduplicated");
        assert_eq!(scan_refs("line one\n#9\nline three"), [9]);
        // Unicode punctuation and whitespace bound it too: what a Mac
        // client's smart quotes and em dashes arrive as.
        assert_eq!(scan_refs("see #51—later"), [51]);
        assert_eq!(scan_refs("“#51” and (#47)…"), [51, 47]);
        assert_eq!(scan_refs("—#8\u{3000}#9"), [8, 9]);
    }

    #[test]
    fn the_shorthand_is_not_found_where_it_means_something_else() {
        for text in [
            "# 51 is a heading",
            "&#51; is a character reference",
            "##51",
            "issue#51",
            "#51st street",
            "#51_x",
            "#0",
            "#",
            "#99999999999",
            "#51é",
            "café#51",
            "#51٣",
        ] {
            assert!(
                scan_refs(text).is_empty(),
                "{text:?} gave {:?}",
                scan_refs(text)
            );
        }
    }

    #[test]
    fn a_scan_offers_a_bounded_number_of_candidates() {
        let body: String = (1..2000).map(|n| format!("#{n} ")).collect();
        assert_eq!(scan_refs(&body).len(), MAX_REF_CANDIDATES);
    }

    #[test]
    fn a_server_without_news_says_so_before_anything_else() {
        let core = Core::new();
        let (uid, _rx) = test_attach(&core, "alice", editor());
        assert_eq!(core.news_tree(uid, None, 1), Err(NewsError::Disabled));
        assert_eq!(post(&core, uid, 1, None, "hello"), Err(NewsError::Disabled));
        assert!(!core.news_enabled());
    }

    #[test]
    fn every_privilege_is_on_top_of_reading() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        // Posting without the read bit: whatever else it holds, a session
        // that cannot read the news cannot act on it.
        let blind = member(
            &core,
            "blind",
            AccessBits::empty()
                .with(bit::POST_NEWS)
                .with(bit::CREATE_CATEGORIES),
        );
        assert_eq!(
            post(&core, blind, cat.id, None, "x"),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(
            core.news_node_create(blind, None, NodeKind::Category, "Mine"),
            Err(NewsError::AccessDenied)
        );

        let lurker = member(&core, "lurker", reader());
        assert!(core.news_tree(lurker, None, 1).is_ok());
        assert_eq!(
            post(&core, lurker, cat.id, None, "x"),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(
            core.news_node_create(lurker, None, NodeKind::Bundle, "B"),
            Err(NewsError::AccessDenied)
        );
        assert!(!core.news_may_post(lurker));
        assert!(core.news_may_post(admin));
    }

    #[test]
    fn creating_and_deleting_each_kind_takes_that_kinds_bit() {
        let core = news_core();
        let cats = member(
            &core,
            "cats",
            reader()
                .with(bit::CREATE_CATEGORIES)
                .with(bit::DELETE_CATEGORIES),
        );
        let bundles = member(
            &core,
            "bundles",
            reader()
                .with(bit::CREATE_NEWS_BUNDLES)
                .with(bit::DELETE_NEWS_BUNDLES),
        );
        let c = core
            .news_node_create(cats, None, NodeKind::Category, "C")
            .unwrap();
        let b = core
            .news_node_create(bundles, None, NodeKind::Bundle, "B")
            .unwrap();
        assert_eq!(
            core.news_node_create(cats, None, NodeKind::Bundle, "no"),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(
            core.news_node_rename(bundles, c.id, "renamed"),
            Err(NewsError::AccessDenied),
            "renaming is part of making, so it takes the create bit"
        );
        assert_eq!(
            core.news_node_delete(cats, b.id),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(core.news_node_delete(bundles, b.id), Ok(0));
        assert_eq!(core.news_node_delete(cats, c.id), Ok(0));
    }

    #[test]
    fn a_post_is_announced_to_every_reader_and_nobody_else() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let (_r, mut reader_rx) = test_attach(&core, "reader", reader());
        let (_n, mut outsider_rx) = test_attach(&core, "outsider", AccessBits::empty());
        drain(&mut reader_rx);
        drain(&mut outsider_rx);

        let id = post(&core, admin, cat.id, None, "hello").unwrap();
        let seen = drain(&mut reader_rx);
        assert!(
            matches!(
                seen.as_slice(),
                [Event::NewsPosted { id: got, category, root, parent: None, .. }]
                    if *got == id && *category == cat.id && *root == id
            ),
            "{seen:?}"
        );
        assert!(
            drain(&mut outsider_rx).is_empty(),
            "a session that may not read news is not told it changed"
        );
    }

    #[test]
    fn an_author_may_delete_their_own_and_only_their_own() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let alice = member(&core, "alice", poster());
        let bob = member(&core, "bob", poster());
        let mine = post(&core, alice, cat.id, None, "alice's").unwrap();
        let theirs = post(&core, bob, cat.id, None, "bob's").unwrap();

        assert_eq!(
            core.news_delete(alice, theirs),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(core.news_delete(alice, mine), Ok(()));
        assert_eq!(
            core.news_delete(alice, mine),
            Err(NewsError::NoSuchArticle),
            "a tombstone has nothing left to delete"
        );
        assert!(core.news_article(alice, mine).unwrap().deleted);

        let moderator = member(&core, "mod", reader().with(bit::DELETE_ARTICLES));
        assert_eq!(core.news_delete(moderator, theirs), Ok(()));
    }

    #[test]
    fn a_guest_owns_nothing_it_posts() {
        // Everyone who walks through `guest` shares one login, so an
        // article one guest posts is not the next guest's to delete.
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let (guest, _rx) = test_attach(&core, "guest", poster());
        let id = post(&core, guest, cat.id, None, "drive-by").unwrap();
        let article = core.news_article(guest, id).unwrap();
        assert_eq!(article.author.login, None);
        assert_eq!(article.author.nick, "guest");
        let (next_guest, _rx) = test_attach(&core, "guest", poster());
        assert_eq!(
            core.news_delete(next_guest, id),
            Err(NewsError::AccessDenied)
        );
        assert_eq!(core.news_delete(guest, id), Err(NewsError::AccessDenied));
    }

    #[test]
    fn authorship_is_the_accounts_not_its_mailboxs() {
        // `[extra] inbox` is mail policy. Turning it off does not make an
        // account's articles nobody's, and turning it on for `guest` does
        // not make a guest's articles every guest's.
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();

        let staff = attach_as(&core, "staff", poster(), false, true);
        let mine = post(&core, staff, cat.id, None, "mine").unwrap();
        let article = core.news_article(staff, mine).unwrap();
        assert_eq!(article.author.login.as_deref(), Some("staff"));
        assert_eq!(core.news_delete(staff, mine), Ok(()));

        let guest = attach_as(&core, "guest", poster(), true, false);
        let id = post(&core, guest, cat.id, None, "drive-by").unwrap();
        assert_eq!(core.news_article(guest, id).unwrap().author.login, None);
        let next_guest = attach_as(&core, "guest", poster(), true, false);
        assert_eq!(
            core.news_delete(next_guest, id),
            Err(NewsError::AccessDenied)
        );
    }

    #[test]
    fn self_delete_off_is_the_period_behavior() {
        let core = Core::new().with_news(
            Arc::new(MemoryNews::default()),
            NewsPolicy {
                self_delete: false,
                ..NewsPolicy::default()
            },
        );
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let alice = member(&core, "alice", poster());
        let mine = post(&core, alice, cat.id, None, "mine").unwrap();
        assert_eq!(core.news_delete(alice, mine), Err(NewsError::AccessDenied));
    }

    #[test]
    fn a_post_is_checked_before_the_store_sees_it() {
        let core = Core::new().with_news(
            Arc::new(MemoryNews::default()),
            NewsPolicy {
                max_body: 10,
                max_subject: 5,
                ..NewsPolicy::default()
            },
        );
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let ask = |subject: &str, body: &str, mime| {
            core.news_post(
                admin,
                PostRequest {
                    category: cat.id,
                    parent: None,
                    subject: subject.into(),
                    body: body.into(),
                    mime,
                },
            )
        };
        assert!(matches!(
            ask("  \r\n ", "x", BodyType::Plain),
            Err(NewsError::BadRequest(_))
        ));
        assert!(matches!(
            ask("toolong", "x", BodyType::Plain),
            Err(NewsError::BadRequest(_))
        ));
        assert!(matches!(
            ask("ok", "this is too long", BodyType::Plain),
            Err(NewsError::BadRequest(_))
        ));
        assert_eq!(
            ask("ok", "x", BodyType::Markdown),
            Err(NewsError::BadBodyType)
        );
        // CRLF counts as one byte once it is LF, and a subject's stray
        // newline becomes a space and is trimmed away.
        let id = ask("ok\n", "a\r\nb\rc", BodyType::Plain).unwrap();
        let article = core.news_article(admin, id).unwrap();
        assert_eq!(article.subject, "ok");
        assert_eq!(article.body, "a\nb\nc");
    }

    #[test]
    fn references_in_a_body_resolve_against_what_exists() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let cat = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        let first = post(&core, admin, cat.id, None, "the first").unwrap();
        let second = post(
            &core,
            admin,
            cat.id,
            None,
            &format!("see #{first}, and #4000 which is nothing"),
        )
        .unwrap();
        let article = core.news_article(admin, second).unwrap();
        assert_eq!(
            article.refs.iter().map(|r| r.id).collect::<Vec<_>>(),
            [first]
        );
        assert_eq!(core.news_article(admin, first).unwrap().referenced_by, 1);
        let back = core.news_refs(admin, first, 10).unwrap();
        assert_eq!(back.iter().map(|r| r.id).collect::<Vec<_>>(), [second]);
        assert_eq!(
            core.news_refs(admin, 4000, 10),
            Err(NewsError::NoSuchArticle)
        );
    }

    #[test]
    fn the_tree_comes_back_as_deep_as_it_was_asked_for() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let top = core
            .news_node_create(admin, None, NodeKind::Bundle, "Projects")
            .unwrap();
        let mid = core
            .news_node_create(admin, Some(top.id), NodeKind::Bundle, "Servers")
            .unwrap();
        core.news_node_create(admin, Some(mid.id), NodeKind::Category, "hxd-ng")
            .unwrap();
        core.news_node_create(admin, None, NodeKind::Category, "Announcements")
            .unwrap();

        let shallow = core.news_tree(admin, None, 1).unwrap();
        assert_eq!(shallow.len(), 2);
        assert!(shallow.iter().all(|t| t.children.is_none()));

        let deep = core.news_tree(admin, None, 3).unwrap();
        let projects = deep.iter().find(|t| t.node.name == "Projects").unwrap();
        let servers = &projects.children.as_ref().unwrap()[0];
        assert_eq!(servers.node.name, "Servers");
        assert_eq!(servers.children.as_ref().unwrap()[0].node.name, "hxd-ng");
        let announcements = deep
            .iter()
            .find(|t| t.node.name == "Announcements")
            .unwrap();
        assert!(
            announcements.children.is_none(),
            "a category holds no nodes"
        );

        assert_eq!(
            core.news_tree(admin, Some(9999), 1),
            Err(NewsError::NoSuchNode)
        );
    }

    #[test]
    fn a_node_event_reaches_readers_on_create_rename_and_delete() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let (_r, mut rx) = test_attach(&core, "reader", reader());
        drain(&mut rx);
        let node = core
            .news_node_create(admin, None, NodeKind::Category, "General")
            .unwrap();
        core.news_node_rename(admin, node.id, "Chatter").unwrap();
        core.news_node_delete(admin, node.id).unwrap();
        let seen = drain(&mut rx);
        assert!(
            matches!(
                seen.as_slice(),
                [
                    Event::NewsNode(a),
                    Event::NewsNode(b),
                    Event::NewsNodeDeleted { id }
                ] if a.name == "General" && b.name == "Chatter" && *id == node.id
            ),
            "{seen:?}"
        );
    }

    #[test]
    fn a_name_is_one_trimmed_line() {
        let core = news_core();
        let admin = member(&core, "admin", editor());
        let node = core
            .news_node_create(admin, None, NodeKind::Category, "  General  ")
            .unwrap();
        assert_eq!(node.name, "General");
        for bad in ["", "   ", "two\nlines", &"x".repeat(MAX_NODE_NAME + 1)] {
            assert!(
                matches!(
                    core.news_node_create(admin, None, NodeKind::Category, bad),
                    Err(NewsError::BadRequest(_))
                ),
                "{bad:?}"
            );
        }
    }
}
