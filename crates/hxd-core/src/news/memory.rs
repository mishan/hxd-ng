//! An in-memory [`NewsStore`]: the domain's unit tests, and a server that
//! wants news within one run of the process and nothing more.
//!
//! Public rather than `#[cfg(test)]` for the reason
//! [`crate::inbox::MemoryStore`] is. Where the SQLite store says a rule
//! in SQL this says it in Rust, and [`super::conformance`] holds the two
//! to the same answers.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::query::{words, Field, Term};
use super::{
    Article, ArticleId, ArticlePage, Author, BodyType, Hit, NewNode, NewPost, NewsError, NewsStore,
    Node, NodeId, NodeKind, Posted, Reference, SearchPage, SearchQuery, SubScope, Subscriber,
    Subscription, ThreadHead, ThreadPage, ThreadQuery,
};
use crate::inbox::{Mailbox, StoreError};

/// How much of a body a memory store's snippet shows.
const SNIPPET_CHARS: usize = 160;

/// Where `words` occurs in `col` as a phrase, the last word as a prefix
/// when `prefix` says so.
fn phrase_in(col: &[String], words: &[String], prefix: bool) -> bool {
    if words.is_empty() || words.len() > col.len() {
        return false;
    }
    (0..=col.len() - words.len()).any(|start| {
        words.iter().enumerate().all(|(k, w)| {
            let here = &col[start + k];
            if prefix && k == words.len() - 1 {
                here.starts_with(w.as_str())
            } else {
                here == w
            }
        })
    })
}

/// A naive scan in place of an index: subject, body and author as words,
/// and a term matched against the ones its field names.
struct Searchable {
    subject: Vec<String>,
    body: Vec<String>,
    author: Vec<String>,
}

impl Searchable {
    fn of(a: &ArticleRow) -> Self {
        Searchable {
            subject: words(&a.subject),
            body: words(&a.body),
            author: words(&format!(
                "{} {}",
                a.author.nick,
                a.author.login.as_deref().unwrap_or("")
            )),
        }
    }

    fn has(&self, t: &Term) -> bool {
        let found = |col: &[String]| phrase_in(col, &t.words, t.prefix);
        match t.field {
            Field::Any => found(&self.subject) || found(&self.body) || found(&self.author),
            Field::Subject => found(&self.subject),
            Field::Author => found(&self.author),
        }
    }
}

/// The start of a body, with the words that matched marked. No ranking
/// and no windowing: enough for a store that exists for tests, and the
/// conformance suite asserts nothing about snippets.
fn snippet(body: &str, terms: &[Term]) -> (String, Vec<(u32, u32)>) {
    let text: String = body.chars().take(SNIPPET_CHARS).collect();
    let wanted: Vec<&Term> = terms
        .iter()
        .filter(|t| !t.negated && t.field == Field::Any)
        .collect();
    let mut marks = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices().chain([(text.len(), ' ')]) {
        match (c.is_alphanumeric(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                let word = text[s..i].to_lowercase();
                let hit = wanted.iter().any(|t| {
                    t.words.iter().enumerate().any(|(k, w)| {
                        word == *w
                            || (t.prefix && k == t.words.len() - 1 && word.starts_with(w.as_str()))
                    })
                });
                if hit {
                    marks.push((s as u32, i as u32));
                }
                start = None;
            }
            _ => {}
        }
    }
    (text, marks)
}

#[derive(Debug, Clone)]
struct NodeRow {
    id: NodeId,
    parent: Option<NodeId>,
    kind: NodeKind,
    name: String,
    guid: [u8; 16],
    add_sn: u32,
    delete_sn: u32,
    created_at: SystemTime,
}

#[derive(Debug, Clone)]
struct ArticleRow {
    id: ArticleId,
    category: NodeId,
    parent: Option<ArticleId>,
    root: ArticleId,
    /// Big-endian ids, root first: the same bytes the SQLite store
    /// orders by, so the two cannot disagree about preorder.
    path: Vec<u8>,
    depth: u16,
    author: Author,
    subject: String,
    body: String,
    mime: BodyType,
    at: SystemTime,
    deleted: bool,
}

#[derive(Debug, Clone)]
struct SubRow {
    /// Insertion order, which is what "newest first" sorts by.
    id: u64,
    owner: Mailbox,
    scope: SubScope,
    auto: bool,
    muted: bool,
    last_seen: ArticleId,
    at: SystemTime,
}

/// Does the row owned by `row` belong to `who`? The mailbox rule, which
/// is the only way a subscription is ever found.
fn owns(who: &Mailbox, row: &Mailbox) -> bool {
    who.matches(&row.login, row.fingerprint.as_ref())
}

#[derive(Default)]
struct Inner {
    last_node: NodeId,
    /// Wider than an id so running out is a check rather than a wrap.
    last_article: u64,
    nodes: Vec<NodeRow>,
    /// In id order, which is insertion order.
    articles: Vec<ArticleRow>,
    /// `(src, dst)` in order of appearance within each `src`.
    refs: Vec<(ArticleId, ArticleId)>,
    last_sub: u64,
    subs: Vec<SubRow>,
}

/// A [`NewsStore`] in a few `Vec`s.
#[derive(Default)]
pub struct MemoryNews {
    inner: Mutex<Inner>,
}

impl MemoryNews {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Inner {
    fn node(&self, id: NodeId) -> Option<&NodeRow> {
        self.nodes.iter().find(|n| n.id == id)
    }

    fn node_mut(&mut self, id: NodeId) -> Option<&mut NodeRow> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    fn row(&self, id: ArticleId) -> Option<&ArticleRow> {
        self.articles.iter().find(|a| a.id == id)
    }

    fn view_node(&self, n: &NodeRow) -> Node {
        let children = match n.kind {
            NodeKind::Bundle => self.nodes.iter().filter(|c| c.parent == Some(n.id)).count(),
            NodeKind::Category => self
                .articles
                .iter()
                .filter(|a| a.category == n.id && !a.deleted)
                .count(),
        };
        Node {
            id: n.id,
            parent: n.parent,
            kind: n.kind,
            name: n.name.clone(),
            guid: n.guid,
            add_sn: n.add_sn,
            delete_sn: n.delete_sn,
            children: children as u32,
            created_at: n.created_at,
        }
    }

    fn reference(&self, a: &ArticleRow) -> Reference {
        Reference {
            id: a.id,
            subject: a.subject.clone(),
            author_nick: a.author.nick.clone(),
            at: a.at,
            deleted: a.deleted,
        }
    }

    fn view(&self, a: &ArticleRow) -> Article {
        let refs = self
            .refs
            .iter()
            .filter(|(src, _)| *src == a.id)
            .filter_map(|(_, dst)| self.row(*dst))
            .map(|t| self.reference(t))
            .collect();
        let referenced_by = self.refs.iter().filter(|(_, dst)| *dst == a.id).count() as u32;
        Article {
            id: a.id,
            category: a.category,
            parent: a.parent,
            root: a.root,
            depth: a.depth,
            author: a.author.clone(),
            subject: a.subject.clone(),
            body: a.body.clone(),
            mime: a.mime,
            at: a.at,
            deleted: a.deleted,
            refs,
            referenced_by,
        }
    }

    fn head(&self, root: &ArticleRow) -> ThreadHead {
        let thread = self.articles.iter().filter(|a| a.root == root.id);
        let (mut count, mut last_at, mut last_id) = (0u32, root.at, root.id);
        for a in thread {
            count += 1;
            last_at = last_at.max(a.at);
            last_id = last_id.max(a.id);
        }
        ThreadHead {
            article: self.view(root),
            replies: count - 1,
            last_at,
            last_id,
        }
    }

    /// How many levels down from the root a node sits; a root-level node
    /// is at 1.
    fn level(&self, mut id: NodeId) -> u16 {
        let mut level = 0;
        while let Some(n) = self.node(id) {
            level += 1;
            match n.parent {
                Some(p) => id = p,
                None => break,
            }
        }
        level
    }

    fn name_taken(&self, parent: Option<NodeId>, name: &str, except: Option<NodeId>) -> bool {
        self.nodes
            .iter()
            .any(|n| n.parent == parent && n.name == name && Some(n.id) != except)
    }

    /// Remove articles outright, and every reference either side of
    /// them.
    fn remove_articles(&mut self, gone: &[ArticleId]) {
        self.articles.retain(|a| !gone.contains(&a.id));
        self.refs
            .retain(|(src, dst)| !gone.contains(src) && !gone.contains(dst));
    }

    /// The articles a scope is about: every one in a thread, the starters
    /// in a category.
    fn in_scope(&self, scope: SubScope) -> impl Iterator<Item = &ArticleRow> {
        self.articles.iter().filter(move |a| match scope {
            SubScope::Thread(root) => a.root == root,
            SubScope::Category(c) => a.category == c && a.parent.is_none(),
        })
    }

    fn newest(&self, scope: SubScope) -> ArticleId {
        self.in_scope(scope).map(|a| a.id).max().unwrap_or(0)
    }

    /// Live articles in `scope` past `last_seen` that `owner` did not
    /// write.
    fn unread(&self, owner: &Mailbox, scope: SubScope, last_seen: ArticleId) -> usize {
        self.unread_before(owner, scope, last_seen, ArticleId::MAX)
    }

    /// The same, counting only articles older than `before`.
    fn unread_before(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        last_seen: ArticleId,
        before: ArticleId,
    ) -> usize {
        self.in_scope(scope)
            .filter(|a| a.id > last_seen && a.id < before)
            .filter(|a| !a.deleted && !a.author.is(owner))
            .count()
    }

    /// Is there something at `scope` to subscribe to?
    fn check_target(&self, scope: SubScope) -> Result<(), NewsError> {
        match scope {
            SubScope::Thread(root) => self
                .row(root)
                .filter(|a| a.parent.is_none())
                .map(|_| ())
                .ok_or(NewsError::NoSuchArticle),
            SubScope::Category(c) => match self.node(c) {
                None => Err(NewsError::NoSuchNode),
                Some(n) if n.kind != NodeKind::Category => Err(NewsError::NotACategory),
                Some(_) => Ok(()),
            },
        }
    }

    fn sub_mut(&mut self, owner: &Mailbox, scope: SubScope) -> Option<&mut SubRow> {
        self.subs
            .iter_mut()
            .find(|r| r.scope == scope && owns(owner, &r.owner))
    }

    /// A new row, caught up, or `TooManySubs`. Answers its cursor.
    fn add_sub(
        &mut self,
        owner: &Mailbox,
        scope: SubScope,
        auto: bool,
        muted: bool,
        max_subs: usize,
        at: SystemTime,
    ) -> Result<ArticleId, NewsError> {
        self.check_target(scope)?;
        if self.subs.iter().filter(|r| owns(owner, &r.owner)).count() >= max_subs {
            return Err(NewsError::TooManySubs);
        }
        self.last_sub += 1;
        let last_seen = self.newest(scope);
        self.subs.push(SubRow {
            id: self.last_sub,
            owner: owner.clone(),
            scope,
            auto,
            muted,
            last_seen,
            at,
        });
        Ok(last_seen)
    }

    /// Rows whose thread or category has gone — with a category's
    /// deletion, or a thread's retention.
    fn drop_orphan_subs(&mut self) {
        let subs = std::mem::take(&mut self.subs);
        self.subs = subs
            .into_iter()
            .filter(|r| self.check_target(r.scope).is_ok())
            .collect();
    }
}

impl NewsStore for MemoryNews {
    fn nodes(&self, parent: Option<NodeId>) -> Result<Vec<Node>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<Node> = inner
            .nodes
            .iter()
            .filter(|n| n.parent == parent)
            .map(|n| inner.view_node(n))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn node(&self, id: NodeId) -> Result<Option<Node>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.node(id).map(|n| inner.view_node(n)))
    }

    fn create_node(&self, n: &NewNode, max_depth: u16) -> Result<Node, NewsError> {
        let mut inner = self.inner.lock().unwrap();
        let level = match n.parent {
            None => 1,
            Some(p) => {
                let parent = inner.node(p).ok_or(NewsError::NoSuchNode)?;
                if parent.kind != NodeKind::Bundle {
                    return Err(NewsError::NotACategory);
                }
                inner.level(p) + 1
            }
        };
        if level > max_depth {
            return Err(NewsError::TooDeep);
        }
        if inner.name_taken(n.parent, &n.name, None) {
            return Err(NewsError::NameTaken);
        }
        inner.last_node += 1;
        let row = NodeRow {
            id: inner.last_node,
            parent: n.parent,
            kind: n.kind,
            name: n.name.clone(),
            guid: n.guid,
            add_sn: 1,
            delete_sn: 1,
            created_at: whole_seconds(n.at),
        };
        let node = inner.view_node(&row);
        inner.nodes.push(row);
        Ok(node)
    }

    fn rename_node(&self, id: NodeId, name: &str) -> Result<Node, NewsError> {
        let mut inner = self.inner.lock().unwrap();
        let parent = inner.node(id).ok_or(NewsError::NoSuchNode)?.parent;
        if inner.name_taken(parent, name, Some(id)) {
            return Err(NewsError::NameTaken);
        }
        let row = inner.node_mut(id).expect("checked above");
        row.name = name.to_string();
        let row = row.clone();
        Ok(inner.view_node(&row))
    }

    fn delete_node(&self, id: NodeId) -> Result<u64, NewsError> {
        let mut inner = self.inner.lock().unwrap();
        let kind = inner.node(id).ok_or(NewsError::NoSuchNode)?.kind;
        let gone: Vec<ArticleId> = match kind {
            NodeKind::Bundle => {
                if inner.nodes.iter().any(|n| n.parent == Some(id)) {
                    return Err(NewsError::NotEmpty);
                }
                Vec::new()
            }
            NodeKind::Category => inner
                .articles
                .iter()
                .filter(|a| a.category == id)
                .map(|a| a.id)
                .collect(),
        };
        inner.remove_articles(&gone);
        inner.nodes.retain(|n| n.id != id);
        inner.drop_orphan_subs();
        Ok(gone.len() as u64)
    }

    fn post(&self, p: &NewPost, max_depth: u16, max_refs: usize) -> Result<Posted, NewsError> {
        let mut inner = self.inner.lock().unwrap();
        let category = inner.node(p.category).ok_or(NewsError::NoSuchNode)?;
        if category.kind != NodeKind::Category {
            return Err(NewsError::NotACategory);
        }
        let (parent_path, depth, root) = match p.parent {
            None => (Vec::new(), 0, None),
            Some(pid) => {
                let parent = inner.row(pid).ok_or(NewsError::NoSuchArticle)?;
                if parent.category != p.category {
                    return Err(NewsError::WrongCategory);
                }
                let depth = parent.depth + 1;
                if depth > max_depth {
                    return Err(NewsError::TooDeep);
                }
                (parent.path.clone(), depth, Some(parent.root))
            }
        };
        let next = inner.last_article + 1;
        let id = ArticleId::try_from(next)
            .map_err(|_| NewsError::Store(StoreError::new("article ids exhausted")))?;
        inner.last_article = next;
        let mut path = parent_path;
        path.extend_from_slice(&id.to_be_bytes());
        let root = root.unwrap_or(id);

        let mut kept: Vec<ArticleId> = Vec::new();
        for &dst in &p.refs {
            if kept.len() >= max_refs {
                break;
            }
            if !kept.contains(&dst) && inner.row(dst).is_some() {
                kept.push(dst);
            }
        }
        inner.refs.extend(kept.into_iter().map(|dst| (id, dst)));
        inner.articles.push(ArticleRow {
            id,
            category: p.category,
            parent: p.parent,
            root,
            path,
            depth,
            author: p.author.clone(),
            subject: p.subject.clone(),
            body: p.body.clone(),
            mime: p.mime,
            at: whole_seconds(p.at),
            deleted: false,
        });
        let cat = inner.node_mut(p.category).expect("checked above");
        cat.add_sn = cat.add_sn.wrapping_add(1);
        // Under the same lock as the article, so no later article is
        // given an id before the row exists. It starts at this one, the
        // thread's newest.
        if let Some(f) = &p.follow {
            let thread = SubScope::Thread(root);
            if inner.sub_mut(&f.owner, thread).is_none() {
                match inner.add_sub(&f.owner, thread, true, false, f.max_subs, p.at) {
                    Ok(_) | Err(NewsError::TooManySubs) => {}
                    Err(e) => panic!("following a thread just written: {e:?}"),
                }
            }
        }
        Ok(Posted { id, root })
    }

    fn article(&self, id: ArticleId) -> Result<Option<Article>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.row(id).map(|a| inner.view(a)))
    }

    fn threads(&self, q: &ThreadQuery) -> Result<ThreadPage, NewsError> {
        if q.limit == 0 {
            return Err(NewsError::BadRequest("A page needs a limit of at least 1."));
        }
        let inner = self.inner.lock().unwrap();
        let category = inner.node(q.category).ok_or(NewsError::NoSuchNode)?;
        if category.kind != NodeKind::Category {
            return Err(NewsError::NotACategory);
        }
        let mut roots: Vec<&ArticleRow> = inner
            .articles
            .iter()
            .filter(|a| a.category == q.category && a.parent.is_none())
            .filter(|a| q.before.is_none_or(|b| a.id < b))
            .filter(|a| q.after.is_none_or(|b| a.id > b))
            .filter(|r| inner.articles.iter().any(|a| a.root == r.id && !a.deleted))
            .collect();
        // Ascending when paging forward, so the page is the threads
        // nearest the cursor; descending otherwise.
        if q.after.is_some() {
            roots.sort_by_key(|a| a.id);
        } else {
            roots.sort_by_key(|a| std::cmp::Reverse(a.id));
        }
        let has_more = roots.len() > q.limit;
        roots.truncate(q.limit);
        if q.after.is_some() {
            roots.reverse();
        }
        Ok(ThreadPage {
            threads: roots.into_iter().map(|r| inner.head(r)).collect(),
            has_more,
        })
    }

    fn thread(
        &self,
        root: ArticleId,
        after: Option<ArticleId>,
        snapshot: Option<ArticleId>,
        limit: usize,
    ) -> Result<ArticlePage, NewsError> {
        if limit == 0 {
            return Err(NewsError::BadRequest("A page needs a limit of at least 1."));
        }
        let inner = self.inner.lock().unwrap();
        inner
            .row(root)
            .filter(|a| a.parent.is_none())
            .ok_or(NewsError::NoSuchArticle)?;
        let newest = inner
            .articles
            .iter()
            .filter(|a| a.root == root)
            .map(|a| a.id)
            .max()
            .expect("a thread contains its starter");
        let snapshot = snapshot.unwrap_or(newest);
        if snapshot < root {
            return Err(NewsError::BadRequest("The snapshot predates this thread."));
        }
        let from: Vec<u8> = match after {
            None => Vec::new(),
            Some(id) => {
                let path = inner
                    .row(id)
                    .filter(|a| a.root == root)
                    .ok_or(NewsError::NoSuchArticle)?
                    .path
                    .clone();
                if id > snapshot {
                    return Err(NewsError::BadRequest("The cursor is past this snapshot."));
                }
                path
            }
        };
        let mut rows: Vec<&ArticleRow> = inner
            .articles
            .iter()
            .filter(|a| a.root == root && a.id <= snapshot && (after.is_none() || a.path > from))
            .collect();
        rows.sort_by(|a, b| a.path.cmp(&b.path));
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        Ok(ArticlePage {
            articles: rows.into_iter().map(|a| inner.view(a)).collect(),
            has_more,
            snapshot,
        })
    }

    fn tombstone(
        &self,
        id: ArticleId,
        _by: &str,
        _at: SystemTime,
    ) -> Result<Option<Article>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(before) = inner.row(id).filter(|a| !a.deleted).map(|a| inner.view(a)) else {
            return Ok(None);
        };
        inner.refs.retain(|(src, _)| *src != id);
        let row = inner
            .articles
            .iter_mut()
            .find(|a| a.id == id)
            .expect("found above");
        row.deleted = true;
        row.subject.clear();
        row.body.clear();
        row.author = Author {
            nick: String::new(),
            login: None,
            fingerprint: None,
        };
        let category = row.category;
        let cat = inner
            .node_mut(category)
            .expect("an article's category exists");
        cat.delete_sn = cat.delete_sn.wrapping_add(1);
        Ok(Some(before))
    }

    fn refs_to(&self, id: ArticleId, limit: usize) -> Result<Vec<Reference>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut srcs: Vec<ArticleId> = inner
            .refs
            .iter()
            .filter(|(_, dst)| *dst == id)
            .map(|(src, _)| *src)
            .collect();
        srcs.sort_unstable_by(|a, b| b.cmp(a));
        Ok(srcs
            .into_iter()
            .take(limit)
            .filter_map(|src| inner.row(src))
            .map(|a| inner.reference(a))
            .collect())
    }

    fn prune(&self, max_age: Duration, now: SystemTime) -> Result<u64, StoreError> {
        let cutoff = whole_seconds(now.checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH));
        let mut inner = self.inner.lock().unwrap();
        let mut stale: Vec<(ArticleId, NodeId)> = Vec::new();
        for root in inner.articles.iter().filter(|a| a.parent.is_none()) {
            let newest = inner
                .articles
                .iter()
                .filter(|a| a.root == root.id)
                .map(|a| a.at)
                .max()
                .unwrap_or(root.at);
            if newest < cutoff {
                stale.push((root.id, root.category));
            }
        }
        let gone: Vec<ArticleId> = inner
            .articles
            .iter()
            .filter(|a| stale.iter().any(|(r, _)| *r == a.root))
            .map(|a| a.id)
            .collect();
        inner.remove_articles(&gone);
        inner.drop_orphan_subs();
        let mut touched: Vec<NodeId> = stale.into_iter().map(|(_, c)| c).collect();
        touched.sort_unstable();
        touched.dedup();
        for c in touched {
            if let Some(cat) = inner.node_mut(c) {
                cat.delete_sn = cat.delete_sn.wrapping_add(1);
            }
        }
        Ok(gone.len() as u64)
    }

    fn search(&self, q: &SearchQuery) -> Result<SearchPage, StoreError> {
        if q.terms.matches_nothing() {
            return Ok(SearchPage::default());
        }
        let inner = self.inner.lock().unwrap();
        let mut found: Vec<&ArticleRow> = inner
            .articles
            .iter()
            .filter(|a| !a.deleted)
            .filter(|a| {
                q.categories
                    .as_ref()
                    .is_none_or(|c| c.contains(&a.category))
            })
            .filter(|a| q.before.is_none_or(|t| a.at < t))
            .filter(|a| q.after.is_none_or(|t| a.at > t))
            .filter(|a| {
                let s = Searchable::of(a);
                q.terms.terms.iter().all(|t| s.has(t) != t.negated)
            })
            .collect();
        // No ranking here: both orders come back newest first, and the
        // conformance suite asserts relevance's result set, never its
        // order.
        found.sort_by_key(|a| std::cmp::Reverse(a.id));
        let total = found.len() as u32;
        let hits = found
            .into_iter()
            .skip(q.offset)
            .take(q.limit)
            .map(|a| {
                let (snippet, marks) = snippet(&a.body, &q.terms.terms);
                Hit {
                    article: a.id,
                    root: a.root,
                    category: a.category,
                    subject: a.subject.clone(),
                    author_nick: a.author.nick.clone(),
                    at: a.at,
                    snippet,
                    marks,
                }
            })
            .collect();
        Ok(SearchPage {
            hits,
            total,
            capped: false,
        })
    }

    /// There is no index to rebuild; the answer is what one would hold.
    fn reindex(&self) -> Result<u64, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.articles.iter().filter(|a| !a.deleted).count() as u64)
    }

    fn subscribe(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        max_subs: usize,
        at: SystemTime,
    ) -> Result<usize, NewsError> {
        let mut inner = self.inner.lock().unwrap();
        inner.check_target(scope)?;
        let last_seen = match inner.sub_mut(owner, scope) {
            Some(row) => {
                // Asking is explicit, and asking to hear about something
                // is not asking for it muted.
                row.auto = false;
                row.muted = false;
                row.last_seen
            }
            None => inner.add_sub(owner, scope, false, false, max_subs, at)?,
        };
        Ok(inner.unread(owner, scope, last_seen))
    }

    fn unsubscribe(&self, owner: &Mailbox, scope: SubScope) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.subs.len();
        inner
            .subs
            .retain(|r| !(r.scope == scope && owns(owner, &r.owner)));
        Ok(inner.subs.len() != before)
    }

    fn mute(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        muted: bool,
        max_subs: usize,
        at: SystemTime,
    ) -> Result<(), NewsError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.sub_mut(owner, scope) {
            Some(row) => {
                row.muted = muted;
                Ok(())
            }
            None if muted => inner
                .add_sub(owner, scope, false, true, max_subs, at)
                .map(|_| ()),
            None => Ok(()),
        }
    }

    fn subscriptions(&self, owner: &Mailbox) -> Result<Vec<Subscription>, StoreError> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<&SubRow> = inner
            .subs
            .iter()
            .filter(|r| owns(owner, &r.owner))
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.id));
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let (category, label) = match r.scope {
                    SubScope::Thread(root) => {
                        let a = inner.row(root)?;
                        (a.category, a.subject.clone())
                    }
                    SubScope::Category(c) => (c, inner.node(c)?.name.clone()),
                };
                Some(Subscription {
                    scope: r.scope,
                    category,
                    label,
                    auto: r.auto,
                    muted: r.muted,
                    last_seen: r.last_seen,
                    unread: inner.unread(owner, r.scope, r.last_seen),
                    at: r.at,
                })
            })
            .collect())
    }

    fn seen(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        up_to: ArticleId,
    ) -> Result<Option<usize>, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let newest = inner.newest(scope);
        let Some(row) = inner.sub_mut(owner, scope) else {
            return Ok(None);
        };
        row.last_seen = row.last_seen.max(up_to.min(newest));
        let last_seen = row.last_seen;
        Ok(Some(inner.unread(owner, scope, last_seen)))
    }

    fn subscribers(
        &self,
        root: ArticleId,
        category: Option<NodeId>,
        article: ArticleId,
    ) -> Result<Vec<Subscriber>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .subs
            .iter()
            .filter(|r| {
                r.scope == SubScope::Thread(root)
                    || category.is_some_and(|c| r.scope == SubScope::Category(c))
            })
            .map(|r| Subscriber {
                owner: r.owner.clone(),
                scope: r.scope,
                muted: r.muted,
                unread: inner.unread(&r.owner, r.scope, r.last_seen),
                earlier: inner.unread_before(&r.owner, r.scope, r.last_seen, article),
            })
            .collect())
    }

    fn unread_total(&self, owner: &Mailbox) -> Result<usize, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .subs
            .iter()
            .filter(|r| !r.muted && owns(owner, &r.owner))
            .map(|r| inner.unread(owner, r.scope, r.last_seen))
            .sum())
    }

    fn subs_claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let identified = Mailbox::identified(login, *fingerprint);
        let held: Vec<SubScope> = inner
            .subs
            .iter()
            .filter(|r| owns(&identified, &r.owner))
            .map(|r| r.scope)
            .collect();
        let mut moved = 0;
        inner.subs.retain_mut(|r| {
            if r.owner.fingerprint.is_some() || r.owner.login != login {
                return true;
            }
            moved += 1;
            if held.contains(&r.scope) {
                return false;
            }
            r.owner.fingerprint = Some(*fingerprint);
            true
        });
        Ok(moved)
    }

    fn subs_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let held: Vec<SubScope> = inner
            .subs
            .iter()
            .filter(|r| r.owner.fingerprint.as_ref() == Some(to))
            .map(|r| r.scope)
            .collect();
        let mut moved = 0;
        inner.subs.retain_mut(|r| {
            if r.owner.fingerprint.as_ref() != Some(from) {
                return true;
            }
            moved += 1;
            if held.contains(&r.scope) {
                return false;
            }
            r.owner.fingerprint = Some(*to);
            true
        });
        Ok(moved)
    }

    fn subs_purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.subs.len();
        inner.subs.retain(|r| !owns(of, &r.owner));
        Ok(before - inner.subs.len())
    }
}

/// A time as a store that keeps Unix seconds holds it. The SQLite store
/// does, so this one does too: an article posted at T.7 is at T in both,
/// and a window that ends at T answers the same about it in both.
pub(crate) fn whole_seconds(t: SystemTime) -> SystemTime {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}
