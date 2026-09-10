//! An in-memory [`NewsStore`]: the domain's unit tests, and a server that
//! wants news within one run of the process and nothing more.
//!
//! Public rather than `#[cfg(test)]` for the reason
//! [`crate::inbox::MemoryStore`] is. Where the SQLite store says a rule
//! in SQL this says it in Rust, and [`super::conformance`] holds the two
//! to the same answers.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use super::{
    Article, ArticleId, ArticlePage, Author, BodyType, NewNode, NewPost, NewsError, NewsStore,
    Node, NodeId, NodeKind, Posted, Reference, ThreadHead, ThreadPage, ThreadQuery,
};
use crate::inbox::StoreError;

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
            created_at: n.at,
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
            at: p.at,
            deleted: false,
        });
        let cat = inner.node_mut(p.category).expect("checked above");
        cat.add_sn = cat.add_sn.wrapping_add(1);
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
        let from: Vec<u8> = match after {
            None => Vec::new(),
            Some(id) => inner
                .row(id)
                .filter(|a| a.root == root)
                .ok_or(NewsError::NoSuchArticle)?
                .path
                .clone(),
        };
        let mut rows: Vec<&ArticleRow> = inner
            .articles
            .iter()
            .filter(|a| a.root == root && (after.is_none() || a.path > from))
            .collect();
        rows.sort_by(|a, b| a.path.cmp(&b.path));
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        Ok(ArticlePage {
            articles: rows.into_iter().map(|a| inner.view(a)).collect(),
            has_more,
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
        let cutoff = now.checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH);
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
        let mut touched: Vec<NodeId> = stale.into_iter().map(|(_, c)| c).collect();
        touched.dedup();
        for c in touched {
            if let Some(cat) = inner.node_mut(c) {
                cat.delete_sn = cat.delete_sn.wrapping_add(1);
            }
        }
        Ok(gone.len() as u64)
    }
}
