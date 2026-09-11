//! The news tree on SQLite (`docs/news.md` §4).
//!
//! Every write that has an invariant to keep takes an immediate
//! transaction and checks it inside, so the check and the write see the
//! same database — the containment rules, reply depth, sibling names and
//! reference resolution are all decided here and nowhere upstream.
//!
//! **A thread is a range of `path`.** Each article stores the big-endian
//! ids of its ancestors and itself, root first, so byte order is preorder
//! and every article under root `r` has a path in `[be(r), be(r + 1))`.
//! That range on `news_article_thread (category, path)` is how a thread
//! comes back in display order with no recursive query.

use std::time::{Duration, SystemTime};

use hxd_core::inbox::{Mailbox, StoreError};
use hxd_core::news::{
    Article, ArticleId, ArticlePage, Author, BodyType, NewNode, NewPost, NewsError, NewsStore,
    Node, NodeId, NodeKind, Posted, Reference, SubScope, Subscriber, Subscription, ThreadHead,
    ThreadPage, ThreadQuery,
};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};

use super::{bind, cutoff, fp_from_hex, fp_hex, from_unix, mailbox_sql, unix, SqliteStore};

const ARTICLE_COLUMNS: &str = "id, category, parent, root, depth, nick, login, login_fp, \
                               subject, body, mime, at, deleted_at IS NOT NULL";

const NODE_COLUMNS: &str = "n.id, n.parent, n.kind, n.name, n.guid, n.add_sn, n.delete_sn, \
     n.created_at, \
     CASE n.kind \
       WHEN 0 THEN (SELECT COUNT(*) FROM news_node c WHERE IFNULL(c.parent, 0) = n.id) \
       ELSE (SELECT COUNT(*) FROM news_article a \
              WHERE a.category = n.id AND a.deleted_at IS NULL) \
     END";

/// A serial is a u32 on the legacy wire and wraps there, so it wraps here.
const WRAP: i64 = 1 << 32;

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

fn article_id(n: i64) -> Result<ArticleId, StoreError> {
    ArticleId::try_from(n).map_err(|_| StoreError::new(format!("article id {n} is not a u32")))
}

fn node_id(n: i64) -> Result<NodeId, StoreError> {
    NodeId::try_from(n).map_err(|_| StoreError::new(format!("node id {n} is not an id")))
}

fn serial(n: i64) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| StoreError::new(format!("serial {n} is not a u32")))
}

/// The raw columns of one `news_article` row, before anything about them
/// has been believed. Everything here is written by this file alone, so a
/// value that does not convert means a hand edit or damage, and the row
/// is refused rather than guessed at.
struct RawArticle {
    id: i64,
    category: i64,
    parent: Option<i64>,
    root: i64,
    depth: i64,
    nick: String,
    login: Option<String>,
    login_fp: Option<String>,
    subject: String,
    body: String,
    mime: String,
    at: i64,
    deleted: bool,
}

fn raw_article(r: &Row<'_>) -> rusqlite::Result<RawArticle> {
    Ok(RawArticle {
        id: r.get(0)?,
        category: r.get(1)?,
        parent: r.get(2)?,
        root: r.get(3)?,
        depth: r.get(4)?,
        nick: r.get(5)?,
        login: r.get(6)?,
        login_fp: r.get(7)?,
        subject: r.get(8)?,
        body: r.get(9)?,
        mime: r.get(10)?,
        at: r.get(11)?,
        deleted: r.get(12)?,
    })
}

impl RawArticle {
    /// The article, with its references resolved as their targets stand
    /// now.
    fn into_article(self, conn: &Connection) -> Result<Article, StoreError> {
        let id = article_id(self.id)?;
        let mut refs = Vec::new();
        {
            let mut stmt = sql(conn.prepare_cached(
                "SELECT t.id, t.subject, t.nick, t.at, t.deleted_at IS NOT NULL
                   FROM news_ref r JOIN news_article t ON t.id = r.dst
                  WHERE r.src = ?1 ORDER BY r.ord",
            ))?;
            let rows = sql(stmt.query_map(params![self.id], raw_reference))?;
            for row in rows {
                refs.push(sql(row)?.into_reference()?);
            }
        }
        let referenced_by: i64 = sql(conn
            .prepare_cached("SELECT COUNT(*) FROM news_ref WHERE dst = ?1")
            .and_then(|mut s| s.query_row(params![self.id], |r| r.get(0))))?;
        Ok(Article {
            id,
            category: node_id(self.category)?,
            parent: self.parent.map(article_id).transpose()?,
            root: article_id(self.root)?,
            depth: u16::try_from(self.depth)
                .map_err(|_| StoreError::new(format!("depth {} is not a u16", self.depth)))?,
            author: Author {
                nick: self.nick,
                login: self.login,
                fingerprint: self.login_fp.as_deref().map(fp_from_hex).transpose()?,
            },
            subject: self.subject,
            body: self.body,
            mime: BodyType::from_mime(&self.mime)
                .ok_or_else(|| StoreError::new(format!("unknown body type {:?}", self.mime)))?,
            at: from_unix(self.at),
            deleted: self.deleted,
            refs,
            referenced_by: u32::try_from(referenced_by).unwrap_or(u32::MAX),
        })
    }
}

struct RawReference {
    id: i64,
    subject: String,
    nick: String,
    at: i64,
    deleted: bool,
}

fn raw_reference(r: &Row<'_>) -> rusqlite::Result<RawReference> {
    Ok(RawReference {
        id: r.get(0)?,
        subject: r.get(1)?,
        nick: r.get(2)?,
        at: r.get(3)?,
        deleted: r.get(4)?,
    })
}

impl RawReference {
    fn into_reference(self) -> Result<Reference, StoreError> {
        Ok(Reference {
            id: article_id(self.id)?,
            subject: self.subject,
            author_nick: self.nick,
            at: from_unix(self.at),
            deleted: self.deleted,
        })
    }
}

struct RawNode {
    id: i64,
    parent: Option<i64>,
    kind: i64,
    name: String,
    guid: Vec<u8>,
    add_sn: i64,
    delete_sn: i64,
    created_at: i64,
    children: i64,
}

fn raw_node(r: &Row<'_>) -> rusqlite::Result<RawNode> {
    Ok(RawNode {
        id: r.get(0)?,
        parent: r.get(1)?,
        kind: r.get(2)?,
        name: r.get(3)?,
        guid: r.get(4)?,
        add_sn: r.get(5)?,
        delete_sn: r.get(6)?,
        created_at: r.get(7)?,
        children: r.get(8)?,
    })
}

impl RawNode {
    fn into_node(self) -> Result<Node, StoreError> {
        Ok(Node {
            id: node_id(self.id)?,
            parent: self.parent.map(node_id).transpose()?,
            kind: NodeKind::from_i64(self.kind)
                .ok_or_else(|| StoreError::new(format!("unknown node kind {}", self.kind)))?,
            name: self.name,
            guid: <[u8; 16]>::try_from(self.guid.as_slice())
                .map_err(|_| StoreError::new("a node guid is not 16 bytes"))?,
            add_sn: serial(self.add_sn)?,
            delete_sn: serial(self.delete_sn)?,
            children: u32::try_from(self.children).unwrap_or(u32::MAX),
            created_at: from_unix(self.created_at),
        })
    }
}

fn load_node(conn: &Connection, id: NodeId) -> Result<Option<Node>, StoreError> {
    let sql_text = format!("SELECT {NODE_COLUMNS} FROM news_node n WHERE n.id = ?1");
    let raw = sql(conn
        .prepare_cached(&sql_text)
        .and_then(|mut s| s.query_row(params![clamp_node(id)], raw_node).optional()))?;
    raw.map(RawNode::into_node).transpose()
}

fn load_article(conn: &Connection, id: ArticleId) -> Result<Option<Article>, StoreError> {
    let sql_text = format!("SELECT {ARTICLE_COLUMNS} FROM news_article WHERE id = ?1");
    let raw = sql(conn
        .prepare_cached(&sql_text)
        .and_then(|mut s| s.query_row(params![i64::from(id)], raw_article).optional()))?;
    raw.map(|r| r.into_article(conn)).transpose()
}

/// A node id as SQLite holds one. Ids past `i64::MAX` were never issued,
/// so clamping makes one a lookup that finds nothing.
fn clamp_node(id: NodeId) -> i64 {
    id.min(i64::MAX as u64) as i64
}

/// What a node's `kind` column says, or `None` when there is no such node.
fn kind_of(conn: &Connection, id: NodeId) -> Result<Option<NodeKind>, StoreError> {
    let kind: Option<i64> = sql(conn
        .prepare_cached("SELECT kind FROM news_node WHERE id = ?1")
        .and_then(|mut s| {
            s.query_row(params![clamp_node(id)], |r| r.get(0))
                .optional()
        }))?;
    kind.map(|k| {
        NodeKind::from_i64(k).ok_or_else(|| StoreError::new(format!("unknown node kind {k}")))
    })
    .transpose()
}

/// How many levels down from the root a node sits; a root-level node is
/// at 1. Walked in Rust rather than a recursive CTE: the depth is capped
/// at `max_node_depth`, so this is a handful of indexed lookups.
fn level(conn: &Connection, mut id: NodeId) -> Result<u16, StoreError> {
    let mut level = 0u16;
    loop {
        let parent: Option<Option<i64>> = sql(conn
            .prepare_cached("SELECT parent FROM news_node WHERE id = ?1")
            .and_then(|mut s| {
                s.query_row(params![clamp_node(id)], |r| r.get(0))
                    .optional()
            }))?;
        let Some(parent) = parent else {
            return Ok(level);
        };
        level = level.saturating_add(1);
        match parent {
            Some(p) => id = node_id(p)?,
            None => return Ok(level),
        }
    }
}

fn name_taken(
    conn: &Connection,
    parent: Option<NodeId>,
    name: &str,
    except: Option<NodeId>,
) -> Result<bool, StoreError> {
    let found: Option<i64> = sql(conn
        .prepare_cached(
            "SELECT 1 FROM news_node
              WHERE IFNULL(parent, 0) = ?1 AND name = ?2 AND id IS NOT ?3 LIMIT 1",
        )
        .and_then(|mut s| {
            s.query_row(
                params![parent.map_or(0, clamp_node), name, except.map(clamp_node)],
                |r| r.get(0),
            )
            .optional()
        }))?;
    Ok(found.is_some())
}

/// A write the sibling index refused is a name collision that raced the
/// check above it; anything else is the store failing.
fn unique_or(e: rusqlite::Error) -> NewsError {
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
        {
            NewsError::NameTaken
        }
        e => NewsError::Store(StoreError::new(e)),
    }
}

/// The first byte string past every path in root `r`'s thread, or `None`
/// for the last possible root, whose range runs to the end.
fn thread_end(root: ArticleId) -> Vec<u8> {
    match root.checked_add(1) {
        Some(n) => n.to_be_bytes().to_vec(),
        // The last id there is. Nothing can reply to it, since a reply's
        // id is higher than its parent's, so its thread is its own path
        // and a fifth byte of 0xFF is past it — and still a bound SQLite
        // can seek to, which `OR ?3 IS NULL` would not be.
        None => vec![0xFF; 5],
    }
}

/// Remove every article matching `which` (a predicate over
/// `news_article`, binding `?1`), with every reference either side of
/// them. Returns how many articles went.
fn remove_articles(conn: &Connection, which: &str, arg: i64) -> Result<u64, StoreError> {
    unindex(conn, which, arg)?;
    sql(conn.execute(
        &format!(
            "DELETE FROM news_ref
              WHERE src IN (SELECT id FROM news_article WHERE {which})
                 OR dst IN (SELECT id FROM news_article WHERE {which})"
        ),
        params![arg],
    ))?;
    let gone = sql(conn.execute(
        &format!("DELETE FROM news_article WHERE {which}"),
        params![arg],
    ))?;
    Ok(gone as u64)
}

fn bump_delete_sn(conn: &Connection, category: i64) -> Result<(), StoreError> {
    sql(conn.execute(
        "UPDATE news_node SET delete_sn = (delete_sn + 1) % ?2 WHERE id = ?1",
        params![category, WRAP],
    ))?;
    Ok(())
}

// --- Subscriptions (docs/news.md §10.4) ---------------------------------
//
// A row is a scope and a cursor. Unread is counted from `news_article`
// every time it is asked — the thread's articles on `news_article_root`,
// a category's starters on `news_article_roots` — so a badge cannot
// drift from what it counts.

/// `?1`'s bind for a scope's target.
fn target_i64(scope: SubScope) -> i64 {
    match scope {
        SubScope::Thread(root) => i64::from(root),
        SubScope::Category(c) => clamp_node(c),
    }
}

/// The articles a scope is about, as a predicate over `news_article`
/// binding its target at `?1`: every article in a thread, the starters in
/// a category.
fn scope_sql(scope: SubScope) -> &'static str {
    match scope {
        SubScope::Thread(_) => "root = ?1",
        SubScope::Category(_) => "category = ?1 AND parent IS NULL",
    }
}

/// "Not written by `m`": the mailbox rule over an article's author
/// columns, binding [`bind`]'s value at `?n`. `IS` rather than `=`, because
/// a guest's article has no login, and `NULL = ?` would make it neither
/// someone's nor not.
fn not_by(m: &Mailbox, n: usize) -> String {
    match m.fingerprint {
        Some(_) => format!("login_fp IS NOT ?{n}"),
        None => format!("NOT (login_fp IS NULL AND login IS ?{n})"),
    }
}

/// The newest article in a scope, tombstones included — a cursor at a
/// tombstone is still a cursor past everything before it.
fn newest(conn: &Connection, scope: SubScope) -> Result<ArticleId, StoreError> {
    let n: Option<i64> = sql(conn.query_row(
        &format!(
            "SELECT MAX(id) FROM news_article WHERE {}",
            scope_sql(scope)
        ),
        params![target_i64(scope)],
        |r| r.get(0),
    ))?;
    Ok(n.map(article_id).transpose()?.unwrap_or(0))
}

fn unread(
    conn: &Connection,
    owner: &Mailbox,
    scope: SubScope,
    last_seen: ArticleId,
) -> Result<usize, StoreError> {
    let n: i64 = sql(conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM news_article
              WHERE {} AND id > ?2 AND deleted_at IS NULL AND {}",
            scope_sql(scope),
            not_by(owner, 3)
        ),
        params![target_i64(scope), i64::from(last_seen), bind(owner)],
        |r| r.get(0),
    ))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// A post's audience and its counts (§10.5): every row on the thread `?1`
/// and on the category `?2`, each with its unread — what [`unread`]
/// counts — and how much of that is older than the article `?3`, the
/// catch-up rule's question (§10.7). One statement, the counts made by
/// the join, rather than two more queries per row under the connection's
/// lock. The author test is [`not_by`]'s mailbox rule, spelled against
/// each row's own owner columns; one arm per scope, so each join runs on
/// its own index.
const SUBSCRIBERS: &str = "
SELECT s.owner, s.owner_fp, s.scope, s.target, s.muted,
       COUNT(a.id), COUNT(CASE WHEN a.id < ?3 THEN 1 END)
  FROM news_sub s
  LEFT JOIN news_article a
         ON a.root = s.target AND a.id > s.last_seen AND a.deleted_at IS NULL
        AND CASE WHEN s.owner_fp IS NULL
                 THEN NOT (a.login_fp IS NULL AND a.login IS s.owner)
                 ELSE a.login_fp IS NOT s.owner_fp END
 WHERE s.scope = 0 AND s.target = ?1
 GROUP BY s.id
UNION ALL
SELECT s.owner, s.owner_fp, s.scope, s.target, s.muted,
       COUNT(a.id), COUNT(CASE WHEN a.id < ?3 THEN 1 END)
  FROM news_sub s
  LEFT JOIN news_article a
         ON a.category = s.target AND a.parent IS NULL
        AND a.id > s.last_seen AND a.deleted_at IS NULL
        AND CASE WHEN s.owner_fp IS NULL
                 THEN NOT (a.login_fp IS NULL AND a.login IS s.owner)
                 ELSE a.login_fp IS NOT s.owner_fp END
 WHERE s.scope = 1 AND s.target = ?2
 GROUP BY s.id";

/// A row of [`SUBSCRIBERS`]: owner, owner_fp, scope, target, muted,
/// unread, earlier.
type AudienceRow = (String, Option<String>, i64, i64, bool, i64, i64);

/// Is there something at `scope` to subscribe to?
fn check_target(conn: &Connection, scope: SubScope) -> Result<(), NewsError> {
    match scope {
        SubScope::Thread(root) => {
            let parent: Option<Option<i64>> = sql(conn
                .query_row(
                    "SELECT parent FROM news_article WHERE id = ?1",
                    params![i64::from(root)],
                    |r| r.get(0),
                )
                .optional())?;
            match parent {
                Some(None) => Ok(()),
                _ => Err(NewsError::NoSuchArticle),
            }
        }
        SubScope::Category(c) => match kind_of(conn, c)? {
            None => Err(NewsError::NoSuchNode),
            Some(NodeKind::Bundle) => Err(NewsError::NotACategory),
            Some(NodeKind::Category) => Ok(()),
        },
    }
}

/// `owner`'s row for `scope`: its id and cursor.
fn sub_row(
    conn: &Connection,
    owner: &Mailbox,
    scope: SubScope,
) -> Result<Option<(i64, ArticleId)>, StoreError> {
    let row: Option<(i64, i64)> = sql(conn
        .query_row(
            &format!(
                "SELECT id, last_seen FROM news_sub
                  WHERE {} AND scope = ?2 AND target = ?3",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), scope.kind_i64(), target_i64(scope)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    row.map(|(id, seen)| Ok((id, article_id(seen)?)))
        .transpose()
}

/// A new row for `owner`, caught up, or `TooManySubs`. Inside the
/// caller's transaction, so the count and the insert see one database.
/// Answers its cursor.
fn add_sub(
    conn: &Connection,
    owner: &Mailbox,
    scope: SubScope,
    auto: bool,
    muted: bool,
    max_subs: usize,
    at: SystemTime,
) -> Result<ArticleId, NewsError> {
    check_target(conn, scope)?;
    let held: i64 = sql(conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM news_sub WHERE {}",
            mailbox_sql(owner, "owner", 1)
        ),
        params![bind(owner)],
        |r| r.get(0),
    ))?;
    if usize::try_from(held).unwrap_or(usize::MAX) >= max_subs {
        return Err(NewsError::TooManySubs);
    }
    let last_seen = newest(conn, scope)?;
    sql(conn.execute(
        "INSERT INTO news_sub (owner, owner_fp, scope, target, auto, muted, last_seen, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            owner.login,
            owner.fingerprint.as_ref().map(fp_hex),
            scope.kind_i64(),
            target_i64(scope),
            auto,
            muted,
            i64::from(last_seen),
            unix(at),
        ],
    ))?;
    Ok(last_seen)
}

/// Rows whose thread or category has gone. Run inside every write that
/// removes either, so a `news_subs` listing never names nothing and a
/// dead row never counts against `max_subs`.
fn drop_orphan_subs(conn: &Connection) -> Result<(), StoreError> {
    sql(conn.execute(
        "DELETE FROM news_sub
          WHERE (scope = 0 AND NOT EXISTS (SELECT 1 FROM news_article a
                                            WHERE a.id = news_sub.target AND a.parent IS NULL))
             OR (scope = 1 AND NOT EXISTS (SELECT 1 FROM news_node n
                                            WHERE n.id = news_sub.target))",
        [],
    ))?;
    Ok(())
}

fn sub_owner(login: String, fp: Option<String>) -> Result<Mailbox, StoreError> {
    Ok(Mailbox {
        login,
        fingerprint: fp.as_deref().map(fp_from_hex).transpose()?,
    })
}

fn scope_of(kind: i64, target: i64) -> Result<SubScope, StoreError> {
    SubScope::from_parts(kind, target)
        .ok_or_else(|| StoreError::new(format!("news_sub scope {kind} target {target}")))
}

// --- The search index (docs/news.md §6) ---------------------------------
//
// **It holds live articles and only those.** An external-content index
// trusts the table to stay in step with it, so every write that makes or
// unmakes a live article writes the index in the same transaction: a post
// adds its row, and a tombstone, a category deletion and retention take
// theirs out — with the values it was indexed under, read off the row
// itself before the row changes. Tombstones are never in it, which is why
// every removal skips them.

/// Every live article, as the index reads it.
const INDEX_LIVE: &str = "INSERT INTO news_fts (rowid, subject, search_body, author)
  SELECT id, subject, search_body, author FROM news_article WHERE deleted_at IS NULL";

fn index_article(conn: &Connection, id: ArticleId) -> Result<(), StoreError> {
    sql(conn.execute(
        "INSERT INTO news_fts (rowid, subject, search_body, author)
         SELECT id, subject, search_body, author FROM news_article WHERE id = ?1",
        params![i64::from(id)],
    ))?;
    Ok(())
}

/// Take every live article matching `which` (binding `?1`) out of the
/// index. Called before the rows change, so what it reads is what was
/// indexed.
fn unindex(conn: &Connection, which: &str, arg: i64) -> Result<(), StoreError> {
    sql(conn.execute(
        &format!(
            "INSERT INTO news_fts (news_fts, rowid, subject, search_body, author)
             SELECT 'delete', id, subject, search_body, author FROM news_article
              WHERE ({which}) AND deleted_at IS NULL"
        ),
        params![arg],
    ))?;
    Ok(())
}

/// The compiled query as an FTS5 expression. Every word is letters and
/// digits (the grammar made sure of it), so a word inside quotes needs no
/// escaping and nothing here can be a syntax error. `None` when there is
/// nothing to look for — exclusions alone are not something FTS5 accepts,
/// and not something worth asking it.
fn fts_expression(q: &hxd_core::news::CompiledQuery) -> Option<String> {
    use hxd_core::news::{Field, Term};
    let render = |t: &Term| {
        let mut phrase = format!("\"{}\"", t.words.join(" "));
        if t.prefix {
            phrase.push_str(" *");
        }
        match t.field {
            Field::Any => phrase,
            Field::Subject => format!("subject : {phrase}"),
            Field::Author => format!("author : {phrase}"),
        }
    };
    let wanted: Vec<String> = q.terms.iter().filter(|t| !t.negated).map(render).collect();
    if wanted.is_empty() {
        return None;
    }
    let mut expr = format!("({})", wanted.join(" AND "));
    for t in q.terms.iter().filter(|t| t.negated) {
        expr.push_str(&format!(" NOT ({})", render(t)));
    }
    Some(expr)
}

/// The tokenizer `news_fts` was made with (lib.rs, schema version 4).
pub(crate) const TOKENIZER: &str = "unicode61 remove_diacritics 2";

/// The query without the terms the index's tokenizer finds nothing in.
/// The grammar's words are letters and digits by Rust's reckoning, and
/// `unicode61` disagrees at the edges: a lone vowel sign or combining
/// mark is a word to one and a separator to the other. A phrase of
/// nothing matches nothing, and ANDed with the rest it would take the
/// whole query down with it; dropped, it is what the grammar does with a
/// term that has no words at all.
///
/// The tokenizer is asked directly, through a temporary table it is the
/// tokenizer of, so what counts as a token here is what counts in the
/// index, and nothing about it lives in the database file.
fn searchable(
    conn: &Connection,
    q: &hxd_core::news::CompiledQuery,
) -> Result<hxd_core::news::CompiledQuery, StoreError> {
    sql(conn.execute_batch(&format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS temp.news_query
           USING fts5(words, tokenize = '{TOKENIZER}');
         CREATE VIRTUAL TABLE IF NOT EXISTS temp.news_query_tokens
           USING fts5vocab(temp, news_query, instance);
         DELETE FROM temp.news_query;"
    )))?;
    for (i, t) in (1i64..).zip(&q.terms) {
        sql(conn.execute(
            "INSERT INTO temp.news_query (rowid, words) VALUES (?1, ?2)",
            params![i, t.words.join(" ")],
        ))?;
    }
    let tokened: std::collections::HashSet<i64> = {
        let mut stmt = sql(conn.prepare_cached("SELECT DISTINCT doc FROM temp.news_query_tokens"))?;
        let rows = sql(stmt.query_map([], |r| r.get(0)))?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(StoreError::new)?
    };
    sql(conn.execute("DELETE FROM temp.news_query", []))?;
    Ok(hxd_core::news::CompiledQuery {
        terms: (1i64..)
            .zip(&q.terms)
            .filter(|(i, _)| tokened.contains(i))
            .map(|(_, t)| t.clone())
            .collect(),
    })
}

/// Where `snippet()` puts its marks: two bytes that never occur in UTF-8,
/// taken back out here and turned into byte ranges, so what leaves the
/// store is text and offsets rather than markup. Any character would do
/// until a body carried it — every one is valid in a body, and a body is
/// stored as typed — and these are the markers no body can.
const MARK_OPEN: u8 = 0xfe;
const MARK_CLOSE: u8 = 0xff;

/// A snippet without its markers, and the ranges they bracketed.
fn unmark(marked: &[u8]) -> Result<(String, Vec<(u32, u32)>), StoreError> {
    let mut text = Vec::with_capacity(marked.len());
    let mut marks = Vec::new();
    let mut open = None;
    for &b in marked {
        match b {
            MARK_OPEN => open = Some(text.len()),
            MARK_CLOSE => {
                if let Some(start) = open.take() {
                    marks.push((start as u32, text.len() as u32));
                }
            }
            b => text.push(b),
        }
    }
    let text = String::from_utf8(text).map_err(StoreError::new)?;
    Ok((text, marks))
}

struct RawHit {
    id: i64,
    subject: String,
    nick: String,
    category: i64,
    root: i64,
    at: i64,
    snippet: Vec<u8>,
}

impl NewsStore for SqliteStore {
    fn nodes(&self, parent: Option<NodeId>) -> Result<Vec<Node>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql_text = format!(
            "SELECT {NODE_COLUMNS} FROM news_node n WHERE IFNULL(n.parent, 0) = ?1 ORDER BY n.name"
        );
        let mut stmt = sql(conn.prepare_cached(&sql_text))?;
        let rows = sql(stmt.query_map(params![parent.map_or(0, clamp_node)], raw_node))?;
        rows.map(|r| sql(r).and_then(RawNode::into_node)).collect()
    }

    fn node(&self, id: NodeId) -> Result<Option<Node>, StoreError> {
        let conn = self.conn.lock().unwrap();
        load_node(&conn, id)
    }

    fn create_node(&self, n: &NewNode, max_depth: u16) -> Result<Node, NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let level = match n.parent {
            None => 1,
            Some(p) => match kind_of(&tx, p)? {
                None => return Err(NewsError::NoSuchNode),
                Some(NodeKind::Category) => return Err(NewsError::NotACategory),
                Some(NodeKind::Bundle) => level(&tx, p)?.saturating_add(1),
            },
        };
        if level > max_depth {
            return Err(NewsError::TooDeep);
        }
        if name_taken(&tx, n.parent, &n.name, None)? {
            return Err(NewsError::NameTaken);
        }
        tx.execute(
            "INSERT INTO news_node (parent, kind, name, guid, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                n.parent.map(clamp_node),
                n.kind.as_i64(),
                n.name,
                n.guid.as_slice(),
                unix(n.at)
            ],
        )
        .map_err(unique_or)?;
        let id = node_id(tx.last_insert_rowid())?;
        let node = load_node(&tx, id)?.ok_or_else(|| StoreError::new("a node vanished"))?;
        sql(tx.commit())?;
        Ok(node)
    }

    fn rename_node(&self, id: NodeId, name: &str) -> Result<Node, NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let node = load_node(&tx, id)?.ok_or(NewsError::NoSuchNode)?;
        if name_taken(&tx, node.parent, name, Some(id))? {
            return Err(NewsError::NameTaken);
        }
        tx.execute(
            "UPDATE news_node SET name = ?1 WHERE id = ?2",
            params![name, clamp_node(id)],
        )
        .map_err(unique_or)?;
        let node = load_node(&tx, id)?.ok_or_else(|| StoreError::new("a node vanished"))?;
        sql(tx.commit())?;
        Ok(node)
    }

    fn delete_node(&self, id: NodeId) -> Result<u64, NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let gone = match kind_of(&tx, id)? {
            None => return Err(NewsError::NoSuchNode),
            Some(NodeKind::Bundle) => {
                let child: Option<i64> = sql(tx
                    .query_row(
                        "SELECT 1 FROM news_node WHERE IFNULL(parent, 0) = ?1 LIMIT 1",
                        params![clamp_node(id)],
                        |r| r.get(0),
                    )
                    .optional())?;
                if child.is_some() {
                    return Err(NewsError::NotEmpty);
                }
                0
            }
            Some(NodeKind::Category) => remove_articles(&tx, "category = ?1", clamp_node(id))?,
        };
        sql(tx.execute(
            "DELETE FROM news_node WHERE id = ?1",
            params![clamp_node(id)],
        ))?;
        drop_orphan_subs(&tx)?;
        sql(tx.commit())?;
        Ok(gone)
    }

    fn post(&self, p: &NewPost, max_depth: u16, max_refs: usize) -> Result<Posted, NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        match kind_of(&tx, p.category)? {
            None => return Err(NewsError::NoSuchNode),
            Some(NodeKind::Bundle) => return Err(NewsError::NotACategory),
            Some(NodeKind::Category) => {}
        }
        let (parent_path, depth, root) = match p.parent {
            None => (Vec::new(), 0u16, None),
            Some(pid) => {
                let found: Option<(i64, i64, Vec<u8>, i64)> = sql(tx
                    .query_row(
                        "SELECT category, depth, path, root FROM news_article WHERE id = ?1",
                        params![i64::from(pid)],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional())?;
                let (category, depth, path, root) = found.ok_or(NewsError::NoSuchArticle)?;
                if category != clamp_node(p.category) {
                    return Err(NewsError::WrongCategory);
                }
                let depth = u16::try_from(depth)
                    .map_err(|_| StoreError::new(format!("depth {depth} is not a u16")))?
                    .saturating_add(1);
                if depth > max_depth {
                    return Err(NewsError::TooDeep);
                }
                (path, depth, Some(article_id(root)?))
            }
        };
        // The path needs the id and the id needs the row, so the row goes
        // in with placeholders and is finished inside the same
        // transaction; nothing outside it ever sees the placeholder.
        sql(tx.execute(
            "INSERT INTO news_article
               (category, parent, root, path, depth, nick, login, login_fp,
                subject, body, mime, plain, at)
             VALUES (?1, ?2, 0, X'', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                clamp_node(p.category),
                p.parent.map(i64::from),
                i64::from(depth),
                p.author.nick,
                p.author.login,
                p.author.fingerprint.as_ref().map(fp_hex),
                p.subject,
                p.body,
                p.mime.mime(),
                p.plain,
                unix(p.at),
            ],
        ))?;
        // Past u32 is an article the legacy wire cannot name (§3.2). The
        // transaction rolls back when `tx` drops.
        let id = ArticleId::try_from(tx.last_insert_rowid())
            .map_err(|_| NewsError::Store(StoreError::new("article ids exhausted")))?;
        let root = root.unwrap_or(id);
        let mut path = parent_path;
        path.extend_from_slice(&id.to_be_bytes());
        sql(tx.execute(
            "UPDATE news_article SET root = ?1, path = ?2 WHERE id = ?3",
            params![i64::from(root), path, i64::from(id)],
        ))?;
        index_article(&tx, id)?;

        let mut kept: Vec<ArticleId> = Vec::new();
        for &dst in &p.refs {
            if kept.len() >= max_refs {
                break;
            }
            if kept.contains(&dst) || dst == id {
                continue;
            }
            let exists: Option<i64> = sql(tx
                .query_row(
                    "SELECT 1 FROM news_article WHERE id = ?1",
                    params![i64::from(dst)],
                    |r| r.get(0),
                )
                .optional())?;
            if exists.is_some() {
                sql(tx.execute(
                    "INSERT INTO news_ref (src, dst, ord) VALUES (?1, ?2, ?3)",
                    params![i64::from(id), i64::from(dst), kept.len() as i64],
                ))?;
                kept.push(dst);
            }
        }
        sql(tx.execute(
            "UPDATE news_node SET add_sn = (add_sn + 1) % ?2 WHERE id = ?1",
            params![clamp_node(p.category), WRAP],
        ))?;
        // In the article's transaction, so no later article is given an
        // id before the row exists. It starts at this one, the thread's
        // newest.
        if let Some(f) = &p.follow {
            let thread = SubScope::Thread(root);
            if sub_row(&tx, &f.owner, thread)?.is_none() {
                match add_sub(&tx, &f.owner, thread, true, false, f.max_subs, p.at) {
                    Ok(_) | Err(NewsError::TooManySubs) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        sql(tx.commit())?;
        Ok(Posted { id, root })
    }

    fn article(&self, id: ArticleId) -> Result<Option<Article>, StoreError> {
        let conn = self.conn.lock().unwrap();
        load_article(&conn, id)
    }

    fn threads(&self, q: &ThreadQuery) -> Result<ThreadPage, NewsError> {
        if q.limit == 0 {
            return Err(NewsError::BadRequest("A page needs a limit of at least 1."));
        }
        let conn = self.conn.lock().unwrap();
        match kind_of(&conn, q.category)? {
            None => return Err(NewsError::NoSuchNode),
            Some(NodeKind::Bundle) => return Err(NewsError::NotACategory),
            Some(NodeKind::Category) => {}
        }
        // Ascending when paging forward, so the page is the threads
        // nearest the cursor; descending otherwise. Reversed afterwards,
        // so either way a page reads newest first.
        let order = if q.after.is_some() { "ASC" } else { "DESC" };
        // Both cursors are always bound, an absent one as the end of the
        // id space, so the roots index is a range scan either way. An
        // `?2 IS NULL OR` bound is one SQLite cannot seek to, and a deep
        // page would walk every newer thread to reach its own.
        let sql_text = format!(
            "SELECT {ARTICLE_COLUMNS} FROM news_article a
              WHERE a.category = ?1 AND a.parent IS NULL
                AND a.id < ?2 AND a.id > ?3
                AND EXISTS (SELECT 1 FROM news_article d
                             WHERE d.root = a.id AND d.deleted_at IS NULL)
              ORDER BY a.id {order} LIMIT ?4"
        );
        let take = q.limit.saturating_add(1).min(i64::MAX as usize) as i64;
        let raws: Vec<RawArticle> = {
            let mut stmt = sql(conn.prepare_cached(&sql_text))?;
            let rows = sql(stmt.query_map(
                params![
                    clamp_node(q.category),
                    q.before.map_or(i64::MAX, i64::from),
                    q.after.map_or(0, i64::from),
                    take
                ],
                raw_article,
            ))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        let has_more = raws.len() > q.limit;
        let mut threads = Vec::with_capacity(raws.len().min(q.limit));
        for raw in raws.into_iter().take(q.limit) {
            let article = raw.into_article(&conn)?;
            let (count, last_at, last_id): (i64, i64, i64) = sql(conn
                .prepare_cached(
                    "SELECT COUNT(*), MAX(at), MAX(id) FROM news_article WHERE root = ?1",
                )
                .and_then(|mut s| {
                    s.query_row(params![i64::from(article.id)], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                }))?;
            threads.push(ThreadHead {
                replies: u32::try_from(count - 1).unwrap_or(0),
                last_at: from_unix(last_at),
                last_id: article_id(last_id)?,
                article,
            });
        }
        if q.after.is_some() {
            threads.reverse();
        }
        Ok(ThreadPage { threads, has_more })
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
        let conn = self.conn.lock().unwrap();
        let starter: Option<(i64, Option<i64>, Option<i64>)> = sql(conn
            .query_row(
                "SELECT category, parent,
                        (SELECT MAX(id) FROM news_article WHERE root = ?1)
                   FROM news_article WHERE id = ?1",
                params![i64::from(root)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional())?;
        let (category, newest) = match starter {
            Some((category, None, Some(newest))) => (category, article_id(newest)?),
            _ => return Err(NewsError::NoSuchArticle),
        };
        let snapshot = snapshot.unwrap_or(newest);
        if snapshot < root {
            return Err(NewsError::BadRequest("The snapshot predates this thread."));
        }
        // The cursor is a place in this thread, so it has to be in it.
        let from: Vec<u8> = match after {
            None => Vec::new(),
            Some(id) => {
                let found: Option<(i64, Vec<u8>)> = sql(conn
                    .query_row(
                        "SELECT root, path FROM news_article WHERE id = ?1",
                        params![i64::from(id)],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional())?;
                let path = match found {
                    Some((r, path)) if r == i64::from(root) => path,
                    _ => return Err(NewsError::NoSuchArticle),
                };
                if id > snapshot {
                    return Err(NewsError::BadRequest("The cursor is past this snapshot."));
                }
                path
            }
        };
        let take = limit.saturating_add(1).min(i64::MAX as usize) as i64;
        let sql_text = format!(
            "SELECT {ARTICLE_COLUMNS} FROM news_article
              WHERE category = ?1 AND path >= ?2 AND path < ?3 AND path > ?4
                AND id <= ?5
              ORDER BY path LIMIT ?6"
        );
        let raws: Vec<RawArticle> = {
            let mut stmt = sql(conn.prepare_cached(&sql_text))?;
            let rows = sql(stmt.query_map(
                params![
                    category,
                    root.to_be_bytes().as_slice(),
                    thread_end(root),
                    from,
                    i64::from(snapshot),
                    take
                ],
                raw_article,
            ))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        let has_more = raws.len() > limit;
        let articles = raws
            .into_iter()
            .take(limit)
            .map(|r| r.into_article(&conn))
            .collect::<Result<_, _>>()?;
        Ok(ArticlePage {
            articles,
            has_more,
            snapshot,
        })
    }

    fn tombstone(
        &self,
        id: ArticleId,
        by: &str,
        at: SystemTime,
    ) -> Result<Option<Article>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let Some(before) = load_article(&tx, id)?.filter(|a| !a.deleted) else {
            return Ok(None);
        };
        sql(tx.execute(
            "DELETE FROM news_ref WHERE src = ?1",
            params![i64::from(id)],
        ))?;
        // Out of the index before its words go: a deletion that left the
        // body findable would not be one (§11).
        unindex(&tx, "id = ?1", i64::from(id))?;
        sql(tx.execute(
            "UPDATE news_article
                SET subject = '', body = '', plain = NULL, attach_names = NULL, nick = '',
                    login = NULL, login_fp = NULL, deleted_at = ?1, deleted_by = ?2
              WHERE id = ?3",
            params![unix(at), by, i64::from(id)],
        ))?;
        bump_delete_sn(&tx, clamp_node(before.category))?;
        sql(tx.commit())?;
        Ok(Some(before))
    }

    fn refs_to(&self, id: ArticleId, limit: usize) -> Result<Vec<Reference>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT s.id, s.subject, s.nick, s.at, s.deleted_at IS NOT NULL
               FROM news_ref r JOIN news_article s ON s.id = r.src
              WHERE r.dst = ?1 ORDER BY r.src DESC LIMIT ?2",
        ))?;
        let rows = sql(stmt.query_map(
            params![i64::from(id), limit.min(i64::MAX as usize) as i64],
            raw_reference,
        ))?;
        rows.map(|r| sql(r).and_then(RawReference::into_reference))
            .collect()
    }

    fn prune(&self, max_age: Duration, now: SystemTime) -> Result<u64, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let stale: Vec<(i64, i64)> = {
            let mut stmt = sql(tx.prepare(
                "SELECT root, MIN(category) FROM news_article
                  GROUP BY root HAVING MAX(at) < ?1",
            ))?;
            let rows = sql(stmt.query_map(params![cutoff(now, max_age)], |r| {
                Ok((r.get(0)?, r.get(1)?))
            }))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        let mut gone = 0;
        let mut touched: Vec<i64> = Vec::new();
        for (root, category) in stale {
            gone += remove_articles(&tx, "root = ?1", root)?;
            if !touched.contains(&category) {
                touched.push(category);
            }
        }
        for category in touched {
            bump_delete_sn(&tx, category)?;
        }
        drop_orphan_subs(&tx)?;
        sql(tx.commit())?;
        Ok(gone)
    }

    fn search(
        &self,
        q: &hxd_core::news::SearchQuery,
    ) -> Result<hxd_core::news::SearchPage, StoreError> {
        use hxd_core::news::{Hit, SearchOrder, SearchPage};
        use rusqlite::types::Value;
        let conn = self.conn.lock().unwrap();
        let terms = searchable(&conn, &q.terms)?;
        let Some(expr) = fts_expression(&terms) else {
            return Ok(SearchPage::default());
        };
        // Built from the query's shape, never its text: every value the
        // user chose is a bound parameter.
        let mut filter = String::new();
        let mut binds: Vec<Value> = vec![Value::Text(expr)];
        if let Some(categories) = &q.categories {
            if categories.is_empty() {
                return Ok(SearchPage::default());
            }
            filter.push_str(" AND a.category IN (");
            filter.push_str(&vec!["?"; categories.len()].join(", "));
            filter.push(')');
            binds.extend(categories.iter().map(|c| Value::Integer(clamp_node(*c))));
        }
        if let Some(t) = q.before {
            filter.push_str(" AND a.at < ?");
            binds.push(Value::Integer(unix(t)));
        }
        if let Some(t) = q.after {
            filter.push_str(" AND a.at > ?");
            binds.push(Value::Integer(unix(t)));
        }
        let from = format!(
            "FROM news_fts JOIN news_article a ON a.id = news_fts.rowid
             WHERE news_fts MATCH ?{filter}"
        );
        let total: i64 = sql(conn.query_row(
            &format!("SELECT COUNT(*) {from}"),
            rusqlite::params_from_iter(binds.iter()),
            |r| r.get(0),
        ))?;
        let mut hits = Vec::new();
        if q.limit > 0 {
            // BM25 with the subject weighted ten to the body's one and the
            // author three (§6.3); ties, and the recent order, newest first.
            let order = match q.order {
                SearchOrder::Relevance => "bm25(news_fts, 10.0, 1.0, 3.0), a.id DESC",
                SearchOrder::Recent => "a.id DESC",
            };
            let sql_text = format!(
                "SELECT a.id, a.subject, a.nick, a.category, a.root, a.at,
                        snippet(news_fts, 1, CAST(X'fe' AS TEXT), CAST(X'ff' AS TEXT),
                                '…', 16)
                 {from} ORDER BY {order} LIMIT ? OFFSET ?"
            );
            let mut all = binds.clone();
            all.push(Value::Integer(q.limit.min(i64::MAX as usize) as i64));
            all.push(Value::Integer(q.offset.min(i64::MAX as usize) as i64));
            let mut stmt = sql(conn.prepare(&sql_text))?;
            let rows = sql(stmt.query_map(rusqlite::params_from_iter(all.iter()), |r| {
                Ok(RawHit {
                    id: r.get(0)?,
                    subject: r.get(1)?,
                    nick: r.get(2)?,
                    category: r.get(3)?,
                    root: r.get(4)?,
                    at: r.get(5)?,
                    // As bytes: with its markers in, it is not UTF-8.
                    snippet: match r.get_ref(6)? {
                        rusqlite::types::ValueRef::Text(b) => b.to_vec(),
                        _ => Vec::new(),
                    },
                })
            }))?;
            for row in rows {
                let raw = sql(row)?;
                let (snippet, marks) = unmark(&raw.snippet)?;
                hits.push(Hit {
                    article: article_id(raw.id)?,
                    root: article_id(raw.root)?,
                    category: node_id(raw.category)?,
                    subject: raw.subject,
                    author_nick: raw.nick,
                    at: from_unix(raw.at),
                    snippet,
                    marks,
                });
            }
        }
        Ok(SearchPage {
            hits,
            total: u32::try_from(total).unwrap_or(u32::MAX),
            capped: false,
        })
    }

    fn reindex(&self) -> Result<u64, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        sql(tx.execute("INSERT INTO news_fts (news_fts) VALUES ('delete-all')", []))?;
        let indexed = sql(tx.execute(INDEX_LIVE, []))?;
        sql(tx.commit())?;
        Ok(indexed as u64)
    }

    fn subscribe(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        max_subs: usize,
        at: SystemTime,
    ) -> Result<usize, NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        check_target(&tx, scope)?;
        let last_seen = match sub_row(&tx, owner, scope)? {
            Some((id, seen)) => {
                // Asking is explicit, and asking to hear about something
                // is not asking for it muted.
                sql(tx.execute(
                    "UPDATE news_sub SET auto = 0, muted = 0 WHERE id = ?1",
                    params![id],
                ))?;
                seen
            }
            None => add_sub(&tx, owner, scope, false, false, max_subs, at)?,
        };
        let n = unread(&tx, owner, scope, last_seen)?;
        sql(tx.commit())?;
        Ok(n)
    }

    fn unsubscribe(&self, owner: &Mailbox, scope: SubScope) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let gone = sql(conn.execute(
            &format!(
                "DELETE FROM news_sub WHERE {} AND scope = ?2 AND target = ?3",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), scope.kind_i64(), target_i64(scope)],
        ))?;
        Ok(gone > 0)
    }

    fn mute(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        muted: bool,
        max_subs: usize,
        at: SystemTime,
    ) -> Result<(), NewsError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        match sub_row(&tx, owner, scope)? {
            Some((id, _)) => {
                sql(tx.execute(
                    "UPDATE news_sub SET muted = ?2 WHERE id = ?1",
                    params![id, muted],
                ))?;
            }
            None if muted => {
                add_sub(&tx, owner, scope, false, true, max_subs, at)?;
            }
            None => {}
        }
        sql(tx.commit())?;
        Ok(())
    }

    fn subscriptions(&self, owner: &Mailbox) -> Result<Vec<Subscription>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let rows: Vec<(i64, i64, bool, bool, i64, i64)> = {
            let mut stmt = sql(conn.prepare(&format!(
                "SELECT scope, target, auto, muted, last_seen, at FROM news_sub
                  WHERE {} ORDER BY id DESC",
                mailbox_sql(owner, "owner", 1)
            )))?;
            let rows = sql(stmt.query_map(params![bind(owner)], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            }))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (kind, target, auto, muted, last_seen, at) in rows {
            let scope = scope_of(kind, target)?;
            let found: Option<(i64, String)> = match scope {
                SubScope::Thread(root) => sql(conn
                    .query_row(
                        "SELECT category, subject FROM news_article WHERE id = ?1",
                        params![i64::from(root)],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional())?,
                SubScope::Category(c) => sql(conn
                    .query_row(
                        "SELECT id, name FROM news_node WHERE id = ?1",
                        params![clamp_node(c)],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional())?,
            };
            // Every write that removes a target removes its rows too, so
            // this is a row that raced one; it is gone either way.
            let Some((category, label)) = found else {
                continue;
            };
            let last_seen = article_id(last_seen)?;
            out.push(Subscription {
                scope,
                category: node_id(category)?,
                label,
                auto,
                muted,
                last_seen,
                unread: unread(&conn, owner, scope, last_seen)?,
                at: from_unix(at),
            });
        }
        Ok(out)
    }

    fn seen(
        &self,
        owner: &Mailbox,
        scope: SubScope,
        up_to: ArticleId,
    ) -> Result<Option<usize>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let Some((id, last_seen)) = sub_row(&tx, owner, scope)? else {
            return Ok(None);
        };
        let last_seen = last_seen.max(up_to.min(newest(&tx, scope)?));
        sql(tx.execute(
            "UPDATE news_sub SET last_seen = ?2 WHERE id = ?1",
            params![id, i64::from(last_seen)],
        ))?;
        let n = unread(&tx, owner, scope, last_seen)?;
        sql(tx.commit())?;
        Ok(Some(n))
    }

    fn subscribers(
        &self,
        root: ArticleId,
        category: Option<NodeId>,
        article: ArticleId,
    ) -> Result<Vec<Subscriber>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let rows: Vec<AudienceRow> = {
            let mut stmt = sql(conn.prepare_cached(SUBSCRIBERS))?;
            // No node has id -1, so a thread-only question binds that.
            let category = category.map_or(-1, clamp_node);
            let rows = sql(stmt.query_map(
                params![i64::from(root), category, i64::from(article)],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            ))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        rows.into_iter()
            .map(|(login, fp, kind, target, muted, unread, earlier)| {
                Ok(Subscriber {
                    owner: sub_owner(login, fp)?,
                    scope: scope_of(kind, target)?,
                    muted,
                    unread: usize::try_from(unread).unwrap_or(0),
                    earlier: usize::try_from(earlier).unwrap_or(0),
                })
            })
            .collect()
    }

    fn unread_total(&self, owner: &Mailbox) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let rows: Vec<(i64, i64, i64)> = {
            let mut stmt = sql(conn.prepare(&format!(
                "SELECT scope, target, last_seen FROM news_sub WHERE {} AND muted = 0",
                mailbox_sql(owner, "owner", 1)
            )))?;
            let rows = sql(stmt.query_map(params![bind(owner)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            }))?;
            rows.collect::<rusqlite::Result<_>>()
                .map_err(StoreError::new)?
        };
        let mut total = 0;
        for (kind, target, last_seen) in rows {
            total += unread(
                &conn,
                owner,
                scope_of(kind, target)?,
                article_id(last_seen)?,
            )?;
        }
        Ok(total)
    }

    fn subs_claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let fp = fp_hex(fingerprint);
        // A scope the identity already follows keeps the identity's row.
        let dropped = sql(tx.execute(
            "DELETE FROM news_sub
              WHERE owner_fp IS NULL AND owner = ?1
                AND EXISTS (SELECT 1 FROM news_sub s
                             WHERE s.owner_fp = ?2 AND s.scope = news_sub.scope
                               AND s.target = news_sub.target)",
            params![login, fp],
        ))?;
        let moved = sql(tx.execute(
            "UPDATE news_sub SET owner_fp = ?2 WHERE owner_fp IS NULL AND owner = ?1",
            params![login, fp],
        ))?;
        sql(tx.commit())?;
        Ok(dropped + moved)
    }

    fn subs_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let (from, to) = (fp_hex(from), fp_hex(to));
        let dropped = sql(tx.execute(
            "DELETE FROM news_sub
              WHERE owner_fp = ?1
                AND EXISTS (SELECT 1 FROM news_sub s
                             WHERE s.owner_fp = ?2 AND s.scope = news_sub.scope
                               AND s.target = news_sub.target)",
            params![from, to],
        ))?;
        let moved = sql(tx.execute(
            "UPDATE news_sub SET owner_fp = ?2 WHERE owner_fp = ?1",
            params![from, to],
        ))?;
        sql(tx.commit())?;
        Ok(dropped + moved)
    }

    fn subs_purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            &format!("DELETE FROM news_sub WHERE {}", mailbox_sql(of, "owner", 1)),
            params![bind(of)],
        ))
    }
}
