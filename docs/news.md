# Threaded news: articles, attachments, references and search

ROADMAP Phase 4 promises "1.2 flat news post/read, and the 1.5 threaded
news tree (categories, bundles, threads)". Nothing is built: `hxd-session`
dispatches no news opcode, `hxd-core` has no `news` module, and the ng
protocol has never had one. This document designs the whole thing — the
domain, the store, markdown bodies, cross-references, full-text search,
image attachments, and the Hotline-ng binding — and specs the legacy 1.5
binding so the model can be checked against the wire it must eventually
serve.

Phase 4's own description is the floor, not the ceiling: what a modern
client wants from a forum is rich text, links between posts and a search
box, and none of the three turns out to need anything the 1.5 wire
cannot be told about — because that wire has carried multipart articles
with per-part MIME types since it was written.

The ordering is deliberate and is the answer to the first question this
design has to settle: **the domain is designed once against both wires,
the ng binding is built first, the legacy binding is built after.** News
is the one Phase 4 subsystem where the ng wire is not a second frontend
onto an existing feature — it is where the feature arrives. Building ng
first means the domain model is shaped by what news actually *is*
(a tree of threads with authors and bodies) rather than by what a 1996
directory walker could express, and §11 is the proof that nothing in it
locks the legacy wire out.

**Decisions (2026-09):**

- **A news article is a row, not a file.** `news_node` and
  `news_article` are two more tables in the store that already holds
  the inbox and the chat log — schema version 3. mhxd's
  directory-of-RFC-822-files layout is the *importer's* input, never
  the native format, exactly as ROADMAP.md said it would be.
- **Threading is a materialized preorder path**, not a recursive query
  and not a client-side reconstruction. Each article stores its root,
  its depth and a `path` blob of concatenated ancestor ids, so a thread
  comes back in display order from one indexed range scan.
- **Attachments are durable and content-addressed**, in a `BlobStore`
  of their own — *not* the 24-hour in-memory `MediaStore` of
  [inline-media.md](inline-media.md). A chat image is a moment; a news
  article is a record, and a record whose picture evaporates overnight
  is not a record. The bytes still go through `hxd-media`'s pipeline,
  because validating and re-encoding hostile image bytes is the same
  problem wherever they land.
- **Attachment authorization is by access bit, not by a captured set.**
  Inline media fixes an audience at relay time because a chat line has
  one. A news article is *published*: its audience is everyone holding
  `read_news`, now and later. This is a deliberate departure from
  inline-media.md §5 and the reason the two stores are separate.
- **Legacy clients get a derivative.** The 1.5 wire's article parts are
  capped at 65 535 bytes by the chunk header, so a 2 MiB photo cannot
  ride it. `hxd-media` re-encodes each attachment once at post time
  into a ≤ 60 000-byte, ≤ 1024 px version, and *that* is what a 1.5
  client fetches with `GETTHREAD`. The canonical bytes are what an ng
  client gets.
- **Bodies are markdown, and the server renders a plain-text part.** The
  1.5 article is natively multipart with per-part MIME types, so an
  article ships `text/markdown` and `text/plain` and each client takes
  what it understands — the same move as the image derivative, one layer
  up. The server parses markdown and **never renders HTML**; drawing is
  the client's job, which is why there is no XSS surface here at all.
- **References are extracted, not rewritten.** `[text](news:51)` and the
  `#51` shorthand become rows in a `news_ref` edge table at post time;
  the body is stored exactly as typed. The edge is indexed both ways, so
  backlinks cost nothing.
- **Search is FTS5 over the rendered text.** The store's SQLite already
  has FTS5 compiled in, so a full-text index is a table and a query
  compiler, not a dependency. The query grammar is ours and closed — a
  malformed search returns results, never an error.
- **Off unless configured**, like the inbox, the chat log and media. A
  server with no `[news]` section answers every news request the way a
  server without the feature does.

---

## 1. What exists to build on

Almost all of the wire knowledge is already in the tree, which is why
this is a design document and not a research one.

- **`hxproto` knows the 1.5 news wire.** On the reply side,
  `parse_dirlist` and `parse_catlist` with their `parse_news_folderitem`
  / `parse_news_categoryitem` entries (including the category guid and
  the add/delete serial numbers) and `parse_news_thread_reply`; on the
  request side, `build_news_dirlist_chunks`, `build_news_catlist_chunks`,
  `build_news_getthread_chunks`, `build_news_post_thread_chunks`,
  `build_news_mkcat_chunks`, `build_news_mkdir_chunks` and
  `build_news_delete_thread_chunks`. They exist because GtkHx is a news
  client; the server side is the same tables read the other way.
  **One gap:** `ClientHdr` enumerates only `GetThread` (`0x190`) and
  `PostThread` (`0x19a`) — the five directory opcodes (`0x172`, `0x173`,
  `0x17c`–`0x17e`) have builders but no enum variants, so W8 opens with
  an hx-libs change and a pin bump, which is a deliberate act with a
  full test run behind it in both consumers.
- **The access bits are already allocated and already parsed**:
  `READ_NEWS` (20), `POST_NEWS` (21), `DELETE_ARTICLES` (33),
  `CREATE_CATEGORIES` (34), `DELETE_CATEGORIES` (35),
  `CREATE_NEWS_BUNDLES` (36), `DELETE_NEWS_BUNDLES` (37) in
  `hxd-core/src/access.rs`. News is the only large subsystem left whose
  permission vocabulary needs nothing new.
- **The store conventions are settled**: one SQLite file behind a
  mutex, WAL, unix seconds at the boundary, `SCHEMA_VERSION` with a
  migration arm per bump, a conformance suite both implementations are
  run against (`hxd-core/src/inbox/conformance.rs`).
- **The image pipeline is built.** `hxd-media` sniffs, walks the
  container to its exact end, probes the header under limits, decodes
  bounded, applies EXIF orientation and re-encodes with no ancillary
  data. News reuses all of it and adds one call: re-encode again,
  smaller, for the legacy wire.
- **The moderation vocabulary is built**: a `moderation` audit table, a
  `report` table, `[extra] moderate` resolved on `Account`, and a
  `media_block` table keyed on canonical SHA-256 — which is exactly the
  key a content-addressed blob store uses.
- **mhxd is readable** (`src/hxd/tnews.c`) for the behavioral questions
  the SDK does not answer: how a path resolves to a directory, that an
  article file is RFC-822 headers plus a body, that `MESSAGE-ID` and
  `REFERENCES` are the id and the parent, and that the reference server
  caps a body at `0xffff`.

## 2. The shape of the thing

Four kinds of object, and the 1.5 wire's containment rules are kept
because they cost ng nothing and keep the two wires isomorphic:

```
  root
   ├── bundle "Projects"          (a folder; holds bundles and categories)
   │     └── category "hxd-ng"    (holds articles, and only articles)
   │           ├── article 41  "Phase 4 is open"
   │           │     ├── article 44  "Re: Phase 4 is open"
   │           │     └── article 47  "Re: Phase 4 is open"
   │           │           └── article 51  "Re: Re: Phase 4 is open"
   │           └── article 42  "Attachment sizes"
   └── category "Announcements"
```

- A **bundle** (the SDK's "news folder") contains bundles and
  categories. Nesting is unbounded in principle and capped by
  `[news] max_node_depth` (default 16) in practice.
- A **category** contains articles and nothing else.
- An **article** has a subject, a body, an author, a time, zero or more
  attachments, and an optional parent article *in the same category*.
- A **thread** is an article with no parent plus its transitive
  replies.

Enforcing "articles only in categories" and "a reply is in its parent's
category" in the domain is what makes §11 a mapping and not a
translation.

## 3. The domain: `hxd-core/src/news.rs`

### 3.1 Types

```rust
pub type NodeId = u64;
pub type ArticleId = u32;      // §3.2 — the ceiling is the legacy wire's

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind { Bundle, Category }

pub struct Node {
    pub id: NodeId,
    pub parent: Option<NodeId>,   // None = a root-level node
    pub kind: NodeKind,
    pub name: String,             // unique among its parent's children
    pub guid: [u8; 16],           // the 1.5 CATEGORYITEM guid; stable forever
    pub add_sn: u32,              // bumped on every post into this category
    pub delete_sn: u32,           // bumped on every delete from it
    pub children: u32,            // sub-nodes for a bundle, articles for a category
    pub created_at: SystemTime,
}

pub struct Author {
    pub nick: String,                        // as it was when they posted
    pub login: Option<String>,               // None for a guest
    pub fingerprint: Option<[u8; 32]>,       // identity, where there is one
}

pub struct Article {
    pub id: ArticleId,
    pub category: NodeId,
    pub parent: Option<ArticleId>,
    pub root: ArticleId,          // == id for a thread starter
    pub depth: u16,               // 0 for a thread starter
    pub author: Author,
    pub subject: String,
    pub body: String,             // verbatim as typed; UTF-8, LF endings
    pub mime: BodyType,           // how to read `body`
    pub plain: Option<String>,    // the §5.4 downgrade; None when body is plain
    pub at: SystemTime,
    pub flags: ArticleFlags,      // DELETED
    pub attachments: Vec<Attachment>,
    pub refs: Vec<Reference>,     // resolved outbound references, §5.3
    pub referenced_by: u32,       // inbound count; the list is `news_refs`
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyType { Plain, Markdown }

/// A resolved outbound reference. Unlike `Author`, this is *current*
/// state, not a snapshot: a reference is a pointer, so it reports the
/// target as it stands now.
pub struct Reference {
    pub id: ArticleId,
    pub subject: String,
    pub author_nick: String,
    pub at: SystemTime,
    pub deleted: bool,
}

/// A thread as a listing shows it: the starter plus what happened to it.
pub struct ThreadHead {
    pub article: Article,         // the starter; body included
    pub replies: u32,
    pub last_at: SystemTime,
    pub last_id: ArticleId,
}

pub struct Attachment {
    pub handle: [u8; 16],         // the wire id; random, not the hash
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,               // canonical size
    pub legacy_bytes: Option<u32>,// the ≤60 000 B derivative, when one exists
    pub name: Option<String>,     // the uploader's file name, for display only
}
```

`Author.nick` is a snapshot, deliberately: a news article says who
posted it at the time, and a rename two years later does not rewrite
history. `login` and `fingerprint` are what moderation selects on —
the same two columns, for the same reason, as `chat_line` and
`message`.

### 3.2 Ids

`NodeId` is a u64 rowid. `ArticleId` is a **u32**, because the 1.5 wire
says so: `CatPost.postid`, `CatPost.parentid` and the `THREADID` chunk
are all u32 big-endian, and an id the legacy wire cannot carry is an id
that cannot be replied to from GtkHx. Ids are globally unique and never
reused (SQLite `AUTOINCREMENT`), which is more than the legacy wire
needs — there, an id is only ever interpreted relative to a `NEWSPATH`
— and exactly what an ng client wants, since `news_article { id }`
then needs no category alongside it.

The ceiling is 4 294 967 295 articles over the life of a server. A
server that reaches it has problems this document is not about; §17
keeps the question of a wider id for an ng-only future.

### 3.3 Threading, and why there is a `path` column

A thread must come back in display order — a reply directly under the
article it answers, siblings oldest-first — and it must come back
without a recursive query, because the store trait is synchronous and
called from `Core`.

Each article stores a `path`: the big-endian u32 ids of its ancestors
and itself, concatenated, root first. Article 41 has path `[41]`;
its reply 44 has `[41, 44]`; 47's reply 51 has `[41, 47, 51]`. Ordering
a category's articles by `path` **is** preorder, byte comparison does
it, and one index (`category, path`) serves both "the whole thread" and
"the thread's next page". The path is built at insert from the parent's,
which is one indexed read, and `[news] max_depth` (default 32) bounds
it to 128 bytes.

The alternative — sending a flat list of `(id, parent)` and letting the
client build the tree, which is what CATLIST does — is what the legacy
wire will keep doing (§11.3), because it has to. The ng wire should not
inherit a 1996 client's job.

### 3.4 The trait

```rust
pub struct NewPost {
    pub category: NodeId,
    pub parent: Option<ArticleId>,
    pub author: Author,
    pub subject: String,
    pub body: String,              // verbatim
    pub mime: BodyType,
    pub plain: Option<String>,     // rendered by the caller, §5.2
    pub refs: Vec<ArticleId>,      // extracted by the caller, already deduped
    pub at: SystemTime,
    pub attach: Vec<[u8; 16]>,     // staged handles, in display order
}

pub struct SearchQuery {
    pub terms: CompiledQuery,      // §6.2 — never a raw user string
    pub category: Option<NodeId>,  // that category and its descendants
    pub from: Option<String>,
    pub before: Option<SystemTime>,
    pub after: Option<SystemTime>,
    pub offset: usize,
    pub limit: usize,
}

pub struct Hit {
    pub article: ArticleId,
    pub subject: String,
    pub author_nick: String,
    pub category: NodeId,
    pub at: SystemTime,
    pub snippet: String,
    pub marks: Vec<(u32, u32)>,    // byte ranges in `snippet` that matched
}

pub struct SearchPage { pub hits: Vec<Hit>, pub total: u32, pub capped: bool }

pub struct ThreadQuery {
    pub category: NodeId,
    pub before: Option<ArticleId>, // cursor on the thread root
    pub after: Option<ArticleId>,
    pub order: ThreadOrder,        // Created | Recent
    pub limit: usize,              // clamped by the caller
}

pub struct ThreadPage { pub threads: Vec<ThreadHead>, pub has_more: bool }
pub struct ArticlePage { pub articles: Vec<Article>, pub has_more: bool }

pub trait NewsStore: Send + Sync + 'static {
    // Tree
    fn nodes(&self, parent: Option<NodeId>) -> Result<Vec<Node>, StoreError>;
    fn node(&self, id: NodeId) -> Result<Option<Node>, StoreError>;
    fn create_node(&self, parent: Option<NodeId>, kind: NodeKind, name: &str)
        -> Result<Node, StoreError>;
    fn rename_node(&self, id: NodeId, name: &str) -> Result<bool, StoreError>;
    fn delete_node(&self, id: NodeId) -> Result<u64, StoreError>; // articles removed

    // Articles
    fn post(&self, p: &NewPost) -> Result<ArticleId, StoreError>;
    fn article(&self, id: ArticleId) -> Result<Option<Article>, StoreError>;
    fn threads(&self, q: &ThreadQuery) -> Result<ThreadPage, StoreError>;
    fn thread(&self, root: ArticleId, after: Option<ArticleId>, limit: usize)
        -> Result<ArticlePage, StoreError>;
    fn category_all(&self, category: NodeId, max: usize)
        -> Result<Vec<Article>, StoreError>;      // the legacy CATLIST shape
    fn tombstone(&self, id: ArticleId, by: &str, at: SystemTime)
        -> Result<Option<Article>, StoreError>;
    fn by_author(&self, who: &Author, since: SystemTime)
        -> Result<Vec<ArticleId>, StoreError>;    // moderation purge

    // References (§5.3) — written with the article, read on the way out
    fn refs_from(&self, id: ArticleId) -> Result<Vec<Reference>, StoreError>;
    fn refs_to(&self, id: ArticleId, limit: usize)
        -> Result<Vec<Reference>, StoreError>;

    // Search (§6)
    fn search(&self, q: &SearchQuery) -> Result<SearchPage, StoreError>;
    fn reindex(&self) -> Result<u64, StoreError>;

    // Retention
    fn prune(&self, max_age: Option<Duration>, now: SystemTime)
        -> Result<u64, StoreError>;
}
```

Synchronous, like `MessageStore` and `ChatLog`, for the reason their
module docs give: `Core` is sync all the way down, and the frontends
already know to call through `off_reactor`.

`category_all` exists because the 1.5 wire has no pagination — a
`NEWSCATLIST` reply is the whole category — and a trait that could not
express that would push the legacy binding into looping over a
paginated API to rebuild something it must send whole. `max` is
`[news] legacy_catlist_max` (default 2000, oldest dropped), because a
category with 50 000 articles must not build a 50 MB frame for a 1.5
client.

### 3.5 What `Core` adds

`Core` gains `news: Option<Arc<dyn NewsStore>>` and `blobs:
Option<Arc<dyn BlobStore>>`, beside `inbox` and `history`, with the same
comment those carry: **they live on `Core` and not in `RosterInner`,
because store calls are disk I/O and must never happen under the roster
lock.**

The methods are thin: check the access bit, clamp the sizes, call the
store, and — for a post or a delete — build the event and fan it out.
Only `news_post` and the delete paths touch the roster at all.

## 4. The store: schema version 3

```sql
CREATE TABLE news_node (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  parent     INTEGER REFERENCES news_node(id),
  kind       INTEGER NOT NULL,              -- 0 bundle, 1 category
  name       TEXT    NOT NULL,
  guid       BLOB    NOT NULL,              -- 16 bytes, stable for the node's life
  add_sn     INTEGER NOT NULL DEFAULT 1,
  delete_sn  INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX news_node_sibling ON news_node (IFNULL(parent, 0), name);

CREATE TABLE news_article (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,   -- constrained to u32, §3.2
  category   INTEGER NOT NULL REFERENCES news_node(id),
  parent     INTEGER REFERENCES news_article(id),
  root       INTEGER NOT NULL,
  path       BLOB    NOT NULL,              -- BE u32 ancestor ids, root first
  depth      INTEGER NOT NULL,
  nick       TEXT    NOT NULL,
  login      TEXT,
  login_fp   TEXT,
  subject    TEXT    NOT NULL,
  body       TEXT    NOT NULL,             -- verbatim as typed
  mime       TEXT    NOT NULL DEFAULT 'text/plain',
  plain      TEXT,                         -- the §5.4 downgrade; NULL when body is plain
  at         INTEGER NOT NULL,
  deleted_at INTEGER,
  deleted_by TEXT
);
CREATE INDEX news_article_thread ON news_article (category, path);
CREATE INDEX news_article_roots  ON news_article (category, id) WHERE parent IS NULL;
CREATE INDEX news_article_author ON news_article (login_fp, login, id);
CREATE INDEX news_article_at     ON news_article (at);

CREATE TABLE news_ref (
  src  INTEGER NOT NULL REFERENCES news_article(id),
  dst  INTEGER NOT NULL REFERENCES news_article(id),
  ord  INTEGER NOT NULL,                   -- order of appearance in the body
  PRIMARY KEY (src, dst)
) WITHOUT ROWID;
CREATE INDEX news_ref_dst ON news_ref (dst, src);

CREATE VIRTUAL TABLE news_fts USING fts5(
  subject, body, author,
  content = 'news_article',
  content_rowid = 'id',
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE news_blob (
  hash        BLOB PRIMARY KEY,             -- SHA-256 of the canonical bytes
  mime        TEXT    NOT NULL,
  width       INTEGER NOT NULL,
  height      INTEGER NOT NULL,
  bytes       INTEGER NOT NULL,
  derivative  INTEGER,                      -- size of the legacy derivative, or NULL
  refs        INTEGER NOT NULL DEFAULT 0,
  at          INTEGER NOT NULL
);

CREATE TABLE news_attach (
  handle      BLOB PRIMARY KEY,             -- 16 random bytes: the wire id
  hash        BLOB    NOT NULL REFERENCES news_blob(hash),
  article     INTEGER REFERENCES news_article(id),   -- NULL while staged
  ord         INTEGER NOT NULL DEFAULT 0,
  name        TEXT,
  uploader    TEXT,
  uploader_fp TEXT,
  staged_at   INTEGER NOT NULL
);
CREATE INDEX news_attach_article ON news_attach (article, ord);
CREATE INDEX news_attach_staged  ON news_attach (staged_at) WHERE article IS NULL;
```

`guid`, `add_sn` and `delete_sn` exist because `HTLC_DATA_CATEGORYITEM`
carries them (`parse_news_categoryitem`: `ntype 3` is `count(2) +
guid(16) + addsn(4) + deletesn(4)` before the name). A 1.5 client uses
them to decide whether its cached view of a category is stale. They are
cheap to maintain — two counters bumped on post and delete — and a
column we do not fill is a client refetching everything forever, so
they are filled from day one even though the legacy binding lands last.

`news_ref` is `WITHOUT ROWID` because it is a pure edge table read by
both of its columns and never by a rowid; the primary key doubles as the
forward index and `news_ref_dst` is the reverse one, which is what makes
`referenced_by` a lookup rather than a scan.

`news_fts` is an external-content table over `news_article`, so it stores
no text of its own (§6.1). Because FTS5 external content trusts the
content table to stay in step, every write that touches `subject`,
`plain`, `body` or an attachment name writes the index in the **same
transaction** — never in a trigger reaching across one, and never
best-effort after a commit.

The migration from version 2 is additive: the new tables, the virtual
table, and their indexes. No `ALTER` on an existing table — the shape
the version-2 arm already established.

## 5. Body text: markdown, references, and the plain-text downgrade

### 5.1 The decision

Markdown could be purely a client convention: the server stores bytes,
clients render them. That reading is a supported configuration (§5.5,
`[news] markdown = "source"`) and it is what "this is just a client-side
thing" would mean. It is not the default, for three reasons that only
became visible once references and search were on the table.

1. **A 1.5 client would see the source.** `**bold**` is survivable;
   `[the sizes thread](news:51)` is not. The multipart article the legacy
   wire already has (§11.3) exists for exactly this: ship `text/markdown`
   and `text/plain` as two parts and let each client take the one it
   understands. That is the same move as the image derivative in §7.3,
   and it needs the server able to produce the plain part.
2. **References have to be extracted somewhere.** A reference is a fact
   about the body — which article it points at — and the server is the
   only party that can resolve it once and hand every reader the answer.
   Extracting it means reading the body's structure.
3. **Search wants text, not syntax.** An index built over markdown
   source matches link destinations, ranks `**important**` differently
   from `important`, and returns snippets full of asterisks.

So: **the server parses markdown, renders plain text, and never renders
HTML.** That last clause is the whole security posture. The server's
output is text; how a client draws it is the client's business; and the
XSS surface a markdown-to-HTML server would open never exists here.

### 5.2 Where it lives

`hxd-markdown`, behind a `BodyRenderer` trait in `hxd-core` and a
`markdown` Cargo feature — the `hxd-media` and `hxd-voice` shape, for the
same reason: a server that wants none does not link a parser.

```rust
pub struct Rendered {
    pub plain: String,           // what a legacy client and the index get
    pub refs: Vec<ArticleId>,    // in order of appearance, deduplicated
}

pub trait BodyRenderer: Send + Sync + 'static {
    fn render(&self, source: &str) -> Rendered;
}
```

Implemented on [`pulldown-cmark`](https://crates.io/crates/pulldown-cmark):
pure Rust, CommonMark, and an event stream — so the plain-text render is
a fold over events and the reference scan is one match arm on
`Tag::Link`. The dialect is CommonMark minus two things:

- **Raw HTML is literal text**, never interpreted, on the way in and on
  the way out.
- **No images by URL.** An article's pictures are its attachments. A body
  that can fetch `https://tracker.example/pixel.gif` is a body that
  reports every reader's address to a stranger, and news is read by more
  people over more time than anything else on this server.

Rendering happens once, at post time, off the reactor. Never on a read.

### 5.3 References

The canonical form is a markdown link whose destination is the `news:`
scheme:

```markdown
This was settled in [the sizes thread](news:51), and #47 has the numbers.
```

`#<digits>` is the shorthand, recognized by a scanner in `hxd-core` — not
by the markdown parser — when it is delimited by whitespace or
punctuation and is not the `#` of an ATX heading. The scanner runs on
**plain bodies too**, which is what lets a GtkHx user typing `see #51`
produce a real link in an ng client's rendering. Reference extraction
therefore works with the `markdown` feature off and with a 1996 client at
the other end.

Three rules carry it:

- **The body is stored verbatim.** The server never rewrites what someone
  typed. References go in a side table; the body is the body.
- **References resolve once, at post time.** An id naming no article is
  not a reference — it is the digits the author typed, and it stays that.
  An article created later does not retroactively become a target. This
  is what keeps a read from re-scanning every body it serves.
- **A reference to an article that is later deleted survives**, resolving
  to `{ id, deleted: true }`. The link stays, its target says it is gone,
  and the thread still reads correctly.

A resolved reference reports the target **as it stands now** — current
subject, current deleted state — which is the opposite of `Author.nick`
being a snapshot (§3.1), and deliberately: an author is who posted, a
reference is a pointer.

`news_ref` is indexed both ways, so **backlinks are free**. An article
carries `referenced_by` as a count and `news_refs { id }` lists the
articles pointing at it. A reference is not a reply: `parent` is
structural and puts an article inside a thread, a reference is textual
and crosses threads and categories.

At most `[news] max_refs` (default 32) references are recorded per
article; past that they stay as text.

Whether referencing someone's article should notify them is the mention
problem push-notifications.md §11 already has open, and it gets the same
answer for now: no. §17.

### 5.4 The plain-text downgrade

`render()` produces the text a 1.5 client sees:

- Emphasis and strong markers are dropped; the words stay.
- A heading becomes its text followed by a blank line.
- A bullet list becomes `- ` lines, an ordered list `1. ` lines —
  markdown's plain-text ancestry doing the work for us.
- A fenced code block becomes its contents indented four spaces, fences
  gone. A block quote becomes `> ` lines.
- `[text](news:51)` becomes `text (news #51)`; `[text](https://…)`
  becomes `text (https://…)`; a bare `#51` is left exactly as typed.
- A table becomes its cells, tab-separated, one row per line. Nobody is
  happy about this and nobody has a better answer for a 1996 text view.

**The downgrade can be longer than the source** — every link grows — so
it is capped independently at `max_body` and truncated at a character
boundary with a trailing `…`. The truncation affects the legacy part
only; the source is untouched and an ng client sees all of it.

### 5.5 The knob

`[news] markdown` takes three values, and references and search work
under all three — only their quality varies.

| Value | Behavior |
|---|---|
| `"render"` (default) | Bodies may declare `text/markdown`; the downgrade is generated; the index is built over it. |
| `"source"` | Markdown is accepted and stored, no downgrade is generated, a legacy client is served the source. The `markdown` feature is not required. This is the pure client-side reading, for an operator who does not want a parser in their server. |
| `"off"` | `text/markdown` is refused with `bad_request`. Every body is `text/plain`. |

## 6. Search and the news index

### 6.1 FTS5, and what it costs

SQLite's FTS5 is already compiled into the store's SQLite: `rusqlite`'s
`bundled` build has it with no additional feature and no additional
dependency (verified against the pinned 0.32 build, SQLite 3.46). Search
therefore costs a table and some care, not a search engine.

```sql
CREATE VIRTUAL TABLE news_fts USING fts5(
  subject, body, author,
  content = 'news_article',
  content_rowid = 'id',
  tokenize = 'unicode61 remove_diacritics 2'
);
```

An **external-content** table: the text is not stored twice, FTS5 reads
it from `news_article` through the rowid. The index is written in the
same transaction as the article — on post, on tombstone, and on a
moderation purge. A tombstoned article is *deleted from the index*, not
blanked in it, which is what makes a deletion real for search as well as
for reads.

What is indexed:

- `subject`, weighted heaviest.
- `body` — **the plain-text downgrade where there is one**, the body
  otherwise. This is the second job that column does, and half the
  argument for computing it.
- `author` — nick and login, so `from:alice` is a query rather than a
  separate filter.
- Attachment file names, appended to `body`. A
  `screenshot-of-the-crash.png` is a searchable fact about an article.

### 6.2 The query language is ours, not FTS5's

Handing user input to `MATCH` is how a search box returns
`fts5: syntax error near "-"`. The request takes a query string and the
server compiles it into an FTS5 expression from a closed grammar:

| Input | Meaning |
|---|---|
| `phase 4` | both terms, anywhere |
| `"phase 4"` | the phrase |
| `-legacy` | exclude |
| `subject:sizes` | the term in the subject only |
| `from:alice` | the term in the author only |
| `sizes*` | prefix |

Everything else — every FTS5 operator, every stray quote or paren — is
escaped into a literal term. **A malformed query returns results, never
an error.** Terms are capped at 16 per query and 64 bytes each, so the
compiled expression is bounded before SQLite sees it.

### 6.3 Results, ranking and paging

Ranking is BM25 with `subject` weighted 10× and `author` 3×. Each hit
carries an FTS5 `snippet()` of the body with the matched terms marked;
the server returns the snippet text plus match offsets rather than
markup, so a client highlights in its own style.

**Paging is by offset, not by cursor, and that is a deliberate
exception** to the id-cursor rule every other paginated request in this
design and in hotline-ng.md follows. A cursor works when the order is
stable, and relevance order is not: one post landing between two pages
reorders everything after it. So `news_search` takes `offset` and
`limit`, caps the reachable set at `[news] search_max_results` (default
500), and reports `total` from FTS5's own count so a client can say
"500+" honestly. A client that wants stable paging asks for
`order: "recent"`, which *is* id-ordered, and pages it with a cursor like
everything else.

Scoping: `category?` (that category and its descendants), `from?`, and
`before?` / `after?` — which are **times, not ids**, because a date range
is what a person means by narrowing a search.

`[news] search_per_minute` (default 30 per session) rate-limits it: a
full-text query is a different unit of work from a keyed read, and this
endpoint faces phones on the open internet.

### 6.4 The memory store, and reindexing

`MemoryNews` implements search as a naive tokenized scan so the
conformance suite (§14) can assert *which* articles a query returns
against both implementations. It does not implement ranking, and the
conformance suite therefore asserts result sets and never order; ranking
is asserted in the SQLite store's own tests.

`hxd news-reindex` rebuilds `news_fts` from `news_article`. It is needed
after an mhxd import (§11.6), after a `markdown` mode change that alters
every downgrade, and as the repair for an index that has drifted.

### 6.5 The legacy wire cannot search

There is no 1.5 transaction for it and none to borrow. A GtkHx user
browses; an ng user searches. This is the one place in the design where
the two wires are not equivalent, and synthesizing a "search results"
category to paper over it would be a lie about what a category is. §17
has what an extension would need to look like.

## 7. Attachments

### 7.1 Why not the `MediaStore`

[inline-media.md](inline-media.md) is explicit that its handles live 24
hours in memory, that nothing touches disk, and that a restart forgets
them all — and it is right, because the spec it implements tells
clients not to cache a handle across sessions and because a chat image
whose moment has passed is not worth an operations problem.

News inverts every one of those premises. An article is read weeks
after it is posted, by people who were not there, and it is read
*because* it is durable. Reusing the ephemeral store would ship a
feature whose defining behavior is that it stops working overnight.

So attachments get their own store, and the two never share a handle
namespace. What they *do* share is `hxd-media`: the sniff, the
container walk, the bounded probe and decode, the orientation fix and
the metadata-free re-encode are the same work on the same hostile
input, and duplicating it would be the actual mistake.

### 7.2 The blob store

```rust
pub struct BlobId(pub [u8; 32]);          // SHA-256 of the canonical bytes

pub trait BlobStore: Send + Sync + 'static {
    fn put(&self, bytes: &[u8]) -> Result<BlobId, StoreError>;
    fn get(&self, id: &BlobId) -> Result<Option<Vec<u8>>, StoreError>;
    fn put_derivative(&self, id: &BlobId, bytes: &[u8]) -> Result<(), StoreError>;
    fn derivative(&self, id: &BlobId) -> Result<Option<Vec<u8>>, StoreError>;
    fn remove(&self, id: &BlobId) -> Result<bool, StoreError>;
    fn total_bytes(&self) -> Result<u64, StoreError>;
}
```

The first implementation is a directory: `<blobs>/ab/cd/abcdef…` and
`<blobs>/ab/cd/abcdef….l` for the derivative, written to a temporary
name and renamed, fsynced before the row that references them is
committed. Content addressing means two people posting the same
screenshot store it once and a re-post costs a refcount increment.

**The refcount is the deletion rule.** `news_blob.refs` counts
`news_attach` rows; a delete decrements, and zero means the files are
unlinked and the row is dropped. A staged attachment holds a reference
too, so an upload nobody ever posted is collected by the stage sweep
and not by a race. An orphan sweep — files with no row, rows with no
files — runs from the same hourly task as inbox retention, logs what it
finds, and unlinks only files older than the stage TTL so an upload in
flight is never swept.

This is the first user content hxd-ng writes to disk, which is worth
saying plainly: it is a thing to back up, a thing a purge must actually
unlink, and a thing that needs shared storage or node affinity when
Phase 8 arrives — the same constraint [file-sources.md](file-sources.md)
identifies for the file area, and the two probably want one answer.

### 7.3 The pipeline, and the legacy derivative

Posting with attachments is two steps, so that a 2 MiB upload is never
inside a WebSocket frame and never inside a request the roster is
waiting on:

1. **Stage.** `POST /news/blob` with the bytes. `hxd-media` runs the
   full §3 pipeline of inline-media.md — sniff, walk to the exact end,
   probe under limits, bounded decode on `spawn_blocking`, orientation,
   metadata-free re-encode, format follows source. The canonical bytes
   are hashed, checked against `media_block` (a hash a moderator has
   banned never comes back, moderation.md §3.2), written to the blob
   store, and given a random 16-byte handle with `article IS NULL`.
   The handle expires after `[news.attach] stage_ttl` (default 30 min).
2. **Commit.** `news_post` names the staged handles. They must belong
   to the caller, be unexpired, and number at most `max_count`. The
   post and the `UPDATE news_attach SET article = ?` are one
   transaction, so an article never references a handle that a
   concurrent sweep is deleting.

The **legacy derivative** is generated at stage time, once, on the same
blocking thread: the decoded image re-encoded to at most 1024 px on its
long edge and at most 60 000 bytes, JPEG for anything opaque and PNG
otherwise, quality stepped down until it fits, and dropped entirely if
it cannot. 60 000 is the number inline-media.md §6 already uses and the
one GtkHx clamps to — it leaves room in a 65 535-byte chunk for the
fields around the payload. It costs one extra encode per upload and it
is the difference between a 1.5 client seeing the picture and seeing a
line of text about it.

### 7.4 Limits

| Limit | Default | Where |
|---|---|---|
| Attachment size (uploaded) | 2 MiB | HTTP, before reading the body |
| Attachments per article | 8 | domain, at commit |
| Canonical formats | JPEG, PNG, GIF | `hxd-media`, at the sniff |
| Dimension / pixels / frames | inline-media's | `hxd-media` |
| Legacy derivative | 60 000 B, 1024 px | `hxd-media`, at stage |
| Staged handle lifetime | 30 min | store, swept hourly |
| Uploads per account | 20 / hour | domain |
| Total blob bytes | 8 GiB | store; a post over it is refused, never evicted |
| Article body | 65 535 bytes | domain — §11.4 says why that number |
| Plain downgrade | 65 535 bytes | renderer, truncated at a char boundary (§5.4) |
| References per article | 32 | domain, at extraction |
| Search terms per query | 16, 64 B each | query compiler (§6.2) |
| Search results reachable | 500 | store (§6.3) |
| Searches per session | 30 / minute | frontend |
| Subject | 255 bytes | domain — the 1.5 pstring |

The total cap is **refused, not evicted**, which is the opposite of the
`MediaStore`'s rule and follows from the same premise: evicting the
oldest chat image loses a moment, evicting the oldest news attachment
silently guts the archive. A server at its cap needs an operator, not a
heuristic.

**v1 accepts images and nothing else.** Not because the wire cannot
carry more — the 1.5 article part carries a MIME type precisely so it
can — but because "validate and re-encode" is a property we can only
offer for formats `hxd-media` understands, and serving opaque bytes
someone uploaded is the file area's problem, with the file area's
design. §17 keeps the question.

## 8. Access

Every bit this needs is already allocated and already parsed:

| Act | Bit |
|---|---|
| Read anything | `READ_NEWS` (20) |
| Post an article or a reply | `POST_NEWS` (21) |
| Delete someone else's article | `DELETE_ARTICLES` (33) |
| Create a category | `CREATE_CATEGORIES` (34) |
| Delete a category | `DELETE_CATEGORIES` (35) |
| Create a bundle | `CREATE_NEWS_BUNDLES` (36) |
| Delete a bundle | `DELETE_NEWS_BUNDLES` (37) |

Two things the bitmap does not cover, both `[extra]` keys rather than
squatted bits, for the reason hotline-ng.md §4/D5 gives:

- **`[extra] attach_news`**, defaulting to the account's `SEND_MEDIA`
  (57). Someone trusted to put an image in chat is trusted to put one
  in an article; an operator can say otherwise either way.
- **`[extra] news_self_delete`**, default `true`: an author may delete
  their own article without bit 33. This is a **deliberate deviation**
  from period behavior, where deletion is bit 33 or nothing. It is
  server-local policy, it never crosses either wire as a bit, and a
  server that wants the period answer sets it `false`.

Deleting a category deletes its articles, which decrements every blob
refcount underneath it; deleting a bundle requires it to be empty,
because "delete this folder and the four hundred articles in it" should
be four hundred audit rows or a refusal, not one click.

Moderation follows moderation.md's ladder unchanged: a moderator may
not delete an article by a session holding `cant_be_disconnected` (23)
unless they hold `delete_users` (15).

## 9. The ng wire

### 9.1 Login reply

`caps` gains `"news"`, and a `news` block rides beside `media`,
`history`, `inbox` and `video`, present exactly when the cap is:

```jsonc
"news": {
  "post": true,                  // this session may post
  "attach": true,                // …and may attach
  "max_body": 65535,
  "max_subject": 255,
  "max_attachments": 8,
  "max_attachment_bytes": 2097152,
  "types": ["image/jpeg", "image/png", "image/gif"],
  "markdown": "render",          // render | source | off — §5.5
  "body_types": ["text/plain", "text/markdown"],
  "max_refs": 32,
  "search": true,                // §6; false on a build without FTS5
  "search_max_results": 500
}
```

`post` and `attach` are this session's resolved permissions, not the
server's ceiling — the same courtesy `moderator` does in
moderation.md §2, so a client can gray out a compose button instead of
discovering the refusal after the user has typed.

### 9.2 Requests

| `req` | params | ok |
|---|---|---|
| `news_tree` | `parent?` (node id; absent = root), `depth?` (1–4, default 1) | `{ "nodes": [ … ] }` |
| `news_threads` | `category`, `before?` / `after?` (thread root id), `order?` (`"created"` \| `"recent"`, default `"created"`), `limit?` (1–200, default 50) | `{ "threads": [ … ], "has_more": bool }` |
| `news_thread` | `root`, `after?` (article id), `limit?` (1–100, default 25) | `{ "articles": [ … ], "has_more": bool }` |
| `news_article` | `id` | `{ "article": { … } }` |
| `news_post` | `category`, `parent?`, `subject`, `body`, `mime?` (`"text/plain"` \| `"text/markdown"`, default plain), `attach?` (handles) | `{ "id": 51 }` |
| `news_delete` | `id`, `reason?` | `{}` |
| `news_refs` | `id`, `limit?` (1–200, default 50) | `{ "referenced_by": [ … ] }` — the articles pointing at this one |
| `news_search` | `q`, `category?`, `from?`, `before?` / `after?` (times), `offset?`, `limit?` (1–50, default 20) | `{ "hits": [ … ], "total": 137, "capped": false }` |
| `news_node_create` | `parent?`, `kind` (`"bundle"` \| `"category"`), `name` | `{ "node": { … } }` |
| `news_node_rename` | `id`, `name` | `{}` |
| `news_node_delete` | `id` | `{ "articles": 12 }` |

Error codes, on top of the universal set: `no_news` (the server has
none — distinct from `access_denied`, which is about you),
`no_such_node`, `no_such_article`, `not_a_category` (posting into a
bundle, or nesting a category under a category), `wrong_category` (a
reply whose parent lives elsewhere), `too_deep`, `no_such_media` (a
staged handle that is not yours or has expired — one answer for both,
as `chat` already does), `attachments_full`, `news_full` (the blob cap),
`name_taken`, `not_empty` (deleting a bundle with children), and
`bad_body_type` (`text/markdown` against a server in `markdown = "off"`).

There is deliberately **no error code for a bad search query**: §6.2
compiles anything into something, so `news_search` answers with results
or with an empty list.

Pagination follows the `history` request exactly: cursors are ids,
`before`/`after` are exclusive, `has_more` is computed by fetching
`limit + 1`, and the caller clamps the limit before the store sees it.

An `article` object:

```jsonc
{
  "id": 51,
  "category": 7,
  "parent": 47,
  "root": 41,
  "depth": 2,
  "from": { "nick": "Alice", "login": "alice",
            "fingerprint": "6htgz65…" },   // login/fingerprint absent for a guest
  "subject": "Re: Re: Phase 4 is open",
  "body": "This was settled in [the sizes thread](news:51).",
  "mime": "text/markdown",       // how to read "body"
  "at": 1789000000,
  "deleted": false,
  "attachments": [
    { "id": "…22 chars…", "type": "image/png",
      "width": 1600, "height": 900, "bytes": 412000, "name": "screenshot.png" }
  ],
  "refs": [                      // resolved once, at post time; current state
    { "id": 51, "subject": "Attachment sizes", "from": "Bob",
      "at": 1788900000, "deleted": false }
  ],
  "referenced_by": 3             // the list is a `news_refs` request
}
```

A `thread` object in `news_threads` is `{ "article": <article>,
"replies": 3, "last_at": …, "last_id": 51 }` — the starter in full,
because a listing that shows the first paragraph needs the body, and
counting a round trip per row is what a mobile client cannot afford.

**The `plain` downgrade never crosses the ng wire.** An ng client is
told the body's type and handed the source; rendering markdown is what
it is for. The downgrade exists for the legacy wire (§11.3) and for the
index (§6.1), and shipping it would be handing every client a second
copy of every body to ignore.

A deleted article keeps its id, its category, its parent and its time,
and loses its subject, body, author, attachments and outbound references.
Its inbound references survive, resolving to `deleted: true` (§5.3), so
an article elsewhere that pointed at it still says so. Its replies stay
where they are: a tombstone in the middle of a thread is what keeps the
conversation legible, and dropping it would reparent four replies onto
nothing.

### 9.3 Events

News is not chat, and most clients are not looking at it. Events are
therefore small — a header, never a body — and a client that cares
fetches.

| `ev` | data |
|---|---|
| `news_posted` | `{ "id", "category", "root", "parent", "subject", "from": { "nick" }, "at", "attachments": 1 }` |
| `news_deleted` | `{ "id", "category" }` |
| `news_node` | `{ "node": { … } }` — created or renamed |
| `news_node_deleted` | `{ "id" }` |

They go to every session holding `READ_NEWS`, which means they consume
a seq in every such session's outbox — including detached ones, where
they buffer like anything else. A client with no interest in news
ignores them by hotline-ng.md §5's rule and its seq accounting stays
gapless.

`news_posted` is what makes a badge possible, and it is deliberately
not a push notification: push is for messages addressed to you
(push-notifications.md §11), and a busy category would be a buzz a
minute. §17 keeps the question of per-category subscription.

### 9.4 Attachment bytes over HTTP

Two routes beside `/media` in `http.rs`, with the same bearer — the
session's public id and its secret token joined by a dot, looked up
constant-time on the hash the way `resume` does:

```
POST /news/blob
  Authorization: Bearer <session>.<token>
  Content-Type: image/jpeg | image/png | image/gif     (a hint; sniffing ignores it)
  Content-Length: ≤ max_attachment_bytes               (413 before reading otherwise)
  X-Attachment-Name: screenshot.png                    (optional, for display)
  <body: the image>

  201 { "blob": { "id": "…22 chars…", "type": "image/png",
                  "width": 1600, "height": 900, "bytes": 412000,
                  "expires_in": 1800 } }

GET /news/blob/{id}
  Authorization: Bearer <session>.<token>
  ?size=legacy                                         (optional: the derivative)

  200  Content-Type: image/png
       Content-Length, ETag: "<hash prefix>",
       Cache-Control: private, max-age=604800, immutable,
       X-Content-Type-Options: nosniff, Content-Disposition: inline,
       Content-Security-Policy: sandbox
       <canonical bytes>
```

Status mapping matches `/media`: 413 too large, 415 unsupported, 429
rate-limited with `Retry-After`, 400 malformed, 503 the decoder was
busy, 507 the blob cap. A download that fails for any reason is
**404** — one answer, so the route cannot be used to test whether a
handle exists.

Two differences from `/media`, both following from §7.1:

- **`immutable`, and a long max-age.** A news attachment's bytes never
  change — the handle names a content hash — so a client may cache it
  for a week. A chat handle could not say that.
- **Authorization is `READ_NEWS` plus a live article**, not a set
  captured at relay time. The handle resolves when the caller holds the
  bit and the attachment's article exists and is not tombstoned, or
  when the caller staged it and has not posted it yet. A tombstoned
  article's attachments stop resolving at once, which is what makes
  `news_delete` a real deletion on every wire.

## 10. Moderation and retention

News is durable content, so [moderation.md](moderation.md) extends to
it rather than being re-invented:

- **Delete is the existing redact**, with a new audit kind
  (`news_delete`) and a new `moderation.target_article` column. The
  audit row carries the article's subject, body, author and attachment
  hashes before they are cleared, so the record of what was removed
  survives the removal.
- **Purge** (moderation.md §3.3) grows a news arm: `by_author` selects
  a person's articles since a cutoff, and every one is tombstoned under
  one audit row.
- **Reports** grow a target: `report.target_article`, filed by anyone
  with `READ_NEWS`, delivered to moderators the moment they are filed.
- **Search and references follow the tombstone.** A deleted article is
  removed from `news_fts` in the same transaction, so it cannot be found
  by text; its outbound `news_ref` rows go with it, and its inbound ones
  stay and resolve to `deleted: true`. A moderation act that left the
  body findable through search would not be a moderation act.
- **Revocation composes for free.** A blob is keyed on its SHA-256, and
  `media_block` is keyed on SHA-256; blocking a hash therefore blocks
  it in chat and in news with one row, and a stage that hashes to a
  blocked value is refused before it is written.

Retention is `[news] retain_days` (default 0, forever) and runs off the
hourly sweeper with the stage expiry and the orphan scan, never on the
request path — the rule chat history already follows.

## 11. The legacy 1.5 binding

Built last (§15, W8), specced now, because a domain model that cannot
serve this wire is the wrong model and this is where that gets checked.

### 11.1 The transactions

Opcode names and values are mhxd's `hotline.h`, which AGENTS.md makes the
behavioral reference for anything a 1.2/1.5 client can observe:

| Client → server | Request fields | What it needs from §3.4 |
|---|---|---|
| `NEWS_LISTDIR` (`0x172`) | `NEWSPATH` | `nodes(parent)` for the resolved node |
| `NEWS_LISTCATEGORY` (`0x173`) | `NEWSPATH` | `category_all(category, legacy_catlist_max)` |
| `NEWS_GETTHREAD` (`0x190`) | `NEWSPATH`, `THREADID`, `NEWSTYPE` | `article(id)`, then the part matching the MIME type |
| `NEWS_POSTTHREAD` (`0x19a`) | `NEWSPATH`, `NEWSFLAGS`, `NEWSTYPE`, `NEWSSUBJECT`, `NEWSDATA`, `THREADID` | `post(NewPost)`, with `THREADID` as the parent |
| `NEWS_MKCATEGORY` (`0x17e`) | `NEWSPATH`, `CATEGORY` | `create_node(.., Category, name)` |
| `NEWS_MKDIR` (`0x17d`) | `NEWSPATH` | `create_node(.., Bundle, name)` |
| `NEWS_DELETE` (`0x17c`) | `NEWSPATH` | `delete_node(id)` |
| `NEWS_DELETETHREAD` (`0x19b`) | `NEWSPATH`, `THREADID` | `tombstone(id, ..)` |

The replies are the `NEWSDIRLIST` and `CATLIST` payloads `hxproto`
already parses; `THREADID` (`0x0146`) is the article id on a fetch or a
delete and the *parent* on a post, which is the naming trap
`build_news_post_thread_chunks` documents at length.

Every request is addressed by `NEWSPATH`, which is the file area's
directory encoding (mhxd's `hldir_to_path`, shared with `FileList`'s
`DIR` field). The binding therefore needs one thing the ng wire does
not: **a path resolver**, walking the components from the root through
`news_node.name` to a `NodeId`, and its inverse for building replies.
It lives in `hxd-session`, not in the domain, because a path is a wire
address for a node and the domain names nodes by id — the same line
that keeps Mac Roman out of `hxd-core`.

Name collisions across the two wires are already handled by the
`(parent, name)` unique index: names are unique among siblings because
the legacy wire addresses them by name, and the ng wire is simply held
to the same rule rather than allowing duplicates it would then have to
explain.

### 11.2 The directory listing

`NEWS_LISTDIR` replies with one `CATEGORYITEM` (`0x0143`) per child:
`ntype 2` for a bundle with its child count, `ntype 3` for a category
with its count, `guid`, `add_sn` and `delete_sn` — all four already
columns (§4). `NEWSFOLDERITEM` (`0x0140`) is the older, thinner
encoding, and `parse_news_folderitem` shows clients accept either; we
send the richer one, which is what lets a client skip a refetch.

### 11.3 The article listing, and its parts

`NEWS_LISTCATEGORY` replies with one `CATLIST` chunk: a `post_count` header,
then per post `postid`, an 8-byte Mac date, `parentid`, flags,
`partcount`, a pstring subject, a pstring sender, and then per part a
pstring MIME type and a **u16 size**.

That per-part MIME type is where everything new in this design meets
the legacy wire. A markdown article with a screenshot lists three parts:

| Part | Size on the wire | What `NEWS_GETTHREAD` returns for it |
|---|---|---|
| `text/plain` | the downgrade's | the §5.4 plain text |
| `text/markdown` | the source's | the body as typed |
| `image/png` | the *derivative's* | the ≤ 60 000-byte version (§7.3) |

A client picks a part by MIME type, which is what `NEWSTYPE` on the
request is for, and a 1.5 client asks for the one it has always asked
for. The sizes are the parts' own — the canonical 412 000-byte PNG
cannot be spelled in a u16, and the derivative exists so that something
true can be.

A server in `markdown = "source"` mode has no downgrade to offer, so it
labels the single body part `text/plain` and serves the markdown source
under that name. That is a small lie told deliberately: a period client
that asks for the only body there is should get bytes, not a task error.
It is also why `"render"` is the default — in `source` mode, a 1.5 user
reads asterisks.

A tombstoned article lists as a post with an empty subject, its
original sender cleared, and one zero-length `text/plain` part, so the
thread structure a client already drew stays intact.

**No period client renders an image part** — GtkHx's news browser asks
for `text/plain` and shows text — so this is a capability waiting for a
client rather than one in use. It is still the right shape: it is what
the wire was designed for, it costs one extra part in a listing, and
it means the client work is a client change and not a protocol
negotiation. §17 has what to raise upstream.

### 11.4 Sizes, and the 65 535 that shows up twice

`NEWSDATA` is a chunk, chunk lengths are u16, and mhxd's own
`read_newsfile` caps an article body at `0xffff`. That is where
`[news] max_body = 65535` comes from: a body the legacy wire cannot
carry is a body a 1.5 client silently truncates, and a limit the ng
wire enforces up front is better than a lossy conversion at the edge.
Subjects are pstrings, hence 255. Both are enforced in the domain, so
neither wire can create something the other cannot show.

The plain downgrade is capped at the same 65 535 **independently of the
source**, because rendering grows text: every `[label](news:51)` becomes
`label (news #51)`. A body that fits and a downgrade that does not is an
ordinary case, not an edge one, and it is why §5.4 truncates rather than
refusing the post.

Text conversion is `hxd-session`'s existing edge: UTF-8 → Mac Roman
with `?` for unmappable on the way out, Mac Roman → UTF-8 on the way
in, LF ↔ CR normalization on bodies (subjects carry no line endings —
the same distinction `build_news_post_thread_chunks` documents on its
`is_body` flag). A client that negotiated the Text-Encoding capability
skips the conversion, as it does everywhere else.

### 11.5 Flat 1.2 news

A 1.2 client speaks `NEWSFILE_GET` (`0x0065`) and `NEWSFILE_POST`
(`0x0067`)
and knows nothing about a tree. It gets a **rendered view**: the most
recent `[news] flat_articles` (default 100) articles across every
category, newest first, each as a header line and a body, in the
`HTLS_DATA_NEWS` chunks the client expects. A post from a 1.2 client
lands in `[news] flat_category` as a top-level article; when no such
category is configured, the post is refused with a readable task error
rather than vanishing.

A markdown article contributes its downgrade to the flat view, never its
source: a 1.2 client is the last place to send raw syntax.

This is a synthesis, not a second store — there is no flat news file to
keep in sync, which is exactly the mhxd bug class we are not
inheriting.

### 11.6 Importing an mhxd tree

`hxd import-mhxd-news <dir>` walks a period news directory: `cat_`-
prefixed directories are categories, others are bundles, and each file
is RFC-822 headers (`From`, `Content-Type`, `Subject`, `Date`,
`Message-Id`, `References`) plus a body. `Message-Id` becomes the
article id where it is free and is remapped where it collides — the
mapping is applied to `References` in the same pass, so threading
survives. Bodies convert Mac Roman → UTF-8 and CR → LF. It is a
one-way import of a format we do not otherwise speak, which is what
ROADMAP.md Phase 4 already said it should be. Imported bodies are
`text/plain`; the `#51` shorthand scanner still runs over them, against
the remapped ids, so an mhxd archive that cross-referenced by number
arrives with its references live. The import ends by running
`news-reindex` (§6.4).

## 12. Configuration

```toml
[news]                          # presence turns news on
db = "hxd.sqlite"               # defaults to the inbox/history database
blobs = "news-blobs"            # directory for attachment bytes
max_body = 65535                # the legacy NEWSDATA ceiling; ↓ freely, ↑ never
max_subject = 255
markdown = "render"             # render | source | off — §5.5
max_refs = 32                   # references recorded per article
search = true                   # false disables news_search and skips the index
search_max_results = 500        # deepest reachable offset
search_per_minute = 30          # per session
max_depth = 32                  # reply nesting
max_node_depth = 16             # bundle nesting
max_page = 200
retain_days = 0                 # 0 = forever
self_delete = true              # authors may delete their own; false = period behavior
legacy_catlist_max = 2000       # articles in one 1.5 category reply
flat_articles = 100             # articles in the synthesized 1.2 flat view
flat_category = "General"       # where 1.2 posts land; absent = refuse them

[news.attach]                   # absent = news without attachments
max_bytes = 2097152             # per attachment, as uploaded
max_count = 8                   # per article
max_total_bytes = 8589934592    # across the whole store; a post over it is refused
stage_ttl = 1800                # seconds a staged handle lives unposted
per_hour = 20                   # uploads per account
legacy_derivative = true        # generate the ≤60 000 B version at post time
```

`[news.attach]` without the `media` feature is a startup error, the way
`[media]` and `[inbox]` already are, and `markdown = "render"` without
the `markdown` feature is the same error for the same reason: a config
that silently does less than it says is worse than one that refuses to
start. `[news]` without `[news.attach]` is news with no pictures, which
is a legitimate server; `markdown = "off"` with `search = false` is
plain-text news with no index, which is the smallest thing this design
builds.

## 13. What this does not change

- **`hxd-core` stays wire-free.** No `NEWSPATH`, no chunk tags, no Mac
  Roman. Paths are resolved in `hxd-session`, ids are the domain's
  currency.
- **The roster lock is never held across store or blob I/O.** `news`
  and `blobs` live on `Core` beside `inbox` and `history` for the
  structural reason those do.
- **Seqs stay gapless.** News events consume one in every
  `READ_NEWS`-holding session's outbox, including detached ones.
- **A 1.5 client sees nothing it does not understand.** The only new
  thing on that wire is extra parts in a listing — a `text/markdown`
  body and an image derivative — which `parse_catlist` has always
  handled and which a client asking for `text/plain` skips.
- **The server renders no HTML, anywhere.** Markdown goes in, markdown
  and plain text come out. Nothing in this design produces markup for a
  browser to interpret, which is why a rich-text feature adds no
  injection surface.

## 14. Testing

- **Domain unit tests** in `hxd-core`: containment rules, path
  construction and preorder ordering, depth caps, tombstone-with-
  replies, refcounts, the access matrix per bit.
- **A store conformance suite**, `news/conformance.rs`, in the shape of
  `inbox/conformance.rs`, run against `MemoryNews` and the SQLite
  store, so the two can never drift.
- **`hxd-media` fixtures** grow the derivative cases: an image that
  fits at quality 85, one that needs stepping down, one that cannot fit
  at all, and an animated GIF whose derivative is a still frame.
- **`hxd-markdown` unit tests**: each downgrade rule of §5.4 with its
  expected plain text; raw HTML surviving as literal text; an image by
  URL rejected; a link to `news:51` yielding both the rendered form and
  the reference; a downgrade that outgrows `max_body` truncated at a
  character boundary and not mid-codepoint.
- **Reference tests**: the `#51` shorthand recognized after whitespace
  and punctuation and *not* as an ATX heading; extraction from a plain
  body with the `markdown` feature off; an id naming nothing staying
  text; a target deleted afterwards resolving `deleted: true`; the
  `max_refs` cap; backlinks in both directions.
- **Search tests**: each grammar row of §6.2; a query of nothing but
  FTS5 operators returning results rather than an error; a tombstone
  disappearing from the index in the same transaction; `news-reindex`
  reproducing an index byte-identically in its results; ranking putting
  a subject match above a body match (SQLite store only).
- **ng e2e** in `crates/hxd/tests/news.rs`: post and read back, thread
  ordering across a deep reply chain, pagination in both directions,
  attachment stage → post → fetch, a stale staged handle refused, a
  non-`READ_NEWS` session refused everything, tombstone semantics, the
  blob cap, a markdown post whose `refs` resolve, and a search that
  finds it.
- **Cross-wire e2e**, once W8 lands: a markdown article posted from ng
  read by a scripted 1.5 client as the right two parts with the right
  thread parentage, and a plain `see #51` posted from the legacy client
  arriving at an ng client as a resolved reference; a 1.2 client's flat
  view of both.
- **GtkHx Tier 3.** Its `test_news15.c`, `test_news_catlist.c`,
  `test_news_fetch.c` and `test_news_post.c` already exist and already
  run against real servers. Pointing them at an hxd-ng container is the
  conformance statement this design is aiming at, and it is the same
  payoff chat history got.

## 15. Staging

Each lands separately with tests, roughly a branch apiece.

1. **W1 — the domain.** `hxd-core/src/news.rs`: the types, the
   `NewsStore` trait, `MemoryNews`, containment and depth rules, path
   construction, the access checks, `Core`'s methods. Includes the
   `#51` reference scanner, which has no dependencies and works on
   plain bodies. No I/O, no wire, no attachments, no markdown.
2. **W2 — the store.** Schema version 3 in `hxd-store-sqlite`, the
   migration arm, `news_ref` and its two directions, the conformance
   suite, retention and pruning.
3. **W3 — body text.** `hxd-markdown`, the `BodyRenderer` trait, the
   §5.4 downgrade rules, the CommonMark restrictions, the `markdown`
   mode knob, `plain` written at post time, references resolved on the
   way out.
4. **W4 — search.** `news_fts`, the §6.2 query compiler, BM25 weights,
   snippets with match offsets, offset paging, `MemoryNews`'s naive
   scan, and `hxd news-reindex`.
5. **W5 — attachments.** `BlobStore`, the filesystem implementation,
   the `hxd-media` call for validation and the derivative, staging,
   refcounts, quotas, the `media_block` check, the orphan sweep,
   attachment names into the index.
6. **W6 — the ng wire.** The request set of §9.2, the events of §9.3,
   the login block, `POST /news/blob` and `GET /news/blob/{id}`, config
   and wiring.
7. **W7 — moderation and retention.** The audit kind, the report
   target, the purge arm, index and reference cleanup on tombstone, the
   sweeper's jobs, the CLI surface.
8. **W8 — the legacy 1.5 binding.** The hx-libs opcode additions and
   the pin bump (§1), path resolution, the transactions of §11.1,
   `CATEGORYITEM` with guid and serials, `CATLIST` with its body and
   attachment parts, `NEWS_GETTHREAD` by MIME type, the Mac Roman
   edges, the 1.2 flat view, and `hxd import-mhxd-news`.

W1–W2 is threaded news with plain bodies — small, and worth landing on
its own. W1–W6 is the whole thing for the ng wire and a mobile client.
W8 is what closes ROADMAP Phase 4.

**W3 and W4 are independent of W5** and of each other: markdown, search
and attachments touch different columns and different crates, so they
can land in whatever order they get written. Only W6 needs all of them.

## 16. Cross-wire, in one sentence each

A thread started in a mobile client is a thread in GtkHx's news browser
with the same subject, the same author and the same replies underneath
it, because both wires are reading one table. A post written in markdown
on a phone is readable prose in a 1996 text view, because the server
rendered the plain part once and the wire has carried multipart articles
since 1.5. A `see #51` typed in GtkHx is a tappable link in the mobile
client, because the reference scanner does not care which wire the body
arrived on. Nobody on the legacy wire can search, and that is the one
thing this design does not give both populations. A screenshot attached
from a phone is a 60 KB `image/png` part a 1.5 client can ask for by
MIME type and a 412 KB canonical PNG the phone fetches over HTTP. A
1.2 client with no tree at all sees the last hundred articles as a text
file and can post into one category. An article deleted by a moderator
is a tombstone in every thread on every wire, its bytes unlinked and
its hash remembered.

## 17. Open questions

- **Per-category read permission.** The bitmap has one `read_news` bit
  for the whole tree, which is what every period client assumes. A
  members-only category is an obvious want and an obvious way to
  produce a category a legacy client can see the name of and not the
  contents of. Probably an ng-only concept if it lands at all.
- **`order: "recent"`.** Listing threads by last activity is what every
  forum does and what the legacy wire cannot express (CATLIST is
  whole-category, and a client sorts it). Cheap to add — one index —
  but it makes the two wires' default views differ, which is worth
  deciding rather than discovering.
- **Read state.** "Which articles are new to me" wants a per-mailbox,
  per-category cursor — one small table, keyed the way the inbox keys a
  mailbox. The 1.5 wire's `add_sn`/`delete_sn` are the client-side
  version of the same idea. Not in v1; the columns it needs already
  exist.
- **Notification.** Should a post into a category you have read before
  produce a push? push-notifications.md §11 leaves mentions open for
  the same reason: a rule that buzzes for a busy category is worse than
  no rule. Per-category subscription is the shape if it lands.
- **Non-image attachments.** PDFs and archives are what people actually
  attach to a forum post, and the 1.5 part encoding was built for
  arbitrary MIME types. Serving them means serving bytes we cannot
  validate, which is the file area's risk model and wants the file
  area's design ([file-sources.md](file-sources.md)) rather than a
  second answer here.
- **Editing.** The 1.5 wire has no edit transaction and the chat-history
  spec reserved `704 Edit` without defining it. ng could edit; whether
  an archive should be editable is a policy question with an audit-trail
  answer, not a protocol one. Markdown makes it more tempting — a typo
  in a table is very visible — and an edit would have to re-render, re-
  extract references and re-index, which is three more reasons to decide
  it deliberately.
- **The markdown dialect is a compatibility surface.** Once clients
  render it, changing what the server accepts or how it downgrades
  changes what old articles look like. Pinning the dialect in this
  document (CommonMark, minus raw HTML, minus remote images) and treating
  a change to it as a wire change is probably right, and is not yet a
  stated rule.
- **Quoting versus referencing.** A reference is a pointer. Quoting —
  pulling a passage of the target into the reply, the way mail and
  imageboards do — is what people actually reach for, and it is a client
  behavior *unless* the quote should stay correct when the target is
  edited or deleted. If it should, quoting is a server feature and it is
  a different table.
- **A reference is a weak existence oracle.** `refs` reports whether an
  id resolved. That is harmless while `read_news` is one bit for the
  whole tree; it is not harmless if per-category permissions ever land,
  where a reference could confirm an article in a category the reader
  cannot see. The fix is to resolve references against the reader's
  visibility rather than the author's, which costs a join and is the
  right answer to write down before the ACL arrives, not after.
- **Search scope.** `news_fts` indexes news. `chat_line` is a table in
  the same database with the same shape of text in it, and one more
  external-content index would make scrollback searchable too. Whether
  that is a good idea is a privacy question (chat-history.md's retention
  is short on purpose) more than a technical one.
- **Searching the legacy wire.** An extension would need one
  transaction — a query string and a limit in, article ids and snippets
  out — and would fit the fogWraith capability shape. Worth proposing
  only once there is a client that would use it; GtkHx's news browser
  has no search box today.
- **The u32 article ceiling** (§3.2). Widening it is an ng-only change
  that breaks the legacy binding's ability to name an article; the
  honest fix is a per-category id space, which is what mhxd effectively
  had. Not a problem until it is.
- **Blob storage and clustering.** Phase 8 needs storage several nodes
  can share, and news blobs are the second thing (after the file area)
  that wants it. One answer should serve both.
- **What to raise upstream.** fogWraith's protocol documentation covers
  the extensions, not the 1.5 core, so there is no news document to
  amend — but the "an article part may be an image, and here is how a
  server sizes it for a u16" convention is worth writing down
  somewhere, and a `Capabilities-News-Media` extension defining a
  proper fetch for a full-size attachment would remove the derivative's
  reason to exist. The `text/markdown` body part wants the same
  treatment: it is a convention two implementations could agree on in a
  paragraph, and it is the difference between rich text in news being a
  hxd-ng feature and being a Hotline one.
