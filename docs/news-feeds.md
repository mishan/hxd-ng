# News feeds: RSS and Atom as read-only categories

Status: designed, not built. §9 stages it.

An operator names a feed and a news category; the server polls the feed
and posts each new item into the category as an article. Users read it
like any other category, on either wire, and can follow it like any
other category (news.md §10), so a release feed becomes a notification
when a release ships. Mobius's feed-backed news is the precedent and the
reason for the feature; this design differs from it where its behavior
is a problem rather than a choice (§8).

**Decisions (2026-10):**

- **A feed category is read-only.** Nobody posts into it or replies in
  it, whatever their bits; a moderator may delete from it. What a feed
  says is the feed's, and a reply thread under a release note is a
  thread nobody upstream will read.
- **An article shows the item's own author.** The nick is the item's
  author as the feed gives it, with the feed's name alongside on the ng
  wire. No login, no fingerprint: the article is attributed to a feed,
  never to an account.
- **The server polls; a reader never causes a fetch.** A fetch on open
  makes every reader an outbound request and every slow feed a slow
  category. A poller fetches on its own schedule and a reader reads
  the store.
- **The address connected to is an address checked**, by the push
  sender's rules (webpush-gateway.md §6) and its classifier, on every
  hop of a redirect. The operator chooses the URL; the feed's host
  chooses the redirects.
- **A feed keeps its newest items**, pruning its oldest beyond `keep`.
  A category that fills and stops taking new items is the failure this
  avoids.
- **Bodies arrive as markdown, built from the feed's HTML by a converter
  that emits no HTML**: text is escaped, links keep their address, and
  anything else is dropped or becomes text. The markdown pipeline
  (news.md §5) renders the plain part legacy clients read.
- **Off unless configured.** No `[[news.feed]]`, no poller, no outbound
  connection.

---

## 1. The shape

```
  [[news.feed]] "mobius"  ──poll──▶  hxd-feeds: fetch, parse, convert
                                         │  items, newest last
                                         ▼
                              Core::news_feed_import
                                         │  dedupe, post, prune
                                         ▼
                      category "Software Updates/Mobius" (read-only)
                                         │
                     news_posted to readers, news_notify to followers
```

Three layers, split where the rest of news is split:

- **`hxd-core`** owns what a feed *is* to the domain: which categories
  are read-only, the import (seen items, the post, pruning, events),
  and the store rows. No network and no XML.
- **`hxd-feeds`**, a new crate behind the `feeds` Cargo feature, owns
  the outside world: the HTTP fetch, the parse, the HTML conversion. It
  hands the domain a list of normalized items and knows nothing about
  Hotline, the way `hxd-push-webpush` knows nothing about it.
- **`hxd`** owns the poller task and the config.

## 2. Configuration

```toml
[news.feeds]                    # settings for every feed; all optional
every = 1800                    # seconds between polls; a feed's own may only be longer than min_every
min_every = 300
keep = 100                      # newest articles a feed keeps; 0 = retain_days decides
first_import = 20               # items taken from a feed's backlog the first time it is polled
max_bytes = 4194304             # a response body, after decompression
timeout = 30                    # seconds for a whole fetch, redirects included
# proxy = "http://10.0.0.5:3128"   # absent = direct; HTTP(S)_PROXY is never read

[[news.feed]]
name = "mobius"                 # stable: what remembers which items are seen
url = "https://github.com/jhalter/mobius/releases.atom"
category = "Software Updates/Mobius"   # as flat_category names one (news.md §13)
# every = 3600
# keep = 50
# author = "Mobius"             # in place of each item's own
# allow_private = false         # lift the address check for this feed (§4)
```

`name` is the feed's identity, not its URL: a feed that moves keeps its
history by keeping its name, and a new name is a new feed. Names are
unique; two feeds may share a category, and each keeps and prunes its
own items.

The category is made at startup if it is missing, bundles above it
included, the way an operator would make it by hand. An existing
category is adopted with what is in it; articles posted there before it
was a feed stay, and are never pruned (§5). A path that names a bundle
is a startup error. A feed removed from the config stops being polled,
and its category becomes an ordinary category again, articles and all.

`[[news.feed]]` without the `feeds` feature is a startup error, as
`[news.attach]` without `media` is (news.md §13). So is a URL that is
not absolute `http` or `https`, carries userinfo, or names a literal
non-public address without `allow_private`.

## 3. Read-only, on both wires

A category is read-only while a configured feed names it. That is held
in `Core` from the config, not stored, so removing the feed is the whole
of making the category writable again.

| Act | In a feed category |
|---|---|
| Read, list, search, follow | as anywhere |
| Post or reply | refused: ng `read_only`, a legacy task error saying the category is a feed |
| Delete an article | `DELETE_ARTICLES` (33). No ladder applies: a feed article's author has no sessions and no account |
| Delete the category | refused while a feed names it: the next start would make it again |
| 1.2 flat news | if `flat_category` is a feed category, 1.2 posts are refused the same way |

The ng `node` object gains `"feed": "mobius"` for a feed category, so a
client can hide its post button rather than offer one that will fail;
the legacy wire has no field for it and gets the refusal.

A deleted feed article is a tombstone like any other (news.md §11), with
its audit row. Its item stays seen, so the next poll does not bring it
back.

## 4. Fetching

The poller wakes each feed at its interval, with a little jitter so
feeds configured together do not fetch together, and fetches one feed
at a time per host.

- **Conditional.** `If-None-Match` and `If-Modified-Since` from the last
  success; a `304` costs a request and nothing else.
- **Bounded.** `timeout` for the whole fetch, `max_bytes` for the body
  *after* decompression, counted as it is read. A feed past either is a
  failure, not a truncated parse.
- **Redirects**: at most five, each to an address checked again, never
  from `https` to `http`, and never remembered: a permanent redirect is
  logged so the operator can update the URL.
- **Addresses.** The push sender's classifier (`hxd_core::push::endpoint`,
  moved where both can use it): a name is resolved once per connection,
  every answer is checked, and the connection is made to a checked
  address. `allow_private` lifts it for one feed, for an operator's own
  intranet feed. Through `proxy` the server cannot see what a name
  resolves to, so the connection to the proxy is not checked and only a
  URL naming a literal address is; the proxy's own rules decide the
  rest. The environment's proxy variables are not read, as they are not
  for push: a setting that moves resolution out of sight is one the
  operator writes down.
- **Failures back off**, doubling from the feed's interval to six hours,
  and a `Retry-After` on a `429` or `503` is honored when it is longer.
  Nothing is posted about a failure; it is logged, counted, and kept
  with the feed's state (§6) for the operator.
- **User-Agent** names hxd-ng and its version.

Formats are RSS 0.9x–2.0 (RDF included), Atom 1.0 and JSON Feed, through
`feed-rs`. Its XML reader expands no DTD entities, so a hostile feed
cannot grow inside the parser past `max_bytes`.

## 5. Importing

Each poll hands `Core::news_feed_import` the feed's items, oldest first.

**Identity.** An item is its `id`/`guid`; failing that, its first
`http(s)` link; failing that, its first enclosure. An item with none is
skipped and counted. The seen key is SHA-256 of the identity, per feed.
An item already seen is skipped even if it changed upstream: an edit to
a release note does not re-post it (§10).

**The first poll** takes the newest `first_import` items and marks the
rest of the backlog seen, so a new feed is not a hundred articles and a
hundred notifications at once, and the backlog does not trickle in
later as if it were new.

**The article.**

| Article | From |
|---|---|
| subject | the item's title as text (markup removed, entities decoded), cut to `max_subject`; `(untitled)` if empty |
| author nick | the feed's `author` if set; else the item's author, the feed's author, the feed's title, then the feed's `name` |
| login, fingerprint | none; the article's `feed` names the feed |
| at | published, else updated, else the fetch time; a time in the future is the fetch time, so a feed cannot pin itself to the top |
| body | §7's conversion of content, else summary, then a `Source:` line and a `Download:` line per enclosure |
| references | none: a feed's `#51` is not this server's article 51 |
| attachments | none: images are links (§7) |

The body is cut to `max_body` *before* the link lines are added, at a
character boundary with a trailing `…`, so a long body never loses its
source.

**Pruning.** After posting, a feed with more than `keep` live articles
deletes its oldest beyond it. Pruning is not moderation: it writes no
audit row and the articles are removed rather than tombstoned, the way
`retain_days` removes. Only the feed's own articles are ever pruned;
articles from before the category was a feed are not the feed's.
`retain_days` still applies to feed articles as to any.

**Limits.** Feed articles count toward `max_articles` and
`max_text_bytes`. An import that would pass either stops there, logs it,
and leaves the rest unseen for the next poll. `max_per_author` does not
apply; `keep` is a feed's equivalent. `[limits] news_posts` is a
budget for people and does not apply.

**Events.** An import that posted anything is one `news_posted` per
category, however many items it took, and followers of the category are
told through news.md §10.6 with its catch-up rule and `max_per_hour`
unchanged. The first poll notifies nobody.

## 6. The store

Two tables and a column, as one additive version:

```sql
CREATE TABLE news_feed (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT    NOT NULL UNIQUE,     -- [[news.feed]] name
  url           TEXT    NOT NULL,            -- as last fetched, for the operator
  etag          TEXT,
  last_modified TEXT,
  last_ok       INTEGER,
  last_error    TEXT,
  failures      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE news_feed_item (
  feed       INTEGER NOT NULL REFERENCES news_feed(id),
  key        BLOB    NOT NULL,               -- SHA-256 of the item's identity
  article    INTEGER REFERENCES news_article(id),  -- NULL once pruned, or never posted
  last_seen  INTEGER NOT NULL,               -- last poll that listed it
  PRIMARY KEY (feed, key)
) WITHOUT ROWID;

ALTER TABLE news_article ADD COLUMN feed INTEGER REFERENCES news_feed(id);
```

Whatever removes a feed article, pruning or `retain_days`, clears its
seen row's `article` in the same transaction; the row itself stays, so
the item stays seen.

`news_article.feed` is what marks an article as a feed's: what pruning
selects, what the ng wire names, and what keeps moderation's `by_author`
purge, which selects on login, away from feed articles. Article ids are
`AUTOINCREMENT` and never reused (news.md §3.2), so a seen item's
article id always means that article.

A seen row whose article is gone and which no poll has listed for thirty
days is dropped by the hourly sweeper. A feed lists its recent items, so
an item thirty days out of the feed is not coming back, and without the
rule the table grows with every item the feed has ever had.

## 7. Bodies

Feeds carry HTML; news bodies are markdown (news.md §5), and the
server never renders HTML. The converter, in `hxd-feeds`, walks the
HTML with a tokenizer, not a parser into a tree, and emits markdown:

- **Text is escaped**, every markdown-significant character, so text
  that looks like markdown stays text.
- `p`, `br`, `div`, headings, lists, `blockquote`, `pre`/`code` and
  `em`/`strong` become their markdown forms.
- `a` becomes `[text](url)` for `http`, `https` and `mailto` URLs, made
  absolute against the item's link; any other scheme is dropped and its
  text kept.
- `img` becomes a link to the image, labeled with its alt text. Nothing
  is fetched: an image a feed names is an outbound request a reader did
  not ask for, from the server's address.
- `script`, `style`, `iframe`, `object`, forms and comments are dropped
  with their contents; any other element is dropped and its text kept.

With `markdown = "off"` the same walk emits plain text. Either way the
plain part legacy clients read is news.md §5.4's downgrade, and search
indexes it like any article's.

## 8. Against Mobius

What is the same: one feed into one category, the item-to-article
mapping, conditional requests, and remembering what was imported.

What differs, and why:

| Mobius | Here |
|---|---|
| A reader opening the category fetches the feed | A poller fetches; reads never wait on a feed |
| Redirects followed to any address | Every hop's address checked (§4) |
| At the article-list limit, new items stop for good | `keep` prunes the oldest; the legacy listing is already capped at `legacy_catlist_max` |
| Users can post and reply in a feed category | Read-only (§3) |
| The category must already exist | Made if missing |
| Link lines added before the body is cut | Body cut first (§5) |

Fixes for the redirect check and the article-list limit were offered
upstream as well.

## 9. Staging

1. **F1 — the domain.** The read-only rule on both wires, `news_feed`,
   `news_feed_item` and `news_article.feed` in both stores with the
   conformance suite, and `Core::news_feed_import` with first-poll,
   dedupe, pruning, limits and events, fed by hand-built items. No
   network, no feature.
2. **F2 — `hxd-feeds`.** The fetch with its address check (the
   classifier moved out of `push`), the parse over fixtures of each
   format, the converter with its hostile cases, all behind a transport
   seam as the push sender's are.
3. **F3 — the wiring.** `[news.feeds]` and `[[news.feed]]`, the `feeds`
   feature, the poller and its backoff, the sweeper's seen-row rule, the
   ng `node.feed` field, metrics, and e2e: a feed served from a test
   server becoming articles both wires read, a post refused on both, a
   delete that stays deleted.
4. **F4 — the client.** hx-ng shows a feed category's name, hides its
   post button, and badges a feed article's author.

F1 and F2 are independent. F3 needs both.

## 10. Open

- **Upstream edits.** An item changed after it was imported is ignored.
  Updating the article in place is possible (it is ours, unlike a
  user's), but a release note that changes under its readers is its own
  surprise.
- **Replies.** A per-feed `replies = true` would let users discuss an
  item under it. Off by the 2026-10 decision; easy to add later, since
  pruning would then have to spare replied-to items.
- **Images as attachments**: fetching an item's images into the blob
  store (news.md §7) would show them inline, at the cost of the server
  fetching what a feed names. Not without a reason.
- **An operator view** of each feed's state beyond the log and metrics:
  `hxd news feeds`, or the ng admin surface.
