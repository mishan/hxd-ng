//! News on the ng wire (`docs/news.md` §9): the requests, the objects
//! they answer with, and the login reply's `news` block.
//!
//! Everything here is a translation. What may be posted where, by whom,
//! and what a reference resolves to are the domain's decisions; this file
//! parses a request, clamps what the wire says it clamps, calls the core
//! off the reactor, and writes the answer down.

use hxd_core::news::{
    Article, ArticleId, BodyType, NewsError, Node, NodeId, NodeKind, NodeTree, PostRequest,
    Reference, ThreadHead, ThreadQuery,
};
use hxd_core::{Core, Uid};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::off_reactor;
use crate::proto::{reply_err, reply_ok, unix, ReqEnvelope};
use crate::NgCtx;

/// The error code and text for a refused news request. The codes are the
/// closed set §9.2 lists.
pub fn news_err(e: &NewsError) -> (&'static str, &'static str) {
    match e {
        NewsError::Disabled => ("no_news", "This server has no news."),
        NewsError::AccessDenied => ("access_denied", "You are not allowed to do that."),
        NewsError::NoSuchNode => ("no_such_node", "There is no such bundle or category."),
        NewsError::NoSuchArticle => ("no_such_article", "There is no such article."),
        NewsError::NotACategory => (
            "not_a_category",
            "Articles go in categories, and categories hold only articles.",
        ),
        NewsError::WrongCategory => (
            "wrong_category",
            "A reply goes in the category of the article it answers.",
        ),
        NewsError::TooDeep => ("too_deep", "That is nested as deep as this server allows."),
        NewsError::NameTaken => ("name_taken", "Something there already has that name."),
        NewsError::NotEmpty => ("not_empty", "That bundle still holds something."),
        NewsError::BadBodyType => (
            "bad_body_type",
            "This server takes plain-text articles only.",
        ),
        NewsError::BadRequest(text) => ("bad_request", text),
        NewsError::NoSession | NewsError::Store(_) => ("server_error", "Server error."),
    }
}

pub fn node_json(n: &Node) -> Value {
    json!({
        "id": n.id,
        "parent": n.parent,
        "kind": n.kind.name(),
        "name": n.name,
        "count": n.children,
        "created_at": unix(n.created_at),
    })
}

fn tree_json(t: &NodeTree) -> Value {
    let mut v = node_json(&t.node);
    if let Some(children) = &t.children {
        v["children"] = Value::Array(children.iter().map(tree_json).collect());
    }
    v
}

/// A reference as a reader sees it: where it points, and what is there
/// now. A deleted target says so and nothing else.
fn ref_json(r: &Reference) -> Value {
    if r.deleted {
        return json!({ "id": r.id, "at": unix(r.at), "deleted": true });
    }
    json!({
        "id": r.id,
        "subject": r.subject,
        "from": r.author_nick,
        "at": unix(r.at),
        "deleted": false,
    })
}

/// One article (§9.2). `login` and `fingerprint` are absent for a guest —
/// absent rather than null, as everywhere on this wire, so a client can
/// test for the key. A tombstone keeps every key with its words emptied,
/// so a client has one shape to draw and `deleted` to branch on.
pub fn article_json(a: &Article) -> Value {
    let mut from = json!({ "nick": a.author.nick });
    if let Some(login) = &a.author.login {
        from["login"] = json!(login);
    }
    if let Some(fp) = a.author.fingerprint {
        from["fingerprint"] = json!(hl_identity::Fingerprint(fp).to_string());
    }
    json!({
        "id": a.id,
        "category": a.category,
        "parent": a.parent,
        "root": a.root,
        "depth": a.depth,
        "from": from,
        "subject": a.subject,
        "body": a.body,
        "mime": a.mime.mime(),
        "at": unix(a.at),
        "deleted": a.deleted,
        // Always present and, until the attachment stage, always empty:
        // one shape now is one less change for every client later.
        "attachments": [],
        "refs": a.refs.iter().map(ref_json).collect::<Vec<_>>(),
        "referenced_by": a.referenced_by,
    })
}

fn thread_json(h: &ThreadHead) -> Value {
    json!({
        "article": article_json(&h.article),
        "replies": h.replies,
        "last_at": unix(h.last_at),
        "last_id": h.last_id,
    })
}

/// The login reply's `news` block, present exactly when the `news` cap
/// is. `post` is this session's own permission rather than the server's
/// ceiling, so a client can gray out a compose button instead of
/// discovering the refusal after someone has typed (§9.1).
pub fn login_json(core: &Core, uid: Uid) -> Option<Value> {
    let p = core.news_policy()?;
    Some(json!({
        "post": core.news_may_post(uid),
        "attach": false,
        "max_body": p.max_body,
        "max_subject": p.max_subject,
        "max_depth": p.max_depth,
        "markdown": "off",
        "body_types": ["text/plain"],
        "max_refs": p.max_refs,
        "search": false,
    }))
}

#[derive(Debug, Default, Deserialize)]
struct TreeParams {
    #[serde(default)]
    parent: Option<NodeId>,
    #[serde(default)]
    depth: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct ThreadsParams {
    category: NodeId,
    #[serde(default)]
    before: Option<ArticleId>,
    #[serde(default)]
    after: Option<ArticleId>,
    #[serde(default)]
    order: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ThreadParams {
    root: ArticleId,
    #[serde(default)]
    after: Option<ArticleId>,
    #[serde(default)]
    snapshot: Option<ArticleId>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ArticleParams {
    id: ArticleId,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct PostParams {
    category: NodeId,
    #[serde(default)]
    parent: Option<ArticleId>,
    subject: String,
    body: String,
    #[serde(default)]
    mime: Option<String>,
    #[serde(default)]
    attach: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NodeCreateParams {
    #[serde(default)]
    parent: Option<NodeId>,
    kind: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct NodeParams {
    id: NodeId,
    #[serde(default)]
    name: Option<String>,
}

/// A page size as the wire allows it: absent is the default, zero is a
/// mistake worth saying so about, and more than the ceiling is the
/// ceiling — the `history` request's rule.
fn page_size(asked: Option<usize>, default: usize, ceiling: usize) -> Result<usize, String> {
    match asked {
        None => Ok(default.min(ceiling)),
        Some(0) => Err("A page needs a limit of at least 1.".into()),
        Some(n) => Ok(n.min(ceiling)),
    }
}

/// Handle one `news_*` request and return the frame that answers it.
pub(crate) async fn handle(ctx: &NgCtx, uid: Uid, req: &ReqEnvelope) -> String {
    let id = req.id;
    let refused = |e: NewsError| {
        let (code, text) = news_err(&e);
        reply_err(id, code, text)
    };
    // Every news request is refused the same way on a server without
    // news, before its params are looked at: a client asking what the
    // tree holds and a client asking with a typo in the request both
    // learn the one thing that matters.
    let Some(policy) = ctx.core.news_policy() else {
        return refused(NewsError::Disabled);
    };
    // Omitted params mean `{}`: `news_tree` for the root needs nothing
    // said, and serde will not read a struct out of a null.
    let params = if req.params.is_null() {
        json!({})
    } else {
        req.params.clone()
    };
    fn parse<T: DeserializeOwned>(v: Value) -> Option<T> {
        serde_json::from_value(v).ok()
    }
    let malformed = || reply_err(id, "bad_request", "Malformed news request.");
    let bad = |text: &str| reply_err(id, "bad_request", text);
    // `None` is the blocking task itself failing — a panic in the store.
    let answer = |r: Option<Result<Value, NewsError>>| match r {
        Some(Ok(ok)) => reply_ok(id, ok),
        Some(Err(e)) => refused(e),
        None => reply_err(id, "server_error", "Server error."),
    };
    let core = &ctx.core;

    match req.req.as_str() {
        "news_tree" => {
            let Some(p) = parse::<TreeParams>(params) else {
                return malformed();
            };
            let depth = p.depth.unwrap_or(1);
            if !(1..=4).contains(&depth) {
                return bad("`depth` is between 1 and 4.");
            }
            answer(
                off_reactor(core, move |c| {
                    c.news_tree(uid, p.parent, depth).map(
                        |nodes| json!({ "nodes": nodes.iter().map(tree_json).collect::<Vec<_>>() }),
                    )
                })
                .await,
            )
        }

        "news_threads" => {
            let Some(p) = parse::<ThreadsParams>(params) else {
                return malformed();
            };
            // Listing by last activity is an open question (§18): it
            // makes the two wires' default views differ, and that is to
            // be decided rather than discovered. Until it is, asking for
            // it is refused rather than quietly answered in another order.
            if p.order.as_deref().is_some_and(|o| o != "created") {
                return bad("Threads are listed in the order they were started.");
            }
            let limit = match page_size(p.limit, 50, policy.max_page) {
                Ok(n) => n,
                Err(text) => return bad(&text),
            };
            let query = ThreadQuery {
                category: p.category,
                before: p.before,
                after: p.after,
                limit,
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_threads(uid, query).map(|page| {
                        json!({
                            "threads": page.threads.iter().map(thread_json).collect::<Vec<_>>(),
                            "has_more": page.has_more,
                        })
                    })
                })
                .await,
            )
        }

        "news_thread" => {
            let Some(p) = parse::<ThreadParams>(params) else {
                return malformed();
            };
            if p.after.is_some() && p.snapshot.is_none() {
                return bad("A later thread page needs the first page's snapshot.");
            }
            let limit = match page_size(p.limit, 25, policy.max_page.min(100)) {
                Ok(n) => n,
                Err(text) => return bad(&text),
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_thread(uid, p.root, p.after, p.snapshot, limit)
                        .map(|page| json!({
                            "articles": page.articles.iter().map(article_json).collect::<Vec<_>>(),
                            "has_more": page.has_more,
                            "snapshot": page.snapshot,
                        }))
                })
                .await,
            )
        }

        "news_article" => {
            let Some(p) = parse::<ArticleParams>(params) else {
                return malformed();
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_article(uid, p.id)
                        .map(|a| json!({ "article": article_json(&a) }))
                })
                .await,
            )
        }

        "news_refs" => {
            let Some(p) = parse::<ArticleParams>(params) else {
                return malformed();
            };
            let limit = match page_size(p.limit, 50, 200) {
                Ok(n) => n,
                Err(text) => return bad(&text),
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_refs(uid, p.id, limit).map(|refs| {
                        json!({ "referenced_by": refs.iter().map(ref_json).collect::<Vec<_>>() })
                    })
                })
                .await,
            )
        }

        "news_post" => {
            let Some(p) = parse::<PostParams>(params) else {
                return malformed();
            };
            // No attachment stage yet, so no handle is one this session
            // staged: the same one answer §9.2 gives for a handle that is
            // someone else's or has expired.
            if !p.attach.is_empty() {
                return reply_err(id, "no_such_media", "No such media.");
            }
            let mime = match p.mime.as_deref() {
                None => BodyType::Plain,
                Some(m) => match BodyType::from_mime(m) {
                    Some(t) => t,
                    None => return bad("`mime` is text/plain or text/markdown."),
                },
            };
            let post = PostRequest {
                category: p.category,
                parent: p.parent,
                subject: p.subject,
                body: p.body,
                mime,
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_post(uid, post).map(|id| json!({ "id": id }))
                })
                .await,
            )
        }

        // `reason` is accepted and not yet kept: the moderation record it
        // belongs in is the moderation stage's (§11).
        "news_delete" => {
            let Some(p) = parse::<ArticleParams>(params) else {
                return malformed();
            };
            answer(off_reactor(core, move |c| c.news_delete(uid, p.id).map(|()| json!({}))).await)
        }

        "news_node_create" => {
            let Some(p) = parse::<NodeCreateParams>(params) else {
                return malformed();
            };
            let Some(kind) = NodeKind::from_name(&p.kind) else {
                return bad("`kind` is bundle or category.");
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_node_create(uid, p.parent, kind, &p.name)
                        .map(|n| json!({ "node": node_json(&n) }))
                })
                .await,
            )
        }

        "news_node_rename" => {
            let Some(NodeParams {
                id: node,
                name: Some(name),
            }) = parse::<NodeParams>(params)
            else {
                return malformed();
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_node_rename(uid, node, &name).map(|_| json!({}))
                })
                .await,
            )
        }

        "news_node_delete" => {
            let Some(p) = parse::<NodeParams>(params) else {
                return malformed();
            };
            answer(
                off_reactor(core, move |c| {
                    c.news_node_delete(uid, p.id)
                        .map(|gone| json!({ "articles": gone }))
                })
                .await,
            )
        }

        _ => reply_err(id, "unknown_method", "Unknown request."),
    }
}
