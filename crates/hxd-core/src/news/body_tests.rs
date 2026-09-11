//! Markdown bodies in the domain (`docs/news.md` §5): which mode takes
//! what, what a body resolves to, and that the downgrade — not the
//! source — is what search reads. The parser is a fake here; the real one
//! is `hxd-markdown`'s, and its own tests say what it writes.

use std::sync::{Arc, Mutex};

use super::*;
use crate::roster::{AttachInfo, Transport};

/// A renderer that records what it was asked, and answers something that
/// could only have come from it.
#[derive(Default)]
struct Fake(Mutex<Vec<(String, usize)>>);

impl BodyRenderer for Fake {
    fn render(&self, source: &str, limit: usize) -> Rendered {
        self.0.lock().unwrap().push((source.to_string(), limit));
        // Kept to its limit, as the trait asks; ASCII in every case here.
        let mut plain = format!("downgraded {}", source.replace('*', ""));
        plain.truncate(limit);
        Rendered {
            plain,
            refs: vec![1],
        }
    }

    fn refuses(&self, source: &str) -> Option<&'static str> {
        source
            .starts_with("too deep")
            .then_some("That article nests too deeply.")
    }
}

fn server(mode: MarkdownMode, renderer: Option<Arc<Fake>>) -> (Core, Uid, NodeId) {
    server_with(
        NewsPolicy {
            markdown: mode,
            ..NewsPolicy::default()
        },
        renderer,
    )
}

fn server_with(policy: NewsPolicy, renderer: Option<Arc<Fake>>) -> (Core, Uid, NodeId) {
    let news = Arc::new(MemoryNews::new());
    let cat = news
        .create_node(
            &NewNode {
                parent: None,
                kind: NodeKind::Category,
                name: "General".into(),
                guid: [1; 16],
                at: SystemTime::now(),
            },
            16,
        )
        .unwrap()
        .id;
    let mut core = Core::new().with_news(news, policy);
    if let Some(renderer) = renderer {
        core = core.with_body_renderer(renderer);
    }
    let (uid, _rx) = core
        .attach(AttachInfo {
            nick: "alice".into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty()
                .with(bit::READ_NEWS)
                .with(bit::POST_NEWS),
            login: "alice".into(),
            addr: None,
            can_detach: false,
            transport: Transport::default(),
            has_inbox: true,
            attach_news: false,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
        })
        .unwrap();
    core.announce(uid);
    (core, uid, cat)
}

fn post(
    core: &Core,
    uid: Uid,
    cat: NodeId,
    body: &str,
    mime: BodyType,
) -> Result<ArticleId, NewsError> {
    core.news_post(
        uid,
        PostRequest {
            category: cat,
            parent: None,
            subject: "subject".into(),
            body: body.into(),
            mime,
            attachments: Vec::new(),
        },
    )
}

fn found(core: &Core, uid: Uid, q: &str) -> Vec<ArticleId> {
    core.news_search(
        uid,
        SearchRequest {
            q: q.into(),
            category: None,
            from: None,
            before: None,
            after: None,
            order: SearchOrder::Recent,
            offset: 0,
            limit: 10,
        },
    )
    .unwrap()
    .hits
    .iter()
    .map(|h| h.article)
    .collect()
}

#[test]
fn off_takes_plain_text_only() {
    let (core, uid, cat) = server(MarkdownMode::Off, None);
    assert_eq!(
        post(&core, uid, cat, "**hi**", BodyType::Markdown),
        Err(NewsError::BadBodyType)
    );
    assert!(post(&core, uid, cat, "**hi**", BodyType::Plain).is_ok());
}

#[test]
fn render_keeps_the_source_and_indexes_the_downgrade() {
    let fake = Arc::new(Fake::default());
    let (core, uid, cat) = server(MarkdownMode::Render, Some(fake.clone()));
    let first = post(&core, uid, cat, "first", BodyType::Plain).unwrap();
    let id = post(&core, uid, cat, "some **bold** words", BodyType::Markdown).unwrap();

    let article = core.news_article(uid, id).unwrap();
    assert_eq!(article.body, "some **bold** words", "stored as typed");
    assert_eq!(article.mime, BodyType::Markdown);
    assert_eq!(
        article.refs.iter().map(|r| r.id).collect::<Vec<_>>(),
        [first],
        "what the renderer found, resolved by the store"
    );
    assert_eq!(
        *fake.0.lock().unwrap(),
        [("some **bold** words".to_string(), 65_535 * DOWNGRADE_ROOM)],
        "once, with room past the body's own ceiling"
    );
    assert_eq!(found(&core, uid, "downgraded"), [id]);
    assert!(
        fake.0.lock().unwrap().len() == 1,
        "a read never renders; only a post does"
    );
    assert!(post(&core, uid, cat, "plain *text*", BodyType::Plain).is_ok());
    assert_eq!(
        fake.0.lock().unwrap().len(),
        1,
        "a plain body is not parsed"
    );
}

#[test]
fn search_reads_a_downgrade_longer_than_a_body_may_be() {
    // A downgrade can outgrow its source (§5.4). Cutting it to `max_body`
    // is for the legacy edge to do; the index reads all of it.
    let fake = Arc::new(Fake::default());
    let (core, uid, cat) = server_with(
        NewsPolicy {
            markdown: MarkdownMode::Render,
            max_body: 32,
            ..NewsPolicy::default()
        },
        Some(fake.clone()),
    );
    let body = "**a** body that ends with a tail";
    assert_eq!(body.len(), 32, "exactly as long as a body may be");
    let id = post(&core, uid, cat, body, BodyType::Markdown).unwrap();
    assert_eq!(fake.0.lock().unwrap()[0].1, 32 * DOWNGRADE_ROOM);
    assert_eq!(
        found(&core, uid, "tail"),
        [id],
        "a word the downgrade puts past max_body"
    );
}

#[test]
fn source_keeps_markdown_and_finds_the_shorthand_in_it() {
    let (core, uid, cat) = server(MarkdownMode::Source, None);
    let first = post(&core, uid, cat, "first", BodyType::Plain).unwrap();
    let id = post(
        &core,
        uid,
        cat,
        &format!("see #{first}, **really**"),
        BodyType::Markdown,
    )
    .unwrap();
    let article = core.news_article(uid, id).unwrap();
    assert_eq!(article.mime, BodyType::Markdown);
    assert_eq!(
        article.refs.iter().map(|r| r.id).collect::<Vec<_>>(),
        [first]
    );
    assert_eq!(
        found(&core, uid, "really"),
        [id],
        "with no downgrade the index reads the source"
    );
}

#[test]
fn render_with_no_parser_is_source() {
    let (core, uid, cat) = server(MarkdownMode::Render, None);
    let id = post(&core, uid, cat, "**hi** there", BodyType::Markdown).unwrap();
    assert_eq!(found(&core, uid, "there"), [id]);
    assert_eq!(
        core.news_markdown(),
        Some(MarkdownMode::Source),
        "and it says so, rather than promising a downgrade it never makes"
    );
    let (parsed, _, _) = server(MarkdownMode::Render, Some(Arc::new(Fake::default())));
    assert_eq!(parsed.news_markdown(), Some(MarkdownMode::Render));
}

#[test]
fn a_body_the_renderer_refuses_is_refused_unparsed() {
    let fake = Arc::new(Fake::default());
    let (core, uid, cat) = server(MarkdownMode::Render, Some(fake.clone()));
    assert_eq!(
        post(&core, uid, cat, "too deep", BodyType::Markdown),
        Err(NewsError::BadRequest("That article nests too deeply."))
    );
    assert!(fake.0.lock().unwrap().is_empty(), "and nothing was parsed");

    // Only a body that would be parsed is asked about.
    assert!(post(&core, uid, cat, "too deep", BodyType::Plain).is_ok());
    let (source, uid, cat) = server(MarkdownMode::Source, Some(Arc::new(Fake::default())));
    assert!(post(&source, uid, cat, "too deep", BodyType::Markdown).is_ok());
}
