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
        Rendered {
            plain: format!("downgraded {}", source.replace('*', "")),
            refs: vec![1],
        }
    }
}

fn server(mode: MarkdownMode, renderer: Option<Arc<Fake>>) -> (Core, Uid, NodeId) {
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
    let mut core = Core::new().with_news(
        news,
        NewsPolicy {
            markdown: mode,
            ..NewsPolicy::default()
        },
    );
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
        [("some **bold** words".to_string(), 65_535)],
        "once, with the body's own ceiling as the limit"
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
}
