//! Search as the domain decides it: who may, how often, where, and how
//! deep. Which articles a query finds is the stores' business, and
//! `conformance` holds both of them to it.

use std::sync::Arc;

use super::*;
use crate::roster::{test_attach, AttachInfo, Transport};

fn core_with(policy: NewsPolicy) -> Core {
    Core::new().with_news(Arc::new(MemoryNews::default()), policy)
}

fn editor(core: &Core) -> Uid {
    let (uid, _rx) = core
        .attach(AttachInfo {
            nick: "Editor".into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty()
                .with(bit::READ_NEWS)
                .with(bit::POST_NEWS)
                .with(bit::CREATE_CATEGORIES)
                .with(bit::CREATE_NEWS_BUNDLES),
            login: "editor".into(),
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
    uid
}

fn search(q: &str) -> SearchRequest {
    SearchRequest {
        q: q.into(),
        category: None,
        from: None,
        before: None,
        after: None,
        order: SearchOrder::Recent,
        offset: 0,
        limit: 20,
    }
}

fn post(core: &Core, uid: Uid, category: NodeId, body: &str) -> ArticleId {
    core.news_post(
        uid,
        PostRequest {
            category,
            parent: None,
            subject: "subject".into(),
            body: body.into(),
            mime: BodyType::Plain,
            attachments: Vec::new(),
        },
    )
    .unwrap()
}

fn found(page: &SearchPage) -> Vec<ArticleId> {
    page.hits.iter().map(|h| h.article).collect()
}

#[test]
fn a_bundle_scopes_a_search_to_every_category_under_it() {
    let core = core_with(NewsPolicy::default());
    let me = editor(&core);
    let outer = core
        .news_node_create(me, None, NodeKind::Bundle, "Projects")
        .unwrap();
    let inner = core
        .news_node_create(me, Some(outer.id), NodeKind::Bundle, "Servers")
        .unwrap();
    let deep = core
        .news_node_create(me, Some(inner.id), NodeKind::Category, "hxd-ng")
        .unwrap();
    let near = core
        .news_node_create(me, Some(outer.id), NodeKind::Category, "gtkhx")
        .unwrap();
    let away = core
        .news_node_create(me, None, NodeKind::Category, "Elsewhere")
        .unwrap();
    let a = post(&core, me, deep.id, "phase four");
    let b = post(&core, me, near.id, "phase four");
    post(&core, me, away.id, "phase four");

    let scoped = |category| {
        core.news_search(
            me,
            SearchRequest {
                category: Some(category),
                ..search("phase")
            },
        )
    };
    assert_eq!(found(&scoped(outer.id).unwrap()), [b, a]);
    assert_eq!(found(&scoped(deep.id).unwrap()), [a]);
    assert_eq!(scoped(9999), Err(NewsError::NoSuchNode));
    let empty = core
        .news_node_create(me, None, NodeKind::Bundle, "Empty")
        .unwrap();
    assert_eq!(
        scoped(empty.id).unwrap().total,
        0,
        "an empty bundle holds nothing to find"
    );
}

#[test]
fn nothing_to_look_for_is_an_empty_page_not_an_error() {
    let core = core_with(NewsPolicy::default());
    let me = editor(&core);
    let cat = core
        .news_node_create(me, None, NodeKind::Category, "General")
        .unwrap();
    let id = post(&core, me, cat.id, "phase four");
    for q in ["", "   ", "-phase", "!!! ***", "\"\""] {
        assert_eq!(
            core.news_search(me, search(q)),
            Ok(SearchPage::default()),
            "{q:?}"
        );
    }
    // An author alone is something to look for.
    let by = core
        .news_search(
            me,
            SearchRequest {
                from: Some("editor".into()),
                ..search("")
            },
        )
        .unwrap();
    assert_eq!(found(&by), [id]);
}

#[test]
fn the_deepest_reachable_result_is_a_ceiling_and_the_total_says_so() {
    let core = core_with(NewsPolicy {
        search_max_results: 2,
        ..NewsPolicy::default()
    });
    let me = editor(&core);
    let cat = core
        .news_node_create(me, None, NodeKind::Category, "General")
        .unwrap();
    for _ in 0..3 {
        post(&core, me, cat.id, "phase");
    }
    let first = core.news_search(me, search("phase")).unwrap();
    assert_eq!((first.hits.len(), first.total, first.capped), (2, 3, true));
    let past = core
        .news_search(
            me,
            SearchRequest {
                offset: 2,
                ..search("phase")
            },
        )
        .unwrap();
    assert!(past.hits.is_empty(), "past the ceiling the page is empty");
    assert_eq!((past.total, past.capped), (3, true));
}

#[test]
fn searches_are_rationed_per_session() {
    let core = core_with(NewsPolicy {
        search_per_minute: 3,
        ..NewsPolicy::default()
    });
    let me = editor(&core);
    for _ in 0..3 {
        assert!(core.news_search(me, search("x")).is_ok());
    }
    assert_eq!(
        core.news_search(me, search("x")),
        Err(NewsError::RateLimited)
    );
    let other = editor(&core);
    assert!(
        core.news_search(other, search("x")).is_ok(),
        "one session's ration is not another's"
    );
}

#[test]
fn search_takes_reading_and_a_server_that_answers_it() {
    let core = core_with(NewsPolicy::default());
    let (blind, _rx) = test_attach(&core, "blind", AccessBits::empty());
    assert_eq!(
        core.news_search(blind, search("x")),
        Err(NewsError::AccessDenied)
    );

    let off = core_with(NewsPolicy {
        search: false,
        ..NewsPolicy::default()
    });
    let me = editor(&off);
    assert_eq!(off.news_search(me, search("x")), Err(NewsError::SearchOff));

    let none = Core::new();
    let (anyone, _rx) = test_attach(&none, "anyone", AccessBits::empty().with(bit::READ_NEWS));
    assert_eq!(
        none.news_search(anyone, search("x")),
        Err(NewsError::Disabled)
    );
}
