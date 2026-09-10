//! A suite every [`NewsStore`] must pass.
//!
//! Two implementations, one set of answers: the in-memory store the
//! domain's tests run on and the SQLite one a server keeps its news in.
//! Where they could drift is in the corners — which error a doubly-wrong
//! request gets, whether a tombstone still holds its place, what a
//! reference to something deleted says — so the cases live here once.
//!
//! Public, like [`crate::inbox::conformance`], because the implementation
//! it most needs to check is in another crate. Times are whole seconds,
//! because the SQLite store keeps whole seconds, and never the wall
//! clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    ArticleId, Author, BodyType, CompiledQuery, NewNode, NewPost, NewsError, NewsStore, NodeId,
    NodeKind, Posted, SearchOrder, SearchQuery, SubScope, ThreadQuery,
};
use crate::inbox::Mailbox;

/// Run every case against a freshly built store. `new_store` is called
/// once per case, so no case sees another's articles.
pub fn run(new_store: &dyn Fn() -> Box<dyn NewsStore>) {
    nodes_nest_and_list_by_name(&*new_store());
    a_name_is_unique_among_its_siblings_only(&*new_store());
    containment_is_the_legacy_wires(&*new_store());
    nodes_nest_no_deeper_than_allowed(&*new_store());
    an_article_round_trips_whole(&*new_store());
    a_thread_comes_back_in_preorder(&*new_store());
    a_reply_stays_in_its_parents_category_and_depth(&*new_store());
    threads_page_newest_first_in_both_directions(&*new_store());
    a_thread_pages_forward_through_its_replies(&*new_store());
    references_resolve_once_and_report_their_target_now(&*new_store());
    a_tombstone_keeps_its_place_and_loses_its_words(&*new_store());
    a_thread_of_nothing_but_tombstones_is_not_listed(&*new_store());
    deleting_a_category_takes_its_articles_and_a_bundle_must_be_empty(&*new_store());
    pruning_takes_whole_threads_by_their_last_post(&*new_store());
    // Search: which articles a query finds. Never the order a relevance
    // search puts them in — the memory store does not rank — and never
    // snippets, which only an index can make well.
    search_follows_the_grammar(&*new_store());
    search_scopes_and_pages(&*new_store());
    search_never_finds_what_is_gone(&*new_store());
    a_long_query_finds_what_it_was_pasted_from(&*new_store());
    // Subscriptions: what unread counts, what a row may and may not be
    // made into, and the mailbox rule holding for them as for mail.
    a_subscription_starts_caught_up_and_counts_what_follows(&*new_store());
    a_subscription_needs_something_to_be_about(&*new_store());
    asking_is_explicit_and_posting_takes_nothing_back(&*new_store());
    the_cap_counts_every_row(&*new_store());
    a_cursor_moves_forward_and_no_further_than_the_news(&*new_store());
    a_posts_audience_sees_muted_rows_too(&*new_store());
    the_two_kinds_of_mailbox_never_meet(&*new_store());
    linking_rotating_and_deleting_move_the_rows(&*new_store());
    rows_go_with_what_they_follow(&*new_store());
    a_listing_is_newest_first_and_says_what_it_follows(&*new_store());
}

/// The corpus the search cases share: two categories, three authors, and
/// words chosen so every row of the grammar tells something apart.
struct Corpus {
    general: NodeId,
    other: NodeId,
    open: ArticleId,
    sizes: ArticleId,
    reply: ArticleId,
    change: ArticleId,
}

fn corpus(s: &dyn NewsStore) -> Corpus {
    let general = category(s, "General");
    let other = category(s, "Other");
    let by = |nick: &str, login: &str| Author {
        nick: nick.into(),
        login: Some(login.into()),
        fingerprint: None,
    };
    let put = |category, parent, author, subject: &str, body: &str, at| {
        s.post(
            &NewPost {
                category,
                parent,
                author,
                subject: subject.into(),
                body: body.into(),
                mime: BodyType::Plain,
                refs: Vec::new(),
                at: t(at),
            },
            32,
            32,
        )
        .unwrap()
        .id
    };
    let open = put(
        general,
        None,
        by("Alice", "alice"),
        "Phase 4 is open",
        "News, finally. The legacy binding comes last.",
        100,
    );
    let sizes = put(
        general,
        None,
        by("Bob", "bob"),
        "Attachment sizes",
        "The derivative is a u16, phase one of 4.",
        200,
    );
    let reply = put(
        general,
        Some(sizes),
        by("Alice", "alice"),
        "Re: Attachment sizes",
        "Sizeable concerns about phase 4.",
        300,
    );
    let change = put(
        other,
        None,
        by("Carol", "carol"),
        "Unrelated",
        "Phase change materials.",
        400,
    );
    Corpus {
        general,
        other,
        open,
        sizes,
        reply,
        change,
    }
}

fn query(q: &str) -> SearchQuery {
    SearchQuery {
        terms: CompiledQuery::parse(q),
        categories: None,
        before: None,
        after: None,
        order: SearchOrder::Recent,
        offset: 0,
        limit: 50,
    }
}

fn found(s: &dyn NewsStore, q: &SearchQuery) -> Vec<ArticleId> {
    s.search(q)
        .unwrap_or_else(|e| panic!("searching {:?}: {e}", q.terms))
        .hits
        .iter()
        .map(|h| h.article)
        .collect()
}

fn search_follows_the_grammar(s: &dyn NewsStore) {
    let c = corpus(s);
    let find = |q: &str| found(s, &query(q));
    assert_eq!(find("phase"), [c.change, c.reply, c.sizes, c.open]);
    assert_eq!(
        find("Phase 4"),
        [c.reply, c.sizes, c.open],
        "both terms, anywhere"
    );
    assert_eq!(find("\"phase 4\""), [c.reply, c.open], "the words together");
    assert_eq!(find("phase -legacy"), [c.change, c.reply, c.sizes]);
    assert_eq!(
        find("subject:sizes"),
        [c.reply, c.sizes],
        "not the body's 'Sizeable'"
    );
    assert_eq!(find("siz*"), [c.reply, c.sizes]);
    assert_eq!(find("from:alice"), [c.reply, c.open]);
    assert_eq!(find("from:bob phase"), [c.sizes]);
    assert_eq!(
        find("alice"),
        [c.reply, c.open],
        "a bare word looks at the author too"
    );
    assert!(find("-phase").is_empty(), "exclusions alone find nothing");

    // Relevance finds the same articles; its order is the store's own.
    let mut relevant = found(
        s,
        &SearchQuery {
            order: SearchOrder::Relevance,
            ..query("phase")
        },
    );
    relevant.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(relevant, [c.change, c.reply, c.sizes, c.open]);

    // Nothing anyone can type is an error.
    for q in [
        "phase\" OR (NEAR -",
        "\"\"\"",
        "subject:\"",
        "* - :",
        "{subject}: x",
        "'; DROP TABLE news_article; --",
    ] {
        assert!(s.search(&query(q)).is_ok(), "{q:?}");
    }

    let hit = s.search(&query("sizeable")).unwrap().hits.remove(0);
    assert_eq!(hit.article, c.reply);
    assert_eq!(hit.root, c.sizes);
    assert_eq!(hit.category, c.general);
    assert_eq!(hit.subject, "Re: Attachment sizes");
    assert_eq!(hit.author_nick, "Alice");
    assert_eq!(hit.at, t(300));
}

fn search_scopes_and_pages(s: &dyn NewsStore) {
    let c = corpus(s);
    let scoped = |categories: Vec<NodeId>| {
        found(
            s,
            &SearchQuery {
                categories: Some(categories),
                ..query("phase")
            },
        )
    };
    assert_eq!(scoped(vec![c.other]), [c.change]);
    assert_eq!(scoped(vec![c.general, c.other]).len(), 4);
    assert!(scoped(vec![]).is_empty(), "no categories is nowhere");

    let dated = |before: Option<u64>, after: Option<u64>| {
        found(
            s,
            &SearchQuery {
                before: before.map(t),
                after: after.map(t),
                ..query("phase")
            },
        )
    };
    assert_eq!(dated(Some(250), None), [c.sizes, c.open]);
    assert_eq!(dated(None, Some(250)), [c.change, c.reply]);
    assert_eq!(dated(Some(350), Some(150)), [c.reply, c.sizes]);

    let page = |offset, limit| {
        s.search(&SearchQuery {
            offset,
            limit,
            ..query("phase")
        })
        .unwrap()
    };
    let first = page(0, 2);
    assert_eq!(
        first.hits.iter().map(|h| h.article).collect::<Vec<_>>(),
        [c.change, c.reply]
    );
    assert_eq!(first.total, 4, "the total is every match, not the page");
    let second = page(2, 2);
    assert_eq!(
        second.hits.iter().map(|h| h.article).collect::<Vec<_>>(),
        [c.sizes, c.open]
    );
    let beyond = page(10, 2);
    assert!(beyond.hits.is_empty());
    assert_eq!(beyond.total, 4);
    let counted = page(0, 0);
    assert!(counted.hits.is_empty(), "a limit of 0 is the count alone");
    assert_eq!(counted.total, 4);
}

fn search_never_finds_what_is_gone(s: &dyn NewsStore) {
    let c = corpus(s);
    s.tombstone(c.open, "moderator", t(500)).unwrap();
    assert!(
        found(s, &query("legacy")).is_empty(),
        "a tombstone is not found"
    );
    assert_eq!(found(s, &query("phase")), [c.change, c.reply, c.sizes]);

    s.delete_node(c.other).unwrap();
    assert!(
        found(s, &query("materials")).is_empty(),
        "nor a deleted category's"
    );

    s.prune(Duration::from_secs(1000), t(1250)).unwrap();
    assert_eq!(
        found(s, &query("phase")),
        [c.reply, c.sizes],
        "a thread with a post inside the window stays findable"
    );
    s.prune(Duration::from_secs(10), t(1250)).unwrap();
    assert!(
        found(s, &query("phase")).is_empty(),
        "nor a pruned thread's"
    );

    // A rebuild holds what the live index held: nothing is left, and
    // nothing comes back.
    assert_eq!(s.reindex().unwrap(), 0);
    let fresh = post(s, c.general, None, "phase anew", 2000);
    assert_eq!(s.reindex().unwrap(), 1);
    assert_eq!(found(s, &query("phase")), [fresh]);
}

fn a_long_query_finds_what_it_was_pasted_from(s: &dyn NewsStore) {
    // Longer than a term may be, so the grammar cuts it, inside a word
    // that then has to match as the prefix it now is.
    let cat = category(s, "General");
    let said = "the legacy binding comes last and then everything else follows it";
    let id = post(s, cat, None, &format!("{said}, eventually"), 100);
    assert_eq!(found(s, &query(&format!("\"{said}\""))), [id]);
}

fn bob_writing() -> Author {
    Author {
        nick: "Bob".into(),
        login: Some("bob".into()),
        fingerprint: None,
    }
}

/// Bob's mailbox: keyed by login, as an account with no identity is.
fn bob() -> Mailbox {
    Mailbox::login("bob")
}

/// Alice's: keyed by the fingerprint `alice()` writes with.
fn alice_mailbox() -> Mailbox {
    Mailbox::identified("alice", [7u8; 32])
}

fn post_by(
    s: &dyn NewsStore,
    author: Author,
    category: NodeId,
    parent: Option<ArticleId>,
    body: &str,
    at: u64,
) -> ArticleId {
    let mut p = new_post(category, parent, body, at);
    p.author = author;
    s.post(&p, 32, 32)
        .unwrap_or_else(|e| panic!("posting {body}: {e:?}"))
        .id
}

fn unread_of(s: &dyn NewsStore, owner: &Mailbox, scope: SubScope) -> usize {
    s.subscriptions(owner)
        .unwrap()
        .into_iter()
        .find(|sub| sub.scope == scope)
        .unwrap_or_else(|| panic!("{} follows nothing at {scope:?}", owner.login))
        .unread
}

fn a_subscription_starts_caught_up_and_counts_what_follows(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    post(s, cat, Some(root), "early reply", 101);
    let thread = SubScope::Thread(root);
    assert_eq!(
        s.subscribe(&bob(), thread, false, 10, t(102)).unwrap(),
        0,
        "a new row starts caught up, or the catch-up rule never rings it"
    );
    let reply = post(s, cat, Some(root), "a reply", 103);
    post_by(s, bob_writing(), cat, Some(root), "bob's own", 104);
    assert_eq!(
        unread_of(s, &bob(), thread),
        1,
        "what bob wrote is not news to bob"
    );
    s.tombstone(reply, "mod", t(105)).unwrap();
    assert_eq!(unread_of(s, &bob(), thread), 0, "nor is a tombstone");

    // A category counts new threads, not replies.
    let whole = SubScope::Category(cat);
    assert_eq!(s.subscribe(&bob(), whole, false, 10, t(106)).unwrap(), 0);
    post(s, cat, Some(root), "another reply", 107);
    assert_eq!(unread_of(s, &bob(), whole), 0);
    post(s, cat, None, "a new thread", 108);
    assert_eq!(unread_of(s, &bob(), whole), 1);
    assert_eq!(
        s.unread_total(&bob()).unwrap(),
        2,
        "the thread's one and the category's one"
    );
}

fn a_subscription_needs_something_to_be_about(s: &dyn NewsStore) {
    let bundle = node(s, None, NodeKind::Bundle, "Projects");
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    let reply = post(s, cat, Some(root), "reply", 101);
    let refused = |scope| s.subscribe(&bob(), scope, false, 10, t(102));
    assert_eq!(
        refused(SubScope::Thread(reply)),
        Err(NewsError::NoSuchArticle),
        "a reply is not a thread"
    );
    assert_eq!(
        refused(SubScope::Thread(9999)),
        Err(NewsError::NoSuchArticle)
    );
    assert_eq!(
        refused(SubScope::Category(bundle)),
        Err(NewsError::NotACategory)
    );
    assert_eq!(
        refused(SubScope::Category(9999)),
        Err(NewsError::NoSuchNode)
    );
    assert_eq!(
        s.mute(&bob(), SubScope::Category(bundle), true, 10, t(102)),
        Err(NewsError::NotACategory)
    );
    assert!(s.subscriptions(&bob()).unwrap().is_empty());
}

fn asking_is_explicit_and_posting_takes_nothing_back(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    let thread = SubScope::Thread(root);
    let row = |scope| {
        s.subscriptions(&bob())
            .unwrap()
            .into_iter()
            .find(|sub| sub.scope == scope)
    };

    s.subscribe(&bob(), thread, true, 10, t(101)).unwrap();
    let r = row(thread).unwrap();
    assert!(r.auto && !r.muted);
    s.subscribe(&bob(), thread, false, 10, t(102)).unwrap();
    assert!(!row(thread).unwrap().auto, "asking makes it explicit");
    s.mute(&bob(), thread, true, 10, t(103)).unwrap();
    s.subscribe(&bob(), thread, true, 10, t(104)).unwrap();
    assert!(
        row(thread).unwrap().muted,
        "posting again does not take back a mute"
    );
    s.subscribe(&bob(), thread, false, 10, t(105)).unwrap();
    assert!(
        !row(thread).unwrap().muted,
        "asking to follow is asking to hear about it"
    );

    // Muting what nobody followed makes a row an automatic subscribe
    // cannot touch: how a thread says "never".
    let other = SubScope::Thread(post(s, cat, None, "other", 106));
    s.mute(&bob(), other, true, 10, t(107)).unwrap();
    s.subscribe(&bob(), other, true, 10, t(108)).unwrap();
    let r = row(other).unwrap();
    assert!(r.muted && !r.auto);

    let third = SubScope::Thread(post(s, cat, None, "third", 109));
    s.mute(&bob(), third, false, 10, t(110)).unwrap();
    assert!(
        row(third).is_none(),
        "unmuting what is not followed is nothing"
    );

    assert!(s.unsubscribe(&bob(), thread).unwrap());
    assert!(!s.unsubscribe(&bob(), thread).unwrap());
    assert!(row(thread).is_none());
}

fn the_cap_counts_every_row(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let [a, b, c] = ["a", "b", "c"].map(|body| SubScope::Thread(post(s, cat, None, body, 100)));
    s.subscribe(&bob(), a, false, 2, t(101)).unwrap();
    s.mute(&bob(), b, true, 2, t(102)).unwrap();
    assert_eq!(
        s.subscribe(&bob(), c, false, 2, t(103)),
        Err(NewsError::TooManySubs),
        "a muted row is a row"
    );
    assert_eq!(
        s.mute(&bob(), c, true, 2, t(103)),
        Err(NewsError::TooManySubs)
    );
    assert_eq!(
        s.subscribe(&bob(), a, false, 2, t(104)),
        Ok(0),
        "what is already held is not a new row"
    );
    assert_eq!(
        s.subscribe(&alice_mailbox(), c, false, 2, t(105)),
        Ok(0),
        "the cap is per mailbox"
    );
}

fn a_cursor_moves_forward_and_no_further_than_the_news(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    let thread = SubScope::Thread(root);
    s.subscribe(&bob(), thread, false, 10, t(101)).unwrap();
    let first = post(s, cat, Some(root), "one", 102);
    let second = post(s, cat, Some(root), "two", 103);
    assert_eq!(s.seen(&bob(), thread, first).unwrap(), Some(1));
    assert_eq!(
        s.seen(&bob(), thread, root).unwrap(),
        Some(1),
        "never backwards"
    );
    assert_eq!(s.seen(&bob(), thread, ArticleId::MAX).unwrap(), Some(0));
    assert_eq!(s.subscriptions(&bob()).unwrap()[0].last_seen, second);
    post(s, cat, Some(root), "three", 104);
    assert_eq!(
        unread_of(s, &bob(), thread),
        1,
        "an id from the future marked nothing that came later"
    );
    assert_eq!(
        s.seen(&Mailbox::login("carol"), thread, second).unwrap(),
        None
    );
}

fn a_posts_audience_sees_muted_rows_too(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    let thread = SubScope::Thread(root);
    let carol = Mailbox::login("carol");
    s.subscribe(&bob(), thread, false, 10, t(101)).unwrap();
    s.mute(&carol, thread, true, 10, t(102)).unwrap();
    s.subscribe(
        &Mailbox::login("dave"),
        SubScope::Category(cat),
        false,
        10,
        t(103),
    )
    .unwrap();
    post(s, cat, Some(root), "a reply", 104);

    let mut rows = s.subscribers(root, None).unwrap();
    rows.sort_by(|a, b| a.owner.login.cmp(&b.owner.login));
    assert_eq!(
        rows.iter()
            .map(|r| (r.owner.login.as_str(), r.muted, r.unread))
            .collect::<Vec<_>>(),
        [("bob", false, 1), ("carol", true, 1)]
    );
    let rows = s.subscribers(root, Some(cat)).unwrap();
    let dave = rows.iter().find(|r| r.owner.login == "dave").unwrap();
    assert_eq!(
        (dave.scope, dave.unread),
        (SubScope::Category(cat), 0),
        "a reply is no new thread"
    );
    assert_eq!(
        s.unread_total(&carol).unwrap(),
        0,
        "a muted row badges nothing"
    );
}

fn the_two_kinds_of_mailbox_never_meet(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    let thread = SubScope::Thread(root);
    let by_login = Mailbox::login("alice");
    s.subscribe(&by_login, thread, false, 10, t(101)).unwrap();
    assert!(
        s.subscriptions(&alice_mailbox()).unwrap().is_empty(),
        "an identity never picks up a login's rows"
    );
    s.subscribe(&alice_mailbox(), thread, false, 10, t(102))
        .unwrap();
    assert_eq!(s.subscriptions(&by_login).unwrap().len(), 1);
    assert_eq!(
        s.subscriptions(&Mailbox::identified("alicia", [7u8; 32]))
            .unwrap()
            .len(),
        1,
        "an identity is itself under any login"
    );
    // `alice()` writes with the fingerprint, so the article is the
    // identity's own and only the login-keyed mailbox counts it.
    post(s, cat, Some(root), "alice again", 103);
    assert_eq!(unread_of(s, &alice_mailbox(), thread), 0);
    assert_eq!(unread_of(s, &by_login, thread), 1);
}

fn linking_rotating_and_deleting_move_the_rows(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let a = SubScope::Thread(post(s, cat, None, "a", 100));
    let b = SubScope::Thread(post(s, cat, None, "b", 101));
    let (first, second) = ([1u8; 32], [2u8; 32]);
    let by_login = Mailbox::login("carol");
    let linked = Mailbox::identified("carol", first);
    s.subscribe(&by_login, a, false, 10, t(102)).unwrap();
    s.subscribe(&by_login, b, false, 10, t(103)).unwrap();
    // The identity already follows b, muted, which tells its row apart.
    s.mute(&linked, b, true, 10, t(104)).unwrap();

    assert_eq!(s.subs_claim("carol", &first).unwrap(), 2);
    assert!(s.subscriptions(&by_login).unwrap().is_empty());
    let rows = s.subscriptions(&linked).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().find(|r| r.scope == b).unwrap().muted,
        "where both followed one scope, the identity's row stands"
    );

    assert_eq!(s.subs_rotate(&first, &second).unwrap(), 2);
    assert!(s.subscriptions(&linked).unwrap().is_empty());
    let rotated = Mailbox::identified("carol", second);
    assert_eq!(s.subscriptions(&rotated).unwrap().len(), 2);

    assert_eq!(s.subs_purge(&rotated).unwrap(), 2);
    assert!(s.subscriptions(&rotated).unwrap().is_empty());
}

fn rows_go_with_what_they_follow(s: &dyn NewsStore) {
    let general = category(s, "General");
    let other = category(s, "Other");
    let old = post(s, general, None, "old", 100);
    let recent = post(s, other, None, "recent", 10_000);
    for scope in [
        SubScope::Thread(old),
        SubScope::Category(general),
        SubScope::Thread(recent),
        SubScope::Category(other),
    ] {
        s.subscribe(&bob(), scope, false, 10, t(10_001)).unwrap();
    }
    s.delete_node(general).unwrap();
    let scopes = |s: &dyn NewsStore| {
        let mut v: Vec<SubScope> = s
            .subscriptions(&bob())
            .unwrap()
            .into_iter()
            .map(|sub| sub.scope)
            .collect();
        v.sort_by_key(|scope| scope.key());
        v
    };
    assert_eq!(
        scopes(s),
        [SubScope::Category(other), SubScope::Thread(recent)]
    );
    s.prune(Duration::from_secs(10), t(20_000)).unwrap();
    assert_eq!(scopes(s), [SubScope::Category(other)]);
    assert_eq!(
        s.subscribe(&bob(), SubScope::Thread(recent), false, 2, t(20_001)),
        Err(NewsError::NoSuchArticle),
        "and the rows that went count against nothing"
    );
}

fn a_listing_is_newest_first_and_says_what_it_follows(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "question", 100);
    s.subscribe(&bob(), SubScope::Thread(root), false, 10, t(101))
        .unwrap();
    s.subscribe(&bob(), SubScope::Category(cat), false, 10, t(102))
        .unwrap();
    let rows = s.subscriptions(&bob()).unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (r.scope, r.category, r.label.as_str(), r.at))
            .collect::<Vec<_>>(),
        [
            (SubScope::Category(cat), cat, "General", t(102)),
            (SubScope::Thread(root), cat, "about question", t(101)),
        ]
    );
    s.tombstone(root, "mod", t(103)).unwrap();
    assert_eq!(
        s.subscriptions(&bob()).unwrap()[1].label,
        "",
        "a tombstone keeps its place and loses its words"
    );
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn alice() -> Author {
    Author {
        nick: "Alice".into(),
        login: Some("alice".into()),
        fingerprint: Some([7u8; 32]),
    }
}

fn node(s: &dyn NewsStore, parent: Option<NodeId>, kind: NodeKind, name: &str) -> NodeId {
    s.create_node(
        &NewNode {
            parent,
            kind,
            name: name.into(),
            guid: [name.len() as u8; 16],
            at: t(50),
        },
        16,
    )
    .unwrap_or_else(|e| panic!("creating {name}: {e:?}"))
    .id
}

fn category(s: &dyn NewsStore, name: &str) -> NodeId {
    node(s, None, NodeKind::Category, name)
}

fn new_post(category: NodeId, parent: Option<ArticleId>, body: &str, at: u64) -> NewPost {
    NewPost {
        category,
        parent,
        author: alice(),
        subject: format!("about {body}"),
        body: body.into(),
        mime: BodyType::Plain,
        refs: Vec::new(),
        at: t(at),
    }
}

fn post(
    s: &dyn NewsStore,
    category: NodeId,
    parent: Option<ArticleId>,
    body: &str,
    at: u64,
) -> ArticleId {
    s.post(&new_post(category, parent, body, at), 32, 32)
        .unwrap_or_else(|e| panic!("posting {body}: {e:?}"))
        .id
}

fn page(
    category: NodeId,
    before: Option<ArticleId>,
    after: Option<ArticleId>,
    limit: usize,
) -> ThreadQuery {
    ThreadQuery {
        category,
        before,
        after,
        limit,
    }
}

fn nodes_nest_and_list_by_name(s: &dyn NewsStore) {
    let projects = node(s, None, NodeKind::Bundle, "Projects");
    node(s, None, NodeKind::Category, "Announcements");
    let inner = node(s, Some(projects), NodeKind::Category, "hxd-ng");

    let root: Vec<String> = s.nodes(None).unwrap().into_iter().map(|n| n.name).collect();
    assert_eq!(root, ["Announcements", "Projects"], "listed by name");

    let p = s.node(projects).unwrap().unwrap();
    assert_eq!(p.kind, NodeKind::Bundle);
    assert_eq!(p.parent, None);
    assert_eq!(p.children, 1, "a bundle counts its sub-nodes");
    assert_eq!(p.guid, [8u8; 16], "the guid is the one it was made with");
    assert_eq!((p.add_sn, p.delete_sn), (1, 1));
    assert_eq!(p.created_at, t(50));

    let c = s.node(inner).unwrap().unwrap();
    assert_eq!(c.parent, Some(projects));
    assert_eq!(c.kind, NodeKind::Category);
    assert_eq!(s.nodes(Some(projects)).unwrap(), vec![c]);
    assert!(s.nodes(Some(inner)).unwrap().is_empty());
    assert!(s.node(9999).unwrap().is_none());
}

fn a_name_is_unique_among_its_siblings_only(s: &dyn NewsStore) {
    let general = node(s, None, NodeKind::Category, "General");
    let bundle = node(s, None, NodeKind::Bundle, "Bundle");
    let again = NewNode {
        parent: None,
        kind: NodeKind::Category,
        name: "General".into(),
        guid: [0; 16],
        at: t(1),
    };
    assert_eq!(s.create_node(&again, 16), Err(NewsError::NameTaken));
    // The same name one level down is a different address.
    node(s, Some(bundle), NodeKind::Category, "General");

    assert_eq!(s.rename_node(bundle, "General"), Err(NewsError::NameTaken));
    let renamed = s.rename_node(bundle, "Bee").unwrap();
    assert_eq!(renamed.name, "Bee");
    assert_eq!(renamed.id, bundle);
    assert_eq!(
        s.rename_node(general, "General").unwrap().name,
        "General",
        "renaming a node to its own name is not a collision"
    );
    assert_eq!(s.rename_node(9999, "x"), Err(NewsError::NoSuchNode));
}

fn containment_is_the_legacy_wires(s: &dyn NewsStore) {
    let bundle = node(s, None, NodeKind::Bundle, "Bundle");
    let cat = category(s, "Category");
    let under = |parent| NewNode {
        parent: Some(parent),
        kind: NodeKind::Category,
        name: "child".into(),
        guid: [0; 16],
        at: t(1),
    };
    assert_eq!(s.create_node(&under(cat), 16), Err(NewsError::NotACategory));
    assert_eq!(s.create_node(&under(9999), 16), Err(NewsError::NoSuchNode));

    let into = |category| s.post(&new_post(category, None, "x", 1), 32, 32);
    assert_eq!(into(bundle), Err(NewsError::NotACategory));
    assert_eq!(into(9999), Err(NewsError::NoSuchNode));
    assert_eq!(
        s.post(&new_post(9999, Some(9999), "x", 1), 32, 32),
        Err(NewsError::NoSuchNode),
        "the category is checked before the parent"
    );

    assert_eq!(
        s.threads(&page(bundle, None, None, 10)),
        Err(NewsError::NotACategory)
    );
    assert_eq!(
        s.threads(&page(9999, None, None, 10)),
        Err(NewsError::NoSuchNode)
    );
}

fn nodes_nest_no_deeper_than_allowed(s: &dyn NewsStore) {
    let deep = |parent, name: &str| {
        s.create_node(
            &NewNode {
                parent,
                kind: NodeKind::Bundle,
                name: name.into(),
                guid: [0; 16],
                at: t(1),
            },
            2,
        )
    };
    let one = deep(None, "one").unwrap();
    let two = deep(Some(one.id), "two").unwrap();
    assert_eq!(deep(Some(two.id), "three"), Err(NewsError::TooDeep));
}

fn an_article_round_trips_whole(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let Posted { id, root } = s
        .post(&new_post(cat, None, "hello\nworld", 1_789_000_000), 32, 32)
        .unwrap();
    assert_eq!(root, id, "a starter is its own root");
    let a = s.article(id).unwrap().unwrap();
    assert_eq!(a.id, id);
    assert_eq!(a.category, cat);
    assert_eq!(a.parent, None);
    assert_eq!(a.root, id);
    assert_eq!(a.depth, 0);
    assert_eq!(a.author, alice());
    assert_eq!(a.subject, "about hello\nworld");
    assert_eq!(a.body, "hello\nworld");
    assert_eq!(a.mime, BodyType::Plain);
    assert_eq!(a.at, t(1_789_000_000));
    assert!(!a.deleted);
    assert!(a.refs.is_empty());
    assert_eq!(a.referenced_by, 0);

    let guest = NewPost {
        author: Author {
            nick: "guest".into(),
            login: None,
            fingerprint: None,
        },
        ..new_post(cat, Some(id), "a guest's reply", 2)
    };
    let reply = s.post(&guest, 32, 32).unwrap();
    assert_eq!(reply.root, id);
    assert_eq!(s.article(reply.id).unwrap().unwrap().author.login, None);

    let n = s.node(cat).unwrap().unwrap();
    assert_eq!(n.children, 2, "a category counts its articles");
    assert_eq!(n.add_sn, 3, "every post bumps the add serial");
    assert!(s.article(9999).unwrap().is_none());

    // A store keeps whole seconds, so a post's fraction of one is not in
    // what comes back — from either store, or a window ending on that
    // second would answer differently about it in each.
    let mut late = new_post(cat, None, "half past", 7);
    late.at += Duration::from_millis(500);
    let late = s.post(&late, 32, 32).unwrap().id;
    assert_eq!(s.article(late).unwrap().unwrap().at, t(7));
}

fn a_thread_comes_back_in_preorder(s: &dyn NewsStore) {
    // docs/news.md §2's tree, and one thing it does not show: a reply to
    // an early reply, posted last, which must still sit under its parent
    // rather than at the end.
    let cat = category(s, "hxd-ng");
    let starter = post(s, cat, None, "Phase 4 is open", 1);
    let other = post(s, cat, None, "Attachment sizes", 2);
    let first = post(s, cat, Some(starter), "first reply", 3);
    let second = post(s, cat, Some(starter), "second reply", 4);
    let deep = post(s, cat, Some(second), "reply to the second", 5);
    let late = post(s, cat, Some(first), "late reply to the first", 6);
    post(s, cat, Some(other), "elsewhere", 7);

    let page = s.thread(starter, None, None, 100).unwrap();
    assert!(!page.has_more);
    let order: Vec<(ArticleId, u16)> = page.articles.iter().map(|a| (a.id, a.depth)).collect();
    assert_eq!(
        order,
        [(starter, 0), (first, 1), (late, 2), (second, 1), (deep, 2)]
    );
    assert!(page.articles.iter().all(|a| a.root == starter));
    assert_eq!(page.articles[2].parent, Some(first));
}

fn a_reply_stays_in_its_parents_category_and_depth(s: &dyn NewsStore) {
    let here = category(s, "Here");
    let there = category(s, "There");
    let starter = post(s, here, None, "starter", 1);
    assert_eq!(
        s.post(&new_post(there, Some(starter), "x", 2), 32, 32),
        Err(NewsError::WrongCategory)
    );
    assert_eq!(
        s.post(&new_post(here, Some(9999), "x", 2), 32, 32),
        Err(NewsError::NoSuchArticle)
    );
    let one = s
        .post(&new_post(here, Some(starter), "1", 3), 2, 32)
        .unwrap();
    let two = s
        .post(&new_post(here, Some(one.id), "2", 4), 2, 32)
        .unwrap();
    assert_eq!(s.article(two.id).unwrap().unwrap().depth, 2);
    assert_eq!(
        s.post(&new_post(here, Some(two.id), "3", 5), 2, 32),
        Err(NewsError::TooDeep)
    );
}

fn threads_page_newest_first_in_both_directions(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let elsewhere = category(s, "Elsewhere");
    let ids: Vec<ArticleId> = (1..=5)
        .map(|n| post(s, cat, None, &format!("t{n}"), n))
        .collect();
    let [t1, t2, t3, t4, t5] = ids[..] else {
        unreachable!()
    };
    post(s, elsewhere, None, "not in this category", 6);
    post(s, cat, Some(t3), "a reply", 100);
    let last = post(s, cat, Some(t3), "another reply", 90);

    let ids_of = |p: &super::ThreadPage| p.threads.iter().map(|h| h.article.id).collect::<Vec<_>>();

    let newest = s.threads(&page(cat, None, None, 2)).unwrap();
    assert_eq!(ids_of(&newest), [t5, t4]);
    assert!(newest.has_more);
    let older = s.threads(&page(cat, Some(t4), None, 2)).unwrap();
    assert_eq!(ids_of(&older), [t3, t2]);
    assert!(older.has_more);
    let oldest = s.threads(&page(cat, Some(t2), None, 2)).unwrap();
    assert_eq!(ids_of(&oldest), [t1]);
    assert!(!oldest.has_more);

    let newer = s.threads(&page(cat, None, Some(t1), 2)).unwrap();
    assert_eq!(
        ids_of(&newer),
        [t3, t2],
        "the threads nearest the cursor, newest first"
    );
    assert!(newer.has_more);
    let newest_again = s.threads(&page(cat, None, Some(t3), 5)).unwrap();
    assert_eq!(ids_of(&newest_again), [t5, t4]);
    assert!(!newest_again.has_more);
    let between = s.threads(&page(cat, Some(t5), Some(t1), 5)).unwrap();
    assert_eq!(ids_of(&between), [t4, t3, t2]);
    assert!(!between.has_more);

    let head = &older.threads[0];
    assert_eq!(head.replies, 2);
    assert_eq!(head.last_at, t(100), "the latest time, not the latest id's");
    assert_eq!(head.last_id, last);
    assert_eq!(head.article.body, "t3", "the starter comes whole");
    let quiet = &older.threads[1];
    assert_eq!((quiet.replies, quiet.last_id, quiet.last_at), (0, t2, t(2)));
}

fn a_thread_pages_forward_through_its_replies(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let root = post(s, cat, None, "root", 1);
    let a = post(s, cat, Some(root), "a", 2);
    let b = post(s, cat, Some(a), "b", 3);
    let c = post(s, cat, Some(root), "c", 4);
    let d = post(s, cat, Some(c), "d", 5);
    let other = post(s, cat, None, "other", 6);

    let ids = |p: &super::ArticlePage| p.articles.iter().map(|a| a.id).collect::<Vec<_>>();
    let first = s.thread(root, None, None, 2).unwrap();
    assert_eq!(ids(&first), [root, a]);
    assert!(first.has_more);
    let snapshot = first.snapshot;
    assert_eq!(snapshot, d);
    let late = post(s, cat, Some(a), "late beneath an earlier reply", 7);
    let second = s.thread(root, Some(a), Some(snapshot), 2).unwrap();
    assert_eq!(ids(&second), [b, c]);
    assert!(second.has_more);
    assert_eq!(second.snapshot, snapshot);
    let third = s.thread(root, Some(c), Some(snapshot), 2).unwrap();
    assert_eq!(ids(&third), [d]);
    assert!(!third.has_more);
    assert_eq!(third.snapshot, snapshot);
    assert_eq!(
        ids(&s.thread(root, None, None, 10).unwrap()),
        [root, a, b, late, c, d],
        "a fresh traversal sees the reply that the earlier snapshot excludes"
    );

    assert_eq!(
        s.thread(root, Some(other), Some(snapshot), 2),
        Err(NewsError::NoSuchArticle),
        "a cursor from another thread is not a place in this one"
    );
    assert_eq!(
        s.thread(a, None, None, 2),
        Err(NewsError::NoSuchArticle),
        "a reply is not a thread"
    );
    assert_eq!(s.thread(9999, None, None, 2), Err(NewsError::NoSuchArticle));
}

fn references_resolve_once_and_report_their_target_now(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let other = category(s, "Other");
    let a = post(s, cat, None, "a", 1);
    let b = post(s, other, None, "b, in another category", 2);

    let citing = |refs: Vec<ArticleId>, max_refs| {
        let mut p = new_post(cat, None, "citing", 3);
        p.refs = refs;
        s.post(&p, 32, max_refs).unwrap().id
    };
    let c = citing(vec![b, a, 9999, b], 32);
    let got = s.article(c).unwrap().unwrap();
    assert_eq!(
        got.refs.iter().map(|r| r.id).collect::<Vec<_>>(),
        [b, a],
        "in order of appearance, once each, and only what exists"
    );
    assert_eq!(got.refs[0].subject, "about b, in another category");
    assert_eq!(got.refs[0].author_nick, "Alice");
    assert_eq!(got.refs[0].at, t(2));
    assert!(!got.refs[0].deleted);
    assert_eq!(s.article(a).unwrap().unwrap().referenced_by, 1);
    assert_eq!(
        s.refs_to(a, 10)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        [c]
    );

    let capped = citing(vec![a, b, c], 2);
    assert_eq!(
        s.article(capped)
            .unwrap()
            .unwrap()
            .refs
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        [a, b]
    );
    assert_eq!(
        s.refs_to(a, 10)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        [capped, c],
        "backlinks are newest first"
    );
    assert_eq!(s.refs_to(a, 1).unwrap().len(), 1);

    // An id that names nothing is the digits someone typed, and stays
    // that — even once an article with that id exists.
    let early = citing(vec![capped + 2], 32);
    let later = post(s, cat, None, "later", 4);
    assert_eq!(later, capped + 2);
    assert!(s.article(early).unwrap().unwrap().refs.is_empty());
    assert_eq!(s.article(later).unwrap().unwrap().referenced_by, 0);
}

fn a_tombstone_keeps_its_place_and_loses_its_words(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let cited = post(s, cat, None, "cited", 1);
    let root = post(s, cat, None, "root", 2);
    let mut middle = new_post(cat, Some(root), "middle", 3);
    middle.refs = vec![cited];
    let middle = s.post(&middle, 32, 32).unwrap().id;
    let below = post(s, cat, Some(middle), "below", 4);
    let mut pointer = new_post(cat, None, "points at the middle", 5);
    pointer.refs = vec![middle];
    let pointer = s.post(&pointer, 32, 32).unwrap().id;
    let before = s.node(cat).unwrap().unwrap();

    let was = s.tombstone(middle, "moderator", t(10)).unwrap().unwrap();
    assert_eq!(was.body, "middle", "the article as it was, for the record");
    assert_eq!(was.refs.len(), 1);

    let thread = s.thread(root, None, None, 10).unwrap();
    assert_eq!(
        thread.articles.iter().map(|a| a.id).collect::<Vec<_>>(),
        [root, middle, below],
        "its replies stay where they are"
    );
    let stone = &thread.articles[1];
    assert!(stone.deleted);
    assert_eq!(stone.subject, "");
    assert_eq!(stone.body, "");
    assert_eq!(stone.author.nick, "");
    assert_eq!(stone.author.login, None);
    assert_eq!(stone.author.fingerprint, None);
    assert_eq!((stone.parent, stone.at), (Some(root), t(3)));
    assert!(stone.refs.is_empty(), "its references went with its body");
    assert_eq!(s.article(cited).unwrap().unwrap().referenced_by, 0);
    assert!(s.refs_to(cited, 10).unwrap().is_empty());

    let inbound = &s.article(pointer).unwrap().unwrap().refs[0];
    assert_eq!(inbound.id, middle);
    assert!(inbound.deleted, "a pointer to it still says it is gone");
    assert_eq!(inbound.subject, "");

    let after = s.node(cat).unwrap().unwrap();
    assert_eq!(after.delete_sn, before.delete_sn + 1);
    assert_eq!(after.children, before.children - 1);
    assert!(s.tombstone(middle, "moderator", t(11)).unwrap().is_none());
    assert!(s.tombstone(9999, "moderator", t(11)).unwrap().is_none());
}

fn a_thread_of_nothing_but_tombstones_is_not_listed(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let alone = post(s, cat, None, "alone", 1);
    let busy = post(s, cat, None, "busy", 2);
    let reply = post(s, cat, Some(busy), "reply", 3);
    s.tombstone(alone, "m", t(4)).unwrap();
    s.tombstone(busy, "m", t(4)).unwrap();
    let listed = |s: &dyn NewsStore| {
        s.threads(&page(cat, None, None, 10))
            .unwrap()
            .threads
            .iter()
            .map(|h| h.article.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(listed(s), [busy], "a live reply keeps its thread listed");
    s.tombstone(reply, "m", t(5)).unwrap();
    assert!(listed(s).is_empty());
}

fn deleting_a_category_takes_its_articles_and_a_bundle_must_be_empty(s: &dyn NewsStore) {
    let bundle = node(s, None, NodeKind::Bundle, "Bundle");
    let doomed = node(s, Some(bundle), NodeKind::Category, "Doomed");
    let kept = category(s, "Kept");
    let root = post(s, doomed, None, "root", 1);
    post(s, doomed, Some(root), "reply", 2);
    let stone = post(s, doomed, None, "tombstoned", 3);
    s.tombstone(stone, "m", t(4)).unwrap();
    let mut citing = new_post(kept, None, "cites into the doomed category", 5);
    citing.refs = vec![root];
    let citing = s.post(&citing, 32, 32).unwrap().id;

    assert_eq!(s.delete_node(bundle), Err(NewsError::NotEmpty));
    assert_eq!(s.delete_node(doomed), Ok(3), "tombstones are articles too");
    assert!(s.node(doomed).unwrap().is_none());
    assert!(s.article(root).unwrap().is_none());
    assert!(
        s.article(citing).unwrap().unwrap().refs.is_empty(),
        "a reference to something that no longer exists at all goes with it"
    );
    assert_eq!(s.delete_node(bundle), Ok(0));
    assert_eq!(s.delete_node(bundle), Err(NewsError::NoSuchNode));
}

fn pruning_takes_whole_threads_by_their_last_post(s: &dyn NewsStore) {
    let cat = category(s, "General");
    let alive = post(s, cat, None, "old starter, recent reply", 100);
    post(s, cat, Some(alive), "recent", 1000);
    let stale = post(s, cat, None, "old and quiet", 100);
    post(s, cat, Some(stale), "also old", 200);
    // Stale threads that take turns between two categories: each
    // category's serial moves once for the prune, however its threads
    // interleave with another's.
    let elsewhere = category(s, "Elsewhere");
    post(s, elsewhere, None, "old, somewhere else", 100);
    post(s, cat, None, "old again", 100);
    let mut citing = new_post(cat, None, "cites the stale one", 1100);
    citing.refs = vec![stale];
    let citing = s.post(&citing, 32, 32).unwrap().id;
    let before = s.node(cat).unwrap().unwrap().delete_sn;
    let before_elsewhere = s.node(elsewhere).unwrap().unwrap().delete_sn;

    let gone = s.prune(Duration::from_secs(500), t(1200)).unwrap();
    assert_eq!(gone, 4);
    assert!(s.article(stale).unwrap().is_none());
    assert!(s.article(alive).unwrap().is_some());
    assert_eq!(s.thread(alive, None, None, 10).unwrap().articles.len(), 2);
    assert!(s.article(citing).unwrap().unwrap().refs.is_empty());
    assert_eq!(s.node(cat).unwrap().unwrap().delete_sn, before + 1);
    assert_eq!(
        s.node(elsewhere).unwrap().unwrap().delete_sn,
        before_elsewhere + 1
    );

    assert_eq!(
        s.prune(Duration::from_secs(10_000), t(1200)).unwrap(),
        0,
        "a window longer than the clock has run prunes nothing"
    );
}

#[cfg(test)]
#[test]
fn memory_news_passes() {
    run(&|| Box::<super::MemoryNews>::default());
}
