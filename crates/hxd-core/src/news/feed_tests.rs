//! Feeds as the domain sees them (`docs/news-feeds.md` §3, §5): the
//! category a feed fills, what may be done in it, and what a poll's items
//! become. Items are built by hand; fetching is `hxd-feeds`'.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::roster::{drain, test_attach};

fn core_with(policy: NewsPolicy) -> Core {
    Core::new().with_news(Arc::new(MemoryNews::new()), policy)
}

fn spec(name: &str, path: &[&str]) -> FeedSpec {
    FeedSpec {
        name: name.into(),
        url: format!("https://example.com/{name}.atom"),
        category: path.iter().map(|s| s.to_string()).collect(),
        keep: 100,
        first_import: 100,
        author: None,
        replies: false,
    }
}

fn open(core: &Core, spec: FeedSpec) -> Feed {
    core.news_feeds_open(&[spec]).unwrap().remove(0)
}

fn item(n: u8) -> FeedItem {
    FeedItem {
        key: [n; 32],
        subject: format!("Release {n}"),
        author: Some("Jeff".into()),
        at: UNIX_EPOCH + Duration::from_secs(1_790_000_000 + u64::from(n)),
        body: format!("Notes for {n}."),
        markdown: false,
    }
}

fn items(range: std::ops::RangeInclusive<u8>) -> Vec<FeedItem> {
    range.map(item).collect()
}

/// The subjects of a category's live articles, oldest first.
fn subjects(core: &Core, category: NodeId) -> Vec<String> {
    let store = core.news.as_ref().unwrap();
    let mut listed = store.recent(category, 1000).unwrap();
    listed.retain(|a| !a.deleted);
    listed.sort_by_key(|a| a.id);
    listed.into_iter().map(|a| a.subject).collect()
}

fn reader() -> AccessBits {
    AccessBits::empty().with(bit::READ_NEWS)
}

fn editor() -> AccessBits {
    reader()
        .with(bit::POST_NEWS)
        .with(bit::DELETE_ARTICLES)
        .with(bit::CREATE_CATEGORIES)
        .with(bit::DELETE_CATEGORIES)
}

fn post(
    core: &Core,
    uid: Uid,
    category: NodeId,
    parent: Option<ArticleId>,
) -> Result<ArticleId, NewsError> {
    core.news_post(
        uid,
        PostRequest {
            category,
            parent,
            subject: "hello".into(),
            body: "a local post".into(),
            mime: BodyType::Plain,
            attachments: Vec::new(),
        },
    )
}

#[test]
fn opening_a_feed_makes_its_category_or_adopts_the_one_there() {
    let core = core_with(NewsPolicy::default());
    let (ed, _rx) = test_attach(&core, "ed", editor());
    let made = open(&core, spec("mobius", &["Software", "Mobius"]));
    let bundle = core.news_tree(ed, None, 1).unwrap();
    assert_eq!(bundle.len(), 1);
    assert_eq!(
        (bundle[0].node.name.as_str(), bundle[0].node.kind),
        ("Software", NodeKind::Bundle)
    );
    assert_eq!(
        open(&core, spec("mobius", &["Software", "Mobius"])).category,
        made.category
    );

    let general = core
        .news_node_create(ed, None, NodeKind::Category, "General")
        .unwrap()
        .id;
    let local = post(&core, ed, general, None).unwrap();
    let adopted = open(&core, spec("releases", &["General"]));
    assert_eq!(adopted.category, general);
    assert!(core.news_article(ed, local).is_ok(), "what was there stays");

    for path in [&["Software"][..], &["General", "Deeper"]] {
        assert_eq!(
            core.news_feeds_open(&[spec("wrong", path)]),
            Err(NewsError::NotACategory),
            "{path:?}"
        );
    }
}

#[test]
fn a_feed_category_is_read_only_until_the_feed_goes() {
    let core = core_with(NewsPolicy::default());
    let (ed, _rx) = test_attach(&core, "ed", editor());
    let feed = open(&core, spec("mobius", &["Releases"]));
    core.news_feed_import(&feed, items(1..=1)).unwrap();
    let imported = core.news_store().unwrap().recent(feed.category, 1).unwrap()[0].id;
    assert_eq!(core.news_feed_of(feed.category).as_deref(), Some("mobius"));

    assert_eq!(
        post(&core, ed, feed.category, None),
        Err(NewsError::ReadOnly)
    );
    assert_eq!(
        post(&core, ed, feed.category, Some(imported)),
        Err(NewsError::ReadOnly)
    );
    assert_eq!(
        core.news_node_rename(ed, feed.category, "Renamed"),
        Err(NewsError::ReadOnly)
    );
    assert_eq!(
        core.news_node_delete(ed, feed.category),
        Err(NewsError::ReadOnly)
    );

    core.news_delete(ed, imported).unwrap();
    let again = core.news_feed_import(&feed, items(1..=1)).unwrap();
    assert_eq!(again.posted, 0, "a deleted item stays deleted");

    core.news_feeds_open(&[]).unwrap();
    assert_eq!(core.news_feed_of(feed.category), None);
    post(&core, ed, feed.category, None).unwrap();
}

#[test]
fn a_first_poll_takes_the_newest_and_the_backlog_never_arrives() {
    let core = core_with(NewsPolicy::default());
    let feed = open(
        &core,
        FeedSpec {
            first_import: 2,
            ..spec("mobius", &["Releases"])
        },
    );
    let first = core.news_feed_import(&feed, items(1..=5)).unwrap();
    assert_eq!(first.posted, 2);
    assert_eq!(subjects(&core, feed.category), ["Release 4", "Release 5"]);

    let next = core.news_feed_import(&feed, items(1..=7)).unwrap();
    assert_eq!(next.posted, 2);
    assert_eq!(
        subjects(&core, feed.category),
        ["Release 4", "Release 5", "Release 6", "Release 7"]
    );
}

#[test]
fn an_article_is_its_item_and_never_a_reference() {
    let core = core_with(NewsPolicy {
        max_subject: 12,
        ..NewsPolicy::default()
    });
    let (reader, _rx) = test_attach(&core, "reader", reader());
    let feed = open(&core, spec("mobius", &["Releases"]));
    let general = open(&core, spec("general", &["General"]));
    let now = SystemTime::now();
    let tomorrow = now + Duration::from_secs(24 * 3600);
    let raw = vec![
        FeedItem {
            subject: "  \n ".into(),
            author: None,
            body: "Fixes #1 and #2.".into(),
            ..item(1)
        },
        FeedItem {
            subject: "Ünïcödé subject past the cap".into(),
            at: tomorrow,
            ..item(2)
        },
    ];
    core.news_feed_import(&feed, raw).unwrap();
    core.news_feed_import(&general, items(3..=3)).unwrap();
    let store = core.news_store().unwrap();
    let mut got = store.recent(feed.category, 10).unwrap();
    got.sort_by_key(|a| a.id);

    assert_eq!(got[0].subject, "(untitled)");
    assert_eq!(
        got[0].author.nick, "mobius",
        "no author anywhere: the feed's name"
    );
    assert_eq!(
        (got[0].author.login.as_ref(), got[0].author.fingerprint),
        (None, None)
    );
    assert_eq!(got[0].feed.as_deref(), Some("mobius"));
    let first = core.news_article(reader, got[0].id).unwrap();
    assert!(
        first.refs.is_empty(),
        "a feed's #1 is not this server's article 1"
    );

    assert_eq!(
        got[1].subject, "Ünïcödé",
        "cut at a character boundary, and trimmed"
    );
    assert_eq!(got[1].author.nick, "Jeff");
    assert!(
        got[1].at <= SystemTime::now(),
        "a feed cannot date itself ahead"
    );

    let renamed = FeedSpec {
        author: Some("Mobius releases".into()),
        ..spec("mobius", &["Releases"])
    };
    let feed = open(&core, renamed);
    core.news_feed_import(&feed, items(4..=4)).unwrap();
    let newest = store.recent(feed.category, 1).unwrap().remove(0);
    assert_eq!(newest.author.nick, "Mobius releases");
}

#[test]
fn a_feed_keeps_its_newest_and_no_more() {
    let core = core_with(NewsPolicy::default());
    let feed = open(
        &core,
        FeedSpec {
            keep: 3,
            ..spec("mobius", &["Releases"])
        },
    );
    let done = core.news_feed_import(&feed, items(1..=5)).unwrap();
    assert_eq!((done.posted, done.pruned), (5, 2));
    assert_eq!(
        subjects(&core, feed.category),
        ["Release 3", "Release 4", "Release 5"]
    );
    assert_eq!(
        core.news_feed_import(&feed, items(1..=5)).unwrap().posted,
        0
    );
}

#[test]
fn a_full_server_leaves_the_rest_for_the_next_poll() {
    let core = core_with(NewsPolicy {
        max_articles: 3,
        max_per_author: 1,
        ..NewsPolicy::default()
    });
    let (ed, _rx) = test_attach(&core, "ed", editor());
    let general = core
        .news_node_create(ed, None, NodeKind::Category, "General")
        .unwrap()
        .id;
    let local = post(&core, ed, general, None).unwrap();
    let feed = open(&core, spec("mobius", &["Releases"]));

    let done = core.news_feed_import(&feed, items(1..=4)).unwrap();
    assert_eq!(
        (done.posted, done.full),
        (2, true),
        "past max_per_author, which is for people, and stopped by max_articles"
    );
    core.news_delete(ed, local).unwrap();
    assert_eq!(
        core.news_feed_import(&feed, items(1..=4)).unwrap().posted,
        1
    );
    assert_eq!(
        subjects(&core, feed.category),
        ["Release 1", "Release 2", "Release 3"],
        "oldest first, the waiting ones in order"
    );
}

#[test]
fn an_import_is_one_announcement_however_much_it_brought() {
    let core = core_with(NewsPolicy::default());
    let (_reader, mut rx) = test_attach(&core, "reader", reader());
    let feed = open(&core, spec("mobius", &["Releases"]));
    drain(&mut rx);

    core.news_feed_import(&feed, items(1..=3)).unwrap();
    let posted: Vec<String> = drain(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::NewsPosted { subject, .. } => Some(subject),
            _ => None,
        })
        .collect();
    assert_eq!(posted, ["Release 3"]);

    core.news_feed_import(&feed, items(1..=3)).unwrap();
    assert!(
        !drain(&mut rx)
            .iter()
            .any(|e| matches!(e, Event::NewsPosted { .. })),
        "nothing new, nothing said"
    );
}

#[test]
fn an_item_changed_upstream_changes_its_article_and_says_so() {
    let core = core_with(NewsPolicy::default());
    let (ed, mut rx) = test_attach(&core, "ed", editor());
    let feed = open(&core, spec("mobius", &["Releases"]));
    core.news_feed_import(&feed, items(1..=2)).unwrap();
    let store = core.news_store().unwrap();
    let mut posted = store.recent(feed.category, 10).unwrap();
    posted.sort_by_key(|a| a.id);
    let (first, second) = (posted[0].id, posted[1].id);
    drain(&mut rx);

    let corrected = |n: u8| FeedItem {
        body: format!("Corrected notes for {n}."),
        ..item(n)
    };
    let done = core
        .news_feed_import(&feed, vec![corrected(1), item(2)])
        .unwrap();
    assert_eq!((done.posted, done.revised), (0, 1));
    assert_eq!(
        core.news_article(ed, first).unwrap().body,
        "Corrected notes for 1."
    );
    let edited: Vec<ArticleId> = drain(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::NewsEdited { id, .. } => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(edited, [first]);
    assert_eq!(
        core.news_feed_import(&feed, vec![corrected(1), item(2)])
            .unwrap()
            .revised,
        0,
        "the same words twice are one change"
    );

    core.news_delete(ed, second).unwrap();
    let done = core
        .news_feed_import(&feed, vec![corrected(1), corrected(2)])
        .unwrap();
    assert_eq!(done.revised, 0, "a deleted article stays deleted");
    assert!(core.news_article(ed, second).unwrap().deleted);
}

#[test]
fn replies_are_a_feeds_to_allow_and_keep_their_thread() {
    let core = core_with(NewsPolicy::default());
    let (ed, _rx) = test_attach(&core, "ed", editor());
    let feed = open(
        &core,
        FeedSpec {
            keep: 1,
            replies: true,
            ..spec("mobius", &["Releases"])
        },
    );
    core.news_feed_import(&feed, items(1..=1)).unwrap();
    let release = core.news_store().unwrap().recent(feed.category, 1).unwrap()[0].id;

    assert_eq!(
        post(&core, ed, feed.category, None),
        Err(NewsError::ReadOnly)
    );
    let reply = post(&core, ed, feed.category, Some(release)).unwrap();
    core.news_feed_import(&feed, items(1..=3)).unwrap();
    assert!(
        core.news_article(ed, release).is_ok(),
        "replied to, so kept past keep"
    );
    assert!(core.news_article(ed, reply).is_ok());
    assert_eq!(
        subjects(&core, feed.category),
        ["Release 1", "hello", "Release 3"]
    );
}
