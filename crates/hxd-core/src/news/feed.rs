//! Feeds polled into read-only categories (`docs/news-feeds.md`): which
//! categories a feed fills, and turning a poll's items into articles.
//! Fetching and parsing are `hxd-feeds`'; nothing here touches a network.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use super::{
    clean_name, clean_subject, news_room, normalize_newlines, store_failed, Asker, Author,
    BodyType, FeedId, FeedListing, FeedPoll, FeedPost, FeedState, MarkdownMode, NewNode, NewPost,
    NewsError, NewsStore, NodeId, NodeKind, Posted,
};
use crate::access::AccessBits;
use crate::inbox::StoreError;
use crate::roster::{Core, Event};

/// How long an item with no article may go unlisted before it is
/// forgotten (news-feeds.md §6).
pub const FEED_FORGET_AFTER: Duration = Duration::from_secs(30 * 24 * 3600);

/// The 1.5 listing carries a poster as a pstring.
const MAX_AUTHOR: usize = 255;

/// A configured feed, as the domain needs it (news-feeds.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedSpec {
    /// What remembers which items are seen; stable across URL changes.
    pub name: String,
    pub url: String,
    /// The category's names from the root.
    pub category: Vec<String>,
    /// Newest live articles kept; 0 leaves it to `retain_days`.
    pub keep: usize,
    /// Items taken from the backlog on a first poll.
    pub first_import: usize,
    /// In place of each item's own author.
    pub author: Option<String>,
    /// May people reply to its articles? Starting a thread is refused
    /// either way.
    pub replies: bool,
}

/// What a feed's category allows, held by `Core` while the feed is
/// configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FeedRule {
    pub(crate) name: String,
    pub(crate) replies: bool,
}

/// An open feed: its spec, its id and the category it fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    pub id: FeedId,
    pub category: NodeId,
    pub spec: FeedSpec,
}

/// One item of a poll, as the fetcher normalized it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedItem {
    /// SHA-256 of the item's identity.
    pub key: [u8; 32],
    pub subject: String,
    pub author: Option<String>,
    pub at: SystemTime,
    pub body: String,
    /// Is `body` markdown, or plain text?
    pub markdown: bool,
}

/// What one import did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FeedImport {
    pub posted: usize,
    /// Articles changed because their items did.
    pub revised: usize,
    pub pruned: u64,
    /// Stopped at a news ceiling; the rest stay unseen for the next poll.
    pub full: bool,
}

fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(s[..end].trim_end().len());
    }
}

/// What an item said, as far as its article shows it.
fn content_hash(item: &FeedItem) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        item.subject.as_bytes(),
        item.author.as_deref().unwrap_or("").as_bytes(),
        item.body.as_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.update([u8::from(item.markdown)]);
    h.finalize().into()
}

impl Core {
    /// Open the configured feeds: each one's category made if missing,
    /// bundles above it included, and every category a feed fills
    /// read-only from here on. Replaces whatever was open before, so a
    /// feed taken out of the config gives its category back.
    pub fn news_feeds_open(&self, specs: &[FeedSpec]) -> Result<Vec<Feed>, NewsError> {
        let store = self.news_store()?;
        let mut feeds = Vec::with_capacity(specs.len());
        let mut filled = HashMap::new();
        for spec in specs {
            let category = self.news_feed_category(&**store, &spec.category)?;
            let state = store
                .feed_open(&spec.name, &spec.url)
                .map_err(|e| store_failed(e.into()))?;
            filled.entry(category).or_insert_with(|| FeedRule {
                name: spec.name.clone(),
                replies: spec.replies,
            });
            feeds.push(Feed {
                id: state.id,
                category,
                spec: spec.clone(),
            });
        }
        *self.news_feeds.write().unwrap() = filled;
        Ok(feeds)
    }

    /// The category `names` spell from the root, made where missing as an
    /// operator would make it by hand.
    fn news_feed_category(
        &self,
        store: &dyn NewsStore,
        names: &[String],
    ) -> Result<NodeId, NewsError> {
        let mut parent = None;
        for (i, name) in names.iter().enumerate() {
            let name = clean_name(name)?;
            let kind = if i + 1 == names.len() {
                NodeKind::Category
            } else {
                NodeKind::Bundle
            };
            let found = store.nodes(parent)?.into_iter().find(|n| n.name == name);
            let node = match found {
                Some(node) => node,
                None => {
                    let mut guid = [0u8; 16];
                    getrandom::getrandom(&mut guid).map_err(|e| {
                        NewsError::Store(StoreError::new(format!("no randomness: {e}")))
                    })?;
                    let node = store
                        .create_node(
                            &NewNode {
                                parent,
                                kind,
                                name,
                                guid,
                                at: SystemTime::now(),
                            },
                            self.news_policy.max_node_depth,
                        )
                        .map_err(store_failed)?;
                    self.news_fan_out(Event::NewsNode(node.clone()));
                    node
                }
            };
            if node.kind != kind {
                return Err(NewsError::NotACategory);
            }
            parent = Some(node.id);
        }
        parent.ok_or(NewsError::BadRequest("A feed needs a category."))
    }

    /// The feed filling `category`, if one does: the first configured,
    /// where several share it.
    pub fn news_feed_of(&self, category: NodeId) -> Option<String> {
        self.news_feed_rule(category).map(|rule| rule.name)
    }

    pub(crate) fn news_feed_rule(&self, category: NodeId) -> Option<FeedRule> {
        self.news_feeds.read().unwrap().get(&category).cloned()
    }

    /// Every feed the store remembers, configured or not, for the
    /// operator.
    pub fn news_feeds_list(&self) -> Result<Vec<FeedListing>, NewsError> {
        self.news_store()?
            .feeds()
            .map_err(|e| store_failed(e.into()))
    }

    /// What the store remembers of `feed`: its validators, for the next
    /// fetch.
    pub fn news_feed_state(&self, feed: &Feed) -> Result<FeedState, NewsError> {
        self.news_store()?
            .feed_open(&feed.spec.name, &feed.spec.url)
            .map_err(|e| store_failed(e.into()))
    }

    pub fn news_feed_polled(&self, feed: &Feed, poll: &FeedPoll) -> Result<(), NewsError> {
        self.news_store()?
            .feed_polled(feed.id, poll, SystemTime::now())
            .map_err(|e| store_failed(e.into()))
    }

    /// The sweeper's: forget items long out of their feeds.
    pub fn news_feeds_forget(&self, now: SystemTime) -> Result<u64, NewsError> {
        let before = now
            .checked_sub(FEED_FORGET_AFTER)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.news_store()?
            .feed_forget(before)
            .map_err(|e| store_failed(e.into()))
    }

    /// Post a poll's new items, oldest first, then prune the feed to its
    /// `keep` (news-feeds.md §5). A first poll takes only the newest
    /// `first_import` and tells nobody; after it, one `news_posted` names
    /// the newest article however many arrived, and followers hear of
    /// each under the catch-up rule.
    pub fn news_feed_import(
        &self,
        feed: &Feed,
        items: Vec<FeedItem>,
    ) -> Result<FeedImport, NewsError> {
        let store = self.news_store()?;
        let failed = |e: StoreError| store_failed(e.into());
        let policy = self.news_policy;
        let now = SystemTime::now();
        let first = !self.news_feed_state(feed)?.polled;
        let keys: Vec<[u8; 32]> = items.iter().map(|i| i.key).collect();
        let seen = store.feed_seen(feed.id, &keys, now).map_err(failed)?;
        let mut taken = HashSet::new();
        let mut fresh: Vec<FeedItem> = Vec::new();
        let mut done = FeedImport::default();
        let mut changed: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for item in items.into_iter().filter(|i| taken.insert(i.key)) {
            let hash = content_hash(&item);
            match seen.get(&item.key) {
                None => fresh.push(item),
                Some(had) if had.hash == hash => {}
                Some(had) => match had.article {
                    Some(article) => {
                        let post = self.news_feed_post(feed, item, now);
                        if store.feed_revise(article, &post).map_err(failed)? {
                            done.revised += 1;
                            self.news_fan_out(Event::NewsEdited {
                                id: article,
                                category: feed.category,
                            });
                        }
                    }
                    None => changed.push((item.key, hash)),
                },
            }
        }
        if first {
            let backlog = fresh.len().saturating_sub(feed.spec.first_import);
            changed.extend(fresh.drain(..backlog).map(|i| (i.key, content_hash(&i))));
        }
        store.feed_skip(feed.id, &changed, now).map_err(failed)?;

        let mut posted: Vec<(NewPost, Posted)> = Vec::new();
        let mut outcome = Ok(());
        for item in fresh {
            let post = self.news_feed_post(feed, item, now);
            let result = {
                let _serial = self.news_post_serial.lock().unwrap();
                news_room(&**store, &post, policy)
                    .and_then(|()| store.post(&post, policy.max_depth, policy.max_refs))
            };
            match result {
                Ok(p) => posted.push((post, p)),
                Err(NewsError::NewsFull) => {
                    done.full = true;
                    break;
                }
                Err(e) => {
                    outcome = Err(store_failed(e));
                    break;
                }
            }
        }
        done.posted = posted.len();
        done.pruned = store.feed_prune(feed.id, feed.spec.keep).map_err(failed)?;

        if let Some((post, p)) = posted.last() {
            self.news_fan_out(Event::NewsPosted {
                id: p.id,
                category: post.category,
                root: p.root,
                parent: None,
                subject: post.subject.clone(),
                from_nick: post.author.nick.clone(),
                at: post.at,
                attachments: 0,
            });
        }
        if let (false, Some(notify)) = (first, policy.notify) {
            let asker = Asker {
                access: AccessBits::default(),
                author: Author {
                    nick: String::new(),
                    login: None,
                    fingerprint: None,
                },
                owner: None,
                mailbox: None,
                blockable: None,
                login: String::new(),
                attach_news: false,
                guest: None,
            };
            for (post, p) in &posted {
                self.news_after_post(&asker, post, *p, notify);
            }
        }
        outcome.map(|()| done)
    }

    fn news_feed_post(&self, feed: &Feed, item: FeedItem, now: SystemTime) -> NewPost {
        let policy = self.news_policy;
        let hash = content_hash(&item);
        let mut subject = clean_subject(&item.subject);
        cut(&mut subject, policy.max_subject);
        if subject.is_empty() {
            subject = "(untitled)".into();
        }
        let mut nick = clean_subject(
            feed.spec
                .author
                .as_deref()
                .or(item.author.as_deref())
                .unwrap_or(&feed.spec.name),
        );
        cut(&mut nick, MAX_AUTHOR);
        let mut body = normalize_newlines(&item.body);
        cut(&mut body, policy.max_body);
        let markdown = item.markdown && policy.markdown != MarkdownMode::Off;
        // References are dropped: a feed's `#51` is not this server's
        // article 51. A body the parser refuses posts as the text it is.
        let (mime, plain) =
            match markdown.then(|| self.news_render(&body, BodyType::Markdown, policy)) {
                Some(Ok((plain, _))) => (BodyType::Markdown, plain),
                _ => (BodyType::Plain, None),
            };
        NewPost {
            category: feed.category,
            parent: None,
            author: Author {
                nick,
                login: None,
                fingerprint: None,
            },
            guest: None,
            subject,
            body,
            mime,
            plain,
            refs: Vec::new(),
            at: item.at.min(now),
            follow: None,
            attachments: Vec::new(),
            attachment_owner: None,
            attachment_cutoff: SystemTime::UNIX_EPOCH,
            feed: Some(FeedPost {
                feed: feed.id,
                key: item.key,
                hash,
            }),
        }
    }
}
