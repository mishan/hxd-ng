//! The feed poller (`docs/news-feeds.md` §4, §5): each `[[news.feed]]`
//! fetched on its own schedule, parsed, and handed to the domain, which
//! decides what is new. A reader never causes a fetch.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hxd_core::news::{Feed, FeedImport, FeedItem, FeedPoll};
use hxd_core::{Core, MarkdownMode};
use hxd_feeds::{FetchConfig, FetchError, Fetched, ParseOptions, Validators};

use crate::NewsSection;

/// The longest a failing feed waits between tries.
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);

/// The most a feed's first poll after a start is put off, so feeds
/// configured together do not fetch together.
const START_SPREAD: Duration = Duration::from_secs(60);

/// Why a poll did not finish, and how long the feed asked to be left.
#[derive(Debug)]
pub struct PollError {
    pub why: String,
    pub retry_after: Option<Duration>,
}

/// Open the configured feeds, making their categories read-only, and
/// poll each from here on. Feeds that share a host are fetched one at a
/// time.
pub fn start(news: &NewsSection, core: Arc<Core>) -> Result<(), String> {
    let specs = news.feed_specs();
    // One at a time first, so a category the domain refuses is reported
    // against the feed that named it; each open replaces the last, and
    // the last opens them all.
    for spec in &specs {
        core.news_feeds_open(std::slice::from_ref(spec))
            .map_err(|e| format!("[[news.feed]] {:?}: {e:?}", spec.name))?;
    }
    let feeds = core
        .news_feeds_open(&specs)
        .map_err(|e| format!("[[news.feed]]: {e:?}"))?;
    let fetch = fetch_config(news);
    let mut hosts: HashMap<String, Arc<tokio::sync::Mutex<()>>> = HashMap::new();
    let count = feeds.len() as u32;
    for (i, (feed, entry)) in feeds.into_iter().zip(&news.feed).enumerate() {
        let host = url_host(&feed.spec.url);
        let turn = hosts.entry(host.clone()).or_default().clone();
        let every = Duration::from_secs(entry.every.unwrap_or(news.feeds.every));
        // The host alone: a private feed's URL often carries its token.
        tracing::info!(feed = feed.spec.name, host, "news feed every {every:?}");
        let first = every.min(START_SPREAD) * i as u32 / count;
        tokio::spawn(run(core.clone(), feed, fetch.clone(), every, first, turn));
    }
    Ok(())
}

pub fn fetch_config(news: &NewsSection) -> FetchConfig {
    FetchConfig {
        timeout: Duration::from_secs(news.feeds.timeout),
        max_bytes: news.feeds.max_bytes,
        proxy: news.feeds.proxy.clone(),
        user_agent: format!("hxd-ng/{}", env!("CARGO_PKG_VERSION")),
    }
}

fn url_host(url: &str) -> String {
    hxd_feeds::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Up to `range`, from the clock: spread, not secrecy. Feeds started
/// together are spread by their place in the config instead, which the
/// clock cannot tell apart.
fn jitter(range: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    range.mul_f64(f64::from(nanos) / 1e9)
}

async fn run(
    core: Arc<Core>,
    feed: Feed,
    fetch: FetchConfig,
    every: Duration,
    first: Duration,
    turn: Arc<tokio::sync::Mutex<()>>,
) {
    let mut wait = first;
    let mut failures = 0u32;
    loop {
        tokio::time::sleep(wait).await;
        let polled = {
            let _turn = turn.lock().await;
            poll_once(&core, &feed, &fetch).await
        };
        wait = match polled {
            Ok(done) => {
                failures = 0;
                if done.posted + done.revised > 0 || done.full {
                    tracing::info!(
                        feed = feed.spec.name,
                        posted = done.posted,
                        revised = done.revised,
                        pruned = done.pruned,
                        full = done.full,
                        "news feed polled"
                    );
                }
                every + jitter(every / 10)
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let backoff = every
                    .saturating_mul(1 << failures.min(16))
                    .min(MAX_BACKOFF.max(every));
                tracing::warn!(
                    feed = feed.spec.name,
                    failures,
                    "news feed: {}; trying again in {backoff:?}",
                    e.why
                );
                backoff.max(e.retry_after.unwrap_or_default())
            }
        };
    }
}

/// One poll: a conditional fetch, the parse, the import, and what the
/// store remembers of it. Every outcome is recorded with the feed, so
/// `hxd news feeds` can say how it went.
pub async fn poll_once(
    core: &Arc<Core>,
    feed: &Feed,
    fetch: &FetchConfig,
) -> Result<FeedImport, PollError> {
    let state = {
        let (core, feed) = (core.clone(), feed.clone());
        crate::spawn_blocking("news", move || core.news_feed_state(&feed))
            .await
            .map_err(|e| other(e.to_string()))?
            .map_err(|e| other(format!("{e:?}")))?
    };
    let validators = Validators {
        etag: state.etag,
        last_modified: state.last_modified,
    };
    let outcome = match hxd_feeds::fetch(fetch, &feed.spec.url, &validators).await {
        Ok(Fetched::NotModified) => {
            hxd_core::instrument::feed_poll("not_modified");
            record(core, feed, FeedPoll::NotModified).await;
            return Ok(FeedImport::default());
        }
        Ok(Fetched::Body {
            bytes,
            validators,
            moved_to,
        }) => {
            if let Some(to) = moved_to {
                tracing::info!(
                    feed = feed.spec.name,
                    "news feed has moved permanently to {to}; update its url"
                );
            }
            let (core, feed) = (core.clone(), feed.clone());
            crate::spawn_blocking("news", move || import(&core, &feed, &bytes, validators))
                .await
                .map_err(|e| other(e.to_string()))?
        }
        Err(e) => Err(PollError {
            retry_after: match e {
                FetchError::Status { retry_after, .. } => retry_after,
                _ => None,
            },
            why: e.to_string(),
        }),
    };
    match &outcome {
        Ok(done) => {
            hxd_core::instrument::feed_poll("fetched");
            hxd_core::instrument::feed_items(done.posted, done.revised, done.pruned)
        }
        Err(e) => {
            hxd_core::instrument::feed_poll("failed");
            record(core, feed, FeedPoll::Failed(e.why.clone())).await;
        }
    }
    outcome
}

fn other(why: String) -> PollError {
    PollError {
        why,
        retry_after: None,
    }
}

async fn record(core: &Arc<Core>, feed: &Feed, poll: FeedPoll) {
    let (core, feed) = (core.clone(), feed.clone());
    let recorded = crate::spawn_blocking("news", move || core.news_feed_polled(&feed, &poll)).await;
    if let Ok(Err(e)) = recorded {
        tracing::warn!("news feed: recording a poll: {e:?}");
    }
}

fn import(
    core: &Core,
    feed: &Feed,
    bytes: &[u8],
    validators: Validators,
) -> Result<FeedImport, PollError> {
    let policy = core
        .news_policy()
        .ok_or_else(|| other("news is off".into()))?;
    let markdown = core.news_markdown().is_some_and(|m| m != MarkdownMode::Off);
    let parsed = hxd_feeds::parse(
        bytes,
        &ParseOptions {
            markdown,
            max_subject: policy.max_subject,
            max_body: policy.max_body,
            now: SystemTime::now(),
            base: hxd_feeds::Url::parse(&feed.spec.url).ok(),
        },
    )
    .map_err(|e| other(e.to_string()))?;
    let items = parsed
        .items
        .into_iter()
        .map(|i| FeedItem {
            key: i.key,
            subject: i.subject,
            author: i.author,
            at: i.at,
            body: i.body,
            markdown: i.markdown,
        })
        .collect();
    let done = core
        .news_feed_import(feed, items)
        .map_err(|e| other(format!("{e:?}")))?;
    // A full server leaves items unseen for the next poll, which a
    // validator would answer with a 304; it asks again unconditionally.
    let poll = match done.full {
        true => FeedPoll::Fetched {
            etag: None,
            last_modified: None,
        },
        false => FeedPoll::Fetched {
            etag: validators.etag,
            last_modified: validators.last_modified,
        },
    };
    core.news_feed_polled(feed, &poll)
        .map_err(|e| other(format!("{e:?}")))?;
    Ok(done)
}
