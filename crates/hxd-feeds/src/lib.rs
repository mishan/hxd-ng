//! Feeds for news (`docs/news-feeds.md`): the fetch, with every address
//! it connects to checked; the parse into items; and the conversion of
//! a feed's HTML into markdown that holds none.
//!
//! Knows nothing about Hotline. What an item becomes, whether it was
//! seen before, and when to ask again are the caller's.

mod html;
mod parse;

pub use hxd_fetch::{check_proxy, check_url, fetch, FetchConfig, FetchError, Fetched, Validators};
pub use parse::{parse, Feed, Item, ParseError, ParseOptions};
pub use url::Url;

/// What a feed fetch accepts, most specific first.
pub const FEED_ACCEPT: &str = "application/atom+xml, application/rss+xml, application/feed+json, \
     application/xml;q=0.9, text/xml;q=0.9, application/json;q=0.9, */*;q=0.8";
