//! Feeds for news (`docs/news-feeds.md`): the fetch, with every address
//! it connects to checked; the parse into items; and the conversion of
//! a feed's HTML into markdown that holds none.
//!
//! Knows nothing about Hotline. What an item becomes, whether it was
//! seen before, and when to ask again are the caller's.

mod fetch;
mod html;
mod parse;

pub use fetch::{fetch, FetchConfig, FetchError, Fetched, Validators};
pub use parse::{parse, Feed, Item, ParseError, ParseOptions};
