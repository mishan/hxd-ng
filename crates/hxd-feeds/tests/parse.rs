use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hxd_feeds::{parse, Feed, ParseOptions};
use sha2::{Digest, Sha256};

fn opts() -> ParseOptions {
    ParseOptions {
        markdown: true,
        max_subject: 255,
        max_body: 4096,
        // 2026-09-01.
        now: UNIX_EPOCH + Duration::from_secs(1_788_220_800),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn at(rfc3339_day: &str) -> SystemTime {
    // Days since the epoch, for the fixtures' midnight UTC dates.
    let days: &[(&str, u64)] = &[
        ("2026-01-01", 20454),
        ("2026-01-02", 20455),
        ("2026-02-01", 20485),
        ("2026-02-02", 20486),
        ("2026-03-03", 20515),
        ("2026-04-01", 20544),
        ("2026-05-01", 20574),
        ("2026-06-01", 20605),
        ("2026-06-02", 20606),
    ];
    let (_, d) = days.iter().find(|(s, _)| *s == rfc3339_day).unwrap();
    UNIX_EPOCH + Duration::from_secs(d * 86400)
}

fn key(identity: &str) -> [u8; 32] {
    Sha256::digest(identity.as_bytes()).into()
}

fn subjects(feed: &Feed) -> Vec<&str> {
    feed.items.iter().map(|i| i.subject.as_str()).collect()
}

#[test]
fn rss2_items_are_known_by_guid_then_link_then_enclosure() {
    let feed = parse(&fixture("rss2.xml"), &opts()).unwrap();
    assert_eq!(feed.title.as_deref(), Some("Mobius Releases"));
    assert_eq!(feed.skipped, 1, "the item with no guid, link or enclosure");
    assert_eq!(subjects(&feed), ["Podcast only", "v1.0", "v2.0 & friends"]);
    let keys: Vec<_> = feed.items.iter().map(|i| i.key).collect();
    assert_eq!(
        keys,
        [
            key("https://example.org/ep/1.mp3"),
            key("https://example.org/r/1.0"),
            key("release-2.0"),
        ]
    );
    let [podcast, v1, v2] = &feed.items[..] else {
        unreachable!()
    };
    assert_eq!(podcast.at, at("2026-02-01") + Duration::from_secs(36000));
    assert_eq!(
        podcast.body, "Download: <https://example.org/ep/1.mp3>",
        "no link, no content: only the enclosure"
    );
    assert_eq!(
        v1.body,
        "First *release*\\.\n\nSource: <https://example.org/r/1.0>"
    );
    assert_eq!(
        v2.body,
        "New [notes](<https://example.org/notes>)\\.\n\n\
         Source: <https://example.org/r/2.0>\n\n\
         Download: <https://example.org/dl/2.0.tar.gz>",
        "content over description, resolved against the item's link, script gone"
    );
    assert!(v2.author.as_deref().unwrap().contains("Dev"));
    assert_eq!(
        v1.author.as_deref(),
        Some("Mobius Releases"),
        "no author anywhere: the feed's title"
    );
}

#[test]
fn rdf_atom_and_json_feed() {
    let feed = parse(&fixture("rdf.xml"), &opts()).unwrap();
    assert_eq!(subjects(&feed), ["First", "Second"]);
    assert_eq!(feed.items[0].at, at("2026-01-01"));
    assert_eq!(feed.items[0].body, "One\n\nSource: <https://example.net/a>");

    let feed = parse(&fixture("atom.xml"), &opts()).unwrap();
    assert_eq!(feed.author.as_deref(), Some("Feed Author"));
    assert_eq!(subjects(&feed), ["Own author", "Bold news & more"]);
    let [own, bold] = &feed.items[..] else {
        unreachable!()
    };
    assert_eq!(own.key, key("urn:entry:1"));
    assert_eq!(own.at, at("2026-04-01"), "published over updated");
    assert_eq!(own.author.as_deref(), Some("Entry Author"));
    assert_eq!(own.body, "Plain \\*summary\\*");
    assert_eq!(bold.author.as_deref(), Some("Feed Author"));
    assert_eq!(bold.at, at("2026-05-01"));
    assert_eq!(
        bold.body,
        "# \\# Not \\*markdown\\*\n\n[shot](<https://example.com/i.png>)\n\n\
         Source: <https://example.com/2>\n\n\
         Download: <https://example.com/2.zip>"
    );

    let feed = parse(&fixture("feed.json"), &opts()).unwrap();
    assert_eq!(subjects(&feed), ["One", "Two"]);
    let [one, two] = &feed.items[..] else {
        unreachable!()
    };
    assert_eq!(one.key, key("1"));
    assert_eq!(one.author.as_deref(), Some("Item Author"));
    assert_eq!(one.body, "One \\*plain\\*");
    assert_eq!(two.author.as_deref(), Some("JSON Feed"));
    assert_eq!(
        two.body,
        "Two **bold**\n\nSource: <https://example.io/2>\n\nDownload: <https://example.io/2.mp3>"
    );
}

fn rss(items: &str) -> Vec<u8> {
    format!("<rss version=\"2.0\"><channel><title>T</title>{items}</channel></rss>").into_bytes()
}

#[test]
fn feed_order_is_reversed_under_one_date_and_undated_items_are_now() {
    let feed = parse(
        &rss("<item><guid>c</guid></item><item><guid>b</guid></item>\
              <item><guid>a</guid><pubDate>Thu, 01 Jan 2099 00:00:00 GMT</pubDate></item>"),
        &opts(),
    )
    .unwrap();
    let keys: Vec<_> = feed.items.iter().map(|i| i.key).collect();
    assert_eq!(keys, [key("a"), key("b"), key("c")]);
    assert!(
        feed.items.iter().all(|i| i.at == opts().now),
        "a date in the future is the fetch time"
    );
    assert!(feed.items.iter().all(|i| i.subject == "(untitled)"));
}

#[test]
fn subjects_are_one_line_of_text_cut_at_a_character() {
    let cases = [
        ("<title>  a\n\tb  </title>", 255, "a b"),
        ("<title>&lt;b&gt;tag&lt;/b&gt;</title>", 255, "<b>tag</b>"),
        ("<title>ab\u{e9}cd</title>", 3, "ab"),
        ("<title>abc def</title>", 4, "abc"),
        ("<title> </title>", 255, "(untitled)"),
    ];
    for (title, max_subject, want) in cases {
        let feed = parse(
            &rss(&format!("<item><guid>g</guid>{title}</item>")),
            &ParseOptions {
                max_subject,
                ..opts()
            },
        )
        .unwrap();
        assert_eq!(feed.items[0].subject, want, "{title}");
    }
}

#[test]
fn a_long_body_is_cut_to_the_room_its_links_leave() {
    let item = format!(
        "<item><guid>g</guid><link>https://e.org/item</link>\
         <description>{}</description>\
         <enclosure url=\"https://e.org/f.bin\" length=\"1\" type=\"application/octet-stream\"/></item>",
        "word ".repeat(1000)
    );
    let body = |markdown: bool, max_body: usize| {
        parse(
            &rss(&item),
            &ParseOptions {
                markdown,
                max_body,
                ..opts()
            },
        )
        .unwrap()
        .items
        .remove(0)
        .body
    };
    for markdown in [true, false] {
        let whole = body(markdown, 100);
        assert!(whole.len() <= 100, "{whole}");
        let (text, links) = whole.split_once("\n\nSource: ").unwrap();
        assert!(text.ends_with('…'), "{text}");
        let want = if markdown {
            "<https://e.org/item>\n\nDownload: <https://e.org/f.bin>"
        } else {
            "https://e.org/item\n\nDownload: https://e.org/f.bin"
        };
        assert_eq!(links, want);

        let tight = body(markdown, 40);
        assert!(tight.len() <= 40, "{tight}");
        assert!(tight.contains("Source: "), "the source stays: {tight}");
        assert!(
            !tight.contains("Download: "),
            "downloads give way first: {tight}"
        );
    }
}

#[test]
fn a_dtd_declares_nothing_that_grows() {
    let mut doc = String::from("<?xml version=\"1.0\"?>\n<!DOCTYPE rss [\n<!ENTITY lol \"lol\">\n");
    for i in 1..=9 {
        let prev = if i == 1 {
            "lol".to_string()
        } else {
            format!("lol{}", i - 1)
        };
        doc.push_str(&format!(
            "<!ENTITY lol{i} \"{}\">\n",
            format!("&{prev};").repeat(10)
        ));
    }
    doc.push_str(
        "]>\n<rss version=\"2.0\"><channel><title>&lol9;</title>\
         <item><guid>g</guid><title>&lol9;</title><description>&lol9;</description></item>\
         </channel></rss>",
    );
    let feed = parse(doc.as_bytes(), &opts()).unwrap();
    assert_eq!(feed.title.as_deref(), Some("&lol9;"));
    assert_eq!(feed.items[0].subject, "&lol9;");
    assert_eq!(feed.items[0].body, "\\&lol9;");
}
