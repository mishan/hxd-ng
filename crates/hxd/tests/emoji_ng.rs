//! Server emoji on the ng wire (`docs/server-emoji.md` §8), from a real
//! `[emoji]` with the catalog `hxd emoji` writes into the running
//! server's database: the `emoji` capability and its block for a login
//! that declares it, `emoji_list` whole, by delta and paged,
//! `emoji_changed` once a reread, `GET /emoji/{hash}`, and the refs a
//! client sends beside a line or a message heard by the sessions that
//! declared `emoji` here and by bit-20 sessions on the classic wire, and
//! the reverse.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::emoji::{EmojiStore, NewEmojiName};
use hxd_core::moderation::Actor;
use hxd_session::emoji::DATA_EMOJI_REFS;
use hxd_testclient::legacy::{self, push, Frame, Login};
use hxd_testclient::messaging as im;
use hxd_testclient::ng::{Client, Resumed};
use hxd_testclient::Error;
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use serde_json::{json, Value};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EMOJI: u32 = 1 << 20;
const UTF8: u32 = 1 << 1;
const CHANGED: u32 = 715;

struct Server {
    classic: SocketAddr,
    ng: SocketAddr,
    core: Arc<hxd_core::Core>,
    config: hxd::Config,
    dir: tempfile::TempDir,
}

impl Server {
    /// `hxd emoji` against the running server's database, then SIGHUP's
    /// reread.
    fn emoji(&self, args: &[&str]) {
        self.emoji_unread(args);
        self.core.emoji_reload().unwrap();
    }

    fn emoji_unread(&self, args: &[&str]) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        hxd::emoji::command(&self.config, &args).unwrap();
    }

    /// A 32 by 32 PNG to add.
    fn png(&self, name: &str) -> String {
        let img = image::RgbaImage::from_fn(32, 32, |x, y| {
            image::Rgba([x as u8 * 8, y as u8 * 8, name.len() as u8, 0xff])
        });
        let path = self.dir.path().join(format!("{name}.png"));
        img.save(&path).unwrap();
        path.display().to_string()
    }

    fn add(&self, name: &str) {
        let png = self.png(name);
        self.emoji(&["add", name, &png]);
    }

    /// The catalog's store, beside the server, for what the codec would
    /// take too long to make.
    fn store(&self) -> hxd_store_sqlite::SqliteStore {
        hxd_store_sqlite::SqliteStore::open(
            self.dir.path().join("hx.db"),
            hxd_store_sqlite::Synchronous::Normal,
        )
        .unwrap()
    }

    fn hash(&self, id: u32) -> String {
        hex(&self
            .core
            .emoji_image(hxd_core::emoji::EmojiId(id))
            .unwrap()
            .hash)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const PERSON: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      send_msgs = true\nmessaging = true\n";

/// Both wires on one database keeping mail, history and messaging, with
/// `emoji` as its `[emoji]`, `sections` beside it and `limits` in
/// `[limits]`. `erin` takes no part in messaging, so mail by login
/// reaches her inbox; `boss` makes rooms.
async fn start_with(emoji: &str, sections: &str, limits: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let accounts = dir.path().join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for (login, access) in [
        ("alice", PERSON.to_string()),
        ("bob", PERSON.to_string()),
        ("carol", PERSON.to_string()),
        ("dave", PERSON.to_string()),
        ("erin", PERSON.replace("messaging = true\n", "")),
        ("frank", PERSON.to_string()),
        ("boss", format!("{PERSON}[extra]\nmanage_rooms = true\n")),
    ] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{access}"),
        )
        .unwrap();
    }
    let path = dir.path().join("hxd-ng.toml");
    std::fs::write(
        &path,
        format!(
            "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n[history]\n\
             [messaging]\nenabled = true\n[rooms]\nfile = \"{d}/rooms.toml\"\n\
             [ng]\nbind = \"127.0.0.1:0\"\n{sections}\n[emoji]\n{emoji}\n\
             [limits]\n{spam}chat_lines = 0\nng_requests = 0\n\
             connections_per_account = 0\nreconnect_seconds = 0\n{limits}\n",
            spam = if limits.contains("spam_points") {
                ""
            } else {
                "spam_points = 0\n"
            },
        ),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    tokio::spawn(hxd::presence_flusher(ctx.core.clone()));
    let classic = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        classic: classic.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        core: ctx.core.clone(),
        config,
        dir,
    };
    tokio::spawn(hxd_session::serve(classic, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

const ON: &str = "enabled = true\n";

async fn start() -> Server {
    start_with(ON, "", "").await
}

/// `who` on the ng wire, declaring `emoji` or not, and its login reply.
async fn ng(s: &Server, who: &str, emoji: bool) -> (Client, Value) {
    let mut c = Client::connect(s.ng).await.unwrap();
    let hello = c
        .login(json!({
            "login": who, "password": "pw", "nick": who,
            "messaging": true, "replies": true, "emoji": emoji,
        }))
        .await
        .unwrap();
    (c, hello)
}

async fn reader(s: &Server, who: &str) -> Client {
    ng(s, who, true).await.0
}

/// `who` on the classic wire offering `caps`.
async fn classic(s: &Server, who: &str, caps: Option<u32>) -> legacy::Client {
    let mut c = legacy::Client::connect(s.classic).await.unwrap();
    c.login(&Login {
        caps,
        ..Login::account(who, who, "pw")
    })
    .await
    .unwrap();
    c.user_list().await.unwrap();
    c
}

fn caps(hello: &Value) -> Vec<&str> {
    hello["caps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

async fn ok(c: &mut Client, req: &str, params: Value) -> Value {
    c.request(req, params)
        .await
        .unwrap_or_else(|e| panic!("{req}: {e:?}"))
}

async fn refused(c: &mut Client, req: &str, params: Value) -> String {
    match c.request(req, params).await {
        Err(Error::Refused { code, .. }) => code,
        other => panic!("{req} was not refused: {other:?}"),
    }
}

async fn event(c: &mut Client, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
    c.event_where(ev, pred)
        .await
        .unwrap_or_else(|e| panic!("no {ev}: {e:?}"))
        .data
}

fn bearer(c: &Client) -> String {
    let (session, token) = c.session.clone().unwrap();
    format!("Bearer {session}.{token}")
}

fn guid(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
}

/// A ref as the ng wire spells one.
fn r(id: u32, name: &str) -> Value {
    json!({ "name": name, "id": id })
}

/// `DATA_EMOJI_REFS` as the draft lays it out.
fn refs(list: &[(u32, &str)]) -> Vec<u8> {
    let mut out = (list.len() as u16).to_be_bytes().to_vec();
    for (id, name) in list {
        out.extend_from_slice(&id.to_be_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
    }
    out
}

/// The next 106 whose formatted text ends with `tail`.
async fn classic_line(c: &mut legacy::Client, tail: &str) -> Frame {
    c.recv_where(|f| {
        f.ty == push::CHAT
            && f.bytes(tag::BODY)
                .is_some_and(|b| b.ends_with(tail.as_bytes()))
    })
    .await
    .unwrap()
}

async fn classic_message(c: &mut legacy::Client, text: &str) -> Frame {
    c.recv_where(|f| f.ty == push::MSG && f.bytes(tag::BODY).as_deref() == Some(text.as_bytes()))
        .await
        .unwrap()
}

// --- The capability and the catalog -------------------------------------

#[tokio::test]
async fn a_login_that_declares_emoji_is_granted_it_with_the_catalogs_numbers() {
    let s = start_with(
        "enabled = true\nmax_count = 300\nmax_bytes = 20000\nmax_dimension = 96\n",
        "",
        "",
    )
    .await;
    s.add("party");
    let (_alice, hello) = ng(&s, "alice", true).await;
    assert!(caps(&hello).contains(&"emoji"), "{hello}");
    assert_eq!(
        hello["emoji"],
        json!({
            "revision": 1, "max_count": 300, "max_bytes": 20000,
            "max_dimension": 96, "manage": false,
        })
    );
    let (mut bob, hello) = ng(&s, "bob", false).await;
    assert!(!caps(&hello).contains(&"emoji"));
    assert!(hello.get("emoji").is_none());
    assert_eq!(
        refused(&mut bob, "emoji_list", json!({})).await,
        "not_available"
    );

    let off = start_with("enabled = false\n", "", "").await;
    let (mut alice, hello) = ng(&off, "alice", true).await;
    assert!(
        !caps(&hello).contains(&"emoji"),
        "a server serving no catalog"
    );
    assert!(hello.get("emoji").is_none());
    assert_eq!(
        refused(&mut alice, "emoji_list", json!({})).await,
        "not_available"
    );
}

#[tokio::test]
async fn the_catalog_is_listed_whole_then_by_what_changed_since_a_revision() {
    let s = start().await;
    s.add("party");
    s.add("polly");
    let mut c = reader(&s, "alice").await;
    let live = |id: u32, revision: u32, name: &str| {
        json!({
            "id": id, "revision": revision, "name": name,
            "hash": s.hash(id), "width": 32, "height": 32,
        })
    };
    let (party, polly) = (live(1, 1, "party"), live(2, 2, "polly"));
    let whole = json!({ "revision": 2, "emoji": [party, polly] });
    assert_eq!(ok(&mut c, "emoji_list", json!({})).await, whole);
    assert_eq!(
        ok(&mut c, "emoji_list", Value::Null).await,
        whole,
        "params left out"
    );
    assert_eq!(
        ok(&mut c, "emoji_list", json!({ "revision": 2 })).await,
        json!({ "revision": 2, "delta": true }),
        "nothing since the current revision"
    );

    // Edits read by a reload: a removal keeping the id and the name and
    // nothing else, and an add.
    s.emoji_unread(&["remove", "party"]);
    s.emoji_unread(&["add", "parade", &s.png("parade")]);
    s.core.emoji_reload().unwrap();
    let removed = json!({ "id": 1, "revision": 3, "name": "party", "removed": true });
    let parade = live(3, 4, "parade");
    assert_eq!(
        ok(&mut c, "emoji_list", json!({ "revision": 2 })).await,
        json!({ "revision": 4, "delta": true, "emoji": [removed, parade] })
    );
    let whole = ok(&mut c, "emoji_list", json!({})).await;
    assert_eq!(whole["emoji"].as_array().unwrap().len(), 3);
    assert!(whole.get("delta").is_none());
    for (case, params, ids, delta) in [
        (
            "ahead of the server",
            json!({ "revision": 40 }),
            vec![1, 2, 3],
            false,
        ),
        ("after an id", json!({ "after": 1 }), vec![2, 3], false),
        (
            "a delta after an id",
            json!({ "revision": 2, "after": 1 }),
            vec![3],
            true,
        ),
        ("past the last", json!({ "after": 3 }), vec![], false),
    ] {
        let got = ok(&mut c, "emoji_list", params).await;
        let listed: Vec<u64> = (got["emoji"].as_array().into_iter().flatten())
            .map(|e| e["id"].as_u64().unwrap())
            .collect();
        assert_eq!(
            (got["revision"].clone(), listed, got.get("delta").is_some()),
            (json!(4), ids, delta),
            "{case}"
        );
        assert!(got.get("has_more").is_none(), "{case}");
    }
    for params in [
        json!({ "revision": "2" }),
        json!({ "revision": -1 }),
        json!({ "revision": 1u64 << 32 }),
        json!({ "after": "1" }),
        json!({ "after": 1.5 }),
        json!([]),
    ] {
        assert_eq!(
            refused(&mut c, "emoji_list", params.clone()).await,
            "bad_request",
            "{params}"
        );
    }
}

#[tokio::test]
async fn a_revision_below_what_the_catalog_remembers_is_answered_whole() {
    // One removed entry kept, so a second removal forgets the first.
    let s = start_with("enabled = true\nmax_count = 1\n", "", "").await;
    s.add("aa"); // 1
    s.emoji(&["remove", "aa"]); // 2
    s.add("bb"); // 3
    s.emoji(&["remove", "bb"]); // 4, forgetting aa: the floor is 2
    let mut c = reader(&s, "alice").await;
    let bb = json!({ "id": 2, "revision": 4, "name": "bb", "removed": true });
    assert_eq!(
        ok(&mut c, "emoji_list", json!({ "revision": 1 })).await,
        json!({ "revision": 4, "emoji": [bb] }),
        "not a delta: aa's removal can no longer be told"
    );
    assert_eq!(
        ok(&mut c, "emoji_list", json!({ "revision": 2 })).await,
        json!({ "revision": 4, "delta": true, "emoji": [bb] })
    );
}

#[tokio::test]
async fn a_catalog_past_one_page_is_paged_with_has_more() {
    let s = start_with("enabled = true\nmax_count = 1000\n", "", "").await;
    // Through the store rather than the codec: the subject is the paging.
    let store = s.store();
    let image = hxd_core::emoji::conformance::image(2);
    for n in 0..401 {
        let name = NewEmojiName::parse(&format!("e{n:04}")).unwrap();
        store
            .add(&name, &image, std::time::SystemTime::now(), 1000)
            .unwrap();
    }
    s.core.emoji_reload().unwrap();
    let mut c = reader(&s, "alice").await;
    let (mut seen, mut pages, mut after) = (Vec::new(), Vec::new(), None::<u64>);
    loop {
        let params = match after {
            Some(a) => json!({ "after": a }),
            None => json!({}),
        };
        let got = ok(&mut c, "emoji_list", params).await;
        assert_eq!(got["revision"], 401);
        let page: Vec<u64> = (got["emoji"].as_array().unwrap().iter())
            .map(|e| e["id"].as_u64().unwrap())
            .collect();
        pages.push(page.len());
        after = page.last().copied();
        seen.extend(page);
        match got.get("has_more") {
            Some(more) => assert_eq!(more, true),
            None => break,
        }
    }
    assert_eq!(pages, [200, 200, 1]);
    assert_eq!(
        seen,
        (1..=401).collect::<Vec<u64>>(),
        "every entry, once, in order"
    );
}

/// The `emoji_changed` revisions `c` has been sent, up to a ping's
/// answer, and whether it was sent a placeholder.
async fn changes(c: &mut Client) -> (Vec<Value>, bool) {
    ok(c, "ping", json!({})).await;
    let backlog = c.rx.take_backlog();
    (
        (backlog.iter())
            .filter(|e| e.ev == "emoji_changed")
            .map(|e| e.data.clone())
            .collect(),
        backlog.iter().any(|e| e.ev == "unsupported"),
    )
}

#[tokio::test]
async fn a_batch_of_edits_and_one_reread_are_one_change_told_to_the_sessions_that_read_it() {
    let s = start().await;
    let mut alice = reader(&s, "alice").await;
    let (mut dave, _) = ng(&s, "dave", false).await;
    let mut carol = classic(&s, "carol", Some(EMOJI | UTF8)).await;
    s.emoji_unread(&["add", "party", &s.png("party")]);
    s.emoji_unread(&["add", "polly", &s.png("polly")]);
    s.emoji_unread(&["rename", "polly", "parrot_two"]);
    s.core.emoji_reload().unwrap();
    assert_eq!(
        changes(&mut alice).await,
        (vec![json!({ "revision": 3 })], false),
        "once, and as itself"
    );
    carol.ping().await.unwrap();
    let told: Vec<Option<u32>> = (carol.rx.take_backlog().iter())
        .filter(|f| f.ty == CHANGED)
        .map(|f| f.uint(hxd_session::emoji::DATA_EMOJI_REVISION))
        .collect();
    assert_eq!(told, [Some(3)], "and once on the classic wire");
    s.core.emoji_reload().unwrap();
    assert_eq!(
        changes(&mut alice).await,
        (vec![], false),
        "a reread that moved nothing"
    );
    assert_eq!(changes(&mut dave).await, (vec![], false));
}

#[tokio::test]
async fn a_login_racing_rereads_is_never_left_behind_the_store() {
    let s = start().await;
    let (store, core) = (s.store(), s.core.clone());
    // Edits go on until a login has landed among them, and a few after.
    let among = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = among.clone();
    let edits = tokio::task::spawn_blocking(move || {
        let image = hxd_core::emoji::conformance::image(3);
        let mut after = 0;
        for n in 0..500 {
            let name = NewEmojiName::parse(&format!("race{n}")).unwrap();
            store
                .add(&name, &image, std::time::SystemTime::now(), 1000)
                .unwrap();
            core.emoji_reload().unwrap();
            after += u32::from(seen.load(std::sync::atomic::Ordering::SeqCst));
            if after > 3 {
                break;
            }
        }
    });
    let mut logins = Vec::new();
    while !edits.is_finished() && logins.len() < 64 {
        let (c, hello) = ng(&s, "alice", true).await;
        let at = hello["emoji"]["revision"].as_u64().unwrap();
        if at > 0 {
            among.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        logins.push((c, at));
    }
    edits.await.unwrap();
    let last = u64::from(s.core.emoji_revision().unwrap());
    assert!(
        logins.iter().any(|(_, at)| (1..last).contains(at)),
        "no login landed among the edits: {:?}",
        logins.iter().map(|(_, at)| at).collect::<Vec<_>>()
    );
    for (mut c, at_login) in logins {
        let told = changes(&mut c).await.0;
        let known = (told.iter())
            .map(|v| v["revision"].as_u64().unwrap())
            .fold(at_login, u64::max);
        assert_eq!(known, last, "logged in at {at_login}, told {told:?}");
    }
}

#[tokio::test]
async fn a_client_told_to_resync_catches_up_from_the_revision_it_holds() {
    let s = start().await;
    s.add("party");
    let (alice, hello) = ng(&s, "alice", true).await;
    let held = hello["emoji"]["revision"].clone();
    s.add("polly");
    // A seq this session never reached: what it was sent is not
    // replayed.
    let session = alice.session.clone().unwrap();
    let last_seq = alice.rx.last_seq + 1000;
    let (mut alice, resumed) = Client::resume(s.ng, session, last_seq, Vec::new())
        .await
        .unwrap();
    assert_eq!(resumed, Resumed::ResyncRequired);
    alice.sync().await.unwrap();
    let caught = ok(&mut alice, "emoji_list", json!({ "revision": held })).await;
    assert_eq!(caught["delta"], true, "and still granted emoji: {caught}");
    assert_eq!(caught["emoji"][0]["name"], "polly");
    assert_eq!(caught["emoji"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_resume_replays_refs_and_the_change_to_a_session_that_declared_emoji_alone() {
    let s = start().await;
    s.add("party");
    let mut bob = reader(&s, "bob").await;
    let mut away = Vec::new();
    for (who, declared) in [("alice", true), ("dave", false)] {
        let (mut c, _) = ng(&s, who, declared).await;
        ok(&mut c, "ping", json!({})).await;
        let held = (c.session.clone().unwrap(), c.rx.last_seq, declared);
        let uid = c.uid;
        c.close().await.unwrap();
        event(&mut bob, "user_changed", |d| {
            d["user"]["uid"] == json!(uid) && d["user"]["status"] == "detached"
        })
        .await;
        away.push(held);
    }
    let said = json!({ "text": "missed :party:", "emoji": [r(1, "party")] });
    ok(&mut bob, "chat", said).await;
    s.add("polly");
    for (session, last_seq, declared) in away {
        let (mut c, resumed) = Client::resume(s.ng, session, last_seq, Vec::new())
            .await
            .unwrap();
        assert!(matches!(resumed, Resumed::Replayed(_)), "{resumed:?}");
        let heard = event(&mut c, "chat", |d| d["text"] == "missed :party:").await;
        let (told, placeholder) = changes(&mut c).await;
        match declared {
            true => {
                assert_eq!(heard["emoji"], json!([r(1, "party")]));
                assert_eq!((told, placeholder), (vec![json!({ "revision": 2 })], false));
            }
            false => {
                assert!(heard.get("emoji").is_none(), "{heard}");
                assert_eq!((told, placeholder), (vec![], false));
            }
        }
    }
}

#[tokio::test]
async fn listing_the_catalog_spends_no_spam_points() {
    let s = start_with(ON, "", "spam_points = 10").await;
    let mut alice = reader(&s, "alice").await;
    for _ in 0..30 {
        ok(&mut alice, "emoji_list", json!({})).await;
    }
    ok(&mut alice, "ping", json!({})).await;
    assert!(
        !alice.rx.take_backlog().iter().any(|e| e.ev == "kicked"),
        "kicked for listing"
    );
}

#[tokio::test]
async fn an_animation_is_listed_as_one_and_served_as_a_gif() {
    let s = start().await;
    // Through the store: the subject is the listing, not the codec.
    let gif = hxd_core::emoji::EmojiImage::new(
        hxd_core::media::MediaType::Gif,
        24,
        16,
        true,
        b"GIF89a-not-decoded".to_vec(),
    );
    let name = NewEmojiName::parse("spin").unwrap();
    (s.store().add(&name, &gif, std::time::SystemTime::now(), 10)).unwrap();
    s.core.emoji_reload().unwrap();
    let mut c = reader(&s, "alice").await;
    let listed = ok(&mut c, "emoji_list", json!({})).await;
    assert_eq!(
        listed["emoji"][0],
        json!({ "id": 1, "revision": 1, "name": "spin", "hash": hex(&gif.hash),
                "width": 24, "height": 16, "animated": true })
    );
    let got = fetch(&s, &hex(&gif.hash), &[("Authorization", &bearer(&c))]).await;
    assert_eq!(got.header("content-type"), Some("image/gif"));
    assert_eq!(&got.body[..], &gif.bytes[..]);
}

// --- GET /emoji/{hash} --------------------------------------------------

struct HttpReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpReply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str, extra: &[(&str, &str)]) -> HttpReply {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status = (lines.next().unwrap().split_whitespace().nth(1))
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    HttpReply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

async fn fetch(s: &Server, hash: &str, extra: &[(&str, &str)]) -> HttpReply {
    http(s.ng, "GET", &format!("/emoji/{hash}"), extra).await
}

const IMMUTABLE: &str = "private, max-age=31536000, immutable";

#[tokio::test]
async fn an_emoji_is_fetched_by_its_hash_while_it_lives() {
    let s = start().await;
    // `png` draws one picture for names of one length: polly is party's
    // twin, and parakeet another.
    s.add("party");
    s.add("polly");
    s.add("parakeet");
    let alice = reader(&s, "alice").await;
    let (dave, _) = ng(&s, "dave", false).await;
    let hash = s.hash(1);
    let etag = format!("\"{hash}\"");
    for c in [&alice, &dave] {
        let got = fetch(&s, &hash, &[("Authorization", &bearer(c))]).await;
        assert_eq!(got.status, 200);
        assert_eq!(hex(&sha2::Sha256::digest(&got.body)), hash);
        assert!(got.body.starts_with(b"\x89PNG\r\n\x1a\n"));
        for (name, want) in [
            ("content-type", "image/png"),
            ("cache-control", IMMUTABLE),
            ("etag", etag.as_str()),
            ("x-content-type-options", "nosniff"),
            ("content-disposition", "inline"),
            ("content-security-policy", "sandbox; default-src 'none'"),
            ("access-control-allow-origin", "*"),
        ] {
            assert_eq!(got.header(name), Some(want), "{name}");
        }
    }
    let auth = bearer(&alice);
    let again = fetch(
        &s,
        &hash,
        &[("Authorization", &auth), ("If-None-Match", &etag)],
    )
    .await;
    assert_eq!(again.status, 304);
    assert_eq!(again.header("etag"), Some(etag.as_str()));
    assert_eq!(again.header("cache-control"), Some(IMMUTABLE));
    let preflight = http(s.ng, "OPTIONS", &format!("/emoji/{hash}"), &[]).await;
    assert_eq!(preflight.header("access-control-allow-origin"), Some("*"));

    for (case, header) in [("no session", None), ("a stranger's", Some("Bearer no.pe"))] {
        let extra: Vec<(&str, &str)> = header.map(|h| ("Authorization", h)).into_iter().collect();
        assert_eq!(fetch(&s, &hash, &extra).await.status, 401, "{case}");
    }

    let gone = hash.clone();
    s.emoji(&["remove", "party"]);
    assert_eq!(
        fetch(&s, &gone, &[("Authorization", &auth)]).await.status,
        200,
        "the bytes of polly too"
    );
    s.emoji(&["remove", "polly"]);
    for (case, hash, extra) in [
        (
            "removed",
            gone.as_str(),
            vec![("Authorization", auth.as_str())],
        ),
        (
            "removed, asked as if cached",
            gone.as_str(),
            vec![
                ("Authorization", auth.as_str()),
                ("If-None-Match", etag.as_str()),
            ],
        ),
        (
            "never served",
            &"0".repeat(64),
            vec![("Authorization", auth.as_str())],
        ),
        (
            "not a hash",
            "party",
            vec![("Authorization", auth.as_str())],
        ),
        (
            "in capitals",
            &s.hash(3).to_uppercase(),
            vec![("Authorization", auth.as_str())],
        ),
    ] {
        let got = fetch(&s, hash, &extra).await;
        assert_eq!(got.status, 404, "{case}");
        assert_eq!(got.json()["error"]["code"], "no_such_emoji", "{case}");
    }
    assert_eq!(
        fetch(&s, &s.hash(3), &[("Authorization", &auth)])
            .await
            .status,
        200,
        "the one still live"
    );

    let off = start_with("enabled = false\n", "", "").await;
    let c = reader(&off, "alice").await;
    assert_eq!(
        fetch(&off, &hash, &[("Authorization", &bearer(&c))])
            .await
            .status,
        404,
        "a server serving no catalog"
    );
}

#[tokio::test]
async fn an_address_fetches_so_many_emoji_a_minute_apart_from_its_avatars() {
    // Loopback held to it, as any address.
    let limits = "avatar_fetches_per_minute = 2\nexempt = []\nconnections_per_addr = 0";
    let s = start_with(ON, "[avatars]\n", limits).await;
    s.add("party");
    let c = reader(&s, "alice").await;
    let auth = bearer(&c);
    let avatar = format!("/avatars/{}", "0".repeat(64));
    for _ in 0..2 {
        assert_ne!(http(s.ng, "GET", &avatar, &[]).await.status, 429);
    }
    assert_eq!(http(s.ng, "GET", &avatar, &[]).await.status, 429);
    // Counted without a session too, as an avatar fetch is.
    assert_eq!(fetch(&s, &s.hash(1), &[]).await.status, 401);
    assert_eq!(
        fetch(&s, &s.hash(1), &[("Authorization", &auth)])
            .await
            .status,
        200,
        "the avatars' count is not the emoji's"
    );
    let refused = fetch(&s, &s.hash(1), &[("Authorization", &auth)]).await;
    assert_eq!(refused.status, 429);
    let wait: u64 = refused.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=30).contains(&wait), "{wait}");
    assert_eq!(refused.json()["error"]["code"], "rate_limited");
    assert_eq!(refused.header("access-control-allow-origin"), Some("*"));
}

// --- References ---------------------------------------------------------

#[tokio::test]
async fn refs_on_a_line_are_heard_by_the_readers_that_read_the_catalog_on_either_wire() {
    let s = start().await;
    s.add("party");
    s.add("polly");
    s.add("gone");
    s.emoji(&["remove", "gone"]);
    let mut alice = reader(&s, "alice").await;
    let mut bob = reader(&s, "bob").await;
    let (mut dave, _) = ng(&s, "dave", false).await;
    let mut carol = classic(&s, "carol", Some(EMOJI | UTF8)).await;
    let mut erin = classic(&s, "erin", None).await;

    let sent = json!([
        { "name": "party", "id": 1, "size": "ignored" },
        r(2, "polly"),
        r(3, "gone"),
        r(9, "nine"),
        r(2, "party"),
        r(1, "party"),
        r(1, "Party"),
        { "name": "big", "id": 1u64 << 40 },
    ]);
    let kept = json!([r(1, "party"), r(2, "polly")]);
    let text = ":party: and :polly:";
    let id = ok(&mut alice, "chat", json!({ "text": text, "emoji": sent })).await["id"].clone();
    for c in [&mut alice, &mut bob] {
        let heard = event(c, "chat", |d| d["id"] == id).await;
        assert_eq!(heard["emoji"], kept);
        assert_eq!(heard["text"], text);
    }
    let plain = event(&mut dave, "chat", |d| d["id"] == id).await;
    assert!(plain.get("emoji").is_none(), "{plain}");
    let heard = classic_line(&mut carol, "and :polly:").await;
    assert_eq!(
        heard.bytes(DATA_EMOJI_REFS),
        Some(refs(&[(1, "party"), (2, "polly")]))
    );
    let period = classic_line(&mut erin, "and :polly:").await;
    assert!(period.chunk(DATA_EMOJI_REFS).is_none());

    // From a bit-20 session to the readers here.
    carol
        .send(
            ClientHdr::Chat.as_u32(),
            &[
                (tag::BODY, b"from carol :party:".to_vec()),
                (DATA_EMOJI_REFS, refs(&[(1, "party"), (5, "five")])),
            ],
        )
        .await
        .unwrap();
    let heard = event(&mut bob, "chat", |d| d["text"] == "from carol :party:").await;
    assert_eq!(heard["emoji"], json!([r(1, "party")]));
    let plain = event(&mut dave, "chat", |d| d["text"] == "from carol :party:").await;
    assert!(plain.get("emoji").is_none());

    // None kept, none sent; and from a session that did not declare
    // `emoji`, ignored whatever its shape.
    ok(
        &mut alice,
        "chat",
        json!({ "text": "only :gone:", "emoji": [r(3, "gone")] }),
    )
    .await;
    let heard = event(&mut bob, "chat", |d| d["text"] == "only :gone:").await;
    assert!(heard.get("emoji").is_none(), "{heard}");
    for (text, refs) in [
        ("mine :party:", json!([r(1, "party")])),
        ("odd", json!("party")),
    ] {
        ok(&mut dave, "chat", json!({ "text": text, "emoji": refs })).await;
        let heard = event(&mut bob, "chat", |d| d["text"] == text).await;
        assert!(heard.get("emoji").is_none(), "{heard}");
    }

    // History: the page and `ids`, to a reader that declared it alone.
    let ids = json!({ "ids": [id] });
    for (who, c, want) in [
        ("alice", &mut alice, Some(kept.clone())),
        ("dave", &mut dave, None),
    ] {
        let page = ok(c, "history", json!({})).await;
        let line = (page["lines"].as_array().unwrap().iter())
            .find(|l| l["id"] == id)
            .unwrap()
            .clone();
        assert_eq!(line.get("emoji").cloned(), want, "{who}'s page");
        let by_id = ok(c, "history", ids.clone()).await;
        assert_eq!(by_id["lines"][0].get("emoji").cloned(), want, "{who}'s ids");
    }
    // A redaction takes them with the words.
    s.core
        .redact_line(Actor::Operator, id.as_u64().unwrap(), "spam")
        .unwrap();
    let by_id = ok(&mut alice, "history", ids).await;
    assert_eq!(by_id["lines"][0]["deleted"], true);
    assert!(by_id["lines"][0].get("emoji").is_none(), "{by_id}");
}

#[tokio::test]
async fn refs_that_are_not_a_list_of_names_and_ids_are_refused() {
    let s = start().await;
    s.add("party");
    let mut alice = reader(&s, "alice").await;
    let bob = reader(&s, "bob").await;
    for refs in [
        json!("party"),
        json!({ "name": "party", "id": 1 }),
        json!([1]),
        json!([["party", 1]]),
        json!([{ "name": "party" }]),
        json!([{ "id": 1 }]),
        json!([{ "name": 7, "id": 1 }]),
        json!([{ "name": "party", "id": "1" }]),
        json!([{ "name": "party", "id": 1.5 }]),
        json!([r(1, "party"), 2]),
    ] {
        for (req, params) in [
            ("chat", json!({ "text": "x", "emoji": refs })),
            ("msg", json!({ "to": bob.uid, "text": "x", "emoji": refs })),
        ] {
            assert_eq!(
                refused(&mut alice, req, params).await,
                "bad_request",
                "{req} {refs}"
            );
        }
    }
}

#[tokio::test]
async fn refs_on_a_room_line_and_a_repeat_are_the_first_lines() {
    let s = start().await;
    s.add("party");
    s.add("polly");
    let mut boss = reader(&s, "boss").await;
    let room = ok(&mut boss, "room_create", json!({ "name": "den" })).await["room"]["id"].clone();
    let mut alice = reader(&s, "alice").await;
    let mut bob = reader(&s, "bob").await;
    let (mut dave, _) = ng(&s, "dave", false).await;
    for c in [&mut alice, &mut bob, &mut dave] {
        ok(c, "room_join", json!({ "room": room })).await;
    }
    let said = json!({ "text": "in here :party:", "room": room, "emoji": [r(1, "party")] });
    let id = ok(&mut alice, "chat", said).await["id"].clone();
    let heard = event(&mut bob, "chat", |d| d["id"] == id).await;
    assert_eq!(
        (&heard["room"], &heard["emoji"]),
        (&room, &json!([r(1, "party")]))
    );
    let plain = event(&mut dave, "chat", |d| d["id"] == id).await;
    assert_eq!(&plain["room"], &room);
    assert!(plain.get("emoji").is_none(), "{plain}");
    let page = ok(&mut bob, "history", json!({ "room": room })).await;
    assert_eq!(page["lines"][0]["emoji"], json!([r(1, "party")]));

    let g = guid(1);
    let first = json!({ "text": "once :party:", "guid": g, "emoji": [r(1, "party")] });
    let id = ok(&mut alice, "chat", first).await["id"].clone();
    let repeat = json!({ "text": "once :polly:", "guid": g, "emoji": [r(2, "polly")] });
    assert_eq!(
        ok(&mut alice, "chat", repeat).await["id"],
        id,
        "the line it repeats"
    );
    let by_id = ok(&mut bob, "history", json!({ "ids": [id] })).await;
    assert_eq!(by_id["lines"][0]["emoji"], json!([r(1, "party")]));
}

#[tokio::test]
async fn refs_on_a_message_reach_its_reader_on_either_wire_and_its_inbox_row() {
    let s = start().await;
    s.add("party");
    let party = json!([r(1, "party")]);
    let mut alice = reader(&s, "alice").await;
    let mut bob = reader(&s, "bob").await;
    let (mut dave, _) = ng(&s, "dave", false).await;
    let mut carol = classic(&s, "carol", Some(EMOJI | UTF8)).await;
    let carol_uid = carol.uid.unwrap();
    let sent = json!([r(1, "party"), r(4, "four")]);

    ok(
        &mut alice,
        "msg",
        json!({ "to": bob.uid, "text": "hi :party:", "emoji": sent }),
    )
    .await;
    assert_eq!(
        event(&mut bob, "msg", |d| d["text"] == "hi :party:").await["emoji"],
        party
    );
    let row = ok(&mut bob, "inbox", json!({})).await["messages"][0].clone();
    assert_eq!(
        (&row["text"], &row["emoji"]),
        (&json!("hi :party:"), &party)
    );
    ok(
        &mut alice,
        "msg",
        json!({ "to": dave.uid, "text": "hi :party:", "emoji": sent }),
    )
    .await;
    let plain = event(&mut dave, "msg", |d| d["text"] == "hi :party:").await;
    assert!(plain.get("emoji").is_none(), "{plain}");
    let row = ok(&mut dave, "inbox", json!({})).await["messages"][0].clone();
    assert!(row.get("emoji").is_none(), "{row}");
    ok(
        &mut alice,
        "msg",
        json!({ "to": carol_uid, "text": "to carol :party:", "emoji": sent }),
    )
    .await;
    let got = classic_message(&mut carol, "to carol :party:").await;
    assert_eq!(got.bytes(DATA_EMOJI_REFS), Some(refs(&[(1, "party")])));

    // From the classic wire.
    carol
        .call(
            ClientHdr::Msg.as_u32(),
            &[
                (tag::UID, (bob.uid.unwrap() as u16).to_be_bytes().to_vec()),
                (tag::BODY, b"from carol :party:".to_vec()),
                (DATA_EMOJI_REFS, refs(&[(1, "party")])),
            ],
        )
        .await
        .unwrap();
    let got = event(&mut bob, "msg", |d| d["text"] == "from carol :party:").await;
    assert_eq!(got["emoji"], party);

    // Mail that waited, flushed at login.
    let mail = json!({ "to_login": "erin", "text": "while away :party:", "emoji": party });
    assert_eq!(ok(&mut alice, "msg", mail).await["queued"], true);
    let mut erin = reader(&s, "erin").await;
    let flushed = event(&mut erin, "msg", |d| d["text"] == "while away :party:").await;
    assert_eq!(flushed["emoji"], party);
    let row = ok(&mut erin, "inbox", json!({})).await["messages"][0].clone();
    assert_eq!(row["emoji"], party, "{row}");

    // From a session that did not declare `emoji`, ignored.
    let unasked = json!({ "to": bob.uid, "text": "from dave :party:", "emoji": party });
    ok(&mut dave, "msg", unasked).await;
    let got = event(&mut bob, "msg", |d| d["text"] == "from dave :party:").await;
    assert!(got.get("emoji").is_none(), "{got}");
}

/// `a` and `b` friends on the ng wire.
async fn befriend(a: &mut Client, b: &mut Client, b_login: &str, a_login: &str) {
    ok(a, "friend_add", json!({ "login": b_login })).await;
    event(b, "friend_request", |d| d["login"] == a_login).await;
    ok(
        b,
        "friend_respond",
        json!({ "login": a_login, "accept": true }),
    )
    .await;
    event(a, "friend", |d| d["friend"]["state"] == "accepted").await;
}

#[tokio::test]
async fn refs_on_an_instant_message_and_a_request_reach_the_readers_that_declared_emoji() {
    let s = start().await;
    s.add("party");
    let party = json!([r(1, "party")]);
    let mut alice = reader(&s, "alice").await;
    let mut bob = reader(&s, "bob").await;
    let (mut dave, _) = ng(&s, "dave", false).await;
    befriend(&mut alice, &mut bob, "bob", "alice").await;
    befriend(&mut alice, &mut dave, "dave", "alice").await;
    for (n, (who, c)) in [("bob", &mut bob), ("dave", &mut dave)]
        .into_iter()
        .enumerate()
    {
        let text = format!("lunch, {who} :party:");
        let sent =
            json!({ "to_login": who, "text": text, "guid": guid(n as u8 + 1), "emoji": party });
        assert_eq!(ok(&mut alice, "msg", sent).await["im"], true);
        let got = event(c, "im", |d| d["text"] == text).await;
        assert_eq!(
            got.get("emoji").cloned(),
            (who == "bob").then(|| party.clone()),
            "{who}"
        );
    }

    let mut frank = reader(&s, "frank").await;
    let (mut boss, _) = ng(&s, "boss", false).await;
    ok(&mut alice, "requests", json!({})).await;
    for (n, (who, c)) in [("frank", &mut frank), ("boss", &mut boss)]
        .into_iter()
        .enumerate()
    {
        ok(c, "presence", json!({ "takes_requests": true })).await;
        let asked = json!({ "to_login": who, "text": "hello :party:", "guid": guid(n as u8 + 10),
                            "emoji": party });
        assert_eq!(ok(&mut alice, "msg", asked).await["requested"], true);
        let listed = ok(c, "requests", json!({})).await;
        let got = listed["requests"][0]["messages"][0].clone();
        assert_eq!(got["text"], "hello :party:", "{listed}");
        assert_eq!(
            got.get("emoji").cloned(),
            (who == "frank").then(|| party.clone()),
            "{who}"
        );
    }
}

fn guid_bytes(n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[6] = 0x40;
    g[8] = 0x80;
    g[15] = n;
    g
}

#[tokio::test]
async fn refs_on_an_instant_message_cross_to_and_from_a_bit_20_friend() {
    let s = start().await;
    s.add("party");
    let mut alice = reader(&s, "alice").await;
    let mut carol = classic(&s, "carol", Some(EMOJI | UTF8 | (1 << 6))).await;
    ok(&mut alice, "friend_add", json!({ "login": "carol" })).await;
    carol
        .recv_type(ServerHdr::FriendRequest.as_u32())
        .await
        .unwrap();
    let answered = carol
        .ask(
            ClientHdr::FriendResponse,
            &im::friend_response(b"alice", true),
        )
        .await
        .unwrap();
    assert!(!answered.is_error());
    event(&mut alice, "friend", |d| d["friend"]["state"] == "accepted").await;

    let sent = json!({ "to_login": "carol", "text": "to carol :party:", "guid": guid(1),
                       "emoji": [r(1, "party")] });
    assert_eq!(ok(&mut alice, "msg", sent).await["im"], true);
    let got = carol
        .recv_where(|f| {
            f.ty == ServerHdr::ImDeliver.as_u32()
                && f.bytes(tag::MESSAGE_BODY).as_deref() == Some(&b"to carol :party:"[..])
        })
        .await
        .unwrap();
    assert_eq!(got.bytes(DATA_EMOJI_REFS), Some(refs(&[(1, "party")])));

    let mut chunks = im::im_send(b"alice", &guid_bytes(2), b"from carol :party:");
    chunks.push((DATA_EMOJI_REFS, refs(&[(1, "party"), (8, "eight")])));
    let f = carol.ask(ClientHdr::ImSend, &chunks).await.unwrap();
    assert!(!f.is_error(), "{:?}", f.error_text());
    let got = event(&mut alice, "im", |d| d["text"] == "from carol :party:").await;
    assert_eq!(got["emoji"], json!([r(1, "party")]));
}
