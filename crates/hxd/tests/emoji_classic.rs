//! Server emoji on the classic wire (`docs/server-emoji.md`): capability
//! bit 20 from a real `[emoji]`, the catalog `hxd emoji` writes into the
//! running server's database read with 713 and 714, the change told
//! with 715, and the refs a client sends beside a chat line, a private
//! message and an instant message heard by the readers that negotiated
//! the bit, as text alone by every other, and paged back with 700.
//!
//! The fields are laid out by hand from the draft here rather than by
//! the server's encoder, so a disagreement between the two shows.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::moderation::{Actor, PersonRef};
use hxd_session::emoji::{
    DATA_EMOJI_ENTRY, DATA_EMOJI_ID, DATA_EMOJI_IMAGE, DATA_EMOJI_MORE, DATA_EMOJI_REFS,
    DATA_EMOJI_REVISION, DATA_MAX_EMOJI, DATA_MAX_EMOJI_BYTES, DATA_MAX_EMOJI_DIMENSION,
    EMOJI_REFS,
};
use hxd_session::structured::{DATA_CHAT_LINE, DATA_CHAT_REASON};
use hxd_testclient::legacy::{push, Client, Frame, Login};
use hxd_testclient::messaging as im;
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use sha2::Digest;

const EMOJI: u32 = 1 << 20;
const UTF8: u32 = 1 << 1;
const HISTORY: u32 = 1 << 4;
const MESSAGING: u32 = 1 << 6;
const STRUCTURED: u32 = 1 << 17;

const GET_CATALOG: u32 = 713;
const GET_EMOJI: u32 = 714;
const CHANGED: u32 = 715;
const MANAGE: u32 = 716;

const NOT_ALLOWED: u16 = 2;
const NO_SUCH_EMOJI: u16 = 7;

struct Server {
    classic: SocketAddr,
    core: Arc<hxd_core::Core>,
    config: hxd::Config,
    dir: tempfile::TempDir,
}

impl Server {
    /// `hxd emoji` against the running server's database, then SIGHUP's
    /// reread.
    fn emoji(&self, args: &[&str]) -> String {
        let said = self.emoji_unread(args);
        self.core.emoji_reload().unwrap();
        said
    }

    fn emoji_unread(&self, args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        hxd::emoji::command(&self.config, &args).unwrap()
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
}

const PERSON: &str = "read_chat = true\nsend_chat = true\nread_chat_history = true\n\
                      send_msgs = true\nmessaging = true\ncreate_pchats = true\n";

/// A server keeping mail, history and messaging in one database, with
/// `emoji` as its `[emoji]` section.
async fn start(emoji: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let accounts = dir.path().join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    for login in ["alice", "bob", "carol", "dave", "erin"] {
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{PERSON}"),
        )
        .unwrap();
    }
    let path = dir.path().join("hxd-ng.toml");
    std::fs::write(
        &path,
        format!(
            "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n[history]\n\
             [messaging]\nenabled = true\n[structured_chat]\nenabled = true\n\
             [limits]\nspam_points = 0\nchat_lines = 0\n[emoji]\n{emoji}"
        ),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    tokio::spawn(hxd::presence_flusher(ctx.core.clone()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        classic: l.local_addr().unwrap(),
        core: ctx.core.clone(),
        config,
        dir,
    };
    tokio::spawn(hxd_session::serve(l, ctx));
    server
}

const ON: &str = "enabled = true\n";

/// `who` logged in offering `caps`, and its login reply.
async fn login(s: &Server, who: &str, caps: Option<u32>) -> (Client, Frame) {
    let mut c = Client::connect(s.classic).await.unwrap();
    let reply = c
        .login(&Login {
            caps,
            ..Login::account(who, who, "pw")
        })
        .await
        .unwrap();
    c.user_list().await.unwrap();
    (c, reply)
}

async fn classic(s: &Server, who: &str, caps: Option<u32>) -> Client {
    login(s, who, caps).await.0
}

fn confirmed(reply: &Frame) -> u32 {
    reply.uint(tag::CAPABILITIES).unwrap_or(0)
}

fn reason(f: &Frame) -> Option<u32> {
    f.uint(DATA_CHAT_REASON)
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

/// A 105 with `refs` beside its text.
async fn say(c: &mut Client, text: &str, sent: &[(u32, &str)]) {
    c.send(
        ClientHdr::Chat.as_u32(),
        &[
            (tag::BODY, text.as_bytes().to_vec()),
            (DATA_EMOJI_REFS, refs(sent)),
        ],
    )
    .await
    .unwrap();
}

/// The next 106 whose formatted text ends with `tail`.
async fn line(c: &mut Client, tail: &str) -> Frame {
    c.recv_where(|f| {
        f.ty == push::CHAT
            && f.bytes(tag::BODY)
                .is_some_and(|b| b.ends_with(tail.as_bytes()))
    })
    .await
    .unwrap()
}

/// An entry's text and its sub-fields.
fn subfields(entry: &[u8]) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
    let be16 = |at: usize| usize::from(u16::from_be_bytes([entry[at], entry[at + 1]]));
    let msg_at = 22 + be16(20);
    let text = entry[msg_at + 2..msg_at + 2 + be16(msg_at)].to_vec();
    let mut at = msg_at + 2 + be16(msg_at);
    let mut out = Vec::new();
    while at < entry.len() {
        let (ty, len) = (be16(at) as u16, be16(at + 2));
        out.push((ty, entry[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    (text, out)
}

fn entry_id(entry: &[u8]) -> u64 {
    u64::from_be_bytes(entry[..8].try_into().unwrap())
}

/// A 700 entry's id, flags, text and sub-fields.
type Paged = (u64, u16, Vec<u8>, Vec<(u16, Vec<u8>)>);

/// The lobby's history as `c` pages it.
async fn paged(c: &mut Client) -> Vec<Paged> {
    let page = c
        .call(700, &[(tag::CHANNEL_ID, 0u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    page.all(tag::HISTORY_ENTRY)
        .iter()
        .map(|e| {
            let (text, subs) = subfields(e);
            (entry_id(e), u16::from_be_bytes([e[16], e[17]]), text, subs)
        })
        .collect()
}

/// A packed catalog entry, read.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    id: u32,
    revision: u32,
    flags: u16,
    size: (u16, u16),
    hash: [u8; 16],
    name: String,
}

fn entry(data: &[u8]) -> Entry {
    let u16_at = |at: usize| u16::from_be_bytes([data[at], data[at + 1]]);
    let u32_at = |at: usize| u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
    let len = usize::from(data[30]);
    assert_eq!(
        data.len(),
        31 + len,
        "an entry is its name long and no more"
    );
    Entry {
        id: u32_at(0),
        revision: u32_at(4),
        flags: u16_at(8),
        size: (u16_at(10), u16_at(12)),
        hash: data[14..30].try_into().unwrap(),
        name: String::from_utf8(data[31..].to_vec()).unwrap(),
    }
}

/// A 713 asking from `revision` after `after`: the revision, the
/// entries and whether more remain.
async fn catalog(
    c: &mut Client,
    revision: Option<u32>,
    after: Option<u32>,
) -> (u32, Vec<Entry>, bool) {
    let mut ask = Vec::new();
    if let Some(r) = revision {
        ask.push((DATA_EMOJI_REVISION, r.to_be_bytes().to_vec()));
    }
    if let Some(a) = after {
        ask.push((DATA_EMOJI_ID, a.to_be_bytes().to_vec()));
    }
    let f = c.call(GET_CATALOG, &ask).await.unwrap();
    assert!(f.wire().len() <= 0xffff + 20, "{} bytes", f.wire().len());
    let more = match f.bytes(DATA_EMOJI_MORE) {
        Some(b) => {
            assert_eq!(b, [1]);
            true
        }
        None => false,
    };
    (
        f.uint(DATA_EMOJI_REVISION).unwrap(),
        f.all(DATA_EMOJI_ENTRY).iter().map(|e| entry(e)).collect(),
        more,
    )
}

#[tokio::test]
async fn bit_20_is_confirmed_beside_bit_1_alone_with_the_catalogs_numbers() {
    let s = start("enabled = true\nmax_count = 300\nmax_bytes = 20000\nmax_dimension = 96\n").await;
    s.add("party");
    let fields = [
        DATA_EMOJI_REVISION,
        DATA_MAX_EMOJI,
        DATA_MAX_EMOJI_BYTES,
        DATA_MAX_EMOJI_DIMENSION,
    ];
    let (_, reply) = login(&s, "alice", Some(EMOJI | UTF8)).await;
    assert_eq!(confirmed(&reply) & (EMOJI | UTF8), EMOJI | UTF8);
    let numbers: Vec<Option<u32>> = fields.iter().map(|&t| reply.uint(t)).collect();
    assert_eq!(numbers, [Some(1), Some(300), Some(20000), Some(96)]);

    for (case, caps) in [
        ("without bit 1", Some(EMOJI)),
        ("a period client", None),
        ("bit 1 alone", Some(UTF8)),
    ] {
        let (mut c, reply) = login(&s, "bob", caps).await;
        assert_eq!(confirmed(&reply) & EMOJI, 0, "{case}");
        assert!(fields.iter().all(|&t| reply.chunk(t).is_none()), "{case}");
        // Answered as any transaction this server does not implement.
        for ty in [GET_CATALOG, GET_EMOJI, MANAGE] {
            let trans = c.send(ty, &[]).await.unwrap();
            let f = c.reply(trans).await.unwrap();
            assert_eq!(
                f.error_text().as_deref(),
                Some("Not implemented."),
                "{case}"
            );
        }
    }

    let off = start("enabled = false\n").await;
    let (_, reply) = login(&off, "alice", Some(EMOJI | UTF8)).await;
    assert_eq!(confirmed(&reply) & EMOJI, 0, "a server serving no catalog");
}

#[tokio::test]
async fn the_catalog_is_listed_whole_then_by_what_changed_since_a_revision() {
    let s = start(ON).await;
    s.add("party");
    s.add("polly");
    let mut c = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let image = |id| s.core.emoji_image(hxd_core::emoji::EmojiId(id)).unwrap();
    let live = |id, revision, name: &str| Entry {
        id,
        revision,
        flags: 0,
        size: (32, 32),
        hash: image(id).hash[..16].try_into().unwrap(),
        name: name.into(),
    };
    let (party, polly) = (live(1, 1, "party"), live(2, 2, "polly"));
    let (revision, entries, more) = catalog(&mut c, None, None).await;
    assert_eq!(
        (revision, &entries[..], more),
        (2, &[party, polly][..], false)
    );
    assert_eq!(catalog(&mut c, Some(2), None).await, (2, vec![], false));

    // Edits read by a reload, and what changed since: a removal keeping
    // the id and the name and nothing else, and an add.
    s.emoji_unread(&["remove", "party"]);
    s.emoji_unread(&["add", "parade", &s.png("parade")]);
    s.core.emoji_reload().unwrap();
    let removed = Entry {
        id: 1,
        revision: 3,
        flags: 2,
        size: (0, 0),
        hash: [0; 16],
        name: "party".into(),
    };
    let parade = live(3, 4, "parade");
    let (revision, entries, _) = catalog(&mut c, Some(2), None).await;
    assert_eq!((revision, &entries[..]), (4, &[removed, parade][..]));
    let whole = catalog(&mut c, None, None).await.1;
    assert_eq!(whole.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 2, 3]);
    // A revision this server never had, as after a restore, is answered
    // whole; and a listing goes on after an id.
    assert_eq!(catalog(&mut c, Some(40), None).await.1, whole);
    let after = catalog(&mut c, None, Some(1)).await.1;
    assert_eq!(after.iter().map(|e| e.id).collect::<Vec<_>>(), [2, 3]);
    let delta_after = catalog(&mut c, Some(2), Some(1)).await.1;
    assert_eq!(delta_after.iter().map(|e| e.id).collect::<Vec<_>>(), [3]);
    assert_eq!(
        catalog(&mut c, None, Some(3)).await,
        (4, vec![], false),
        "past the last"
    );
    // An integer field in two bytes, as hxproto and mhxd read one.
    let short = c
        .call(
            GET_CATALOG,
            &[
                (DATA_EMOJI_REVISION, 2u16.to_be_bytes().to_vec()),
                (DATA_EMOJI_ID, 1u16.to_be_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    let ids: Vec<u32> = short
        .all(DATA_EMOJI_ENTRY)
        .iter()
        .map(|e| entry(e).id)
        .collect();
    assert_eq!(ids, [3]);
    let got = c
        .call(GET_EMOJI, &[(DATA_EMOJI_ID, 3u16.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert!(got.chunk(DATA_EMOJI_IMAGE).is_some());
}

#[tokio::test]
async fn a_catalog_past_one_reply_is_paged_with_more() {
    use hxd_core::emoji::{EmojiStore, NewEmojiName};
    let s = start("enabled = true\nmax_count = 1000\n").await;
    // Through the store rather than the codec: the subject is the
    // paging, and a thousand renditions would be the whole test's time.
    let store = hxd_store_sqlite::SqliteStore::open(
        s.dir.path().join("hx.db"),
        hxd_store_sqlite::Synchronous::Normal,
    )
    .unwrap();
    let image = hxd_core::emoji::conformance::image(2);
    for n in 0..1000 {
        let name = NewEmojiName::parse(&format!("e{n:04}_{}", "x".repeat(26))).unwrap();
        store
            .add(&name, &image, std::time::SystemTime::now(), 1000)
            .unwrap();
    }
    s.core.emoji_reload().unwrap();
    let mut c = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let (revision, entries, more) = catalog(&mut c, None, after).await;
        assert_eq!(revision, 1000);
        assert!(!entries.is_empty());
        after = entries.last().map(|e| e.id);
        seen.extend(entries.into_iter().map(|e| e.id));
        if !more {
            break;
        }
    }
    assert_eq!(
        seen,
        (1..=1000).collect::<Vec<u32>>(),
        "every entry, once, in order"
    );
    assert!(after.is_some());
}

#[tokio::test]
async fn an_emoji_is_fetched_by_its_id_while_it_lives_and_managed_by_the_operator_alone() {
    let s = start(ON).await;
    s.add("party");
    s.add("polly");
    s.emoji(&["remove", "polly"]);
    let mut c = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let hash = catalog(&mut c, None, None).await.1[0].hash;
    let got = c
        .call(GET_EMOJI, &[(DATA_EMOJI_ID, 1u32.to_be_bytes().to_vec())])
        .await
        .unwrap();
    assert_eq!(got.uint(DATA_EMOJI_ID), Some(1));
    let png = got.bytes(DATA_EMOJI_IMAGE).unwrap();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    let side = |at: usize| u32::from_be_bytes(png[at..at + 4].try_into().unwrap());
    assert!(side(16) <= 128 && side(20) <= 128, "within the square");
    assert_eq!(
        sha2::Sha256::digest(&png)[..16],
        hash,
        "the bytes the entry hashes"
    );

    for (case, id) in [("removed", 2u32), ("never given", 99)] {
        let trans = c
            .send(GET_EMOJI, &[(DATA_EMOJI_ID, id.to_be_bytes().to_vec())])
            .await
            .unwrap();
        let f = c.reply(trans).await.unwrap();
        assert!(f.is_error(), "{case}");
        assert_eq!(reason(&f), Some(NO_SUCH_EMOJI.into()), "{case}");
    }
    // Whatever it asks, the image unread.
    let png = std::fs::read(s.png("parade")).unwrap();
    let trans = c
        .send(
            MANAGE,
            &[
                (0x0f3d, 1u16.to_be_bytes().to_vec()),
                (0x0f39, b"parade".to_vec()),
                (DATA_EMOJI_IMAGE, png),
            ],
        )
        .await
        .unwrap();
    let f = c.reply(trans).await.unwrap();
    assert!(f.is_error());
    assert!(f.error_text().is_some_and(|t| !t.is_empty()));
    assert_eq!(reason(&f), Some(NOT_ALLOWED.into()));
    assert_eq!(s.core.emoji_revision(), Some(3), "nothing added");
}

/// The 715s `c` has been sent, up to a ping's answer.
async fn changes(c: &mut Client) -> Vec<(u32, Option<u32>)> {
    c.ping().await.unwrap();
    c.rx.take_backlog()
        .iter()
        .filter(|f| f.ty == CHANGED)
        .map(|f| (f.trans, f.uint(DATA_EMOJI_REVISION)))
        .collect()
}

#[tokio::test]
async fn a_batch_of_edits_and_one_reread_are_one_change_told_to_bit_20_alone() {
    let s = start(ON).await;
    let mut reader = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let mut period = classic(&s, "bob", None).await;
    let mut utf8 = classic(&s, "carol", Some(UTF8 | STRUCTURED)).await;
    s.emoji_unread(&["add", "party", &s.png("party")]);
    s.emoji_unread(&["add", "polly", &s.png("polly")]);
    s.emoji_unread(&["rename", "polly", "parrot_two"]);
    s.core.emoji_reload().unwrap();
    assert_eq!(
        changes(&mut reader).await,
        [(0, Some(3))],
        "task id 0, once"
    );
    s.core.emoji_reload().unwrap();
    assert_eq!(
        changes(&mut reader).await,
        [],
        "a reread that moved nothing"
    );
    for c in [&mut period, &mut utf8] {
        assert_eq!(changes(c).await, []);
    }
}

#[tokio::test]
async fn refs_on_a_chat_line_are_kept_heard_by_bit_20_and_paged_back_by_it() {
    let s = start(ON).await;
    s.add("party");
    s.add("polly");
    s.add("gone");
    s.emoji(&["remove", "gone"]);
    let mut alice = classic(&s, "alice", Some(EMOJI | UTF8 | STRUCTURED | HISTORY)).await;
    let mut bob = classic(&s, "bob", Some(EMOJI | UTF8)).await;
    let mut carol = classic(&s, "carol", Some(UTF8 | STRUCTURED | HISTORY)).await;
    let mut dave = classic(&s, "dave", None).await;

    let sent = [
        (1, "party"),
        (2, "polly"),
        (3, "gone"),
        (9, "nine"),
        (2, "party"),
        (1, "party"),
    ];
    let kept = refs(&[(1, "party"), (2, "polly")]);
    say(&mut alice, ":party: and :polly:", &sent).await;
    let tail = "and :polly:";
    let echo = line(&mut alice, tail).await;
    assert_eq!(echo.bytes(DATA_EMOJI_REFS).as_ref(), Some(&kept));
    // Beside the entry and never in it.
    let live = echo.bytes(DATA_CHAT_LINE).unwrap();
    assert_eq!(subfields(&live).1, []);
    let heard = line(&mut bob, tail).await;
    assert_eq!(heard.bytes(DATA_EMOJI_REFS), Some(kept.clone()));
    assert_eq!(
        heard.bytes(tag::BODY).unwrap(),
        b"\r        alice:  :party: and :polly:"
    );
    for (who, c) in [("bit 17", &mut carol), ("a period client", &mut dave)] {
        let f = line(c, tail).await;
        assert!(f.chunk(DATA_EMOJI_REFS).is_none(), "{who}");
        assert_eq!(f.bytes(tag::BODY), heard.bytes(tag::BODY), "{who}");
    }

    // From a session without bit 20, dropped unread.
    say(&mut carol, "mine :party:", &[(1, "party")]).await;
    let f = line(&mut bob, "mine :party:").await;
    assert!(f.chunk(DATA_EMOJI_REFS).is_none());
    // None kept, none sent.
    say(&mut alice, "only :gone:", &[(3, "gone")]).await;
    assert!(line(&mut bob, "only :gone:")
        .await
        .chunk(DATA_EMOJI_REFS)
        .is_none());

    let id = entry_id(&live);
    let refs_of = |page: &[Paged]| {
        page.iter()
            .map(|(_, _, _, subs)| {
                subs.iter()
                    .find(|(t, _)| *t == EMOJI_REFS)
                    .map(|(_, d)| d.clone())
            })
            .collect::<Vec<_>>()
    };
    let page = paged(&mut alice).await;
    assert_eq!(page[0].0, id);
    assert_eq!(refs_of(&page), [Some(kept.clone()), None, None]);
    assert_eq!(
        refs_of(&paged(&mut carol).await),
        [None, None, None],
        "without bit 20"
    );
}

#[tokio::test]
async fn a_redaction_and_a_purge_take_a_lines_refs_with_its_words() {
    let s = start(ON).await;
    s.add("party");
    let mut alice = classic(&s, "alice", Some(EMOJI | UTF8 | STRUCTURED | HISTORY)).await;
    let mut ids = Vec::new();
    for text in ["one :party:", "two :party:", "three :party:"] {
        say(&mut alice, text, &[(1, "party")]).await;
        ids.push(entry_id(
            &line(&mut alice, text).await.bytes(DATA_CHAT_LINE).unwrap(),
        ));
    }
    s.core.redact_line(Actor::Operator, ids[0], "spam").unwrap();
    let page = paged(&mut alice).await;
    let shown: Vec<(usize, bool)> = (page.iter())
        .map(|(_, flags, _, subs)| (subs.len(), flags & 4 != 0))
        .collect();
    assert_eq!(shown, [(0, true), (1, false), (1, false)]);
    s.core
        .purge_sender(
            Actor::Operator,
            &PersonRef::Login("alice".into()),
            Duration::from_secs(3600),
            "spam",
        )
        .unwrap();
    let page = paged(&mut alice).await;
    assert!(page
        .iter()
        .all(|(_, flags, text, subs)| flags & 4 != 0 && text.is_empty() && subs.is_empty()));
}

/// A 108 to `to` with `refs` beside its text.
async fn message(c: &mut Client, to: u16, text: &str, sent: &[(u32, &str)]) {
    c.call(
        ClientHdr::Msg.as_u32(),
        &[
            (tag::UID, to.to_be_bytes().to_vec()),
            (tag::BODY, text.as_bytes().to_vec()),
            (DATA_EMOJI_REFS, refs(sent)),
        ],
    )
    .await
    .unwrap();
}

async fn private_message(c: &mut Client, text: &str) -> Frame {
    c.recv_where(|f| f.ty == push::MSG && f.bytes(tag::BODY).as_deref() == Some(text.as_bytes()))
        .await
        .unwrap()
}

#[tokio::test]
async fn refs_on_a_private_message_are_kept_and_heard_by_bit_20_alone() {
    let s = start(ON).await;
    s.add("party");
    let mut alice = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let mut bob = classic(&s, "bob", Some(EMOJI | UTF8)).await;
    let mut carol = classic(&s, "carol", Some(UTF8)).await;
    let mut dave = classic(&s, "dave", None).await;
    let uid = |c: &Client| c.uid.unwrap();
    let (bob_uid, dave_uid) = (uid(&bob), uid(&dave));
    let party = [(1, "party")];

    message(
        &mut alice,
        bob_uid,
        "hi :party:",
        &[(1, "party"), (1, "polly")],
    )
    .await;
    let got = private_message(&mut bob, "hi :party:").await;
    assert_eq!(got.bytes(DATA_EMOJI_REFS), Some(refs(&party)));
    message(&mut alice, dave_uid, "hi :party:", &party).await;
    assert!(private_message(&mut dave, "hi :party:")
        .await
        .chunk(DATA_EMOJI_REFS)
        .is_none());
    message(&mut carol, bob_uid, "from carol :party:", &party).await;
    let got = private_message(&mut bob, "from carol :party:").await;
    assert!(
        got.chunk(DATA_EMOJI_REFS).is_none(),
        "from a sender without bit 20"
    );
}

/// `a` and `b` friends, both classic.
async fn befriend(a: &mut Client, a_login: &str, b: &mut Client, b_login: &str) {
    let asked = a
        .ask(
            ClientHdr::AddFriend,
            &im::add_friend(b_login.as_bytes(), None),
        )
        .await
        .unwrap();
    assert!(!asked.is_error());
    b.recv_type(ServerHdr::FriendRequest.as_u32())
        .await
        .unwrap();
    let answered = b
        .ask(
            ClientHdr::FriendResponse,
            &im::friend_response(a_login.as_bytes(), true),
        )
        .await
        .unwrap();
    assert!(!answered.is_error());
    a.recv_type(ServerHdr::RosterEntry.as_u32()).await.unwrap();
}

fn guid(n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[6] = 0x40;
    g[8] = 0x80;
    g[15] = n;
    g
}

/// An 810 to `to` with `refs` beside its body.
async fn instant(c: &mut Client, to: &str, n: u8, text: &str, sent: &[(u32, &str)]) {
    let mut chunks = im::im_send(to.as_bytes(), &guid(n), text.as_bytes());
    chunks.push((DATA_EMOJI_REFS, refs(sent)));
    let f = c.ask(ClientHdr::ImSend, &chunks).await.unwrap();
    assert!(!f.is_error(), "{:?}", f.error_text());
}

async fn delivered(c: &mut Client, text: &str) -> Frame {
    c.recv_where(|f| {
        f.ty == ServerHdr::ImDeliver.as_u32()
            && f.bytes(tag::MESSAGE_BODY).as_deref() == Some(text.as_bytes())
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn refs_on_an_instant_message_are_heard_live_and_after_it_waited() {
    let s = start(ON).await;
    s.add("party");
    let both = EMOJI | UTF8 | MESSAGING;
    let mut alice = classic(&s, "alice", Some(both)).await;
    let mut bob = classic(&s, "bob", Some(both)).await;
    let mut erin = classic(&s, "erin", Some(UTF8 | MESSAGING)).await;
    befriend(&mut alice, "alice", &mut bob, "bob").await;
    befriend(&mut alice, "alice", &mut erin, "erin").await;
    let party = [(1, "party")];

    instant(
        &mut alice,
        "bob",
        1,
        "live :party:",
        &[(1, "party"), (7, "seven")],
    )
    .await;
    let got = delivered(&mut bob, "live :party:").await;
    assert_eq!(got.bytes(DATA_EMOJI_REFS), Some(refs(&party)));
    instant(&mut alice, "erin", 2, "live :party:", &party).await;
    assert!(delivered(&mut erin, "live :party:")
        .await
        .chunk(DATA_EMOJI_REFS)
        .is_none());
    instant(&mut erin, "alice", 3, "from erin :party:", &party).await;
    let got = delivered(&mut alice, "from erin :party:").await;
    assert!(
        got.chunk(DATA_EMOJI_REFS).is_none(),
        "from a sender without bit 20"
    );

    let gone = bob.uid.unwrap();
    bob.shutdown().await.unwrap();
    // Until bob's session is gone, a message would reach it.
    for _ in 0..500 {
        if s.core.user(gone).is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    instant(&mut alice, "bob", 4, "while away :party:", &party).await;
    let mut bob = classic(&s, "bob", Some(both)).await;
    let roster = bob.ask(ClientHdr::GetRoster, &[]).await.unwrap();
    assert!(!roster.is_error());
    let got = delivered(&mut bob, "while away :party:").await;
    assert_eq!(
        got.bytes(DATA_EMOJI_REFS),
        Some(refs(&party)),
        "kept while it waited"
    );
}

#[tokio::test]
async fn refs_on_a_private_chat_line_are_heard_by_its_bit_20_members_alone() {
    let s = start(ON).await;
    s.add("party");
    let mut alice = classic(&s, "alice", Some(EMOJI | UTF8)).await;
    let mut bob = classic(&s, "bob", Some(EMOJI | UTF8)).await;
    let mut dave = classic(&s, "dave", None).await;
    let created = alice
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, bob.uid.unwrap().to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let chat = created.uint(tag::CHAT_ID).unwrap().to_be_bytes().to_vec();
    alice
        .call(
            ClientHdr::ChatInvite.as_u32(),
            &[
                (tag::CHAT_ID, chat.clone()),
                (tag::UID, dave.uid.unwrap().to_be_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    for c in [&mut bob, &mut dave] {
        c.call(
            ClientHdr::ChatJoin.as_u32(),
            &[(tag::CHAT_ID, chat.clone())],
        )
        .await
        .unwrap();
    }
    alice
        .send(
            ClientHdr::Chat.as_u32(),
            &[
                (tag::CHAT_ID, chat.clone()),
                (tag::BODY, b"psst :party:".to_vec()),
                (DATA_EMOJI_REFS, refs(&[(1, "party"), (2, "none")])),
            ],
        )
        .await
        .unwrap();
    let heard = line(&mut bob, "psst :party:").await;
    assert_eq!(heard.bytes(tag::CHAT_ID), Some(chat.clone()));
    assert_eq!(heard.bytes(DATA_EMOJI_REFS), Some(refs(&[(1, "party")])));
    let period = line(&mut dave, "psst :party:").await;
    assert_eq!(period.bytes(tag::CHAT_ID), Some(chat));
    assert!(period.chunk(DATA_EMOJI_REFS).is_none());
}

#[tokio::test]
async fn refs_on_a_message_request_are_kept_until_it_is_approved() {
    use hxproto::messaging::{Presence, PresenceState, RequestAction};
    let s = start(ON).await;
    s.add("party");
    let both = EMOJI | UTF8 | MESSAGING;
    let mut alice = classic(&s, "alice", Some(both)).await;
    let mut dave = classic(&s, "dave", Some(both)).await;
    // Both understand requests, and dave takes them.
    for (c, takes) in [(&mut alice, false), (&mut dave, true)] {
        let set = im::set_presence(&Presence {
            state: Some(PresenceState::Online),
            status_text: None,
            discoverable: None,
            takes_requests: Some(takes),
        });
        assert!(!c
            .ask(ClientHdr::SetPresence, &set)
            .await
            .unwrap()
            .is_error());
    }
    instant(&mut alice, "dave", 5, "may I :party:", &[(1, "party")]).await;
    let approve = im::answer_message_request(b"alice", RequestAction::Approve);
    let f = dave
        .ask(ClientHdr::AnswerMessageRequest, &approve)
        .await
        .unwrap();
    assert!(!f.is_error(), "{:?}", f.error_text());
    let got = delivered(&mut dave, "may I :party:").await;
    assert_eq!(got.bytes(DATA_EMOJI_REFS), Some(refs(&[(1, "party")])));
}
