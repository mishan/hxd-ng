//! What a notification says, and how much of it (`docs/webpush-gateway.md`
//! §4).
//!
//! Content policy is applied **here, before encryption**, and not at
//! render time on the device: a client cannot be told something the
//! server chose not to encrypt, and an operator who set `generic` can
//! say so truthfully rather than hoping every client honors a flag.

use hxd_core::notify::{MessageNotice, NewsNotice, Notification};
use serde_json::{json, Value};

use crate::encrypt::MAX_PLAINTEXT;

/// How much of a message or an excerpt leaves the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Content {
    /// The text itself. Safe to recommend on Web Push in a way it is not
    /// on a vendor backend, because nothing between here and the device
    /// holds a key for it.
    Full,
    /// Who it is from, and nothing they said.
    #[default]
    Sender,
    /// That something arrived. No name, no words.
    Generic,
}

impl Content {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Content::Full),
            "sender" => Some(Content::Sender),
            "generic" => Some(Content::Generic),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Content::Full => "full",
            Content::Sender => "sender",
            Content::Generic => "generic",
        }
    }
}

/// The plaintext to encrypt, and the collapse key it travels under.
pub struct Built {
    pub plaintext: Vec<u8>,
    /// `Topic`'s input: the conversation or the news scope. Keyed-hashed and
    /// truncated by the caller, because RFC 8030 restricts the header's
    /// alphabet and length.
    pub collapse: String,
}

/// Build one notification's payload under `content`.
pub fn build(n: &Notification<'_>, content: Content) -> Built {
    let (mut body, collapse) = match n {
        Notification::Message(m) => (message(m, content), conversation(m)),
        Notification::News(a) => (news(a, content), a.scope.key()),
    };
    // The ceiling is the record's, and the text is the only field that
    // can approach it. Truncated here rather than discovered at the
    // provider, which costs a round trip to learn something we knew.
    if let Some(field) = long_field(n) {
        let text = body[field].as_str().unwrap_or("").to_string();
        let room = MAX_PLAINTEXT.saturating_sub(body.to_string().len() - text.len());
        if text.len() > room {
            body[field] = Value::String(truncate(&text, room));
        }
    }
    Built {
        plaintext: body.to_string().into_bytes(),
        collapse,
    }
}

/// Which field of a built payload is the one that can be long. `None`
/// when the content policy already removed it.
fn long_field(n: &Notification<'_>) -> Option<&'static str> {
    match n {
        Notification::Message(_) => Some("text"),
        Notification::News(_) => Some("excerpt"),
    }
}

fn message(m: &MessageNotice<'_>, content: Content) -> Value {
    let mut v = json!({
        "kind": "message",
        "id": m.id.to_string(),
        "unread": m.unread,
    });
    if content != Content::Generic {
        v["from_nick"] = json!(m.from_nick);
        if let Some(from) = m.from {
            v["from"] = json!(from.login);
        }
    }
    if content == Content::Full {
        v["text"] = json!(m.text);
    }
    v
}

fn news(a: &NewsNotice<'_>, content: Content) -> Value {
    let mut v = json!({
        "kind": "news",
        "reason": a.reason.name(),
        "article": a.article,
        "root": a.root,
        "category": a.category,
        // Two fields, as the `news_notify` event spells it (news.md
        // §10.6), so a client parses one shape whichever way the notice
        // reached it.
        "scope": a.scope.kind_name(),
        "target": a.scope.target(),
        "unread": a.unread,
    });
    if content != Content::Generic {
        v["from_nick"] = json!(a.from_nick);
        // A subject is the article's title, not its contents: it is what
        // a thread is called, and withholding it under `sender` would
        // leave a notification that names nothing to open.
        v["subject"] = json!(a.subject);
    }
    if content == Content::Full {
        v["excerpt"] = json!(a.excerpt);
    }
    v
}

/// The collapse key for a message: the conversation it belongs to, which
/// is the sender, so two messages from one person replace rather than
/// stack.
fn conversation(m: &MessageNotice<'_>) -> String {
    match m.from {
        Some(from) => match from.fingerprint {
            Some(fp) => format!("dm:{}", hex(&fp[..8])),
            None => format!("dm:{}", from.login),
        },
        None => "dm".to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cut `text` to at most `room` bytes on a character boundary, with an
/// ellipsis if anything went. JSON-escaping can still grow what this
/// returns, which is why the caller's `room` is computed against the
/// encoded object and left with slack by [`MAX_PLAINTEXT`]'s own
/// margin.
fn truncate(text: &str, room: usize) -> String {
    const ELLIPSIS: &str = "…";
    let room = room.saturating_sub(ELLIPSIS.len());
    let mut end = room.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ELLIPSIS}", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::inbox::Mailbox;
    use hxd_core::news::{NotifyReason, SubScope};

    fn mailbox() -> Mailbox {
        Mailbox::login("alice")
    }

    fn notice<'a>(to: &'a Mailbox, from: &'a Mailbox, text: &'a str) -> Notification<'a> {
        Notification::Message(MessageNotice {
            to,
            from: Some(from),
            from_nick: "Alice",
            text,
            id: 42,
            unread: 3,
        })
    }

    fn built(n: &Notification<'_>, c: Content) -> Value {
        serde_json::from_slice(&build(n, c).plaintext).unwrap()
    }

    #[test]
    fn content_policy_decides_what_is_encrypted_at_all() {
        let (to, from) = (Mailbox::login("bob"), mailbox());
        let n = notice(&to, &from, "the launch codes");

        let full = built(&n, Content::Full);
        assert_eq!(full["text"], "the launch codes");
        assert_eq!(full["from_nick"], "Alice");
        assert_eq!(full["unread"], 3);

        let sender = built(&n, Content::Sender);
        assert!(sender.get("text").is_none(), "no words under `sender`");
        assert_eq!(sender["from_nick"], "Alice");

        let generic = built(&n, Content::Generic);
        assert!(generic.get("text").is_none());
        assert!(generic.get("from_nick").is_none(), "no name either");
        assert!(generic.get("from").is_none());
        assert_eq!(generic["unread"], 3, "a badge is not content");
        assert_eq!(generic["kind"], "message");
    }

    #[test]
    fn a_news_notice_names_a_thread_to_open() {
        let to = Mailbox::login("bob");
        let n = Notification::News(NewsNotice {
            to: &to,
            reason: NotifyReason::Reply,
            from_nick: "Alice",
            subject: "Phase 4 is open",
            excerpt: "News, finally.",
            article: 412,
            root: 398,
            category: 3,
            scope: SubScope::Thread(398),
            unread: 2,
        });
        let full = built(&n, Content::Full);
        assert_eq!(full["kind"], "news");
        assert_eq!(full["reason"], "reply");
        assert_eq!(full["article"], 412);
        assert_eq!(full["scope"], "thread");
        assert_eq!(full["target"], 398);
        assert_eq!(full["excerpt"], "News, finally.");
        assert_eq!(build(&n, Content::Full).collapse, "thread:398");

        let sender = built(&n, Content::Sender);
        assert!(sender.get("excerpt").is_none());
        assert_eq!(
            sender["subject"], "Phase 4 is open",
            "the thread's name is what there is to open"
        );

        // Nothing an author wrote, and everything needed to open it.
        let generic = built(&n, Content::Generic);
        assert!(generic.get("subject").is_none());
        assert!(generic.get("from_nick").is_none());
        assert_eq!(generic["article"], 412);
        assert_eq!(generic["root"], 398);
        assert_eq!(generic["scope"], "thread");
        assert_eq!(generic["target"], 398);
    }

    #[test]
    fn a_long_message_is_cut_here_and_not_at_the_provider() {
        let (to, from) = (Mailbox::login("bob"), mailbox());
        let long = "x".repeat(MAX_PLAINTEXT * 2);
        let n = notice(&to, &from, &long);
        let built = build(&n, Content::Full);
        assert!(
            built.plaintext.len() <= MAX_PLAINTEXT,
            "{} bytes is past one record",
            built.plaintext.len()
        );
        let v: Value = serde_json::from_slice(&built.plaintext).unwrap();
        assert!(
            v["text"].as_str().unwrap().ends_with('…'),
            "and says that it was cut"
        );
    }

    #[test]
    fn a_cut_never_lands_inside_a_character() {
        // Four bytes each, so a naive cut splits one.
        let text = "😀".repeat(2000);
        let (to, from) = (Mailbox::login("bob"), mailbox());
        let n = notice(&to, &from, &text);
        let built = build(&n, Content::Full);
        let v: Value = serde_json::from_slice(&built.plaintext)
            .expect("still valid UTF-8, and still valid JSON");
        assert!(v["text"].as_str().unwrap().ends_with('…'));
    }

    #[test]
    fn two_messages_from_one_person_collapse_together() {
        let (to, from) = (Mailbox::login("bob"), mailbox());
        let n = notice(&to, &from, "one");
        let m = notice(&to, &from, "two");
        assert_eq!(
            build(&n, Content::Full).collapse,
            build(&m, Content::Full).collapse
        );

        let other = Mailbox::login("carol");
        assert_ne!(
            build(&n, Content::Full).collapse,
            build(&notice(&to, &other, "three"), Content::Full).collapse,
            "and two people do not collapse onto each other"
        );
    }
}
