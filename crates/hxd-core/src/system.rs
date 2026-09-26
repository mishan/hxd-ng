//! The reserved server account, and the commands a private message to it
//! carries (`docs/system-account.md`).
//!
//! **The rule this implements, in one sentence:** the server interprets
//! text only where the user addressed it *to the server*, and never
//! where they addressed it to the room. Public chat is never parsed — a
//! period client typing `/report` into the chat box gets chat, because
//! that is what they asked for. A private message to the account called
//! *Server* is a command line, because opening a window to a thing
//! called Server and typing at it is deliberate in a way a chat line is
//! not.
//!
//! That is the whole of the difference, and it is why this is a roster
//! session rather than a magic address: the legacy wire needs a uid on a
//! private message for a window to open, and it needs the same uid to
//! still be there when the user hits reply.
//!
//! **Every command runs as the session that sent it.** The system
//! account confers nothing — it is a place to type. Authorization is
//! whatever the equivalent ng request would check, so a command an ng
//! client could not make, this cannot make either.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use tracing::warn;

use crate::access::bit;
use crate::inbox::Mailbox;
use crate::news::SubScope;
use crate::roster::{AttachInfo, Core, Event, Transport, Uid};

/// `[system]`: the reserved account and what it answers.
#[derive(Debug, Clone)]
pub struct SystemPolicy {
    /// The reserved login. Reserved everywhere a login is reserved.
    pub login: String,
    /// What the roster shows.
    pub nick: String,
    pub icon: u16,
    /// Parse private messages to it. Off, it is still the account
    /// notifications come from, and it answers every message with one
    /// line saying so.
    pub commands: bool,
    /// Commands a minute, per session.
    pub rate: u32,
}

impl Default for SystemPolicy {
    fn default() -> Self {
        SystemPolicy {
            login: "server".into(),
            nick: "Server".into(),
            icon: 0,
            commands: true,
            rate: 10,
        }
    }
}

/// The account's state: its policy, the uid its session holds once
/// started, and the per-session command ration.
pub(crate) struct SystemState {
    pub(crate) policy: SystemPolicy,
    pub(crate) uid: Mutex<Option<Uid>>,
    /// `uid -> (serial, last refill, tokens, warned)`, the same bucket
    /// shape the news push budget uses, plus whether this session has
    /// already been told to slow down. Session state: an entry left by a
    /// session that has ended is replaced, not inherited, when its uid is
    /// handed to someone else, which the serial is there to notice. At
    /// most one entry per uid, so the map is bounded by the uid space.
    pub(crate) rate: Mutex<HashMap<Uid, Ration>>,
    /// The last news scope each mailbox was notified about, which is
    /// what a bare `/stop` unsubscribes from. Memory, deliberately: the
    /// article is durable and the subscription is durable, and "the
    /// thing you were just told about" is neither.
    pub(crate) last_notified: Mutex<LastNotified>,
}

/// One session's command ration: the serial of the session it belongs
/// to, when it was last refilled, what is left of it, and whether this
/// session has already been told to slow down.
type Ration = (u64, Instant, f64, bool);

/// The last news scope a mailbox was notified about, keyed as every
/// mailbox-keyed map in the domain is — fingerprint where there is one,
/// login where there is not.
type LastNotified = HashMap<(Option<[u8; 32]>, String), SubScope>;

/// Whether a command may run, and whether its sender has already been
/// told why not.
enum Rationed {
    Allowed,
    Refused { first: bool },
}

/// How many `last_notified` entries are kept before the oldest-inserted
/// are forgotten. Forgetting one costs a bare `/stop` its shorthand;
/// `/stop #398` still works, and so does unfollowing from a client.
const NOTIFIED_KEPT: usize = 4096;

impl Core {
    /// The reserved account. Absent means there is no system account at
    /// all: nothing is on the roster, and a private message is a private
    /// message.
    pub fn with_system(mut self, policy: SystemPolicy) -> Self {
        self.system = Some(SystemState {
            policy,
            uid: Mutex::new(None),
            rate: Mutex::new(HashMap::new()),
            last_notified: Mutex::new(HashMap::new()),
        });
        self
    }

    /// Put the account on the roster. Called once at startup, before any
    /// client can connect, so its uid is taken before anyone else's and
    /// stays put for the life of the server — a real uid, because uid 0
    /// goes through the broadcast path on a period client and would
    /// render as a server-wide announcement rather than a message from
    /// someone.
    pub fn start_system_session(&self) -> Option<Uid> {
        let system = self.system.as_ref()?;
        let uid = self
            .attach(AttachInfo {
                nick: system.policy.nick.clone(),
                icon: system.policy.icon,
                // A 1.x user list draws an admin in red, which is the
                // only affordance that wire has for "this is not a
                // person".
                admin: true,
                // It never sends chat, joins a room or moves a file.
                // Everything it does, it does as the server.
                access: crate::AccessBits::empty(),
                login: system.policy.login.clone(),
                addr: None,
                can_detach: false,
                transport: Transport {
                    encrypted: true,
                    ..Transport::default()
                },
                // Nothing is ever queued *for* it: a message addressed
                // to it is a command, answered and not stored.
                has_inbox: false,
                attach_news: false,
                moderate: false,
                is_person: false,
                reads_on_delivery: false,
                identity: None,
                system: true,
            })?
            .0;
        self.announce(uid);
        *system.uid.lock().unwrap() = Some(uid);
        Some(uid)
    }

    /// The system account's uid, once it has one.
    pub fn system_uid(&self) -> Option<Uid> {
        self.system.as_ref()?.uid.lock().unwrap().and_then(|uid| {
            // A uid that is no longer on the roster is not the system
            // account: nothing should ever end this session, and if
            // something did, a stale uid here would address a stranger.
            let r = self.roster.lock().unwrap();
            r.users.get(&uid).filter(|s| s.system).map(|_| uid)
        })
    }

    /// What the system account is called on the roster.
    pub fn system_nick(&self) -> Option<String> {
        self.system.as_ref().map(|s| s.policy.nick.clone())
    }

    /// Is `login` the reserved one? Asked where a login is looked up, so
    /// a private message to the account by name is a command too.
    pub fn is_system_login(&self, login: &str) -> bool {
        self.system
            .as_ref()
            .is_some_and(|s| s.policy.login.eq_ignore_ascii_case(login))
    }

    /// Remember what `to` was last told about, for a bare `/stop`.
    pub(crate) fn system_notified(&self, to: &Mailbox, scope: SubScope) {
        let Some(system) = self.system.as_ref() else {
            return;
        };
        let key = (to.fingerprint, to.login.clone());
        let mut last = system.last_notified.lock().unwrap();
        if last.len() >= NOTIFIED_KEPT && !last.contains_key(&key) {
            // Cheap and arbitrary: this is a convenience cache, and the
            // worst a forgotten entry costs is that `/stop` asks for an
            // article number.
            last.clear();
        }
        last.insert(key, scope);
    }

    /// A private message addressed to the system account. Answers the
    /// text of the one message to send back, or `None` when there is no
    /// system account and the message is an ordinary one.
    pub(crate) fn system_command(&self, from: Uid, text: &str) -> Option<String> {
        let system = self.system.as_ref()?;
        if !system.policy.commands {
            return Some(
                "Commands are off on this server. This account only sends notifications.".into(),
            );
        }
        match self.system_rate_allows(from, system.policy.rate) {
            Rationed::Allowed => Some(self.run_command(from, text)),
            // One refusal per burst, and silence after it: a client
            // pasting a script should not get a message back per line.
            Rationed::Refused { first: true } => Some("error: slow down".into()),
            Rationed::Refused { first: false } => None,
        }
    }

    fn system_rate_allows(&self, uid: Uid, per_minute: u32) -> Rationed {
        let Some(system) = self.system.as_ref() else {
            return Rationed::Refused { first: false };
        };
        // Copied out and released before the ration's own lock: nothing
        // here holds the roster while taking another.
        let Some(serial) = self
            .roster
            .lock()
            .unwrap()
            .users
            .get(&uid)
            .map(|s| s.serial)
        else {
            return Rationed::Refused { first: false };
        };
        let mut rate = system.rate.lock().unwrap();
        if per_minute == 0 {
            // No commands at all is not a burst to warn about once; it
            // is the configuration, and saying so every time is right.
            return Rationed::Refused { first: true };
        }
        let per_minute = f64::from(per_minute);
        let now = Instant::now();
        let fresh = (serial, now, per_minute, false);
        let ration = rate.entry(uid).or_insert(fresh);
        if ration.0 != serial {
            // The uid was recycled: a new session starts with a full
            // ration, not with whatever its predecessor left.
            *ration = fresh;
        }
        let (_, at, tokens, warned) = ration;
        let refill = now.duration_since(*at).as_secs_f64() * per_minute / 60.0;
        *tokens = (*tokens + refill).min(per_minute);
        *at = now;
        if *tokens < 1.0 {
            let first = !*warned;
            *warned = true;
            return Rationed::Refused { first };
        }
        *tokens -= 1.0;
        *warned = false;
        Rationed::Allowed
    }

    /// One command per message: the first line is the command, and what
    /// follows belongs to its last argument, so a reason or a message
    /// body can have line breaks in it.
    fn run_command(&self, from: Uid, text: &str) -> String {
        let text = text.trim_start();
        let (first, rest) = match text.split_once('\n') {
            Some((first, rest)) => (first, Some(rest)),
            None => (text, None),
        };
        let mut words = first.split_whitespace();
        let Some(word) = words.next() else {
            return self.help();
        };
        // The leading slash is optional: `news.md` §10.11 promised the
        // bare word `stop`, and a user who types `/stop` because every
        // other chat system wants one should not be told they are wrong.
        let command = word.trim_start_matches('/').to_ascii_lowercase();
        let tail = |words: std::str::SplitWhitespace<'_>| {
            let head = words.collect::<Vec<_>>().join(" ");
            match rest {
                Some(rest) if !rest.is_empty() => format!("{head}\n{rest}"),
                _ => head,
            }
        };
        match command.as_str() {
            "help" => self.help(),
            "msg" => {
                let Some(who) = words.next() else {
                    return "error: /msg <login> <message>".into();
                };
                let body = tail(words);
                if body.trim().is_empty() {
                    return "error: /msg <login> <message>".into();
                }
                self.command_msg(from, who, body)
            }
            "block" | "unblock" => {
                let Some(who) = words.next() else {
                    return format!("error: /{command} <nick or login>");
                };
                self.command_block(from, who, command == "block")
            }
            "blocks" => self.command_blocks(from),
            "report" => {
                let Some(who) = words.next() else {
                    return "error: /report <nick or login> <reason>".into();
                };
                let reason = tail(words);
                if reason.trim().is_empty() {
                    return "error: /report <nick or login> <reason>".into();
                }
                self.command_report(from, who, &reason)
            }
            "stop" => self.command_stop(from, words.next()),
            _ => self.help(),
        }
    }

    fn help(&self) -> String {
        // Under ten lines, and only the commands this server can
        // actually run: a help text that lists something unimplemented
        // is worse than one that is short.
        "commands (send them to me as a private message):\n\
         /help — this\n\
         /msg <login> <message> — message an account, online or not\n\
         /block <nick or login>, /unblock <…>, /blocks — who may message you\n\
         /report <nick or login> <reason> — tell the moderators about someone\n\
         /stop [#article] — stop following a news thread"
            .into()
    }

    fn command_msg(&self, from: Uid, who: &str, body: String) -> String {
        if !self.session_allows(from, bit::SEND_MSGS) {
            return "error: you are not allowed to send messages".into();
        }
        if self.is_system_login(who) {
            return "error: that is me".into();
        }
        match self.msg_login(from, who, body, None, None) {
            Ok(crate::MsgOutcome::Delivered) => "ok: sent".into(),
            Ok(crate::MsgOutcome::Queued { .. }) => "ok: queued".into(),
            Err(crate::ChatError::NoSuchUser) => "error: no such account".into(),
            Err(crate::ChatError::Blocked) => "ok: sent".into(),
            Err(crate::ChatError::MailboxFull) => "error: that mailbox is full".into(),
            Err(_) => "error: that did not work".into(),
        }
    }

    fn command_block(&self, from: Uid, who: &str, blocked: bool) -> String {
        let verb = if blocked { "blocked" } else { "unblocked" };
        // A nick first, because a nick is what a period client's user
        // list shows; a login second, because that is what someone who
        // is not here has.
        let result = match self.uid_of_nick(who) {
            Some(uid) => self.inbox_block_uid(from, uid, blocked),
            None => self.inbox_block(from, who, blocked),
        };
        match result {
            Ok(()) => format!("ok: {verb} {who}"),
            Err(crate::ChatError::NoSuchUser) => "error: nobody by that name".into(),
            Err(crate::ChatError::NoInbox) => {
                "error: this server does not keep a block list".into()
            }
            Err(_) => "error: that did not work".into(),
        }
    }

    /// `/report`: the ng `report { user }` request, for a wire that has
    /// no report transaction (`docs/moderation.md` §6). By nick first,
    /// as a period client's user list names people, then by login.
    fn command_report(&self, from: Uid, who: &str, reason: &str) -> String {
        if self.is_system_login(who)
            || self
                .system_nick()
                .is_some_and(|n| n.eq_ignore_ascii_case(who))
        {
            return "error: that is me".into();
        }
        let person = match self.uid_of_nick(who) {
            Some(uid) => crate::moderation::PersonRef::Uid(uid),
            None => crate::moderation::PersonRef::Login(who.into()),
        };
        let request = crate::moderation::ReportRequest::User(person);
        match self.report(from, request, reason, None) {
            Ok(filed) if filed.follow_up => format!("ok: report #{} filed", filed.id),
            Ok(filed) => format!(
                "ok: report #{} filed — as a guest you will not hear how it ends",
                filed.id
            ),
            Err(crate::moderation::ModError::NoSuchTarget) => "error: nobody by that name".into(),
            Err(crate::moderation::ModError::RateLimited) => {
                "error: you have reported enough for one hour".into()
            }
            Err(crate::moderation::ModError::Disabled) => {
                "error: this server takes no reports".into()
            }
            Err(crate::moderation::ModError::BadRequest(why)) => format!("error: {why}"),
            Err(_) => "error: that did not work".into(),
        }
    }

    fn command_blocks(&self, from: Uid) -> String {
        match self.inbox_blocked(from) {
            Ok(blocked) if blocked.is_empty() => "ok: you have blocked nobody".into(),
            Ok(blocked) => {
                let names: Vec<&str> = blocked.iter().map(|m| m.login.as_str()).collect();
                format!("ok: blocked — {}", names.join(", "))
            }
            Err(crate::ChatError::NoInbox) => {
                "error: this server does not keep a block list".into()
            }
            Err(_) => "error: that did not work".into(),
        }
    }

    fn command_stop(&self, from: Uid, target: Option<&str>) -> String {
        let scope = match target {
            // `#398` or `398`, because a period client's user typing
            // what they saw in a notification should not have to know
            // which of the two we meant.
            Some(text) => {
                let Ok(id) = text.trim_start_matches('#').parse() else {
                    return "error: /stop [#article]".into();
                };
                match self.news_article(from, id) {
                    Ok(article) => SubScope::Thread(article.root),
                    Err(_) => return "error: no such article".into(),
                }
            }
            None => match self.last_notified_scope(from) {
                Some(scope) => scope,
                None => {
                    return "error: nothing recent to stop — try /stop #article".into();
                }
            },
        };
        match scope {
            // A reply to someone's article, or a citation of it, reaches
            // them whether or not they follow the thread, so
            // unsubscribing would answer `ok` and the next reply would
            // ring anyway. What `stop` means is this thread (`news.md`
            // §10.11), and the thing that silences every reason in a
            // thread is a mute.
            SubScope::Thread(_) => match self.news_mute(from, scope, true) {
                Ok(()) => "ok: stopped — nothing in that thread will notify you".into(),
                Err(crate::news::NewsError::TooManySubs) => {
                    "error: you follow or mute too many threads already".into()
                }
                Err(_) => "error: that did not work".into(),
            },
            // A category rings only the people following it, and only for
            // new threads; a mute there would leave a row behind for no
            // reason a follow does not already cover.
            SubScope::Category(_) => match self.news_unsubscribe(from, scope) {
                Ok(()) => "ok: stopped".into(),
                Err(_) => "error: that did not work".into(),
            },
        }
    }

    fn last_notified_scope(&self, uid: Uid) -> Option<SubScope> {
        let system = self.system.as_ref()?;
        let mailbox = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid)?;
            sess.has_inbox.then(|| sess.mailbox())?
        };
        let last = system.last_notified.lock().unwrap();
        last.get(&(mailbox.fingerprint, mailbox.login)).copied()
    }

    /// Does the session behind `uid` hold `bit`? Commands run as the
    /// session that sent them, so this is the same question the
    /// equivalent request's frontend asks.
    fn session_allows(&self, uid: Uid, bit: u8) -> bool {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).is_some_and(|s| s.access.has(bit))
    }

    /// The visible session whose nick is `nick`, case-insensitively.
    /// `None` when no one or more than one answers to it — a nick is not
    /// unique, and blocking the wrong person because two people share a
    /// name is worse than being asked for a login.
    fn uid_of_nick(&self, nick: &str) -> Option<Uid> {
        let r = self.roster.lock().unwrap();
        let mut found = None;
        for (uid, sess) in r.users.iter() {
            if sess.visible && !sess.system && sess.info.nick.eq_ignore_ascii_case(nick) {
                if found.is_some() {
                    return None;
                }
                found = Some(*uid);
            }
        }
        found
    }

    /// Send the account's one-message answer, live. Not through the
    /// inbox: a `/help` that arrives again on every reconnect is noise,
    /// and an answer to a command is only worth anything to the session
    /// that asked.
    pub(crate) fn system_reply(&self, to: Uid, text: String) {
        let Some(system) = self.system.as_ref() else {
            return;
        };
        let Some(from) = self.system_uid() else {
            warn!("system: no session to answer from");
            return;
        };
        let mut r = self.roster.lock().unwrap();
        r.send_to(
            to,
            Event::Msg {
                from,
                from_nick: system.policy.nick.clone(),
                from_login: Some(system.policy.login.clone()),
                text,
                id: None,
                sent_at: SystemTime::now(),
                queued: false,
                media: None,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::Events;

    use super::*;
    use crate::account::AccountDirectory;
    use crate::inbox::MemoryStore;
    use crate::roster::drain;
    use crate::{AccessBits, InboxPolicy};

    /// Accounts by login, so `msg_login` and the block list have
    /// something to resolve against.
    struct Directory(Vec<String>);

    impl AccountDirectory for Directory {
        fn inbox_account(&self, login: &str) -> Option<Mailbox> {
            self.0
                .iter()
                .any(|l| l == login)
                .then(|| Mailbox::login(login))
        }

        fn mailbox_access(&self, _who: &Mailbox) -> Option<AccessBits> {
            Some(member())
        }
    }

    fn member() -> AccessBits {
        AccessBits::empty().with(bit::SEND_MSGS)
    }

    struct Server {
        core: Arc<Core>,
    }

    fn server(policy: SystemPolicy) -> Server {
        let directory = Arc::new(Directory(
            ["alice", "bob"].iter().map(|l| l.to_string()).collect(),
        ));
        Server {
            core: Arc::new(
                Core::new()
                    .with_inbox(
                        Arc::new(MemoryStore::new()),
                        directory,
                        InboxPolicy::default(),
                    )
                    .with_system(policy),
            ),
        }
    }

    impl Server {
        fn login(&self, login: &str) -> (Uid, Events) {
            self.login_with(login, member())
        }

        fn login_with(&self, login: &str, access: AccessBits) -> (Uid, Events) {
            let (uid, rx) = self
                .core
                .attach(AttachInfo {
                    nick: login.to_string(),
                    icon: 1,
                    admin: false,
                    access,
                    login: login.to_string(),
                    addr: None,
                    can_detach: true,
                    transport: Transport::default(),
                    has_inbox: true,
                    attach_news: false,
                    moderate: false,
                    is_person: true,
                    reads_on_delivery: false,
                    identity: None,
                    system: false,
                })
                .unwrap();
            self.core.announce(uid);
            (uid, rx)
        }
    }

    /// What the system account said, in order.
    fn answers(rx: &mut Events) -> Vec<String> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Msg { text, .. } => Some(text),
                _ => None,
            })
            .collect()
    }

    fn command(s: &Server, from: Uid, rx: &mut Events, text: &str) -> String {
        let to = s.core.system_uid().expect("the account is on the roster");
        s.core.msg(from, to, text.into(), None, None).unwrap();
        let said = answers(rx);
        assert_eq!(said.len(), 1, "one command, one answer: {said:?}");
        said.into_iter().next().unwrap()
    }

    #[test]
    fn the_account_is_on_the_roster_and_is_not_a_person() {
        let s = server(SystemPolicy::default());
        let uid = s.core.start_system_session().unwrap();
        assert_eq!(s.core.system_uid(), Some(uid));
        let row = s
            .core
            .snapshot()
            .into_iter()
            .find(|u| u.uid == uid)
            .expect("visible on the roster");
        assert_eq!(row.nick, "Server");
        assert!(row.system, "and says so, for a client that draws it");
        assert!(
            row.admin,
            "a 1.x list draws an admin in red, the closest that wire has"
        );
        assert!(
            s.core.kick(uid, None).is_err(),
            "the server cannot be kicked off its own roster"
        );
        assert!(
            s.core.is_system_login("SERVER"),
            "and its login is reserved"
        );
    }

    #[test]
    fn a_message_to_it_is_a_command_and_is_never_stored() {
        let s = server(SystemPolicy::default());
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");

        let help = command(&s, alice, &mut rx, "/help");
        assert!(help.starts_with("commands"), "{help}");
        assert_eq!(
            command(&s, alice, &mut rx, "mumble"),
            help,
            "anything unrecognised is answered with help, never silence"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "help"),
            help,
            "the leading slash is optional"
        );
        assert_eq!(
            s.core.inbox_counts(alice).unwrap().total,
            0,
            "an answer to a command is not mail"
        );
    }

    #[test]
    fn msg_addresses_an_account_the_legacy_wire_cannot_name() {
        let s = server(SystemPolicy::default());
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");

        // bob is not logged in: this is the whole point of the command,
        // since a period client can only name someone on its user list.
        assert_eq!(
            command(&s, alice, &mut rx, "/msg bob are you there"),
            "ok: queued"
        );
        let (bob, mut bob_rx) = s.login("bob");
        s.core.flush_inbox(bob);
        let waiting = answers(&mut bob_rx);
        assert_eq!(waiting, ["are you there"]);

        assert_eq!(
            command(&s, alice, &mut rx, "/msg nobody hello"),
            "error: no such account"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/msg bob"),
            "error: /msg <login> <message>"
        );
        // The rest of the message is the message, newlines and all.
        assert_eq!(
            command(&s, alice, &mut rx, "/msg bob one\ntwo"),
            "ok: sent",
            "bob is here now"
        );
        assert_eq!(answers(&mut bob_rx), ["one\ntwo"]);
    }

    #[test]
    fn a_command_runs_as_the_session_that_sent_it() {
        let s = server(SystemPolicy::default());
        s.core.start_system_session().unwrap();
        let (mute, mut rx) = s.login_with("alice", AccessBits::empty());
        assert_eq!(
            command(&s, mute, &mut rx, "/msg bob hello"),
            "error: you are not allowed to send messages",
            "the system account confers nothing"
        );
    }

    #[test]
    fn blocking_works_by_nick_and_by_login() {
        let s = server(SystemPolicy::default());
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");
        let (_bob, _bob_rx) = s.login("bob");

        assert_eq!(
            command(&s, alice, &mut rx, "/blocks"),
            "ok: you have blocked nobody"
        );
        assert_eq!(command(&s, alice, &mut rx, "/block bob"), "ok: blocked bob");
        assert_eq!(command(&s, alice, &mut rx, "/blocks"), "ok: blocked — bob");
        assert_eq!(
            command(&s, alice, &mut rx, "/unblock bob"),
            "ok: unblocked bob"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/block nobody"),
            "error: nobody by that name"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/block"),
            "error: /block <nick or login>"
        );
    }

    #[test]
    fn stop_needs_something_to_stop() {
        let s = server(SystemPolicy::default());
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");
        assert_eq!(
            command(&s, alice, &mut rx, "/stop"),
            "error: nothing recent to stop — try /stop #article",
            "nothing has notified anyone on a server with no news"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/stop #398"),
            "error: no such article"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/stop x"),
            "error: /stop [#article]"
        );
    }

    #[test]
    fn commands_can_be_turned_off_and_the_account_stays() {
        let s = server(SystemPolicy {
            commands: false,
            ..SystemPolicy::default()
        });
        let uid = s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");
        let said = command(&s, alice, &mut rx, "/help");
        assert!(said.contains("Commands are off"), "{said}");
        assert_eq!(
            s.core.system_uid(),
            Some(uid),
            "and it is still there to send notifications from"
        );
    }

    #[test]
    fn a_session_gets_ten_commands_a_minute() {
        let s = server(SystemPolicy {
            rate: 2,
            ..SystemPolicy::default()
        });
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");
        let to = s.core.system_uid().unwrap();
        for _ in 0..5 {
            s.core.msg(alice, to, "/help".into(), None, None).unwrap();
        }
        let said = answers(&mut rx);
        assert_eq!(
            said.len(),
            3,
            "two commands, then one refusal and silence: {said:?}"
        );
        assert_eq!(said[2], "error: slow down");
    }

    #[test]
    fn report_files_against_a_nick_or_a_login_and_reaches_the_moderators() {
        let directory = Arc::new(Directory(
            ["alice", "bob", "carol"]
                .iter()
                .map(|l| l.to_string())
                .collect(),
        ));
        let store = Arc::new(crate::moderation::MemoryModeration::default());
        let s = Server {
            core: Arc::new(
                Core::new()
                    .with_inbox(
                        Arc::new(MemoryStore::new()),
                        directory,
                        InboxPolicy::default(),
                    )
                    .with_system(SystemPolicy::default())
                    .with_moderation(store.clone(), Default::default()),
            ),
        };
        s.core.start_system_session().unwrap();
        let (alice, mut rx) = s.login("alice");
        let (_bob, _) = s.login("bob");
        let (carol, mut carol_rx) = s
            .core
            .attach(AttachInfo {
                nick: "carol".into(),
                icon: 1,
                admin: true,
                access: member(),
                login: "carol".into(),
                addr: None,
                can_detach: true,
                transport: Transport::default(),
                has_inbox: true,
                attach_news: false,
                moderate: true,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        s.core.announce(carol);
        drain(&mut carol_rx);

        assert_eq!(
            command(&s, alice, &mut rx, "/report BOB spamming\nsince noon"),
            "ok: report #1 filed"
        );
        let filed = drain(&mut carol_rx)
            .into_iter()
            .find_map(|e| match e {
                Event::Report(r) => Some(r),
                _ => None,
            })
            .expect("the moderator hears it");
        assert_eq!(filed.about.login.as_deref(), Some("bob"));
        assert_eq!(
            filed.reason, "spamming\nsince noon",
            "the reason may run on"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/report nobody at all"),
            "error: nobody by that name"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/report bob"),
            "error: /report <nick or login> <reason>"
        );
        assert_eq!(
            command(&s, alice, &mut rx, "/report server hi"),
            "error: that is me"
        );
    }

    #[test]
    fn without_a_section_a_private_message_is_a_private_message() {
        let core = Core::new();
        assert_eq!(core.system_uid(), None);
        assert!(!core.is_system_login("server"));
        assert_eq!(core.start_system_session(), None);
    }
}
