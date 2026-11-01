//! Friends, presence and discovery against the in-memory stores
//! (`docs/instant-messaging.md` §3, §4.4, §6).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::inbox::{MemoryStore, MessageGuid, MessageKind, MessageStore, NewMessage};
use crate::relationships::{MemoryRelationships, SentOn};
use crate::roster::{drain, AttachInfo, InboxPolicy};
use crate::{AccessBits, AccountDirectory, Events};

/// Accounts by login, each with its bits.
pub(super) struct Directory(pub(super) Vec<(Mailbox, AccessBits)>);

impl AccountDirectory for Directory {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        self.0
            .iter()
            // As the accounts directory resolves one, whatever its case.
            .find(|(m, _)| m.login.eq_ignore_ascii_case(login))
            .map(|(m, _)| m.clone())
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
        self.0
            .iter()
            .find(|(m, _)| who.matches(&m.login, m.fingerprint.as_ref()))
            .map(|(_, a)| *a)
    }

    fn account_by_key(&self, fp: &[u8; 32]) -> Option<(Mailbox, AccessBits)> {
        self.0
            .iter()
            .find(|(m, _)| m.fingerprint == Some(*fp))
            .cloned()
    }
}

pub(super) fn messaging_bits() -> AccessBits {
    AccessBits::empty()
        .with(bit::SEND_MSGS)
        .with(bit::MESSAGING)
}

pub(super) struct Server {
    pub(super) core: Arc<Core>,
    pub(super) rel: Arc<MemoryRelationships>,
    pub(super) inbox: Arc<MemoryStore>,
}

pub(super) fn server_with(policy: MessagingPolicy, accounts: &[(&str, AccessBits)]) -> Server {
    server_notifying(policy, accounts, None)
}

fn server_notifying(
    policy: MessagingPolicy,
    accounts: &[(&str, AccessBits)],
    gateway: Option<Arc<dyn crate::NotificationGateway>>,
) -> Server {
    let dir = Directory(
        accounts
            .iter()
            .map(|(l, a)| (Mailbox::login(*l), *a))
            .collect(),
    );
    server_of(dir, policy, InboxPolicy::default(), gateway)
}

pub(super) fn server_of(
    dir: Directory,
    policy: MessagingPolicy,
    inbox_policy: InboxPolicy,
    gateway: Option<Arc<dyn crate::NotificationGateway>>,
) -> Server {
    let rel = Arc::new(MemoryRelationships::new());
    let inbox = Arc::new(MemoryStore::gated(rel.clone()));
    let mut core = Core::new()
        .with_inbox(inbox.clone(), Arc::new(dir), inbox_policy)
        .with_relationships(rel.clone())
        .with_messaging(policy);
    if let Some(gateway) = gateway {
        core = core.with_notifications(gateway);
    }
    Server {
        core: Arc::new(core),
        rel,
        inbox,
    }
}

pub(super) fn policy() -> MessagingPolicy {
    MessagingPolicy {
        enabled: true,
        presence_debounce: Duration::ZERO,
        ..MessagingPolicy::default()
    }
}

pub(super) fn server(logins: &[&str]) -> Server {
    let accounts: Vec<(&str, AccessBits)> = logins.iter().map(|l| (*l, messaging_bits())).collect();
    server_with(policy(), &accounts)
}

pub(super) fn attach_as(core: &Core, login: &str, access: AccessBits, addr: &str) -> (Uid, Events) {
    attach_on(
        core,
        login,
        access,
        addr,
        crate::Transport::default(),
        false,
    )
}

fn attach_on(
    core: &Core,
    login: &str,
    access: AccessBits,
    addr: &str,
    transport: crate::Transport,
    classic: bool,
) -> (Uid, Events) {
    let (uid, rx) = unannounced(core, login, access, addr, transport, classic);
    core.announce(uid);
    (uid, rx)
}

fn unannounced(
    core: &Core,
    login: &str,
    access: AccessBits,
    addr: &str,
    transport: crate::Transport,
    classic: bool,
) -> (Uid, Events) {
    core.attach(AttachInfo {
        account: None,
        nick: login.to_string(),
        icon: 1,
        admin: false,
        access,
        login: login.to_string(),
        addr: Some(addr.parse().unwrap()),
        can_detach: true,
        transport,
        has_inbox: true,
        attach_news: false,
        set_avatar: false,
        moderate: false,
        can_spam: false,
        manage_rooms: false,
        set_subject: false,
        is_person: true,
        reads_on_delivery: classic,
        identity: None,
        system: false,
    })
    .unwrap()
}

/// A session taking part that has read its roster, so it is told.
pub(super) fn messenger(core: &Core, login: &str) -> (Uid, Events) {
    let (uid, mut rx) = attach_as(core, login, messaging_bits(), "10.0.0.1");
    core.friends_roster(uid).unwrap();
    drain(&mut rx);
    (uid, rx)
}

pub(super) fn friends(s: &Server, a: Uid, a_rx: &mut Events, b: Uid, b_rx: &mut Events) {
    let login = |uid| s.core.roster.lock().unwrap().users[&uid].login.clone();
    assert_eq!(
        s.core.friend_add(a, &login(b), None),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        s.core.friend_respond(b, &login(a), true),
        Ok(RosterState::Accepted)
    );
    drain(a_rx);
    drain(b_rx);
}

fn entries(evs: &[Event]) -> Vec<(String, RosterState)> {
    evs.iter()
        .filter_map(|e| match e {
            Event::FriendEntry(e) => Some((e.login.clone(), e.state)),
            _ => None,
        })
        .collect()
}

fn presences(evs: &[Event]) -> Vec<(String, Presence)> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Presence { login, state, .. } => Some((login.clone(), *state)),
            _ => None,
        })
        .collect()
}

fn requests(evs: &[Event]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Event::FriendRequest { login, .. } => Some(login.clone()),
            _ => None,
        })
        .collect()
}

pub(super) fn state_of(core: &Core, uid: Uid, login: &str) -> Option<(RosterState, Presence)> {
    core.friends_roster(uid)
        .unwrap()
        .into_iter()
        .find(|e| e.login == login)
        .map(|e| (e.state, e.presence))
}

#[test]
fn a_request_accepted_makes_friends_and_tells_both() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");

    assert_eq!(
        s.core.friend_add(a, "bob", Some("hi".into())),
        Ok(RosterState::PendingOut)
    );
    assert_eq!(
        entries(&drain(&mut ra)),
        [("bob".into(), RosterState::PendingOut)]
    );
    assert_eq!(requests(&drain(&mut rb)), ["alice"]);
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::PendingIn, Presence::Offline))
    );
    assert_eq!(
        s.core.friend_add(a, "bob", None),
        Err(MessagingError::RequestPending)
    );

    assert_eq!(
        s.core.friend_respond(b, "alice", true),
        Ok(RosterState::Accepted)
    );
    assert_eq!(
        entries(&drain(&mut ra)),
        [("bob".into(), RosterState::Accepted)]
    );
    assert_eq!(
        entries(&drain(&mut rb)),
        [("alice".into(), RosterState::Accepted)]
    );
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::Accepted, Presence::Online)),
        "a friend's presence comes with the entry"
    );
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Err(MessagingError::AlreadyFriends)
    );
}

#[test]
fn crossing_requests_accept_each_other_only_from_a_session_that_understands() {
    for (held, understands) in [(false, true), (true, true), (false, false), (true, false)] {
        let case = format!("held: {held}, understands: {understands}");
        let s = server(&["alice", "bob"]);
        let (a, _ra) = if understands {
            taker(&s.core, "alice")
        } else {
            messenger(&s.core, "alice")
        };
        let (b, mut rb) = messenger(&s.core, "bob");
        if held {
            s.rel
                .hold(
                    &Mailbox::login("alice"),
                    &Requester::Account(Mailbox::login("bob")),
                    s.core.clock.wall() + Duration::from_secs(3600),
                )
                .unwrap();
        }
        assert_eq!(
            s.core.friend_add(b, "alice", None),
            Ok(RosterState::PendingOut),
            "{case}"
        );
        drain(&mut rb);
        if understands {
            assert_eq!(
                s.core.friend_add(a, "bob", None),
                Ok(RosterState::Accepted),
                "{case}: the same friendship asked for twice"
            );
            assert_eq!(
                entries(&drain(&mut rb)),
                [("alice".into(), RosterState::Accepted)],
                "{case}"
            );
        } else {
            assert_eq!(
                s.core.friend_add(a, "bob", None),
                Err(MessagingError::RequestPending),
                "{case}: as the extension answers it, shown or not"
            );
            assert!(drain(&mut rb).is_empty(), "{case}");
        }
    }
}

#[test]
fn ending_a_request_or_a_friendship_tells_both_and_holds_where_it_should() {
    // How it ends, and whether alice is held from asking bob again.
    type End = fn(&Core, Uid, Uid) -> Result<(), MessagingError>;
    let cases: [(&str, bool, End, bool); 4] = [
        (
            "a declined request",
            false,
            |c, _, b| c.friend_respond(b, "alice", false).map(|_| ()),
            true,
        ),
        (
            "a request rejected by removal",
            false,
            |c, _, b| c.friend_remove(b, "alice"),
            true,
        ),
        (
            "a withdrawn request",
            false,
            |c, a, _| c.friend_remove(a, "bob"),
            false,
        ),
        (
            "a removed friend",
            true,
            |c, _, b| c.friend_remove(b, "alice"),
            true,
        ),
    ];
    for (case, accepted, end, held) in cases {
        let s = server(&["alice", "bob"]);
        let (a, mut ra) = messenger(&s.core, "alice");
        let (b, mut rb) = messenger(&s.core, "bob");
        if accepted {
            friends(&s, a, &mut ra, b, &mut rb);
        } else {
            s.core.friend_add(a, "bob", None).unwrap();
            drain(&mut ra);
            drain(&mut rb);
        }
        end(&s.core, a, b).unwrap();
        assert_eq!(
            entries(&drain(&mut ra)),
            [("bob".into(), RosterState::Removed)],
            "{case}"
        );
        assert_eq!(
            entries(&drain(&mut rb)),
            [("alice".into(), RosterState::Removed)],
            "{case}"
        );
        assert_eq!(state_of(&s.core, a, "bob"), None, "{case}");

        // Asking again is answered as asking always is; a held request
        // reaches nobody.
        assert_eq!(
            s.core.friend_add(a, "bob", None),
            Ok(RosterState::PendingOut),
            "{case}"
        );
        assert_eq!(
            requests(&drain(&mut rb)).is_empty(),
            held,
            "{case}: shown to bob again"
        );
        assert_eq!(
            state_of(&s.core, b, "alice").is_none(),
            held,
            "{case}: listed as pending in"
        );
    }
}

#[test]
fn a_block_ends_the_friendship_and_reads_to_the_blocked_as_no_account() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.friend_alias(b, "alice", Some("al")).unwrap();
    drain(&mut rb);

    s.core.inbox_block(b, "alice", true).unwrap();
    assert_eq!(
        entries(&drain(&mut ra)),
        [("bob".into(), RosterState::Removed)],
        "the blocked hears only that the row is gone"
    );
    match &drain(&mut rb)[..] {
        [Event::FriendEntry(e)] => {
            assert_eq!(e.state, RosterState::Blocked);
            assert_eq!(e.alias.as_deref(), Some("al"), "a block keeps the alias");
        }
        other => panic!("expected bob's blocked row, got {other:?}"),
    }
    for refused in [
        s.core.friend_add(a, "bob", None).map(|_| ()),
        s.core.find_user(a, "bob").map(|_| ()),
        s.core.messaging_user_info(a, "bob").map(|_| ()),
    ] {
        assert_eq!(refused, Err(MessagingError::AccountNotFound));
    }
    assert_eq!(
        s.core.friend_add(b, "alice", None),
        Err(MessagingError::Blocked),
        "the blocker is told of its own block"
    );

    s.core.inbox_block(b, "alice", false).unwrap();
    assert_eq!(
        entries(&drain(&mut rb)),
        [("alice".into(), RosterState::Removed)]
    );
    assert!(
        drain(&mut ra).is_empty(),
        "an unblock tells the other nothing"
    );
    assert_eq!(
        s.rel
            .relationship(
                &Mailbox::login("bob"),
                &Mailbox::login("alice"),
                s.core.clock.wall()
            )
            .unwrap(),
        None,
        "nor keeps the alias"
    );
}

#[test]
fn a_block_tells_the_blocked_only_of_a_row_it_could_see() {
    // What bob had with alice before he blocked her, and whether she
    // hears her row about him is gone.
    type Before = fn(&Server, Uid, &mut Events, Uid, &mut Events);
    let cases: [(&str, Before, bool); 4] = [
        ("nothing", |_, _, _, _, _| {}, false),
        (
            "a friendship",
            |s, a, ra, b, rb| friends(s, a, ra, b, rb),
            true,
        ),
        (
            "bob's request, shown to her",
            |s, _, _, b, _| {
                s.core.friend_add(b, "alice", None).unwrap();
            },
            true,
        ),
        (
            "her own request",
            |s, a, _, _, _| {
                s.core.friend_add(a, "bob", None).unwrap();
            },
            false,
        ),
    ];
    for (case, before, told) in cases {
        let s = server(&["alice", "bob"]);
        let (a, mut ra) = messenger(&s.core, "alice");
        let (b, mut rb) = messenger(&s.core, "bob");
        before(&s, a, &mut ra, b, &mut rb);
        drain(&mut ra);
        s.core.inbox_block(b, "alice", true).unwrap();
        let heard = entries(&drain(&mut ra));
        let want: Vec<(String, RosterState)> = told
            .then(|| ("bob".into(), RosterState::Removed))
            .into_iter()
            .collect();
        assert_eq!(heard, want, "{case}");
        assert_eq!(
            state_of(&s.core, b, "alice"),
            Some((RosterState::Blocked, Presence::Offline)),
            "{case}"
        );
        assert_eq!(state_of(&s.core, a, "bob"), None, "{case}: nothing left");
        s.core.inbox_block(b, "alice", false).unwrap();
        assert_eq!(state_of(&s.core, b, "alice"), None, "{case}");
    }
}

#[test]
fn a_blocker_reads_as_no_account_to_every_act_that_names_it() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.inbox_block(b, "alice", true).unwrap();
    for (act, got) in [
        ("respond", s.core.friend_respond(a, "bob", true).map(|_| ())),
        ("remove", s.core.friend_remove(a, "bob")),
        ("alias", s.core.friend_alias(a, "bob", Some("b"))),
    ] {
        assert_eq!(got, Err(MessagingError::AccountNotFound), "{act}");
    }
}

#[test]
fn an_alias_is_a_friends_alone() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    messenger(&s.core, "bob");
    assert_eq!(
        s.core.friend_alias(a, "bob", Some("b")),
        Err(MessagingError::NotFriends)
    );
    assert!(entries(&drain(&mut ra)).is_empty());
}

#[test]
fn presence_is_the_most_available_session_and_invisible_hides_them_all() {
    let s = server(&["alice", "bob"]);
    let (a1, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a1, &mut ra, b, &mut rb);
    let (a2, _ra2) = messenger(&s.core, "alice");
    assert!(presences(&drain(&mut rb)).is_empty(), "still just online");

    // Each step, and what bob is told of alice after it.
    let steps: [(Uid, Presence, Option<Presence>); 6] = [
        (a1, Presence::Away, None),
        (a2, Presence::Away, Some(Presence::Away)),
        (a2, Presence::Busy, Some(Presence::Busy)),
        (a1, Presence::Invisible, Some(Presence::Offline)),
        (a1, Presence::Away, Some(Presence::Busy)),
        (a2, Presence::Online, Some(Presence::Online)),
    ];
    for (i, (uid, state, told)) in steps.into_iter().enumerate() {
        s.core
            .set_presence(
                uid,
                PresenceUpdate {
                    state: Some(state),
                    ..Default::default()
                },
            )
            .unwrap();
        let want: Vec<(String, Presence)> = told.map(|p| ("alice".into(), p)).into_iter().collect();
        assert_eq!(presences(&drain(&mut rb)), want, "step {i}: {state:?}");
    }

    s.core.end_session(a2);
    assert_eq!(
        presences(&drain(&mut rb)),
        [("alice".into(), Presence::Away)]
    );
    s.core.end_session(a1);
    assert_eq!(
        presences(&drain(&mut rb)),
        [("alice".into(), Presence::Offline)]
    );
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::Accepted, Presence::Offline))
    );
}

#[test]
fn signing_on_is_told_to_friends_and_to_nobody_else() {
    let s = server(&["alice", "bob", "carol"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    let (_c, mut rc) = messenger(&s.core, "carol");
    // A friend's session that never asked anything of the family.
    let (_b2, mut rb2) = attach_as(&s.core, "bob", messaging_bits(), "10.0.0.2");

    s.core.end_session(a);
    attach_as(&s.core, "alice", messaging_bits(), "10.0.0.1");
    assert_eq!(
        presences(&drain(&mut rb)),
        [
            ("alice".into(), Presence::Offline),
            ("alice".into(), Presence::Online)
        ]
    );
    for rx in [&mut rc, &mut rb2] {
        assert!(presences(&drain(rx)).is_empty());
    }
}

#[test]
fn a_burst_of_changes_is_told_once_with_where_it_ended() {
    let s = server_with(
        MessagingPolicy {
            presence_debounce: Duration::from_secs(5),
            ..policy()
        },
        &[("alice", messaging_bits()), ("bob", messaging_bits())],
    );
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    let later = Instant::now() + Duration::from_secs(60);
    s.core.presence_flush(later);
    drain(&mut rb);

    for state in [
        Presence::Away,
        Presence::Busy,
        Presence::Away,
        Presence::Busy,
    ] {
        s.core
            .set_presence(
                a,
                PresenceUpdate {
                    state: Some(state),
                    status_text: Some(Some(format!("{state:?}"))),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert!(presences(&drain(&mut rb)).is_empty(), "held back");
    assert_eq!(s.core.presence_flush(later), None, "and nothing more owed");
    match &drain(&mut rb)[..] {
        [Event::Presence {
            state, status_text, ..
        }] => {
            assert_eq!(*state, Presence::Busy);
            assert_eq!(status_text.as_deref(), Some("Busy"));
        }
        other => panic!("expected one presence, got {other:?}"),
    }
}

#[test]
fn a_stranger_finds_the_account_and_nothing_of_where_it_is() {
    let s = server(&["alice", "bob", "carol"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    let (c, _rc) = messenger(&s.core, "carol");
    friends(&s, a, &mut ra, b, &mut rb);
    s.rel
        .update_account(
            &Mailbox::login("alice"),
            &AccountUpdate {
                profile: Some(Profile {
                    nickname: Some("Alice A.".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();

    let stranger = s.core.messaging_user_info(c, "alice").unwrap();
    assert_eq!(
        (stranger.name.as_str(), stranger.presence, stranger.profile),
        ("Alice A.", None, None)
    );
    let friend = s.core.messaging_user_info(b, "alice").unwrap();
    assert_eq!(friend.presence, Some((Presence::Online, None)));
    assert!(friend.profile.is_some());
    assert!(s.core.find_user(b, "alice").unwrap().profile.is_none());
    assert!(s
        .core
        .messaging_user_info(a, "alice")
        .unwrap()
        .profile
        .is_some());
    assert_eq!(
        s.core.find_user(c, "nobody").map(|_| ()),
        Err(MessagingError::AccountNotFound)
    );
}

#[test]
fn who_takes_part() {
    let without = AccessBits::empty().with(bit::SEND_MSGS);
    let s = server_with(
        policy(),
        &[
            ("alice", messaging_bits()),
            ("plain", without),
            ("admin", messaging_bits()),
            ("guest", messaging_bits()),
        ],
    );
    let (a, _ra) = messenger(&s.core, "alice");
    for login in ["plain", "admin", "guest", "nobody"] {
        assert_eq!(
            s.core.friend_add(a, login, None),
            Err(MessagingError::AccountNotFound),
            "{login}"
        );
    }
    for (login, access) in [("plain", without), ("admin", messaging_bits())] {
        let (uid, _rx) = attach_as(&s.core, login, access, "10.0.0.3");
        assert_eq!(
            s.core.friends_roster(uid),
            Err(MessagingError::NotEnabled),
            "{login}"
        );
    }
    let off = server_with(
        MessagingPolicy::default(),
        &[("alice", messaging_bits()), ("bob", messaging_bits())],
    );
    let (a, _ra) = attach_as(&off.core, "alice", messaging_bits(), "10.0.0.1");
    assert_eq!(
        off.core.friends_roster(a),
        Err(MessagingError::NotEnabled),
        "off unless turned on"
    );
}

#[test]
fn friend_requests_are_bounded_by_what_was_sent() {
    let p = MessagingPolicy {
        max_friend_requests: 1,
        requests_per_day: 2,
        max_roster: 3,
        ..policy()
    };
    let logins = ["alice", "bob", "carol", "dave", "erin"];
    let accounts: Vec<(&str, AccessBits)> = logins.iter().map(|l| (*l, messaging_bits())).collect();
    let s = server_with(p, &accounts);
    let (a, _ra) = messenger(&s.core, "alice");
    let (b, _rb) = messenger(&s.core, "bob");
    let (c, mut rc) = messenger(&s.core, "carol");
    let (d, _rd) = messenger(&s.core, "dave");

    // Carol's box takes one; bob's is dropped, answered the same.
    s.core.friend_add(a, "carol", None).unwrap();
    drain(&mut rc);
    assert_eq!(
        s.core.friend_add(b, "carol", None),
        Ok(RosterState::PendingOut)
    );
    assert!(
        requests(&drain(&mut rc)).is_empty(),
        "dropped, not delivered"
    );
    assert_eq!(state_of(&s.core, c, "bob"), None);

    // Carol and dave are alice's two recipients for the day.
    s.core.friend_add(a, "dave", None).unwrap();
    assert_eq!(
        s.core.friend_add(a, "erin", None),
        Err(MessagingError::RateLimited)
    );

    // A waiting request takes no place in the recipient's roster, so
    // accepting it at the cap is refused and leaves it waiting.
    s.core.friend_add(d, "bob", None).unwrap();
    s.core.friend_add(d, "carol", None).unwrap();
    s.core.inbox_block(d, "erin", true).unwrap();
    assert_eq!(
        s.core.friend_respond(d, "alice", true),
        Err(MessagingError::RosterFull)
    );
    assert_eq!(
        state_of(&s.core, d, "alice"),
        Some((RosterState::PendingIn, Presence::Offline))
    );
}

#[test]
fn an_unanswered_request_lapses_without_a_word() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, _rb) = messenger(&s.core, "bob");
    s.core.friend_add(a, "bob", None).unwrap();
    drain(&mut ra);
    s.core
        .clock
        .advance(policy().request_retention + Duration::from_secs(1));
    assert_eq!(
        s.core.friend_respond(b, "alice", true),
        Err(MessagingError::NotFriends)
    );
    assert_eq!(state_of(&s.core, a, "bob"), None);
    assert!(drain(&mut ra).is_empty());
}

#[test]
fn a_purged_account_is_gone_from_its_friends_rosters() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.end_session(a);
    drain(&mut rb);
    s.core.inbox_purge(&Mailbox::login("alice"));
    assert_eq!(
        entries(&drain(&mut rb)),
        [("alice".into(), RosterState::Removed)]
    );
    assert_eq!(state_of(&s.core, b, "alice"), None);
}

#[test]
fn a_claim_that_folds_a_block_beside_a_friendship_ends_it() {
    let s = server(&["alice", "bob"]);
    let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
    let alice_fp = Mailbox::identified("alice", [7u8; 32]);
    let now = s.core.clock.wall();
    // Alice befriended bob as a login, and her identity had blocked him:
    // linking makes the two one row.
    s.rel.befriend(&alice, &bob, now).unwrap();
    s.rel.set_blocked(&alice_fp, &bob, true, now).unwrap();
    let (b, mut rb) = messenger(&s.core, "bob");

    s.core.inbox_claim("alice", &[7u8; 32]);
    assert_eq!(
        entries(&drain(&mut rb)),
        [("alice".into(), RosterState::Removed)]
    );
    assert_eq!(state_of(&s.core, b, "alice"), None);
    let row = s.rel.relationship(&alice_fp, &bob, now).unwrap().unwrap();
    assert!(row.blocked_at.is_some() && row.friendship.is_none());
}

#[test]
fn a_claim_restamps_what_was_sent_on_a_friendship_it_merged() {
    let s = server(&["alice", "bob"]);
    let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
    let alice_fp = Mailbox::identified("alice", [7u8; 32]);
    let now = s.core.clock.wall();
    let lost = s.rel.befriend(&alice, &bob, now).unwrap();
    let kept = s.rel.befriend(&alice_fp, &bob, now).unwrap();
    s.inbox
        .push(
            &NewMessage {
                recipient: bob.clone(),
                sender: Some(alice.clone()),
                sender_nick: "alice".into(),
                body: "on the old one".into(),
                sent_at: now,
                guid: None,
                kind: MessageKind::Message,
                media: None,
                signed: None,
                friendship: Some(SentOn::Relation(lost)),
                sender_address: None,
            },
            10,
        )
        .unwrap();
    s.core.inbox_claim("alice", &[7u8; 32]);
    assert_eq!(s.inbox.all()[0].friendship, Some(SentOn::Relation(kept)));
}

// --- Instant messages --------------------------------------------------

fn ims(evs: &[Event]) -> Vec<(String, bool)> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Im(im) => Some((im.text.clone(), im.queued)),
            _ => None,
        })
        .collect()
}

fn msgs(evs: &[Event]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Msg { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn receipts(evs: &[Event]) -> Vec<(String, bool)> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Receipt { login, read, .. } => Some((login.clone(), *read)),
            _ => None,
        })
        .collect()
}

/// A session whose wire speaks the friend family from login on.
fn family(core: &Core, login: &str) -> (Uid, Events) {
    let (uid, mut rx) = attach_on(
        core,
        login,
        messaging_bits(),
        "10.0.0.1",
        crate::Transport {
            messaging: true,
            ..Default::default()
        },
        false,
    );
    drain(&mut rx);
    (uid, rx)
}

#[test]
fn a_send_by_login_from_a_session_without_an_inbox_is_refused() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core
        .roster
        .lock()
        .unwrap()
        .users
        .get_mut(&a)
        .unwrap()
        .has_inbox = false;
    assert_eq!(
        s.core.im_send_login(a, "bob", "hi".into(), None),
        Err(MessagingError::NotEnabled)
    );
    assert!(s.inbox.all().is_empty());
}

#[test]
fn an_im_is_handed_to_a_friend_and_again_until_it_is_acknowledged() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);

    let sent = s.core.im_send(a, "bob", "hi".into(), None, None).unwrap();
    assert!(sent.delivered, "a messenger session took it");
    assert_eq!(ims(&drain(&mut rb)), [("hi".into(), false)]);
    assert!(
        s.inbox.all()[0].delivered_at.is_none(),
        "delivered is the acknowledgment's to say"
    );
    s.core.friends_roster(b).unwrap();
    assert_eq!(
        ims(&drain(&mut rb)),
        [("hi".into(), true)],
        "handed over again at the next roster read"
    );

    s.core.im_ack(b, "alice", &sent.guid, false).unwrap();
    assert_eq!(receipts(&drain(&mut ra)), [("bob".into(), false)]);
    assert!(s.inbox.all()[0].delivered_at.is_some());
    s.core.friends_roster(b).unwrap();
    assert!(ims(&drain(&mut rb)).is_empty());
}

#[test]
fn an_im_is_refused_to_anyone_but_a_friend() {
    let p = MessagingPolicy {
        max_message_bytes: 8,
        ..policy()
    };
    let accounts: Vec<(&str, AccessBits)> = ["alice", "bob", "carol"]
        .iter()
        .map(|l| (*l, messaging_bits()))
        .collect();
    let s = server_with(p, &accounts);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    let (c, _rc) = messenger(&s.core, "carol");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.inbox_block(c, "alice", true).unwrap();
    for (case, to, text, want) in [
        ("a stranger", "carol", "hi", MessagingError::NotFriends),
        ("a blocker", "carol", "hi", MessagingError::AccountNotFound),
        (
            "too long",
            "bob",
            "nine byte",
            MessagingError::MessageTooLong,
        ),
    ] {
        let from = if case == "a stranger" { b } else { a };
        assert_eq!(
            s.core.im_send(from, to, text.into(), None, None),
            Err(want),
            "{case}"
        );
    }
    assert!(s.inbox.all().is_empty(), "nothing stored");
}

#[test]
fn a_family_session_waits_for_its_roster_read_and_any_other_is_handed_a_message() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.end_session(b);
    let sent = s
        .core
        .im_send(a, "bob", "later".into(), None, None)
        .unwrap();
    assert!(!sent.delivered, "queued for a login with nobody there");

    let (b, mut rb) = family(&s.core, "bob");
    assert_eq!(s.core.flush_inbox(b), 0, "not at the login flush");
    assert!(drain(&mut rb).is_empty());
    s.core.friends_roster(b).unwrap();
    assert_eq!(ims(&drain(&mut rb)), [("later".into(), true)]);
    s.core.end_session(b);
    s.core
        .im_send(a, "bob", "for a plain one".into(), None, None)
        .unwrap();

    let (b, mut rb) = attach_as(&s.core, "bob", messaging_bits(), "10.0.0.2");
    s.core.flush_inbox(b);
    assert_eq!(
        msgs(&drain(&mut rb)),
        ["for a plain one"],
        "a session that speaks no friend family reads it as a private message"
    );
    assert!(s.inbox.all()[1].delivered_at.is_some());
    let (_b2, mut rb2) = attach_as(&s.core, "bob", messaging_bits(), "10.0.0.3");
    s.core.im_send(a, "bob", "live".into(), None, None).unwrap();
    assert_eq!(msgs(&drain(&mut rb)), ["live"]);
    assert_eq!(msgs(&drain(&mut rb2)), ["live"], "and every other one");
}

#[test]
fn what_was_queued_on_a_friendship_is_held_once_it_ends() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.end_session(b);
    s.core
        .im_send(a, "bob", "before".into(), None, None)
        .unwrap();
    s.core.friend_remove(a, "bob").unwrap();
    // Made again, it is another friendship.
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.friends_roster(b).unwrap();
    assert!(ims(&drain(&mut rb)).is_empty());
    assert_eq!(
        s.core.inbox_counts(b).unwrap().total,
        0,
        "nor listed or counted"
    );
}

#[test]
fn a_read_waits_for_a_sender_that_was_not_there() {
    for gone in ["ended", "detached", "resumed"] {
        let s = server(&["alice", "bob"]);
        let (a, mut ra) = messenger(&s.core, "alice");
        let (b, mut rb) = messenger(&s.core, "bob");
        friends(&s, a, &mut ra, b, &mut rb);
        let sent = s.core.im_send(a, "bob", "hi".into(), None, None).unwrap();
        s.core.im_typing(b, "alice", true).unwrap();
        let last_seq = std::iter::from_fn(|| ra.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        if gone == "ended" {
            s.core.end_session(a);
        } else {
            s.core.connection_lost(a, 4);
        }
        s.core.im_ack(b, "alice", &sent.guid, true).unwrap();
        s.core.im_ack(b, "alice", &sent.guid, true).unwrap();
        assert!(s.inbox.all()[0].read_at.is_some());

        let (a, mut ra, replayed) = if gone == "resumed" {
            let crate::Resume::Replayed(rx, replay) = s.core.resume(a, last_seq) else {
                panic!("{gone}: resume should replay");
            };
            (a, rx, replay.into_iter().map(|se| se.event).collect())
        } else {
            let (a, ra) = family(&s.core, "alice");
            (a, ra, Vec::new())
        };
        s.core.friends_roster(a).unwrap();
        let mut heard = receipts(&replayed);
        heard.extend(receipts(&drain(&mut ra)));
        assert_eq!(
            heard,
            [("bob".into(), true)],
            "{gone}: kept once, however often it was read"
        );
        s.core.friends_roster(a).unwrap();
        assert!(receipts(&drain(&mut ra)).is_empty(), "{gone}: once");
    }
}

#[test]
fn a_read_after_a_period_clients_delivery_is_still_told() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.end_session(b);
    let (_p, _rp) = classic(&s.core, "bob", messaging_bits());
    let sent = s.core.im_send(a, "bob", "hi".into(), None, None).unwrap();
    assert!(
        s.inbox.all()[0].read_at.is_some(),
        "a period client's delivery is its read"
    );
    let (b, _rb) = messenger(&s.core, "bob");
    s.core.im_ack(b, "alice", &sent.guid, true).unwrap();
    assert_eq!(receipts(&drain(&mut ra)), [("bob".into(), true)]);
}

#[test]
fn a_signed_id_and_the_daily_quota_hold_an_im_as_they_hold_mail() {
    let key = |n: u8| [n; 32];
    let dir = Directory(
        [("alice", 1), ("bob", 2), ("carol", 3), ("dave", 4)]
            .iter()
            .map(|(l, n)| (Mailbox::identified(*l, key(*n)), messaging_bits()))
            .collect(),
    );
    let quota = InboxPolicy {
        max_sent_per_day: 3,
        ..InboxPolicy::default()
    };
    let s = server_of(dir, policy(), quota, None);
    let (a, mut ra) = attach_identified(&s.core, "alice", key(1));
    let (b, mut rb) = attach_identified(&s.core, "bob", key(2));
    let (c, mut rc) = attach_identified(&s.core, "carol", key(3));
    friends(&s, a, &mut ra, b, &mut rb);
    friends(&s, a, &mut ra, c, &mut rc);
    let signed = |to: u8, says: u8| {
        Some(crate::chat::SignedMsg {
            signature: crate::history::Signature {
                form: vec![says],
                content: [says; 32],
            },
            to: key(to),
        })
    };
    let (g1, g2, g4) = (
        MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000011").unwrap(),
        MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000012").unwrap(),
        MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000014").unwrap(),
    );
    // A signed request to a stranger, who deletes it.
    let (d, _rd) = attach_identified(&s.core, "dave", key(4));
    for uid in [a, d] {
        s.core
            .set_presence(
                uid,
                PresenceUpdate {
                    takes_requests: Some(true),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(
        s.core.msg_login_signed(
            a,
            "dave",
            "hello?".into(),
            Some(g4.clone()),
            None,
            signed(4, 4)
        ),
        Ok(crate::MsgOutcome::Requested)
    );
    s.core
        .request_answer(d, "alice", RequestAction::Delete)
        .unwrap();
    let im = |to: &str, text: &str, guid: &MessageGuid, signed| {
        s.core
            .im_send(a, to, text.into(), Some(guid.clone()), signed)
            .map(|_| ())
    };
    for (case, to, guid, signed, want) in [
        (
            "a request's id, whatever became of it",
            "bob",
            &g4,
            signed(2, 4),
            Err(MessagingError::Equivocation),
        ),
        ("signed", "bob", &g1, signed(2, 1), Ok(())),
        (
            "other words",
            "bob",
            &g1,
            signed(2, 9),
            Err(MessagingError::Equivocation),
        ),
        (
            "another recipient",
            "carol",
            &g1,
            signed(3, 1),
            Err(MessagingError::Equivocation),
        ),
        ("the day's last", "bob", &g2, None, Ok(())),
        ("a retry past it", "bob", &g2, None, Ok(())),
        (
            "past the quota, to a friend there",
            "bob",
            &MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000013").unwrap(),
            None,
            Ok(()),
        ),
    ] {
        assert_eq!(im(to, case, guid, signed), want, "{case}");
    }
    assert_eq!(
        s.inbox.all().len(),
        2,
        "nothing refused, or past the quota, was stored"
    );
    assert!(
        drain(&mut rb)
            .iter()
            .any(|e| matches!(e, Event::Im(im) if im.id.is_none() && !im.queued)),
        "handed over live, with no row"
    );
    // A plain session beside the messenger is kept nothing to be handed
    // later, so it hears it now, as mail.
    let (beside, mut rbeside) = attach_identified(&s.core, "bob", key(2));
    assert_eq!(
        im(
            "bob",
            "to both kinds",
            &MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000017").unwrap(),
            None
        ),
        Ok(())
    );
    assert_eq!(ims(&drain(&mut rb)), [("to both kinds".into(), false)]);
    assert_eq!(msgs(&drain(&mut rbeside)), ["to both kinds"]);
    s.core.end_session(beside);
    s.core.end_session(b);
    // With no messenger there, as a private message to every session.
    let plain: Vec<(Uid, Events)> = (0..2)
        .map(|_| attach_identified(&s.core, "bob", key(2)))
        .collect();
    assert_eq!(
        im(
            "bob",
            "to the plain ones",
            &MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000016").unwrap(),
            None
        ),
        Ok(())
    );
    for (uid, mut rx) in plain {
        assert_eq!(msgs(&drain(&mut rx)), ["to the plain ones"]);
        s.core.end_session(uid);
    }
    assert_eq!(
        im(
            "bob",
            "with nobody there",
            &MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000015").unwrap(),
            None
        ),
        Err(MessagingError::RateLimited)
    );
}

#[test]
fn typing_and_receipts_reach_friends_alone() {
    let s = server(&["alice", "bob", "carol"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    let (c, mut rc) = messenger(&s.core, "carol");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.im_typing(a, "bob", true).unwrap();
    s.core.im_typing(c, "bob", true).unwrap();
    let typing: Vec<String> = drain(&mut rb)
        .iter()
        .filter_map(|e| match e {
            Event::Typing { login, .. } => Some(login.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(typing, ["alice"]);

    // A message alice sent bob before carol could ask for anything.
    let sent = s.core.im_send(a, "bob", "hi".into(), None, None).unwrap();
    s.core.im_ack(c, "alice", &sent.guid, true).unwrap();
    assert!(receipts(&drain(&mut ra)).is_empty());
    assert!(drain(&mut rc).is_empty());
}

#[test]
fn a_message_by_login_to_a_friend_is_an_instant_message() {
    let without = AccessBits::empty().with(bit::SEND_MSGS);
    let s = server_with(
        policy(),
        &[
            ("alice", messaging_bits()),
            ("bob", messaging_bits()),
            ("carol", without),
        ],
    );
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    let (_c, mut rc) = attach_as(&s.core, "carol", without, "10.0.0.3");
    friends(&s, a, &mut ra, b, &mut rb);
    let (plain, _rp) = attach_as(&s.core, "alice", messaging_bits(), "10.0.0.2");

    assert_eq!(
        s.core
            .msg_login(plain, "bob", "by login".into(), None, None),
        Ok(crate::MsgOutcome::Delivered)
    );
    assert_eq!(ims(&drain(&mut rb)), [("by login".into(), false)]);
    s.core
        .msg_login(plain, "carol", "outside messaging".into(), None, None)
        .unwrap();
    assert_eq!(
        msgs(&drain(&mut rc)),
        ["outside messaging"],
        "an account outside messaging is sent a private message as before"
    );
}

#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<String>>);

impl crate::NotificationGateway for Recorder {
    fn notify(&self, n: &crate::Notification<'_>) {
        if let crate::Notification::Message(m) = n {
            self.0.lock().unwrap().push(m.text.to_string());
        }
    }
}

#[test]
fn an_im_pushes_unless_its_recipient_is_there_or_busy() {
    let gw = Arc::new(Recorder::default());
    let accounts = [("alice", messaging_bits()), ("bob", messaging_bits())];
    let s = server_notifying(policy(), &accounts, Some(gw.clone()));
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);

    s.core
        .im_send(a, "bob", "attentive".into(), None, None)
        .unwrap();
    s.core.connection_lost(b, 4);
    s.core
        .im_send(a, "bob", "detached".into(), None, None)
        .unwrap();
    let (b, _rb) = family(&s.core, "bob");
    s.core.connection_lost(b, 4);
    for (state, text) in [(Presence::Invisible, "invisible"), (Presence::Busy, "busy")] {
        s.core.resume(b, 0);
        s.core
            .set_presence(
                b,
                PresenceUpdate {
                    state: Some(state),
                    ..Default::default()
                },
            )
            .unwrap();
        s.core.connection_lost(b, 4);
        s.core.im_send(a, "bob", text.into(), None, None).unwrap();
    }
    assert_eq!(*gw.0.lock().unwrap(), ["detached", "invisible"]);
}

// --- Message requests and approvals ------------------------------------

/// A messenger session that has opted in to requests, so its account
/// takes them and it is shown them.
fn taker(core: &Core, login: &str) -> (Uid, Events) {
    let (uid, mut rx) = messenger(core, login);
    core.set_presence(
        uid,
        PresenceUpdate {
            takes_requests: Some(true),
            ..Default::default()
        },
    )
    .unwrap();
    drain(&mut rx);
    (uid, rx)
}

/// A period client's session: it can never list requests.
fn classic(core: &Core, login: &str, access: AccessBits) -> (Uid, Events) {
    let (uid, mut rx) = attach_on(
        core,
        login,
        access,
        "10.0.0.9",
        crate::Transport::default(),
        true,
    );
    drain(&mut rx);
    (uid, rx)
}

fn waiting(core: &Core, uid: Uid) -> Vec<(String, Vec<String>)> {
    core.requests_list(uid)
        .unwrap()
        .requests
        .into_iter()
        .map(|g| {
            (
                g.from.login,
                g.messages.into_iter().map(|m| m.body).collect(),
            )
        })
        .collect()
}

fn changed(evs: &[Event]) -> Vec<usize> {
    evs.iter()
        .filter_map(|e| match e {
            Event::RequestsChanged { count } => Some(*count),
            _ => None,
        })
        .collect()
}

fn send(
    core: &Core,
    uid: Uid,
    to: &str,
    text: &str,
) -> Result<crate::MsgOutcome, crate::ChatError> {
    core.msg_login(uid, to, text.into(), None, None)
}

#[test]
fn a_message_to_a_stranger_is_a_request_answered_alike_however_it_ends() {
    let p = MessagingPolicy {
        max_requests: 1,
        ..policy()
    };
    let accounts: Vec<(&str, AccessBits)> = ["alice", "bob", "carol"]
        .iter()
        .map(|l| (*l, messaging_bits()))
        .collect();
    let s = server_with(p, &accounts);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    let (c, _rc) = taker(&s.core, "carol");

    assert_eq!(
        send(&s.core, a, "bob", "hello?"),
        Ok(crate::MsgOutcome::Requested)
    );
    let to_bob = drain(&mut rb);
    assert_eq!(changed(&to_bob), [1]);
    assert!(
        ims(&to_bob).is_empty() && msgs(&to_bob).is_empty(),
        "a request is not delivered"
    );
    assert_eq!(
        waiting(&s.core, b),
        [("alice".into(), vec!["hello?".into()])]
    );

    // Past bob's box, carol's is dropped and answered the same.
    assert_eq!(
        send(&s.core, c, "bob", "me too"),
        Ok(crate::MsgOutcome::Requested)
    );
    assert_eq!(s.core.requests_list(b).unwrap().dropped, 1);

    // Deleted, alice is held: answered the same, stored nowhere.
    s.core
        .request_answer(b, "alice", RequestAction::Delete)
        .unwrap();
    assert_eq!(
        send(&s.core, a, "bob", "again"),
        Ok(crate::MsgOutcome::Requested)
    );
    assert!(waiting(&s.core, b).is_empty());
    assert_eq!(
        s.core.request_answer(b, "alice", RequestAction::Approve),
        Err(MessagingError::NoSuchRequest)
    );
}

#[test]
fn who_may_ask_and_who_is_answered_otherwise() {
    use crate::{ChatError, MsgOutcome};
    let without = AccessBits::empty().with(bit::SEND_MSGS);
    type Setup = fn(&Server) -> Uid;
    let cases: [(&str, Setup, Result<MsgOutcome, ChatError>); 10] = [
        (
            "both opted in",
            |s| taker(&s.core, "alice").0,
            Ok(MsgOutcome::Requested),
        ),
        (
            "a sender that only listed, which is understanding",
            |s| {
                let (alice, _) = messenger(&s.core, "alice");
                s.core.requests_list(alice).unwrap();
                alice
            },
            Ok(MsgOutcome::Requested),
        ),
        (
            "a sender that never understood",
            |s| messenger(&s.core, "alice").0,
            Err(ChatError::NotFriends),
        ),
        (
            "a classic sender, without the bit",
            |s| classic(&s.core, "plain", AccessBits::empty().with(bit::SEND_MSGS)).0,
            Ok(MsgOutcome::Requested),
        ),
        (
            "an ng sender without the bit",
            |s| {
                attach_as(
                    &s.core,
                    "plain",
                    AccessBits::empty().with(bit::SEND_MSGS),
                    "10.0.0.4",
                )
                .0
            },
            Err(ChatError::NotFriends),
        ),
        (
            "a guest",
            |s| guest_at(&s.core, "10.0.1.1").0,
            Ok(MsgOutcome::Requested),
        ),
        (
            "a guest, to a recipient that turned requests off",
            |s| {
                let (bob, _) = taker(&s.core, "bob");
                s.core
                    .set_presence(
                        bob,
                        PresenceUpdate {
                            takes_requests: Some(false),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                guest_at(&s.core, "10.0.1.1").0
            },
            Err(ChatError::NotFriends),
        ),
        (
            "a recipient that turned requests off",
            |s| {
                let (bob, _) = taker(&s.core, "bob");
                s.core
                    .set_presence(
                        bob,
                        PresenceUpdate {
                            takes_requests: Some(false),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                taker(&s.core, "alice").0
            },
            Err(ChatError::NotFriends),
        ),
        (
            "a recipient that blocked the sender",
            |s| {
                let (bob, _) = taker(&s.core, "bob");
                s.core.inbox_block(bob, "alice", true).unwrap();
                taker(&s.core, "alice").0
            },
            Err(ChatError::NoSuchUser),
        ),
        (
            "a sender that blocked the recipient",
            |s| {
                let (alice, _) = taker(&s.core, "alice");
                s.core.inbox_block(alice, "bob", true).unwrap();
                alice
            },
            Err(ChatError::NotFriends),
        ),
    ];
    for (case, setup, want) in cases {
        let s = server_with(
            policy(),
            &[
                ("alice", messaging_bits()),
                ("bob", messaging_bits()),
                ("plain", without),
            ],
        );
        // Bob takes requests unless a case says otherwise.
        let (bob, _rb) = taker(&s.core, "bob");
        let from = setup(&s);
        assert_eq!(send(&s.core, from, "bob", "hi"), want, "{case}");
        let stored = !waiting(&s.core, bob).is_empty();
        assert_eq!(stored, want.is_ok(), "{case}");
    }

    // A recipient none of whose sessions has opted in takes none, though
    // it lists them.
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = messenger(&s.core, "bob");
    s.core.requests_list(b).unwrap();
    assert_eq!(send(&s.core, a, "bob", "hi"), Err(ChatError::NotFriends));
}

#[test]
fn requests_are_bounded_by_what_was_sent_and_a_retry_is_not_counted() {
    use crate::{ChatError, MsgOutcome};
    let p = MessagingPolicy {
        request_messages: 2,
        requests_per_day: 1,
        ..policy()
    };
    let accounts: Vec<(&str, AccessBits)> = ["alice", "bob", "carol"]
        .iter()
        .map(|l| (*l, messaging_bits()))
        .collect();
    let s = server_with(p, &accounts);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    taker(&s.core, "carol");
    let g = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
    for text in ["one", "two"] {
        let guid = (text == "two").then(|| g.clone());
        assert_eq!(
            s.core.msg_login(a, "bob", text.into(), guid, None),
            Ok(MsgOutcome::Requested)
        );
    }
    assert_eq!(
        s.core.msg_login(a, "bob", "two".into(), Some(g), None),
        Ok(MsgOutcome::Requested),
        "a retry is answered as its original was"
    );
    assert_eq!(
        send(&s.core, a, "bob", "three"),
        Err(ChatError::RequestFull)
    );
    assert_eq!(
        waiting(&s.core, b),
        [("alice".into(), vec!["one".into(), "two".into()])]
    );
    assert_eq!(
        send(&s.core, a, "carol", "hi"),
        Err(ChatError::SendQuota),
        "past the day's recipients"
    );
}

#[test]
fn an_approved_conversation_shows_less_than_a_friendship() {
    use crate::MsgOutcome;
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    // Bob's other session shows no requests, so it is shown none of this.
    let (_b2, mut rb2) = messenger(&s.core, "bob");
    send(&s.core, a, "bob", "may I?").unwrap();
    drain(&mut rb);

    s.core
        .request_answer(b, "alice", RequestAction::Approve)
        .unwrap();
    let to_bob = drain(&mut rb);
    assert_eq!(ims(&to_bob), [("may I?".into(), true)]);
    assert!(matches!(&to_bob[..], [.., Event::Im(im)] if im.approval));
    assert_eq!(changed(&to_bob), [0]);
    assert_eq!(
        s.core.requests_list(b).unwrap().approvals,
        [Mailbox::login("alice")]
    );

    // Every send is answered as queued, both ways.
    assert!(matches!(
        send(&s.core, a, "bob", "thanks"),
        Ok(MsgOutcome::Queued(_))
    ));
    assert_eq!(ims(&drain(&mut rb)), [("thanks".into(), false)]);
    assert!(matches!(
        send(&s.core, b, "alice", "sure"),
        Ok(MsgOutcome::Queued(_))
    ));
    let sure = drain(&mut ra)
        .into_iter()
        .find_map(|e| match e {
            Event::Im(im) => Some(im.guid),
            _ => None,
        })
        .expect("bob's reply");
    assert!(ims(&drain(&mut rb2)).is_empty());

    // A delivery receipt says when someone is around; a read is an act.
    s.core.im_ack(a, "bob", &sure, false).unwrap();
    assert!(receipts(&drain(&mut rb)).is_empty());
    s.core.im_ack(a, "bob", &sure, true).unwrap();
    assert_eq!(receipts(&drain(&mut rb)), [("alice".into(), true)]);
    s.core.im_typing(a, "bob", true).unwrap();
    assert!(drain(&mut rb).is_empty(), "nor typing");

    // Ended, it holds alice, and what she sends is a request again.
    s.core
        .request_answer(b, "alice", RequestAction::End)
        .unwrap();
    assert_eq!(send(&s.core, a, "bob", "hm"), Ok(MsgOutcome::Requested));
    assert!(waiting(&s.core, b).is_empty());
}

#[test]
fn writing_back_approves_and_a_friendship_takes_what_waited() {
    use crate::MsgOutcome;
    let s = server(&["alice", "bob", "carol"]);
    let (a, mut ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    let (c, _rc) = taker(&s.core, "carol");
    send(&s.core, a, "bob", "hi bob").unwrap();
    drain(&mut rb);
    assert!(matches!(
        send(&s.core, b, "alice", "hi alice"),
        Ok(MsgOutcome::Queued(_))
    ));
    assert_eq!(ims(&drain(&mut rb)), [("hi bob".into(), true)]);
    assert_eq!(ims(&drain(&mut ra)), [("hi alice".into(), false)]);

    // A request answered with a friendship is delivered when the sender
    // accepts it.
    send(&s.core, c, "bob", "hello from carol").unwrap();
    s.core.friend_add(b, "carol", None).unwrap();
    drain(&mut rb);
    assert_eq!(
        waiting(&s.core, b),
        [("carol".into(), vec!["hello from carol".into()])]
    );
    s.core.friend_respond(c, "bob", true).unwrap();
    assert_eq!(ims(&drain(&mut rb)), [("hello from carol".into(), true)]);
    assert!(waiting(&s.core, b).is_empty());
}

#[test]
fn clearing_takes_what_came_in_the_span_and_keeps_what_came_before() {
    let s = server(&["alice", "bob", "carol", "dave"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    let (c, _rc) = taker(&s.core, "carol");
    let (d, mut rd) = taker(&s.core, "dave");
    send(&s.core, a, "bob", "before the flood").unwrap();
    s.core.clock.advance(Duration::from_secs(60));
    // A second back, since what is stored is kept to the second.
    let flood = s.core.clock.wall() - Duration::from_secs(1);
    send(&s.core, c, "bob", "flood").unwrap();
    s.core.friend_add(d, "bob", None).unwrap();
    drain(&mut rb);
    drain(&mut rd);

    assert_eq!(
        s.core.requests_clear(b, Some(flood), None),
        Ok(Cleared {
            declined: 1,
            deleted: 1
        })
    );
    let to_bob = drain(&mut rb);
    assert_eq!(changed(&to_bob), [1], "told once");
    assert_eq!(entries(&to_bob), [("dave".into(), RosterState::Removed)]);
    assert_eq!(
        entries(&drain(&mut rd)),
        [("bob".into(), RosterState::Removed)]
    );
    assert_eq!(
        waiting(&s.core, b),
        [("alice".into(), vec!["before the flood".into()])]
    );
    // Each sender is held.
    send(&s.core, c, "bob", "again").unwrap();
    assert_eq!(waiting(&s.core, b).len(), 1);
}

#[test]
fn a_block_deletes_the_requests_it_meets() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    send(&s.core, a, "bob", "hi").unwrap();
    s.core.inbox_block(b, "alice", true).unwrap();
    s.core.inbox_block(b, "alice", false).unwrap();
    assert!(waiting(&s.core, b).is_empty());
}

#[test]
fn a_classic_party_is_sent_an_approval_as_private_messages() {
    // Live to whatever of the party is attached, or at the flush of a
    // session that speaks the friend family but does not understand
    // requests.
    for case in [
        "classic",
        "classic beside family",
        "attached family",
        "later family",
    ] {
        let s = server_with(
            policy(),
            &[
                ("plain", AccessBits::empty().with(bit::SEND_MSGS)),
                ("bob", messaging_bits()),
            ],
        );
        let (p, mut rp) = classic(&s.core, "plain", AccessBits::empty().with(bit::SEND_MSGS));
        let (b, _rb) = taker(&s.core, "bob");
        send(&s.core, p, "bob", "from a period client").unwrap();
        if case != "classic" && case != "classic beside family" {
            s.core.end_session(p);
        }
        let mut family_rx = (case.ends_with("family") && case != "later family")
            .then(|| family(&s.core, "plain").1);
        // Every such session, not the first.
        let mut second_rx = (case == "attached family").then(|| family(&s.core, "plain").1);
        assert!(matches!(
            send(&s.core, b, "plain", "welcome"),
            Ok(crate::MsgOutcome::Queued(_))
        ));
        let mut heard = drain(&mut rp);
        if let Some(rx) = family_rx.as_mut() {
            heard.extend(drain(rx));
        }
        if let Some(rx) = second_rx.as_mut() {
            assert_eq!(msgs(&drain(rx)), ["welcome"], "{case}: the second session");
        }
        if case == "later family" {
            let (f, mut rf) = family(&s.core, "plain");
            s.core.flush_inbox(f);
            heard.extend(drain(&mut rf));
        }
        assert_eq!(msgs(&heard), ["welcome"], "{case}");
    }
}

// --- Blocks, flushes and presence races ----------------------------------

fn attach_identified(core: &Core, login: &str, fp: [u8; 32]) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(AttachInfo {
            account: None,
            nick: login.to_string(),
            icon: 1,
            admin: false,
            access: messaging_bits(),
            login: login.to_string(),
            addr: Some("10.0.0.7".parse().unwrap()),
            can_detach: true,
            transport: crate::Transport::default(),
            has_inbox: true,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_rooms: false,
            set_subject: false,
            is_person: true,
            reads_on_delivery: false,
            identity: Some(fp),
            system: false,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

#[test]
fn a_blocker_reads_as_no_account_whatever_is_sent_by_login() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    s.core.inbox_block(b, "alice", true).unwrap();
    let long = "x".repeat(policy().max_message_bytes + 1);
    for (case, text, media) in [
        ("text", "hi", None),
        ("an image", "hi", Some([0u8; crate::media::HANDLE_LEN])),
        ("too long", long.as_str(), None),
    ] {
        assert_eq!(
            s.core.msg_login(a, "bob", text.into(), None, media),
            Err(crate::ChatError::NoSuchUser),
            "{case}"
        );
    }
}

#[test]
fn a_retry_under_an_approval_is_answered_queued() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    send(&s.core, a, "bob", "may I?").unwrap();
    s.core
        .request_answer(b, "alice", RequestAction::Approve)
        .unwrap();
    drain(&mut rb);
    let g = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000002").unwrap();
    let send_g = || {
        s.core
            .msg_login(a, "bob", "again".into(), Some(g.clone()), None)
    };
    assert!(matches!(send_g(), Ok(crate::MsgOutcome::Queued(_))));
    s.core.im_ack(b, "alice", &g, true).unwrap();
    assert!(
        matches!(send_g(), Ok(crate::MsgOutcome::Queued(_))),
        "a retry of one read is answered as queued too"
    );
}

#[test]
fn a_backlog_the_flush_must_skip_never_starves_private_mail() {
    // Whose session, and what it may not be handed at the login flush.
    for (case, speaks_family, on_approval) in [
        ("a family session's friend messages", true, false),
        ("a plain session's approved messages", false, true),
    ] {
        let s = server(&["alice", "bob"]);
        let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
        let now = s.core.clock.wall();
        let on = if on_approval {
            // Bob's account takes requests, so an approval's traffic
            // waits for a session that understands them.
            let (b, _rb) = taker(&s.core, "bob");
            s.core.end_session(b);
            s.rel.approve(&bob, &alice, now).unwrap()
        } else {
            s.rel.befriend(&alice, &bob, now).unwrap()
        };
        let row = |body: String, n: usize, friendship| NewMessage {
            recipient: bob.clone(),
            sender: Some(alice.clone()),
            sender_nick: "alice".into(),
            body,
            sent_at: now,
            guid: MessageGuid::parse(&format!("{n:032x}")),
            kind: MessageKind::Message,
            media: None,
            signed: None,
            friendship,
            sender_address: None,
        };
        let backlog = InboxPolicy::default().deliver_at_flush + 5;
        for i in 0..backlog {
            s.inbox
                .push(&row(format!("im {i}"), i, Some(SentOn::Relation(on))), 1000)
                .unwrap();
        }
        s.inbox
            .push(&row("private".into(), backlog, None), 1000)
            .unwrap();
        let (b, mut rb) = if speaks_family {
            family(&s.core, "bob")
        } else {
            attach_as(&s.core, "bob", messaging_bits(), "10.0.0.2")
        };
        s.core.flush_inbox(b);
        let evs = drain(&mut rb);
        assert_eq!(msgs(&evs), ["private"], "{case}");
        assert!(
            !evs.iter().any(|e| matches!(e, Event::Notice { .. })),
            "{case}: nothing it may be handed is left"
        );
    }
}

#[test]
fn a_sign_on_racing_the_last_session_out_keeps_its_friends() {
    let s = server(&["alice", "bob"]);
    let (a1, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a1, &mut ra, b, &mut rb);
    // The new session's entry is read while the old one still has it,
    // and joined once the old one's leaving has dropped it.
    let (a2, mut ra2) = s
        .core
        .attach(AttachInfo {
            account: None,
            nick: "alice".into(),
            icon: 1,
            admin: false,
            access: messaging_bits(),
            login: "alice".into(),
            addr: None,
            can_detach: false,
            transport: crate::Transport::default(),
            has_inbox: true,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_rooms: false,
            set_subject: false,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
            system: false,
        })
        .unwrap();
    let mut load = s.core.presence_load(a2).unwrap();
    s.core.end_session(a1);
    s.core.roster.lock().unwrap().presence_join(a2, &mut load);
    s.core.presence_shown(load);
    assert_eq!(
        presences(&drain(&mut rb)),
        [
            ("alice".into(), Presence::Offline),
            ("alice".into(), Presence::Online)
        ]
    );
    s.core.friends_roster(a2).unwrap();
    drain(&mut ra2);
    s.core
        .set_presence(
            b,
            PresenceUpdate {
                state: Some(Presence::Away),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        presences(&drain(&mut ra2)),
        [("bob".into(), Presence::Away)]
    );
}

#[test]
fn signing_on_ends_invisible() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core
        .set_presence(
            a,
            PresenceUpdate {
                state: Some(Presence::Invisible),
                ..Default::default()
            },
        )
        .unwrap();
    drain(&mut rb);
    messenger(&s.core, "alice");
    assert_eq!(
        presences(&drain(&mut rb)),
        [("alice".into(), Presence::Online)]
    );
}

#[test]
fn a_friends_status_text_is_listed_whether_or_not_it_is_there() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core
        .set_presence(
            a,
            PresenceUpdate {
                status_text: Some(Some("at lunch".into())),
                ..Default::default()
            },
        )
        .unwrap();
    s.core.end_session(a);
    let alice = s
        .core
        .friends_roster(b)
        .unwrap()
        .into_iter()
        .find(|e| e.login == "alice")
        .unwrap();
    assert_eq!(
        (alice.presence, alice.status_text.as_deref()),
        (Presence::Offline, Some("at lunch"))
    );
}

#[test]
fn a_friend_requests_note_is_bounded_and_listed_with_it() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = messenger(&s.core, "alice");
    let (b, _rb) = messenger(&s.core, "bob");
    assert_eq!(
        s.core
            .friend_add(a, "bob", Some("x".repeat(policy().max_message_bytes + 1))),
        Err(MessagingError::MessageTooLong)
    );
    s.core.friend_add(a, "bob", Some("hi".into())).unwrap();
    let asking = s
        .core
        .friends_roster(b)
        .unwrap()
        .into_iter()
        .find(|e| e.login == "alice")
        .unwrap();
    assert_eq!(
        (asking.state, asking.note.as_deref()),
        (RosterState::PendingIn, Some("hi"))
    );
}

#[test]
fn a_request_left_alone_lapses_and_frees_its_place() {
    let p = MessagingPolicy {
        max_requests: 1,
        ..policy()
    };
    let accounts: Vec<(&str, AccessBits)> = ["alice", "bob", "carol"]
        .iter()
        .map(|l| (*l, messaging_bits()))
        .collect();
    let s = server_with(p, &accounts);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    let (c, _rc) = taker(&s.core, "carol");
    send(&s.core, a, "bob", "hello?").unwrap();
    s.core.end_session(b);
    s.core
        .clock
        .advance(p.request_retention + Duration::from_secs(1));
    // Bob's opt-in has lapsed, with no session of his opted in: carol is
    // answered as ever, and dropped.
    assert_eq!(
        send(&s.core, c, "bob", "anyone?"),
        Ok(crate::MsgOutcome::Requested)
    );
    // Bob opts in again, so he is not a recipient whose opt-in lapsed.
    let (b, _rb) = taker(&s.core, "bob");
    assert!(waiting(&s.core, b).is_empty(), "lapsed, and dropped");
    send(&s.core, c, "bob", "me?").unwrap();
    assert_eq!(waiting(&s.core, b), [("carol".into(), vec!["me?".into()])]);
}

#[test]
fn a_request_to_a_full_mailbox_is_dropped_and_counted() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    s.core.end_session(b);
    for i in 0..InboxPolicy::default().max_queued {
        s.inbox
            .push(
                &NewMessage {
                    recipient: Mailbox::login("bob"),
                    sender: None,
                    sender_nick: "someone".into(),
                    body: format!("{i}"),
                    sent_at: s.core.clock.wall(),
                    guid: None,
                    kind: MessageKind::Message,
                    media: None,
                    signed: None,
                    friendship: None,
                    sender_address: None,
                },
                usize::MAX,
            )
            .unwrap();
    }
    assert_eq!(
        send(&s.core, a, "bob", "hi"),
        Ok(crate::MsgOutcome::Requested)
    );
    let (b, _rb) = messenger(&s.core, "bob");
    let listed = s.core.requests_list(b).unwrap();
    assert!(listed.requests.is_empty());
    assert_eq!(listed.dropped, 1);
}

#[test]
fn a_claim_rekeys_its_friends_presence() {
    let s = server(&["alice", "bob"]);
    let fp = [9u8; 32];
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    s.core.end_session(a);
    s.core.inbox_claim("alice", &fp);
    let (a, mut ra) = attach_identified(&s.core, "alice", fp);
    s.core.friends_roster(a).unwrap();
    drain(&mut ra);
    s.core
        .set_presence(
            b,
            PresenceUpdate {
                state: Some(Presence::Busy),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(presences(&drain(&mut ra)), [("bob".into(), Presence::Busy)]);
}

#[test]
fn a_rotation_tells_a_friend_with_no_row_naming_the_successor() {
    let (old, new) = ([4u8; 32], [5u8; 32]);
    let dir = Directory(vec![
        (Mailbox::identified("alice", new), messaging_bits()),
        (Mailbox::login("bob"), messaging_bits()),
    ]);
    let s = server_of(dir, policy(), InboxPolicy::default(), None);
    let bob = Mailbox::login("bob");
    let now = s.core.clock.wall();
    // Bob was shown a request from alice's old key, and her new one had
    // blocked him: the rotation folds the two, and the block ends it.
    s.rel
        .set_pending_out(
            &Mailbox::identified("alice", old),
            &bob,
            Some(&PendingOut {
                sent_at: now,
                lapses_at: now + Duration::from_secs(3600),
                delivered: true,
                note: None,
            }),
        )
        .unwrap();
    s.rel
        .set_blocked(&Mailbox::identified("alice", new), &bob, true, now)
        .unwrap();
    let (_b, mut rb) = messenger(&s.core, "bob");
    s.core.rotate_identity(&old, &new).unwrap();
    assert_eq!(
        entries(&drain(&mut rb)),
        [("alice".into(), RosterState::Removed)]
    );
}

#[test]
fn an_approvals_backlog_never_starves_a_friends_im() {
    let s = server(&["alice", "bob", "carol"]);
    let (alice, bob) = (Mailbox::login("alice"), Mailbox::login("bob"));
    let now = s.core.clock.wall();
    // Bob's account takes requests, so an approval's traffic waits for a
    // session that understands them.
    let (b, _rb) = taker(&s.core, "bob");
    s.core.end_session(b);
    let on = s.rel.approve(&bob, &alice, now).unwrap();
    for i in 0..InboxPolicy::default().deliver_at_flush + 5 {
        s.inbox
            .push(
                &NewMessage {
                    recipient: bob.clone(),
                    sender: Some(alice.clone()),
                    sender_nick: "alice".into(),
                    body: format!("approved {i}"),
                    sent_at: now,
                    guid: MessageGuid::parse(&format!("{i:032x}")),
                    kind: MessageKind::Message,
                    media: None,
                    signed: None,
                    friendship: Some(SentOn::Relation(on)),
                    sender_address: None,
                },
                1000,
            )
            .unwrap();
    }
    let (c, mut rc) = messenger(&s.core, "carol");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, c, &mut rc, b, &mut rb);

    s.core.im_send(c, "bob", "live".into(), None, None).unwrap();
    assert_eq!(ims(&drain(&mut rb)), [("live".into(), false)]);
    s.core.friends_roster(b).unwrap();
    assert_eq!(
        ims(&drain(&mut rb)),
        [("live".into(), true)],
        "and again at the roster read"
    );
}

#[test]
fn a_retry_of_a_request_is_answered_as_one_whatever_came_after() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    let g = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000003").unwrap();
    let send_g = || {
        s.core
            .msg_login(a, "bob", "hi".into(), Some(g.clone()), None)
    };
    assert_eq!(send_g(), Ok(crate::MsgOutcome::Requested));
    s.core
        .request_answer(b, "alice", RequestAction::Delete)
        .unwrap();
    friends(&s, b, &mut rb, a, &mut ra);
    assert_eq!(send_g(), Ok(crate::MsgOutcome::Requested));
    assert!(
        ims(&drain(&mut rb)).is_empty(),
        "what was deleted is not sent again"
    );
}

#[test]
fn listing_renews_an_opt_in_and_never_makes_one() {
    let s = server(&["alice", "bob", "carol"]);
    let retention = policy().request_retention;
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    let (c, _rc) = messenger(&s.core, "carol");
    s.core.clock.advance(retention - Duration::from_secs(3600));
    waiting(&s.core, b);
    waiting(&s.core, c);
    s.core.end_session(b);
    s.core.end_session(c);
    s.core.clock.advance(Duration::from_secs(7200));
    send(&s.core, a, "bob", "still taking?").unwrap();
    assert_eq!(
        send(&s.core, a, "carol", "and you?"),
        Err(crate::ChatError::NotFriends),
        "carol never opted in"
    );
    let (b, _rb) = messenger(&s.core, "bob");
    assert_eq!(
        waiting(&s.core, b),
        [("alice".into(), vec!["still taking?".into()])]
    );
}

#[test]
fn an_opt_in_held_by_a_session_still_there_never_lapses() {
    let s = server(&["alice", "bob"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    s.core
        .clock
        .advance(policy().request_retention + Duration::from_secs(1));
    assert_eq!(
        send(&s.core, a, "bob", "still there?"),
        Ok(crate::MsgOutcome::Requested)
    );
    assert_eq!(
        waiting(&s.core, b),
        [("alice".into(), vec!["still there?".into()])]
    );
}

#[test]
fn an_opt_out_switches_the_account_off_and_the_session_still_understands() {
    use crate::MsgOutcome;
    let s = server(&["alice", "bob", "carol", "dave"]);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, mut rb) = taker(&s.core, "bob");
    let (_c, _rc) = taker(&s.core, "carol");
    let (d, mut rd) = taker(&s.core, "dave");
    send(&s.core, d, "bob", "may I?").unwrap();
    s.core
        .request_answer(b, "dave", RequestAction::Approve)
        .unwrap();
    s.core
        .set_presence(
            b,
            PresenceUpdate {
                takes_requests: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    drain(&mut rb);
    assert_eq!(
        send(&s.core, a, "bob", "hi"),
        Err(crate::ChatError::NotFriends),
        "the account takes no new requests"
    );
    assert_eq!(
        send(&s.core, b, "carol", "hello"),
        Ok(MsgOutcome::Requested),
        "but its session still writes to a stranger"
    );
    assert!(matches!(
        send(&s.core, d, "bob", "thanks"),
        Ok(MsgOutcome::Queued(_))
    ));
    assert_eq!(
        ims(&drain(&mut rb)),
        [("thanks".into(), false)],
        "and is still handed what comes under an approval it gave"
    );
    assert!(matches!(
        send(&s.core, b, "dave", "welcome"),
        Ok(MsgOutcome::Queued(_))
    ));
    let welcome = drain(&mut rd)
        .into_iter()
        .find_map(|e| match e {
            Event::Im(im) => Some(im.guid),
            _ => None,
        })
        .expect("bob's message");
    s.core.im_ack(d, "bob", &welcome, true).unwrap();
    assert_eq!(
        receipts(&drain(&mut rb)),
        [("dave".into(), true)],
        "and told when what it sent under it is read"
    );
}

#[test]
fn a_roster_read_within_the_debounce_never_runs_ahead_of_what_is_told() {
    let s = server_with(
        MessagingPolicy {
            presence_debounce: Duration::from_secs(5),
            ..policy()
        },
        &[("alice", messaging_bits()), ("bob", messaging_bits())],
    );
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    let later = Instant::now() + Duration::from_secs(60);
    s.core.end_session(a);
    s.core.presence_flush(later);
    drain(&mut rb);

    // Alice signs on and goes invisible within the debounce.
    let (a, _ra) = messenger(&s.core, "alice");
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::Accepted, Presence::Offline)),
        "not shown before it is told"
    );
    let set = |state| {
        s.core
            .set_presence(
                a,
                PresenceUpdate {
                    state: Some(state),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    set(Presence::Invisible);
    s.core.presence_flush(later);
    assert!(presences(&drain(&mut rb)).is_empty(), "nothing to correct");
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::Accepted, Presence::Offline))
    );

    set(Presence::Online);
    s.core.presence_flush(later + Duration::from_secs(60));
    assert_eq!(
        presences(&drain(&mut rb)),
        [("alice".into(), Presence::Online)]
    );
    assert_eq!(
        state_of(&s.core, b, "alice"),
        Some((RosterState::Accepted, Presence::Online))
    );
}

#[test]
fn a_friends_status_text_is_read_as_it_was_told() {
    let s = server_with(
        MessagingPolicy {
            presence_debounce: Duration::from_secs(5),
            ..policy()
        },
        &[("alice", messaging_bits()), ("bob", messaging_bits())],
    );
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    let mut later = Instant::now() + Duration::from_secs(60);
    let mut flush = || {
        s.core.presence_flush(later);
        later += Duration::from_secs(60);
    };
    let say = |state, text: &str| {
        s.core
            .set_presence(
                a,
                PresenceUpdate {
                    state,
                    status_text: Some(Some(text.into())),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    let read = || {
        s.core
            .friends_roster(b)
            .unwrap()
            .into_iter()
            .find(|e| e.login == "alice")
            .map(|e| (e.presence, e.status_text))
            .unwrap()
    };
    say(None, "here");
    flush();
    assert_eq!(read(), (Presence::Online, Some("here".into())));

    say(None, "lunch");
    assert_eq!(
        read(),
        (Presence::Online, Some("here".into())),
        "not before it is told"
    );
    flush();
    assert_eq!(read(), (Presence::Online, Some("lunch".into())));

    say(Some(Presence::Invisible), "hiding");
    flush();
    say(None, "still hiding");
    flush();
    assert_eq!(
        read(),
        (Presence::Offline, Some("lunch".into())),
        "invisible reads as offline, with what it last showed"
    );
}

fn set(core: &Core, uid: Uid, state: Option<Presence>, text: Option<&str>) {
    core.set_presence(
        uid,
        PresenceUpdate {
            state,
            status_text: text.map(|t| Some(t.into())),
            ..Default::default()
        },
    )
    .unwrap();
}

fn alice_as_read(core: &Core, uid: Uid) -> Shown {
    core.friends_roster(uid)
        .unwrap()
        .into_iter()
        .find(|e| e.login == "alice")
        .map(|e| (e.presence, e.status_text))
        .unwrap()
}

#[test]
fn a_text_set_while_invisible_is_not_read_once_the_last_session_leaves() {
    type Read = fn(&Core, Uid, &mut Events) -> Shown;
    let readers: [(&str, Read); 4] = [
        ("the roster", |core, b, _| alice_as_read(core, b)),
        ("Find User", |core, b, _| {
            core.find_user(b, "alice").unwrap().presence.unwrap()
        }),
        ("Get User Info", |core, b, _| {
            core.messaging_user_info(b, "alice")
                .unwrap()
                .presence
                .unwrap()
        }),
        ("an entry told", |core, b, rb| {
            core.friend_alias(b, "alice", Some("al")).unwrap();
            drain(rb)
                .into_iter()
                .find_map(|e| match e {
                    Event::FriendEntry(e) => Some((e.presence, e.status_text)),
                    _ => None,
                })
                .unwrap()
        }),
    ];
    for (case, read) in readers {
        let s = server(&["alice", "bob"]);
        let (a, mut ra) = messenger(&s.core, "alice");
        let (b, mut rb) = messenger(&s.core, "bob");
        friends(&s, a, &mut ra, b, &mut rb);
        set(&s.core, a, None, Some("here"));
        set(&s.core, a, Some(Presence::Invisible), Some("secret"));
        assert_eq!(
            s.core.find_user(a, "alice").unwrap().presence,
            Some((Presence::Invisible, Some("secret".into()))),
            "{case}: the account reads what it set"
        );
        s.core.end_session(a);
        drain(&mut rb);
        assert_eq!(
            read(&s.core, b, &mut rb),
            (Presence::Offline, Some("here".into())),
            "{case}"
        );
    }
}

#[test]
fn signing_on_shows_the_text_set_while_invisible() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    set(&s.core, a, Some(Presence::Invisible), Some("secret"));
    s.core.end_session(a);
    drain(&mut rb);

    let (a, _ra) = messenger(&s.core, "alice");
    let told: Vec<Shown> = drain(&mut rb)
        .into_iter()
        .filter_map(|e| match e {
            Event::Presence {
                state, status_text, ..
            } => Some((state, status_text)),
            _ => None,
        })
        .collect();
    assert_eq!(told, [(Presence::Online, Some("secret".into()))]);
    s.core.end_session(a);
    assert_eq!(
        alice_as_read(&s.core, b),
        (Presence::Offline, Some("secret".into())),
        "shown once, and read so after"
    );
}

#[test]
fn a_text_never_told_before_going_invisible_is_not_read_after() {
    let s = server_with(
        MessagingPolicy {
            presence_debounce: Duration::from_secs(5),
            ..policy()
        },
        &[("alice", messaging_bits()), ("bob", messaging_bits())],
    );
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    let mut later = Instant::now() + Duration::from_secs(60);
    let mut flush = || {
        s.core.presence_flush(later);
        later += Duration::from_secs(60);
    };
    set(&s.core, a, None, Some("here"));
    flush();
    // Within the debounce, so friends are never told it.
    set(&s.core, a, None, Some("lunch"));
    set(&s.core, a, Some(Presence::Invisible), None);
    flush();
    s.core.end_session(a);
    flush();
    assert_eq!(
        alice_as_read(&s.core, b),
        (Presence::Offline, Some("here".into()))
    );
}

#[test]
fn a_released_request_counts_once_toward_the_daily_quota() {
    use crate::{ChatError, MsgOutcome};
    let dir = Directory(
        ["alice", "bob"]
            .iter()
            .map(|l| (Mailbox::login(*l), messaging_bits()))
            .collect(),
    );
    let quota = InboxPolicy {
        max_sent_per_day: 2,
        ..InboxPolicy::default()
    };
    let s = server_of(dir, policy(), quota, None);
    let (a, _ra) = taker(&s.core, "alice");
    let (b, _rb) = taker(&s.core, "bob");
    assert_eq!(send(&s.core, a, "bob", "may I?"), Ok(MsgOutcome::Requested));
    s.core
        .request_answer(b, "alice", RequestAction::Approve)
        .unwrap();
    assert!(matches!(
        send(&s.core, a, "bob", "thanks"),
        Ok(MsgOutcome::Queued(_))
    ));
    assert_eq!(
        send(&s.core, a, "bob", "and another"),
        Err(ChatError::SendQuota)
    );
}

// --- A guest's requests (§4.1) ------------------------------------------

/// A classic guest session from `addr`.
fn guest_at(core: &Core, addr: &str) -> (Uid, Events) {
    guest_as(core, addr, None)
}

/// [`guest_at`], proving `identity` where given.
fn guest_as(core: &Core, addr: &str, identity: Option<[u8; 32]>) -> (Uid, Events) {
    let (uid, mut rx) = core
        .attach(AttachInfo {
            account: None,
            nick: "visitor".into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty().with(bit::SEND_MSGS),
            login: "guest".into(),
            addr: Some(addr.parse().unwrap()),
            can_detach: false,
            transport: crate::Transport::default(),
            has_inbox: false,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_rooms: false,
            set_subject: false,
            is_person: false,
            reads_on_delivery: true,
            identity,
            system: false,
        })
        .unwrap();
    core.announce(uid);
    drain(&mut rx);
    (uid, rx)
}

fn guests(texts: &[&str]) -> Vec<(String, Vec<String>)> {
    vec![(
        "guest".into(),
        texts.iter().map(|t| t.to_string()).collect(),
    )]
}

#[test]
fn a_guests_message_by_login_is_a_request_bounded_by_its_address() {
    use crate::{ChatError, MsgOutcome};
    let p = MessagingPolicy {
        request_messages: 2,
        ..policy()
    };
    let s = server_with(p, &[("bob", messaging_bits())]);
    let (b, mut rb) = taker(&s.core, "bob");
    let (one, _r1) = guest_at(&s.core, "10.0.1.1");
    let (two, _r2) = guest_at(&s.core, "10.0.1.1");
    let (elsewhere, _r3) = guest_at(&s.core, "10.0.1.2");
    assert_eq!(send(&s.core, one, "bob", "one"), Ok(MsgOutcome::Requested));
    assert_eq!(send(&s.core, two, "bob", "two"), Ok(MsgOutcome::Requested));
    assert_eq!(
        send(&s.core, two, "bob", "three"),
        Err(ChatError::RequestFull),
        "two guests from one address share its count"
    );
    assert_eq!(
        send(&s.core, elsewhere, "bob", "other"),
        Ok(MsgOutcome::Requested)
    );
    assert!(msgs(&drain(&mut rb)).is_empty(), "nothing went live");
    assert_eq!(waiting(&s.core, b), guests(&["one", "two", "other"]));
}

#[test]
fn a_guest_that_reconnects_earns_no_new_requests_and_stays_held() {
    use crate::{ChatError, MsgOutcome};
    let p = MessagingPolicy {
        request_messages: 3,
        ..policy()
    };
    let s = server_with(p, &[("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    let again = |text: &str| {
        let (g, _rx) = guest_at(&s.core, "10.0.1.1");
        let sent = send(&s.core, g, "bob", text);
        s.core.end_session(g);
        sent
    };
    assert_eq!(again("one"), Ok(MsgOutcome::Requested));
    assert_eq!(again("two"), Ok(MsgOutcome::Requested));
    s.core
        .request_answer(b, "guest", RequestAction::Delete)
        .unwrap();
    assert_eq!(again("three"), Ok(MsgOutcome::Requested));
    assert!(waiting(&s.core, b).is_empty(), "held");
    assert_eq!(again("four"), Err(ChatError::RequestFull), "and counted");
}

#[test]
fn an_approval_of_guest_lets_in_the_session_that_asked_and_no_other_guest() {
    use crate::{ChatError, MsgOutcome};
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, mut rb) = taker(&s.core, "bob");
    let (asked, _ra) = guest_at(&s.core, "10.0.1.1");
    let (other, _ro) = guest_at(&s.core, "10.0.1.2");
    let (gone, _rg) = guest_at(&s.core, "10.0.1.3");
    assert_eq!(
        send(&s.core, gone, "bob", "gone"),
        Ok(MsgOutcome::Requested)
    );
    s.core.end_session(gone);
    assert_eq!(send(&s.core, asked, "bob", "hi"), Ok(MsgOutcome::Requested));
    drain(&mut rb);
    s.core
        .request_answer(b, "guest", RequestAction::Approve)
        .unwrap();
    assert_eq!(
        msgs(&drain(&mut rb)),
        ["hi"],
        "what waited is handed over at once, as mail"
    );
    assert_eq!(
        waiting(&s.core, b),
        guests(&["gone"]),
        "a guest that left is let in by nobody"
    );
    assert_eq!(
        s.core.requests_list(b).unwrap().approvals,
        [Mailbox::login("guest")]
    );
    assert_eq!(
        send(&s.core, asked, "bob", "thanks"),
        Ok(MsgOutcome::Delivered)
    );
    assert_eq!(msgs(&drain(&mut rb)), ["thanks"]);
    assert_eq!(
        send(&s.core, other, "bob", "me too"),
        Ok(MsgOutcome::Requested),
        "another guest is not let in"
    );
    s.core.end_session(b);
    assert_eq!(
        send(&s.core, asked, "bob", "anyone?"),
        Err(ChatError::NoSuchUser),
        "an approved guest reaches a session that is there or nobody"
    );
}

#[test]
fn writing_back_by_uid_approves_the_guest_that_asked() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, mut rb) = taker(&s.core, "bob");
    let (g, mut rg) = guest_at(&s.core, "10.0.1.1");
    let (other, _ro) = guest_at(&s.core, "10.0.1.2");
    assert_eq!(send(&s.core, g, "bob", "hi"), Ok(MsgOutcome::Requested));
    assert_eq!(
        send(&s.core, other, "bob", "other"),
        Ok(MsgOutcome::Requested)
    );
    drain(&mut rb);
    s.core.msg(b, g, "hello".into(), None, None).unwrap();
    assert_eq!(msgs(&drain(&mut rg)), ["hello"]);
    assert_eq!(
        msgs(&drain(&mut rb)),
        ["hi"],
        "what it asked is handed over, and no other address's"
    );
    assert_eq!(waiting(&s.core, b), guests(&["other"]));
    assert_eq!(send(&s.core, g, "bob", "thanks"), Ok(MsgOutcome::Delivered));
    assert_eq!(msgs(&drain(&mut rb)), ["thanks"]);
}

#[test]
fn writing_back_lets_in_no_guest_whose_address_is_held() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    let (g, _rg) = guest_at(&s.core, "10.0.1.1");
    assert_eq!(send(&s.core, g, "bob", "hi"), Ok(MsgOutcome::Requested));
    s.core
        .request_answer(b, "guest", RequestAction::Delete)
        .unwrap();
    s.core.msg(b, g, "go away".into(), None, None).unwrap();
    assert_eq!(send(&s.core, g, "bob", "again"), Ok(MsgOutcome::Requested));
    assert!(waiting(&s.core, b).is_empty(), "still held");
}

#[test]
fn naming_guest_in_any_case_never_writes_an_approval() {
    use crate::MsgOutcome;
    type Act = fn(&Core, Uid, &str);
    let acts: [(&str, Act); 2] = [
        ("a send to it", |core, b, guest| {
            let _ = send(core, b, guest, "who is this?");
        }),
        ("an approval of it", |core, b, guest| {
            core.request_answer(b, guest, RequestAction::Approve)
                .unwrap();
        }),
    ];
    for (what, act) in acts {
        for guest in ["guest", "Guest", "GUEST"] {
            let s = server_with(
                policy(),
                &[("bob", messaging_bits()), ("guest", messaging_bits())],
            );
            let (b, _rb) = taker(&s.core, "bob");
            let (g, _rg) = guest_at(&s.core, "10.0.1.1");
            assert_eq!(send(&s.core, g, "bob", "hi"), Ok(MsgOutcome::Requested));
            act(&s.core, b, guest);
            let row = s
                .rel
                .relationship(
                    &Mailbox::login("bob"),
                    &Mailbox::login("guest"),
                    s.core.clock.wall(),
                )
                .unwrap();
            assert!(
                row.is_none_or(|r| r.approval.is_none()),
                "{what}, as {guest}"
            );
        }
    }
}

#[test]
fn what_an_approval_hands_over_from_a_guest_names_no_session() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, mut rb) = taker(&s.core, "bob");
    let (other, _ro) = guest_at(&s.core, "10.0.1.2");
    let (asked, _ra) = guest_at(&s.core, "10.0.1.1");
    assert!(other < asked);
    assert_eq!(send(&s.core, asked, "bob", "hi"), Ok(MsgOutcome::Requested));
    drain(&mut rb);
    s.core
        .request_answer(b, "guest", RequestAction::Approve)
        .unwrap();
    let from: Vec<Uid> = drain(&mut rb)
        .iter()
        .filter_map(|e| match e {
            Event::Msg { from, .. } => Some(*from),
            _ => None,
        })
        .collect();
    assert_eq!(from, [0], "the guests' shared mailbox is nobody's uid");
}

#[test]
fn clearing_a_span_takes_and_holds_the_guests_that_asked_within_it() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    let mut at = Vec::new();
    let mut sessions = Vec::new();
    for (addr, text) in [("10.0.1.1", "a"), ("10.0.1.2", "b"), ("10.0.1.3", "c")] {
        at.push(s.core.clock.wall());
        let (g, rx) = guest_at(&s.core, addr);
        assert_eq!(send(&s.core, g, "bob", text), Ok(MsgOutcome::Requested));
        sessions.push((g, rx));
        s.core.clock.advance(Duration::from_secs(60));
    }
    let cleared = s.core.requests_clear(b, Some(at[1]), Some(at[2])).unwrap();
    assert_eq!(cleared.deleted, 1);
    assert_eq!(
        waiting(&s.core, b),
        guests(&["a", "c"]),
        "the guests before and after the span keep theirs"
    );
    for ((g, _), text) in sessions.iter().zip(["a again", "b again", "c again"]) {
        assert_eq!(send(&s.core, *g, "bob", text), Ok(MsgOutcome::Requested));
    }
    assert_eq!(
        waiting(&s.core, b),
        guests(&["a", "c", "a again", "c again"]),
        "only the address that asked within the span is held"
    );
}

#[test]
fn an_identity_guests_message_by_login_goes_as_mail() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    let (g, _rg) = guest_as(&s.core, "10.0.1.1", Some([7; 32]));
    s.core.end_session(b);
    assert!(matches!(
        send(&s.core, g, "bob", "hi"),
        Ok(MsgOutcome::Queued(_))
    ));
    let (b, _rb) = taker(&s.core, "bob");
    assert!(waiting(&s.core, b).is_empty(), "no request");
}

#[test]
fn deleting_guest_holds_each_address_that_asked_and_ending_holds_who_it_let_in() {
    use crate::MsgOutcome;
    let s = server_with(policy(), &[("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    for addr in ["10.0.1.1", "10.0.1.2"] {
        let (g, _rx) = guest_at(&s.core, addr);
        assert_eq!(send(&s.core, g, "bob", addr), Ok(MsgOutcome::Requested));
    }
    s.core
        .request_answer(b, "guest", RequestAction::Delete)
        .unwrap();
    for addr in ["10.0.1.1", "10.0.1.2"] {
        let (g, _rx) = guest_at(&s.core, addr);
        assert_eq!(send(&s.core, g, "bob", "again"), Ok(MsgOutcome::Requested));
    }
    assert!(waiting(&s.core, b).is_empty(), "both held");

    let (g, _rx) = guest_at(&s.core, "10.0.1.3");
    assert_eq!(send(&s.core, g, "bob", "new"), Ok(MsgOutcome::Requested));
    s.core
        .request_answer(b, "guest", RequestAction::Approve)
        .unwrap();
    s.core
        .request_answer(b, "guest", RequestAction::End)
        .unwrap();
    assert_eq!(send(&s.core, g, "bob", "still?"), Ok(MsgOutcome::Requested));
    assert!(waiting(&s.core, b).is_empty(), "let out and held");
    assert_eq!(
        s.core.request_answer(b, "guest", RequestAction::End),
        Err(MessagingError::NoSuchRequest)
    );
}

#[test]
fn the_guests_hold_two_senders_worth_and_count_as_one() {
    use crate::MsgOutcome;
    let p = MessagingPolicy {
        request_messages: 1,
        max_requests: 2,
        ..policy()
    };
    let s = server_with(p, &[("alice", messaging_bits()), ("bob", messaging_bits())]);
    let (b, _rb) = taker(&s.core, "bob");
    for n in 1..=3 {
        let (g, _rx) = guest_at(&s.core, &format!("10.0.1.{n}"));
        let text = n.to_string();
        assert_eq!(send(&s.core, g, "bob", &text), Ok(MsgOutcome::Requested));
    }
    let (a, _ra) = taker(&s.core, "alice");
    assert_eq!(send(&s.core, a, "bob", "a"), Ok(MsgOutcome::Requested));
    assert_eq!(s.core.requests_list(b).unwrap().dropped, 1);
    assert_eq!(
        waiting(&s.core, b),
        [
            ("guest".into(), vec!["1".into(), "2".into()]),
            ("alice".into(), vec!["a".into()]),
        ]
    );
}

#[test]
fn a_session_gone_before_its_join_shows_nothing_set_while_invisible() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    set(&s.core, a, None, Some("here"));
    set(&s.core, a, Some(Presence::Invisible), Some("secret"));
    s.core.end_session(a);
    // Loaded for an announce that finds the session gone.
    let (a, _ra) = unannounced(
        &s.core,
        "alice",
        messaging_bits(),
        "10.0.0.1",
        crate::Transport::default(),
        false,
    );
    let load = s.core.presence_load(a);
    s.core.end_session(a);
    drop(load);
    assert_eq!(
        alice_as_read(&s.core, b),
        (Presence::Offline, Some("here".into()))
    );
}

#[test]
fn coming_back_from_invisible_shows_the_text_set_there() {
    let s = server(&["alice", "bob"]);
    let (a, mut ra) = messenger(&s.core, "alice");
    let (b, mut rb) = messenger(&s.core, "bob");
    friends(&s, a, &mut ra, b, &mut rb);
    set(&s.core, a, None, Some("here"));
    set(&s.core, a, Some(Presence::Invisible), Some("secret"));
    set(&s.core, a, Some(Presence::Online), None);
    s.core.end_session(a);
    assert_eq!(
        alice_as_read(&s.core, b),
        (Presence::Offline, Some("secret".into()))
    );
}

#[test]
fn a_request_address_key_is_not_the_news_key_of_the_same_address_and_secret() {
    let core = Core::new()
        .with_request_keyer(crate::relationships::RequestKeyer::new([9; 32]))
        .with_news_guest_keyer(crate::news::GuestKeyer::new([9; 32]));
    let (ann, _rx) = attach_as(&core, "ann", messaging_bits(), "10.0.0.1");
    let news = core.news_guest_keyer.key("10.0.0.1".parse().unwrap());
    let request = core.request_address(ann).expect("not exempt");
    assert_ne!(request, news.to_hex());
}
