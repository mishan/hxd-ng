mod chats;
mod link;
mod voice;

use crate::access::{bit, AccessBits};
use crate::account::{Account, AccountConfig, IdentityLink};
use crate::roster::{drain, AttachInfo, Core, Event, Events, SessionStatus, Transport, Uid};

pub(crate) const ALICE: [u8; 32] = [7; 32];

/// A session of `login`, its account linking `linked`, proved as `identity`.
fn attach(
    core: &Core,
    login: &str,
    identity: Option<[u8; 32]>,
    linked: Option<[u8; 32]>,
) -> (Uid, Events) {
    attach_on(core, login, identity, linked, Transport::default())
}

fn attach_on(
    core: &Core,
    login: &str,
    identity: Option<[u8; 32]>,
    linked: Option<[u8; 32]>,
    transport: Transport,
) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(session(login, identity, linked, transport))
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

/// One of alice's devices, as `f` makes it, announced or not.
pub(crate) fn alice(core: &Core, announce: bool, f: impl FnOnce(&mut AttachInfo)) -> (Uid, Events) {
    let mut info = session("alice", Some(ALICE), Some(ALICE), Transport::default());
    f(&mut info);
    let (uid, rx) = core.attach(info).unwrap();
    if announce {
        core.announce(uid);
    }
    (uid, rx)
}

pub(crate) fn at(addr: &str) -> impl FnOnce(&mut AttachInfo) + '_ {
    move |i| i.addr = Some(addr.parse().unwrap())
}

fn moderated() -> Core {
    Core::new()
        .with_moderation(
            std::sync::Arc::new(crate::moderation::MemoryModeration::default()),
            crate::moderation::ModerationPolicy::default(),
        )
        .with_coalesce(true)
}

pub(crate) fn session(
    login: &str,
    identity: Option<[u8; 32]>,
    linked: Option<[u8; 32]>,
    transport: Transport,
) -> AttachInfo {
    let link = IdentityLink {
        fingerprint: linked,
        ..IdentityLink::default()
    };
    let account = Account::new(
        login.into(),
        login.into(),
        true,
        link,
        AccountConfig {
            access: chatting(),
            ..AccountConfig::default()
        },
    );
    AttachInfo {
        account: Some(Box::new(account)),
        nick: login.to_string(),
        icon: 1,
        admin: false,
        access: AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT),
        login: login.to_string(),
        addr: None,
        can_detach: true,
        transport,
        has_inbox: false,
        attach_news: false,
        set_avatar: false,
        moderate: false,
        can_spam: false,
        manage_rooms: false,
        set_subject: false,
        is_person: true,
        reads_on_delivery: false,
        identity,
        system: false,
    }
}

fn rows(core: &Core) -> Vec<(Uid, String, SessionStatus)> {
    core.snapshot()
        .into_iter()
        .map(|u| (u.uid, u.nick, u.status))
        .collect()
}

/// The joins, changes and parts `rx` has been told, as (kind, uid).
fn told(rx: &mut Events) -> Vec<(&'static str, Uid)> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::Joined(u) => Some(("joined", u.uid)),
            Event::Changed(u) => Some(("changed", u.uid)),
            Event::Parted(uid) => Some(("parted", uid)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_persons_sessions_are_one_row_that_joins_with_the_first_and_parts_with_the_last() {
    let core = Core::new().with_coalesce(true);
    let (bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert_eq!(told(&mut watching), [("joined", a1)]);
    let alice = (a1, "alice".to_string(), SessionStatus::Active);
    assert_eq!(
        rows(&core),
        [(bob, "bob".into(), SessionStatus::Active), alice.clone()]
    );

    // The first ends: the row is still alice's, under her first uid.
    core.end_session(a1);
    core.end_session(a3);
    assert_eq!(told(&mut watching), []);
    assert_eq!(rows(&core)[1], alice);
    core.end_session(a2);
    assert_eq!(told(&mut watching), [("parted", a1)]);
    assert_eq!(rows(&core).len(), 1);
}

#[test]
fn the_census_counts_a_persons_devices_as_sessions_and_as_one_row() {
    let core = Core::new().with_coalesce(true);
    let (_bob, _rb) = attach(&core, "bob", None, None);
    let (a1, _r1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (_a2, _r2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let c = core.census();
    assert_eq!((c.attached, c.rows), (3, 2));
    // The row holds while a device is on, whichever.
    core.end_session(a1);
    let c = core.census();
    assert_eq!((c.attached, c.rows), (2, 2));
}

#[test]
fn a_person_is_as_present_as_its_most_present_session() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let status = |uid, s| core.roster.lock().unwrap().set_status(uid, s);
    status(a2, SessionStatus::Detached);
    assert_eq!(told(&mut watching), [], "the phone away, the desktop not");
    status(a1, SessionStatus::Detached);
    assert_eq!(told(&mut watching), [("changed", a1)]);
    assert_eq!(rows(&core)[1].2, SessionStatus::Detached);
    status(a2, SessionStatus::Active);
    assert_eq!(told(&mut watching), [("changed", a1)]);
    assert_eq!(rows(&core)[1].2, SessionStatus::Active);
}

#[test]
fn only_a_persons_own_account_logged_in_as_its_linked_identity_is_grouped() {
    let other = [8; 32];
    for (what, on, identity, linked) in [
        ("coalescing off", false, Some(ALICE), Some(ALICE)),
        ("no identity", true, None, Some(ALICE)),
        (
            "an identity the account does not link",
            true,
            Some(ALICE),
            None,
        ),
        (
            "another identity than the linked one",
            true,
            Some(other),
            Some(ALICE),
        ),
    ] {
        let core = Core::new().with_coalesce(on);
        attach(&core, "alice", identity, linked);
        attach(&core, "alice", identity, linked);
        assert_eq!(rows(&core).len(), 2, "{what}");
    }
}

/// A session of `login` whose account file says `personal`, with a
/// password or not, linking `linked` and proved as `identity`.
fn personal(
    core: &Core,
    login: &str,
    personal: Option<bool>,
    password: bool,
    identity: Option<[u8; 32]>,
    linked: Option<[u8; 32]>,
) -> Uid {
    let mut info = session(login, identity, linked, Transport::default());
    let account = info.account.as_mut().unwrap();
    account.config.personal = personal == Some(true);
    account.has_password = password;
    info.is_person = account.is_person();
    let (uid, _rx) = core.attach(info).unwrap();
    core.announce(uid);
    uid
}

#[test]
fn a_personal_accounts_sessions_are_one_row_without_an_identity_to_say_so() {
    let other = [8; 32];
    for (what, on, says, password, identity, linked, rows_) in [
        (
            "its password sessions",
            true,
            Some(true),
            true,
            None,
            None,
            1,
        ),
        ("not said", true, None, true, None, None, 2),
        ("said false", true, Some(false), true, None, None, 2),
        ("coalescing off", false, Some(true), true, None, None, 2),
        // No password and no identity: a login anyone may walk
        // through, whatever its file says.
        (
            "an account that is no one",
            true,
            Some(true),
            false,
            None,
            None,
            2,
        ),
        (
            "an identity it links and a password",
            true,
            Some(true),
            true,
            Some(ALICE),
            Some(ALICE),
            1,
        ),
        // A key it does not link is somebody's, not the account's.
        (
            "a key it does not link",
            true,
            Some(true),
            true,
            Some(other),
            None,
            2,
        ),
    ] {
        let core = Core::new().with_coalesce(on);
        // A password session of a linked account carries its identity.
        personal(&core, "carol", says, password, linked, linked);
        personal(&core, "carol", says, password, identity, linked);
        assert_eq!(rows(&core).len(), rows_, "{what}");
    }
}

#[test]
fn a_key_a_personal_account_does_not_link_stays_apart_however_often_proved() {
    let core = Core::new().with_coalesce(true);
    let other = Some([8; 32]);
    personal(&core, "carol", Some(true), true, other, None);
    personal(&core, "carol", Some(true), true, other, None);
    assert_eq!(rows(&core).len(), 2);
}

#[test]
fn a_personal_account_linked_while_its_row_is_on_keeps_one_row() {
    let core = Core::new().with_coalesce(true);
    personal(&core, "carol", Some(true), true, None, None);
    personal(&core, "carol", Some(true), true, None, None);
    // Linked meanwhile: its password sessions carry the link (§12 J).
    personal(&core, "carol", Some(true), true, Some(ALICE), Some(ALICE));
    assert_eq!(rows(&core).len(), 1);
}

#[test]
fn a_personal_row_holds_one_identity_whichever_device_carries_it() {
    let core = Core::new().with_coalesce(true);
    let relinked = Some([9; 32]);
    personal(&core, "carol", Some(true), true, None, None);
    personal(&core, "carol", Some(true), true, Some(ALICE), Some(ALICE));
    // Its link changed while the row is on: another person's key.
    personal(&core, "carol", Some(true), true, relinked, relinked);
    assert_eq!(rows(&core).len(), 2);
}

#[test]
fn a_device_joining_a_masked_personal_account_is_masked() {
    let core = Core::new().with_coalesce(true);
    let a1 = personal(&core, "carol", Some(true), true, None, None);
    assert!(core.set_session_mask(a1, muted()));
    let a2 = personal(&core, "carol", Some(true), true, None, None);
    assert_eq!(core.mask_of(a2), muted());
}

#[test]
fn a_uid_names_the_person_by_its_row_and_nobody_by_a_grouped_sessions_own() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert_eq!(core.user_details(a1).map(|d| d.info.uid), Some(a1));
    assert!(core.user_details(a2).is_none());
    core.end_session(a1);
    assert_eq!(
        core.user_details(a1).map(|d| d.info.uid),
        Some(a1),
        "the row outlives its first session"
    );
}

#[test]
fn a_row_is_given_to_nobody_else_while_its_person_lives() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (_a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    core.end_session(a1);
    core.roster.lock().unwrap().last_uid = a1 - 1;
    let (next, _rx) = attach(&core, "bob", None, None);
    assert_ne!(next, a1);
}

#[test]
fn a_line_from_any_of_a_persons_sessions_is_the_rows() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    core.chat_public(a2, "from the phone".into(), 0, None)
        .unwrap();
    let from: Vec<Uid> = drain(&mut watching)
        .into_iter()
        .filter_map(|e| match e {
            Event::Chat { from, .. } => Some(from.uid),
            _ => None,
        })
        .collect();
    assert_eq!(from, [a1]);
}

#[test]
fn a_device_ending_leaves_its_person_in_its_chats() {
    let core = Core::new().with_coalesce(true);
    let (bob, _rxb) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (cid, _) = core.chat_create(a1, bob).unwrap();
    core.chat_join(cid, a2, "").unwrap();
    core.end_session(a1);
    assert_eq!(core.chats_of(a2), [cid]);
}

#[test]
fn a_message_to_a_persons_row_reaches_each_of_its_sessions_from_the_row() {
    let core = Core::new().with_coalesce(true);
    let (bob, mut to_bob) = attach(&core, "bob", None, None);
    let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let msgs = |rx: &mut Events| -> Vec<Uid> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Msg { from, .. } => Some(from),
                _ => None,
            })
            .collect()
    };
    core.msg(bob, a1, "hi alice".into(), None, None).unwrap();
    assert_eq!((msgs(&mut rx1), msgs(&mut rx2)), (vec![bob], vec![bob]));
    core.msg(a2, bob, "hi bob".into(), None, None).unwrap();
    assert_eq!(
        msgs(&mut to_bob),
        [a1],
        "from the row, so a reply reaches her"
    );
    assert!(
        core.msg(bob, a2, "x".into(), None, None).is_err(),
        "a device's own uid names nobody"
    );
}

#[test]
fn a_session_is_told_its_row_and_finds_itself_by_its_own_uid() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert_eq!(core.user(a2).map(|u| u.uid), Some(a1));
    assert_eq!(core.own_details(a2).map(|d| d.login), Some("alice".into()));
    assert!(core.user_details(a2).is_none());
}

#[test]
fn a_message_from_a_device_to_its_own_row_is_from_nobody() {
    let core = Core::new().with_coalesce(true);
    let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut rx1);
    core.msg(a2, a1, "note to self".into(), None, None).unwrap();
    let from: Vec<Uid> = drain(&mut rx1)
        .into_iter()
        .filter_map(|e| match e {
            Event::Msg { from, .. } => Some(from),
            _ => None,
        })
        .collect();
    assert_eq!(from, [0]);
}

#[test]
fn a_session_under_another_identity_of_the_login_stands_apart() {
    let core = Core::new().with_coalesce(true);
    let relinked = [9; 32];
    attach(&core, "alice", Some(ALICE), Some(ALICE));
    attach(&core, "alice", Some(relinked), Some(relinked));
    assert_eq!(rows(&core).len(), 2);
}

#[test]
fn a_nick_a_device_sends_again_is_no_rename_and_a_new_one_renames_the_person() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let nick = |uid| core.user(uid).map(|u| u.nick);
    assert!(
        !core.update(a2, Some("alice".into()), None),
        "its login nick again"
    );
    assert!(core.update(a2, Some("Ally".into()), None));
    assert_eq!(told(&mut watching), [("changed", a1)]);
    assert_eq!(
        (nick(a1), nick(a2)),
        (Some("Ally".into()), Some("Ally".into()))
    );
    assert!(
        !core.update(a1, Some("alice".into()), None),
        "what a1 itself last sent"
    );
    assert_eq!(rows(&core)[1].1, "Ally");
    assert!(
        core.update(a1, Some("alice".into()), Some(2)),
        "its icon is new"
    );
    assert_eq!(rows(&core)[1].1, "Ally", "but its nick still is not");

    let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert_eq!(
        nick(a3),
        Some("Ally".into()),
        "a new device takes the person's"
    );
    assert_eq!(told(&mut watching), [("changed", a1)], "the icon only");
}

#[test]
fn a_device_going_away_alone_is_told_its_own_status_and_nobody_else_anything() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    drain(&mut rx2);
    core.roster
        .lock()
        .unwrap()
        .set_status(a2, SessionStatus::Idle);
    assert_eq!(told(&mut watching), []);
    assert!(drain(&mut rx2)
        .iter()
        .any(|e| matches!(e, Event::Changed(u) if u.uid == a1 && u.status == SessionStatus::Idle)));
}

#[test]
fn a_kick_ends_every_device_and_tells_the_roster_once() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let tls = Transport {
        encrypted: true,
        ..Transport::default()
    };
    let (a2, mut rx2) = attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
    drain(&mut watching);
    core.kick(a1, None).unwrap();
    assert!(drain(&mut rx1).contains(&Event::Kicked));
    assert!(drain(&mut rx2).contains(&Event::Kicked));
    // Its devices go as their connections close: the safer one left
    // alone for a moment is no change worth telling.
    core.end_session(a1);
    core.end_session(a2);
    assert_eq!(told(&mut watching), [("parted", a1)]);
}

#[test]
fn a_login_while_its_person_is_kicked_is_a_person_of_its_own() {
    let core = Core::new().with_coalesce(true);
    let (bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let begun = core.kick_begin(a1, false).unwrap();
    let (a3, mut rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    core.kick_end(begun, None);
    assert!(!drain(&mut rx3).contains(&Event::Kicked));
    core.end_session(a1);
    core.end_session(a2);
    assert_eq!(told(&mut watching), [("joined", a3), ("parted", a1)]);
    let listed: Vec<Uid> = rows(&core).into_iter().map(|r| r.0).collect();
    assert_eq!(listed, [bob, a3]);
}

fn chatting() -> AccessBits {
    AccessBits::empty()
        .with(bit::READ_CHAT)
        .with(bit::SEND_CHAT)
}

/// The mask the tests set: no sending to public chat, and no
/// disconnecting users, which the row shows as its admin flag.
fn muted() -> crate::DenyMask {
    crate::DenyMask {
        access: AccessBits::empty()
            .with(bit::SEND_CHAT)
            .with(bit::DISCONNECT_USERS),
        ..Default::default()
    }
}

/// One of alice's devices whose account may disconnect users.
fn admin(i: &mut AttachInfo) {
    let access = chatting().with(bit::DISCONNECT_USERS);
    let link = IdentityLink {
        fingerprint: Some(ALICE),
        ..IdentityLink::default()
    };
    let config = AccountConfig {
        access,
        ..AccountConfig::default()
    };
    let account = Account::new("alice".into(), "alice".into(), true, link, config);
    i.account = Some(Box::new(account));
    i.access = access;
    i.admin = true;
}

/// The admin flag of the rows `rx` was told changed, in order.
fn admins(rx: &mut Events) -> Vec<bool> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::Changed(u) => Some(u.admin),
            _ => None,
        })
        .collect()
}

fn sends(core: &Core, uid: Uid) -> bool {
    core.access_of(uid).is_some_and(|a| a.has(bit::SEND_CHAT))
}

fn told_account(rx: &mut Events) -> Option<bool> {
    drain(rx).into_iter().rev().find_map(|e| match e {
        Event::AccountChanged(a) => Some(a.access.has(bit::SEND_CHAT)),
        _ => None,
    })
}

#[test]
fn a_masked_session_still_joins_its_person() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = alice(&core, true, |_| {});
    let (a2, _rx2) = alice(&core, false, |_| {});
    assert!(core.set_session_mask(a2, muted()));
    core.announce(a2);
    assert_eq!(core.row_uid(a2), a1);
    // A mask is the person's, so the person's replaces its own.
    assert_eq!(core.mask_of(a2), crate::DenyMask::default());
}

#[test]
fn a_device_joining_a_masked_person_is_told_its_row_as_masked() {
    let core = Core::new().with_coalesce(true);
    let tls = |i: &mut AttachInfo| {
        admin(i);
        i.transport.encrypted = true;
    };
    let (a1, _rx1) = alice(&core, true, tls);
    assert!(core.set_session_mask(a1, muted()));
    // A plain device makes the row less safe: it is told the row.
    let (_a2, mut rx2) = alice(&core, true, admin);
    assert_eq!(admins(&mut rx2), [false]);
}

/// An account backend whose roles, once armed, wait for a release.
#[derive(Default)]
struct GatedRoles {
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicBool,
    held: std::sync::Mutex<bool>,
    release: std::sync::Condvar,
}

impl crate::account::AccountAdmin for GatedRoles {
    fn read_account(&self, _: &str) -> Result<Account, crate::AdminError> {
        Err(crate::AdminError::NoSuchAccount)
    }
    fn list_accounts(&self) -> Result<Vec<Account>, crate::AdminError> {
        Ok(Vec::new())
    }
    fn write_account(
        &self,
        _: &crate::AccountEdit,
        _: crate::account::WriteCheck<'_>,
    ) -> Result<Account, crate::AdminError> {
        Err(crate::AdminError::NotAllowed)
    }
    fn delete_account(
        &self,
        _: &str,
        _: &dyn Fn(&Account) -> Result<(), crate::AdminError>,
    ) -> Result<(), crate::AdminError> {
        Err(crate::AdminError::NotAllowed)
    }
    fn roles(&self) -> Vec<crate::RoleView> {
        use std::sync::atomic::Ordering;
        if self.armed.swap(false, Ordering::SeqCst) {
            *self.held.lock().unwrap() = true;
            self.entered.store(true, Ordering::SeqCst);
            let held = self.held.lock().unwrap();
            drop(self.release.wait_while(held, |h| *h).unwrap());
        }
        Vec::new()
    }
}

#[test]
fn a_device_joining_while_its_person_is_masked_is_masked() {
    use std::sync::atomic::Ordering;
    let admin = std::sync::Arc::new(GatedRoles::default());
    let core = std::sync::Arc::new(Core::new().with_admin(admin.clone()).with_coalesce(true));
    let (a1, _rx1) = alice(&core, true, |_| {});
    admin.armed.store(true, Ordering::SeqCst);
    let masking = {
        let core = core.clone();
        std::thread::spawn(move || core.set_session_mask(a1, muted()))
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !admin.entered.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "never asked the roles"
        );
        std::thread::yield_now();
    }
    // Joins while the mask is being set.
    let (a2, _rx2) = alice(&core, true, |_| {});
    *admin.held.lock().unwrap() = false;
    admin.release.notify_all();
    assert!(masking.join().unwrap());
    assert_eq!(core.mask_of(a2), muted());
}

#[test]
fn a_mask_set_on_a_row_whose_own_device_left_masks_the_person() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = alice(&core, true, |_| {});
    let (a2, _rx2) = alice(&core, true, |_| {});
    core.end_session(a1);
    assert!(core.set_session_mask(a1, muted()));
    assert_eq!(core.mask_of(a2), muted());
    assert!(!sends(&core, a2));
}

#[test]
fn a_mask_on_one_device_is_its_persons_and_lifts_from_every_device() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, mut rx1) = alice(&core, true, admin);
    let (a2, mut rx2) = alice(&core, true, admin);
    drain(&mut watching);
    assert!(core.set_session_mask(a2, muted()));
    assert_eq!(admins(&mut watching), [false], "one change, the row's");
    assert_eq!((sends(&core, a1), sends(&core, a2)), (false, false));
    assert_eq!(core.mask_of(a1), muted());
    assert_eq!(
        told_account(&mut rx1),
        Some(false),
        "the other device is told"
    );
    assert_eq!(told_account(&mut rx2), Some(false));
    assert!(core.set_session_mask(a1, crate::DenyMask::default()));
    assert_eq!((sends(&core, a1), sends(&core, a2)), (true, true));
    assert_eq!(told_account(&mut rx2), Some(true));
    assert_eq!(admins(&mut watching), [true], "one change, the row's");
}

#[test]
fn a_device_joining_a_masked_person_is_masked() {
    let core = Core::new().with_coalesce(true);
    let (a1, _rx1) = alice(&core, true, |_| {});
    assert!(core.set_session_mask(a1, muted()));
    let (a2, mut rx2) = alice(&core, true, |_| {});
    assert_eq!(core.mask_of(a2), muted());
    assert!(!sends(&core, a2));
    assert_eq!(told_account(&mut rx2), Some(false));
}

#[test]
fn with_coalescing_off_a_mask_is_one_sessions() {
    let core = Core::new();
    let (a1, _rx1) = alice(&core, true, |_| {});
    assert!(core.set_session_mask(a1, muted()));
    let (a2, _rx2) = alice(&core, true, |_| {});
    assert_eq!((sends(&core, a1), sends(&core, a2)), (false, true));
    assert_eq!(core.mask_of(a2), crate::DenyMask::default());
}

/// Accounts whose identity is linked: every login names one, linked
/// to alice's identity.
struct Linked;

impl crate::AccountDirectory for Linked {
    fn inbox_account(&self, login: &str) -> Option<crate::inbox::Mailbox> {
        Some(crate::inbox::Mailbox::identified(login, ALICE))
    }

    fn mailbox_access(&self, _: &crate::inbox::Mailbox) -> Option<AccessBits> {
        Some(AccessBits::empty())
    }
}

#[test]
fn a_kick_ban_ends_another_account_of_the_identity_at_the_agreement() {
    let core = moderated().with_accounts(std::sync::Arc::new(Linked));
    let (a1, _rx1) = alice(&core, true, at("192.0.2.1"));
    let (_other, mut waiting) = core
        .attach(session(
            "ally",
            Some(ALICE),
            Some(ALICE),
            Transport::default(),
        ))
        .unwrap();
    let ban = crate::KickBan {
        by: crate::Actor::Operator,
        for_: std::time::Duration::from_secs(60),
        reason: "spam".into(),
    };
    assert!(core.kick_by(a1, Some(ban)).unwrap().banned);
    assert!(
        drain(&mut waiting).contains(&Event::Kicked),
        "the identity is banned with the login"
    );
}

#[test]
fn a_person_being_kicked_is_told_no_change() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let begun = core.kick_begin(a1, false).unwrap();
    core.update(a2, Some("Ally".into()), None);
    core.kick_end(begun, None);
    assert_eq!(told(&mut watching), []);
}

#[test]
fn a_person_already_being_kicked_is_not_kicked_again() {
    for flood_first in [false, true] {
        let core = Core::new()
            .with_coalesce(true)
            .with_flood_limits(crate::FloodLimits {
                chat_lines: 1,
                chat_per: std::time::Duration::from_secs(60),
                spam_points: 0,
                spam_per: std::time::Duration::from_secs(60),
                ban_for: std::time::Duration::ZERO,
            });
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        if flood_first {
            let _ = core.chat_public(a2, "one\rtwo".into(), 0, None);
        } else {
            core.kick(a1, None).unwrap();
        }
        assert_eq!(
            core.kick(a1, None),
            Err(crate::ChatError::NoSuchUser),
            "flood first {flood_first}"
        );
    }
}

#[test]
fn a_kick_purging_hears_no_device_from_its_first_step_on() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let kicked = core.kick_with(a1, None, |c| {
        c.chat_public(a2, "between the purge and the kick".into(), 0, None)
    });
    let (kicked, between) = kicked;
    assert!(kicked.is_ok());
    assert_eq!(between, Some(Err(crate::ChatError::Flooding)));
    assert!(drain(&mut rx1).contains(&Event::Kicked));
    assert!(!drain(&mut watching)
        .iter()
        .any(|e| matches!(e, Event::Chat { .. })));
}

#[test]
fn a_kick_whose_purge_fails_or_panics_still_ends_every_device() {
    for panics in [false, true] {
        let core = Core::new().with_coalesce(true);
        let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (_a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let kicked = core.kick_with(a1, None, |_| -> Result<(), &str> {
            assert!(!panics, "a purge that panics");
            Err("the store failed")
        });
        let (kicked, purged) = kicked;
        assert!(kicked.is_ok(), "panics {panics}");
        let expected = (!panics).then_some(Err("the store failed"));
        assert_eq!(purged, expected, "panics {panics}");
        for rx in [&mut rx1, &mut rx2] {
            assert!(drain(rx).contains(&Event::Kicked), "panics {panics}");
        }
    }
}

#[test]
fn a_purge_asked_of_a_target_that_left_is_still_made() {
    let core = moderated().with_coalesce(false).with_history(
        std::sync::Arc::new(crate::history::MemoryLog::default()),
        Default::default(),
    );
    let (a1, _rx1) = alice(&core, true, |_| {});
    let line = core
        .chat_public(a1, "buy now".into(), 0, None)
        .unwrap()
        .expect("logged");
    let check = core
        .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
        .unwrap();
    core.end_session(a1);
    let within = std::time::Duration::from_secs(3600);
    let (kicked, purged) = core.kick_purging(a1, None, Some((check, within)));
    assert_eq!(kicked, Err(crate::ChatError::NoSuchUser));
    assert_eq!(purged, Some(true));
    let line = core.history.as_ref().unwrap().line(line).unwrap().unwrap();
    assert!(line.flags.contains(crate::history::LineFlags::DELETED));
}

#[test]
fn a_purge_of_a_persons_row_kicks_it_once_its_first_device_is_gone() {
    let core = moderated();
    let (a1, _rx1) = alice(&core, true, |_| {});
    let (_a2, mut rx2) = alice(&core, true, |_| {});
    let check = core
        .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
        .unwrap();
    core.end_session(a1);
    let within = std::time::Duration::from_secs(3600);
    let (kicked, _) = core.kick_purging(a1, None, Some((check, within)));
    assert!(kicked.is_ok());
    assert!(drain(&mut rx2).contains(&Event::Kicked));
}

#[test]
fn a_purge_the_store_fails_still_kicks_every_device() {
    let store = std::sync::Arc::new(crate::moderation::faulty::FaultyModeration::default());
    let core = Core::new()
        .with_moderation(
            store.clone(),
            crate::moderation::ModerationPolicy::default(),
        )
        .with_coalesce(true);
    let (a1, mut rx1) = alice(&core, true, |_| {});
    let (_a2, mut rx2) = alice(&core, true, |_| {});
    let check = core
        .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
        .unwrap();
    store.fail("record");
    let within = std::time::Duration::from_secs(3600);
    let (kicked, purged) = core.kick_purging(a1, None, Some((check, within)));
    assert!(kicked.is_ok());
    assert_eq!(purged, Some(false));
    for rx in [&mut rx1, &mut rx2] {
        assert!(drain(rx).contains(&Event::Kicked));
    }
}

#[test]
fn a_kick_ban_never_ends_its_kicker_who_shares_the_identity() {
    let core = moderated().with_accounts(std::sync::Arc::new(Linked));
    let (a1, mut rx1) = alice(&core, true, at("192.0.2.1"));
    let mut kicker = session("mod", Some(ALICE), Some(ALICE), Transport::default());
    kicker.moderate = true;
    let (moderator, mut rx_mod) = core.attach(kicker).unwrap();
    core.announce(moderator);
    let ban = crate::KickBan {
        by: crate::Actor::Session(moderator),
        for_: std::time::Duration::from_secs(60),
        reason: "spam".into(),
    };
    assert!(core.kick_by(a1, Some(ban)).unwrap().banned);
    assert!(drain(&mut rx1).contains(&Event::Kicked));
    assert!(!drain(&mut rx_mod).contains(&Event::Kicked), "the kicker");
    let bans = core.list_bans(true, None, 10).unwrap();
    assert!(
        !bans
            .iter()
            .any(|b| b.target == crate::ban::BanTarget::Identity(ALICE)),
        "the kicker's own identity, banned: {bans:?}"
    );
}

#[test]
fn a_person_being_kicked_says_nothing_more() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    drain(&mut watching);
    let begun = core.kick_begin(a1, false).unwrap();
    assert_eq!(
        core.chat_public(a2, "a last word".into(), 0, None),
        Err(crate::ChatError::Flooding)
    );
    core.kick_end(begun, None);
    assert!(!drain(&mut watching)
        .iter()
        .any(|e| matches!(e, Event::Chat { .. })));
}

#[test]
fn a_person_is_protected_whichever_device_holds_its_row() {
    let protected = |i: &mut AttachInfo| i.access = i.access.with(bit::CANT_BE_DISCONNECTED);
    for ended in [None, Some(0), Some(1)] {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = alice(&core, true, protected);
        let (a2, _rx2) = alice(&core, true, protected);
        let devices = [a1, a2];
        if let Some(i) = ended {
            core.end_session(devices[i]);
        }
        assert!(
            core.access_of(a1)
                .is_some_and(|a| a.has(bit::CANT_BE_DISCONNECTED)),
            "the row, with device {ended:?} ended"
        );
    }
}

/// How a test ends a person: a moderator's kick, with or without its
/// ban, or a spam kick and the ban it asks for.
#[derive(Debug, Clone, Copy)]
enum Kick {
    Plain,
    Banned,
    Spam,
}

#[test]
fn a_kick_ends_every_live_device_and_its_ban_one_still_at_the_agreement() {
    use Kick::*;
    // Each device: announced (live) or still at the agreement, and
    // whether the kick ends it.
    for (devices, how) in [
        (&[(true, true)][..], Plain),
        (&[(true, true)][..], Banned),
        (&[(true, true)][..], Spam),
        (&[(true, true), (true, true)][..], Plain),
        (&[(true, true), (true, true)][..], Banned),
        (&[(true, true), (true, true)][..], Spam),
        (&[(true, true), (false, false)][..], Plain),
        (&[(true, true), (false, true)][..], Banned),
        (&[(true, true), (false, true)][..], Spam),
    ] {
        let core = moderated().with_flood_limits(crate::FloodLimits {
            spam_points: 1,
            ..crate::FloodLimits::MHXD
        });
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let mut sessions: Vec<(Uid, Events)> = devices
            .iter()
            .enumerate()
            .map(|(i, (live, _))| alice(&core, *live, at(["192.0.2.1", "198.51.100.1"][i])))
            .collect();
        drain(&mut watching);
        let first = sessions[0].0;
        match how {
            Plain => drop(core.kick(first, None).unwrap()),
            Banned => {
                let ban = crate::KickBan {
                    by: crate::Actor::Operator,
                    for_: std::time::Duration::from_secs(60),
                    reason: "spam".into(),
                };
                assert!(core.kick_by(first, Some(ban)).unwrap().banned);
            }
            Spam => {
                let flooded = core.spend_spam(first, 1, 105).unwrap_err();
                assert!(flooded.ban.is_some(), "a ban to place");
                core.spam_kicked(flooded);
            }
        }
        for (i, ((_, ends), (uid, rx))) in devices.iter().zip(&mut sessions).enumerate() {
            assert_eq!(
                drain(rx).contains(&Event::Kicked),
                *ends,
                "{how:?} of {devices:?}: device {i}"
            );
            if *ends {
                core.end_session(*uid);
            }
        }
        let parted = told(&mut watching)
            .into_iter()
            .filter(|(kind, _)| *kind == "parted")
            .collect::<Vec<_>>();
        assert_eq!(parted, [("parted", first)], "{how:?} of {devices:?}");
    }
}

#[test]
fn a_kicked_persons_row_is_held_and_its_next_login_is_a_row_of_its_own() {
    let core = Core::new().with_coalesce(true);
    let (bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    core.kick(a1, None).unwrap();
    core.end_session(a1);
    core.end_session(a2);
    assert!(core.roster.lock().unwrap().freed_uids.holds(a1));
    drain(&mut watching);
    let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert!(![a1, a2].contains(&a3), "a held uid given out: {a3}");
    assert_eq!(told(&mut watching), [("joined", a3)]);
    let listed: Vec<Uid> = rows(&core).into_iter().map(|r| r.0).collect();
    assert_eq!(listed, [bob, a3]);
}

#[test]
fn a_ban_ends_the_devices_it_names_and_the_row_parts_with_the_last() {
    use crate::ban::BanTarget;
    let address = || BanTarget::address("192.0.2.1".parse().unwrap(), 32).unwrap();
    let one = ["192.0.2.1", "192.0.2.1"];
    let two = ["192.0.2.1", "198.51.100.1"];
    for (target, addrs, ended) in [
        (BanTarget::Login("alice".into()), one, [true, true]),
        (BanTarget::Login("alice".into()), two, [true, true]),
        (BanTarget::Identity(ALICE), one, [true, true]),
        (BanTarget::Identity(ALICE), two, [true, true]),
        (address(), one, [true, true]),
        (address(), two, [true, false]),
    ] {
        let core = moderated();
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let mut devices: Vec<(Uid, Events)> =
            addrs.iter().map(|a| alice(&core, true, at(a))).collect();
        let row = devices[0].0;
        drain(&mut watching);
        core.place_ban(
            crate::Actor::Operator,
            crate::ban::NewBan {
                target: target.clone(),
                reason: "spam".into(),
                note: None,
                expires_at: None,
                source: crate::ban::BanSource::Cli,
            },
        )
        .unwrap();
        for ((uid, rx), ends) in devices.iter_mut().zip(ended) {
            assert_eq!(
                drain(rx).contains(&Event::Kicked),
                ends,
                "{target:?} at {addrs:?}: {uid}"
            );
            if ends {
                core.end_session(*uid);
            }
        }
        let parts = ended.iter().all(|e| *e);
        let expected: &[(&str, Uid)] = if parts { &[("parted", row)] } else { &[] };
        assert_eq!(told(&mut watching), expected, "{target:?} at {addrs:?}");
    }
}

#[test]
fn a_person_floods_as_one_and_is_kicked_once() {
    for (spam, can_spam) in [(false, false), (true, false), (false, true), (true, true)] {
        let core = Core::new()
            .with_coalesce(true)
            .with_flood_limits(crate::FloodLimits {
                chat_lines: 4,
                chat_per: std::time::Duration::from_secs(60),
                spam_points: 4,
                spam_per: std::time::Duration::from_secs(60),
                ban_for: std::time::Duration::ZERO,
            });
        let case = format!("spam {spam}, can_spam {can_spam}");
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let exempt = |i: &mut AttachInfo| i.can_spam = can_spam;
        let (a1, mut rx1) = alice(&core, true, exempt);
        let (a2, mut rx2) = alice(&core, true, exempt);
        drain(&mut watching);
        // Each device alone stays inside its budget.
        for _ in 0..3 {
            for uid in [a1, a2] {
                if spam {
                    if let Err(flooded) = core.spend_spam(uid, 1, 105) {
                        core.spam_kicked(flooded);
                    }
                } else {
                    let _ = core.chat_public(uid, "hi".into(), 0, None);
                }
            }
        }
        let notices = drain(&mut watching)
            .into_iter()
            .filter(|e| matches!(e, Event::Notice { .. }))
            .count();
        assert_eq!(notices, usize::from(!can_spam), "{case}");
        for rx in [&mut rx1, &mut rx2] {
            assert_eq!(drain(rx).contains(&Event::Kicked), !can_spam, "{case}");
        }
    }
}

#[test]
fn with_coalescing_off_every_act_is_one_sessions_as_before() {
    let core = moderated()
        .with_coalesce(false)
        .with_flood_limits(crate::FloodLimits {
            chat_lines: 4,
            chat_per: std::time::Duration::from_secs(60),
            spam_points: 4,
            spam_per: std::time::Duration::from_secs(60),
            ban_for: std::time::Duration::ZERO,
        });
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let (a1, mut rx1) = alice(&core, true, at("192.0.2.1"));
    let (a2, mut rx2) = alice(&core, true, at("198.51.100.1"));
    assert_eq!(told(&mut watching), [("joined", a1), ("joined", a2)]);
    // Three lines and three points each: neither is past its own.
    for _ in 0..3 {
        for uid in [a1, a2] {
            let _ = core.chat_public(uid, "hi".into(), 0, None);
            let _ = core.spend_spam(uid, 1, 105);
        }
    }
    assert!(
        !core.kicks_own_row(a2, a1),
        "a session of one's own is anyone"
    );
    assert!(!drain(&mut rx1).contains(&Event::Kicked));
    let begun = core.kick_begin(a1, false).unwrap();
    assert!(
        core.chat_public(a2, "still here".into(), 0, None).is_ok(),
        "another session of the login is not being kicked"
    );
    core.kick_end(begun, None);
    assert!(drain(&mut rx1).contains(&Event::Kicked));
    assert!(!drain(&mut rx2).contains(&Event::Kicked));
    core.end_session(a1);
    drain(&mut watching);
    let (a3, mut rx3) = alice(&core, true, at("203.0.113.1"));
    let ban = crate::KickBan {
        by: crate::Actor::Operator,
        for_: std::time::Duration::from_secs(60),
        reason: "spam".into(),
    };
    assert!(core.kick_by(a2, Some(ban)).unwrap().banned);
    assert!(drain(&mut rx2).contains(&Event::Kicked));
    assert!(
        !drain(&mut rx3).contains(&Event::Kicked),
        "a kick's ban ends the session the kick does, and no other"
    );
    core.end_session(a2);
    assert_eq!(told(&mut watching), [("joined", a3), ("parted", a2)]);
}

#[test]
fn a_kick_of_ones_own_row_is_refused_and_of_anyone_else_is_not() {
    let core = Core::new().with_coalesce(true);
    let (bob, _rxb) = attach(&core, "bob", None, None);
    let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
    for (kicker, target, own) in [
        (a2, a1, true),
        (a1, a1, true),
        (bob, a1, false),
        (a1, bob, false),
        // A session alone kicks itself as it always could.
        (bob, bob, false),
    ] {
        assert_eq!(
            core.kicks_own_row(kicker, target),
            own,
            "{kicker} kicking {target}"
        );
    }
}

#[test]
fn a_person_is_shown_as_safe_as_its_least_safe_device() {
    let core = Core::new().with_coalesce(true);
    let tls = Transport {
        encrypted: true,
        ..Transport::default()
    };
    attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
    assert!(core.snapshot()[0].transport.encrypted);
    attach(&core, "alice", Some(ALICE), Some(ALICE));
    assert!(!core.snapshot()[0].transport.encrypted);
}

fn proved(signs: bool) -> Transport {
    Transport {
        identity: Some(crate::roster::IdentityTag {
            fingerprint: ALICE,
            device: [1; 32],
            handle: Some("alice@reg.example".into()),
            quiet_until: None,
            signs,
            can_sign: true,
            device_expires: 0,
            sealed: None,
            device_cert: None,
        }),
        ..Transport::default()
    }
}

#[test]
fn a_person_shows_its_identity_whichever_device_is_first() {
    let core = Core::new().with_coalesce(true);
    // A password session of the linked account first, the key after.
    attach(&core, "alice", Some(ALICE), Some(ALICE));
    attach_on(&core, "alice", Some(ALICE), Some(ALICE), proved(true));
    let row = &core.snapshot()[0];
    let identity = row
        .transport
        .identity
        .as_ref()
        .expect("the person's identity");
    assert_eq!(identity.handle.as_deref(), Some("alice@reg.example"));
    assert!(!identity.signs, "one device does not sign");
}

#[test]
fn each_of_a_persons_devices_is_told_its_own_view_of_the_row_once() {
    let core = Core::new().with_coalesce(true);
    let (_bob, mut watching) = attach(&core, "bob", None, None);
    let tls = Transport {
        encrypted: true,
        ..Transport::default()
    };
    let (a1, mut rx1) = attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
    drain(&mut watching);
    drain(&mut rx1);
    attach(&core, "alice", Some(ALICE), Some(ALICE));
    let changed = |rx: &mut Events| -> Vec<(Uid, bool)> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Changed(u) => Some((u.uid, u.transport.encrypted)),
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        changed(&mut watching),
        [(a1, false)],
        "the row, as safe as its least"
    );
    assert_eq!(changed(&mut rx1), [(a1, true)], "its own link, once");
}
