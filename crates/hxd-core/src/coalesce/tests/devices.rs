//! The devices under a person's row: shown to its own devices and to a
//! viewer with the kick bit, each told of a change to them alone, and to
//! nobody else.

use super::{session, ALICE};
use crate::access::{bit, AccessBits};
use crate::coalesce::{device_label, Device, LABEL_MAX_CHARS};
use crate::roster::{
    drain, AttachInfo, Core, Event, Events, IdentityTag, SessionStatus, Transport, Uid,
};

/// The ng wire, `persons` declared or not.
fn ng(persons: bool) -> Transport {
    Transport {
        ng: true,
        roles: true,
        persons,
        ..Transport::default()
    }
}

/// `t`, on a device that proved alice's identity.
fn proved(t: Transport) -> Transport {
    Transport {
        identity: Some(IdentityTag {
            fingerprint: ALICE,
            device: [1; 32],
            handle: None,
            quiet_until: None,
            signs: false,
            can_sign: false,
            device_expires: u64::MAX,
            sealed: None,
            device_cert: None,
        }),
        ..t
    }
}

/// A session attached and announced, then sent its user list, as an ng
/// login is.
fn on(core: &Core, info: AttachInfo) -> (Uid, Events) {
    let (uid, rx) = core.attach(info).unwrap();
    core.announce(uid);
    core.roster_for(uid);
    (uid, rx)
}

/// One of alice's devices on `t`.
fn alice(core: &Core, t: Transport) -> (Uid, Events) {
    on(core, session("alice", Some(ALICE), Some(ALICE), t))
}

/// Someone else on `t`, who may kick or not.
fn other(core: &Core, login: &str, t: Transport, kicks: bool) -> (Uid, Events) {
    let mut info = session(login, None, None, t);
    if kicks {
        info.access = info.access.with(bit::DISCONNECT_USERS);
        if let Some(account) = info.account.as_mut() {
            account.access = account.access.with(bit::DISCONNECT_USERS);
            account.config.access = account.config.access.with(bit::DISCONNECT_USERS);
        }
    }
    on(core, info)
}

/// The devices each row-with-devices event `rx` was told carried, as
/// (joined, row, device ids).
fn rows_told(rx: &mut Events) -> Vec<(bool, Uid, Vec<u64>)> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::PersonRow {
                joined,
                user,
                devices,
            } => Some((joined, user.uid, devices.iter().map(|d| d.device).collect())),
            _ => None,
        })
        .collect()
}

/// Every join, change or part `rx` was told, of any kind.
fn presence(rx: &mut Events) -> Vec<Event> {
    drain(rx)
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                Event::Joined(_) | Event::Changed(_) | Event::Parted(_) | Event::PersonRow { .. }
            )
        })
        .collect()
}

fn device_of(core: &Core, uid: Uid) -> u64 {
    core.roster.lock().unwrap().users[&uid].device
}

fn status(core: &Core, uid: Uid, s: SessionStatus) {
    core.roster.lock().unwrap().set_status(uid, s);
}

#[test]
fn a_persons_devices_are_shown_to_its_own_devices_and_to_a_viewer_who_may_kick() {
    let core = Core::new().with_coalesce(true);
    let (a1, _r1) = alice(&core, proved(ng(true)));
    let (a2, _r2) = alice(&core, ng(false));
    let (moderator, _r3) = other(&core, "mod", ng(true), true);
    let (carol, _r4) = other(&core, "carol", ng(true), false);
    let (dave, _r5) = other(&core, "dave", ng(false), true);
    let (classic, _r6) = other(&core, "erin", Transport::default(), true);
    let row = a1;
    for (who, viewer, sees) in [
        ("its own device", a1, true),
        ("a viewer with the kick bit", moderator, true),
        ("a stranger", carol, false),
        ("a viewer who did not declare persons", dave, false),
        ("a classic viewer", classic, false),
        ("its own device that did not declare persons", a2, false),
    ] {
        let (rows, devices) = core.roster_for(viewer);
        assert!(rows.iter().any(|u| u.uid == row), "{who}");
        assert_eq!(devices.contains_key(&row), sees, "{who}");
        assert!(
            !devices.contains_key(&moderator),
            "{who}: a session alone has no devices to show"
        );
    }
    assert_eq!(
        core.roster_for(moderator).1[&row]
            .iter()
            .map(|d| d.device)
            .collect::<Vec<_>>(),
        [device_of(&core, a1), device_of(&core, a2)],
    );
}

#[test]
fn a_device_of_a_person_sees_itself_as_the_merged_row_with_its_own_status_in_its_entry() {
    let core = Core::new().with_coalesce(true);
    let (a1, _r1) = alice(&core, proved(ng(true)));
    let (a2, _r2) = alice(&core, proved(ng(false)));
    status(&core, a1, SessionStatus::Idle);
    let me = core.self_view(a1).unwrap();
    assert_eq!(me.info.uid, a1);
    assert_eq!(me.info.status, SessionStatus::Active, "the person's");
    let mine = me.devices.unwrap();
    let own = mine.iter().find(|d| Some(d.device) == me.device).unwrap();
    assert_eq!(own.status, SessionStatus::Idle, "its own");
    status(&core, a2, SessionStatus::Idle);
    let not_persons = core.self_view(a2).unwrap();
    assert_eq!(
        not_persons.info.status,
        SessionStatus::Idle,
        "its own, as before"
    );
    assert!(not_persons.device.is_none() && not_persons.devices.is_none());
}

#[test]
fn a_change_to_a_device_alone_reaches_those_who_see_devices_and_nobody_else() {
    let core = Core::new().with_coalesce(true);
    let (_a1, mut r1) = alice(&core, proved(ng(true)));
    let (a2, mut r2) = alice(&core, proved(ng(true)));
    let (_m, mut rm) = other(&core, "mod", ng(true), true);
    let (carol, mut rc) = other(&core, "carol", ng(true), false);
    let (_d, mut rd) = other(&core, "dave", ng(false), true);
    let (_e, mut re) = other(&core, "erin", Transport::default(), true);
    for rx in [&mut r1, &mut r2, &mut rm, &mut rc, &mut rd, &mut re] {
        drain(rx);
    }
    let seq = core.current_seq(carol);
    status(&core, a2, SessionStatus::Idle);
    for (who, rx) in [
        ("its other device", &mut r1),
        ("the device itself", &mut r2),
    ] {
        let told = drain(rx);
        assert!(
            matches!(&told[..], [Event::PersonRow { joined: false, user, devices }]
                if user.status == SessionStatus::Active
                    && devices.iter().map(|d| d.status).collect::<Vec<_>>()
                        == [SessionStatus::Active, SessionStatus::Idle]),
            "{who}: {told:?}"
        );
    }
    assert_eq!(rows_told(&mut rm).len(), 1, "the viewer with the kick bit");
    for (who, rx) in [
        ("a stranger", &mut rc),
        ("dave", &mut rd),
        ("classic", &mut re),
    ] {
        assert!(presence(rx).is_empty(), "{who}");
    }
    assert_eq!(core.current_seq(carol), seq, "no seq spent on a stranger");
}

#[test]
fn a_change_to_the_row_reaches_a_device_that_declared_persons_as_the_row_with_its_devices() {
    let core = Core::new().with_coalesce(true);
    let (a1, mut r1) = alice(&core, proved(ng(true)));
    let (a2, mut r2) = alice(&core, proved(ng(false)));
    let (_c, mut rc) = other(&core, "carol", ng(true), false);
    for rx in [&mut r1, &mut r2, &mut rc] {
        drain(rx);
    }
    assert!(core.update(a2, Some("Ally".into()), None));
    assert!(matches!(&presence(&mut r1)[..],
        [Event::PersonRow { joined: false, user, devices }] if user.nick == "Ally" && devices.len() == 2));
    assert!(
        matches!(&presence(&mut r2)[..],
        [Event::Changed(u)] if u.uid == a1 && u.nick == "Ally"),
        "as before, its own view"
    );
    assert!(matches!(&presence(&mut rc)[..], [Event::Changed(u)] if u.uid == a1));
}

#[test]
fn each_devices_event_carries_the_whole_list_as_it_stood_when_it_was_made() {
    let core = Core::new().with_coalesce(true);
    let (_m, mut rm) = other(&core, "mod", ng(true), true);
    let (a1, _r1) = alice(&core, proved(ng(true)));
    let (a2, _r2) = alice(&core, ng(false));
    let (a3, _r3) = alice(&core, Transport::default());
    core.end_session(a2);
    let d = |u| device_of(&core, u);
    let (d1, d3) = (d(a1), d(a3));
    let told = rows_told(&mut rm);
    assert_eq!(
        told[0],
        (true, a1, vec![d1]),
        "the person joined, with its one device"
    );
    assert_eq!(told[1].2.len(), 2);
    assert_eq!(told[2].2.len(), 3);
    assert_eq!(told[3], (false, a1, vec![d1, d3]), "a2 gone");
    assert_eq!(told.len(), 4);
    core.end_session(a1);
    core.end_session(a3);
    assert!(
        matches!(&drain(&mut rm)[..], [.., Event::Parted(row)] if *row == a1),
        "the person parts as before"
    );
}

#[test]
fn a_password_device_sees_only_the_password_devices_of_its_person() {
    let core = Core::new().with_coalesce(true);
    let (a1, mut r1) = alice(&core, proved(ng(true)));
    let (p1, mut rp1) = alice(&core, ng(true));
    let (p2, _rp2) = alice(&core, ng(true));
    let (_m, mut rm) = other(&core, "mod", ng(true), true);
    let ids = |viewer| -> Vec<u64> {
        core.roster_for(viewer).1[&a1]
            .iter()
            .map(|d| d.device)
            .collect()
    };
    let d = |u| device_of(&core, u);
    assert_eq!(ids(a1), [d(a1), d(p1), d(p2)], "a proved device");
    assert_eq!(ids(p1), [d(p1), d(p2)], "a password one");
    assert_eq!(
        core.self_view(p1)
            .unwrap()
            .devices
            .unwrap()
            .iter()
            .map(|d| d.device)
            .collect::<Vec<_>>(),
        [d(p1), d(p2)]
    );
    for rx in [&mut r1, &mut rp1, &mut rm] {
        drain(rx);
    }
    status(&core, a1, SessionStatus::Idle);
    assert!(
        rows_told(&mut rp1).is_empty(),
        "a proved device's change is not a password's to see"
    );
    assert_eq!(rows_told(&mut r1).len(), 1);
    assert_eq!(rows_told(&mut rm).len(), 1);
    status(&core, p2, SessionStatus::Idle);
    assert_eq!(rows_told(&mut rp1), [(false, a1, vec![d(p1), d(p2)])]);
    assert_eq!(rows_told(&mut r1), [(false, a1, vec![d(a1), d(p1), d(p2)])]);
}

/// mod's account with the kick bit or without it, as an edit makes it.
fn mod_account(kicks: bool) -> crate::Account {
    let mut info = session("mod", None, None, ng(true));
    let account = info.account.as_mut().unwrap();
    if kicks {
        account.access = account.access.with(bit::DISCONNECT_USERS);
        account.config.access = account.config.access.with(bit::DISCONNECT_USERS);
    }
    *info.account.unwrap()
}

#[test]
fn gaining_or_losing_the_kick_bit_tells_a_persons_viewer_its_user_list_is_stale() {
    let deny = |bits: AccessBits| crate::DenyMask {
        access: bits,
        ..Default::default()
    };
    let kick = AccessBits::empty().with(bit::DISCONNECT_USERS);
    #[derive(Debug, Clone, Copy)]
    enum By {
        Mask,
        Edit,
    }
    for (by, persons, other_bit, stale) in [
        (By::Mask, true, false, true),
        (By::Edit, true, false, true),
        (By::Mask, true, true, false),
        (By::Mask, false, false, false),
        (By::Edit, false, false, false),
    ] {
        let case = format!("{by:?}, persons {persons}, another bit {other_bit}");
        let core = Core::new().with_coalesce(true);
        let (a1, _ra) = alice(&core, proved(ng(true)));
        let (_a2, _rb) = alice(&core, ng(true));
        let (m, mut rm) = other(&core, "mod", ng(persons), true);
        let sees = |core: &Core| core.roster_for(m).1.contains_key(&a1);
        assert_eq!(sees(&core), persons, "{case}: before");
        drain(&mut rm);
        let lose = |core: &Core| match by {
            By::Mask if other_bit => {
                core.set_session_mask(m, deny(AccessBits::empty().with(bit::SEND_CHAT)))
            }
            By::Mask => core.set_session_mask(m, deny(kick)),
            By::Edit => core.apply_account(&mod_account(false)) == 1,
        };
        assert!(lose(&core), "{case}");
        let told = drain(&mut rm);
        assert_eq!(
            told.contains(&Event::RosterStale),
            stale,
            "{case}: {told:?}"
        );
        assert_eq!(sees(&core), persons && other_bit, "{case}: after");
        status(&core, a1, SessionStatus::Idle);
        assert_eq!(
            rows_told(&mut rm).is_empty(),
            !(persons && other_bit),
            "{case}: the next change to a device"
        );
        let regain = match by {
            By::Mask => core.set_session_mask(m, deny(AccessBits::empty())),
            By::Edit => core.apply_account(&mod_account(true)) == 1,
        };
        assert!(regain, "{case}");
        let told = drain(&mut rm);
        assert_eq!(
            told.contains(&Event::RosterStale),
            stale,
            "{case}, regained: {told:?}"
        );
        assert_eq!(sees(&core), persons, "{case}: regained");
        status(&core, a1, SessionStatus::Active);
        assert_eq!(
            rows_told(&mut rm).is_empty(),
            !persons,
            "{case}: regained, the next change"
        );
    }
}

#[test]
fn an_edit_of_the_kick_bit_before_a_session_is_announced_sends_it_no_stale_list() {
    let core = Core::new().with_coalesce(true);
    let mut info = session("mod", None, None, ng(true));
    info.access = info.access.with(bit::DISCONNECT_USERS);
    info.account = Some(Box::new(mod_account(true)));
    let (m, mut rm) = core.attach(info).unwrap();
    assert_eq!(core.apply_account(&mod_account(false)), 1);
    let told = drain(&mut rm);
    assert!(!told.contains(&Event::RosterStale), "{told:?}");
    core.announce(m);
    core.roster_for(m);
    assert_eq!(core.apply_account(&mod_account(true)), 1);
    assert!(
        drain(&mut rm).contains(&Event::RosterStale),
        "once it has its list"
    );
}

#[test]
fn what_a_detached_viewer_holds_of_others_devices_is_the_row_alone_once_it_may_not_kick() {
    let core = Core::new().with_coalesce(true);
    let (a1, _ra) = alice(&core, proved(ng(true)));
    let (m, mut rm) = other(&core, "mod", ng(true), true);
    drain(&mut rm);
    let seq = core.current_seq(m).unwrap();
    assert!(core.connection_lost(m, usize::MAX));
    let (_a2, _rb) = alice(&core, ng(true));
    status(&core, a1, SessionStatus::Idle);
    assert!(core.set_session_mask(
        m,
        crate::DenyMask {
            access: AccessBits::empty().with(bit::DISCONNECT_USERS),
            ..Default::default()
        }
    ));
    let crate::Resume::Replayed(_, replay) = core.resume(m, seq) else {
        panic!("held for its resume");
    };
    let seqs: Vec<u64> = replay.iter().map(|se| se.seq).collect();
    assert_eq!(
        seqs,
        ((seq + 1)..=(seq + seqs.len() as u64)).collect::<Vec<_>>(),
        "gapless"
    );
    assert!(
        !replay
            .iter()
            .any(|se| matches!(se.event, Event::PersonRow { .. })),
        "{replay:?}"
    );
    assert!(replay
        .iter()
        .any(|se| matches!(&se.event, Event::Changed(u) if u.uid == a1)));
    assert!(matches!(
        replay.last().map(|se| &se.event),
        Some(Event::RosterStale)
    ));
}

#[test]
fn a_device_joining_a_masked_person_is_sent_no_stale_list_before_it_has_one() {
    let core = Core::new().with_coalesce(true);
    let mut info = session("alice", Some(ALICE), Some(ALICE), proved(ng(true)));
    info.access = info.access.with(bit::DISCONNECT_USERS);
    let account = info.account.as_mut().unwrap();
    account.access = account.access.with(bit::DISCONNECT_USERS);
    account.config.access = account.config.access.with(bit::DISCONNECT_USERS);
    let mut second = info.clone();
    let (a1, _ra) = on(&core, info);
    assert!(core.set_session_mask(
        a1,
        crate::DenyMask {
            access: AccessBits::empty().with(bit::DISCONNECT_USERS),
            ..Default::default()
        }
    ));
    second.transport = proved(ng(true));
    let (_a2, mut rb) = on(&core, second);
    let told = drain(&mut rb);
    assert!(
        told.iter().any(|e| matches!(e, Event::AccountChanged(_))),
        "it takes the mask: {told:?}"
    );
    assert!(!told.contains(&Event::RosterStale), "{told:?}");
}

#[test]
fn a_change_of_front_between_wires_tells_nobody_who_sees_no_devices() {
    let core = Core::new().with_coalesce(true);
    let (_c, mut rc) = other(&core, "carol", ng(false), false);
    let (_e, mut re) = other(&core, "erin", Transport::default(), false);
    let (a1, _ra) = alice(&core, proved(ng(true)));
    let (_a2, _rb) = alice(&core, proved(ng(false)));
    drain(&mut rc);
    drain(&mut re);
    core.end_session(a1);
    assert!(presence(&mut rc).is_empty(), "ng without persons");
    assert!(presence(&mut re).is_empty(), "classic");
}

/// Takes any picture, as it is.
struct Pictures;

impl crate::media::MediaCodec for Pictures {
    fn canonicalize(
        &self,
        _input: &[u8],
    ) -> Result<crate::media::Canonical, crate::media::MediaReject> {
        Err(crate::media::MediaReject::Unsupported)
    }

    fn avatar(
        &self,
        input: &[u8],
        _limits: &crate::avatar::AvatarLimits,
    ) -> Result<crate::avatar::AvatarImages, crate::media::MediaReject> {
        Ok(crate::avatar::AvatarImages {
            canonical: crate::media::Canonical {
                mime: crate::media::MediaType::Png,
                width: 64,
                height: 48,
                bytes: input.to_vec(),
            },
            legacy_gif: None,
        })
    }
}

#[test]
fn an_avatar_change_reaches_those_who_see_devices_as_the_row_with_them() {
    let core = Core::new()
        .with_avatars(
            std::sync::Arc::new(crate::avatar::MemoryAvatars::default()),
            std::sync::Arc::new(Pictures),
            crate::avatar::AvatarPolicy {
                set_interval: std::time::Duration::ZERO,
                ..Default::default()
            },
        )
        .with_coalesce(true);
    let mut info = session("alice", Some(ALICE), Some(ALICE), proved(ng(true)));
    info.set_avatar = true;
    let (a1, mut ra) = on(&core, info);
    let (_a2, _rb) = alice(&core, ng(true));
    let (_m, mut rm) = other(&core, "mod", ng(true), true);
    let (_c, mut rc) = other(&core, "carol", ng(true), false);
    for rx in [&mut ra, &mut rm, &mut rc] {
        drain(rx);
    }
    core.set_avatar(a1, b"picture").unwrap();
    for (who, rx) in [
        ("its own device", &mut ra),
        ("a viewer who may kick", &mut rm),
    ] {
        let told = drain(rx);
        assert!(
            matches!(&told[..], [Event::PersonRow { user, devices, .. }]
                if user.uid == a1 && user.avatar.is_some() && devices.len() == 2),
            "{who}: {told:?}"
        );
    }
    assert!(matches!(&drain(&mut rc)[..], [Event::AvatarChanged(u)] if u.uid == a1));
}

#[test]
fn a_label_is_kept_only_as_it_may_be_shown() {
    let long = "x".repeat(LABEL_MAX_CHARS);
    for (raw, kept) in [
        ("Pixel 8", Some("Pixel 8")),
        ("Desktop \u{1f5a5}", Some("Desktop \u{1f5a5}")),
        // NFC: e and a combining acute become one character.
        ("Cafe\u{301}", Some("Caf\u{e9}")),
        (long.as_str(), Some(long.as_str())),
        (&format!("{long}x"), None),
        ("", None),
        (" Pixel", None),
        ("Pixel ", None),
        ("   ", None),
        ("Pix\u{200b}el", None),
        ("Pixel\u{202e}8", None),
        ("Pixel\u{2066}8", None),
        ("Pixel\n8", None),
        ("Pixel\t8", None),
        ("Pixel\u{7}", None),
        ("Pixel\u{feff}", None),
        ("Pixel\u{2800}", None),
        ("Pixel\u{fe0f}", None),
    ] {
        assert_eq!(device_label(raw).as_deref(), kept, "{raw:?}");
    }
}

#[test]
fn a_label_is_shown_beside_the_facts_and_only_to_those_who_see_devices() {
    let core = Core::new().with_coalesce(true);
    let (a1, _r1) = core
        .attach(session("alice", Some(ALICE), Some(ALICE), proved(ng(true))))
        .unwrap();
    core.label_device(a1, "Pixel\u{200b}8");
    assert_eq!(
        core.roster.lock().unwrap().users[&a1].label,
        None,
        "dropped"
    );
    core.label_device(a1, "Pixel 8");
    core.announce(a1);
    let (a2, _r2) = alice(&core, ng(true));
    let devices = core.roster_for(a1).1.remove(&a1).unwrap();
    let mine: &Device = &devices[0];
    assert_eq!(mine.label.as_deref(), Some("Pixel 8"));
    assert!(mine.ng && mine.proved && !devices[1].proved);
    assert!(
        core.roster_for(a2).1[&a1].iter().all(|d| d.label.is_none()),
        "a2 sees only itself"
    );
    assert!(
        core.snapshot().iter().all(|u| !u.nick.contains("Pixel")),
        "never the row's"
    );
}

#[test]
fn a_device_id_is_its_own_and_below_two_to_the_53() {
    let core = Core::new().with_coalesce(true);
    let ids: Vec<u64> = (0..64)
        .map(|_| device_of(&core, alice(&core, ng(true)).0))
        .collect();
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());
    assert!(ids.iter().all(|d| *d != 0 && *d < 1 << 53));
}

#[test]
fn with_coalescing_off_nothing_is_shown_of_devices() {
    let core = Core::new().with_coalesce(false);
    let (a1, mut r1) = alice(&core, proved(ng(true)));
    let (_a2, _r2) = alice(&core, ng(true));
    let (m, mut rm) = other(&core, "mod", ng(true), true);
    assert!(core.roster_for(a1).1.is_empty());
    assert!(core.roster_for(m).1.is_empty());
    assert!(core.self_view(a1).unwrap().devices.is_none());
    status(&core, a1, SessionStatus::Idle);
    assert!(rows_told(&mut r1).is_empty() && rows_told(&mut rm).is_empty());
}

/// What `rx` was told that ends it.
fn ends(rx: &mut Events) -> Vec<Event> {
    drain(rx)
        .into_iter()
        .filter(|e| matches!(e, Event::Kicked | Event::Ended))
        .collect()
}

#[test]
fn a_device_ends_another_of_its_person_or_itself_and_the_last_is_its_person() {
    use crate::coalesce::DeviceRefusal;
    // (case, devices besides the actor, the one ended: 0 the actor
    // itself, 1 the next, and how that one is on).
    #[derive(Clone, Copy, Debug)]
    enum On {
        Ng,
        Detached,
        Classic,
    }
    for (case, others, target, on) in [
        ("itself", 1, 0, On::Ng),
        ("another", 1, 1, On::Ng),
        ("a detached one", 1, 1, On::Detached),
        ("a classic one", 1, 1, On::Classic),
        ("the last, itself", 0, 0, On::Ng),
    ] {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut rb) = other(&core, "bob", ng(false), false);
        let (a1, r1) = alice(&core, proved(ng(true)));
        let mut devices = vec![(a1, r1)];
        for _ in 0..others {
            let t = match on {
                On::Classic => proved(Transport::default()),
                _ => proved(ng(true)),
            };
            devices.push(alice(&core, t));
        }
        let ended = devices[target].0;
        if matches!(on, On::Detached) {
            assert!(core.connection_lost(ended, usize::MAX), "{case}");
        }
        drain(&mut rb);
        for (_, rx) in devices.iter_mut() {
            drain(rx);
        }

        assert_eq!(
            core.device_end(a1, device_of(&core, ended)),
            Ok(()),
            "{case}"
        );
        if matches!(on, On::Detached) {
            assert!(
                core.user(ended).is_none(),
                "{case}: no connection to end it"
            );
        } else {
            let (_, rx) = devices.iter_mut().find(|(u, _)| *u == ended).unwrap();
            // A classic device has no `ended` to hear.
            let told = if matches!(on, On::Classic) {
                Event::Kicked
            } else {
                Event::Ended
            };
            assert_eq!(ends(rx), [told], "{case}: the ended device is told so");
            // Its connection ends it, having told it.
            assert!(core.user(ended).is_some(), "{case}");
            core.end_session(ended);
        }
        // The rest of the person stays; only the last parts.
        let parted = presence(&mut rb)
            .into_iter()
            .any(|e| e == Event::Parted(a1));
        assert_eq!(parted, others == 0, "{case}: bob sees the person go");
        for (uid, rx) in devices.iter_mut().filter(|(u, _)| *u != ended) {
            assert_eq!(ends(rx), [], "{case}: {uid} stays");
        }
        // Gone is gone.
        assert_eq!(
            core.device_end(a1, device_of_gone(&core, ended)),
            Err(if ended == a1 {
                DeviceRefusal::NoSuchUser
            } else {
                DeviceRefusal::NoSuchDevice
            }),
            "{case}"
        );
    }
}

/// A device id nobody holds once `uid` has gone, or its own while it is
/// on its way.
fn device_of_gone(core: &Core, uid: Uid) -> u64 {
    core.roster
        .lock()
        .unwrap()
        .users
        .get(&uid)
        .map_or(u64::MAX, |s| s.device)
}

#[test]
fn a_password_device_ends_only_its_persons_password_devices() {
    use crate::coalesce::DeviceRefusal;
    let core = Core::new().with_coalesce(true);
    let (keyed, mut rk) = alice(&core, proved(ng(true)));
    let (pw, _rp) = alice(&core, ng(true));
    let (pw2, mut rp2) = alice(&core, ng(true));
    drain(&mut rk);
    assert_eq!(
        core.device_end(pw, device_of(&core, keyed)),
        Err(DeviceRefusal::NoSuchDevice),
        "a password does not reach the device that proved the identity"
    );
    assert_eq!(ends(&mut rk), []);
    assert_eq!(core.device_end(pw, device_of(&core, pw2)), Ok(()));
    assert_eq!(ends(&mut rp2), [Event::Ended]);
    // And the device that proved it reaches every one.
    core.end_session(pw2);
    assert_eq!(core.device_end(keyed, device_of(&core, pw)), Ok(()));
}

#[test]
fn a_device_kick_ends_one_device_and_leaves_its_last_to_a_kick() {
    use crate::coalesce::{DeviceKick, DeviceRefusal};
    let core = Core::new().with_coalesce(true);
    let (_bob, mut rb) = other(&core, "bob", ng(false), false);
    let (a1, mut r1) = alice(&core, proved(ng(true)));
    let (a2, mut r2) = alice(&core, proved(ng(true)));
    drain(&mut rb);
    drain(&mut r1);
    assert_eq!(
        core.kick_device(a1, device_of(&core, a2)),
        Ok(DeviceKick::Ended)
    );
    assert_eq!(ends(&mut r2), [Event::Kicked]);
    assert_eq!(ends(&mut r1), [], "the rest of the person stays");
    // Nobody is told the person went: it has not.
    assert!(drain(&mut rb).iter().all(|e| !matches!(
        e,
        Event::Parted(_) | Event::Notice { .. } | Event::Chat { .. }
    )));
    // Its last device, while the kicked one is still on its way: a kick
    // of the person, left to the caller, with nothing done yet.
    assert_eq!(
        core.kick_device(a1, device_of(&core, a1)),
        Ok(DeviceKick::Last)
    );
    assert_eq!(ends(&mut r1), []);
    assert_eq!(
        core.kick_device(a1, u64::MAX),
        Err(DeviceRefusal::NoSuchDevice)
    );
    assert_eq!(core.kick_device(999, 1), Err(DeviceRefusal::NoSuchUser));
    // A person already being kicked is refused, as a second kick is.
    core.end_session(a2);
    let (a3, _r3) = alice(&core, proved(ng(true)));
    core.kick_begin(a1, false).unwrap();
    assert_eq!(
        core.kick_device(a1, device_of(&core, a3)),
        Err(DeviceRefusal::NoSuchUser)
    );
    assert_eq!(
        core.device_end(a3, device_of(&core, a1)),
        Err(DeviceRefusal::NoSuchUser)
    );
}

#[test]
fn a_devices_ending_is_told_to_its_persons_other_devices_as_its_going_and_not_why() {
    let core = Core::new().with_coalesce(true);
    let (a1, mut r1) = alice(&core, proved(ng(true)));
    let (a2, _r2) = alice(&core, proved(ng(true)));
    let (a3, _r3) = alice(&core, proved(ng(true)));
    let row = a1;
    let mut kinds = Vec::new();
    for (ended, kick) in [(a2, false), (a3, true)] {
        drain(&mut r1);
        let device = device_of(&core, ended);
        if kick {
            core.kick_device(row, device).unwrap();
        } else {
            core.device_end(a1, device).unwrap();
        }
        core.end_session(ended);
        let told = drain(&mut r1);
        let Some(Event::PersonRow { devices, .. }) = told.last() else {
            panic!("{told:?}");
        };
        assert!(devices.iter().all(|d| d.device != device), "{told:?}");
        kinds.push(told.iter().map(Event::kind).collect::<Vec<_>>());
    }
    assert_eq!(kinds[0], kinds[1], "ended or kicked, it reads the same");
}

#[test]
fn a_viewer_with_the_kick_bit_sees_each_devices_login_and_address_and_nobody_else_does() {
    let core = Core::new().with_coalesce(true);
    let mut info = session("alice", Some(ALICE), Some(ALICE), proved(ng(true)));
    info.addr = Some("192.0.2.7".parse().unwrap());
    let (a1, mut r1) = on(&core, info);
    let (m, mut rm) = other(&core, "mod", ng(true), true);
    drain(&mut r1);
    drain(&mut rm);
    let mut info = session("alice", Some(ALICE), Some(ALICE), proved(ng(true)));
    info.addr = Some("198.51.100.9".parse().unwrap());
    let (_a2, _r2) = on(&core, info);
    let row = a1;
    let details = |rx: &mut Events| -> Vec<(Option<String>, Option<String>)> {
        drain(rx)
            .into_iter()
            .rev()
            .find_map(|e| match e {
                Event::PersonRow { devices, .. } => Some(devices),
                _ => None,
            })
            .unwrap()
            .iter()
            .map(|d| (d.login.clone(), d.addr.map(|a| a.to_string())))
            .collect()
    };
    assert_eq!(
        details(&mut rm),
        [
            (Some("alice".into()), Some("192.0.2.7".into())),
            (Some("alice".into()), Some("198.51.100.9".into())),
        ],
        "a moderator, told of the change"
    );
    assert_eq!(
        details(&mut r1),
        [(None, None), (None, None)],
        "its own device, which may not kick"
    );
    let r = core.roster.lock().unwrap();
    assert!(r
        .devices_for(m, row)
        .unwrap()
        .iter()
        .all(|d| d.login.is_some() && d.addr.is_some()));
    assert!(r
        .devices_for(a1, row)
        .unwrap()
        .iter()
        .all(|d| d.login.is_none() && d.addr.is_none()));
}

#[test]
fn a_device_that_never_declared_persons_is_ended_as_kicked() {
    let core = Core::new().with_coalesce(true);
    let (a1, _r1) = alice(&core, proved(ng(true)));
    let (plain, mut rp) = alice(&core, proved(ng(false)));
    let (classic, mut rc) = alice(&core, proved(Transport::default()));
    drain(&mut rp);
    drain(&mut rc);
    for (uid, rx) in [(plain, &mut rp), (classic, &mut rc)] {
        core.device_end(a1, device_of(&core, uid)).unwrap();
        assert_eq!(ends(rx), [Event::Kicked], "{uid}");
    }
}

#[test]
fn a_request_from_a_device_already_ended_is_no_flood_of_its_own() {
    let core = Core::new().with_coalesce(true);
    let (a1, _r1) = alice(&core, proved(ng(true)));
    let (a2, _r2) = alice(&core, proved(ng(true)));
    core.device_end(a1, device_of(&core, a2)).unwrap();
    let refused = core.spend_spam(a2, 2, 0x69).unwrap_err();
    assert!(refused.already_out(), "{refused:?}");
}

#[test]
fn a_detached_device_that_loses_the_kick_bit_replays_its_own_devices_without_their_details() {
    let core = Core::new().with_coalesce(true);
    let mut info = session("alice", Some(ALICE), Some(ALICE), proved(ng(true)));
    info.access = info.access.with(bit::DISCONNECT_USERS);
    info.addr = Some("192.0.2.7".parse().unwrap());
    let (a1, mut r1) = on(&core, info);
    drain(&mut r1);
    let seq = core.current_seq(a1).unwrap();
    assert!(core.connection_lost(a1, usize::MAX));
    let (_a2, _r2) = alice(&core, proved(ng(true)));
    assert!(core.set_session_mask(
        a1,
        crate::DenyMask {
            access: AccessBits::empty().with(bit::DISCONNECT_USERS),
            ..Default::default()
        }
    ));
    let crate::Resume::Replayed(_, replay) = core.resume(a1, seq) else {
        panic!("held for its resume");
    };
    let own: Vec<&Device> = replay
        .iter()
        .filter_map(|se| match &se.event {
            Event::PersonRow { user, devices, .. } if user.uid == a1 => Some(devices.iter()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(!own.is_empty(), "{replay:?}");
    assert!(
        own.iter().all(|d| d.login.is_none() && d.addr.is_none()),
        "{own:?}"
    );
}

/// A device that proved identity `fingerprint` with device key `device`.
fn proved_as(fingerprint: [u8; 32], device: u8) -> Transport {
    let mut t = proved(ng(false));
    if let Some(id) = t.identity.as_mut() {
        id.fingerprint = fingerprint;
        id.device = [device; 32];
    }
    t
}

#[test]
fn a_session_ended_or_kicked_is_remembered_so_and_one_that_lapsed_or_rotated_is_not() {
    use crate::ending::EndedBy;
    let hour = std::time::Duration::from_secs(3600);
    for (case, coalesce) in [("coalescing", true), ("not coalescing", false)] {
        let core = Core::new().with_coalesce(coalesce);
        let away = |core: &Core, uid: Uid| {
            assert!(core.connection_lost(uid, usize::MAX));
            (uid, core.session_serial(uid).unwrap())
        };
        let (a1, _r1) = alice(&core, proved(ng(true)));
        let (a2, _r2) = alice(&core, proved(ng(true)));
        let (b, _rb) = other(&core, "bob", ng(false), false);
        let (c, _rc) = other(&core, "carol", ng(false), false);

        let kicked = away(&core, b);
        core.kick(b, None).unwrap();
        assert_eq!(
            core.ended_by(kicked.0, kicked.1, hour),
            Some(EndedBy::Kicked),
            "{case}"
        );

        let lapsed = away(&core, c);
        core.sweep_detached(std::time::Duration::ZERO);
        assert_eq!(
            core.ended_by(lapsed.0, lapsed.1, hour),
            None,
            "{case}: lapsed"
        );

        // Kicked while connected, and refused by a revocation, as told;
        // a key rotated away from is its successor's to log in with.
        let (d, _rd) = other(&core, "dave", ng(false), false);
        let live = (d, core.session_serial(d).unwrap());
        core.kick(d, None).unwrap();
        assert_eq!(
            core.ended_by(live.0, live.1, hour),
            Some(EndedBy::Kicked),
            "{case}: live"
        );
        let (e, _re) = on(
            &core,
            session("erin", Some([5; 32]), None, proved_as([5; 32], 5)),
        );
        let revoked = (e, core.session_serial(e).unwrap());
        core.set_revocations(crate::Revocations {
            devices: [[5; 32]].into(),
            ..Default::default()
        });
        assert_eq!(
            core.ended_by(revoked.0, revoked.1, hour),
            Some(EndedBy::Kicked),
            "{case}: revoked"
        );
        let (f, _rf) = on(
            &core,
            session("fay", Some([6; 32]), None, proved_as([6; 32], 6)),
        );
        let rotated = (f, core.session_serial(f).unwrap());
        core.refuse_rotated([6; 32]);
        assert_eq!(
            core.ended_by(rotated.0, rotated.1, hour),
            None,
            "{case}: rotated"
        );

        if coalesce {
            let ended = away(&core, a2);
            core.device_end(a1, device_of(&core, a2)).unwrap();
            assert_eq!(
                core.ended_by(ended.0, ended.1, hour),
                Some(EndedBy::Ended),
                "{case}"
            );
        }
    }
}
