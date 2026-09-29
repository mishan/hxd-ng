//! Domain-side avatar tests. The codec is a fake, as for inline media:
//! what these test is whose avatar it is, who hears about a change, and
//! what survives a session.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use crate::access::AccessBits;
use crate::roster::{AttachInfo, Transport};
use crate::Events;

/// Accepts anything non-empty. Its canonical bytes are the input
/// reversed, and its legacy GIF the input as given, so a test can tell
/// which rendition it holds.
struct FakeCodec;

impl MediaCodec for FakeCodec {
    fn canonicalize(&self, _input: &[u8]) -> Result<Canonical, MediaReject> {
        Err(MediaReject::Unsupported)
    }

    fn avatar(&self, input: &[u8], _limits: &AvatarLimits) -> Result<AvatarImages, MediaReject> {
        if input.is_empty() {
            return Err(MediaReject::Unsupported);
        }
        Ok(AvatarImages {
            canonical: Canonical {
                mime: MediaType::Png,
                width: 64,
                height: 48,
                bytes: input.iter().rev().copied().collect(),
            },
            legacy_gif: Some(input.to_vec()),
        })
    }
}

fn core() -> Core {
    Core::new().with_avatars(
        Arc::new(MemoryAvatars::default()),
        Arc::new(FakeCodec),
        AvatarPolicy {
            set_interval: Duration::ZERO,
            ..Default::default()
        },
    )
}

enum Who<'a> {
    Account(&'a str),
    Guest(Option<[u8; 32]>),
}

/// A visible session, with its owner's avatar restored as the frontends
/// do before announcing it.
fn join(core: &Core, who: Who) -> (Uid, Events) {
    join_from(core, who, IpAddr::V4(Ipv4Addr::LOCALHOST), true)
}

/// [`join`], from `addr`, with the account's `set_avatar` as given.
fn join_from(core: &Core, who: Who, addr: IpAddr, set_avatar: bool) -> (Uid, Events) {
    let (login, is_person, identity) = match who {
        Who::Account(login) => (login.to_string(), true, None),
        Who::Guest(identity) => ("guest".to_string(), false, identity),
    };
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: login.clone(),
            icon: 1,
            admin: false,
            access: AccessBits::empty(),
            login,
            addr: Some(addr),
            can_detach: false,
            transport: Transport::default(),
            has_inbox: false,
            attach_news: false,
            set_avatar,
            moderate: false,
            can_spam: false,
            is_person,
            reads_on_delivery: false,
            identity,
            system: false,
        })
        .unwrap();
    core.restore_avatar(uid);
    core.announce(uid);
    (uid, rx)
}

/// The avatar changes a session has been told about, in order.
fn changes(rx: &mut Events) -> Vec<(Uid, Option<AvatarRef>)> {
    let mut out = Vec::new();
    while let Ok(se) = rx.try_recv() {
        if let Event::AvatarChanged(info) = se.event {
            out.push((info.uid, info.avatar));
        }
    }
    out
}

fn user(core: &Core, uid: Uid) -> crate::roster::UserInfo {
    core.snapshot().into_iter().find(|u| u.uid == uid).unwrap()
}

#[test]
fn a_set_is_announced_to_everyone_and_shown_on_the_roster() {
    let core = core();
    let (alice, mut alice_rx) = join(&core, Who::Account("alice"));
    let (_bob, mut bob_rx) = join(&core, Who::Account("bob"));
    changes(&mut alice_rx);

    let meta = core.set_avatar(alice, b"GIF89a-alice").unwrap();
    assert_eq!(meta.id, AvatarId::of(b"ecila-a98FIG"));
    assert_eq!(user(&core, alice).avatar, Some(meta.clone()));
    assert_eq!(changes(&mut alice_rx), vec![(alice, Some(meta.clone()))]);
    assert_eq!(changes(&mut bob_rx), vec![(alice, Some(meta.clone()))]);

    let held = core.avatar_of(alice).unwrap();
    assert_eq!(&*held.bytes, b"ecila-a98FIG");
    assert_eq!(held.legacy_gif.as_deref(), Some(&b"GIF89a-alice"[..]));
    assert_eq!(core.avatars(), vec![(alice, held.clone())]);
    assert_eq!(core.avatar_by_id(&meta.id), Some(held));
}

#[test]
fn an_accounts_avatar_is_on_every_session_and_the_next_one() {
    let core = core();
    let (first, mut first_rx) = join(&core, Who::Account("alice"));
    let (second, mut second_rx) = join(&core, Who::Account("alice"));
    let (watcher, mut watcher_rx) = join(&core, Who::Account("bob"));
    changes(&mut first_rx);
    changes(&mut second_rx);

    let meta = core.set_avatar(first, b"picture").unwrap();
    assert_eq!(user(&core, second).avatar, Some(meta.clone()));
    // Each session's change is its own, and everyone hears both.
    let both = vec![(first, Some(meta.clone())), (second, Some(meta.clone()))];
    let mut heard = changes(&mut watcher_rx);
    heard.sort_by_key(|(uid, _)| *uid);
    assert_eq!(heard, both);

    core.end_session(first);
    core.end_session(second);
    // Stored, so a fetch by id still answers with nobody on the roster.
    assert!(core.avatar_by_id(&meta.id).is_some());

    // A new session joins with it, and nobody is told of a change: the
    // join carries the picture.
    let (third, _) = join(&core, Who::Account("alice"));
    assert_eq!(user(&core, third).avatar, Some(meta));
    assert!(changes(&mut watcher_rx).is_empty());
    let _ = watcher;
}

#[test]
fn a_guest_keeps_one_only_for_the_session_unless_it_proved_an_identity() {
    let core = core();
    let (guest, _) = join(&core, Who::Guest(None));
    let (other_guest, _) = join(&core, Who::Guest(None));
    core.set_avatar(guest, b"mine").unwrap();
    assert!(user(&core, other_guest).avatar.is_none(), "guest is shared");
    core.end_session(guest);
    let (next_guest, _) = join(&core, Who::Guest(None));
    assert!(user(&core, next_guest).avatar.is_none());

    let (keyed, _) = join(&core, Who::Guest(Some([4; 32])));
    let meta = core.set_avatar(keyed, b"keyed").unwrap();
    core.end_session(keyed);
    let (again, _) = join(&core, Who::Guest(Some([4; 32])));
    assert_eq!(user(&core, again).avatar, Some(meta));
    let (stranger, _) = join(&core, Who::Guest(Some([5; 32])));
    assert!(user(&core, stranger).avatar.is_none());
}

#[test]
fn a_clear_is_announced_once_and_clearing_nothing_is_quiet() {
    let core = core();
    let (alice, mut rx) = join(&core, Who::Account("alice"));
    assert_eq!(core.clear_avatar(alice), Ok(false));
    core.set_avatar(alice, b"picture").unwrap();
    changes(&mut rx);
    assert_eq!(core.clear_avatar(alice), Ok(true));
    assert_eq!(changes(&mut rx), vec![(alice, None)]);
    assert!(core.avatar_of(alice).is_none());
    assert_eq!(core.clear_avatar(alice), Ok(false));
    assert!(changes(&mut rx).is_empty());

    core.end_session(alice);
    let (back, _) = join(&core, Who::Account("alice"));
    assert!(user(&core, back).avatar.is_none(), "the clear was stored");
}

#[test]
fn changes_are_rationed_per_owner() {
    let core = Core::new().with_avatars(
        Arc::new(MemoryAvatars::default()),
        Arc::new(FakeCodec),
        AvatarPolicy::default(),
    );
    let (alice, _) = join(&core, Who::Account("alice"));
    let (alice_too, _) = join(&core, Who::Account("alice"));
    let (bob, _) = join(&core, Who::Account("bob"));
    let (guest, _) = join_from(&core, Who::Guest(None), v4(1), true);
    let (other_guest, _) = join_from(&core, Who::Guest(None), v4(2), true);
    core.set_avatar(alice, b"one").unwrap();
    assert_eq!(
        core.set_avatar(alice, b"two"),
        Err(MediaReject::RateLimited)
    );
    assert_eq!(core.clear_avatar(alice), Err(MediaReject::RateLimited));
    // Another session of the same account is the same owner.
    assert_eq!(
        core.set_avatar(alice_too, b"two"),
        Err(MediaReject::RateLimited)
    );
    assert_eq!(
        core.avatar_change_admits(alice_too),
        Err(MediaReject::RateLimited),
        "asked before the bytes are read"
    );
    for _ in 0..3 {
        assert_eq!(core.avatar_change_admits(bob), Ok(()), "and asking is free");
    }
    core.set_avatar(bob, b"one").unwrap();
    // Guests without an identity are each their own, one per address.
    core.set_avatar(guest, b"one").unwrap();
    core.set_avatar(other_guest, b"one").unwrap();
    assert_eq!(
        core.set_avatar(guest, b"two"),
        Err(MediaReject::RateLimited)
    );
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

#[test]
fn a_guests_turn_is_its_address_and_survives_a_reconnect() {
    let core = Core::new().with_avatars(
        Arc::new(MemoryAvatars::default()),
        Arc::new(FakeCodec),
        AvatarPolicy::default(),
    );
    let (guest, _) = join_from(&core, Who::Guest(None), v4(1), true);
    core.set_avatar(guest, b"one").unwrap();
    // Reconnecting is a new session, not a new turn.
    core.end_session(guest);
    let (back, _) = join_from(&core, Who::Guest(None), v4(1), true);
    assert_eq!(core.set_avatar(back, b"two"), Err(MediaReject::RateLimited));
    // Nor is a freshly minted identity from the same address.
    let (minted, _) = join_from(&core, Who::Guest(Some([6; 32])), v4(1), true);
    assert_eq!(
        core.set_avatar(minted, b"two"),
        Err(MediaReject::RateLimited)
    );
    // An IPv6 guest is its /64, which is what one subscriber holds.
    let net = |host: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host));
    let (here, _) = join_from(&core, Who::Guest(None), net(1), true);
    core.set_avatar(here, b"one").unwrap();
    let (next_door, _) = join_from(&core, Who::Guest(None), net(2), true);
    assert_eq!(
        core.set_avatar(next_door, b"two"),
        Err(MediaReject::RateLimited)
    );
    // Another address is another guest; an account is held by its
    // login alone, whoever else shares its address.
    let (elsewhere, _) = join_from(&core, Who::Guest(None), v4(2), true);
    core.set_avatar(elsewhere, b"one").unwrap();
    let (alice, _) = join_from(&core, Who::Account("alice"), v4(1), true);
    core.set_avatar(alice, b"one").unwrap();
}

#[test]
fn a_session_that_may_not_set_is_refused_before_anything_is_spent() {
    let core = Core::new().with_avatars(
        Arc::new(MemoryAvatars::default()),
        Arc::new(FakeCodec),
        AvatarPolicy::default(),
    );
    let (guest, mut rx) = join_from(&core, Who::Guest(None), v4(1), false);
    let (_watcher, mut watcher_rx) = join(&core, Who::Account("bob"));
    changes(&mut rx);
    assert_eq!(
        core.set_avatar(guest, b"one"),
        Err(MediaReject::NotAuthorized)
    );
    assert!(user(&core, guest).avatar.is_none());
    assert!(changes(&mut watcher_rx).is_empty(), "nothing announced");
    // Clearing is never refused, and there is nothing to clear.
    assert_eq!(core.clear_avatar(guest), Ok(false));
    // The refusal spent no turn: a guest on the same address that may
    // set one still can, inside the interval.
    let (allowed, _) = join_from(&core, Who::Guest(None), v4(1), true);
    core.set_avatar(allowed, b"one").unwrap();
    // An account whose file says no is refused the same way.
    let (kiosk, _) = join_from(&core, Who::Account("kiosk"), v4(3), false);
    assert_eq!(
        core.set_avatar(kiosk, b"one"),
        Err(MediaReject::NotAuthorized)
    );
}

#[test]
fn an_identitys_avatar_ages_out_once_it_stops_coming_back() {
    let core = core();
    let day = Duration::from_secs(24 * 3600);
    let (keyed, _) = join(&core, Who::Guest(Some([4; 32])));
    core.set_avatar(keyed, b"keyed").unwrap();
    let (alice, _) = join(&core, Who::Account("alice"));
    core.set_avatar(alice, b"alice").unwrap();
    let later = SystemTime::now() + 365 * day;
    // Still on the roster, so still seen: nothing goes.
    assert_eq!(core.prune_avatars(later), 0);
    core.end_session(keyed);
    core.end_session(alice);
    // Seen by that prune a year on, so a prune the same day keeps it.
    assert_eq!(core.prune_avatars(later), 0);
    assert_eq!(core.prune_avatars(later + 100 * day), 1);
    let (again, _) = join(&core, Who::Guest(Some([4; 32])));
    assert!(user(&core, again).avatar.is_none(), "the identity's went");
    let (alice, _) = join(&core, Who::Account("alice"));
    assert!(user(&core, alice).avatar.is_some(), "the account's stays");

    // Zero keeps an identity's for good.
    let forever = Core::new().with_avatars(
        Arc::new(MemoryAvatars::default()),
        Arc::new(FakeCodec),
        AvatarPolicy {
            set_interval: Duration::ZERO,
            identity_retention: Duration::ZERO,
            ..Default::default()
        },
    );
    let (keyed, _) = join(&forever, Who::Guest(Some([4; 32])));
    forever.set_avatar(keyed, b"keyed").unwrap();
    forever.end_session(keyed);
    assert_eq!(forever.prune_avatars(later + 100 * day), 0);
}

/// Ends the session it is decoding for, as a kick or a logout would
/// during a slow decode.
struct EndingCodec {
    core: std::sync::OnceLock<std::sync::Weak<Core>>,
    victim: std::sync::atomic::AtomicU16,
}

impl MediaCodec for EndingCodec {
    fn canonicalize(&self, _input: &[u8]) -> Result<Canonical, MediaReject> {
        Err(MediaReject::Unsupported)
    }

    fn avatar(&self, input: &[u8], limits: &AvatarLimits) -> Result<AvatarImages, MediaReject> {
        let core = self.core.get().unwrap().upgrade().unwrap();
        core.end_session(self.victim.load(std::sync::atomic::Ordering::SeqCst));
        FakeCodec.avatar(input, limits)
    }
}

#[test]
fn a_session_that_ends_during_the_decode_changes_nothing() {
    let store = Arc::new(MemoryAvatars::default());
    let codec = Arc::new(EndingCodec {
        core: Default::default(),
        victim: Default::default(),
    });
    let core = Arc::new(Core::new().with_avatars(
        store.clone(),
        codec.clone(),
        AvatarPolicy {
            set_interval: Duration::ZERO,
            ..Default::default()
        },
    ));
    codec.core.set(Arc::downgrade(&core)).unwrap();
    let (alice, _) = join(&core, Who::Account("alice"));
    codec
        .victim
        .store(alice, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(core.set_avatar(alice, b"late"), Err(MediaReject::Generic));
    assert_eq!(
        store.load(&AvatarOwner::Account("alice".into())).unwrap(),
        None,
        "nothing stored for a session that was gone"
    );
    // And a uid with no session at all is refused before any decode.
    assert_eq!(core.set_avatar(alice, b"x"), Err(MediaReject::Generic));
}

#[test]
fn uploads_past_the_ceiling_and_servers_without_avatars_are_refused() {
    let core = core();
    let (alice, _) = join(&core, Who::Account("alice"));
    let too_big = vec![0u8; AvatarPolicy::default().limits.max_bytes + 1];
    assert_eq!(core.set_avatar(alice, &too_big), Err(MediaReject::TooLarge));
    assert_eq!(core.set_avatar(alice, b""), Err(MediaReject::Unsupported));

    let bare = Core::new();
    let (uid, _) = join(&bare, Who::Account("alice"));
    assert_eq!(bare.set_avatar(uid, b"x"), Err(MediaReject::Unsupported));
    assert_eq!(bare.clear_avatar(uid), Err(MediaReject::Unsupported));
    assert!(bare.avatar_policy().is_none());
    assert!(bare.avatar_by_id(&AvatarId([0; 32])).is_none());
}

#[test]
fn ids_are_lowercase_hex_both_ways() {
    let id = AvatarId::of(b"abc");
    let text = id.to_string();
    assert_eq!(
        text,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(AvatarId::parse(&text), Some(id));
    assert_eq!(AvatarId::parse(&text.to_uppercase()), None);
    assert_eq!(AvatarId::parse(&text[1..]), None);
    assert_eq!(AvatarId::parse(&format!("{}g", &text[1..])), None);
}

#[test]
fn the_memory_store_conforms() {
    conformance::run(&|| Box::new(MemoryAvatars::default()));
}
