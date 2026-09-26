//! Domain-side avatar tests. The codec is a fake, as for inline media:
//! what these test is whose avatar it is, who hears about a change, and
//! what survives a session.

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::access::AccessBits;
use crate::roster::{AttachInfo, SeqEvent, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

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
fn join(core: &Core, who: Who) -> (Uid, UnboundedReceiver<SeqEvent>) {
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
            addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            can_detach: false,
            transport: Transport::default(),
            has_inbox: false,
            attach_news: false,
            moderate: false,
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
fn changes(rx: &mut UnboundedReceiver<SeqEvent>) -> Vec<(Uid, Option<AvatarRef>)> {
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
    let (guest, _) = join(&core, Who::Guest(None));
    let (other_guest, _) = join(&core, Who::Guest(None));
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
    core.set_avatar(bob, b"one").unwrap();
    // Guests without an identity are each their own.
    core.set_avatar(guest, b"one").unwrap();
    core.set_avatar(other_guest, b"one").unwrap();
    assert_eq!(
        core.set_avatar(guest, b"two"),
        Err(MediaReject::RateLimited)
    );
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
