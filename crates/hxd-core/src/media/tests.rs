//! Domain-side media tests. No image is ever decoded here: the codec is
//! a fake that answers with fixed metadata, which is the point — what
//! these test is who may upload, who may fetch, how long a handle
//! lives, and what a relay captures.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::access::{bit, AccessBits};
use crate::roster::{AttachInfo, SeqEvent, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// A codec that decodes nothing and accepts anything non-empty. Its
/// "canonical" bytes are the input reversed, so a test can tell what
/// came out from what went in.
struct FakeCodec;

impl MediaCodec for FakeCodec {
    fn canonicalize(&self, input: &[u8]) -> Result<Canonical, MediaReject> {
        if input.is_empty() {
            return Err(MediaReject::Unsupported);
        }
        Ok(Canonical {
            mime: MediaType::Png,
            width: 8,
            height: 4,
            bytes: input.iter().rev().copied().collect(),
        })
    }
}

fn core_with(cfg: MediaConfig) -> Core {
    Core::new().with_media(Arc::new(FakeCodec), cfg)
}

/// The defaults, minus the interval between uploads: a test that starts
/// two uploads in a row is testing something other than the throttle,
/// which has a case of its own.
fn core() -> Core {
    core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        ..Default::default()
    })
}

/// A session that may send chat and media, on a wire that can carry a
/// reference.
fn attach(core: &Core, nick: &str, addr: Ipv4Addr) -> (Uid, UnboundedReceiver<SeqEvent>) {
    attach_with(core, nick, addr, true, true)
}

/// The same, for an account that has a mailbox — which is what makes a
/// private message take the durable path.
fn attach_boxed(core: &Core, nick: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: nick.into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty()
                .with(bit::READ_CHAT)
                .with(bit::SEND_CHAT)
                .with(bit::SEND_MSGS)
                .with(bit::SEND_MEDIA),
            login: nick.into(),
            addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            can_detach: false,
            transport: Transport {
                inline_media: true,
                ..Default::default()
            },
            has_inbox: true,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn attach_with(
    core: &Core,
    nick: &str,
    addr: Ipv4Addr,
    capable: bool,
    may_send: bool,
) -> (Uid, UnboundedReceiver<SeqEvent>) {
    let mut access = AccessBits::empty()
        .with(bit::READ_CHAT)
        .with(bit::SEND_CHAT)
        .with(bit::CREATE_PCHATS);
    if may_send {
        access = access.with(bit::SEND_MEDIA);
    }
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: nick.into(),
            icon: 1,
            admin: false,
            access,
            login: nick.into(),
            addr: Some(IpAddr::V4(addr)),
            can_detach: false,
            transport: Transport {
                inline_media: capable,
                ..Default::default()
            },
            has_inbox: false,
            is_person: false,
            reads_on_delivery: false,
            identity: None,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn upload(core: &Core, uid: Uid, bytes: &[u8]) -> Result<MediaRef, MediaReject> {
    match core.media_upload_part(
        uid,
        UploadPart {
            payload: bytes,
            declared: None,
            token: None,
            index: 0,
            count: None,
            last: true,
        },
    )? {
        UploadOutcome::Done(m) => Ok(m),
        UploadOutcome::Token(_) => panic!("a single-shot upload answered with a token"),
    }
}

fn part<'a>(
    payload: &'a [u8],
    token: Option<Handle>,
    index: u16,
    count: Option<u16>,
    last: bool,
) -> UploadPart<'a> {
    UploadPart {
        payload,
        declared: None,
        token,
        index,
        count,
        last,
    }
}

fn token_of(outcome: UploadOutcome) -> Handle {
    match outcome {
        UploadOutcome::Token(t) => t,
        other => panic!("expected a token, got {other:?}"),
    }
}

fn chat_media(events: &[crate::roster::Event]) -> Option<MediaRef> {
    events.iter().find_map(|e| match e {
        crate::roster::Event::Chat { media, .. } => media.clone(),
        _ => None,
    })
}

fn drain(rx: &mut UnboundedReceiver<SeqEvent>) -> Vec<crate::roster::Event> {
    let mut out = Vec::new();
    while let Ok(se) = rx.try_recv() {
        out.push(se.event);
    }
    out
}

#[test]
fn an_upload_needs_the_send_media_bit() {
    let core = core();
    let (uid, _rx) = attach_with(&core, "alice", Ipv4Addr::LOCALHOST, true, false);
    // The spec has operators grant it explicitly, so an account file
    // that says nothing says no.
    assert_eq!(
        upload(&core, uid, b"hello"),
        Err(MediaReject::NotAuthorized)
    );
}

#[test]
fn a_relay_captures_the_capable_recipients_and_nobody_else() {
    let core = core();
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (bob, mut rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    // Carol is on a wire that cannot carry the reference — a 1.5 client
    // that never negotiated bit 3. She sees the line and not the image.
    let (carol, mut rc) = attach_with(&core, "carol", Ipv4Addr::LOCALHOST, false, true);

    let media = upload(&core, alice, b"an image").unwrap();
    let handle = media.id.unwrap();
    core.chat_public(alice, "look".into(), 0, Some(handle))
        .unwrap();

    let to_bob = chat_media(&drain(&mut rb)).expect("bob's line carries the reference");
    assert_eq!(to_bob.id, Some(handle));
    // The event carries it either way — the *frontends* strip per
    // connection — but only a capable recipient was captured, and the
    // set is what a download is checked against.
    let _ = drain(&mut rc);
    let bob_who = core.principal_of(bob).unwrap();
    let carol_who = core.principal_of(carol).unwrap();
    assert!(core.media_fetch_as(&bob_who, &handle).is_some());
    assert!(
        core.media_fetch_as(&carol_who, &handle).is_none(),
        "a session that was not shown the image cannot fetch it"
    );

    // And the bytes are the canonical ones, not what was uploaded.
    let fetched = core.media_fetch_as(&bob_who, &handle).unwrap();
    assert_eq!(fetched.bytes.as_ref().as_slice(), b"egami na");
    assert_eq!(fetched.mime, MediaType::Png);
}

#[test]
fn only_the_uploader_may_attach_a_handle() {
    let core = core();
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (bob, mut rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    let handle = upload(&core, alice, b"an image").unwrap().id.unwrap();

    // Bob saw the handle go past on a chat line; that does not make it
    // his to republish.
    core.chat_public(alice, "look".into(), 0, Some(handle))
        .unwrap();
    let _ = drain(&mut rb);
    assert_eq!(
        core.chat_public(bob, "mine now".into(), 0, Some(handle)),
        Err(crate::ChatError::NoSuchMedia)
    );
    // And a handle that never existed answers the same way, so a send
    // cannot be used to test whether one does.
    assert_eq!(
        core.chat_public(bob, "?".into(), 0, Some([0u8; HANDLE_LEN])),
        Err(crate::ChatError::NoSuchMedia)
    );
}

#[test]
fn a_chunked_upload_assembles_in_order_and_refuses_everything_else() {
    let core = core();
    let (alice, _rx) = attach(&core, "alice", Ipv4Addr::LOCALHOST);

    let token = token_of(
        core.media_upload_part(alice, part(b"first ", None, 0, Some(3), false))
            .unwrap(),
    );
    // An out-of-order part discards the whole session rather than being
    // reordered: a client that cannot count its own chunks is one whose
    // bytes should not be assembled on trust.
    assert_eq!(
        core.media_upload_part(alice, part(b"third", Some(token), 2, None, true)),
        Err(MediaReject::Generic)
    );
    assert_eq!(
        core.media_upload_part(alice, part(b"second", Some(token), 1, None, false)),
        Err(MediaReject::Generic),
        "the session went with the bad part"
    );

    // A clean run of the same shape.
    let token = token_of(
        core.media_upload_part(alice, part(b"ab", None, 0, Some(3), false))
            .unwrap(),
    );
    core.media_upload_part(alice, part(b"cd", Some(token), 1, None, false))
        .unwrap();
    match core
        .media_upload_part(alice, part(b"ef", Some(token), 2, None, true))
        .unwrap()
    {
        UploadOutcome::Done(m) => {
            let who = core.principal_of(alice).unwrap();
            let fetched = core.media_fetch_as(&who, &m.id.unwrap()).unwrap();
            assert_eq!(fetched.bytes.as_ref().as_slice(), b"fedcba");
        }
        other => panic!("expected a handle, got {other:?}"),
    }
}

#[test]
fn an_upload_session_belongs_to_the_account_that_opened_it() {
    let core = core();
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (bob, _rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    let token = token_of(
        core.media_upload_part(alice, part(b"ab", None, 0, Some(2), false))
            .unwrap(),
    );
    // A token is a bearer credential for one upload, and holding one
    // must not let someone else finish it.
    assert_eq!(
        core.media_upload_part(bob, part(b"cd", Some(token), 1, None, true)),
        Err(MediaReject::NotAuthorized)
    );
}

#[test]
fn the_upload_quotas_hold() {
    let core = core_with(MediaConfig {
        upload_interval: Duration::from_secs(60),
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    upload(&core, alice, b"one").unwrap();
    assert_eq!(
        upload(&core, alice, b"two"),
        Err(MediaReject::RateLimited),
        "the interval between one account's uploads"
    );

    // Per hour, per account. Every guest shares the `guest` account's
    // bucket deliberately — the shared door is the one that needs the
    // throttle most.
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        upload_per_hour: 2,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    upload(&core, alice, b"one").unwrap();
    upload(&core, alice, b"two").unwrap();
    assert_eq!(
        upload(&core, alice, b"three"),
        Err(MediaReject::RateLimited)
    );

    // Per hour, per address: what tells two guests apart.
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        upload_per_hour_per_addr: 1,
        ..Default::default()
    });
    let here = Ipv4Addr::new(10, 0, 0, 7);
    let (alice, _ra) = attach(&core, "alice", here);
    let (bob, _rb) = attach(&core, "bob", here);
    upload(&core, alice, b"one").unwrap();
    assert_eq!(upload(&core, bob, b"two"), Err(MediaReject::RateLimited));
}

#[test]
fn an_assembled_upload_cannot_exceed_the_cap() {
    let core = core_with(MediaConfig {
        max_bytes: 8,
        upload_interval: Duration::ZERO,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    assert_eq!(
        upload(&core, alice, &[0u8; 9]),
        Err(MediaReject::TooLarge),
        "single-shot"
    );
    let token = token_of(
        core.media_upload_part(alice, part(&[0u8; 6], None, 0, Some(2), false))
            .unwrap(),
    );
    assert_eq!(
        core.media_upload_part(alice, part(&[0u8; 6], Some(token), 1, None, true)),
        Err(MediaReject::TooLarge),
        "the cap is on the assembled payload, not on one part"
    );
}

#[test]
fn a_handle_dies_with_its_ttl() {
    let core = core_with(MediaConfig {
        handle_ttl: Duration::ZERO,
        upload_interval: Duration::ZERO,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let media = upload(&core, alice, b"an image").unwrap();
    let handle = media.id.unwrap();
    let who = core.principal_of(alice).unwrap();

    // Expiry is checked on access, not only by the sweeper, so nothing
    // is served between sweeps that a sweep would have taken.
    assert!(core.media_fetch_as(&who, &handle).is_none());
    // The metadata outlives the bytes, without the handle: a line that
    // referenced it still renders a placeholder.
    let stale = core.media_meta(&handle).unwrap();
    assert_eq!(stale.id, None);
    assert_eq!((stale.width, stale.height), (8, 4));
    // And it cannot be attached to anything new.
    assert_eq!(
        core.chat_public(alice, "look".into(), 0, Some(handle)),
        Err(crate::ChatError::NoSuchMedia)
    );
    assert_eq!(core.media_sweep(), 1);
    assert!(core.media_meta(&handle).is_none());
}

#[test]
fn the_total_cap_evicts_the_oldest() {
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        // Room for two of the three-byte canonical images below.
        max_total_bytes: 7,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let first = upload(&core, alice, b"one").unwrap().id.unwrap();
    let second = upload(&core, alice, b"two").unwrap().id.unwrap();
    let third = upload(&core, alice, b"six").unwrap().id.unwrap();
    // Evicting the oldest beats refusing the newest: the spec lets a
    // server drop handles early, and the quotas are the real bound on a
    // hostile uploader.
    assert!(core.media_meta(&first).is_none(), "the oldest went");
    assert!(core.media_meta(&second).is_some());
    assert!(core.media_meta(&third).is_some());
}

#[test]
fn a_revocation_drops_the_bytes_tells_the_room_and_blocks_the_file() {
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (bob, mut rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    let handle = upload(&core, alice, b"an image").unwrap().id.unwrap();
    core.chat_public(alice, "look".into(), 0, Some(handle))
        .unwrap();
    let _ = drain(&mut rb);
    let bob_who = core.principal_of(bob).unwrap();
    assert!(core.media_fetch_as(&bob_who, &handle).is_some());

    let reference = core.media_revoke(&handle, true).expect("a live handle");
    assert_eq!(reference.id, None);
    assert_eq!((reference.width, reference.height), (8, 4));
    assert!(
        core.media_fetch_as(&bob_who, &handle).is_none(),
        "an in-flight download stops on its next part"
    );
    // Everyone who could have it on screen is told.
    assert!(drain(&mut rb)
        .iter()
        .any(|e| matches!(e, crate::roster::Event::MediaRevoked { id } if *id == handle)));
    // The metadata stays, so the line that carried it still renders a
    // placeholder rather than nothing.
    assert_eq!(core.media_meta(&handle).map(|m| m.id), Some(None));

    // And the same file cannot come back. The hash is of the canonical
    // bytes, so the same source re-uploaded is caught and a recompressed
    // one is not — a nuisance filter, and it says so.
    assert_eq!(upload(&core, alice, b"an image"), Err(MediaReject::Generic));
    upload(&core, alice, b"a different image").expect("a different file is fine");
}

#[test]
fn a_reported_handle_can_outlive_its_ttl() {
    // The one widening moderation is allowed (moderation.md §4.3): a
    // moderator cannot judge an image that expired while the report sat
    // in a queue.
    let core = core_with(MediaConfig {
        handle_ttl: Duration::ZERO,
        upload_interval: Duration::ZERO,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (carol, _rc) = attach(&core, "carol", Ipv4Addr::LOCALHOST);
    let handle = upload(&core, alice, b"an image").unwrap().id.unwrap();

    assert!(core.media_pin(&handle, Duration::from_secs(600)));
    assert!(core.media_grant(&handle, core.principal_of(carol).unwrap()));
    let who = core.principal_of(carol).unwrap();
    assert!(
        core.media_fetch_as(&who, &handle).is_some(),
        "a pinned handle is fetchable by a moderator added to its set"
    );
    assert_eq!(core.media_sweep(), 0, "a pin survives the sweeper");
}

#[test]
fn a_private_room_captures_its_members_at_that_moment() {
    let core = core();
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let (bob, mut rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    let (dave, _rd) = attach(&core, "dave", Ipv4Addr::LOCALHOST);
    let (cid, _) = core.chat_create(alice, bob).unwrap();
    core.chat_join(cid, bob, "").unwrap();

    let handle = upload(&core, alice, b"an image").unwrap().id.unwrap();
    core.chat_private(cid, alice, "look".into(), 0, Some(handle))
        .unwrap();
    assert!(chat_media(&drain(&mut rb)).is_some());
    assert!(core.media_fetch(bob, &handle).is_some());

    // Dave joins afterwards. Nothing is added to a set after the relay,
    // and he did not receive that line.
    core.chat_join(cid, dave, "").unwrap();
    assert!(core.media_fetch(dave, &handle).is_none());
}

#[test]
fn a_grant_on_a_mailbox_survives_the_session_that_made_it() {
    // A session's uploads are the session's; a grant to a mailbox is the
    // account's. This is what lets a private message's image be read by
    // whatever session of that mailbox eventually collects it.
    let core = core();
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let handle = upload(&core, alice, b"an image").unwrap().id.unwrap();
    let mailbox = crate::inbox::Mailbox::login("bob");
    assert!(core.media_grant(&handle, Principal::Mailbox(mailbox.clone())));

    core.end_session(alice);
    let (bob, _rb) = attach(&core, "bob", Ipv4Addr::LOCALHOST);
    // A session is not its account here: this roster entry has no
    // mailbox of its own (`has_inbox` is false), so the grant is what
    // the fetch presents.
    assert!(core.media_fetch(bob, &handle).is_none());
    assert!(core
        .media_fetch_as(&Principal::Mailbox(mailbox), &handle)
        .is_some());
}

#[test]
fn handles_spell_the_same_both_ways() {
    let raw = [
        0x00, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
        0xe0,
    ];
    let spelled = handle_str(&raw);
    assert_eq!(spelled.len(), 22, "sixteen bytes, unpadded base64url");
    assert!(!spelled.contains('+') && !spelled.contains('/') && !spelled.contains('='));
    assert_eq!(handle_from_str(&spelled), Some(raw));
    // Anything that is not exactly a handle is not one: a shorter path
    // segment must not become a shorter key.
    assert_eq!(handle_from_str(&spelled[..21]), None);
    assert_eq!(handle_from_str(""), None);
    assert_eq!(handle_from_str("!!!"), None);
    assert_eq!(handle_prefix(&raw), spelled[..6]);
}

/// A directory that knows a fixed set of logins, so `msg_login` can find
/// a mailbox for one of them.
struct Directory(Vec<crate::inbox::Mailbox>);

impl crate::AccountDirectory for Directory {
    fn inbox_account(&self, login: &str) -> Option<crate::inbox::Mailbox> {
        let l = login.to_ascii_lowercase();
        self.0.iter().find(|m| m.login == l).cloned()
    }

    fn mailbox_access(&self, who: &crate::inbox::Mailbox) -> Option<crate::AccessBits> {
        self.0
            .iter()
            .any(|m| who.matches(&m.login, m.fingerprint.as_ref()))
            .then(crate::AccessBits::empty)
    }
}

/// A core that has both an inbox and media, which is what a refused
/// private message needs to be one.
fn core_with_inbox(logins: &[&str], policy: crate::InboxPolicy) -> Core {
    let dir = Arc::new(Directory(
        logins
            .iter()
            .map(|l| crate::inbox::Mailbox::login(*l))
            .collect(),
    ));
    Core::new()
        .with_inbox(
            Arc::new(crate::inbox::memory::MemoryStore::new()),
            dir,
            policy,
        )
        .with_media(
            Arc::new(FakeCodec),
            MediaConfig {
                upload_interval: Duration::ZERO,
                ..Default::default()
            },
        )
}

#[test]
fn a_refused_message_captures_nobody() {
    // The audience is what a *relay* showed someone, and a send that
    // came back an error relayed nothing. Capturing before the store
    // could refuse left the recipient a grant on an image they were
    // never sent — and the set is only ever extended, so it never went
    // away again.
    let core = core_with_inbox(
        &["alice", "dave"],
        crate::InboxPolicy {
            max_queued: 1,
            ..Default::default()
        },
    );
    let (alice, _ra) = attach_boxed(&core, "alice");
    let dave = Principal::Mailbox(crate::inbox::Mailbox::login("dave"));

    let first = upload(&core, alice, b"one").unwrap().id.unwrap();
    core.msg_login(alice, "dave", "look".into(), None, Some(first))
        .expect("the mailbox has room for one");
    assert!(
        core.media_fetch_as(&dave, &first).is_some(),
        "a message that was stored grants the mailbox that will read it"
    );

    let second = upload(&core, alice, b"two").unwrap().id.unwrap();
    assert_eq!(
        core.msg_login(alice, "dave", "and this".into(), None, Some(second)),
        Err(crate::chat::ChatError::MailboxFull),
    );
    assert!(
        core.media_fetch_as(&dave, &second).is_none(),
        "the message was refused, so its image was never shown to anyone"
    );
}

#[test]
fn a_pinned_handle_is_not_what_eviction_reaches_for() {
    // A pin is old by construction — a report on an image posted a while
    // ago — so it sits at the front of the eviction order, which is
    // exactly where oldest-first looks first. The next upload would drop
    // the evidence the pin exists to keep.
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        // Room for two of the three-byte canonical images below.
        max_total_bytes: 7,
        ..Default::default()
    });
    let (alice, _ra) = attach(&core, "alice", Ipv4Addr::LOCALHOST);
    let reported = upload(&core, alice, b"one").unwrap().id.unwrap();
    assert!(core.media_pin(&reported, Duration::from_secs(600)));
    let second = upload(&core, alice, b"two").unwrap().id.unwrap();
    let third = upload(&core, alice, b"six").unwrap().id.unwrap();

    assert!(
        core.media_meta(&reported).and_then(|m| m.id).is_some(),
        "the pinned handle kept its bytes"
    );
    assert!(
        core.media_meta(&second).and_then(|m| m.id).is_none(),
        "the oldest unpinned one went instead"
    );
    assert!(core.media_meta(&third).and_then(|m| m.id).is_some());
}

#[test]
fn a_quota_refused_by_the_address_does_not_spend_the_account() {
    // The two buckets are asked before either is charged. Charging the
    // account first meant two guests behind one address could drain the
    // shared `guest` hour without a single upload landing.
    let core = core_with(MediaConfig {
        upload_interval: Duration::ZERO,
        // One apiece, so the slot a refused attempt used to spend is the
        // only slot there was.
        upload_per_hour: 1,
        upload_per_hour_per_addr: 1,
        ..Default::default()
    });
    let here = Ipv4Addr::new(10, 0, 0, 7);
    let (alice, _ra) = attach(&core, "alice", here);
    let (bob, _rb) = attach(&core, "bob", here);
    upload(&core, alice, b"one").unwrap();
    assert_eq!(
        upload(&core, bob, b"two"),
        Err(MediaReject::RateLimited),
        "the address is full"
    );
    // Bob's own hour is untouched by the attempt the address refused, so
    // he can still upload from somewhere else.
    let (bob_elsewhere, _rb2) = attach(&core, "bob", Ipv4Addr::new(10, 0, 0, 8));
    upload(&core, bob_elsewhere, b"three").expect("the refusal cost bob's account nothing");
}
