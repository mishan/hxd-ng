//! A suite every [`PushStore`] must pass.
//!
//! Two implementations, one set of answers: the in-memory registry the
//! domain's tests run on and the SQLite one a server keeps its devices
//! in. Public, like [`crate::inbox::conformance`], because the
//! implementation it most needs to check is in another crate. Times are
//! whole seconds, because the SQLite store keeps whole seconds, and
//! never the wall clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Device, DeviceId, PushStore, Registered, SidecarRecord};

/// The cap the cases register under, where the cap is not the subject.
const CAP: usize = 8;
use crate::inbox::Mailbox;

/// Run every case against a freshly built store.
pub fn run(new_store: &dyn Fn() -> Box<dyn PushStore>) {
    a_device_is_found_by_its_owner_and_replaced_by_its_key(&*new_store());
    the_two_kinds_of_mailbox_never_meet(&*new_store());
    an_expired_certificate_is_not_pushed_at_and_then_swept(&*new_store());
    a_send_stamps_the_device_it_reached(&*new_store());
    unregistering_takes_one_or_all(&*new_store());
    linking_claims_and_deleting_purges(&*new_store());
    rotation_drops_what_the_successor_never_vouched_for(&*new_store());
    a_mailbox_holds_a_bounded_number_of_devices(&*new_store());
    a_gone_answer_retires_only_the_endpoint_it_was_about(&*new_store());
    a_rekey_clears_every_mailbox(&*new_store());
    expiry_is_at_the_instant_not_after_it(&*new_store());
    taking_all_of_one_kind_leaves_the_other(&*new_store());
    claiming_touches_only_that_login(&*new_store());
    an_identified_device_is_the_fingerprints_whatever_the_login(&*new_store());
    a_stamp_never_crosses_kinds(&*new_store());
    a_registration_answers_with_what_it_took(&*new_store());
    a_delivery_point_lasts_as_long_as_its_subscription(&*new_store());
    a_delivery_point_is_written_only_over_its_own_subscription(&*new_store());
    a_pruned_device_is_retired_by_its_delivery_point(&*new_store());
    a_lost_delivery_point_is_cleared_and_listed_again(&*new_store());
    linking_moves_a_row_out_from_under_its_delivery_point(&*new_store());
    the_sidecar_record_is_kept(&*new_store());
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn bob() -> Mailbox {
    Mailbox::login("bob")
}

fn fp() -> [u8; 32] {
    [7; 32]
}

fn devid(s: &str) -> DeviceId {
    DeviceId::parse(s).expect("a test id is a valid one")
}

fn device(owner: Mailbox, id: &str, endpoint: &str, at: u64) -> Device {
    Device {
        owner,
        devid: devid(id),
        endpoint: endpoint.into(),
        p256dh: [4; 65],
        auth: [9; 16],
        expires: None,
        registered_at: t(at),
        last_push_at: None,
        delivery_point: None,
    }
}

fn a_device_is_found_by_its_owner_and_replaced_by_its_key(s: &dyn PushStore) {
    let phone = device(bob(), "phone-install", "https://push.example/1", 100);
    assert_eq!(
        s.register(&phone, CAP).unwrap().0,
        Registered::Added,
        "nothing to replace"
    );
    let laptop = device(bob(), "laptop-install", "https://push.example/2", 101);
    assert_eq!(s.register(&laptop, CAP).unwrap().0, Registered::Added);
    assert_eq!(
        s.devices(&bob(), t(102))
            .unwrap()
            .iter()
            .map(|d| d.devid.as_str().to_string())
            .collect::<Vec<_>>(),
        ["laptop-install", "phone-install"],
        "newest registration first"
    );

    // The distributor re-provisions: same device, new endpoint. One row,
    // not two, which is the whole reason the key is ours.
    let moved = device(bob(), "phone-install", "https://push.example/3", 200);
    assert_eq!(
        s.register(&moved, CAP).unwrap().0,
        Registered::Replaced,
        "it replaced a row"
    );
    let rows = s.devices(&bob(), t(201)).unwrap();
    assert_eq!(rows.len(), 2);
    let phone = rows
        .iter()
        .find(|d| d.devid == devid("phone-install"))
        .unwrap();
    assert_eq!(phone.endpoint, "https://push.example/3");
    assert_eq!(phone.registered_at, t(200));

    // Somebody else's device is not bob's.
    s.register(
        &device(
            Mailbox::login("carol"),
            "carols-phone",
            "https://push.example/4",
            202,
        ),
        CAP,
    )
    .unwrap();
    assert_eq!(s.devices(&bob(), t(203)).unwrap().len(), 2);
}

fn the_two_kinds_of_mailbox_never_meet(s: &dyn PushStore) {
    let by_login = Mailbox::login("bob");
    let by_fp = Mailbox::identified("bob", fp());
    s.register(
        &device(by_login.clone(), "same-devid-x", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(by_fp.clone(), "same-devid-x", "https://b.example/1", 101),
        CAP,
    )
    .unwrap();

    // The same login and the same devid, and still two devices: an
    // identified mailbox never claims an unidentified row.
    assert_eq!(s.devices(&by_login, t(102)).unwrap().len(), 1);
    assert_eq!(s.devices(&by_fp, t(102)).unwrap().len(), 1);
    assert_eq!(
        s.devices(&by_fp, t(102)).unwrap()[0].endpoint,
        "https://b.example/1"
    );
    assert!(s
        .unregister(&by_fp, &devid("same-devid-x"))
        .unwrap()
        .is_some());
    assert_eq!(s.devices(&by_login, t(103)).unwrap().len(), 1, "untouched");
}

fn an_expired_certificate_is_not_pushed_at_and_then_swept(s: &dyn PushStore) {
    let mut certified = device(bob(), "identity-devi", "https://a.example/1", 100);
    certified.expires = Some(t(500));
    s.register(&certified, CAP).unwrap();
    s.register(
        &device(bob(), "password-devi", "https://a.example/2", 101),
        CAP,
    )
    .unwrap();

    assert_eq!(s.devices(&bob(), t(499)).unwrap().len(), 2);
    assert_eq!(
        s.devices(&bob(), t(501))
            .unwrap()
            .iter()
            .map(|d| d.devid.as_str().to_string())
            .collect::<Vec<_>>(),
        ["password-devi"],
        "a lapsed certificate stops being pushed at without a sweep"
    );

    assert!(s.sweep_expired(t(499)).unwrap().is_empty());
    assert_eq!(
        s.sweep_expired(t(501)).unwrap()[0].devid,
        devid("identity-devi")
    );
    assert!(
        s.sweep_expired(t(900)).unwrap().is_empty(),
        "nothing left to take"
    );
    assert_eq!(s.devices(&bob(), t(900)).unwrap().len(), 1);
}

fn a_send_stamps_the_device_it_reached(s: &dyn PushStore) {
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    assert_eq!(s.devices(&bob(), t(101)).unwrap()[0].last_push_at, None);
    s.touch(&bob(), &devid("phone-install"), t(200)).unwrap();
    assert_eq!(
        s.devices(&bob(), t(201)).unwrap()[0].last_push_at,
        Some(t(200))
    );

    // Stamping something that is not there is not an error: the gateway
    // races a client that just unregistered, and losing that race costs
    // a timestamp.
    s.touch(&bob(), &devid("gone-already"), t(202)).unwrap();

    // A re-registration is a new subscription, so the stamp goes.
    s.register(
        &device(bob(), "phone-install", "https://a.example/9", 300),
        CAP,
    )
    .unwrap();
    assert_eq!(s.devices(&bob(), t(301)).unwrap()[0].last_push_at, None);
}

fn unregistering_takes_one_or_all(s: &dyn PushStore) {
    for (i, id) in ["one-install!", "two-install!", "three-instal"]
        .iter()
        .enumerate()
    {
        s.register(
            &device(bob(), id, "https://a.example/1", 100 + i as u64),
            CAP,
        )
        .unwrap();
    }
    assert_eq!(
        s.unregister(&bob(), &devid("two-install!"))
            .unwrap()
            .map(|d| d.devid),
        Some(devid("two-install!"))
    );
    assert!(
        s.unregister(&bob(), &devid("two-install!"))
            .unwrap()
            .is_none(),
        "and it is gone, which the second call says"
    );
    assert_eq!(s.devices(&bob(), t(200)).unwrap().len(), 2);
    assert_eq!(s.unregister_all(&bob()).unwrap().len(), 2);
    assert!(s.unregister_all(&bob()).unwrap().is_empty());
    assert!(s.devices(&bob(), t(201)).unwrap().is_empty());
}

fn linking_claims_and_deleting_purges(s: &dyn PushStore) {
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(bob(), "laptop-instal", "https://a.example/2", 101),
        CAP,
    )
    .unwrap();
    // The phone has already registered under the identity — it logged in
    // with its certificate before the account was linked.
    s.register(
        &device(
            Mailbox::identified("bob", fp()),
            "phone-install",
            "https://a.example/3",
            102,
        ),
        CAP,
    )
    .unwrap();

    let taken = s.devices_claim("bob", &fp()).unwrap();
    assert_eq!(taken.len(), 2, "both login rows");
    assert!(
        taken.iter().all(|d| d.owner == bob()),
        "as they were, under the login"
    );
    let rows = s
        .devices(&Mailbox::identified("bob", fp()), t(200))
        .unwrap();
    assert_eq!(rows.len(), 2, "the laptop moved, the phone did not double");
    let phone = rows
        .iter()
        .find(|d| d.devid == devid("phone-install"))
        .unwrap();
    assert_eq!(
        phone.endpoint, "https://a.example/3",
        "the identity's own row is the one the device last registered"
    );
    assert!(
        s.devices(&bob(), t(200)).unwrap().is_empty(),
        "nothing is left addressed by the login"
    );

    assert_eq!(
        s.devices_purge(&Mailbox::identified("bob", fp()))
            .unwrap()
            .len(),
        2
    );
    assert!(s
        .devices(&Mailbox::identified("bob", fp()), t(201))
        .unwrap()
        .is_empty());
}

fn rotation_drops_what_the_successor_never_vouched_for(s: &dyn PushStore) {
    let old = Mailbox::identified("bob", fp());
    let new_fp = [8; 32];
    s.register(
        &device(old.clone(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(
            Mailbox::login("carol"),
            "carols-phone",
            "https://a.example/2",
            101,
        ),
        CAP,
    )
    .unwrap();

    assert_eq!(s.devices_rotate(&fp(), &new_fp).unwrap().len(), 1);
    assert!(
        s.devices(&old, t(200)).unwrap().is_empty(),
        "the predecessor's devices went"
    );
    assert!(
        s.devices(&Mailbox::identified("bob", new_fp), t(200))
            .unwrap()
            .is_empty(),
        "and did not arrive under the successor: they re-register at login"
    );
    assert_eq!(
        s.devices(&Mailbox::login("carol"), t(200)).unwrap().len(),
        1,
        "nobody else is touched"
    );
}

fn a_mailbox_holds_a_bounded_number_of_devices(s: &dyn PushStore) {
    let reg = |d: &Device| s.register(d, 2).unwrap().0;
    assert_eq!(
        reg(&device(bob(), "first-device", "https://a.example/1", 100)),
        Registered::Added
    );
    assert_eq!(
        reg(&device(bob(), "second-devic", "https://a.example/2", 101)),
        Registered::Added
    );
    assert_eq!(
        reg(&device(bob(), "third-device", "https://a.example/3", 102)),
        Registered::Full,
        "a new devid past the cap is refused"
    );
    assert_eq!(
        s.devices(&bob(), t(103)).unwrap().len(),
        2,
        "and not stored"
    );
    assert_eq!(
        reg(&device(bob(), "first-device", "https://a.example/9", 104)),
        Registered::Replaced,
        "a device the mailbox already has re-registers at the cap"
    );

    // The cap is per mailbox, and an identified mailbox is its own.
    assert_eq!(
        reg(&device(
            Mailbox::login("carol"),
            "carols-phone",
            "https://a.example/4",
            105
        )),
        Registered::Added
    );
    assert_eq!(
        reg(&device(
            Mailbox::identified("bob", fp()),
            "third-device",
            "https://a.example/5",
            106
        )),
        Registered::Added
    );

    // A lapsed certificate does not hold a place: registering prunes the
    // mailbox's own expired rows before it counts.
    let dave = Mailbox::login("dave");
    let mut lapsing = device(dave.clone(), "lapsing-devi", "https://a.example/6", 100);
    lapsing.expires = Some(t(200));
    reg(&lapsing);
    reg(&device(
        dave.clone(),
        "steady-devic",
        "https://a.example/7",
        101,
    ));
    assert_eq!(
        reg(&device(
            dave.clone(),
            "later-device",
            "https://a.example/8",
            199
        )),
        Registered::Full,
        "still live at registration"
    );
    assert_eq!(
        reg(&device(
            dave.clone(),
            "later-device",
            "https://a.example/8",
            300
        )),
        Registered::Added,
        "lapsed by then, and gone to make room"
    );
    assert_eq!(s.devices(&dave, t(301)).unwrap().len(), 2);
    assert!(s.sweep_expired(t(301)).unwrap().is_empty(), "already taken");
}

fn a_gone_answer_retires_only_the_endpoint_it_was_about(s: &dyn PushStore) {
    s.register(
        &device(bob(), "phone-install", "https://a.example/old", 100),
        CAP,
    )
    .unwrap();
    // The client re-subscribes while a push to the old endpoint is in
    // flight, and then the old endpoint answers 410.
    s.register(
        &device(bob(), "phone-install", "https://a.example/new", 101),
        CAP,
    )
    .unwrap();
    assert!(
        !s.retire(&bob(), &devid("phone-install"), "https://a.example/old")
            .unwrap(),
        "the answer was about an endpoint the row no longer holds"
    );
    assert_eq!(
        s.devices(&bob(), t(102)).unwrap()[0].endpoint,
        "https://a.example/new"
    );
    assert!(s
        .retire(&bob(), &devid("phone-install"), "https://a.example/new")
        .unwrap());
    assert!(s.devices(&bob(), t(103)).unwrap().is_empty());
    assert!(
        !s.retire(
            &Mailbox::identified("bob", fp()),
            &devid("phone-install"),
            "https://a.example/new"
        )
        .unwrap(),
        "nor across kinds"
    );
}

fn a_rekey_clears_every_mailbox(s: &dyn PushStore) {
    assert!(!s.any_devices().unwrap());
    assert_eq!(s.devices_clear().unwrap(), 0);
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(
            Mailbox::identified("carol", fp()),
            "carols-phone",
            "https://a.example/2",
            101,
        ),
        CAP,
    )
    .unwrap();
    assert!(s.any_devices().unwrap());
    assert_eq!(s.devices_clear().unwrap(), 2);
    assert!(!s.any_devices().unwrap());
}

fn expiry_is_at_the_instant_not_after_it(s: &dyn PushStore) {
    let mut d = device(bob(), "identity-devi", "https://a.example/1", 100);
    d.expires = Some(t(500));
    s.register(&d, CAP).unwrap();
    assert_eq!(s.devices(&bob(), t(499)).unwrap().len(), 1);
    assert!(
        s.devices(&bob(), t(500)).unwrap().is_empty(),
        "a certificate is not valid at the second it expires"
    );
    assert_eq!(s.sweep_expired(t(500)).unwrap().len(), 1);
}

fn taking_all_of_one_kind_leaves_the_other(s: &dyn PushStore) {
    let by_fp = Mailbox::identified("bob", fp());
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(by_fp.clone(), "phone-install", "https://a.example/2", 101),
        CAP,
    )
    .unwrap();

    assert_eq!(s.unregister_all(&bob()).unwrap().len(), 1);
    assert_eq!(
        s.devices(&by_fp, t(102)).unwrap().len(),
        1,
        "the login's all is not the identity's"
    );
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 103),
        CAP,
    )
    .unwrap();
    assert_eq!(s.devices_purge(&by_fp).unwrap().len(), 1);
    assert_eq!(
        s.devices(&bob(), t(104)).unwrap().len(),
        1,
        "nor is the identity's purge the login's"
    );
}

fn claiming_touches_only_that_login(s: &dyn PushStore) {
    let other_fp = [9; 32];
    s.register(
        &device(bob(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.register(
        &device(
            Mailbox::login("carol"),
            "carols-phone",
            "https://a.example/2",
            101,
        ),
        CAP,
    )
    .unwrap();
    s.register(
        &device(
            Mailbox::identified("dave", other_fp),
            "phone-install",
            "https://a.example/3",
            102,
        ),
        CAP,
    )
    .unwrap();

    assert_eq!(s.devices_claim("bob", &fp()).unwrap().len(), 1);
    assert_eq!(
        s.devices(&Mailbox::login("carol"), t(103)).unwrap().len(),
        1,
        "another login's device stays where it was"
    );
    let dave = s
        .devices(&Mailbox::identified("dave", other_fp), t(103))
        .unwrap();
    assert_eq!(
        dave.len(),
        1,
        "and another identity's, with the same devid, is neither taken as \
         the identity's own row nor moved"
    );
    assert_eq!(dave[0].endpoint, "https://a.example/3");
    assert_eq!(
        s.devices(&Mailbox::identified("bob", fp()), t(103))
            .unwrap()
            .len(),
        1
    );
}

/// An identified row is unique per fingerprint whatever login sits
/// beside it, as mail's and subscriptions' are: a renamed account's
/// device re-registering under the new login replaces its own row.
fn an_identified_device_is_the_fingerprints_whatever_the_login(s: &dyn PushStore) {
    s.register(
        &device(
            Mailbox::identified("bob", fp()),
            "phone-install",
            "https://a.example/1",
            100,
        ),
        CAP,
    )
    .unwrap();
    assert_eq!(
        s.register(
            &device(
                Mailbox::identified("robert", fp()),
                "phone-install",
                "https://a.example/2",
                101,
            ),
            CAP,
        )
        .unwrap()
        .0,
        Registered::Replaced
    );
    let rows = s
        .devices(&Mailbox::identified("robert", fp()), t(102))
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, "https://a.example/2");
}

fn a_stamp_never_crosses_kinds(s: &dyn PushStore) {
    let by_fp = Mailbox::identified("bob", fp());
    s.register(
        &device(by_fp.clone(), "phone-install", "https://a.example/1", 100),
        CAP,
    )
    .unwrap();
    s.touch(&bob(), &devid("phone-install"), t(200)).unwrap();
    assert_eq!(s.devices(&by_fp, t(201)).unwrap()[0].last_push_at, None);
}

fn subscribed(s: &dyn PushStore, d: &Device, dp: &str) {
    assert!(s.set_delivery_point(d, dp).unwrap(), "{dp} written");
}

fn a_registration_answers_with_what_it_took(s: &dyn PushStore) {
    let mut lapsing = device(bob(), "lapsing-devi", "https://a.example/1", 100);
    lapsing.expires = Some(t(200));
    s.register(&lapsing, CAP).unwrap();
    let phone = device(bob(), "phone-install", "https://a.example/2", 101);
    s.register(&phone, CAP).unwrap();

    let (_, taken) = s
        .register(
            &device(bob(), "phone-install", "https://a.example/3", 300),
            CAP,
        )
        .unwrap();
    let mut taken: Vec<_> = taken.into_iter().map(|d| d.endpoint).collect();
    taken.sort();
    assert_eq!(
        taken,
        ["https://a.example/1", "https://a.example/2"],
        "the lapsed row and the subscription the phone replaced"
    );

    let (_, taken) = s
        .register(
            &device(bob(), "phone-install", "https://a.example/3", 301),
            CAP,
        )
        .unwrap();
    assert!(
        taken.is_empty(),
        "a re-registration of the same subscription takes nothing"
    );
}

fn a_delivery_point_lasts_as_long_as_its_subscription(s: &dyn PushStore) {
    let phone = device(bob(), "phone-install", "https://a.example/1", 100);
    s.register(&phone, CAP).unwrap();
    assert_eq!(s.devices(&bob(), t(101)).unwrap()[0].delivery_point, None);
    subscribed(s, &phone, "webpush:aaaa");
    assert_eq!(
        s.devices(&bob(), t(101)).unwrap()[0]
            .delivery_point
            .as_deref(),
        Some("webpush:aaaa")
    );

    // A client re-registers at every login with what it already has.
    let mut again = device(bob(), "phone-install", "https://a.example/1", 200);
    again.delivery_point = Some("webpush:forged".into());
    s.register(&again, CAP).unwrap();
    assert_eq!(
        s.devices(&bob(), t(201)).unwrap()[0]
            .delivery_point
            .as_deref(),
        Some("webpush:aaaa"),
        "the same subscription keeps the store's name for it, never the caller's"
    );

    let mut rekeyed = device(bob(), "phone-install", "https://a.example/1", 300);
    rekeyed.auth = [1; 16];
    s.register(&rekeyed, CAP).unwrap();
    assert_eq!(
        s.devices(&bob(), t(301)).unwrap()[0].delivery_point,
        None,
        "new keys are a new subscription, which the sidecar has not named"
    );
}

fn a_delivery_point_is_written_only_over_its_own_subscription(s: &dyn PushStore) {
    let old = device(bob(), "phone-install", "https://a.example/old", 100);
    s.register(&old, CAP).unwrap();
    // The subscribe for `old` is in flight when the phone re-provisions.
    s.register(
        &device(bob(), "phone-install", "https://a.example/new", 101),
        CAP,
    )
    .unwrap();
    assert!(
        !s.set_delivery_point(&old, "webpush:old").unwrap(),
        "an answer about the old subscription"
    );
    assert_eq!(s.devices(&bob(), t(102)).unwrap()[0].delivery_point, None);
    assert!(
        !s.set_delivery_point(
            &device(
                Mailbox::identified("bob", fp()),
                "phone-install",
                "https://a.example/new",
                101
            ),
            "webpush:new"
        )
        .unwrap(),
        "nor across kinds"
    );
    assert_eq!(s.unsubscribed(t(102)).unwrap().len(), 1);
}

fn a_pruned_device_is_retired_by_its_delivery_point(s: &dyn PushStore) {
    let phone = device(bob(), "phone-install", "https://a.example/1", 100);
    let twin = device(bob(), "phone-reinsta", "https://a.example/1", 101);
    let laptop = device(bob(), "laptop-instal", "https://a.example/2", 102);
    let carols = device(
        Mailbox::login("carol"),
        "carols-phone",
        "https://a.example/1",
        103,
    );
    for d in [&phone, &twin, &laptop, &carols] {
        s.register(d, CAP).unwrap();
    }
    // Two rows of one mailbox with one subscription are one device to
    // the sidecar, and carol's has the same name only by this test's
    // choosing: a sidecar's names are per subscriber.
    for d in [&phone, &twin, &carols] {
        subscribed(s, d, "webpush:gone");
    }
    subscribed(s, &laptop, "webpush:live");

    let mut taken: Vec<_> = s
        .retire_delivery_point(&bob(), "webpush:gone")
        .unwrap()
        .into_iter()
        .map(|d| d.devid)
        .collect();
    taken.sort();
    assert_eq!(taken, [devid("phone-install"), devid("phone-reinsta")]);
    assert_eq!(
        s.devices(&bob(), t(200)).unwrap().len(),
        1,
        "the laptop stays"
    );
    assert_eq!(
        s.devices(&Mailbox::login("carol"), t(200)).unwrap().len(),
        1,
        "and nobody else's row is touched"
    );
    assert!(s
        .retire_delivery_point(&bob(), "webpush:gone")
        .unwrap()
        .is_empty());
}

fn a_lost_delivery_point_is_cleared_and_listed_again(s: &dyn PushStore) {
    let phone = device(bob(), "phone-install", "https://a.example/1", 100);
    let laptop = device(bob(), "laptop-instal", "https://a.example/2", 101);
    let carols = device(
        Mailbox::login("carol"),
        "carols-phone",
        "https://a.example/3",
        102,
    );
    let mut lapsed = device(
        Mailbox::login("dave"),
        "daves-phone!",
        "https://a.example/4",
        103,
    );
    lapsed.expires = Some(t(150));
    for d in [&phone, &laptop, &carols, &lapsed] {
        s.register(d, CAP).unwrap();
    }
    assert_eq!(
        s.unsubscribed(t(200))
            .unwrap()
            .into_iter()
            .map(|d| d.devid)
            .collect::<Vec<_>>(),
        [
            devid("phone-install"),
            devid("laptop-instal"),
            devid("carols-phone")
        ],
        "oldest first, and never a lapsed row"
    );
    subscribed(s, &phone, "webpush:one");
    subscribed(s, &laptop, "webpush:two");
    subscribed(s, &carols, "webpush:one");

    assert_eq!(s.clear_delivery_point(&bob(), "webpush:one").unwrap(), 1);
    assert_eq!(
        s.unsubscribed(t(200))
            .unwrap()
            .into_iter()
            .map(|d| d.devid)
            .collect::<Vec<_>>(),
        [devid("phone-install")],
        "bob's, not carol's of the same name"
    );
    assert_eq!(s.clear_delivery_points().unwrap(), 2);
    assert_eq!(s.unsubscribed(t(200)).unwrap().len(), 3);
}

fn linking_moves_a_row_out_from_under_its_delivery_point(s: &dyn PushStore) {
    let phone = device(bob(), "phone-install", "https://a.example/1", 100);
    s.register(&phone, CAP).unwrap();
    subscribed(s, &phone, "webpush:login");
    let taken = s.devices_claim("bob", &fp()).unwrap();
    assert_eq!(taken[0].delivery_point.as_deref(), Some("webpush:login"));
    assert_eq!(
        s.devices(&Mailbox::identified("bob", fp()), t(101))
            .unwrap()[0]
            .delivery_point,
        None,
        "the sidecar knows it under the subscriber it left"
    );
}

fn the_sidecar_record_is_kept(s: &dyn PushStore) {
    assert_eq!(s.sidecar().unwrap(), None);
    let mut record = SidecarRecord {
        service: "hxd".into(),
        public_key: "BEl6".into(),
        contact: "mailto:a@example.org".into(),
        cursor: None,
    };
    s.set_sidecar(&record).unwrap();
    assert_eq!(s.sidecar().unwrap(), Some(record.clone()));
    record.cursor = Some("1756900012345-0".into());
    s.set_sidecar(&record).unwrap();
    assert_eq!(s.sidecar().unwrap(), Some(record.clone()));
    s.devices_clear().unwrap();
    assert_eq!(
        s.sidecar().unwrap(),
        Some(record),
        "a rekey takes the rows and not the record of what was handed over"
    );
}
