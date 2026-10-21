//! The gateway against a real uniqush-push 2.11 (`docs/push-notifications.md`
//! §4.1, §9 P3): everything `tests/gateway.rs`'s script would only be
//! agreeing with itself about.
//!
//! Gated on `HXD_TEST_UNIQUSH`, uniqush's address as `[push.uniqush]
//! addr` spells it, with `HXD_TEST_UNIQUSH_TOKEN_FILE` its token over TCP
//! and `HXD_TEST_UNIQUSH_PUSH_HOST` the name uniqush reaches this machine
//! by, where the test runs the push service it sends to. That uniqush
//! needs `allow_private_addresses=true` in its `[webpush]` section, and
//! its own Redis or Valkey. Unset, the test says it skipped; CI's
//! `uniqush` job sets them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hxd_core::inbox::Mailbox;
use hxd_core::notify::{MessageNotice, Notification, NotificationGateway};
use hxd_core::push::{Device, DeviceId, MemoryDevices, PushStore, SidecarRecord};
use hxd_push_uniqush::{subscriber, Addr, Client, Config, Refused, UniqushGateway};
use hxd_push_webpush::{payload, Content, Vapid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the push service was sent, by path.
type Received = Arc<Mutex<HashMap<String, Vec<HashMap<String, String>>>>>;

/// A push service that answers by the endpoint's first path segment:
/// `ok` is accepted, `gone` is gone, and `flaky` is in trouble once and
/// then gone.
async fn push_service() -> (u16, Received) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Received = Arc::default();
    let r = received.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let r = r.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let head_end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                let headers: HashMap<String, String> = head
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let len: usize = headers
                    .get("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let seen = {
                    let mut r = r.lock().unwrap();
                    let list = r.entry(path.clone()).or_default();
                    list.push(headers);
                    list.len()
                };
                let status = match path.split('/').nth(1) {
                    Some("ok") => "201 Created",
                    Some("flaky") if seen == 1 => "503 Service Unavailable\r\nRetry-After: 1",
                    _ => "410 Gone",
                };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (port, received)
}

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hxd-uniqush-real-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn device(owner: &Mailbox, id: &str, endpoint: String) -> Device {
    // A subscription's keys as a browser makes them: RFC 8291's example.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    let p256dh = B64
        .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
        .unwrap();
    Device {
        owner: owner.clone(),
        devid: DeviceId::parse(id).unwrap(),
        endpoint,
        p256dh: p256dh.try_into().unwrap(),
        auth: [9; 16],
        expires: None,
        registered_at: SystemTime::now(),
        last_push_at: None,
        delivery_point: None,
    }
}

fn message<'a>(to: &'a Mailbox, from: &'a Mailbox) -> Notification<'a> {
    Notification::Message(MessageNotice {
        to,
        from: Some(from),
        from_nick: "Alice",
        text: "are you there",
        id: 7,
        unread: 1,
    })
}

async fn eventually(what: &str, secs: u64, cond: impl Fn() -> bool) {
    for _ in 0..secs * 10 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never happened: {what}");
}

fn dps(devices: &MemoryDevices, owner: &Mailbox) -> Vec<(String, Option<String>)> {
    devices
        .devices(owner, SystemTime::now())
        .unwrap()
        .into_iter()
        .map(|d| (d.devid.as_str().to_string(), d.delivery_point))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn against_a_real_uniqush() {
    let Ok(addr) = std::env::var("HXD_TEST_UNIQUSH") else {
        // Past the harness's capture, which would swallow it for a test
        // that passes.
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "against_a_real_uniqush skipped: HXD_TEST_UNIQUSH is not set"
        );
        return;
    };
    let addr = Addr::parse(&addr).unwrap();
    let token = std::env::var("HXD_TEST_UNIQUSH_TOKEN_FILE")
        .ok()
        .map(|p| std::fs::read_to_string(p).unwrap().trim().to_string());
    let push_host = std::env::var("HXD_TEST_UNIQUSH_PUSH_HOST")
        .expect("HXD_TEST_UNIQUSH_PUSH_HOST: where uniqush reaches this machine");
    // A service of its own, so a rerun against the same Redis starts clean.
    let service = format!(
        "hxd-test-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let (port, received) = push_service().await;
    let endpoint = |path: &str| format!("http://{push_host}:{port}/{path}");
    let raw = Client::new(addr.clone(), token.clone(), Duration::from_secs(10));
    let config = || Config {
        addr: addr.clone(),
        token: token.clone(),
        service: service.clone(),
    };
    let push = hxd_push_webpush::Config {
        timeout: Duration::from_secs(40),
        ..Default::default()
    };
    let vapid = Arc::new(
        Vapid::load_or_create(&scratch().join("vapid.key"), "mailto:a@example.org", true).unwrap(),
    );
    let devices = Arc::new(MemoryDevices::new());
    let gateway = UniqushGateway::new(devices.clone(), vapid.clone(), push.clone(), config());

    // The provider: handed over, then recognized as this server's although
    // uniqush shows the contact bare.
    gateway.prepare().await.unwrap();
    let psps = raw.call("/psps", &[]).await.unwrap();
    let ours = &psps["services"][service.as_str()][0];
    assert_eq!(ours["vapidpublickey"], vapid.public_key());
    assert_eq!(ours["subscriber"], "a@example.org");
    assert_eq!(ours["vapidprivatekey"], "[redacted]");
    gateway.prepare().await.unwrap();

    // Another key under the service, with no record of handing it over.
    let stranger = Arc::new(
        Vapid::load_or_create(&scratch().join("vapid.key"), "mailto:b@example.org", true).unwrap(),
    );
    let refused = UniqushGateway::new(
        Arc::new(MemoryDevices::new()),
        stranger,
        push.clone(),
        config(),
    )
    .prepare()
    .await
    .unwrap_err();
    assert!(matches!(refused, Refused::Fatal(_)), "{refused:?}");

    if matches!(addr, Addr::Tcp { .. }) {
        let wrong = Client::new(addr.clone(), Some("not-it".into()), Duration::from_secs(5));
        let e = wrong.call("/psps", &[]).await.unwrap_err();
        assert!(e.to_string().contains("token_file"), "{e}");
    }

    let (bob, carol, alice) = (
        Mailbox::login("bob"),
        Mailbox::identified("carol", [3; 32]),
        Mailbox::login("alice"),
    );
    for (owner, id, path) in [
        (&bob, "bobs-phone!!", "ok/bob"),
        (&bob, "bobs-old-one", "gone/bob"),
        (&carol, "carols-phone", "flaky/carol"),
        (&carol, "carols-other", "ok/carol"),
    ] {
        devices
            .register(&device(owner, id, endpoint(path)), 8)
            .unwrap();
    }
    gateway.start();
    eventually("every row named by uniqush", 20, || {
        devices.unsubscribed(SystemTime::now()).unwrap().is_empty()
    })
    .await;
    let bobs = dps(&devices, &bob);
    assert!(
        bobs.iter()
            .all(|(_, dp)| dp.as_deref().is_some_and(|d| d.starts_with("webpush:"))),
        "{bobs:?}"
    );

    // A push reaches bob's live device with the in-process sender's
    // headers, and the dead one is pruned in the answer and retired here.
    let n = message(&bob, &alice);
    gateway.notify(&n);
    eventually("bob's dead device retired", 40, || {
        dps(&devices, &bob).len() == 1
    })
    .await;
    let got = received.lock().unwrap()["/ok/bob"][0].clone();
    assert_eq!(got["ttl"], push.message_ttl.as_secs().to_string());
    assert_eq!(got["urgency"], "high");
    assert_eq!(
        got["topic"],
        hxd_push_webpush::http::topic(
            &vapid.topic_key(),
            &payload::build(&n, Content::default()).collapse
        )
    );
    assert!(
        got["content-length"].parse::<usize>().unwrap() > 86,
        "an RFC 8291 record, which uniqush encrypted"
    );

    // uniqush loses bob's device behind the store's back: the next push is
    // answered NOT_SUBSCRIBED and the row is subscribed again, not retired.
    let row = devices.devices(&bob, SystemTime::now()).unwrap().remove(0);
    let before = row.delivery_point.clone();
    let lost = raw
        .call(
            "/unsubscribe",
            &[
                ("service", service.as_str()),
                ("subscriber", subscriber::of(&bob).as_str()),
                ("pushservicetype", "webpush"),
                ("endpoint", row.endpoint.as_str()),
                ("p256dh", &b64(&row.p256dh)),
                ("auth", &b64(&row.auth)),
            ],
        )
        .await
        .unwrap();
    assert_eq!(lost["details"]["code"], "UNIQUSH_SUCCESS");
    let held = || async {
        raw.call(
            "/nrdp",
            &[
                ("service", service.as_str()),
                ("subscriber", subscriber::of(&bob).as_str()),
            ],
        )
        .await
        .unwrap()
        .as_u64()
    };
    assert_eq!(held().await, Some(0));
    gateway.notify(&message(&bob, &alice));
    let mut again = false;
    for _ in 0..200 {
        if held().await == Some(1) && dps(&devices, &bob)[0].1.is_some() {
            again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(again, "the lost device subscribed again");
    assert_eq!(dps(&devices, &bob).len(), 1, "and not retired");
    assert_eq!(
        received.lock().unwrap()["/ok/bob"].len(),
        1,
        "nothing was pushed to a device uniqush did not have"
    );
    assert_eq!(
        dps(&devices, &bob)[0].1,
        before,
        "the same subscription is the same name"
    );
    gateway.notify(&message(&bob, &alice));
    eventually("and pushed at", 20, || {
        received.lock().unwrap()["/ok/bob"].len() == 2
    })
    .await;

    // A retry's removal is only in uniqush's log: carol's flaky device is
    // retried after a 503 and gone by the time it is, and the next push
    // that reports a drop has the gateway read the log.
    gateway.notify(&message(&carol, &alice));
    eventually("the retry gone", 30, || {
        received
            .lock()
            .unwrap()
            .get("/flaky/carol")
            .is_some_and(|v| v.len() == 2)
    })
    .await;
    devices
        .register(&device(&bob, "bobs-tablet!", endpoint("gone/tablet")), 8)
        .unwrap();
    gateway.devices_changed(true, &[]);
    eventually("the tablet named", 20, || {
        let rows = dps(&devices, &bob);
        rows.len() == 2 && rows.iter().all(|d| d.1.is_some())
    })
    .await;
    gateway.notify(&message(&bob, &alice));
    eventually("carol's flaky device retired from the log", 30, || {
        dps(&devices, &carol).len() == 1
    })
    .await;
    assert_eq!(dps(&devices, &carol)[0].0, "carols-other");
    let cursor = devices.sidecar().unwrap().unwrap().cursor;
    assert!(cursor.is_some(), "the place in the log is kept");

    // A cursor uniqush does not know, as after a reset of its database:
    // every row is subscribed again, and none retired.
    devices
        .set_sidecar(&SidecarRecord {
            cursor: Some("99999999999999-0".into()),
            ..devices.sidecar().unwrap().unwrap()
        })
        .unwrap();
    let restarted = UniqushGateway::new(devices.clone(), vapid.clone(), push.clone(), config());
    restarted.prepare().await.unwrap();
    restarted.start();
    eventually("the cursor replaced", 20, || {
        devices.sidecar().unwrap().unwrap().cursor.as_deref() != Some("99999999999999-0")
    })
    .await;
    eventually("everything named again", 20, || {
        devices.unsubscribed(SystemTime::now()).unwrap().is_empty()
    })
    .await;
    assert_eq!(
        dps(&devices, &bob).len(),
        1,
        "bob's live device, and nothing retired"
    );
    assert_eq!(dps(&devices, &carol).len(), 1);
}

fn b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    B64.encode(bytes)
}
