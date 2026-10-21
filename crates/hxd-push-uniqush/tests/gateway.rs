//! The gateway against a scripted uniqush (`docs/push-notifications.md`
//! §4.1): the answers a real daemon gives only after a push service
//! misbehaves, a Redis loses its data or a log is trimmed, on demand.
//! What a real uniqush says to the same requests is `tests/uniqush.rs`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hxd_core::inbox::Mailbox;
use hxd_core::notify::{MessageNotice, Notification, NotificationGateway};
use hxd_core::push::{Device, DeviceId, MemoryDevices, PushStore, SidecarRecord};
use hxd_push_uniqush::{subscriber, Addr, Config, Refused, UniqushGateway};
use hxd_push_webpush::{payload, Content, Vapid};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// One request as the mock saw it.
#[derive(Debug, Clone)]
struct Req {
    path: String,
    form: HashMap<String, String>,
    authorization: Option<String>,
}

enum Reply {
    Json(u16, Value),
    /// Never answer: a wedged sidecar.
    Hang,
}

type Script = dyn Fn(&Req) -> Option<Reply> + Send + Sync;

/// A uniqush that answers what a healthy one would, unless the script
/// says otherwise, and remembers what it was asked.
#[derive(Clone)]
struct Mock {
    seen: Arc<Mutex<Vec<Req>>>,
}

impl Mock {
    fn seen(&self, path: &str) -> Vec<Req> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }
}

/// What uniqush calls a device: a hash of the subscriber and the
/// subscription, so the same ones give the same name.
fn dp_of(form: &HashMap<String, String>) -> String {
    let mut h = DefaultHasher::new();
    for k in ["subscriber", "endpoint", "p256dh", "auth"] {
        form.get(k).hash(&mut h);
    }
    format!("webpush:{:016x}", h.finish())
}

fn healthy(r: &Req) -> Value {
    let f = &r.form;
    match r.path.as_str() {
        "/psps" => json!({"services": {}, "code": "UNIQUSH_SUCCESS"}),
        "/addpsp" => json!({"status": 0, "details": {"code": "UNIQUSH_SUCCESS"}}),
        "/subscribe" => json!({"status": 0, "details": {
            "deliveryPoint": dp_of(f), "code": "UNIQUSH_SUCCESS"}}),
        "/unsubscribe" => json!({"status": 0, "details": {"code": "UNIQUSH_SUCCESS"}}),
        "/removed" => json!({"code": "UNIQUSH_SUCCESS", "removed": [],
            "next": f.get("since").cloned().unwrap_or("0".into()), "truncated": false}),
        "/health" => json!({"status": "ok", "database": "ok", "code": "UNIQUSH_SUCCESS"}),
        "/push" => {
            let ok: Vec<Value> = f["delivery_point_id"]
                .split(',')
                .map(|dp| json!({"deliveryPoint": dp, "code": "UNIQUSH_SUCCESS"}))
                .collect();
            json!({"type": "Push", "successDetails": ok, "failureDetails": [], "droppedDetails": []})
        }
        other => panic!("nothing calls {other}"),
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    seen: Arc<Mutex<Vec<Req>>>,
    script: Arc<Script>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
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
    let header = |name: &str| {
        head.lines()
            .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
            .map(|l| l[name.len() + 1..].trim().to_string())
    };
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let form = form_urlencoded::parse(&buf[head_end..head_end + len])
        .into_owned()
        .collect();
    let req = Req {
        path,
        form,
        authorization: header("authorization"),
    };
    seen.lock().unwrap().push(req.clone());
    let (status, body) = match script(&req) {
        Some(Reply::Hang) => {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return;
        }
        Some(Reply::Json(status, v)) => (status, v),
        None => (200, healthy(&req)),
    };
    let body = format!("{body}\r\n");
    let _ = s
        .write_all(
            format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await;
}

async fn mock(script: impl Fn(&Req) -> Option<Reply> + Send + Sync + 'static) -> (Mock, Addr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script: Arc<Script> = Arc::new(script);
    let mock = Mock { seen: seen.clone() };
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(serve(s, seen.clone(), script.clone()));
        }
    });
    let addr = Addr::Tcp {
        host: "127.0.0.1".into(),
        port,
    };
    (mock, addr)
}

fn scratch() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "hxd-uniqush-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn vapid() -> Arc<Vapid> {
    Arc::new(
        Vapid::load_or_create(&scratch().join("vapid.key"), "mailto:a@example.org", true).unwrap(),
    )
}

fn push_config() -> hxd_push_webpush::Config {
    hxd_push_webpush::Config {
        timeout: Duration::from_millis(500),
        breaker_failures: 2,
        breaker_cooldown: Duration::from_secs(600),
        ..Default::default()
    }
}

struct Server {
    gateway: UniqushGateway,
    devices: Arc<MemoryDevices>,
    vapid: Arc<Vapid>,
}

fn gateway(addr: Addr, devices: Arc<MemoryDevices>) -> Server {
    let vapid = vapid();
    let gateway = UniqushGateway::new(
        devices.clone(),
        vapid.clone(),
        push_config(),
        Config {
            addr,
            token: Some("t0ken".into()),
            service: "hxd-test".into(),
        },
    );
    Server {
        gateway,
        devices,
        vapid,
    }
}

/// A gateway that has checked the provider and is running.
async fn running(addr: Addr) -> Server {
    let s = gateway(addr, Arc::new(MemoryDevices::new()));
    s.gateway.prepare().await.unwrap();
    s.gateway.start();
    s
}

fn device(owner: &Mailbox, id: &str, endpoint: &str) -> Device {
    Device {
        owner: owner.clone(),
        devid: DeviceId::parse(id).unwrap(),
        endpoint: endpoint.into(),
        p256dh: [4; 65],
        auth: [9; 16],
        expires: None,
        registered_at: SystemTime::now(),
        last_push_at: None,
        delivery_point: None,
    }
}

/// Register `d` as `Core` would: the store, then the gateway told.
fn register(s: &Server, d: &Device) {
    let (_, taken) = s.devices.register(d, 8).unwrap();
    s.gateway.devices_changed(true, &taken);
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

/// Wait for what a background task does, failing loudly if it never does.
async fn eventually(what: &str, cond: impl Fn() -> bool) {
    for _ in 0..250 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never happened: {what}");
}

fn dps(s: &Server, owner: &Mailbox) -> Vec<Option<String>> {
    s.devices
        .devices(owner, SystemTime::now())
        .unwrap()
        .into_iter()
        .map(|d| d.delivery_point)
        .collect()
}

fn all_subscribed(s: &Server, owner: &Mailbox) -> bool {
    dps(s, owner).iter().all(Option::is_some)
}

#[tokio::test]
async fn a_push_names_its_devices_and_carries_the_in_process_payload() {
    let (uq, addr) = mock(|_| None).await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    register(&s, &device(&bob, "laptop-instal", "https://push.example/2"));
    register(
        &s,
        &device(&alice, "alices-phone", "https://push.example/3"),
    );
    eventually("every row subscribed", || {
        all_subscribed(&s, &bob) && all_subscribed(&s, &alice)
    })
    .await;
    let sub = &uq.seen("/subscribe")[0];
    assert_eq!(sub.authorization.as_deref(), Some("Bearer t0ken"));
    assert_eq!(sub.form["pushservicetype"], "webpush");
    assert_eq!(sub.form["service"], "hxd-test");

    let n = message(&bob, &alice);
    s.gateway.notify(&n);
    eventually("a push", || !uq.seen("/push").is_empty()).await;
    let push = &uq.seen("/push")[0].form;
    assert_eq!(push["subscriber"], subscriber::of(&bob));
    let mut named: Vec<_> = push["delivery_point_id"].split(',').collect();
    named.sort();
    let mut bobs: Vec<_> = dps(&s, &bob).into_iter().flatten().collect();
    bobs.sort();
    assert_eq!(named, bobs, "bob's devices, and no one else's");
    let built = payload::build(&n, Content::default());
    assert_eq!(
        push["uniqush.payload.webpush"].as_bytes(),
        built.plaintext,
        "byte for byte what the in-process sender encrypts"
    );
    assert_eq!(
        push["msggroup"],
        hxd_push_webpush::http::topic(&s.vapid.topic_key(), &built.collapse)
    );
    assert_eq!(push["uniqush.urgency"], "high");
    assert_eq!(push["ttl"], push_config().message_ttl.as_secs().to_string());
    eventually("the devices stamped", || {
        s.devices
            .devices(&bob, SystemTime::now())
            .unwrap()
            .iter()
            .all(|d| d.last_push_at.is_some())
    })
    .await;
}

#[tokio::test]
async fn a_mailbox_with_nothing_subscribed_is_not_pushed_at() {
    // Every subscribe is refused, so no row ever has a delivery point.
    let (uq, addr) = mock(|r| {
        (r.path == "/subscribe").then(|| {
            Reply::Json(
                200,
                json!({"status": 1, "details": {"code": "UNIQUSH_ERROR_BUILD_DELIVERY_POINT"}}),
            )
        })
    })
    .await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("a subscribe", || !uq.seen("/subscribe").is_empty()).await;
    s.gateway.notify(&message(&bob, &alice));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        uq.seen("/push").is_empty(),
        "a push naming no device would reach every device uniqush has for bob"
    );
}

#[tokio::test]
async fn a_device_pruned_during_a_push_is_retired_and_unsubscribed() {
    let pruned = Arc::new(Mutex::new(String::new()));
    let p = pruned.clone();
    let (uq, addr) = mock(move |r| {
        (r.path == "/push").then(|| {
            let dp = p.lock().unwrap().clone();
            Reply::Json(
                200,
                json!({"successDetails": [], "failureDetails": [], "droppedDetails": [{
                    "deliveryPoint": dp, "code": "UNIQUSH_UPDATE_UNSUBSCRIBE",
                    "removed": {"service": "hxd-test", "deliveryPoint": dp,
                                "devid": "phone-install", "reason": "UNIQUSH_UPDATE_UNSUBSCRIBE"}}]}),
            )
        })
    })
    .await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("subscribed", || all_subscribed(&s, &bob)).await;
    *pruned.lock().unwrap() = dps(&s, &bob)[0].clone().unwrap();
    let logs_read = uq.seen("/removed").len();

    s.gateway.notify(&message(&bob, &alice));
    eventually("the row retired", || dps(&s, &bob).is_empty()).await;
    eventually("and unsubscribed", || !uq.seen("/unsubscribe").is_empty()).await;
    let unsub = &uq.seen("/unsubscribe")[0].form;
    assert_eq!(unsub["endpoint"], "https://push.example/1");
    assert_eq!(unsub["subscriber"], subscriber::of(&bob));
    eventually("the log read after a drop", || {
        uq.seen("/removed").len() > logs_read
    })
    .await;
}

#[tokio::test]
async fn a_device_uniqush_lacks_is_subscribed_again_never_retired() {
    let (uq, addr) = mock(|r| {
        (r.path == "/push").then(|| {
            let dropped: Vec<Value> = r.form["delivery_point_id"]
                .split(',')
                .map(|dp| json!({"deliveryPoint": dp, "code": "UNIQUSH_NOT_SUBSCRIBED"}))
                .collect();
            Reply::Json(
                200,
                json!({"successDetails": [], "failureDetails": [], "droppedDetails": dropped}),
            )
        })
    })
    .await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("subscribed", || all_subscribed(&s, &bob)).await;
    s.gateway.notify(&message(&bob, &alice));
    eventually("subscribed again", || uq.seen("/subscribe").len() >= 2).await;
    assert_eq!(dps(&s, &bob).len(), 1, "the row stays");
    assert!(uq.seen("/unsubscribe").is_empty());
}

#[tokio::test]
async fn the_log_retires_what_it_names_and_the_store_keeps_the_cursor() {
    let named = Arc::new(Mutex::new(None::<(String, String)>));
    let n = named.clone();
    let (uq, addr) = mock(move |r| {
        if r.path != "/removed" {
            return None;
        }
        let (sub, dp) = n.lock().unwrap().clone()?;
        if r.form.contains_key("since") && r.form["since"] == "9-0" {
            return None;
        }
        Some(Reply::Json(
            200,
            json!({"code": "UNIQUSH_SUCCESS", "truncated": false, "next": "9-0", "removed": [
                {"id": "9-0", "service": "other-server", "subscriber": sub, "deliveryPoint": dp},
                {"id": "9-0", "service": "hxd-test", "subscriber": sub, "deliveryPoint": dp}]}),
        ))
    })
    .await;
    let s = gateway(addr, Arc::new(MemoryDevices::new()));
    s.gateway.prepare().await.unwrap();
    let bob = Mailbox::login("bob");
    let phone = device(&bob, "phone-install", "https://push.example/1");
    s.devices.register(&phone, 8).unwrap();
    s.devices
        .set_delivery_point(&phone, "webpush:pruned")
        .unwrap();
    *named.lock().unwrap() = Some((subscriber::of(&bob), "webpush:pruned".into()));

    s.gateway.start();
    eventually("the row retired", || dps(&s, &bob).is_empty()).await;
    eventually("the cursor kept", || {
        s.devices.sidecar().unwrap().and_then(|r| r.cursor) == Some("9-0".into())
    })
    .await;
    assert!(
        !uq.seen("/removed")[0].form.contains_key("since"),
        "without a cursor it starts from the oldest entry uniqush keeps"
    );
}

/// A log that cannot say what was removed is a reason to subscribe
/// every row again, and never to retire one.
#[tokio::test]
async fn a_log_that_lost_track_resubscribes_everything() {
    for answer in [
        json!({"code": "UNIQUSH_ERROR_GENERIC", "errorMsg": "invalid cursor"}),
        json!({"code": "UNIQUSH_SUCCESS", "removed": [], "next": "5-0", "truncated": true}),
    ] {
        let first = Arc::new(AtomicUsize::new(0));
        let f = first.clone();
        let (uq, addr) = mock(move |r| {
            (r.path == "/removed" && f.fetch_add(1, Ordering::SeqCst) == 0)
                .then(|| Reply::Json(200, answer.clone()))
        })
        .await;
        let s = gateway(addr, Arc::new(MemoryDevices::new()));
        let bob = Mailbox::login("bob");
        let phone = device(&bob, "phone-install", "https://push.example/1");
        s.devices.register(&phone, 8).unwrap();
        s.devices.set_delivery_point(&phone, "webpush:old").unwrap();
        s.devices
            .set_sidecar(&SidecarRecord {
                service: "hxd-test".into(),
                public_key: s.vapid.public_key().into(),
                contact: "mailto:a@example.org".into(),
                cursor: Some("4-0".into()),
            })
            .unwrap();
        s.gateway.prepare().await.unwrap();
        s.gateway.start();
        eventually("subscribed again", || !uq.seen("/subscribe").is_empty()).await;
        assert_eq!(dps(&s, &bob).len(), 1, "never retired");
        eventually("named afresh", || all_subscribed(&s, &bob)).await;
    }
}

#[tokio::test]
async fn a_renamed_service_resubscribes_everything() {
    let (uq, addr) = mock(|_| None).await;
    let s = gateway(addr, Arc::new(MemoryDevices::new()));
    let bob = Mailbox::login("bob");
    let phone = device(&bob, "phone-install", "https://push.example/1");
    s.devices.register(&phone, 8).unwrap();
    s.devices.set_delivery_point(&phone, "webpush:old").unwrap();
    s.devices
        .set_sidecar(&SidecarRecord {
            service: "old-name".into(),
            public_key: "BOld".into(),
            contact: "mailto:a@example.org".into(),
            cursor: Some("4-0".into()),
        })
        .unwrap();
    s.gateway.prepare().await.unwrap();
    assert_eq!(dps(&s, &bob), [None::<String>]);
    let record = s.devices.sidecar().unwrap().unwrap();
    assert_eq!(record.service, "hxd-test");
    assert_eq!(record.cursor, None, "the old service's place in its log");
    assert_eq!(uq.seen("/addpsp").len(), 1);
}

#[tokio::test]
async fn a_provider_is_this_servers_or_the_gateway_refuses_it() {
    let shown = Arc::new(Mutex::new(json!([])));
    let sh = shown.clone();
    let (uq, addr) = mock(move |r| {
        (r.path == "/psps").then(|| {
            Reply::Json(
                200,
                json!({"services": {"hxd-test": sh.lock().unwrap().clone()},
                       "code": "UNIQUSH_SUCCESS"}),
            )
        })
    })
    .await;
    let s = gateway(addr, Arc::new(MemoryDevices::new()));

    // Nothing there: handed over, and recorded.
    s.gateway.prepare().await.unwrap();
    let add = &uq.seen("/addpsp")[0].form;
    assert_eq!(add["vapidpublickey"], s.vapid.public_key());
    assert_eq!(add["vapidprivatekey"], s.vapid.private_key());
    assert_eq!(add["subscriber"], "mailto:a@example.org");
    assert!(!add.contains_key("replace"));

    // uniqush shows a mailto: contact bare, and that is the same one.
    *shown.lock().unwrap() = json!([{"service": "hxd-test",
        "vapidpublickey": s.vapid.public_key(), "subscriber": "a@example.org",
        "vapidprivatekey": "[redacted]"}]);
    s.gateway.prepare().await.unwrap();
    assert_eq!(uq.seen("/addpsp").len(), 1, "nothing to hand over");

    // The key this server handed over before a rekey is replaced.
    s.devices
        .set_sidecar(&SidecarRecord {
            service: "hxd-test".into(),
            public_key: "BOldKey".into(),
            contact: "mailto:a@example.org".into(),
            cursor: None,
        })
        .unwrap();
    *shown.lock().unwrap() = json!([{"vapidpublickey": "BOldKey", "subscriber": "a@example.org"}]);
    s.gateway.prepare().await.unwrap();
    assert_eq!(uq.seen("/addpsp")[1].form["replace"], "true");

    // A key nobody here handed over is someone else's.
    *shown.lock().unwrap() =
        json!([{"vapidpublickey": "BSomeoneElse", "subscriber": "b@example.org"}]);
    let refused = s.gateway.prepare().await.unwrap_err();
    assert!(matches!(refused, Refused::Fatal(_)), "{refused:?}");
    assert_eq!(uq.seen("/addpsp").len(), 2, "and it is not replaced");
}

/// A `/push` that runs out of time counts against uniqush only when
/// `/health` agrees that uniqush is in trouble: otherwise it was the
/// account's endpoints that were slow. A device being retried never
/// counts.
#[tokio::test]
async fn only_uniqush_itself_failing_opens_the_breaker() {
    // 0: devices being retried; 1: /push hangs, /health fine;
    // 2: /push hangs and /health fails.
    let mode = Arc::new(AtomicUsize::new(0));
    let m = mode.clone();
    let (uq, addr) = mock(move |r| match (r.path.as_str(), m.load(Ordering::SeqCst)) {
        ("/health", 2) => Some(Reply::Json(
            503,
            json!({"status": "unhealthy", "code": "UNIQUSH_ERROR_DATABASE"}),
        )),
        ("/push", 1 | 2) => Some(Reply::Hang),
        ("/push", _) => {
            let failed: Vec<Value> = r.form["delivery_point_id"]
                .split(',')
                .map(|dp| {
                    json!({"deliveryPoint": dp, "code": "UNIQUSH_PUSH_RETRYING",
                           "errorMsg": "push server returned HTTP 503"})
                })
                .collect();
            Some(Reply::Json(
                200,
                json!({"successDetails": [], "failureDetails": failed, "droppedDetails": []}),
            ))
        }
        _ => None,
    })
    .await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("subscribed", || all_subscribed(&s, &bob)).await;

    let mut sent = 0;
    for m in [0, 1] {
        mode.store(m, Ordering::SeqCst);
        for _ in 0..4 {
            s.gateway.notify(&message(&bob, &alice));
            sent += 1;
            eventually("each push sent", || uq.seen("/push").len() == sent).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
    }
    assert_eq!(
        uq.seen("/health").len(),
        4,
        "each timeout asked /health, and it answered"
    );

    // Past `breaker_failures` timeouts that /health confirms, uniqush is
    // skipped.
    mode.store(2, Ordering::SeqCst);
    for _ in 0..4 {
        s.gateway.notify(&message(&bob, &alice));
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    assert_eq!(uq.seen("/push").len(), sent + 2);
    assert_eq!(dps(&s, &bob).len(), 1, "and no failure costs a device");
}

#[tokio::test]
async fn a_push_names_no_more_devices_than_uniqush_tries_at_once() {
    let (uq, addr) = mock(|_| None).await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    for i in 0..20 {
        let d = device(
            &bob,
            &format!("install-{i:02}"),
            &format!("https://push.example/{i}"),
        );
        let (_, taken) = s.devices.register(&d, 20).unwrap();
        s.gateway.devices_changed(true, &taken);
    }
    eventually("subscribed", || {
        dps(&s, &bob).len() == 20 && all_subscribed(&s, &bob)
    })
    .await;
    s.gateway.notify(&message(&bob, &alice));
    eventually("two pushes", || uq.seen("/push").len() == 2).await;
    let mut named: Vec<usize> = uq
        .seen("/push")
        .iter()
        .map(|r| r.form["delivery_point_id"].split(',').count())
        .collect();
    named.sort();
    assert_eq!(named, [4, 16]);
}

#[tokio::test]
async fn a_lost_provider_is_handed_over_again() {
    let (uq, addr) = mock(|r| {
        (r.path == "/push").then(|| {
            Reply::Json(
                200,
                json!({"successDetails": [], "droppedDetails": [], "failureDetails": [{
                    "code": "UNIQUSH_ERROR_NO_PUSH_SERVICE_PROVIDER"}]}),
            )
        })
    })
    .await;
    let s = running(addr).await;
    let (bob, alice) = (Mailbox::login("bob"), Mailbox::login("alice"));
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("subscribed", || all_subscribed(&s, &bob)).await;
    assert_eq!(uq.seen("/addpsp").len(), 1);
    s.gateway.notify(&message(&bob, &alice));
    eventually("handed over again", || uq.seen("/addpsp").len() == 2).await;
}

#[tokio::test]
async fn a_refused_row_waits_for_the_period() {
    let (uq, addr) = mock(|r| {
        (r.path == "/subscribe").then(|| {
            Reply::Json(
                200,
                json!({"status": 1, "details": {"code": "UNIQUSH_ERROR_BUILD_DELIVERY_POINT"}}),
            )
        })
    })
    .await;
    let s = running(addr).await;
    let bob = Mailbox::login("bob");
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    eventually("a subscribe", || uq.seen("/subscribe").len() == 1).await;
    // Every other registration wakes the keeper; the refused row is not
    // asked about again.
    for i in 0..3 {
        register(
            &s,
            &device(
                &Mailbox::login("carol"),
                &format!("carols-{i:03}!"),
                "https://push.example/c",
            ),
        );
        eventually("carol's asked about", || {
            uq.seen("/subscribe").len() == 2 + i
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        uq.seen("/subscribe")
            .iter()
            .filter(|r| r.form["subscriber"] == subscriber::of(&bob))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_row_deleted_is_unsubscribed_unless_another_holds_its_subscription() {
    let (uq, addr) = mock(|_| None).await;
    let s = running(addr).await;
    let bob = Mailbox::login("bob");
    // One phone, registered twice under two install ids: one device to
    // uniqush.
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    register(&s, &device(&bob, "phone-reinsta", "https://push.example/1"));
    eventually("subscribed", || {
        dps(&s, &bob).len() == 2 && all_subscribed(&s, &bob)
    })
    .await;

    let gone = s
        .devices
        .unregister(&bob, &DeviceId::parse("phone-install").unwrap())
        .unwrap();
    s.gateway
        .devices_changed(false, &gone.into_iter().collect::<Vec<_>>());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        uq.seen("/unsubscribe").is_empty(),
        "the twin still holds the device"
    );

    let gone = s.devices.unregister_all(&bob).unwrap();
    s.gateway.devices_changed(false, &gone);
    eventually("unsubscribed", || uq.seen("/unsubscribe").len() == 1).await;

    // A replaced subscription takes the old one with it.
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    register(&s, &device(&bob, "phone-install", "https://push.example/2"));
    eventually("the old one unsubscribed", || {
        uq.seen("/unsubscribe")
            .iter()
            .filter(|r| r.form["endpoint"] == "https://push.example/1")
            .count()
            == 2
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn over_a_unix_socket_no_token_is_needed() {
    let path = scratch().join("uniqush.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let uq = Mock { seen: seen.clone() };
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(serve(s, seen.clone(), Arc::new(|_: &Req| None::<Reply>)));
        }
    });
    let s = UniqushGateway::new(
        Arc::new(MemoryDevices::new()),
        vapid(),
        push_config(),
        Config {
            addr: Addr::Unix(path),
            token: None,
            service: "hxd-test".into(),
        },
    );
    s.prepare().await.unwrap();
    assert_eq!(uq.seen("/psps")[0].authorization, None);
    assert_eq!(uq.seen("/addpsp").len(), 1);
}

#[tokio::test]
async fn an_unreachable_sidecar_is_tried_again_and_a_refused_token_is_said() {
    let s = gateway(
        Addr::Tcp {
            host: "127.0.0.1".into(),
            port: 1,
        },
        Arc::new(MemoryDevices::new()),
    );
    assert!(matches!(
        s.gateway.prepare().await,
        Err(Refused::Unreachable(_))
    ));

    let (_uq, addr) = mock(|_| {
        Some(Reply::Json(
            401,
            json!({"code": "UNIQUSH_ERROR_UNAUTHORIZED"}),
        ))
    })
    .await;
    let s = gateway(addr, Arc::new(MemoryDevices::new()));
    match s.gateway.prepare().await {
        Err(Refused::Fatal(e)) => assert!(e.contains("token_file"), "{e}"),
        other => panic!("{other:?}"),
    }
}

/// A slow `/psps` is uniqush having trouble, whatever `/health` says,
/// and never a reason to think the provider is someone else's.
#[tokio::test]
async fn a_slow_provider_check_is_tried_again_not_refused() {
    let (_uq, addr) = mock(|r| (r.path == "/psps").then_some(Reply::Hang)).await;
    let s = gateway(addr, Arc::new(MemoryDevices::new()));
    match s.gateway.prepare().await {
        Err(Refused::Unreachable(_)) => {}
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_mailbox_holds_at_most_two_deliveries_at_once() {
    let (uq, addr) = mock(|r| (r.path == "/push").then_some(Reply::Hang)).await;
    let s = running(addr).await;
    let (bob, carol, alice) = (
        Mailbox::login("bob"),
        Mailbox::login("carol"),
        Mailbox::login("alice"),
    );
    register(&s, &device(&bob, "phone-install", "https://push.example/1"));
    register(
        &s,
        &device(&carol, "carols-phone", "https://push.example/2"),
    );
    eventually("subscribed", || {
        all_subscribed(&s, &bob) && all_subscribed(&s, &carol)
    })
    .await;
    for _ in 0..4 {
        s.gateway.notify(&message(&bob, &alice));
    }
    s.gateway.notify(&message(&carol, &alice));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let to = |who: &Mailbox| {
        uq.seen("/push")
            .iter()
            .filter(|r| r.form["subscriber"] == subscriber::of(who))
            .count()
    };
    assert_eq!(to(&bob), 2, "bob's third and fourth are dropped");
    assert_eq!(to(&carol), 1, "and carol is not held up by him");
}
