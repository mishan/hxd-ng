//! Device registration over the ng wire (`docs/webpush-gateway.md` §7).
//!
//! A real server, a real WebSocket client and the real registry: what is
//! faked is only the sending, because a test that waited on a push
//! service would be a test of the internet. What the gateway does with
//! an answer is `hxd-push-webpush`'s own suite; what is checked here is
//! the wire — who may register, what a login is told, and that a
//! registration lands under the session's own mailbox and nobody else's.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::{SinkExt, StreamExt};
use hxd_core::push::{MemoryDevices, PushStore};
use hxd_core::{Core, InboxPolicy};
use hxd_ng_session::push::PushInfo;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// A subscription's keys, as a browser hands them to a client: the
/// RFC 8291 example's, so they are a real point on the curve.
const P256DH: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";

struct Server {
    ng: SocketAddr,
    devices: Arc<MemoryDevices>,
}

async fn start(dir: &Path, push: bool) -> Server {
    start_with(dir, push, hxd_core::push::PushPolicy::default()).await
}

async fn start_with(dir: &Path, push: bool, policy: hxd_core::push::PushPolicy) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    std::fs::write(
        accounts.join("bob.toml"),
        "name = \"Bob\"\npassword = \"s3cret\"\n[access]\nread_chat = true\nsend_chat = true\n\
         send_msgs = true\nuse_any_name = true\n",
    )
    .unwrap();
    let auth: Arc<hxd_auth_file::FileAuth> = Arc::new(hxd_auth_file::FileAuth::new(accounts));
    let devices = Arc::new(MemoryDevices::new());
    let core = Arc::new(
        Core::new()
            .with_inbox(
                Arc::new(hxd_core::inbox::MemoryStore::new()),
                auth.clone(),
                InboxPolicy::default(),
            )
            .with_devices(devices.clone())
            .with_push_policy(policy),
    );
    let ng_ctx = NgCtx {
        core,
        auth: auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: "push".into(),
            agreement: None,
            login_timeout: Duration::from_secs(5),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: Default::default(),
            forwarded_header: Default::default(),
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: None,
        registrar: None,
        push: push.then(|| {
            Arc::new(PushInfo {
                vapid: "BEl6…".into(),
                content: "sender".into(),
            })
        }),
        banner: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = listener.local_addr().unwrap();
    tokio::spawn(hxd_ng_session::serve(listener, ng_ctx));
    Server { ng, devices }
}

struct Client {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl Client {
    async fn login(addr: SocketAddr, login: &str, password: &str) -> (Client, Value) {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
            .await
            .unwrap();
        let mut c = Client { ws, next_id: 1 };
        let ok = c
            .request(
                "login",
                json!({ "login": login, "password": password, "nick": login }),
            )
            .await;
        let ok = ok["ok"].clone();
        (c, ok)
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.ws
            .send(Message::Text(
                json!({ "id": id, "req": method, "params": params }).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let msg = timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("timed out")
                .expect("closed")
                .expect("ws error");
            if let Message::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v.get("reply").and_then(Value::as_u64) == Some(id) {
                    return v;
                }
            }
        }
    }
}

fn register(devid: &str) -> Value {
    json!({
        "type": "webpush",
        "endpoint": format!("https://push.example.net/v/{devid}"),
        "p256dh": P256DH,
        "auth": AUTH,
        "devid": devid,
    })
}

#[tokio::test]
async fn a_client_is_told_about_push_and_can_register_a_device() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), true).await;
    let (mut bob, ok) = Client::login(s.ng, "bob", "s3cret").await;

    assert!(
        ok["caps"].as_array().unwrap().iter().any(|c| c == "push"),
        "a configured gateway is a capability: {ok}"
    );
    assert_eq!(ok["push"]["vapid"], "BEl6…");
    assert_eq!(ok["push"]["types"][0], "webpush");
    assert_eq!(
        ok["push"]["content"], "sender",
        "a client can tell its user what leaves the server before it asks"
    );

    let reply = bob.request("push_register", register("bobs-phone")).await;
    assert_eq!(reply["ok"]["devid"], "bobs-phone", "{reply}");

    let mailbox = hxd_core::inbox::Mailbox::login("bob");
    let rows = s.devices.devices(&mailbox, SystemTime::now()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, "https://push.example.net/v/bobs-phone");
    assert_eq!(
        rows[0].expires, None,
        "a password device has no certificate"
    );

    // The same device again with a new endpoint replaces rather than
    // accumulates: a distributor re-provisioning must not leave a second
    // row nobody reads.
    let mut moved = register("bobs-phone");
    moved["endpoint"] = json!("https://push.example.net/v/moved");
    assert!(bob.request("push_register", moved).await["ok"].is_object());
    let rows = s.devices.devices(&mailbox, SystemTime::now()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, "https://push.example.net/v/moved");

    // Omitting `devid` on a password session is refused rather than
    // guessed, and `all` is how you silence everything.
    bob.request("push_register", register("bobs-laptop")).await;
    let refused = bob.request("push_unregister", json!({})).await;
    assert_eq!(refused["error"]["code"], "bad_request", "{refused}");
    assert!(bob
        .request("push_unregister", json!({ "devid": "bobs-phone" }))
        .await["ok"]
        .is_object());
    assert_eq!(
        s.devices
            .devices(&mailbox, SystemTime::now())
            .unwrap()
            .len(),
        1
    );
    assert!(bob.request("push_unregister", json!({ "all": true })).await["ok"].is_object());
    assert!(s
        .devices
        .devices(&mailbox, SystemTime::now())
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn what_a_registration_will_not_take() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), true).await;
    let (mut bob, _) = Client::login(s.ng, "bob", "s3cret").await;

    let refuses = |params: Value| async {
        let mut client = Client {
            ws: tokio_tungstenite::connect_async(format!("ws://{}", s.ng))
                .await
                .unwrap()
                .0,
            next_id: 1,
        };
        client
            .request(
                "login",
                json!({ "login": "bob", "password": "s3cret", "nick": "bob" }),
            )
            .await;
        client.request("push_register", params).await
    };

    // Not an https URL: the client is told, because it can act on it.
    let mut http = register("bobs-phone");
    http["endpoint"] = json!("http://push.example.net/v/1");
    assert_eq!(refuses(http).await["error"]["code"], "bad_request");

    // Credentials in the authority, which a push endpoint has no use
    // for and which would put a secret in every log line.
    let mut userinfo = register("bobs-phone");
    userinfo["endpoint"] = json!("https://user:pw@push.example.net/v/1");
    assert_eq!(refuses(userinfo).await["error"]["code"], "bad_request");

    // A destination inside the server's own network: a URL this process
    // would then fetch, which is the shape of every request forgery
    // there has ever been. A literal is refused while the client is
    // still asking; a name that resolves there is refused at send time.
    let mut inside = register("bobs-phone");
    inside["endpoint"] = json!("https://127.0.0.1:8443/v/1");
    assert_eq!(refuses(inside).await["error"]["code"], "bad_request");

    // Keys of the wrong size are a different kind of value, not a short
    // one.
    let mut short = register("bobs-phone");
    short["p256dh"] = json!("AAAA");
    assert_eq!(refuses(short).await["error"]["code"], "bad_request");

    // A vendor type this server has no credentials for, and cannot be
    // given any: refused rather than stored and never used.
    let mut apns = register("bobs-phone");
    apns["type"] = json!("apns");
    assert_eq!(refuses(apns).await["error"]["code"], "bad_request");

    // A device id that is not one.
    let mut short_id = register("bobs-phone");
    short_id["devid"] = json!("x");
    assert_eq!(refuses(short_id).await["error"]["code"], "bad_request");

    assert!(s
        .devices
        .devices(&hxd_core::inbox::Mailbox::login("bob"), SystemTime::now())
        .unwrap()
        .is_empty());
    let _ = bob.request("ping", json!({})).await;
}

#[tokio::test]
async fn a_guest_is_never_offered_push_and_cannot_register() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), true).await;
    let (mut guest, ok) = Client::login(s.ng, "guest", "").await;
    assert!(
        ok.get("push").is_none(),
        "a guest has no mailbox, so there is nothing to be notified about: {ok}"
    );
    let refused = guest
        .request("push_register", register("some-device"))
        .await;
    assert_eq!(refused["error"]["code"], "no_mailbox", "{refused}");
}

#[tokio::test]
async fn a_server_with_no_gateway_says_so_rather_than_taking_registrations() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), false).await;
    let (mut bob, ok) = Client::login(s.ng, "bob", "s3cret").await;
    assert!(ok.get("push").is_none());
    assert!(
        !ok["caps"].as_array().unwrap().iter().any(|c| c == "push"),
        "and the capability is absent, so a client does not ask its user"
    );
    let refused = bob.request("push_register", register("bobs-phone")).await;
    assert_eq!(refused["error"]["code"], "not_available", "{refused}");
    let refused = bob.request("push_unregister", json!({ "all": true })).await;
    assert_eq!(refused["error"]["code"], "not_available", "{refused}");
}

/// An account holds a bounded number of devices: a new one past the cap
/// is refused, and one it already has re-registers regardless.
#[tokio::test]
async fn an_account_holds_a_bounded_number_of_devices() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_with(
        dir.path(),
        true,
        hxd_core::push::PushPolicy {
            max_devices: 2,
            ..Default::default()
        },
    )
    .await;
    let (mut bob, ok) = Client::login(s.ng, "bob", "s3cret").await;
    assert_eq!(
        ok["push"]["types"],
        json!(["webpush", "unifiedpush"]),
        "the types it takes are the types it says"
    );
    for id in ["first-device", "second-devic"] {
        let r = bob.request("push_register", register(id)).await;
        assert!(r.get("ok").is_some(), "{r}");
    }
    let r = bob.request("push_register", register("third-device")).await;
    assert_eq!(r["error"]["code"], "too_many_devices", "{r}");
    let mut moved = register("first-device");
    moved["endpoint"] = json!("https://push.example.net/v/renewed");
    let r = bob.request("push_register", moved).await;
    assert!(
        r.get("ok").is_some(),
        "a re-registration is not a new device: {r}"
    );
    assert_eq!(
        s.devices
            .devices(&hxd_core::inbox::Mailbox::login("bob"), SystemTime::now())
            .unwrap()
            .len(),
        2
    );
}

/// A password session's own id may not be spelled like a device
/// fingerprint: that spelling is an identity device's, and on a linked
/// account the two share a mailbox.
#[tokio::test]
async fn a_password_session_cannot_name_an_identity_device() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), true).await;
    let (mut bob, _) = Client::login(s.ng, "bob", "s3cret").await;
    let r = bob
        .request("push_register", register(&"ab".repeat(32)))
        .await;
    assert_eq!(r["error"]["code"], "bad_request", "{r}");
}

/// `allow_private_endpoints` is for the operator whose push service is
/// on their own network, and it lifts the address check at registration
/// for a literal address as well as for a name.
#[tokio::test]
async fn the_operators_own_push_service_may_be_on_their_network() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_with(
        dir.path(),
        true,
        hxd_core::push::PushPolicy {
            allow_private_endpoints: true,
            ..Default::default()
        },
    )
    .await;
    let (mut bob, _) = Client::login(s.ng, "bob", "s3cret").await;
    let mut inside = register("bobs-phone");
    inside["endpoint"] = json!("https://10.0.0.5:8443/v/1");
    let r = bob.request("push_register", inside).await;
    assert!(r.get("ok").is_some(), "{r}");
}
