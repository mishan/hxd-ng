//! Each scenario, small and short, against a real server in this
//! process, built from a config file as `hxd` builds one: a classic
//! listener and an ng listener on one domain core.
//!
//! These are the harness's own tests — that it drives both wires, that
//! its checks hold on a healthy server, and that the report carries what
//! it measured — and, because the server is real, a small load run of
//! each scenario on every `cargo test`.

use std::net::SocketAddr;
use std::path::Path;

use hxd_load::config::{Account, Accounts, Kind, Scenario};

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

async fn start(dir: &Path, ng: &str) -> Server {
    let d = dir.display();
    // Its clients talk as fast as a load test does, so no flood limit
    // and no request limit, and log in and resume as fast, so no
    // account's reconnect rate either.
    let text = format!(
        "[limits]\nchat_lines = 0\nspam_points = 0\nng_requests = 0\nnews_posts = 0\n\
         reconnect_seconds = 0\n\
         [paths]\naccounts = \"{d}/accounts\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n{ng}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx));
    server
}

fn scenario(server: &Server, kind: Kind, duration: f64) -> Scenario {
    let mut s = Scenario::default();
    s.target.legacy = Some(server.legacy);
    s.target.ng = Some(server.ng);
    s.run.scenario = kind;
    s.run.duration = duration;
    s.run.settle = 3.0;
    s
}

fn assert_clean(report: &hxd_load::report::Report) {
    assert_eq!(report.violations, 0, "{}", report.summary());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chat_every_line_reaches_every_reader_on_both_wires() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut s = scenario(&server, Kind::Chat, 2.0);
    s.chat.readers_legacy = 4;
    s.chat.readers_ng = 4;
    s.chat.talkers_legacy = 2;
    s.chat.talkers_ng = 2;
    s.chat.rate = 40.0;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    // Twelve readers, each of every line: the ledger ran.
    let heard = &report.checks["chat.all_heard"];
    assert_eq!(heard.held, 12 * 4);
    let delivery = &report.ops["chat.delivery"];
    assert!(delivery.count > 12 * 40, "{}", report.summary());
    assert!(report.ops["chat.echo"].count > 0);
    assert!(report.checks["roster.agrees"].held == 12);
    assert!(report.checks["roster.no_ghosts"].held == 1);
    assert!(report.checks["ng.seq_gapless"].held == 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_login_storm_logs_in_on_both_wires_and_reports_its_steps() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut s = scenario(&server, Kind::LoginStorm, 2.0);
    s.login_storm.rate = 20.0;
    s.login_storm.ramp_step = 20.0;
    s.login_storm.ramp_every = 1.0;
    s.login_storm.linger = 0.2;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    let legacy = &report.ops["login.legacy"];
    let ng = &report.ops["login.ng"];
    assert!(legacy.count > 0 && ng.count > 0, "{}", report.summary());
    assert!(
        legacy.errors.is_empty() && ng.errors.is_empty(),
        "{}",
        report.summary()
    );
    let steps = report.detail["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[1]["rate"], 40.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn churn_keeps_seqs_gapless_across_drops_resumes_and_kicks() {
    let td = tempfile::tempdir().unwrap();
    // Every churner detaches from one address, and the server must let
    // them.
    let server = start(td.path(), "max_detached_per_addr = 16").await;
    let accounts = Accounts {
        prefix: "churn".into(),
        count: 6,
        password: "load-test".into(),
    };
    hxd_load::accounts::write(
        &td.path().join("accounts"),
        &accounts.prefix,
        accounts.count,
        &accounts.password,
        Some("moderator"),
    )
    .unwrap();
    let mut s = scenario(&server, Kind::Churn, 3.0);
    s.target.accounts = Some(accounts);
    s.target.admin = Some(Account {
        login: "moderator".into(),
        password: "load-test".into(),
    });
    s.churn.ng = 6;
    s.churn.legacy = 4;
    s.churn.cycle = 0.2;
    s.churn.away = 0.05;
    s.churn.chat_rate = 20.0;
    // Kicks arrive as a Poisson process; at this mean, a three-second
    // run without one is a chance of about e^-30.
    s.churn.kick_every = 0.1;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    // A churner drops only after reading up to a ping's reply, so most
    // resumes find their gap still buffered.
    assert!(
        report.checks["churn.resumed"].held > 0,
        "{}",
        report.summary()
    );
    let replayed = report.ops["churn.resume.replayed"].count;
    let resynced = report.ops.get("churn.resume.resync").map_or(0, |s| s.count);
    assert!(replayed > resynced, "{}", report.summary());
    let kicked = report.checks.get("churn.kicked").map_or(0, |c| c.held);
    assert!(kicked > 0, "{}", report.summary());
    assert!(report.checks["ng.seq_gapless"].held > 0);
    assert!(report.checks["roster.no_ghosts"].held == 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_consumer_is_measured_and_costs_the_room_nothing() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let mut s = scenario(&server, Kind::SlowConsumer, 2.0);
    s.chat.readers_legacy = 2;
    s.chat.readers_ng = 2;
    s.chat.rate = 100.0;
    s.chat.line_bytes = 1000;
    let report = hxd_load::run(s).await.unwrap();
    // The room is held to everything the chat scenario holds it to.
    for check in [
        "chat.in_order_once",
        "chat.all_heard",
        "roster.agrees",
        "roster.no_ghosts",
        "ng.seq_gapless",
    ] {
        let c = &report.checks[check];
        assert!(
            c.held > 0 && c.violated == 0,
            "{check}: {}",
            report.summary()
        );
    }
    // And both stalled clients were probed. Whether the server hung up on
    // them is the scenario's finding, not the harness's correctness, and a
    // run this short never queues enough for it to, so it is reported
    // rather than asserted here (docs/load-testing.md §5).
    let stalled = report.detail["stalled"].as_array().unwrap();
    assert_eq!(stalled.len(), 2);
    assert!(stalled.iter().all(|s| s["drained"].as_u64().unwrap() > 0));
    assert_eq!(
        report.checks["slow.disconnected"].held + report.checks["slow.disconnected"].violated,
        2
    );
}

/// A server like `start`'s, with a TLS port and a `[link]` keyed by
/// `seed` repeated, linking as `peer` says, waited for until it has.
async fn start_linked(
    dir: &Path,
    seed: u8,
    tag: &str,
    peer: &str,
    tls: tokio::net::TcpListener,
) -> Server {
    let (server, hub) = start_linked_with(dir, seed, tag, peer, tls).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while hub.status().is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "{tag} never linked");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    server
}

async fn start_linked_with(
    dir: &Path,
    seed: u8,
    tag: &str,
    peer: &str,
    tls: tokio::net::TcpListener,
) -> (Server, hxd_link::Hub) {
    let d = dir.display();
    let seed_hex: String = [seed; 32].iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("link.key"), seed_hex).unwrap();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), issued.signing_key.serialize_pem()).unwrap();
    let text = format!(
        "[limits]\nchat_lines = 0\nspam_points = 0\nng_requests = 0\nnews_posts = 0\n\
         reconnect_seconds = 0\n\
         [paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n\
         [tls]\ncert = \"{d}/cert.pem\"\nkey = \"{d}/key.pem\"\n\
         [link]\ntag = \"{tag}\"\nkey = \"{d}/link.key\"\n{peer}\n"
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let hub = hxd::link::build(&config, ctx.core.clone())
        .unwrap()
        .unwrap();
    let certs = std::sync::Arc::new(
        hxd_session::LegacyTls::load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap(),
    );
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ngl.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx.clone()));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx));
    tokio::spawn(hxd_session::serve_tls_with_peers(
        tls,
        ctx,
        certs,
        Some(std::sync::Arc::new(hub.clone()) as std::sync::Arc<dyn hxd_session::PeerAcceptor>),
    ));
    hub.start();
    (server, hub)
}

/// The same, not waited for: a server that dials through a proxy the run
/// has yet to start.
async fn start_unlinked(
    dir: &Path,
    seed: u8,
    tag: &str,
    peer: &str,
    tls: tokio::net::TcpListener,
) -> Server {
    start_linked_with(dir, seed, tag, peer, tls).await.0
}

fn link_key(seed: u8) -> String {
    use base64::Engine;
    let key = hxd_link::LinkKey::from_seed(&[seed; 32]).public();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

/// Without `metrics` in this build, the link checks that read the
/// servers' own numbers (`link.stayed_up`, `link.no_ghosts`) are the
/// baseline's to make; what the clients see is checked here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn across_a_link_every_line_and_every_join_is_heard_on_the_other_server() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_tls.local_addr().unwrap();
    let a_peer = format!(
        "[[link.peer]]\nname = \"bb\"\naccept = true\nprotection = \"key\"\n\
         key = \"{}\"\naccount = \"link-bb\"\nfeatures = [\"chat\"]\n",
        link_key(2)
    );
    let b_peer = format!(
        "[[link.peer]]\nname = \"aa\"\ndial = \"{a_addr}\"\nprotection = \"key\"\n\
         key = \"{}\"\naccount = \"link-bb\"\nfeatures = [\"chat\"]\n",
        link_key(1)
    );
    let b_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = tokio::join!(
        start_linked(da.path(), 1, "aa", &a_peer, a_tls),
        start_linked(db.path(), 2, "bb", &b_peer, b_tls),
    );
    let linked = |kind, duration| {
        let mut s = scenario(&a, kind, duration);
        s.target.linked = vec![hxd_load::config::Server {
            name: "b".into(),
            legacy: Some(b.legacy),
            ng: Some(b.ng),
            ..Default::default()
        }];
        s
    };

    let mut s = linked(Kind::Chat, 2.0);
    s.chat.readers_legacy = 4;
    s.chat.readers_ng = 4;
    s.chat.talkers_legacy = 2;
    s.chat.talkers_ng = 2;
    s.chat.rate = 40.0;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    assert_eq!(report.checks["chat.all_heard"].held, 12 * 4);
    assert!(report.ops["chat.delivery.cross"].count > 0);
    assert_eq!(report.checks["roster.agrees"].held, 12);
    assert_eq!(report.checks["roster.no_ghosts"].held, 2);

    let mut s = linked(Kind::LoginStorm, 2.0);
    s.login_storm.rate = 10.0;
    s.login_storm.ramp_step = 0.0;
    s.login_storm.linger = 0.2;
    s.login_storm.observers_legacy = 1;
    s.login_storm.observers_ng = 1;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    assert_eq!(report.checks["link.joins_heard"].held, 2);
    assert!(report.ops["link.join"].count > 0, "{}", report.summary());
}

/// L-3 on two servers with a two-second grace, `b` dialing through the
/// run's proxy: a cut inside the grace shows nobody leaving, one past it
/// is a netsplit, and after each the watchers are shown everyone again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_inside_the_grace_shows_nothing_and_one_past_it_recovers() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_tls.local_addr().unwrap();
    // A port for the proxy, free again by the time the run binds it.
    let listen = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let a_peer = format!(
        "grace = 2\n[[link.peer]]\nname = \"bb\"\naccept = true\nprotection = \"key\"\n\
         key = \"{}\"\naccount = \"link-bb\"\n",
        link_key(2)
    );
    let b_peer = format!(
        "grace = 2\n[[link.peer]]\nname = \"aa\"\ndial = \"{listen}\"\nprotection = \"key\"\n\
         key = \"{}\"\naccount = \"link-bb\"\n",
        link_key(1)
    );
    let b_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = start_unlinked(da.path(), 1, "aa", &a_peer, a_tls).await;
    let b = start_unlinked(db.path(), 2, "bb", &b_peer, b_tls).await;

    let mut s = scenario(&a, Kind::Interruption, 1.0);
    s.target.linked = vec![hxd_load::config::Server {
        name: "b".into(),
        legacy: Some(b.legacy),
        ng: Some(b.ng),
        ..Default::default()
    }];
    s.target.proxy = Some(hxd_load::config::ProxyAt {
        listen,
        upstream: a_addr,
    });
    let i = &mut s.interruption;
    (i.population_legacy, i.population_ng) = (4, 4);
    i.cuts = vec![0.5, 4.0];
    i.grace = 2;
    i.recover = 20.0;
    i.between = 0.5;
    let report = hxd_load::run(s).await.unwrap();
    assert_clean(&report);
    assert_eq!(report.checks["link.recovered"].held, 2);
    assert_eq!(report.checks["link.grace_held"].held, 1);
    let cuts = report.detail["cuts"].as_array().unwrap();
    assert_eq!(cuts[0]["parts"], 0, "{cuts:?}");
    assert_eq!(cuts[1]["parts"], 8, "{cuts:?}");
    assert_eq!(cuts[1]["joins"], 8, "{cuts:?}");
}

/// L-4 on three servers: `a` accepting `b` through the run's proxy and
/// `c` directly, the room on `a` and `c`, and `b`'s link stalled. Lines
/// near the classic wire's longest, fast enough to fill `a`'s queue for
/// `b` and its socket's buffer in seconds rather than wait out a write's
/// minute without progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_peer_is_dropped_and_costs_the_room_nothing() {
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let a_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_tls.local_addr().unwrap();
    let listen = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let accept = |name: &str, seed: u8| {
        format!(
            "[[link.peer]]\nname = \"{name}\"\naccept = true\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = [\"chat\"]\n",
            link_key(seed)
        )
    };
    let dial = |to: std::net::SocketAddr, name: &str| {
        format!(
            "[[link.peer]]\nname = \"aa\"\ndial = \"{to}\"\nprotection = \"key\"\n\
             key = \"{}\"\naccount = \"link-{name}\"\nfeatures = [\"chat\"]\n",
            link_key(1)
        )
    };
    let bind = || async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() };
    let (a, a_hub) = start_linked_with(
        dirs[0].path(),
        1,
        "aa",
        &(accept("bb", 2) + &accept("cc", 3)),
        a_tls,
    )
    .await;
    let b = start_unlinked(dirs[1].path(), 2, "bb", &dial(listen, "bb"), bind().await).await;
    let c = start_linked(dirs[2].path(), 3, "cc", &dial(a_addr, "cc"), bind().await).await;

    let mut s = scenario(&a, Kind::SlowPeer, 16.0);
    let linked = |name: &str, at: &Server| hxd_load::config::Server {
        name: name.into(),
        legacy: Some(at.legacy),
        ng: Some(at.ng),
        ..Default::default()
    };
    s.target.linked = vec![linked("b", &b), linked("c", &c)];
    s.target.proxy = Some(hxd_load::config::ProxyAt {
        listen,
        upstream: a_addr,
    });
    (s.chat.readers_legacy, s.chat.readers_ng) = (2, 2);
    (s.chat.talkers_legacy, s.chat.talkers_ng) = (2, 2);
    s.chat.rate = 400.0;
    s.chat.line_bytes = 4000;
    s.slow_peer.stall_after = 2.0;
    s.slow_peer.drop_within = 14.0;
    s.slow_peer.recover = 20.0;

    let b_id = hxd_link::LinkKey::from_seed(&[2; 32]).server_id();
    let up = move |hub: &hxd_link::Hub| hub.status().iter().any(|l| l.server == b_id);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watched = tokio::spawn({
        let (a_hub, done) = (a_hub.clone(), done.clone());
        async move {
            // Dropped by `a` after it had been up longer than the talking
            // runs before the stall: a flap earlier is not this.
            let mut up_since = None;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                match (up(&a_hub), up_since) {
                    (true, None) => up_since = Some(tokio::time::Instant::now()),
                    (false, Some(t)) if t.elapsed().as_secs_f64() > 2.0 => return true,
                    (false, Some(_)) => up_since = None,
                    _ => {}
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            false
        }
    });
    let report = hxd_load::run(s).await.unwrap();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_clean(&report);
    assert!(report.checks["link.contained"].held == 1);
    assert!(watched.await.unwrap(), "a never dropped b");
}
