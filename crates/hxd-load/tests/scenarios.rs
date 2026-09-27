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
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
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
    // them is the scenario's finding, not the harness's correctness, so
    // it is reported rather than asserted here: on this server, today,
    // neither is disconnected (docs/load-testing.md).
    let stalled = report.detail["stalled"].as_array().unwrap();
    assert_eq!(stalled.len(), 2);
    assert!(stalled.iter().all(|s| s["drained"].as_u64().unwrap() > 0));
    assert_eq!(
        report.checks["slow.disconnected"].held + report.checks["slow.disconnected"].violated,
        2
    );
}
