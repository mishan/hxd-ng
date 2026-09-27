//! `GET /metrics` end to end (`docs/metrics.md`): a server built from a
//! real `[metrics]` section, a scripted legacy client and a WebSocket
//! client doing what clients do, and the scrape that should account for
//! them — then for their leaving. And who may not scrape: an address the
//! section does not allow, and anyone behind a proxy the server does not
//! trust.
//!
//! The recorder is one per process, so every server here writes into the
//! same one. What these check is therefore what a scrape must contain,
//! and the roster's census, which each scrape reads from its own server.
#![cfg(feature = "metrics")]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hxd_testclient::legacy::{self, Login};
use hxd_testclient::ng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HDR_LOGIN: u32 = 0x6b;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

/// A server built the way `hxd` builds one, from a config file.
async fn start(dir: &Path, metrics: &str) -> Server {
    start_with(dir, "", metrics).await
}

/// The same, with more of `[ng]`.
async fn start_with(dir: &Path, ng: &str, metrics: &str) -> Server {
    let d = dir.display();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n{ng}\n\
         {metrics}\n"
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
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

async fn get(addr: SocketAddr, path: &str, extra: &[(&str, &str)]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let raw = String::from_utf8(raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

async fn scrape(server: &Server) -> String {
    let (status, body) = get(server.ng, "/metrics", &[]).await;
    assert_eq!(status, 200, "{body}");
    body
}

/// The value of an unlabeled-histogram-free series, by its exact name
/// and labels as the exposition writes them.
fn value(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|v| v.trim().parse().ok())
}

/// Whether any line of `metric` carries every one of `labels`.
fn has(text: &str, metric: &str, labels: &[&str]) -> bool {
    text.lines()
        .filter(|l| l.starts_with(metric))
        .any(|l| labels.iter().all(|want| l.contains(want)))
}

/// Scrape until `pred` holds: a departure is noticed by the server's
/// own tasks, a moment after the socket closes.
async fn scrape_until(server: &Server, pred: impl Fn(&str) -> bool) -> String {
    for _ in 0..100 {
        let text = scrape(server).await;
        if pred(&text) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the scrape never showed it:\n{}", scrape(server).await);
}

#[tokio::test]
async fn a_scrape_accounts_for_both_wires_and_for_their_leaving() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "[metrics]").await;

    let text = scrape(&server).await;
    assert_eq!(value(&text, "hxd_sessions{state=\"attached\"}"), Some(0.0));

    let mut legacy = legacy::Client::login_at(server.legacy, &Login::guest("classic"))
        .await
        .unwrap();
    legacy.user_list().await.unwrap();
    let (ng, _) = ng::Client::guest(server.ng, "modern").await.unwrap();

    let text = scrape_until(&server, |t| {
        value(t, "hxd_sessions{state=\"attached\"}") == Some(2.0)
    })
    .await;
    assert_eq!(value(&text, "hxd_sessions{state=\"detached\"}"), Some(0.0));
    // Each wire's login, by how it logged in.
    assert!(has(
        &text,
        "hxd_login_seconds_count",
        &["wire=\"legacy\"", "auth=\"guest\""]
    ));
    assert!(has(
        &text,
        "hxd_login_seconds_count",
        &["wire=\"ng\"", "auth=\"guest\""]
    ));
    // The roster lock, named for what it guards and by where it was held.
    assert!(has(
        &text,
        "hxd_lock_hold_seconds_bucket",
        &["lock=\"RosterInner\"", "site=\"hxd-core/src/roster.rs:"]
    ));
    assert!(has(
        &text,
        "hxd_lock_wait_seconds_count",
        &["lock=\"RosterInner\""]
    ));
    // Frames, by the transaction type the server knows them as.
    assert!(has(
        &text,
        "hxd_frames_total",
        &[
            "wire=\"legacy\"",
            "dir=\"in\"",
            &format!("type=\"{HDR_LOGIN}\"")
        ]
    ));
    assert!(has(
        &text,
        "hxd_frames_total",
        &["wire=\"ng\"", "dir=\"in\"", "type=\"login\""]
    ));
    // A task reply is a reply, whatever it answers.
    assert!(has(
        &text,
        "hxd_frames_total",
        &["wire=\"legacy\"", "dir=\"out\"", "type=\"reply\""]
    ));
    assert!(!has(&text, "hxd_frames_total", &["type=\"other\""]));
    assert!(value(&text, "hxd_frame_bytes_total{wire=\"ng\",dir=\"in\"}").is_some_and(|n| n > 0.0));
    assert!(has(
        &text,
        "hxd_fanout_seconds_count",
        &["event=\"joined\""]
    ));
    assert!(value(&text, "hxd_process_open_fds").is_some_and(|n| n > 0.0));
    assert!(value(&text, "hxd_runtime_workers").is_some_and(|n| n > 0.0));

    // Both leave, cleanly: a FIN on the legacy socket and a close frame
    // on the WebSocket. (Dropping either with unread pushes in the
    // receive buffer is a reset, which counts as `io_error`.) A guest
    // never detaches, so leaving is ending.
    legacy.shutdown().await.unwrap();
    ng.close().await.unwrap();
    // The roster lets go first and the counter is told after, so wait
    // for both.
    let text = scrape_until(&server, |t| {
        value(t, "hxd_sessions{state=\"attached\"}") == Some(0.0)
            && has(
                t,
                "hxd_disconnects_total",
                &["wire=\"legacy\"", "reason=\"eof\""],
            )
            && has(
                t,
                "hxd_disconnects_total",
                &["wire=\"ng\"", "reason=\"closed\""],
            )
            // Only this test runs legacy clients in this process, so the
            // queue gauges are its own: whatever was queued for them has
            // been written or given back.
            && value(t, "hxd_write_queued_frames{wire=\"legacy\"}") == Some(0.0)
            && value(t, "hxd_write_queued_bytes{wire=\"legacy\"}") == Some(0.0)
    })
    .await;
    assert_eq!(value(&text, "hxd_sessions{state=\"detached\"}"), Some(0.0));
    assert_eq!(value(&text, "hxd_sessions{state=\"hidden\"}"), Some(0.0));
}

#[tokio::test]
async fn an_address_the_section_does_not_allow_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "[metrics]\nallow = [\"192.0.2.1\"]").await;
    let (status, body) = get(server.ng, "/metrics", &[]).await;
    assert_eq!(status, 403);
    assert!(!body.contains("hxd_"), "{body}");
}

#[tokio::test]
async fn a_proxy_the_server_does_not_trust_is_refused_even_on_loopback() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "[metrics]").await;
    // What a reverse proxy on this same host adds on the way through.
    for header in ["X-Forwarded-For", "Forwarded", "X-Real-IP"] {
        let (status, _) = get(server.ng, "/metrics", &[(header, "203.0.113.9")]).await;
        assert_eq!(status, 403, "{header}");
    }
}

#[tokio::test]
async fn a_trusted_proxy_must_name_the_client_it_forwards() {
    let td = tempfile::tempdir().unwrap();
    // The proxy is this host; the one client allowed is out there.
    let server = start_with(
        td.path(),
        "trusted_proxies = [\"127.0.0.1\"]",
        "[metrics]\nallow = [\"127.0.0.1\", \"203.0.113.9\"]",
    )
    .await;
    // Named, in the header this server reads: that client's own answer.
    let (status, body) = get(server.ng, "/metrics", &[("X-Forwarded-For", "203.0.113.9")]).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = get(
        server.ng,
        "/metrics",
        &[("X-Forwarded-For", "198.51.100.4")],
    )
    .await;
    assert_eq!(status, 403);
    // Named nobody it could read: the proxy's own loopback address is
    // standing in for whoever that was, and it is refused.
    for extra in [
        &[][..],
        &[("X-Real-IP", "203.0.113.9")][..],
        &[("X-Forwarded-For", "not an address")][..],
    ] {
        let (status, _) = get(server.ng, "/metrics", extra).await;
        assert_eq!(status, 403, "{extra:?}");
    }
}

#[tokio::test]
async fn without_the_section_there_is_no_route() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path(), "").await;
    let (status, _) = get(server.ng, "/metrics", &[]).await;
    assert_eq!(status, 404);
}
