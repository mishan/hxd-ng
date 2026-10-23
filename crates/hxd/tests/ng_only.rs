//! A server run with `[server] classic = false`, as the binary from a
//! config file, since which listeners open is `main`'s to decide: no
//! classic port and no transfer port, no TRTP or HTXF over WebSocket
//! offered or served, and the ng wire working as ever, banner included.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use hxd_testclient::ng;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Killed when the test ends, however it ends.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Two adjacent loopback ports, held for the test: the classic port and
/// the transfer port derived from it. A server that tried to listen on
/// either would exit with the bind's error before its ng port opened.
fn held_pair() -> (TcpListener, TcpListener) {
    loop {
        let classic = TcpListener::bind("127.0.0.1:0").unwrap();
        let next = classic.local_addr().unwrap().port().checked_add(1);
        if let Some(Ok(htxf)) = next.map(|p| TcpListener::bind(("127.0.0.1", p))) {
            return (classic, htxf);
        }
    }
}

/// A plain GET, with `bearer` as its Authorization if there is one: the
/// status and the body.
async fn get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = bearer
        .map(|b| format!("Authorization: {b}\r\n"))
        .unwrap_or_default();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

/// Discovery, once the server answers it; `None` if the ng port was
/// taken before the server could bind it, and the server's log if it
/// exits for anything else.
async fn discovery(server: &mut Server, ng: SocketAddr, log: &Path) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            let said = std::fs::read_to_string(log).unwrap_or_default();
            if said.contains(&format!("ng bind {ng}")) {
                return None;
            }
            panic!("hxd exited ({status}) before it listened:\n{said}");
        }
        if TcpStream::connect(ng).await.is_ok() {
            let (status, body) = get(ng, "/.well-known/hotline", None).await;
            assert_eq!(status, 200);
            return Some(serde_json::from_slice(&body).unwrap());
        }
        assert!(tokio::time::Instant::now() < deadline, "hxd never listened");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The server, on an ng port picked for it, and its discovery document.
/// The port is free when picked and bound by the server a moment later,
/// so it is picked again, once, if something took it in between.
async fn start(dir: &Path, classic: &TcpListener) -> (Server, SocketAddr, Value) {
    let log = dir.join("hxd.log");
    for _ in 0..2 {
        let ng = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        // `[identity]` and a `[banner]` file are what make a classic
        // server offer both tunnels.
        std::fs::write(
            dir.join("hxd-ng.toml"),
            format!(
                "[server]\nname = \"ng only\"\nbind = \"{}\"\nclassic = false\n\
                 [ng]\nbind = \"{ng}\"\n[identity]\n[banner]\nfile = \"banner.gif\"\n",
                classic.local_addr().unwrap()
            ),
        )
        .unwrap();
        let out = std::fs::File::create(&log).unwrap();
        let mut server = Server(
            Command::new(env!("CARGO_BIN_EXE_hxd"))
                .args(["--config", "hxd-ng.toml"])
                .current_dir(dir)
                .stdout(out.try_clone().unwrap())
                .stderr(out)
                .spawn()
                .unwrap(),
        );
        if let Some(doc) = discovery(&mut server, ng, &log).await {
            return (server, ng, doc);
        }
    }
    panic!("the ng port was taken twice before the server could bind it");
}

#[tokio::test]
async fn an_ng_only_server_opens_nothing_for_the_classic_wire() {
    let dir = tempfile::tempdir().unwrap();
    let (classic, _htxf) = held_pair();
    let banner = b"GIF89a-banner";
    std::fs::write(dir.path().join("banner.gif"), banner).unwrap();
    let (_server, ng, doc) = start(dir.path(), &classic).await;

    assert_eq!(doc["name"], "ng only", "{doc}");
    assert_eq!(doc["identity"]["enabled"], true, "{doc}");
    assert!(doc["ng"].get("trtp").is_none(), "{doc}");
    assert!(doc["ng"].get("htxf").is_none(), "{doc}");
    for path in ["/trtp", "/htxf"] {
        let refused = tokio_tungstenite::connect_async(format!("ws://{ng}{path}")).await;
        assert!(
            matches!(&refused, Err(tokio_tungstenite::tungstenite::Error::Http(r)) if r.status() == 404),
            "{path}: {refused:?}"
        );
    }

    let (_probe, hello) = ng::Client::guest(ng, "Probe").await.unwrap();
    assert_eq!(hello["banner"]["url"], "/banner", "{hello}");
    let bearer = format!(
        "Bearer {}.{}",
        hello["session"].as_str().unwrap(),
        hello["token"].as_str().unwrap()
    );
    assert_eq!(
        get(ng, "/banner", Some(&bearer)).await,
        (200, banner.to_vec())
    );
}
