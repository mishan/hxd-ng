//! What the harness reads from the server's side: `/metrics`, its log,
//! and the host it runs on.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// One scrape of `GET /metrics`, the unlabeled and labeled series alike,
/// keyed as the exposition writes them (`hxd_sessions{state="attached"}`).
/// Histogram buckets are left out; their counts and sums are kept.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Scrape(pub BTreeMap<String, f64>);

impl Scrape {
    pub fn get(&self, series: &str) -> Option<f64> {
        self.0.get(series).copied()
    }

    /// Sessions on the roster that are anyone's: attached and detached,
    /// not the server account and not a login half done.
    pub fn sessions(&self) -> Option<f64> {
        Some(
            self.get("hxd_sessions{state=\"attached\"}")?
                + self.get("hxd_sessions{state=\"detached\"}")?,
        )
    }
}

pub async fn scrape(ng: SocketAddr) -> Result<Scrape, String> {
    let body = timeout(Duration::from_secs(10), get(ng, "/metrics"))
        .await
        .map_err(|_| "scrape timed out".to_owned())??;
    let mut out = BTreeMap::new();
    for line in body.lines() {
        if line.starts_with('#') || line.contains("_bucket{") {
            continue;
        }
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        if let Ok(v) = value.parse() {
            out.insert(series.to_owned(), v);
        }
    }
    Ok(Scrape(out))
}

async fn get(addr: SocketAddr, path: &str) -> Result<String, String> {
    let mut s = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
    let raw = String::from_utf8_lossy(&raw);
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or("no end to the response head")?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(format!(
            "GET {path} answered {status}: is the server built with `metrics` and does \
             [metrics] allow this host?"
        ));
    }
    Ok(body.to_owned())
}

/// A log file, read from where it ended when the run began.
pub struct LogTail {
    path: PathBuf,
    from: u64,
}

impl LogTail {
    pub fn start(path: &Path) -> Result<LogTail, String> {
        let from = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        Ok(LogTail {
            path: path.to_owned(),
            from,
        })
    }

    /// Lines written since the start that a healthy run never writes: a
    /// panic, or anything logged at `ERROR`.
    pub fn alarming(&self) -> Result<Vec<String>, String> {
        let mut f =
            std::fs::File::open(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        f.seek(SeekFrom::Start(self.from))
            .map_err(|e| e.to_string())?;
        let mut text = String::new();
        f.read_to_string(&mut text).map_err(|e| e.to_string())?;
        Ok(text
            .lines()
            .filter(|l| l.contains("panicked") || l.contains(" ERROR "))
            .map(str::to_owned)
            .collect())
    }
}

/// What a result is not comparable without.
#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub cpus: usize,
    pub cpu_model: Option<String>,
    pub kernel: Option<String>,
    pub os: &'static str,
    pub arch: &'static str,
}

impl Host {
    pub fn read() -> Host {
        let cpu_model = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_owned())
        });
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_owned());
        Host {
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            cpu_model,
            kernel,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        }
    }
}

/// The revision the harness was built from, if it was built in a git
/// checkout.
pub fn revision() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
