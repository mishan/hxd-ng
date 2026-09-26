//! `[metrics]`: the recorder behind `GET /metrics` on the ng port
//! (`docs/metrics.md`).
//!
//! The recording happens all over the server, through
//! `hxd_core::instrument`; this module installs the Prometheus recorder
//! those calls reach, fills in the gauges that are read rather than kept
//! (the roster's census, the process, the runtime) and renders it all
//! for a scrape. Built without the `metrics` feature, there is nothing
//! to install and a `[metrics]` section is a startup error.

use std::sync::Arc;

use hxd_core::Core;
use hxd_ng_session::metrics::MetricsSource;
use serde::Deserialize;

use crate::Config;

/// `[metrics]`: who may read them. Everything else about the recorder is
/// fixed, so the section's presence is most of what it says.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// Addresses and networks that may scrape, in the `trusted_proxies`
    /// syntax. This host only by default: a scrape from anywhere else is
    /// a decision the operator makes by writing it here.
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
}

fn default_allow() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1".into()]
}

/// A `[metrics]` section on a binary without the recorder, or without the
/// ng listener it is served from, is refused at startup rather than
/// ignored.
pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = config.metrics.as_ref() else {
        return Ok(());
    };
    if !cfg!(feature = "metrics") {
        return Err("[metrics] is configured, but this build has no recorder \
                    (built without the `metrics` feature)"
            .into());
    }
    if config.ng.is_none() {
        return Err("[metrics] needs [ng]: /metrics is served by the ng listener".into());
    }
    hxd_ng_session::TrustedProxies::parse(&section.allow)
        .map(|_| ())
        .map_err(|e| format!("[metrics] allow: {e}"))
}

/// The source `NgCtx::metrics` holds, or `None` when `[metrics]` is
/// absent.
#[cfg(feature = "metrics")]
pub fn build(config: &Config, core: &Arc<Core>) -> Result<Option<Arc<dyn MetricsSource>>, String> {
    let Some(section) = config.metrics.as_ref() else {
        return Ok(None);
    };
    let allow = hxd_ng_session::TrustedProxies::parse(&section.allow)
        .map_err(|e| format!("[metrics] allow: {e}"))?;
    Ok(Some(Arc::new(Source {
        handle: recorder()?,
        allow,
        core: core.clone(),
        runtime: tokio::runtime::Handle::try_current().ok(),
    })))
}

#[cfg(not(feature = "metrics"))]
pub fn build(
    _config: &Config,
    _core: &Arc<Core>,
) -> Result<Option<Arc<dyn MetricsSource>>, String> {
    // `check` has already refused a section this build cannot serve.
    Ok(None)
}

#[cfg(feature = "metrics")]
pub use recorder::recorder;

#[cfg(feature = "metrics")]
mod recorder {
    use std::sync::Mutex;

    use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

    /// Seconds, from a microsecond (an uncontended lock) to ten seconds
    /// (a disk that has stopped answering).
    const SECONDS: &[f64] = &[
        1e-6, 5e-6, 1e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 2.5e-3, 5e-3, 1e-2, 2.5e-2, 5e-2, 0.1,
        0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// Counts: recipients of a fan-out, depth of a queue.
    const COUNTS: &[f64] = &[
        0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0,
        65536.0,
    ];

    static INSTALLED: Mutex<Option<PrometheusHandle>> = Mutex::new(None);

    /// The process's recorder, installed on first use. One per process
    /// because the `metrics` facade has one global recorder; every server
    /// a test starts in one process shares it, which is also true of the
    /// locks it measures.
    pub fn recorder() -> Result<PrometheusHandle, String> {
        let mut installed = INSTALLED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = installed.as_ref() {
            return Ok(handle.clone());
        }
        let recorder = PrometheusBuilder::new()
            .set_buckets_for_metric(Matcher::Suffix("_seconds".into()), SECONDS)
            .and_then(|b| {
                b.set_buckets_for_metric(Matcher::Full("hxd_outbox_depth".into()), COUNTS)
            })
            .and_then(|b| {
                b.set_buckets_for_metric(Matcher::Full("hxd_fanout_recipients".into()), COUNTS)
            })
            .map_err(|e| format!("metrics recorder: {e}"))?
            .build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder).map_err(|e| format!("metrics recorder: {e}"))?;
        *installed = Some(handle.clone());
        Ok(handle)
    }
}

#[cfg(feature = "metrics")]
struct Source {
    handle: metrics_exporter_prometheus::PrometheusHandle,
    allow: hxd_ng_session::TrustedProxies,
    core: Arc<Core>,
    runtime: Option<tokio::runtime::Handle>,
}

#[cfg(feature = "metrics")]
impl MetricsSource for Source {
    fn allows(&self, client: std::net::IpAddr) -> bool {
        self.allow.contains(client)
    }

    fn render(&self) -> String {
        use hxd_core::instrument::gauge;

        let c = self.core.census();
        gauge("hxd_sessions", &[("state", "attached")], c.attached as f64);
        gauge("hxd_sessions", &[("state", "detached")], c.detached as f64);
        gauge("hxd_sessions", &[("state", "hidden")], c.hidden as f64);
        gauge("hxd_sessions", &[("state", "system")], c.system as f64);
        gauge("hxd_detached_broken", &[], c.broken as f64);
        gauge(
            "hxd_detached_buffered_events",
            &[("of", "sum")],
            c.buffered as f64,
        );
        gauge(
            "hxd_detached_buffered_events",
            &[("of", "max")],
            c.buffered_max as f64,
        );
        gauge("hxd_private_chats", &[], c.chats as f64);

        if let Some(fds) = open_fds() {
            gauge("hxd_process_open_fds", &[], fds as f64);
        }
        if let Some(rss) = resident_bytes() {
            gauge("hxd_process_resident_bytes", &[], rss as f64);
        }
        if let Some(rt) = &self.runtime {
            let m = rt.metrics();
            gauge("hxd_runtime_workers", &[], m.num_workers() as f64);
            gauge("hxd_runtime_alive_tasks", &[], m.num_alive_tasks() as f64);
            gauge(
                "hxd_runtime_global_queue_depth",
                &[],
                m.global_queue_depth() as f64,
            );
        }

        self.handle.run_upkeep();
        self.handle.render()
    }
}

/// Descriptors this process holds, where `/proc` says.
#[cfg(feature = "metrics")]
fn open_fds() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|dir| dir.count())
}

/// Resident memory, from `/proc/self/status`'s `VmRSS`, which is in KiB
/// whatever the page size.
#[cfg(feature = "metrics")]
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn a_build_without_the_recorder_refuses_the_section() {
        let err = check(&config("[ng]\n[metrics]\n")).unwrap_err();
        assert!(err.contains("`metrics` feature"), "{err}");
        assert!(check(&config("[ng]\n")).is_ok());
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn the_section_needs_the_ng_listener_and_a_readable_allow_list() {
        assert!(check(&config("[ng]\n[metrics]\n")).is_ok());
        let err = check(&config("[metrics]\n")).unwrap_err();
        assert!(err.contains("needs [ng]"), "{err}");
        let err = check(&config("[ng]\n[metrics]\nallow = [\"not an address\"]\n")).unwrap_err();
        assert!(err.contains("[metrics] allow"), "{err}");
    }
}
