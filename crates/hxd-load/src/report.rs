//! A run's result, as JSON: enough to compare it with another run and to
//! repeat it — the harness's revision, the host, the scenario with its
//! defaults filled in, every operation's latencies, every check, and the
//! server's own numbers before and after.

use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use crate::check::Check;
use crate::config::Scenario;
use crate::stats::Summary;
use crate::target::{self, Host, Scrape};
use crate::Ctx;

#[derive(Serialize)]
pub struct Report {
    pub harness: Harness,
    pub host: Host,
    pub scenario: Scenario,
    /// Seconds since the epoch at the start.
    pub started: u64,
    /// Seconds the whole run took, setup and teardown included.
    pub wall: f64,
    pub ops: BTreeMap<String, Summary>,
    pub checks: BTreeMap<String, Check>,
    pub violations: u64,
    /// What only this scenario measures.
    pub detail: Value,
    pub metrics_before: Option<Scrape>,
    pub metrics_after: Option<Scrape>,
}

/// The scenario as it ran, less its passwords: a report is made to be
/// shared and compared.
fn redacted(s: &Scenario) -> Scenario {
    let mut s = s.clone();
    if let Some(a) = s.target.accounts.as_mut() {
        a.password = "(redacted)".into();
    }
    if let Some(a) = s.target.admin.as_mut() {
        a.password = "(redacted)".into();
    }
    s
}

#[derive(Serialize)]
pub struct Harness {
    pub version: &'static str,
    pub revision: Option<String>,
    /// This run's tag, in every nick and line it sent.
    pub run: String,
}

impl Report {
    pub fn new(
        ctx: &Ctx,
        started: SystemTime,
        detail: Value,
        before: Option<Scrape>,
        after: Option<Scrape>,
    ) -> Report {
        let checks = ctx.checks.report();
        Report {
            harness: Harness {
                version: env!("CARGO_PKG_VERSION"),
                revision: target::revision(),
                run: ctx.run.clone(),
            },
            host: Host::read(),
            scenario: redacted(&ctx.scenario),
            started: started
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            wall: started.elapsed().map_or(0.0, |d| d.as_secs_f64()),
            ops: ctx.stats.summary(),
            violations: checks.values().map(|c| c.violated).sum(),
            checks,
            detail,
            metrics_before: before,
            metrics_after: after,
        }
    }

    /// A few lines for a terminal: the verdict, the latencies, and every
    /// violated check with its first example.
    pub fn summary(&self) -> String {
        let mut out = format!(
            "{:?} for {}s: {}\n",
            self.scenario.run.scenario,
            self.scenario.run.duration,
            if self.violations == 0 {
                "every check held".to_owned()
            } else {
                format!("{} violations", self.violations)
            }
        );
        for (op, s) in &self.ops {
            let errors: u64 = s.errors.values().sum();
            out.push_str(&format!(
                "  {op:<24} n={:<8} p50={:.2}ms p99={:.2}ms p99.9={:.2}ms max={:.2}ms errors={errors}\n",
                s.count, s.p50_ms, s.p99_ms, s.p999_ms, s.max_ms
            ));
        }
        for (name, c) in &self.checks {
            if c.violated > 0 {
                out.push_str(&format!(
                    "  VIOLATED {name}: {} of {} ({})\n",
                    c.violated,
                    c.violated + c.held,
                    c.examples.first().map_or("", String::as_str)
                ));
            }
        }
        out
    }
}
