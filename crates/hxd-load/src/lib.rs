//! `hxd-load`: load scenarios for hxd-ng on both wires, with the server's
//! invariants checked while it is under load.
//!
//! The goal is bottlenecks and bugs, in that order of visibility;
//! throughput numbers are a side effect. Every scenario times what it
//! does and also checks what must hold whatever the load: every chat line
//! reaches every reader exactly once and in order, ng seqs stay gapless
//! across resumes, a detached session is there when it comes back, the
//! user lists agree once things are quiet, nobody this
//! run brought is left on the roster after it leaves, and the server logs
//! no panic. Any violation fails the run.
//!
//! Scenarios (the load-testing plan's numbering):
//!
//! - **S1** [`storm`]: logins at a rising rate, on each wire.
//! - **S3** [`chat`]: readers and talkers in public chat.
//! - **S5** [`slow`]: the same, with clients that stop reading.
//! - **S6** [`churn`]: sessions dropping and resuming, connections dying
//!   mid-handshake, kicks.
//! - **L-3** [`interruption`]: links between servers cut at a proxy
//!   ([`proxy`]) and restored, across their grace period.
//! - **L-4** [`slow_peer`]: one server's link stalled at the proxy while
//!   the room talks on the others.
//! - **L-6** [`requests`]: private messages and user info to ghosts, as
//!   there are more of them.

pub mod accounts;
pub mod chat;
pub mod check;
pub mod churn;
pub mod config;
pub mod interruption;
pub mod ledger;
pub mod member;
pub mod proxy;
pub mod report;
pub mod requests;
pub mod slow;
pub mod slow_peer;
pub mod stats;
pub mod storm;
pub mod target;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use check::Checks;
use config::{Kind, Scenario};
use stats::Stats;

/// What every task of a run shares.
pub struct Ctx {
    pub scenario: Scenario,
    /// `[target]` and the servers linked to it, in that order.
    pub servers: Vec<config::Server>,
    /// The run's clock: every due time and latency is measured on it.
    pub t0: Instant,
    /// A tag in every nick and chat line, so this run's traffic is told
    /// apart from anyone else's.
    pub run: String,
    pub stats: Stats,
    pub checks: Checks,
    /// Logins the server refused as busy (`member::retry_busy`).
    pub busy: member::BusyLogins,
    rng: Mutex<Rng>,
}

impl Ctx {
    pub fn new(scenario: Scenario) -> Arc<Ctx> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let seed = scenario.run.seed;
        Arc::new(Ctx {
            servers: scenario.target.servers(),
            scenario,
            t0: Instant::now(),
            run: format!("{:04x}", nanos & 0xffff),
            stats: Stats::default(),
            checks: Checks::default(),
            busy: member::BusyLogins::default(),
            rng: Mutex::new(Rng::new(seed)),
        })
    }

    /// A nick for client `i` of kind `w` (`L`egacy, `T`LS, `N`g, ...):
    /// short enough for the classic wire's 31 bytes.
    pub fn nick(&self, w: char, i: usize) -> String {
        format!("{}{}{w}{i}", self.scenario.run.prefix, self.run)
    }

    /// Whether a nick is one of this run's.
    pub fn ours(&self, nick: &str) -> bool {
        nick.starts_with(&format!("{}{}", self.scenario.run.prefix, self.run))
    }

    pub fn random(&self) -> f64 {
        self.rng.lock().unwrap().unit()
    }

    /// Exponentially distributed, mean `mean` seconds.
    pub fn exp(&self, mean: f64) -> Duration {
        let u = self.random().max(1e-12);
        Duration::from_secs_f64(-u.ln() * mean)
    }

    pub fn duration(&self) -> Duration {
        Duration::from_secs_f64(self.scenario.run.duration)
    }
}

/// xorshift64*: seeded, so a run's choices repeat.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let x = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        (x >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Run a scenario to the end and report on it.
pub async fn run(scenario: Scenario) -> Result<report::Report, String> {
    scenario.check()?;
    let started = SystemTime::now();
    let ctx = Ctx::new(scenario);
    let mut logs = Vec::new();
    for s in &ctx.servers {
        if let Some(path) = &s.log {
            logs.push((s.name.clone(), target::LogTail::start(path)?));
        }
    }
    let proxy = match &ctx.scenario.target.proxy {
        Some(p) => Some(
            proxy::Proxy::start(p.listen, p.upstream, Duration::from_millis(p.latency_ms)).await?,
        ),
        None => None,
    };
    let before = links_up(&ctx).await?;

    let extra = match ctx.scenario.run.scenario {
        Kind::LoginStorm => storm::run(&ctx).await?,
        Kind::Chat => chat::run(&ctx).await?,
        Kind::SlowConsumer => slow::run(&ctx).await?,
        Kind::Churn => churn::run(&ctx).await?,
        Kind::Interruption => {
            let proxy = proxy.as_ref().expect("checked by the scenario");
            interruption::run(&ctx, proxy, &before).await?
        }
        Kind::SlowPeer => {
            let proxy = proxy.as_ref().expect("checked by the scenario");
            slow_peer::run(&ctx, proxy, &before).await?
        }
        Kind::Requests => requests::run(&ctx, proxy.as_ref()).await?,
    };

    // Everyone this run brought has left; every roster should say so.
    for (k, b) in before.iter().enumerate() {
        member::no_ghosts(&ctx, k, b.as_ref()).await;
    }
    // From here a failure is a finding, not a reason to lose the report:
    // a server that died under load is the run most worth keeping.
    let mut after = Vec::new();
    for s in &ctx.servers {
        after.push(match scrape(s).await {
            Ok(after) => after,
            Err(e) => {
                ctx.checks
                    .violated("server.reachable", format!("{} after the run: {e}", s.name));
                None
            }
        });
    }
    // Either scenario that takes a link down on purpose has checks of its
    // own for how it came back.
    let cuts = matches!(
        ctx.scenario.run.scenario,
        Kind::Interruption | Kind::SlowPeer
    );
    if ctx.servers.len() > 1 && !cuts {
        links_stayed(&ctx, &before, &after);
    }
    for (name, log) in logs {
        match log.alarming() {
            Ok(lines) => ctx.checks.check("server.log_clean", lines.is_empty(), || {
                format!(
                    "{name}: {} alarming lines, first: {}",
                    lines.len(),
                    lines[0]
                )
            }),
            Err(e) => ctx
                .checks
                .violated("server.log_clean", format!("{name} unreadable: {e}")),
        }
    }
    Ok(report::Report::new(&ctx, started, extra, before, after))
}

async fn scrape(s: &config::Server) -> Result<Option<target::Scrape>, String> {
    match (s.metrics, s.ng) {
        (true, Some(ng)) => target::scrape(ng)
            .await
            .map(Some)
            .map_err(|e| format!("{}: {e}", s.name)),
        _ => Ok(None),
    }
}

/// Every server's scrape once each with metrics has a link up. A run
/// across servers that are not linked would fail every check for the
/// server's fault rather than the run's, so it does not start; a link
/// through the run's own proxy comes up only once the run has started
/// it, and is waited for. Without metrics nothing is waited for here.
async fn links_up(ctx: &Ctx) -> Result<Vec<Option<target::Scrape>>, String> {
    let deadline = Instant::now() + LINK_WAIT;
    loop {
        let mut scrapes = Vec::new();
        for s in &ctx.servers {
            scrapes.push(scrape(s).await?);
        }
        // Every topology a run builds is a star on `[target]`: it has a
        // link to each of the others, and each of them one to it. Counted
        // only once all are, a scenario's count of links before is whole.
        let want = |k: usize| if k == 0 { ctx.servers.len() - 1 } else { 1 } as f64;
        let down = ctx
            .servers
            .iter()
            .zip(&scrapes)
            .enumerate()
            .filter(|(k, (_, b))| {
                ctx.servers.len() > 1
                    && b.as_ref()
                        .is_some_and(|b| b.get("hxd_links_up").unwrap_or(0.0) < want(*k))
            })
            .map(|(_, (s, _))| s.name.clone())
            .next();
        match down {
            None => return Ok(scrapes),
            Some(name) if Instant::now() >= deadline => {
                return Err(format!("{name} does not have all its links up"))
            }
            Some(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// How long a run waits for its servers' links before it gives up: a
/// dialer refused while the proxy was not yet listening backs off.
const LINK_WAIT: Duration = Duration::from_secs(30);

/// No link ended during the run, nor did one come up: the scenario cut
/// none, so either is a link that went down.
fn links_stayed(ctx: &Ctx, before: &[Option<target::Scrape>], after: &[Option<target::Scrape>]) {
    for ((s, b), a) in ctx.servers.iter().zip(before).zip(after) {
        let (Some(b), Some(a)) = (b, a) else { continue };
        let ends = |m: &target::Scrape| -> f64 {
            m.0.iter()
                .filter(|(k, _)| k.starts_with("hxd_link_ends_total"))
                .map(|(_, v)| v)
                .sum()
        };
        let (eb, ea) = (ends(b), ends(a));
        let (ub, ua) = (b.get("hxd_links_up"), a.get("hxd_links_up"));
        ctx.checks
            .check("link.stayed_up", eb == ea && ub == ua, || {
                format!(
                    "{}: {} link ends during the run, links up {ub:?} then {ua:?}",
                    s.name,
                    ea - eb
                )
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrape(series: &[(&str, f64)]) -> Option<target::Scrape> {
        Some(target::Scrape(
            series.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        ))
    }

    #[test]
    fn a_link_that_ended_went_down_or_came_up_during_the_run_is_a_violation() {
        let up = scrape(&[("hxd_links_up", 1.0)]);
        let ended = scrape(&[
            ("hxd_links_up", 1.0),
            ("hxd_link_ends_total{reason=\"dead\"}", 1.0),
        ]);
        let down = scrape(&[("hxd_links_up", 0.0)]);
        let another = scrape(&[("hxd_links_up", 2.0)]);
        for (after, ok) in [
            (&up, true),
            (&ended, false),
            (&down, false),
            (&another, false),
        ] {
            let ctx = Ctx::new(Scenario::default());
            links_stayed(&ctx, std::slice::from_ref(&up), std::slice::from_ref(after));
            let r = ctx.checks.report();
            assert_eq!(r["link.stayed_up"].violated == 0, ok, "{after:?}");
        }
    }
}
