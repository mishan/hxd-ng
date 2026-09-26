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

pub mod accounts;
pub mod chat;
pub mod check;
pub mod churn;
pub mod config;
pub mod ledger;
pub mod member;
pub mod report;
pub mod slow;
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
    /// The run's clock: every due time and latency is measured on it.
    pub t0: Instant,
    /// A tag in every nick and chat line, so this run's traffic is told
    /// apart from anyone else's.
    pub run: String,
    pub stats: Stats,
    pub checks: Checks,
    rng: Mutex<Rng>,
}

impl Ctx {
    pub fn new(scenario: Scenario) -> Arc<Ctx> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let seed = scenario.run.seed;
        Arc::new(Ctx {
            scenario,
            t0: Instant::now(),
            run: format!("{:04x}", nanos & 0xffff),
            stats: Stats::default(),
            checks: Checks::default(),
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
    let log = match &ctx.scenario.target.log {
        Some(path) => Some(target::LogTail::start(path)?),
        None => None,
    };
    let before = scrape(&ctx).await?;

    let extra = match ctx.scenario.run.scenario {
        Kind::LoginStorm => storm::run(&ctx).await?,
        Kind::Chat => chat::run(&ctx).await?,
        Kind::SlowConsumer => slow::run(&ctx).await?,
        Kind::Churn => churn::run(&ctx).await?,
    };

    // Everyone this run brought has left; the roster should say so.
    member::no_ghosts(&ctx, before.as_ref()).await;
    let after = scrape(&ctx).await?;

    if let Some(log) = log {
        let lines = log.alarming()?;
        ctx.checks.check("server.log_clean", lines.is_empty(), || {
            format!("{} alarming lines, first: {}", lines.len(), lines[0])
        });
    }
    Ok(report::Report::new(&ctx, started, extra, before, after))
}

async fn scrape(ctx: &Ctx) -> Result<Option<target::Scrape>, String> {
    match (ctx.scenario.target.metrics, ctx.scenario.target.ng) {
        (true, Some(ng)) => target::scrape(ng).await.map(Some),
        _ => Ok(None),
    }
}
