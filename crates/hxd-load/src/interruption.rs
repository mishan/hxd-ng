//! L-3, interruptions: idle users on `[target]`, watchers on every linked
//! server, and the links between them cut at the proxy for each of
//! `cuts` seconds in turn (`docs/load-testing.md` §8.3).
//!
//! A cut shorter than the servers' grace period must show the watchers
//! nobody leaving (`link.grace_held`); a longer one is a netsplit, every
//! user parted and joined again, and what is measured is the burst each
//! watcher takes. Either way every link must be back, and every watcher
//! shown everyone again, within `recover` of the cut ending
//! (`link.recovered`), and nobody on either side may lose their
//! connection over it. With metrics on every server, when the links came
//! back is timed too (`link.reconnect`); without, a recovery is the
//! watchers' lists alone, looked at once the grace is past and within
//! `recover` of then.
//!
//! A cut is over only once its grace is: until then the servers hold
//! what the link learned and list it whether or not the link is back,
//! and a netsplit at the grace's end belongs to this cut, not the next.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::member::{Got, Member, Parts, Rx, Tx, Wire};
use crate::proxy::Proxy;
use crate::target::{self, Scrape};
use crate::Ctx;

/// What one watcher heard since the last cut began.
#[derive(Default)]
struct Heard {
    parts: AtomicU64,
    joins: AtomicU64,
}

#[derive(Serialize)]
struct CutReport {
    cut_s: f64,
    /// Whether the cut was shorter than the servers' grace period.
    within_grace: bool,
    /// From the cut ending to every link up again, and to every
    /// watcher's list showing the whole population.
    links_back_ms: Option<f64>,
    roster_back_ms: Option<f64>,
    /// The most any one watcher heard of the population leaving and
    /// joining, from the cut to `between` after its recovery.
    parts: u64,
    joins: u64,
}

pub async fn run(
    ctx: &Arc<Ctx>,
    proxy: &Proxy,
    before: &[Option<Scrape>],
) -> Result<Value, String> {
    let c = &ctx.scenario.interruption;
    let (stop_tx, stop) = watch::channel(false);

    let mut population = Vec::new();
    let mut i = 0;
    for (wire, n) in [
        (Wire::Legacy, c.population_legacy),
        (Wire::Ng, c.population_ng),
    ] {
        for _ in 0..n {
            let m = Member::join(ctx, wire, i, None)
                .await
                .map_err(|e| format!("{} {i} could not join: {e}", wire.name()))?;
            population.push(m);
            i += 1;
        }
    }
    let nicks: Arc<BTreeSet<String>> =
        Arc::new(population.iter().map(|m| m.nick.clone()).collect());
    let mut tasks: Vec<JoinHandle<(Tx, Rx, Parts)>> = Vec::new();
    for m in population {
        tasks.push(listen(ctx, m, stop.clone(), None, &nicks));
    }
    let mut watchers = Vec::new();
    let mut n = 0;
    for server in &ctx.servers[1..] {
        for wire in std::iter::repeat_n(Wire::Legacy, c.watchers_legacy)
            .chain(std::iter::repeat_n(Wire::Ng, c.watchers_ng))
        {
            let m = Member::join_at(ctx, server, wire, ctx.nick('W', n), None)
                .await
                .map_err(|e| format!("watcher {n} on {} could not join: {e}", server.name))?;
            n += 1;
            let heard = Arc::new(Heard::default());
            watchers.push(heard.clone());
            tasks.push(listen(ctx, m, stop.clone(), Some(heard), &nicks));
        }
    }
    // One for the whole run on each linked server: one joining and leaving
    // for each look would be heard leaving, inside the grace or not.
    let mut observers = Vec::new();
    for (k, server) in ctx.servers.iter().enumerate().skip(1) {
        let wire = if server.ng.is_some() {
            Wire::Ng
        } else {
            Wire::Legacy
        };
        observers.push(
            Member::join_at(ctx, server, wire, ctx.nick('R', k), None)
                .await
                .map_err(|e| format!("observer on {} could not join: {e}", server.name))?,
        );
    }
    let mut observers = Observers {
        members: observers,
        touched: Instant::now(),
    };
    let recover = Duration::from_secs_f64(c.recover);
    if roster_back(ctx, &mut observers, &nicks, Instant::now() + recover)
        .await
        .is_none()
    {
        return Err("the watchers' servers never showed the whole population".into());
    }

    let timed = ctx.servers.iter().all(|s| s.metrics);
    let grace = Duration::from_secs(c.grace) + GRACE_MARGIN;
    let mut cuts = Vec::new();
    for &cut_s in &c.cuts {
        for w in &watchers {
            w.parts.store(0, Ordering::Relaxed);
            w.joins.store(0, Ordering::Relaxed);
        }
        let started = Instant::now();
        proxy.cut();
        observers
            .wait_until(ctx, started + Duration::from_secs_f64(cut_s))
            .await;
        proxy.restore();
        let ended = Instant::now();
        let (links_back, roster_from) = if timed {
            let back = links_back(ctx, before, ended + recover, Some(&mut observers)).await;
            (back, Instant::now())
        } else {
            observers.wait_until(ctx, started + grace).await;
            (None, Instant::now())
        };
        let roster_back = roster_back(
            ctx,
            &mut observers,
            &nicks,
            roster_from.max(ended) + recover,
        )
        .await;
        let quiet = (Instant::now() + Duration::from_secs_f64(c.between)).max(started + grace);
        observers.wait_until(ctx, quiet).await;
        let most = |f: fn(&Heard) -> &AtomicU64| {
            watchers
                .iter()
                .map(|w| f(w).load(Ordering::Relaxed))
                .max()
                .unwrap_or(0)
        };
        let ms = |t: Option<Instant>| t.map(|t| (t - ended).as_secs_f64() * 1000.0);
        let report = CutReport {
            cut_s,
            within_grace: cut_s < c.grace as f64,
            links_back_ms: ms(links_back),
            roster_back_ms: ms(roster_back),
            parts: most(|h| &h.parts),
            joins: most(|h| &h.joins),
        };
        ctx.checks.check(
            "link.recovered",
            (links_back.is_some() || !timed) && roster_back.is_some(),
            || {
                format!(
                    "after a {cut_s}s cut: links back {links_back:?}, roster back {roster_back:?}"
                )
            },
        );
        if report.within_grace {
            ctx.checks.check("link.grace_held", report.parts == 0, || {
                format!(
                    "a {cut_s}s cut, inside the grace, showed a watcher {} parts",
                    report.parts
                )
            });
        }
        if let Some(t) = links_back {
            ctx.stats.record("link.reconnect", t - ended);
        }
        cuts.push(report);
    }

    let _ = stop_tx.send(true);
    for o in observers.members {
        if let Err(e) = o.leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
    for t in tasks {
        let (tx, rx, parts) = t.await.expect("a listening task does not panic");
        if let Err(e) = Member::rejoin(tx, rx, parts).leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
    Ok(json!({ "cuts": cuts }))
}

/// How long past the grace a cut's netsplit is waited for: the servers
/// sweep what they hold when it runs out, and their parts take a moment
/// to cross.
const GRACE_MARGIN: Duration = Duration::from_secs(1);

/// Read everything `m` is sent until the run is over, counting what a
/// watcher hears of the population, and holding everyone to staying
/// connected.
fn listen(
    ctx: &Arc<Ctx>,
    m: Member,
    mut stop: watch::Receiver<bool>,
    heard: Option<Arc<Heard>>,
    nicks: &Arc<BTreeSet<String>>,
) -> JoinHandle<(Tx, Rx, Parts)> {
    let (ctx, nicks) = (ctx.clone(), nicks.clone());
    let (tx, mut rx, parts) = m.split();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => break,
                got = rx.next() => match got {
                    Ok(Got::Parted) => {
                        if let Some(h) = &heard {
                            h.parts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(Got::Joined(nick)) if nicks.contains(&nick) => {
                        if let Some(h) = &heard {
                            h.joins.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(Got::Kicked) | Err(_) => {
                        ctx.checks.violated("link.stayed_connected", format!("{} lost its connection", parts.nick));
                        break;
                    }
                    Ok(_) => {}
                },
            }
        }
        (tx, rx, parts)
    })
}

/// When every server had as many links up as before the run, polling
/// until `deadline`.
async fn links_back(
    ctx: &Ctx,
    before: &[Option<Scrape>],
    deadline: Instant,
    mut observers: Option<&mut Observers>,
) -> Option<Instant> {
    loop {
        if let Some(o) = observers.as_deref_mut() {
            o.touch(ctx).await;
        }
        let mut all = true;
        for (s, b) in ctx.servers.iter().zip(before) {
            let (Some(ng), Some(b)) = (s.ng, b) else {
                continue;
            };
            let now = target::scrape(ng).await.ok();
            all &= now.and_then(|n| n.get("hxd_links_up")) >= b.get("hxd_links_up");
        }
        if all {
            return Some(Instant::now());
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// When every observer listed the whole population, polling until
/// `deadline`. An observer that can no longer say has lost its
/// connection, which is a finding of its own, not an empty list.
async fn roster_back(
    ctx: &Ctx,
    observers: &mut Observers,
    nicks: &BTreeSet<String>,
    deadline: Instant,
) -> Option<Instant> {
    for o in &mut observers.members {
        loop {
            match o.nicks().await {
                Ok(shown) if nicks.is_subset(&shown) => break,
                Ok(_) => {}
                Err(e) => {
                    ctx.checks.violated(
                        "link.stayed_connected",
                        format!("{} lost its connection: {e}", o.nick),
                    );
                    return None;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    observers.touched = Instant::now();
    Some(Instant::now())
}

/// The observers, one on each linked server, and when they last spoke:
/// nothing reads them between looks, and an ng connection silent past
/// the server's pong deadline is dropped, so every wait asks them for
/// their lists at least every `KEEPALIVE`.
struct Observers {
    members: Vec<Member>,
    touched: Instant,
}

/// Well inside the ng port's pong deadline.
const KEEPALIVE: Duration = Duration::from_secs(20);

impl Observers {
    async fn touch(&mut self, ctx: &Ctx) {
        if self.touched.elapsed() < KEEPALIVE {
            return;
        }
        for o in &mut self.members {
            if let Err(e) = o.nicks().await {
                ctx.checks.violated(
                    "link.stayed_connected",
                    format!("{} lost its connection: {e}", o.nick),
                );
            }
        }
        self.touched = Instant::now();
    }

    async fn wait_until(&mut self, ctx: &Ctx, until: Instant) {
        while Instant::now() < until {
            self.touch(ctx).await;
            let next = (Instant::now() + KEEPALIVE).min(until);
            tokio::time::sleep_until(next.into()).await;
        }
    }
}
