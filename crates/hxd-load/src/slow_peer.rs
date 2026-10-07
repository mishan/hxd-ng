//! L-4, a slow peer: the `[chat]` room on every server but one, and that
//! one's link stalled at the proxy from `stall_after` seconds into the
//! talking until it ends, so its peer's writes to it back up as they
//! would behind a server that stopped reading (`docs/load-testing.md`
//! §8.3).
//!
//! The room is held to everything public chat is, and its delivery from
//! the stall on to no worse than `contained` times its p99 before
//! (`link.contained`): the slow peer must cost everyone else nothing.
//! With metrics, `[target]` must drop the stalled link as a slow consumer
//! within `drop_within` (`link.peer_dropped`), its writers' queues must
//! stay under `max_queued_bytes` meanwhile (`link.bounded`), and every
//! link must be back within `recover` of the stall ending
//! (`link.recovered`).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::chat;
use crate::member::{self, Member, Wire};
use crate::proxy::Proxy;
use crate::target::{self, Scrape};
use crate::Ctx;

/// What `link.contained` allows past the factor: at a millisecond or two
/// of p99, the factor alone would be scheduling noise.
const CONTAINED_FLOOR_MS: f64 = 10.0;

pub async fn run(
    ctx: &Arc<Ctx>,
    proxy: &Proxy,
    before: &[Option<Scrape>],
) -> Result<Value, String> {
    let p = &ctx.scenario.slow_peer;
    let stalled = ctx
        .servers
        .iter()
        .position(|s| s.name == p.stalled)
        .expect("checked by the scenario");
    let rest: Vec<usize> = (0..ctx.servers.len()).filter(|&k| k != stalled).collect();
    let room = chat::gather_on(ctx, &rest).await?;
    let on_target: BTreeSet<String> = room
        .members
        .iter()
        .zip(&room.on)
        .filter(|(_, &k)| k == 0)
        .map(|(m, _)| m.nick.clone())
        .collect();
    shown(ctx, stalled, &on_target).await?;

    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let stall_at = start + Duration::from_secs_f64(p.stall_after);
    let end = start + ctx.duration();
    let watch = async {
        tokio::time::sleep_until((ctx.t0 + stall_at).into()).await;
        proxy.stall();
        let seen = watch_target(ctx, before.first().and_then(Option::as_ref), stall_at, end).await;
        proxy.unstall();
        seen
    };
    let ((mut members, sent), seen) =
        tokio::join!(chat::speak_at(ctx, room, start, Some(stall_at)), watch);
    let links_back = crate::interruption::links_back(
        ctx,
        before,
        Instant::now() + Duration::from_secs_f64(p.recover),
        None,
    )
    .await;

    let ops = ctx.stats.summary();
    match (
        ops.get("chat.delivery.before"),
        ops.get("chat.delivery.after"),
    ) {
        (Some(calm), Some(stall)) if calm.count > 0 && stall.count > 0 => {
            let allowed = calm.p99_ms * p.contained + CONTAINED_FLOOR_MS;
            ctx.checks.check("link.contained", stall.p99_ms <= allowed, || {
                format!(
                    "the room's p99 went from {:.2}ms to {:.2}ms once {} stalled, past {allowed:.2}ms",
                    calm.p99_ms, stall.p99_ms, p.stalled
                )
            });
        }
        _ => ctx
            .checks
            .violated("link.contained", "no lines heard on one side of the stall"),
    }
    if let Some(seen) = &seen {
        ctx.checks.check(
            "link.peer_dropped",
            seen.dropped_after
                .is_some_and(|d| d.as_secs_f64() <= p.drop_within),
            || {
                format!(
                    "{} did not drop {} within {}s of the stall (dropped after {:?})",
                    ctx.servers[0].name, p.stalled, p.drop_within, seen.dropped_after
                )
            },
        );
        ctx.checks.check(
            "link.bounded",
            seen.peak_queued <= p.max_queued_bytes as f64,
            || format!("the classic writers held {} bytes queued", seen.peak_queued),
        );
        ctx.checks
            .check("link.recovered", links_back.is_some(), || {
                format!(
                    "the links were not back within {}s of the stall ending",
                    p.recover
                )
            });
    }

    member::roster_agrees(ctx, &mut members, &[]).await;
    chat::leave(ctx, members).await;
    Ok(json!({
        "lines_sent": sent,
        "dropped_after_s": seen.as_ref().and_then(|s| s.dropped_after).map(|d| d.as_secs_f64()),
        "peak_queued_bytes": seen.as_ref().map(|s| s.peak_queued),
        "peak_resident_bytes": seen.as_ref().map(|s| s.peak_resident),
    }))
}

/// Wait until a client on the stalled server lists `nicks`, the room's
/// members on `[target]`: its link is up, through a proxy the run only
/// just started, so the stall has a link to stall. Gone again before the
/// talking, so no room's list shows it.
async fn shown(ctx: &Ctx, stalled: usize, nicks: &BTreeSet<String>) -> Result<(), String> {
    let at = &ctx.servers[stalled];
    let wire = if at.ng.is_some() {
        Wire::Ng
    } else {
        Wire::Legacy
    };
    let mut o = Member::join_at(ctx, at, wire, ctx.nick('S', 0), None)
        .await
        .map_err(|e| format!("a client on {} could not join: {e}", at.name))?;
    let deadline = Instant::now() + Duration::from_secs_f64(ctx.scenario.slow_peer.recover);
    while !nicks.is_subset(&o.nicks().await.unwrap_or_default()) {
        if Instant::now() >= deadline {
            let _ = o.leave().await;
            return Err(format!("{} never showed the room on its link", at.name));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    o.leave().await.map_err(|e| e.to_string())
}

/// What `[target]`'s metrics showed while the link was stalled.
struct Seen {
    /// From the stall to the first sign `[target]` gave up on the link.
    dropped_after: Option<Duration>,
    peak_queued: f64,
    peak_resident: f64,
}

/// Watch `[target]` from the stall to the end of the talking, when it
/// has metrics.
async fn watch_target(
    ctx: &Ctx,
    before: Option<&Scrape>,
    stall_at: Duration,
    end: Duration,
) -> Option<Seen> {
    let (Some(ng), Some(before)) = (ctx.servers[0].ng.filter(|_| ctx.servers[0].metrics), before)
    else {
        tokio::time::sleep_until((ctx.t0 + end).into()).await;
        return None;
    };
    let gave_up_before = gave_up(before);
    // Given up on this link, not another: one fewer up than before.
    let links_before = before.get("hxd_links_up").unwrap_or(0.0);
    let mut seen = Seen {
        dropped_after: None,
        peak_queued: 0.0,
        peak_resident: 0.0,
    };
    while ctx.t0.elapsed() < end {
        if let Ok(s) = target::scrape(ng).await {
            let fewer = s.get("hxd_links_up").unwrap_or(0.0) < links_before;
            if seen.dropped_after.is_none() && fewer && gave_up(&s) > gave_up_before {
                seen.dropped_after = Some(ctx.t0.elapsed().saturating_sub(stall_at));
            }
            let queued = s
                .get("hxd_write_queued_bytes{wire=\"legacy\"}")
                .unwrap_or(0.0);
            seen.peak_queued = seen.peak_queued.max(queued);
            let resident = s.get("hxd_process_resident_bytes").unwrap_or(0.0);
            seen.peak_resident = seen.peak_resident.max(resident);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Some(seen)
}

/// Every way a server gives up on a link that will not take what it is
/// sent: its writer's bound, or its share of the export feed or of what
/// other links pass on.
fn gave_up(s: &Scrape) -> f64 {
    s.get("hxd_link_ends_total{reason=\"slow_consumer\"}")
        .unwrap_or(0.0)
        + s.get("hxd_link_lagged_total{queue=\"export\"}")
            .unwrap_or(0.0)
        + s.get("hxd_link_lagged_total{queue=\"relay\"}")
            .unwrap_or(0.0)
}
