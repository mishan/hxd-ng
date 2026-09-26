//! S5, the slow consumer: the chat room of S3, plus clients that log in
//! and then never read another byte. Everything the room says is still
//! addressed to them.
//!
//! What should happen is that the server notices, disconnects them, and
//! holds a bounded amount for them meanwhile; what the load-testing plan
//! suspects is that the classic wire's writers queue without limit. The
//! run samples the server's memory and write queues (with `metrics`),
//! and afterwards reads from each stalled client to see whether the
//! server hung up on it or is still sending. Everyone else in the room is
//! held to S3's invariants: one client's stall must cost the others
//! nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hxd_testclient::Error;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::chat;
use crate::member::{self, Member, Rx, Wire};
use crate::Ctx;

#[derive(Serialize)]
struct Sample {
    t: f64,
    resident_bytes: Option<f64>,
    write_queued_bytes: Option<f64>,
    sessions: Option<f64>,
}

#[derive(Serialize)]
struct Stalled {
    nick: String,
    wire: &'static str,
    /// The server closed the connection.
    disconnected: bool,
    /// Frames (classic) or messages (ng) still waiting to be read, up to
    /// the probe's limit.
    drained: u64,
}

/// How long, and how much, the probe reads from a stalled client.
const PROBE_FOR: Duration = Duration::from_secs(5);
const PROBE_FRAMES: u64 = 1_000_000;

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let s = &ctx.scenario.slow_consumer;
    let room = chat::gather(ctx).await?;
    let mut stalled = Vec::new();
    let base = room.members.len();
    for (k, (wire, n)) in [(Wire::Legacy, s.stalled_legacy), (Wire::Ng, s.stalled_ng)]
        .into_iter()
        .enumerate()
    {
        for j in 0..n {
            let m = Member::join(ctx, wire, base + k * 1000 + j, None)
                .await
                .map_err(|e| format!("stalled {} {j} could not join: {e}", wire.name()))?;
            // Split, and read nothing from here on.
            stalled.push(m.split());
        }
    }

    let (stop, stopped) = watch::channel(false);
    let sampler = ctx.scenario.target.metrics.then(|| {
        let ctx = ctx.clone();
        tokio::spawn(async move { sample(&ctx, stopped).await })
    });
    let (mut members, sent) = chat::speak(ctx, room).await;
    let _ = stop.send(true);
    let samples = match sampler {
        Some(t) => t.await.unwrap_or_default(),
        None => Vec::new(),
    };
    let stalled_nicks: Vec<String> = stalled.iter().map(|(_, _, p)| p.nick.clone()).collect();
    member::roster_agrees(ctx, &mut members, &stalled_nicks).await;

    let mut probed = Vec::new();
    for (_, rx, parts) in stalled {
        let (disconnected, drained) = probe(rx).await;
        ctx.checks.check("slow.disconnected", disconnected, || {
            format!(
                "{} ({}) was still connected after the run, {drained} frames waiting",
                parts.nick,
                parts.wire.name()
            )
        });
        probed.push(Stalled {
            nick: parts.nick,
            wire: parts.wire.name(),
            disconnected,
            drained,
        });
    }
    if let Some(peak) = samples
        .iter()
        .filter_map(|s| s.write_queued_bytes)
        .reduce(f64::max)
    {
        ctx.checks
            .check("slow.bounded", peak <= s.max_queued_bytes as f64, || {
                format!(
                    "the classic writers held {peak} bytes at the peak; the bound is {}",
                    s.max_queued_bytes
                )
            });
    }
    chat::leave(ctx, members).await;
    Ok(json!({ "lines_sent": sent, "stalled": probed, "samples": samples }))
}

/// Scrape every `sample_every` until told to stop.
async fn sample(ctx: &Ctx, mut stop: watch::Receiver<bool>) -> Vec<Sample> {
    let ng = ctx.scenario.target.ng.expect("checked by the scenario");
    let every = Duration::from_secs_f64(ctx.scenario.slow_consumer.sample_every);
    let mut out = Vec::new();
    loop {
        if let Ok(s) = crate::target::scrape(ng).await {
            out.push(Sample {
                t: ctx.t0.elapsed().as_secs_f64(),
                resident_bytes: s.get("hxd_process_resident_bytes"),
                write_queued_bytes: s.get("hxd_write_queued_bytes{wire=\"legacy\"}"),
                sessions: s.sessions(),
            });
        }
        tokio::select! {
            _ = stop.changed() => return out,
            _ = tokio::time::sleep(every) => {}
        }
    }
}

/// Read what the server still has for a stalled client: until it hangs
/// up, until the limit, or until the socket goes quiet.
async fn probe(mut rx: Rx) -> (bool, u64) {
    let until = Instant::now() + PROBE_FOR;
    let mut frames = 0u64;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || frames >= PROBE_FRAMES {
            return (false, frames);
        }
        let quiet = left.min(Duration::from_millis(500));
        match tokio::time::timeout(quiet, next(&mut rx)).await {
            Err(_) => return (false, frames), // Quiet: connected, and drained.
            Ok(Ok(())) => frames += 1,
            Ok(Err(Error::Closed | Error::Io(_))) => return (true, frames),
            Ok(Err(_)) => return (false, frames),
        }
    }
}

async fn next(rx: &mut Rx) -> Result<(), Error> {
    match rx {
        Rx::Legacy(rx) => rx.recv_forever().await.map(|_| ()),
        Rx::Ng(rx) => rx.next_forever().await.map(|_| ()),
    }
}
