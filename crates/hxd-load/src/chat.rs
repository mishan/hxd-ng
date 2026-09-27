//! S3, public chat: readers and talkers on both wires, lines on a fixed
//! schedule, every line accounted for by every reader.
//!
//! Membership is fixed for the whole run: everyone joins before the first
//! line is due and stays until the last is heard (or `settle` runs out),
//! so a reader missing a line is a violation, not bad timing.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::ledger::{self, Heard};
use crate::member::{self, Got, Member, Parts, Rx, Tx, Wire};
use crate::Ctx;

/// Everyone in the room, joined. Talkers come first, so talker `k` is
/// sender `k` in the ledger.
pub struct Room {
    pub members: Vec<Member>,
    pub talkers: usize,
}

pub async fn gather(ctx: &Ctx) -> Result<Room, String> {
    let c = &ctx.scenario.chat;
    let plan = [
        (Wire::Legacy, c.talkers_legacy),
        (Wire::Ng, c.talkers_ng),
        (Wire::Legacy, c.readers_legacy),
        (Wire::Ng, c.readers_ng),
    ];
    let mut members = Vec::new();
    let mut i = 0;
    for (wire, n) in plan {
        for _ in 0..n {
            let m = Member::join(ctx, wire, i, None)
                .await
                .map_err(|e| format!("{} {i} could not join: {e}", wire.name()))?;
            members.push(m);
            i += 1;
        }
    }
    Ok(Room {
        members,
        talkers: c.talkers_legacy + c.talkers_ng,
    })
}

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let room = gather(ctx).await?;
    let (mut members, sent) = speak(ctx, room).await;
    member::roster_agrees(ctx, &mut members, &[]).await;
    leave(ctx, members).await;
    Ok(json!({ "lines_sent": sent }))
}

/// Run the room's conversation to the end: talk for the run's duration,
/// then wait for every reader to hear every line, or for `settle` to run
/// out. Returns the members, whole again, and how many lines each talker
/// sent.
pub async fn speak(ctx: &Arc<Ctx>, room: Room) -> (Vec<Member>, Vec<u64>) {
    let c = &ctx.scenario.chat;
    let (done_tx, done_rx) = watch::channel(None::<Arc<Vec<u64>>>);
    let mut readers: Vec<JoinHandle<(Rx, Heard, Parts)>> = Vec::new();
    let mut talkers: Vec<JoinHandle<(Tx, u64)>> = Vec::new();
    let mut txs = Vec::new();
    for (k, m) in room.members.into_iter().enumerate() {
        let (tx, rx, parts) = m.split();
        let own = (k < room.talkers).then_some(k);
        let heard = Heard::new(parts.nick.clone(), own);
        readers.push(tokio::spawn(read(
            ctx.clone(),
            rx,
            heard,
            parts,
            done_rx.clone(),
        )));
        txs.push(tx);
    }
    // Every talker on its own schedule, staggered so the room as a whole
    // hears `rate` lines a second, evenly.
    let every = Duration::from_secs_f64(room.talkers as f64 / c.rate);
    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let end = start + ctx.duration();
    let mut rest = Vec::new();
    for (k, tx) in txs.into_iter().enumerate() {
        if k < room.talkers {
            let offset = every.mul_f64(k as f64 / room.talkers as f64);
            talkers.push(tokio::spawn(talk(
                ctx.clone(),
                tx,
                k,
                start + offset,
                every,
                end,
            )));
        } else {
            rest.push(tx);
        }
    }
    let mut sent = Vec::new();
    let mut talker_txs = Vec::new();
    for t in talkers {
        let (tx, n) = t.await.expect("a talker task does not panic");
        sent.push(n);
        talker_txs.push(tx);
    }
    let _ = done_tx.send(Some(Arc::new(sent.clone())));

    let mut members = Vec::new();
    for (k, (r, tx)) in readers
        .into_iter()
        .zip(talker_txs.into_iter().chain(rest))
        .enumerate()
    {
        let (rx, heard, parts) = r.await.expect("a reader task does not panic");
        heard.account(&sent, &ctx.checks);
        ctx.stats.merge("chat.delivery", &heard.delivery);
        if k < room.talkers {
            ctx.stats.merge("chat.echo", &heard.echo);
        }
        members.push(Member::rejoin(tx, rx, parts));
    }
    (members, sent)
}

/// Send lines on schedule until `end`: line `n` is due at
/// `first + n * every`, whenever the previous one actually went out.
async fn talk(
    ctx: Arc<Ctx>,
    mut tx: Tx,
    me: usize,
    first: Duration,
    every: Duration,
    end: Duration,
) -> (Tx, u64) {
    let pad = ctx.scenario.chat.line_bytes;
    let mut sent = 0u64;
    loop {
        let due = first + every.mul_f64(sent as f64);
        if due >= end {
            break;
        }
        tokio::time::sleep_until((ctx.t0 + due).into()).await;
        let line = ledger::line(&ctx.run, me, sent + 1, due, pad);
        match tx.chat(&line).await {
            Ok(()) => sent += 1,
            Err(e) => {
                ctx.stats.error("chat.send", &e.to_string());
                break;
            }
        }
    }
    (tx, sent)
}

/// Hear everything until every line sent has arrived, or `settle` has
/// passed since the talking stopped.
async fn read(
    ctx: Arc<Ctx>,
    mut rx: Rx,
    mut heard: Heard,
    parts: Parts,
    mut done: watch::Receiver<Option<Arc<Vec<u64>>>>,
) -> (Rx, Heard, Parts) {
    let settle = Duration::from_secs_f64(ctx.scenario.run.settle);
    let mut deadline = None::<tokio::time::Instant>;
    loop {
        let sent = done.borrow().clone();
        if let Some(sent) = &sent {
            if heard.has_all(sent) {
                break;
            }
            let d = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + settle);
            if tokio::time::Instant::now() >= d {
                break;
            }
        }
        let wait = deadline.unwrap_or_else(|| tokio::time::Instant::now() + settle);
        tokio::select! {
            _ = done.changed(), if sent.is_none() => {}
            _ = tokio::time::sleep_until(wait) => {}
            got = rx.next() => match got {
                Ok(Got::Chat(text)) => heard.hear(&ctx.run, &text, ctx.t0, &ctx.checks),
                Ok(Got::Refused(v)) => ctx.stats.error("chat.send", &v["error"]["code"].to_string()),
                Ok(Got::Kicked) => {
                    ctx.checks.violated("chat.stayed", format!("{} was kicked", parts.nick));
                    break;
                }
                Ok(Got::Other) => {}
                Err(e) => {
                    ctx.checks.violated("chat.stayed", format!("{} lost its connection: {e}", parts.nick));
                    break;
                }
            },
        }
    }
    if parts.wire == Wire::Ng {
        let faults = rx.seq_faults();
        ctx.checks.check("ng.seq_gapless", faults.is_empty(), || {
            format!("{}: {faults:?}", parts.nick)
        });
    }
    (rx, heard, parts)
}

pub async fn leave(ctx: &Ctx, members: Vec<Member>) {
    for m in members {
        if let Err(e) = m.leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
}
