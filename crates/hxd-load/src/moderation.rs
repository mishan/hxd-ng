//! L-7, moderation under load: the `[chat]` room on every server, and a
//! moderator on `[target]` kicking or banning the users of the servers
//! linked to it, one every `every` seconds from `acts_after` into the
//! talking (`docs/load-testing.md` §8.3).
//!
//! A kick hides the ghost at the kicker's server and tells the user,
//! who stays connected at home; a ban is placed by the user's home
//! server, on the account, and ends the session there. Each act must be
//! answered, and carried out on the victim's server within `settle`
//! (`link.acts_carried`), a kicked ghost gone from the moderator's list
//! (`link.kick_hides`); and the room, the home servers' bans written to
//! their stores meanwhile, must not notice (`link.contained`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hxproto::messages::{tag, ClientHdr};
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::chat;
use crate::member::{self, Conn, Got, Member, Parts, Rx, Tx, Wire};
use crate::Ctx;

/// What a victim heard, by when, on the run's clock.
#[derive(Default, Clone, Copy)]
struct Seen {
    /// Told another server removed it: the kick's own words, not any
    /// message from the server.
    told: Option<Duration>,
    ended: Option<Duration>,
}

type Victims = Arc<Mutex<HashMap<String, Seen>>>;

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let m = &ctx.scenario.moderation;
    let accounts = ctx
        .scenario
        .target
        .accounts
        .clone()
        .expect("checked by the scenario");
    let admin = ctx
        .scenario
        .target
        .admin
        .clone()
        .expect("checked by the scenario");
    let (stop_tx, stop) = watch::channel(false);
    let seen: Victims = Arc::default();

    let mut victims = Vec::new();
    let mut listeners = Vec::new();
    for i in 0..m.victims {
        let server = &ctx.servers[1 + i % (ctx.servers.len() - 1)];
        let creds = Some((accounts.login(i), accounts.password.clone()));
        let v = Member::join_at(ctx, server, Wire::Legacy, ctx.nick('X', i), creds)
            .await
            .map_err(|e| format!("victim {i} could not join: {e}"))?;
        victims.push(v.nick.clone());
        listeners.push(listen(ctx.clone(), v, stop.clone(), seen.clone()));
    }
    let creds = Some((admin.login, admin.password));
    let mut moderator =
        Member::join_at(ctx, &ctx.servers[0], Wire::Legacy, ctx.nick('M', 0), creds)
            .await
            .map_err(|e| format!("the moderator could not log in: {e}"))?;
    let uids = shown(ctx, &mut moderator, &victims).await?;
    let room = chat::gather(ctx).await?;

    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let acts_at = start + Duration::from_secs_f64(m.acts_after);
    let end = start + ctx.duration();
    let ((mut members, sent), (moderator, acts)) = tokio::join!(
        chat::speak_at(ctx, room, start, Some(acts_at)),
        act(ctx, moderator, &victims, &uids, acts_at, end),
    );
    carried(ctx, &seen, &acts).await;
    let mut moderator = moderator;
    still_hidden(ctx, &mut moderator, &acts).await;
    chat::contained(ctx, m.contained, "the acts began");

    // The victims, kicked and not, and the moderator are no members of
    // the room, which lists them as it may.
    let mut apart = victims.clone();
    apart.push(ctx.nick('M', 0));
    member::roster_agrees(ctx, &mut members, &apart).await;
    chat::leave(ctx, members).await;
    let _ = stop_tx.send(true);
    for l in listeners {
        let (tx, rx, parts, ended) = l.await.expect("a victim's listener does not panic");
        if !ended {
            let _ = Member::rejoin(tx, rx, parts).leave().await;
        }
    }
    let _ = moderator.leave().await;
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &acts {
        *kinds
            .entry(if a.ban { "bans" } else { "kicks" })
            .or_default() += 1;
    }
    Ok(json!({ "lines_sent": sent, "acts": kinds }))
}

/// One act: on whom, which, when it was due, and whether it was answered.
struct Act {
    nick: String,
    ban: bool,
    due: Duration,
    answered: Result<(), String>,
}

/// Kick or ban one victim every `every` seconds from `from` until `end`
/// or the victims run out, timing each answer from when it was due.
async fn act(
    ctx: &Ctx,
    mut moderator: Member,
    victims: &[String],
    uids: &[u64],
    from: Duration,
    end: Duration,
) -> (Member, Vec<Act>) {
    let m = &ctx.scenario.moderation;
    let mut acts = Vec::new();
    for (i, (nick, &uid)) in victims.iter().zip(uids).enumerate() {
        let due = from + Duration::from_secs_f64(i as f64 * m.every);
        if due >= end {
            break;
        }
        drain_until(&mut moderator, ctx.t0 + due).await;
        let ban = ctx.random() < m.ban_share;
        let mut chunks = vec![(tag::UID, (uid as u16).to_be_bytes().to_vec())];
        if ban {
            chunks.push((tag::BAN, vec![0, 1]));
        }
        let Conn::Legacy(c) = &mut moderator.conn else {
            unreachable!("the moderator is classic");
        };
        let answered = c
            .call(ClientHdr::UserKick.as_u32(), &chunks)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
        drop(c.rx.take_backlog());
        if answered.is_ok() {
            let op = if ban {
                "moderation.ban"
            } else {
                "moderation.kick"
            };
            ctx.stats.record(op, ctx.t0.elapsed().saturating_sub(due));
        }
        if answered.is_ok() && !ban {
            // Hidden at once at the kicker's server, whatever its home
            // server makes of it.
            let shown = moderator.users().await.unwrap_or_default();
            ctx.checks.check(
                "link.kick_hides",
                shown.iter().all(|(_, u)| *u != uid),
                || {
                    format!(
                        "{nick} still listed on {} after its kick",
                        ctx.servers[0].name
                    )
                },
            );
        }
        acts.push(Act {
            nick: nick.clone(),
            ban,
            due,
            answered,
        });
    }
    (moderator, acts)
}

/// Read and drop what the moderator is sent until `until`: it hears the
/// room, and a classic server drops a client whose writes go a minute
/// without progress.
async fn drain_until(moderator: &mut Member, until: std::time::Instant) {
    let Conn::Legacy(c) = &mut moderator.conn else {
        unreachable!("the moderator is classic");
    };
    let until = tokio::time::Instant::from_std(until);
    while tokio::time::timeout_at(until, c.rx.recv_forever())
        .await
        .is_ok()
    {}
    drop(c.rx.take_backlog());
}

/// Every victim acted on, kicked or banned, still not on the moderator's
/// list at the end: a kicked ghost stays hidden for as long as it is
/// shown, and a banned one is gone.
async fn still_hidden(ctx: &Ctx, moderator: &mut Member, acts: &[Act]) {
    let listed = moderator.nick_list().await.unwrap_or_default();
    for a in acts.iter().filter(|a| a.answered.is_ok()) {
        ctx.checks
            .check("link.kick_hides", !listed.contains(&a.nick), || {
                format!(
                    "{} listed on {} again by the end",
                    a.nick, ctx.servers[0].name
                )
            });
    }
}

/// Every act answered, and within `settle` carried out at the victim's
/// server: a kicked user told and still there, a banned one gone.
async fn carried(ctx: &Ctx, seen: &Victims, acts: &[Act]) {
    let done = |s: &Seen, a: &Act| {
        if a.ban {
            s.ended.is_some()
        } else {
            s.told.is_some()
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(ctx.scenario.run.settle);
    while tokio::time::Instant::now() < deadline {
        let all = {
            let s = seen.lock().unwrap();
            acts.iter()
                .filter(|a| a.answered.is_ok())
                .all(|a| done(&s.get(&a.nick).copied().unwrap_or_default(), a))
        };
        if all {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let s = seen.lock().unwrap();
    for a in acts {
        let v = s.get(&a.nick).copied().unwrap_or_default();
        if let Err(e) = &a.answered {
            ctx.checks.violated(
                "link.acts_carried",
                format!("{}'s act refused: {e}", a.nick),
            );
            continue;
        }
        let kept = a.ban || v.ended.is_none();
        ctx.checks
            .check("link.acts_carried", done(&v, a) && kept, || {
                format!(
                    "{} {}: told {:?}, ended {:?}",
                    a.nick,
                    if a.ban { "banned" } else { "kicked" },
                    v.told,
                    v.ended
                )
            });
        let at = if a.ban { v.ended } else { v.told };
        if let Some(at) = at {
            ctx.stats
                .record("moderation.carried", at.saturating_sub(a.due));
        }
    }
}

/// The uids the moderator's server shows `nicks` under, once it shows
/// them all, within `settle`.
async fn shown(ctx: &Ctx, looker: &mut Member, nicks: &[String]) -> Result<Vec<u64>, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(ctx.scenario.run.settle);
    loop {
        if let Ok(users) = looker.users().await {
            let by_nick: HashMap<String, u64> = users.into_iter().collect();
            if let Some(uids) = nicks.iter().map(|n| by_nick.get(n).copied()).collect() {
                return Ok(uids);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("{} never showed every victim", ctx.servers[0].name));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Hear what a victim is told until the run stops or its session ends.
fn listen(
    ctx: Arc<Ctx>,
    m: Member,
    mut stop: watch::Receiver<bool>,
    seen: Victims,
) -> JoinHandle<(Tx, Rx, Parts, bool)> {
    let (tx, mut rx, parts) = m.split();
    tokio::spawn(async move {
        let mut ended = false;
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => break,
                got = rx.next() => {
                    let now = ctx.t0.elapsed();
                    let mut s = seen.lock().unwrap();
                    let v = s.entry(parts.nick.clone()).or_default();
                    match got {
                        Ok(Got::Told(text)) if text.contains("has removed you") => {
                            v.told.get_or_insert(now);
                        }
                        Ok(Got::Kicked) | Err(_) => {
                            v.ended.get_or_insert(now);
                            ended = true;
                            break;
                        }
                        Ok(_) => {}
                    }
                }
            }
        }
        (tx, rx, parts, ended)
    })
}
