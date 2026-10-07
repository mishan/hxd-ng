//! A scenario file: what to load, where, and how hard.
//!
//! ```toml
//! [target]
//! legacy = "127.0.0.1:5500"
//! ng = "127.0.0.1:5700"
//! metrics = true              # scrape http://<ng>/metrics before, during, after
//! log = "/var/log/hxd.log"    # tailed for panics and ERROR lines
//!
//! [[target.linked]]          # a server linked to it: chat and login_storm
//! name = "b"
//! legacy = "127.0.0.1:6500"
//! ng = "127.0.0.1:6700"
//! metrics = true
//!
//! [run]
//! scenario = "chat"           # login_storm | chat | slow_consumer | churn
//! duration = 30               # seconds of load
//!
//! [chat]
//! readers_legacy = 50
//! readers_ng = 50
//! talkers_legacy = 5
//! talkers_ng = 5
//! rate = 50                   # lines a second, all talkers together
//! ```
//!
//! Every section and key has a default, so a file names only what it
//! changes. The whole of it goes into the report, defaults filled in, so
//! a run can be repeated from its own output.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scenario {
    pub target: Target,
    pub run: Run,
    pub login_storm: LoginStorm,
    pub chat: Chat,
    pub slow_consumer: SlowConsumer,
    pub churn: Churn,
    pub interruption: Interruption,
    pub slow_peer: SlowPeer,
    pub requests: Requests,
    pub moderation: Moderation,
}

impl Scenario {
    pub fn parse(text: &str) -> Result<Scenario, String> {
        let s: Scenario = toml::from_str(text).map_err(|e| e.to_string())?;
        s.check()?;
        Ok(s)
    }

    pub fn check(&self) -> Result<(), String> {
        // Every time is used as a duration and some as a divisor or a
        // mean; none of them may be zero, negative or not a number.
        let positive = [
            ("[run] duration", self.run.duration),
            ("[login_storm] ramp_every", self.login_storm.ramp_every),
            (
                "[slow_consumer] sample_every",
                self.slow_consumer.sample_every,
            ),
            ("[churn] cycle", self.churn.cycle),
            ("[churn] kick_every", self.churn.kick_every),
        ];
        let not_negative = [
            ("[run] settle", self.run.settle),
            ("[run] teardown", self.run.teardown),
            ("[login_storm] linger", self.login_storm.linger),
            ("[login_storm] ramp_step", self.login_storm.ramp_step),
            ("[churn] away", self.churn.away),
            ("[churn] chat_rate", self.churn.chat_rate),
            ("[chat] rate", self.chat.rate),
        ];
        for (name, v) in positive {
            if !(v.is_finite() && v > 0.0) {
                return Err(format!("{name} must be a positive number of seconds"));
            }
        }
        for (name, v) in not_negative {
            if !(v.is_finite() && v >= 0.0) {
                return Err(format!("{name} must not be negative"));
            }
        }
        if self.run.scenario == Kind::LoginStorm
            && (self.login_storm.rate <= 0.0 || !self.login_storm.rate.is_finite())
        {
            return Err("[login_storm] rate must be positive".into());
        }
        if self.run.scenario == Kind::LoginStorm
            && self.login_storm.accounts
            && self.target.accounts.is_none()
        {
            return Err("[login_storm] accounts = true needs [target] accounts".into());
        }
        if self.run.scenario == Kind::Churn
            && self.target.admin.is_some()
            && self.target.ng.is_none()
        {
            return Err("[target] admin kicks from the ng port, and [target] names none".into());
        }
        let needs_legacy = match self.run.scenario {
            Kind::LoginStorm => self.login_storm.legacy > 0,
            Kind::Chat => self.chat.readers_legacy + self.chat.talkers_legacy > 0,
            Kind::SlowConsumer => {
                self.chat.readers_legacy
                    + self.chat.talkers_legacy
                    + self.slow_consumer.stalled_legacy
                    > 0
            }
            Kind::Churn => self.churn.legacy > 0,
            Kind::Interruption => self.interruption.population_legacy > 0,
            Kind::SlowPeer => self.chat.readers_legacy + self.chat.talkers_legacy > 0,
            Kind::Requests => self.requests.requesters_legacy > 0,
            // The moderator, and the victims on the linked servers.
            Kind::Moderation => true,
        };
        let needs_ng = match self.run.scenario {
            Kind::LoginStorm => self.login_storm.ng > 0,
            Kind::Chat => self.chat.readers_ng + self.chat.talkers_ng > 0,
            Kind::SlowConsumer => {
                self.chat.readers_ng + self.chat.talkers_ng + self.slow_consumer.stalled_ng > 0
            }
            Kind::Churn => self.churn.ng > 0,
            Kind::Interruption => self.interruption.population_ng > 0,
            Kind::SlowPeer => self.chat.readers_ng + self.chat.talkers_ng > 0,
            Kind::Requests => self.requests.requesters_ng > 0,
            Kind::Moderation => self.chat.readers_ng + self.chat.talkers_ng > 0,
        };
        if !self.target.linked.is_empty() {
            self.check_linked(needs_legacy, needs_ng)?;
        }
        if self.run.scenario == Kind::Interruption {
            self.check_interruption()?;
        }
        if self.run.scenario == Kind::SlowPeer {
            self.check_slow_peer()?;
        }
        if self.run.scenario == Kind::Requests {
            self.check_requests()?;
        }
        if self.run.scenario == Kind::Moderation {
            self.check_moderation()?;
        }
        if needs_legacy && self.target.legacy.is_none() {
            return Err(
                "this scenario has legacy clients but [target] names no legacy port".into(),
            );
        }
        if (needs_ng || self.target.metrics) && self.target.ng.is_none() {
            return Err("this scenario needs the ng port but [target] names none".into());
        }
        if self.login_storm.legacy_tls > 0 && self.target.legacy_tls.is_none() {
            return Err("[login_storm] legacy_tls needs [target] legacy_tls".into());
        }
        if self.run.scenario == Kind::Churn && self.churn.ng > 0 {
            let have = self.target.accounts.as_ref().map_or(0, |a| a.count);
            if have < self.churn.ng {
                return Err(format!(
                    "[churn] ng = {} needs that many accounts that may detach; \
                     [target] accounts has {have} (see `hxd-load accounts`)",
                    self.churn.ng
                ));
            }
        }
        if self.run.scenario == Kind::Chat || self.run.scenario == Kind::SlowConsumer {
            if self.chat.talkers_legacy + self.chat.talkers_ng == 0 {
                return Err("[chat] needs at least one talker".into());
            }
            if self.chat.rate <= 0.0 {
                return Err("[chat] rate must be positive".into());
            }
        }
        Ok(())
    }

    /// The servers linked to the target: each named once, and with every
    /// port the clients a scenario puts there need.
    fn check_linked(&self, needs_legacy: bool, needs_ng: bool) -> Result<(), String> {
        let (legacy, ng) = match self.run.scenario {
            Kind::Chat => (needs_legacy, needs_ng),
            Kind::LoginStorm => (
                self.login_storm.observers_legacy > 0,
                self.login_storm.observers_ng > 0,
            ),
            Kind::Interruption => (
                self.interruption.watchers_legacy > 0,
                self.interruption.watchers_ng > 0,
            ),
            Kind::SlowPeer => (needs_legacy, needs_ng),
            // The watchers and lookers on each.
            Kind::Churn => (false, true),
            // The users the requests are for, on both wires.
            Kind::Requests => (true, true),
            // The victims, on the classic wire; the room as chat's.
            Kind::Moderation => (true, needs_ng),
            _ => {
                return Err("[[target.linked]] is for chat, login_storm, churn, \
                                interruption, slow_peer, requests and moderation"
                    .into())
            }
        };
        if self.run.scenario == Kind::LoginStorm
            && self.login_storm.observers_legacy + self.login_storm.observers_ng == 0
        {
            return Err("[[target.linked]] in a login storm needs [login_storm] observers".into());
        }
        let mut names = vec![PRIMARY];
        for l in &self.target.linked {
            if l.name.is_empty() || names.contains(&l.name.as_str()) {
                return Err(format!(
                    "[[target.linked]] name {:?} is empty or not unique",
                    l.name
                ));
            }
            names.push(&l.name);
            if legacy && l.legacy.is_none() {
                return Err(format!("[[target.linked]] {} names no legacy port", l.name));
            }
            if (ng || l.metrics) && l.ng.is_none() {
                return Err(format!("[[target.linked]] {} names no ng port", l.name));
            }
        }
        Ok(())
    }
}

impl Scenario {
    /// An interruption cuts the proxy every link runs through.
    fn check_interruption(&self) -> Result<(), String> {
        let i = &self.interruption;
        if self.target.proxy.is_none() || self.target.linked.is_empty() {
            return Err("interruption needs [target.proxy] and [[target.linked]]".into());
        }
        // Shorter, and the links' counts read after it could still be
        // the ones from before it.
        if i.cuts.is_empty() || !i.cuts.iter().all(|c| c.is_finite() && *c >= MIN_CUT) {
            return Err(format!(
                "[interruption] cuts must be at least {MIN_CUT} seconds"
            ));
        }
        for (name, v) in [("recover", i.recover), ("between", i.between)] {
            if !(v.is_finite() && v >= 0.0) {
                return Err(format!("[interruption] {name} must not be negative"));
            }
        }
        if i.watchers_legacy + i.watchers_ng == 0 {
            return Err("[interruption] needs watchers".into());
        }
        Ok(())
    }
}

impl Scenario {
    /// A slow peer stalls the proxy one linked server dials through, while
    /// the room talks on the others.
    fn check_slow_peer(&self) -> Result<(), String> {
        let p = &self.slow_peer;
        if self.target.proxy.is_none() {
            return Err("slow_peer needs [target.proxy]".into());
        }
        if !self.target.linked.iter().any(|l| l.name == p.stalled) {
            return Err(format!(
                "[slow_peer] stalled = {:?} names no [[target.linked]] server",
                p.stalled
            ));
        }
        if self.chat.talkers_legacy + self.chat.talkers_ng == 0 || self.chat.rate <= 0.0 {
            return Err("[chat] needs talkers and a positive rate".into());
        }
        for (name, v) in [
            ("stall_after", p.stall_after),
            ("contained", p.contained),
            ("drop_within", p.drop_within),
            ("recover", p.recover),
        ] {
            if !(v.is_finite() && v > 0.0) {
                return Err(format!("[slow_peer] {name} must be positive"));
            }
        }
        // A stall shorter than the time allowed to drop it could end
        // before the server was due to, and prove nothing either way.
        if p.stall_after + p.drop_within > self.run.duration {
            return Err(
                "[slow_peer] stall_after + drop_within must fall inside [run] duration".into(),
            );
        }
        Ok(())
    }
}

impl Scenario {
    /// Requests go from `[target]` to the users of the servers linked to
    /// it, step by step as there are more of them.
    fn check_requests(&self) -> Result<(), String> {
        let r = &self.requests;
        if self.target.linked.is_empty() {
            return Err("requests needs [[target.linked]]".into());
        }
        if r.requesters_legacy + r.requesters_ng == 0 {
            return Err("[requests] needs requesters".into());
        }
        if r.ghosts.is_empty() || r.ghosts.windows(2).any(|w| w[0] >= w[1]) || r.ghosts[0] == 0 {
            return Err("[requests] ghosts must be rising counts above zero".into());
        }
        if !(r.rate.is_finite() && r.rate > 0.0 && r.step.is_finite() && r.step > 0.0) {
            return Err("[requests] rate and step must be positive".into());
        }
        if !(0.0..=1.0).contains(&r.info_share) {
            return Err("[requests] info_share must be between 0 and 1".into());
        }
        if r.peer_latency_ms.is_some() && self.target.proxy.is_none() {
            return Err("[requests] peer_latency_ms needs [target.proxy]".into());
        }
        Ok(())
    }
}

impl Scenario {
    /// Moderation is a moderator on `[target]` acting on the users of the
    /// servers linked to it, while the room talks.
    fn check_moderation(&self) -> Result<(), String> {
        let m = &self.moderation;
        if self.target.linked.is_empty() || self.target.admin.is_none() {
            return Err("moderation needs [[target.linked]] and [target] admin".into());
        }
        if m.victims == 0 {
            return Err("[moderation] needs victims to act on".into());
        }
        let have = self.target.accounts.as_ref().map_or(0, |a| a.count);
        if have < m.victims {
            return Err(format!(
                "[moderation] victims = {} needs that many [target] accounts, \
                 on the linked servers too; there are {have}",
                m.victims
            ));
        }
        if self.chat.talkers_legacy + self.chat.talkers_ng == 0 || self.chat.rate <= 0.0 {
            return Err("[chat] needs talkers and a positive rate".into());
        }
        for (name, v) in [
            ("every", m.every),
            ("acts_after", m.acts_after),
            ("contained", m.contained),
        ] {
            if !(v.is_finite() && v > 0.0) {
                return Err(format!("[moderation] {name} must be positive"));
            }
        }
        if !(0.0..=1.0).contains(&m.ban_share) {
            return Err("[moderation] ban_share must be between 0 and 1".into());
        }
        if m.acts_after >= self.run.duration {
            return Err("[moderation] acts_after must fall inside [run] duration".into());
        }
        Ok(())
    }
}

/// The shortest cut an interruption takes, in seconds.
const MIN_CUT: f64 = 0.1;

/// `linkproxy` (`proxy.rs`): where a linked server dials, and the peer
/// port it is carried on to.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyAt {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    /// Milliseconds added to every byte it carries, each way.
    #[serde(default)]
    pub latency_ms: u64,
}

/// What the report calls `[target]` among the servers of a run.
pub const PRIMARY: &str = "target";

/// One server of a run, its ports and what is read from it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub name: String,
    pub legacy: Option<SocketAddr>,
    pub legacy_tls: Option<SocketAddr>,
    pub ng: Option<SocketAddr>,
    pub metrics: bool,
    pub log: Option<PathBuf>,
}

impl Target {
    /// Every server of the run: `[target]` first, then the linked ones.
    pub fn servers(&self) -> Vec<Server> {
        let primary = Server {
            name: PRIMARY.into(),
            legacy: self.legacy,
            legacy_tls: self.legacy_tls,
            ng: self.ng,
            metrics: self.metrics,
            log: self.log.clone(),
        };
        std::iter::once(primary)
            .chain(self.linked.iter().cloned())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Target {
    /// The classic port.
    pub legacy: Option<SocketAddr>,
    /// The classic wire's TLS port, and the name its certificate carries.
    /// The certificate is not checked: a load run measures the
    /// handshake, it does not audit it.
    pub legacy_tls: Option<SocketAddr>,
    pub tls_name: String,
    /// The ng listener, plain HTTP.
    pub ng: Option<SocketAddr>,
    /// Scrape `GET /metrics` on the ng port. The server needs the
    /// `metrics` feature and a `[metrics]` section allowing this host.
    pub metrics: bool,
    /// The server's log, to tail for panics and `ERROR` lines.
    pub log: Option<PathBuf>,
    /// Accounts `hxd-load accounts` wrote: `<prefix>0` up to
    /// `<prefix><count - 1>`, all with `password`.
    pub accounts: Option<Accounts>,
    /// An account allowed to disconnect users, for the kicks in churn.
    pub admin: Option<Account>,
    /// Servers linked to this one (`docs/server-link.md`). A chat room
    /// is spread over all of them, each client on the next server in
    /// turn; a login storm arrives here and is watched from them.
    pub linked: Vec<Server>,
    /// A proxy the run starts and the linked servers dial through, for a
    /// scenario that cuts their links.
    pub proxy: Option<ProxyAt>,
}

impl Default for Target {
    fn default() -> Self {
        Target {
            legacy: None,
            legacy_tls: None,
            tls_name: "localhost".into(),
            ng: None,
            metrics: false,
            log: None,
            accounts: None,
            admin: None,
            linked: Vec::new(),
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Accounts {
    pub prefix: String,
    pub count: usize,
    pub password: String,
}

impl Accounts {
    pub fn login(&self, i: usize) -> String {
        format!("{}{}", self.prefix, i % self.count.max(1))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub login: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// S1: connect, log in, agree and fetch the user list, at a rising
    /// rate.
    LoginStorm,
    /// S3: readers and talkers in public chat.
    #[default]
    Chat,
    /// S5: chat, with some clients that stop reading.
    SlowConsumer,
    /// S6: sessions dropping and resuming, connections dying mid-way,
    /// kicks, all at once.
    Churn,
    /// L-3: links cut and restored, and what the linked servers' users
    /// are shown meanwhile.
    Interruption,
    /// L-4: one linked server stops reading what its peer sends it, while
    /// the room talks on the others.
    SlowPeer,
    /// L-6: private messages and user info sent across a link, as the
    /// users behind it grow in number.
    Requests,
    /// L-7: kicks and bans of other servers' users while the room talks.
    Moderation,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Moderation {
    /// Users on the linked servers, logged in to `[target] accounts`
    /// (which those servers must have too, a ban being placed on an
    /// account), each acted on once.
    pub victims: usize,
    /// Seconds into the talking when the acts begin.
    pub acts_after: f64,
    /// Seconds between acts, on a fixed schedule.
    pub every: f64,
    /// The share of acts that are bans rather than kicks.
    pub ban_share: f64,
    /// How much worse the room's p99 delivery may get once the acts
    /// begin, as a factor of its p99 before.
    pub contained: f64,
}

impl Default for Moderation {
    fn default() -> Self {
        Moderation {
            victims: 20,
            acts_after: 5.0,
            every: 1.0,
            ban_share: 0.5,
            contained: 3.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Requests {
    /// Idle users on the linked servers, each count a step: the ghosts
    /// `[target]` shows, whom the requests are for.
    pub ghosts: Vec<usize>,
    /// Clients on `[target]` that send them.
    pub requesters_legacy: usize,
    pub requesters_ng: usize,
    /// Requests a second, every requester together, on a fixed schedule.
    pub rate: f64,
    /// Seconds of requests at each step.
    pub step: f64,
    /// Of the classic requesters' requests, the share that ask for a
    /// user's info rather than send a message; ng has no user info.
    pub info_share: f64,
    /// With `[target.proxy]`, milliseconds it adds each way once the
    /// links are up: a peer further off than a link could be set up
    /// across, whose answers outlast the server's wait for them.
    pub peer_latency_ms: Option<u64>,
}

impl Default for Requests {
    fn default() -> Self {
        Requests {
            ghosts: vec![50, 200, 800],
            requesters_legacy: 2,
            requesters_ng: 2,
            rate: 50.0,
            step: 10.0,
            info_share: 0.5,
            peer_latency_ms: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SlowPeer {
    /// The `[[target.linked]]` server that dials through the proxy, whose
    /// link is stalled. The `[chat]` room is spread over the rest.
    pub stalled: String,
    /// Seconds into the talking when the stall begins; it lasts until the
    /// talking ends.
    pub stall_after: f64,
    /// How much worse the room's p99 delivery may get once the stall
    /// begins, as a factor of its p99 before: past it, a slow peer cost
    /// everyone else.
    pub contained: f64,
    /// Seconds from the stall by which, with metrics, `[target]` must
    /// have dropped the stalled link as a slow consumer.
    pub drop_within: f64,
    /// Seconds from the stall's end by which every link must be back.
    pub recover: f64,
    /// The most `[target]`'s classic writers, the link's among them, may
    /// hold queued, in bytes.
    pub max_queued_bytes: u64,
}

impl Default for SlowPeer {
    fn default() -> Self {
        SlowPeer {
            stalled: "b".into(),
            stall_after: 10.0,
            contained: 3.0,
            // A stalled link is given up when a write has made no progress
            // for a minute, after its socket's buffer has filled.
            drop_within: 150.0,
            recover: 60.0,
            max_queued_bytes: 16 << 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Interruption {
    /// Clients on `[target]`, idle: the users each cut puts at stake.
    pub population_legacy: usize,
    pub population_ng: usize,
    /// Clients on each linked server, hearing what the cuts show them.
    pub watchers_legacy: usize,
    pub watchers_ng: usize,
    /// Each cut's length in seconds, in order: one run sweeps across the
    /// servers' grace period.
    pub cuts: Vec<f64>,
    /// The `[link] grace` the servers run with, in whole seconds as that
    /// takes it: a cut shorter than it must show the watchers nobody
    /// leaving.
    pub grace: u64,
    /// Seconds, after a cut ends, by which every link must be up again
    /// and every watcher's list whole.
    pub recover: f64,
    /// Seconds of quiet between one recovery and the next cut, and never
    /// less than the grace after the last cut began. Past a ping interval
    /// (60 seconds) the next cut ends a link that has settled, as an
    /// operator's would be; less, and back-to-back cuts measure a
    /// flapping link's backoff.
    pub between: f64,
}

impl Default for Interruption {
    fn default() -> Self {
        Interruption {
            population_legacy: 25,
            population_ng: 25,
            watchers_legacy: 1,
            watchers_ng: 1,
            cuts: vec![5.0, 90.0],
            grace: 60,
            recover: 30.0,
            between: 65.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Run {
    pub scenario: Kind,
    /// Seconds of load, not counting setup and teardown.
    pub duration: f64,
    /// Seeds every random choice, so a run repeats.
    pub seed: u64,
    /// Seconds readers may still take to hear the last lines once the
    /// talking stops. A line not heard by then counts as not heard at
    /// all (`chat.all_heard`), and its latency is not in the report: a
    /// server slower than this looks like one that loses lines, so a run
    /// that expects a slow server sets it higher.
    pub settle: f64,
    /// Seconds the server has to empty its roster after everyone leaves.
    pub teardown: f64,
    /// Nicks start with this, so the checks can tell this run's users
    /// from anyone else on the server.
    pub prefix: String,
}

impl Default for Run {
    fn default() -> Self {
        Run {
            scenario: Kind::Chat,
            duration: 10.0,
            seed: 1,
            settle: 5.0,
            teardown: 10.0,
            prefix: "lt".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoginStorm {
    /// Arrivals a second at the start.
    pub rate: f64,
    /// Added to the rate every `ramp_every` seconds.
    pub ramp_step: f64,
    pub ramp_every: f64,
    /// Seconds each client stays after its user list, then leaves.
    pub linger: f64,
    /// The mix, by weight.
    pub legacy: u32,
    pub legacy_tls: u32,
    pub ng: u32,
    /// Log in to `[target] accounts` rather than as guests, which puts
    /// the auth backend in the path.
    pub accounts: bool,
    /// Clients connecting or connected at once, at most. An arrival past
    /// it is not attempted, and counted as shed: the generator's limit,
    /// not the server's.
    pub max_in_flight: usize,
    /// Clients on each `[[target.linked]]` server, there before the first
    /// arrival, timing when each arrival is heard to join there.
    pub observers_legacy: usize,
    pub observers_ng: usize,
}

impl Default for LoginStorm {
    fn default() -> Self {
        LoginStorm {
            rate: 20.0,
            ramp_step: 20.0,
            ramp_every: 5.0,
            linger: 1.0,
            legacy: 1,
            legacy_tls: 0,
            ng: 1,
            accounts: false,
            max_in_flight: 4000,
            observers_legacy: 0,
            observers_ng: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Chat {
    pub readers_legacy: usize,
    pub readers_ng: usize,
    /// Talkers read too: each hears its own echo.
    pub talkers_legacy: usize,
    pub talkers_ng: usize,
    /// Lines a second, all talkers together, on a fixed schedule.
    pub rate: f64,
    /// Bytes of padding after each line's tag.
    pub line_bytes: usize,
}

impl Default for Chat {
    fn default() -> Self {
        Chat {
            readers_legacy: 5,
            readers_ng: 5,
            talkers_legacy: 1,
            talkers_ng: 1,
            rate: 10.0,
            line_bytes: 32,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SlowConsumer {
    /// Clients that log in, then never read again. They hear the same
    /// chat as everyone else.
    pub stalled_legacy: usize,
    pub stalled_ng: usize,
    /// Seconds between samples of the server's memory and queues.
    pub sample_every: f64,
    /// What "bounded" means: the most the legacy writers may hold queued,
    /// in bytes, for the run to pass.
    pub max_queued_bytes: u64,
}

impl Default for SlowConsumer {
    fn default() -> Self {
        SlowConsumer {
            stalled_legacy: 1,
            stalled_ng: 1,
            sample_every: 1.0,
            max_queued_bytes: 16 << 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Churn {
    /// Account sessions that drop their connection and resume, over and
    /// over. Each needs its own account in `[target] accounts`.
    pub ng: usize,
    /// Guests that come and go on the classic wire, some of them dying
    /// in the middle of a handshake or a login.
    pub legacy: usize,
    /// Mean seconds between one client's actions.
    pub cycle: f64,
    /// Mean seconds a dropped ng session stays away before resuming.
    /// Keep it well under the server's `[ng] grace`.
    pub away: f64,
    /// Lines a second from two steady talkers, so there is always
    /// something in flight to replay.
    pub chat_rate: f64,
    /// Mean seconds between kicks by `[target] admin`, if there is one.
    pub kick_every: f64,
}

impl Default for Churn {
    fn default() -> Self {
        Churn {
            ng: 5,
            legacy: 5,
            cycle: 0.5,
            away: 0.2,
            chat_rate: 5.0,
            kick_every: 2.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped examples parse and pass the checks, so they are the
    /// files someone copies rather than ones that rotted.
    #[test]
    fn every_example_scenario_is_a_valid_one() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/scenarios");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            Scenario::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            seen += 1;
        }
        assert_eq!(seen, 12);
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let err = Scenario::parse("[chat]\nreaders = 5\n").unwrap_err();
        assert!(err.contains("readers"), "{err}");
    }

    #[test]
    fn a_time_that_would_panic_or_spin_is_refused() {
        let target = "[target]\nng = \"127.0.0.1:1\"\nlegacy = \"127.0.0.1:2\"\n";
        for bad in [
            "[login_storm]\nramp_every = 0\n",
            "[run]\nsettle = -1\n",
            "[churn]\nkick_every = 0\n",
            "[slow_consumer]\nsample_every = 0\n",
            "[run]\nscenario = \"login_storm\"\n[login_storm]\nrate = 0\n",
        ] {
            assert!(Scenario::parse(&format!("{target}{bad}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_slow_run_with_stalled_classic_clients_needs_the_classic_port() {
        let text = "[target]\nng = \"127.0.0.1:1\"\n[run]\nscenario = \"slow_consumer\"\n\
                    [chat]\nreaders_legacy = 0\ntalkers_legacy = 0\n";
        let err = Scenario::parse(text).unwrap_err();
        assert!(err.contains("legacy"), "{err}");
    }

    #[test]
    fn a_linked_server_must_be_named_once_and_have_the_ports_its_clients_need() {
        let target = "[target]\nng = \"127.0.0.1:1\"\nlegacy = \"127.0.0.1:2\"\n";
        let linked = "[[target.linked]]\nname = \"b\"\nng = \"127.0.0.1:3\"\n";
        assert!(Scenario::parse(&format!(
            "{target}{linked}[chat]\nreaders_legacy = 0\ntalkers_legacy = 0\n"
        ))
        .is_ok());
        for (bad, why) in [
            (format!("{target}{linked}"), "legacy"),
            (
                format!("{target}{linked}{linked}[chat]\nreaders_legacy = 0\ntalkers_legacy = 0\n"),
                "unique",
            ),
            (
                format!("{target}{linked}[run]\nscenario = \"login_storm\"\n"),
                "observers",
            ),
            (
                format!("{target}{linked}[run]\nscenario = \"slow_consumer\"\n"),
                "is for chat",
            ),
        ] {
            let err = Scenario::parse(&bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn churn_without_enough_accounts_is_refused() {
        let text = "[target]\nng = \"127.0.0.1:1\"\nlegacy = \"127.0.0.1:2\"\n\
                    [run]\nscenario = \"churn\"\n[churn]\nng = 3\n";
        let err = Scenario::parse(text).unwrap_err();
        assert!(err.contains("accounts"), "{err}");
    }
}
