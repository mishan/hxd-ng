//! A scenario file: what to load, where, and how hard.
//!
//! ```toml
//! [target]
//! legacy = "127.0.0.1:5500"
//! ng = "127.0.0.1:5700"
//! metrics = true              # scrape http://<ng>/metrics before, during, after
//! log = "/var/log/hxd.log"    # tailed for panics and ERROR lines
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
        };
        let needs_ng = match self.run.scenario {
            Kind::LoginStorm => self.login_storm.ng > 0,
            Kind::Chat => self.chat.readers_ng + self.chat.talkers_ng > 0,
            Kind::SlowConsumer => {
                self.chat.readers_ng + self.chat.talkers_ng + self.slow_consumer.stalled_ng > 0
            }
            Kind::Churn => self.churn.ng > 0,
        };
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
        assert_eq!(seen, 4);
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
    fn churn_without_enough_accounts_is_refused() {
        let text = "[target]\nng = \"127.0.0.1:1\"\nlegacy = \"127.0.0.1:2\"\n\
                    [run]\nscenario = \"churn\"\n[churn]\nng = 3\n";
        let err = Scenario::parse(text).unwrap_err();
        assert!(err.contains("accounts"), "{err}");
    }
}
