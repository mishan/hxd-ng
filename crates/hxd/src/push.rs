//! Wiring a push gateway into the server: the in-process Web Push
//! sender (`docs/webpush-gateway.md` §8), or a uniqush-push sidecar
//! (`docs/push-notifications.md` §4.1) behind the `uniqush` feature.
//!
//! A Cargo feature as well as a config section, as voice and media are:
//! a server that wants no TLS client and no elliptic curves in its
//! binary builds without it, and then a `[push]` section is a startup
//! error rather than a silently ignored promise.
//!
//! The configuration is checked in [`build`], and the key is read — or,
//! on a first start, created — in [`Push::start`], once the device
//! registry is open and before anything is bound. A server that cannot
//! read its VAPID key has no business starting: every subscription its
//! users hold is bound to that key, and a second key minted beside it
//! would leave the pushes accepted by nobody and no client able to tell
//! why. Which is also why a missing key is only a first start when the
//! registry is empty (`docs/webpush-gateway.md` §3).

use crate::Config;

pub use imp::{build, rekey, Push};

#[cfg(feature = "push")]
mod imp {
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use hxd_core::push::PushStore;
    use hxd_core::NotificationGateway;
    use hxd_ng_session::push::PushInfo;
    use hxd_push_webpush::{Content, Vapid, WebPushGateway};

    use super::*;

    /// The push subsystem, once its configuration is known good: the
    /// sender's settings, and — once [`Push::start`] has read the key —
    /// what a client is told at login.
    pub struct Push {
        vapid_key: std::path::PathBuf,
        contact: String,
        config: hxd_push_webpush::Config,
        policy: hxd_core::push::PushPolicy,
        timeout: Duration,
        #[cfg(feature = "uniqush")]
        uniqush: Option<hxd_push_uniqush::Config>,
        info: OnceLock<Arc<PushInfo>>,
    }

    /// How long uniqush gives a push service by default (its `[webpush]
    /// request_timeout`). `/push` answers only after the first attempt at
    /// each device, so a client that gives up sooner hears nothing of
    /// what happened (`docs/push-notifications.md` §4.1).
    pub const UNIQUSH_REQUEST_TIMEOUT: u64 = 30;

    impl Push {
        /// Read the key — creating it only when `devices` is empty, which
        /// is what a first start looks like — and build the gateway over
        /// the registry. Built inside the runtime, because every send is
        /// spawned.
        pub fn start(
            &self,
            devices: Arc<dyn PushStore>,
        ) -> Result<Arc<dyn NotificationGateway>, String> {
            let first_start = !devices
                .any_devices()
                .map_err(|e| format!("[push] reading the device registry: {e}"))?;
            let vapid = Vapid::load_or_create(&self.vapid_key, &self.contact, first_start)
                .map_err(|e| format!("[push] {e}"))?;
            let _ = self.info.set(Arc::new(PushInfo {
                vapid: vapid.public_key().to_string(),
                content: self.config.content.name().to_string(),
            }));
            #[cfg(feature = "uniqush")]
            if let Some(uniqush) = &self.uniqush {
                return uniqush::start(devices, vapid, self, uniqush.clone());
            }
            // The public key in the log, so an operator reading two
            // servers' logs can tell whose subscriptions are whose — and
            // can see at a glance that a restart did not change it.
            tracing::info!(vapid = %vapid.public_key(), "push: Web Push gateway configured");
            let transport =
                hxd_push_webpush::http::shared(self.timeout, self.policy.allow_private_endpoints)?;
            Ok(Arc::new(WebPushGateway::new(
                devices,
                Arc::new(vapid),
                self.config.clone(),
                transport,
            )))
        }

        /// What a registration may do, for the domain.
        pub fn policy(&self) -> hxd_core::push::PushPolicy {
            self.policy
        }

        /// What a client is told at login. `None` until [`Self::start`]
        /// has read the key, which the server does before it builds the
        /// ng context.
        pub fn info(&self) -> Option<Arc<PushInfo>> {
            self.info.get().cloned()
        }
    }

    /// `None` when push is not configured.
    pub fn build(config: &Config) -> Result<Option<Push>, String> {
        let Some(section) = config.push.as_ref() else {
            return Ok(None);
        };
        let content = Content::from_name(&section.content).ok_or_else(|| {
            format!(
                "[push] content = {:?}: it is \"full\", \"sender\" or \"generic\"",
                section.content
            )
        })?;
        if section.max_inflight == 0 {
            return Err("[push] max_inflight must be at least 1".into());
        }
        if section.max_inflight_per_origin == 0 {
            return Err("[push] max_inflight_per_origin must be at least 1".into());
        }
        hxd_push_webpush::vapid::check_contact(&section.contact)
            .map_err(|e| format!("[push] {e}"))?;
        let (uniqush, timeout) = match (section.gateway.as_str(), &section.uniqush) {
            ("webpush", None) => (None, section.timeout.unwrap_or(10)),
            ("webpush", Some(_)) => {
                return Err(
                    "[push.uniqush] is configured, but [push] gateway is \"webpush\"".into(),
                )
            }
            ("uniqush", None) => {
                return Err("[push] gateway = \"uniqush\" needs a [push.uniqush] section".into())
            }
            ("uniqush", Some(u)) => {
                let timeout = section.timeout.unwrap_or(UNIQUSH_REQUEST_TIMEOUT + 10);
                if timeout <= UNIQUSH_REQUEST_TIMEOUT {
                    return Err(format!(
                        "[push] timeout = {timeout}: through uniqush it must be longer than \
                         uniqush's own [webpush] request_timeout, {UNIQUSH_REQUEST_TIMEOUT} \
                         seconds unless its config changes it, since /push answers only \
                         after that"
                    ));
                }
                (Some(u), timeout)
            }
            (other, _) => {
                return Err(format!(
                    "[push] gateway = {other:?}: it is \"webpush\" or \"uniqush\""
                ))
            }
        };
        if timeout == 0 {
            return Err("[push] timeout must be at least a second".into());
        }
        #[cfg(feature = "uniqush")]
        let uniqush = uniqush.map(uniqush::config).transpose()?;
        #[cfg(not(feature = "uniqush"))]
        if uniqush.is_some() {
            return Err(
                "[push] gateway = \"uniqush\", but this build has no uniqush gateway \
                        (built without the `uniqush` feature)"
                    .into(),
            );
        }
        let timeout = Duration::from_secs(timeout);
        Ok(Some(Push {
            vapid_key: section.vapid_key.clone(),
            contact: section.contact.clone(),
            config: hxd_push_webpush::Config {
                content,
                timeout,
                message_ttl: Duration::from_secs(section.message_ttl),
                news_ttl: Duration::from_secs(section.news_ttl),
                breaker_failures: section.breaker_failures,
                breaker_cooldown: Duration::from_secs(section.breaker_cooldown),
                max_inflight: section.max_inflight,
                max_inflight_per_origin: section.max_inflight_per_origin,
                allow_private_endpoints: section.allow_private_endpoints,
            },
            policy: hxd_core::push::PushPolicy {
                max_devices: section.max_devices,
                allow_private_endpoints: section.allow_private_endpoints,
            },
            timeout,
            #[cfg(feature = "uniqush")]
            uniqush,
            info: OnceLock::new(),
        }))
    }

    /// `hxd push rekey`: a new VAPID key, and no devices.
    ///
    /// Every row is bound to the key being replaced, and a push service
    /// answers a mismatched one with a `401` or `403` that never retires
    /// a row — so rows kept across a rekey would fail on every
    /// notification without end (`docs/webpush-gateway.md` §3). The rows
    /// go first: if writing the key then fails, the old key still stands
    /// and every client re-registers against it at its next login, which
    /// is the same thing a rekey costs anyway. Answers how many devices
    /// went and the new public key.
    pub fn rekey(config: &Config) -> Result<(usize, String), String> {
        let section = config
            .push
            .as_ref()
            .ok_or("[push] is not configured; there is no key to replace")?;
        let dropped = match crate::push_db(config).filter(|p| p.exists()) {
            Some(path) => {
                let store = crate::open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?;
                PushStore::devices_clear(&*store).map_err(|e| e.to_string())?
            }
            None => 0,
        };
        let vapid = Vapid::rekey(&section.vapid_key, &section.contact)
            .map_err(|e| format!("[push] {e}"))?;
        Ok((dropped, vapid.public_key().to_string()))
    }

    /// The sidecar half, behind a feature of its own so a build without it
    /// carries nothing of it.
    #[cfg(feature = "uniqush")]
    mod uniqush {
        use std::sync::Arc;

        use hxd_core::push::PushStore;
        use hxd_core::NotificationGateway;
        use hxd_push_uniqush::{Addr, Refused, UniqushGateway};
        use hxd_push_webpush::Vapid;

        use crate::UniqushSection;

        /// `[push.uniqush]`, checked, with its token read.
        pub fn config(section: &UniqushSection) -> Result<hxd_push_uniqush::Config, String> {
            let addr =
                Addr::parse(&section.addr).map_err(|e| format!("[push.uniqush] addr {e}"))?;
            if !hxd_push_uniqush::valid_service(&section.service) {
                return Err(format!(
                    "[push.uniqush] service = {:?}: letters, digits, '-', '_', '@' and '.'",
                    section.service
                ));
            }
            let token = match &section.token_file {
                Some(path) => {
                    let token = std::fs::read_to_string(path).map_err(|e| {
                        format!("[push.uniqush] token_file {}: {e}", path.display())
                    })?;
                    let token = token.trim();
                    if token.is_empty()
                        || token.chars().any(|c| c.is_whitespace() || c.is_control())
                    {
                        return Err(format!(
                            "[push.uniqush] token_file {}: not one token",
                            path.display()
                        ));
                    }
                    Some(token.to_string())
                }
                None => None,
            };
            if token.is_none() && matches!(addr, Addr::Tcp { .. }) {
                return Err(
                    "[push.uniqush] needs token_file over TCP: whoever reaches uniqush's \
                            API reads every device and pushes as this server. Or use its Unix \
                            socket, addr = \"unix:/path\""
                        .into(),
                );
            }
            Ok(hxd_push_uniqush::Config {
                addr,
                token,
                service: section.service.clone(),
            })
        }

        /// Build the gateway and check uniqush's provider before anything
        /// binds: one that is not this server's refuses the start. A uniqush
        /// that does not answer yet does not, since the Hotline server is
        /// worth running without push; the gateway keeps trying, and pushes
        /// once it answers.
        pub fn start(
            devices: Arc<dyn PushStore>,
            vapid: Vapid,
            push: &super::Push,
            config: hxd_push_uniqush::Config,
        ) -> Result<Arc<dyn NotificationGateway>, String> {
            if push.policy.allow_private_endpoints {
                tracing::warn!(
                    "push: [push] allow_private_endpoints is on; uniqush checks where each push \
                     goes, so its [webpush] allow_private_addresses must be true, and its \
                     allowed_hosts unset or naming every private push service, or those \
                     devices are refused at send"
                );
            }
            let gateway =
                UniqushGateway::new(devices, Arc::new(vapid), push.config.clone(), config);
            // A runtime cannot be blocked on from inside itself, so the check
            // gets a thread and a runtime of its own, and holds up the start
            // for no more than its few seconds a call.
            let checked = std::thread::scope(|s| {
                s.spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| Refused::Fatal(e.to_string()))?
                        .block_on(gateway.prepare())
                })
                .join()
                .unwrap_or_else(|_| Err(Refused::Fatal("the check panicked".into())))
            });
            match checked {
                Ok(()) => {}
                Err(Refused::Fatal(e)) => return Err(format!("[push.uniqush] {e}")),
                Err(Refused::Unreachable(e)) => {
                    tracing::warn!("push: uniqush is not answering ({e}); pushing once it does")
                }
            }
            gateway.start();
            Ok(Arc::new(gateway))
        }
    }
}

#[cfg(not(feature = "push"))]
mod imp {
    use super::*;

    use std::sync::Arc;

    use hxd_core::push::PushStore;
    use hxd_core::NotificationGateway;
    use hxd_ng_session::push::PushInfo;

    /// Push, in a build without it: a type nothing can construct, so
    /// every use site type-checks and none can run.
    pub enum Push {}

    impl Push {
        pub fn start(
            &self,
            _devices: Arc<dyn PushStore>,
        ) -> Result<Arc<dyn NotificationGateway>, String> {
            match *self {}
        }

        pub fn policy(&self) -> hxd_core::push::PushPolicy {
            match *self {}
        }

        pub fn info(&self) -> Option<Arc<PushInfo>> {
            match *self {}
        }
    }

    pub fn build(config: &Config) -> Result<Option<Push>, String> {
        if config.push.is_some() {
            return Err("[push] is configured, but this build has no push gateway \
                        (built without the `push` feature)"
                .into());
        }
        Ok(None)
    }

    pub fn rekey(_config: &Config) -> Result<(usize, String), String> {
        Err("this build has no push gateway (built without the `push` feature)".into())
    }
}
