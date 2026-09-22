//! Wiring the Web Push gateway into the server
//! (`docs/webpush-gateway.md` §8).
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
        info: OnceLock<Arc<PushInfo>>,
    }

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
            // The public key in the log, so an operator reading two
            // servers' logs can tell whose subscriptions are whose — and
            // can see at a glance that a restart did not change it.
            tracing::info!(vapid = %vapid.public_key(), "push: Web Push gateway configured");
            let _ = self.info.set(Arc::new(PushInfo {
                vapid: vapid.public_key().to_string(),
                content: self.config.content.name().to_string(),
            }));
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
        if section.timeout == 0 {
            return Err("[push] timeout must be at least a second".into());
        }
        hxd_push_webpush::vapid::check_contact(&section.contact)
            .map_err(|e| format!("[push] {e}"))?;
        let timeout = Duration::from_secs(section.timeout);
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
