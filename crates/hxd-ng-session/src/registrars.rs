//! The registrars this server trusts, as a verifying server uses them
//! (`docs/identity-registrar.md` §7.1–§7.2, `docs/identity-records.md`):
//! each one's keys, from the operator's table or its discovery document,
//! and the signed record list it publishes against an identity, fetched
//! when the identity authenticates and kept, on disk, for when the
//! registrar cannot be reached. What the records then mean is
//! `identity.rs`'s; this only says what they are and whether they are
//! current.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hl_identity::{
    Attestation, Fingerprint, ListKind, PublicKey, Record, RegistrarKeys, SignedList,
};
use hxd_core::identity_records::{CachedList, RecordCache};
use hxd_fetch::{FetchConfig, Fetched, Validators};
use tracing::{debug, warn};

/// How long a discovery document is believed (§7.1).
const DISCOVERY_TTL: Duration = Duration::from_secs(24 * 3600);

/// How soon a key nobody has heard of sends this server to a registrar's
/// discovery document again, ahead of `DISCOVERY_TTL`: often enough that
/// a key rotation is not a day of refusals, and no more often, since any
/// client can show an attestation naming any key.
const REDISCOVERY: Duration = Duration::from_secs(60);

/// The largest discovery document or page read.
const MAX_BYTES: usize = 1 << 20;

/// The most pages of one identity's list read: a registrar bounds what
/// one identity may post, and a list longer than this is one to refuse.
const MAX_PAGES: usize = 16;

/// The path a registrar serves its records at unless it says otherwise.
const RECORDS: &str = "/registrar/records";

/// What to do when an identity's records cannot be had fresh (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// Use the last list fetched, however old.
    Cached,
    /// Admit the identity as though it were unattested, which the lists
    /// held for it still apply to.
    Guest,
    Deny,
}

#[derive(Debug, Clone)]
pub struct RegistrarsConfig {
    /// The operator's word for a registrar's key, which its discovery
    /// document does not override.
    pub keys: HashMap<String, PublicKey>,
    /// Hosts trusted on their discovery document's key.
    pub trusted: Vec<String>,
    /// Where a registrar is reached when it is not at `https://<host>`:
    /// a base URL, asked for under the registrar's own name.
    pub urls: HashMap<String, String>,
    /// The longest a handshake waits on registrars.
    pub timeout: Duration,
    /// The longest a list is used for, whatever its `expires` says.
    pub max_age: Duration,
    pub stale: Stale,
    pub user_agent: String,
}

struct Discovered {
    /// With each retiring key's `until`. Empty for an operator-keyed
    /// registrar whose document could not be had.
    keys: Vec<(PublicKey, Option<u64>)>,
    records: String,
    at: Instant,
}

pub struct Registrars {
    cfg: RegistrarsConfig,
    discovered: Mutex<HashMap<String, Discovered>>,
    /// One discovery at a time per host, so logins arriving together
    /// wait on one fetch rather than each making their own.
    discovering: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When a host's discovery document last could not be had: not asked
    /// again for `REDISCOVERY`, so a registrar that is down costs one
    /// failed fetch a minute rather than one for every login.
    failed: Mutex<HashMap<String, Instant>>,
    /// Held across comparing a fetched list with the one held and
    /// replacing it, so two fetches finishing together cannot leave the
    /// older one.
    storing: Arc<Mutex<()>>,
    cache: Arc<dyn RecordCache>,
}

/// What the registrars publish against one identity, as known now.
#[derive(Debug, Default)]
pub struct Lookup {
    /// Every verified record, oldest first.
    pub records: Vec<Record>,
    /// Some registrar that attested the identity has no list this
    /// server can call current: `RegistrarsConfig::stale` decides.
    pub stale: bool,
}

impl Registrars {
    pub fn new(cfg: RegistrarsConfig, cache: Arc<dyn RecordCache>) -> Self {
        Registrars {
            cfg,
            discovered: Mutex::new(HashMap::new()),
            discovering: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            storing: Arc::new(Mutex::new(())),
            cache,
        }
    }

    pub fn config(&self) -> &RegistrarsConfig {
        &self.cfg
    }

    pub fn trusts(&self, host: &str) -> bool {
        self.cfg.keys.contains_key(host) || self.cfg.trusted.iter().any(|h| h == host)
    }

    /// Every host trusted, for the discovery document.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.cfg.keys.keys().cloned().collect();
        hosts.extend(self.cfg.trusted.iter().cloned());
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// The keys an attestation from `host` may be signed by at `now`: the
    /// operator's; else the discovered key and any retiring one whose
    /// `until` has not passed; else, as after a restart that has not yet
    /// reached the registrar, those its last list for `identity` verified
    /// under. Reads the store: called off the reactor.
    pub fn keys(&self, host: &str, identity: &PublicKey, now: u64) -> Vec<PublicKey> {
        let current = self.keys_now(host, now);
        if !current.is_empty() || !self.trusts(host) {
            return current;
        }
        self.cache
            .lists(&Fingerprint::of(identity).0)
            .unwrap_or_default()
            .into_iter()
            .find(|l| l.registrar == host)
            .map(|l| live(&l.keys, now))
            .unwrap_or_default()
    }

    /// The keys a list or an attestation from `host` is verified under
    /// now, without the store: the operator's, or the discovered ones.
    fn keys_now(&self, host: &str, now: u64) -> Vec<PublicKey> {
        live(&self.keys_until(host, now), now)
    }

    /// [`Self::keys_now`], each with its `until`.
    fn keys_until(&self, host: &str, now: u64) -> Vec<(PublicKey, Option<u64>)> {
        if let Some(key) = self.cfg.keys.get(host) {
            return vec![(*key, None)];
        }
        if !self.trusts(host) {
            return Vec::new();
        }
        self.discovered
            .lock()
            .unwrap()
            .get(host)
            .map(|d| {
                d.keys
                    .iter()
                    .filter(|(_, until)| until.is_none_or(|u| u > now))
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Fetch and keep `identity`'s lists from the trusted registrars that
    /// `attestations` name, all at once and all within the configured
    /// wait. What cannot be had in it is left to [`Self::lookup`] to call
    /// stale. Asked only for an identity whose login has verified.
    pub async fn refresh(&self, identity: &PublicKey, attestations: &[Attestation], now: u64) {
        let mut hosts: Vec<&str> = attestations
            .iter()
            .map(|a| a.registrar.as_str())
            .filter(|h| self.trusts(h))
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        let each = hosts.into_iter().map(|host| async move {
            let named: Vec<PublicKey> = attestations
                .iter()
                .filter(|a| a.registrar == host)
                .map(|a| a.registrar_key)
                .collect();
            if let Err(e) = self.refresh_one(identity, host, now, &named).await {
                warn!(registrar = host, "identity records: {e}");
            }
        });
        let all = futures_util::future::join_all(each);
        if tokio::time::timeout(self.cfg.timeout, all).await.is_err() {
            warn!("identity records: registrars did not all answer in time");
        }
    }

    async fn refresh_one(
        &self,
        identity: &PublicKey,
        host: &str,
        now: u64,
        named: &[PublicKey],
    ) -> Result<(), String> {
        let fp = Fingerprint::of(identity);
        let cache = self.cache.clone();
        let held = crate::spawn_blocking("identity", move || cache.lists(&fp.0))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.0)?
            .into_iter()
            .find(|l| l.registrar == host);
        // An attestation is anyone's to write: only one under a key the
        // registrar publishes sends this server to it, after asking once
        // whether that key is one it has rotated to since.
        let published = |this: &Self| {
            let keys = this.keys_now(host, now);
            named.is_empty() || named.iter().any(|k| keys.contains(k))
        };
        if !published(self) {
            self.discover(host, true).await?;
            if !published(self) {
                return Err("attested under a key the registrar does not publish".into());
            }
        }
        if held.as_ref().is_some_and(|l| self.current(l, now)) {
            return Ok(());
        }
        let records = self.discover(host, false).await?;
        let keys = self.keys_until(host, now);
        let verify_keys = live(&keys, now);
        let rk = RegistrarKeys {
            host,
            keys: &verify_keys,
        };
        let mut pages = Vec::new();
        let mut since: Option<u64> = None;
        loop {
            let path = match since {
                None => format!("{records}/{fp}"),
                Some(seq) => format!("{records}/{fp}?since={seq}"),
            };
            let bytes = self.get(host, &path, "application/cbor").await?;
            let page = SignedList::parse(&bytes, ListKind::Records, rk)
                .map_err(|e| format!("record list did not verify: {e}"))?;
            if page.fingerprint != Some(fp.0) {
                return Err("record list is for another key".into());
            }
            pages.push(bytes);
            match page.entries.last() {
                Some((seq, _)) if page.more => since = Some(*seq),
                _ => break,
            }
            if pages.len() == MAX_PAGES {
                return Err(format!("record list is longer than {MAX_PAGES} pages"));
            }
        }
        let list = CachedList {
            registrar: host.to_owned(),
            pages,
            fetched: now,
            keys,
        };
        let (cache, storing) = (self.cache.clone(), self.storing.clone());
        crate::spawn_blocking("identity", move || {
            let issued = |l: &CachedList| verified(l).map(|pages| pages[0].issued);
            let fetched = issued(&list).ok_or("record list is not one whole list")?;
            let _one = storing.lock().unwrap_or_else(|e| e.into_inner());
            let held = cache.lists(&fp.0).map_err(|e| e.0)?;
            // A list issued before the one held, as a replay or a stale
            // cache in between would bring, says less than what is held;
            // unless the one held claims to be from the future, which a
            // registrar's clock briefly ahead would otherwise make final.
            if held
                .iter()
                .find(|l| l.registrar == list.registrar)
                .and_then(issued)
                .is_some_and(|held| held > fetched && held <= now)
            {
                return Err("record list is older than the one held".into());
            }
            cache.put(&fp.0, &list).map_err(|e| e.0)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// A list fetched within `max_age` and not past its own `expires`.
    fn current(&self, held: &CachedList, now: u64) -> bool {
        now.saturating_sub(held.fetched) < self.cfg.max_age.as_secs()
            && self.under_configured_key(held)
            && verified(held).is_some_and(|pages| pages.iter().all(|p| p.expires > now))
    }

    /// A list from an operator-keyed registrar counts only if it was
    /// fetched under the key configured now: replacing a key is how an
    /// operator stops trusting what the old one signed.
    fn under_configured_key(&self, held: &CachedList) -> bool {
        self.cfg
            .keys
            .get(&held.registrar)
            .is_none_or(|key| held.keys.iter().any(|(k, _)| k == key))
    }

    /// The records path at `host`, discovering it, and its keys, when
    /// what is known of it is a day old, or a minute old and `again`.
    /// An operator-keyed registrar whose document cannot be had is asked
    /// at the path a registrar serves by default, and not asked for the
    /// document again until the day is out.
    async fn discover(&self, host: &str, again: bool) -> Result<String, String> {
        let known = || {
            let fresh = if again { REDISCOVERY } else { DISCOVERY_TTL };
            self.discovered
                .lock()
                .unwrap()
                .get(host)
                .filter(|d| d.at.elapsed() < fresh)
                .map(|d| d.records.clone())
        };
        if let Some(records) = known() {
            return Ok(records);
        }
        let gate = self
            .discovering
            .lock()
            .unwrap()
            .entry(host.to_owned())
            .or_default()
            .clone();
        let _gate = gate.lock().await;
        if let Some(records) = known() {
            return Ok(records);
        }
        let keyed = self.cfg.keys.contains_key(host);
        if self
            .failed
            .lock()
            .unwrap()
            .get(host)
            .is_some_and(|at| at.elapsed() < REDISCOVERY)
        {
            return Err("discovery failed within the minute".into());
        }
        let found = match (self.fetch_discovery(host).await, keyed) {
            (Ok(found), _) => found,
            (Err(e), true) => {
                debug!(registrar = host, "discovery: {e}; using the configured key");
                Discovered {
                    keys: Vec::new(),
                    records: RECORDS.into(),
                    at: Instant::now(),
                }
            }
            (Err(e), false) => {
                self.failed
                    .lock()
                    .unwrap()
                    .insert(host.to_owned(), Instant::now());
                return Err(format!("discovery: {e}"));
            }
        };
        let records = found.records.clone();
        self.discovered
            .lock()
            .unwrap()
            .insert(host.to_owned(), found);
        Ok(records)
    }

    async fn fetch_discovery(&self, host: &str) -> Result<Discovered, String> {
        let bytes = self
            .get(host, "/.well-known/hotline", "application/json")
            .await?;
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("not JSON: {e}"))?;
        let block = &doc["registrar"];
        if block["host"].as_str() != Some(host) {
            return Err("no registrar block for this host".into());
        }
        let key = |v: &serde_json::Value| -> Option<PublicKey> {
            crate::identity::unb64(v.as_str()?)?.try_into().ok()
        };
        let mut keys = vec![(key(&block["key"]).ok_or("no key")?, None)];
        for r in block["retiring"].as_array().into_iter().flatten() {
            if let (Some(k), Some(until)) = (key(&r["key"]), r["until"].as_u64()) {
                keys.push((k, Some(until)));
            }
        }
        // A path on the registrar's own origin, and nothing that could
        // make the URL built from it another host's or another port's.
        let records = block["endpoints"]["records"].as_str().unwrap_or(RECORDS);
        let path_only = records.starts_with('/')
            && !records.starts_with("//")
            && records
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b));
        if !path_only {
            return Err(format!("records endpoint {records:?} is not a path"));
        }
        Ok(Discovered {
            keys,
            records: records.trim_end_matches('/').to_owned(),
            at: Instant::now(),
        })
    }

    async fn get(&self, host: &str, path: &str, accept: &'static str) -> Result<Vec<u8>, String> {
        let (base, name) = match self.cfg.urls.get(host) {
            Some(url) => (url.trim_end_matches('/').to_owned(), Some(host.to_owned())),
            None => (format!("https://{host}"), None),
        };
        let cfg = FetchConfig {
            timeout: self.cfg.timeout,
            max_bytes: MAX_BYTES,
            proxy: None,
            user_agent: self.cfg.user_agent.clone(),
            accept,
            name,
        };
        match hxd_fetch::fetch(&cfg, &format!("{base}{path}"), &Validators::default()).await {
            Ok(Fetched::Body { bytes, .. }) => Ok(bytes),
            Ok(Fetched::NotModified) => Err("not modified, unasked".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// What the cached lists of the trusted registrars say of `identity`,
    /// and whether one of `hosts` (the registrars that attested it) has
    /// none current. Reads the store: called off the reactor.
    pub fn lookup(&self, identity: &PublicKey, hosts: &[String], now: u64) -> Lookup {
        let fp = Fingerprint::of(identity);
        let held = match self.cache.lists(&fp.0) {
            Ok(held) => held,
            Err(e) => {
                warn!("identity records cache: {}", e.0);
                Vec::new()
            }
        };
        let mut lookup = Lookup::default();
        for host in hosts.iter().filter(|h| self.trusts(h)) {
            if !held
                .iter()
                .any(|l| &l.registrar == host && self.current(l, now))
            {
                lookup.stale = true;
            }
        }
        for l in held
            .iter()
            .filter(|l| self.trusts(&l.registrar) && self.under_configured_key(l))
        {
            let Some(pages) = verified(l) else {
                continue;
            };
            let keys: Vec<PublicKey> = l.keys.iter().map(|(k, _)| *k).collect();
            let keys = RegistrarKeys {
                host: &l.registrar,
                keys: &keys,
            };
            for page in pages.iter().filter(|p| p.fingerprint == Some(fp.0)) {
                for (_, bytes) in &page.entries {
                    match Record::parse(bytes, Some(keys)) {
                        Ok(r) if r.identity() == identity => lookup.records.push(r),
                        Ok(_) => {}
                        Err(e) => debug!(registrar = %l.registrar, "a record did not verify: {e}"),
                    }
                }
            }
        }
        lookup.records.sort_by_key(Record::time);
        lookup
    }
}

/// The keys of `keys` whose `until` has not passed.
fn live(keys: &[(PublicKey, Option<u64>)], now: u64) -> Vec<PublicKey> {
    keys.iter()
        .filter(|(_, until)| until.is_none_or(|u| u > now))
        .map(|(k, _)| *k)
        .collect()
}

/// Every page of `held`, verified under the keys it was fetched with, or
/// `None` if one fails or they are not one whole list: from the start,
/// each page taking up where the last left off, and the last not cut
/// short. A page is verified under a key retired since, as it was when
/// fetched.
fn verified(held: &CachedList) -> Option<Vec<SignedList>> {
    let keys: Vec<PublicKey> = held.keys.iter().map(|(k, _)| *k).collect();
    let rk = RegistrarKeys {
        host: &held.registrar,
        keys: &keys,
    };
    let pages: Vec<SignedList> = held
        .pages
        .iter()
        .map(|p| SignedList::parse(p, ListKind::Records, rk).ok())
        .collect::<Option<_>>()?;
    let mut since = None;
    for page in &pages {
        if page.since != since {
            return None;
        }
        since = page.entries.last().map(|(seq, _)| *seq);
    }
    pages.last().is_some_and(|p| !p.more).then_some(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::ServerKey;

    #[test]
    fn a_retiring_key_held_is_used_only_until_its_deadline() {
        let (old, new) = ([1; 32], [2; 32]);
        let cache = Arc::new(hxd_core::identity_records::MemoryRecordCache::default());
        let identity = [9; 32];
        cache
            .put(
                &Fingerprint::of(&identity).0,
                &CachedList {
                    registrar: "hl.example".into(),
                    pages: vec![],
                    keys: vec![(old, Some(100)), (new, None)],
                    fetched: 1,
                },
            )
            .unwrap();
        let registrars = Registrars::new(
            RegistrarsConfig {
                keys: HashMap::new(),
                trusted: vec!["hl.example".into()],
                urls: HashMap::new(),
                timeout: Duration::from_secs(1),
                max_age: Duration::from_secs(1),
                stale: Stale::Cached,
                user_agent: String::new(),
            },
            cache,
        );
        assert_eq!(registrars.keys("hl.example", &identity, 99), [old, new]);
        assert_eq!(registrars.keys("hl.example", &identity, 100), [new]);
    }

    #[test]
    fn a_list_is_used_only_whole() {
        let key = ServerKey::from_seed(&[3; 32]);
        let page = |since: Option<u64>, seqs: &[u64], more: bool| {
            SignedList {
                registrar: "hl.example".into(),
                issued: 1,
                expires: 2,
                fingerprint: Some([7; 32]),
                since,
                more,
                entries: seqs.iter().map(|s| (*s, vec![])).collect(),
            }
            .sign(ListKind::Records, &key)
        };
        let whole = |pages: Vec<Vec<u8>>| {
            verified(&CachedList {
                registrar: "hl.example".into(),
                pages,
                keys: vec![(key.public(), None)],
                fetched: 1,
            })
            .is_some()
        };
        assert!(whole(vec![page(None, &[], false)]));
        assert!(whole(vec![
            page(None, &[1, 2], true),
            page(Some(2), &[3], false)
        ]));
        assert!(!whole(vec![]), "no pages");
        assert!(!whole(vec![page(None, &[1, 2], true)]), "cut short");
        assert!(
            !whole(vec![page(None, &[1, 2], true), page(Some(5), &[6], false)]),
            "a gap"
        );
        assert!(!whole(vec![page(Some(2), &[3], false)]), "no first page");
    }
}
