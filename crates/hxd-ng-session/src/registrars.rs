//! The registrars this server trusts, as a verifying server uses them
//! (`docs/identity-registrar.md` §7.1–§7.2, `docs/identity-records.md`):
//! each one's keys, from the operator's table or its discovery document,
//! and the signed record list it publishes against an identity, fetched
//! when the identity authenticates and kept, on disk, for when the
//! registrar cannot be reached. What the records then mean is
//! `identity.rs`'s; this only says what they are and whether they are
//! current.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hl_identity::{
    Attestation, DeviceEpoch, Fingerprint, ListKind, PublicKey, Record, RegistrarKeys, SignedList,
};
use hxd_core::identity_records::{CachedList, KeptEpoch, RecordCache};
use hxd_fetch::{FetchConfig, Fetched, Validators};
use tracing::{debug, warn};

/// How long a discovery document is believed (§7.1).
const DISCOVERY_TTL: Duration = Duration::from_secs(24 * 3600);

/// How soon a key nobody has heard of sends this server to a registrar's
/// discovery document again, ahead of `DISCOVERY_TTL`: often enough that
/// a key rotation is not a day of refusals, and no more often, since any
/// client can show an attestation naming any key.
const REDISCOVERY: Duration = Duration::from_secs(60);

/// How long an identity's registrars are remembered without a session:
/// a transport token's life, and the wait on registrars before it.
const ADMITTING: Duration = Duration::from_secs(120);

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
    /// How long it is believed: `DISCOVERY_TTL`, or for a stand-in made
    /// when the document could not be had, `REDISCOVERY`.
    ttl: Duration,
}

pub struct Registrars {
    cfg: RegistrarsConfig,
    clock: hxd_core::clock::Clock,
    discovered: Mutex<HashMap<String, Discovered>>,
    /// One discovery at a time per host, so logins arriving together
    /// wait on one fetch rather than each making their own.
    discovering: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When a host's records last could not be fetched, or its discovery
    /// document had: that document is not asked for again for
    /// `REDISCOVERY`, and a sweep asks the host nothing more once it has
    /// failed in it, so a registrar that is down costs a sweep one wait
    /// rather than one for every identity swept.
    failed: Mutex<HashMap<String, Instant>>,
    /// The trusted registrars each identity admitted here was attested
    /// by, and when that was last seen, for the sweep to ask even when
    /// admission held no list from them. A restart forgets it, as it ends
    /// the sessions it is for.
    attested: Mutex<HashMap<Fingerprint, (HashSet<String>, Instant)>>,
    /// Held across comparing a fetched list with the one held and
    /// replacing it, so two fetches finishing together cannot leave the
    /// older one. Under it, the resets a replaced list carried that could
    /// not be kept: applied by each lookup, and kept by the first whose
    /// write succeeds. A restart forgets them.
    storing: Arc<Mutex<Unkept>>,
    cache: Arc<dyn RecordCache>,
}

/// Device epoch records, as signed, that a store could not keep.
type Unkept = HashMap<Fingerprint, Vec<(DeviceEpoch, Vec<u8>)>>;

/// A rotation found: the predecessor, the successor and the record as
/// it was published.
pub type Rotated = (Fingerprint, Fingerprint, Vec<u8>);

/// What the registrars publish against one identity, as known now.
#[derive(Debug, Default)]
pub struct Lookup {
    /// Every verified record, oldest first, with the device epoch
    /// records kept for the identity whatever its lists carry now
    /// (`docs/identity-records.md` §3).
    pub records: Vec<Record>,
    /// The rotation records among them, as they were published, by the
    /// predecessor's fingerprint: what a friend's client fetches to check
    /// a rotation for itself (`docs/proposals/portable-friends.md` §10).
    /// Each with its successor's too, since a predecessor can be named by
    /// two rotations to two keys, of which only one stands here.
    pub rotations: Vec<(Fingerprint, Fingerprint, Vec<u8>)>,
    /// Some registrar that attested the identity, or that a list is held
    /// from, has no list this server can call current:
    /// `RegistrarsConfig::stale` decides.
    pub stale: bool,
    /// The identity's lists were read, there was at least one, and every
    /// one from a registrar still trusted verified under its configured
    /// key: only then does a record missing from them mean no trusted
    /// registrar published it. Lists from registrars no longer trusted
    /// alone count as complete and refusing nothing, which lifts what
    /// those registrars revoked.
    pub complete: bool,
    /// The identity's lists could be read from the cache.
    pub read: bool,
    /// A list held from a trusted registrar is not one whole list under
    /// the keys it was fetched with. Unlike a list that is merely old, it
    /// proves nothing either way, so admission refuses rather than take
    /// it as stale.
    pub damaged: bool,
}

impl Registrars {
    pub fn new(
        cfg: RegistrarsConfig,
        cache: Arc<dyn RecordCache>,
        clock: hxd_core::clock::Clock,
    ) -> Self {
        Registrars {
            cfg,
            clock,
            discovered: Mutex::new(HashMap::new()),
            discovering: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            attested: Mutex::new(HashMap::new()),
            storing: Arc::new(Mutex::new(HashMap::new())),
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
    /// `attestations` name, and from those [`Self::held`] names, all at
    /// once and all within the configured wait: a card shown without its
    /// attestations, or with one under a key no longer published, still
    /// has its registrars asked. What cannot be had in it is left to
    /// [`Self::lookup`] to call stale. Asked only for an identity whose
    /// login has verified.
    pub async fn refresh(&self, identity: &PublicKey, attestations: &[Attestation], now: u64) {
        let fp = Fingerprint::of(identity);
        let held = self.held(fp).await.unwrap_or_default();
        let mut hosts: Vec<(&str, Vec<PublicKey>)> = attestations
            .iter()
            .map(|a| a.registrar.as_str())
            .chain(held.iter().map(String::as_str))
            .filter(|h| self.trusts(h))
            .map(|host| {
                let named = attestations
                    .iter()
                    .filter(|a| a.registrar == host)
                    .map(|a| a.registrar_key)
                    .collect();
                (host, named)
            })
            .collect();
        hosts.sort_unstable();
        hosts.dedup_by_key(|(host, _)| *host);
        self.refresh_hosts(fp, &hosts, now, None).await;
    }

    /// Refresh, where they are due, the lists of the registrars that
    /// attested `fp` when it was admitted, whatever card it shows now,
    /// which is what a sweep must keep asking. A registrar that has
    /// failed since `sweep` began is not asked again in it.
    pub async fn refresh_held(&self, fp: Fingerprint, now: u64, sweep: Instant) {
        let Some(hosts) = self.held(fp).await else {
            return;
        };
        let hosts: Vec<(&str, Vec<PublicKey>)> = hosts
            .iter()
            .filter(|h| self.trusts(h))
            .map(|h| (h.as_str(), Vec::new()))
            .collect();
        self.refresh_hosts(fp, &hosts, now, Some(sweep)).await;
    }

    /// The registrars on file for `fp`: those it holds a list from, and
    /// those it was admitted while unable to reach. `None` when the
    /// store cannot be read.
    async fn held(&self, fp: Fingerprint) -> Option<Vec<String>> {
        let cache = self.cache.clone();
        let held = crate::spawn_blocking("identity", move || cache.lists(&fp.0)).await;
        let mut hosts: Vec<String> = match held {
            Ok(Ok(held)) => held.into_iter().map(|l| l.registrar).collect(),
            _ => return None,
        };
        hosts.extend(
            self.attested
                .lock()
                .unwrap()
                .get(&fp)
                .into_iter()
                .flat_map(|(hosts, _)| hosts)
                .cloned(),
        );
        hosts.sort_unstable();
        hosts.dedup();
        Some(hosts)
    }

    /// Is a trusted registrar remembered as having attested `fp`?
    pub fn attested(&self, fp: &Fingerprint) -> bool {
        self.attested
            .lock()
            .unwrap()
            .get(fp)
            .is_some_and(|(hosts, _)| hosts.iter().any(|h| self.trusts(h)))
    }

    /// Forget the registrars that attested identities the sweep no longer
    /// reads, but for one admitted within `ADMITTING`, whose session may
    /// not have attached yet.
    pub fn retain_attested(&self, live: &[Fingerprint]) {
        let live: HashSet<&Fingerprint> = live.iter().collect();
        self.attested
            .lock()
            .unwrap()
            .retain(|fp, (_, at)| live.contains(fp) || self.clock.since(*at) < ADMITTING);
    }

    async fn refresh_hosts(
        &self,
        fp: Fingerprint,
        hosts: &[(&str, Vec<PublicKey>)],
        now: u64,
        sweep: Option<Instant>,
    ) {
        let each = hosts.iter().map(|(host, named)| async move {
            let failed_since = |since: Instant| {
                self.failed
                    .lock()
                    .unwrap()
                    .get(*host)
                    .is_some_and(|at| *at >= since)
            };
            if sweep.is_some_and(failed_since) {
                return;
            }
            match tokio::time::timeout(self.cfg.timeout, self.refresh_one(fp, host, now, named))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(registrar = host, "identity records: {e}"),
                Err(_) => {
                    self.failed
                        .lock()
                        .unwrap()
                        .insert(host.to_string(), self.clock.now());
                    warn!(registrar = host, "identity records: no answer in time");
                }
            }
        });
        futures_util::future::join_all(each).await;
    }

    async fn refresh_one(
        &self,
        fp: Fingerprint,
        host: &str,
        now: u64,
        named: &[PublicKey],
    ) -> Result<(), String> {
        let cache = self.cache.clone();
        let (owned, max_age) = (host.to_owned(), self.cfg.max_age);
        // Read, and checked against the clock, off the reactor: checking
        // is verifying signatures.
        let (held, current) = crate::spawn_blocking("identity", move || {
            let held = cache
                .lists(&fp.0)?
                .into_iter()
                .find(|l| l.registrar == owned);
            let current = held.as_ref().is_some_and(|l| current(l, max_age, now));
            Ok::<_, hxd_core::inbox::StoreError>((held, current))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.0)?;
        // An attestation is anyone's to write: only one under a key the
        // registrar publishes sends this server to it, after asking once
        // whether that key is one it has rotated to since. A list held
        // from it is reason enough of the server's own.
        let published = |this: &Self| {
            let keys = this.keys_now(host, now);
            named.is_empty() || named.iter().any(|k| keys.contains(k))
        };
        if !published(self) {
            // An operator's key is not one discovery can change.
            if !self.cfg.keys.contains_key(host) {
                let found = self.discover(host, true).await;
                if held.is_none() {
                    found?;
                }
            }
            if !published(self) && held.is_none() {
                return Err("attested under a key the registrar does not publish".into());
            }
        }
        {
            let mut attested = self.attested.lock().unwrap();
            let (hosts, at) = attested
                .entry(fp)
                .or_insert_with(|| (HashSet::new(), self.clock.now()));
            hosts.insert(host.to_owned());
            *at = self.clock.now();
        }
        if current && held.as_ref().is_some_and(|l| self.under_configured_key(l)) {
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
            let bytes = self
                .get(host, &path, "application/cbor")
                .await
                .inspect_err(|_| {
                    self.failed
                        .lock()
                        .unwrap()
                        .insert(host.to_owned(), self.clock.now());
                })?;
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
            let mut unkept = storing.lock().unwrap_or_else(|e| e.into_inner());
            let held = cache.lists(&fp.0).map_err(|e| e.0)?;
            // A list issued before the one held, as a replay or a stale
            // cache in between would bring, says less than what is held;
            // unless the one held claims to be from the future, which a
            // registrar's clock briefly ahead would otherwise make final.
            let replaced = held.iter().find(|l| l.registrar == list.registrar);
            if replaced
                .and_then(issued)
                .is_some_and(|held| held > fetched && held <= now)
            {
                return Err("record list is older than the one held".into());
            }
            let pages = verified(&list).unwrap_or_default();
            let fresh = epochs_in(&pages, fp);
            // A reset the list replaced carries and this one does not is
            // kept first, as a list from before the floor table, or one
            // whose resets could not be kept, may hold; or, if it cannot
            // be, held here, so that the fetched list, which may revoke
            // what the held one did not, is stored all the same.
            let dropped: Vec<_> = replaced
                .and_then(verified)
                .map(|pages| epochs_in(&pages, fp))
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, bytes)| !fresh.iter().any(|(_, b)| b == bytes))
                .collect();
            if !dropped.is_empty() {
                if let Err(e) = keep_epochs(&*cache, fp, &dropped) {
                    warn!("identity device floor: {}; held until it can be kept", e.0);
                    unkept.entry(fp).or_default().extend(dropped);
                }
            }
            cache.put(&fp.0, &list).map_err(|e| e.0)?;
            keep_epochs(&*cache, fp, &fresh)
                .map(|_| ())
                .map_err(|e| e.0)
        })
        .await
        .map_err(|e| e.to_string())?
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
    /// at the path last discovered, else the one a registrar serves by
    /// default, and asked for the document again once that stand-in's
    /// minute is out, whatever its records fetches did meanwhile.
    async fn discover(&self, host: &str, again: bool) -> Result<String, String> {
        let known = || {
            let fresh = if again { REDISCOVERY } else { DISCOVERY_TTL };
            self.discovered
                .lock()
                .unwrap()
                .get(host)
                .filter(|d| self.clock.since(d.at) < fresh.min(d.ttl))
                .map(|d| d.records.clone())
        };
        // The path last known, however old, else the default.
        let last = || {
            self.discovered
                .lock()
                .unwrap()
                .get(host)
                .map_or_else(|| RECORDS.into(), |d| d.records.clone())
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
        // A keyed registrar's stand-in is its own minute: `failed`, which
        // a records fetch at the wrong path renews, would hold it there.
        if !keyed
            && self
                .failed
                .lock()
                .unwrap()
                .get(host)
                .is_some_and(|at| self.clock.since(*at) < REDISCOVERY)
        {
            return Err("discovery failed within the minute".into());
        }
        // A keyed registrar's stand-in, asked for again after the minute:
        // a registrar serving its records elsewhere would otherwise be
        // asked at the wrong path for a day, and a damaged list held from
        // it never replaced. Written before the document is asked for, so
        // an ask the handshake's wait cuts short is the minute's too.
        if keyed {
            let stand_in = Discovered {
                keys: Vec::new(),
                records: last(),
                at: self.clock.now(),
                ttl: REDISCOVERY,
            };
            self.discovered
                .lock()
                .unwrap()
                .insert(host.to_owned(), stand_in);
        }
        let found = match (self.fetch_discovery(host).await, keyed) {
            (Ok(found), _) => found,
            (Err(e), true) => {
                debug!(registrar = host, "discovery: {e}; using the configured key");
                return Ok(last());
            }
            (Err(e), false) => {
                self.failed
                    .lock()
                    .unwrap()
                    .insert(host.to_owned(), self.clock.now());
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
            at: self.clock.now(),
            ttl: DISCOVERY_TTL,
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

    /// What the held lists of `identities` (fingerprints) refuse, as one
    /// list: each identity revoked, each frozen when `frozen_refuses`
    /// (refused, not revoked), each device an identity revoked, as that
    /// identity's, and each identity's device epoch floor; and, apart,
    /// the rotations away from them, for the caller to accept or not, and
    /// the identities whose lists could not be read.
    /// Reads the store and verifies: called off the reactor.
    pub fn refused(
        &self,
        identities: &[Fingerprint],
        frozen_refuses: bool,
    ) -> (hxd_core::Published, Vec<Rotated>, Vec<Fingerprint>) {
        let mut refused = hxd_core::Published::default();
        let mut rotations = Vec::new();
        let mut unread = Vec::new();
        for fp in identities {
            let mut frozen: HashMap<String, bool> = HashMap::new();
            let found = self.lookup_fp(*fp, &[], 0);
            if !found.read {
                unread.push(*fp);
            }
            if found.complete {
                refused.covered.insert(fp.0);
            }
            for record in found.records {
                match record {
                    Record::RevokeIdentity(_) => {
                        refused.identities.insert(fp.0);
                    }
                    Record::RevokeDevice(r) => {
                        refused.devices.insert((fp.0, Fingerprint::of(&r.device).0));
                    }
                    Record::Freeze(f) => {
                        frozen.insert(f.registrar, f.frozen);
                    }
                    Record::DeviceEpoch(e) => {
                        let floor = refused.floors.entry(fp.0).or_default();
                        *floor = (*floor).max(e.epoch);
                    }
                    Record::Rotate(r) if Fingerprint::of(&r.identity) == *fp => {
                        let to = Fingerprint::of(&r.successor);
                        let record = found
                            .rotations
                            .iter()
                            .find(|(from, succ, _)| from == fp && *succ == to)
                            .map(|(_, _, b)| b.clone())
                            .unwrap_or_default();
                        rotations.push((*fp, to, record));
                    }
                    _ => {}
                }
            }
            if frozen_refuses && frozen.values().any(|f| *f) {
                refused.unrevoked.insert(fp.0);
            }
        }
        (refused, rotations, unread)
    }

    /// What the cached lists of the trusted registrars say of `identity`,
    /// and whether one of `hosts` (the registrars that attested it), or
    /// of those a list is held from, has none current. Reads the store:
    /// called off the reactor.
    pub fn lookup(&self, identity: &PublicKey, hosts: &[String], now: u64) -> Lookup {
        self.lookup_fp(Fingerprint::of(identity), hosts, now)
    }

    fn lookup_fp(&self, fp: Fingerprint, hosts: &[String], now: u64) -> Lookup {
        let (held, read) = match self.cache.lists(&fp.0) {
            Ok(held) => (held, true),
            Err(e) => {
                warn!("identity records cache: {}", e.0);
                (Vec::new(), false)
            }
        };
        let mut seen = Vec::new();
        let mut lookup = Lookup {
            complete: read && !held.is_empty(),
            read,
            ..Lookup::default()
        };
        let on_file = held.iter().map(|l| &l.registrar);
        for host in hosts.iter().chain(on_file).filter(|h| self.trusts(h)) {
            if !held.iter().any(|l| {
                &l.registrar == host
                    && self.under_configured_key(l)
                    && current(l, self.cfg.max_age, now)
            }) {
                lookup.stale = true;
            }
        }
        for l in held.iter().filter(|l| self.trusts(&l.registrar)) {
            // Whole first: keys damaged beside a list can read as a key
            // the operator replaced, while a list truly fetched under one
            // still verifies under it, says nothing, and is stale.
            let Some(pages) = verified(l) else {
                lookup.damaged = true;
                lookup.complete = false;
                continue;
            };
            if !self.under_configured_key(l) {
                lookup.complete = false;
                continue;
            }
            let keys: Vec<PublicKey> = l.keys.iter().map(|(k, _)| *k).collect();
            let keys = RegistrarKeys {
                host: &l.registrar,
                keys: &keys,
            };
            for page in pages.iter().filter(|p| p.fingerprint == Some(fp.0)) {
                for (_, bytes) in &page.entries {
                    let record = Record::parse(bytes, Some(keys));
                    match &record {
                        Ok(Record::Rotate(r)) => lookup.rotations.push((
                            Fingerprint::of(&r.identity),
                            Fingerprint::of(&r.successor),
                            bytes.clone(),
                        )),
                        Ok(Record::DeviceEpoch(e)) if Fingerprint::of(&e.identity) == fp => {
                            seen.push((e.clone(), bytes.clone()))
                        }
                        _ => {}
                    }
                    match record {
                        Ok(r) if Fingerprint::of(r.identity()) == fp => lookup.records.push(r),
                        // A rotation is published under both keys, and the
                        // successor's admission is where it is learned.
                        Ok(Record::Rotate(r)) if Fingerprint::of(&r.successor) == fp => {
                            lookup.records.push(Record::Rotate(r))
                        }
                        Ok(_) => {}
                        Err(e) => debug!(registrar = %l.registrar, "a record did not verify: {e}"),
                    }
                }
            }
        }
        // What was kept of the identity's device epochs, raised with what
        // the lists carry now: a list that no longer carries one lowers
        // no floor. One that cannot be read proves nothing either way.
        let kept = {
            let mut unkept = self.storing.lock().unwrap_or_else(|e| e.into_inner());
            let held = unkept.get(&fp).cloned().unwrap_or_default();
            for (e, _) in &held {
                let e = Record::DeviceEpoch(e.clone());
                if !lookup.records.contains(&e) {
                    lookup.records.push(e);
                }
            }
            seen.extend(held);
            let kept = keep_epochs(&*self.cache, fp, &seen);
            if kept.is_ok() {
                unkept.remove(&fp);
            }
            kept
        };
        match kept {
            Ok(kept) => {
                for e in kept.into_iter().map(Record::DeviceEpoch) {
                    if !lookup.records.contains(&e) {
                        lookup.records.push(e);
                    }
                }
            }
            Err(e) => {
                warn!("identity device floor: {}", e.0);
                lookup.read = false;
                lookup.complete = false;
                lookup.damaged = true;
            }
        }
        lookup.records.sort_by_key(Record::time);
        lookup
    }

    /// [`kept_floor`] in the store this keeps lists in.
    pub fn kept_floor(&self, fp: &Fingerprint) -> Result<u64, hxd_core::StoreError> {
        kept_floor(&*self.cache, fp)
    }
}

/// The device epoch floor kept in `cache` for `fp`, as far as what is
/// kept verifies. Reads the store and verifies: called off the reactor.
pub fn kept_floor(cache: &dyn RecordCache, fp: &Fingerprint) -> Result<u64, hxd_core::StoreError> {
    let rows = cache.epochs(&fp.0)?;
    Ok(kept_verified(*fp, rows)
        .iter()
        .map(|e| e.epoch)
        .max()
        .unwrap_or(0))
}

/// `fp`'s device epoch records among the entries of `pages`, as signed.
fn epochs_in(pages: &[SignedList], fp: Fingerprint) -> Vec<(DeviceEpoch, Vec<u8>)> {
    pages
        .iter()
        .filter(|p| p.fingerprint == Some(fp.0))
        .flat_map(|p| &p.entries)
        .filter_map(|(_, bytes)| Some((DeviceEpoch::parse(bytes).ok()?, bytes.clone())))
        .filter(|(e, _)| Fingerprint::of(&e.identity) == fp)
        .collect()
}

/// Keep each of `seen`, `fp`'s device epoch records as signed, that is
/// earlier for its epoch than what is kept, or whose epoch's row does not
/// verify, and answer every one kept that verifies. A `time` the store
/// cannot hold is not kept. Called with the store's writes held, so two
/// readers cannot each keep a later record over the other's earlier one.
fn keep_epochs(
    cache: &dyn RecordCache,
    fp: Fingerprint,
    seen: &[(DeviceEpoch, Vec<u8>)],
) -> Result<Vec<DeviceEpoch>, hxd_core::StoreError> {
    let rows = cache.epochs(&fp.0)?;
    let stored: HashSet<u64> = rows.iter().map(|r| r.epoch).collect();
    let mut kept = kept_verified(fp, rows);
    for (e, bytes) in seen.iter().filter(|(e, _)| i64::try_from(e.time).is_ok()) {
        let held = kept.iter().find(|k| k.epoch == e.epoch);
        if held.is_some_and(|k| k.time <= e.time) {
            continue;
        }
        let row = KeptEpoch {
            epoch: e.epoch,
            time: e.time,
            record: bytes.clone(),
        };
        match held.is_none() && stored.contains(&e.epoch) {
            true => cache.replace_epoch(&fp.0, &row)?,
            false => cache.keep_epoch(&fp.0, &row)?,
        }
        kept.retain(|k| k.epoch != e.epoch);
        kept.push(e.clone());
    }
    Ok(kept)
}

/// The rows of `rows` that verify as `fp`'s device epoch records, each as
/// its row says. One that does not is ignored rather than refused, until
/// a record of its epoch replaces it: whoever could damage the row could
/// as well have deleted it, and refusing on it would shut the identity
/// out until then.
fn kept_verified(fp: Fingerprint, rows: Vec<KeptEpoch>) -> Vec<DeviceEpoch> {
    rows.into_iter()
        .filter_map(|row| match DeviceEpoch::parse(&row.record) {
            Ok(e)
                if Fingerprint::of(&e.identity) == fp
                    && (e.epoch, e.time) == (row.epoch, row.time) =>
            {
                Some(e)
            }
            _ => {
                warn!(fingerprint = %fp.short(), epoch = row.epoch, "a kept device epoch record did not verify; ignored");
                None
            }
        })
        .collect()
}

/// A list fetched within `max_age` and not past its own `expires`.
fn current(held: &CachedList, max_age: Duration, now: u64) -> bool {
    now.saturating_sub(held.fetched) < max_age.as_secs()
        && verified(held).is_some_and(|pages| pages.iter().all(|p| p.expires > now))
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

    fn registrars(cache: Arc<dyn RecordCache>) -> Registrars {
        Registrars::new(
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
            hxd_core::clock::Clock::default(),
        )
    }

    #[test]
    fn an_identity_still_being_admitted_keeps_its_registrars() {
        let r = registrars(Arc::new(
            hxd_core::identity_records::MemoryRecordCache::default(),
        ));
        let (admitting, gone, live) = (
            Fingerprint([1; 32]),
            Fingerprint([2; 32]),
            Fingerprint([3; 32]),
        );
        let long_ago = Instant::now() - ADMITTING;
        {
            let mut attested = r.attested.lock().unwrap();
            let hosts = || HashSet::from(["hl.example".to_owned()]);
            attested.insert(admitting, (hosts(), Instant::now()));
            attested.insert(gone, (hosts(), long_ago));
            attested.insert(live, (hosts(), long_ago));
        }
        r.retain_attested(&[live]);
        let attested = r.attested.lock().unwrap();
        assert!(attested.contains_key(&admitting));
        assert!(!attested.contains_key(&gone));
        assert!(attested.contains_key(&live));
    }

    /// A cache that cannot be read, or a trusted list in it that does not
    /// verify or was fetched under a key the operator has since replaced,
    /// covers nobody: its silence is not a registrar's, and must not lift
    /// a revocation it holds. One that does not verify is damaged too,
    /// which admission refuses.
    #[test]
    fn records_not_read_whole_cover_no_identity() {
        struct Unreadable;
        impl RecordCache for Unreadable {
            fn put(&self, _: &[u8; 32], _: &CachedList) -> Result<(), hxd_core::StoreError> {
                Ok(())
            }
            fn lists(&self, _: &[u8; 32]) -> Result<Vec<CachedList>, hxd_core::StoreError> {
                Err(hxd_core::StoreError("unreadable".into()))
            }
            fn first_seen(&self, _: &[u8; 32], now: u64) -> Result<u64, hxd_core::StoreError> {
                Ok(now)
            }
            fn keep_epoch(
                &self,
                _: &[u8; 32],
                _: &hxd_core::identity_records::KeptEpoch,
            ) -> Result<(), hxd_core::StoreError> {
                Ok(())
            }
            fn replace_epoch(
                &self,
                _: &[u8; 32],
                _: &hxd_core::identity_records::KeptEpoch,
            ) -> Result<(), hxd_core::StoreError> {
                Ok(())
            }
            fn epochs(
                &self,
                _: &[u8; 32],
            ) -> Result<Vec<hxd_core::identity_records::KeptEpoch>, hxd_core::StoreError>
            {
                Ok(Vec::new())
            }
        }
        let fp = Fingerprint([1; 32]);
        let unverified = hxd_core::identity_records::MemoryRecordCache::default();
        unverified
            .put(
                &fp.0,
                &CachedList {
                    registrar: "hl.example".into(),
                    pages: vec![],
                    keys: vec![],
                    fetched: 1,
                },
            )
            .unwrap();
        let (fetched_under, configured) = (ServerKey::from_seed(&[3; 32]), [4; 32]);
        let replaced = hxd_core::identity_records::MemoryRecordCache::default();
        let page = SignedList {
            registrar: "hl.example".into(),
            issued: 1,
            expires: u64::MAX,
            fingerprint: Some(fp.0),
            since: None,
            more: false,
            entries: vec![],
        }
        .sign(ListKind::Records, &fetched_under);
        replaced
            .put(
                &fp.0,
                &CachedList {
                    registrar: "hl.example".into(),
                    pages: vec![page],
                    keys: vec![(fetched_under.public(), None)],
                    fetched: 1,
                },
            )
            .unwrap();
        let caches: [(Arc<dyn RecordCache>, Option<PublicKey>); 3] = [
            (Arc::new(Unreadable), None),
            (Arc::new(unverified), None),
            (Arc::new(replaced), Some(configured)),
        ];
        for (i, (cache, key)) in caches.into_iter().enumerate() {
            let mut r = registrars(cache);
            r.cfg.keys.extend(key.map(|k| ("hl.example".to_owned(), k)));
            let (refused, _, unread) = r.refused(&[fp], false);
            assert!(refused.covered.is_empty(), "{key:?}");
            assert_eq!(
                unread.is_empty(),
                i > 0,
                "only the unreadable cache is unread"
            );
            assert_eq!(
                r.lookup_fp(fp, &[], 0).damaged,
                i == 1,
                "a list under a replaced key is stale, not damaged"
            );
        }
    }

    /// An operator-keyed registrar whose discovery document could not be
    /// had is asked for it again once the minute is out, however often its
    /// records were asked for at the default path meanwhile, so a damaged
    /// list held from one serving its records at a path of its own is
    /// fetched whole there; and a document lost later keeps that path.
    #[tokio::test]
    async fn a_keyed_registrar_without_its_document_is_asked_again_after_the_minute() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const DOWN: u8 = 0;
        const UP: u8 = 1;
        const NO_DOCUMENT: u8 = 2;
        let key = ServerKey::from_seed(&[3; 32]);
        let fp = Fingerprint([7; 32]);
        let cache = Arc::new(hxd_core::identity_records::MemoryRecordCache::default());
        let damaged = CachedList {
            registrar: "hl.example".into(),
            pages: vec![],
            keys: vec![(key.public(), None)],
            fetched: 1,
        };
        cache.put(&fp.0, &damaged).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut r = registrars(cache);
        r.cfg.keys.insert("hl.example".into(), key.public());
        let url = format!("http://{}", listener.local_addr().unwrap());
        r.cfg.urls.insert("hl.example".into(), url);

        let doc = serde_json::json!({ "registrar": {
            "host": "hl.example",
            "key": crate::identity::b64(&key.public()),
            "endpoints": { "records": "/elsewhere" },
        }})
        .to_string();
        let list = SignedList {
            registrar: "hl.example".into(),
            issued: r.clock.unix(),
            expires: u64::MAX,
            fingerprint: Some(fp.0),
            since: None,
            more: false,
            entries: vec![],
        }
        .sign(ListKind::Records, &key);
        let mode = Arc::new(AtomicU8::new(DOWN));
        let serving = mode.clone();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let n = c.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                let path = request.split(' ').nth(1).unwrap_or_default();
                let mode = serving.load(Ordering::SeqCst);
                let (status, body) = match path {
                    _ if mode == DOWN => continue,
                    "/.well-known/hotline" if mode == UP => ("200 OK", doc.as_bytes()),
                    p if p.starts_with("/elsewhere/") => ("200 OK", &list[..]),
                    _ => ("404 Not Found", &b""[..]),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = c.write_all(&[head.as_bytes(), body].concat()).await;
            }
        });
        let whole = |r: &Registrars| !r.lookup_fp(fp, &[], 0).damaged;
        async fn refresh(r: &Registrars, fp: Fingerprint) {
            let now = r.clock.unix();
            r.refresh_hosts(fp, &[("hl.example", Vec::new())], now, None)
                .await;
        }

        // After a restart, with the registrar down.
        refresh(&r, fp).await;
        assert!(!whole(&r));
        // Back, and asked at the default path within the minute, twice.
        mode.store(UP, Ordering::SeqCst);
        for _ in 0..2 {
            r.clock.advance(REDISCOVERY / 2);
            refresh(&r, fp).await;
        }
        assert!(whole(&r), "fetched whole once the minute was out");

        mode.store(NO_DOCUMENT, Ordering::SeqCst);
        r.clock.advance(DISCOVERY_TTL);
        assert_eq!(r.discover("hl.example", false).await.unwrap(), "/elsewhere");
    }

    /// A keyed registrar's document asked for and never answered counts
    /// as the minute's ask though the wait is cut short: a login within
    /// the minute asks for it no more.
    #[tokio::test]
    async fn a_keyed_registrar_that_never_answers_is_asked_once_a_minute() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut r = registrars(Arc::new(
            hxd_core::identity_records::MemoryRecordCache::default(),
        ));
        r.cfg
            .keys
            .insert("hl.example".into(), ServerKey::from_seed(&[3; 32]).public());
        let url = format!("http://{}", listener.local_addr().unwrap());
        r.cfg.urls.insert("hl.example".into(), url);
        let asked = Arc::new(AtomicUsize::new(0));
        let count = asked.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (c, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                held.push(c);
            }
        });
        let cut_short = Duration::from_millis(300);
        for _ in 0..2 {
            let _ = tokio::time::timeout(cut_short, r.discover("hl.example", false)).await;
        }
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        r.clock.advance(REDISCOVERY);
        let _ = tokio::time::timeout(cut_short, r.discover("hl.example", false)).await;
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "and again after the minute"
        );
    }

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
        let registrars = registrars(cache);
        assert_eq!(registrars.keys("hl.example", &identity, 99), [old, new]);
        assert_eq!(registrars.keys("hl.example", &identity, 100), [new]);
    }

    #[test]
    fn each_rotation_found_carries_its_own_record() {
        use hl_identity::{IdentityKey, Rotation};
        let key = ServerKey::from_seed(&[3; 32]);
        let from = IdentityKey::from_seed(&[4; 32]);
        let to = [5u8, 6].map(|n| IdentityKey::from_seed(&[n; 32]));
        let records = to.each_ref().map(|t| {
            Rotation {
                identity: from.public(),
                successor: t.public(),
                time: 10,
                next: None,
            }
            .sign(&from, t)
            .unwrap()
        });
        let pred = Fingerprint::of(&from.public());
        let page = SignedList {
            registrar: "hl.example".into(),
            issued: 1,
            expires: u64::MAX,
            fingerprint: Some(pred.0),
            since: None,
            more: false,
            entries: records
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, r)| (i as u64 + 1, r))
                .collect(),
        }
        .sign(ListKind::Records, &key);
        let cache = Arc::new(hxd_core::identity_records::MemoryRecordCache::default());
        cache
            .put(
                &pred.0,
                &CachedList {
                    registrar: "hl.example".into(),
                    pages: vec![page],
                    keys: vec![(key.public(), None)],
                    fetched: 1,
                },
            )
            .unwrap();
        let (refused, rotations, _) = registrars(cache).refused(&[pred], false);
        assert!(refused.covered.contains(&pred.0), "its list was read");
        assert_eq!(rotations.len(), 2);
        for (f, t, record) in rotations {
            let r = Rotation::parse(&record).unwrap();
            assert_eq!(
                (f, t),
                (Fingerprint::of(&r.identity), Fingerprint::of(&r.successor)),
                "a record for the rotation it is passed with"
            );
        }
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

    /// A kept row is believed only as far as its record verifies as the
    /// identity's, at the epoch and time the row says: a row damaged, or
    /// written with another's record or another epoch or time than its
    /// own, raises no floor and refuses nothing.
    #[test]
    fn a_kept_floor_is_what_verifies_of_it() {
        use hl_identity::IdentityKey;
        let cache = Arc::new(hxd_core::identity_records::MemoryRecordCache::default());
        let (alice, mallory) = (
            IdentityKey::from_seed(&[1; 32]),
            IdentityKey::from_seed(&[2; 32]),
        );
        let fp = Fingerprint::of(&alice.public());
        let record = |id: &IdentityKey, epoch, time| {
            DeviceEpoch {
                identity: id.public(),
                epoch,
                time,
            }
            .sign(id)
            .unwrap()
        };
        let mut damaged = record(&alice, 7, 10);
        *damaged.last_mut().unwrap() ^= 1;
        for (epoch, time, record) in [
            (1, 10, record(&alice, 1, 10)),
            (9, 10, record(&alice, 1, 10)),
            (2, 5, record(&alice, 2, 10)),
            (8, 10, record(&mallory, 8, 10)),
            (7, 10, damaged),
        ] {
            let kept = KeptEpoch {
                epoch,
                time,
                record,
            };
            cache.keep_epoch(&fp.0, &kept).unwrap();
        }
        let r = registrars(cache);
        assert_eq!(r.kept_floor(&fp).unwrap(), 1);
        let found = r.lookup_fp(fp, &[], 0);
        let floors: Vec<u64> = found
            .records
            .iter()
            .filter_map(|r| match r {
                Record::DeviceEpoch(e) => Some(e.epoch),
                _ => None,
            })
            .collect();
        assert_eq!(floors, [1]);
    }

    /// A row that does not verify gives way to the next record of its
    /// epoch seen, whatever its time, rather than shadowing the epoch.
    #[test]
    fn a_damaged_row_is_replaced_by_a_record_of_its_epoch() {
        use hl_identity::IdentityKey;
        let cache = hxd_core::identity_records::MemoryRecordCache::default();
        let alice = IdentityKey::from_seed(&[1; 32]);
        let fp = Fingerprint::of(&alice.public());
        let damaged = KeptEpoch {
            epoch: 1,
            time: 5,
            record: vec![0; 8],
        };
        cache.keep_epoch(&fp.0, &damaged).unwrap();
        let e = DeviceEpoch {
            identity: alice.public(),
            epoch: 1,
            time: 10,
        };
        let bytes = e.sign(&alice).unwrap();
        keep_epochs(&cache, fp, &[(e, bytes)]).unwrap();
        assert_eq!(kept_floor(&cache, &fp).unwrap(), 1);
    }
}
