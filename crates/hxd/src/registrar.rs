//! Wiring the registrar into the server (`docs/identity-registrar.md`
//! §11), and the operator's commands for it.
//!
//! The registrar keeps its store in SQLite, so it rides the `inbox`
//! Cargo feature that carries the SQLite stores: a build without it
//! refuses a `[registrar]` section at startup rather than ignoring it.
//!
//! Two things come from outside the section. The names it reserves
//! include every account login on this server and the system account's
//! — `new_accounts = create` names accounts after handles, so a handle
//! issued as an existing login would be an account taken over by name —
//! and both are re-read on SIGHUP, with the invites file. The clock-skew
//! tolerance is `[identity]`'s, since the registrar is an
//! identity-enabled server and there is one clock.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hxd_registrar::{Rates, Registrar, Signup};
use serde::Deserialize;

use crate::Config;

/// `[registrar]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrarSection {
    /// The name attestations carry (§3): the hostname this server's
    /// discovery document is fetched from, lowercase, with no port.
    pub host: String,
    /// The registrar's signing seed, apart from the server key (§3).
    /// Generated on first start, owner-only.
    #[serde(default = "default_key")]
    pub key: PathBuf,
    /// Keys still valid for verification after a rotation (§4.1).
    #[serde(default)]
    pub retiring: Vec<RetiringKey>,
    #[serde(default = "default_store")]
    pub store: PathBuf,
    /// `open`, `proof` or `closed` (§5.3). `proof` by default, which is
    /// the one that does not make a fresh install a sybil factory.
    #[serde(default = "default_signup")]
    pub signup: String,
    /// What `signup = proof` asks for: `invite`, or `none` with
    /// `signup = open`. Absent means whichever of the two `signup` needs.
    pub proof: Option<String>,
    /// Where someone without an invite can ask for one; returned with
    /// `proof_required`.
    pub proof_url: Option<String>,
    /// Invite codes, one per line, imported at start and on SIGHUP; a
    /// code is spent in the store, not by editing this file.
    #[serde(default = "default_invites")]
    pub invites: PathBuf,
    /// Written into every attestation (§5.3). Defaults to what `proof`
    /// supports, and may not exceed it.
    pub level: Option<u64>,
    #[serde(default = "default_days")]
    pub attestation_days: u64,
    #[serde(default = "default_days")]
    pub hold_days: u64,
    #[serde(default = "default_handle_min")]
    pub handle_min: usize,
    #[serde(default = "default_handle_max")]
    pub handle_max: usize,
    /// Local parts reserved beside the built-in list and the server's
    /// account logins.
    #[serde(default)]
    pub reserved: Vec<String>,
    /// Seconds a posted rotation waits before it is published, so a
    /// freeze can meet one signed by a thief (§5.4). The spec's default
    /// applies a day only where the registrar holds a contact to warn,
    /// and this one holds none, so it is 0 unless set.
    #[serde(default)]
    pub rotation_delay: u64,
    #[serde(default = "default_records_max_age")]
    pub records_max_age: u64,
    /// Key backup (§9). Not built: `true` is refused rather than
    /// promised.
    #[serde(default)]
    pub envelopes: bool,
    #[serde(default)]
    pub rate: RateSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiringKey {
    /// Base64url, 32 bytes.
    pub key: String,
    /// Unix seconds.
    pub until: u64,
}

/// `[registrar.rate]`: §10's ceilings, one key per row.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateSection {
    #[serde(default = "default_per_address")]
    pub registrations_per_address: u32,
    #[serde(default = "default_per_hour")]
    pub registrations_per_hour: u32,
    #[serde(default = "default_records_per_identity")]
    pub records_per_identity: u32,
    #[serde(default = "default_lookups")]
    pub lookups_per_minute: u32,
    #[serde(default = "default_devices_kept")]
    pub device_revocations_kept: usize,
}

impl Default for RateSection {
    fn default() -> Self {
        let r = Rates::default();
        RateSection {
            registrations_per_address: r.registrations_per_address,
            registrations_per_hour: r.registrations_total,
            records_per_identity: r.records_per_identity,
            lookups_per_minute: r.lookups_per_address,
            device_revocations_kept: r.device_revocations_kept,
        }
    }
}

fn default_key() -> PathBuf {
    "registrar.key".into()
}
fn default_store() -> PathBuf {
    "registrar.db".into()
}
fn default_signup() -> String {
    "proof".into()
}
fn default_invites() -> PathBuf {
    "registrar-invites".into()
}
fn default_days() -> u64 {
    365
}
fn default_handle_min() -> usize {
    3
}
fn default_handle_max() -> usize {
    32
}
fn default_records_max_age() -> u64 {
    3600
}
fn default_per_address() -> u32 {
    Rates::default().registrations_per_address
}
fn default_per_hour() -> u32 {
    Rates::default().registrations_total
}
fn default_records_per_identity() -> u32 {
    Rates::default().records_per_identity
}
fn default_lookups() -> u32 {
    Rates::default().lookups_per_address
}
fn default_devices_kept() -> usize {
    Rates::default().device_revocations_kept
}

/// The largest handle an attestation can carry (identity spec §3.5).
const HANDLE_MAX_BYTES: usize = 64;

impl RegistrarSection {
    /// Everything but the reserved names, checked: the combinations a
    /// `Deserialize` cannot rule out, each with the sentence an operator
    /// needs.
    pub fn settings(&self, clock_skew: u64) -> Result<hxd_registrar::Config, String> {
        let host = &self.host;
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        {
            return Err(format!(
                "[registrar] host {host:?} must be a lowercase hostname with no port: \
                 it is the name attestations carry, and the name verifiers fetch \
                 https://<host>/.well-known/hotline from"
            ));
        }
        let signup = match self.signup.as_str() {
            "open" => Signup::Open,
            "proof" => Signup::Invite,
            "closed" => Signup::Closed,
            other => {
                return Err(format!(
                    "[registrar] signup: {other:?} is not open, proof or closed"
                ))
            }
        };
        let proof = self.proof.clone().unwrap_or_else(|| {
            if signup == Signup::Open {
                "none"
            } else {
                "invite"
            }
            .to_string()
        });
        let max_level = match (proof.as_str(), signup) {
            ("none", Signup::Invite) => {
                return Err(
                    "[registrar] signup = proof needs a proof; this build checks invite".into(),
                )
            }
            ("invite", Signup::Open) => {
                return Err(
                    "[registrar] signup = open takes proof = none; to require invites, \
                            set signup = proof"
                        .into(),
                )
            }
            ("none", _) => 0,
            ("invite", _) => 2,
            ("email" | "oidc" | "vouch", _) => {
                return Err(format!(
                    "[registrar] proof = {proof}: this build checks invites only"
                ))
            }
            (other, _) => {
                return Err(format!(
                    "[registrar] proof: {other:?} is not invite or none"
                ))
            }
        };
        let level = self.level.unwrap_or(max_level);
        if level > max_level {
            return Err(format!(
                "[registrar] level {level} claims more than proof = {proof} establishes \
                 (at most {max_level}; identity-registrar.md §5.3)"
            ));
        }
        if self.handle_min == 0
            || self.handle_max > HANDLE_MAX_BYTES
            || self.handle_min > self.handle_max
        {
            return Err(format!(
                "[registrar] handle_min and handle_max must satisfy 1 ≤ min ≤ max ≤ {HANDLE_MAX_BYTES}"
            ));
        }
        if self.attestation_days == 0 {
            return Err("[registrar] attestation_days must be at least 1".into());
        }
        if self.records_max_age == 0 {
            return Err("[registrar] records_max_age must be at least 1".into());
        }
        if self.envelopes {
            return Err(
                "[registrar] envelopes: key backup (identity-registrar.md §9) is not built".into(),
            );
        }
        let retiring = self
            .retiring
            .iter()
            .map(|r| {
                crate::decode_key(&r.key)
                    .map(|k| (k, r.until))
                    .map_err(|e| format!("[registrar] retiring key: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rate = &self.rate;
        if rate.registrations_per_address == 0
            || rate.registrations_per_hour == 0
            || rate.records_per_identity == 0
            || rate.lookups_per_minute == 0
            || rate.device_revocations_kept == 0
        {
            return Err(
                "[registrar.rate] every ceiling must be at least 1; use signup = closed \
                        to stop registrations"
                    .into(),
            );
        }
        Ok(hxd_registrar::Config {
            host: host.clone(),
            signup,
            proof_url: self.proof_url.clone(),
            level,
            attestation_days: self.attestation_days,
            hold_days: self.hold_days,
            handle_min: self.handle_min,
            handle_max: self.handle_max,
            reserved: HashSet::new(),
            rotation_delay: self.rotation_delay,
            records_max_age: self.records_max_age,
            retiring,
            clock_skew,
            rates: Rates {
                registrations_per_address: rate.registrations_per_address,
                registrations_total: rate.registrations_per_hour,
                records_per_identity: rate.records_per_identity,
                lookups_per_address: rate.lookups_per_minute,
                device_revocations_kept: rate.device_revocations_kept,
            },
        })
    }
}

/// Config-level checks for `check_config`.
pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = &config.registrar else {
        return Ok(());
    };
    let Some(identity) = &config.identity else {
        return Err(
            "[registrar] needs [identity]: a registrar is an identity-enabled server, \
                    and serves its cards and discovery through it"
                .into(),
        );
    };
    section.settings(identity.clock_skew).map(|_| ())
}

/// Every name the registrar reserves (§5.2, §11): the built-in list,
/// the section's additions, the system account's login, and every
/// account login on this server.
pub fn reserved(config: &Config, section: &RegistrarSection) -> HashSet<String> {
    let mut names: HashSet<String> = hxd_registrar::Config::BUILT_IN_RESERVED
        .iter()
        .map(|s| s.to_string())
        .collect();
    names.extend(
        section
            .reserved
            .iter()
            .map(|s| s.trim().to_ascii_lowercase()),
    );
    if let Some(system) = &config.system {
        names.insert(system.login.to_ascii_lowercase());
    }
    names.extend(hxd_auth_file::FileAuth::new(&config.paths.accounts).logins());
    names
}

/// The codes in the invites file: one per line, blank lines and `#`
/// comments skipped. A missing file is no codes.
#[cfg_attr(not(feature = "inbox"), allow(dead_code))]
fn read_invites(path: &Path) -> Result<Vec<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub use imp::{build, freeze, invites_add, open, recover, reload, revoke};

#[cfg(feature = "inbox")]
mod imp {
    use super::*;

    use hxd_store_sqlite::{SqliteRegistrarStore, Synchronous};

    fn store(section: &RegistrarSection) -> Result<Arc<SqliteRegistrarStore>, String> {
        SqliteRegistrarStore::open(&section.store, Synchronous::Full)
            .map(Arc::new)
            .map_err(|e| format!("{}: {e}", section.store.display()))
    }

    fn assemble(config: &Config, key: hl_identity::ServerKey) -> Result<Option<Registrar>, String> {
        let Some(section) = &config.registrar else {
            return Ok(None);
        };
        let skew = config.identity.as_ref().map_or(300, |i| i.clock_skew);
        let mut settings = section.settings(skew)?;
        settings.reserved = reserved(config, section);
        let registrar = Registrar::new(settings, key, store(section)?);
        let codes = read_invites(&section.invites)?;
        let added = registrar
            .add_invites(&codes)
            .map_err(|e| format!("[registrar] importing invites: {e}"))?;
        if added > 0 {
            tracing::info!(
                added,
                "registrar: invites imported from {}",
                section.invites.display()
            );
        }
        Ok(Some(registrar))
    }

    /// The registrar the server runs, creating its key on a first start.
    pub fn build(config: &Config) -> Result<Option<Arc<Registrar>>, String> {
        let Some(section) = &config.registrar else {
            return Ok(None);
        };
        let key = crate::load_key(&section.key, "registrar")?;
        let reg = assemble(config, key)?.map(Arc::new);
        if let Some(reg) = &reg {
            tracing::info!(
                host = %reg.config().host,
                key = %hl_identity::Fingerprint::of(&reg.public_key()).short(),
                "registrar enabled"
            );
        }
        Ok(reg)
    }

    /// The registrar an operator command acts through: the same store
    /// and key as the running server, never a new key. A command run
    /// from the wrong directory would otherwise mint a registrar nobody
    /// trusts and sign with it.
    pub fn open(config: &Config) -> Result<Registrar, String> {
        let section = config
            .registrar
            .as_ref()
            .ok_or("[registrar] is not configured")?;
        let key = crate::read_key(&section.key)
            .map_err(|e| format!("{e}; start the server once to create the registrar key"))?;
        Ok(assemble(config, key)?.expect("the section is there"))
    }

    /// What SIGHUP re-reads: the reserved names (account logins come and
    /// go) and the invites file.
    pub fn reload(reg: &Registrar, path: &Path) -> Result<(usize, usize), String> {
        let config = Config::load(path)?;
        let section = config
            .registrar
            .as_ref()
            .ok_or("[registrar] is gone from the file; it stays on until a restart")?;
        let names = reserved(&config, section);
        let n = names.len();
        reg.set_reserved(names);
        let added = reg
            .add_invites(&read_invites(&section.invites)?)
            .map_err(|e| e.to_string())?;
        Ok((n, added))
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn fingerprint(text: &str) -> Result<[u8; 32], String> {
        crate::parse_fingerprint(text).map_err(|_| {
            format!("{text:?} is not a fingerprint: the 52-character form, or 64 hex characters")
        })
    }

    /// `hxd registrar freeze <fingerprint> [--lift]` (§8.1).
    pub fn freeze(config: &Config, fp: &str, lift: bool) -> Result<u64, String> {
        let reg = open(config)?;
        reg.freeze(&fingerprint(fp)?, !lift, now())
            .map_err(|e| e.to_string())
    }

    /// `hxd registrar revoke <handle> --reason …` (§4.8). `abuse` also
    /// bars the holder from reissuing it for the hold.
    pub fn revoke(config: &Config, handle: &str, reason: &str) -> Result<u64, String> {
        use hl_identity::registrar::attestation_reason as r;
        let (code, bar) = match reason {
            "abuse" => (r::ABUSE, true),
            "lapsed" => (r::LAPSED, false),
            "unspecified" => (r::UNSPECIFIED, false),
            other => {
                return Err(format!(
                    "--reason {other:?}: abuse, lapsed or unspecified (recovery and \
                     rotation revoke by themselves)"
                ))
            }
        };
        open(config)?
            .revoke_handle(handle, code, bar, now())
            .map_err(|e| e.to_string())
    }

    /// `hxd registrar recover <handle> --identity <fp> [--keep-age]`
    /// (§8.3).
    pub fn recover(config: &Config, handle: &str, fp: &str, keep_age: bool) -> Result<u64, String> {
        open(config)?
            .recover(handle, &fingerprint(fp)?, keep_age, now())
            .map_err(|e| e.to_string())
    }

    /// `hxd registrar invites --add N`: new codes, appended to the
    /// invites file and added to the store, so a running server honors
    /// them without a reload.
    pub fn invites_add(config: &Config, n: usize) -> Result<Vec<String>, String> {
        let reg = open(config)?;
        let section = config.registrar.as_ref().expect("open checked");
        let codes: Vec<String> = (0..n).map(|_| hxd_registrar::new_invite_code()).collect();
        append_private(&section.invites, &codes)
            .map_err(|e| format!("{}: {e}", section.invites.display()))?;
        reg.add_invites(&codes).map_err(|e| e.to_string())?;
        Ok(codes)
    }
}

#[cfg(not(feature = "inbox"))]
mod imp {
    use super::*;

    const NO_STORE: &str =
        "[registrar] is configured, but this build has no SQLite store (built without the \
         `inbox` feature)";

    pub fn build(config: &Config) -> Result<Option<Arc<Registrar>>, String> {
        match config.registrar {
            Some(_) => Err(NO_STORE.into()),
            None => Ok(None),
        }
    }
    pub fn open(_: &Config) -> Result<Registrar, String> {
        Err(NO_STORE.into())
    }
    pub fn reload(_: &Registrar, _: &Path) -> Result<(usize, usize), String> {
        Err(NO_STORE.into())
    }
    pub fn freeze(_: &Config, _: &str, _: bool) -> Result<u64, String> {
        Err(NO_STORE.into())
    }
    pub fn revoke(_: &Config, _: &str, _: &str) -> Result<u64, String> {
        Err(NO_STORE.into())
    }
    pub fn recover(_: &Config, _: &str, _: &str, _: bool) -> Result<u64, String> {
        Err(NO_STORE.into())
    }
    pub fn invites_add(_: &Config, _: usize) -> Result<Vec<String>, String> {
        Err(NO_STORE.into())
    }
}

/// Append lines to a file only its owner can read: invite codes are
/// secrets until they are spent.
#[cfg_attr(not(feature = "inbox"), allow(dead_code))]
fn append_private(path: &Path, lines: &[String]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    for line in lines {
        writeln!(f, "{line}")?;
    }
    Ok(())
}

// --- `hxd registrar inspect` (§6.6) ---------------------------------------

/// Fetch a registrar's discovery, log and stats, verify all of it, and
/// describe the last month. `target` is a host, fetched over HTTPS as a
/// verifier would, or a full base URL for a test rig.
pub fn inspect(target: &str) -> Result<String, String> {
    use hl_identity::{Attestation, ListKind, RegistrarKeys, SignedList, Stats};
    use std::fmt::Write as _;

    let base = if target.contains("://") {
        target.trim_end_matches('/').to_string()
    } else {
        format!("https://{target}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build();
    let get = |path: &str| -> Result<Vec<u8>, String> {
        let url = format!("{base}{path}");
        let resp = agent.get(&url).call().map_err(|e| format!("{url}: {e}"))?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(resp.into_reader(), 2 * 1024 * 1024),
            &mut body,
        )
        .map_err(|e| format!("{url}: {e}"))?;
        Ok(body)
    };

    let doc: serde_json::Value = serde_json::from_slice(&get("/.well-known/hotline")?)
        .map_err(|e| format!("discovery is not JSON: {e}"))?;
    let block = doc
        .get("registrar")
        .filter(|b| !b.is_null())
        .ok_or("that server's discovery has no registrar block")?;
    let host = block["host"]
        .as_str()
        .ok_or("registrar block has no host")?;
    let mut keys = vec![crate::decode_key(
        block["key"].as_str().ok_or("registrar block has no key")?,
    )?];
    if let Some(retiring) = block["retiring"].as_array() {
        for r in retiring {
            if let Some(k) = r["key"].as_str() {
                keys.push(crate::decode_key(k)?);
            }
        }
    }
    let endpoint = |name: &str, default: &str| {
        block["endpoints"][name]
            .as_str()
            .unwrap_or(default)
            .to_string()
    };
    let rk = RegistrarKeys { host, keys: &keys };

    let stats = Stats::parse(&get(&endpoint("stats", "/registrar/stats"))?, rk)
        .map_err(|e| format!("stats did not verify: {e}"))?;

    let log_path = endpoint("log", "/registrar/log");
    let mut since = 0u64;
    let mut entries: Vec<(u64, Result<Attestation, String>)> = Vec::new();
    for _ in 0..10_000 {
        let page = SignedList::parse(
            &get(&format!("{log_path}?since={since}"))?,
            ListKind::Log,
            rk,
        )
        .map_err(|e| format!("a log page did not verify: {e}"))?;
        for (seq, bytes) in &page.entries {
            let checked = Attestation::parse(bytes)
                .map_err(|e| e.to_string())
                .and_then(|a| {
                    if a.registrar != host {
                        Err(format!("names registrar {}", a.registrar))
                    } else if !keys.contains(&a.registrar_key) {
                        Err("signed by a key the registrar does not publish".to_string())
                    } else {
                        Ok(a)
                    }
                });
            entries.push((*seq, checked));
            since = *seq;
        }
        if !page.more {
            break;
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = String::new();
    let _ = writeln!(out, "registrar {host}");
    let _ = writeln!(
        out,
        "  key         {} ({} retiring)",
        hl_identity::Fingerprint::of(&keys[0]),
        keys.len() - 1
    );
    let _ = writeln!(
        out,
        "  signup      {}{}, level {}, attestations for {} days",
        block["signup"].as_str().unwrap_or("?"),
        block["proof"]
            .as_str()
            .map(|p| format!(" ({p})"))
            .unwrap_or_default(),
        block["level"],
        block["attestation_days"]
    );
    let _ = writeln!(
        out,
        "  stats       {} identities hold a name; first registrations: {} in 24h, {} in 7d, \
         {} in all; {} attestations revoked; {} frozen",
        stats.identities,
        stats.issued_24h,
        stats.issued_7d,
        stats.issued_total,
        stats.revoked_total,
        stats.frozen
    );
    let last = entries.last().map_or(0, |(seq, _)| *seq);
    let _ = writeln!(
        out,
        "  log         {} entries, last seq {last} — {}",
        entries.len(),
        // Stats are cached; the log is live. A log ahead of the stats is
        // just the cache's age — only stats ahead of the log disagree.
        if stats.log_seq <= last {
            "agrees with the stats".to_string()
        } else {
            format!("the stats say {}; they disagree", stats.log_seq)
        }
    );
    let bad: Vec<_> = entries
        .iter()
        .filter_map(|(seq, r)| r.as_ref().err().map(|e| (seq, e)))
        .collect();
    for (seq, e) in &bad {
        let _ = writeln!(out, "  !! log entry {seq} does not verify: {e}");
    }
    // The shape of the last month, a week at a time. A first
    // registration is an attestation issued at its own `registered`.
    let _ = writeln!(out, "  last 30 days, newest first:");
    for week in 0..5u64 {
        let (from, to) = (week * 7, (week * 7 + 7).min(30));
        if from >= 30 {
            break;
        }
        let (mut new, mut reissued) = (0, 0);
        for a in entries.iter().filter_map(|(_, r)| r.as_ref().ok()) {
            let age = now.saturating_sub(a.issued) / 86_400;
            if age >= from && age < to {
                if a.registered == a.issued {
                    new += 1;
                } else {
                    reissued += 1;
                }
            }
        }
        let _ = writeln!(
            out,
            "    {from:>2}–{:<2} days ago  {new} new, {reissued} reissued",
            to - 1
        );
    }
    if !bad.is_empty() {
        return Err(format!("{out}{} log entries did not verify", bad.len()));
    }
    Ok(out)
}
