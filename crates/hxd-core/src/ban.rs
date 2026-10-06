//! Bans (`docs/moderation.md` §3.5): who the server refuses, why, until
//! when, and on whose word.
//!
//! **A ban is a moderation act, not a revocation.** A revocation
//! (`crate::revoked`) says a key was stolen and its owner is the victim;
//! a ban says a person misbehaved and refuses them by what the server
//! can tie to them: an address or a block of them, a login, an identity,
//! or every identity a registrar issued. The two stay apart.
//!
//! A registrar is matched by the handle a login proves: an identity's
//! card, on a socket that authenticated with its key. An account keeps
//! only its linked identity's fingerprint, not the handle, so a password
//! login to that account is refused by an identity ban, which follows
//! the fingerprint, and not by a registrar ban.
//!
//! **The store is the record; matching is in memory.** Every standing
//! ban is held in a [`BanMatcher`], loaded when the store is given to the
//! domain and kept current as bans are placed and lifted, so the accept
//! path never waits on a disk. A ban's expiry is checked when it is
//! matched, so nothing has to sweep for it to stop applying.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::time::SystemTime;

pub type BanId = u64;

/// What a ban refuses, each in its canonical form: equal targets are
/// equal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BanTarget {
    /// An address block, as IPv6 with IPv4 mapped (`::ffff:a.b.c.d`) and
    /// the prefix counted over that form, so an IPv4 /24 is a /120. The
    /// bits past the prefix are zero.
    Address { net: [u8; 16], prefix: u8 },
    /// A login as the auth backend canonicalizes it.
    Login(String),
    /// An identity fingerprint: every device of it, on any account.
    Identity([u8; 32]),
    /// A registrar's host, lowercase: every identity whose handle it
    /// issued (`name@host`).
    Registrar(String),
}

impl BanTarget {
    /// `ip` and the prefix in its own family's terms (32 for one IPv4
    /// address, 64 for an IPv6 /64).
    pub fn address(ip: IpAddr, prefix: u8) -> Result<Self, String> {
        let (v6, prefix) = match ip.to_canonical() {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(format!("an IPv4 prefix is at most 32, not {prefix}"));
                }
                (v4.to_ipv6_mapped(), prefix + 96)
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(format!("an IPv6 prefix is at most 128, not {prefix}"));
                }
                (v6, prefix)
            }
        };
        Ok(BanTarget::Address {
            net: mask(v6.octets(), prefix),
            prefix,
        })
    }

    pub fn login(login: &str) -> Result<Self, String> {
        let login = login.trim().to_lowercase();
        if login.is_empty() {
            return Err("a login ban needs a login".into());
        }
        Ok(BanTarget::Login(login))
    }

    pub fn registrar(host: &str) -> Result<Self, String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || !host.is_ascii() || host.contains(['@', '/', ' ']) {
            return Err(format!("{host:?} is not a registrar host"));
        }
        Ok(BanTarget::Registrar(host))
    }

    /// Parse what an operator types: `192.0.2.7`, `10.0.0.0/8`,
    /// `2001:db8::/48`, `login:alice`, `identity:<fingerprint>`,
    /// `*@host` or `registrar:host`. An address without a prefix is that
    /// one address. `fingerprint` reads the identity's printed form.
    pub fn parse(s: &str, fingerprint: impl Fn(&str) -> Option<[u8; 32]>) -> Result<Self, String> {
        let s = s.trim();
        if let Some(login) = s.strip_prefix("login:") {
            return BanTarget::login(login);
        }
        if let Some(fp) = s.strip_prefix("identity:") {
            return fingerprint(fp.trim())
                .map(BanTarget::Identity)
                .ok_or_else(|| format!("{fp:?} is not an identity fingerprint"));
        }
        if let Some(host) = s
            .strip_prefix("registrar:")
            .or_else(|| s.strip_prefix("*@"))
        {
            return BanTarget::registrar(host);
        }
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = addr.parse().map_err(|_| {
            format!(
                "{s:?} is not an address, a block, login:NAME, identity:FINGERPRINT \
                 or *@REGISTRAR"
            )
        })?;
        let full = if ip.to_canonical().is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => full,
            Some(p) => p
                .parse()
                .map_err(|_| format!("{s:?} has a bad prefix length"))?,
        };
        BanTarget::address(ip, prefix)
    }

    pub fn kind_i64(&self) -> i64 {
        match self {
            BanTarget::Address { .. } => 1,
            BanTarget::Login(_) => 2,
            BanTarget::Identity(_) => 3,
            BanTarget::Registrar(_) => 4,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            BanTarget::Address { .. } => "address",
            BanTarget::Login(_) => "login",
            BanTarget::Identity(_) => "identity",
            BanTarget::Registrar(_) => "registrar",
        }
    }

    /// The stored bytes and the address prefix: the store's `target`
    /// and `prefix_len` columns.
    pub fn to_row(&self) -> (Vec<u8>, Option<u8>) {
        match self {
            BanTarget::Address { net, prefix } => (net.to_vec(), Some(*prefix)),
            BanTarget::Login(l) => (l.as_bytes().to_vec(), None),
            BanTarget::Identity(fp) => (fp.to_vec(), None),
            BanTarget::Registrar(h) => (h.as_bytes().to_vec(), None),
        }
    }

    pub fn from_row(kind: i64, target: &[u8], prefix: Option<u8>) -> Option<Self> {
        Some(match (kind, prefix) {
            (1, Some(prefix)) => BanTarget::Address {
                net: target.try_into().ok()?,
                prefix,
            },
            (2, None) => BanTarget::Login(String::from_utf8(target.to_vec()).ok()?),
            (3, None) => BanTarget::Identity(target.try_into().ok()?),
            (4, None) => BanTarget::Registrar(String::from_utf8(target.to_vec()).ok()?),
            _ => return None,
        })
    }

    /// How a moderator reads it: `192.0.2.0/24`, `2001:db8::/64`,
    /// `login alice`. An identity's fingerprint is left to the caller,
    /// which knows its printed form.
    pub fn describe(&self, fingerprint: impl Fn(&[u8; 32]) -> String) -> String {
        match self {
            BanTarget::Address { net, prefix } => {
                let v6 = Ipv6Addr::from(*net);
                match v6.to_ipv4_mapped() {
                    Some(v4) if *prefix >= 96 => {
                        if *prefix == 128 {
                            v4.to_string()
                        } else {
                            format!("{v4}/{}", prefix - 96)
                        }
                    }
                    _ if *prefix == 128 => v6.to_string(),
                    _ => format!("{v6}/{prefix}"),
                }
            }
            BanTarget::Login(l) => format!("login {l}"),
            BanTarget::Identity(fp) => format!("identity {}", fingerprint(fp)),
            BanTarget::Registrar(h) => format!("*@{h}"),
        }
    }
}

fn mask(mut octets: [u8; 16], prefix: u8) -> [u8; 16] {
    let prefix = usize::from(prefix.min(128));
    for (i, byte) in octets.iter_mut().enumerate() {
        let bits_before = i * 8;
        if bits_before >= prefix {
            *byte = 0;
        } else if prefix - bits_before < 8 {
            *byte &= 0xff << (8 - (prefix - bits_before));
        }
    }
    octets
}

fn v6_octets(ip: IpAddr) -> [u8; 16] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Where a ban came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanSource {
    /// A kick with a ban.
    Kick,
    /// A moderator's `ban_add`.
    Moderator,
    /// `hxd ban add`.
    Cli,
    /// `[moderation] banned` in the config.
    Config,
}

impl BanSource {
    pub fn as_i64(self) -> i64 {
        match self {
            BanSource::Kick => 1,
            BanSource::Moderator => 2,
            BanSource::Cli => 3,
            BanSource::Config => 4,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        Some(match n {
            1 => BanSource::Kick,
            2 => BanSource::Moderator,
            3 => BanSource::Cli,
            4 => BanSource::Config,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            BanSource::Kick => "kick",
            BanSource::Moderator => "moderator",
            BanSource::Cli => "cli",
            BanSource::Config => "config",
        }
    }
}

/// One ban, standing or not. `id` is 0 until the store records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub id: BanId,
    pub target: BanTarget,
    /// Shown to the banned client where its wire can show it.
    pub reason: String,
    /// For moderators only.
    pub note: Option<String>,
    /// The login that placed it, or `crate::moderation::OPERATOR`.
    pub actor: String,
    pub actor_fp: Option<[u8; 32]>,
    pub source: BanSource,
    pub created_at: SystemTime,
    /// `None` is until lifted.
    pub expires_at: Option<SystemTime>,
    pub lifted_at: Option<SystemTime>,
    pub lifted_by: Option<String>,
    /// The audit row that placed it.
    pub act: Option<crate::moderation::ActId>,
}

impl Ban {
    /// Is it refusing anyone at `now`?
    pub fn standing(&self, now: SystemTime) -> bool {
        self.lifted_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }
}

/// What a refused client is told, and what a frontend logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanHit {
    pub id: BanId,
    pub reason: String,
    pub expires_at: Option<SystemTime>,
}

/// Every standing ban, arranged for matching without the store.
#[derive(Debug, Default)]
pub(crate) struct BanMatcher {
    /// Address blocks by prefix length, so a match is a probe per length
    /// in use: a handful, at most 129.
    addrs: BTreeMap<u8, HashMap<[u8; 16], BanHit>>,
    logins: HashMap<String, BanHit>,
    identities: HashMap<[u8; 32], BanHit>,
    registrars: HashMap<String, BanHit>,
    /// Where each ban is filed, for lifting it.
    by_id: HashMap<BanId, BanTarget>,
}

impl BanMatcher {
    pub(crate) fn load(bans: impl IntoIterator<Item = Ban>) -> Self {
        let mut m = BanMatcher::default();
        for ban in bans {
            m.insert(&ban);
        }
        m
    }

    /// File a standing ban, replacing whatever was filed under its id or
    /// its target: a target holds one ban, and the id it is filed under
    /// is the one that names it.
    pub(crate) fn insert(&mut self, ban: &Ban) {
        self.remove(ban.id);
        let hit = BanHit {
            id: ban.id,
            reason: ban.reason.clone(),
            expires_at: ban.expires_at,
        };
        let displaced = match &ban.target {
            BanTarget::Address { net, prefix } => {
                self.addrs.entry(*prefix).or_default().insert(*net, hit)
            }
            BanTarget::Login(l) => self.logins.insert(l.clone(), hit),
            BanTarget::Identity(fp) => self.identities.insert(*fp, hit),
            BanTarget::Registrar(h) => self.registrars.insert(h.clone(), hit),
        };
        if let Some(old) = displaced {
            self.by_id.remove(&old.id);
        }
        self.by_id.insert(ban.id, ban.target.clone());
    }

    /// Unfile the ban `id`. Only its own entry goes: a target since
    /// filed under another id keeps that one.
    pub(crate) fn remove(&mut self, id: BanId) {
        let Some(target) = self.by_id.remove(&id) else {
            return;
        };
        fn take<K: std::hash::Hash + Eq>(set: &mut HashMap<K, BanHit>, key: &K, id: BanId) {
            if set.get(key).is_some_and(|hit| hit.id == id) {
                set.remove(key);
            }
        }
        match target {
            BanTarget::Address { net, prefix } => {
                if let Some(set) = self.addrs.get_mut(&prefix) {
                    take(set, &net, id);
                    if set.is_empty() {
                        self.addrs.remove(&prefix);
                    }
                }
            }
            BanTarget::Login(l) => take(&mut self.logins, &l, id),
            BanTarget::Identity(fp) => take(&mut self.identities, &fp, id),
            BanTarget::Registrar(h) => take(&mut self.registrars, &h, id),
        }
    }

    /// Is the ban `id` filed?
    pub(crate) fn contains(&self, id: BanId) -> bool {
        self.by_id.contains_key(&id)
    }

    /// The ban refusing `ip` at `now`, if any.
    pub(crate) fn address(&self, ip: IpAddr, now: SystemTime) -> Option<BanHit> {
        let octets = v6_octets(ip);
        // Each family matches only its own bans. An IPv4 peer is looked
        // up in its mapped form, whose top 80 bits are zero, so masked
        // to an IPv6 block shorter than /96 it is `::` and would be
        // found in `::/64` (a kick-ban of an IPv6 loopback peer) or an
        // operator's `::/32`: every IPv4 client banned by one IPv6 ban.
        // Every IPv4 ban is a /96 or longer inside `::ffff:0:0/96`, so
        // skipping the shorter lengths is the whole rule; an IPv6 peer
        // is never in that block, so an IPv4 ban cannot mask to it.
        let v4 = ip.to_canonical().is_ipv4();
        let shortest = if v4 { 96 } else { 0 };
        self.addrs.range(shortest..).find_map(|(prefix, set)| {
            set.get(&mask(octets, *prefix))
                .filter(|hit| live(hit, now))
                .cloned()
        })
    }

    /// The ban refusing a person known by these, if any: the login, the
    /// identity, and the registrar that issued its handle.
    pub(crate) fn person(
        &self,
        login: Option<&str>,
        identity: Option<&[u8; 32]>,
        handle: Option<&str>,
        now: SystemTime,
    ) -> Option<BanHit> {
        let by_login = login.and_then(|l| self.logins.get(&l.to_lowercase()));
        let by_identity = identity.and_then(|fp| self.identities.get(fp));
        let by_registrar = handle
            .and_then(|h| h.rsplit_once('@'))
            .and_then(|(_, host)| self.registrars.get(&host.to_ascii_lowercase()));
        [by_login, by_identity, by_registrar]
            .into_iter()
            .flatten()
            .find(|hit| live(hit, now))
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

fn live(hit: &BanHit, now: SystemTime) -> bool {
    hit.expires_at.is_none_or(|e| e > now)
}

/// A ban about to be placed: everything but who and when.
#[derive(Debug, Clone)]
pub struct NewBan {
    pub target: BanTarget,
    pub reason: String,
    pub note: Option<String>,
    pub expires_at: Option<SystemTime>,
    pub source: BanSource,
}

impl crate::Core {
    /// The ban refusing connections from `ip`, if any.
    pub fn address_banned(&self, ip: IpAddr) -> Option<BanHit> {
        self.bans.read().unwrap().address(ip, SystemTime::now())
    }

    /// The ban refusing a person who logs in as `login`, with the
    /// identity `identity` whose handle is `handle`, if any.
    pub fn person_banned(
        &self,
        login: Option<&str>,
        identity: Option<&[u8; 32]>,
        handle: Option<&str>,
    ) -> Option<BanHit> {
        self.bans
            .read()
            .unwrap()
            .person(login, identity, handle, SystemTime::now())
    }

    /// The ban now refusing session `uid`, by its address or as the
    /// person it is, if any, and that session ended when one does. A
    /// frontend asks after `attach`: a ban placed between its
    /// connection's or its login's check and the attach found no session
    /// to end, and a reread of the bans (`Core::reload_bans`) will not
    /// look for one again.
    pub fn end_if_banned(&self, uid: crate::Uid) -> Option<BanHit> {
        self.end_if_refused(uid, true)
    }

    /// The ban now refusing the person session `uid` is, if any, and
    /// that session ended when one does: asked before a resume, since a
    /// ban placed while the session was away may have spared it
    /// (`Core::end_refused`) or come from the command line, which ends
    /// nothing until a reread. The session's address is not asked: it is
    /// the address it logged in from, and the resume's own connection was
    /// asked of the address it comes from, as a spared session is refused
    /// at its next connection and not for where it used to be.
    pub fn end_if_person_banned(&self, uid: crate::Uid) -> Option<BanHit> {
        self.end_if_refused(uid, false)
    }

    fn end_if_refused(&self, uid: crate::Uid, by_address: bool) -> Option<BanHit> {
        let (serial, addr, login, identity, handle) = {
            let r = self.roster.lock().unwrap();
            let s = r.users.get(&uid)?;
            (
                s.serial,
                s.addr.filter(|_| by_address),
                s.login.clone(),
                s.identity,
                s.info
                    .transport
                    .identity
                    .as_ref()
                    .and_then(|t| t.handle.clone()),
            )
        };
        // The address first, as the connection was asked first. Nobody
        // is spared (`Core::end_refused` spares two): this repeats the
        // checks at the door, and they spare nobody either.
        let hit = addr
            .and_then(|a| self.address_banned(a))
            .or_else(|| self.person_banned(Some(&login), identity.as_ref(), handle.as_deref()))?;
        let mut r = self.roster.lock().unwrap();
        // The uid, if it has since been recycled, is somebody else.
        if r.users.get(&uid).is_some_and(|s| s.serial == serial) {
            r.end_session(uid);
        }
        Some(hit)
    }

    /// Place a ban as `by` (`docs/moderation.md` §3.5). Returns every row
    /// placed: a login ban also bans the identity its account links, in
    /// the same act, so relinking the identity elsewhere does not evade
    /// it. Every session the ban now refuses is ended, detached ones
    /// included — except for a kick's ban, which ends only the session
    /// the kick does.
    pub fn place_ban(
        &self,
        by: crate::moderation::Actor,
        ban: NewBan,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        let acting = self.acting(by)?;
        self.place_ban_as(&acting, ban)
    }

    pub(crate) fn place_ban_as(
        &self,
        acting: &crate::moderation::Acting,
        ban: NewBan,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        self.place_bans_as(acting, ban, Vec::new())
    }

    /// [`Core::place_ban_as`], banning each of `also` beside
    /// `ban.target` in the same act and on the same terms: a kick's ban
    /// on the person and on their address is one ban, and lifting either
    /// row lifts both (`Core::lift_ban`). Any target refused refuses
    /// them all.
    ///
    /// A store that fails partway leaves the rows written before it
    /// standing, and they are what is returned, with the failure in the
    /// log; only a ban of which no row was written is an error. Undoing
    /// the rows already written is not clean: one may have extended a
    /// ban that stood before this act (`ModerationStore::ban`), and the
    /// store keeps no earlier expiry to put back. So what the caller
    /// reports is what stands.
    pub(crate) fn place_bans_as(
        &self,
        acting: &crate::moderation::Acting,
        ban: NewBan,
        also: Vec<BanTarget>,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        self.place_bans_act(acting, ban, also)
            .map(|(_, placed)| placed)
    }

    /// [`Core::place_bans_as`], with the act it recorded: the rows it
    /// created carry it, and a row it only extended keeps its own.
    pub(crate) fn place_bans_act(
        &self,
        acting: &crate::moderation::Acting,
        ban: NewBan,
        also: Vec<BanTarget>,
    ) -> Result<(Option<crate::moderation::ActId>, Vec<Ban>), crate::moderation::ModError> {
        use crate::moderation::{Act, ActKind, ModError};
        if ban.reason.trim().is_empty() {
            return Err(ModError::BadRequest("a ban needs a reason"));
        }
        // Only a session can be the one it bans. The operator acts under
        // a name (`OPERATOR`) that no reserved login is, so an account
        // that happens to share it is banned like any other.
        let own_login = acting.uid.map(|_| acting.name.to_lowercase());
        let own_fp = acting.uid.and(acting.fingerprint);
        let mut targets: Vec<BanTarget> = Vec::with_capacity(2 + also.len());
        for target in std::iter::once(ban.target.clone()).chain(also) {
            let mut twin = None;
            match &target {
                // `guest` is everyone who walks in, and the server account
                // is the server: disabling the one and refusing the other
                // are not bans. Nor is refusing yourself.
                BanTarget::Login(l) => {
                    if l == "guest" || l.is_empty() || self.is_system_login(l) {
                        return Err(ModError::BadRequest(
                            "not that login: disable the account instead",
                        ));
                    }
                    if own_login.as_ref() == Some(l) {
                        return Err(ModError::BadRequest("a moderator does not ban themselves"));
                    }
                    // The account as it stands, whether or not it keeps a
                    // mailbox: an account that takes no mail links a key
                    // all the same.
                    twin = self
                        .directory
                        .as_ref()
                        .and_then(|d| d.account(l))
                        .and_then(|(m, _)| m.fingerprint)
                        .map(BanTarget::Identity);
                }
                BanTarget::Identity(fp) => {
                    if own_fp.as_ref() == Some(fp) {
                        return Err(ModError::BadRequest("a moderator does not ban themselves"));
                    }
                }
                BanTarget::Address { .. } | BanTarget::Registrar(_) => {}
            }
            for t in std::iter::once(target).chain(twin) {
                if !targets.contains(&t) {
                    targets.push(t);
                }
            }
        }
        let now = SystemTime::now();
        let fp_text = |fp: &[u8; 32]| hl_fingerprint(fp);
        let described: Vec<String> = targets.iter().map(|t| t.describe(fp_text)).collect();
        let mut act = Act::new(ActKind::Ban, acting, ban.reason.clone());
        act.evidence = Some(match ban.expires_at {
            Some(until) => format!(
                "{} until {}",
                described.join(", "),
                until
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            ),
            None => format!("{} until lifted", described.join(", ")),
        });
        act.login = targets.iter().find_map(|t| match t {
            BanTarget::Login(l) => Some(l.clone()),
            _ => None,
        });
        act.fingerprint = targets.iter().find_map(|t| match t {
            BanTarget::Identity(fp) => Some(*fp),
            _ => None,
        });
        let act_id = match self.moderation.as_ref() {
            Some(store) => Some(store.record(&act)?),
            None => None,
        };
        let mut placed = Vec::with_capacity(targets.len());
        let wanted = targets.len();
        {
            let _writing = self.ban_writes.lock().unwrap();
            for target in targets {
                let row = Ban {
                    id: 0,
                    target,
                    reason: ban.reason.clone(),
                    note: ban.note.clone(),
                    actor: acting.name.clone(),
                    actor_fp: acting.fingerprint,
                    source: ban.source,
                    created_at: now,
                    expires_at: ban.expires_at,
                    lifted_at: None,
                    lifted_by: None,
                    act: act_id,
                };
                let row = match self.moderation.as_ref().map(|store| store.ban(&row)) {
                    Some(Ok(row)) => row,
                    Some(Err(e)) if placed.is_empty() => return Err(e.into()),
                    Some(Err(e)) => {
                        tracing::warn!(
                            act = act_id,
                            placed = placed.len(),
                            wanted,
                            "ban: the store failed partway, and the rows written stand: {e}"
                        );
                        break;
                    }
                    // With nothing to keep it in, a ban lasts as long as
                    // the process, as every ban did before there was a
                    // store.
                    None => Ban {
                        id: self
                            .ban_ids
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1,
                        ..row
                    },
                };
                self.bans.write().unwrap().insert(&row);
                placed.push(row);
            }
        }
        // A kick's ban ends the one session the kick ends, as the
        // reference server's does: anyone else behind the address is
        // refused at their next connection, not thrown off with the
        // one who was kicked.
        if ban.source != BanSource::Kick {
            for row in &placed {
                self.end_refused(&row.target, acting.uid);
            }
        }
        Ok((act_id, placed))
    }

    /// Lift a ban as `by`, and with it every standing ban placed in the
    /// same act: a login ban's twin on the identity its account links
    /// (`Core::place_ban`), or a kick's ban on a person and on their
    /// address (`Core::kick_ban_targets`), is one ban, and lifting only
    /// the row named would leave that person refused while the lift said
    /// they were not. A row the act only extended, standing before it,
    /// is another act's ban and is left as it now stands. Returns every
    /// row lifted, the one named first. A ban the config places is the
    /// config's to lift (`docs/moderation.md` §3.5): refused here.
    pub fn lift_ban(
        &self,
        by: crate::moderation::Actor,
        id: BanId,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        let acting = self.acting(by)?;
        self.lift_ban_as(&acting, id)
    }

    pub(crate) fn lift_ban_as(
        &self,
        acting: &crate::moderation::Acting,
        id: BanId,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        use crate::moderation::{Act, ActKind, ModError};
        let store = self.moderation.as_ref().ok_or(ModError::Disabled)?;
        let _writing = self.ban_writes.lock().unwrap();
        let Some(ban) = store
            .bans(None, Some(id.saturating_add(1)), 1)?
            .into_iter()
            .find(|b| b.id == id && b.lifted_at.is_none())
        else {
            return Err(ModError::NoSuchBan);
        };
        if ban.source == BanSource::Config {
            return Err(ModError::ConfigBan);
        }
        let now = SystemTime::now();
        // The act's other rows, found before this one is lifted. Only
        // rows the act created carry its number: one it merely extended
        // keeps the act that created it (`extend_ban`), and stands.
        let twins: Vec<BanId> = match ban.act {
            None => Vec::new(),
            Some(act) => store
                .bans(Some(now), None, usize::MAX)?
                .into_iter()
                .filter(|b| b.id != id && b.act == Some(act) && b.source != BanSource::Config)
                .map(|b| b.id)
                .collect(),
        };
        let mut lifted = Vec::with_capacity(1 + twins.len());
        for id in std::iter::once(id).chain(twins) {
            match store.lift_ban(id, &acting.name, now)? {
                Some(row) => lifted.push(row),
                // Only the one named has to be there to lift.
                None if lifted.is_empty() => return Err(ModError::NoSuchBan),
                None => {}
            }
        }
        let ids: Vec<String> = lifted.iter().map(|b| format!("#{}", b.id)).collect();
        let mut act = Act::new(ActKind::Unban, acting, format!("ban {}", ids.join(", ")));
        act.evidence = Some(
            lifted
                .iter()
                .map(|b| b.target.describe(hl_fingerprint))
                .collect::<Vec<_>>()
                .join(", "),
        );
        store.record(&act)?;
        let mut held = self.bans.write().unwrap();
        for row in &lifted {
            held.remove(row.id);
        }
        Ok(lifted)
    }

    /// Bans, newest first, before `before`: standing ones, or all.
    pub fn list_bans(
        &self,
        standing: bool,
        before: Option<BanId>,
        limit: usize,
    ) -> Result<Vec<Ban>, crate::moderation::ModError> {
        let store = self
            .moderation
            .as_ref()
            .ok_or(crate::moderation::ModError::Disabled)?;
        Ok(store.bans(standing.then(SystemTime::now), before, limit)?)
    }

    /// Read the standing bans again from the store: after the command
    /// line has placed or lifted one while the server ran. Only a ban
    /// this server had not filed ends the sessions it refuses: one it
    /// already held has ended whom it was going to, and a session it
    /// spared (`Core::end_refused`) stays spared by a reread.
    pub fn reload_bans(&self) {
        let Some(store) = self.moderation.as_ref() else {
            return;
        };
        let fresh: Vec<BanTarget> = {
            let _writing = self.ban_writes.lock().unwrap();
            let bans = match store.bans(Some(SystemTime::now()), None, usize::MAX) {
                Ok(bans) => bans,
                Err(e) => {
                    tracing::warn!("moderation: the ban list would not reload: {e}");
                    return;
                }
            };
            let matcher = BanMatcher::load(bans);
            let mut held = self.bans.write().unwrap();
            let fresh = matcher
                .by_id
                .iter()
                .filter(|(id, _)| !held.contains(**id))
                .map(|(_, target)| target.clone())
                .collect();
            *held = matcher;
            fresh
        };
        for target in &fresh {
            self.end_refused(target, None);
        }
    }

    /// End every session `target` refuses: sent the kick, and ended
    /// outright if detached, which has no connection to see it.
    ///
    /// Two are spared. The acting session is not ended by its own ban,
    /// though an address ban may cover it: a moderator behind the same
    /// NAT as the one they ban. And a session holding
    /// `cant_be_disconnected` is not, as no kick ends it either. Both are
    /// refused at their next connection like anyone else.
    fn end_refused(&self, target: &BanTarget, spare: Option<crate::Uid>) {
        let matcher = BanMatcher::load([Ban {
            id: 0,
            target: target.clone(),
            reason: String::new(),
            note: None,
            actor: String::new(),
            actor_fp: None,
            source: BanSource::Moderator,
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: None,
            lifted_at: None,
            lifted_by: None,
            act: None,
        }]);
        let now = SystemTime::now();
        let mut r = self.roster.lock().unwrap();
        let refused: Vec<crate::Uid> = r
            .users
            .iter()
            .filter(|(uid, s)| {
                !s.info.system
                    && Some(**uid) != spare
                    && !s.access.has(crate::access::bit::CANT_BE_DISCONNECTED)
            })
            .filter(|(_, s)| {
                s.addr.is_some_and(|a| matcher.address(a, now).is_some())
                    || matcher
                        .person(
                            Some(&s.login),
                            s.identity.as_ref(),
                            s.info
                                .transport
                                .identity
                                .as_ref()
                                .and_then(|t| t.handle.as_deref()),
                            now,
                        )
                        .is_some()
            })
            .map(|(uid, _)| *uid)
            .collect();
        for uid in refused {
            if let Some(sess) = r.users.get_mut(&uid) {
                sess.kicked = true;
            }
            r.send_to(uid, crate::Event::Kicked);
            if r.users.get(&uid).is_some_and(crate::roster::is_buffering) {
                r.end_session(uid);
            }
        }
    }
}

/// An identity fingerprint in the audit trail: hex, since the domain
/// does not know the printed form.
fn hl_fingerprint(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ban(id: BanId, target: BanTarget, expires: Option<u64>) -> Ban {
        Ban {
            id,
            target,
            reason: format!("ban {id}"),
            note: None,
            actor: "carol".into(),
            actor_fp: None,
            source: BanSource::Moderator,
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: expires.map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s)),
            lifted_at: None,
            lifted_by: None,
            act: None,
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn an_address_block_is_one_canonical_target_in_either_family() {
        let a = BanTarget::parse("10.0.0.7/24", |_| None).unwrap();
        let b = BanTarget::parse("10.0.0.0/24", |_| None).unwrap();
        assert_eq!(a, b, "the bits past the prefix are not the target");
        assert_eq!(
            a,
            BanTarget::address("::ffff:10.0.0.200".parse().unwrap(), 24).unwrap(),
            "a mapped address is its IPv4 one, prefix and all"
        );
        assert!(
            matches!(a, BanTarget::Address { prefix: 120, .. }),
            "stored as a /120"
        );
        assert_eq!(a.describe(|_| String::new()), "10.0.0.0/24");
        let one = BanTarget::parse("192.0.2.7", |_| None).unwrap();
        assert_eq!(one.describe(|_| String::new()), "192.0.2.7");
        let six = BanTarget::parse("2001:db8:1:2::9/64", |_| None).unwrap();
        assert_eq!(six.describe(|_| String::new()), "2001:db8:1:2::/64");
        let (bytes, prefix) = six.to_row();
        assert_eq!(BanTarget::from_row(1, &bytes, prefix), Some(six));
        assert!(BanTarget::parse("10.0.0.0/33", |_| None).is_err());
        assert!(BanTarget::parse("nonsense", |_| None).is_err());
        assert_eq!(
            BanTarget::parse("*@Example.ORG", |_| None).unwrap(),
            BanTarget::Registrar("example.org".into())
        );
        assert_eq!(
            BanTarget::parse("login: Alice", |_| None).unwrap(),
            BanTarget::Login("alice".into())
        );
    }

    #[test]
    fn a_matcher_finds_blocks_people_and_registrars_until_they_expire() {
        let m = BanMatcher::load([
            ban(1, BanTarget::parse("10.1.0.0/16", |_| None).unwrap(), None),
            ban(
                2,
                BanTarget::parse("2001:db8::/32", |_| None).unwrap(),
                Some(100),
            ),
            ban(3, BanTarget::login("alice").unwrap(), None),
            ban(4, BanTarget::Identity([7; 32]), None),
            ban(5, BanTarget::registrar("bad.example").unwrap(), None),
        ]);
        let hit = |ip: &str, t| m.address(ip.parse().unwrap(), at(t)).map(|h| h.id);
        assert_eq!(hit("10.1.200.3", 0), Some(1));
        assert_eq!(hit("::ffff:10.1.0.1", 0), Some(1));
        assert_eq!(hit("10.2.0.1", 0), None);
        assert_eq!(hit("2001:db8:ffff::1", 50), Some(2));
        assert_eq!(hit("2001:db8:ffff::1", 100), None, "expired");
        let person = |l, fp: Option<[u8; 32]>, h| m.person(l, fp.as_ref(), h, at(0)).map(|h| h.id);
        assert_eq!(person(Some("ALICE"), None, None), Some(3));
        assert_eq!(person(Some("bob"), Some([7; 32]), None), Some(4));
        assert_eq!(person(Some("bob"), None, Some("bob@Bad.Example")), Some(5));
        assert_eq!(
            person(Some("bob"), Some([8; 32]), Some("bob@good.example")),
            None
        );
    }

    #[test]
    fn an_address_ban_refuses_only_its_own_family() {
        let m = BanMatcher::load([
            ban(1, BanTarget::parse("::/64", |_| None).unwrap(), None),
            ban(2, BanTarget::parse("::/0", |_| None).unwrap(), None),
        ]);
        let hit = |ip: &str| m.address(ip.parse().unwrap(), at(0)).map(|h| h.id);
        assert!(hit("::1").is_some());
        assert_eq!(hit("2001:db8::1"), Some(2));
        for v4 in ["192.0.2.7", "::ffff:192.0.2.7", "127.0.0.1"] {
            assert_eq!(hit(v4), None, "an IPv6 block refuses no IPv4 peer: {v4}");
        }

        let m = BanMatcher::load([
            ban(3, BanTarget::parse("0.0.0.0/0", |_| None).unwrap(), None),
            ban(4, BanTarget::parse("192.0.2.7", |_| None).unwrap(), None),
        ]);
        let hit = |ip: &str| m.address(ip.parse().unwrap(), at(0)).map(|h| h.id);
        assert_eq!(hit("198.51.100.1"), Some(3));
        assert!(hit("::ffff:192.0.2.7").is_some());
        for v6 in [
            "::1",
            "::",
            "::c000:207",
            "2001:db8::1",
            "64:ff9b::c000:207",
        ] {
            assert_eq!(hit(v6), None, "an IPv4 block refuses no IPv6 peer: {v6}");
        }
    }

    #[test]
    fn a_target_holds_one_ban_and_a_stale_id_lifts_nothing() {
        let alice = || BanTarget::login("alice").unwrap();
        let mut m = BanMatcher::load([ban(1, alice(), None)]);
        m.insert(&ban(2, alice(), None));
        assert!(!m.contains(1), "the target's old id is let go");
        m.remove(1);
        assert_eq!(
            m.person(Some("alice"), None, None, at(0)).map(|h| h.id),
            Some(2),
            "a lift by the old id leaves the new ban standing"
        );
        m.remove(2);
        assert!(m.is_empty());
        assert!(m.person(Some("alice"), None, None, at(0)).is_none());
    }

    #[test]
    fn a_reread_neither_loses_a_ban_placed_meanwhile_nor_resurrects_a_lifted_one() {
        use crate::moderation::{Actor, MemoryModeration, ModerationPolicy};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let core = crate::Core::new().with_moderation(
            std::sync::Arc::new(MemoryModeration::default()),
            ModerationPolicy::default(),
        );
        let placers = AtomicUsize::new(4);
        std::thread::scope(|scope| {
            for n in 0..4 {
                let (core, placers) = (&core, &placers);
                scope.spawn(move || {
                    // Counted down even by a failing assertion, so the
                    // rereads stop and the failure is reported.
                    struct Done<'a>(&'a AtomicUsize);
                    impl Drop for Done<'_> {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    let _done = Done(placers);
                    for i in 0..200 {
                        let login = format!("u{n}-{i}");
                        let placed = core
                            .place_ban(
                                Actor::Operator,
                                NewBan {
                                    target: BanTarget::login(&login).unwrap(),
                                    reason: "spam".into(),
                                    note: None,
                                    expires_at: None,
                                    source: BanSource::Cli,
                                },
                            )
                            .unwrap();
                        // Nobody else touches this login: what this
                        // thread just did is what the matcher says.
                        assert!(
                            core.person_banned(Some(&login), None, None).is_some(),
                            "a ban placed during a reread is lost"
                        );
                        if i % 2 == 0 {
                            core.lift_ban(Actor::Operator, placed[0].id).unwrap();
                            assert!(
                                core.person_banned(Some(&login), None, None).is_none(),
                                "a ban lifted during a reread is back"
                            );
                        }
                    }
                });
            }
            scope.spawn(|| {
                while placers.load(Ordering::Relaxed) > 0 {
                    core.reload_bans();
                    // Room for the placers: the lock is not fair.
                    std::thread::sleep(Duration::from_micros(50));
                }
            });
        });
        let mut standing: Vec<BanId> = core
            .list_bans(true, None, usize::MAX)
            .unwrap()
            .iter()
            .map(|b| b.id)
            .collect();
        let mut held: Vec<BanId> = core.bans.read().unwrap().by_id.keys().copied().collect();
        standing.sort_unstable();
        held.sort_unstable();
        assert_eq!(held, standing);
    }

    #[test]
    fn a_lifted_ban_is_gone_from_the_matcher() {
        let mut m = BanMatcher::load([ban(1, BanTarget::login("alice").unwrap(), None)]);
        m.remove(1);
        assert!(m.person(Some("alice"), None, None, at(0)).is_none());
        assert!(m.is_empty());
    }
}
