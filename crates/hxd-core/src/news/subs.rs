//! Subscriptions, and the notifications a post earns (`docs/news.md` §10).
//!
//! **There is no notification table** (§10.4). A private message needs the
//! inbox because the message exists nowhere else; an article is already
//! the durable thing, so what is stored is a subscription and a cursor,
//! and unread is a count the store makes when asked. A badge that is
//! computed cannot drift from what it counts.
//!
//! What a post does, in order:
//!
//! 1. **It subscribes its poster** (`auto_subscribe`), so whoever asked a
//!    question is subscribed to the answers with nothing to click. The
//!    store does that in the post's own write ([`AutoFollow`]), so the
//!    row exists before any later article is given an id.
//! 2. **It names an audience**: the parent's author (`reply`), the authors
//!    of what the body cited (`reference`), and the thread's subscribers
//!    and — for a new thread — the category's (`subscription`),
//!    deduplicated by mailbox with the highest reason kept. Then filtered:
//!    never the poster, never through a muted thread, never an account
//!    that has since lost read-news, never one that has blocked the
//!    poster.
//! 3. **It is delivered**: `news_notify` to every session of that account,
//!    always, because it carries the badge; and a push through the gateway
//!    when none of those sessions is attentive, *and* the scope was caught
//!    up before this post — the catch-up rule of §10.7, which is the whole
//!    of news's answer to coalescing — *and* the hourly budget allows.
//!
//! The decision is here, in the domain, for the reason `crate::notify`
//! gives: a frontend that computed it would be a frontend that could skip
//! it, and the legacy binding (W9) posts through the same `news_post`.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tracing::warn;

use super::{
    store_failed, ArticleId, Asker, AutoFollow, AutoSubscribe, NewPost, NewsError, NewsStore,
    NodeKind, Notified, NotifyPolicy, NotifyReason, Posted, SubScope, Subscription,
};
use crate::access::bit;
use crate::inbox::Mailbox;
use crate::notify::{NewsNotice, Notification};
use crate::roster::{Core, Event, SessionStatus, Uid};

/// How much of a body a notification carries, in characters.
const EXCERPT_CHARS: usize = 160;

/// Push budgets kept before idle ones are forgotten. A full bucket is the
/// same as no entry, so forgetting one changes nothing but memory.
const BUDGETS_KEPT: usize = 4096;

/// Are `a` and `b` one mailbox? The mailbox rule, both ways round being
/// the same answer: one fingerprint, or one login with no fingerprint on
/// either side.
fn same(a: &Mailbox, b: &Mailbox) -> bool {
    a.matches(&b.login, b.fingerprint.as_ref())
}

/// A mailbox as an hourly budget's map key: its fingerprint, or its login
/// when it has none.
pub(super) type BudgetKey = (Option<[u8; 32]>, String);

/// Hourly budgets by mailbox: when each was last spent from, and what is
/// left in it.
pub(super) type Budgets = std::collections::HashMap<BudgetKey, (Instant, f64)>;

/// The key a push budget is kept under — the mailbox rule as a map key, so
/// a renamed identity keeps its budget and a login someone else has since
/// taken does not inherit one.
pub(super) fn budget_key(m: &Mailbox) -> BudgetKey {
    match m.fingerprint {
        Some(fp) => (Some(fp), String::new()),
        None => (None, m.login.clone()),
    }
}

/// Take one from `key`'s bucket in `budgets`: `per_hour` of them,
/// refilling across the hour, so a burst up to the hour's worth and then
/// one as each comes due. Past [`BUDGETS_KEPT`] entries the full buckets
/// are forgotten first. The caller holds the map's lock and has refused a
/// `per_hour` of zero, whose bucket would never fill to be forgotten.
pub(super) fn spend(budgets: &mut Budgets, key: BudgetKey, per_hour: u32) -> bool {
    let per_hour = f64::from(per_hour);
    let refill =
        |at: Instant, now: Instant| now.duration_since(at).as_secs_f64() * per_hour / 3600.0;
    let now = Instant::now();
    if budgets.len() >= BUDGETS_KEPT {
        budgets.retain(|_, (at, tokens)| *tokens + refill(*at, now) < per_hour);
    }
    let (at, tokens) = budgets.entry(key).or_insert((now, per_hour));
    *tokens = (*tokens + refill(*at, now)).min(per_hour);
    *at = now;
    if *tokens < 1.0 {
        return false;
    }
    *tokens -= 1.0;
    true
}

/// The opening of a body as one line, cut at a word near the limit. What a
/// lock screen shows, if the gateway's content policy shows anything.
fn excerpt(body: &str) -> String {
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= EXCERPT_CHARS {
        return flat;
    }
    let cut: String = flat.chars().take(EXCERPT_CHARS).collect();
    let cut = match cut.rfind(' ') {
        Some(at) if at > cut.len() * 3 / 5 => &cut[..at],
        _ => &cut[..],
    };
    format!("{}…", cut.trim_end())
}

/// The subscription posting owes its poster, if any: none on a server
/// that keeps no subscriptions, none for a guest, and otherwise as
/// `auto_subscribe` says.
pub(super) fn auto_follow(
    asker: &Asker,
    starter: bool,
    notify: Option<NotifyPolicy>,
) -> Option<AutoFollow> {
    let notify = notify?;
    let auto = match notify.auto_subscribe {
        AutoSubscribe::Participated => true,
        AutoSubscribe::OwnThread => starter,
        AutoSubscribe::Off => false,
    };
    let owner = asker.mailbox.clone().filter(|_| auto)?;
    Some(AutoFollow {
        owner,
        max_subs: notify.max_subs,
    })
}

/// Is there something at `scope` to follow: a thread starter, or a
/// category? `news_subscribe` and muting learn it by making a row. The
/// requests that make none ask it here, so a scope nobody follows is still
/// a no-op and one that names nothing is refused the way subscribing
/// refuses it (§10.9). Asked only where no row answers it: a row goes with
/// its target, so one that exists already has.
fn scope_exists(store: &dyn NewsStore, scope: SubScope) -> Result<(), NewsError> {
    match scope {
        SubScope::Thread(root) => match store.article(root)? {
            Some(a) if a.parent.is_none() => Ok(()),
            _ => Err(NewsError::NoSuchArticle),
        },
        SubScope::Category(c) => match store.node(c)?.map(|n| n.kind) {
            None => Err(NewsError::NoSuchNode),
            Some(NodeKind::Bundle) => Err(NewsError::NotACategory),
            Some(NodeKind::Category) => Ok(()),
        },
    }
}

impl Core {
    /// The store, the asking session's mailbox and the policy, or why
    /// this session cannot hold a subscription: no news, no
    /// subscriptions on this server, no read-news, or no mailbox — a
    /// guest, whose shared login names nobody durable (§10.2).
    fn news_subscriber(
        &self,
        uid: Uid,
    ) -> Result<(&Arc<dyn NewsStore>, Mailbox, NotifyPolicy), NewsError> {
        let store = self.news_store()?;
        let notify = self.news_policy.notify.ok_or(NewsError::NotifyOff)?;
        let asker = self.news_reader(uid)?;
        let mailbox = asker.mailbox.ok_or(NewsError::NoMailbox)?;
        Ok((store, mailbox, notify))
    }

    /// May this session hold subscriptions? The login reply says so, the
    /// way it says whether it may post, so a client draws no Follow button
    /// that can only be refused.
    pub fn news_may_subscribe(&self, uid: Uid) -> bool {
        if self.news.is_none() || self.news_policy.notify.is_none() {
            return false;
        }
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .is_some_and(|s| s.has_inbox && s.access.has(bit::READ_NEWS))
    }

    /// Unread across this session's subscriptions, for the login reply's
    /// badge; `None` when it cannot hold any. A store that will not answer
    /// is an empty badge and a line in the log, as the inbox's count is —
    /// refusing a login over a number would be worse.
    pub fn news_unread(&self, uid: Uid) -> Option<usize> {
        let (store, mailbox, _) = self.news_subscriber(uid).ok()?;
        Some(store.unread_total(&mailbox).unwrap_or_else(|e| {
            warn!("news: unread for {}: {e}", mailbox.login);
            0
        }))
    }

    /// Follow a thread or a category, answering its unread count.
    pub fn news_subscribe(&self, uid: Uid, scope: SubScope) -> Result<usize, NewsError> {
        let (store, mailbox, notify) = self.news_subscriber(uid)?;
        store
            .subscribe(&mailbox, scope, notify.max_subs, SystemTime::now())
            .map_err(store_failed)
    }

    /// Stop following. Idempotent: not following is the answer either way,
    /// for a scope that is there to follow ([`scope_exists`]).
    pub fn news_unsubscribe(&self, uid: Uid, scope: SubScope) -> Result<(), NewsError> {
        let (store, mailbox, _) = self.news_subscriber(uid)?;
        let gone = store
            .unsubscribe(&mailbox, scope)
            .map_err(|e| store_failed(e.into()))?;
        if !gone {
            scope_exists(&**store, scope).map_err(store_failed)?;
        }
        Ok(())
    }

    pub fn news_mute(&self, uid: Uid, scope: SubScope, muted: bool) -> Result<(), NewsError> {
        let (store, mailbox, notify) = self.news_subscriber(uid)?;
        if !muted {
            scope_exists(&**store, scope).map_err(store_failed)?;
        }
        store
            .mute(&mailbox, scope, muted, notify.max_subs, SystemTime::now())
            .map_err(store_failed)
    }

    pub fn news_subs(&self, uid: Uid) -> Result<Vec<Subscription>, NewsError> {
        let (store, mailbox, _) = self.news_subscriber(uid)?;
        store
            .subscriptions(&mailbox)
            .map_err(|e| store_failed(e.into()))
    }

    /// The client has shown its user `scope` up to `up_to` (§10.8).
    /// **Explicit, never implied by a read**: serving a thread does not
    /// move the cursor, because a client may prefetch, may render nothing,
    /// or may be drawing a search preview. Not following is 0 unread,
    /// not an error — a client that says "seen" on every thread it shows
    /// should not have to know which ones it follows first. A scope that
    /// names nothing is an error ([`scope_exists`]).
    pub fn news_seen(
        &self,
        uid: Uid,
        scope: SubScope,
        up_to: ArticleId,
    ) -> Result<usize, NewsError> {
        let (store, mailbox, _) = self.news_subscriber(uid)?;
        match store
            .seen(&mailbox, scope, up_to)
            .map_err(|e| store_failed(e.into()))?
        {
            Some(unread) => Ok(unread),
            None => scope_exists(&**store, scope)
                .map(|()| 0)
                .map_err(store_failed),
        }
    }

    /// The news half of `inbox_claim`: subscriptions are keyed the way a
    /// mailbox is, so linking an identity owes them the same stamp.
    ///
    /// The push budget kept under the old key goes too. The new key starts
    /// with a full hour's worth, which is at most one hour's extra pushes;
    /// the other way round, a later holder of a freed login would start
    /// out with the previous holder's spent budget. Every link site is in
    /// the running server, so this one always reaches the budgets.
    pub(crate) fn news_subs_claim(&self, login: &str, fingerprint: &[u8; 32]) {
        self.forget_news_budget(&Mailbox::login(login));
        if let Some(store) = self.news.as_ref() {
            if let Err(e) = store.subs_claim(login, fingerprint) {
                warn!("news: claiming {login}'s subscriptions: {e}");
            }
        }
    }

    /// A rotation and a purge forget the budget too, but only in the
    /// process they run in. Nothing rotates yet, and a purge is
    /// `hxd inbox purge`, a process of its own that never reaches a
    /// running server's memory: there, a login deleted and taken again
    /// within the hour can start with the previous holder's partly spent
    /// budget. That costs a push delayed until the bucket refills — never
    /// an event and never a count — and a restart forgets it.
    pub(crate) fn news_subs_rotate(&self, from: &[u8; 32], to: &[u8; 32]) {
        self.forget_news_budget(&Mailbox::identified("", *from));
        if let Some(store) = self.news.as_ref() {
            if let Err(e) = store.subs_rotate(from, to) {
                warn!("news: rotating an identity's subscriptions: {e}");
            }
        }
    }

    pub(crate) fn news_subs_purge(&self, of: &Mailbox) {
        self.forget_news_budget(of);
        if let Some(store) = self.news.as_ref() {
            if let Err(e) = store.subs_purge(of) {
                warn!("news: purging {}'s subscriptions: {e}", of.login);
            }
        }
    }

    /// Everything a post owes after it is stored: telling everyone it is
    /// addressed to. The poster's own subscription is already made, in
    /// the post's write.
    pub(super) fn news_after_post(
        &self,
        asker: &Asker,
        post: &NewPost,
        posted: Posted,
        notify: NotifyPolicy,
    ) {
        let Some(store) = self.news.as_ref() else {
            return;
        };
        let starter = post.parent.is_none();
        let thread = SubScope::Thread(posted.root);

        // A tombstone has no author, and a guest's article has no login;
        // either way there is nobody to tell.
        let author_of = |id: ArticleId| -> Option<Mailbox> {
            let article = store
                .article(id)
                .map_err(|e| warn!("news notify: reading #{id}: {e}"))
                .ok()??;
            Some(Mailbox {
                login: article.author.login?,
                fingerprint: article.author.fingerprint,
            })
        };
        let mut audience: Vec<(Mailbox, NotifyReason)> = Vec::new();
        let mut add = |to: Mailbox, reason: NotifyReason| match audience
            .iter_mut()
            .find(|(m, _)| same(m, &to))
        {
            Some((_, kept)) => *kept = (*kept).min(reason),
            None => audience.push((to, reason)),
        };
        if let Some(parent) = post.parent {
            if let Some(m) = author_of(parent) {
                add(m, NotifyReason::Reply);
            }
        }
        if notify.reference {
            // What the store kept rather than what the scanner found: an
            // id that named nothing is the digits someone typed, and
            // names nobody.
            let cited = store
                .article(posted.id)
                .ok()
                .flatten()
                .map(|a| a.refs)
                .unwrap_or_default();
            for r in cited.iter().filter(|r| !r.deleted) {
                if let Some(m) = author_of(r.id) {
                    add(m, NotifyReason::Reference);
                }
            }
        }
        let rows = store
            .subscribers(posted.root, starter.then_some(post.category), posted.id)
            .unwrap_or_else(|e| {
                warn!("news notify: subscribers of #{}: {e}", posted.root);
                Vec::new()
            });
        for row in rows.iter().filter(|r| !r.muted) {
            add(row.owner.clone(), NotifyReason::Subscription);
        }

        // The downgrade where there is one: a lock screen is a text view.
        let excerpt = excerpt(post.plain.as_deref().unwrap_or(&post.body));
        for (to, reason) in audience {
            // You are not news to yourself, whichever reason would apply.
            if asker.mailbox.as_ref().is_some_and(|me| same(me, &to)) {
                continue;
            }
            let row = |scope: SubScope| {
                rows.iter()
                    .find(|r| r.scope == scope && same(&r.owner, &to))
            };
            // Which cursor this counts against. A muted thread silences
            // every reason in it; a muted category only its own, because a
            // reply to your article is not something muting a category
            // was about. A reply or a citation to someone with no cursor
            // in the thread counts against the thread with none — nothing
            // is created by being notified, and `max_per_hour` is what
            // bounds it.
            let (scope, cursor) = match row(thread) {
                Some(r) if r.muted => continue,
                Some(r) => (thread, Some(r)),
                None if reason == NotifyReason::Subscription => {
                    let category = SubScope::Category(post.category);
                    match row(category) {
                        Some(r) if !r.muted => (category, Some(r)),
                        _ => continue,
                    }
                }
                None => (thread, None),
            };
            if !self.news_may_notify(&to, asker.blockable.as_ref()) {
                continue;
            }
            // The catch-up rule (§10.7): nothing older than this post was
            // unread, so the owner had seen everything before it. Asked of
            // what came *before* this article rather than of the total, so
            // two posts that land together cannot each count the other
            // and both stay silent: the earlier one rings.
            let rings = cursor.is_none_or(|r| r.earlier == 0);
            let notified = Notified {
                reason,
                scope,
                article: posted.id,
                root: posted.root,
                category: post.category,
                subject: post.subject.clone(),
                excerpt: excerpt.clone(),
                from_nick: post.author.nick.clone(),
                from_login: post.author.login.clone(),
                at: post.at,
                unread: cursor.map_or(1, |r| r.unread),
            };
            self.news_deliver(&to, notified, rings, notify.max_per_hour);
        }
    }

    /// The account-level filters of §10.5, asked of an account that may
    /// not be here: does it still hold read-news, and has it blocked the
    /// poster? Revoking the bit is what stops the pushes, and a block
    /// suppresses the notification, never the article.
    fn news_may_notify(&self, to: &Mailbox, poster: Option<&Mailbox>) -> bool {
        // Without a directory there is no way to ask whether the bit
        // survived, and a server wired that way notifies nobody rather
        // than guess.
        let Some(directory) = self.directory.as_ref() else {
            return false;
        };
        if !directory
            .mailbox_access(to)
            .is_some_and(|a| a.has(bit::READ_NEWS))
        {
            return false;
        }
        match (self.inbox.as_ref(), poster) {
            (Some(inbox), Some(poster)) => match inbox.is_blocked(to, poster) {
                Ok(blocked) => !blocked,
                Err(e) => {
                    warn!("news notify: reading {}'s blocks: {e}", to.login);
                    false
                }
            },
            _ => true,
        }
    }

    /// The event to every session `to` holds, and the push when none of
    /// them is watching (§10.6).
    fn news_deliver(&self, to: &Mailbox, n: Notified, rings: bool, per_hour: u32) {
        let attentive = {
            let mut r = self.roster.lock().unwrap();
            let uids = crate::chat::sessions_of(&r, to);
            for &uid in &uids {
                r.send_to(uid, Event::NewsNotify(n.clone()));
            }
            // Across every session that owns the mailbox, as a private
            // message decides it: someone reading on a laptop does not
            // need their phone to buzz. But only a session that can show
            // the event counts. The legacy wire drops `news_notify` (it
            // has no way to say it, §10.11), so a classic client sitting
            // in chat is not someone who has been told, and the phone is
            // the only place this can reach them. `reads_on_delivery` is
            // exactly "this is the legacy wire".
            uids.iter().any(|uid| {
                r.users
                    .get(uid)
                    .is_some_and(|s| s.info.status == SessionStatus::Active && !s.reads_on_delivery)
            })
        };
        if attentive || !rings {
            return;
        }
        let Some(gateway) = self.gateway.as_ref() else {
            return;
        };
        if !self.news_push_allowed(to, per_hour) {
            return;
        }
        gateway.notify(&Notification::News(NewsNotice {
            to,
            reason: n.reason,
            from_nick: &n.from_nick,
            subject: &n.subject,
            excerpt: &n.excerpt,
            article: n.article,
            root: n.root,
            category: n.category,
            scope: n.scope,
            unread: n.unread,
        }));
    }

    /// `max_per_hour` as a bucket that refills across the hour: a burst up
    /// to the hour's worth, then one as each comes due. The floor under
    /// the catch-up rule, for an account following forty quiet scopes that
    /// all wake at once. Its lock is taken with nothing else held.
    fn news_push_allowed(&self, to: &Mailbox, per_hour: u32) -> bool {
        // Zero is no pushes at all, and there is nothing to remember
        // about that: a bucket that can never fill would never be
        // forgotten either.
        if per_hour == 0 {
            return false;
        }
        spend(
            &mut self.news_push.lock().unwrap(),
            budget_key(to),
            per_hour,
        )
    }

    /// Drop the push budget kept for a mailbox that is going, or moving
    /// to another key — in this process; see [`Self::news_subs_rotate`].
    fn forget_news_budget(&self, who: &Mailbox) {
        self.news_push.lock().unwrap().remove(&budget_key(who));
    }
}
