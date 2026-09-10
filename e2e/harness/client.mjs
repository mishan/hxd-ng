/**
 * Driving a server with `@hotline-ng/client`.
 *
 * The library is the point. It is a second implementation of this wire,
 * written from `docs/hotline-ng.md` by the client rather than by the
 * server, so where it and hxd-ng agree the agreement is evidence — which
 * is exactly what the hand-rolled JSON in `crates/hxd/tests/ng.rs`
 * cannot say about itself. Where they disagree, the spec says which is
 * wrong, and that conversation is the value.
 *
 * What this file adds is the ability to *wait*, and it does it from the
 * trace hook rather than from `Connection.on`. Two reasons, and the
 * second decides it: `on` is additive with no way to remove a handler,
 * so a test cannot subscribe for the duration of one assertion; and
 * `onEvent` drops any event with no registered handler, so a name list
 * here would have to be kept in step with the wire forever and would
 * silently miss the next event the protocol grows. `onTrace` sees every
 * frame in both directions, named and unnamed, before dispatch.
 */

import { Connection } from '@hotline-ng/client';

// This suite's other claim is that the library runs in a bare runtime.
// A shim would turn that claim into a tautology — and two of them would
// actively lie. A `Map` standing in for `sessionStorage` gets tab
// scoping, quota and private-mode throwing wrong, and the library shares
// one storage key across every session: a second client would adopt the
// first's saved session and `resume` into it, which the server correctly
// honors as a takeover. A fake `location` is worse, because `wsToHttp`
// returns a page-relative '' when the hostname matches and the media
// fetches then have no base at all.
//
// So: nothing is installed, and anything already there is a bug worth
// hearing about.
for (const global of ['window', 'document', 'sessionStorage', 'localStorage', 'location']) {
  if (global in globalThis) {
    throw new Error(
      `e2e: globalThis.${global} exists. This suite proves @hotline-ng/client ` +
        `runs without a browser; a shim makes that proof circular.`,
    );
  }
}

class TimeoutError extends Error {}

/** One thing that happened, in one flat stream so `waitFor` has a single
 *  thing to scan. `kind` is `ev` | `reply` | `req` | `state` | `hook`. */
class Record {
  constructor(n, kind, name, data, seq) {
    this.n = n;
    this.kind = kind;
    this.name = name;
    this.data = data;
    this.seq = seq;
  }
}

/** `{ 'from.nick': 'Alice' }` as a predicate. A plain object is a subset
 *  match on dotted paths, which covers most assertions and reads better
 *  than the arrow function it replaces. */
function toPredicate(match) {
  if (typeof match === 'function') return match;
  if (match && typeof match === 'object') {
    const pairs = Object.entries(match);
    return (data) =>
      pairs.every(([path, want]) => {
        let cur = data;
        for (const step of path.split('.')) {
          if (cur === null || cur === undefined) return false;
          cur = cur[step];
        }
        return cur === want;
      });
  }
  throw new TypeError(`a matcher must be a function or an object, got ${typeof match}`);
}

function describeMatch(match) {
  return typeof match === 'function' ? match.toString().replace(/\s+/g, ' ') : JSON.stringify(match);
}

/** A CI log is a public artifact. */
function redact(raw) {
  return raw.replace(/("(?:password|token)":")[^"]*"/g, '$1…"');
}

export class TestClient {
  /**
   * @param {import('./server.mjs').Server} server
   * @param {object} creds `login`/`password`/`nick`/`icon`/`identity`
   */
  constructor(server, creds = {}) {
    this.server = server;
    this.who = creds.nick ?? creds.login ?? 'guest';
    this.log = [];
    this.waiters = [];
    this.n = 0;

    this.conn = new Connection(
      {
        url: server.wsUrl,
        login: creds.login ?? '',
        password: creds.password ?? '',
        nick: creds.nick ?? 'guest',
        icon: creds.icon ?? 0,
        ...(creds.identity ? { identity: creds.identity } : {}),
      },
      {
        onTrace: (t) => this.onTrace(t),
        onState: (s, detail) => this.push('state', s, { detail }),
        onEnded: (reason) => this.push('hook', 'onEnded', { reason }),
        onResumed: (replay) => this.push('hook', 'onResumed', { replay }),
        onLogin: (ok) => this.push('hook', 'onLogin', ok),
        onSnapshot: (ok) => this.push('hook', 'onSnapshot', ok),
        // These two change what the client *sends*: with no hook the
        // library skips the `inbox` and `history` catch-up entirely. A
        // suite that wants to observe recovery has to ask for it.
        onMissedMail: (ok) => this.push('hook', 'onMissedMail', ok),
        onMissedHistory: (ok) => this.push('hook', 'onMissedHistory', ok),
      },
    );
  }

  onTrace(t) {
    let frame;
    try {
      frame = JSON.parse(t.raw);
    } catch {
      return this.push('raw', t.kind, { raw: t.raw });
    }
    if (t.dir === 'out') return this.push('req', frame.req ?? t.kind, frame.params ?? {});
    if (t.kind.startsWith('ev:')) {
      return this.push('ev', frame.ev, frame.data ?? {}, frame.seq);
    }
    // `reply:ok` or `reply:<code>`; the name is the outcome, so a test
    // can wait for a specific refusal.
    return this.push('reply', t.kind.slice('reply:'.length), frame.ok ?? frame.error ?? {});
  }

  push(kind, name, data, seq) {
    const rec = new Record(this.n++, kind, name, data, seq);
    this.log.push(rec);
    for (const w of [...this.waiters]) {
      if (w.settle(rec)) this.waiters.splice(this.waiters.indexOf(w), 1);
    }
  }

  async start(opts) {
    await this.conn.start(opts);
    return this;
  }

  /** A cursor to pass back as `since`, so a second wait for the same
   *  kind of thing cannot be answered by the first one again. Better
   *  than consuming matched records, which makes two assertions about
   *  one event fight each other. */
  mark() {
    return this.n;
  }

  /**
   * Wait for an event, scanning what has already arrived first.
   *
   * The matcher is required on purpose. A sender receives the echo of
   * its own chat line, so "the next `chat`" is almost never the one a
   * test means, and a defaulted always-true matcher is that bug waiting
   * to be written.
   */
  waitFor(name, match, opts = {}) {
    return this.await_('ev', name, match, opts);
  }

  /** Wait for a reply by outcome — `'ok'`, or an error code like
   *  `'rate_limited'`. */
  waitForReply(name, match, opts = {}) {
    return this.await_('reply', name, match, opts);
  }

  /** Wait for a lifecycle hook: `onEnded`, `onResumed`, `onMissedMail`. */
  waitForHook(name, match = () => true, opts = {}) {
    return this.await_('hook', name, match, opts);
  }

  /** Wait for a connection state: `'reconnecting'`, `'online'`. */
  waitForState(name, opts = {}) {
    return this.await_('state', name, () => true, opts);
  }

  await_(kind, name, match, { timeout = 5000, since = 0 } = {}) {
    const predicate = toPredicate(match);
    const hit = (rec) => {
      if (rec.kind !== kind || rec.name !== name || rec.n < since) return false;
      try {
        return predicate(rec.data);
      } catch {
        // A predicate reaching into a shape that isn't there is a "no",
        // not a crash — the next frame may well be the one it wanted.
        return false;
      }
    };
    // A session the server has ended will never produce what is being
    // waited for, and five seconds of silence says nothing about why.
    const dead = (rec) =>
      kind !== 'hook' && rec.kind === 'hook' && rec.name === 'onEnded' && rec.n >= since;

    for (const rec of this.log) {
      if (hit(rec)) return Promise.resolve(rec);
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        settle: (rec) => {
          if (hit(rec)) {
            resolve(rec);
            return true;
          }
          if (dead(rec)) {
            reject(new Error(this.diagnose(`session ended (${rec.data.reason}) while waiting for ${kind} ${name}`, since)));
            return true;
          }
          return false;
        },
      };
      this.waiters.push(waiter);
      setTimeout(() => {
        const i = this.waiters.indexOf(waiter);
        if (i < 0) return;
        this.waiters.splice(i, 1);
        reject(
          new TimeoutError(
            this.diagnose(`no ${kind} ${name} matching ${describeMatch(match)} within ${timeout}ms`, since),
          ),
        );
      }, timeout).unref();
    });
  }

  /**
   * Assert something does *not* arrive. Costs its full wait every time,
   * so it is spent where the absence is the whole point — the client who
   * was never in the room not being shown the image.
   */
  async expectNo(name, match, { timeout = 750, since = 0 } = {}) {
    try {
      const rec = await this.waitFor(name, match, { timeout, since });
      throw new Error(
        this.diagnose(`expected no ${name}, got ${JSON.stringify(rec.data)}`, since),
      );
    } catch (e) {
      if (e instanceof TimeoutError) return;
      throw e;
    }
  }

  /** Synchronous scan, for asserting about everything that happened
   *  rather than waiting for one thing. */
  seen(kind, name, match = () => true) {
    const predicate = toPredicate(match);
    return this.log.filter((r) => {
      if (r.kind !== kind || r.name !== name) return false;
      try {
        return predicate(r.data);
      } catch {
        return false;
      }
    });
  }

  /** Everything worth knowing when an assertion fails: what this client
   *  saw, where the session had got to, what the server thought it was
   *  doing, and how to run the same thing again with both wire traces
   *  on. */
  diagnose(message, since = 0) {
    const arrow = { req: '->', reply: '<-', ev: '<-', state: ' *', hook: ' *', raw: '<-' };
    const wire = this.log
      .filter((r) => r.n >= since)
      .slice(-25)
      .map((r) => {
        const label = r.kind === 'ev' ? `ev:${r.name}` : r.kind === 'req' ? r.name : `${r.kind}:${r.name}`;
        return `    ${arrow[r.kind] ?? '  '} ${label.padEnd(18)} ${redact(JSON.stringify(r.data))}`;
      })
      .join('\n');
    const c = this.conn;
    return [
      `[${this.who}] ${message}`,
      `  session: state=${c.state} seq=${c.seq} ${c.session ? 'has session' : 'no session'}`,
      `  this client's wire:`,
      wire || '    (nothing)',
      `  server:`,
      this.server.log(),
      `  reproduce: ${this.server.repro()}`,
    ].join('\n');
  }

  /**
   * Always `logout()`, even when the socket looks dead.
   *
   * The reconnect timer is a ref'd Node timer that reschedules for as
   * long as the process lives, so a client dropped and left alone will
   * hold `node --test` open past the end of the file. `logout` cancels
   * it before it tries to send anything, which is why it is the safe
   * universal teardown rather than only the polite one.
   */
  async close() {
    try {
      await this.conn.logout();
    } catch {
      // Kicked, replaced, or never up: there is nothing to log out of,
      // and saying so is not this helper's job.
    }
  }
}

/** Log a client in and hand it back ready to assert against. */
export async function connect(server, creds = {}) {
  const client = new TestClient(server, creds);
  await client.start();
  return client;
}

/**
 * A file's worth of clients, all of which get closed however the tests
 * end.
 *
 * Not tidiness. `Connection` answers a socket that closed for any reason
 * it does not recognize by scheduling a reconnect, on a ref'd timer, and
 * it reschedules for as long as the process lives — so a single client
 * left behind, *including one whose login was refused*, holds
 * `node --test` open past the end of the file and the run simply hangs
 * with nothing to say. Registration happens before `start`, so a client
 * that fails to log in is still cleaned up.
 *
 * Never construct a bare `Connection` in a test for the same reason.
 */
export function fleet(getServer) {
  const open = [];
  return {
    /** Log in, and remember to clean up. */
    async connect(creds = {}) {
      const client = new TestClient(getServer(), creds);
      open.push(client);
      await client.start();
      return client;
    },
    /** For a login that is expected to be refused: hand back the client
     *  and the error, with the client already registered for teardown. */
    async refused(creds = {}) {
      const client = new TestClient(getServer(), creds);
      open.push(client);
      try {
        await client.start();
      } catch (e) {
        return { client, error: e };
      }
      throw new Error(client.diagnose('expected this login to be refused, but it succeeded'));
    },
    async closeAll() {
      for (const c of open) await c.close();
      open.length = 0;
    },
  };
}

/**
 * Move a session from one client to another, the way `sessionStorage`
 * would across a page reload.
 *
 * Explicit, because there is no reload here and a shared storage slot
 * between two live clients is not a fixture, it is a bug: the second
 * would adopt the first's session and resume into it, which the server
 * honors as a takeover. Spelling it out means only the test that wants a
 * takeover gets one.
 */
export function adoptSession(from, to) {
  to.conn.session = from.conn.session;
  to.conn.token = from.conn.token;
  to.conn.seq = from.conn.seq;
  to.conn.caps = [...from.conn.caps];
  to.conn.grace = from.conn.grace;
}

/**
 * One handshake frame on a socket of its own, with no library in the
 * way.
 *
 * `login`, `resume` and `sync` are handshake-only — sent on an
 * established session they are `bad_request`, correctly — so a test that
 * wants to know what the server says to a *stale* resume cannot ask an
 * already-logged-in `Connection` to send one. It needs a fresh socket
 * saying nothing else.
 *
 * Being a second, dependency-free implementation of the frame is a
 * bonus rather than the reason: where this and `@hotline-ng/client`
 * agree about a reply, two independent readings of §6 agree.
 */
export function rawHandshake(server, req, params, { timeout = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(server.wsUrl);
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`no reply to ${req} within ${timeout}ms`));
    }, timeout);
    timer.unref?.();
    ws.onerror = () => {
      clearTimeout(timer);
      reject(new Error(`could not reach ${server.wsUrl}`));
    };
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, req, params }));
    ws.onmessage = (e) => {
      const frame = JSON.parse(e.data);
      // Events can precede the reply; only the reply settles this.
      if (frame.reply === undefined) return;
      clearTimeout(timer);
      ws.close();
      resolve(frame.error ? { error: frame.error } : { ok: frame.ok ?? {} });
    };
  });
}
