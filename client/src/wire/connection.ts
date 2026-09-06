/**
 * One Hotline-ng session, across however many WebSockets it takes.
 *
 * The protocol's whole point is that a session outlives its connection
 * (`docs/hotline-ng.md` §2), so this class owns the *session* and treats
 * the socket as a replaceable attachment. Drop the network and it comes
 * back with `resume`, replays what it missed and carries on with the same
 * uid; let the grace window lapse and it says so instead of pretending.
 *
 * Everything that crosses the wire, in either direction, goes through
 * `trace` first. The debug panel is not instrumentation bolted on
 * afterwards — it is this hook, and it sees exactly what the socket saw.
 */

import {
  isEvent,
  isReply,
  RESYNC_REQUIRED,
  type EventFrame,
  type Events,
  type LoginOk,
  type LoginParams,
  type ReplyFrame,
  type ResumeOk,
  type ServerFrame,
  type SyncOk,
  type User,
  type VideoConfig,
  type WireError,
} from './protocol';

export type ConnState =
  | 'offline'
  | 'connecting'
  | 'online'
  /** The socket died but the session may still be alive server-side;
   *  we are inside the grace window trying to `resume` back into it. */
  | 'reconnecting';

export interface TraceEntry {
  t: number;
  dir: 'out' | 'in';
  /** `req`/`reply`/`ev` name, for filtering without re-parsing JSON. */
  kind: string;
  /** The frame as it went over the wire. */
  raw: string;
  /** Set on a reply carrying an error, so the panel can colour it. */
  error?: boolean;
}

export interface Credentials {
  url: string;
  login: string;
  password: string;
  nick: string;
  icon: number;
}

/** What a resumed session is allowed to remember between page loads. The
 *  token is a bearer credential for one session and dies with it, so it
 *  lives in sessionStorage — per tab, gone when the tab is.
 *
 *  The capability facts ride along because only the *login* reply
 *  carries them: `resume` answers with `self` and a replay, and `sync`
 *  with the roster, so a client that comes back through either one has
 *  no other way to learn whether this server offers voice. They describe
 *  the session and die with it, which is exactly this record's lifetime.
 *  (Worth revisiting in the spec: a `caps` echo on the resume reply would
 *  make this unnecessary.) */
interface Saved {
  url: string;
  session: string;
  token: string;
  seq: number;
  caps: string[];
  grace: number | null;
  video: VideoConfig | null;
}

const SAVED_KEY = 'hxd-ng.session';

/** Does this tab hold a session for `url` that a `resume` could pick up?
 *  The client asks before showing a login form, so a reload goes
 *  straight back into the room. */
export function hasSavedSession(url: string): boolean {
  const s = readSaved();
  return !!s && s.url === url;
}

export class WireFailure extends Error {
  constructor(readonly wire: WireError) {
    super(wire.text || wire.code);
    this.name = 'WireFailure';
  }
}

type EventHandler<K extends keyof Events> = (data: Events[K]) => void;

export interface ConnectionHooks {
  onState?: (state: ConnState, detail?: string) => void;
  onTrace?: (entry: TraceEntry) => void;
  /** A full roster replacement: the login snapshot, or a `sync` after
   *  the outbox overflowed. Everything else arrives as events. */
  onSnapshot?: (ok: { self: User; users: User[]; server: SyncOk['server'] }) => void;
  onLogin?: (ok: LoginOk) => void;
  /** Resume succeeded; `replay` events are about to arrive. */
  onResumed?: (replay: number) => void;
  /** The session is gone for good — kicked, logged out, banned, or the
   *  grace window lapsed. No further reconnection will be attempted. */
  onEnded?: (reason: string) => void;
}

export class Connection {
  private ws: WebSocket | null = null;
  private nextId = 0;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  private handlers = new Map<string, Set<(data: any) => void>>();
  private retry = 0;
  private resumeOnly = false;
  /** Has the app been handed a roster yet in this page load? A resume
   *  replays events but never re-sends the user list, so a client that
   *  resumed into a session it did not itself log into has to ask. */
  private gotSnapshot = false;
  private retryTimer: number | null = null;
  private closing = false;

  state: ConnState = 'offline';
  /** The last seq we have actually processed. Resume's `last_seq`. */
  seq = 0;
  session: string | null = null;
  token: string | null = null;
  self: User | null = null;
  caps: string[] = [];
  grace: number | null = null;
  login: LoginOk | null = null;
  /** The video ceilings, from the login reply or from the saved session
   *  a resume came back through. */
  video: VideoConfig | null = null;
  /** Round-trip time of the last explicit `ping`, in milliseconds. */
  rtt: number | null = null;

  constructor(
    private creds: Credentials,
    private hooks: ConnectionHooks = {},
  ) {}

  // --- lifecycle --------------------------------------------------------

  /** Connect and log in. If this tab has a live session for the same
   *  server, try to resume into it first — a page reload should not cost
   *  you your place in the room.
   *
   *  `resumeOnly` is for exactly that reload: the password was never
   *  stored, so falling back to a fresh login would send an empty one
   *  and get `login_failed` for an account that is perfectly fine. Fail
   *  the resume instead and let the caller ask for the password. */
  async start(opts: { resumeOnly?: boolean } = {}): Promise<void> {
    this.closing = false;
    const saved = readSaved();
    if (saved && saved.url === this.creds.url) {
      this.session = saved.session;
      this.token = saved.token;
      this.seq = saved.seq;
      this.caps = saved.caps ?? [];
      this.grace = saved.grace ?? null;
      this.video = saved.video ?? null;
    } else if (opts.resumeOnly) {
      throw new Error('no session to resume');
    }
    this.resumeOnly = opts.resumeOnly ?? false;
    await this.attach();
  }

  /** End the session now, with no grace window. */
  async logout(): Promise<void> {
    this.closing = true;
    this.cancelRetry();
    try {
      await this.request('logout', {});
    } catch {
      /* the socket dying during logout is a successful logout */
    }
    clearSaved();
    this.ws?.close();
    this.setState('offline');
  }

  /** Drop the socket without ending the session — the manual version of
   *  closing a laptop lid, and the only way to exercise resume by hand. */
  drop(): void {
    this.ws?.close();
  }

  private async attach(): Promise<void> {
    this.setState(this.session ? 'reconnecting' : 'connecting');
    const ws = new WebSocket(this.creds.url);
    this.ws = ws;

    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error(`Could not reach ${this.creds.url}`));
      ws.onclose = () => reject(new Error(`Could not reach ${this.creds.url}`));
    });

    ws.onmessage = (e) => this.onMessage(String(e.data));
    ws.onerror = null;
    ws.onclose = (e) => this.onClose(e);

    if (this.session && this.token) {
      const ok = await this.tryResume();
      if (ok) return;
      if (this.resumeOnly) {
        this.closing = true;
        ws.close();
        throw new Error('session expired');
      }
    }
    await this.doLogin();
  }

  private async doLogin(): Promise<void> {
    const params: LoginParams = {
      login: this.creds.login,
      password: this.creds.password,
      icon: this.creds.icon,
    };
    if (this.creds.nick) params.nick = this.creds.nick;

    const ok = await this.request<LoginOk>('login', params);
    this.session = ok.session;
    this.token = ok.token;
    this.self = ok.self;
    this.caps = ok.caps ?? [];
    this.grace = ok.detach ? ok.detach.grace : null;
    this.seq = ok.seq ?? 0;
    this.login = ok;
    this.video = ok.video ?? null;
    // Only a session that may detach is worth remembering: without the
    // permission a resume can only ever answer session_expired, and
    // storing a token we know is useless just invites a confusing
    // reconnect on the next page load.
    if (ok.detach) this.persist();
    this.gotSnapshot = true;
    this.retry = 0;
    this.setState('online');
    this.hooks.onLogin?.(ok);
    this.hooks.onSnapshot?.({ self: ok.self, users: ok.users, server: ok.server });
  }

  /** Returns true when the session was recovered (with or without a
   *  resync), false when it is gone and a fresh login is needed. */
  private async tryResume(): Promise<boolean> {
    try {
      const ok = await this.request<ResumeOk>('resume', {
        session: this.session,
        token: this.token,
        last_seq: this.seq,
      });
      this.self = ok.self;
      this.retry = 0;
      this.setState('online');
      this.hooks.onResumed?.(ok.replay);
      // A resume into a session this page load never logged into — the
      // reload case — has a `self` and a replay but no user list. `sync`
      // is the spec's answer for exactly that, and asking for it costs
      // one round trip against re-typing a password.
      if (!this.gotSnapshot) await this.snapshot();
      return true;
    } catch (e) {
      if (!(e instanceof WireFailure)) throw e;
      if (e.wire.code !== RESYNC_REQUIRED) {
        // session_expired and friends: the session is gone, but the
        // socket is fine — log in on it rather than opening another.
        this.session = null;
        this.token = null;
        this.seq = 0;
        clearSaved();
        return false;
      }
      // The session lives; only the replay is unrecoverable. Take a
      // fresh snapshot and continue from the seq it reports.
      const ok = await this.snapshot();
      this.seq = ok.seq;
      this.retry = 0;
      this.setState('online');
      return true;
    }
  }

  /** `sync`: the roster and server info, without disturbing the session. */
  private async snapshot(): Promise<SyncOk> {
    const ok = await this.request<SyncOk>('sync', {});
    this.gotSnapshot = true;
    if (this.self) this.hooks.onSnapshot?.({ self: this.self, users: ok.users, server: ok.server });
    return ok;
  }

  private onClose(e: CloseEvent): void {
    for (const p of this.pending.values()) p.reject(new Error('connection closed'));
    this.pending.clear();
    this.ws = null;
    if (this.closing) return;

    // The server names the two closes that mean "do not come back".
    // `replaced` is another device taking the session over — last device
    // wins is the mobile-friendly answer, and this one lost.
    const reason = e.reason || '';
    if (reason === 'replaced') return this.end('This session was taken over by another connection.');
    if (reason === 'kicked') return this.end('You were disconnected by an administrator.');
    if (reason === 'logout') return this.end('Logged out.');

    if (this.grace === null && this.session) {
      // This account cannot detach, so the session died with the socket.
      // Reconnecting means logging in fresh, which is fine — but do not
      // pretend the old session is recoverable.
      this.session = null;
      this.token = null;
      this.seq = 0;
      clearSaved();
    }
    this.scheduleRetry();
  }

  private end(reason: string): void {
    this.closing = true;
    this.cancelRetry();
    clearSaved();
    this.session = null;
    this.token = null;
    this.setState('offline', reason);
    this.hooks.onEnded?.(reason);
  }

  /** Exponential backoff, capped well inside a five-minute grace window
   *  so a flaky network never sleeps through its own chance to resume. */
  private scheduleRetry(): void {
    const delay = Math.min(500 * 2 ** this.retry, 15000);
    this.retry++;
    this.setState('reconnecting', `retrying in ${(delay / 1000).toFixed(1)}s`);
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null;
      this.attach().catch((e) => {
        if (e instanceof WireFailure) return this.end(e.wire.text || e.wire.code);
        this.scheduleRetry();
      });
    }, delay);
  }

  private cancelRetry(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  // --- frames -----------------------------------------------------------

  request<T = unknown>(req: string, params: unknown = {}): Promise<T> {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('not connected'));
    }
    const id = ++this.nextId;
    const raw = JSON.stringify({ id, req, params });
    this.trace('out', req, raw);
    ws.send(raw);
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
  }

  async ping(): Promise<number> {
    const t0 = performance.now();
    await this.request('ping', {});
    this.rtt = Math.round(performance.now() - t0);
    return this.rtt;
  }

  private onMessage(raw: string): void {
    let frame: ServerFrame;
    try {
      frame = JSON.parse(raw) as ServerFrame;
    } catch {
      this.trace('in', 'unparseable', raw, true);
      return;
    }
    if (isReply(frame)) return this.onReply(frame, raw);
    if (isEvent(frame)) return this.onEvent(frame, raw);
    this.trace('in', 'unknown', raw, true);
  }

  private onReply(frame: ReplyFrame, raw: string): void {
    this.trace('in', `reply:${frame.error ? frame.error.code : 'ok'}`, raw, !!frame.error);
    const p = this.pending.get(frame.reply);
    if (!p) return;
    this.pending.delete(frame.reply);
    if (frame.error) p.reject(new WireFailure(frame.error));
    else p.resolve(frame.ok ?? {});
  }

  private onEvent(frame: EventFrame, raw: string): void {
    this.trace('in', `ev:${frame.ev}`, raw);
    // Seq accounting comes first and applies to *every* event, including
    // the ones this client does not understand. The server promises the
    // stream is gapless; honouring that promise is what makes a later
    // resume able to pick up exactly where we left off.
    this.seq = frame.seq;
    this.persist();
    const set = this.handlers.get(frame.ev);
    if (!set) return; // unknown `ev` values are ignored, per spec
    for (const h of set) h(frame.data);
  }

  on<K extends keyof Events>(ev: K, handler: EventHandler<K>): void {
    let set = this.handlers.get(ev);
    if (!set) this.handlers.set(ev, (set = new Set()));
    set.add(handler as (data: any) => void);
  }

  /** Keep the tab's resume record current. A session that cannot detach
   *  is never worth storing — a resume for it can only answer
   *  `session_expired`. */
  private persist(): void {
    if (!this.session || !this.token || this.grace === null) return;
    saveSession({
      url: this.creds.url,
      session: this.session,
      token: this.token,
      seq: this.seq,
      caps: this.caps,
      grace: this.grace,
      video: this.video,
    });
  }

  private trace(dir: 'out' | 'in', kind: string, raw: string, error = false): void {
    this.hooks.onTrace?.({ t: Date.now(), dir, kind, raw, error });
  }

  private setState(state: ConnState, detail?: string): void {
    this.state = state;
    this.hooks.onState?.(state, detail);
  }
}

// --- session storage ----------------------------------------------------

function readSaved(): Saved | null {
  try {
    const raw = sessionStorage.getItem(SAVED_KEY);
    return raw ? (JSON.parse(raw) as Saved) : null;
  } catch {
    return null;
  }
}

function saveSession(s: Saved): void {
  try {
    sessionStorage.setItem(SAVED_KEY, JSON.stringify(s));
  } catch {
    /* private browsing, storage disabled — resume across reloads is a
       convenience, never a correctness requirement */
  }
}

function clearSaved(): void {
  try {
    sessionStorage.removeItem(SAVED_KEY);
  } catch {
    /* as above */
  }
}
