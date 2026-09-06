/**
 * The client shell: it owns the connection, the store, and the layout
 * that shows them.
 *
 * The wiring principle throughout is that the server is the source of
 * truth. Nothing is drawn optimistically off the back of a request — a
 * line of chat appears when the `chat` event carrying it arrives, which
 * is also how the sender sees their own line, because a Hotline server
 * echoes chat to everyone including its author. Private messages are the
 * one exception the protocol forces: `msg` has no echo, so the sender's
 * own half of a PM is added locally and marked as such.
 */

import { LOBBY, pmId, type ConvId, type Line, Store, styleToKind } from '../state';
import {
  Connection,
  hasSavedSession,
  type ConnState,
  type Credentials,
  WireFailure,
} from '../wire/connection';
import { errorText, type User } from '../wire/protocol';
import { connectScreen, remembered, type Details } from './connect';
import { DebugPanel } from './debug';
import { clock, fill, h } from './dom';
import { icon } from './icons';
import { pickIcon } from './iconpicker';
import { captureBlockedReason, Media, screenShareBlockedReason } from './media';
import { renderRoster } from './roster';
import { appendLine, isAtBottom, renderTranscript, scrollToEnd } from './transcript';

const THEME_KEY = 'hxd-ng.theme';
type Theme = 'auto' | 'dark' | 'light';

export class App {
  private store = new Store();
  private conn: Connection | null = null;
  private media: Media | null = null;
  private debug: DebugPanel;
  private pingTimer: number | null = null;
  private url = '';

  // Long-lived DOM.
  private shell = h('div', { class: 'app', hidden: true });
  private serverName = h('strong', { class: 'server-name' });
  private subject = h('span', { class: 'subject' });
  private pill = h('button', { class: 'pill', title: 'Connection state' });
  private rail = h('nav', { class: 'rail' });
  private callbar = h('div', { class: 'callbar', hidden: true });
  private transcript = h('div', { class: 'transcript' });
  private composer = h('textarea', {
    class: 'composer-input',
    rows: 1,
    placeholder: 'Say something…',
    spellcheck: true,
  });
  private composerHint = h('span', { class: 'composer-hint' });
  private rosterEl = h('aside', { class: 'roster' });
  private scrim = h('div', { class: 'scrim' });
  private peopleBtn = h(
    'button',
    { class: 'ghost people-toggle', title: 'Show the user list' },
    'People',
  );
  private meButton = h('button', { class: 'identity', title: 'Change your icon' });

  constructor(private root: HTMLElement) {
    this.debug = new DebugPanel(
      () => this.facts(),
      () => this.media?.stats() ?? Promise.resolve({ media: 'not connected' }),
    );
    this.buildShell();
    this.applyTheme(readTheme());

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        this.debug.toggle();
      }
      if (e.key === 'Escape' && document.body.classList.contains('show-roster')) {
        this.showRoster(false);
      }
    });
  }

  mount(): void {
    const screen = connectScreen((d) => this.connect(d));
    this.root.append(screen, this.shell, this.debug.el);
    // `?debug` opens the drawer before the first frame, which is what you
    // want when the thing you are debugging is the login itself.
    if (new URLSearchParams(location.search).has('debug')) this.debug.toggle(true);

    // A reload is a dropped connection like any other: if this tab still
    // holds a session for the server it was last on, go straight back
    // into it rather than making someone log in again to reach the room
    // they never left.
    const saved = remembered();
    if (hasSavedSession(saved.url)) {
      screen.hidden = true;
      const splash = h('div', { class: 'connect' }, h('p', { class: 'muted' }, 'Resuming your session…'));
      this.root.prepend(splash);
      this.connect(saved, { resumeOnly: true })
        .catch(() => {
          screen.hidden = false;
        })
        .finally(() => splash.remove());
    }
  }

  // --- connecting -------------------------------------------------------

  private async connect(d: Details, opts: { resumeOnly?: boolean } = {}): Promise<void> {
    const creds: Credentials = { ...d };
    const conn = new Connection(creds, {
      onTrace: (e) => this.debug.push(e),
      onState: (s, detail) => this.onState(s, detail),
      onLogin: (ok) => {
        this.store.server = ok.server;
        if (this.media) this.media.limits = ok.video ?? null;
        if (ok.server.agreement) {
          this.store.add(LOBBY, {
            t: Date.now(),
            kind: 'notice',
            text: ok.server.agreement,
          });
        }
      },
      onSnapshot: ({ self, users, server }) => {
        this.store.self = self;
        this.store.server = server;
        this.store.replaceRoster(users);
        this.renderAll();
      },
      onResumed: (replay) => {
        this.say(
          replay > 0
            ? `Reconnected — ${replay} ${replay === 1 ? 'message' : 'messages'} replayed.`
            : 'Reconnected.',
        );
      },
      onEnded: (reason) => {
        this.say(reason);
        this.media?.teardown();
        if (this.pingTimer !== null) {
          clearInterval(this.pingTimer);
          this.pingTimer = null;
        }
      },
    });
    this.conn = conn;
    this.media = new Media(conn, {
      onLog: (text, bad) => this.say(bad ? `Media error: ${text}` : text),
      onRoom: () => this.renderRoster(),
      onControls: () => this.renderCallbar(),
      nickOf: (uid) => this.store.nickOf(uid),
    });
    this.bindEvents(conn);

    try {
      await conn.start(opts);
    } catch (e) {
      this.conn = null;
      this.media = null;
      throw new Error(
        e instanceof WireFailure ? errorText(e.wire) : e instanceof Error ? e.message : String(e),
      );
    }

    for (const el of this.root.querySelectorAll('.connect')) el.remove();
    this.shell.hidden = false;
    this.url = d.url;
    this.media.limits = conn.video;
    this.mountTiles();
    this.renderAll();
    this.composer.focus();
    this.pingTimer = window.setInterval(() => {
      if (conn.state === 'online') void conn.ping().then(() => this.renderPill());
    }, 15000);
  }

  private bindEvents(conn: Connection): void {
    conn.on('user_joined', (d) => {
      this.store.put(d.user);
      this.push(LOBBY, { t: Date.now(), kind: 'notice', text: `${d.user.nick} joined.` });
      this.renderRoster();
    });

    conn.on('user_changed', (d) => {
      const before = this.store.user(d.user.uid);
      this.store.put(d.user);
      if (before && before.nick !== d.user.nick) {
        this.push(LOBBY, {
          t: Date.now(),
          kind: 'notice',
          text: `${before.nick} is now known as ${d.user.nick}.`,
        });
        const pm = this.store.conversation(pmId(d.user.uid));
        if (pm) pm.title = d.user.nick;
      }
      if (d.user.uid === this.store.self?.uid) this.store.self = d.user;
      this.renderRoster();
      this.renderRail();
      this.renderMe();
    });

    conn.on('user_parted', (d) => {
      const gone = this.store.remove(d.uid);
      this.push(LOBBY, {
        t: Date.now(),
        kind: 'notice',
        text: `${gone?.nick ?? `uid ${d.uid}`} left.`,
      });
      this.renderRoster();
    });

    conn.on('chat', (d) => {
      this.push(LOBBY, {
        t: Date.now(),
        kind: styleToKind(d.style),
        from: d.from,
        text: d.text,
      });
    });

    conn.on('msg', (d) => {
      const conv = this.store.openPm(d.from.uid, d.from.nick);
      this.push(conv.id, { t: Date.now(), kind: 'chat', from: d.from, text: d.text });
      this.renderRail();
    });

    conn.on('notice', (d) => {
      this.push(LOBBY, { t: Date.now(), kind: 'notice', text: d.text });
    });

    conn.on('broadcast', (d) => {
      this.push(LOBBY, { t: Date.now(), kind: 'broadcast', from: d.from, text: d.text });
    });

    conn.on('subject', (d) => {
      this.store.server = { ...this.store.server, subject: d.subject };
      this.renderTopbar();
      this.push(LOBBY, { t: Date.now(), kind: 'notice', text: `Subject: ${d.subject}` });
    });

    conn.on('kicked', () => {
      this.push(LOBBY, {
        t: Date.now(),
        kind: 'notice',
        text: 'You were disconnected by an administrator.',
      });
    });
  }

  private onState(s: ConnState, detail?: string): void {
    this.renderPill(detail);
    if (s !== 'online' && this.media?.joined) {
      // A dropped socket takes the peer connection with it: the SFU's
      // session is keyed to ours and there is nothing to salvage. Voice
      // is rejoined by hand after a resume, deliberately — nobody wants
      // their microphone reopened without being asked.
      this.media.teardown();
      this.say('Voice ended with the connection.');
    }
  }

  // --- sending ----------------------------------------------------------

  private async send(text: string): Promise<void> {
    const conn = this.conn;
    if (!conn) return;
    if (text.startsWith('/')) return this.command(text);

    const conv = this.store.conversation(this.store.active);
    if (conv?.kind === 'pm' && conv.uid !== undefined) {
      await conn.request('msg', { to: conv.uid, text });
      // PMs have no echo, so the sender's own half is local.
      const me = this.store.self;
      this.push(conv.id, {
        t: Date.now(),
        kind: 'chat',
        from: { uid: me?.uid ?? 0, nick: me?.nick ?? 'you' },
        text,
        local: true,
      });
      return;
    }
    await conn.request('chat', { text });
  }

  private async command(raw: string): Promise<void> {
    const conn = this.conn;
    if (!conn) return;
    const [word, ...rest] = raw.slice(1).split(' ');
    const arg = rest.join(' ');
    switch ((word ?? '').toLowerCase()) {
      case 'me':
        if (arg) await conn.request('chat', { text: arg, style: 'action' });
        return;
      case 'msg': {
        const [who, ...words] = rest;
        const target = who ? this.findUser(who) : undefined;
        if (!target) return this.say(`No such user: ${who ?? '(nobody)'}`);
        const conv = this.store.openPm(target.uid, target.nick);
        this.select(conv.id);
        if (words.length) await this.send(words.join(' '));
        return;
      }
      case 'nick':
        if (!arg) return this.say('Usage: /nick <name>');
        await conn.request('nick', { nick: arg });
        return;
      case 'icon': {
        const id = Number(arg);
        if (!Number.isInteger(id)) return this.say('Usage: /icon <number>');
        await conn.request('nick', { icon: id });
        return;
      }
      case 'drop':
        // The manual version of losing your network, so resume can be
        // exercised without unplugging anything.
        this.say('Dropping the socket; the session should resume.');
        conn.drop();
        return;
      case 'clear': {
        const conv = this.store.conversation(this.store.active);
        if (conv) conv.lines.length = 0;
        this.renderTranscript();
        return;
      }
      case 'close':
        this.closeConversation(this.store.active);
        return;
      case 'logout':
        await conn.logout();
        location.reload();
        return;
      case 'debug':
        this.debug.toggle();
        return;
      case 'help':
        return this.say(
          '/me · /msg <nick> <text> · /nick <name> · /icon <n> · /clear · /close · /drop · /debug · /logout',
        );
      default:
        return this.say(`Unknown command: /${word}`);
    }
  }

  private findUser(needle: string): User | undefined {
    const byId = Number(needle);
    if (Number.isInteger(byId) && this.store.user(byId)) return this.store.user(byId);
    const lower = needle.toLowerCase();
    return this.store.roster().find((u) => u.nick.toLowerCase() === lower)
      ?? this.store.roster().find((u) => u.nick.toLowerCase().startsWith(lower));
  }

  // --- conversations ----------------------------------------------------

  private select(id: ConvId): void {
    const conv = this.store.conversation(id);
    if (!conv) return;
    this.store.active = id;
    conv.unread = 0;
    this.renderRail();
    this.renderTranscript();
    this.renderComposerHint();
    this.composer.focus();
  }

  private closeConversation(id: ConvId): void {
    if (id === LOBBY) return;
    this.store.closePm(id);
    this.renderRail();
    this.renderTranscript();
    this.renderComposerHint();
  }

  private push(id: ConvId, line: Line): void {
    const conv = this.store.add(id, line);
    if (!conv) return;
    if (id === this.store.active) appendLine(this.transcript, line, conv, this.store);
    else this.renderRail();
    this.renderUnreadTitle();
  }

  /** Something this client wants to say about itself. */
  private say(text: string): void {
    this.push(this.store.active, { t: Date.now(), kind: 'system', text, local: true });
  }

  // --- rendering --------------------------------------------------------

  private renderAll(): void {
    this.renderTopbar();
    this.renderRail();
    this.renderRoster();
    this.renderTranscript();
    this.renderCallbar();
    this.renderPill();
    this.renderMe();
    this.renderComposerHint();
  }

  private renderTopbar(): void {
    this.serverName.textContent = this.store.server.name || 'Hotline';
    this.subject.textContent = this.store.server.subject || '';
    this.subject.hidden = !this.store.server.subject;
  }

  private renderPill(detail?: string): void {
    const conn = this.conn;
    const state = conn?.state ?? 'offline';
    const label =
      state === 'online'
        ? conn?.rtt !== null && conn?.rtt !== undefined
          ? `online · ${conn.rtt} ms`
          : 'online'
        : state === 'reconnecting'
          ? 'reconnecting'
          : state === 'connecting'
            ? 'connecting'
            : 'offline';
    this.pill.className = `pill ${state}`;
    this.pill.textContent = label;
    this.pill.title = detail ?? (conn?.grace ? `Grace window: ${conn.grace}s` : 'This account cannot detach');
  }

  private renderMe(): void {
    const me = this.store.self;
    if (!me) return;
    fill(this.meButton, icon(me.icon, 2), h('span', { class: 'nick' }, me.nick));
  }

  private renderRail(): void {
    const items = [...this.store.conversations.values()].map((c) => {
      const active = c.id === this.store.active;
      const el = h(
        'button',
        { class: `rail-item${active ? ' on' : ''}${c.unread ? ' unread' : ''}` },
        c.kind === 'lobby'
          ? h('span', { class: 'rail-glyph' }, '#')
          : icon(this.store.user(c.uid!)?.icon ?? 128, 1),
        h('span', { class: 'rail-title' }, c.title),
        c.unread ? h('span', { class: 'badge' }, String(c.unread)) : null,
      );
      el.onclick = () => this.select(c.id);
      if (c.kind === 'pm') {
        const close = h('span', { class: 'rail-close', title: 'Close' }, '×');
        close.onclick = (e) => {
          e.stopPropagation();
          this.closeConversation(c.id);
        };
        el.append(close);
      }
      return el;
    });
    fill(this.rail, h('div', { class: 'rail-head' }, 'Conversations'), ...items);
  }

  private renderRoster(): void {
    if (!this.media) return;
    renderRoster(this.rosterEl, this.store, this.media, {
      onMessage: (u) => {
        this.select(this.store.openPm(u.uid, u.nick).id);
        this.showRoster(false);
      },
      onClose: () => this.showRoster(false),
    });
  }

  private renderTranscript(): void {
    const conv = this.store.conversation(this.store.active);
    if (conv) renderTranscript(this.transcript, conv, this.store);
  }

  private renderComposerHint(): void {
    const conv = this.store.conversation(this.store.active);
    const pm = conv?.kind === 'pm';
    this.composer.placeholder = pm ? `Message ${conv.title}…` : 'Say something…';
    this.composerHint.textContent = pm ? 'private message' : 'public chat';
  }

  private renderUnreadTitle(): void {
    const total = [...this.store.conversations.values()].reduce((n, c) => n + c.unread, 0);
    const name = this.store.server.name || 'Hotline';
    document.title = total ? `(${total}) ${name}` : name;
  }

  /** The voice and video controls, rebuilt from scratch on every change:
   *  the set of things you can do depends on what the server offers, what
   *  you have joined, and what you are publishing, and rebuilding is
   *  cheaper to reason about than patching six buttons in place. */
  private renderCallbar(): void {
    const media = this.media;
    if (!media || !media.hasVoice) {
      this.callbar.hidden = true;
      return;
    }
    this.callbar.hidden = false;
    const buttons: HTMLElement[] = [];
    const add = (label: string, on: boolean, fn: () => Promise<void>, cls = '') => {
      const b = h('button', { class: `call ${cls}${on ? ' on' : ''}` }, label);
      b.onclick = () => {
        b.disabled = true;
        fn()
          .catch((e: Error) => this.say(e instanceof WireFailure ? errorText(e.wire) : e.message))
          .finally(() => (b.disabled = false));
      };
      buttons.push(b);
    };

    // Capture permission is a property of how the page was *served*, not
    // of the server or the account, so it is checked here and reported
    // in the bar rather than discovered by a failed tap.
    const noCapture = captureBlockedReason();
    const disable = (why: string) => {
      const b = buttons[buttons.length - 1] as HTMLButtonElement;
      b.disabled = true;
      b.title = why;
    };

    if (!media.joined) {
      add('Join voice', false, () => media.join(), 'suggest');
      if (noCapture) disable(noCapture);
    } else {
      add(media.muted ? 'Unmute' : 'Mute', !media.muted, () => media.setMuted(!media.muted));
      add('Leave voice', false, () => media.leave());
      if (media.hasVideo) {
        const cam = media.publishing.includes('camera');
        add(cam ? 'Stop camera' : 'Camera', cam, () => media.toggleCamera());
        if (cam) add(media.camPaused ? 'Resume' : 'Pause', media.camPaused, () => media.togglePause());
        const scr = media.publishing.includes('screen');
        add(scr ? 'Stop sharing' : 'Share screen', scr, () => media.toggleShare());
        const noShare = scr ? null : screenShareBlockedReason();
        if (noShare) disable(noShare);
        add(
          media.watching ? 'Stop watching' : 'Watch video',
          media.watching,
          () => media.setWatching(!media.watching),
        );
      }
    }
    const detail = media.joined
      ? `${media.participants.length} in voice${media.codec ? ` · ${media.codec}` : ''}`
      : noCapture
        ? noCapture
        : media.hasVideo
          ? 'voice and video'
          : 'voice';
    fill(
      this.callbar,
      ...buttons,
      h('span', { class: `call-detail ${noCapture && !media.joined ? 'warn' : 'muted'}` }, detail),
    );
  }

  // --- shell ------------------------------------------------------------

  private buildShell(): void {
    // The roster is a column on a desktop and a slide-in panel on a
    // phone; this button only exists for the second case, and CSS is
    // what decides which case we are in.
    this.peopleBtn.onclick = () =>
      this.showRoster(!document.body.classList.contains('show-roster'));
    this.scrim.onclick = () => this.showRoster(false);

    const debugBtn = h('button', { class: 'ghost', title: 'Wire trace and session state (⇧⌘D)' }, 'Debug');
    debugBtn.onclick = () => this.debug.toggle();

    const themeBtn = h('button', { class: 'ghost', title: 'Theme' });
    const paintTheme = (t: Theme) => (themeBtn.textContent = t === 'auto' ? 'Auto' : t === 'dark' ? 'Dark' : 'Light');
    paintTheme(readTheme());
    themeBtn.onclick = () => {
      const next: Theme = readTheme() === 'auto' ? 'dark' : readTheme() === 'dark' ? 'light' : 'auto';
      this.applyTheme(next);
      paintTheme(next);
    };

    this.pill.onclick = () => this.debug.toggle(true);
    this.meButton.onclick = () => void this.editSelf();

    this.composer.onkeydown = (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const text = this.composer.value.trim();
        if (!text) return;
        this.composer.value = '';
        this.autoGrow();
        this.send(text).catch((err: Error) =>
          this.say(err instanceof WireFailure ? errorText(err.wire) : err.message),
        );
      }
    };
    this.composer.oninput = () => this.autoGrow();

    // Opening the debug drawer, or any other resize, must not silently
    // scroll the newest line out of view.
    let pinned = true;
    this.transcript.addEventListener('scroll', () => (pinned = isAtBottom(this.transcript)));
    new ResizeObserver(() => {
      if (pinned) scrollToEnd(this.transcript);
    }).observe(this.transcript);

    this.shell.append(
      h(
        'header',
        { class: 'topbar' },
        h('div', { class: 'server' }, this.serverName, this.subject),
        h('div', { class: 'spacer' }),
        this.meButton,
        this.pill,
        this.peopleBtn,
        themeBtn,
        debugBtn,
      ),
      h(
        'div',
        { class: 'panes' },
        this.rail,
        h(
          'main',
          {},
          this.callbar,
          h('div', { class: 'tiles-slot' }),
          this.transcript,
          h('div', { class: 'composer' }, this.composer, this.composerHint),
        ),
        // Both live inside `.panes` rather than the document, so the
        // slide-in panel is bounded by the pane area and never covers
        // the title bar — including the button that opens it.
        this.scrim,
        this.rosterEl,
      ),
    );
  }

  /** The video strip lives inside `main`, above the transcript, and is
   *  owned by the media layer — mounting it here keeps the two from
   *  needing to know each other's DOM. */
  private mountTiles(): void {
    const slot = this.shell.querySelector('.tiles-slot');
    if (slot && this.media && !this.media.tiles.isConnected) slot.append(this.media.tiles);
  }

  /** Open or close the narrow-layout roster panel.
   *
   *  A panel you cannot dismiss is worse than no panel, so there are
   *  four ways out and this is the one place that knows about all of
   *  them: the same button (which stays reachable because the panel is
   *  confined to the pane area), the scrim behind it, Escape, and
   *  picking someone to message. */
  private showRoster(open: boolean): void {
    document.body.classList.toggle('show-roster', open);
    this.peopleBtn.classList.toggle('on', open);
    this.peopleBtn.setAttribute('aria-expanded', String(open));
    this.peopleBtn.title = open ? 'Hide the user list' : 'Show the user list';
  }

  private async editSelf(): Promise<void> {
    const me = this.store.self;
    const conn = this.conn;
    if (!me || !conn) return;
    const id = await pickIcon(me.icon);
    if (id === null || id === me.icon) return;
    try {
      await conn.request('nick', { icon: id });
    } catch (e) {
      this.say(e instanceof WireFailure ? errorText(e.wire) : String(e));
    }
  }

  private autoGrow(): void {
    this.composer.style.height = 'auto';
    this.composer.style.height = `${Math.min(this.composer.scrollHeight, 160)}px`;
  }

  private applyTheme(t: Theme): void {
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    try {
      localStorage.setItem(THEME_KEY, t);
    } catch {
      /* storage disabled; the theme simply resets next load */
    }
  }

  private facts(): Record<string, unknown> {
    const c = this.conn;
    return {
      'client time': clock(),
      url: this.url || '—',
      state: c?.state ?? 'offline',
      session: c?.session ?? '—',
      'token held': c?.token ? 'yes (not shown)' : 'no',
      uid: c?.self?.uid ?? '—',
      nick: c?.self?.nick ?? '—',
      icon: c?.self?.icon ?? '—',
      admin: c?.self?.admin ?? '—',
      status: c?.self?.status ?? '—',
      seq: c?.seq ?? 0,
      'ping rtt': c?.rtt !== null && c?.rtt !== undefined ? `${c.rtt} ms` : '—',
      'detach grace': c?.grace !== null && c?.grace !== undefined ? `${c.grace}s` : 'not permitted',
      caps: c?.caps ?? [],
      'video limits': c?.video ?? null,
      server: this.store.server.name,
      subject: this.store.server.subject,
      roster: this.store.users.size,
      conversations: [...this.store.conversations.keys()],
    };
  }
}

function readTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY);
    if (t === 'dark' || t === 'light' || t === 'auto') return t;
  } catch {
    /* fall through */
  }
  return 'auto';
}
