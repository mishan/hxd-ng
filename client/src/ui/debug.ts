/**
 * The debug drawer: every frame this client sent or received, the
 * session's own bookkeeping, and whatever the media layer knows.
 *
 * This is deliberately a first-class part of the client rather than a
 * developer afterthought. Two audiences need it and want the same thing:
 * someone writing a server handler wants to see the exact bytes their
 * change produced, and someone filing a bug wants to attach them. So the
 * trace is the same string the socket carried, in order, with a Copy
 * button that packages it with the session state a maintainer will ask
 * for anyway.
 *
 * Nothing here is sampled or summarised — if it crossed the wire, it is
 * in the list.
 */

import type { TraceEntry } from '../wire/connection';
import { fill, h } from './dom';

/** Frames kept in the ring. Big enough to hold a login plus a long
 *  conversation; small enough that a room left open for a day does not
 *  eat the tab's memory. */
const MAX_FRAMES = 1500;

export type Facts = () => Record<string, unknown>;

type Tab = 'wire' | 'session' | 'media';

export class DebugPanel {
  readonly el: HTMLElement;
  private list: HTMLElement;
  private facts: HTMLElement;
  private mediaEl: HTMLElement;
  private filterInput: HTMLInputElement;
  private frames: TraceEntry[] = [];
  private tab: Tab = 'wire';
  private paused = false;
  private filter = '';
  private timer: number | null = null;

  open = false;

  constructor(
    private sessionFacts: Facts,
    private mediaFacts: () => Promise<Record<string, unknown>>,
  ) {
    this.list = h('div', { class: 'trace' });
    this.facts = h('div', { class: 'facts' });
    this.mediaEl = h('div', { class: 'facts' });
    this.filterInput = h('input', {
      class: 'filter',
      type: 'search',
      placeholder: 'filter frames…',
      spellcheck: false,
    });
    this.filterInput.oninput = () => {
      this.filter = this.filterInput.value.toLowerCase();
      this.redrawTrace();
    };

    const pauseBtn = h('button', { class: 'ghost', title: 'Stop appending new frames' }, 'Pause');
    pauseBtn.onclick = () => {
      this.paused = !this.paused;
      pauseBtn.textContent = this.paused ? 'Resume' : 'Pause';
      pauseBtn.classList.toggle('on', this.paused);
      if (!this.paused) this.redrawTrace();
    };
    const clearBtn = h('button', { class: 'ghost' }, 'Clear');
    clearBtn.onclick = () => {
      this.frames = [];
      this.redrawTrace();
    };
    const copyBtn = h('button', { class: 'ghost' }, 'Copy report');
    copyBtn.onclick = () => {
      void this.copyReport(copyBtn);
    };

    const tabs = (['wire', 'session', 'media'] as Tab[]).map((t) => {
      const b = h('button', { class: `tab ${t === this.tab ? 'on' : ''}`, dataset: { tab: t } },
        t === 'wire' ? 'Wire' : t === 'session' ? 'Session' : 'Media');
      b.onclick = () => this.select(t);
      return b;
    });

    this.el = h(
      'section',
      { class: 'debug', hidden: true },
      h(
        'header',
        { class: 'debug-bar' },
        h('div', { class: 'tabs' }, ...tabs),
        h('div', { class: 'spacer' }),
        this.filterInput,
        pauseBtn,
        clearBtn,
        copyBtn,
      ),
      h('div', { class: 'debug-body' }, this.list, this.facts, this.mediaEl),
    );
    this.select('wire');
  }

  toggle(force?: boolean): void {
    this.open = force ?? !this.open;
    this.el.hidden = !this.open;
    document.body.classList.toggle('debug-open', this.open);
    if (this.open) {
      // The trace is collected from the first frame but only drawn while
      // the drawer is up, so opening it has to catch the list up with
      // the ring buffer — otherwise the login you wanted to look at is
      // exactly the part that is missing.
      if (this.tab === 'wire') this.redrawTrace();
      this.refreshFacts();
      this.timer ??= window.setInterval(() => this.refreshFacts(), 1000);
    } else if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private select(t: Tab): void {
    this.tab = t;
    for (const b of this.el.querySelectorAll<HTMLElement>('.tab')) {
      b.classList.toggle('on', b.dataset.tab === t);
    }
    this.list.hidden = t !== 'wire';
    this.facts.hidden = t !== 'session';
    this.mediaEl.hidden = t !== 'media';
    this.filterInput.hidden = t !== 'wire';
    if (t === 'wire') this.redrawTrace();
    else this.refreshFacts();
  }

  /** Called for every frame, open or closed — the trace has to be
   *  complete from the first login, not from whenever someone thought to
   *  open the drawer. */
  push(entry: TraceEntry): void {
    this.frames.push(entry);
    if (this.frames.length > MAX_FRAMES) this.frames.splice(0, this.frames.length - MAX_FRAMES);
    if (this.paused || !this.open || this.tab !== 'wire') return;
    if (!this.matches(entry)) return;
    const atBottom =
      this.list.scrollHeight - this.list.scrollTop - this.list.clientHeight < 40;
    this.list.append(this.row(entry));
    while (this.list.childElementCount > MAX_FRAMES) this.list.firstElementChild?.remove();
    if (atBottom) this.list.scrollTop = this.list.scrollHeight;
  }

  private matches(e: TraceEntry): boolean {
    if (!this.filter) return true;
    return e.kind.toLowerCase().includes(this.filter) || e.raw.toLowerCase().includes(this.filter);
  }

  private row(e: TraceEntry): HTMLElement {
    const time = new Date(e.t);
    const stamp = `${String(time.getHours()).padStart(2, '0')}:${String(
      time.getMinutes(),
    ).padStart(2, '0')}:${String(time.getSeconds()).padStart(2, '0')}.${String(
      time.getMilliseconds(),
    ).padStart(3, '0')}`;
    return h(
      'div',
      { class: `frame ${e.dir}${e.error ? ' bad' : ''}` },
      h('span', { class: 'stamp' }, stamp),
      h('span', { class: 'arrow' }, e.dir === 'out' ? '→' : '←'),
      h('span', { class: 'kind' }, e.kind),
      h('span', { class: 'raw' }, e.raw),
    );
  }

  private redrawTrace(): void {
    fill(this.list, ...this.frames.filter((e) => this.matches(e)).map((e) => this.row(e)));
    this.list.scrollTop = this.list.scrollHeight;
  }

  private refreshFacts(): void {
    if (!this.open) return;
    if (this.tab === 'session') fill(this.facts, ...factRows(this.sessionFacts()));
    else if (this.tab === 'media') {
      void this.mediaFacts().then((f) => fill(this.mediaEl, ...factRows(f)));
    }
  }

  /** Everything a maintainer would ask for, on the clipboard in one
   *  click: what the client is, what the server said it was, and the
   *  frames that led here. */
  private async copyReport(btn: HTMLElement): Promise<void> {
    const facts = this.sessionFacts();
    const lines = [
      `hxd-ng web client — debug report`,
      `generated: ${new Date().toISOString()}`,
      `user agent: ${navigator.userAgent}`,
      '',
      '## session',
      ...Object.entries(facts).map(([k, v]) => `${k}: ${format(v)}`),
      '',
      `## wire (${this.frames.length} frames)`,
      ...this.frames.map(
        (e) => `${new Date(e.t).toISOString()} ${e.dir === 'out' ? '-->' : '<--'} ${e.raw}`,
      ),
    ];
    const text = lines.join('\n');
    const was = btn.textContent;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'Copied';
    } catch {
      // Clipboard access needs a secure context and can be refused;
      // falling back to a download keeps the button honest.
      const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      const a = h('a', { href: url, download: 'hxd-ng-debug.txt' });
      a.click();
      URL.revokeObjectURL(url);
      btn.textContent = 'Saved';
    }
    setTimeout(() => (btn.textContent = was), 1400);
  }
}

function factRows(facts: Record<string, unknown>): HTMLElement[] {
  return Object.entries(facts).map(([k, v]) =>
    h('div', { class: 'fact' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, format(v))),
  );
}

function format(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}
