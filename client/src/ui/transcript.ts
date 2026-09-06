/** Rendering chat.
 *
 * Hotline's own layout was `\r%13.13s:  %s` — the nick right-aligned in
 * a thirteen-character column, then the text. That alignment is the
 * reason a Hotline window is so easy to read at a glance, and it is kept
 * here: a fixed nick column, right-aligned, with the message body
 * starting on one shared left edge. What is *not* kept is the
 * thirteen-byte truncation, which existed because the server was
 * formatting into a fixed-width buffer; the ng wire hands us
 * `{from, text, style}` and lets the client lay it out.
 *
 * Runs of lines from one person collapse into one labelled block, the
 * modern convention, which costs nothing and reads better than the same
 * name repeated eleven times.
 */

import type { Conversation, Line } from '../state';
import type { Store } from '../state';
import { clock, fill, h, linkify } from './dom';
import { icon } from './icons';

/** Chat-gutter icons stay at 1× — at 2× they compete with the text for
 *  attention, and the roster is where you go to look at people. */
const CHAT_SCALE = 1;

export function renderTranscript(el: HTMLElement, conv: Conversation, store: Store): void {
  const nodes: HTMLElement[] = [];
  let prev: Line | undefined;
  for (const line of conv.lines) {
    nodes.push(lineEl(line, prev, store));
    prev = line;
  }
  fill(el, ...nodes);
  scrollToEnd(el);
}

export function appendLine(el: HTMLElement, line: Line, conv: Conversation, store: Store): void {
  const atBottom = isAtBottom(el);
  const prev = conv.lines[conv.lines.length - 2];
  el.append(lineEl(line, prev, store));
  while (el.childElementCount > conv.lines.length) el.firstElementChild?.remove();
  if (atBottom) scrollToEnd(el);
}

export function isAtBottom(el: HTMLElement): boolean {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 48;
}

export function scrollToEnd(el: HTMLElement): void {
  el.scrollTop = el.scrollHeight;
}

/** The clock is printed only when it changes. A room where thirty lines
 *  all say 03:46 has spent a column telling you nothing; the full
 *  timestamp stays on the line's tooltip either way. */
function stamp(line: Line, prev: Line | undefined): string {
  const now = clock(line.t);
  return prev && clock(prev.t) === now ? '' : now;
}

function lineEl(line: Line, prev: Line | undefined, store: Store): HTMLElement {
  if (line.kind !== 'chat') return eventLine(line, prev);

  const from = line.from;
  const sameSpeaker =
    prev?.kind === 'chat' &&
    prev.from?.uid === from?.uid &&
    prev.from?.nick === from?.nick &&
    line.t - prev.t < 5 * 60 * 1000;

  const me = from?.uid === store.self?.uid;
  const user = from ? store.user(from.uid) : undefined;

  return h(
    'div',
    {
      class: `line chat${sameSpeaker ? ' cont' : ''}${me ? ' mine' : ''}`,
      title: new Date(line.t).toLocaleString(),
    },
    h('span', { class: 'time' }, stamp(line, prev)),
    h(
      'span',
      { class: 'gutter' },
      sameSpeaker || !user ? null : icon(user.icon, CHAT_SCALE),
    ),
    h('span', { class: 'name', title: from ? `uid ${from.uid}` : '' }, sameSpeaker ? '' : (from?.nick ?? '')),
    h('span', { class: 'text' }, ...linkify(line.text)),
  );
}

/** Actions, notices, broadcasts and this client's own remarks all read
 *  as one column of asides rather than as chat with a strange name. */
function eventLine(line: Line, prev: Line | undefined): HTMLElement {
  const text =
    line.kind === 'action'
      ? `${line.from?.nick ?? ''} ${line.text}`
      : line.kind === 'broadcast'
        ? `${line.from?.nick ?? 'server'}: ${line.text}`
        : line.text;
  const label =
    line.kind === 'broadcast' ? 'broadcast' : line.kind === 'notice' ? '' : '';
  return h(
    'div',
    { class: `line ${line.kind}`, title: new Date(line.t).toLocaleString() },
    h('span', { class: 'time' }, stamp(line, prev)),
    h('span', { class: 'gutter' }),
    h('span', { class: 'name' }, label),
    h('span', { class: 'text' }, ...linkify(text)),
  );
}
