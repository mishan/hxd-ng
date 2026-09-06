/** The user list.
 *
 * A Hotline user list is a small thing that carries a lot: who is here,
 * which of them is an administrator, who stepped away, and — since the
 * icon is chosen by its owner — some of who they are. This one adds the
 * two facts the ng wire knows and the 1.x list could not express: the
 * difference between away and *disconnected but inside the grace
 * window*, and whether someone is in voice or publishing video.
 */

import { statusLabel, type Store } from '../state';
import type { User } from '../wire/protocol';
import type { Media } from './media';
import { fill, h } from './dom';
import { icon, MAX_ICON_WIDTH } from './icons';

/** Icons render at 2×: the art is 16 px and unapologetically pixelated,
 *  and doubling it is both crisper and closer to what these lists look
 *  like on a modern display. */
export const ROSTER_SCALE = 2;

export interface RosterHooks {
  onMessage: (u: User) => void;
  /** Dismiss the panel. Only reachable on the narrow layout, where the
   *  roster slides in over the conversation. */
  onClose: () => void;
}

export function renderRoster(el: HTMLElement, store: Store, media: Media, hooks: RosterHooks): void {
  const users = store.roster();
  const rows = users.map((u) => row(u, store, media, hooks));
  const close = h(
    'button',
    { class: 'roster-close', type: 'button', title: 'Hide the user list' },
    '\u00d7',
  );
  close.onclick = () => hooks.onClose();
  fill(
    el,
    h(
      'div',
      { class: 'roster-head' },
      h('span', {}, users.length === 1 ? '1 person' : `${users.length} people`),
      h('div', { class: 'spacer' }),
      close,
    ),
    ...rows,
  );
}

function row(u: User, store: Store, media: Media, hooks: RosterHooks): HTMLElement {
  const me = u.uid === store.self?.uid;
  const status = statusLabel(u.status);
  const voice = media.inVoice(u.uid);
  const pubs = media.publicationsOf(u.uid);

  const marks: HTMLElement[] = [];
  if (voice) {
    marks.push(
      h('span', {
        class: `mark ${voice.muted ? 'muted-mic' : 'mic'}`,
        title: voice.muted ? 'in voice, muted' : 'in voice',
      }),
    );
  }
  for (const p of pubs) {
    marks.push(
      h('span', {
        class: `mark ${p.kind === 'camera' ? 'cam' : 'screen'}${p.paused ? ' paused' : ''}`,
        title: `${p.kind}${p.paused ? ' (paused)' : ''}`,
      }),
    );
  }

  // The icon column is as wide as the widest sprite in the sheet and the
  // art is right-aligned inside it, so banner-width icons extend to the
  // left and every nick still starts on the same column. GtkHx does the
  // same thing for the same reason.
  const art = h(
    'span',
    { class: 'icon-cell-fixed', style: { width: `${MAX_ICON_WIDTH * ROSTER_SCALE}px` } },
    icon(u.icon, ROSTER_SCALE),
  );

  const el = h(
    'div',
    {
      class: `person${u.admin ? ' admin' : ''}${u.status !== 'active' ? ' away' : ''}${me ? ' me' : ''}`,
      title: `uid ${u.uid} · icon ${u.icon}${u.admin ? ' · administrator' : ''}${status ? ` · ${status}` : ''}`,
      tabIndex: 0,
    },
    art,
    h(
      'span',
      { class: 'who' },
      h('span', { class: 'nick' }, u.nick),
      status ? h('span', { class: 'status' }, status) : null,
    ),
    marks.length ? h('span', { class: 'marks' }, ...marks) : null,
  );
  if (!me) {
    el.onclick = () => hooks.onMessage(u);
    el.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        hooks.onMessage(u);
      }
    };
  }
  return el;
}
