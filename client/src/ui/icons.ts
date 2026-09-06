/**
 * The classic Hotline icon set, as one sprite sheet.
 *
 * `DATA_ICON` on the wire is a 16-bit id into a sprite table every client
 * of the era shipped a copy of; ours is `gtkhx/icons.rsrc`, packed by
 * `tools/build-icons.py` into `public/icons.png` plus an index. Both are
 * committed, so this module only ever fetches two files, and a user list
 * of thirty people costs the same as a user list of one.
 *
 * Sprites are drawn as a scaled `background-position` window onto the
 * sheet with `image-rendering: pixelated`, so a 16×16 icon authored in
 * 1997 stays crisp at 2× on a modern display instead of being smeared by
 * a bilinear filter.
 */

import { h } from './dom';

interface Index {
  atlas: string;
  width: number;
  height: number;
  icons: Record<string, [number, number, number, number]>;
}

let index: Index | null = null;
let atlasUrl = '';

/** The icon a Hotline client falls back to; the server's own default for
 *  a login that names none. */
export const DEFAULT_ICON = 128;

/** The widest sprite in the sheet, in source pixels. The user list
 *  reserves this much so a banner-width icon and a plain 16×16 one line
 *  their right edges up against the nick — the same left-shift GtkHx
 *  gives banner art. */
export const MAX_ICON_WIDTH = 32;

export async function loadIcons(base = import.meta.env.BASE_URL): Promise<void> {
  const res = await fetch(`${base}icons.json`);
  if (!res.ok) throw new Error(`icons.json: ${res.status}`);
  index = (await res.json()) as Index;
  atlasUrl = `${base}${index.atlas}`;
  // Decode the sheet once, up front, so the first roster paint does not
  // flash empty cells.
  await new Promise<void>((resolve) => {
    const img = new Image();
    img.onload = () => resolve();
    img.onerror = () => resolve();
    img.src = atlasUrl;
  });
}

export function iconIds(): number[] {
  if (!index) return [];
  return Object.keys(index.icons)
    .map(Number)
    .sort((a, b) => a - b);
}

export function hasIcon(id: number): boolean {
  return !!index && index.icons[String(id)] !== undefined;
}

/** Style a bare element as the sprite for `id`. Returns false when the
 *  sheet has no such icon, which is normal — servers and other clients
 *  are free to use ids ours never shipped. */
export function paintIcon(el: HTMLElement, id: number, scale = 1): boolean {
  const rect = index?.icons[String(id)];
  if (!index || !rect) {
    el.style.backgroundImage = 'none';
    el.style.width = `${MAX_ICON_WIDTH * scale}px`;
    el.style.height = `${16 * scale}px`;
    return false;
  }
  const [x, y, w, hgt] = rect;
  el.style.backgroundImage = `url(${atlasUrl})`;
  el.style.backgroundSize = `${index.width * scale}px ${index.height * scale}px`;
  el.style.backgroundPosition = `${-x * scale}px ${-y * scale}px`;
  el.style.width = `${w * scale}px`;
  el.style.height = `${hgt * scale}px`;
  return true;
}

export function icon(id: number, scale = 1, cls = ''): HTMLElement {
  const el = h('span', { class: `sprite ${cls}`.trim() });
  paintIcon(el, id, scale);
  return el;
}
