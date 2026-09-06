/** A hyperscript small enough to read in one sitting.
 *
 * There is no framework here on purpose: this client's job is to be a
 * legible reference for the Hotline-ng wire, and a reader chasing a bug
 * should never have to know a rendering library's rules to follow what
 * the DOM is doing.
 */

type Child = Node | string | number | null | undefined | false;

export type Props<K extends keyof HTMLElementTagNameMap> = Partial<
  Omit<HTMLElementTagNameMap[K], 'style' | 'children' | 'className' | 'dataset' | 'classList'>
> & {
  class?: string;
  style?: Partial<CSSStyleDeclaration>;
  dataset?: Record<string, string>;
};

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props<K> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === 'class') el.className = String(v);
    else if (k === 'style') Object.assign(el.style, v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else (el as Record<string, unknown>)[k] = v;
  }
  el.append(...flatten(children));
  return el;
}

function flatten(children: Child[]): (Node | string)[] {
  const out: (Node | string)[] = [];
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    out.push(typeof c === 'number' ? String(c) : c);
  }
  return out;
}

/** Replace an element's children in one go. */
export function fill(el: Element, ...children: Child[]): void {
  el.replaceChildren(...flatten(children));
}

export function $<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(sel);
  if (!el) throw new Error(`no element for ${sel}`);
  return el;
}

/** `14:32` — chat timestamps, in the reader's own locale and zone. */
export function clock(t = Date.now()): string {
  return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/** Turn bare URLs into links and leave everything else as text. Chat is
 *  never interpreted as markup: the server hands us UTF-8 from strangers
 *  and `textContent` is the only safe thing to do with it. */
export function linkify(text: string): (Node | string)[] {
  const out: (Node | string)[] = [];
  const re = /\b(https?:\/\/[^\s<>"']+)/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const i = m.index ?? 0;
    if (i > last) out.push(text.slice(last, i));
    out.push(h('a', { href: m[0], target: '_blank', rel: 'noreferrer noopener' }, m[0]));
    last = i + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
