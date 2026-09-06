/** Pick one of the six hundred icons the sprite sheet holds.
 *
 * A native `<dialog>` so Escape, the backdrop and focus trapping are the
 * platform's problem rather than ours. */

import { h } from './dom';
import { icon, iconIds } from './icons';

export function pickIcon(current: number): Promise<number | null> {
  return new Promise((resolve) => {
    let chosen = current;

    const grid = h('div', { class: 'icon-grid' });
    const buttons = new Map<number, HTMLButtonElement>();
    for (const id of iconIds()) {
      const b = h(
        'button',
        { class: `icon-cell${id === current ? ' on' : ''}`, title: `icon ${id}`, type: 'button' },
        icon(id, 2),
      );
      b.onclick = () => {
        buttons.get(chosen)?.classList.remove('on');
        chosen = id;
        b.classList.add('on');
        readout.textContent = `icon ${id}`;
      };
      b.ondblclick = () => done(chosen);
      buttons.set(id, b);
      grid.append(b);
    }

    const readout = h('span', { class: 'muted' }, `icon ${current}`);
    const search = h('input', {
      type: 'search',
      placeholder: 'icon number…',
      inputMode: 'numeric',
      spellcheck: false,
    });
    search.oninput = () => {
      const q = search.value.trim();
      for (const [id, b] of buttons) b.hidden = q !== '' && !String(id).startsWith(q);
    };

    const cancel = h('button', { class: 'ghost', type: 'button' }, 'Cancel');
    const ok = h('button', { class: 'primary', type: 'button' }, 'Use this icon');
    cancel.onclick = () => done(null);
    ok.onclick = () => done(chosen);

    const dialog = h(
      'dialog',
      { class: 'picker' },
      h('header', {}, h('h2', {}, 'Choose an icon'), readout, h('div', { class: 'spacer' }), search),
      grid,
      h('footer', {}, cancel, ok),
    );
    dialog.addEventListener('close', () => done(null));

    function done(value: number | null): void {
      if (!dialog.isConnected) return;
      dialog.remove();
      resolve(value);
    }

    document.body.append(dialog);
    dialog.showModal();
    buttons.get(current)?.scrollIntoView({ block: 'center' });
  });
}
