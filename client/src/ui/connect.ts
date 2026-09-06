/** The connect screen.
 *
 * Everything but the password is remembered, because a Hotline user goes
 * back to the same couple of servers for years. The password is not
 * remembered anywhere, ever — it is a plaintext-equivalent secret on this
 * protocol, and a client that stashes it in localStorage has quietly
 * made every other tab's XSS bug into a credential leak.
 */

import { h, type Props } from './dom';
import { icon, DEFAULT_ICON } from './icons';
import { pickIcon } from './iconpicker';

export interface Details {
  url: string;
  login: string;
  password: string;
  nick: string;
  icon: number;
}

const KEY = 'hxd-ng.connect';

export function remembered(): Details {
  const fallback: Details = {
    // The ng listener's default, and the localhost the spec tells you to
    // bind it to. A real deployment is a wss:// URL behind the proxy
    // that terminates its TLS.
    url: 'ws://127.0.0.1:5700',
    login: '',
    password: '',
    nick: '',
    icon: DEFAULT_ICON,
  };
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return fallback;
    const saved = JSON.parse(raw) as Partial<Details>;
    return { ...fallback, ...saved, password: '' };
  } catch {
    return fallback;
  }
}

function remember(d: Details): void {
  try {
    const { password: _password, ...rest } = d;
    localStorage.setItem(KEY, JSON.stringify(rest));
  } catch {
    /* storage disabled; the form simply starts from its defaults */
  }
}

export function connectScreen(onConnect: (d: Details) => Promise<void>): HTMLElement {
  const saved = remembered();
  let chosenIcon = saved.icon;

  const url = field('Server', 'url', saved.url, { placeholder: 'ws://127.0.0.1:5700' });
  const login = field('Account', 'text', saved.login, { placeholder: 'guest', autocomplete: 'username' });
  const password = field('Password', 'password', '', { autocomplete: 'current-password' });
  const nick = field('Nickname', 'text', saved.nick, { placeholder: 'as the account is named' });

  const iconArt = h('span', { class: 'icon-cell-fixed' }, icon(chosenIcon, 2));
  const iconBtn = h('button', { class: 'icon-button', type: 'button' }, iconArt, h('span', { class: 'muted' }, `#${chosenIcon}`));
  iconBtn.onclick = () => {
    void pickIcon(chosenIcon).then((id) => {
      if (id === null) return;
      chosenIcon = id;
      iconArt.replaceChildren(icon(id, 2));
      iconBtn.lastElementChild!.textContent = `#${id}`;
    });
  };

  const error = h('p', { class: 'error', hidden: true });
  const submit = h('button', { class: 'primary', type: 'submit' }, 'Connect');

  const form = h(
    'form',
    { class: 'connect-card' },
    h('h1', {}, 'Hotline'),
    h('p', { class: 'muted' }, 'A web client for the Hotline-ng wire.'),
    url.row,
    login.row,
    password.row,
    nick.row,
    h('label', { class: 'row' }, h('span', {}, 'Icon'), iconBtn),
    error,
    submit,
  );

  form.onsubmit = (e) => {
    e.preventDefault();
    const details: Details = {
      url: url.input.value.trim(),
      login: login.input.value.trim(),
      password: password.input.value,
      nick: nick.input.value.trim(),
      icon: chosenIcon,
    };
    if (!details.url) return;
    remember(details);
    error.hidden = true;
    submit.disabled = true;
    submit.textContent = 'Connecting…';
    onConnect(details)
      .catch((err: Error) => {
        error.textContent = err.message;
        error.hidden = false;
      })
      .finally(() => {
        submit.disabled = false;
        submit.textContent = 'Connect';
      });
  };

  queueMicrotask(() => (saved.login ? password.input : login.input).focus());
  return h('div', { class: 'connect' }, form);
}

function field(
  label: string,
  type: string,
  value: string,
  extra: Props<'input'> = {},
): { row: HTMLElement; input: HTMLInputElement } {
  const input = h('input', { type, value, spellcheck: false, ...extra });
  return { row: h('label', { class: 'row' }, h('span', {}, label), input), input };
}
