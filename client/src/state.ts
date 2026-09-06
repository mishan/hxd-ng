/** What the client remembers: the roster, and one transcript per
 *  conversation. No DOM in this file — the UI reads from here, never the
 *  other way round. */

import type { ChatStyle, Sender, ServerInfo, Status, User } from './wire/protocol';

export type LineKind =
  /** Public chat, or a private message inside a PM conversation. */
  | 'chat'
  /** `/me`, which the server carries as style 1. */
  | 'action'
  /** A server notice: joins and parts the server chose to announce,
   *  kick announcements, agreement text. */
  | 'notice'
  | 'broadcast'
  /** Something this client is saying about itself — connection state,
   *  errors. Never came off the wire. */
  | 'system';

export interface Line {
  t: number;
  kind: LineKind;
  from?: Sender;
  text: string;
  /** Set on lines this client generated, so the transcript can mark them
   *  as not having come from the server. */
  local?: boolean;
}

export type ConvId = string;

export interface Conversation {
  id: ConvId;
  kind: 'lobby' | 'pm';
  /** The other party, for a PM conversation. */
  uid?: number;
  title: string;
  lines: Line[];
  unread: number;
}

export const LOBBY: ConvId = 'lobby';

export function pmId(uid: number): ConvId {
  return `pm:${uid}`;
}

/** How many lines a transcript keeps. Long enough that scrolling back
 *  through an evening works, short enough that a room left open
 *  overnight does not grow without bound. */
const MAX_LINES = 2000;

export class Store {
  server: ServerInfo = { name: '', subject: '' };
  self: User | null = null;
  users = new Map<number, User>();
  conversations = new Map<ConvId, Conversation>();
  active: ConvId = LOBBY;

  constructor() {
    this.conversations.set(LOBBY, {
      id: LOBBY,
      kind: 'lobby',
      title: 'Lobby',
      lines: [],
      unread: 0,
    });
  }

  /** Roster order: admins first, then everyone else, each alphabetically
   *  and case-insensitively. Hotline servers send the list in join order;
   *  a sorted list is easier to find a name in, which is what a user list
   *  is for. */
  roster(): User[] {
    return [...this.users.values()].sort((a, b) => {
      if (a.admin !== b.admin) return a.admin ? -1 : 1;
      return a.nick.localeCompare(b.nick, undefined, { sensitivity: 'base' }) || a.uid - b.uid;
    });
  }

  user(uid: number): User | undefined {
    return this.users.get(uid);
  }

  /** The nick to show for a uid that has left: the roster no longer has
   *  it, but a transcript line that mentions it still should. */
  nickOf(uid: number, fallback = `uid ${uid}`): string {
    return this.users.get(uid)?.nick ?? fallback;
  }

  replaceRoster(users: User[]): void {
    this.users.clear();
    for (const u of users) this.users.set(u.uid, u);
  }

  put(u: User): void {
    this.users.set(u.uid, u);
  }

  remove(uid: number): User | undefined {
    const u = this.users.get(uid);
    this.users.delete(uid);
    return u;
  }

  conversation(id: ConvId): Conversation | undefined {
    return this.conversations.get(id);
  }

  /** Open (or find) the PM conversation with a user. */
  openPm(uid: number, nick: string): Conversation {
    const id = pmId(uid);
    let c = this.conversations.get(id);
    if (!c) {
      c = { id, kind: 'pm', uid, title: nick, lines: [], unread: 0 };
      this.conversations.set(id, c);
    } else {
      c.title = nick;
    }
    return c;
  }

  closePm(id: ConvId): void {
    if (id === LOBBY) return;
    this.conversations.delete(id);
    if (this.active === id) this.active = LOBBY;
  }

  add(id: ConvId, line: Line): Conversation | undefined {
    const c = this.conversations.get(id);
    if (!c) return undefined;
    c.lines.push(line);
    if (c.lines.length > MAX_LINES) c.lines.splice(0, c.lines.length - MAX_LINES);
    if (id !== this.active) c.unread++;
    return c;
  }

  system(text: string, id: ConvId = this.active): Conversation | undefined {
    return this.add(id, { t: Date.now(), kind: 'system', text, local: true });
  }
}

export function styleToKind(style: ChatStyle): LineKind {
  return style === 'action' ? 'action' : 'chat';
}

/** Away and detached are one thing to a 1.x client and two things here.
 *  The distinction is worth showing: "away" is a person who stepped out,
 *  "detached" is a phone whose network dropped and whose session is
 *  counting down its grace window. */
export function statusLabel(s: Status): string {
  switch (s) {
    case 'active':
      return '';
    case 'idle':
      return 'away';
    case 'detached':
      return 'disconnected';
  }
}
