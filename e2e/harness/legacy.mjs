/**
 * A Hotline 1.5 client, from scratch.
 *
 * Its whole reason for existing is independence. The scripted legacy
 * client in `crates/hxd/tests/` packs with `pack_frame` and parses with
 * `read_frame` — the server's own functions, from the same `hxproto` the
 * server unpacks with — so a bug inside that shared crate cancels out
 * and no test in the tree can see it. Nothing here shares a line with
 * the server: the framing is in `frame.mjs`, the Mac Roman table comes
 * from Node, and this file is the conversation.
 *
 * It speaks only as much of the wire as the cross-wire tests need:
 * login, the user list, chat, private messages, a nick change and a
 * kick. Files, news and the private-chat room family are not here, and
 * should not be until something wants them.
 */

import { connect as tcpConnect } from 'node:net';

import { CLIENT_MAGIC, Framer, SERVER_MAGIC, pack } from './frame.mjs';
import { toBytes, toText } from './macroman.mjs';

/** Client → server. `hotline.h`'s `HTLC_HDR_*`. */
export const req = {
  CHAT: 0x69,
  LOGIN: 0x6b,
  MSG: 0x6c,
  USER_KICK: 0x6e,
  AGREEMENT_AGREE: 0x79,
  USER_GETLIST: 0x12c,
  USER_CHANGE: 0x130,
  PING: 0x1f4,
};

/** Server → client. `HTLS_HDR_*`, plus the task reply. */
export const hdr = {
  TASK: 0x0001_0000,
  MSG: 0x68,
  CHAT: 0x6a,
  AGREEMENT: 0x6d,
  USER_CHANGE: 0x12d,
  USER_PART: 0x12e,
  USER_SELFINFO: 0x162,
  MSG_BROADCAST: 0x163,
};

/** Data chunk tags. */
export const tag = {
  TASK_ERROR: 0x64,
  BODY: 0x65,
  NAME: 0x66,
  UID: 0x67,
  ICON: 0x68,
  LOGIN: 0x69,
  PASSWORD: 0x6a,
  STYLE: 0x6d,
  ACCESS: 0x6e,
  COLOUR: 0x70,
  OPTIONS: 0x71,
  BAN: 0x71,
  CHAT_ID: 0x72,
  VERSION: 0xa0,
  USER_LIST: 0x12c,
};

/**
 * Credentials are one's-complement on the wire.
 *
 * Not encryption and never was — `~b` for every byte, self-inverse,
 * which is why the same function serves both directions. It is worth
 * knowing that a single NUL byte in PASSWORD means "no password", and
 * that a single NUL in LOGIN is the HOPE probe rather than an empty
 * login.
 */
export function twiddle(bytes) {
  return Buffer.from(Buffer.from(bytes).map((b) => ~b & 0xff));
}

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};

/** One row of `HTLS_DATA_USER_LIST`: uid, icon, color, name length, name. */
function parseUserRow(data) {
  const nameLen = data.readUInt16BE(6);
  return {
    uid: data.readUInt16BE(0),
    icon: data.readUInt16BE(2),
    color: data.readUInt16BE(4),
    nick: toText(data.subarray(8, 8 + nameLen)),
  };
}

class TimeoutError extends Error {}

export class LegacyClient {
  constructor(server, who) {
    this.server = server;
    this.who = who;
    this.frames = [];
    this.waiters = [];
    this.trans = 0;
    this.n = 0;
    this.closed = false;
  }

  /** The TRTP hello, then whatever the caller wants to say. */
  async open() {
    this.sock = tcpConnect({ host: '127.0.0.1', port: this.server.ports.legacy });
    const framer = new Framer();
    let greeted = false;
    let pending = Buffer.alloc(0);

    await new Promise((resolve, reject) => {
      this.sock.once('error', reject);
      this.sock.once('connect', resolve);
    });
    this.sock.on('error', () => {
      this.closed = true;
    });
    this.sock.on('close', () => {
      this.closed = true;
      for (const w of this.waiters.splice(0)) w.onClose?.();
    });
    this.sock.on('data', (chunk) => {
      if (!greeted) {
        pending = Buffer.concat([pending, chunk]);
        if (pending.length < SERVER_MAGIC.length) return;
        const hello = pending.subarray(0, SERVER_MAGIC.length);
        if (Buffer.compare(hello, SERVER_MAGIC) !== 0) {
          throw new Error(`server said ${hello.toString('hex')}, not TRTP + a zero error`);
        }
        greeted = true;
        chunk = pending.subarray(SERVER_MAGIC.length);
      }
      for (const frame of framer.push(chunk)) this.record(frame);
    });

    this.sock.write(CLIENT_MAGIC);
    return this;
  }

  record(frame) {
    frame.n = this.n++;
    this.frames.push(frame);
    for (const w of [...this.waiters]) {
      if (w.settle(frame)) this.waiters.splice(this.waiters.indexOf(w), 1);
    }
  }

  send(type, chunks = []) {
    this.trans += 1;
    this.sock.write(pack(type, this.trans, 0, chunks));
    return this.trans;
  }

  /**
   * Log in.
   *
   * Sending NAME completes the login immediately; leaving it out on a
   * client claiming version >= 150 parks it in the agreement dance
   * instead, which `agree` finishes. Both paths are real, and a client
   * that only ever exercises the first has not tested the login the
   * 1.5 clients actually perform.
   */
  async login({ login, password, nick, icon = 0, version = 150, withNick = true } = {}) {
    const chunks = [[tag.VERSION, u16(version)]];
    if (login) chunks.push([tag.LOGIN, twiddle(toBytes(login))]);
    if (password) chunks.push([tag.PASSWORD, twiddle(toBytes(password))]);
    if (withNick && nick) chunks.push([tag.NAME, toBytes(nick)]);
    if (icon) chunks.push([tag.ICON, u16(icon)]);

    const trans = this.send(req.LOGIN, chunks);
    const reply = await this.waitFor((f) => f.type === hdr.TASK && f.trans === trans);
    if (reply.flag !== 0) {
      const why = reply.get(tag.TASK_ERROR);
      throw new Error(`[${this.who}] login refused: ${why ? toText(why) : 'no reason given'}`);
    }
    // Without a nick there is no session yet — the server has sent the
    // agreement and is waiting for `agree`, so there is no SELFINFO to
    // wait for and waiting would hang. The caller drives the rest.
    if (!withNick || !nick) return this;
    // SELFINFO carries ACCESS and a *user-list row*, not a bare UID
    // chunk — the uid is the first two bytes of that row. Worth knowing
    // before reaching for `tag.UID` here, which is what a reading of the
    // other transactions would suggest.
    const self = await this.waitFor((f) => f.type === hdr.USER_SELFINFO);
    const row = self.get(tag.USER_LIST);
    // Into `self` rather than onto `this`: the row's `nick` field would
    // otherwise land on top of the `nick()` method.
    this.self = row ? parseUserRow(row) : null;
    this.uid = this.self?.uid;
    this.access = self.get(tag.ACCESS);
    return this;
  }

  /** Finish the agreement dance a nick-less login parks in. */
  /** Finish the agreement dance a nick-less login parks in, and adopt
   *  the session it produces. */
  async agree(nick) {
    this.send(req.AGREEMENT_AGREE, [
      [tag.NAME, toBytes(nick)],
      [tag.OPTIONS, u16(0)],
    ]);
    const self = await this.waitFor((f) => f.type === hdr.USER_SELFINFO);
    const row = self.get(tag.USER_LIST);
    this.self = row ? parseUserRow(row) : null;
    this.uid = this.self?.uid;
    this.access = self.get(tag.ACCESS);
    return this;
  }

  /**
   * Say something in the public room.
   *
   * Deliberately not awaited: a chat send is notification-style and the
   * reference server answers it with nothing at all, success or
   * failure — it drops chat from a client without send-chat access in
   * silence. So there is no reply to wait for, and a test that wants to
   * know the line landed waits for the line.
   */
  chat(text) {
    this.send(req.CHAT, [[tag.BODY, toBytes(text)]]);
  }

  async msg(uid, text) {
    const trans = this.send(req.MSG, [
      [tag.UID, u16(uid)],
      [tag.BODY, toBytes(text)],
    ]);
    return this.waitFor((f) => f.type === hdr.TASK && f.trans === trans);
  }

  /** Also notification-style, also unanswered. */
  nick(name, icon) {
    const chunks = [[tag.NAME, toBytes(name)]];
    if (icon !== undefined) chunks.push([tag.ICON, u16(icon)]);
    this.send(req.USER_CHANGE, chunks);
  }

  async kick(uid, { ban = false } = {}) {
    const chunks = [[tag.UID, u16(uid)]];
    if (ban) chunks.push([tag.BAN, u16(1)]);
    const trans = this.send(req.USER_KICK, chunks);
    return this.waitFor((f) => f.type === hdr.TASK && f.trans === trans);
  }

  /** The roster, as the legacy wire spells it: one chunk per user. */
  async users() {
    const trans = this.send(req.USER_GETLIST, []);
    const reply = await this.waitFor((f) => f.type === hdr.TASK && f.trans === trans);
    return reply.all(tag.USER_LIST).map(parseUserRow);
  }

  /** Every chat line this client has been shown, decoded. */
  chatLines() {
    return this.frames
      .filter((f) => f.type === hdr.CHAT)
      .map((f) => ({ n: f.n, text: toText(f.get(tag.BODY) ?? Buffer.alloc(0)) }));
  }

  mark() {
    return this.n;
  }

  /** Predicate-matched, and required, for the same reason as on the ng
   *  side: a sender is shown its own chat line. */
  waitFor(predicate, { timeout = 5000, since = 0 } = {}) {
    const hit = (f) => {
      if (f.n < since) return false;
      try {
        return predicate(f);
      } catch {
        return false;
      }
    };
    for (const f of this.frames) if (hit(f)) return Promise.resolve(f);
    return new Promise((resolve, reject) => {
      const waiter = {
        settle: (f) => {
          if (!hit(f)) return false;
          resolve(f);
          return true;
        },
        onClose: () => reject(new Error(this.diagnose('the connection closed while waiting', since))),
      };
      this.waiters.push(waiter);
      setTimeout(() => {
        const i = this.waiters.indexOf(waiter);
        if (i < 0) return;
        this.waiters.splice(i, 1);
        reject(new TimeoutError(this.diagnose(`nothing matched within ${timeout}ms`, since)));
      }, timeout).unref();
    });
  }

  async expectNo(predicate, { timeout = 750, since = 0 } = {}) {
    try {
      const f = await this.waitFor(predicate, { timeout, since });
      throw new Error(this.diagnose(`expected no such frame, got type 0x${f.type.toString(16)}`, since));
    } catch (e) {
      if (e instanceof TimeoutError) return;
      throw e;
    }
  }

  diagnose(message, since = 0) {
    const wire = this.frames
      .filter((f) => f.n >= since)
      .slice(-20)
      .map((f) => {
        const body = f.get(tag.BODY);
        const detail = body ? ` ${JSON.stringify(toText(body))}` : '';
        return `    <- 0x${f.type.toString(16).padStart(6, '0')} trans=${f.trans} flag=${f.flag}${detail}`;
      })
      .join('\n');
    return [
      `[${this.who}] ${message}`,
      `  uid: ${this.uid ?? '(not logged in)'}${this.closed ? ' — socket closed' : ''}`,
      `  this client's wire:`,
      wire || '    (nothing)',
      `  server:`,
      this.server.log(),
      `  reproduce: ${this.server.repro()}`,
    ].join('\n');
  }

  close() {
    this.sock?.destroy();
    this.closed = true;
  }
}

/** Connect and log in, the ordinary case. */
export async function legacyLogin(server, creds) {
  const client = new LegacyClient(server, creds.nick ?? creds.login ?? 'legacy');
  await client.open();
  await client.login(creds);
  return client;
}

/** A file's worth of legacy clients, all closed at the end. */
export function legacyFleet(getServer) {
  const open = [];
  return {
    async login(creds) {
      const client = new LegacyClient(getServer(), creds.nick ?? creds.login ?? 'legacy');
      open.push(client);
      await client.open();
      await client.login(creds);
      return client;
    },
    async raw(who) {
      const client = new LegacyClient(getServer(), who);
      open.push(client);
      await client.open();
      return client;
    },
    closeAll() {
      for (const c of open) c.close();
      open.length = 0;
    },
  };
}

export { toBytes, toText };
