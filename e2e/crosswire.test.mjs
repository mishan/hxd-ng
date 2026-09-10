/**
 * A 1997 client and a 2026 browser client, in one room.
 *
 * This is the file the whole suite is aimed at. On one side
 * `@hotline-ng/client`, which speaks JSON over a WebSocket and has never
 * seen `hxd-core`. On the other a Hotline 1.5 client written from the
 * wire format in `harness/frame.mjs`, which shares no code with the
 * server either — unlike the scripted client in `crates/hxd/tests/`,
 * which packs and parses with the same `hxproto` the server does, so a
 * bug symmetric between the two would be invisible to it.
 *
 * Neither end here can agree with hxd-ng by construction. When they do,
 * that is a fact about the wire.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { hdr, legacyFleet, tag, toText } from './harness/legacy.mjs';
import { startServer } from './harness/server.mjs';

const account = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
get_user_info = true
use_any_name = true
`;

const ADMIN = `name = "Admin"
password = "pw-admin"
[access]
read_chat = true
send_chat = true
send_msgs = true
disconnect_users = true
use_any_name = true
`;

describe('one room, two wire eras', () => {
  let server;
  const ng = fleet(() => server);
  const old = legacyFleet(() => server);

  before(async () => {
    server = await startServer({
      accounts: { alice: account('alice'), bob: account('bob'), admin: ADMIN },
    });
  });
  after(async () => {
    old.closeAll();
    await ng.closeAll();
    await server?.stop();
  });

  test('a line from the browser arrives at the 1.5 client already formatted', async () => {
    // The formatting is the server's, and it is mhxd's byte for byte:
    // a carriage return, the nick right-aligned into thirteen columns,
    // a colon and two spaces. A 1997 client renders a transcript by
    // printing what it is handed, so this string *is* the feature.
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Bob' });
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Alice' });

    await modern.conn.chat({ text: 'hello from the future' });

    const line = await classic.waitFor(
      (f) => f.type === hdr.CHAT && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('hello from the future'),
    );
    const text = toText(line.get(tag.BODY));
    assert.equal(text, '\r        Alice:  hello from the future');
  });

  test('a line from 1997 arrives at the browser as structure, not as text', async () => {
    // The same event, told the way each era asks for it: the old client
    // is handed a rendered line, the new one a `from` and a `text` it
    // can lay out however it likes.
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Alice' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Bobby' });
    await modern.waitFor('user_joined', { 'user.uid': classic.uid });

    classic.chat('hello from the past');

    const ev = await modern.waitFor('chat', { text: 'hello from the past' });
    assert.equal(ev.data.from.nick, 'Bobby');
    assert.equal(ev.data.from.uid, classic.uid);
    assert.equal(ev.data.style, 'normal');
  });

  test('one roster, whichever wire you ask down', async () => {
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Modern' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Legacy' });
    await modern.waitFor('user_joined', { 'user.nick': 'Legacy' });

    const asOld = await classic.users();
    const asNew = await modern.conn.request('sync');

    const oldUids = asOld.map((u) => u.uid).sort();
    const newUids = asNew.users.map((u) => u.uid).sort();
    for (const uid of [classic.uid, modern.conn.self.uid]) {
      assert.ok(oldUids.includes(uid), `${uid} missing from the legacy user list`);
      assert.ok(newUids.includes(uid), `${uid} missing from the ng roster`);
    }
    // Same nicks, same uids — uids stay 16-bit precisely so the two
    // rosters can be one roster.
    const oldByUid = new Map(asOld.map((u) => [u.uid, u.nick]));
    for (const u of asNew.users) assert.equal(oldByUid.get(u.uid), u.nick);
  });

  test('a private message crosses in both directions', async () => {
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Correspondent' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Pen Pal' });
    await modern.waitFor('user_joined', { 'user.nick': 'Pen Pal' });

    await modern.conn.msg({ to: classic.uid, text: 'a note for you' });
    const note = await classic.waitFor(
      (f) => f.type === hdr.MSG && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('a note for you'),
    );
    assert.ok(toText(note.get(tag.BODY)).includes('a note for you'));

    const mark = modern.mark();
    await classic.msg(modern.conn.self.uid, 'and one back');
    const reply = await modern.waitFor('msg', { text: 'and one back' }, { since: mark });
    assert.equal(reply.data.from.uid, classic.uid);
  });

  test('a nick change on one wire is a change on the other', async () => {
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Observer' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Before' });
    await modern.waitFor('user_joined', { 'user.uid': classic.uid });
    const mark = modern.mark();

    await classic.nick('After', 7);

    const ev = await modern.waitFor('user_changed', { 'user.uid': classic.uid, 'user.nick': 'After' }, { since: mark });
    assert.equal(ev.data.user.icon, 7);
    await modern.expectNo('user_parted', { uid: classic.uid }, { since: mark });
  });

  test('a Mac Roman nick survives the trip out to a browser and back', async () => {
    // The domain is UTF-8 and the conversion lives at the legacy edge,
    // where it is injective on the way in — so a nick typed on a 1997
    // client reaches a 2026 one as the same characters, and the byte
    // that means "Δ" here is the byte glibc's iconv says it is.
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Reader' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Café Δ' });

    const ev = await modern.waitFor('user_joined', { 'user.uid': classic.uid });
    assert.equal(ev.data.user.nick, 'Café Δ');

    const rows = await classic.users();
    assert.equal(rows.find((u) => u.uid === classic.uid).nick, 'Café Δ');
  });

  test('a detached browser session reads as away on the 1997 wire', async () => {
    // The two eras describe the same fact in their own vocabulary. ng
    // says `status: "detached"`; the legacy wire has no such idea, so
    // the server sets bit 0 of the status color — the away flag a 1.5
    // client already knows how to grey out. That translation is the
    // whole reason a detachable session does not break old clients.
    const modern = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Fading' });
    const classic = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Onlooker' });
    const uid = modern.conn.self.uid;

    // Catch up before dropping. A resume replays from the moment the
    // socket died, so a client still holding an unprocessed event
    // resumes from a seq the buffer no longer reaches and is told
    // `resync_required` — which recovers through `sync`, and so never
    // fires `onResumed`. Correct server behavior, and a hang for a test
    // that did not wait.
    await modern.waitFor('user_joined', { 'user.uid': classic.uid });

    const before = (await classic.users()).find((u) => u.uid === uid);
    assert.equal(before.color & 1, 0, 'present and active');

    const away = (bit) => (f) =>
      f.type === hdr.USER_CHANGE &&
      f.get(tag.UID)?.readUInt16BE(0) === uid &&
      (f.get(tag.COLOUR)?.readUInt16BE(0) & 1) === bit;

    const mark = classic.mark();
    modern.conn.drop();
    await classic.waitFor(away(1), { since: mark });

    // And back again when the session resumes. Asserted by waiting
    // rather than by re-reading the roster in between: the library
    // reconnects within a second of its own accord, so any snapshot
    // taken "while detached" is a race against it.
    await modern.waitForHook('onResumed', () => true, { timeout: 20_000 });
    await classic.waitFor(away(0), { since: mark });

    // Away, not gone. Checked over the whole episode after the fact,
    // for the same reason: a timed absence check would be competing
    // with the resume it is trying to observe.
    const parts = classic.frames.filter(
      (f) => f.n >= mark && f.type === hdr.USER_PART && f.get(tag.UID)?.readUInt16BE(0) === uid,
    );
    assert.deepEqual(parts, [], 'the old client was never told this person left, because they did not');
  });

  test('a kick from the old wire ends the new session', async () => {
    const admin = await old.login({ login: 'admin', password: 'pw-admin', nick: 'Admin' });
    const doomed = await ng.connect({ login: 'alice', password: 'pw-alice', nick: 'Doomed' });
    const mark = doomed.mark();

    await admin.kick(doomed.conn.self.uid);

    const ended = await doomed.waitForHook('onEnded', () => true, { since: mark });
    assert.match(ended.data.reason, /administrator/);
    await admin.waitFor((f) => f.type === hdr.USER_PART && f.get(tag.UID)?.readUInt16BE(0) === doomed.conn.self.uid);
  });
});
