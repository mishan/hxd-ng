/**
 * Replies (hotline-ng.md §7.3): `re` on `chat` and `msg`, kept and
 * relayed as sent to sessions that said `replies`, and `history`'s
 * `ids`.
 *
 * `crates/hxd/tests/replies.rs` builds its `Core` with every store a
 * reply can name and lists the targets it was built with. Here the
 * binary works out from its own file what it keeps — `[history]`,
 * `[inbox]`, `[messaging]`, `[identity]`'s hosts — and the client is
 * the library a browser uses, which reads the block and sends `re` as
 * its types spell it.
 */

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';

import { CAP_REPLIES } from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { signingIdentity } from './harness/device.mjs';
import { startServer } from './harness/server.mjs';

const account = (name, extra = '') => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
read_chat_history = true
send_chat = true
send_msgs = true
use_any_name = true
messaging = true
${extra}`;

/** A request's refusal code, or `ok`. */
const code = (pending) =>
  pending.then(
    () => 'ok',
    (e) => {
      if (!e.wire) throw e;
      return e.wire.code;
    },
  );

describe('replies', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: (ports) => ({
        history: { db: 'history.db' },
        inbox: { db: 'messages.db' },
        messaging: { enabled: true },
        identity: signingIdentity(ports),
      }),
      accounts: {
        alice: account('alice'),
        bob: account('bob'),
        dave: account('dave'),
        erin: account('erin'),
        finn: account('finn'),
        carol: account('carol', 'disconnect_users = true\n'),
        // A writer of long lines, faster than mhxd's chat budget allows.
        scribe: account('scribe', '[extra]\ncan_spam = true\n'),
        boss: account('boss', '[extra]\nmanage_rooms = true\n'),
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, replies = true) =>
    crew.connect({ login: who, password: `pw-${who}`, nick: who, messaging: true, replies });

  const say = async (c, params) => (await c.conn.chat(params)).id;
  const heard = (c, text) => c.waitFor('chat', { text });

  test('the targets are what the config keeps, and a login that does not ask is granted none', async () => {
    const alice = await login('alice');
    assert.ok(alice.conn.hasCap(CAP_REPLIES), JSON.stringify(alice.conn.caps));
    assert.deepEqual(alice.conn.replies, { targets: ['line', 'pm', 'im', 'signed'] });

    const dave = await login('dave', false);
    assert.ok(!dave.conn.hasCap(CAP_REPLIES), JSON.stringify(dave.conn.caps));
    assert.equal(dave.conn.replies, null);
  });

  test('a reply to a line reaches the sessions that asked, live and in history, and a dangling one is kept', async () => {
    const [alice, bob, dave] = [await login('alice'), await login('bob'), await login('dave', false)];
    const asked = await say(alice, { text: 'lunch at noon?' });
    const re = { line: asked };
    await say(bob, { text: 'noon works', re });
    assert.deepEqual((await heard(alice, 'noon works')).data.re, re);
    assert.equal((await heard(dave, 'noon works')).data.re, undefined);

    // Never refused for naming nothing, and the `re` of a session that
    // never said `replies` ignored as an unknown param is.
    const never = { line: asked + 1000 };
    await say(bob, { text: 'pointing at nothing', re: never });
    await say(dave, { text: 'unasked', re });
    assert.deepEqual((await heard(alice, 'pointing at nothing')).data.re, never);
    assert.equal((await heard(alice, 'unasked')).data.re, undefined);

    const kept = async (c) => (await c.conn.history({ after: asked - 1 })).lines.map((l) => [l.text, l.re]);
    assert.deepEqual((await kept(alice)).slice(0, 4), [
      ['lunch at noon?', undefined],
      ['noon works', re],
      ['pointing at nothing', never],
      ['unasked', undefined],
    ]);
    assert.ok((await kept(dave)).every(([, r]) => r === undefined));
  });

  test('history by ids answers the lines of its room among them, and has_more past its bound', async () => {
    const boss = await login('boss');
    const room = (await boss.conn.roomCreate({ name: 'lounge' })).room.id;
    const alice = await login('alice');
    await alice.conn.roomJoin(room);
    const inRoom = await say(alice, { text: 'in the lounge', room });
    const first = await say(alice, { text: 'first' });
    const second = await say(alice, { text: 'second' });

    const got = await alice.conn.history({ ids: [second, inRoom, first, second + 1000] });
    assert.deepEqual(
      got.lines.map((l) => [l.id, l.text]),
      [
        [first, 'first'],
        [second, 'second'],
      ],
      "the lobby's, ascending, with neither the lounge's nor a missing one",
    );
    assert.equal(got.has_more, false);
    assert.deepEqual(
      (await alice.conn.history({ room, ids: [inRoom, first] })).lines.map((l) => l.id),
      [inRoom],
    );

    for (const [what, params] of [
      ['none', { ids: [] }],
      ['51', { ids: Array.from({ length: 51 }, (_, i) => i + 1) }],
      ['beside a cursor', { ids: [first], before: second }],
    ]) {
      assert.equal(await code(alice.conn.history(params)), 'bad_request', what);
    }

    // More than one reply holds: the highest ids are left to ask for again.
    const scribe = await login('scribe');
    const long = 'x'.repeat(4000);
    const said = [];
    for (let i = 0; i < 24; i++) said.push(await say(scribe, { text: long }));
    const page = await alice.conn.history({ ids: said });
    const shown = page.lines.map((l) => l.id);
    assert.equal(page.has_more, true);
    assert.ok(shown.length > 0 && shown.length < said.length, `${shown.length} of ${said.length}`);
    assert.deepEqual(shown, said.slice(0, shown.length));
    const rest = await alice.conn.history({ ids: said.slice(shown.length) });
    assert.equal(rest.has_more, false);
    assert.deepEqual(
      rest.lines.map((l) => l.id),
      said.slice(shown.length),
    );
  });

  test('a reply to a private message is carried live and on the inbox row', async () => {
    const [alice, bob] = [await login('alice'), await login('bob')];
    const sent = await alice.conn.msg({ to: bob.conn.self.uid, text: 'psst, bob' });
    const got = await bob.waitFor('msg', { text: 'psst, bob' });
    assert.equal(typeof sent.ref, 'string');
    assert.equal(got.data.ref, sent.ref, 'both parties name it alike');

    const re = { pm: got.data.ref };
    await bob.conn.msg({ to: alice.conn.self.uid, text: 'what is it?', re });
    assert.deepEqual((await alice.waitFor('msg', { text: 'what is it?' })).data.re, re);
    const row = (await alice.conn.inbox()).messages.find((m) => m.text === 'what is it?');
    assert.deepEqual(row.re, re);
  });

  test('a reply to an instant message between friends names it by login and guid', async () => {
    const [erin, finn] = [await login('erin'), await login('finn')];
    assert.deepEqual(await erin.conn.friendAdd('finn'), { state: 'pending_out' });
    await finn.waitFor('friend_request', { login: 'erin' });
    assert.deepEqual(await finn.conn.friendRespond('erin', true), { state: 'accepted' });
    await erin.waitFor('friend', { 'friend.login': 'finn', 'friend.state': 'accepted' });

    const guid = randomUUID();
    await erin.conn.msg({ to_login: 'finn', text: 'coffee?', guid });
    await finn.waitFor('im', { text: 'coffee?' });
    const re = { im: { login: 'erin', guid } };
    await finn.conn.msg({ to_login: 'erin', text: 'always', guid: randomUUID(), re });
    assert.deepEqual((await erin.waitFor('im', { text: 'always' })).data.re, re);
  });

  test('a target of the wrong kind, of another conversation, or beside a signature is refused', async () => {
    const boss = await login('boss');
    const room = (await boss.conn.roomCreate({ name: 'den' })).room.id;
    const [alice, bob] = [await login('alice'), await login('bob')];
    await alice.conn.roomJoin(room);
    const lobby = await say(alice, { text: 'said in the lobby' });
    const { ref } = await alice.conn.msg({ to: bob.conn.self.uid, text: 'between us' });
    const to = bob.conn.self.uid;

    for (const [what, sent] of [
      ['a message from public chat', alice.conn.chat({ text: 'x', re: { pm: ref } })],
      ['a line from a message', alice.conn.msg({ to, text: 'x', re: { line: lobby } })],
      ['a lobby line from a room', alice.conn.chat({ text: 'x', room, re: { line: lobby } })],
      ["a room's line from the lobby", alice.conn.chat({ text: 'x', re: { line: lobby, room } })],
      ['a malformed target', alice.conn.chat({ text: 'x', re: { line: 'one' } })],
      // Refused before the signature is looked at: its `re` would bind
      // nothing.
      ['beside signed', alice.conn.chat({ text: 'x', guid: randomUUID(), signed: 'AAAA', re: { line: lobby } })],
    ]) {
      assert.equal(await code(sent), 'bad_request', what);
    }
  });

  test("a redaction takes a line's re with its words, and a reply to a redacted line keeps its own", async () => {
    const [alice, bob, carol] = [await login('alice'), await login('bob'), await login('carol')];
    const asked = await say(alice, { text: 'anyone up?' });
    const re = { line: asked };
    const answer = await say(bob, { text: 'me', re });
    const again = await say(bob, { text: 'me too', re });
    await carol.conn.redact(asked, 'test');
    await carol.conn.redact(again, 'test');

    const lines = (await alice.conn.history({ ids: [asked, answer, again] })).lines;
    assert.deepEqual(
      lines.map((l) => l.id),
      [asked, answer, again],
    );
    assert.deepEqual(lines[1].re, re, 'a reply outlives what it answered');
    assert.equal(lines[2].deleted, true);
    assert.equal(lines[2].re, undefined, JSON.stringify(lines[2]));
  });
});

describe('replies on a server that keeps less', () => {
  /** `check` a login that asked for `replies`, on a server of its own. */
  async function asking(config, check) {
    const server = await startServer({ config, accounts: { alice: account('alice') } });
    const crew = fleet(() => server);
    try {
      await check(await crew.connect({ login: 'alice', password: 'pw-alice', nick: 'alice', replies: true }));
    } finally {
      await crew.closeAll();
      await server.stop();
    }
  }

  test('an inbox alone keeps messages, and a line is not a target', () =>
    asking({ inbox: { db: 'messages.db' } }, async (alice) => {
      assert.deepEqual(alice.conn.replies, { targets: ['pm'] });
      // Without `[history]` no line has an id, so this one names nothing.
      assert.equal(await code(alice.conn.chat({ text: 'x', re: { line: 1 } })), 'bad_request');
    }));

  test('a server that keeps nothing a reply could name grants no replies', () =>
    asking({}, async (alice) => {
      assert.ok(!alice.conn.hasCap(CAP_REPLIES), JSON.stringify(alice.conn.caps));
      assert.equal(alice.conn.replies, null);
    }));
});
