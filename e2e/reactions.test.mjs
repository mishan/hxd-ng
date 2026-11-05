/**
 * Reactions (hotline-ng.md §7.3): `reactions`, as the library's
 * `reactionsGet` sends it, and `react` on a stored and an instant
 * message, against the binary built from real `[reactions]`, `[inbox]`
 * and `[messaging]` sections. `crates/hxd/tests/reactions.rs` holds the
 * server to the rest; here the two implementations agree on the replies'
 * and the changes' shapes and on a key's spelling.
 */

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const account = (name, extra = '') => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
read_chat_history = true
send_chat = true
use_any_name = true
${extra}`;

const UP = { emoji: '\u{1F44D}' };
const TADA = { emoji: '\u{1F389}' };

describe('reactions read again', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: () => ({ history: { db: 'history.db' }, reactions: { enabled: true } }),
      accounts: {
        alice: account('alice'),
        bob: account('bob'),
        boss: account('boss', '[extra]\nmanage_rooms = true\n'),
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, nick = who) => crew.connect({ login: who, password: `pw-${who}`, nick, reactions: true });
  const say = async (c, params) => (await c.conn.chat(params)).id;

  test("a line is answered with its keys and the reader's own, and one it could not have read is left out", async () => {
    const boss = await login('boss');
    const room = (await boss.conn.roomCreate({ name: 'staff', read: ['alice'] })).room.id;
    const [alice, bob] = [await login('alice'), await login('bob')];
    await alice.conn.roomJoin(room);
    const hi = await say(alice, { text: 'hi' });
    const inside = { line: await say(alice, { text: 'in here', room }), room };
    await bob.conn.react({ line: hi }, UP);
    await alice.conn.react({ line: hi }, TADA);
    await alice.conn.react(inside, UP);

    const keys = [
      { key: UP, count: 1 },
      { key: TADA, count: 1 },
    ];
    assert.deepEqual(await bob.conn.reactionsGet([inside, { line: hi }]), {
      reactions: [{ target: { line: hi }, keys, mine: [0] }],
    });
    assert.deepEqual(await alice.conn.reactionsGet([inside, { line: hi }]), {
      reactions: [
        { target: inside, keys: [{ key: UP, count: 1 }], mine: [0] },
        { target: { line: hi }, keys, mine: [1] },
      ],
    });
  });

  test('with a key, who holds it is named by nick, never by login, newest first', async () => {
    const [alice, bob] = [await login('alice'), await login('bob', 'Bobby')];
    const line = { line: await say(alice, { text: 'cake?' }) };
    // Sent without its emoji selector, and spelled with one coming back.
    await bob.conn.react(line, { emoji: '\u2764' });
    await alice.conn.react(line, { emoji: '\u2764\uFE0F' });

    const [got] = (await alice.conn.reactionsGet([line], { emoji: '\u2764' })).reactions;
    assert.deepEqual(got.keys, [{ key: { emoji: '\u2764\uFE0F' }, count: 2 }]);
    assert.deepEqual(got.from, [{ nick: 'alice' }, { nick: 'Bobby' }]);
  });
});

describe('reactions on messages', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: () => ({
        history: { db: 'history.db' },
        inbox: { db: 'messages.db' },
        messaging: { enabled: true },
        reactions: { enabled: true },
      }),
      // alice, bob and carol take no part in messaging, so mail by login
      // between them is stored rather than a request.
      accounts: Object.fromEntries(
        ['alice', 'bob', 'carol', 'dave', 'eve'].map((p) => [
          p,
          account(p, `send_msgs = true\nmessaging = ${['dave', 'eve'].includes(p)}\n`),
        ]),
      ),
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, messaging = false) =>
    crew.connect({ login: who, password: `pw-${who}`, nick: who, messaging, reactions: true });

  test('the login block lists every kind of target', async () => {
    const dave = await login('dave', true);
    assert.deepEqual([...dave.conn.reactions.targets].sort(), ['im', 'line', 'pm']);
  });

  test('a stored message is answered {}, told to its sender and read back by both parties alone', async () => {
    const alice = await login('alice');
    const sent = await alice.conn.msg({ to_login: 'bob', text: 'left on your desk' });
    assert.equal(sent.queued, true);
    assert.equal(sent.im, undefined);
    const target = { pm: sent.ref };

    const bob = await login('bob');
    assert.equal((await bob.waitFor('msg', { ref: sent.ref })).data.text, 'left on your desk');
    assert.deepEqual(await bob.conn.react(target, UP), {});

    const told = await alice.waitFor('reactions_changed', (d) => d.changes.some((c) => c.target.pm === sent.ref));
    assert.deepEqual(told.data.changes, [{ target, action: 'summary', keys: [{ key: UP, count: 1 }] }]);
    assert.deepEqual(await alice.conn.reactionsGet([target]), {
      reactions: [{ target, keys: [{ key: UP, count: 1 }] }],
    });
    assert.deepEqual(await bob.conn.reactionsGet([target]), {
      reactions: [{ target, keys: [{ key: UP, count: 1 }], mine: [0] }],
    });
    const carol = await login('carol');
    assert.deepEqual(await carol.conn.reactionsGet([target]), { reactions: [{ target, keys: [] }] });
  });

  test("an instant message's reply says so, and a reaction to it reaches the other party", async () => {
    const [dave, eve] = [await login('dave', true), await login('eve', true)];
    await dave.conn.friendAdd('eve');
    await eve.waitFor('friend_request', { login: 'dave' });
    await eve.conn.friendRespond('dave', true);
    await dave.waitFor('friend', { 'friend.login': 'eve', 'friend.state': 'accepted' });

    const guid = randomUUID();
    const { queued, im, guid: named } = await dave.conn.msg({ to_login: 'eve', text: 'lunch?', guid });
    assert.deepEqual({ queued, im, named }, { queued: false, im: true, named: guid });
    await eve.waitFor('im', { guid });
    const target = { im: { login: 'dave', guid } };
    assert.deepEqual(await eve.conn.react(target, TADA, { with: 'dave' }), {});

    const told = await dave.waitFor('reactions_changed', (d) => d.changes.some((c) => c.target.im?.guid === guid));
    assert.deepEqual(told.data.changes, [{ target, action: 'add', key: TADA, from: { login: 'eve' } }]);
  });
});
