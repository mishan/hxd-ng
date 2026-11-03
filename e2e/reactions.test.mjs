/**
 * Reactions read again (hotline-ng.md §7.3): `reactions`, as the
 * library's `reactionsGet` sends it, against the binary built from a
 * real `[reactions]` section. `crates/hxd/tests/reactions.rs` holds the
 * server to the rest; here the two implementations agree on the reply's
 * shape and on a key's spelling.
 */

import assert from 'node:assert/strict';
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
