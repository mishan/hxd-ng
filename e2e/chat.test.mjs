/**
 * Chat over the ng wire, against a real server.
 *
 * Worth reading alongside `crates/hxd/tests/ng.rs`: that suite asserts
 * much of the same behavior with JSON the server's own author wrote.
 * Here the frames are built and parsed by a client that has never seen
 * `hxd-core`, so the agreement is evidence about the wire rather than
 * about one person's reading of it.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { connect } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const BOB = `name = "Bob"
password = "s3cret"
[access]
read_chat = true
read_chat_history = true
send_chat = true
send_msgs = true
use_any_name = true
`;

describe('chat', () => {
  let server;
  const open = [];

  before(async () => {
    server = await startServer({
      config: { history: { db: 'history.db' } },
      accounts: { bob: BOB },
    });
  });

  after(async () => {
    for (const c of open) await c.close();
    await server?.stop();
  });

  /** Every client this file makes gets closed, whatever the test does.
   *  The reconnect timer is ref'd, so one left running holds the whole
   *  file open past its last assertion. */
  async function client(creds) {
    const c = await connect(server, creds);
    open.push(c);
    return c;
  }

  test('a line reaches the room, and its sender', async () => {
    const alice = await client({ nick: 'Alice' });
    const bob = await client({ login: 'bob', password: 's3cret', nick: 'Bob' });

    await alice.conn.chat({ text: 'the room is open' });

    const heard = await bob.waitFor('chat', { text: 'the room is open' });
    assert.equal(heard.data.from.nick, 'Alice');
    assert.equal(heard.data.style, 'normal');

    // The sender is not a special case — it hears itself, which is the
    // rule every other assertion in this suite is written around.
    const echo = await alice.waitFor('chat', { text: 'the room is open' });
    assert.equal(echo.data.from.uid, alice.conn.self.uid);
  });

  test('an action line keeps its style across the wire', async () => {
    const alice = await client({ nick: 'Actor' });
    await alice.conn.chat({ text: 'waves', style: 'action' });
    const heard = await alice.waitFor('chat', { text: 'waves' });
    assert.equal(heard.data.style, 'action');
  });

  test('seqs are gapless, including for events this client cannot name', async () => {
    // The invariant the whole ng session model rests on: every event a
    // session should see consumes a seq, so `resume`'s `last_seq`
    // arithmetic means something. A hole is not cosmetic — it is a
    // replay that silently skips a message.
    //
    // Recording from the trace rather than from `Connection.on` is what
    // makes this checkable: an event the client has no handler for is
    // dropped before dispatch, and those are exactly the placeholder
    // frames whose seqs matter most here.
    const watcher = await client({ nick: 'Watcher' });
    const talker = await client({ nick: 'Talker' });

    for (const text of ['one', 'two', 'three']) {
      await talker.conn.chat({ text });
    }
    await watcher.waitFor('chat', { text: 'three' });
    await talker.close();
    await watcher.waitFor('user_parted', { uid: talker.conn.self.uid });

    const seqs = watcher.log.filter((r) => r.kind === 'ev').map((r) => r.seq);
    assert.ok(seqs.length >= 4, `expected several events, saw ${seqs.length}`);
    assert.deepEqual(
      seqs,
      seqs.map((_, i) => seqs[0] + i),
      `seqs must ascend without a hole, got ${seqs.join(',')}`,
    );
    assert.equal(watcher.conn.seq, seqs[seqs.length - 1]);
  });

  test('a persisted line carries the id history will page it under', async () => {
    const alice = await client({ login: 'bob', password: 's3cret', nick: 'Scribe' });
    await alice.conn.chat({ text: 'for the record' });
    const line = await alice.waitFor('chat', { text: 'for the record' });
    assert.ok(typeof line.data.id === 'number', 'a server with history gives a chat line an id');

    const page = await alice.conn.history({ limit: 200 });
    const found = page.lines.find((l) => l.id === line.data.id);
    assert.ok(found, `line ${line.data.id} should be in history, saw ${page.lines.length} lines`);
    assert.equal(found.text, 'for the record');
  });
});
