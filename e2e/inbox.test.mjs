/**
 * Mail that waits.
 *
 * The inbox is the part of the ng design that survives everything else:
 * the session lapses, the process restarts, and a message sent to
 * somebody who was not there is still there when they are. That means a
 * real SQLite file, which means the binary — `open_inbox` creates it
 * 0600 before SQLite touches it, migrates it, and chmods the `-wal` and
 * `-shm` beside it, and none of that is reachable from an in-process
 * test that hands `Core` a store it built itself.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { statSync } from 'node:fs';
import { join } from 'node:path';

import { fleet } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const account = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
`;

describe('the inbox', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: { inbox: { db: 'messages.db' } },
      accounts: { alice: account('alice'), bob: account('bob') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, nick) => crew.connect({ login: who, password: `pw-${who}`, nick: nick ?? who });

  test('the database is created private, before SQLite is let near it', async () => {
    // 0600 by construction rather than by umask: the file holds the text
    // of everybody's private messages, and a mode set afterwards is a
    // window during which it was readable.
    const mode = statSync(join(server.dir, 'messages.db')).mode & 0o777;
    assert.equal(mode, 0o600, `messages.db is mode ${mode.toString(8)}`);
  });

  test('mail for somebody who is not here waits for them', async () => {
    const alice = await login('alice');
    const ok = await alice.conn.msg({ to_login: 'bob', text: 'left on your desk' });
    assert.equal(ok.queued, true, 'nobody was there to hand it to');

    const bob = await login('bob');
    // Delivered as an ordinary event after the login reply, never inside
    // it — the seq is what makes it replayable if this socket dies too.
    const waiting = await bob.waitFor('msg', { text: 'left on your desk' });
    assert.equal(waiting.data.queued, true, 'and it says it had been waiting');
    assert.equal(waiting.data.from.login, 'alice');
    assert.ok(typeof waiting.data.id === 'number', 'stored mail has an id to mark read by');
  });

  test('the login reply carries a badge count before any mail arrives', async () => {
    const alice = await login('alice');
    await alice.conn.msg({ to_login: 'bob', text: 'one for the pile' });

    const bob = await login('bob', 'bob-badge');
    assert.ok(bob.conn.login.inbox, 'a server with an inbox always says so');
    assert.ok(typeof bob.conn.login.inbox.unread === 'number');
    assert.ok(typeof bob.conn.login.inbox.total === 'number');
  });

  test('inbox pages newest first, and msg_read moves the cursor', async () => {
    const alice = await login('alice');
    for (const text of ['first', 'second', 'third']) {
      await alice.conn.msg({ to_login: 'bob', text });
    }

    const bob = await login('bob', 'bob-read');
    const page = await bob.conn.inbox({ limit: 200 });
    assert.ok(page.messages.length >= 3);
    const ids = page.messages.map((m) => m.id);
    assert.deepEqual(ids, [...ids].sort((a, b) => b - a), 'newest first');

    const counts = await bob.conn.msgRead(Math.max(...ids));
    assert.equal(counts.unread, 0, 'everything up to that id is read now');
    assert.ok(counts.total >= 3, 'read is not deleted');
  });

  test('a read cursor belongs to its owner and nobody else', async () => {
    const bob = await login('bob', 'bob-owner');
    const alice = await login('alice', 'alice-owner');
    await bob.conn.msg({ to_login: 'alice', text: 'for alice only' });

    const mine = await alice.conn.inbox({ limit: 50 });
    assert.ok(mine.messages.some((m) => m.text === 'for alice only'));

    const theirs = await bob.conn.inbox({ limit: 50 });
    assert.ok(!theirs.messages.some((m) => m.text === 'for alice only'), "the sender's own inbox is not the recipient's");
  });

  test('a guest has no inbox of its own, and is told so plainly', async () => {
    // A different thing from "no such user": this is about *your*
    // account, so it gets its own code.
    const guest = await crew.connect({ nick: 'Passerby' });
    const code = await guest.conn
      .inbox({ limit: 10 })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(code, 'no_inbox');
  });
});
