/**
 * Private messages between sessions that are both here.
 *
 * The durable side — mail that waits for someone — is `inbox.test.mjs`.
 * This file is about the live path and the rules around addressing it,
 * which are mostly rules about what the server declines to tell you.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

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

describe('private messages', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: { inbox: { db: 'messages.db' } },
      accounts: { alice: account('alice'), bob: account('bob'), carol: account('carol') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, nick) => crew.connect({ login: who, password: `pw-${who}`, nick: nick ?? who });

  test('a message to a uid on the roster is delivered, not queued', async () => {
    const alice = await login('alice');
    const bob = await login('bob');

    const ok = await alice.conn.msg({ to: bob.conn.self.uid, text: 'just between us' });
    assert.equal(ok.queued, false, 'the recipient is right here');

    const got = await bob.waitFor('msg', { text: 'just between us' });
    assert.equal(got.data.from.uid, alice.conn.self.uid);
    assert.equal(got.data.from.login, 'alice', 'there is somebody to reply to');
    assert.equal(got.data.queued, false);
  });

  test('the same guid twice is one message, so a retry after a dead socket is safe', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-guid');
    const guid = '6f9619ff-8b86-d011-b42d-00c04fc964ff';

    await alice.conn.msg({ to: bob.conn.self.uid, text: 'sent once', guid });
    const first = await bob.waitFor('msg', { text: 'sent once' });

    const mark = bob.mark();
    const retry = await alice.conn.msg({ to: bob.conn.self.uid, text: 'sent once', guid });
    assert.equal(retry.queued, false, 'a retry is answered, never refused');
    await bob.expectNo('msg', { text: 'sent once' }, { since: mark });
    assert.equal(bob.seen('ev', 'msg', { text: 'sent once' }).length, 1);
    assert.ok(first.data.id === undefined || typeof first.data.id === 'number');
  });

  test('a blocked sender is told the same thing whatever the truth is', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-block');

    await bob.conn.block({ login: 'alice' });
    const blocks = await bob.conn.blocks();
    assert.ok(blocks.blocked.some((b) => b.login === 'alice'));

    const refused = await alice.conn
      .msg({ to: bob.conn.self.uid, text: 'let me in' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(refused, 'blocked');

    await bob.conn.unblock({ login: 'alice' });
    const ok = await alice.conn.msg({ to: bob.conn.self.uid, text: 'thanks' });
    assert.equal(ok.queued, false);
    await bob.waitFor('msg', { text: 'thanks' });
  });

  test('addressing failures leak nothing about who exists', async () => {
    // One code covers "no such account", "no such uid", and "that
    // account takes no offline messages", precisely so none of them can
    // be told apart by asking.
    const alice = await login('alice');

    const noUid = await alice.conn
      .msg({ to: 60000, text: 'anyone?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(noUid, 'no_such_user');

    const noLogin = await alice.conn
      .msg({ to_login: 'nobody-by-that-name', text: 'anyone?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(noLogin, 'no_such_user');
  });

  test('naming both a uid and a login is refused rather than guessed at', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-both');
    const code = await alice.conn
      .request('msg', { to: bob.conn.self.uid, to_login: 'carol', text: 'which of you?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(code, 'bad_request', 'guessing is how a message reaches the wrong person');
  });

  test('an over-long message is truncated, not refused', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-long');
    const huge = 'x'.repeat(9000);

    await alice.conn.msg({ to: bob.conn.self.uid, text: huge });
    const got = await bob.waitFor('msg', (d) => d.text.startsWith('xxxx'));
    assert.ok(got.data.text.length < huge.length, 'the wire caps it');
    assert.ok(got.data.text.length >= 4000, `expected roughly the 4096-byte cap, got ${got.data.text.length}`);
  });
});
