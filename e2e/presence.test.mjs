/**
 * Presence: the roster, and the events that keep it true.
 *
 * Presence in this server is user-scoped rather than connection-scoped,
 * which is the change the whole ng design turns on. From a client's side
 * that shows up here — in who appears in the login snapshot, what a
 * change looks like, and when a part is a part.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const ALICE = `name = "Alice"
password = "hunter2"
[access]
read_chat = true
send_chat = true
send_msgs = true
get_user_info = true
use_any_name = true
`;

describe('presence', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({ accounts: { alice: ALICE } });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('the login reply carries the roster, so one round trip renders', async () => {
    const first = await crew.connect({ nick: 'First' });
    const second = await crew.connect({ nick: 'Second' });

    // The snapshot is the point: a mobile client draws a populated
    // window without asking a second question.
    assert.ok(second.conn.login.users.some((u) => u.uid === first.conn.self.uid));
    assert.ok(second.conn.login.users.some((u) => u.uid === second.conn.self.uid));
    assert.equal(second.conn.login.server.name, server.name);
  });

  test('a join is announced to everyone already there', async () => {
    const watcher = await crew.connect({ nick: 'Watcher' });
    const mark = watcher.mark();
    const arrival = await crew.connect({ nick: 'Arrival' });
    const ev = await watcher.waitFor('user_joined', { 'user.nick': 'Arrival' }, { since: mark });
    assert.equal(ev.data.user.uid, arrival.conn.self.uid);
    // Both fields are present whether or not the endpoints that fill
    // them are enabled, so a client can warn about an unencrypted
    // recipient without feature-detecting anything.
    assert.equal(ev.data.user.transport, 'encrypted');
    assert.equal(ev.data.user.identity, undefined);
  });

  test('a nick change is a change, not a part and a join', async () => {
    const watcher = await crew.connect({ nick: 'Watcher2' });
    const mover = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Before' });
    const mark = watcher.mark();

    await mover.conn.request('nick', { nick: 'After', icon: 42 });

    const ev = await watcher.waitFor('user_changed', { 'user.nick': 'After' }, { since: mark });
    assert.equal(ev.data.user.uid, mover.conn.self.uid, 'the same uid throughout — this is one person');
    assert.equal(ev.data.user.icon, 42);
    await watcher.expectNo('user_parted', { uid: mover.conn.self.uid }, { since: mark });
  });

  test('a guest that leaves is gone, because a guest never detaches', async () => {
    // Detach policy is per-account and defaults to has-a-password, so a
    // guest socket dying is the end of the session rather than the
    // start of a grace window. The login reply says so up front.
    const watcher = await crew.connect({ nick: 'Watcher3' });
    const passing = await crew.connect({ nick: 'Passing' });
    assert.equal(passing.conn.grace, null, 'a guest is told there is no grace window');

    const mark = watcher.mark();
    await passing.close();
    await watcher.waitFor('user_parted', { uid: passing.conn.self.uid }, { since: mark });
  });

  test('an account with a password is offered a grace window', async () => {
    const alice = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Alice' });
    assert.ok(alice.conn.grace > 0, `expected a grace window, got ${alice.conn.grace}`);
    assert.ok(alice.conn.session && alice.conn.token, 'and the credentials to use it');
  });

  test('sync re-answers the roster without disturbing the session', async () => {
    const alice = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Syncer' });
    const ok = await alice.conn.request('sync');
    assert.equal(ok.server.name, server.name);
    assert.ok(ok.users.some((u) => u.uid === alice.conn.self.uid));
    assert.ok(typeof ok.seq === 'number');
    assert.equal(alice.conn.state, 'online');
  });
});
