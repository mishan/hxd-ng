/**
 * The grace window actually lapsing.
 *
 * This file exists because nothing else in the tree runs the ng sweeper.
 * `crates/hxd/tests/` never spawns it — the in-process suites build an
 * `NgCtx` and call `serve`, and the sweeper is started beside that in
 * `main.rs` — so the promise at the center of the ng session model, that
 * a detached session is kept *for a while and then not*, has been tested
 * from the "kept" side only.
 *
 * It is slow on purpose. The sweeper ticks every fifteen seconds, and no
 * amount of cleverness makes a wall clock go faster, so this is its own
 * file: `node --test` runs files in parallel processes, and this one
 * spends most of its life waiting while the rest of the suite finishes.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet, rawHandshake } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const ALICE = `name = "Alice"
password = "hunter2"
[access]
read_chat = true
send_chat = true
use_any_name = true
`;

describe('the sweeper', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    // One second of grace, so the very next sweep is past it.
    server = await startServer({ config: { ng: { grace: 1 } }, accounts: { alice: ALICE } });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('a detached session that is never resumed is eventually ended', async () => {
    const watcher = await crew.connect({ nick: 'Watcher' });
    const leaver = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Alice' });
    const uid = leaver.conn.self.uid;
    const { session, token } = leaver.conn;
    assert.equal(leaver.conn.grace, 1, 'the server offered the window this test is about to outlast');

    await watcher.waitFor('user_joined', { 'user.uid': uid });
    const mark = watcher.mark();

    // Drop and *stay* dropped. The library would resume within a second
    // if left alone, which is the opposite of what is being tested, so
    // the client is torn down rather than merely disconnected.
    leaver.conn.drop();
    await watcher.waitFor('user_changed', { 'user.uid': uid, 'user.status': 'detached' }, { since: mark });
    await leaver.close();

    // Up to one tick plus the window. Generous, because a loaded CI box
    // is exactly where a tight bound turns a real pass into a red build.
    const parted = await watcher.waitFor('user_parted', { uid }, { since: mark, timeout: 45_000 });
    assert.equal(parted.data.uid, uid);
    assert.ok(
      server.lines.some((l) => /detached sessions swept/.test(l)),
      'and the server says it was the sweeper that did it',
    );

    // The credentials outlive nothing: the session they name is gone.
    const stale = await rawHandshake(server, 'resume', { session, token, last_seq: 0 });
    assert.equal(stale.error?.code, 'session_expired');
  });

  test('a session resumed inside the window survives the sweep that follows', async () => {
    // The other half of the same promise, and the reason the first test
    // is not enough on its own: a sweeper that ended everything it found
    // would pass that one.
    const alice = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Survivor' });
    const uid = alice.conn.self.uid;
    const mark = alice.mark();

    alice.conn.drop();
    await alice.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });

    // Sit through a sweep. Still here.
    await new Promise((r) => setTimeout(r, 17_000));
    assert.equal(alice.conn.state, 'online');
    const ok = await alice.conn.request('sync');
    assert.ok(ok.users.some((u) => u.uid === uid), 'still on the roster after the sweep');
  });
});
