/**
 * Detach and resume: a session outliving its connection.
 *
 * This is the paradigm shift the ng protocol exists for, and it is the
 * part a real client exercises differently from a scripted one. The
 * library reconnects on its own — backoff, `resume`, replay — so what
 * these tests drive is a dropped socket, and what they assert is that
 * the session on the other side was still there and had kept everything
 * this client had not yet seen.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { adoptSession, fleet, rawHandshake } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const account = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
read_chat_history = true
send_chat = true
send_msgs = true
use_any_name = true
`;

describe('resume', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: { history: { db: 'history.db' } },
      accounts: { alice: account('alice'), bob: account('bob') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who) => crew.connect({ login: who, password: `pw-${who}`, nick: who });

  test('a dropped socket comes back to the same session, with what it missed', async () => {
    const alice = await login('alice');
    const bob = await login('bob');
    const uid = alice.conn.self.uid;

    // Catch up before dropping, and this is a real property rather than
    // test hygiene: the buffer a resume replays from starts at the
    // moment the socket died, so a client that resumes from a seq older
    // than that is told `resync_required` — correctly, because the
    // events in between went to a channel it had stopped reading. Bob's
    // arrival is the event in flight here.
    await alice.waitFor('user_joined', { 'user.uid': bob.conn.self.uid });
    const seqBefore = alice.conn.seq;

    const mark = alice.mark();
    alice.conn.drop();
    await alice.waitForState('reconnecting', { since: mark });

    // Said into a room the client is still a member of but has no
    // socket for. The session buffers it; the wire has nowhere to put it
    // yet.
    await bob.conn.chat({ text: 'said while you were away' });

    const resumed = await alice.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });
    assert.ok(resumed.data.replay >= 1, `expected a replay, got ${resumed.data.replay}`);
    assert.equal(alice.conn.self.uid, uid, 'the same uid — this is the same person, not a new login');

    const missed = await alice.waitFor('chat', { text: 'said while you were away' }, { since: mark });
    assert.ok(missed.seq > seqBefore, 'the replayed line is new to this client');

    // Replay continues the seq run rather than restarting it, and it is
    // continuous: the chat is not seq `seqBefore + 1`, because alice's
    // own transition to `detached` took a seq of its own first. That is
    // the invariant — every event a session should see consumes one,
    // including the ones about itself — and it is what makes
    // `last_seq` arithmetic mean anything.
    const replayed = alice.log.filter((r) => r.kind === 'ev' && r.n >= mark).map((r) => r.seq);
    assert.deepEqual(
      replayed,
      replayed.map((_, i) => seqBefore + 1 + i),
      `expected a contiguous run from ${seqBefore + 1}, got ${replayed.join(',')}`,
    );
  });

  test('the room never saw a part, because the user never left', async () => {
    // A detached session is a status change, not a departure. That is
    // the whole difference between this and a reconnecting chat client,
    // and it is what the legacy wire renders as the away color.
    const watcher = await login('alice');
    const flaky = await login('bob');
    const mark = watcher.mark();

    flaky.conn.drop();
    await flaky.waitForState('reconnecting', { since: flaky.mark() - 1 });
    await watcher.waitFor('user_changed', { 'user.uid': flaky.conn.self.uid, 'user.status': 'detached' }, { since: mark });
    await watcher.expectNo('user_parted', { uid: flaky.conn.self.uid }, { since: mark });

    await flaky.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });
    await watcher.waitFor('user_changed', { 'user.uid': flaky.conn.self.uid, 'user.status': 'active' }, { since: mark });
  });

  test('a second client holding the session takes it over, and the first is told', async () => {
    // Last device wins, which is the mobile-friendly answer: a phone
    // that wakes up and resumes should not have to argue with the
    // laptop that never closed its tab.
    const first = await login('alice');
    const second = await crew.connect({ login: 'alice', password: 'pw-alice', nick: 'alice' });

    // What sessionStorage does across a page reload, written out —
    // there is no reload here, and a shared storage slot between two
    // live clients is a bug rather than a fixture.
    await second.close();
    const taker = await crew.connect({ login: 'alice', password: 'pw-alice', nick: 'alice' });
    adoptSession(first, taker);
    const mark = first.mark();
    await taker.conn.start();

    // The library turns the wire's close reason into something a user
    // can read, so what a test can see is the sentence rather than the
    // code `replaced`.
    const ended = await first.waitForHook('onEnded', () => true, { since: mark, timeout: 20_000 });
    assert.match(ended.data.reason, /taken over/);
    assert.equal(first.conn.state, 'offline');
  });

  test('a session that logs out is gone, grace or no grace', async () => {
    const alice = await login('bob');
    const { session, token } = alice.conn;
    assert.ok(alice.conn.grace > 0, 'this account could have detached');

    await alice.conn.logout();

    // On a socket of its own, because `resume` is handshake-only and an
    // established session answers it `bad_request`. Logout means now,
    // not "in five minutes".
    const answer = await rawHandshake(server, 'resume', { session, token, last_seq: 0 });
    assert.equal(answer.error?.code, 'session_expired');
  });

  test('a token that was never minted is refused the same way', async () => {
    // One code for "no such session" and "wrong token", so neither can
    // be told from the other by trying.
    const bogus = await rawHandshake(server, 'resume', {
      session: 's_00000099',
      token: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      last_seq: 0,
    });
    assert.equal(bogus.error?.code, 'session_expired');
  });
});
