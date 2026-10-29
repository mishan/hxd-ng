/**
 * Instant messaging: friends, their presence, instant messages with
 * receipts and typing, and message requests (hotline-ng.md §7.5).
 *
 * `crates/hxd/tests/friends.rs` drives the family with the server's own
 * scripted client against a `Core` it built, and spawns the presence
 * flusher itself. Here the binary reads `[messaging]` and `[inbox]` from
 * its file, `main.rs` starts the flusher or nothing tells a friend of a
 * change, and the client is the library a browser uses, which asks for
 * `friends` after a login on its own.
 */

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startFailing, startServer } from './harness/server.mjs';

const account = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
messaging = true
`;

const PEOPLE = ['alice', 'bob', 'carol', 'dave', 'eve', 'finn', 'nora', 'omar', 'pia', 'quinn', 'rex', 'sam'];

/** Every event only a session that speaks the family is sent, and the
 *  placeholder a server sends for one a client cannot read. */
const FAMILY = ['friend', 'friend_request', 'presence', 'im', 'receipt', 'typing', 'requests_changed', 'unsupported'];

describe('instant messaging', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: { inbox: { db: 'messages.db' }, messaging: { enabled: true } },
      accounts: Object.fromEntries(PEOPLE.map((p) => [p, account(p)])),
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, messaging = true) =>
    crew.connect({ login: who, password: `pw-${who}`, nick: who, messaging });

  async function befriended(x, y) {
    const a = await login(x);
    const b = await login(y);
    assert.deepEqual(await a.conn.friendAdd(y), { state: 'pending_out' });
    await b.waitFor('friend_request', { login: x });
    assert.deepEqual(await b.conn.friendRespond(x, true), { state: 'accepted' });
    await a.waitFor('friend', { 'friend.login': y, 'friend.state': 'accepted' });
    return [a, b];
  }

  test('two clients become friends, and a burst of presence reaches the friend once, as it ended', async () => {
    const alice = await login('alice');
    assert.ok(alice.conn.caps.includes('messaging'), JSON.stringify(alice.conn.caps));
    assert.equal(alice.conn.messaging.takes_part, true);
    assert.equal(alice.conn.messaging.state, 'online');
    const bob = await login('bob');

    assert.deepEqual(await alice.conn.friendAdd('bob', "hi, it's alice"), { state: 'pending_out' });
    const asked = await bob.waitFor('friend_request', { login: 'alice' });
    assert.equal(asked.data.note, "hi, it's alice");
    assert.deepEqual((await bob.conn.friends()).friends, [{ login: 'alice', state: 'pending_in', note: "hi, it's alice" }]);
    assert.deepEqual(await bob.conn.friendRespond('alice', true), { state: 'accepted' });
    await alice.waitFor('friend', { 'friend.login': 'bob', 'friend.state': 'accepted' });

    // A friend is shown what alice's friends were last told, so her
    // sign-on may still be owed; once it is told, what follows is a burst
    // of its own.
    const row = await bob.waitFor('friend', { 'friend.login': 'alice', 'friend.state': 'accepted' });
    if (row.data.friend.presence !== 'online') await bob.waitFor('presence', { login: 'alice', state: 'online' });

    const mark = bob.mark();
    await alice.conn.setPresence({ state: 'busy', status_text: 'in a meeting' });
    await alice.conn.setPresence({ state: 'away', status_text: 'at lunch' });
    const told = await bob.waitFor('presence', { login: 'alice' }, { since: mark });
    assert.deepEqual(told.data, { login: 'alice', state: 'away', status_text: 'at lunch' });
  });

  test('an instant message is received and read, and typing is shown', async () => {
    const [carol, dave] = await befriended('carol', 'dave');
    const guid = randomUUID();
    assert.equal((await carol.conn.msg({ to_login: 'dave', text: 'lunch?', guid })).queued, false);
    const im = await dave.waitFor('im', { guid });
    assert.equal(im.data.text, 'lunch?');
    assert.equal(im.data.from.login, 'carol');
    assert.equal(im.data.queued, false);
    assert.equal(im.data.approval, undefined);
    assert.equal(dave.seen('ev', 'msg', { text: 'lunch?' }).length, 0, 'an instant message, never mail too');

    for (const read of [false, true]) {
      await dave.conn.receipt('carol', guid, read);
      const receipt = await carol.waitFor('receipt', { guid, read });
      assert.deepEqual(receipt.data, { login: 'dave', guid, read });
    }
    for (const typing of [true, false]) {
      const mark = carol.mark();
      await dave.conn.typing('carol', typing);
      await carol.waitFor('typing', { login: 'dave', typing }, { since: mark });
    }
  });

  test('a message to a friend away waits for their next login, and a read for the sender', async () => {
    const [eve, finn] = await befriended('eve', 'finn');
    await finn.close();
    const guid = randomUUID();
    const sent = await eve.conn.msg({ to_login: 'finn', text: 'while you were out', guid });
    assert.equal(sent.queued, true);
    assert.equal(typeof sent.id, 'number');

    // The library reads the roster after the login unasked, and that
    // read is what hands it over.
    const back = await login('finn');
    const roster = await back.waitForHook('onFriends');
    assert.deepEqual(roster.data.friends.map((f) => [f.login, f.state]), [['eve', 'accepted']]);
    const im = await back.waitFor('im', { guid });
    assert.equal(im.data.queued, true);
    assert.equal(im.data.id, sent.id);
    assert.equal(im.data.text, 'while you were out');
    assert.equal(back.seen('ev', 'msg').length, 0, 'an instant message, never mail too');

    // Not acknowledged, so handed over again at the next read; read, so
    // not.
    let mark = back.mark();
    await back.conn.friends();
    await back.waitFor('im', { guid }, { since: mark });
    await eve.close();
    await back.conn.receipt('eve', guid, true);
    mark = back.mark();
    await back.conn.friends();
    await back.expectNo('im', { guid }, { since: mark });

    const sender = await login('eve');
    await sender.waitForHook('onFriends');
    const read = await sender.waitFor('receipt', { guid });
    assert.deepEqual(read.data, { login: 'finn', guid, read: true });
  });

  test('a message request is listed, approved and answered, and takes_requests outlives the session', async () => {
    const nora = await login('nora');
    const omar = await login('omar');
    await nora.conn.setPresence({ takes_requests: true });
    // Listing his own makes omar's a session that understands requests,
    // which is what a request may only be sent from.
    assert.equal((await omar.conn.requests()).takes_requests, false);

    const guid = randomUUID();
    assert.deepEqual(await omar.conn.msg({ to_login: 'nora', text: 'hello nora', guid }), {
      queued: true,
      requested: true,
    });
    await nora.waitFor('requests_changed', { count: 1 });
    const listed = await nora.conn.requests();
    assert.equal(listed.takes_requests, true);
    assert.deepEqual(listed.approvals, []);
    assert.deepEqual(
      listed.requests.map((r) => [r.login, r.messages.map((m) => [m.text, m.guid])]),
      [['omar', [['hello nora', guid]]]],
    );

    await nora.conn.requestAnswer('omar', 'approve');
    assert.equal((await nora.waitFor('im', { guid })).data.approval, true);
    const reply = randomUUID();
    assert.equal((await nora.conn.msg({ to_login: 'omar', text: 'hi omar', guid: reply })).queued, true);
    assert.equal((await omar.waitFor('im', { guid: reply })).data.approval, true);
    await omar.conn.receipt('nora', reply, true);
    await nora.waitFor('receipt', { guid: reply, login: 'omar', read: true });

    // Clearing takes every request and leaves the approval.
    const pia = await login('pia');
    await pia.conn.requests();
    assert.deepEqual(await pia.conn.msg({ to_login: 'nora', text: 'me too' }), { queued: true, requested: true });
    const quinn = await login('quinn');
    assert.deepEqual(await quinn.conn.friendAdd('nora'), { state: 'pending_out' });
    await nora.waitFor('friend_request', { login: 'quinn' });
    assert.deepEqual(await nora.conn.requestsClear(), { declined: 1, deleted: 1 });
    const left = await nora.conn.requests();
    assert.deepEqual(left.requests, []);
    assert.deepEqual(left.approvals.map((a) => a.login), ['omar']);

    await nora.close();
    const again = await login('nora');
    assert.equal(again.conn.messaging.takes_requests, true);
  });

  test('a session that never declared messaging is sent none of it until it asks', async () => {
    const rex = await login('rex');
    const sam = await login('sam', false);
    assert.equal(sam.conn.messaging.takes_part, true, 'the block is there whether or not the login said messaging');

    assert.deepEqual(await rex.conn.friendAdd('sam'), { state: 'pending_out' });
    const code = await rex.conn
      .msg({ to_login: 'sam', text: 'are you there?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(code, 'not_friends');
    await sam.expectNo('friend_request', () => true);
    assert.deepEqual(
      sam.log.filter((r) => r.kind === 'ev' && (FAMILY.includes(r.name) || r.name === 'msg')).map((r) => r.name),
      [],
    );
    assert.equal(sam.seen('hook', 'onFriends').length, 0);

    // Its first request of the family makes it a session that speaks it,
    // and the library then reads the roster a login would have.
    await sam.conn.findUser('rex');
    const roster = await sam.waitForHook('onFriends');
    assert.deepEqual(roster.data.friends.map((f) => [f.login, f.state]), [['rex', 'pending_in']]);
    await rex.conn.friendRemove('sam');
    await sam.waitFor('friend', { 'friend.login': 'rex', 'friend.state': 'removed' });
  });
});

test('[messaging] without [inbox] is refused at startup', async () => {
  const { code, output } = await startFailing({ config: { messaging: { enabled: true } } });
  assert.notEqual(code, 0);
  assert.match(output, /\[messaging\] needs \[inbox\]: instant messages are kept there/);
});
