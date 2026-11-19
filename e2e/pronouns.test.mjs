/**
 * Pronouns (docs/hotline-ng.md sections 7.3 and 7.4, system-account.md
 * section 3): set and cleared through the client library, kept in the
 * account files the binary reads, and crossing to and from the classic
 * wire.
 *
 * What the Rust suites cannot say is that a client written from the spec
 * reads the `user` object's `pronouns` where the server puts it: in the
 * login snapshot, in `self`, and in `user_changed`, whose clear is the
 * key's absence.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { CAP_PRONOUNS, pronounsValid } from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { hdr, legacyFleet, req, tag, toText } from './harness/legacy.mjs';
import { startServer } from './harness/server.mjs';

const account = (name, more = '') => `name = "${name}"
password = "pw"
[access]
read_chat = true
send_chat = true
send_msgs = true
get_user_info = true
${more}`;

const ACCOUNTS = {
  alice: account('Alice'),
  bob: account('Bob'),
  dana: account('Dana', '[profile]\npronouns = "they/them"\n'),
  erin: account('Erin'),
  hal: account('Hal', '[extra]\npronouns = false\n[profile]\npronouns = "he/him"\n'),
};

const refusal = (p) => p.then(() => null, (e) => e.wire);

const row = (users, uid) => users.find((u) => u.uid === uid);

describe('pronouns', () => {
  let server;
  const crew = fleet(() => server);
  const old = legacyFleet(() => server);

  before(async () => {
    // `[system]` for the classic `/pronouns`.
    server = await startServer({ config: { system: {} }, accounts: ACCOUNTS });
  });
  after(async () => {
    old.closeAll();
    await crew.closeAll();
    await server?.stop();
  });

  test('set over ng, every session shows them, and a later login reads them in its snapshot', async () => {
    const alice = await crew.connect({ login: 'alice', password: 'pw', nick: 'Alice' });
    const bob = await crew.connect({ login: 'bob', password: 'pw', nick: 'Bob' });
    assert.ok(alice.conn.caps.includes(CAP_PRONOUNS));
    assert.equal(alice.conn.self.pronouns, undefined);
    const uid = alice.conn.self.uid;

    const [sinceAlice, sinceBob] = [alice.mark(), bob.mark()];
    assert.deepEqual(await alice.conn.setPronouns('she/her'), {});
    // One change an account in a while, counting only those made.
    const again = await refusal(alice.conn.setPronouns('she/they'));
    assert.equal(again?.code, 'rate_limited');
    assert.ok(again.retry_after > 0, JSON.stringify(again));
    await alice.waitFor('user_changed', { 'user.uid': uid, 'user.pronouns': 'she/her' }, { since: sinceAlice });
    await bob.waitFor('user_changed', { 'user.uid': uid, 'user.pronouns': 'she/her' }, { since: sinceBob });

    const carol = await crew.connect({ nick: 'Carol' });
    assert.equal(row(carol.conn.login.users, uid)?.pronouns, 'she/her');
    assert.ok(row(carol.conn.login.users, bob.conn.self.uid), 'Bob is on the list');
    assert.equal(row(carol.conn.login.users, bob.conn.self.uid).pronouns, undefined);

    // The classic wire sees them in Get User Info alone.
    const ed = await old.login({ login: 'erin', password: 'pw', nick: 'Ed' });
    const info = await ed.request(req.USER_GETINFO, [[tag.UID, Buffer.from([uid >> 8, uid & 0xff])]]);
    assert.match(toText(info.get(tag.BODY)), /^ {4}name: Alice\rpronouns: she\/her\r/);
  });

  test('pronouns kept in the account file show at login, and a clear takes them away', async () => {
    const dana = await crew.connect({ login: 'dana', password: 'pw', nick: 'Dana' });
    const bob = await crew.connect({ login: 'bob', password: 'pw', nick: 'Bob' });
    const uid = dana.conn.self.uid;
    assert.equal(dana.conn.self.pronouns, 'they/them');
    assert.equal(row(bob.conn.login.users, uid)?.pronouns, 'they/them');

    const since = bob.mark();
    assert.deepEqual(await dana.conn.setPronouns(null), {});
    const cleared = await bob.waitFor('user_changed', (d) => d.user.uid === uid && !('pronouns' in d.user), { since });
    assert.equal(cleared.data.user.nick, 'Dana');

    const later = await crew.connect({ nick: 'Later' });
    assert.ok(row(later.conn.login.users, uid), 'still on the list');
    assert.equal(row(later.conn.login.users, uid).pronouns, undefined);
  });

  test('set with the classic /pronouns, an ng client sees them', async () => {
    const watcher = await crew.connect({ login: 'bob', password: 'pw', nick: 'Watcher' });
    const erin = await old.login({ login: 'erin', password: 'pw', nick: 'Erin' });
    const users = await erin.users();
    const system = users.find((u) => u.nick === 'Server');
    assert.ok(system, 'the system account is on the list');
    const { uid } = users.find((u) => u.nick === 'Erin');

    const since = watcher.mark();
    const mark = erin.mark();
    await erin.msg(system.uid, '/pronouns xe/xem');
    const answer = await erin.waitFor(
      (f) => f.type === hdr.MSG && f.get(tag.UID)?.readUInt16BE(0) === system.uid,
      { since: mark },
    );
    assert.equal(toText(answer.get(tag.BODY)), 'ok: your pronouns are xe/xem');
    await watcher.waitFor('user_changed', { 'user.uid': uid, 'user.pronouns': 'xe/xem' }, { since });

    const later = await crew.connect({ nick: 'Later' });
    assert.equal(row(later.conn.login.users, uid)?.pronouns, 'xe/xem');
  });

  test('a set is refused for a value the client would refuse, a guest, and an account that may not', async () => {
    const bob = await crew.connect({ login: 'bob', password: 'pw', nick: 'Bob' });
    for (const value of ['she  her', ' she', 'a'.repeat(33)]) {
      assert.equal(pronounsValid(value), false, value);
      assert.equal((await refusal(bob.conn.setPronouns(value)))?.code, 'bad_request', value);
    }

    const guest = await crew.connect({ nick: 'Guest' });
    assert.equal((await refusal(guest.conn.setPronouns('she/her')))?.code, 'access_denied');

    // `[extra] pronouns = false` hides what the file keeps and refuses a set.
    const hal = await crew.connect({ login: 'hal', password: 'pw', nick: 'Hal' });
    assert.equal(hal.conn.self.pronouns, undefined);
    const later = await crew.connect({ nick: 'Later' });
    assert.ok(row(later.conn.login.users, hal.conn.self.uid), 'Hal is on the list');
    assert.equal(row(later.conn.login.users, hal.conn.self.uid).pronouns, undefined);
    assert.equal((await refusal(hal.conn.setPronouns('he/him')))?.code, 'access_denied');

    // None of those was a change, so none waits its turn.
    assert.deepEqual(await bob.conn.setPronouns('he/they'), {});
  });
});

describe('pronouns on a server that shows none', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({ config: { server: { pronouns: false } }, accounts: ACCOUNTS });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('no capability, nothing shown, a set not_available and a clear still taken', async () => {
    const dana = await crew.connect({ login: 'dana', password: 'pw', nick: 'Dana' });
    assert.ok(!dana.conn.caps.includes(CAP_PRONOUNS), JSON.stringify(dana.conn.caps));
    assert.equal(dana.conn.self.pronouns, undefined);
    assert.equal((await refusal(dana.conn.setPronouns('they/them')))?.code, 'not_available');
    assert.deepEqual(await dana.conn.setPronouns(null), {});
    assert.doesNotMatch(readFileSync(join(server.dir, 'accounts', 'dana.toml'), 'utf8'), /pronouns/);
  });
});
