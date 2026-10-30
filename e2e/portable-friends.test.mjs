/**
 * Portable friendships (hotline-ng.md §7.5, proposals/portable-friends.md):
 * two real servers, and people with a device on each.
 *
 * `crates/hxd/tests/portable_friends.rs` signs every object with
 * hl-identity, the crate the server checks them with. Here the offers,
 * acceptances and withdrawals are signed by the library a browser uses,
 * from the spec, with keys WebCrypto will not export, and what the
 * server hands back is checked by that library again; where the two
 * agree byte for byte, two implementations do. What only the binary
 * can show is the operator's side: a device revoked in the config file,
 * on SIGHUP or at the next start, takes its presentations with it, and
 * what a server took is on disk across a restart.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, before, describe, test } from 'node:test';

import {
  base64urlToBytes,
  bytesToBase64url,
  checkFriendOffer,
  checkFriendship,
  fingerprintFromString,
  fingerprintOf,
  friendshipBytes,
  pairHash,
  signFriendAcceptance,
  signFriendOffer,
  signFriendWithdrawal,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { enrolledDevice, signingIdentity } from './harness/device.mjs';
import { hxdCommand, startServer } from './harness/server.mjs';

const DAY = 24 * 3600;
const b64 = bytesToBase64url;
const unb64 = base64urlToBytes;
const now = () => Math.floor(Date.now() / 1000);
const hash = (f) => b64(createHash('sha256').update(f).digest());
const fp = (dev) => fingerprintFromString(dev.fingerprint);

const account = (name, fingerprint) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
messaging = true
[identity]
fingerprint = "${fingerprint}"
`;

const start = () =>
  startServer({
    config: (ports) => ({ inbox: { db: 'messages.db' }, messaging: { enabled: true }, identity: signingIdentity(ports) }),
  });

async function logged(server, pattern, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.lines.some((l) => pattern.test(l))) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`the server never logged ${pattern}\n${server.log()}`);
}

const offer = (from, to) =>
  signFriendOffer(from.key, { from: from.identity, to: fp(to), time: now() - 60, expires: now() + DAY, cert: from.cert });

async function accept(raw, by) {
  const acceptance = await signFriendAcceptance(by.key, { offer: raw, from: by.identity, time: now() - 60, cert: by.cert });
  return friendshipBytes(raw, acceptance);
}

const withdraw = async (by, other, before) =>
  signFriendWithdrawal(by.key, { from: by.identity, pair: await pairHash(fp(by), fp(other)), before, time: now(), cert: by.cert });

const accepted = (login, f) => (d) =>
  d.friend.login === login && d.friend.state === 'accepted' && (!f || d.friend.friendships?.[0] === hash(f));
const removed = (login) => (d) => d.friend.login === login && d.friend.state === 'removed';

describe('portable friendships across two servers', () => {
  let one;
  let two;
  const crewOne = fleet(() => one);
  const crewTwo = fleet(() => two);

  before(async () => {
    [one, two] = await Promise.all([start(), start()]);
  });
  after(async () => {
    await crewOne.closeAll();
    await crewTwo.closeAll();
    await Promise.all([one?.stop(), two?.stop()]);
  });

  /** `name` with an identity of its own, an account linked to it on both
   *  servers, and a device on each. */
  async function person(name) {
    const first = await enrolledDevice(one, name);
    const second = await enrolledDevice(two, name, first.identityFile);
    for (const s of [one, two]) s.account(name, account(name, first.fingerprint));
    return { name, devices: [first, second] };
  }

  async function signIn(crew, who, dev) {
    const c = await crew.connect({
      nick: who.name,
      identity: { getToken: dev.getToken },
      messaging: true,
      friendships: true,
    });
    assert.ok(c.conn.caps.includes('friendships'), JSON.stringify(c.conn.caps));
    return c;
  }

  /** `a` and `b` made friends on the first server, a portable friendship
   *  from the start: its bytes and both sessions there. */
  async function befriend(a, b) {
    const [a1, b1] = [await signIn(crewOne, a, a.devices[0]), await signIn(crewOne, b, b.devices[0])];
    const o = await offer(a.devices[0], b.devices[0]);
    assert.deepEqual(await a1.conn.friendAdd(b.name, undefined, b64(o)), { state: 'pending_out' });
    const asked = await b1.waitFor('friend_request', { login: a.name });
    assert.equal(asked.data.offer, b64(o), 'the offer as signed');
    const checked = await checkFriendOffer(unb64(asked.data.offer), now());
    assert.equal(await fingerprintOf(checked.from), a.devices[0].fingerprint);
    const f = await accept(o, b.devices[0]);
    assert.deepEqual(await b1.conn.friendRespond(a.name, true, b64(f)), { state: 'accepted' });
    await a1.waitFor('friend', accepted(b.name, f));
    return { f, a1, b1 };
  }

  /** Both present `f` on the second server, where neither has asked for
   *  anything: friends there with no request. */
  async function carry(f, a, b, a2Signed) {
    const a2 = a2Signed ?? (await signIn(crewTwo, a, a.devices[1]));
    const b2 = await signIn(crewTwo, b, b.devices[1]);
    for (const c of [a2, b2]) {
      assert.deepEqual((await c.conn.friendshipsPresent({ friendships: [b64(f)] })).friendships, [{ hash: hash(f), result: 'ok' }]);
    }
    await a2.waitFor('friend', accepted(b.name, f));
    return { a2, b2 };
  }

  test('a friendship the library signed on one server is in place on the next, with no request', async () => {
    const [alice, bob] = [await person('alice'), await person('bob')];
    const { f } = await befriend(alice, bob);

    const a2 = await signIn(crewTwo, alice, alice.devices[1]);
    const found = await a2.conn.findUser({ fingerprint: bob.devices[1].fingerprint });
    assert.equal(found.user.login, 'bob', 'found by the identity, not the login');
    const { b2 } = await carry(f, alice, bob, a2);
    const listed = (await b2.conn.friends()).friends.find((e) => e.login === 'alice');
    assert.deepEqual(listed.friendships, [hash(f)]);

    // What the server keeps is the bytes as signed, which the library
    // checks again on the way back.
    const { friendships } = await b2.conn.friendshipsFetch({ hashes: [hash(f)] });
    assert.deepEqual(friendships, [{ hash: hash(f), friendship: b64(f) }]);
    const back = await checkFriendship(unb64(friendships[0].friendship), now());
    assert.deepEqual(back.pair, await pairHash(fp(alice.devices[0]), fp(bob.devices[0])));
  });

  test('a withdrawal on one server ends the friendship on the other, and the friendship is refused there after', async () => {
    const [carol, dave] = [await person('carol'), await person('dave')];
    const { f, a1: carol1, b1: dave1 } = await befriend(carol, dave);
    const { a2: carol2, b2: dave2 } = await carry(f, carol, dave);

    const cutoff = now();
    const w = await withdraw(carol.devices[1], dave.devices[1], cutoff);
    await carol2.conn.friendRemove({ login: 'dave', withdraw: b64(w) });
    const gone = await dave2.waitFor('friend', removed('carol'));
    assert.equal(gone.data.friend.withdraw, b64(w));

    // A server takes a withdrawal only under the presenting device's own
    // certificate, so Carol's other device signs the same cutoff again.
    const again = await withdraw(carol.devices[0], dave.devices[0], cutoff);
    const since = dave1.mark();
    const taken = await carol1.conn.friendshipsPresent({ withdrawals: [b64(again)] });
    assert.equal(taken.withdrawals[0].result, 'ok');
    const there = await dave1.waitFor('friend', removed('carol'), { since });
    assert.equal(there.data.friend.withdraw, b64(again));
    const refused = await dave1.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.deepEqual(refused.friendships, [{ hash: hash(f), result: 'withdrawn', withdraw: b64(again) }]);
  });

  test('a device revoked in the file, on SIGHUP, takes what it presented with it', async () => {
    const [eve, finn] = [await person('eve'), await person('finn')];
    const { f } = await befriend(eve, finn);
    const { a2: eve2, b2: finn2 } = await carry(f, eve, finn);

    const device = await fingerprintOf(eve.devices[1].device);
    let since = finn2.mark();
    const r = hxdCommand(two, ['identity', 'revoke', device, '--device']);
    assert.equal(r.status, 0, r.stderr);
    two.proc.kill('SIGHUP');
    await logged(two, /SIGHUP: \d+ revoked keys installed .*; 1 sessions ended/);
    await eve2.waitFor('kicked', () => true);
    const gone = await finn2.waitFor('friend', removed('eve'), { since });
    assert.equal(gone.data.friend.withdraw, undefined, 'a revocation is no withdrawal');

    // Eve's other device brings the friendship back: it was never ended.
    const eveAgain = await signIn(crewTwo, eve, await enrolledDevice(two, 'eve', eve.devices[0].identityFile));
    since = finn2.mark();
    const back = await eveAgain.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.equal(back.friendships[0].result, 'ok');
    await finn2.waitFor('friend', accepted('eve', f), { since });
  });

  // Last: the restart ends every session on the second server.
  test('what a server took is kept across a restart, and a device revoked while it was down is dropped as it starts', async () => {
    const [gail, hugo, ines, jack] = [await person('gail'), await person('hugo'), await person('ines'), await person('jack')];
    const kept = (await befriend(gail, hugo)).f;
    const dropped = (await befriend(ines, jack)).f;
    await carry(kept, gail, hugo);
    await carry(dropped, ines, jack);

    await crewTwo.closeAll();
    const r = hxdCommand(two, ['identity', 'revoke', await fingerprintOf(ines.devices[1].device), '--device']);
    assert.equal(r.status, 0, r.stderr);
    await two.restart();

    const hugo2 = await signIn(crewTwo, hugo, hugo.devices[1]);
    const jack2 = await signIn(crewTwo, jack, jack.devices[1]);
    const roster = (await hugo2.conn.friends()).friends.find((e) => e.login === 'gail');
    assert.equal(roster?.state, 'accepted', JSON.stringify(roster));
    assert.deepEqual(roster.friendships, [hash(kept)]);
    const fetched = await hugo2.conn.friendshipsFetch({ hashes: [hash(kept)] });
    assert.equal(fetched.friendships[0].friendship, b64(kept));
    const left = (await jack2.conn.friends()).friends.find((e) => e.login === 'ines');
    assert.equal(left, undefined, JSON.stringify(left));
  });
});
