/**
 * Portable friendships (hotline-ng.md §7.5, proposals/portable-friends.md):
 * real servers, and people with a device on each.
 *
 * `crates/hxd/tests/portable_friends.rs` signs every object with
 * hl-identity, the crate the server checks them with. Here the offers,
 * acceptances and withdrawals are signed by the library a browser uses,
 * from the spec, with keys WebCrypto will not export, and what the
 * server hands back is checked by that library again; where the two
 * agree byte for byte, two implementations do. What only the binary can show is the operator's side: a device
 * revoked in the config file, on SIGHUP or at the next start, taking its
 * presentations with it, what a server took being on disk across a
 * restart, an identity unlinked through the endpoint, and a rotation
 * published by a registrar `hlid` drove, which a server that trusts it
 * applies and serves to the friend's client to check.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import {
  FRIENDSHIPS_PER_REQUEST,
  FriendshipRefused,
  base64urlToBytes,
  bytesToBase64url,
  checkFriendOffer,
  checkFriendship,
  checkWithdrawalPair,
  fingerprintFromString,
  fingerprintOf,
  friendshipBytes,
  pairHash,
  parseFriendWithdrawal,
  parseRotation,
  rotationChainEnd,
  signFriendAcceptance,
  signFriendOffer,
  signFriendWithdrawal,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { enrolledDevice, signingIdentity } from './harness/device.mjs';
import { hdr, legacyFleet, tag, toText } from './harness/legacy.mjs';
import { hlid, hxdCommand, startServer } from './harness/server.mjs';

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
${fingerprint ? `[identity]\nfingerprint = "${fingerprint}"\n` : ''}`;

/** A server that takes part in messaging and verifies identities, with
 *  `identity` over the `[identity]` every one here has. */
const start = (identity = () => ({})) =>
  startServer({
    config: (ports) => ({
      inbox: { db: 'messages.db' },
      messaging: { enabled: true },
      identity: { ...signingIdentity(ports), ...identity(ports) },
    }),
  });

/** A request's refusal code, or `ok`. */
const code = (pending) =>
  pending.then(
    () => 'ok',
    (e) => {
      if (!e.wire) throw e;
      return e.wire.code;
    },
  );

async function logged(server, pattern, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.lines.some((l) => pattern.test(l))) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`the server never logged ${pattern}\n${server.log()}`);
}

const offer = (from, to, time = now() - 60) =>
  signFriendOffer(from.key, { from: from.identity, to: fp(to), time, expires: time + DAY, cert: from.cert });

async function accept(raw, by, time = now()) {
  const acceptance = await signFriendAcceptance(by.key, { offer: raw, from: by.identity, time, cert: by.cert });
  return friendshipBytes(raw, acceptance);
}

const withdraw = async (by, other, before = now(), time = now()) =>
  signFriendWithdrawal(by.key, { from: by.identity, pair: await pairHash(fp(by), fp(other)), before, time, cert: by.cert });

const accepted = (login, f) => (d) =>
  d.friend.login === login && d.friend.state === 'accepted' && (!f || d.friend.friendships?.[0] === hash(f));
const removed = (login) => (d) => d.friend.login === login && d.friend.state === 'removed';
const entry = async (c, login) => (await c.conn.friends()).friends.find((e) => e.login === login);

/** `name` with an identity of its own and a device on each of `servers`,
 *  the same server twice for two devices on one, its account linked on
 *  each of `linkedOn`. `identity`, `card` and `caps` are
 *  `enrolledDevice`'s. */
async function person(name, servers, { linkedOn = servers, identity, card, caps } = {}) {
  const devices = [];
  for (const s of servers) {
    // Issued two hours back, so that an act signed an hour ago is one the
    // certificate covers and is refused for its time alone.
    const opts = { identity: identity ?? devices[0]?.identityFile, card, caps, issued: now() - 7200 };
    devices.push(await enrolledDevice(s, name, opts));
  }
  for (const s of new Set(linkedOn)) s.account(name, account(name, devices[0].fingerprint));
  return { name, devices };
}

/** A friendships session for `who` on `dev`'s server. */
async function signIn(crew, who, dev, creds = {}) {
  const c = await crew.connect({ nick: who.name, identity: { getToken: dev.getToken }, messaging: true, friendships: true, ...creds });
  if (creds.friendships !== false) assert.ok(c.conn.caps.includes('friendships'), JSON.stringify(c.conn.caps));
  return c;
}

/** `a` asks `b` with an offer from its device `ad`, and `b` accepts from
 *  `bd`: the friendship's bytes, checked by the library as `b` was sent
 *  the offer and as the server keeps it. */
async function befriend(a, ac, ad, b, bc, bd) {
  const o = await offer(ad, bd);
  assert.deepEqual(await ac.conn.friendAdd(b.name, undefined, b64(o)), { state: 'pending_out' });
  const asked = await bc.waitFor('friend_request', { login: a.name });
  assert.equal(asked.data.offer, b64(o), 'the offer as signed');
  const checked = await checkFriendOffer(unb64(asked.data.offer), now());
  assert.equal(await fingerprintOf(checked.from), ad.fingerprint);
  const f = await accept(o, bd);
  assert.deepEqual(await bc.conn.friendRespond(a.name, true, b64(f)), { state: 'accepted' });
  await ac.waitFor('friend', accepted(b.name, f));
  return f;
}

describe('portable friendships across two servers', () => {
  let one;
  let two;
  const crewOne = fleet(() => one);
  const crewTwo = fleet(() => two);
  const old = legacyFleet(() => two);

  before(async () => {
    [one, two] = await Promise.all([start(), start()]);
  });
  after(async () => {
    old.closeAll();
    await crewOne.closeAll();
    await crewTwo.closeAll();
    await Promise.all([one?.stop(), two?.stop()]);
  });

  const both = (name, opts) => person(name, [one, two], opts);

  /** Friends on the first server: the friendship and both sessions there. */
  async function friendsOnOne(a, b) {
    const [a1, b1] = [await signIn(crewOne, a, a.devices[0]), await signIn(crewOne, b, b.devices[0])];
    return { f: await befriend(a, a1, a.devices[0], b, b1, b.devices[0]), a1, b1 };
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
    const [alice, bob] = [await both('alice'), await both('bob')];
    const { f } = await friendsOnOne(alice, bob);

    const a2 = await signIn(crewTwo, alice, alice.devices[1]);
    const found = await a2.conn.findUser({ fingerprint: bob.devices[1].fingerprint });
    assert.equal(found.user.login, 'bob', 'found by the identity, not the login');
    assert.equal(found.user.fingerprint, bob.devices[1].fingerprint, "what an offer's to is");
    const { b2 } = await carry(f, alice, bob, a2);
    assert.deepEqual((await entry(b2, 'alice')).friendships, [hash(f)]);

    // What the server keeps is the bytes as signed, which the library
    // checks again on the way back.
    const { friendships } = await b2.conn.friendshipsFetch({ hashes: [hash(f)] });
    assert.deepEqual(friendships, [{ hash: hash(f), friendship: b64(f) }]);
    const back = await checkFriendship(unb64(friendships[0].friendship), now());
    assert.deepEqual(back.pair, await pairHash(fp(alice.devices[0]), fp(bob.devices[0])));
  });

  test('a hash tells a stranger nothing', async () => {
    const [kate, liam, mia] = [await both('kate'), await both('liam'), await both('mia')];
    const { f } = await friendsOnOne(kate, liam);
    await carry(f, kate, liam);
    const stranger = await signIn(crewTwo, mia, mia.devices[1]);
    const asked = await stranger.conn.friendshipsFetch({ hashes: [hash(f), b64(new Uint8Array(32).fill(7))] });
    assert.deepEqual(asked.friendships, [{ hash: hash(f) }, { hash: b64(new Uint8Array(32).fill(7)) }]);
  });

  test('presenting answers for a friend who is not here, or has blocked, as for no one', async () => {
    const nora = await both('nora');
    const omar = await person('omar', [one, two], { linkedOn: [one] });
    const { f } = await friendsOnOne(nora, omar);
    const nora2 = await signIn(crewTwo, nora, nora.devices[1]);
    const absent = await nora2.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.deepEqual(absent.friendships, [{ hash: hash(f), result: 'no_such_user' }]);

    // Omar arrives, and blocks Nora before presenting: one answer.
    two.account('omar', account('omar', omar.devices[0].fingerprint));
    const omar2 = await signIn(crewTwo, omar, omar.devices[1]);
    await omar2.conn.block({ login: 'nora' });
    const blocked = await nora2.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.deepEqual(blocked.friendships, [{ hash: hash(f), result: 'no_such_user' }]);
    assert.equal(await code(nora2.conn.findUser({ fingerprint: omar.devices[1].fingerprint })), 'no_such_user');
  });

  test('a withdrawal on one server ends the friendship on the other, and the friendship is refused there after', async () => {
    const [carol, dave] = [await both('carol'), await both('dave')];
    const { f, a1: carol1, b1: dave1 } = await friendsOnOne(carol, dave);
    const { a2: carol2, b2: dave2 } = await carry(f, carol, dave);

    const cutoff = now();
    const w = await withdraw(carol.devices[1], dave.devices[1], cutoff);
    await carol2.conn.friendRemove({ login: 'dave', withdraw: b64(w) });
    const gone = await dave2.waitFor('friend', removed('carol'));
    assert.equal(gone.data.friend.withdraw, b64(w));
    // The library reads what the friend was told as a withdrawal of this
    // pair, and the cutoff it gives ends the friendship.
    const kept = await parseFriendWithdrawal(unb64(gone.data.friend.withdraw), now());
    const ends = await checkWithdrawalPair(kept, [fp(carol.devices[0]), fp(dave.devices[0])]);
    assert.equal(ends.before, cutoff);

    // A server takes a withdrawal only under the presenting device's own
    // certificate, so Carol's other device signs the same cutoff again.
    const foreign = await carol1.conn.friendshipsPresent({ withdrawals: [b64(w)] });
    assert.equal(foreign.withdrawals[0].result, 'bad_signature');
    const again = await withdraw(carol.devices[0], dave.devices[0], cutoff);
    const since = dave1.mark();
    const taken = await carol1.conn.friendshipsPresent({ withdrawals: [b64(again)] });
    assert.equal(taken.withdrawals[0].result, 'ok');
    const there = await dave1.waitFor('friend', removed('carol'), { since });
    assert.equal(there.data.friend.withdraw, b64(again));
    const refused = await dave1.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.deepEqual(refused.friendships, [{ hash: hash(f), result: 'withdrawn', withdraw: b64(again) }]);
    // What Carol signed before her cutoff is ended with it; Dave's own
    // offers are not hers to end.
    const before = await offer(carol.devices[0], dave.devices[0], cutoff - 30);
    assert.equal(await code(carol1.conn.friendAdd('dave', undefined, b64(before))), 'withdrawn');
    const his = await offer(dave.devices[0], carol.devices[0], cutoff - 30);
    assert.deepEqual(await dave1.conn.friendAdd('carol', undefined, b64(his)), { state: 'pending_out' });
  });

  test('a withdrawal brought first ends a friendship that has never been presented there', async () => {
    const [pia, quinn] = [await both('pia'), await both('quinn')];
    const { f } = await friendsOnOne(pia, quinn);
    const pia2 = await signIn(crewTwo, pia, pia.devices[1]);
    const w = await withdraw(pia.devices[1], quinn.devices[1]);
    assert.deepEqual((await pia2.conn.friendshipsPresent({ withdrawals: [b64(w)] })).withdrawals, [
      { hash: b64(await pairHash(fp(pia.devices[0]), fp(quinn.devices[0]))), result: 'ok' },
    ]);
    const quinn2 = await signIn(crewTwo, quinn, quinn.devices[1]);
    const answer = (await quinn2.conn.friendshipsPresent({ friendships: [b64(f)] })).friendships[0];
    assert.equal(answer.result, 'withdrawn');
    assert.equal(answer.withdraw, b64(w), 'with the withdrawal, for the client to check');
  });

  test('a block with a withdrawal is a removal on the other server, never a block', async () => {
    const [rex, sam] = [await both('rex'), await both('sam')];
    const { f, a1: rex1, b1: sam1 } = await friendsOnOne(rex, sam);
    const { a2: rex2, b2: sam2 } = await carry(f, rex, sam);
    const cutoff = now();
    await rex2.conn.block({ login: 'sam', withdraw: b64(await withdraw(rex.devices[1], sam.devices[1], cutoff)) });
    assert.deepEqual((await rex2.conn.blocks()).blocked.map((b) => b.login), ['sam']);
    await sam2.waitFor('friend', removed('rex'));

    const since = sam1.mark();
    await rex1.conn.friendshipsPresent({ withdrawals: [b64(await withdraw(rex.devices[0], sam.devices[0], cutoff))] });
    await sam1.waitFor('friend', removed('rex'), { since });
    assert.equal(await code(sam2.conn.findUser('rex')), 'no_such_user', 'blocked on two');
    assert.equal((await sam1.conn.findUser('rex')).user.login, 'rex', 'and not on one');
  });

  test('a removal without a withdrawal is this server alone, and not presented straight back', async () => {
    const [gail, hugo] = [await both('gail'), await both('hugo')];
    const { f } = await friendsOnOne(gail, hugo);
    const { a2: gail2, b2: hugo2 } = await carry(f, gail, hugo);
    await gail2.conn.friendRemove('hugo');
    const gone = await hugo2.waitFor('friend', removed('gail'));
    assert.equal(gone.data.friend.withdraw, undefined, 'ended here alone');
    // The server keeps a withdrawal of its own for Gail, so that none of
    // her devices presents the friendship straight back; it is the
    // server's, so there is none to hand over.
    const back = (await gail2.conn.friendshipsPresent({ friendships: [b64(f)] })).friendships[0];
    assert.deepEqual(back, { hash: hash(f), result: 'withdrawn' });
  });

  test('a presentation the other party never matched is dropped by fingerprint', async () => {
    const [ines, jack] = [await both('ines'), await both('jack')];
    const { f } = await friendsOnOne(ines, jack);
    const ines2 = await signIn(crewTwo, ines, ines.devices[1]);
    assert.equal((await ines2.conn.friendshipsPresent({ friendships: [b64(f)] })).friendships[0].result, 'ok');
    for (let i = 0; i < 2; i++) assert.deepEqual(await ines2.conn.friendRemove({ fingerprint: jack.devices[1].fingerprint }), {});
    const jack2 = await signIn(crewTwo, jack, jack.devices[1]);
    assert.equal((await jack2.conn.friendshipsPresent({ friendships: [b64(f)] })).friendships[0].result, 'ok');
    assert.equal(await entry(jack2, 'ines'), undefined, 'one side presented, so nothing stands');
  });

  test('past either bound, presenting and fetching are refused whole', async () => {
    const [ned, olga] = [await both('ned'), await both('olga')];
    const { f } = await friendsOnOne(ned, olga);
    const ned2 = await signIn(crewTwo, ned, ned.devices[1]);
    const many = Array(FRIENDSHIPS_PER_REQUEST + 1).fill(b64(f));
    assert.equal(await code(ned2.conn.friendshipsPresent({ friendships: many })), 'bad_request');
    assert.equal(await code(ned2.conn.friendshipsFetch({ hashes: many.map(() => hash(f)) })), 'bad_request');
    const w = b64(await withdraw(ned.devices[1], olga.devices[1]));
    assert.equal(await code(ned2.conn.friendshipsPresent({ withdrawals: [w, w] })), 'bad_request', 'one withdrawal to a pair');
    assert.equal(await code(ned2.conn.friendshipsPresent({ friendships: many.slice(1), withdrawals: [w] })), 'bad_request', 'both together');
    // At the bound it is served, and nothing refused was applied.
    const served = await ned2.conn.friendshipsPresent({ friendships: many.slice(1) });
    assert.equal(served.friendships.length, FRIENDSHIPS_PER_REQUEST);
    assert.ok(served.friendships.every((x) => x.result === 'ok'), JSON.stringify(served));
  });

  test('a device revoked in the file, on SIGHUP, takes what it presented with it', async () => {
    const [eve, finn] = [await both('eve'), await both('finn')];
    const { f } = await friendsOnOne(eve, finn);
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

    // A new device of Eve's brings the friendship back: it was never ended.
    const eveAgain = await signIn(crewTwo, eve, await enrolledDevice(two, 'eve', { identity: eve.devices[0].identityFile }));
    since = finn2.mark();
    const back = await eveAgain.conn.friendshipsPresent({ friendships: [b64(f)] });
    assert.equal(back.friendships[0].result, 'ok');
    await finn2.waitFor('friend', accepted('eve', f), { since });
  });

  test("a classic session of the friend's own account hears none of it", async () => {
    const [pete, rosa] = [await both('pete'), await both('rosa')];
    const classic = await old.login({ login: 'rosa', password: 'pw-rosa', nick: 'rosa' });
    const { f } = await friendsOnOne(pete, rosa);
    const { a2: pete2, b2: rosa2 } = await carry(f, pete, rosa);
    await pete2.conn.friendRemove({ login: 'rosa', withdraw: b64(await withdraw(pete.devices[1], rosa.devices[1])) });
    await rosa2.waitFor('friend', removed('pete'));

    const allowed = new Set([hdr.TASK, hdr.CHAT, hdr.USER_CHANGE, hdr.USER_PART, hdr.USER_SELFINFO, hdr.AGREEMENT]);
    const said = 'rosa still here';
    classic.chat(said);
    await classic.waitFor((fr) => fr.type === hdr.CHAT && toText(fr.get(tag.BODY) ?? Buffer.alloc(0)).includes(said));
    const stray = classic.frames.filter((fr) => !allowed.has(fr.type)).map((fr) => fr.type.toString(16));
    assert.deepEqual(stray, [], classic.diagnose('stray frames'));
  });

  // Last: the restart ends every session on the second server.
  test('what a server took is kept across a restart, withdrawals too, and a device revoked while it was down is dropped as it starts', async () => {
    const people = [];
    for (const n of ['abe', 'cal', 'gus', 'hal', 'ivy', 'jo']) people.push(await both(n));
    const [abe, cal, gus, hal, ivy, jo] = people;
    const kept = (await friendsOnOne(abe, cal)).f;
    const dropped = (await friendsOnOne(gus, hal)).f;
    const ended = (await friendsOnOne(ivy, jo)).f;
    await carry(kept, abe, cal);
    await carry(dropped, gus, hal);
    const ivy2 = await signIn(crewTwo, ivy, ivy.devices[1]);
    const taken = await ivy2.conn.friendshipsPresent({ withdrawals: [b64(await withdraw(ivy.devices[1], jo.devices[1]))] });
    assert.equal(taken.withdrawals[0].result, 'ok');

    await crewTwo.closeAll();
    const r = hxdCommand(two, ['identity', 'revoke', await fingerprintOf(gus.devices[1].device), '--device']);
    assert.equal(r.status, 0, r.stderr);
    await two.restart();

    const cal2 = await signIn(crewTwo, cal, cal.devices[1]);
    const row = await entry(cal2, 'abe');
    assert.equal(row?.state, 'accepted', JSON.stringify(row));
    assert.deepEqual(row.friendships, [hash(kept)]);
    assert.equal((await cal2.conn.friendshipsFetch({ hashes: [hash(kept)] })).friendships[0].friendship, b64(kept));
    const hal2 = await signIn(crewTwo, hal, hal.devices[1]);
    assert.equal(await entry(hal2, 'gus'), undefined, 'what the revoked device presented is gone');
    const jo2 = await signIn(crewTwo, jo, jo.devices[1]);
    assert.equal((await jo2.conn.friendshipsPresent({ friendships: [b64(ended)] })).friendships[0].result, 'withdrawn');
  });
});

describe('the device-act gate', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await start();
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  /** Two devices on this server. */
  const twice = (name) => person(name, [server, server]);
  const password = (who, creds = {}) =>
    crew.connect({ login: who.name, password: `pw-${who.name}`, nick: who.name, messaging: true, friendships: true, ...creds });

  test('friendships is granted only to a device login that asked, and kept across a resume', async () => {
    const [alice, bob] = [await twice('alice'), await twice('bob')];
    const quiet = await signIn(crew, alice, alice.devices[0], { friendships: false });
    assert.ok(!quiet.conn.caps.includes('friendships'), 'listed only to a login that asked');
    assert.equal((await quiet.conn.findUser('bob')).user.fingerprint, undefined, 'a link shown only to a friendships session');
    const byPassword = await password(alice);
    assert.ok(!byPassword.conn.caps.includes('friendships'), 'a session that proved no device asks in vain');
    assert.equal(await code(byPassword.conn.friendshipsPresent({ friendships: [] })), 'access_denied');

    const asked = await signIn(crew, alice, alice.devices[1]);
    const mark = asked.mark();
    asked.conn.drop();
    await asked.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });
    const after = await asked.conn.findUser('bob');
    assert.equal(after.user.fingerprint, bob.devices[0].fingerprint, 'a resume keeps what the login was granted');
  });

  test('an offer is refused by name: no device, another device, a clock off, someone else, bytes changed', async () => {
    const [carol, dave, erin] = [await twice('carol'), await twice('dave'), await twice('erin')];
    server.account('plain', account('plain'));
    const carol0 = await signIn(crew, carol, carol.devices[0]);
    const byPassword = await password(carol);
    const good = await offer(carol.devices[0], dave.devices[0]);
    const tampered = good.slice();
    tampered[tampered.length - 1] ^= 1;
    await assert.rejects(checkFriendOffer(tampered, now()), FriendshipRefused, 'the library refuses it too');

    for (const [why, c, login, o, expect] of [
      ['a password session', byPassword, 'dave', good, 'access_denied'],
      ["another device's signature", carol0, 'dave', await offer(carol.devices[1], dave.devices[0]), 'bad_signature'],
      ['an hour old', carol0, 'dave', await offer(carol.devices[0], dave.devices[0], now() - 3600), 'stale'],
      ['an hour ahead', carol0, 'dave', await offer(carol.devices[0], dave.devices[0], now() + 3600), 'stale'],
      ['to an account linking another identity', carol0, 'erin', good, 'no_such_user'],
      ['to an account linking none', carol0, 'plain', good, 'no_such_user'],
      ['a byte changed', carol0, 'dave', tampered, 'bad_signature'],
    ]) {
      assert.equal(await code(c.conn.friendAdd(login, undefined, b64(o))), expect, why);
    }
    assert.equal(await code(carol0.conn.friendAdd('dave', undefined, b64(good))), 'ok', 'and the good one, after them all');
  });

  test('an acceptance is refused unless it is the one offered, by this device, now', async () => {
    const [finn, gail] = [await twice('finn'), await twice('gail')];
    const finn0 = await signIn(crew, finn, finn.devices[0]);
    const gail0 = await signIn(crew, gail, gail.devices[0]);
    const o = await offer(finn.devices[0], gail.devices[0]);
    await finn0.conn.friendAdd('gail', undefined, b64(o));
    await gail0.waitFor('friend_request', { login: 'finn' });
    for (const [why, f, expect] of [
      ["another device's acceptance", await accept(o, gail.devices[1]), 'bad_signature'],
      ['an offer never sent', await accept(await offer(finn.devices[0], gail.devices[0]), gail.devices[0]), 'bad_signature'],
      ['twenty minutes ahead', await accept(o, gail.devices[0], now() + 1200), 'stale'],
    ]) {
      assert.equal(await code(gail0.conn.friendRespond('finn', true, b64(f))), expect, why);
    }
    const f = await accept(o, gail.devices[0]);
    assert.deepEqual(await gail0.conn.friendRespond('finn', true, b64(f)), { state: 'accepted' });
    await finn0.waitFor('friend', accepted('gail', f));
  });

  test("the same account's password session is sent the friendship plain", async () => {
    const [hugo, ines] = [await twice('hugo'), await twice('ines')];
    const hugo0 = await signIn(crew, hugo, hugo.devices[0]);
    const ines0 = await signIn(crew, ines, ines.devices[0]);
    const plain = await password(ines);
    const f = await befriend(hugo, hugo0, hugo.devices[0], ines, ines0, ines.devices[0]);
    const asked = await plain.waitFor('friend_request', { login: 'hugo' });
    assert.equal(asked.data.offer, undefined, 'no offer to a session that cannot accept one');
    const row = await plain.waitFor('friend', accepted('hugo'));
    assert.equal(row.data.friend.friendships, undefined);
    assert.equal(await code(plain.conn.friendshipsFetch({ hashes: [hash(f)] })), 'access_denied');
    // A password session can still remove a friend, here alone.
    await plain.conn.friendRemove('hugo');
    const gone = await hugo0.waitFor('friend', removed('ines'));
    assert.equal(gone.data.friend.withdraw, undefined);
  });

  test('a friendship of this server alone is upgraded, and an upgrade offer cancelled or declined leaves it standing', async () => {
    const [jack, kate] = [await twice('jack'), await twice('kate')];
    const jack0 = await signIn(crew, jack, jack.devices[0]);
    const kate0 = await signIn(crew, kate, kate.devices[0]);
    const katePlain = await password(kate);
    assert.deepEqual(await jack0.conn.friendAdd('kate'), { state: 'pending_out' });
    await kate0.waitFor('friend_request', { login: 'jack' });
    await katePlain.waitFor('friend_request', { login: 'jack' });
    const plainSince = katePlain.mark();
    assert.deepEqual(await kate0.conn.friendRespond('jack', true), { state: 'accepted' });
    await jack0.waitFor('friend', accepted('kate'));

    const first = await offer(jack.devices[0], kate.devices[0]);
    assert.deepEqual(await jack0.conn.friendAdd('kate', undefined, b64(first)), { state: 'accepted' }, 'an upgrade offer');
    await kate0.waitFor('friend_request', (d) => d.offer === b64(first));
    assert.equal((await entry(kate0, 'jack')).offer, b64(first), 'on the accepted entry, unanswered');
    await jack0.conn.friendRemove({ login: 'kate', offer: b64(first) });
    assert.equal((await entry(kate0, 'jack')).offer, undefined, 'cancelled alone');

    const second = await offer(jack.devices[0], kate.devices[0], now() - 30);
    await jack0.conn.friendAdd('kate', undefined, b64(second));
    await kate0.waitFor('friend_request', (d) => d.offer === b64(second));
    assert.deepEqual(await kate0.conn.friendRespond('jack', false), { state: 'accepted' }, 'a decline drops the offer alone');
    assert.equal((await entry(jack0, 'kate')).state, 'accepted');

    const third = await offer(jack.devices[0], kate.devices[0], now() - 20);
    await jack0.conn.friendAdd('kate', undefined, b64(third));
    await kate0.waitFor('friend_request', (d) => d.offer === b64(third));
    const f = await accept(third, kate.devices[0]);
    assert.deepEqual(await kate0.conn.friendRespond('jack', true, b64(f)), { state: 'accepted' });
    await jack0.waitFor('friend', accepted('kate', f));
    await katePlain.expectNo('friend_request', { login: 'jack' }, { since: plainSince });
  });

  test('a withdrawal refused still removes, and a block stands whatever its withdrawal', async () => {
    const [liam, mia, ned] = [await twice('liam'), await twice('mia'), await twice('ned')];
    const liam0 = await signIn(crew, liam, liam.devices[0]);
    const mia0 = await signIn(crew, mia, mia.devices[0]);
    const ned0 = await signIn(crew, ned, ned.devices[0]);
    const withMia = await befriend(liam, liam0, liam.devices[0], mia, mia0, mia.devices[0]);
    await befriend(liam, liam0, liam.devices[0], ned, ned0, ned.devices[0]);

    const hourAgo = now() - 3600;
    const stale = await withdraw(liam.devices[0], mia.devices[0], hourAgo, hourAgo);
    assert.equal(await code(liam0.conn.friendRemove({ login: 'mia', withdraw: b64(stale) })), 'stale');
    await mia0.waitFor('friend', removed('liam'));
    const back = await liam0.conn.friendshipsPresent({ friendships: [b64(withMia)] });
    assert.equal(back.friendships[0].result, 'withdrawn', "the server's own withdrawal stands in for the refused one");
    const foreign = await withdraw(liam.devices[1], ned.devices[0]);
    assert.equal(await code(liam0.conn.block({ login: 'ned', withdraw: b64(foreign) })), 'bad_signature');
    assert.deepEqual((await liam0.conn.blocks()).blocked.map((b) => b.login), ['ned']);
    await ned0.waitFor('friend', removed('liam'));

    const w = b64(await withdraw(liam.devices[0], ned.devices[0]));
    assert.equal(await code(liam0.conn.block({ uid: ned0.conn.self.uid, withdraw: w })), 'bad_request');
    assert.equal(await code(liam0.conn.unblock({ login: 'ned', withdraw: w })), 'bad_request');
  });

  test('a certificate that does not allow messages is not granted friendships', async () => {
    const quinn = await person('quinn', [server], { caps: 'login' });
    const c = await signIn(crew, quinn, quinn.devices[0], { friendships: false });
    assert.ok(!c.conn.caps.includes('friendships'), JSON.stringify(c.conn.caps));
  });

  test('an offer that meets a request from the other side is answered request_pending', async () => {
    const [rex, sam] = [await twice('rex'), await twice('sam')];
    const rex0 = await signIn(crew, rex, rex.devices[0]);
    const sam0 = await signIn(crew, sam, sam.devices[0]);
    const theirs = await offer(rex.devices[0], sam.devices[0]);
    await rex0.conn.friendAdd('sam', undefined, b64(theirs));
    await sam0.waitFor('friend_request', { login: 'rex' });
    assert.equal(await code(sam0.conn.friendAdd('rex', undefined, b64(await offer(sam.devices[0], rex.devices[0])))), 'request_pending');
    const f = await accept(theirs, sam.devices[0]);
    assert.deepEqual(await sam0.conn.friendRespond('rex', true, b64(f)), { state: 'accepted' }, 'answered with friend_respond instead');
  });

  test('an identity unlinked makes friendship acts no more', async () => {
    // Unlinking is account management, which a `web` certificate is not
    // allowed.
    const olga = await person('olga', [server, server], { caps: 'all' });
    const pete = await twice('pete');
    const olga0 = await signIn(crew, olga, olga.devices[0]);
    const pete0 = await signIn(crew, pete, pete.devices[0]);
    const f = await befriend(olga, olga0, olga.devices[0], pete, pete0, pete.devices[0]);
    const res = await fetch(new URL('/identity/unlink', server.httpBase), {
      method: 'POST',
      headers: { authorization: `Bearer ${await olga.devices[1].getToken()}` },
    });
    assert.equal(res.status, 200, await res.clone().text());
    assert.equal((await res.json()).unlinked, 'olga');
    assert.equal(await code(olga0.conn.friendshipsPresent({ friendships: [b64(f)] })), 'access_denied');
    assert.equal(await code(olga0.conn.friendAdd('pete', undefined, b64(await offer(olga.devices[0], pete.devices[0])))), 'access_denied');
  });
});

describe('a rotation the registrar publishes', () => {
  let registrar;
  let server;
  const crew = fleet(() => server);

  before(async () => {
    registrar = await startServer({
      config: (ports) => ({
        identity: { key: 'identity-server.key', hosts: [`127.0.0.1:${ports.ng}`] },
        registrar: { host: '127.0.0.1' },
      }),
    });
    server = await start(() => ({
      trusted_registrars: ['127.0.0.1'],
      registrar_urls: { '127.0.0.1': registrar.httpBase },
      // Read afresh at each login, so the rotation is seen at the next.
      revocation_max_age: 1,
    }));
  });
  after(async () => {
    await crew.closeAll();
    await Promise.all([server?.stop(), registrar?.stop()]);
  });

  test("a friend follows it from the records the server serves, and the friendship moves to the successor's offer", async () => {
    // Alice's identity is `hlid`'s, registered with a successor committed.
    const init = hlid(registrar.dir, ['init', '--name', 'alice']);
    assert.match(init, /fingerprint: /);
    const invite = hxdCommand(registrar, ['registrar', 'invites', '--add', '1']);
    assert.equal(invite.status, 0, invite.stderr);
    hlid(registrar.dir, [
      'register', '--registrar', registrar.httpBase, '--handle', 'alice', '--proof', invite.stdout.trim(), '--successor-commit',
    ]);
    const alice = await person('alice', [server], {
      identity: join(registrar.dir, 'identity.key'),
      card: join(registrar.dir, 'card.bin'),
    });
    const bob = await person('bob', [server]);
    const alice0 = await signIn(crew, alice, alice.devices[0]);
    const bob0 = await signIn(crew, bob, bob.devices[0]);
    const old = await befriend(alice, alice0, alice.devices[0], bob, bob0, bob.devices[0]);

    hlid(registrar.dir, ['rotate', '--registrar', registrar.httpBase, '--to', join(registrar.dir, 'successor.key')]);
    await new Promise((r) => setTimeout(r, 1100));
    const next = await enrolledDevice(server, 'alice-next', { identity: join(registrar.dir, 'successor.key') });
    await assert.rejects(alice.devices[0].getToken(), (e) => e.code === 'rotated', 'the predecessor is refused by name');
    const alice1 = await signIn(crew, { name: 'alice' }, next);
    const found = await bob0.conn.findUser({ fingerprint: next.fingerprint });
    assert.equal(found.user.login, 'alice', 'the account moved with the link');

    // Bob's client checks the records itself before it believes them.
    const { rotations } = await bob0.conn.friendshipsFetch({ fingerprints: [next.fingerprint] });
    assert.equal(rotations[0].fingerprint, next.fingerprint);
    const records = await Promise.all(rotations[0].records.map((r) => parseRotation(unb64(r))));
    assert.ok(records.length > 0, JSON.stringify(rotations));
    assert.deepEqual(rotationChainEnd(fp(alice.devices[0]), records), fp(next));
    const carol = await person('carol', [server]);
    const stranger = await signIn(crew, carol, carol.devices[0]);
    const none = await stranger.conn.friendshipsFetch({ fingerprints: [next.fingerprint] });
    assert.deepEqual(none.rotations, [{ fingerprint: next.fingerprint, records: [] }], "a friend's records, to a friend alone");

    const o = await offer(next, bob.devices[0]);
    assert.deepEqual(await alice1.conn.friendAdd('bob', undefined, b64(o)), { state: 'accepted' }, 'an upgrade offer');
    const asked = await bob0.waitFor('friend_request', (d) => d.offer === b64(o));
    assert.equal(asked.data.login, 'alice');
    const f = await accept(o, bob.devices[0]);
    assert.deepEqual(await bob0.conn.friendRespond('alice', true, b64(f)), { state: 'accepted' });
    const moved = await alice1.waitFor('friend', accepted('bob', f));
    assert.deepEqual(moved.data.friend.friendships, [hash(f)], `the successor's alone, not ${hash(old)}`);
  });
});
