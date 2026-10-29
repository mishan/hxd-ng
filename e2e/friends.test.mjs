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
import { hdr, legacyFleet, tag, toText } from './harness/legacy.mjs';
import { startFailing, startServer } from './harness/server.mjs';

const account = (name, messaging = true) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
messaging = ${messaging}
`;

const PEOPLE = [
  'alice', 'bob', 'carol', 'dave', 'eve', 'finn', 'nora', 'omar', 'pia', 'quinn', 'rex', 'sam',
  'gail', 'hugo', 'ines', 'jack', 'kate', 'liam', 'mia', 'ned', 'olga', 'pete', 'rosa',
  'zoe', 'abe', 'cal', 'gus', 'hal', 'ivy', 'jo', 'kim', 'lee', 'uma', 'val',
];
/** Accounts outside messaging: on disk without the bit. */
const OUTSIDERS = ['tom', 'wes'];

const MESSAGING = { inbox: { db: 'messages.db' }, messaging: { enabled: true } };

/** Every event only a session that speaks the family is sent, and the
 *  placeholder a server sends for one a client cannot read. */
const FAMILY = ['friend', 'friend_request', 'presence', 'im', 'receipt', 'typing', 'requests_changed', 'unsupported'];

const REQUESTED = { queued: true, requested: true };

/** A request's refusal code, or `ok`. */
const code = (pending) =>
  pending.then(
    () => 'ok',
    (e) => {
      if (!e.wire) throw e;
      return e.wire.code;
    },
  );

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function logged(server, pattern, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.lines.some((l) => pattern.test(l))) return;
    await sleep(25);
  }
  assert.fail(`the server never logged ${pattern}\n${server.log()}`);
}

/** `a` and `b` friends, as two clients make them. */
async function befriend(a, b) {
  assert.deepEqual(await a.conn.friendAdd(b.who), { state: 'pending_out' });
  await b.waitFor('friend_request', { login: a.who });
  assert.deepEqual(await b.conn.friendRespond(a.who, true), { state: 'accepted' });
  for (const [c, other] of [
    [a, b],
    [b, a],
  ]) {
    await c.waitFor('friend', { 'friend.login': other.who, 'friend.state': 'accepted' });
  }
}

/** Until `watcher` has been told `login` is online. A friend is shown
 *  what the friend's friends were last told, so a sign-on may still be
 *  owed under the debounce when the friendship is made. */
async function shownOnline(watcher, login) {
  const row = await watcher.waitFor('friend', { 'friend.login': login, 'friend.state': 'accepted' });
  if (row.data.friend.presence !== 'online') await watcher.waitFor('presence', { login, state: 'online' });
}

const signIn = (crew) => (who, messaging = true) =>
  crew.connect({ login: who, password: `pw-${who}`, nick: who, messaging });

describe('instant messaging', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      // `[system]` for the classic `/msg <login>`.
      config: { ...MESSAGING, system: {} },
      accounts: Object.fromEntries([
        ...PEOPLE.map((p) => [p, account(p)]),
        ...OUTSIDERS.map((p) => [p, account(p, false)]),
      ]),
    });
  });
  after(async () => {
    old.closeAll();
    await crew.closeAll();
    await server?.stop();
  });

  const old = legacyFleet(() => server);
  const login = signIn(crew);

  async function befriended(x, y) {
    const [a, b] = [await login(x), await login(y)];
    await befriend(a, b);
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

    await shownOnline(bob, 'alice');

    // Both changes land well inside the server's one-second presence
    // debounce, so they are one burst; a host stalled past it between
    // the two requests would see busy told first.
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
    await dave.expectNo('msg', { text: 'lunch?' });

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
    // A friend is shown presence and profile, as a stranger is not
    // (below).
    const shown = (await dave.conn.userProfile('carol')).user;
    assert.ok(shown.presence, JSON.stringify(shown));
    assert.ok(shown.profile, JSON.stringify(shown));
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
    await back.expectNo('msg', { text: 'while you were out' });

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
    assert.equal(await code(rex.conn.msg({ to_login: 'sam', text: 'are you there?' })), 'not_friends');
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

  test("an alias is the owner's alone, a removal tells both, and a decline tells the asker", async () => {
    const [gail, hugo] = await befriended('gail', 'hugo');
    for (const alias of ['Hugh', null]) {
      const [mine, theirs] = [gail.mark(), hugo.mark()];
      await gail.conn.friendAlias('hugo', alias);
      const row = await gail.waitFor('friend', (d) => d.friend.login === 'hugo' && d.friend.alias === (alias ?? undefined), {
        since: mine,
      });
      assert.equal(row.data.friend.state, 'accepted');
      await hugo.expectNo('friend', () => true, { since: theirs });
    }
    const [gails, hugos] = [(await gail.conn.friends()).friends, (await hugo.conn.friends()).friends];
    assert.deepEqual([gails[0].alias, hugos[0].alias], [undefined, undefined]);

    await gail.conn.friendRemove('hugo');
    for (const [c, other] of [
      [gail, 'hugo'],
      [hugo, 'gail'],
    ]) {
      await c.waitFor('friend', { 'friend.login': other, 'friend.state': 'removed' });
    }

    const ines = await login('ines');
    await ines.conn.friendAdd('gail');
    await gail.waitFor('friend_request', { login: 'ines' });
    assert.deepEqual(await gail.conn.friendRespond('ines', false), { state: 'removed' });
    await ines.waitFor('friend', { 'friend.login': 'gail', 'friend.state': 'removed' });
  });

  test('crossing requests meet where requests are understood, and wait where they are not', async () => {
    for (const [first, second, understands, want] of [
      ['jack', 'kate', true, 'ok'],
      ['liam', 'mia', false, 'request_pending'],
    ]) {
      const [a, b] = [await login(first), await login(second)];
      await a.conn.friendAdd(second);
      await b.waitFor('friend_request', { login: first });
      if (understands) await b.conn.setPresence({ takes_requests: false });
      assert.equal(await code(b.conn.friendAdd(first)), want, second);
      if (understands) await a.waitFor('friend', { 'friend.login': second, 'friend.state': 'accepted' });
    }
  });

  test('a block reads as a missing account to the blocked, on every request that names one', async () => {
    const [ned, olga] = [await login('ned'), await login('olga')];
    await olga.conn.block({ login: 'ned' });
    for (const [req, ask] of [
      ['findUser', (who) => ned.conn.findUser(who)],
      ['userProfile', (who) => ned.conn.userProfile(who)],
      ['friendAdd', (who) => ned.conn.friendAdd(who)],
      ['msg', (who) => ned.conn.msg({ to_login: who, text: 'hello?' })],
    ]) {
      const answers = [await code(ask('olga')), await code(ask('nobody-by-that-name'))];
      assert.deepEqual(answers, ['no_such_user', 'no_such_user'], req);
    }
    assert.equal(await code(olga.conn.friendAdd('ned')), 'blocked', 'the blocker is told of its own block');

    await olga.conn.unblock({ login: 'ned' });
    // A stranger is shown no presence and no profile.
    for (const ask of [ned.conn.findUser('olga'), ned.conn.userProfile('olga')]) {
      assert.deepEqual((await ask).user, { login: 'olga', name: 'olga' });
    }
  });

  test('invisible shows a friend offline and nothing more, until a new login ends it', async () => {
    const [pete, rosa] = await befriended('pete', 'rosa');
    await shownOnline(rosa, 'pete');
    let mark = rosa.mark();
    await pete.conn.setPresence({ state: 'invisible' });
    await rosa.waitFor('presence', { login: 'pete', state: 'offline' }, { since: mark });

    // Past the debounce, so a change would have been told.
    mark = rosa.mark();
    await pete.conn.setPresence({ status_text: 'nobody here' });
    await rosa.expectNo('presence', { login: 'pete' }, { since: mark, timeout: 2000 });
    assert.equal((await rosa.conn.friends()).friends[0].presence, 'offline');
    assert.equal((await pete.conn.findUser('pete')).user.presence, 'invisible');

    const guid = randomUUID();
    assert.equal((await rosa.conn.msg({ to_login: 'pete', text: 'you there?', guid })).queued, false);
    await pete.waitFor('im', { guid });

    mark = rosa.mark();
    const second = await login('pete');
    assert.equal(second.conn.messaging.state, 'online');
    await rosa.waitFor('presence', { login: 'pete', state: 'online' }, { since: mark });
  });

  test('requests turned off refuse new ones, and leave writing to a stranger and an approval given', async () => {
    const [zoe, abe, cal] = [await login('zoe'), await login('abe'), await login('cal')];
    await zoe.conn.setPresence({ takes_requests: true });
    await abe.conn.requests();
    assert.deepEqual(await abe.conn.msg({ to_login: 'zoe', text: 'hi zoe' }), REQUESTED);
    await zoe.conn.requestAnswer('abe', 'approve');
    await zoe.conn.setPresence({ takes_requests: false });

    await cal.conn.setPresence({ takes_requests: true });
    assert.equal(await code(cal.conn.msg({ to_login: 'zoe', text: 'me too?' })), 'not_friends');
    assert.equal((await abe.conn.msg({ to_login: 'zoe', text: 'still here' })).queued, true);
    await zoe.waitFor('im', { text: 'still here', approval: true });
    assert.deepEqual(await zoe.conn.msg({ to_login: 'cal', text: 'hello cal' }), REQUESTED);
    await cal.waitFor('requests_changed', { count: 1 });
    assert.equal((await zoe.conn.requests()).takes_requests, false);
  });

  test('a detached session is replayed what the family told it, and its roster read hands over the rest', async () => {
    const [gus, hal] = await befriended('gus', 'hal');
    const [jo, ivy] = [await login('jo'), await login('ivy')];
    await befriend(gus, jo);
    const uid = hal.conn.self.uid;

    // Kept away until everything below has happened, however slow.
    let release;
    const away = new Promise((resolve) => (release = resolve));
    const attach = hal.conn.attach;
    hal.conn.attach = async function () {
      await away;
      return attach.call(this);
    };
    const [mark, watching] = [hal.mark(), gus.mark()];
    hal.conn.drop();
    await gus.waitFor('user_changed', (d) => d.user.uid === uid && d.user.status === 'detached', { since: watching });

    await ivy.conn.friendAdd('hal');
    await gus.conn.setPresence({ state: 'away' });
    // Told to every friend at once, so jo hearing it means hal's buffer
    // holds it.
    await jo.waitFor('presence', { login: 'gus', state: 'away' });
    const guid = randomUUID();
    assert.equal((await gus.conn.msg({ to_login: 'hal', text: 'while you were detached', guid })).queued, true);
    release();

    const resumed = await hal.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });
    const asked = hal.seen('req', 'resume').at(-1);
    const answered = hal.log.find((r) => r.kind === 'reply' && r.id === asked.id);
    const replayed = hal.log.filter((r) => r.kind === 'ev' && r.n > answered.n).slice(0, resumed.data.replay);
    const at = (name, login) => replayed.findIndex((r) => r.name === name && r.data.login === login);
    assert.ok(at('friend_request', 'ivy') >= 0, hal.diagnose('no friend_request in the replay', mark));
    assert.ok(at('friend_request', 'ivy') < at('presence', 'gus'), hal.diagnose('replayed out of order', mark));
    for (let i = 1; i < replayed.length; i++) assert.equal(replayed[i].seq, replayed[i - 1].seq + 1);
    assert.ok(!replayed.some((r) => r.name === 'im'), 'an im for a detached session waits for the roster read');

    await hal.waitForHook('onFriends', () => true, { since: answered.n });
    const im = await hal.waitFor('im', { guid }, { since: mark });
    assert.equal(im.data.queued, true);
  });

  test('a resync re-reads the roster, which hands over what waited', async () => {
    const [lee, kim] = await befriended('lee', 'kim');
    const uid = kim.conn.self.uid;
    await lee.conn.typing('kim', true);
    const typed = await kim.waitFor('typing', { login: 'lee', typing: true });

    // Resuming from before an event the session already sent is past
    // what any buffer holds: resync_required.
    let release;
    const away = new Promise((resolve) => (release = resolve));
    const attach = kim.conn.attach;
    kim.conn.attach = async function () {
      await away;
      this.seq = typed.seq - 1;
      return attach.call(this);
    };
    const [mark, watching] = [kim.mark(), lee.mark()];
    kim.conn.drop();
    await lee.waitFor('user_changed', (d) => d.user.uid === uid && d.user.status === 'detached', { since: watching });
    const guid = randomUUID();
    assert.equal((await lee.conn.msg({ to_login: 'kim', text: 'missed this', guid })).queued, true);
    release();

    await kim.waitForReply('resync_required', () => true, { since: mark, timeout: 20_000 });
    await kim.waitForHook('onFriends', () => true, { since: mark });
    const im = await kim.waitFor('im', { guid }, { since: mark });
    assert.equal(im.data.queued, true);
  });

  test('messaging given on disk takes part from the next login, not mid-session', async () => {
    const before = await login('wes');
    assert.equal(before.conn.messaging.takes_part, false);
    assert.equal(await code(before.conn.findUser('alice')), 'access_denied');

    server.account('wes', account('wes'));
    server.proc.kill('SIGHUP');
    await logged(server, /SIGHUP: accounts reloaded/);
    assert.equal(await code(before.conn.findUser('alice')), 'access_denied');

    const after = await login('wes');
    assert.equal(after.conn.messaging.takes_part, true);
    assert.equal((await after.conn.findUser('alice')).user.login, 'alice');
  });

  test('a classic /msg by login is an instant message to a friend and a request to a stranger', async () => {
    const [uma, valNg] = await befriended('uma', 'val');
    await valNg.close();
    await uma.conn.setPresence({ takes_requests: true });
    const val = await old.login({ login: 'val', password: 'pw-val', nick: 'val' });
    // Outside messaging: a classic sender is held to the request's
    // bounds without the bit or understanding requests.
    const tom = await old.login({ login: 'tom', password: 'pw-tom', nick: 'tom' });
    const system = (await tom.users()).find((u) => u.nick === 'Server');
    assert.ok(system, 'the system account is on the list');
    const body = (f) => toText(f.get(tag.BODY) ?? Buffer.alloc(0));
    const command = async (who, line) => {
      const mark = who.mark();
      await who.msg(system.uid, line);
      const answer = await who.waitFor((f) => f.type === hdr.MSG && f.get(tag.UID)?.readUInt16BE(0) === system.uid, {
        since: mark,
      });
      return body(answer);
    };

    assert.equal(await command(val, '/msg uma hello from the old client'), 'ok: sent');
    const im = await uma.waitFor('im', { text: 'hello from the old client' });
    assert.equal(im.data.from.login, 'val');
    assert.equal(im.data.approval, undefined);
    await uma.expectNo('msg', { text: 'hello from the old client' });

    assert.equal(await command(tom, '/msg uma hello stranger'), 'ok: queued');
    await uma.waitFor('requests_changed', { count: 1 });
    const listed = await uma.conn.requests();
    assert.deepEqual(
      listed.requests.map((r) => [r.login, r.messages.map((m) => m.text)]),
      [['tom', ['hello stranger']]],
    );
    await uma.conn.requestAnswer('tom', 'approve');
    await uma.waitFor('im', { text: 'hello stranger', approval: true });
    const mark = tom.mark();
    await uma.conn.msg({ to_login: 'tom', text: 'welcome, tom' });
    await tom.waitFor((f) => f.type === hdr.MSG && body(f) === 'welcome, tom', { since: mark });

    // Nothing of the family reaches either classic client.
    const allowed = new Set([hdr.TASK, hdr.MSG, hdr.CHAT, hdr.USER_CHANGE, hdr.USER_PART, hdr.USER_SELFINFO, hdr.AGREEMENT]);
    for (const c of [val, tom]) {
      const said = `${c.who} still here`;
      c.chat(said);
      await c.waitFor((f) => f.type === hdr.CHAT && body(f).includes(said));
      const stray = c.frames.filter((f) => !allowed.has(f.type)).map((f) => f.type.toString(16));
      assert.deepEqual(stray, [], c.diagnose('stray frames'));
    }
  });
});

describe('instant messaging across a restart', () => {
  let server;
  const crew = fleet(() => server);
  const login = signIn(crew);

  before(async () => {
    server = await startServer({
      config: MESSAGING,
      accounts: Object.fromEntries(['ada', 'ben', 'cy', 'dot', 'eli'].map((p) => [p, account(p)])),
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('what the family keeps is kept, and acts the same', async () => {
    const [ada, ben] = [await login('ada'), await login('ben')];
    await befriend(ada, ben);
    await ada.conn.friendAlias('ben', 'Benny');
    await ada.conn.setPresence({ status_text: 'back soon', takes_requests: true, discoverable: true });
    const [cy, dot] = [await login('cy'), await login('dot')];
    for (const [who, text] of [
      [cy, 'from cy'],
      [dot, 'from dot'],
    ]) {
      await who.conn.requests();
      assert.deepEqual(await who.conn.msg({ to_login: 'ada', text }), REQUESTED);
    }
    await ada.conn.requestAnswer('dot', 'approve');
    await ada.conn.block({ login: 'eli' });
    await ben.close();
    const guid = randomUUID();
    assert.equal((await ada.conn.msg({ to_login: 'ben', text: 'see you after the restart', guid })).queued, true);

    await crew.closeAll();
    await server.restart();

    const again = await login('ada');
    const { status_text, takes_requests, discoverable } = again.conn.messaging;
    assert.deepEqual({ status_text, takes_requests, discoverable }, {
      status_text: 'back soon',
      takes_requests: true,
      discoverable: true,
    });
    const rows = (hook) =>
      hook.data.friends.map((f) => [f.login, f.state, f.alias]).sort((x, y) => x[0].localeCompare(y[0]));
    assert.deepEqual(rows(await again.waitForHook('onFriends')), [
      ['ben', 'accepted', 'Benny'],
      ['eli', 'blocked', undefined],
    ]);
    const listed = await again.conn.requests();
    assert.deepEqual(
      listed.requests.map((r) => [r.login, r.messages.map((m) => m.text)]),
      [['cy', ['from cy']]],
    );
    assert.deepEqual(listed.approvals.map((a) => a.login), ['dot']);

    const benBack = await login('ben');
    assert.deepEqual(rows(await benBack.waitForHook('onFriends')), [['ada', 'accepted', undefined]]);
    assert.equal((await benBack.waitFor('im', { guid })).data.queued, true);
    const dotBack = await login('dot');
    assert.equal((await dotBack.conn.msg({ to_login: 'ada', text: 'still approved' })).queued, true);
    await again.waitFor('im', { text: 'still approved', approval: true });
    const eli = await login('eli');
    assert.equal(await code(eli.conn.findUser('ada')), 'no_such_user');
  });
});

describe('instant messaging under the request limit', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: { ...MESSAGING, limits: { ng_requests: 6, ng_request_seconds: 2 } },
      accounts: { fay: account('fay') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('a burst of the family is answered rate_limited with retry_after, then served', async () => {
    const fay = await signIn(crew)('fay');
    const answers = await Promise.all(
      Array.from({ length: 12 }, () => fay.conn.findUser('fay').then(() => 'ok', (e) => e.wire ?? Promise.reject(e))),
    );
    const limited = answers.filter((a) => a !== 'ok');
    assert.ok(limited.length > 0, 'a burst past the bucket is paced');
    for (const a of limited) {
      assert.equal(a.code, 'rate_limited');
      assert.ok(a.retry_after > 0, JSON.stringify(a));
    }
    await sleep(Math.max(...limited.map((a) => a.retry_after)) * 1000);
    assert.equal((await fay.conn.findUser('fay')).user.login, 'fay');
  });
});

test('[messaging] without [inbox] is refused at startup', async () => {
  const { code, output } = await startFailing({ config: { messaging: { enabled: true } } });
  assert.notEqual(code, 0);
  assert.match(output, /\[messaging\] needs \[inbox\]: instant messages are kept there/);
});
