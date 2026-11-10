/**
 * Server emoji (docs/server-emoji.md), from a real `[emoji]` section,
 * with the catalog `hxd emoji` writes beside the running server and the
 * SIGHUP that has it reread, read by the browser client's library:
 * `EmojiCatalog` over `emoji_list`, `fetchEmoji`, the references
 * `emojiRefsFor` makes and `emojiSegments` reads, and a server emoji as
 * a reaction key. `crates/hxd/tests/emoji_ng.rs`, `emoji_classic.rs` and
 * `reactions.rs` hold the wire to the rest, the classic one included,
 * and `emoji.rs` the binary's reread of what the command wrote; what
 * only this layer reaches is a client of the binary watching that
 * reread, and a second implementation of §8 agreeing with the server
 * about what it is sent.
 */

import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { CAP_EMOJI, EmojiCatalog, emojiRefsFor, emojiSegments } from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { png } from './harness/png.mjs';
import { hxdCommand, startFailing, startServer } from './harness/server.mjs';

const account = (name, extra = '') => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
read_chat_history = true
send_chat = true
send_msgs = true
${extra}`;

/** What a request came back as: `ok`, or the code it was refused with. */
const code = (p) =>
  p.then(
    () => 'ok',
    (e) => e.wire?.code ?? String(e),
  );

/** Wait for a line in the server's log, which is where a reload says
 *  what it did. */
async function logged(server, pattern, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.lines.some((l) => pattern.test(l))) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`the server never logged ${pattern}\n${server.log()}`);
}

/** The `emoji_list` requests a client sent since `mark`. */
const listings = (c, mark) => c.log.filter((r) => r.n >= mark && r.kind === 'req' && r.name === 'emoji_list').map((r) => r.data);

describe('server emoji', () => {
  let server;
  const crew = fleet(() => server);
  // Every edit spends one, so the reread that applies it is the one
  // logging this revision.
  let revision = 0;

  before(async () => {
    server = await startServer({
      config: () => ({
        inbox: { db: 'server.sqlite' },
        history: {},
        messaging: { enabled: true },
        reactions: { enabled: true },
        emoji: { enabled: true, max_count: 300, max_bytes: 20000, max_dimension: 64 },
      }),
      accounts: {
        ...Object.fromEntries(['alice', 'bob', 'dave'].map((p) => [p, account(p)])),
        // Taking part in messaging: mail by login to them is an instant
        // message or a request, and to erin it waits in her inbox.
        ...Object.fromEntries(['mia', 'ned', 'pat', 'ola', 'quin'].map((p) => [p, account(p, 'messaging = true\n')])),
        erin: account('erin'),
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, opts = {}) => crew.connect({ login: who, password: `pw-${who}`, nick: who, ...opts });

  /** `hxd emoji` beside the running server, as an operator runs it. */
  function edit(...args) {
    const r = hxdCommand(server, ['emoji', ...args]);
    assert.equal(r.status, 0, `hxd emoji ${args.join(' ')}: ${r.stderr}`);
    revision++;
  }
  /** `hxd emoji add` of a 128 by 64 picture of its own color, so no two
   *  entries share an image. */
  function add(name) {
    const file = join(server.dir, `${name}.png`);
    const n = revision + 1;
    writeFileSync(file, png(128, 64, [n & 0xff, (n >> 8) & 0xff, 0x80]));
    edit('add', name, file);
  }
  async function reread() {
    server.proc.kill('SIGHUP');
    await logged(server, new RegExp(`SIGHUP: emoji catalog now at revision ${revision}\\b`));
  }
  async function catalogOf(c) {
    const catalog = new EmojiCatalog((p) => c.conn.emojiList(p));
    await catalog.refresh();
    return catalog;
  }

  test('a login that declares emoji is granted the numbers in the file, and one that does not is granted nothing', async () => {
    const alice = await login('alice', { emoji: true });
    assert.ok(alice.conn.hasCap(CAP_EMOJI), JSON.stringify(alice.conn.caps));
    assert.deepEqual(alice.conn.emoji, { revision, max_count: 300, max_bytes: 20000, max_dimension: 64, manage: false });

    const bob = await login('bob');
    assert.equal(bob.conn.hasCap(CAP_EMOJI), false);
    assert.equal(bob.conn.emoji, null);
    assert.equal(await code(bob.conn.emojiList()), 'not_available');
  });

  test('EmojiCatalog reads what hxd emoji changed once SIGHUP rereads it, and a removed emoji is no longer fetched', async () => {
    add('party');
    add('polly');
    await reread();
    const [alice, bob] = [await login('alice', { emoji: true }), await login('bob')];
    const catalog = await catalogOf(alice);
    const [party, polly] = [catalog.named('party'), catalog.named('polly')];
    assert.deepEqual({ width: party.width, height: party.height }, { width: 64, height: 32 }, 'fitted within max_dimension');

    const bytes = Buffer.from(await (await alice.conn.fetchEmoji(party.hash)).arrayBuffer());
    assert.equal(createHash('sha256').update(bytes).digest('hex'), party.hash);
    assert.deepEqual([bytes.readUInt32BE(16), bytes.readUInt32BE(20)], [64, 32], "the PNG's own size");

    const [mark, watching] = [alice.mark(), bob.mark()];
    edit('rename', 'polly', 'pollywog');
    edit('remove', 'party');
    add('parade');
    await reread();
    await alice.waitFor('emoji_changed', { revision }, { since: mark });
    assert.equal(alice.seen('ev', 'emoji_changed').filter((r) => r.n >= mark).length, 1, 'a batch of edits, one reread');
    const held = catalog.revision;
    assert.equal(await catalog.refresh(), true);
    assert.deepEqual(listings(alice, mark), [{ revision: held }], 'a delta from the revision held');
    assert.equal(catalog.revision, revision);
    assert.equal(catalog.live(party.id), undefined);
    assert.deepEqual(catalog.get(party.id), { id: party.id, revision: revision - 1, name: 'party', removed: true });
    assert.deepEqual(catalog.named('pollywog'), { ...polly, name: 'pollywog', revision: revision - 2 }, 'renamed, the same id');
    assert.equal(catalog.named('polly'), undefined);
    assert.ok(catalog.named('parade'));
    assert.equal(await catalog.refresh(), false, 'nothing since');

    assert.equal(await code(alice.conn.fetchEmoji(party.hash)), 'no_such_emoji');
    await bob.expectNo('emoji_changed', () => true, { since: watching });
  });

  test('a catalog past one page is paged to its end, whole and as a delta', async () => {
    const alice = await login('alice', { emoji: true });
    const catalog = await catalogOf(alice);
    const held = catalog.revision;
    // More changes than a page holds, so the delta pages too.
    for (let n = 0; n <= 200; n++) add(`page_${n}`);
    await reread();

    const mark = alice.mark();
    assert.equal(await catalog.refresh(), true);
    const fresh = new EmojiCatalog((p) => alice.conn.emojiList(p));
    await fresh.refresh();
    const [delta, whole] = [listings(alice, mark).slice(0, 2), listings(alice, mark).slice(2)];
    assert.equal(delta.length, 2, JSON.stringify(listings(alice, mark)));
    assert.deepEqual(delta[0], { revision: held });
    assert.deepEqual(Object.keys(delta[1]).sort(), ['after', 'revision']);
    assert.equal(delta[1].revision, held, 'a later page asks from the revision the first was asked from');
    assert.equal(whole.length, 2, JSON.stringify(whole));
    assert.deepEqual(whole[0], {});
    assert.deepEqual(Object.keys(whole[1]), ['after']);

    for (const c of [catalog, fresh]) {
      assert.equal(c.revision, revision);
      assert.ok(c.named('page_0') && c.named('page_200'));
    }
    assert.deepEqual(fresh.entries(), catalog.entries());
  });

  test('references are kept and carried on chat, history, msg and the inbox to readers that declared emoji, and a send naming one renamed or removed since dropped', async () => {
    add('blob');
    add('kitty');
    add('gone');
    edit('remove', 'gone');
    await reread();
    const [alice, bob, dave] = [await login('alice', { emoji: true }), await login('bob', { emoji: true }), await login('dave')];
    const [sent, read] = [await catalogOf(alice), await catalogOf(bob)];
    const [blob, kitty] = [sent.named('blob'), sent.named('kitty')];
    const refs = [
      { name: 'blob', id: blob.id },
      { name: 'kitty', id: kitty.id },
    ];

    const text = ':blob: and :kitty:, not :gone:';
    assert.deepEqual(emojiRefsFor(text, sent), refs);
    const { id } = await alice.conn.chat({ text, emoji: refs });
    const heard = await bob.waitFor('chat', { id });
    assert.deepEqual(heard.data.emoji, refs);
    assert.deepEqual(emojiSegments(heard.data.text, heard.data.emoji, read), [refs[0], ' and ', refs[1], ', not :gone:']);
    assert.equal((await dave.waitFor('chat', { id })).data.emoji, undefined);
    const kept = async (c) => (await c.conn.history()).lines.find((l) => l.id === id).emoji;
    assert.deepEqual(await kept(bob), refs);
    assert.equal(await kept(dave), undefined);

    for (const [who, reader, want] of [
      ['bob', bob, refs],
      ['dave', dave, undefined],
    ]) {
      const words = `to ${who} ${text}`;
      await alice.conn.msg({ to: reader.conn.self.uid, text: words, emoji: refs });
      assert.deepEqual((await reader.waitFor('msg', { text: words })).data.emoji, want, `${who}'s msg`);
      const row = (await reader.conn.inbox()).messages.find((m) => m.text === words);
      assert.deepEqual(row.emoji, want, `${who}'s inbox row`);
    }
    const waited = 'while you were out :blob:';
    assert.equal((await alice.conn.msg({ to_login: 'erin', text: waited, emoji: refs })).queued, true);
    const erin = await login('erin', { emoji: true });
    assert.deepEqual((await erin.waitFor('msg', { text: waited })).data.emoji, refs, 'flushed at login');

    // The sender's catalog is a reread behind: the server drops a ref to
    // a name no longer current and to an emoji no longer live. The line
    // kept before keeps both, drawing the renamed one as the sender saw
    // it and the removed one as text.
    edit('rename', 'blob', 'blobby');
    edit('remove', 'kitty');
    await reread();
    const stale = await alice.conn.chat({ text, emoji: emojiRefsFor(text, sent) });
    assert.equal((await bob.waitFor('chat', { id: stale.id })).data.emoji, undefined);
    assert.deepEqual(await kept(bob), refs);
    await read.refresh();
    assert.deepEqual(emojiSegments(text, await kept(bob), read), [refs[0], ' and :kitty:, not :gone:']);
  });

  test('references reach an instant message and a request listing for readers that declared emoji alone', async () => {
    add('hiya');
    await reread();
    const mia = await login('mia', { emoji: true, messaging: true });
    const hiya = (await catalogOf(mia)).named('hiya');
    const refs = [{ name: 'hiya', id: hiya.id }];
    const readers = [
      ['ned', true],
      ['pat', false],
    ];
    for (const [who, emoji] of readers) {
      const friend = await login(who, { emoji, messaging: true });
      await mia.conn.friendAdd(who);
      await friend.waitFor('friend_request', { login: 'mia' });
      await friend.conn.friendRespond('mia', true);
      await mia.waitFor('friend', { 'friend.login': who, 'friend.state': 'accepted' });
      const guid = randomUUID();
      assert.equal((await mia.conn.msg({ to_login: who, text: 'hi :hiya:', guid, emoji: refs })).im, true);
      assert.deepEqual((await friend.waitFor('im', { guid })).data.emoji, emoji ? refs : undefined, who);
    }
    // Listing her own makes mia's a session a request may be sent from.
    await mia.conn.requests();
    for (const [who, emoji] of [
      ['ola', true],
      ['quin', false],
    ]) {
      const stranger = await login(who, { emoji, messaging: true });
      await stranger.conn.setPresence({ takes_requests: true });
      const text = `hello ${who} :hiya:`;
      assert.equal((await mia.conn.msg({ to_login: who, text, emoji: refs })).requested, true);
      const listed = (await stranger.conn.requests()).requests.flatMap((r) => r.messages).find((m) => m.text === text);
      assert.deepEqual(listed.emoji, emoji ? refs : undefined, who);
    }
  });

  test('a server emoji is a reaction key while it lives, and one made with it can be taken back after', async () => {
    add('cheer');
    await reread();
    const [alice, bob, dave] = [
      await login('alice', { emoji: true, reactions: true }),
      await login('bob', { emoji: true, reactions: true }),
      await login('dave', { reactions: true }),
    ];
    const key = { custom: (await catalogOf(alice)).named('cheer').id };
    const line = { line: (await alice.conn.chat({ text: 'look' })).id };
    const mark = dave.mark();
    assert.equal((await alice.conn.react(line, key)).count, 1);
    const told = await dave.waitFor('reactions_changed', (d) => d.changes.some((c) => c.target.line === line.line), { since: mark });
    assert.deepEqual(
      told.data.changes,
      [{ target: line, action: 'summary', keys: [{ key, count: 1 }] }],
      'shown to a reader that never declared emoji',
    );
    assert.equal(await code(dave.conn.react(line, key)), 'bad_request', 'sent by a session that did not declare it');

    edit('remove', 'cheer');
    await reread();
    const catalog = await catalogOf(bob);
    assert.deepEqual(catalog.get(key.custom), { id: key.custom, revision, name: 'cheer', removed: true }, 'what the key is still shown as');
    assert.equal(await code(bob.conn.react(line, key)), 'no_such_emoji');
    assert.equal((await alice.conn.react(line, key, { remove: true })).count, 0);
  });
});

describe('server emoji turned off', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: () => ({ inbox: { db: 'server.sqlite' }, emoji: { enabled: false } }),
      accounts: { alice: account('alice') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('a catalog in the database is served to nobody, and hxd emoji says so', async () => {
    const file = join(server.dir, 'party.png');
    writeFileSync(file, png(32, 32));
    const r = hxdCommand(server, ['emoji', 'add', 'party', file]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /a server serves it once \[emoji\] is enabled/);
    // Restarted, so the catalog is in the database when the server starts.
    await server.restart();

    const alice = await crew.connect({ login: 'alice', password: 'pw-alice', nick: 'alice', emoji: true });
    assert.equal(alice.conn.hasCap(CAP_EMOJI), false);
    assert.equal(alice.conn.emoji, null);
    assert.equal(await code(alice.conn.emojiList()), 'not_available');
  });
});

test('a config whose [emoji] the server cannot serve is refused at startup', async () => {
  for (const [config, refusal] of [
    [{ emoji: { enabled: true } }, /\[emoji\] needs a database/],
    [{ inbox: { db: 'server.sqlite' }, emoji: { enabled: true, max_dimension: 512 } }, /\[emoji\] max_dimension must be/],
  ]) {
    const { code: exit, output } = await startFailing({ config });
    assert.notEqual(exit, 0);
    assert.match(output, refusal);
  }
});
