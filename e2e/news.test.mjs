/**
 * Threaded news, from a real config file, through the real binary, read
 * by the browser client's library.
 *
 * `crates/hxd/tests/news.rs` covers the wire in depth with hand-rolled
 * JSON. What only this suite reaches is `[news]` read out of a file by
 * `Config::load`, the database it shares with `[inbox]` because the file
 * says so, and a second implementation of §9 — one the client wrote from
 * the spec — agreeing with the server about what an article is.
 */

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import {
  BAD_SIGNATURE,
  base64urlToBytes,
  fetchChallenge,
  fingerprintFromString,
  markedSpans,
  newsScopeOf,
  readSignedArticle,
  referenceSpans,
  signNewsPost,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { enrolledDevice, signingIdentity } from './harness/device.mjs';
import { pngBlob } from './harness/png.mjs';
import { startFailing, startServer } from './harness/server.mjs';

const account = (name, access) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
${access}`;

/** What a request came back as: `ok`, or the code it was refused with. */
const code = (p) =>
  p.then(
    () => 'ok',
    (e) => e.wire?.code ?? String(e),
  );

const EDITOR = `read_news = true
post_news = true
delete_articles = true
create_categories = true
delete_categories = true
create_news_bundles = true
delete_news_bundles = true
`;

describe('threaded news', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      // No `db` of its own: it shares the inbox's file, which is the
      // configuration the design recommends and the one only this layer
      // can see being honored.
      // `[news.notify]` empty: subscriptions on, every key its default,
      // which is itself something only a real config file can say.
      // `[identity]` with its hosts, so the server carries signed articles.
      config: (ports) => ({ inbox: { db: 'server.sqlite' }, news: { max_depth: 2, notify: {} }, identity: signingIdentity(ports) }),
      accounts: {
        editor: account('editor', EDITOR),
        alice: account('alice', 'read_news = true\npost_news = true\n'),
        reader: account('reader', 'read_news = true\n'),
        outsider: account('outsider', ''),
        // Accounts of their own for following, so what the cases above
        // posted and answered is not already in their badges.
        asker: account('asker', 'read_news = true\npost_news = true\n'),
        follower: account('follower', 'read_news = true\n'),
        timeliner: account('timeliner', 'read_news = true\n'),
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who) => crew.connect({ login: who, password: `pw-${who}`, nick: who });

  test('the login reply says what each session may do', async () => {
    const alice = await login('alice');
    assert.ok(alice.conn.hasCap('news'));
    assert.equal(alice.conn.news.post, true);
    assert.equal(alice.conn.news.max_depth, 2, 'the value from the config file');
    assert.equal(alice.conn.news.markdown, 'render', 'the default in a build with a parser');
    assert.deepEqual(alice.conn.news.body_types, ['text/plain', 'text/markdown']);
    const reader = await login('reader');
    assert.equal(reader.conn.news.post, false, 'a reader who may not post is told so');
  });

  test('a thread comes back in reading order, with references the client finds again', async () => {
    const editor = await login('editor');
    const alice = await login('alice');
    const reader = await login('reader');

    const { node: bundle } = await editor.conn.newsNodeCreate({ kind: 'bundle', name: 'Projects' });
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'hxd-ng', parent: bundle.id });
    await reader.waitFor('news_node', { 'node.id': node.id });

    const { id: root } = await alice.conn.newsPost({ category: node.id, subject: 'Phase 4 is open', body: 'News, finally.' });
    const posted = await reader.waitFor('news_posted', { id: root });
    assert.equal(posted.data.root, root);
    assert.equal(posted.data.parent, null);
    assert.equal(posted.data.from.nick, 'alice');

    const { id: first } = await editor.conn.newsPost({
      category: node.id,
      parent: root,
      subject: 'Re: Phase 4 is open',
      body: `About time — see #${root}, and #99999 which is nothing.`,
    });
    const { id: second } = await alice.conn.newsPost({ category: node.id, parent: root, subject: 'Re: Phase 4 is open', body: 'Two' });
    const { id: under } = await reader.conn
      .newsPost({ category: node.id, parent: first, subject: 'x', body: 'x' })
      .then(
        () => assert.fail('a reader may not post'),
        (e) => {
          assert.equal(e.wire.code, 'access_denied');
          return alice.conn.newsPost({ category: node.id, parent: first, subject: 'Re: Re', body: 'Under the first' });
        },
      );

    const thread = await reader.conn.newsThread({ root });
    assert.deepEqual(
      thread.articles.map((a) => [a.id, a.depth]),
      [
        [root, 0],
        [first, 1],
        [under, 2],
        [second, 1],
      ],
      'every reply under the article it answers',
    );

    const cited = thread.articles[1];
    assert.deepEqual(
      cited.refs.map((r) => r.id),
      [root],
      'only the id that named an article',
    );
    const links = referenceSpans(cited.body, cited.refs).filter((s) => 'ref' in s);
    assert.deepEqual(
      links.map((s) => s.text),
      [`#${root}`],
      'the client finds the reference where the server did, and nothing else',
    );
    assert.equal(referenceSpans(cited.body, cited.refs).map((s) => s.text).join(''), cited.body);
    assert.equal((await reader.conn.newsArticle(root)).referenced_by, 1);

    const listing = await reader.conn.newsThreads({ category: node.id });
    assert.equal(listing.threads[0].article.id, root);
    assert.equal(listing.threads[0].replies, 3);

    const tree = await reader.conn.newsTree({ depth: 2 });
    const projects = tree.nodes.find((n) => n.id === bundle.id);
    assert.equal(projects.children[0].name, 'hxd-ng');
    assert.equal(projects.children[0].count, 4);
  });

  test('a refusal comes back as the code the client has words for', async () => {
    const editor = await login('editor');
    const outsider = await login('outsider');
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Rules' });
    const { id: root } = await editor.conn.newsPost({ category: node.id, subject: 's', body: 'b' });
    const { id: one } = await editor.conn.newsPost({ category: node.id, parent: root, subject: 's', body: 'b' });
    const { id: two } = await editor.conn.newsPost({ category: node.id, parent: one, subject: 's', body: 'b' });

    assert.equal(await code(editor.conn.newsPost({ category: node.id, parent: two, subject: 's', body: 'b' })), 'too_deep');
    assert.equal(
      await code(editor.conn.newsPost({ category: node.id, subject: 's', body: 'b', mime: 'text/html' })),
      'bad_request',
    );
    assert.equal(await code(editor.conn.newsNodeCreate({ kind: 'category', name: 'Rules' })), 'name_taken');
    assert.equal(await code(outsider.conn.newsTree()), 'access_denied');
    assert.equal(outsider.conn.news.post, false);

    await editor.conn.newsDelete(root);
    const stone = await editor.conn.newsArticle(root);
    assert.equal(stone.deleted, true);
    assert.equal(stone.body, '');
    assert.deepEqual(
      (await editor.conn.newsThread({ root })).articles.map((a) => a.id),
      [root, one, two],
      'the tombstone keeps its place, and its replies keep theirs',
    );
    const { articles } = await editor.conn.newsNodeDelete(node.id);
    assert.equal(articles, 3);
  });

  test('a search finds what was posted, and the client marks what matched', async () => {
    const editor = await login('editor');
    const reader = await login('reader');
    assert.equal(reader.conn.news.search, true);
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Searchable' });
    const { id } = await editor.conn.newsPost({
      category: node.id,
      subject: 'Attachment sizes',
      body: 'Ünïcødé 🎈 first: the derivative is a u16.',
    });

    const page = await reader.conn.newsSearch({ q: 'derivative', category: node.id });
    assert.equal(page.total, 1);
    const [hit] = page.hits;
    assert.equal(hit.id, id);
    assert.equal(hit.root, id);
    assert.equal(hit.from, 'editor');
    // The server counts marks in UTF-16 and the client slices in UTF-16:
    // past the accents and the balloon, two implementations have to agree
    // to the code unit for this to come out as one word.
    assert.deepEqual(
      markedSpans(hit.snippet, hit.marks)
        .filter((s) => s.mark)
        .map((s) => s.text),
      ['derivative'],
    );
    assert.equal((await reader.conn.newsSearch({ q: '"the derivative"' })).total, 1);
    assert.equal((await reader.conn.newsSearch({ q: '"derivative the"' })).total, 0, 'a phrase is in order');
    assert.equal((await reader.conn.newsSearch({ q: 'deriv*', from: 'editor' })).total, 1);
    assert.equal((await reader.conn.newsSearch({ q: '(OR "' })).total, 0, 'no query is an error');

    await editor.conn.newsDelete(id);
    assert.equal((await reader.conn.newsSearch({ q: 'derivative' })).total, 0, 'a deletion reaches the index');
  });

  test('a markdown article comes back as written, and search reads it as text', async () => {
    const editor = await login('editor');
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Marked' });
    const { id: target } = await editor.conn.newsPost({ category: node.id, subject: 'Target', body: 'Here.' });
    const body = `## Findings\n\nSee [the target](news:${target}), **carefully**.\n\n    #${target} in code is only code\n`;
    const { id } = await editor.conn.newsPost({ category: node.id, subject: 'Marked up', body, mime: 'text/markdown' });

    const article = await editor.conn.newsArticle(id);
    assert.equal(article.mime, 'text/markdown');
    assert.equal(article.body, body, 'the server never rewrites what was typed');
    assert.deepEqual(
      article.refs.map((r) => r.id),
      [target],
    );

    const page = await editor.conn.newsSearch({ q: 'carefully', category: node.id });
    assert.deepEqual(
      page.hits.map((h) => h.id),
      [id],
    );
    assert.ok(!page.hits[0].snippet.includes('**'), page.hits[0].snippet);
  });

  test('an answer reaches whoever asked, and following a category hears what starts there', async () => {
    const editor = await login('editor');
    const asker = await login('asker');
    const follower = await login('follower');
    assert.equal(asker.conn.news.subscribe, true);
    assert.equal(asker.conn.news.auto_subscribe, 'participated', 'the default an empty section gets');
    assert.equal(asker.conn.news.unread, 0);

    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Questions' });
    await follower.waitFor('news_node', { 'node.id': node.id });
    const { id: root } = await asker.conn.newsPost({ category: node.id, subject: 'Does it ring?', body: 'Asking.' });
    const { subs } = await asker.conn.newsSubs();
    assert.deepEqual(
      subs.map((s) => [s.scope, s.target, s.subject, s.auto]),
      [['thread', root, 'Does it ring?', true]],
      'asking followed the thread, with nothing to click',
    );
    assert.deepEqual(await follower.conn.newsSubscribe({ category: node.id }), { unread: 0 });

    const { id: answer } = await editor.conn.newsPost({
      category: node.id,
      parent: root,
      subject: 'Re: Does it ring?',
      body: 'It rings.',
    });
    const notice = await asker.waitFor('news_notify', { article: answer });
    assert.equal(notice.data.reason, 'reply');
    assert.deepEqual(newsScopeOf(notice.data), { thread: root });
    assert.equal(notice.data.from.login, 'editor');
    assert.equal(notice.data.unread, 1);
    await follower.waitFor('news_posted', { id: answer });
    await follower.expectNo('news_notify', { article: answer }, { since: 0 });

    const { id: started } = await editor.conn.newsPost({ category: node.id, subject: 'Another', body: 'New.' });
    const heard = await follower.waitFor('news_notify', { article: started });
    assert.equal(heard.data.reason, 'subscription');
    assert.deepEqual(newsScopeOf(heard.data), { category: node.id });

    assert.deepEqual(await asker.conn.newsSeen({ thread: root }, answer), { unread: 0 });
    const again = await login('asker');
    assert.equal(again.conn.news.unread, 0, 'the badge on the first frame agrees');
  });

  test('the timeline merges what a reader follows, pages both ways, and is seen as far as it was shown', async () => {
    const editor = await login('editor');
    const alice = await login('alice');
    const reader = await login('timeliner');
    const made = async (name) => (await editor.conn.newsNodeCreate({ kind: 'category', name })).node.id;
    const [quiet, busy, hushed, elsewhere] = [await made('Quiet'), await made('Busy'), await made('Hushed'), await made('Elsewhere')];
    for (const category of [quiet, busy, hushed]) await reader.conn.newsSubscribe({ category });
    await reader.conn.newsMute({ category: hushed }, true);
    const start = async (category, subject) => (await alice.conn.newsPost({ category, subject, body: 'b' })).id;

    const q1 = await start(quiet, 'Rarely');
    await start(elsewhere, 'Not followed');
    await start(hushed, 'Asked never to hear');
    const b1 = await start(busy, 'One');
    const b2 = await start(busy, 'Two');
    const { id: reply } = await alice.conn.newsPost({ category: busy, parent: b1, subject: 'Re: One', body: 'no thread' });

    const marks = ({ threads }) => threads.map((t) => [t.article.id, t.unread]);
    const page = await reader.conn.newsTimeline({ limit: 2 });
    assert.deepEqual(marks(page), [
      [b2, true],
      [b1, true],
    ]);
    assert.equal(page.has_more, true);
    assert.deepEqual([page.threads[1].article.category, page.threads[1].replies, page.threads[1].last_id], [busy, 1, reply]);
    const older = await reader.conn.newsTimeline({ before: b1, limit: 2 });
    assert.deepEqual(marks(older), [[q1, true]], 'neither the muted category nor the unfollowed one');
    assert.equal(older.has_more, false);
    const oldest = await reader.conn.newsTimeline({ after: 0, limit: 2 });
    assert.deepEqual(marks(oldest).map(([id]) => id), [b1, q1], 'an after page holds the nearest, newest first');
    assert.equal(oldest.has_more, true);
    const top = await reader.conn.newsTimeline({ after: b1, limit: 2 });
    assert.deepEqual(marks(top).map(([id]) => id), [b2]);
    assert.equal(top.has_more, false);

    // The badge the timeline answers is its unmuted category rows', which
    // the muted row, still counting its own thread, is no part of.
    const rows = async () => {
      const { subs } = await reader.conn.newsSubs();
      const left = subs.filter((s) => s.scope === 'category' && !s.muted).reduce((n, s) => n + s.unread, 0);
      return { left, muted: subs.find((s) => s.scope === 'category' && s.target === hushed).unread };
    };
    assert.deepEqual(await rows(), { left: 3, muted: 1 });

    // Shown: the first page. Quiet's thread is older than it, so stays unread.
    assert.deepEqual(await reader.conn.newsSeenTimeline(b1, b2), { unread: 1 });
    assert.deepEqual(await rows(), { left: 1, muted: 1 });
    assert.deepEqual(marks(await reader.conn.newsTimeline()), [
      [b2, false],
      [b1, false],
      [q1, true],
    ]);
    assert.deepEqual(await reader.conn.newsSeenTimeline(0, b2), { unread: 0 }, 'a run that reached the end');
    assert.deepEqual(await rows(), { left: 0, muted: 1 });

    const fresh = await start(quiet, 'Again');
    assert.deepEqual(marks(await reader.conn.newsTimeline({ after: b2 })), [[fresh, true]]);
  });

  test('a guest is refused the timeline by what its account file says', async () => {
    const refusals = async () => {
      const guest = await crew.connect({ nick: 'Passerby' });
      return [await code(guest.conn.newsTimeline()), await code(guest.conn.newsSeenTimeline(0, 1))];
    };
    assert.deepEqual(await refusals(), ['access_denied', 'access_denied'], 'the guest the server bootstrapped reads no news');
    const bootstrapped = readFileSync(join(server.dir, 'accounts', 'guest.toml'), 'utf8');
    server.account('guest', `${bootstrapped}read_news = true\n`);
    assert.deepEqual(await refusals(), ['no_mailbox', 'no_mailbox'], 'one that may read has nowhere to keep a follow');
  });

  test('a signed article is posted, listed and read back as signed, and signed again it is the same article', async () => {
    const author = await enrolledDevice(server, 'news-author');
    server.account('scribe', `${account('scribe', 'read_news = true\npost_news = true\n')}[identity]\nfingerprint = "${author.fingerprint}"\n`);
    const scribe = await crew.connect({ nick: 'Scribe', identity: { getToken: author.getToken, signs: () => 'able' } });
    assert.equal(scribe.conn.signing, 'able');
    const editor = await login('editor');
    const reader = await login('reader');
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Signed' });
    const category = base64urlToBytes(node.guid);
    assert.equal(category.length, 16, 'a node carries its guid on a server that offers signed');
    const { serverKey } = await fetchChallenge(author.challengeAt);
    const by = fingerprintFromString(author.fingerprint);

    const sign = (over) =>
      signNewsPost(author.key, { cert: author.cert, server: serverKey, category, subject: 'In ink', body: 'Signed **here**.', mime: 'text/markdown', ...over });
    const post = (p, parent) =>
      scribe.conn.newsPost({ category: node.id, ...(parent ? { parent } : {}), subject: p.subject, body: p.body, mime: p.mime, signed: p.signed });
    const starter = await sign({});
    const { id } = await post(starter);
    const reply = await sign({ subject: 'Re: In ink', body: 'Countersigned.', parent: { article: id, signed: { id: starter.id, by } } });
    const { id: answer } = await post(reply, id);

    // Read back as the reader is shown each: the starter in its category's
    // listing and on its own, the reply in the thread under it.
    const read = (a, parent) =>
      readSignedArticle(a.signed, a, { at: a.at, sender: { named: a.from.fingerprint }, scope: { server: serverKey, category, parent } });
    const verified = { state: 'verified', signer: author.fingerprint, sentApart: false };
    const listed = (await reader.conn.newsThreads({ category: node.id })).threads.find((t) => t.article.id === id).article;
    assert.equal(listed.signed, starter.signed);
    assert.deepEqual((await read(listed, null)).outcome, verified);
    assert.deepEqual((await read(await reader.conn.newsArticle(id), null)).outcome, verified);
    const thread = await reader.conn.newsThread({ root: id });
    const replied = thread.articles.find((a) => a.id === answer);
    assert.equal(replied.signed, reply.signed);
    assert.deepEqual((await read(replied, { article: id, signed: { id: starter.id, by } })).outcome, verified);

    // The same post signed again under its id is answered as the article
    // it is (e2e-messages.md §4.10); other words under it are refused.
    const sent = Math.floor(Date.now() / 1000) - 5;
    const again = await signNewsPost(
      author.key,
      { id: starter.id, cert: author.cert, server: serverKey, category, subject: 'In ink', body: 'Signed **here**.', mime: 'text/markdown' },
      sent,
    );
    assert.notEqual(again.signed, starter.signed);
    assert.equal((await post(again)).id, id);
    const other = await sign({ id: starter.id, body: 'Signed elsewhere.' });
    const refused = await post(other).then(
      () => 'ok',
      (e) => e.wire?.code ?? String(e),
    );
    assert.equal(refused, BAD_SIGNATURE);
    assert.equal((await reader.conn.newsThreads({ category: node.id })).threads.length, 1, 'nothing more was posted');
  });
});

describe('news attachments', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      // `blobs` named, so bytes landing there is the file's doing, and
      // `[news.attach]` with one key, so every other limit is the default
      // a real config file gets.
      config: { inbox: { db: 'server.sqlite' }, news: { blobs: 'pictures', attach: { max_count: 2 } } },
      accounts: {
        editor: account('editor', `${EDITOR}send_media = true\n`),
        reader: account('reader', 'read_news = true\n'),
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who) => crew.connect({ login: who, password: `pw-${who}`, nick: who });
  const stored = () =>
    readdirSync(join(server.dir, 'pictures'), { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).length;

  test('an image staged over HTTP goes out with its article and comes back to another client', async () => {
    const editor = await login('editor');
    const reader = await login('reader');
    assert.equal(editor.conn.news.attach, true);
    assert.equal(editor.conn.news.max_attachments, 2, 'the value from the config file');
    assert.equal(editor.conn.news.max_attachment_bytes, 2 * 1024 * 1024, 'the default');
    assert.equal(reader.conn.news.attach, false, 'a reader who may not post may not attach');
    assert.equal(await code(reader.conn.uploadNewsAttachment(pngBlob(4, 4))), 'access_denied');

    const staged = await editor.conn.uploadNewsAttachment(pngBlob(24, 12), 'Café 日本.png');
    assert.equal(staged.name, 'Café 日本.png', 'a name past ASCII survives the header both ways');
    assert.deepEqual([staged.type, staged.width, staged.height], ['image/png', 24, 12]);
    assert.equal(staged.expires_in, 1800);
    assert.ok(stored() > 0, 'the bytes are where the config file said');

    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'Pictures' });
    const { id } = await editor.conn.newsPost({ category: node.id, subject: 'With a picture', body: 'See.', attach: [staged.id] });
    const article = await reader.conn.newsArticle(id);
    assert.deepEqual(
      article.attachments.map((a) => [a.id, a.name]),
      [[staged.id, 'Café 日本.png']],
    );
    const image = await reader.conn.fetchNewsAttachment(staged.id);
    assert.equal(image.type, 'image/png');
    assert.deepEqual([...new Uint8Array(await image.slice(0, 4).arrayBuffer())], [0x89, 0x50, 0x4e, 0x47]);

    await editor.conn.newsDelete(id);
    assert.equal(await code(reader.conn.fetchNewsAttachment(staged.id)), 'no_such_media');
    assert.equal(stored(), 0, 'a deletion unlinks the bytes, not only the row');
  });
});

describe('a news section the server cannot honor', () => {
  test('refuses to start rather than doing less than it says', async () => {
    const { output } = await startFailing({ config: { news: { db: 'news.sqlite', markdown: 'html' } } });
    assert.match(output, /markdown/);
    const alone = await startFailing({ config: { news: {} } });
    assert.match(alone.output, /\[news\] needs db/);
    const none = await startFailing({ config: { news: { db: 'news.sqlite', attach: { max_count: 0 } } } });
    assert.match(none.output, /\[news\.attach\]/);
    const flat = await startFailing({ config: { news: { db: 'news.sqlite', flat_reply: 'newest' } } });
    assert.match(flat.output, /flat_reply/);
  });
});

describe('a timeline the config file leaves out', () => {
  // The gates in front of `news_timeline` are sections of the file:
  // without `[news]` there is no news, and without `[news.notify]` no
  // follows for a timeline to be made of.
  for (const [what, config, refused] of [
    ['no [news]', {}, 'no_news'],
    ['no [news.notify]', { news: { db: 'news.sqlite' } }, 'not_available'],
  ]) {
    test(`with ${what} the timeline is ${refused}`, async () => {
      const server = await startServer({ config, accounts: { reader: account('reader', 'read_news = true\n') } });
      const crew = fleet(() => server);
      try {
        const { conn } = await crew.connect({ login: 'reader', password: 'pw-reader', nick: 'reader' });
        assert.deepEqual([await code(conn.newsTimeline()), await code(conn.newsSeenTimeline(0, 1))], [refused, refused]);
      } finally {
        await crew.closeAll();
        await server.stop();
      }
    });
  }
});
