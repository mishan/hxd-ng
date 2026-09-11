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
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { markedSpans, newsScopeOf, referenceSpans } from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { pngBlob } from './harness/png.mjs';
import { startFailing, startServer } from './harness/server.mjs';

const account = (name, access) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
${access}`;

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
      config: { inbox: { db: 'server.sqlite' }, news: { max_depth: 2, notify: {} } },
      accounts: {
        editor: account('editor', EDITOR),
        alice: account('alice', 'read_news = true\npost_news = true\n'),
        reader: account('reader', 'read_news = true\n'),
        outsider: account('outsider', ''),
        // Accounts of their own for following, so what the cases above
        // posted and answered is not already in their badges.
        asker: account('asker', 'read_news = true\npost_news = true\n'),
        follower: account('follower', 'read_news = true\n'),
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

    const code = (p) =>
      p.then(
        () => 'ok',
        (e) => e.wire?.code ?? String(e),
      );
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
  const code = (p) =>
    p.then(
      () => 'ok',
      (e) => e.wire?.code ?? String(e),
    );

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
  });
});
