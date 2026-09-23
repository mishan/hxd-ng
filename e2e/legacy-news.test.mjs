/**
 * News across both wire eras, from a real config file.
 *
 * `crates/hxd/tests/news.rs` drives the legacy news binding with the
 * server's own `hxproto`. What only this suite reaches is `[news]`'s
 * legacy keys read out of a file by `Config::load` — `flat_category` and
 * `flat_masthead` above all — and a 1.5 client written from the wire
 * format reading what the browser client wrote.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { hdr, legacyFleet, newsPath, parseCatlist, req, tag, toBytes, toText } from './harness/legacy.mjs';
import { startServer } from './harness/server.mjs';

const account = (name, access) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
read_news = true
${access}`;

describe('news on the legacy wire', () => {
  let server;
  const ng = fleet(() => server);
  const old = legacyFleet(() => server);

  before(async () => {
    server = await startServer({
      config: {
        news: { db: 'news.sqlite', flat_category: 'General', flat_masthead: 'The front page.' },
      },
      accounts: {
        editor: account('editor', 'post_news = true\ncreate_categories = true\n'),
        alice: account('alice', 'post_news = true\n'),
        bob: account('bob', 'post_news = true\n'),
      },
    });
  });
  after(async () => {
    old.closeAll();
    await ng.closeAll();
    await server?.stop();
  });

  const login = (who) => ng.connect({ login: who, password: `pw-${who}`, nick: who });

  test('a 1.2 client reads the flat category and posts a reply into it', async () => {
    const editor = await login('editor');
    const alice = await login('alice');
    const { node } = await editor.conn.newsNodeCreate({ kind: 'category', name: 'General' });
    const { id: welcome } = await alice.conn.newsPost({
      category: node.id,
      subject: 'Welcome',
      body: 'Hello from the browser.',
    });

    const bob = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Bob' });
    const reply = await bob.request(req.NEWSFILE_GET);
    assert.equal(reply.flag, 0);
    const doc = toText(reply.get(tag.BODY));
    assert.ok(doc.startsWith('The front page.\r'), doc);
    assert.ok(doc.includes(`]  #${welcome}\rSubject: Welcome\r\rHello from the browser.\r`), doc);

    // The two lines it read are the two lines it types.
    const since = bob.mark();
    const posted = await bob.request(req.NEWSFILE_POST, [
      [tag.BODY, toBytes(`Subject: Caf\u00e9 talk\rRe: #${welcome}\r\rA reply from 1997.`)],
    ]);
    assert.equal(posted.flag, 0);
    const heard = await alice.waitFor('news_posted', { subject: 'Caf\u00e9 talk' });
    assert.equal(heard.data.parent, welcome);
    const article = await alice.conn.newsArticle(heard.data.id);
    assert.equal(article.body, 'A reply from 1997.');

    // And the push that grows its pane arrives for its own post.
    const push = await bob.waitFor(
      (f) => f.type === hdr.NEWSFILE_POST && toText(f.get(tag.BODY)).includes(`#${heard.data.id}\r`),
      { since },
    );
    assert.ok(toText(push.get(tag.BODY)).includes(`Subject: Caf\u00e9 talk\rRe: #${welcome}\r`));
  });

  test('a 1.5 client lists the category and fetches an article by type', async () => {
    const alice = await login('alice');
    const tree = await alice.conn.newsTree();
    const general = tree.nodes.find((n) => n.name === 'General');
    const { id } = await alice.conn.newsPost({
      category: general.id,
      subject: 'Marked',
      body: '**Bold** text',
      mime: 'text/markdown',
    });

    const bob = await old.login({ login: 'bob', password: 'pw-bob', nick: 'Bob' });
    const listing = await bob.request(req.NEWS_LISTCATEGORY, [[tag.NEWS_PATH, newsPath('General')]]);
    assert.equal(listing.flag, 0);
    const posts = parseCatlist(listing.get(tag.NEWS_CATLIST));
    const marked = posts.find((p) => p.id === id);
    assert.equal(marked.subject, 'Marked');
    assert.equal(marked.parent, 0);
    assert.deepEqual(
      marked.parts.map((p) => p.mime),
      ['text/plain', 'text/markdown'],
    );

    const u32 = (n) => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n);
      return b;
    };
    const fetch = (mime) =>
      bob.request(req.NEWS_GETTHREAD, [
        [tag.NEWS_PATH, newsPath('General')],
        [tag.NEWS_THREADID, u32(id)],
        [tag.NEWS_MIMETYPE, toBytes(mime)],
      ]);
    const plain = await fetch('text/plain');
    assert.equal(toText(plain.get(tag.NEWS_DATA)), 'Bold text');
    assert.equal(plain.get(tag.NEWS_DATA).length, marked.parts[0].size);
    const source = await fetch('text/markdown');
    assert.equal(toText(source.get(tag.NEWS_DATA)), '**Bold** text');
    assert.equal(source.get(tag.NEWS_DATA).length, marked.parts[1].size);
  });
});
