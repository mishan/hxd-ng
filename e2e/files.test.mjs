import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const body = Buffer.from('the same bytes on both wires\n');
let fixture;
let origin;
let server;
let crew;

function listen(http) {
  return new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(0, '127.0.0.1', () => {
      http.off('error', reject);
      resolve(http.address());
    });
  });
}

before(async () => {
  fixture = mkdtempSync(join(tmpdir(), 'hxd-files-e2e-'));
  const manifest = join(fixture, 'manifest.json');
  writeFileSync(
    manifest,
    JSON.stringify({
      version: 1,
      files: [
        {
          path: 'manuals/read me.txt',
          size: String(body.length),
          media_type: 'text/plain',
          etag: '"files-e2e-v1"',
          ranges: true,
          created: 0,
          modified: 1,
          comment: 'served from the configured origin',
        },
      ],
    }),
  );

  origin = createHttpServer((req, res) => {
    if (req.url !== '/manuals/read%20me.txt') {
      res.writeHead(404).end();
      return;
    }
    if (req.headers['if-match'] !== '"files-e2e-v1"') {
      res.writeHead(412).end();
      return;
    }
    res.setHeader('etag', '"files-e2e-v1"');
    res.setHeader('accept-ranges', 'bytes');
    res.setHeader('content-type', 'text/plain');
    const match = /^bytes=(\d+)-$/.exec(req.headers.range ?? '');
    if (match) {
      const start = Number(match[1]);
      const end = body.length - 1;
      if (start > end || end >= body.length) {
        res.writeHead(416).end();
        return;
      }
      const slice = body.subarray(start, end + 1);
      res.setHeader('content-range', `bytes ${start}-${end}/${body.length}`);
      res.setHeader('content-length', slice.length);
      res.writeHead(206).end(slice);
      return;
    }
    res.setHeader('content-length', body.length);
    res.writeHead(200).end(body);
  });
  const address = await listen(origin);
  server = await startServer({
    config: (ports) => ({
      files: {
        manifest,
        origin: `http://127.0.0.1:${address.port}`,
        bind: `127.0.0.1:${ports.files}`,
      },
    }),
    accounts: {
      reader:
        'name = "Reader"\npassword = "pw"\n[access]\n' +
        'download_files = true\nread_chat = true\nuse_any_name = true\n',
    },
  });
  crew = fleet(() => server);
});

after(async () => {
  await crew?.closeAll();
  await server?.stop();
  await new Promise((resolve) => origin?.close(resolve));
  if (fixture) rmSync(fixture, { recursive: true, force: true });
});

describe('files', () => {
  test('the real binary exposes exact metadata and streams resumable downloads', async () => {
    const client = await crew.connect({ login: 'reader', password: 'pw', nick: 'Reader' });
    assert.ok(client.conn.caps.includes('files'));

    const root = await client.conn.filesList();
    assert.deepEqual(root.entries.map((entry) => entry.name), ['manuals']);
    assert.equal(root.entries[0].kind, 'folder');

    const listing = await client.conn.filesList('manuals');
    assert.equal(listing.entries[0].size, String(body.length));
    const info = await client.conn.fileInfo('manuals/read me.txt');
    assert.equal(info.comment, 'served from the configured origin');

    const prepared = await client.conn.prepareFileDownload('manuals/read me.txt');
    assert.equal(prepared.size, String(body.length));
    const full = await client.conn.fetchFile(prepared);
    assert.equal(Buffer.from(await full.arrayBuffer()).compare(body), 0);

    const resumed = await client.conn.fetchFile(prepared, { offset: 9n });
    assert.equal(resumed.status, 206);
    assert.equal(Buffer.from(await resumed.arrayBuffer()).compare(body.subarray(9)), 0);
  });

  test('a token stops authorizing bytes after its session ends', async () => {
    const client = await crew.connect({ login: 'reader', password: 'pw', nick: 'Short lived' });
    const prepared = await client.conn.prepareFileDownload('manuals/read me.txt');
    const url = new URL(prepared.url, server.httpBase);
    await client.close();
    const response = await fetch(url);
    assert.equal(response.status, 404);
  });
});
