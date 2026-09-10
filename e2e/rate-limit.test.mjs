/**
 * The limits, left at their defaults.
 *
 * Its own file because it is the one place the suite must *not* raise a
 * cap to get its work done: everywhere else the tests configure the
 * limiter out of the way, on the grounds that a file's worth of clients
 * on 127.0.0.1 reads as a single very busy one. Here that is the point.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { pngBlob } from './harness/png.mjs';
import { startServer } from './harness/server.mjs';

const ALICE = `name = "Alice"
password = "hunter2"
[access]
read_chat = true
send_chat = true
send_media = true
use_any_name = true
`;

describe('rate limits', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    // `[media]` with no `[media.rate]`: the recommended defaults, which
    // is what a real deployment gets.
    server = await startServer({ config: { media: {} }, accounts: { alice: ALICE } });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('a second upload hard on the heels of the first is refused', async () => {
    const alice = await crew.connect({ login: 'alice', password: 'hunter2', nick: 'Alice' });

    const first = await alice.conn.uploadMedia(pngBlob(8, 8, [1, 2, 3]));
    assert.ok(first.id, 'the first one goes through');

    const code = await alice.conn
      .uploadMedia(pngBlob(8, 8, [4, 5, 6]))
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(code, 'rate_limited');
  });

  test('the refusal is a delay, not a door closing', async () => {
    // A limiter that latched would be a denial of service against the
    // person it protects, so the window has to reopen. The property is
    // that it reopens, not that it takes ten seconds to — hence a
    // server of this test's own with a short interval, rather than a
    // ten-second sleep in every future run of this suite.
    const brisk = await startServer({
      config: { media: { rate: { upload_interval: 1 } } },
      accounts: { alice: ALICE },
    });
    const theirs = fleet(() => brisk);
    try {
      const alice = await theirs.connect({ login: 'alice', password: 'hunter2', nick: 'Patient' });
      await alice.conn.uploadMedia(pngBlob(8, 8, [7, 7, 7]));

      const refused = await alice.conn
        .uploadMedia(pngBlob(8, 8, [8, 8, 8]))
        .then(() => null)
        .catch((e) => e.wire.code);
      assert.equal(refused, 'rate_limited');

      await new Promise((r) => setTimeout(r, 1500));
      const later = await alice.conn.uploadMedia(pngBlob(8, 8, [9, 9, 9]));
      assert.ok(later.id, 'past the interval, the same client is served again');
    } finally {
      await theirs.closeAll();
      await brisk.stop();
    }
  });
});
