/**
 * Inline media, and the two questions that must not be confused.
 *
 * `docs/inline-media.md`: attaching a handle asks whether *this session*
 * uploaded it; fetching one asks whether this principal was shown it.
 * Getting those two confused is how an image reaches someone who was not
 * in the room, so most of this file is about who is refused.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { noisyPngBlob, pngBlob } from './harness/png.mjs';
import { startServer } from './harness/server.mjs';

const poster = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
send_media = true
use_any_name = true
`;

describe('inline media', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: {
        media: {
          max_bytes: 262144,
          // The rate limiter is real and it is right: uploads are
          // per-address, and every client in this file is the same
          // address. Left at its defaults, the file as a whole reads as
          // one client uploading far too fast, and the second test to
          // ask is told `rate_limited` — which is the limiter working,
          // not a bug. Raised here so the other tests can say what they
          // are about; `rate-limit.test.mjs` leaves it alone and asserts
          // it bites.
          rate: {
            upload_interval: 0,
            upload_per_hour: 1000,
            upload_per_hour_per_addr: 1000,
            download_per_minute: 1000,
          },
        },
      },
      accounts: { alice: poster('alice'), bob: poster('bob'), carol: poster('carol') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, nick) => crew.connect({ login: who, password: `pw-${who}`, nick: nick ?? who });

  test('the login reply states the limits, so a client can refuse locally', async () => {
    const alice = await login('alice');
    const limits = alice.conn.media;
    assert.ok(limits, 'a media server says what it takes');
    assert.equal(limits.max_bytes, 262144);
    assert.ok(limits.types.includes('image/png'));
    assert.ok(limits.max_dimension > 0 && limits.max_pixels > 0);
  });

  test('an uploaded image comes back as itself, by handle', async () => {
    const alice = await login('alice');
    const uploaded = await alice.conn.uploadMedia(pngBlob(16, 16, [10, 20, 30]));
    assert.ok(uploaded.id, 'an upload answers with a handle');
    assert.equal(uploaded.type, 'image/png');
    assert.equal(uploaded.width, 16);
    assert.equal(uploaded.height, 16);

    const back = await alice.conn.fetchMedia(uploaded.id);
    const bytes = Buffer.from(await back.arrayBuffer());
    assert.equal(bytes.subarray(1, 4).toString(), 'PNG');
    // Not the bytes that went up: the server decoded and re-encoded it,
    // which is what makes metadata-stripping a property of the
    // construction rather than of a filter that could miss a chunk.
    assert.ok(bytes.length > 0);
  });

  test('a handle in a chat line reaches the room, and only the room', async () => {
    const alice = await login('alice');
    const bob = await login('bob');

    const uploaded = await alice.conn.uploadMedia(pngBlob(24, 24, [200, 0, 100]));
    await alice.conn.chat({ text: '', media: uploaded.id });

    const seen = await bob.waitFor('chat', (d) => d.media?.id === uploaded.id);
    assert.equal(seen.data.media.width, 24);

    // Bob was in the room when the line was relayed, so the handle
    // authorizes him.
    const got = await bob.conn.fetchMedia(uploaded.id);
    assert.equal(Buffer.from(await got.arrayBuffer()).subarray(1, 4).toString(), 'PNG');

    // Carol was not. The audience is fixed when the line is relayed and
    // may narrow but never widen, so arriving afterwards is not a way in.
    const carol = await login('carol');
    const refused = await carol.conn
      .fetchMedia(uploaded.id)
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(refused, 'no_such_media', 'and it is not told the difference from a handle that never existed');
  });

  test('a handle belongs to the session that uploaded it', async () => {
    // The other question. Bob may well be allowed to *see* this image;
    // that has no bearing on whether he may put it on a line of his own.
    const alice = await login('alice');
    const bob = await login('bob', 'bob-attach');
    const uploaded = await alice.conn.uploadMedia(pngBlob(8, 8));
    await alice.conn.chat({ text: '', media: uploaded.id });
    await bob.waitFor('chat', (d) => d.media?.id === uploaded.id);

    const code = await bob.conn
      .request('chat', { text: '', media: uploaded.id })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.notEqual(code, null, 'attaching somebody else’s upload is refused');
  });

  test('a guest may look but not post, and the account file says so', async () => {
    // `send_media` is the one access bit that lets a stranger put a
    // picture on everyone's screen, so the bootstrapped guest account
    // ships with it commented out.
    const guest = await crew.connect({ nick: 'Passerby' });
    const refused = await guest.conn
      .uploadMedia(pngBlob(8, 8))
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.ok(refused, `expected a refusal, got ${refused}`);
  });

  test('something that is not an image is refused whatever it claims to be', async () => {
    const alice = await login('alice');
    const liar = new Blob([Buffer.from('GIF89a and then some nonsense')], { type: 'image/png' });
    const code = await alice.conn
      .uploadMedia(liar)
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.ok(code, 'the sniff and the walk have to agree with the claim');
  });

  test('an image over the cap is refused, and the client could have known', async () => {
    const alice = await login('alice');
    // Genuinely over `max_bytes`, not merely a large picture: random
    // pixels do not deflate, so this is ~480 KB against a 256 KB cap.
    const big = noisyPngBlob(400, 400);
    assert.ok(big.size > alice.conn.media.max_bytes);

    // The library checks locally first so the answer is instant, and the
    // server checks again because its answer is the one that counts.
    const { mediaBlockedReason } = await import('@hotline-ng/client');
    assert.match(mediaBlockedReason(big, alice.conn.media), /takes up to/);

    const code = await alice.conn
      .uploadMedia(big)
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.ok(code, 'a file over the cap does not get decoded to find out');
  });
});
