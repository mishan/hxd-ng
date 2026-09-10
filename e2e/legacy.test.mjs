/**
 * The legacy wire, checked by something that does not share its code.
 *
 * Every legacy test in `crates/hxd/tests/` packs with `pack_frame` and
 * parses with `read_frame`. Those are the server's own functions, from
 * the `hxproto` the server unpacks with, so a framing bug symmetric
 * between the two ends is invisible to all of them — the suite would
 * agree with itself and say nothing. This file frames from the format,
 * and spends most of its length on what the server is supposed to
 * *refuse*, which is the half a friendly client never reaches.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { CLIENT_MAGIC, HDR_LEN, SERVER_MAGIC, pack } from './harness/frame.mjs';
import { hdr, legacyFleet, req, tag, toBytes, toText, twiddle } from './harness/legacy.mjs';
import { startServer } from './harness/server.mjs';
import { connect } from 'node:net';

const BOB = `name = "Bob"
password = "s3cret"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
`;

/** A socket that has said hello and nothing else, for the cases where
 *  the point is what happens *instead of* a conversation. */
function rawSocket(server) {
  return new Promise((resolve, reject) => {
    const sock = connect({ host: '127.0.0.1', port: server.ports.legacy });
    const seen = [];
    let closed = false;
    sock.on('data', (d) => seen.push(d));
    sock.on('close', () => (closed = true));
    sock.on('error', () => (closed = true));
    sock.once('error', reject);
    sock.once('connect', () => {
      sock.write(CLIENT_MAGIC);
      resolve({
        sock,
        bytes: () => Buffer.concat(seen),
        isClosed: () => closed,
        async settle(ms = 750) {
          await new Promise((r) => setTimeout(r, ms));
        },
        close: () => sock.destroy(),
      });
    });
  });
}

describe('the legacy wire', () => {
  let server;
  const old = legacyFleet(() => server);
  const strays = [];

  before(async () => {
    server = await startServer({ accounts: { bob: BOB } });
  });
  after(async () => {
    for (const s of strays) s.close();
    old.closeAll();
    await server?.stop();
  });

  test('the handshake is TRTPHOTL out and TRTP plus a zero error back', async () => {
    const raw = await rawSocket(server);
    strays.push(raw);
    await raw.settle(300);
    assert.equal(Buffer.compare(raw.bytes().subarray(0, 8), SERVER_MAGIC), 0);
  });

  test('a login carrying a nick completes without the agreement dance', async () => {
    const bob = await old.login({ login: 'bob', password: 's3cret', nick: 'Bob' });
    assert.ok(bob.uid > 0);
    assert.equal(bob.self.nick, 'Bob');
  });

  test('a 1.5 login without a nick is parked until it agrees', async () => {
    // The other login path, and the one a real 1.5 client takes: the
    // server sends the agreement and waits. `ng.rs`'s scripted client
    // only ever sends NAME, so this half has had no coverage from a
    // socket.
    const client = await old.raw('Patient');
    await client.login({ login: 'bob', password: 's3cret', version: 150, withNick: false });
    await client.waitFor((f) => f.type === hdr.AGREEMENT);
    await client.expectNo((f) => f.type === hdr.USER_SELFINFO);

    await client.agree('Agreeable');
    assert.ok(client.uid > 0, 'and only now is there a session to describe');
    assert.equal(client.self.nick, 'Agreeable');
  });

  test('credentials are one-s complement, and the transform is its own inverse', async () => {
    // Not encryption, and never was. Worth a test because a client that
    // gets this wrong fails as "wrong password", which is the least
    // informative possible symptom.
    const round = twiddle(twiddle(toBytes('s3cret')));
    assert.equal(round.toString(), 's3cret');

    const wrong = await old.raw('Impostor');
    await assert.rejects(
      () => wrong.login({ login: 'bob', password: toText(twiddle(toBytes('s3cret'))) }),
      /login refused/,
    );
  });

  test('a frame whose two lengths disagree is refused, not half-understood', async () => {
    // `len` is TotalSize and `len2` is DataSize; they differ only for a
    // sender that fragments, and no client does. The server frames by
    // `len2` and rejects a mismatch outright — the alternative, trusting
    // one and reading by the other, is the desync gtkhx paid for.
    const raw = await rawSocket(server);
    strays.push(raw);
    await raw.settle(200);

    const frame = pack(req.LOGIN, 1, 0, [[tag.NAME, toBytes('Ambiguous')]]);
    frame.writeUInt32BE(frame.readUInt32BE(16) + 8, 12); // len, now a lie
    raw.sock.write(frame);

    await raw.settle(1000);
    assert.ok(raw.isClosed(), 'the server hangs up rather than guessing which length is true');
  });

  test('a frame claiming more than the cap is refused before it is read', async () => {
    const raw = await rawSocket(server);
    strays.push(raw);
    await raw.settle(200);

    // A header alone, promising a body far past mhxd's
    // MAX_HOTLINE_PACKET_LEN. Nothing follows it: a server that trusted
    // the number would now be waiting on a quarter-megabyte allocation.
    const head = Buffer.alloc(HDR_LEN);
    head.writeUInt32BE(req.CHAT, 0);
    head.writeUInt32BE(1, 4);
    head.writeUInt32BE(0, 8);
    head.writeUInt32BE(0x0100_0000, 12);
    head.writeUInt32BE(0x0100_0000, 16);
    head.writeUInt16BE(1, 20);
    raw.sock.write(head);

    await raw.settle(1000);
    assert.ok(raw.isClosed());
  });

  test('a nick longer than the wire allows is cut to fit, after conversion', async () => {
    // Thirty-one bytes, and the truncation happens on the Mac Roman
    // side — so the limit is bytes rather than characters, and an
    // accented nick loses more of itself than an ASCII one.
    const long = await old.login({ login: 'bob', password: 's3cret', nick: 'A'.repeat(60) });
    assert.ok(long.self.nick.length <= 31, `got ${long.self.nick.length} characters`);

    const rows = await long.users();
    const me = rows.find((u) => u.uid === long.uid);
    assert.equal(me.nick, long.self.nick, 'and the roster agrees with what it told me about myself');
  });

  test('a chat line is relayed to the room in the reference format', async () => {
    const speaker = await old.login({ login: 'bob', password: 's3cret', nick: 'Speaker' });
    const listener = await old.login({ login: 'bob', password: 's3cret', nick: 'Listener' });

    speaker.chat('and so I said');

    const line = await listener.waitFor(
      (f) => f.type === hdr.CHAT && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('and so I said'),
    );
    // Carriage return, thirteen right-aligned columns of nick, colon,
    // two spaces. mhxd's `\r%13.13s:  %s`, byte for byte.
    assert.equal(toText(line.get(tag.BODY)), '\r      Speaker:  and so I said');
  });
});
