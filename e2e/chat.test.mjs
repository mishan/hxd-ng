/**
 * Chat over the ng wire, against a real server.
 *
 * Worth reading alongside `crates/hxd/tests/ng.rs`: that suite asserts
 * much of the same behavior with JSON the server's own author wrote.
 * Here the frames are built and parsed by a client that has never seen
 * `hxd-core`, so the agreement is evidence about the wire rather than
 * about one person's reading of it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import {
  CAP_CHAT_GUID,
  CAP_SIGNED,
  bytesToHex,
  fetchChallenge,
  fetchDiscovery,
  postAuth,
  readSignedChat,
  signChatRequest,
  signLoginProof,
} from '@hotline-ng/client';

import { connect } from './harness/client.mjs';
import { hlid, startServer } from './harness/server.mjs';

const BOB = `name = "Bob"
password = "s3cret"
[access]
read_chat = true
read_chat_history = true
send_chat = true
send_msgs = true
use_any_name = true
`;

describe('chat', () => {
  let server;
  const open = [];

  before(async () => {
    server = await startServer({
      // Identity with the hosts it signs challenges for, which is what
      // makes the server carry signed lines (e2e-messages.md §4.6).
      config: (ports) => ({
        history: { db: 'history.db' },
        identity: {
          key: 'identity-server.key',
          hosts: [`127.0.0.1:${ports.ng}`],
          new_accounts: 'guest',
          unattested: 'guest',
          // A key new here may not chat at once (identity-registrar.md
          // §7.3), which is not what this file is about.
          newcomer_delay: 0,
        },
      }),
      accounts: { bob: BOB },
    });
  });

  after(async () => {
    for (const c of open) await c.close();
    await server?.stop();
  });

  /** Every client this file makes gets closed, whatever the test does.
   *  The reconnect timer is ref'd, so one left running holds the whole
   *  file open past its last assertion. */
  async function client(creds) {
    const c = await connect(server, creds);
    open.push(c);
    return c;
  }

  /** A device as a browser holds one, certified by `hlid` for messages
   *  as well as login, and the token-minting an identity login runs. */
  async function enrolledDevice(name) {
    const sign = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    const enc = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const signPub = new Uint8Array(await crypto.subtle.exportKey('raw', sign.publicKey));
    const encPub = new Uint8Array(await crypto.subtle.exportKey('raw', enc.publicKey));
    const keygen = hlid(server.dir, ['keygen', 'identity', `${name}.key`]);
    const fingerprint = /fingerprint: (\S+)/.exec(keygen)?.[1];
    hlid(server.dir, [
      'cert',
      '--identity', `${name}.key`,
      '--device-pub', bytesToHex(signPub),
      '--device-enc-pub', bytesToHex(encPub),
      '--caps', 'web',
      '-o', `${name}.cert`,
    ]);
    hlid(server.dir, ['card', '--identity', `${name}.key`, '--name', name, '-o', `${name}.card`]);
    const cert = new Uint8Array(readFileSync(join(server.dir, `${name}.cert`)));
    const card = new Uint8Array(readFileSync(join(server.dir, `${name}.card`)));
    const doc = await fetchDiscovery(server.httpBase);
    const endpoint = (path) => new URL(path, server.httpBase).toString();
    const getToken = async () => {
      const challenge = await fetchChallenge(endpoint(doc.identity.endpoints.challenge));
      const proof = await signLoginProof(sign.privateKey, {
        challenge: challenge.challenge,
        serverKey: challenge.serverKey,
        host: challenge.host,
        device: signPub,
        time: Math.floor(Date.now() / 1000),
      });
      const auth = await postAuth(endpoint(doc.identity.endpoints.auth), { host: challenge.host, card, deviceCert: cert, proof });
      return auth.token;
    };
    return { key: sign.privateKey, cert, fingerprint, getToken, challengeAt: endpoint(doc.identity.endpoints.challenge) };
  }

  test('a line reaches the room, and its sender', async () => {
    const alice = await client({ nick: 'Alice' });
    const bob = await client({ login: 'bob', password: 's3cret', nick: 'Bob' });

    await alice.conn.chat({ text: 'the room is open' });

    const heard = await bob.waitFor('chat', { text: 'the room is open' });
    assert.equal(heard.data.from.nick, 'Alice');
    assert.equal(heard.data.style, 'normal');

    // The sender is not a special case — it hears itself, which is the
    // rule every other assertion in this suite is written around.
    const echo = await alice.waitFor('chat', { text: 'the room is open' });
    assert.equal(echo.data.from.uid, alice.conn.self.uid);
  });

  test('an action line keeps its style across the wire', async () => {
    const alice = await client({ nick: 'Actor' });
    await alice.conn.chat({ text: 'waves', style: 'action' });
    const heard = await alice.waitFor('chat', { text: 'waves' });
    assert.equal(heard.data.style, 'action');
  });

  test('seqs are gapless, including for events this client cannot name', async () => {
    // The invariant the whole ng session model rests on: every event a
    // session should see consumes a seq, so `resume`'s `last_seq`
    // arithmetic means something. A hole is not cosmetic — it is a
    // replay that silently skips a message.
    //
    // Recording from the trace rather than from `Connection.on` is what
    // makes this checkable: an event the client has no handler for is
    // dropped before dispatch, and those are exactly the placeholder
    // frames whose seqs matter most here.
    const watcher = await client({ nick: 'Watcher' });
    const talker = await client({ nick: 'Talker' });

    for (const text of ['one', 'two', 'three']) {
      await talker.conn.chat({ text });
    }
    await watcher.waitFor('chat', { text: 'three' });
    await talker.close();
    await watcher.waitFor('user_parted', { uid: talker.conn.self.uid });

    const seqs = watcher.log.filter((r) => r.kind === 'ev').map((r) => r.seq);
    assert.ok(seqs.length >= 4, `expected several events, saw ${seqs.length}`);
    assert.deepEqual(
      seqs,
      seqs.map((_, i) => seqs[0] + i),
      `seqs must ascend without a hole, got ${seqs.join(',')}`,
    );
    assert.equal(watcher.conn.seq, seqs[seqs.length - 1]);
  });

  test('a persisted line carries the id history will page it under', async () => {
    const alice = await client({ login: 'bob', password: 's3cret', nick: 'Scribe' });
    await alice.conn.chat({ text: 'for the record' });
    const line = await alice.waitFor('chat', { text: 'for the record' });
    assert.ok(typeof line.data.id === 'number', 'a server with history gives a chat line an id');

    const page = await alice.conn.history({ limit: 200 });
    const found = page.lines.find((l) => l.id === line.data.id);
    assert.ok(found, `line ${line.data.id} should be in history, saw ${page.lines.length} lines`);
    assert.equal(found.text, 'for the record');
  });

  test('a signed line is heard with its signature, and its guid makes a repeat the same line', async () => {
    const device = await enrolledDevice('signer');
    const signer = await client({ nick: 'Signer', identity: { getToken: device.getToken, signs: () => 'default' } });
    assert.ok(signer.conn.hasCap(CAP_SIGNED) && signer.conn.hasCap(CAP_CHAT_GUID));
    assert.equal(signer.conn.signing, 'default', 'signs is echoed for a device whose certificate allows messages');

    const reader = await client({ login: 'bob', password: 's3cret', nick: 'Reader' });
    const row = reader.conn.login.users.find((u) => u.uid === signer.conn.self.uid);
    assert.equal(row.identity.fingerprint, device.fingerprint);
    assert.equal(row.identity.signs, true);

    // The key a line is scoped to, as the server's challenge proves it
    // for this host.
    const { serverKey } = await fetchChallenge(device.challengeAt);
    const req = await signChatRequest(device.key, { cert: device.cert, server: serverKey, room: 0, text: 'signed and said' });
    const ok = await signer.conn.chat(req);
    assert.equal(typeof ok.id, 'number', 'the reply carries the line id');

    const echo = await signer.waitFor('chat', (d) => d.id === ok.id);
    assert.equal(echo.data.guid, req.guid, 'the sender alone is shown its guid');
    const heard = await reader.waitFor('chat', (d) => d.id === ok.id);
    assert.equal(heard.data.text, 'signed and said');
    assert.equal(heard.data.signed, req.signed);
    assert.equal(heard.data.guid, undefined);
    const scope = { server: serverKey, room: 0 };
    const read = await readSignedChat(heard.data.signed, heard.data.text, heard.data.style === 'action', {
      at: heard.data.at,
      sender: { named: row.identity.fingerprint },
      scope,
    });
    assert.deepEqual(read.outcome, { state: 'verified', signer: device.fingerprint, sentApart: false });

    // A retry under the same guid is answered as the original, and
    // nothing more is relayed.
    const again = await signer.conn.chat(req);
    assert.equal(again.id, ok.id);
    await reader.expectNo('chat', (d) => d.signed === req.signed, { since: heard.n + 1 });

    const page = await reader.conn.history({ limit: 200 });
    const kept = page.lines.find((l) => l.id === ok.id);
    assert.equal(kept.signed, req.signed);
    assert.equal(
      (await readSignedChat(kept.signed, kept.text, kept.style === 'action', { at: kept.at, sender: 'certificate', scope })).outcome.state,
      'verified',
    );
  });
});
