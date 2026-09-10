/**
 * Logging in with a key instead of a password.
 *
 * Everything real: a device keypair generated in this process and never
 * exported, a certificate cut by the actual `hlid` binary, a card it
 * signed, the server's own challenge, and a proof built by
 * `@hotline-ng/client` — the same code the browser client signs with.
 * The only thing standing in for a browser is where the private key
 * lives, and even that is a `CryptoKey` this file cannot read.
 *
 * `crates/hxd/tests/identity.rs` covers the endpoints exhaustively from
 * the server's side. What it cannot cover is the client's arithmetic
 * agreeing with the server's: the CBOR field order, the domain
 * separator, the fingerprint spelling. Two implementations either
 * arrive at the same bytes or they do not.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import {
  bytesToHex,
  decodeDeviceCert,
  fetchChallenge,
  fetchDiscovery,
  fingerprintOf,
  postAuth,
  signLoginProof,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { hlid, startServer } from './harness/server.mjs';

/**
 * A device's keys, the way a browser holds them: non-extractable for
 * the signing key, so nothing in this file can copy it out either.
 *
 * The public halves are what `hlid cert` is handed, which is the whole
 * ceremony — an identity certifies a device it never sees the secret
 * of.
 */
async function newDevice() {
  const sign = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const enc = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const signPub = new Uint8Array(await crypto.subtle.exportKey('raw', sign.publicKey));
  const encPub = new Uint8Array(await crypto.subtle.exportKey('raw', enc.publicKey));
  return { key: sign.privateKey, signPub, encPub };
}

describe('identity login', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: {
        identity: {
          key: 'identity-server.key',
          // Nobody has attested this identity, so the strictest useful
          // posture that still lets a stranger in: a guest with a name
          // the server can prove is stable.
          new_accounts: 'guest',
          unattested: 'guest',
        },
      },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('discovery advertises identity and where to do it', async () => {
    const doc = await fetchDiscovery(server.httpBase);
    assert.equal(doc.identity.enabled, true);
    assert.ok(doc.identity.endpoints.challenge);
    assert.ok(doc.identity.endpoints.auth);
    // The policy is advertised, so a client can say what will happen
    // before it spends a signature finding out.
    assert.equal(doc.identity.newAccounts, 'guest');
    assert.ok(Array.isArray(doc.identity.bindings));
  });

  test('a real hlid certificate logs a real device in', async () => {
    const device = await newDevice();

    // `hlid` mints an identity and certifies this browser's public keys
    // — the ceremony `hlid cert --device-pub` exists for.
    const keygen = hlid(server.dir, ['keygen', 'identity', 'identity.key']);
    const fingerprint = /fingerprint: (\S+)/.exec(keygen)?.[1];
    assert.ok(fingerprint, `no fingerprint in: ${keygen}`);

    hlid(server.dir, [
      'cert',
      '--identity', 'identity.key',
      '--device-pub', bytesToHex(device.signPub),
      '--device-enc-pub', bytesToHex(device.encPub),
      '--caps', 'web',
      '--name', 'e2e device',
      '-o', 'cert.bin',
    ]);
    hlid(server.dir, ['card', '--identity', 'identity.key', '--name', 'Keyholder', '-o', 'card.bin']);

    const cert = new Uint8Array(readFileSync(join(server.dir, 'cert.bin')));
    const card = new Uint8Array(readFileSync(join(server.dir, 'card.bin')));

    // The client's own reading of what hlid wrote. If the CBOR or the
    // domain separator disagreed, this is where it would show.
    const decoded = decodeDeviceCert(cert);
    assert.equal(bytesToHex(decoded.device), bytesToHex(device.signPub));
    assert.equal(await fingerprintOf(decoded.identity), fingerprint);

    // Challenge, proof, token — the client half of §6.
    const doc = await fetchDiscovery(server.httpBase);
    const endpoint = (path) => new URL(path, server.httpBase).toString();
    const challenge = await fetchChallenge(endpoint(doc.identity.endpoints.challenge));
    const proof = await signLoginProof(device.key, {
      challenge: challenge.challenge,
      serverKey: challenge.serverKey,
      device: device.signPub,
      time: Math.floor(Date.now() / 1000),
    });
    const auth = await postAuth(endpoint(doc.identity.endpoints.auth), {
      card,
      deviceCert: cert,
      proof,
    });
    assert.equal(auth.fingerprint, fingerprint, 'the server and hlid spell it the same way');
    assert.equal(auth.outcome, 'unattested_guest');
    assert.ok(auth.token);

    // And now the token is the credential: no login, no password.
    const holder = await crew.connect({
      nick: 'Keyholder',
      identity: { getToken: async () => auth.token },
    });
    assert.equal(holder.conn.self.identity?.fingerprint, fingerprint);
    assert.ok(holder.conn.caps.includes('identity'));

    // What the roster is entitled to show, and no more — never `age`,
    // never `outcome`, never anything that authorizes.
    const onlooker = await crew.connect({ nick: 'Onlooker' });
    const seen = onlooker.conn.login.users.find((u) => u.uid === holder.conn.self.uid);
    assert.equal(seen.identity.fingerprint, fingerprint);
    assert.equal(seen.identity.age, undefined);
    assert.equal(seen.identity.outcome, undefined);
  });

  test('a proof signed by the wrong key is refused', async () => {
    // The certificate is real and the card is real; only the signature
    // is somebody else's. This is the whole security property, so it is
    // worth watching fail.
    const device = await newDevice();
    const impostor = await newDevice();

    hlid(server.dir, ['keygen', 'identity', 'identity2.key']);
    hlid(server.dir, [
      'cert',
      '--identity', 'identity2.key',
      '--device-pub', bytesToHex(device.signPub),
      '--device-enc-pub', bytesToHex(device.encPub),
      '-o', 'cert2.bin',
    ]);
    hlid(server.dir, ['card', '--identity', 'identity2.key', '--name', 'Genuine', '-o', 'card2.bin']);

    const doc = await fetchDiscovery(server.httpBase);
    const endpoint = (path) => new URL(path, server.httpBase).toString();
    const challenge = await fetchChallenge(endpoint(doc.identity.endpoints.challenge));
    const proof = await signLoginProof(impostor.key, {
      challenge: challenge.challenge,
      serverKey: challenge.serverKey,
      device: device.signPub,
      time: Math.floor(Date.now() / 1000),
    });

    await assert.rejects(
      () =>
        postAuth(endpoint(doc.identity.endpoints.auth), {
          card: new Uint8Array(readFileSync(join(server.dir, 'card2.bin'))),
          deviceCert: new Uint8Array(readFileSync(join(server.dir, 'cert2.bin'))),
          proof,
        }),
      (e) => e.name === 'AuthError',
    );
  });

  test('a challenge is good once', async () => {
    // Replay is the attack a challenge exists to stop, and "spent"
    // has to mean spent even when the proof is otherwise perfect.
    const device = await newDevice();
    hlid(server.dir, ['keygen', 'identity', 'identity3.key']);
    hlid(server.dir, [
      'cert',
      '--identity', 'identity3.key',
      '--device-pub', bytesToHex(device.signPub),
      '--device-enc-pub', bytesToHex(device.encPub),
      '-o', 'cert3.bin',
    ]);
    hlid(server.dir, ['card', '--identity', 'identity3.key', '--name', 'Once', '-o', 'card3.bin']);

    const doc = await fetchDiscovery(server.httpBase);
    const endpoint = (path) => new URL(path, server.httpBase).toString();
    const challenge = await fetchChallenge(endpoint(doc.identity.endpoints.challenge));
    const req = {
      card: new Uint8Array(readFileSync(join(server.dir, 'card3.bin'))),
      deviceCert: new Uint8Array(readFileSync(join(server.dir, 'cert3.bin'))),
      proof: await signLoginProof(device.key, {
        challenge: challenge.challenge,
        serverKey: challenge.serverKey,
        device: device.signPub,
        time: Math.floor(Date.now() / 1000),
      }),
    };

    const first = await postAuth(endpoint(doc.identity.endpoints.auth), req);
    assert.ok(first.token);
    await assert.rejects(
      () => postAuth(endpoint(doc.identity.endpoints.auth), req),
      (e) => e.name === 'AuthError',
      'the same proof a second time is not a second login',
    );
  });
});
