/**
 * Server-local revocation (`docs/identity-registrar.md`), from the
 * real binary: the lists in its own config file, and SIGHUP to re-read
 * them.
 *
 * `crates/hxd/tests/identity.rs` covers what installing a list does. What
 * only the process can show is the operator's side of it: `hxd identity
 * revoke` editing the file the server reads, SIGHUP re-reading it rather
 * than killing the server, as it did before there was anything to
 * reload, and a file which no longer reads leaving the server running
 * with the lists it had.
 */

import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import {
  bytesToHex,
  fetchChallenge,
  fetchDiscovery,
  postAuth,
  signLoginProof,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { hlid, hxdCommand, startServer } from './harness/server.mjs';
import { toToml } from './harness/toml.mjs';

/** A device the way a browser holds one: the signing key cannot be
 *  exported, and `hlid` certifies only its public half. */
async function newDevice() {
  const sign = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const enc = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const signPub = new Uint8Array(await crypto.subtle.exportKey('raw', sign.publicKey));
  const encPub = new Uint8Array(await crypto.subtle.exportKey('raw', enc.publicKey));
  return { key: sign.privateKey, signPub, encPub };
}

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

describe('revocation by hand', () => {
  let server;
  const crew = fleet(() => server);
  let fingerprint;
  let device;

  /** One `/identity/auth` for the device, which rejects if refused. */
  async function authenticate() {
    const doc = await fetchDiscovery(server.httpBase);
    const endpoint = (path) => new URL(path, server.httpBase).toString();
    const challenge = await fetchChallenge(endpoint(doc.identity.endpoints.challenge));
    const proof = await signLoginProof(device.key, {
      challenge: challenge.challenge,
      serverKey: challenge.serverKey,
      device: device.signPub,
      time: Math.floor(Date.now() / 1000),
    });
    return postAuth(endpoint(doc.identity.endpoints.auth), {
      card: new Uint8Array(readFileSync(join(server.dir, 'card.bin'))),
      deviceCert: new Uint8Array(readFileSync(join(server.dir, 'cert.bin'))),
      proof,
    });
  }

  /** Run `hxd identity revoke` beside the server, as an operator would. */
  function revoke(...args) {
    const r = hxdCommand(server, ['identity', 'revoke', ...args]);
    assert.equal(r.status, 0, `hxd identity revoke ${args.join(' ')}:\n${r.stderr}`);
    return r.stdout;
  }

  /** Rewrite `[identity]` in the server's own config file by hand, and
   *  hang up. How to get a file the command would refuse to write. */
  function reload(identity) {
    const config = { ...server.config, identity: { ...server.config.identity, ...identity } };
    writeFileSync(join(server.dir, 'hxd-ng.toml'), toToml(config));
    server.proc.kill('SIGHUP');
  }

  before(async () => {
    server = await startServer({
      config: {
        identity: {
          key: 'identity-server.key',
          new_accounts: 'guest',
          unattested: 'guest',
        },
      },
    });
    device = await newDevice();
    const keygen = hlid(server.dir, ['keygen', 'identity', 'identity.key']);
    fingerprint = /fingerprint: (\S+)/.exec(keygen)?.[1];
    assert.ok(fingerprint, `no fingerprint in: ${keygen}`);
    hlid(server.dir, [
      'cert',
      '--identity', 'identity.key',
      '--device-pub', bytesToHex(device.signPub),
      '--device-enc-pub', bytesToHex(device.encPub),
      '-o', 'cert.bin',
    ]);
    hlid(server.dir, ['card', '--identity', 'identity.key', '--name', 'Stolen', '-o', 'card.bin']);
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('the command refuses what would revoke nothing', async () => {
    const r = hxdCommand(server, ['identity', 'revoke', 'not-a-fingerprint']);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not a fingerprint/);
  });

  test('a list that does not read leaves the server up and the key in', async () => {
    reload({ revoked_identities: ['not-a-fingerprint'] });
    await logged(server, /SIGHUP: .*not a fingerprint.*unchanged/);
    assert.equal(server.exitCode, null, 'SIGHUP no longer ends the server');
    assert.ok((await authenticate()).token, 'and the key still works');
  });

  test('SIGHUP revokes a key and ends the session it holds', async () => {
    const auth = await authenticate();
    const holder = await crew.connect({
      nick: 'Stolen',
      identity: { getToken: async () => auth.token },
    });
    const bystander = await crew.connect({ nick: 'Bystander' });

    // The file is rewritten while the server runs, and nothing happens
    // until it is told to look.
    writeFileSync(join(server.dir, 'hxd-ng.toml'), toToml(server.config));
    assert.match(revoke(fingerprint), /revoked identity/);
    assert.match(revoke(fingerprint), /already revoked/);
    assert.ok((await authenticate()).token, 'not applied before the reload');
    server.proc.kill('SIGHUP');
    await holder.waitFor('kicked', () => true);
    await logged(server, /SIGHUP: 1 revoked keys installed .*; 1 sessions ended/);

    await assert.rejects(
      () => authenticate(),
      (e) => e.name === 'AuthError' && e.code === 'revoked',
      'refused by name, so a client can say why',
    );
    // Nobody else was dropped to do it.
    assert.equal(server.exitCode, null);
    assert.ok(bystander.conn.self.uid);

    // Lifting it is the same command backwards.
    assert.match(revoke('--lift', fingerprint), /lifted/);
    server.proc.kill('SIGHUP');
    await logged(server, /SIGHUP: 0 revoked keys installed/);
    assert.ok((await authenticate()).token);
  });
});
