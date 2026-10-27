/**
 * A device as a browser holds one, for the suites that sign.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { bytesToHex, fetchChallenge, fetchDiscovery, postAuth, signLoginProof } from '@hotline-ng/client';

import { hlid } from './server.mjs';

/** A device certified by `hlid` for messages as well as login, under an
 *  identity of its own named `name` in `server`'s directory, and the
 *  token-minting an identity login runs. */
export async function enrolledDevice(server, name) {
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

/** The `[identity]` a file's server signs with: its hosts, which make it
 *  carry signed messages (e2e-messages.md §4.6), and no newcomer delay,
 *  so a key new here may send at once. */
export const signingIdentity = (ports) => ({
  key: 'identity-server.key',
  hosts: [`127.0.0.1:${ports.ng}`],
  new_accounts: 'guest',
  unattested: 'guest',
  newcomer_delay: 0,
});
