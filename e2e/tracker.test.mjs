/** Tracker registration from the real hxd process. */

import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import dgram from 'node:dgram';
import { test } from 'node:test';

import { startServer } from './harness/server.mjs';

const H3 = 0x4833;
const DEREGISTER = 0x0010;
const HMAC_SHA256 = 0x0801;
const NONCE = 0x0802;

function pascal(packet, at) {
  const length = packet[at];
  return { value: packet.subarray(at + 1, at + 1 + length), next: at + 1 + length };
}

function parseRegistration(packet) {
  assert.ok(packet.length >= 15, 'registration has its header and Pascal string lengths');
  let at = 12;
  const name = pascal(packet, at);
  const description = pascal(packet, name.next);
  const password = pascal(packet, description.next);
  at = password.next;

  const fields = new Map();
  if (packet.readUInt16BE(0) === 3) {
    assert.equal(packet.readUInt16BE(at), H3);
    const count = packet.readUInt16BE(at + 2);
    at += 4;
    for (let index = 0; index < count; index++) {
      const id = packet.readUInt16BE(at);
      const length = packet.readUInt16BE(at + 2);
      at += 4;
      fields.set(id, { value: packet.subarray(at, at + length), valueAt: at });
      at += length;
    }
  }
  assert.equal(at, packet.length, 'registration has no unparsed bytes');
  return {
    version: packet.readUInt16BE(0),
    port: packet.readUInt16BE(2),
    users: packet.readUInt16BE(4),
    reserved: packet.readUInt16BE(6),
    passId: packet.readUInt32BE(8),
    name: name.value.toString('utf8'),
    description: description.value.toString('utf8'),
    password: password.value,
    fields,
  };
}

function listen(socket) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', () => {
      socket.off('error', reject);
      resolve();
    });
  });
}

async function waitFor(packets, predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = packets.find(predicate);
    if (found) return found;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`tracker datagram did not arrive within ${timeoutMs}ms`);
}

test('the binary registers with v1 and v3 trackers and deregisters v3 on SIGTERM', async () => {
  const socket = dgram.createSocket('udp4');
  const packets = [];
  socket.on('message', (packet) => packets.push(Buffer.from(packet)));
  await listen(socket);
  const trackerPort = socket.address().port;
  const secret = 'e2e tracker secret';
  let server;

  try {
    server = await startServer({
      config: {
        tracker: {
          description: 'The real process',
          ack_timeout_ms: 100,
          targets: [
            { address: `127.0.0.1:${trackerPort}`, protocol: 'v1' },
            { address: `127.0.0.1:${trackerPort}`, protocol: 'v3', hmac_secret: secret },
          ],
        },
      },
    });

    const v1Packet = await waitFor(packets, (packet) => packet.readUInt16BE(0) === 1);
    const v3Packet = await waitFor(packets, (packet) => {
      if (packet.readUInt16BE(0) !== 3) return false;
      return !parseRegistration(packet).fields.has(DEREGISTER);
    });
    const v1 = parseRegistration(v1Packet);
    const v3 = parseRegistration(v3Packet);

    for (const registration of [v1, v3]) {
      assert.equal(registration.port, server.ports.legacy);
      assert.equal(registration.users, 0);
      assert.equal(registration.reserved, 0);
      assert.notEqual(registration.passId, 0);
      assert.equal(registration.name, server.name);
      assert.equal(registration.description, 'The real process');
      assert.equal(registration.password.length, 0);
    }
    assert.equal(v1.passId, v3.passId, 'PassID is stable for this server process');

    assert.equal(v3.fields.get(NONCE).value.length, 8);
    const hmac = v3.fields.get(HMAC_SHA256);
    assert.equal(hmac.value.length, 32);
    const unsigned = Buffer.from(v3Packet);
    unsigned.fill(0, hmac.valueAt, hmac.valueAt + hmac.value.length);
    assert.deepEqual(hmac.value, createHmac('sha256', secret).update(unsigned).digest());

    await server.stop();
    server = undefined;
    const deregistrationPacket = await waitFor(packets, (packet) => {
      if (packet.readUInt16BE(0) !== 3) return false;
      return parseRegistration(packet).fields.get(DEREGISTER)?.value.equals(Buffer.from([1]));
    });
    const deregistration = parseRegistration(deregistrationPacket);
    assert.equal(deregistration.port, v3.port);
    assert.equal(deregistration.passId, v3.passId);
  } finally {
    if (server) await server.stop();
    socket.close();
  }
});
