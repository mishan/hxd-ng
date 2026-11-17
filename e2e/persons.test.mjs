/**
 * Persons (docs/hotline-ng.md §7.6): one account's devices as one row,
 * driven by `@hotline-ng/client` declaring `persons`.
 *
 * Its own server with `[server] coalesce` on, whatever the suite's
 * `HXD_E2E_COALESCE` says, since every case here is about grouping, and
 * a second server with it off for what a server that does not group
 * answers. `pam` is a password account that is one person's by
 * `[extra] personal`; `pat` links an identity, proved by two devices of
 * it, and has a password too, so a password device sits beside them.
 * The last describe seals to a person (e2e-messages.md §4.14).
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import {
  CAP_PERSONS,
  MemorySealedReplay,
  base64urlToBytes,
  deviceCertBytes,
  fingerprintFromString,
  openSealed,
  sealBoxes,
  sealMsgRequest,
} from '@hotline-ng/client';

import { fleet, rawHandshake } from './harness/client.mjs';
import { enrolledDevice, signingIdentity } from './harness/device.mjs';
import { startServer } from './harness/server.mjs';

const account = (name, extra = '') => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
${extra}`;

const PERSONAL = '[extra]\npersonal = true\n';
const MOD = account('mod', 'disconnect_users = true\n');

const DEVICE_ID = (d) => Number.isSafeInteger(d) && d >= 1;

describe('persons', () => {
  let server;
  let plain;
  const crew = fleet(() => server);
  const elsewhere = fleet(() => plain);

  before(async () => {
    server = await startServer({
      config: (ports) => ({ server: { coalesce: true }, identity: signingIdentity(ports) }),
      accounts: { pam: account('pam', PERSONAL), bob: account('bob'), mod: MOD },
    });
    plain = await startServer({
      config: () => ({ server: { coalesce: false } }),
      accounts: { pam: account('pam', PERSONAL) },
    });
  });
  after(async () => {
    await crew.closeAll();
    await elsewhere.closeAll();
    await server?.stop();
    await plain?.stop();
  });

  const pam = (label, extra = {}) =>
    crew.connect({ login: 'pam', password: 'pw-pam', nick: 'Pam', persons: true, ...(label ? { deviceLabel: label } : {}), ...extra });

  /** The row the client was last sent for `uid`, from its log. */
  const rowOf = (client, uid) => {
    const changes = client.seen('ev', 'user_changed', { 'user.uid': uid }).concat(client.seen('ev', 'user_joined', { 'user.uid': uid }));
    const last = changes.sort((a, b) => a.n - b.n).at(-1);
    return last?.data.user ?? client.conn.login.users.find((u) => u.uid === uid);
  };

  test('persons is granted only when asked, and only where the server groups persons', async () => {
    const asked = await pam('Laptop');
    assert.ok(asked.conn.hasCap(CAP_PERSONS));
    assert.ok(DEVICE_ID(asked.conn.device), `device id ${asked.conn.device}`);
    assert.equal(asked.conn.self.device, asked.conn.device);
    assert.deepEqual(asked.conn.self.devices.map((d) => d.device), [asked.conn.device]);

    const unasked = await crew.connect({ login: 'pam', password: 'pw-pam', nick: 'Pam' });
    assert.ok(!unasked.conn.hasCap(CAP_PERSONS));
    assert.equal(unasked.conn.device, null);
    assert.equal(unasked.conn.self.devices, undefined);

    const off = await elsewhere.connect({ login: 'pam', password: 'pw-pam', nick: 'Pam', persons: true });
    assert.ok(!off.conn.hasCap(CAP_PERSONS));
    const refused = await off.conn.request('device_end', { device: 1 }).catch((e) => e.wire);
    assert.equal(refused.code, 'unknown_method');

    await Promise.all([asked.close(), unasked.close(), off.close()]);
  });

  test('a second device is one row, its devices told to the first device and to nobody else', async () => {
    const first = await pam('Laptop');
    const bob = await crew.connect({ login: 'bob', password: 'pw-bob', nick: 'Bob', persons: true });
    const uid = first.conn.self.uid;
    const since = bob.mark();
    const second = await pam('Phone');

    assert.equal(second.conn.self.uid, uid, 'the row is the first device');
    const told = await first.waitFor('user_changed', (d) => d.user.uid === uid && d.user.devices?.length === 2);
    assert.deepEqual(
      told.data.user.devices.map((d) => [d.device, d.label, d.wire, d.proved]),
      [
        [first.conn.device, 'Laptop', 'ng', false],
        [second.conn.device, 'Phone', 'ng', false],
      ],
    );
    for (const d of told.data.user.devices) {
      assert.ok(DEVICE_ID(d.device) && Number.isInteger(d.since) && d.status && d.transport);
      assert.equal(d.login, undefined, 'login and addr are a kick-bit viewer\'s alone');
      assert.equal(d.addr, undefined);
    }
    await bob.expectNo('user_joined', { 'user.uid': uid }, { since });
    await bob.expectNo('user_changed', (d) => d.user.uid === uid && d.user.devices !== undefined, { since });
    assert.equal(rowOf(bob, uid).devices, undefined);

    await Promise.all([first.close(), second.close(), bob.close()]);
  });

  test('a label that fails the rules is dropped, not refused', async () => {
    for (const label of ['\u202Eevil', ' padded ', 'x'.repeat(33)]) {
      const c = await pam(label);
      assert.equal(c.conn.self.devices.find((d) => d.device === c.conn.device).label, undefined, JSON.stringify(label));
      await c.close();
    }
  });

  test('device_end ends another device, which is told ended and comes back neither by resume nor login', async () => {
    const keeper = await pam('Laptop');
    const stale = await pam('Old phone');
    const { session, token } = stale.conn;

    await keeper.conn.deviceEnd(stale.conn.device);
    await stale.waitFor('ended', () => true);
    await stale.waitForHook('onEnded', { reason: 'This session was ended from one of your devices.' });
    const since = keeper.mark();
    await keeper.waitFor('user_changed', (d) => d.user.devices?.length === 1);
    await keeper.expectNo('user_changed', (d) => d.user.devices?.length === 2, { since, timeout: 1500 });
    assert.equal(stale.conn.state, 'offline');
    assert.equal(stale.seen('req', 'login').length, 1, 'no fresh login after ended');

    // A client that lost its socket before it read `ended` is told again.
    const again = await rawHandshake(server, 'resume', { session, token, last_seq: 0 });
    assert.equal(again.error.code, 'ended');

    await keeper.close();
  });

  test('device_end of this device is a logout of it, and the person stays', async () => {
    const keeper = await pam('Laptop');
    const leaving = await pam('Tablet');
    await leaving.conn.deviceEnd(leaving.conn.device);
    assert.equal(leaving.conn.state, 'offline');
    await keeper.waitFor('user_changed', (d) => d.user.devices?.length === 1);
    await keeper.expectNo('user_parted', { uid: keeper.conn.self.uid });
    await keeper.close();
  });

  test('a device ended while away is told so by its resume, and its client does not log in again', async () => {
    const keeper = await pam('Laptop');
    // The server's answer, on a session no client will resume: logged in
    // on a socket that then closes.
    const raw = await rawHandshake(server, 'login', { login: 'pam', password: 'pw-pam', nick: 'Pam', persons: true });
    await keeper.conn.deviceEnd(raw.ok.self.device);
    const told = await rawHandshake(server, 'resume', { session: raw.ok.session, token: raw.ok.token, last_seq: 0 });
    assert.equal(told.error.code, 'ended');

    // A client ended around a drop of its own, by the event or by its
    // resume, whichever it meets: either way it stops.
    const away = await pam('Phone in a pocket');
    away.conn.drop();
    await keeper.conn.deviceEnd(away.conn.device);
    await away.waitForHook('onEnded', { reason: 'This session was ended from one of your devices.' }, { timeout: 20_000 });
    assert.equal(away.seen('req', 'login').length, 1, 'no fresh login after ended');
    await keeper.close();
  });

  test('device_end refuses a device that is not this person\'s, and is not offered without persons', async () => {
    const mine = await pam('Laptop');
    const bob = await crew.connect({ login: 'bob', password: 'pw-bob', nick: 'Bob', persons: true });
    const refused = await mine.conn.request('device_end', { device: bob.conn.device }).catch((e) => e.wire);
    assert.equal(refused.code, 'no_such_device');
    const unasked = await crew.connect({ login: 'pam', password: 'pw-pam', nick: 'Pam' });
    const unknown = await unasked.conn.request('device_end', { device: mine.conn.device }).catch((e) => e.wire);
    assert.equal(unknown.code, 'unknown_method');
    await Promise.all([mine.close(), bob.close(), unasked.close()]);
  });

  test('a password device sees and ends only password devices; a proved one sees them all', async () => {
    const key = await enrolledDevice(server, 'pat-laptop');
    const other = await enrolledDevice(server, 'pat-phone', { identity: key.identityFile });
    server.account('pat', `${account('pat')}[identity]\nfingerprint = "${key.fingerprint}"\n`);
    const proved = (device, label) => crew.connect({ nick: 'Pat', persons: true, deviceLabel: label, identity: { getToken: device.getToken } });

    const laptop = await proved(key, 'Laptop');
    const phone = await proved(other, 'Phone');
    const password = await crew.connect({ login: 'pat', password: 'pw-pat', nick: 'Pat', persons: true, deviceLabel: 'Shared PC' });
    assert.equal(password.conn.self.uid, laptop.conn.self.uid);

    await laptop.waitFor('user_changed', (d) => d.user.devices?.length === 3);
    assert.deepEqual(
      password.conn.self.devices.map((d) => [d.label, d.proved]),
      [['Shared PC', false]],
      'a password device is shown password devices alone',
    );
    const refused = await password.conn.request('device_end', { device: phone.conn.device }).catch((e) => e.wire);
    assert.equal(refused.code, 'no_such_device');

    await laptop.conn.deviceEnd(password.conn.device);
    await password.waitFor('ended', () => true);
    await Promise.all([laptop.close(), phone.close()]);
  });

  test('a kick-bit viewer sees every device with login and addr, and kicks one, then the last as the person', async () => {
    const first = await pam('Laptop');
    const second = await pam('Phone');
    const mod = await crew.connect({ login: 'mod', password: 'pw-mod', nick: 'Mod', persons: true });
    const uid = first.conn.self.uid;
    const row = mod.conn.login.users.find((u) => u.uid === uid);
    assert.equal(row.devices.length, 2);
    for (const d of row.devices) {
      assert.equal(d.login, 'pam');
      assert.match(d.addr, /127\.0\.0\.1/);
    }

    const since = mod.mark();
    await mod.conn.kick({ uid, device: second.conn.device });
    await second.waitFor('kicked', () => true);
    await second.waitForHook('onEnded', { reason: 'You were disconnected by an administrator.' });
    await mod.waitFor('user_changed', (d) => d.user.uid === uid && d.user.devices?.length === 1, { since });
    await mod.expectNo('notice', () => true, { since });
    await mod.expectNo('user_parted', { uid }, { since });

    await mod.conn.kick({ uid, device: first.conn.device });
    await first.waitFor('kicked', () => true);
    await mod.waitFor('user_parted', { uid }, { since });
    await mod.close();
  });

  test('kick by device is refused for one\'s own person, and with ban or purge beside it', async () => {
    const first = await pam('Laptop');
    const mod = await crew.connect({ login: 'mod', password: 'pw-mod', nick: 'Mod', persons: true });
    const uid = first.conn.self.uid;
    const ban = await mod.conn.request('kick', { uid, device: first.conn.device, ban: 60 }).catch((e) => e.wire);
    assert.equal(ban.code, 'bad_request');
    const own = await mod.conn.request('kick', { uid: mod.conn.self.uid, device: mod.conn.device }).catch((e) => e.wire);
    assert.equal(own.code, 'bad_request');
    const wrong = await mod.conn.request('kick', { uid, device: mod.conn.device }).catch((e) => e.wire);
    assert.equal(wrong.code, 'no_such_device');
    await Promise.all([first.close(), mod.close()]);
  });

  test('a resume keeps the device id and label, and its self carries the devices', async () => {
    const first = await pam('Laptop');
    const second = await pam('Phone');
    const { device } = second.conn;
    const mark = second.mark();
    second.conn.drop();
    // Replayed, or synced when the replay cannot be had: either way the
    // same session.
    await Promise.any([
      second.waitForHook('onResumed', () => true, { since: mark, timeout: 10_000 }),
      second.waitForHook('onSnapshot', () => true, { since: mark, timeout: 10_000 }),
    ]);
    assert.equal(second.seen('req', 'login').length, 1, 'no fresh login');
    assert.equal(second.conn.device, device);
    assert.equal(second.conn.self.device, device);
    assert.deepEqual(
      second.conn.self.devices.map((d) => d.label),
      ['Laptop', 'Phone'],
    );
    await Promise.all([first.close(), second.close()]);
  });

  test('a session kicked is refused kicked by its resume, and its client does not log in again', async () => {
    const mod = await crew.connect({ login: 'mod', password: 'pw-mod', nick: 'Mod', persons: true });
    const raw = await rawHandshake(server, 'login', { login: 'bob', password: 'pw-bob', nick: 'Bob' });
    await mod.conn.kick({ uid: raw.ok.self.uid });
    const told = await rawHandshake(server, 'resume', { session: raw.ok.session, token: raw.ok.token, last_seq: 0 });
    assert.equal(told.error.code, 'kicked');

    const victim = await crew.connect({ login: 'bob', password: 'pw-bob', nick: 'Bob', persons: true });
    victim.conn.drop();
    await mod.conn.kick({ uid: victim.conn.self.uid });
    await victim.waitForHook('onEnded', { reason: 'You were disconnected by an administrator.' }, { timeout: 20_000 });
    assert.equal(victim.seen('req', 'login').length, 1, 'no fresh login after kicked');
    await mod.close();
  });
});

describe('sealing to a person', () => {
  let server;
  const crew = fleet(() => server);
  let pat;
  let sven;

  before(async () => {
    server = await startServer({
      config: (ports) => ({ server: { coalesce: true }, identity: signingIdentity(ports) }),
    });
    const laptop = await enrolledDevice(server, 'pat-laptop');
    const phone = await enrolledDevice(server, 'pat-phone', { identity: laptop.identityFile });
    const writer = await enrolledDevice(server, 'sven');
    const linked = (who, device) => server.account(who, `${account(who)}[identity]\nfingerprint = "${device.fingerprint}"\n`);
    linked('pat', laptop);
    linked('sven', writer);
    pat = { laptop, phone };
    sven = writer;
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const sealing = (device, persons = true) =>
    crew.connect({ nick: 'x', persons, identity: { getToken: device.getToken, signs: () => 'able', sealed: () => true } });
  const keysOf = (device) => ({ sign: device.key, enc: device.enc });
  const opens = async (reader, device, d, sender) => {
    const opened = await openSealed(
      base64urlToBytes(d.sealed),
      device.enc,
      { now: Math.floor(Date.now() / 1000), at: d.at, reader: device.fingerprint, sender: { named: sender } },
      new MemorySealedReplay(),
    );
    return opened.state === 'verified' ? opened.message.message.text : opened.state;
  };

  test('a person is listed by device, each box opens on its own device, and a box short is refused devices_changed', async () => {
    const laptop = await sealing(pat.laptop);
    const phone = await sealing(pat.phone);
    const writer = await sealing(sven);
    const uid = laptop.conn.self.uid;

    const listed = await writer.conn.deviceCert(uid);
    assert.deepEqual(listed.devices.map((d) => d.device).sort(), [laptop.conn.device, phone.conn.device].sort());
    const one = await writer.conn.deviceCert(uid, phone.conn.device);
    assert.deepEqual(base64urlToBytes(one.cert), pat.phone.cert);
    const stranger = await writer.conn.deviceCert(uid, writer.conn.device).catch((e) => e.wire);
    assert.equal(stranger.code, 'no_such_device');

    const to = fingerprintFromString(pat.laptop.fingerprint);
    const message = { cert: sven.cert, to, text: 'to both of you' };
    const short = await sealBoxes(keysOf(sven), message, deviceCertBytes(listed.devices).slice(0, 1));
    const refused = await writer.conn.msg({ to: uid, boxes: short }).catch((e) => e.wire);
    assert.equal(refused.code, 'devices_changed');
    assert.equal(refused.devices.length, 2);

    const boxes = await sealBoxes(keysOf(sven), message, deviceCertBytes(refused.devices));
    const ok = await writer.conn.msg({ to: uid, boxes });
    assert.equal(ok.held_full, undefined);
    for (const [client, device] of [
      [laptop, pat.laptop],
      [phone, pat.phone],
    ]) {
      const got = await client.waitFor('msg', (d) => d.sealed !== undefined && boxes.some((b) => b.sealed === d.sealed));
      assert.equal(got.data.sealed, boxes.find((b) => b.device === client.conn.device).sealed, 'each device is sent its own box alone');
      assert.equal(got.data.from.device, writer.conn.device, 'a sealer that is a person names its device');
      assert.equal(await opens(client, device, got.data, sven.fingerprint), 'to both of you');
    }
    await Promise.all([laptop.close(), phone.close(), writer.close()]);
  });

  test('a box sealed to another key is cert_changed, naming its device, and nothing is delivered', async () => {
    const laptop = await sealing(pat.laptop);
    const phone = await sealing(pat.phone);
    const writer = await sealing(sven);
    const uid = laptop.conn.self.uid;
    const listed = await writer.conn.deviceCert(uid);
    const to = fingerprintFromString(pat.laptop.fingerprint);
    const boxes = await sealBoxes(keysOf(sven), { cert: sven.cert, to, text: 'wrong key' }, deviceCertBytes(listed.devices));
    const [a, b] = boxes;
    const since = phone.mark();
    const refused = await writer.conn.msg({ to: uid, boxes: [a, { ...b, cert: a.cert }] }).catch((e) => e.wire);
    assert.equal(refused.code, 'cert_changed');
    assert.equal(refused.device, b.device);
    await phone.expectNo('msg', (d) => d.sealed !== undefined, { since });
    await Promise.all([laptop.close(), phone.close(), writer.close()]);
  });

  test('sealing to your own person reaches your other device from the row, naming the device that sealed it', async () => {
    const laptop = await sealing(pat.laptop);
    const phone = await sealing(pat.phone);
    const uid = laptop.conn.self.uid;
    const listed = await laptop.conn.deviceCert(uid);
    assert.deepEqual(listed.devices.map((d) => d.device), [phone.conn.device], 'the sender leaves itself out');
    const to = fingerprintFromString(pat.laptop.fingerprint);
    const boxes = await sealBoxes(keysOf(pat.laptop), { cert: pat.laptop.cert, to, text: 'a note to myself' }, deviceCertBytes(listed.devices));
    await laptop.conn.msg({ to: uid, boxes });
    const got = await phone.waitFor('msg', (d) => d.sealed === boxes[0].sealed);
    assert.equal(got.data.from.uid, uid);
    assert.equal(got.data.from.device, laptop.conn.device);
    assert.equal(await opens(phone, pat.phone, got.data, pat.laptop.fingerprint), 'a note to myself');
    await Promise.all([laptop.close(), phone.close()]);
  });

  test('a client without persons seals to a person of one device alone, and sends no boxes', async () => {
    const laptop = await sealing(pat.laptop);
    const writer = await sealing(sven, false);
    const uid = laptop.conn.self.uid;
    const single = await writer.conn.deviceCert(uid);
    assert.deepEqual(base64urlToBytes(single.cert), pat.laptop.cert);
    const to = fingerprintFromString(pat.laptop.fingerprint);
    const req = await sealMsgRequest(keysOf(sven), { cert: sven.cert, to, text: 'one device' }, base64urlToBytes(single.cert));
    assert.deepEqual(await writer.conn.msg({ to: uid, ...req }), { queued: false });

    const boxes = await writer.conn.request('msg', { to: uid, boxes: [{ device: laptop.conn.device, ...req }] }).catch((e) => e.wire);
    assert.equal(boxes.code, 'bad_request');

    const phone = await sealing(pat.phone);
    const two = await writer.conn.deviceCert(uid).catch((e) => e.wire);
    assert.equal(two.code, 'not_sealed', 'two devices, and a client that cannot name either');
    await Promise.all([laptop.close(), phone.close(), writer.close()]);
  });
});
