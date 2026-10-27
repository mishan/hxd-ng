/**
 * Private messages between sessions that are both here.
 *
 * The durable side — mail that waits for someone — is `inbox.test.mjs`.
 * This file is about the live path and the rules around addressing it,
 * which are mostly rules about what the server declines to tell you, and
 * about a signed message, live and waiting, checked by its recipient,
 * and a sealed one, live and held, opened by the device it was sealed to.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import {
  BAD_SIGNATURE,
  CERT_CHANGED,
  MemorySealedReplay,
  base64urlToBytes,
  bytesToBase64url,
  bytesToHex,
  decodeDeviceCert,
  fingerprintFromString,
  hexToBytes,
  openSealed,
  readSignedMessage,
  sealMsgRequest,
  signMsgRequest,
} from '@hotline-ng/client';

import { fleet } from './harness/client.mjs';
import { enrolledDevice, signingIdentity } from './harness/device.mjs';
import { startServer } from './harness/server.mjs';

const account = (name) => `name = "${name}"
password = "pw-${name}"
[access]
read_chat = true
send_chat = true
send_msgs = true
use_any_name = true
`;

describe('private messages', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      config: (ports) => ({ inbox: { db: 'messages.db' }, identity: signingIdentity(ports) }),
      accounts: { alice: account('alice'), bob: account('bob'), carol: account('carol') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  const login = (who, nick) => crew.connect({ login: who, password: `pw-${who}`, nick: nick ?? who });

  test('a message to a uid on the roster is delivered, not queued', async () => {
    const alice = await login('alice');
    const bob = await login('bob');

    const ok = await alice.conn.msg({ to: bob.conn.self.uid, text: 'just between us' });
    assert.equal(ok.queued, false, 'the recipient is right here');

    const got = await bob.waitFor('msg', { text: 'just between us' });
    assert.equal(got.data.from.uid, alice.conn.self.uid);
    assert.equal(got.data.from.login, 'alice', 'there is somebody to reply to');
    assert.equal(got.data.queued, false);
  });

  test('the same guid twice is one message, so a retry after a dead socket is safe', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-guid');
    const guid = '6f9619ff-8b86-d011-b42d-00c04fc964ff';

    await alice.conn.msg({ to: bob.conn.self.uid, text: 'sent once', guid });
    const first = await bob.waitFor('msg', { text: 'sent once' });

    const mark = bob.mark();
    const retry = await alice.conn.msg({ to: bob.conn.self.uid, text: 'sent once', guid });
    assert.equal(retry.queued, false, 'a retry is answered, never refused');
    await bob.expectNo('msg', { text: 'sent once' }, { since: mark });
    assert.equal(bob.seen('ev', 'msg', { text: 'sent once' }).length, 1);
    assert.ok(first.data.id === undefined || typeof first.data.id === 'number');
  });

  test('a blocked sender is told the same thing whatever the truth is', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-block');

    await bob.conn.block({ login: 'alice' });
    const blocks = await bob.conn.blocks();
    assert.ok(blocks.blocked.some((b) => b.login === 'alice'));

    const refused = await alice.conn
      .msg({ to: bob.conn.self.uid, text: 'let me in' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(refused, 'blocked');

    await bob.conn.unblock({ login: 'alice' });
    const ok = await alice.conn.msg({ to: bob.conn.self.uid, text: 'thanks' });
    assert.equal(ok.queued, false);
    await bob.waitFor('msg', { text: 'thanks' });
  });

  test('addressing failures leak nothing about who exists', async () => {
    // One code covers "no such account", "no such uid", and "that
    // account takes no offline messages", precisely so none of them can
    // be told apart by asking.
    const alice = await login('alice');

    const noUid = await alice.conn
      .msg({ to: 60000, text: 'anyone?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(noUid, 'no_such_user');

    const noLogin = await alice.conn
      .msg({ to_login: 'nobody-by-that-name', text: 'anyone?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(noLogin, 'no_such_user');
  });

  test('naming both a uid and a login is refused rather than guessed at', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-both');
    const code = await alice.conn
      .request('msg', { to: bob.conn.self.uid, to_login: 'carol', text: 'which of you?' })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(code, 'bad_request', 'guessing is how a message reaches the wrong person');
  });

  test('an over-long message is truncated, not refused', async () => {
    const alice = await login('alice');
    const bob = await login('bob', 'bob-long');
    const huge = 'x'.repeat(9000);

    await alice.conn.msg({ to: bob.conn.self.uid, text: huge });
    const got = await bob.waitFor('msg', (d) => d.text.startsWith('xxxx'));
    assert.ok(got.data.text.length < huge.length, 'the wire caps it');
    assert.ok(got.data.text.length >= 4000, `expected roughly the 4096-byte cap, got ${got.data.text.length}`);
  });

  test('a signed message reaches its recipient live and waiting, and the recipient verifies it', async () => {
    const sender = await enrolledDevice(server, 'pm-sender');
    const recipient = await enrolledDevice(server, 'pm-recipient');
    // Both accounts, so the message is stored and a retry under its guid
    // is the same one (hotline-ng.md §7.1).
    const linked = (who, device) => server.account(who, `${account(who)}[identity]\nfingerprint = "${device.fingerprint}"\n`);
    linked('dora', recipient);
    linked('sigrid', sender);
    const dora = await crew.connect({ nick: 'Dora', identity: { getToken: recipient.getToken, signs: () => 'able' } });
    const signer = await crew.connect({ nick: 'Signer', identity: { getToken: sender.getToken, signs: () => 'able' } });
    assert.equal(signer.conn.signing, 'able', 'signs is echoed for a device whose certificate allows messages');

    // Signed to the identity the sender's roster shows for her, and read
    // against the one her own session proved.
    const row = signer.conn.login.users.find((u) => u.uid === dora.conn.self.uid);
    assert.equal(row.identity.fingerprint, recipient.fingerprint);
    const to = fingerprintFromString(row.identity.fingerprint);
    const read = (d, sender) =>
      readSignedMessage(d.signed, d.text, { at: d.at, sender, scope: recipient.fingerprint });
    const verified = { state: 'verified', signer: sender.fingerprint, sentApart: false };

    const live = await signMsgRequest(sender.key, { cert: sender.cert, to, text: 'signed, not sealed' });
    assert.equal((await signer.conn.msg({ to: dora.conn.self.uid, ...live })).queued, false);
    const heard = await dora.waitFor('msg', (d) => d.signed === live.signed);
    assert.equal(heard.data.text, live.text);
    const joined = await dora.waitFor('user_joined', (d) => d.user.uid === signer.conn.self.uid);
    const named = { named: joined.data.user.identity.fingerprint };
    const got = await read(heard.data, named);
    assert.deepEqual(got.outcome, verified);
    assert.equal(bytesToHex(got.message.id), live.guid.replaceAll('-', ''), 'its id is its guid');

    // Away, it waits with its signature, and a retry signed again under
    // its id is the same message, while other words under it are not.
    await dora.close();
    const later = await signMsgRequest(sender.key, { cert: sender.cert, to, text: 'for later' });
    assert.equal((await signer.conn.msg({ to_login: 'dora', ...later })).queued, true);
    const id = hexToBytes(later.guid.replaceAll('-', ''));
    const sent = Math.floor(Date.now() / 1000) - 5;
    const again = await signMsgRequest(sender.key, { id, cert: sender.cert, to, text: 'for later' }, sent);
    assert.notEqual(again.signed, later.signed);
    assert.equal((await signer.conn.msg({ to_login: 'dora', ...again })).queued, true);
    const other = await signMsgRequest(sender.key, { id, cert: sender.cert, to, text: 'for sooner' }, sent);
    const refused = await signer.conn
      .msg({ to_login: 'dora', ...other })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(refused, BAD_SIGNATURE);

    const back = await crew.connect({ nick: 'Dora', identity: { getToken: recipient.getToken, signs: () => 'able' } });
    const flushed = await back.waitFor('msg', (d) => d.text === 'for later');
    assert.equal(flushed.data.queued, true);
    assert.equal(flushed.data.signed, later.signed);
    assert.ok(flushed.data.from.uid > 0, 'the sender is still here, so the flush names their uid');
    const senderRow = back.conn.login.users.find((u) => u.uid === flushed.data.from.uid);
    assert.ok(senderRow?.identity, `no roster row with an identity for uid ${flushed.data.from.uid}`);
    assert.deepEqual((await read(flushed.data, { named: senderRow.identity.fingerprint })).outcome, verified);
    await back.expectNo('msg', (d) => d.text === 'for later', { since: flushed.n + 1 });

    // And listed, named by its certificate, as an inbox row is.
    const page = await back.conn.inbox();
    const rows = page.messages.filter((m) => m.text === 'for later');
    assert.equal(rows.length, 1, 'stored once');
    assert.equal(rows[0].signed, later.signed);
    assert.deepEqual((await read(rows[0], 'certificate')).outcome, verified);
  });

  test('a sealed message reaches the device it was sealed to, signed or deniably, live and held, and opens once', async () => {
    const sender = await enrolledDevice(server, 'seal-sender');
    const recipient = await enrolledDevice(server, 'seal-recipient');
    // Accounts with passwords, so the recipient may detach and be held for.
    const linked = (who, device) => server.account(who, `${account(who)}[identity]\nfingerprint = "${device.fingerprint}"\n`);
    linked('selma', recipient);
    linked('sven', sender);
    const sealing = (device) => ({ getToken: device.getToken, signs: () => 'able', sealed: () => true });
    const reader = await crew.connect({ nick: 'Selma', identity: sealing(recipient) });
    const writer = await crew.connect({ nick: 'Sven', identity: sealing(sender) });
    const uid = reader.conn.self.uid;
    assert.equal(reader.conn.sealing, true, 'sealed is echoed for a device whose certificate allows messages');
    assert.equal(writer.conn.sealing, true);
    assert.equal(reader.conn.self.identity.sealed, true);

    // Sealed to the identity the writer's roster shows, and to the
    // certificate device_cert answers, which is the reader's own.
    const row = writer.conn.login.users.find((u) => u.uid === uid);
    assert.equal(row.identity.sealed, true);
    assert.equal(row.identity.fingerprint, recipient.fingerprint);
    const cert = base64urlToBytes((await writer.conn.deviceCert(uid)).cert);
    assert.deepEqual(cert, recipient.cert);
    const keys = { sign: sender.key, enc: sender.enc };
    const to = fingerprintFromString(row.identity.fingerprint);
    const seal = (text, deniable = false) => sealMsgRequest(keys, { cert: sender.cert, to, text }, cert, deniable);

    // Opened as the reader's client opens one: by its own device key, as
    // from the fingerprint its roster shows for the sender's uid, with
    // one memory of what it accepted.
    const joined = await reader.waitFor('user_joined', (d) => d.user.uid === writer.conn.self.uid);
    const named = { named: joined.data.user.identity.fingerprint };
    const replay = new MemorySealedReplay();
    const open = (d) =>
      openSealed(base64urlToBytes(d.sealed), recipient.enc, { now: Math.floor(Date.now() / 1000), at: d.at, reader: recipient.fingerprint, sender: named }, replay);
    const delivered = async (req, since = 0) => {
      const got = await reader.waitFor('msg', (d) => d.sealed === req.sealed, { since });
      assert.equal(got.data.text, '[Encrypted message]');
      assert.equal(got.data.queued, false);
      assert.equal(got.data.id, undefined, 'never stored');
      assert.equal(got.data.from.fingerprint, sender.fingerprint);
      return got.data;
    };

    const signed = await seal('sealed and signed');
    assert.deepEqual(await writer.conn.msg({ to: uid, ...signed }), { queued: false });
    const opened = await open(await delivered(signed));
    assert.equal(opened.state, 'verified');
    assert.equal(opened.signer, sender.fingerprint);
    assert.equal(opened.message.message.text, 'sealed and signed');

    const deniable = await seal('sealed deniably', true);
    assert.deepEqual(await writer.conn.msg({ to: uid, ...deniable }), { queued: false });
    const denied = await open(await delivered(deniable));
    assert.equal(denied.state, 'deniable');
    assert.equal(denied.signer, sender.fingerprint);
    assert.deepEqual(denied.senderEnc, decodeDeviceCert(sender.cert).deviceEnc, 'opened under the key its certificate names');
    assert.equal(denied.message.text, 'sealed deniably');

    // The same box again is carried again, and opened by nobody twice.
    const again = reader.mark();
    await writer.conn.msg({ to: uid, ...signed });
    assert.equal((await open(await delivered(signed, again))).state, 'dropped');

    // A key the target does not hold is the sender's to fetch again.
    const otherKey = bytesToBase64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(32))));
    const refused = await writer.conn
      .msg({ to: uid, sealed: signed.sealed, cert: otherKey })
      .then(() => null)
      .catch((e) => e.wire.code);
    assert.equal(refused, CERT_CHANGED);

    // Away, a box is held for the session and handed over at its resume,
    // which says sealed again.
    const held = await seal('while you were away');
    const [mark, watching] = [reader.mark(), writer.mark()];
    // The reader stays away until the box is sent, however slow the
    // sending, so the box can only have been held.
    let release;
    const away = new Promise((resolve) => (release = resolve));
    const attach = reader.conn.attach;
    reader.conn.attach = async function () {
      await away;
      return attach.call(this);
    };
    reader.conn.drop();
    await writer.waitFor('user_changed', (d) => d.user.uid === uid && d.user.status === 'detached', { since: watching });
    assert.deepEqual(await writer.conn.msg({ to: uid, ...held }), { queued: false });
    release();
    const resumed = await reader.waitForHook('onResumed', () => true, { since: mark, timeout: 20_000 });
    const asked = reader.seen('req', 'resume').at(-1);
    assert.equal(asked.data.sealed, true);
    assert.equal(reader.conn.sealing, true);
    const back = await open(await delivered(held, mark));
    assert.equal(back.state, 'verified');
    assert.equal(back.message.message.text, 'while you were away');
    // Handed over in the resume: one of the events it replayed, which
    // follow its reply.
    const answered = reader.log.find((r) => r.kind === 'reply' && r.id === asked.id);
    const replayed = reader.log.filter((r) => r.kind === 'ev' && r.n > answered.n).slice(0, resumed.data.replay);
    assert.ok(
      replayed.some((r) => r.name === 'msg' && r.data.sealed === held.sealed),
      `expected the box among the ${resumed.data.replay} events the resume replayed`,
    );
  });
});
