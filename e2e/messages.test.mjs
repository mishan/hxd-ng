/**
 * Private messages between sessions that are both here.
 *
 * The durable side — mail that waits for someone — is `inbox.test.mjs`.
 * This file is about the live path and the rules around addressing it,
 * which are mostly rules about what the server declines to tell you, and
 * about a signed message, live and waiting, checked by its recipient.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { BAD_SIGNATURE, bytesToHex, fingerprintFromString, hexToBytes, readSignedMessage, signMsgRequest } from '@hotline-ng/client';

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
});
