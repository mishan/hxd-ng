/**
 * Roles (docs/roles.md §7): made, given and changed through the client
 * library, against a server whose roles file it writes itself.
 *
 * What the Rust suites cannot say is that a client written from the spec
 * keeps the same picture the server does: the roles block it was handed
 * at login, kept current by `roles_changed`, the account object's own
 * keys, and a roster the server called stale fetched again whole. And
 * that the binary itself sends a `roles_changed` it held back.
 */

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startServer } from './harness/server.mjs';

const plain = (name) => `name = "${name}"
password = "pw"
[access]
read_chat = true
`;

const BOSS = `name = "Boss"
password = "pw"
[access]
read_chat = true
send_chat = true
read_users = true
modify_users = true
get_user_info = true
disconnect_users = true
[extra]
manage_roles = true
`;

describe('roles', () => {
  let server;
  const crew = fleet(() => server);

  before(async () => {
    server = await startServer({
      // So one edit changing two holders' rows is past it: the config
      // key as the binary reads it.
      config: { roles: { bulk_rows: 1 } },
      accounts: { boss: BOSS, ann: plain('Ann'), ben: plain('Ben'), carol: plain('Carol') },
    });
  });
  after(async () => {
    await crew.closeAll();
    await server?.stop();
  });

  test('a role made, given and widened reaches every client as the server has it', async () => {
    const boss = await crew.connect({ login: 'boss', password: 'pw', nick: 'Boss' });
    const carol = await crew.connect({ login: 'carol', password: 'pw', nick: 'Carol' });
    assert.ok(boss.conn.caps.includes('roles'));
    assert.equal(boss.conn.roles.manage_roles, true);
    assert.equal(carol.conn.roles.manage_roles, undefined);

    const { role } = await boss.conn.roleCreate({
      name: 'staff',
      title: 'Staff',
      color: 0x336699,
      access: ['get_user_info'],
    });
    assert.deepEqual(
      { name: role.name, title: role.title, color: role.color, access: role.access },
      { name: 'staff', title: 'Staff', color: 0x336699, access: ['get_user_info'] },
    );
    await carol.waitFor('roles_changed', (d) => d.list.some((r) => r.name === 'staff'));
    assert.equal(carol.conn.roles.list.find((r) => r.name === 'staff')?.color, 0x336699);

    const ann = await crew.connect({ login: 'ann', password: 'pw', nick: 'Ann' });
    const ben = await crew.connect({ login: 'ben', password: 'pw', nick: 'Ben' });
    assert.ok(ann.conn.roles.list.some((r) => r.name === 'staff'), 'in the login reply');
    const { account } = await boss.conn.accountUpdate({
      login: 'ann',
      roles: ['staff'],
      grant: ['read_chat', 'send_chat'],
      deny: [],
    });
    assert.deepEqual(
      { roles: account.roles, grant: account.grant, deny: account.deny },
      { roles: ['staff'], grant: ['read_chat', 'send_chat'], deny: [] },
    );
    assert.ok(account.access.includes('get_user_info'), JSON.stringify(account));
    const holds = (who) => (d) => d.user.uid === who.conn.self.uid && d.user.roles?.[0] === 'staff';
    await carol.waitFor('user_changed', holds(ann));
    await boss.conn.accountUpdate({ login: 'ben', roles: ['staff'] });
    await carol.waitFor('user_changed', holds(ben));

    // Two holders' rows change at once, past bulk_rows: told the roster
    // is stale, the client fetches it whole.
    const since = carol.mark();
    await boss.conn.roleUpdate({ name: 'staff', access: ['get_user_info', 'disconnect_users'] });
    await carol.waitFor('roster_stale', () => true, { since });
    const snap = await carol.waitForHook('onSnapshot', (ok) => ok.stale === true, { since });
    for (const who of [ann, ben]) {
      const row = snap.data.users.find((u) => u.uid === who.conn.self.uid);
      assert.equal(row?.admin, true, JSON.stringify(snap.data.users));
    }
    // A change to what the role grants reaches its holders, and is not
    // how roles look: nobody hears `roles_changed`, nor each row.
    await ann.waitFor('account_changed', (d) => d.access.includes('disconnect_users'), { since: 0 });
    const holders = new Set([ann.conn.self.uid, ben.conn.self.uid]);
    await Promise.all([
      carol.expectNo('user_changed', (d) => holders.has(d.user.uid), { since }),
      carol.expectNo('roles_changed', () => true, { since }),
    ]);

    const listed = await boss.conn.roleList();
    assert.equal(listed.roles.find((r) => r.name === 'staff')?.holder_count, 2);
  });

  test('a second change to how a role looks, held back, goes out on its own', async () => {
    const boss = await crew.connect({ login: 'boss', password: 'pw', nick: 'Boss' });
    const carol = await crew.connect({ login: 'carol', password: 'pw', nick: 'Carol' });
    await boss.conn.roleCreate({ name: 'aides', title: 'Aides' });
    // Within the server's few seconds of the first: held, then sent by
    // the binary's own timer with nobody asking.
    await boss.conn.roleUpdate({ name: 'aides', title: 'Helpers' });
    await carol.waitFor('roles_changed', (d) => d.list.some((r) => r.name === 'aides' && r.title === 'Helpers'), {
      timeout: 8000,
    });
    assert.equal(carol.conn.roles.list.find((r) => r.name === 'aides')?.title, 'Helpers');
  });
});
