/**
 * The identity registrar (`docs/identity-registrar.md`), from the real
 * binary.
 *
 * `crates/hxd/tests/registrar.rs` covers the registrar's rules through a
 * server it assembles in process. What only the process can show is the
 * operator's side: `[registrar]` read from a file `hxd` parses itself,
 * the key it writes on first start, `hxd registrar …` acting on the store
 * of the server running beside it, SIGHUP re-reading the names it
 * reserves, and a section the binary refuses to start with. `hlid` is
 * the client throughout — the registrar is not in `@hotline-ng/client`,
 * so nothing here moves the hx-ng pin.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { hlid, hxdCommand, startFailing, startServer } from './harness/server.mjs';

/** Wait for a line in the server's log. */
async function logged(server, pattern, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.lines.some((l) => pattern.test(l))) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`the server never logged ${pattern}\n${server.log()}`);
}

/** `hlid`, expected to fail: what it said about why. */
function hlidRefused(cwd, args) {
  const bin = join(import.meta.dirname, '..', 'target', 'release', 'hlid');
  const r = spawnSync(bin, args, { cwd, env: { ...process.env, HLID_HOME: cwd }, encoding: 'utf8' });
  assert.notEqual(r.status, 0, `hlid ${args.join(' ')} unexpectedly succeeded:\n${r.stdout}`);
  return r.stderr;
}

const INVITE = /^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/;

describe('the registrar', () => {
  let server;
  let invites = [];
  let fingerprint;

  function invite() {
    if (invites.length === 0) {
      const r = hxdCommand(server, ['registrar', 'invites', '--add', '3']);
      assert.equal(r.status, 0, `hxd registrar invites:\n${r.stderr}`);
      invites = r.stdout.trim().split('\n');
      assert.equal(invites.length, 3);
      for (const code of invites) assert.match(code, INVITE);
    }
    return invites.shift();
  }

  before(async () => {
    server = await startServer({
      config: {
        identity: { key: 'identity-server.key' },
        registrar: { host: '127.0.0.1' },
      },
    });
    const init = hlid(server.dir, ['init', '--name', 'Alice']);
    fingerprint = /fingerprint: (\S+)/.exec(init)?.[1];
    assert.ok(fingerprint, `no fingerprint in: ${init}`);
  });
  after(async () => {
    await server?.stop();
  });

  test('discovery carries the registrar block, with a key of its own', async () => {
    const doc = await server.discovery();
    const block = doc.registrar;
    assert.ok(block, `no registrar block:\n${JSON.stringify(doc)}`);
    assert.equal(block.host, '127.0.0.1');
    assert.equal(block.signup, 'proof');
    assert.equal(block.proof, 'invite');
    assert.equal(block.level, 2);
    assert.notEqual(block.key, doc.server_key);
    assert.ok(existsSync(join(server.dir, 'registrar.key')), 'the key is written on first start');
  });

  test('hlid registers with an invite from the command, and not without one', async () => {
    assert.match(
      hlidRefused(server.dir, ['register', '--registrar', server.httpBase, '--handle', 'alice']),
      /proof_required/,
    );
    const out = hlid(server.dir, [
      'register',
      '--registrar', server.httpBase,
      '--handle', 'alice',
      '--proof', invite(),
      '--successor-commit',
    ]);
    assert.match(out, /registered alice@127\.0\.0\.1/);
    assert.match(out, /card published/);

    const found = await fetch(`${server.httpBase}/registrar/lookup/alice`);
    assert.equal(found.status, 200);
    assert.equal((await found.json()).fingerprint, fingerprint);
    // The card the registrar serves is the one hlid rewrote.
    const card = await fetch(`${server.httpBase}/identity/card/${fingerprint}`);
    assert.equal(card.status, 200);
    assert.deepEqual(
      new Uint8Array(await card.arrayBuffer()),
      new Uint8Array(readFileSync(join(server.dir, 'card.bin'))),
    );
  });

  test('the operator freezes an identity, and the registrar refuses it', async () => {
    const froze = hxdCommand(server, ['registrar', 'freeze', fingerprint]);
    assert.equal(froze.status, 0, froze.stderr);
    assert.match(froze.stdout, /froze/);
    assert.match(
      hlidRefused(server.dir, ['register', '--registrar', server.httpBase, '--handle', 'alice']),
      /frozen/,
    );
    const lifted = hxdCommand(server, ['registrar', 'freeze', '--lift', fingerprint]);
    assert.equal(lifted.status, 0, lifted.stderr);
    // A second on from the refused request, so this one is new.
    await new Promise((r) => setTimeout(r, 1100));
    const out = hlid(server.dir, [
      'register', '--registrar', server.httpBase, '--handle', 'alice', '--no-put',
    ]);
    assert.match(out, /reissued alice@127\.0\.0\.1/);

    // A flag from another command is refused rather than ignored.
    const wrong = hxdCommand(server, ['registrar', 'freeze', '--device', fingerprint]);
    assert.notEqual(wrong.status, 0);
    assert.match(wrong.stderr, /--device belongs to/);
  });

  test('SIGHUP reserves an account made after start', async () => {
    hlid(server.dir, ['keygen', 'identity', 'bob.key']);
    hlid(server.dir, ['card', '--identity', 'bob.key', '--name', 'Bob', '-o', 'bob-card.bin']);
    server.account('carol', 'name = "Carol"\npassword = "pw"\n');
    server.proc.kill('SIGHUP');
    await logged(server, /SIGHUP: registrar reserves \d+ names/);
    assert.equal(server.exitCode, null);
    assert.match(
      hlidRefused(server.dir, [
        'register',
        '--registrar', server.httpBase,
        '--handle', 'carol',
        '--proof', invite(),
        '--identity', 'bob.key',
        '--card', 'bob-card.bin',
        '--no-put',
      ]),
      /handle_reserved/,
    );
  });

  test('inspect verifies the log and the stats', async () => {
    const r = hxdCommand(server, ['registrar', 'inspect', server.httpBase]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /registrar 127\.0\.0\.1/);
    assert.match(r.stdout, /agrees with the stats/);
    assert.match(r.stdout, /1 new, 1 reissued/);
  });
});

describe('a registrar section the binary refuses', () => {
  test('without [identity]', async () => {
    const { output } = await startFailing({ config: { registrar: { host: 'hl.example' } } });
    assert.match(output, /\[registrar\] needs \[identity\]/);
  });

  test('with a port in its host', async () => {
    const { output } = await startFailing({
      config: { identity: {}, registrar: { host: 'hl.example:443' } },
    });
    assert.match(output, /no port/);
  });

  test('promising key backup it does not have', async () => {
    const { output } = await startFailing({
      config: { identity: {}, registrar: { host: 'hl.example', envelopes: true } },
    });
    assert.match(output, /not built/);
  });
});
