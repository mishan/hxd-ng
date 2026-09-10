/**
 * The config file, and what the binary does with it.
 *
 * Nothing else in the tree covers any of this. `Config::load`,
 * `check_config` and the feature-gated section errors are reachable only
 * by handing `hxd` a file and watching what it does — the in-process
 * suites construct `ServerCtx` and `NgCtx` directly and never parse a
 * key. A refusal here is a startup message an operator reads at three in
 * the morning, so the exact words are worth asserting.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { fleet } from './harness/client.mjs';
import { startFailing, startServer } from './harness/server.mjs';

/** Each case here wants a differently-configured server, so unlike the
 *  rest of the suite this file starts one per test and tears it down. */
async function withServer(opts, body) {
  const server = await startServer(opts);
  const crew = fleet(() => server);
  try {
    await body(server, crew);
  } finally {
    await crew.closeAll();
    await server.stop();
  }
}

describe('config', () => {
  test('discovery answers for the server the config named', async () => {
    await withServer({ config: { server: { name: 'A Particular Server' } } }, async (server) => {
      const doc = await server.discovery();
      assert.equal(doc.name, 'A Particular Server');
      assert.equal(doc.v, 1);
      assert.equal(doc.ng.ws, '/ng');
      assert.equal(doc.identity.enabled, false);
    });
  });

  test('a server told to do nothing optional promises nothing optional', async () => {
    // `ng_caps` gates each name on the section being present *and* the
    // cargo feature being compiled in. A client believes this list —
    // it is what makes feature detection possible at all — so an
    // over-promise here is a client calling a request that cannot work.
    await withServer({}, async (_server, crew) => {
      const probe = await crew.connect({ nick: 'Probe' });
      assert.deepEqual(probe.conn.caps, []);
      assert.equal(probe.conn.media, null);
    });
  });

  test('each optional section shows up in the capability list', async () => {
    await withServer(
      { config: { history: { db: 'history.db' }, inbox: { db: 'messages.db' }, media: {} } },
      async (_server, crew) => {
        const probe = await crew.connect({ nick: 'Probe' });
        for (const cap of ['history', 'inbox', 'media']) {
          assert.ok(probe.conn.caps.includes(cap), `expected ${cap} in ${JSON.stringify(probe.conn.caps)}`);
        }
        assert.ok(probe.conn.media, 'a media server states its limits in the login reply');
        assert.ok(probe.conn.media.max_bytes > 0);
      },
    );
  });

  test('[identity] without [ng] is refused rather than silently ignored', async () => {
    const { code, output } = await startFailing({
      config: { ng: undefined, identity: { key: 'identity-server.key' } },
    });
    assert.notEqual(code, 0);
    assert.match(output, /\[identity\] needs \[ng\]/);
  });

  test('an out-of-range max_page is refused', async () => {
    const { code, output } = await startFailing({
      config: { history: { db: 'history.db', max_page: 201 } },
    });
    assert.notEqual(code, 0);
    assert.match(output, /max_page must be between 1 and 200/);
  });

  test('[history] with nowhere to write is refused', async () => {
    const { code, output } = await startFailing({ config: { history: { max_lines: 100 } } });
    assert.notEqual(code, 0);
    assert.match(output, /\[history\] needs db/);
  });

  test('a misspelled key is a startup error, not a silently ignored promise', async () => {
    // `deny_unknown_fields` on every section. The failure it prevents is
    // the worst kind: a server that starts, looks healthy, and does not
    // do the thing the operator asked for.
    const { code, output } = await startFailing({ config: { ng: { grase: 300 } } });
    assert.notEqual(code, 0);
    assert.match(output, /grase|unknown field/);
  });

  test('deleting guest.toml is how guest logins are turned off', async () => {
    // The comment `FileAuth::bootstrap` writes into the file it creates
    // says exactly this, and an accounts directory that already exists
    // is left alone — the same code path an operator takes.
    await withServer({ guest: false }, async (_server, crew) => {
      const { error } = await crew.refused({ nick: 'Nobody' });
      assert.equal(error.wire?.code, 'login_failed');
    });
  });
});
