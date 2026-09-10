/**
 * Building, configuring, starting and stopping a real `hxd`.
 *
 * This is the whole reason the suite exists. `crates/hxd/tests/` builds
 * `Core`/`ServerCtx`/`NgCtx` by hand and spawns `serve` on an ephemeral
 * port, which is the right shape for what those tests prove and leaves
 * an entire layer unobserved: `Config::load` and `check_config`,
 * `build_ctx`, `voice::build`, the ng sweeper, the pruners,
 * `FileAuth::bootstrap`, the account audit, the server key that writes
 * itself on first run. All of that is `main.rs`, and until now nothing
 * ran `main.rs`.
 *
 * So: a real binary, a real config file it parses itself, a real
 * directory it bootstraps into, real sockets.
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

import { findBlock } from './ports.mjs';
import { toToml } from './toml.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

function bin(name) {
  const path = join(REPO, 'target', 'release', name);
  if (!existsSync(path)) {
    // Loudly, per the house rule. A missing binary is not an absent
    // optional dependency here — it is this repo's own artifact, and
    // skipping would report green for a suite that ran nothing.
    throw new Error(
      `${path} is missing.\n` +
        `Run: cargo build --release -p hxd -p hlid\n` +
        `(\`npm test\` in e2e/ does this for you.)`,
    );
  }
  return path;
}

async function waitForDiscovery(server, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error(`hxd exited ${server.exitCode} before it listened`);
    }
    try {
      const res = await fetch(`${server.httpBase}/.well-known/hotline`);
      if (res.ok) {
        const doc = await res.json();
        // The guard, and it is not paperwork. `Config::load` answers a
        // missing file with `Ok(Config::default())` — a *runnable*
        // server on 0.0.0.0:5500 with no `[ng]` section. Get the temp
        // path wrong and you would spawn a public server squatting the
        // real Hotline port while the test times out against something
        // else entirely. A per-server nonce in the name means we only
        // ever talk to the server we started.
        if (doc.name !== server.name) {
          throw new Error(
            `${server.httpBase} answered for "${doc.name}", not "${server.name}" — ` +
              `something else is on this port`,
          );
        }
        return doc;
      }
      last = `HTTP ${res.status}`;
    } catch (e) {
      if (/answered for/.test(String(e.message))) throw e;
      last = String(e);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${server.httpBase} did not answer within ${timeoutMs}ms (${last})`);
}

/**
 * A server under test.
 *
 * `log()` is the point of most of this: every failure a test reports
 * carries the server's own account of the same moment, which turns
 * "waitFor(chat) timed out" into something you can read.
 */
export class Server {
  constructor(proc, dir, ports, config, name) {
    this.proc = proc;
    this.dir = dir;
    this.ports = ports;
    this.config = config;
    this.name = name;
    this.exitCode = null;
    this.lines = [];
    const take = (d) => {
      for (const line of String(d).split('\n')) if (line) this.lines.push(line);
      // A ring, not an ever-growing string: a file's worth of tests on a
      // debug-traced server produces a lot of log, and only the tail
      // ever helps.
      if (this.lines.length > 400) this.lines.splice(0, this.lines.length - 400);
    };
    proc.stdout.on('data', take);
    proc.stderr.on('data', take);
    proc.on('exit', (code) => (this.exitCode = code));
  }

  get httpBase() {
    return `http://127.0.0.1:${this.ports.ng}`;
  }

  get wsUrl() {
    return `ws://127.0.0.1:${this.ports.ng}/ng`;
  }

  /** Everything the server has said lately, indented for an assertion
   *  message. */
  log() {
    const tail = this.lines.slice(-30).map((l) => `    ${l}`);
    if (this.exitCode !== null) tail.push(`    (hxd has exited: ${this.exitCode})`);
    return tail.join('\n') || '    (the server said nothing)';
  }

  async discovery() {
    const res = await fetch(`${this.httpBase}/.well-known/hotline`);
    return res.json();
  }

  /** Write an account file the way an operator would, into the accounts
   *  directory the server bootstrapped for itself. Picked up on the next
   *  login — `FileAuth` reads the directory rather than caching it. */
  account(login, toml) {
    writeFileSync(join(this.dir, 'accounts', `${login}.toml`), toml);
  }

  /** How to get this exact server back, with the wire trace on. The two
   *  traces line up: `HXD_DEBUG=proto`'s format matches gtkhx's, and the
   *  client's own trace is in every failure message. */
  repro(file) {
    return `HXD_E2E_PORT_BASE=${this.ports.base} HXD_E2E_DEBUG=1 node --test ${file ?? 'e2e/'}`;
  }

  async stop() {
    if (this.exitCode === null) {
      this.proc.kill();
      await new Promise((r) => this.proc.once('exit', r));
    }
    rmSync(this.dir, { recursive: true, force: true });
  }
}

/** The config every test starts from: no optional feature turned on at
 *  all, so a test that wants one says so and a test that doesn't gets a
 *  build whose `caps` are honestly empty. */
function baseConfig(ports, name) {
  return {
    server: {
      bind: `127.0.0.1:${ports.legacy}`,
      name,
      version: 185,
      login_timeout: 10,
    },
    paths: { accounts: 'accounts' },
    ng: {
      bind: `127.0.0.1:${ports.ng}`,
      // The default is 2, and it is right for a deployment. It is wrong
      // for a suite where every client in a file is a different person
      // on 127.0.0.1: the cap is enforced by *eviction*, oldest first
      // (`roster.rs`), so a third detached session silently ends the
      // first and the test that owned it fails with `session_expired`
      // pointing at resume rather than at the cap. Raised here, and one
      // file lowers it back to 2 to assert the eviction on purpose.
      max_detached_per_addr: 64,
    },
  };
}

function materialize({ config, ports, name, guest }) {
  const merged = { ...baseConfig(ports, name) };
  for (const [section, body] of Object.entries(config)) {
    merged[section] = body === undefined ? undefined : { ...(merged[section] ?? {}), ...body };
  }
  const dir = mkdtempSync(join(tmpdir(), 'hxd-e2e-'));
  // The accounts directory is deliberately left for the server to make.
  // `FileAuth::bootstrap` returns early if it already exists, so a
  // harness that helpfully creates it first produces a server with no
  // guest account — which is real behavior (an operator with an existing
  // directory does not get one silently added), and was worth an hour to
  // rediscover. `guest: false` asks for exactly that, by making the
  // directory ahead of the server: it is how `docs` says to turn guest
  // logins off, so it is worth being able to test.
  if (guest === false) mkdirSync(join(dir, 'accounts'), { recursive: true });
  writeFileSync(join(dir, 'hxd-ng.toml'), toToml(merged));
  // `merged.server.name` is what the readiness check compares against,
  // which is why a test is free to override it: the guard's job is to
  // notice we are talking to *the server whose config we just wrote*,
  // and the name the accident produces — plain `hxd-ng`, from
  // `Config::default()` — is not any of these.
  return { dir, merged };
}

function launch(dir) {
  // An absolute `--config`, always. A path `hxd` cannot find is not an
  // error to it: `Config::load` treats `NotFound` as "use the defaults",
  // and the defaults are a real server on a real port.
  return spawn(bin('hxd'), ['--config', join(dir, 'hxd-ng.toml')], {
    cwd: dir,
    stdio: 'pipe',
    env: process.env.HXD_E2E_DEBUG ? { ...process.env, HXD_DEBUG: 'proto' } : process.env,
  });
}

/**
 * Start a server and wait until it answers as itself.
 *
 * `config` is merged one section deep over {@link baseConfig}, so
 * `{ ng: { grace: 1 } }` keeps the bind address and `{ media: {} }` adds
 * a whole section. A section set to `undefined` is removed, which is how
 * a test asks for a server without one.
 *
 * `accounts` is written before the server starts, so first-run bootstrap
 * and a hand-placed account file are exercised together.
 */
export async function startServer({ config = {}, accounts = {}, guest = true } = {}) {
  let lastError;
  for (let attempt = 0; attempt < 4; attempt++) {
    const ports = await findBlock();
    const nonce = `hxd-e2e-${randomUUID().slice(0, 8)}`;
    const { dir, merged } = materialize({ config, ports, name: nonce, guest });
    const server = new Server(launch(dir), dir, ports, merged, merged.server.name);
    try {
      await waitForDiscovery(server, 15_000);
      // After the server has bootstrapped its own directory, never
      // before. `FileAuth` reads the directory per login rather than
      // caching it, so an account written now is live for the next one.
      for (const [login, toml] of Object.entries(accounts)) server.account(login, toml);
      return server;
    } catch (e) {
      lastError = new Error(`${e.message}\n${server.log()}`);
      const lost = server.lines.some((l) => /Address already in use/.test(l));
      await server.stop();
      // Losing the port race is the one failure worth another roll.
      // Anything else — a config the server refused, a panic — is the
      // answer, and retrying would only bury it.
      if (!lost) throw lastError;
    }
  }
  throw lastError;
}

/**
 * Start a server that is expected *not* to start, and return what it
 * said on the way out.
 *
 * Coverage nothing else in the tree can reach: `check_config`'s
 * cross-section rules, the feature-gated section errors, and every
 * `deny_unknown_fields` refusal are reachable only by handing the binary
 * a file and watching it exit.
 */
export async function startFailing({ config = {}, guest = true } = {}) {
  const ports = await findBlock();
  const nonce = `hxd-e2e-${randomUUID().slice(0, 8)}`;
  const { dir } = materialize({ config, ports, name: nonce, guest });
  const proc = launch(dir);
  let output = '';
  proc.stdout.on('data', (d) => (output += d));
  proc.stderr.on('data', (d) => (output += d));
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      proc.kill();
      resolve('running');
    }, 15_000);
    proc.on('exit', (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  rmSync(dir, { recursive: true, force: true });
  if (code === 'running') {
    throw new Error(`expected hxd to refuse this config, but it started:\n${output}`);
  }
  return { code, output };
}

/** Run `hlid` with its own `$HLID_HOME`, so nothing lands in the home
 *  directory of whoever ran the suite — `hlid init` and every file flag
 *  fall back to `~/.hlid`, and a test that wrote there would quietly
 *  become the default for that person's own commands. */
export function hlid(cwd, args) {
  const r = spawnSync(bin('hlid'), args, {
    cwd,
    env: { ...process.env, HLID_HOME: cwd },
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    throw new Error(`hlid ${args.join(' ')} failed (exit ${r.status}):\n${r.stderr}`);
  }
  return r.stdout;
}
