/**
 * `[tls]`, as the binary reads it: the TLS control port a config names,
 * the transfer port it derives, the fingerprint it logs, the refusals it
 * starts with, and the certificate SIGHUP swaps under a running server.
 *
 * The in-process suite (`crates/hxd/tests/tls.rs`) proves the protocol
 * inside TLS; it builds the listeners by hand and so never parses the
 * section, derives a port or installs the signal handler. This file is
 * the half only a real `hxd` reaches — and its client is Node's TLS
 * stack and a framer that shares nothing with the server's.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { after, before, describe, test } from 'node:test';

import { hdr, legacyLogin, tag, toText } from './harness/legacy.mjs';
import { startFailing, startServer } from './harness/server.mjs';

/** A self-signed pair for `localhost`, written into `dir`. openssl is
 *  what an operator would use, and a missing one fails here, loudly. */
function issue(dir) {
  const cert = join(dir, 'cert.pem');
  const key = join(dir, 'key.pem');
  const made = spawnSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
      '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-days', '1',
    ],
    { encoding: 'utf8' },
  );
  if (made.status !== 0) throw new Error(`openssl could not make a certificate: ${made.error ?? made.stderr}`);
  return { cert, key, pem: readFileSync(cert) };
}

/** The form the server logs: `sha256:` and lowercase hex. */
function fingerprint(pem) {
  return `sha256:${new X509Certificate(pem).fingerprint256.replaceAll(':', '').toLowerCase()}`;
}

/** Handshake with whatever is on `port`, trusting `ca`, and say which
 *  certificate it presented. */
function presented(port, ca) {
  return new Promise((resolve, reject) => {
    const sock = tlsConnect({ host: '127.0.0.1', port, ca, servername: 'localhost' });
    sock.once('error', reject);
    sock.once('secureConnect', () => {
      const raw = sock.getPeerCertificate().raw;
      sock.destroy();
      resolve(`sha256:${new X509Certificate(raw).fingerprint256.replaceAll(':', '').toLowerCase()}`);
    });
  });
}

describe('tls', () => {
  let dir;
  let pair;
  let server;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), 'hxd-e2e-tls-'));
    pair = issue(dir);
    // Beside the certificate, not around it: a file area that held the
    // key would hand it to anyone who asked.
    const files = join(dir, 'files');
    mkdirSync(files);
    server = await startServer({
      config: (ports) => ({
        files: { root: files, bind: `127.0.0.1:${ports.files}` },
        tls: { bind: `127.0.0.1:${ports.tls}`, cert: pair.cert, key: pair.key },
      }),
    });
  });

  after(async () => {
    await server?.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  test('the server logs the fingerprint of the certificate it presents', async () => {
    const want = fingerprint(pair.pem);
    assert.ok(
      server.lines.some((l) => l.includes(want)),
      `expected ${want} in the startup log\n${server.log()}`,
    );
    assert.equal(await presented(server.ports.tls, pair.pem), want);
  });

  test('a client over TLS and one in the clear chat in one room', async () => {
    const sealed = await legacyLogin(
      server,
      { nick: 'Sealed' },
      { tls: { port: server.ports.tls, ca: pair.pem } },
    );
    const open = await legacyLogin(server, { nick: 'Open' });
    try {
      open.chat('can you hear me');
      const line = await sealed.waitFor(
        (f) => f.type === hdr.CHAT && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('can you hear me'),
      );
      assert.equal(toText(line.get(tag.BODY)), '\r         Open:  can you hear me');
      sealed.chat('loud and clear');
      await open.waitFor(
        (f) => f.type === hdr.CHAT && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('loud and clear'),
      );
    } finally {
      sealed.close();
      open.close();
    }
  });

  test('with [files], the TLS transfer port is the TLS control port plus one', async () => {
    assert.equal(await presented(server.ports.tls + 1, pair.pem), fingerprint(pair.pem));
  });

  // Last in the file: it changes the certificate the other cases trust.
  test('SIGHUP swaps the certificate and keeps the sessions it did not start', async () => {
    const before = fingerprint(pair.pem);
    const sealed = await legacyLogin(
      server,
      { nick: 'Steady' },
      { tls: { port: server.ports.tls, ca: pair.pem } },
    );
    try {
      const renewed = issue(dir);
      const want = fingerprint(renewed.pem);
      assert.notEqual(want, before);
      server.proc.kill('SIGHUP');
      const deadline = Date.now() + 5000;
      let got;
      while (Date.now() < deadline) {
        got = await presented(server.ports.tls, renewed.pem).catch(() => null);
        if (got === want) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.equal(got, want, `the next handshake presents the new certificate\n${server.log()}`);

      // The session that handshook under the old one is still up.
      sealed.chat('still here');
      await sealed.waitFor(
        (f) => f.type === hdr.CHAT && toText(f.get(tag.BODY) ?? Buffer.alloc(0)).includes('still here'),
      );
    } finally {
      sealed.close();
    }
  });
});

describe('tls self-signed', () => {
  test('self_signed makes a pair on first start, keeps it, and says Let\'s Encrypt is better', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'hxd-e2e-tls-'));
    const cert = join(dir, 'cert.pem');
    const key = join(dir, 'key.pem');
    const config = (ports) => ({ tls: { bind: `127.0.0.1:${ports.tls}`, cert, key, self_signed: true } });
    try {
      const first = await startServer({ config });
      let pem;
      try {
        pem = readFileSync(cert);
        assert.ok(first.lines.some((l) => l.includes("Let's Encrypt")), first.log());
        assert.equal(await presented(first.ports.tls, pem), fingerprint(pem));
      } finally {
        await first.stop();
      }
      const second = await startServer({ config });
      try {
        assert.equal(await presented(second.ports.tls, pem), fingerprint(pem), 'the pin survives a restart');
        assert.ok(!second.lines.some((l) => l.includes('made a self-signed')), second.log());
      } finally {
        await second.stop();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('tls refusals', () => {
  let dir;
  let pair;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'hxd-e2e-tls-'));
    pair = issue(dir);
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  test('a certificate that is not there stops the server before it listens', async () => {
    const missing = join(dir, 'missing.pem');
    const { code, output } = await startFailing({
      config: (ports) => ({ tls: { bind: `127.0.0.1:${ports.tls}`, cert: missing, key: pair.key } }),
    });
    assert.notEqual(code, 0);
    assert.ok(output.includes(`[tls] ${missing}`), output);
  });

  test('a key that is not the certificate\'s is refused', async () => {
    const other = mkdtempSync(join(tmpdir(), 'hxd-e2e-tls-'));
    try {
      const stranger = issue(other);
      const { code, output } = await startFailing({
        config: (ports) => ({ tls: { bind: `127.0.0.1:${ports.tls}`, cert: pair.cert, key: stranger.key } }),
      });
      assert.notEqual(code, 0);
      assert.match(output, /\[tls\]/);
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });

  test('files_bind without [files] is refused rather than silently ignored', async () => {
    const { code, output } = await startFailing({
      config: (ports) => ({
        tls: { bind: `127.0.0.1:${ports.tls}`, cert: pair.cert, key: pair.key, files_bind: `127.0.0.1:${ports.tls + 1}` },
      }),
    });
    assert.notEqual(code, 0);
    assert.match(output, /\[tls\] files_bind needs \[files\]/);
  });
});
