// Finding ports for a server this suite is about to start.
//
// Never a fixed port. The machine running these tests is, more often
// than not, the machine somebody is also running an hxd on — and a test
// that connects to *that* server logs in against real accounts, fails in
// a way that looks like a protocol bug, and leaves you debugging a
// process the suite never started.
//
// Nor `:0`. That draws from the ephemeral range, which is the same pool
// every outbound connection this suite makes draws from — a server can
// be handed the port its own client is about to want. Worse, a port
// learned from a listener that has since closed is only a guess by the
// time `hxd` binds it.
//
// So: an aligned block *below* the ephemeral range, probed cheaply, and
// then the server's own bind is the thing that decides. If it loses, we
// roll again.

import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { readFileSync } from 'node:fs';

/** One block, one server:
 *
 *     base+0   [server]  legacy TCP
 *     base+1   [ng]      WebSocket and HTTP
 *     base+2   [files]   legacy HTXF
 *     base+4   [voice]   UDP, *derived* rather than configured
 *
 * The gap is not padding. `voice::build` defaults the media port to the
 * legacy port plus four when `[voice] bind` is absent, so a block laid
 * out this way lets a test leave the key out and exercise the
 * derivation — which today only a unit test in `voice.rs` covers. */
export const BLOCK = 8;

function ephemeralFloor() {
  try {
    const range = readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8');
    const low = Number(range.trim().split(/\s+/)[0]);
    if (Number.isFinite(low) && low > 1024) return low;
  } catch {
    // Not Linux, or a kernel that doesn't say. The default below is the
    // conventional floor and is safe to assume.
  }
  return 32768;
}

/** `HXD_E2E_PORT_BASE` pins the roll, so a failure is reproducible —
 *  and so you can point a real GtkHx at the same server while a test is
 *  paused on it. */
function roll() {
  const pinned = Number(process.env.HXD_E2E_PORT_BASE);
  if (Number.isFinite(pinned) && pinned > 0) return pinned - (pinned % BLOCK);
  const top = ephemeralFloor() - BLOCK;
  const bottom = 20000;
  const slots = Math.floor((top - bottom) / BLOCK);
  return bottom + Math.floor(Math.random() * slots) * BLOCK;
}

function tcpFree(port) {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

/** TCP and UDP are separate namespaces, and the SFU wants the UDP one —
 *  probing the TCP port of the same number proves nothing about it. */
function udpFree(port) {
  return new Promise((resolve) => {
    const sock = createSocket('udp4');
    sock.once('error', () => resolve(false));
    sock.bind(port, '127.0.0.1', () => sock.close(() => resolve(true)));
  });
}

/**
 * A block whose three interesting ports are free right now.
 *
 * "Right now" is the honest limit of what this can promise: between the
 * probe and `hxd`'s bind, anything could take one. That race is closed
 * by the caller retrying against a fresh block when the server fails to
 * start, which works because the bind that decides is the server's own.
 */
export async function findBlock() {
  for (let attempt = 0; attempt < 40; attempt++) {
    const base = roll();
    if (
      (await tcpFree(base)) &&
      (await tcpFree(base + 1)) &&
      (await tcpFree(base + 2)) &&
      (await udpFree(base + 4))
    ) {
      return { base, legacy: base, ng: base + 1, files: base + 2, voice: base + 4 };
    }
    if (process.env.HXD_E2E_PORT_BASE) {
      throw new Error(
        `HXD_E2E_PORT_BASE=${base} is not free ` +
          `(needs ${base}, ${base + 1}, ${base + 2}, udp ${base + 4})`,
      );
    }
  }
  throw new Error('found no free port block below the ephemeral range after many tries');
}
