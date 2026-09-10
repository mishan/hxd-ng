/**
 * Which client this suite is pinned to, and which one it is about to run.
 *
 * CI checks hx-ng out at the commit `e2e/hx-ng.rev` names. A local run
 * uses whatever the sibling `../hx-ng` holds, and the two differ often
 * and legitimately — one side is usually mid-change — so a difference is
 * a note, never a failure. It is here so that a suite passing locally
 * and failing in CI, or the reverse, explains itself before anyone
 * chases it.
 *
 * Run as `pretest`, so it speaks once per `npm test` rather than once
 * per file.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const E2E = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLIENT = join(E2E, '..', '..', 'hx-ng');

const pin = readFileSync(join(E2E, 'hx-ng.rev'), 'utf8').trim();
// The file is this repo's own, so a malformed one is a broken repo, not
// a local circumstance: that one fails.
if (!/^[0-9a-f]{40}$/.test(pin)) {
  throw new Error(`e2e/hx-ng.rev must hold one full commit hash, and holds ${JSON.stringify(pin)}`);
}

function git(...args) {
  const r = spawnSync('git', ['-C', CLIENT, ...args], { encoding: 'utf8' });
  return { status: r.status, out: (r.stdout ?? '').trim() };
}

function note(lines) {
  console.error(['', ...lines.map((l) => `  ${l}`), ''].join('\n'));
}

const short = (rev) => rev.slice(0, 12);
const head = git('rev-parse', 'HEAD');

if (head.status !== 0) {
  note([
    `e2e: ${CLIENT} is not a git checkout, so which client this runs against is unknown.`,
    `CI runs hx-ng at ${short(pin)} (e2e/hx-ng.rev).`,
  ]);
} else {
  const lines = [];
  if (head.out !== pin) {
    // Where the checkout stands relative to the pin says what to expect:
    // ahead is normal mid-change, behind means tests newer than the
    // client may fail here that pass in CI.
    const ahead = git('merge-base', '--is-ancestor', pin, head.out).status;
    const behind = git('merge-base', '--is-ancestor', head.out, pin).status;
    const where =
      ahead === 0
        ? 'ahead of the pin'
        : behind === 0
          ? 'behind the pin'
          : ahead === 128
            ? 'somewhere the pin is not known (fetch hx-ng?)'
            : 'on a line the pin is not on';
    lines.push(`e2e: ../hx-ng is at ${short(head.out)}, ${where}; CI runs ${short(pin)} (e2e/hx-ng.rev).`);
  }
  if (git('status', '--porcelain', '--', 'packages/hotline-ng').out !== '') {
    lines.push('e2e: ../hx-ng has uncommitted changes in packages/hotline-ng, which this run will use.');
  }
  if (lines.length > 0) note(lines);
}
