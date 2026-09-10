// Just enough TOML to write a config file.
//
// Writing the config rather than templating a string is what makes the
// server helper's `config` argument a plain object a test can override
// one key of, which is most of what this suite is for: a good half of
// the coverage here is `hxd` reading a section it has never been handed
// by a test before.

function scalar(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return `[${v.map(scalar).join(', ')}]`;
  throw new Error(`no TOML spelling for ${typeof v}: ${String(v)}`);
}

/**
 * `{ server: { name: 'e2e' }, voice: { video: { max_fps: 30 } } }` into
 * the `[server]` / `[voice.video]` shape hxd expects. Nesting is one
 * level deep, which is all the config has ever needed.
 *
 * A section whose value is `undefined` is omitted entirely — that is how
 * a test says "this build gets no `[media]` section", which is a
 * different server from one with an empty section.
 */
export function toToml(config) {
  const out = [];
  for (const [section, body] of Object.entries(config)) {
    if (body === undefined) continue;
    const keys = Object.entries(body).filter(([, v]) => v !== undefined && typeof v !== 'object');
    const tables = Object.entries(body).filter(([, v]) => v !== undefined && typeof v === 'object' && !Array.isArray(v));
    const arrays = Object.entries(body).filter(([, v]) => Array.isArray(v));
    out.push(`[${section}]`);
    for (const [k, v] of [...keys, ...arrays]) out.push(`${k} = ${scalar(v)}`);
    out.push('');
    for (const [name, sub] of tables) {
      out.push(`[${section}.${name}]`);
      for (const [k, v] of Object.entries(sub)) {
        if (v !== undefined) out.push(`${k} = ${scalar(v)}`);
      }
      out.push('');
    }
  }
  return out.join('\n');
}
