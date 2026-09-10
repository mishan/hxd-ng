/**
 * Mac Roman, for the legacy client — derived, not transcribed.
 *
 * Node already carries the table: `TextDecoder('macintosh')` is the
 * WHATWG label for it, and it maps all 256 bytes one to one, so both
 * directions fall out of the platform and there is no 128-entry array in
 * this file to drift from anything.
 *
 * Two bytes need saying out loud. hxproto follows glibc's iconv
 * MACINTOSH table rather than the Unicode Consortium's, because the C
 * gtkhx it replaced went through `g_convert(..., "MACINTOSH", ...)` and
 * a drop-in replacement has to be one. Where the two tables disagree,
 * this file agrees with the server on purpose — the point of an
 * independent implementation is to be independent about the parts that
 * are a *choice*, and this one was made and written down.
 */

const WHATWG = new TextDecoder('macintosh');

/** byte -> code point, for 0x00..0xFF. */
const DECODE = (() => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const table = [...WHATWG.decode(bytes)].map((c) => c.codePointAt(0));
  if (table.length !== 256) {
    throw new Error(
      `this Node's 'macintosh' decoder is not one-to-one (${table.length} of 256) — ` +
        'a full-ICU build is needed',
    );
  }
  // The two deliberate divergences, cited at hxproto's `text.rs`:
  // 0xC6 is GREEK CAPITAL LETTER DELTA rather than INCREMENT, and 0xF0
  // is a private-use codepoint rather than the Apple logo.
  table[0xc6] = 0x0394;
  table[0xf0] = 0xe01e;
  return table;
})();

/** code point -> byte. Injective, so this is just the inverse. */
const ENCODE = new Map(DECODE.map((cp, byte) => [cp, byte]));

/**
 * Wire bytes to a string, mirroring `hxproto::text::to_utf8`.
 *
 * Valid UTF-8 passes through untouched, and that is not an optimization
 * — it is the documented behavior of the C function this descends from,
 * and it is what lets a modern client put a real "é" on the wire and
 * have it come back as one character rather than two.
 */
export function toText(bytes) {
  const buf = Buffer.from(bytes);
  const asUtf8 = buf.toString('utf8');
  if (Buffer.compare(Buffer.from(asUtf8, 'utf8'), buf) === 0) return asUtf8;
  let out = '';
  for (const b of buf) out += String.fromCodePoint(DECODE[b]);
  return out;
}

/**
 * A string to wire bytes, with `?` for anything Mac Roman has no room
 * for — the same substitution the server makes on the way out.
 */
export function toBytes(text) {
  const out = [];
  for (const ch of text) {
    const byte = ENCODE.get(ch.codePointAt(0));
    out.push(byte === undefined ? 0x3f : byte);
  }
  return Buffer.from(out);
}
