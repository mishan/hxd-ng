// A real PNG, built here.
//
// The media pipeline decodes what it is given and re-encodes it, so a
// test needs an actual image rather than a plausible-looking byte
// string — and pulling an encoder in for that would be the only
// dependency in this suite. A PNG small enough to hand-assemble is four
// chunks and a CRC, and `node:zlib` does the only hard part.

import { deflateSync } from 'node:zlib';

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = ~0;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

/**
 * A `width` x `height` truecolor PNG, filled with one color.
 *
 * The color is a parameter so a test can prove the *same* handle came
 * back rather than merely a picture of the right size.
 */
function encode(raw, width, height) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // truecolor
  // Compression, filter and interlace all take their only defined value.
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

export function png(width, height, [r, g, b] = [255, 0, 0]) {
  // One filter byte per scanline, filter type 0 (None), then RGB.
  const raw = Buffer.alloc(height * (1 + width * 3));
  for (let y = 0; y < height; y++) {
    const row = y * (1 + width * 3);
    raw[row] = 0;
    for (let x = 0; x < width; x++) {
      raw[row + 1 + x * 3] = r;
      raw[row + 2 + x * 3] = g;
      raw[row + 3 + x * 3] = b;
    }
  }
  return encode(raw, width, height);
}

/** The same image as a `Blob`, which is what `uploadMedia` takes. */
export function pngBlob(width, height, color) {
  return new Blob([png(width, height, color)], { type: 'image/png' });
}

/**
 * A PNG of `width` x `height` random pixels.
 *
 * Random data does not compress, so this is the only reliable way to
 * build a file that is genuinely over a byte cap rather than a large
 * picture that deflates to nothing. Seeded, so a failure repeats.
 */
export function noisyPng(width, height, seed = 1) {
  let state = seed >>> 0 || 1;
  const next = () => {
    // xorshift32: no dependency, and reproducible across runs.
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) & 0xff;
  };
  const raw = Buffer.alloc(height * (1 + width * 3));
  for (let y = 0; y < height; y++) {
    const row = y * (1 + width * 3);
    raw[row] = 0;
    for (let i = 1; i <= width * 3; i++) raw[row + i] = next();
  }
  return encode(raw, width, height);
}

/** The noisy image as a `Blob`. */
export function noisyPngBlob(width, height, seed) {
  return new Blob([noisyPng(width, height, seed)], { type: 'image/png' });
}
