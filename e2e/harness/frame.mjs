/**
 * The legacy transaction frame, written from the wire format rather than
 * from the server's code.
 *
 * That independence is the entire point of this file. Every legacy test
 * in `crates/hxd/tests/` packs with `hxd_session::frame::pack_frame` and
 * parses with `read_frame` — the server's own functions — so a framing
 * bug symmetric between the two is invisible to all of them. Here the
 * bytes are laid out from `docs` and from the 22-byte header itself, so
 * a disagreement shows up as a disagreement.
 *
 * Header, big-endian throughout:
 *
 *     0   type   u32
 *     4   trans  u32
 *     8   flag   u32
 *     12  len    u32   TotalSize
 *     16  len2   u32   DataSize
 *     20  hc     u16   chunk count
 *
 * `len` and `len2` both count the body *plus* the two bytes of `hc`,
 * which is why the body that follows is `len2 - 2` long.
 */

export const HDR_LEN = 22;
export const CHUNK_HDR_LEN = 4;
/** mhxd's `MAX_HOTLINE_PACKET_LEN`. */
export const MAX_FRAME_DATA = 0x40000;

/** `"TRTPHOTL" 0x0001 0x0002`, and the eight bytes back. */
export const CLIENT_MAGIC = Buffer.from('TRTPHOTL\x00\x01\x00\x02', 'binary');
export const SERVER_MAGIC = Buffer.from('TRTP\x00\x00\x00\x00', 'binary');

/** Chunks are `(tag u16, len u16, bytes)`. */
export function pack(type, trans, flag, chunks) {
  const bodyLen = chunks.reduce((n, [, data]) => n + CHUNK_HDR_LEN + data.length, 0);
  const wireLen = bodyLen + 2; // + sizeof(hc)
  const head = Buffer.alloc(HDR_LEN);
  head.writeUInt32BE(type, 0);
  head.writeUInt32BE(trans, 4);
  head.writeUInt32BE(flag, 8);
  head.writeUInt32BE(wireLen, 12);
  head.writeUInt32BE(wireLen, 16);
  head.writeUInt16BE(chunks.length, 20);
  const body = [];
  for (const [tag, data] of chunks) {
    const th = Buffer.alloc(CHUNK_HDR_LEN);
    th.writeUInt16BE(tag, 0);
    th.writeUInt16BE(data.length, 2);
    body.push(th, Buffer.from(data));
  }
  return Buffer.concat([head, ...body]);
}

/** A parsed transaction: the header fields, and its chunks as a list of
 *  `{ tag, data }` in wire order (a tag can repeat — the user list is
 *  one chunk per user). */
export class Frame {
  constructor(type, trans, flag, chunks) {
    this.type = type;
    this.trans = trans;
    this.flag = flag;
    this.chunks = chunks;
  }

  /** The first chunk with this tag, or undefined. */
  get(tag) {
    return this.chunks.find((c) => c.tag === tag)?.data;
  }

  all(tag) {
    return this.chunks.filter((c) => c.tag === tag).map((c) => c.data);
  }
}

/**
 * Accumulate bytes and yield whole transactions.
 *
 * Framing is by **`len2` (DataSize), not `len` (TotalSize)**. The
 * distinction only shows up against a sender that fragments, and it cost
 * gtkhx a real desync to learn, so this reads the field the server
 * reads. A frame whose two lengths disagree is rejected outright rather
 * than half-understood — no known client fragments, so a mismatch is a
 * broken or hostile peer either way.
 */
export class Framer {
  constructor() {
    this.buf = Buffer.alloc(0);
  }

  push(bytes) {
    this.buf = Buffer.concat([this.buf, bytes]);
    const frames = [];
    for (;;) {
      if (this.buf.length < HDR_LEN) break;
      const type = this.buf.readUInt32BE(0);
      const trans = this.buf.readUInt32BE(4);
      const flag = this.buf.readUInt32BE(8);
      const len = this.buf.readUInt32BE(12);
      const len2 = this.buf.readUInt32BE(16);
      const hc = this.buf.readUInt16BE(20);
      if (len2 > MAX_FRAME_DATA) throw new Error(`data size ${len2} exceeds the cap`);
      if (len !== len2) throw new Error(`len ${len} disagrees with len2 ${len2}`);
      const bodyLen = len2 - 2;
      if (this.buf.length < HDR_LEN + bodyLen) break;

      const body = this.buf.subarray(HDR_LEN, HDR_LEN + bodyLen);
      const chunks = [];
      let at = 0;
      for (let i = 0; i < hc; i++) {
        if (at + CHUNK_HDR_LEN > body.length) throw new Error('chunk header runs past the body');
        const tag = body.readUInt16BE(at);
        const size = body.readUInt16BE(at + 2);
        at += CHUNK_HDR_LEN;
        if (at + size > body.length) throw new Error(`chunk ${tag} runs past the body`);
        chunks.push({ tag, data: Buffer.from(body.subarray(at, at + size)) });
        at += size;
      }
      frames.push(new Frame(type, trans, flag, chunks));
      this.buf = this.buf.subarray(HDR_LEN + bodyLen);
    }
    return frames;
  }
}
