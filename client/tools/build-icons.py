#!/usr/bin/env python3
"""Pack every 'cicn' in a Mac resource fork into one web sprite sheet.

    ./build-icons.py ../../gtkhx/icons.rsrc ../public

Writes `icons.png` (the atlas) and `icons.json` (the index) next to each
other. Both are committed, so running the client needs no Python and no
Pillow; this only runs when icons.rsrc changes — the same policy
gtkhx's cicndump follows for src/pixmaps.

**Why an atlas and not a directory of PNGs.** icons.rsrc holds hundreds
of icons and a Hotline user list shows a handful of them, but which
handful is not known until people join. Six hundred separate requests is
the worst of both worlds; one atlas is a single cacheable file the
browser decodes once, and `background-position` picks the sprite. Icons
that decode to identical pixels — and there are plenty, the same art
filed under several ids — share one cell, so the sheet is smaller than
the sum of its parts.

The decoder is a transliteration of gtkhx's `tools/cicndump/cicndump.c`,
including its default palettes; that file is the reference if the two
ever disagree.

License: GPL-2.0-or-later.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

from PIL import Image

TYPE_cicn = 0x6369636E

# Atlas geometry. 512 is wide enough to shelf-pack the whole set into a
# sheet a texture-minded browser is happy with, and every cell is fenced
# by a transparent gutter so a fractionally-scaled background-position
# can't drag a neighbour's edge pixel into view.
ATLAS_WIDTH = 512
GUTTER = 1


# ---------- default palettes (cicndump.c) ------------------------------
#
# A cicn carries its own ColorTable, but it only overrides the entries it
# names; anything it leaves out falls back to the Mac system palette for
# that depth.

def _pal(hexstr):
    b = bytes.fromhex(hexstr)
    return [(b[i], b[i + 1], b[i + 2]) for i in range(0, len(b), 3)]


PAL = {
    8: _pal(
        "fffffffffecbfffe9afffe66fffe33fefe00ffcbfeffcbcbffcc9affcc66ffcc33fecb00"
        "ff9afeff9accff9a9aff9966ff9933fe9800ff66feff66ccff6699ff6666ff6633fe6500"
        "ff33feff33ccff3399ff3366ff3333fe3200fe00fefe00cbfe0098fe0065fe0032fe0000"
        "cbffffcbffcbccff9accff66ccff33cbfe00cbcbffcccccccccc99cccc66cbcb32cdcd00"
        "cc9affcc99cccc9999cc9966cb9832cd9a00cc66ffcc66cccc6699cc6666cb6532cd6600"
        "cc33ffcb32cbcb3298cb3265cb3232cd3300cb00fecd00cdcd009acd0066cd0033cd0000"
        "9affff9affcc9aff9a99ff6699ff3399fe009accff99cccc00986599cc6699cb329acd00"
        "9a9aff9999cc9999999898659a9a339898009966ff9966cc9865989865659a6633986500"
        "9933ff9832cb9a339a9a33669a33339832009800fe9a00cd980098980065980032980000"
        "66ffff66ffcc66ff9966ff6666ff3366fe0066ccff66cccc66cc9966cc6666cb3266cd00"
        "6699ff6699cc659898659865669a336598006666ff6666cc656598666666656532666600"
        "6633ff6532cb66339a6532656532326633006500fe6600cd650098660066660033660000"
        "33ffff33ffcc33ff9933ff6633ff3333fe0033ccff32cbcb32cb9832cb6533cb3233cd00"
        "3399ff3299cb339a9a339a66339a333298003366ff3266cb33669a326565326532336600"
        "3333ff3233cb33339a3232653333333333003200fe3300cd320098330066330033330000"
        "00fefe00fecb00fe9800fe6500fe3200fe0000cbfe00cdcd00cd9a00cd6600cd3300cd00"
        "0098fe009acd0098980098650098320098000066fe0066cd006598006666006633006600"
        "0033fe0033cd0032980033660033330033000000fe0000cd000098000066000033ef0000"
        "dc0000ba0000ab000089000077000055000044000022000011000000ef0000dc0000ba00"
        "00ab000089000077000055000044000022000011000000ef0000dc0000ba0000ab000089"
        "000077000055000044000022000011eeeeeeddddddbbbbbbaaaaaa888888777777555555"
        "444444222222111111000000"
    ),
    4: _pal(
        "ffffffffff00ffa07aff0000ff14938a2be20000806495ed228b220064008b4513d2b48c"
        "d3d3d3bebebe696969000000"
    ),
    2: _pal("ffffffffff0000ffff000000"),
    1: _pal("ffffff000000"),
}


# ---------- resource fork walker ---------------------------------------

def read_cicns(path):
    """Yield (resource id, raw cicn bytes) in resource-fork order."""
    raw = path.read_bytes()
    if len(raw) < 256:
        raise SystemExit(f"{path}: too short to be a Mac resource fork")
    data_off, map_off, _dlen, _mlen = struct.unpack(">IIII", raw[:16])
    m = raw[map_off:]
    type_list_off = struct.unpack(">H", m[24:26])[0]
    num_types = struct.unpack(">H", m[28:30])[0] + 1

    for i in range(num_types):
        base = type_list_off + 2 + 8 * i
        typ, count_m1, ref_off = struct.unpack(">IHH", m[base:base + 8])
        if typ != TYPE_cicn:
            continue
        for j in range(count_m1 + 1):
            e = m[type_list_off + ref_off + 12 * j:][:12]
            # Icon ids are unsigned on the Hotline wire (DATA_ICON is a
            # u16), so read them that way even though the Resource
            # Manager's own id is signed — 32766 and -2 are the same
            # sixteen bits, and the wire's reading is the one that has
            # to match what a client asks for.
            resid = struct.unpack(">H", e[0:2])[0]
            off = data_off + ((e[5] << 16) | (e[6] << 8) | e[7])
            length = struct.unpack(">I", raw[off:off + 4])[0]
            yield resid, raw[off + 4:off + 4 + length]


# ---------- cicn decoder -----------------------------------------------

def decode_cicn(r):
    """Decode one cicn to an RGBA Pillow image, or None if unreadable.

    Layout: PixMap(50) MaskBitMap(14) BitMap(14) Handle(4), then mask
    data, bitmap data, ColorTable, and the pixels as the resource's
    trailing rowBytes*height bytes.
    """
    if len(r) < 82:
        return None
    pm_row = struct.unpack(">H", r[4:6])[0] & 0x7FFF
    pm_top, pm_left, pm_bottom, pm_right = struct.unpack(">HHHH", r[6:14])
    bpp = struct.unpack(">H", r[32:34])[0]

    mb_row = struct.unpack(">H", r[54:56])[0]
    mb_top, _mb_left, mb_bottom, mb_right = struct.unpack(">HHHH", r[56:64])
    bm_row = struct.unpack(">H", r[68:70])[0]
    bm_top, _bl, bm_bottom, _br = struct.unpack(">HHHH", r[70:78])

    if bpp not in PAL:
        return None
    if pm_right <= pm_left or pm_bottom <= pm_top:
        return None
    if mb_bottom < mb_top or bm_bottom < bm_top:
        return None

    w, h = pm_right - pm_left, pm_bottom - pm_top
    if w > 4096 or h > 4096 or pm_row < (w * bpp + 7) // 8:
        return None

    ct_off = 82 + mb_row * (mb_bottom - mb_top) + bm_row * (bm_bottom - bm_top)
    if ct_off + 8 > len(r):
        return None
    ct_n = struct.unpack(">H", r[ct_off + 6:ct_off + 8])[0] + 1
    if ct_off + 8 + ct_n * 8 > len(r):
        return None

    pix_size = pm_row * h
    if pix_size > len(r):
        return None
    pix = r[len(r) - pix_size:]
    mask = r[82:]
    have_mask = mb_right != 0 and mb_bottom != 0

    palette = list(PAL[bpp])
    for i in range(ct_n):
        e = r[ct_off + 8 + i * 8:][:8]
        v = struct.unpack(">H", e[0:2])[0] & ((1 << bpp) - 1)
        palette[v] = (e[2], e[4], e[6])

    out = bytearray(w * h * 4)
    for y in range(h):
        row = pix[pm_row * y:]
        mrow = mask[mb_row * y:] if have_mask else None
        for x in range(w):
            if bpp == 8:
                idx = row[x]
            elif bpp == 4:
                idx = (row[x >> 1] >> ((1 - (x & 1)) * 4)) & 0x0F
            elif bpp == 2:
                idx = (row[x >> 2] >> ((3 - (x & 3)) * 2)) & 0x03
            else:
                idx = (row[x >> 3] >> (7 - (x & 7))) & 0x01
            cr, cg, cb = palette[idx]
            a = 255
            if mrow is not None:
                a = 255 if (mrow[x >> 3] >> (7 - (x & 7))) & 1 else 0
            o = (y * w + x) * 4
            out[o:o + 4] = bytes((cr, cg, cb, a))
    return Image.frombytes("RGBA", (w, h), bytes(out))


# ---------- shelf packer -----------------------------------------------

def pack(cells, width):
    """Place (key, image) pairs on shelves, tallest first. Returns
    {key: (x, y)} and the atlas height."""
    order = sorted(cells, key=lambda kv: (-kv[1].height, -kv[1].width))
    placed = {}
    x = y = shelf_h = 0
    for key, im in order:
        w, h = im.width + GUTTER, im.height + GUTTER
        if x + w > width:
            x, y = 0, y + shelf_h
            shelf_h = 0
        placed[key] = (x, y)
        x += w
        shelf_h = max(shelf_h, h)
    return placed, y + shelf_h


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: build-icons.py <icons.rsrc> <output dir>\n")
        return 1
    src, outdir = Path(argv[1]), Path(argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    # Decode everything, then fold identical art onto one cell. The same
    # picture is filed under several ids often enough to be worth it.
    by_hash, ids, skipped = {}, {}, []
    for resid, blob in read_cicns(src):
        im = decode_cicn(blob)
        if im is None:
            skipped.append(resid)
            continue
        key = hashlib.sha256(
            im.tobytes() + bytes(f"{im.width}x{im.height}", "ascii")
        ).hexdigest()
        by_hash.setdefault(key, im)
        ids[resid] = key

    placed, height = pack(list(by_hash.items()), ATLAS_WIDTH)
    atlas = Image.new("RGBA", (ATLAS_WIDTH, height), (0, 0, 0, 0))
    for key, im in by_hash.items():
        atlas.paste(im, placed[key])
    atlas.save(outdir / "icons.png", optimize=True)

    index = {
        "atlas": "icons.png",
        "width": ATLAS_WIDTH,
        "height": height,
        # id -> [x, y, w, h]. Ids are strings because JSON object keys
        # are; the client parses them back to numbers on load.
        "icons": {
            str(resid): [
                placed[key][0], placed[key][1],
                by_hash[key].width, by_hash[key].height,
            ]
            for resid, key in sorted(ids.items())
        },
    }
    (outdir / "icons.json").write_text(json.dumps(index, separators=(",", ":")) + "\n")

    print(f"{len(ids)} icons -> {len(by_hash)} cells, "
          f"{ATLAS_WIDTH}x{height}, "
          f"{(outdir / 'icons.png').stat().st_size} bytes")
    if skipped:
        print(f"skipped (undecodable): {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
