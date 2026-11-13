"""Test helper: inspect / tamper with a saved patch-wise stego PNG at the PIXEL level.

Deliberately INDEPENDENT of the image service's code (stdlib + numpy + Pillow only): it re-implements
the documented layouts (docs/patchwise-transport.md), so it doubles as a cross-check of the format.

  bootstrap carrier (LSBs of the flat samples from index 0):
      preamble(16) = "SB" | ver=2 | flags=0 | manifest_len u32 | frame_len u32 | crc32(first 12)
      manifest(manifest_len) | crc32(manifest)
  manifest v1: 24-byte fixed part, 12 bytes per patch, RLE cell map

Usage: python3 tamper_png.py <mode> <path> [args...]
"""
import io
import json
import struct
import sys
import zlib

import numpy as np
from PIL import Image

mode, path = sys.argv[1], sys.argv[2]
args = sys.argv[3:]


def load():
    with Image.open(path) as im:
        im.load()
        return im.copy()


def save(arr):
    Image.fromarray(arr).save(path, format="PNG")


def get_bytes(flat, start_bit, n):
    return bytearray(np.packbits(flat[start_bit:start_bit + 8 * n] & 1).tobytes())


def put_bytes(flat, start_bit, data):
    bits = np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))
    flat[start_bit:start_bit + bits.size] = (flat[start_bit:start_bit + bits.size] & 0xFE) | bits


def read_carrier(flat):
    pre = get_bytes(flat, 0, 16)
    assert pre[:2] == b"SB" and pre[2] == 2, "not a bootstrap v2 image"
    mlen, flen = struct.unpack(">II", pre[4:12])
    return pre, get_bytes(flat, 128, mlen), mlen, flen


def write_preamble(flat, pre):
    pre[12:16] = struct.pack(">I", zlib.crc32(bytes(pre[:12])))
    put_bytes(flat, 0, pre)


def write_manifest(flat, man):
    """Rewrite the manifest (same length) with a VALID carrier CRC: CRC is not authentication."""
    put_bytes(flat, 128, man)
    put_bytes(flat, 128 + 8 * len(man), struct.pack(">I", zlib.crc32(bytes(man))))


def parse_manifest(man):
    magic, ver, seg, sel, ch, w, h, cell, n, rrows, plen, maplen = struct.unpack(">4sBBBBHHBBHII", bytes(man[:24]))
    assert magic == b"IOPM"
    entries = [struct.unpack(">BBHII", bytes(man[24 + 12 * i:36 + 12 * i])) for i in range(n)]
    rows, cols = -(-h // cell), -(-w // cell)
    labels, i, data = [], 0, man[24 + 12 * n:]
    while i < len(data):
        lab = data[i]
        i += 1
        run, shift = 0, 0
        while True:
            b = data[i]
            i += 1
            run |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        labels += [lab] * run
    assert len(labels) == rows * cols, "map does not cover the grid"
    grid = np.array(labels, dtype=np.uint8).reshape(rows, cols)
    px = np.repeat(np.repeat(grid, cell, 0), cell, 1)[:h, :w].copy()
    return {"channels": ch, "width": w, "height": h, "cell": cell, "n": n, "reserved_rows": rrows, "payload_len": plen,
            "entries": entries, "pixel_labels": px, "map_offset": 24 + 12 * n, "map_len": maplen}


if mode in ("make-cover", "make-mixed-cover"):
    rng = np.random.default_rng(7)
    h, w = 240, 320
    y, x = np.mgrid[0:h, 0:w].astype(np.float64)
    if mode == "make-cover":
        # natural-looking RGB test cover (smooth gradients + seeded noise): stands in for a webcam frame
        base = [110 + 60 * np.sin(x / 37.0 + k) + 40 * np.cos(y / 29.0 - k) + 0.15 * x for k in range(3)]
        img = np.stack([np.clip(b + rng.normal(0, 7, (h, w)), 0, 255) for b in base], axis=-1).astype(np.uint8)
    else:
        # sky / smooth ramp / textured / edged areas in one frame, so that patches differ in character
        g = np.full((h, w), 120.0)
        g[: h // 3] = 205 + 0.02 * x[: h // 3]
        g[h // 3: 2 * h // 3, : w // 2] = 85 + 55 * np.sin(x[h // 3: 2 * h // 3, : w // 2] / 5.0) + rng.normal(0, 14, (h // 3, w // 2))
        g[h // 3: 2 * h // 3, w // 2:] = 60 + 0.5 * x[h // 3: 2 * h // 3, w // 2:]
        g[2 * h // 3:] = 110 + rng.normal(0, 28, (h - 2 * h // 3, w))
        g[2 * h // 3:, ::16] = 30
        img = np.clip(np.stack([g, g * 0.9 + 10, g * 0.8 + 25 + rng.normal(0, 2, (h, w))], axis=-1), 4, 251).astype(np.uint8)
    Image.fromarray(img, "RGB").save(path, format="PNG")
elif mode == "truncate":
    data = open(path, "rb").read()
    open(path, "wb").write(data[: len(data) // 2])
elif mode == "garbage":
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + b"not really a png" * 4)
elif mode == "jpeg":
    im = load()
    buf = io.BytesIO()
    im.convert("RGB").save(buf, format="JPEG", quality=90)
    buf.seek(0)
    Image.open(buf).convert(im.mode).save(path, format="PNG")
else:
    arr = np.array(load(), dtype=np.uint8)
    flat = arr.reshape(-1)
    if mode == "blank":
        flat[:] = 128
    elif mode == "dump":
        pre, man, mlen, flen = read_carrier(flat)
        m = parse_manifest(man)
        crc_ok = bytes(get_bytes(flat, 128 + 8 * mlen, 4)) == struct.pack(">I", zlib.crc32(bytes(man)))
        counts = np.bincount(m["pixel_labels"].reshape(-1), minlength=m["n"]).tolist()
        print(json.dumps({"manifest_len": mlen, "frame_len": flen, "crc_ok": crc_ok, "width": m["width"], "height": m["height"],
                          "channels": m["channels"], "cell": m["cell"], "patch_count": m["n"], "reserved_rows": m["reserved_rows"],
                          "payload_len": m["payload_len"], "pixels_per_patch": counts,
                          "patches": [{"patch_id": i, "alg_id": e[0], "param": e[1], "offset": e[3], "length": e[4]} for i, e in enumerate(m["entries"])]}))
        sys.exit(0)
    elif mode == "carrier-flip":          # flip one carrier LSB (no CRC repair)
        flat[int(args[0])] ^= 1
    elif mode == "preamble-set":          # field value, CRC repaired
        pre, man, mlen, flen = read_carrier(flat)
        field, value = args[0], int(args[1])
        if field == "version":
            pre[2] = value
        elif field == "flags":
            pre[3] = value
        elif field == "manifest_len":
            pre[4:8] = struct.pack(">I", (mlen + value) & 0xFFFFFFFF if args[1][0] in "+-" else value)
        elif field == "frame_len":
            pre[8:12] = struct.pack(">I", (flen + value) & 0xFFFFFFFF if args[1][0] in "+-" else value)
        else:
            sys.exit("unknown preamble field")
        write_preamble(flat, pre)
    elif mode == "manifest-entry":        # patch field value   (carrier CRC repaired)
        pre, man, mlen, flen = read_carrier(flat)
        patch, field, value = int(args[0]), args[1], int(args[2])
        base = 24 + 12 * patch
        if field == "alg":
            man[base] = value
        elif field == "param":
            man[base + 1] = value
        elif field == "offset":
            man[base + 4:base + 8] = struct.pack(">I", value)
        elif field == "length":
            man[base + 8:base + 12] = struct.pack(">I", value)
        else:
            sys.exit("unknown entry field")
        write_manifest(flat, man)
    elif mode == "manifest-move-byte":    # shift one payload byte between two used patches (still contiguous)
        pre, man, mlen, flen = read_carrier(flat)
        m = parse_manifest(man)
        used = [i for i, e in enumerate(m["entries"]) if e[0]]
        a, b = used[0], used[1]
        ea, eb = m["entries"][a], m["entries"][b]
        man[24 + 12 * a + 8:24 + 12 * a + 12] = struct.pack(">I", ea[4] - 1)
        man[24 + 12 * b + 4:24 + 12 * b + 8] = struct.pack(">I", eb[3] - 1)
        man[24 + 12 * b + 8:24 + 12 * b + 12] = struct.pack(">I", eb[4] + 1)
        write_manifest(flat, man)
    elif mode == "manifest-byte":         # absolute manifest byte offset, value (carrier CRC repaired)
        pre, man, mlen, flen = read_carrier(flat)
        off = int(args[0])
        man[off if off >= 0 else len(man) + off] = int(args[1])
        write_manifest(flat, man)
    elif mode == "manifest-relabel":      # relabel the first map run from patch a to patch b (carrier CRC repaired)
        pre, man, mlen, flen = read_carrier(flat)
        m = parse_manifest(man)
        a, b = int(args[0]), int(args[1])
        i, data = m["map_offset"], man
        prev = None
        done = False
        while i < len(data):
            lab_pos = i
            i += 1
            while data[i] & 0x80:
                i += 1
            i += 1
            nxt = data[i] if i < len(data) else None
            if data[lab_pos] == a and prev != b and nxt != b:
                data[lab_pos] = b
                done = True
                break
            prev = data[lab_pos]
        if not done:
            sys.exit("no relabelable run")
        write_manifest(flat, man)
    elif mode == "flip-patch":            # patch_id [count]: flip LSBs of pixels inside one patch (payload area)
        pre, man, mlen, flen = read_carrier(flat)
        m = parse_manifest(man)
        lab = m["pixel_labels"]
        lab[: m["reserved_rows"]] = 255
        ys, xs = np.nonzero(lab == int(args[0]))
        k = int(args[1]) if len(args) > 1 else ys.size
        arr[ys[:k], xs[:k]] ^= 1
    else:
        sys.exit("unknown mode")
    save(arr)
