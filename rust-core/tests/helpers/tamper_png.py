"""Test helper: inspect / tamper with a saved patch-wise stego PNG at the PIXEL level.

Deliberately INDEPENDENT of the image service's code (stdlib + numpy + Pillow only): it re-implements
the documented layouts (docs/bootstrap-v3-design.md, docs/patchwise-transport.md), so it doubles as a
cross-check of the format. It holds no key: the Rust test derives the frame's value stream (and decrypts or
re-encrypts the carrier) and passes the value stream in a file.

  carrier pixels P = first distinct values of (v_i mod (W*H)), v_i = big-endian u32 from the value file
  sample slot k    = pixel P[k div C], channel k mod C
  manifest v2: 24-byte fixed part (carrier_pixels at bytes 14..16), 12 bytes per patch, RLE cell map

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


def positions(values_file, n_pixels):
    v = np.frombuffer(open(values_file, "rb").read(), dtype=">u4").astype(np.int64) % n_pixels
    _, first = np.unique(v, return_index=True)
    return v[np.sort(first)]


def slots(arr, pos, start, n):
    c = 1 if arr.ndim == 2 else arr.shape[2]
    k = np.arange(start, start + n)
    return pos[k // c] * c + k % c


def parse_manifest(man):
    magic, ver, seg, sel, ch, w, h, cell, n, cpix, plen, maplen = struct.unpack(">4sBBBBHHBBHII", bytes(man[:24]))
    assert magic == b"IOPM" and ver == 2, "not a manifest v2"
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
    return {"channels": ch, "width": w, "height": h, "cell": cell, "n": n, "carrier_pixels": cpix, "payload_len": plen,
            "entries": entries, "pixel_labels": px}


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
    npix = arr.shape[0] * arr.shape[1]
    if mode == "blank":
        flat[:] = 128
    elif mode == "legacy-v2":             # blank image carrying a valid retired bootstrap-v2 preamble in the top-row LSBs
        flat[:] = 128
        body = struct.pack(">2sBBII", b"SB", 2, 0, 100, 400)
        pre = body + struct.pack(">I", zlib.crc32(body))
        bits = np.unpackbits(np.frombuffer(pre, dtype=np.uint8))
        flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    elif mode == "read-bits":             # values_file start n_bits -> hex
        pos = positions(args[0], npix)
        print(np.packbits(flat[slots(arr, pos, int(args[1]), int(args[2]))] & 1).tobytes().hex())
        sys.exit(0)
    elif mode == "write-bits":            # values_file hex: set the LSBs of slots 0.. to the given bits (+-1 change)
        pos = positions(args[0], npix)
        bits = np.unpackbits(np.frombuffer(bytes.fromhex(args[1]), dtype=np.uint8))
        idx = slots(arr, pos, 0, bits.size)
        diff = idx[(flat[idx] & 1) != bits]
        flat[diff] = np.where(flat[diff] == 255, 254, flat[diff] + 1)
    elif mode == "carrier-flip":          # values_file slot: flip one carrier LSB (no repair)
        pos = positions(args[0], npix)
        k = slots(arr, pos, int(args[1]), 1)[0]
        flat[k] = flat[k] - 1 if flat[k] & 1 else flat[k] + 1
    elif mode == "dump":                  # values_file manifest_hex -> independent view of the patch layout
        m = parse_manifest(bytes.fromhex(args[1]))
        pos = positions(args[0], npix)[:m["carrier_pixels"]]
        lab = m["pixel_labels"]
        counts = np.bincount(lab.reshape(-1), minlength=m["n"]).tolist()
        eff = lab.copy().reshape(-1)
        eff[pos] = 255
        usable = np.bincount(eff[eff != 255], minlength=m["n"]).tolist()
        rows_touched = sorted(set((pos // m["width"]).tolist()))
        print(json.dumps({"width": m["width"], "height": m["height"], "channels": m["channels"], "cell": m["cell"],
                          "patch_count": m["n"], "carrier_pixels": m["carrier_pixels"], "carrier_pixels_distinct": int(len(set(pos.tolist()))),
                          "carrier_rows_touched": len(rows_touched), "payload_len": m["payload_len"],
                          "pixels_per_patch": counts, "usable_pixels_per_patch": usable,
                          "patches": [{"patch_id": i, "alg_id": e[0], "param": e[1], "offset": e[3], "length": e[4]} for i, e in enumerate(m["entries"])]}))
        sys.exit(0)
    elif mode == "flip-patch":            # values_file manifest_hex patch_id [count] [cover]: damage pixels inside one patch.
        # Bit 0 AND bit 7 are toggled so LSB-plane and transform-domain embeddings are both disturbed.
        m = parse_manifest(bytes.fromhex(args[1]))
        lab = m["pixel_labels"]
        lab.reshape(-1)[positions(args[0], npix)[:m["carrier_pixels"]]] = 255
        ys, xs = np.nonzero(lab == int(args[2]))
        k = int(args[3]) if len(args) > 3 else ys.size
        if len(args) > 4:
            # partial damage: only pixels the embedding actually modified (stego != cover)
            cov = np.asarray(Image.open(args[4]))
            ch = (cov != arr).reshape(arr.shape[0], arr.shape[1], -1).any(axis=2)[ys, xs]
            ys, xs = ys[ch], xs[ch]
            if ys.size == 0:
                sys.exit("patch has no modified pixel")
        arr[ys[:k], xs[:k]] ^= 0x81
    else:
        sys.exit("unknown mode")
    save(arr)
