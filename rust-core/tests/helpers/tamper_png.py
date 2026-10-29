"""Test helper: tamper with a saved stego PNG at the PIXEL level (stdlib+numpy+Pillow only).
Usage: python3 tamper_png.py <mode> <path> [arg]
Bootstrap layout (docs/stego-implementation-note.md §1.3): 16 bytes in the LSBs of samples [0,128).
"""
import sys, zlib, io
import numpy as np
from PIL import Image

mode, path = sys.argv[1], sys.argv[2]
arg = sys.argv[3] if len(sys.argv) > 3 else None


def load():
    with Image.open(path) as im:
        im.load()
        return im.copy()


def samples(im):
    return np.array(im, dtype=np.uint8).reshape(-1), np.array(im).shape


def save(flat, shape, im):
    Image.fromarray(flat.reshape(shape)).save(path, format="PNG")


def read_bootstrap(flat):
    bits = flat[:128] & 1
    return bytearray(np.packbits(bits).tobytes())


def write_bootstrap(flat, bs):
    bits = np.unpackbits(np.frombuffer(bytes(bs), dtype=np.uint8))
    flat[:128] = (flat[:128] & 0xFE) | bits


def recrc(bs):
    bs[12:16] = zlib.crc32(bytes(bs[:12])).to_bytes(4, "big")


if mode == "make-cover":
    # natural-looking RGB test cover (smooth gradients + seeded noise): stands in for a webcam frame
    rng = np.random.default_rng(7)
    h, w = 240, 320
    y, x = np.mgrid[0:h, 0:w]
    base = [110 + 60 * np.sin(x / 37.0 + k) + 40 * np.cos(y / 29.0 - k) + 0.15 * x for k in range(3)]
    img = np.stack([np.clip(b + rng.normal(0, 7, (h, w)), 0, 255) for b in base], axis=-1).astype(np.uint8)
    Image.fromarray(img, "RGB").save(path, format="PNG")
elif mode == "truncate":
    data = open(path, "rb").read()
    open(path, "wb").write(data[: len(data) // 2])
elif mode == "garbage":
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + b"not really a png" * 4)
elif mode == "blank":
    im = load()
    flat, shape = samples(im)
    flat[:] = 128
    save(flat, shape, im)
elif mode == "jpeg":
    im = load().convert("RGB")
    buf = io.BytesIO()
    im.save(buf, format="JPEG", quality=90)
    buf.seek(0)
    Image.open(buf).convert(load().mode).save(path, format="PNG")
else:
    im = load()
    flat, shape = samples(im)
    if mode == "flip-payload":  # flip the LSB of payload sample 128 + int(arg)
        flat[128 + int(arg or 0)] ^= 1
    elif mode == "flip-bootstrap-crc":
        flat[120] ^= 1
    elif mode == "set-alg":
        bs = read_bootstrap(flat)
        bs[3] = int(arg)
        recrc(bs)
        write_bootstrap(flat, bs)
    elif mode == "set-version":
        bs = read_bootstrap(flat)
        bs[2] = int(arg)
        recrc(bs)
        write_bootstrap(flat, bs)
    elif mode == "adjust-length":
        bs = read_bootstrap(flat)
        n = int.from_bytes(bs[6:10], "big") + int(arg)
        bs[6:10] = n.to_bytes(4, "big")
        recrc(bs)
        write_bootstrap(flat, bs)
    elif mode == "huge-length":
        bs = read_bootstrap(flat)
        bs[6:10] = (0x7FFFFFFF).to_bytes(4, "big")
        recrc(bs)
        write_bootstrap(flat, bs)
    else:
        sys.exit("unknown mode")
    save(flat, shape, im)
