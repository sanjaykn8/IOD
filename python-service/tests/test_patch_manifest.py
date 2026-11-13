"""Manifest v1, bootstrap v2 and Frame v2 structure: exact layouts, canonical encoding, strict rejection."""
import struct
import zlib

import numpy as np
import pytest

from stego import bootstrap as B
from stego.errors import StegoError
from stego.patch import manifest as M


def tiny_manifest():
    """64x64 gray image, cell 16 -> 4x4 cell grid, two patches; the 40 payload bytes are in patch 1."""
    lab = np.array([[0, 0, 1, 1], [0, 1, 1, 1], [0, 1, 1, 1], [0, 0, 0, 1]], np.uint8)
    mlen = M.manifest_len_for(2, len(M.rle_encode(lab)))
    rr = M.reserved_rows_for(mlen, 64, 1)
    return M.Manifest(1, 64, 64, 16, rr, 40, (M.PatchEntry(0, 0, 0, 0), M.PatchEntry(1, 0, 0, 40)), lab)


def test_manifest_test_vector_exact_bytes():
    """The documented test vector (docs/patchwise-transport.md section 6)."""
    m = tiny_manifest()
    data = M.pack(m)
    # runs may span rows: 0x2 1x2 0x1 1x3 0x1 1x3 0x3 1x1
    rle = bytes([0, 2, 1, 2, 0, 1, 1, 3, 0, 1, 1, 3, 0, 3, 1, 1])
    assert M.rle_encode(m.cell_labels) == rle
    assert M.manifest_len_for(2, 16) == 24 + 2 * 12 + 16 == 64 == len(data)
    # carrier = 16 + 64 + 4 bytes = 672 bits; 64 samples per row -> ceil(672 / 64) = 11 reserved rows
    assert M.carrier_bits(64) == 672 and m.reserved_rows == 11
    fixed = b"IOPM" + bytes([1, 1, 1, 1]) + struct.pack(">HHBBHII", 64, 64, 16, 2, 11, 40, 16)
    entries = struct.pack(">BBHII", 0, 0, 0, 0, 0) + struct.pack(">BBHII", 1, 0, 0, 0, 40)
    assert data == fixed + entries + rle
    assert data.hex() == ("494f504d01010101004000401002000b0000002800000010"
                          "000000000000000000000000" "010000000000000000000028"
                          "00020102000101030001010300030101")
    assert M.parse(data).patches == m.patches


def realistic(n=5, h=96, w=128, ch=3, cell=8, plen=200):
    rows, cols = M.grid_shape(h, w, cell)
    lab = (np.arange(rows * cols).reshape(rows, cols) * n // (rows * cols)).astype(np.uint8)
    mlen = M.manifest_len_for(n, len(M.rle_encode(lab)))
    rr = M.reserved_rows_for(mlen, w, ch)
    per = plen // (n - 1)
    ents, off = [M.PatchEntry(0, 0, 0, 0)], 0
    for i in range(1, n):
        ln = per if i < n - 1 else plen - off
        ents.append(M.PatchEntry(i, 0, off, ln))
        off += ln
    return M.Manifest(ch, w, h, cell, rr, plen, tuple(ents), lab)


def test_pack_parse_round_trip_and_masks():
    m = realistic()
    data = M.pack(m)
    p = M.parse(data)
    assert p.patches == m.patches and np.array_equal(p.cell_labels, m.cell_labels)
    assert (p.width, p.height, p.channels, p.cell, p.reserved_rows, p.payload_len) == (128, 96, 3, 8, m.reserved_rows, 200)
    lab = M.pixel_labels(p)
    assert lab.shape == (96, 128)
    eff = M.effective_masks(p)
    assert np.all(eff[:p.reserved_rows] == 255) and np.array_equal(eff[p.reserved_rows:], lab[p.reserved_rows:])
    assert p.reserved_rows == -(-8 * (16 + len(data) + 4) // (128 * 3))


def _mut(data, off, fmt, value):
    b = bytearray(data)
    struct.pack_into(fmt, b, off, value)
    return bytes(b)


@pytest.mark.parametrize("mutate,code", [
    (lambda d: b"XOPM" + d[4:], "MANIFEST_INVALID"),
    (lambda d: _mut(d, 4, ">B", 2), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 5, ">B", 9), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 6, ">B", 9), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 7, ">B", 2), "MANIFEST_INVALID"),            # channels
    (lambda d: _mut(d, 8, ">H", 0), "MANIFEST_INVALID"),            # width 0
    (lambda d: _mut(d, 8, ">H", 60000), "MANIFEST_INVALID"),        # width > limit
    (lambda d: _mut(d, 12, ">B", 5), "MANIFEST_INVALID"),           # cell not whitelisted
    (lambda d: _mut(d, 13, ">B", 0), "MANIFEST_INVALID"),           # zero patches
    (lambda d: _mut(d, 13, ">B", 6), "MANIFEST_INVALID"),           # count/length mismatch
    (lambda d: _mut(d, 14, ">H", 1), "MANIFEST_INVALID"),           # reserved rows lie
    (lambda d: _mut(d, 16, ">I", 201), "MANIFEST_INVALID"),         # payload_len != sum(chunks)
    (lambda d: _mut(d, 16, ">I", 0xFFFFFFFF), "MANIFEST_INVALID"),
    (lambda d: _mut(d, 20, ">I", 0xFFFFFFF0), "MANIFEST_INVALID"),  # map_len overflow
    (lambda d: _mut(d, 24 + 12, ">B", 11), "UNKNOWN_ALGORITHM"),
    (lambda d: _mut(d, 24 + 12, ">B", 255), "UNKNOWN_ALGORITHM"),
    (lambda d: _mut(d, 24 + 12 + 2, ">H", 1), "MANIFEST_INVALID"),  # flags
    (lambda d: _mut(d, 24 + 12 + 4, ">I", 1), "MANIFEST_INVALID"),  # first offset not 0
    (lambda d: _mut(d, 24 + 24 + 4, ">I", 49), "MANIFEST_INVALID"), # overlap
    (lambda d: _mut(d, 24 + 24 + 4, ">I", 51), "MANIFEST_INVALID"), # gap
    (lambda d: _mut(d, 24 + 12 + 8, ">I", 0), "MANIFEST_INVALID"),  # zero-length used chunk
    (lambda d: _mut(d, 24 + 12 + 8, ">I", 0xFFFFFFFF), "MANIFEST_INVALID"),
    (lambda d: _mut(d, 24 + 4, ">I", 7), "MANIFEST_INVALID"),       # unused patch with an offset
    (lambda d: d[:-1], "MANIFEST_INVALID"),
    (lambda d: d + b"\x00", "MANIFEST_INVALID"),
    (lambda d: d[:30], "MANIFEST_INVALID"),
    (lambda d: b"", "MANIFEST_INVALID"),
])
def test_parse_rejects_malformed_manifests(mutate, code):
    data = M.pack(realistic())
    with pytest.raises(StegoError) as e:
        M.parse(mutate(data))
    assert e.value.code == code


def test_parse_rejects_oversized_and_non_bytes():
    with pytest.raises(StegoError) as e:
        M.parse(b"\x00" * (M.MAX_MANIFEST_BYTES + 1))
    assert e.value.code == "MANIFEST_TOO_LARGE"
    with pytest.raises(StegoError):
        M.parse("text")


def test_rle_is_canonical_and_strict():
    lab = np.array([[0, 0, 0, 1], [1, 1, 2, 2], [2, 2, 2, 2]], np.uint8)
    enc = M.rle_encode(lab)
    assert enc == bytes([0, 3, 1, 3, 2, 6])
    assert np.array_equal(M.rle_decode(enc, 12, 3), lab.reshape(-1))
    long = np.zeros((1, 300), np.uint8)
    long[0, 200:] = 1
    e2 = M.rle_encode(long)
    assert e2 == bytes([0, 0xC8, 0x01, 1, 100]) and np.array_equal(M.rle_decode(e2, 300, 2), long.reshape(-1))
    bad = [
        bytes([0, 3, 1, 3, 2, 5]),          # too few cells
        bytes([0, 3, 1, 3, 2, 7]),          # too many cells
        bytes([0, 3, 1, 3, 3, 6]),          # label >= patch count
        bytes([0, 2, 0, 1, 1, 3, 2, 6]),    # adjacent equal labels (non-canonical)
        bytes([0, 0, 0, 3, 1, 3, 2, 6]),    # zero-length run
        bytes([0, 0x83, 0x00, 1, 3, 2, 6]), # non-minimal varint
        bytes([0, 3, 1, 3, 2]),             # truncated
        bytes([0, 3, 1, 3, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),  # varint overflow
    ]
    for b in bad:
        with pytest.raises(StegoError) as e:
            M.rle_decode(b, 12, 3)
        assert e.value.code == "MANIFEST_INVALID", b.hex()


def test_patch_missing_from_map_is_rejected():
    m = realistic()
    lab = m.cell_labels.copy()
    lab[lab == 4] = 3
    with pytest.raises(StegoError):
        M.pack(M.Manifest(m.channels, m.width, m.height, m.cell, m.reserved_rows, m.payload_len, m.patches, lab))


# ------------------------------------------------------------------ bootstrap v2
def test_preamble_test_vector_and_crc():
    pre = B.pack_preamble(64, 16 + 64 + 8 + 32)     # manifest of the test vector, 8-byte wire
    body = b"SB" + bytes([2, 0]) + struct.pack(">II", 64, 120)
    assert pre == body + struct.pack(">I", zlib.crc32(body)) and len(pre) == 16
    assert pre.hex() == "534202000000004000000078bccc9fc7"
    p = B.parse_preamble(pre, 4096)
    assert (p.version, p.manifest_len, p.frame_len) == (2, 64, 120)


@pytest.mark.parametrize("off,val,code", [(0, 0x00, "BOOTSTRAP_MISSING"), (2, 1, "UNSUPPORTED_VERSION"), (3, 1, "BOOTSTRAP_CORRUPT"),
                                          (7, 0x39, "BOOTSTRAP_CORRUPT"), (11, 0x71, "BOOTSTRAP_CORRUPT"), (15, 0, "BOOTSTRAP_CORRUPT")])
def test_preamble_corruption_fails_closed(off, val, code):
    pre = bytearray(B.pack_preamble(56, 112))
    pre[off] = val
    with pytest.raises(StegoError) as e:
        B.parse_preamble(bytes(pre), 4096)
    assert e.value.code == code


def _with_crc(body):
    return body + struct.pack(">I", zlib.crc32(body))


def test_preamble_semantic_checks_even_with_valid_crc():
    for mlen, flen in ((0, 200), (70000, 80000), (56, 60), (56, 5000)):
        raw = _with_crc(b"SB" + bytes([2, 0]) + struct.pack(">II", mlen, flen))
        with pytest.raises(StegoError):
            B.parse_preamble(raw, 4096)
    raw = _with_crc(b"SB" + bytes([3, 0]) + struct.pack(">II", 56, 112))
    with pytest.raises(StegoError) as e:
        B.parse_preamble(raw, 4096)
    assert e.value.code == "UNSUPPORTED_VERSION"


def test_carrier_round_trip_and_corruption():
    man = M.pack(realistic())
    flat = np.random.default_rng(3).integers(0, 256, 96 * 128 * 3, dtype=np.uint8)
    orig = flat.copy()
    bits = B.write_carrier(flat, man, 16 + len(man) + 200)
    assert bits == 8 * (16 + len(man) + 4) == M.carrier_bits(len(man))
    assert np.array_equal(flat[bits:], orig[bits:]) and np.all((flat[:bits] ^ orig[:bits]) <= 1)
    pre, got = B.read_carrier(flat, 4096)
    assert got == man and pre.manifest_len == len(man)
    t = flat.copy()
    t[8 * 16 + 77] ^= 1            # one manifest bit
    with pytest.raises(StegoError) as e:
        B.read_carrier(t, 4096)
    assert e.value.code == "BOOTSTRAP_CORRUPT"
    with pytest.raises(StegoError):
        B.read_carrier(flat[:300], 4096)   # truncated image


# ------------------------------------------------------------------ frame v2 structure
def test_frame_header_and_split():
    man = M.pack(realistic())
    wire = bytes(range(168))
    frame = M.frame_header(len(man), len(wire)) + man + wire + b"T" * 32
    assert frame[:16] == b"IOD2" + bytes([2, 0, 0, 0]) + struct.pack(">II", len(man), 168)
    assert len(frame) == M.frame_len_for(len(man), 168)
    mb, payload = M.split_frame(frame, 8192)
    assert mb == man and payload == wire + b"T" * 32
    for bad, code in ((b"IODF" + frame[4:], "FRAME_MALFORMED"), (frame[:4] + b"\x01" + frame[5:], "UNSUPPORTED_VERSION"),
                      (frame[:5] + b"\x01" + frame[6:], "FRAME_MALFORMED"), (frame[:-1], "FRAME_MALFORMED"),
                      (frame + b"x", "FRAME_MALFORMED"), (frame[:20], "FRAME_MALFORMED")):
        with pytest.raises(StegoError) as e:
            M.split_frame(bad, 8192)
        assert e.value.code == code
    with pytest.raises(StegoError) as e:
        M.split_frame(frame, 100)
    assert e.value.code == "FRAME_TOO_LARGE"
