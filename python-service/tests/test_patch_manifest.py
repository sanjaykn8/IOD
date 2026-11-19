"""Manifest v2, bootstrap-v3 pixel mapping and Frame v3 structure: exact layouts, canonical encoding, strict rejection."""
import struct
import zlib

import numpy as np
import pytest

from stego import bootstrap as B
from stego.errors import StegoError
from stego.patch import manifest as M


def tiny_manifest():
    """64x64 RGB image, cell 16 -> 4x4 cell grid, two patches; the 40 payload bytes are in patch 1."""
    lab = np.array([[0, 0, 1, 1], [0, 1, 1, 1], [0, 1, 1, 1], [0, 0, 0, 1]], np.uint8)
    mlen = M.manifest_len_for(2, len(M.rle_encode(lab)))
    return M.Manifest(3, 64, 64, 16, M.carrier_pixels_for(mlen, 3), 40, (M.PatchEntry(0, 0, 0, 0), M.PatchEntry(1, 0, 0, 40)), lab)


def test_manifest_test_vector_exact_bytes():
    """The documented test vector (docs/patchwise-transport.md section 6; rust-core manifest.rs pins the same bytes)."""
    m = tiny_manifest()
    data = M.pack(m)
    # runs may span rows: 0x2 1x2 0x1 1x3 0x1 1x3 0x3 1x1
    rle = bytes([0, 2, 1, 2, 0, 1, 1, 3, 0, 1, 1, 3, 0, 3, 1, 1])
    assert M.rle_encode(m.cell_labels) == rle
    assert M.manifest_len_for(2, 16) == 24 + 2 * 12 + 16 == 64 == len(data)
    # R = ceil((96 + 8 * (64 + 64 + 4)) / 3) = 384 carrier pixels (<= 64 * 64 / 8 = 512)
    assert M.carrier_pixels_for(64, 3) == 384 == m.carrier_pixels
    fixed = b"IOPM" + bytes([2, 1, 2, 3]) + struct.pack(">HHBBHII", 64, 64, 16, 2, 384, 40, 16)
    entries = struct.pack(">BBHII", 0, 0, 0, 0, 0) + struct.pack(">BBHII", 1, 0, 0, 0, 40)
    assert data == fixed + entries + rle
    assert data.hex() == ("494f504d020102030040004010020180000000280000001000000000000000000000000001000000000000000000002800020102000101030001010300030101")
    assert M.parse(data).patches == m.patches


def realistic(n=5, h=96, w=128, ch=3, cell=8, plen=200):
    rows, cols = M.grid_shape(h, w, cell)
    lab = (np.arange(rows * cols).reshape(rows, cols) * n // (rows * cols)).astype(np.uint8)
    mlen = M.manifest_len_for(n, len(M.rle_encode(lab)))
    per = plen // (n - 1)
    ents, off = [M.PatchEntry(0, 0, 0, 0)], 0
    for i in range(1, n):
        ln = per if i < n - 1 else plen - off
        ents.append(M.PatchEntry(i, 0, off, ln))
        off += ln
    return M.Manifest(ch, w, h, cell, M.carrier_pixels_for(mlen, ch), plen, tuple(ents), lab)


def test_pack_parse_round_trip_and_masks():
    m = realistic()
    data = M.pack(m)
    p = M.parse(data)
    assert p.patches == m.patches and np.array_equal(p.cell_labels, m.cell_labels)
    assert (p.width, p.height, p.channels, p.cell, p.carrier_pixels, p.payload_len) == (128, 96, 3, 8, m.carrier_pixels, 200)
    assert p.carrier_pixels == -(-(96 + 8 * (len(data) + 64 + 4)) // 3)
    lab = M.pixel_labels(p)
    assert lab.shape == (96, 128)
    values = np.random.default_rng(1).integers(0, 2 ** 32, 8192, dtype=np.int64)
    car = M.carrier_positions(p, values)
    assert len(car) == p.carrier_pixels == len(set(car.tolist()))
    eff = M.effective_masks(p, car)
    flat = eff.reshape(-1)
    assert np.all(flat[car] == 255)
    keep = np.ones(flat.size, bool)
    keep[car] = False
    assert np.array_equal(flat[keep], lab.reshape(-1)[keep]), "only the carrier pixels are removed; no rows are reserved"
    rows = np.unique(car // 128)
    assert rows.size > 48, "carrier pixels are spread over the image"
    with pytest.raises(StegoError) as e:
        M.carrier_positions(p, values[:100])
    assert e.value.code == "BOOTSTRAP_CORRUPT"


def _mut(data, off, fmt, value):
    b = bytearray(data)
    struct.pack_into(fmt, b, off, value)
    return bytes(b)


@pytest.mark.parametrize("mutate,code", [
    (lambda d: b"XOPM" + d[4:], "MANIFEST_INVALID"),
    (lambda d: _mut(d, 4, ">B", 1), "UNSUPPORTED_VERSION"),          # manifest v1
    (lambda d: _mut(d, 4, ">B", 3), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 5, ">B", 9), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 6, ">B", 9), "UNSUPPORTED_VERSION"),
    (lambda d: _mut(d, 7, ">B", 2), "MANIFEST_INVALID"),            # channels
    (lambda d: _mut(d, 8, ">H", 0), "MANIFEST_INVALID"),            # width 0
    (lambda d: _mut(d, 8, ">H", 60000), "MANIFEST_INVALID"),        # width > limit
    (lambda d: _mut(d, 12, ">B", 5), "MANIFEST_INVALID"),           # cell not whitelisted
    (lambda d: _mut(d, 13, ">B", 0), "MANIFEST_INVALID"),           # zero patches
    (lambda d: _mut(d, 13, ">B", 6), "MANIFEST_INVALID"),           # count/length mismatch
    (lambda d: _mut(d, 14, ">H", 1), "MANIFEST_INVALID"),           # carrier_pixels not canonical
    (lambda d: _mut(d, 14, ">H", 0xFFFF), "MANIFEST_INVALID"),
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
        M.pack(M.Manifest(m.channels, m.width, m.height, m.cell, m.carrier_pixels, m.payload_len, m.patches, lab))


# ------------------------------------------------------------------ bootstrap v3 (pixel side only)
def test_carrier_pixels_must_fit_an_eighth_of_the_image():
    m = realistic(h=32, w=32, ch=1, plen=200)      # R far above 32 * 32 / 8
    with pytest.raises(StegoError) as e:
        M.pack(m)
    assert e.value.code == "MANIFEST_INVALID"


def test_positions_are_first_distinct_values_in_stream_order():
    vals = np.array([5, 17, 5, 3, 105, 9, 3], dtype=np.int64)       # mod 100 -> 5 17 5 3 5 9 3
    assert B.positions(vals, 100).tolist() == [5, 17, 3, 9]
    # a prefix of the stream maps to a prefix of the positions (discovery reads only the first values)
    v = np.random.default_rng(2).integers(0, 2 ** 32, 8192, dtype=np.int64)
    full, pre = B.positions(v, 320 * 240), B.positions(v[:128], 320 * 240)
    assert np.array_equal(full[:len(pre)], pre)


def test_bit_io_round_trip_with_lsb_matching():
    rng = np.random.default_rng(3)
    img = rng.integers(0, 256, (96, 128, 3), dtype=np.uint8)
    img[0, :8] = 0                                            # saturated samples are handled
    img[1, :8] = 255
    orig = img.copy()
    v = rng.integers(0, 2 ** 32, 4096, dtype=np.int64)
    v[:16] = np.arange(16) + np.array([0] * 8 + [120] * 8)   # include saturated pixels
    pos = B.positions(v, 96 * 128)
    data = bytes(rng.integers(0, 256, 300, dtype=np.uint8))
    changed = B.write_bits(img, pos, data, 8 * len(data))
    assert B.read_bits(img, pos, 0, 8 * len(data)) == data
    assert B.read_bits(img, pos, 96, 64) == data[12:20]
    d = img.astype(int) - orig.astype(int)
    assert np.abs(d).max() == 1 and np.count_nonzero(d) == changed > 0, "+-1 changes only"
    touched = np.zeros(96 * 128, bool)
    touched[pos[:-(-8 * len(data) // 3)]] = True
    assert not np.any(d.reshape(-1, 3).any(axis=1) & ~touched), "nothing outside the carrier slots changes"
    with pytest.raises(StegoError) as e:
        B.read_bits(img, pos[:10], 0, 96 * 3)
    assert e.value.code == "BOOTSTRAP_CORRUPT"
    with pytest.raises(StegoError):
        B.read_bits(img, pos, 0, 7)


def test_value_and_bit_decoding_is_bounded():
    import base64
    with pytest.raises(StegoError):
        B.decode_values("")
    with pytest.raises(StegoError):
        B.decode_values(base64.b64encode(b"abc").decode())        # not a multiple of 4
    with pytest.raises(StegoError):
        B.decode_values(base64.b64encode(b"\0" * (4 * B.MAX_VALUES + 4)).decode())
    with pytest.raises(StegoError):
        B.decode_values("!!!!")
    assert B.decode_values(base64.b64encode(struct.pack(">II", 7, 2 ** 32 - 1)).decode()).tolist() == [7, 2 ** 32 - 1]


def test_deflate_is_raw_and_within_the_reserve_bound():
    man = M.pack(realistic())
    d = B.deflate(man)
    assert zlib.decompress(d, -15) == man
    noise = bytes(np.random.default_rng(4).integers(0, 256, 5000, dtype=np.uint8))
    assert len(B.deflate(noise)) <= len(noise) + B.DEFLATE_SLACK
    assert B.carrier_bits_for(len(d)) <= M.carrier_pixels_for(len(man), 3) * 3


def test_legacy_v2_preamble_is_recognised():
    img = np.full((64, 64, 3), 128, np.uint8)
    assert not B.legacy_v2_preamble(img)
    body = struct.pack(">2sBBII", b"SB", 2, 0, 100, 400)
    pre = body + struct.pack(">I", zlib.crc32(body))
    bits = np.unpackbits(np.frombuffer(pre, dtype=np.uint8))
    flat = img.reshape(-1)
    flat[:128] = (flat[:128] & 0xFE) | bits
    assert B.legacy_v2_preamble(img)
    flat[127] ^= 1
    assert not B.legacy_v2_preamble(img)


# ------------------------------------------------------------------ frame v3 structure
def test_frame_header_and_split():
    man = M.pack(realistic())
    wire = bytes(range(168))
    frame = M.frame_header(len(man), len(wire)) + man + wire + b"T" * 32
    assert frame[:16] == b"IOD3" + bytes([3, 0, 0, 0]) + struct.pack(">II", len(man), 168)
    assert len(frame) == M.frame_len_for(len(man), 168)
    mb, payload = M.split_frame(frame, 8192)
    assert mb == man and payload == wire + b"T" * 32
    for bad, code in ((b"IODF" + frame[4:], "FRAME_MALFORMED"), (b"IOD2" + frame[4:], "FRAME_MALFORMED"), (frame[:4] + b"\x01" + frame[5:], "UNSUPPORTED_VERSION"),
                      (frame[:5] + b"\x01" + frame[6:], "FRAME_MALFORMED"), (frame[:-1], "FRAME_MALFORMED"),
                      (frame + b"x", "FRAME_MALFORMED"), (frame[:20], "FRAME_MALFORMED")):
        with pytest.raises(StegoError) as e:
            M.split_frame(bad, 8192)
        assert e.value.code == code
    with pytest.raises(StegoError) as e:
        M.split_frame(frame, 100)
    assert e.value.code == "FRAME_TOO_LARGE"
