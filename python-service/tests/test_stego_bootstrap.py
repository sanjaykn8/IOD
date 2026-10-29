import io
import struct
import zlib

import numpy as np
import pytest
from PIL import Image

from stego import bootstrap, codec, images, service
from stego.algorithms import get_by_name
from stego.artifacts import ArtifactStore, new_id
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import natural_cover, payload

COVER = natural_cover(96, 128, 3)
LIM = Limits()


def stego_with(alg="lsb_replacement", data=b"frame-bytes-0123456789", param=0, cover=COVER):
    a = get_by_name(alg)
    stego, _ = codec.embed_frame(cover, a, param, data)
    return stego


def with_bootstrap(arr, raw16):
    out = arr.copy()
    bootstrap.write(out.reshape(-1), raw16)
    return out


def code_of(fn, *a, **k):
    with pytest.raises(StegoError) as ei:
        fn(*a, **k)
    return ei.value.code


def test_pack_parse_roundtrip_layout():
    raw = bootstrap.pack(3, 0, 1234)
    assert len(raw) == 16 and raw[:2] == b"SB" and raw[2] == 1 and raw[3] == 3
    assert struct.unpack(">I", raw[12:])[0] == zlib.crc32(raw[:12])
    bs = bootstrap.parse(raw)
    assert (bs.version, bs.alg_id, bs.param, bs.flags, bs.frame_len) == (1, 3, 0, 0, 1234)


def test_pack_rejects_out_of_range():
    for kw in ({"alg_id": 256}, {"param": -1}, {"frame_len": 2**32}):
        args = dict(alg_id=1, param=0, frame_len=1)
        args.update(kw)
        assert code_of(bootstrap.pack, **args) == "INVALID_REQUEST"


@pytest.mark.parametrize("alg", ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"])
def test_frame_roundtrip_all_algorithms(alg):
    s = stego_with(alg)
    frame, bs, a = codec.extract_frame(s, LIM)
    assert frame == b"frame-bytes-0123456789" and a.name == alg and bs.frame_len == 22


def test_bootstrap_bits_are_msb_first_lsb_of_first_128_samples():
    s = stego_with()
    bits = s.reshape(-1)[:128] & 1
    assert np.packbits(bits).tobytes() == bootstrap.pack(1, 0, 22)


def test_clean_image_has_no_bootstrap():
    assert code_of(codec.extract_frame, COVER, LIM) == "BOOTSTRAP_MISSING"


@pytest.mark.parametrize("bit", [0, 8, 15])  # magic bits
def test_corrupt_magic(bit):
    s = stego_with()
    s.reshape(-1)[bit] ^= 1
    assert code_of(codec.extract_frame, s, LIM) == "BOOTSTRAP_MISSING"


@pytest.mark.parametrize("bit", [24, 30, 48, 60, 80, 90, 96, 100, 110, 127])  # body fields + CRC
def test_single_bit_flip_in_bootstrap_detected(bit):
    s = stego_with()
    s.reshape(-1)[bit] ^= 1
    assert code_of(codec.extract_frame, s, LIM) in ("BOOTSTRAP_CORRUPT", "UNSUPPORTED_VERSION")


def test_bad_crc():
    raw = bytearray(bootstrap.pack(1, 0, 22))
    raw[12] ^= 0xFF
    assert code_of(codec.extract_frame, with_bootstrap(COVER, bytes(raw)), LIM) == "BOOTSTRAP_CORRUPT"


def test_invalid_version():
    raw = bootstrap.pack(1, 0, 22, version=2)
    assert code_of(codec.extract_frame, with_bootstrap(COVER, raw), LIM) == "UNSUPPORTED_VERSION"


@pytest.mark.parametrize("alg_id", [0, 6, 9, 255])
def test_invalid_algorithm_id(alg_id):
    raw = bootstrap.pack(alg_id, 0, 22)
    assert code_of(codec.extract_frame, with_bootstrap(COVER, raw), LIM) == "UNKNOWN_ALGORITHM"


def test_nonzero_flags_and_reserved():
    assert code_of(codec.extract_frame, with_bootstrap(COVER, bootstrap.pack(1, 0, 22, flags=1)), LIM) == "BOOTSTRAP_CORRUPT"
    assert code_of(codec.extract_frame, with_bootstrap(COVER, bootstrap.pack(1, 0, 22, reserved=7)), LIM) == "BOOTSTRAP_CORRUPT"


@pytest.mark.parametrize("alg_id,param", [(3, 5), (5, 3), (5, 65), (1, 1)])
def test_invalid_param_for_algorithm(alg_id, param):
    assert code_of(codec.extract_frame, with_bootstrap(COVER, bootstrap.pack(alg_id, param, 4)), LIM) == "BOOTSTRAP_CORRUPT"


def test_frame_len_bounds():
    cap = get_by_name("lsb_replacement").capacity_bits(COVER) // 8
    ok = with_bootstrap(COVER, bootstrap.pack(1, 0, cap))
    assert len(codec.extract_frame(ok, LIM)[0]) == cap  # exactly at capacity is fine
    for ln in (0, cap + 1, 2**32 - 1):
        assert code_of(codec.extract_frame, with_bootstrap(COVER, bootstrap.pack(1, 0, ln)), LIM) == "FRAME_LENGTH_INVALID"
    # configured frame ceiling lower than a valid length
    assert code_of(codec.extract_frame, ok, Limits(max_frame_bytes=cap - 1)) == "FRAME_LENGTH_INVALID"


def test_frame_len_vs_algorithm_specific_capacity():
    cap = get_by_name("dct").capacity_bits(COVER) // 8
    bad = with_bootstrap(COVER, bootstrap.pack(5, 0, cap + 1))
    assert code_of(codec.extract_frame, bad, LIM) == "FRAME_LENGTH_INVALID"
    flat = np.full((64, 64), 128, np.uint8)
    assert code_of(codec.extract_frame, with_bootstrap(flat, bootstrap.pack(4, 0, 1)), LIM) == "FRAME_LENGTH_INVALID"


def test_truncated_frame_len_yields_prefix():
    s = stego_with(data=bytes(range(30)))
    flat = s.reshape(-1)
    bootstrap.write(flat, bootstrap.pack(1, 0, 10))
    assert codec.extract_frame(s, LIM)[0] == bytes(range(10))


def test_damaged_payload_is_not_detectable_by_python():
    """Payload authentication is Rust's job (frame MAC); Python returns the damaged bytes."""
    s = stego_with(data=b"A" * 40)
    s.reshape(-1)[128 + 17] ^= 1
    frame = codec.extract_frame(s, LIM)[0]
    assert frame != b"A" * 40 and len(frame) == 40


def test_tampered_edge_mask_gives_structured_error_or_other_bytes():
    s = stego_with("edge_adaptive_lsb")
    s[:] = 128  # destroy texture -> mask collapses
    s2 = with_bootstrap(s, bootstrap.pack(4, 0, 22))
    assert code_of(codec.extract_frame, s2, LIM) == "FRAME_LENGTH_INVALID"


# -------- image-level checks through the service (PNG files) --------
@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "art")


def put(store, data):
    aid = new_id()
    store.write(aid, "stego", data)
    return aid


def pil_bytes(img, fmt="PNG"):
    b = io.BytesIO()
    img.save(b, format=fmt)
    return b.getvalue()


def test_extract_tampered_png_structured(store):
    s = stego_with()
    s.reshape(-1)[3] ^= 1
    aid = put(store, images.encode_png(s))
    assert code_of(service.extract_artifact, {"artifact_id": aid}, store) == "BOOTSTRAP_MISSING"


@pytest.mark.parametrize("mode", ["RGBA", "P", "1", "LA", "I;16"])
def test_wrong_image_mode(store, mode):
    img = Image.new(mode, (64, 64))
    aid = put(store, pil_bytes(img))
    assert code_of(service.extract_artifact, {"artifact_id": aid}, store) == "UNSUPPORTED_IMAGE_MODE"


def test_too_small_and_too_large(store):
    assert code_of(service.extract_artifact, {"artifact_id": put(store, pil_bytes(Image.new("L", (31, 64))))}, store) == "IMAGE_TOO_SMALL"
    assert code_of(service.extract_artifact, {"artifact_id": put(store, pil_bytes(Image.new("L", (64, 31))))}, store) == "IMAGE_TOO_SMALL"
    big = put(store, pil_bytes(Image.new("L", (4097, 32))))
    assert code_of(service.extract_artifact, {"artifact_id": big}, store) == "IMAGE_TOO_LARGE"
    ok = put(store, images.encode_png(stego_with()))
    assert code_of(service.extract_artifact, {"artifact_id": ok, "limits": {"max_width": 64}}, store) == "IMAGE_TOO_LARGE"
    assert service.extract_artifact({"artifact_id": ok, "limits": {"max_width": 100000}}, store)["ok"]  # cannot raise ceilings


def test_not_a_png(store):
    jpg = put(store, pil_bytes(Image.new("RGB", (64, 64)), "JPEG"))
    assert code_of(service.extract_artifact, {"artifact_id": jpg}, store) == "IMAGE_DECODE_ERROR"
    assert code_of(service.extract_artifact, {"artifact_id": put(store, b"garbage")}, store) == "IMAGE_DECODE_ERROR"
    assert code_of(service.extract_artifact, {"artifact_id": put(store, b"")}, store) == "IMAGE_DECODE_ERROR"


def test_truncated_png(store):
    data = images.encode_png(stego_with())
    assert code_of(service.extract_artifact, {"artifact_id": put(store, data[: len(data) // 2])}, store) == "IMAGE_DECODE_ERROR"


def test_check_array_validation():
    for bad in (np.zeros((40, 40), np.int16), np.zeros((40, 40, 4), np.uint8), np.zeros((40,), np.uint8), [1]):
        assert code_of(images.check_array, bad, LIM) == "UNSUPPORTED_IMAGE_MODE"
    assert code_of(images.check_array, np.zeros((31, 40), np.uint8), LIM) == "IMAGE_TOO_SMALL"
    assert code_of(codec.extract_frame, np.zeros((31, 40), np.uint8), LIM) == "IMAGE_TOO_SMALL"
