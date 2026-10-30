import numpy as np
import pytest

from stego import images
from stego.algorithms import _ALL, get_by_name
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import natural_cover, payload

ALGS = [a.name for a in _ALL]
# 256x256 so that every algorithm (including 1-bit-per-8x8-block dct_svd) holds the 120-byte vectors
COVERS = {"rgb": natural_cover(256, 256, 3), "gray": natural_cover(256, 256, 1, seed=11)}
CODES = ("CAPACITY_INSUFFICIENT", "EDGE_CAPACITY_INSUFFICIENT")


def png_roundtrip(arr):
    out, tr = images.decode_png(images.encode_png(arr), Limits(), convert=False)
    assert tr == []
    return out


@pytest.fixture(params=ALGS)
def alg(request):
    return get_by_name(request.param)


@pytest.fixture(params=sorted(COVERS))
def cover(request):
    return COVERS[request.param]


def test_ids_and_names():
    assert [(a.id, a.name) for a in _ALL] == [(1, "lsb_replacement"), (2, "lsb_matching"), (3, "pvd"),
                                              (4, "edge_adaptive_lsb"), (5, "dct"), (6, "dwt"), (7, "dct_svd"),
                                              (8, "hugo"), (9, "wow"), (10, "s_uniward")]
    for a in _ALL:
        assert a.variant and a.domain and a.reference


@pytest.mark.parametrize("data", [b"", b"\x00", b"\xff", b"hello world", bytes(range(120)),
                                  b"\xff\xfe\x80\xc3\x28\xa0\xa1\xf8\x88\x88\x88", payload(40)])
def test_round_trip(alg, cover, data):
    out = alg.embed(cover, data)
    assert out.stego.shape == cover.shape and out.stego.dtype == np.uint8
    assert alg.extract(out.stego, len(data)) == data
    assert alg.extract(png_roundtrip(out.stego), len(data)) == data  # exact through PNG


def test_does_not_mutate_input(alg, cover):
    before = cover.copy()
    alg.embed(cover, payload(20))
    assert np.array_equal(before, cover)


def test_at_capacity_and_over(alg, cover):
    cap = alg.capacity_bits(cover)
    n = cap // 8
    assert n > 0
    data = payload(n, seed=5)
    out = alg.embed(cover, data)
    assert out.capacity_bits == cap
    assert alg.extract(png_roundtrip(out.stego), n) == data
    with pytest.raises(StegoError) as ei:
        alg.embed(cover, payload(n + 1))
    assert ei.value.code in CODES
    with pytest.raises(StegoError) as ei2:
        alg.extract(out.stego, n + 1)
    assert ei2.value.code == "EXTRACT_FAILED"


def test_capacity_estimate_matches_embedding(alg, cover):
    cap = alg.capacity_bits(cover)
    alg.embed(cover, payload(cap // 8))  # accepted
    with pytest.raises(StegoError):
        alg.embed(cover, payload(cap // 8 + 1))
    # capacity is a property of the cover that the stego image shares (extractor relies on it)
    assert alg.capacity_bits(alg.embed(cover, payload(cap // 8)).stego) == cap


def test_determinism(alg, cover):
    d = payload(33)
    a, b = alg.embed(cover, d).stego, alg.embed(cover.copy(), d).stego
    assert a.tobytes() == b.tobytes()


def test_reserved_samples_untouched(alg, cover):
    cap = alg.capacity_bits(cover)
    for n in (1, 17, cap // 8):
        out = alg.embed(cover, payload(n)).stego
        assert np.array_equal(out.reshape(-1)[:128], cover.reshape(-1)[:128])


def test_empty_payload_changes_nothing(alg, cover):
    assert np.array_equal(alg.embed(cover, b"").stego, cover)


def test_input_validation(alg, cover):
    with pytest.raises(StegoError):
        alg.embed(cover.astype(np.int16), b"x")
    with pytest.raises(StegoError):
        alg.embed(cover, "text")
    with pytest.raises(StegoError):
        alg.extract(cover, -1)
    with pytest.raises(StegoError):
        alg.extract(cover, True)
    with pytest.raises(StegoError):
        alg.embed(cover, b"x", param=1000)


def test_lsb_matching_moves_by_one_and_only_on_mismatch():
    alg = get_by_name("lsb_matching")
    cov = COVERS["rgb"]
    out = alg.embed(cov, payload(200)).stego
    diff = np.abs(out.astype(int) - cov.astype(int))
    assert diff.max() == 1
    assert 0 < (diff > 0).sum() <= 1600


def test_lsb_replacement_changes_only_lsb():
    alg = get_by_name("lsb_replacement")
    cov = COVERS["rgb"]
    out = alg.embed(cov, payload(200)).stego
    assert np.array_equal(out >> 1, cov >> 1)


def test_param_resolution():
    assert get_by_name("dct").resolve_param(0) == 12
    assert get_by_name("edge_adaptive_lsb").resolve_param(0) == 6
    assert get_by_name("dct").resolve_param(20) == 20
    for bad in (3, 65):
        with pytest.raises(StegoError):
            get_by_name("dct").resolve_param(bad)
    with pytest.raises(StegoError):
        get_by_name("pvd").resolve_param(1)


@pytest.mark.parametrize("p", [4, 12, 32, 64])
def test_dct_steps_round_trip(p):
    alg = get_by_name("dct")
    cov = COVERS["rgb"]
    d = payload(60)
    out = alg.embed(cov, d, p).stego
    assert alg.extract(png_roundtrip(out), 60, p) == d


@pytest.mark.parametrize("t", [1, 6, 20])
def test_edge_thresholds_round_trip(t):
    alg = get_by_name("edge_adaptive_lsb")
    cov = COVERS["rgb"]
    n = min(40, alg.capacity_bits(cov, t) // 8)
    d = payload(n)
    assert alg.extract(alg.embed(cov, d, t).stego, n, t) == d
