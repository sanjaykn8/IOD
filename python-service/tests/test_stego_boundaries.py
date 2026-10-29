import numpy as np
import pytest

from stego import images
from stego.algorithms import get_by_name
from stego.algorithms.dct import Dct
from stego.algorithms.edge_adaptive import edge_mask
from stego.algorithms.pvd import LOWER, NBITS, range_index
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import bw_cover, natural_cover, payload


def png(a):
    return images.decode_png(images.encode_png(a), Limits())[0]


# ---------------- LSB matching -----------------
@pytest.mark.parametrize("value", [0, 255])
@pytest.mark.parametrize("shape", [(40, 40), (40, 40, 3)])
def test_lsbm_saturated(value, shape):
    alg = get_by_name("lsb_matching")
    cov = np.full(shape, value, dtype=np.uint8)
    n = alg.capacity_bits(cov) // 8
    d = payload(n)
    out = alg.embed(cov, d).stego
    assert alg.extract(png(out), n) == d
    assert set(np.unique(out)) <= ({0, 1} if value == 0 else {254, 255})


def test_lsbm_extremes_mixed():
    alg = get_by_name("lsb_matching")
    cov = np.random.default_rng(1).choice([0, 1, 254, 255], size=(40, 40, 3)).astype(np.uint8)
    d = payload(alg.capacity_bits(cov) // 8)
    out = alg.embed(cov, d).stego
    assert alg.extract(out, len(d)) == d
    assert np.abs(out.astype(int) - cov.astype(int)).max() <= 1


# ---------------- PVD -----------------
@pytest.mark.parametrize("d,bits", [(0, 3), (7, 3), (8, 3), (15, 3), (16, 4), (31, 4), (32, 5), (63, 5),
                                    (64, 6), (127, 6), (128, 7), (255, 7)])
def test_pvd_range_table(d, bits):
    alg = get_by_name("pvd")
    cov = np.zeros((32, 32), dtype=np.uint8)
    flat = cov.reshape(-1)
    flat[128 + 1::2] = d
    assert alg.capacity_bits(cov) == bits * ((1024 - 128) // 2)
    assert NBITS[range_index(np.array([d]))[0]] == bits


def test_pvd_table_constants():
    assert LOWER.tolist() == [0, 8, 16, 32, 64, 128] and NBITS.tolist() == [3, 3, 4, 5, 6, 7]


def test_pvd_all_pairs_exhaustive():
    """Every (a,b) pair in 0..255 appears once; all payload values get embedded."""
    alg = get_by_name("pvd")
    a, b = np.meshgrid(np.arange(256), np.arange(256), indexing="ij")
    body = np.stack([a.reshape(-1), b.reshape(-1)], axis=1).reshape(-1)
    flat = np.concatenate([np.full(128, 100), body]).astype(np.uint8)
    cov = flat.reshape(328, 400)
    assert cov.size == 131200
    cap = alg.capacity_bits(cov)
    d = payload(cap // 8, seed=9)
    out = alg.embed(cov, d).stego
    assert alg.extract(out, len(d)) == d
    sa, sb = out.reshape(-1)[128:].reshape(-1, 2).astype(int).T
    ca, cb = body.reshape(-1, 2).astype(int).T
    n = len(d) * 8  # pairs fully used keep their range
    assert np.array_equal(range_index(np.abs(sa - sb)), range_index(np.abs(ca - cb)))
    assert sa.min() >= 0 and sa.max() <= 255 and sb.min() >= 0 and sb.max() <= 255
    assert np.sign(sa - sb)[ca > cb].min() >= 0  # sign of a-b preserved where d>0 and a>b
    assert np.sign(sa - sb)[(ca < cb)].max() <= 0


@pytest.mark.parametrize("value", [0, 255])
def test_pvd_saturated(value):
    alg = get_by_name("pvd")
    cov = np.full((40, 40), value, dtype=np.uint8)
    d = payload(alg.capacity_bits(cov) // 8)
    assert alg.extract(png(alg.embed(cov, d).stego), len(d)) == d


def test_pvd_checkerboard_and_bw():
    alg = get_by_name("pvd")
    cb = ((np.indices((40, 40)).sum(0) % 2) * 255).astype(np.uint8)
    for cov in (cb, bw_cover(64, 64), 255 - cb):
        d = payload(alg.capacity_bits(cov) // 8)
        assert alg.extract(png(alg.embed(cov, d).stego), len(d)) == d


# ---------------- edge adaptive -----------------
def test_edge_flat_cover_has_no_capacity():
    alg = get_by_name("edge_adaptive_lsb")
    flat = np.full((64, 64, 3), 120, dtype=np.uint8)
    assert alg.capacity_bits(flat) == 0
    assert alg.embed(flat, b"").stego.tobytes() == flat.tobytes()
    with pytest.raises(StegoError) as ei:
        alg.embed(flat, b"x")
    assert ei.value.code == "EDGE_CAPACITY_INSUFFICIENT"
    assert ei.value.details["capacity_bits"] == 0


def test_edge_low_capacity_exact_boundary():
    alg = get_by_name("edge_adaptive_lsb")
    cov = np.full((64, 64), 100, dtype=np.uint8)
    cov[:, 40:] = 200  # one vertical edge
    cap = alg.capacity_bits(cov)
    assert 0 < cap < 200
    d = payload(cap // 8)
    out = alg.embed(cov, d).stego
    assert alg.extract(out, len(d)) == d
    with pytest.raises(StegoError) as ei:
        alg.embed(cov, payload(cap // 8 + 1))
    assert ei.value.code == "EDGE_CAPACITY_INSUFFICIENT"


def test_edge_mask_depends_only_on_msbs():
    cov = natural_cover(64, 64, 3)
    for t in (1, 6, 30):
        m = edge_mask(cov, t)
        assert np.array_equal(m, edge_mask(cov ^ 1, t))
        assert np.array_equal(m, edge_mask((cov & 0xFE) | 1, t))


def test_edge_mask_survives_embedding():
    alg = get_by_name("edge_adaptive_lsb")
    cov = natural_cover(96, 128, 3)
    out = alg.embed(cov, payload(100)).stego
    assert np.array_equal(edge_mask(cov, 6), edge_mask(out, 6))


def test_edge_threshold_monotonic():
    cov = natural_cover(64, 64, 3)
    caps = [get_by_name("edge_adaptive_lsb").capacity_bits(cov, t) for t in (1, 6, 20, 100)]
    assert caps == sorted(caps, reverse=True)


# ---------------- DCT -----------------
@pytest.mark.parametrize("h,w", [(37, 45), (33, 70), (50, 33), (64, 64), (32, 32), (40, 32), (32, 40), (100, 37)])
@pytest.mark.parametrize("channels", [1, 3])
def test_dct_odd_sizes(h, w, channels):
    alg = get_by_name("dct")
    cov = natural_cover(h, w, channels, seed=h * w)
    cap = alg.capacity_bits(cov)
    assert cap == 6 * max(0, h // 8 - 1) * (w // 8)
    n = cap // 8
    assert n >= 1
    d = payload(n, seed=h)
    out = alg.embed(cov, d).stego
    assert alg.extract(png(out), n) == d
    # untouched: first block row, right/bottom margins, non-plane channels
    assert np.array_equal(out[:8], cov[:8])
    assert np.array_equal(out[:, (w // 8) * 8:], cov[:, (w // 8) * 8:])
    assert np.array_equal(out[(h // 8) * 8:], cov[(h // 8) * 8:])
    if channels == 3:
        assert np.array_equal(out[..., :2], cov[..., :2])


def test_dct_minimal_images():
    alg = get_by_name("dct")
    assert alg.capacity_bits(np.zeros((8, 8), np.uint8)) == 0
    assert alg.capacity_bits(np.zeros((15, 100), np.uint8)) == 0
    assert alg.capacity_bits(np.zeros((16, 8), np.uint8)) == 6
    tiny = natural_cover(16, 8, 1)
    out = alg.embed(tiny, b"").stego
    assert np.array_equal(out, tiny)
    with pytest.raises(StegoError):
        alg.embed(tiny, b"x")


@pytest.mark.parametrize("value", [0, 255, 1, 254, 128])
def test_dct_saturated_exact_or_clean_failure(value):
    alg = get_by_name("dct")
    cov = np.full((40, 40, 3), value, dtype=np.uint8)
    d = payload(alg.capacity_bits(cov) // 8)
    try:
        out = alg.embed(cov, d).stego
    except StegoError as exc:
        assert exc.code == "ENCODE_VERIFY_FAILED"
        assert exc.details["failed_blocks"] > 0
    else:
        assert alg.extract(png(out), len(d)) == d  # never silent corruption


def test_dct_extreme_noise_never_silent_corruption():
    alg = get_by_name("dct")
    rng = np.random.default_rng(4)
    for k in range(6):
        cov = rng.choice([0, 255, 3, 252, 128], size=(48, 48, 3)).astype(np.uint8)
        d = payload(alg.capacity_bits(cov) // 8, seed=k)
        try:
            out = alg.embed(cov, d).stego
        except StegoError as exc:
            assert exc.code == "ENCODE_VERIFY_FAILED"
        else:
            assert alg.extract(out, len(d)) == d


def test_dct_bw_procedural_cover():
    alg = get_by_name("dct")
    cov = bw_cover(64, 64)
    d = payload(alg.capacity_bits(cov) // 8)
    try:
        out = alg.embed(cov, d).stego
    except StegoError as exc:
        assert exc.code == "ENCODE_VERIFY_FAILED"
    else:
        assert alg.extract(out, len(d)) == d


def test_dct_matrix_orthonormal():
    from stego.algorithms import dct
    assert np.allclose(dct._C @ dct._C.T, np.eye(8), atol=1e-12)
