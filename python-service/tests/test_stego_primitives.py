"""Unit tests of the low-level primitives shared by the patch algorithms (STC, cost maps, transforms, tables)."""
import itertools

import numpy as np
import pytest

from stego.algorithms import BY_NAME, NAMES, costs as K, stc
from stego.algorithms import dwt as D, dct_svd as DS, blocks as B
from stego.algorithms.dct import _C
from stego.algorithms.edge_adaptive import edge_mask
from stego.algorithms.pvd import LOWER, NBITS, range_index
from stego.errors import StegoError
from stego_helpers import natural_cover, payload

NEW = ["dwt", "dct_svd", "hugo", "wow", "s_uniward"]
STC_ALGS = ["hugo", "wow", "s_uniward"]


@pytest.mark.parametrize("d,bits", [(0, 3), (7, 3), (8, 3), (15, 3), (16, 4), (31, 4), (32, 5), (63, 5),
                                    (64, 6), (127, 6), (128, 7), (255, 7)])
def test_pvd_range_table(d, bits):
    assert NBITS[range_index(np.array([d]))[0]] == bits


def test_pvd_table_constants():
    assert LOWER.tolist() == [0, 8, 16, 32, 64, 128] and NBITS.tolist() == [3, 3, 4, 5, 6, 7]


def test_edge_mask_depends_only_on_msbs():
    cov = natural_cover(64, 64, 3)
    for t in (1, 6, 30):
        m = edge_mask(cov, t)
        assert np.array_equal(m, edge_mask(cov ^ 1, t))
        assert np.array_equal(m, edge_mask((cov & 0xFE) | 1, t))


def test_dct_matrix_orthonormal():
    from stego.algorithms import dct
    assert np.allclose(dct._C @ dct._C.T, np.eye(8), atol=1e-12)


@pytest.mark.parametrize("name", NEW)
def test_new_algorithms_registered_with_ids_and_metadata(name):
    a = BY_NAME[name]
    assert a.id == NAMES.index(name) + 1 and 6 <= a.id <= 10
    d = a.describe()
    assert d["variant"] and d["reference"] and "doi" in d["reference"].lower()


def test_stc_encoder_decoder_agreement_random():
    rng = np.random.default_rng(9)
    for m, w, h in [(1, 2, 7), (7, 2, 7), (64, 5, 7), (500, 10, 7), (33, 3, 4), (20, 64, 7)]:
        n = m * w
        x = rng.integers(0, 2, n).astype(np.uint8)
        rho = rng.random(n) + 0.01
        msg = rng.integers(0, 2, m).astype(np.uint8)
        y, cost = stc.embed(x, rho, msg, w, h)
        assert np.array_equal(stc.syndrome(y, m, w, h), msg)
        assert cost == pytest.approx(float((rho * (y != x)).sum()))


def test_stc_viterbi_is_optimal_bruteforce():
    rng = np.random.default_rng(4)
    for _ in range(25):
        m, w, h = 3, 3, 2
        n = m * w
        x = rng.integers(0, 2, n).astype(np.uint8)
        rho = rng.random(n)
        msg = rng.integers(0, 2, m).astype(np.uint8)
        _, cost = stc.embed(x, rho, msg, w, h)
        best = min(float((rho * (np.array(v) != x)).sum()) for v in itertools.product([0, 1], repeat=n)
                   if np.array_equal(stc.syndrome(np.array(v, np.uint8), m, w, h), msg))
        assert cost == pytest.approx(best)


def test_stc_submatrix_deterministic_and_wet_elements_avoided():
    assert stc.submatrix(7, 10) == stc.submatrix(7, 10)
    for c in stc.submatrix(7, 10):
        assert c & 1 and c & (1 << 6) and c < 128
    rng = np.random.default_rng(1)
    m, w = 50, 4
    x = rng.integers(0, 2, m * w).astype(np.uint8)
    rho = np.ones(m * w)
    rho[::2] = K.WET  # half of the elements are 'wet'
    msg = rng.integers(0, 2, m).astype(np.uint8)
    y, _ = stc.embed(x, rho, msg, w)
    assert np.array_equal(stc.syndrome(y, m, w), msg)
    assert not (y != x)[::2].any()


def test_stc_empty_and_short_cover():
    y, c = stc.embed(np.zeros(0, np.uint8), np.zeros(0), np.zeros(0, np.uint8), 4)
    assert y.size == 0 and c == 0
    with pytest.raises(StegoError):
        stc.embed(np.zeros(5, np.uint8), np.zeros(5), np.ones(3, np.uint8), 2)
    with pytest.raises(StegoError):
        stc.syndrome(np.zeros(5, np.uint8), 3, 2)


def test_db8_filters():
    assert np.sum(K.HPDF ** 2) == pytest.approx(1.0, abs=1e-8)
    assert np.sum(K.LPDF) == pytest.approx(np.sqrt(2), abs=1e-8)
    assert np.sum(K.HPDF) == pytest.approx(0.0, abs=1e-8)
    assert np.dot(K.HPDF, K.LPDF) == pytest.approx(0.0, abs=1e-8)
    try:
        import pywt
    except ImportError:
        return
    assert np.allclose(pywt.Wavelet("db8").dec_hi, K.HPDF, atol=1e-9)
    assert np.allclose(pywt.Wavelet("db8").dec_lo, K.LPDF, atol=1e-9)


def test_conv_same_matches_direct_definition():
    rng = np.random.default_rng(2)
    x = rng.random((7, 9))
    f = rng.random(4)
    got = K.conv1d_same(x, f, 1)
    want = np.zeros_like(x)
    for r in range(7):
        for n in range(9):
            for t in range(4):
                j = n + 2 - t
                if 0 <= j < 9:
                    want[r, n] += f[t] * x[r, j]
    assert np.allclose(got, want)


@pytest.mark.parametrize("fn", [K.wow_plane, K.uniward_plane])
def test_cost_maps_are_adaptive(fn):
    smooth = np.full((64, 64), 120, np.uint8)
    noisy = np.random.default_rng(5).integers(60, 190, (64, 64)).astype(np.uint8)
    img = np.concatenate([smooth, noisy], axis=1)
    rho = fn(img)
    assert rho.shape == img.shape and np.all(rho > 0) and np.all(np.isfinite(rho))
    assert np.median(rho[:, 8:56]) > 10 * np.median(rho[:, 72:120])  # flat area is far more expensive


def test_hugo_exact_single_change_costs_match_full_distortion():
    rng = np.random.default_rng(3)
    x = rng.integers(0, 256, (8, 9)).astype(np.uint8)
    x[0, 0], x[4, 4] = 255, 0
    rows, cols = [a.ravel() for a in np.meshgrid(np.arange(8), np.arange(9), indexing="ij")]
    rp, rm = K.hugo_costs(x, rows, cols)
    for i, (r, c) in enumerate(zip(rows, cols)):
        for d, arr in ((1, rp), (-1, rm)):
            v = int(x[r, c]) + d
            if not 0 <= v <= 255:
                assert np.isinf(arr[i])
                continue
            y = x.astype(np.int64)
            y[r, c] = v
            assert arr[i] == pytest.approx(K.hugo_distortion(x, y), abs=1e-9)


def test_hugo_truncation_and_weights():
    assert K.hugo_weight(0.0, 0.0, 0.0) == pytest.approx(1.0)
    assert K.hugo_weight(3.0, 4.0, 0.0) == pytest.approx(1 / 6)
    # differences beyond T saturate, so a change inside a saturated triple costs nothing in it
    x = np.array([[0, 200, 0, 200, 0, 200]], np.uint8)
    rp, _ = K.hugo_costs(x, np.array([0]), np.array([2]))
    assert rp[0] == pytest.approx(0.0)


def test_haar_and_dct_are_orthonormal():
    assert np.allclose(_C @ _C.T, np.eye(8))
    blk = np.array([[[10.0, 20.0], [30.0, 50.0]]])
    co = D.haar_all(blk)
    a = (co["LL"] + co["HL"] + co["LH"] + co["HH"]) / 2
    assert a[0] == pytest.approx(10.0)
    assert sum(v[0] ** 2 for v in co.values()) == pytest.approx(10 ** 2 + 20 ** 2 + 30 ** 2 + 50 ** 2)


def test_qim_candidates_order_and_parity():
    c = B.qim_candidates(np.array([5.0, -3.0]), 4.0, np.array([1, 0]), 6)
    assert all(q % 2 == 1 for q in c[0]) and all(q % 2 == 0 for q in c[1])
    assert c[0][0] == 1 and c[1][0] in (0, -2) and abs(c[1][0] * 4 + 3) <= 4
    nn = B.qim_candidates(np.array([1.0]), 16.0, np.array([1]), 4, nonnegative=True)
    assert nn[0][0] == 1


def test_s_uniward_cost_equals_direct_distortion_of_single_changes():
    """rho_ij == D(X, X + e_ij) for the spatial UNIWARD distortion (additive approximation exact for one change)."""
    rng = np.random.default_rng(12)
    x = rng.integers(20, 235, (40, 48)).astype(np.uint8)
    rho = K.uniward_plane(x)
    xp = np.pad(x.astype(np.float64), K.PAD, mode="symmetric")
    wx = {k: K.conv2_same(xp, v, h) for k, (v, h) in K.FILTERS.items()}
    for (r, c) in [(0, 0), (5, 7), (20, 24), (39, 47), (13, 46)]:
        yp = xp.copy()
        yp[K.PAD + r, K.PAD + c] += 1
        d = sum(float(np.sum(np.abs(K.conv2_same(yp, v, h) - wx[k]) / (K.SIGMA_UNIWARD + np.abs(wx[k]))))
                for k, (v, h) in K.FILTERS.items())
        assert rho[r, c] == pytest.approx(d, rel=1e-9)
