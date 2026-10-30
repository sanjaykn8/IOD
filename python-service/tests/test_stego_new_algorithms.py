"""Tests specific to the five algorithms added in transport v2 (dwt, dct_svd, hugo, wow, s_uniward)
and to the STC coder. The generic contract tests in test_stego_algorithms.py also run on them."""
import itertools

import numpy as np
import pytest

from stego import codec, images
from stego.algorithms import BY_NAME, NAMES, costs as K, stc
from stego.algorithms.adaptive import N_MAX, W_MAX, AdaptiveStc
from stego.algorithms.dct import _C
from stego.algorithms import dwt as D, dct_svd as DS, blocks as B
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import bw_cover, natural_cover, payload

NEW = ["dwt", "dct_svd", "hugo", "wow", "s_uniward"]
BIG = natural_cover(384, 384, 1, seed=21)       # holds 256 bytes even for dct_svd (2256 bits)
BIG_RGB = natural_cover(384, 384, 3, seed=22)
ALL_BYTES = bytes(range(256))


def png(arr):
    return images.decode_png(images.encode_png(arr), Limits())[0]


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("cover", [BIG, BIG_RGB], ids=["gray", "rgb"])
def test_every_algorithm_all_byte_values_through_bootstrap_and_png(name, cover):
    """Complete pipeline used by the transport: payload + bootstrap, saved PNG, extraction from the image alone."""
    alg = BY_NAME[name]
    frame = ALL_BYTES + b"\x00" * 8 + b"\xff" * 4  # every byte value, runs of 0x00/0xff
    stego, out = codec.embed_frame(cover, alg, 0, frame)
    assert stego.dtype == np.uint8 and stego.shape == cover.shape
    got, bs, a2 = codec.extract_frame(png(stego), Limits())
    assert got == frame and a2.name == name and bs.alg_id == alg.id and bs.frame_len == len(frame)


@pytest.mark.parametrize("name", NEW)
def test_new_algorithms_registered_with_ids_and_metadata(name):
    a = BY_NAME[name]
    assert a.id == NAMES.index(name) + 1 and 6 <= a.id <= 10
    d = a.describe()
    assert d["variant"] and d["reference"] and "doi" in d["reference"].lower()


@pytest.mark.parametrize("name", NEW)
def test_reproducible_and_cover_untouched(name):
    a = BY_NAME[name]
    before = BIG_RGB.copy()
    s1 = a.embed(BIG_RGB, payload(100)).stego
    s2 = a.embed(BIG_RGB.copy(), payload(100)).stego
    assert np.array_equal(BIG_RGB, before) and s1.tobytes() == s2.tobytes()


@pytest.mark.parametrize("name", NEW)
def test_rejects_invalid_images(name):
    a = BY_NAME[name]
    for bad in (BIG.astype(np.float32), np.zeros((8, 8, 4), np.uint8), np.zeros((8,), np.uint8)):
        with pytest.raises(StegoError):
            a.embed(bad, b"x")


@pytest.mark.parametrize("name", ["hugo", "wow", "s_uniward"])
def test_stc_algorithms_change_by_one_only(name):
    a = BY_NAME[name]
    out = a.embed(BIG_RGB, payload(300))
    diff = out.stego.astype(int) - BIG_RGB.astype(int)
    assert set(np.unique(diff)) <= {-1, 0, 1}
    assert int((diff != 0).sum()) == out.detail["changes"]
    # coding efficiency sanity: far fewer changes than payload bits
    assert out.detail["changes"] < 300 * 8 * 0.5


@pytest.mark.parametrize("name", ["hugo", "wow", "s_uniward"])
def test_stc_changes_prefer_textured_regions(name):
    """Content adaptivity: on a cover with a smooth half and a textured half, the changes go to the texture."""
    a = BY_NAME[name]
    rng = np.random.default_rng(8)
    y, x = np.mgrid[0:128, 0:128]
    smooth = (80 + 0.3 * x + 0.2 * y)[:, :64]
    textured = rng.integers(40, 216, (128, 64))
    cov = np.clip(np.concatenate([smooth, textured], axis=1), 0, 255).astype(np.uint8)
    out = a.embed(cov, payload(150))
    idx = a.elements(cov, out.detail["n"])
    changed = idx[out.stego.reshape(-1)[idx] != cov.reshape(-1)[idx]]
    in_texture = (changed % 128) >= 64
    used_in_texture = ((idx % 128) >= 64).mean()
    assert 0.4 < used_in_texture < 0.6
    assert in_texture.mean() > 0.9, in_texture.mean()
    rho, _ = a.element_costs(cov, idx)
    assert np.median(rho[(idx % 128) < 64]) > 5 * np.median(rho[(idx % 128) >= 64])


@pytest.mark.parametrize("name", ["hugo", "wow", "s_uniward"])
def test_stc_rate_parameter_and_auto_rate(name):
    a = BY_NAME[name]
    cov = natural_cover(64, 64, 1, seed=3)          # N_eff = 4096 - 128 = 3968
    ne = AdaptiveStc.n_eff(cov)
    assert a.capacity_bits(cov) == ne // 2 and a.capacity_bits(cov, 4) == ne // 4
    assert a.rate_w(cov, 100, 0) == min(W_MAX, ne // 100)
    assert a.rate_w(cov, ne // 2, 0) == 2              # automatic rate at capacity
    for w in (2, 3, 16):
        d = payload(min(40, ne // w // 8))
        out = a.embed(cov, d, w)
        assert out.detail["w"] == w and a.extract(png(out.stego), len(d), w) == d
    with pytest.raises(StegoError):
        a.resolve_param(1)
    with pytest.raises(StegoError):
        a.resolve_param(65)
    with pytest.raises(StegoError) as e:
        a.embed(cov, payload(ne // 2 // 8 + 1))
    assert e.value.code == "CAPACITY_INSUFFICIENT"
    assert AdaptiveStc.n_eff(np.zeros((1024, 1024, 3), np.uint8)) == N_MAX


# ------------------------------------------------------------------ STC coder
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


# ------------------------------------------------------------------ cost functions
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


def test_hugo_sign_choice_uses_cheaper_direction():
    a = BY_NAME["hugo"]
    idx = a.elements(BIG, 500)
    rho, sign = a.element_costs(BIG, idx)
    ch = 1
    rows, cols = idx // BIG.shape[1], idx % BIG.shape[1]
    rp, rm = K.hugo_costs(BIG, rows, cols)
    assert np.allclose(rho, np.minimum(rp, rm)) and np.array_equal(sign, np.where(rp <= rm, 1, -1))
    assert ch == 1


# ------------------------------------------------------------------ transform methods
def test_haar_and_dct_are_orthonormal():
    assert np.allclose(_C @ _C.T, np.eye(8))
    blk = np.array([[[10.0, 20.0], [30.0, 50.0]]])
    co = D.haar_all(blk)
    a = (co["LL"] + co["HL"] + co["LH"] + co["HH"]) / 2
    assert a[0] == pytest.approx(10.0)
    assert sum(v[0] ** 2 for v in co.values()) == pytest.approx(10 ** 2 + 20 ** 2 + 30 ** 2 + 50 ** 2)


@pytest.mark.parametrize("p", [4, 8, 16, 64])
def test_dwt_steps_and_decision_margin(p):
    a = BY_NAME["dwt"]
    out = a.embed(BIG, payload(150), p).stego
    assert a.extract(png(out), 150, p) == payload(150)
    br, bc = B.block_coords(BIG, 2, 1200)
    hh = D.haar_hh(B.gather(out, 2, br, bc))
    margin = np.abs(hh / p - np.rint(hh / p))
    assert margin.max() <= 0.25 + 1e-9  # rounding moved HH by <= 1 = delta/4 for delta>=4


@pytest.mark.parametrize("p", [8, 16, 32])
def test_dct_svd_steps_and_decision_margin(p):
    a = BY_NAME["dct_svd"]
    out = a.embed(BIG, payload(100), p).stego
    assert a.extract(png(out), 100, p) == payload(100)
    br, bc = B.block_coords(BIG, 8, 800)
    s1 = DS.read_s1(B.gather(out, 8, br, bc))
    assert np.all(np.abs(s1 / p - np.rint(s1 / p)) < 0.5)


@pytest.mark.parametrize("name", ["dwt", "dct_svd"])
def test_transform_methods_survive_saturated_black_white_cover(name):
    cov = bw_cover(384, 384)
    a = BY_NAME[name]
    d = payload(150)
    out = a.embed(cov, d)
    assert a.extract(png(out.stego), len(d)) == d and out.detail["blocks_retried"] > 0


def test_transform_methods_skip_bootstrap_rows():
    for name, blk in (("dwt", 2), ("dct_svd", 8)):
        for shape in ((64, 64), (64, 64, 3), (40, 32)):
            cov = natural_cover(shape[0], shape[1], 3 if len(shape) == 3 else 1)
            b0 = B.first_block_row(cov, blk)
            ch = 1 if cov.ndim == 2 else 3
            assert b0 * blk * cov.shape[1] * ch >= 128


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
