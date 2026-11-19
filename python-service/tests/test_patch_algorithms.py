"""All ten algorithms on IRREGULAR patch masks: support, measured capacity, embed, extract, isolation."""
import numpy as np
import pytest

from stego import images
from stego.algorithms import BY_ID, BY_NAME, NAMES
from stego.algorithms.adaptive import AdaptiveStc
from stego.config import Limits
from stego.errors import StegoError
from stego.patch import features as PF, kb as KB
from stego.patch.region import CoverCtx, Region
from stego_helpers import bw_cover, disc_mask, natural_cover, payload

IDS = {"lsb_replacement": 1, "lsb_matching": 2, "pvd": 3, "edge_adaptive_lsb": 4, "dct": 5,
       "dwt": 6, "dct_svd": 7, "hugo": 8, "wow": 9, "s_uniward": 10}
COVERS = {"rgb": lambda: natural_cover(96, 128), "gray": lambda: natural_cover(96, 128, channels=1)}


def param_for(alg, img, reg, n):
    return alg.choose_w(img, reg, n) if isinstance(alg, AdaptiveStc) else alg.resolve_param(0)


def run(alg, cover, reg, data, param=None):
    p = param_for(alg, cover, reg, len(data)) if param is None else param
    out = cover.copy()
    detail = alg.embed(CoverCtx(cover), reg, out, data, p)
    return out, p, detail


def outside_changes(cover, out, mask):
    ch = (out != cover) if cover.ndim == 2 else (out != cover).any(axis=2)
    return int(np.count_nonzero(ch & ~mask))


def test_ids_names_and_variant_labels_are_stable_and_honest():
    assert {n: BY_NAME[n].id for n in NAMES} == IDS and list(NAMES) == sorted(IDS, key=IDS.get)
    assert all(BY_ID[i].name == n for n, i in IDS.items())
    assert "approximation" in BY_NAME["hugo"].variant.lower() or "additive" in BY_NAME["hugo"].variant.lower()
    for n in ("hugo", "wow", "s_uniward"):
        assert "custom" in BY_NAME[n].coding.lower() or "custom" in BY_NAME[n].variant.lower()
    for n in NAMES:
        d = BY_NAME[n].describe()
        assert d["variant"] and d["mask_support"] and d["block"] in (0, 2, 8)


@pytest.mark.parametrize("cover", list(COVERS))
@pytest.mark.parametrize("name", list(IDS))
def test_irregular_mask_round_trip_through_png_without_touching_other_pixels(name, cover):
    cov = COVERS[cover]()
    reg = Region(3, disc_mask(96, 128))
    alg = BY_NAME[name]
    ok, why = alg.support(cov, reg)
    assert ok, why
    n = max(1, min(20, alg.capacity_bits(cov, reg, 0 if not isinstance(alg, AdaptiveStc) else 2) // 8))
    data = payload(n, seed=IDS[name])
    out, p, _ = run(alg, cov, reg, data)
    assert outside_changes(cov, out, reg.mask) == 0
    back, _ = images.decode_png(images.encode_png(out), Limits())
    assert np.array_equal(back, out)
    assert alg.extract(back, reg, n, p) == data
    # deterministic
    out2, p2, _ = run(alg, cov, reg, data)
    assert p2 == p and np.array_equal(out2, out)


@pytest.mark.parametrize("name", list(IDS))
def test_capacity_is_measured_exactly_and_overflow_is_rejected(name):
    cov = natural_cover(96, 128, channels=1)
    reg = Region(0, disc_mask(96, 128))
    alg = BY_NAME[name]
    p = 2 if isinstance(alg, AdaptiveStc) else alg.resolve_param(0)
    cap = alg.capacity_bits(cov, reg, p)
    assert cap > 0
    full = payload(cap // 8, seed=5)
    out, _, _ = run(alg, cov, reg, full, p)
    assert alg.extract(out, reg, len(full), p) == full
    with pytest.raises(StegoError) as e:
        run(alg, cov, reg, payload(cap // 8 + 1), p)
    assert e.value.code in (alg.capacity_code, "CAPACITY_INSUFFICIENT")
    with pytest.raises(StegoError) as e:
        alg.extract(out, reg, cap // 8 + 1, p)
    assert e.value.code == "EXTRACT_FAILED"


@pytest.mark.parametrize("name", list(IDS))
def test_two_adjacent_patches_do_not_interfere(name):
    """Embedding in patch B after patch A must not change what A extracts (no cross-patch context)."""
    cov = natural_cover(96, 128)
    y, x = np.mgrid[0:96, 0:128]
    a = (x + 0.4 * y) < 60
    ra, rb = Region(0, a), Region(1, ~a)
    alg = BY_NAME[name]
    da, db = payload(6, 1), payload(6, 2)
    ctx = CoverCtx(cov)
    out = cov.copy()
    pa, pb = param_for(alg, cov, ra, 6), param_for(alg, cov, rb, 6)
    alg.embed(ctx, ra, out, da, pa)
    snapshot = out.copy()
    alg.embed(ctx, rb, out, db, pb)
    assert np.array_equal(out[a], snapshot[a]), "patch B embedding changed patch A pixels"
    assert alg.extract(out, ra, 6, pa) == da and alg.extract(out, rb, 6, pb) == db


@pytest.mark.parametrize("name,block", [("dct", 8), ("dct_svd", 8), ("dwt", 2)])
def test_block_methods_use_only_complete_blocks_inside_the_mask(name, block):
    cov = natural_cover(96, 128, channels=1)
    mask = disc_mask(96, 128)
    reg = Region(0, mask)
    alg = BY_NAME[name]
    br, bc = reg.blocks(block)
    assert br.size > 0
    inside = np.zeros_like(mask)
    for r, c in zip(br, bc):
        assert mask[r * block:(r + 1) * block, c * block:(c + 1) * block].all()
        inside[r * block:(r + 1) * block, c * block:(c + 1) * block] = True
    n = alg.capacity_bits(cov, reg, 0) // 8
    out, p, _ = run(alg, cov, reg, payload(n))
    changed = out != cov
    assert not np.any(changed & ~inside), "a partial block (or a pixel outside the mask) was modified"
    per_block = {"dct": 6, "dct_svd": 1, "dwt": 1}[name]
    assert alg.capacity_bits(cov, reg, 0) == per_block * br.size


@pytest.mark.parametrize("name", ["dct", "dct_svd"])
def test_block_methods_report_unsupported_geometry_instead_of_falling_back(name):
    cov = natural_cover(64, 64, channels=1)
    thin = np.zeros((64, 64), bool)
    thin[10:60, 20:25] = True          # 5 pixels wide: no complete 8x8 block
    reg = Region(0, thin)
    alg = BY_NAME[name]
    ok, why = alg.support(cov, reg)
    assert not ok and "8X8" in why
    assert alg.capacity_bits(cov, reg, 0) == 0
    with pytest.raises(StegoError):
        run(alg, cov, reg, b"x", alg.resolve_param(0))
    out = cov.copy()
    assert np.array_equal(out, cov)
    # sample-based methods still work on the same thin patch
    assert BY_NAME["lsb_replacement"].support(cov, reg)[0] and BY_NAME["wow"].support(cov, reg)[0]


def test_empty_and_tiny_patches():
    cov = natural_cover(32, 32, channels=1)
    empty = Region(0, np.zeros((32, 32), bool))
    for n in NAMES:
        ok, why = BY_NAME[n].support(cov, empty)
        assert not ok and why
    one = np.zeros((32, 32), bool)
    one[5, 5] = True
    assert BY_NAME["pvd"].capacity_bits(cov, Region(0, one), 0) == 0
    assert not BY_NAME["hugo"].support(cov, Region(0, one))[0]


def test_lsb_family_changes_and_stc_changes_are_at_most_one():
    cov = natural_cover(96, 128)
    reg = Region(2, disc_mask(96, 128))
    for n in ("lsb_replacement", "lsb_matching", "hugo", "wow", "s_uniward"):
        out, _, _ = run(BY_NAME[n], cov, reg, payload(24))
        d = np.abs(out.astype(int) - cov.astype(int))
        assert d.max() <= 1, n


def test_stc_costs_respect_the_mask_and_prefer_texture():
    """Changes of the cost-based methods concentrate in the textured half of one patch."""
    rng = np.random.default_rng(4)
    cov = np.full((96, 128), 120, np.uint8)
    cov[:, 64:] = np.clip(120 + rng.normal(0, 30, (96, 64)), 5, 250).astype(np.uint8)
    mask = np.zeros((96, 128), bool)
    mask[8:88, 8:120] = True
    reg = Region(0, mask)
    for n in ("hugo", "wow", "s_uniward"):
        alg = BY_NAME[n]
        out, p, _ = run(alg, cov, reg, payload(40), 8)
        ch = out != cov
        assert outside_changes(cov, out, mask) == 0
        assert ch[:, 64:].sum() > 3 * max(1, ch[:, :64].sum()), n


def test_edge_adaptive_selection_survives_embedding_and_ignores_neighbour_patches():
    cov = natural_cover(96, 128, channels=1, noise=18.0)
    mask = disc_mask(96, 128)
    reg = Region(0, mask)
    alg = BY_NAME["edge_adaptive_lsb"]
    cap = alg.capacity_bits(cov, reg, 0)
    out, p, _ = run(alg, cov, reg, payload(cap // 8))
    assert alg.capacity_bits(out, reg, p) == cap
    # arbitrary changes OUTSIDE the patch must not move the carrier set
    noisy = out.copy()
    noisy[~mask] = np.random.default_rng(9).integers(0, 256, int((~mask).sum()), dtype=np.uint8)
    assert alg.capacity_bits(noisy, reg, p) == cap
    assert alg.extract(noisy, reg, cap // 8, p) == payload(cap // 8)


def test_dct_saturated_patch_is_filtered():
    """Local heuristic in the KB: DCT is excluded on saturated patches; the implementation fails cleanly there."""
    bw = bw_cover(64, 64)
    lab = np.zeros((64, 64), np.uint8)
    f = PF.compute(bw, lab, 1)[0]
    assert f["saturation"] >= 0.02
    reg = Region(0, lab == 0)
    sups = {n: BY_NAME[n].support(bw, reg) for n in NAMES}
    assert KB.structural(f, sups)["dct"] is False
    try:
        out, p, _ = run(BY_NAME["dct"], bw, reg, payload(8))
        assert BY_NAME["dct"].extract(out, reg, 8, p) == payload(8)   # if it embeds, it must be exact
    except StegoError as exc:
        assert exc.code in ("ENCODE_VERIFY_FAILED", "CAPACITY_INSUFFICIENT", "PATCH_EMBED_FAILED")


@pytest.mark.parametrize("name", ["dwt", "dct_svd", "lsb_replacement", "lsb_matching", "pvd"])
def test_saturated_black_white_patch_round_trip(name):
    bw = bw_cover(64, 64)
    reg = Region(0, disc_mask(64, 64, r=28))
    alg = BY_NAME[name]
    n = min(4, alg.capacity_bits(bw, reg, 0) // 8)
    assert n >= 1
    out, p, _ = run(alg, bw, reg, payload(n))
    assert alg.extract(out, reg, n, p) == payload(n) and outside_changes(bw, out, reg.mask) == 0


def test_param_validation_and_stc_rate():
    for n in NAMES:
        alg = BY_NAME[n]
        for bad in (-1, 256, True, "3", 1.5):
            with pytest.raises(StegoError):
                alg.resolve_param(bad)
    cov = natural_cover(96, 128, channels=1)
    reg = Region(0, disc_mask(96, 128))
    alg = BY_NAME["wow"]
    n_eff = alg.n_eff(cov, reg)
    assert alg.choose_w(cov, reg, 10) == min(10, n_eff // 80)
    assert alg.choose_w(cov, reg, n_eff) == 0          # cannot fit even at rate 1/2
    assert alg.capacity_bits(cov, reg, 4) == n_eff // 4
    with pytest.raises(StegoError):
        alg.resolve_param(1)


def test_rejects_invalid_images():
    reg = Region(0, np.ones((8, 8), bool))
    for n in NAMES:
        for bad in (np.zeros((8, 8), np.float32), np.zeros((8, 8, 4), np.uint8)):
            with pytest.raises(StegoError):
                BY_NAME[n].embed(CoverCtx(np.zeros((8, 8), np.uint8)), reg, bad, b"a", BY_NAME[n].default_param or 2)
