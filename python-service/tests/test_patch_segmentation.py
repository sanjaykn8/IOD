"""Adaptive region-growing segmentation: partition, connectivity, determinism, bounds, refinement."""
import numpy as np
import pytest

from stego.errors import StegoError
from stego.patch import segment as S
from stego_helpers import bw_cover, mixed_cover, natural_cover

COVERS = {
    "natural_rgb": lambda: natural_cover(96, 128),
    "natural_gray": lambda: natural_cover(120, 90, channels=1),
    "mixed_rgb": lambda: mixed_cover(),
    "mixed_gray": lambda: mixed_cover(160, 200, 1),
    "flat": lambda: np.full((96, 96), 128, np.uint8),
    "noise": lambda: np.random.default_rng(1).integers(0, 256, (128, 128, 3), dtype=np.uint8),
    "bw": lambda: bw_cover(64, 64),
    "odd": lambda: natural_cover(101, 67),
    "tiny": lambda: natural_cover(32, 32, channels=1),
}


@pytest.mark.parametrize("name", list(COVERS))
def test_partition_connected_bounded_and_deterministic(name):
    arr = COVERS[name]()
    cfg = S.SegConfig()
    seg = S.segment(arr, cfg, 0)
    h, w = arr.shape[:2]
    assert seg.labels.shape == (h, w) and seg.labels.dtype == np.uint8
    n = seg.n_regions
    assert 1 <= n <= min(cfg.max_regions, 255)
    # every pixel belongs to exactly one region; ids are dense 0..n-1
    assert set(np.unique(seg.labels).tolist()) == set(range(n))
    assert int(np.bincount(seg.labels.reshape(-1), minlength=n).sum()) == h * w
    for rid in range(n):
        assert S.is_connected(seg.cell_labels, rid), f"region {rid} is not connected"
    # the pixel map is the exact expansion of the cell map (what the manifest carries)
    big = np.repeat(np.repeat(seg.cell_labels, seg.cell, 0), seg.cell, 1)[:h, :w]
    assert np.array_equal(big, seg.labels)
    again = S.segment(arr.copy(), cfg, 0)
    assert np.array_equal(again.labels, seg.labels) and again.info == seg.info
    assert seg.info["version"] == "arg-cells-1" and seg.info["regions"] == n


def test_region_count_is_dynamic_not_fixed():
    counts = {k: S.segment(f(), None, 0).n_regions for k, f in COVERS.items()}
    assert len(set(counts.values())) >= 3, counts
    big = S.segment(mixed_cover(384, 512), None, 0).n_regions
    assert big > S.segment(mixed_cover(96, 128), None, 0).n_regions
    # complexity matters at a fixed size
    flat = S.segment(np.full((256, 256), 90, np.uint8), None, 0)
    busy = S.segment(mixed_cover(256, 256, 1), None, 0)
    assert busy.info["complexity"] > flat.info["complexity"] and busy.info["target_regions"] > flat.info["target_regions"]


def test_regions_are_irregular_not_a_grid():
    seg = S.segment(mixed_cover(), None, 0)
    lab = seg.labels
    rect = 0
    for rid in range(seg.n_regions):
        ys, xs = np.nonzero(lab == rid)
        if (ys.max() - ys.min() + 1) * (xs.max() - xs.min() + 1) == ys.size:
            rect += 1
    assert rect < seg.n_regions, "all regions are rectangles"
    assert len({int((lab == r).sum()) for r in range(seg.n_regions)}) > 1


def test_min_size_merge_and_max_size():
    arr = mixed_cover()
    cfg = S.SegConfig(min_region_px=1024)
    seg = S.segment(arr, cfg, 0)
    sizes = np.bincount(seg.cell_labels.reshape(-1)) * seg.cell * seg.cell
    assert sizes.min() >= seg.info["min_region_px"] >= 1024 or seg.n_regions == 1
    assert seg.info["regions_before_merge"] >= seg.n_regions
    assert sizes.max() <= max(seg.info["max_region_px"], sizes.sum())


def test_refinement_levels_are_coarser_and_bounded():
    arr = mixed_cover(256, 320)
    cfg = S.SegConfig()
    ns = [S.segment(arr, cfg, lv).n_regions for lv in range(cfg.max_refine_levels + 1)]
    assert ns[0] >= ns[-1] and ns[-1] < ns[0]
    assert all(a >= b for a, b in zip(ns, ns[1:])), ns
    with pytest.raises(StegoError) as e:
        S.segment(arr, cfg, cfg.max_refine_levels + 1)
    assert e.value.code == "SEGMENTATION_FAILED"


def test_weights_change_the_result_and_settings_are_validated():
    arr = mixed_cover()
    a = S.segment(arr, S.SegConfig(), 0)
    b = S.segment(arr, S.SegConfig(w_texture=0.0, w_gradient=0.0, w_color=0.0, w_intensity=3.0), 0)
    assert not np.array_equal(a.labels, b.labels)
    assert S.parse_config({"min_region_px": 512, "max_regions": 40}).max_regions == 40
    for bad in ({"nope": 1}, {"max_regions": 999}, {"cell_size": 5}, {"min_region_px": True}, {"w_color": "x"}, [1]):
        with pytest.raises(StegoError) as e:
            S.parse_config(bad)
        assert e.value.code == "INVALID_REQUEST"


def test_rejects_non_uint8_or_wrong_rank():
    for bad in (np.zeros((8, 8), np.float32), np.zeros((4, 4, 4, 4), np.uint8), [[1, 2]]):
        with pytest.raises(StegoError):
            S.segment(bad)


def test_cell_size_rule():
    assert S.auto_cell(32, 32) == 4 and S.auto_cell(480, 640) == 8 and S.auto_cell(2000, 2000) == 16
