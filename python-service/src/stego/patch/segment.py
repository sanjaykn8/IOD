"""Adaptive region growing (segmentation version ``arg-cells-1``).

Every pixel gets exactly one region id. Regions are irregular, 4-connected unions of
small square cells (cell = 4, 8 or 16 px, chosen from the image size); the per-pixel map
is the exact expansion of the cell map, which is what the manifest transmits.

Algorithm (deterministic; no randomness):
 1. Per-cell features: mean luma, luma standard deviation (texture), mean gradient
    magnitude and, for RGB, mean Cb/Cr. Weighted and normalised into a feature vector.
 2. Image complexity c in [0,1] from the mean gradient and mean cell deviation.
    Target region count  n_target = clip(round(sqrt(H*W)/64 * (1 + 3c) * 0.5^level), 2, max_regions)
    -> depends on the image size AND its measured complexity (never a fixed count).
 3. Seeded region growing: seeds are taken in order of increasing cell gradient (most
    homogeneous first, ties by cell index). A region absorbs the 4-neighbour cell with the
    smallest distance to the region's running mean feature while that distance <= tau and
    the region is below max_region_cells.
 4. tau is adapted by bisection (bounded iterations) so that the region count after merging
    is as close as possible to n_target. The final count is whatever the image yields.
 5. Undersized regions (< min_region_cells) are merged, smallest first (ties: lowest id),
    into the adjacent region with the smallest mean-feature distance whose merged size
    respects max_region_cells (if no neighbour qualifies, the closest neighbour is used).
    Region statistics are recomputed after each merge. The same step enforces max_regions.
 6. Regions are renumbered by first appearance in raster order (stable ids).
`level` > 0 is the bounded refinement used when capacity or the manifest does not fit:
it halves the target count and doubles the minimum region size (coarser regions).
"""

import heapq
from dataclasses import asdict, dataclass

import numpy as np

from ..errors import StegoError
from . import SEGMENTATION_VERSION

HARD_MAX_REGIONS = 255


@dataclass(frozen=True)
class SegConfig:
    cell_size: int = 0              # 0 = automatic (4 / 8 / 16 from the image size)
    min_region_px: int = 256
    max_region_frac: float = 0.35
    max_regions: int = 96
    w_intensity: float = 1.0
    w_texture: float = 1.0
    w_gradient: float = 0.6
    w_color: float = 0.5
    tau_iterations: int = 7
    max_refine_levels: int = 3

    def to_dict(self):
        return asdict(self)


def parse_config(raw):
    """Maintainer/env supplied settings; bounds enforced, unknown keys rejected."""
    if raw is None:
        return SegConfig()
    if not isinstance(raw, dict):
        raise StegoError("INVALID_REQUEST", "segmentation must be an object")
    d = SegConfig().to_dict()
    bounds = {"cell_size": (0, 16), "min_region_px": (16, 1 << 20), "max_region_frac": (0.05, 1.0),
              "max_regions": (2, HARD_MAX_REGIONS), "w_intensity": (0.0, 10.0), "w_texture": (0.0, 10.0),
              "w_gradient": (0.0, 10.0), "w_color": (0.0, 10.0), "tau_iterations": (1, 12), "max_refine_levels": (0, 6)}
    for k, v in raw.items():
        if k not in d:
            raise StegoError("INVALID_REQUEST", f"unknown segmentation setting '{k}'")
        lo, hi = bounds[k]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise StegoError("INVALID_REQUEST", f"segmentation.{k} must be within [{lo}, {hi}]")
        d[k] = type(d[k])(v)
    if d["cell_size"] not in (0, 4, 8, 16):
        raise StegoError("INVALID_REQUEST", "segmentation.cell_size must be 0, 4, 8 or 16")
    return SegConfig(**d)


@dataclass
class Segmentation:
    cell: int
    cell_labels: np.ndarray     # (rows, cols) uint8
    labels: np.ndarray          # (H, W) uint8
    n_regions: int
    info: dict


def luma_of(arr):
    a = arr.astype(np.float64)
    if a.ndim == 2:
        return a
    return 0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2]


def gradient_of(luma):
    g = np.zeros_like(luma)
    g[:, :-1] += np.abs(np.diff(luma, axis=1))
    g[:-1, :] += np.abs(np.diff(luma, axis=0))
    return g


def auto_cell(h, w):
    if min(h, w) < 64:
        return 4
    return 8 if h * w <= (1 << 21) else 16


def _cell_mean(x, cell, rows, cols):
    h, w = x.shape
    pad = np.pad(x, ((0, rows * cell - h), (0, cols * cell - w)), mode="edge")
    return pad.reshape(rows, cell, cols, cell).mean(axis=(1, 3))


def _cell_features(arr, cell, cfg):
    h, w = arr.shape[:2]
    rows, cols = -(-h // cell), -(-w // cell)
    luma = luma_of(arr)
    m = _cell_mean(luma, cell, rows, cols)
    sd = np.sqrt(np.maximum(_cell_mean(luma * luma, cell, rows, cols) - m * m, 0.0))
    gr = _cell_mean(gradient_of(luma), cell, rows, cols)
    feats = [cfg.w_intensity * m / 255.0, cfg.w_texture * np.minimum(sd, 64.0) / 64.0, cfg.w_gradient * np.minimum(gr, 64.0) / 64.0]
    if arr.ndim == 3:
        a = arr.astype(np.float64)
        cb = _cell_mean(a[..., 2] - luma, cell, rows, cols)
        cr = _cell_mean(a[..., 0] - luma, cell, rows, cols)
        feats += [cfg.w_color * cb / 255.0, cfg.w_color * cr / 255.0]
    f = np.stack([x.reshape(-1) for x in feats], axis=1)
    complexity = float(np.clip((gr.mean() / 16.0 + sd.mean() / 16.0) / 2.0, 0.0, 1.0))
    return f, gr.reshape(-1), rows, cols, complexity


def _neighbours(i, rows, cols):
    r, c = divmod(i, cols)
    if r > 0:
        yield i - cols
    if c > 0:
        yield i - 1
    if c < cols - 1:
        yield i + 1
    if r < rows - 1:
        yield i + cols


def _grow(f, order, rows, cols, tau, max_cells):
    n = rows * cols
    lab = [-1] * n
    fl = f.tolist()
    dim = len(fl[0])
    count = 0
    for seed in order:
        if lab[seed] != -1:
            continue
        rid = count
        count += 1
        lab[seed] = rid
        mean = list(fl[seed])
        size = 1
        heap = []
        for nb in _neighbours(seed, rows, cols):
            if lab[nb] == -1:
                heapq.heappush(heap, (0.0, nb))
        while heap and size < max_cells:
            _, c = heapq.heappop(heap)
            if lab[c] != -1:
                continue
            fc = fl[c]
            d = sum((fc[k] - mean[k]) ** 2 for k in range(dim)) ** 0.5
            if d > tau:
                continue
            lab[c] = rid
            size += 1
            for k in range(dim):
                mean[k] += (fc[k] - mean[k]) / size
            for nb in _neighbours(c, rows, cols):
                if lab[nb] == -1:
                    fn = fl[nb]
                    heapq.heappush(heap, (sum((fn[k] - mean[k]) ** 2 for k in range(dim)) ** 0.5, nb))
    return lab, count


def _merge(lab, f, rows, cols, n_regions, min_cells, max_cells, max_regions):
    """Merge undersized regions (and enforce max_regions). Returns (labels list, merges)."""
    n = rows * cols
    dim = f.shape[1]
    size = [0] * n_regions
    sums = [[0.0] * dim for _ in range(n_regions)]
    adj = [set() for _ in range(n_regions)]
    fl = f.tolist()
    for i in range(n):
        a = lab[i]
        size[a] += 1
        s = sums[a]
        fi = fl[i]
        for k in range(dim):
            s[k] += fi[k]
        r, c = divmod(i, cols)
        if c < cols - 1 and lab[i + 1] != a:
            adj[a].add(lab[i + 1]); adj[lab[i + 1]].add(a)
        if r < rows - 1 and lab[i + cols] != a:
            adj[a].add(lab[i + cols]); adj[lab[i + cols]].add(a)
    parent = list(range(n_regions))
    alive = set(range(n_regions))
    heap = [(size[a], a) for a in alive]
    heapq.heapify(heap)
    merges = 0

    def dist(a, b):
        return sum((sums[a][k] / size[a] - sums[b][k] / size[b]) ** 2 for k in range(dim)) ** 0.5

    while heap and len(alive) > 1:
        s, a = heapq.heappop(heap)
        if a not in alive or s != size[a]:
            continue
        if s >= min_cells and len(alive) <= max_regions:
            break  # heap is size-ordered: nothing smaller remains
        nbrs = sorted(adj[a])
        if not nbrs:
            continue
        ok = [b for b in nbrs if size[a] + size[b] <= max_cells] or nbrs
        b = min(ok, key=lambda x: (dist(a, x), x))
        # merge a into b
        size[b] += size[a]
        for k in range(dim):
            sums[b][k] += sums[a][k]
        for x in adj[a]:
            adj[x].discard(a)
            if x != b:
                adj[x].add(b); adj[b].add(x)
        adj[b].discard(b)
        parent[a] = b
        alive.discard(a)
        merges += 1
        heapq.heappush(heap, (size[b], b))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    return [find(x) for x in lab], merges


def _relabel(lab):
    """Stable ids: order of first appearance in raster order."""
    arr = np.asarray(lab, dtype=np.int64)
    _, first, inv = np.unique(arr, return_index=True, return_inverse=True)
    rank = np.argsort(np.argsort(first))
    return rank[inv], int(first.size)


def _run(f, order, rows, cols, tau, min_cells, max_cells, max_regions):
    lab, cnt = _grow(f, order, rows, cols, tau, max_cells)
    lab, merges = _merge(lab, f, rows, cols, cnt, min_cells, max_cells, max_regions)
    out, n = _relabel(lab)
    return out, n, cnt, merges


def segment(arr, cfg=None, level=0):
    """Segment `arr` (uint8 HxW or HxWx3). Deterministic for identical input, cfg, level and version."""
    cfg = cfg or SegConfig()
    if not isinstance(arr, np.ndarray) or arr.dtype != np.uint8 or arr.ndim not in (2, 3):
        raise StegoError("UNSUPPORTED_IMAGE_MODE", "segmentation needs a uint8 (H,W) or (H,W,3) image")
    h, w = arr.shape[:2]
    if h < 1 or w < 1:
        raise StegoError("IMAGE_TOO_SMALL", "empty image")
    if not 0 <= level <= cfg.max_refine_levels:
        raise StegoError("SEGMENTATION_FAILED", "refinement level out of range")
    cell = cfg.cell_size or auto_cell(h, w)
    f, grad, rows, cols, complexity = _cell_features(arr, cell, cfg)
    n_cells = rows * cols
    max_regions = min(cfg.max_regions, HARD_MAX_REGIONS, n_cells)
    n_target = int(np.clip(round(np.sqrt(h * w) / 64.0 * (1.0 + 3.0 * complexity) * (0.5 ** level)), 2, max(2, max_regions)))
    n_target = min(n_target, n_cells)
    min_cells = max(1, int(np.ceil(cfg.min_region_px * (2 ** level) / (cell * cell))), n_cells // (6 * n_target))
    max_cells = max(int(np.ceil(n_cells * cfg.max_region_frac)), 2 * min_cells, 1)
    if n_cells == 1:
        lab, n, grown, merges, tau = np.zeros(1, dtype=np.int64), 1, 1, 0, 0.0
        trace = []
    else:
        order = np.lexsort((np.arange(n_cells), grad)).tolist()
        lo, hi = 0.004, 1.5
        best, trace = None, []
        for _ in range(cfg.tau_iterations):
            tau = float(np.sqrt(lo * hi))
            lab, n, grown, merges = _run(f, order, rows, cols, tau, min_cells, max_cells, max_regions)
            trace.append({"tau": round(tau, 6), "grown": grown, "regions": n})
            key = (abs(n - n_target), -tau)
            if best is None or key < best[0]:
                best = (key, lab, n, grown, merges, tau)
            if n > n_target:
                lo = tau
            elif n < n_target:
                hi = tau
            else:
                break
        _, lab, n, grown, merges, tau = best
    cell_labels = np.asarray(lab, dtype=np.uint8).reshape(rows, cols)
    labels = np.ascontiguousarray(np.repeat(np.repeat(cell_labels, cell, axis=0), cell, axis=1)[:h, :w])
    info = {
        "version": SEGMENTATION_VERSION, "method": "adaptive region growing on a cell grid", "level": level,
        "cell_size": cell, "grid_rows": rows, "grid_cols": cols, "complexity": round(complexity, 6),
        "target_regions": n_target, "regions": n, "regions_before_merge": grown, "merges": merges,
        "tau": round(float(tau), 6), "min_region_px": min_cells * cell * cell, "max_region_px": max_cells * cell * cell,
        "tau_search": trace, "settings": cfg.to_dict(),
    }
    return Segmentation(cell, cell_labels, labels, n, info)


def is_connected(cell_labels, rid):
    """4-connectivity of region `rid` on the cell grid (used by tests and diagnostics)."""
    m = cell_labels == rid
    idx = np.argwhere(m)
    if idx.size == 0:
        return False
    rows, cols = m.shape
    seen = np.zeros_like(m)
    stack = [tuple(idx[0])]
    seen[stack[0]] = True
    count = 0
    while stack:
        r, c = stack.pop()
        count += 1
        for rr, cc in ((r - 1, c), (r + 1, c), (r, c - 1), (r, c + 1)):
            if 0 <= rr < rows and 0 <= cc < cols and m[rr, cc] and not seen[rr, cc]:
                seen[rr, cc] = True
                stack.append((rr, cc))
    return count == int(m.sum())
