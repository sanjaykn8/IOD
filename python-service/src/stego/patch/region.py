"""A patch as the algorithms see it: an exact boolean pixel mask (bootstrap rows excluded)
plus cached carrier index lists. Algorithms may read/write ONLY through these indices."""

import hashlib

import numpy as np


class Region:
    def __init__(self, rid, mask):
        self.id = int(rid)
        self.mask = mask                      # (H, W) bool, effective (reserved rows removed)
        self.shape = mask.shape
        self._pix = None
        self._blocks = {}

    @classmethod
    def from_labels(cls, eff_labels, rid):
        return cls(rid, eff_labels == rid)

    @property
    def pixels(self):
        """Raster-order flat pixel indices of the patch."""
        if self._pix is None:
            self._pix = np.flatnonzero(self.mask.reshape(-1))
        return self._pix

    @property
    def n_pixels(self):
        return int(self.pixels.size)

    def samples(self, channels):
        """Raster-order flat sample indices (pixel-major, then channel)."""
        p = self.pixels
        if channels == 1:
            return p
        return (p[:, None] * channels + np.arange(channels)[None, :]).reshape(-1)

    def blocks(self, b):
        """(block-rows, block-cols) of the b x b blocks of the global b-grid lying ENTIRELY inside the patch."""
        if b not in self._blocks:
            h, w = self.shape
            hb, wb = h // b, w // b
            if hb == 0 or wb == 0:
                self._blocks[b] = (np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.int64))
            else:
                full = self.mask[:hb * b, :wb * b].reshape(hb, b, wb, b).all(axis=(1, 3))
                br, bc = np.nonzero(full)
                self._blocks[b] = (br.astype(np.int64), bc.astype(np.int64))
        return self._blocks[b]

    def bbox(self):
        rows = np.flatnonzero(self.mask.any(axis=1))
        cols = np.flatnonzero(self.mask.any(axis=0))
        if rows.size == 0:
            return (0, 0, 0, 0)
        return int(rows[0]), int(cols[0]), int(rows[-1]) + 1, int(cols[-1]) + 1


class CoverCtx:
    """Read-only view of the cover with caches shared by all patches of one embedding run."""

    def __init__(self, cover):
        self.cover = cover
        self.channels = 1 if cover.ndim == 2 else 3
        self._digest = None
        self._costs = {}

    @property
    def digest(self):
        if self._digest is None:
            self._digest = hashlib.sha256(np.ascontiguousarray(self.cover).tobytes()).digest()
        return self._digest

    def seed(self, tag, rid):
        h = hashlib.sha256(self.digest + tag + int(rid).to_bytes(2, "big")).digest()
        return int.from_bytes(h[:8], "big")

    def cost_map(self, name, fn):
        if name not in self._costs:
            self._costs[name] = fn(self.cover)
        return self._costs[name]
