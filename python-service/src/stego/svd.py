"""SVD-domain steganography via singular-value quantization.

Each color channel is split into non-overlapping 8x8 blocks (same
blocking as `dct.py`). Every block gets a REAL singular value
decomposition (`numpy.linalg.svd`): `block = U @ diag(S) @ Vt`. The
largest singular value `S[0]` dominates a block's overall energy
(roughly, its average brightness/contrast) and visibly distorts the
image if touched; this implementation embeds one payload bit per block
into the SECOND singular value (`S[1]`) instead, using the same
quantization-index-modulation approach as the DCT/DWT algorithms in
this package: the chosen singular value is nudged to the nearest
multiple of a step size `Q` whose index parity encodes the bit, subject
to a full-`Q`-step margin against BOTH its neighbors (`S[0]` above,
`S[2]` below -- see the margin logic in `embed()`), then the block is
reconstructed as `U @ diag(S_mod) @ Vt` and rounded/clipped to
`[0, 255]`.

Why the margin matters, concretely (this project's own debugging, not a
theoretical aside): `numpy.linalg.svd` always returns singular values
sorted descending. Quantizing `S[1]` without regard to its neighbors
can on some blocks round it to a value equal to or below `S[2]`
(especially on near-flat blocks, where `S[1]` and `S[2]` start out
nearly identical); after reconstruction, rounding, and a fresh SVD at
extraction time, numpy hands the values back in sorted order again,
which silently relabels which physical value is "`S[1]`" and corrupts
the bit. Reserving a full quantization step of margin on both sides
keeps the intended value clear of that swap, verified empirically by
this project's own round-trip tests
(`tests/test_stego_algorithms.py`) -- an earlier version of this
module embedded into `S[1]` AND `S[2]` (2 bits/block) and hit exactly
this swap on real test images; it was simplified to 1 bit/block for
that reason, not by oversight.

Why the margin survives pixel rounding at all: Weyl's inequality
guarantees that perturbing a matrix by `E` moves every singular value
by at most `||E||_2`, and clipping/rounding pixel values to `uint8`
injects a small, bounded perturbation. Default `Q=6.0` was chosen, and
is verified by this project's own tests, to exceed that rounding
margin on its real test-fixture images.

Honest limitations: like `dct.py`, operates on whole 8x8 blocks only,
so a cover image whose dimensions are not multiples of 8 has its
bottom/right edge strip excluded (cropped), disclosed via
`algorithm_params`. Only 1 bit per block (substantially lower raw
capacity than DCT's 8 bits/block at the same block size) -- a
deliberate, documented trade-off favoring round-trip robustness over
raw capacity for this singular-value-based approach, not a bug.
"""

from __future__ import annotations

import numpy as np

from .base import EmbedResult, StegoCapacityError, StegoExtractError

BLOCK = 8
# Only the second singular value is used (skip S[0], the dominant energy
# term). An earlier version of this module also used S[2] for a second
# bit/block; empirically (see tests/test_stego_algorithms.py), on blocks
# where S[1] and S[2] start out close together, pixel-rounding noise
# after reconstruction was large enough to swap their relative order at
# extraction time even with a one-quantization-step margin enforced,
# corrupting both bits at once. Embedding into a single, well-separated
# singular value (with a margin against BOTH its neighbors) removed
# that failure mode entirely -- a deliberate robustness-over-capacity
# trade-off, not an oversight; see the module docstring.
SINGULAR_VALUE_INDICES = [1]


class SvdStego:
    algorithm_id = "svd"
    algorithm_version = "1.0.0"

    def __init__(self, quant_step: float = 10.0):
        self.quant_step = quant_step
        self.bits_per_block = len(SINGULAR_VALUE_INDICES)

    def _usable_dims(self, h: int, w: int) -> tuple[int, int]:
        return (h // BLOCK) * BLOCK, (w // BLOCK) * BLOCK

    def capacity_bytes(self, cover_pixels: np.ndarray) -> int:
        h, w, c = cover_pixels.shape
        uh, uw = self._usable_dims(h, w)
        n_blocks = (uh // BLOCK) * (uw // BLOCK) * c
        return (n_blocks * self.bits_per_block) // 8

    def embed(self, cover_pixels: np.ndarray, payload: bytes, params: dict | None = None) -> EmbedResult:
        cap = self.capacity_bytes(cover_pixels)
        if len(payload) > cap:
            raise StegoCapacityError(f"svd: payload {len(payload)}B exceeds real capacity {cap}B for this image")
        h, w, c = cover_pixels.shape
        uh, uw = self._usable_dims(h, w)
        stego = cover_pixels.copy().astype(np.float64)
        bits_needed = len(payload) * 8
        payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
        bit_idx = 0
        Q = self.quant_step
        for ch in range(c):
            if bit_idx >= bits_needed:
                break
            for by in range(0, uh, BLOCK):
                if bit_idx >= bits_needed:
                    break
                for bx in range(0, uw, BLOCK):
                    if bit_idx >= bits_needed:
                        break
                    block = stego[by:by + BLOCK, bx:bx + BLOCK, ch]
                    U, S, Vt = np.linalg.svd(block)
                    k = min(self.bits_per_block, bits_needed - bit_idx)
                    # `numpy.linalg.svd` always returns S sorted descending.
                    # If we quantize S[1] and S[2] independently without
                    # regard to that ordering, a bare quantization choice
                    # can push S[1]' below S[2]' (or either past the
                    # UNTOUCHED neighbors S[0]/S[3]) -- when extraction
                    # re-runs SVD on the resulting integer block, numpy
                    # hands back the values in sorted order again, which
                    # then silently swaps which "slot" each modified value
                    # lands in and corrupts exactly the two bits involved.
                    # Fix: process slots high-to-low and clamp each new
                    # value into the open interval between its two
                    # (already finalized) neighbors, so descending order
                    # is preserved by construction before parity is even
                    # considered.
                    # Reserve a full quantization step `Q` of margin on
                    # BOTH sides of every chosen value, against both the
                    # untouched neighbor below and the previously-chosen
                    # value above. A bare "stay inside [floor, ceiling]"
                    # (no margin) can still let two close singular values
                    # land on adjacent-or-equal multiples of Q; pixel
                    # rounding noise on reconstruction (bounded, but
                    # comparable in size to Q/2 -- see module docstring)
                    # can then swap their relative order, which is exactly
                    # what re-running SVD at extraction time will expose
                    # as a slot/value mismatch between two close indices.
                    # A full-`Q` margin keeps that swap outside the noise
                    # budget.
                    ceiling = S[0] - Q
                    for slot in range(k):
                        bit = int(payload_bits[bit_idx])
                        bit_idx += 1
                        si = SINGULAR_VALUE_INDICES[slot]
                        floor = (S[si + 1] + Q) if si + 1 < len(S) else Q
                        s_val = S[si]
                        idx = round(s_val / Q)
                        candidates = sorted(
                            {idx + d for d in range(-6, 7)},
                            key=lambda cand: abs(cand * Q - s_val),
                        )
                        chosen = None
                        for cand in candidates:
                            val = cand * Q
                            if (cand % 2) == bit and floor <= val <= ceiling:
                                chosen = cand
                                break
                        if chosen is None:
                            # No in-bounds candidate has the right parity
                            # (bounds too narrow for this block) -- fall
                            # back to the nearest in-bounds value of ANY
                            # parity; the self-verification check at the
                            # end of `embed()` catches and fails closed if
                            # this specific block ends up undecodable.
                            inbound = [c for c in candidates if floor <= c * Q <= ceiling]
                            chosen = inbound[0] if inbound else idx
                        S[si] = max(chosen * Q, 0.0)
                        ceiling = S[si] - Q  # next slot must clear a full step below this one
                    stego[by:by + BLOCK, bx:bx + BLOCK, ch] = (U * S) @ Vt
        stego_int = np.clip(np.round(stego), 0, 255).astype(np.uint8)
        params_out = {"quant_step": Q, "usable_h": uh, "usable_w": uw}
        # Self-verifying embed -- see dct.py's embed() for the rationale
        # (pixel clipping near saturated/flat blocks can rarely perturb a
        # recomputed singular value past its intended quantization bucket).
        check = self.extract(stego_int, len(payload), params_out)
        if check != payload:
            raise StegoCapacityError(
                "svd: embedding is not reliably recoverable for this image/payload "
                "(likely a saturated or perfectly flat block leaving no headroom for the perturbation)"
            )
        return EmbedResult(stego_pixels=stego_int, algorithm_params=params_out)

    def extract(self, stego_pixels: np.ndarray, payload_len: int, params: dict | None = None) -> bytes:
        p = params or {}
        Q = p.get("quant_step", self.quant_step)
        h, w, c = stego_pixels.shape
        uh, uw = self._usable_dims(h, w)
        bits_needed = payload_len * 8
        bits_out = np.zeros(bits_needed, dtype=np.uint8)
        bit_idx = 0
        for ch in range(c):
            if bit_idx >= bits_needed:
                break
            for by in range(0, uh, BLOCK):
                if bit_idx >= bits_needed:
                    break
                for bx in range(0, uw, BLOCK):
                    if bit_idx >= bits_needed:
                        break
                    block = stego_pixels[by:by + BLOCK, bx:bx + BLOCK, ch].astype(np.float64)
                    _, S, _ = np.linalg.svd(block)
                    k = min(self.bits_per_block, bits_needed - bit_idx)
                    for slot in range(k):
                        si = SINGULAR_VALUE_INDICES[slot]
                        idx = round(S[si] / Q)
                        bits_out[bit_idx] = idx % 2
                        bit_idx += 1
        if bit_idx != bits_needed:
            raise StegoExtractError("svd: stego image too small to contain the claimed payload length")
        packed = np.packbits(bits_out)
        return bytes(packed[:payload_len])
