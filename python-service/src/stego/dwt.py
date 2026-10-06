"""DWT-domain steganography via quantization-index modulation (QIM).

Each color channel gets one real level of a 2D discrete wavelet
transform (`pywt.dwt2`, Haar wavelet -- chosen because it is an exact
orthogonal transform with no edge-effect ambiguity for even-sized
images, which keeps the embed/extract round trip exact). That produces
four subbands (`LL`, `LH`, `HL`, `HH`); this implementation embeds into
the `HH` (diagonal detail / highest-frequency) subband, the same choice
classical DWT-steganography surveys recommend (see
`docs/steganography.md` for the citation) because it carries the least
perceptually-significant energy in most natural images.

Embedding uses the same quantization-index-modulation idea as the DCT
algorithm in this package (`dct.py`): each `HH` coefficient is nudged to
the nearest multiple of a step size `Q` whose index parity encodes one
payload bit, then the channel is reconstructed with the real inverse
DWT (`pywt.idwt2`) and rounded/clipped back to `[0, 255]`. Extraction
re-runs the real forward DWT on the actual stego pixels and reads
parity directly -- no information beyond the image and payload length
is needed.

Honest limitations: requires even height and width (Haar DWT's natural
domain for an exact round trip); an odd dimension is cropped by one
pixel on the affected edge, exactly as `dct.py` crops to a multiple of
8 -- disclosed via `algorithm_params`. Single-level decomposition only
(no multi-resolution embedding). `Q=12.0` default was chosen for the
same rounding-noise-margin reason explained in `dct.py` and verified by
`tests/test_stego_dwt.py`.
"""

from __future__ import annotations

import numpy as np
import pywt

from .base import EmbedResult, StegoCapacityError, StegoExtractError

WAVELET = "haar"


class DwtStego:
    algorithm_id = "dwt"
    algorithm_version = "1.0.0"

    def __init__(self, quant_step: float = 12.0):
        self.quant_step = quant_step

    def _usable_dims(self, h: int, w: int) -> tuple[int, int]:
        return h - (h % 2), w - (w % 2)

    def capacity_bytes(self, cover_pixels: np.ndarray) -> int:
        h, w, c = cover_pixels.shape
        uh, uw = self._usable_dims(h, w)
        _, (_, _, hh) = pywt.dwt2(np.zeros((uh, uw)), WAVELET)
        total_bits = hh.size * c
        return total_bits // 8

    def embed(self, cover_pixels: np.ndarray, payload: bytes, params: dict | None = None) -> EmbedResult:
        cap = self.capacity_bytes(cover_pixels)
        if len(payload) > cap:
            raise StegoCapacityError(f"dwt: payload {len(payload)}B exceeds real capacity {cap}B for this image")
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
            channel = stego[:uh, :uw, ch]
            ll, (lh, hl, hh) = pywt.dwt2(channel, WAVELET)
            flat_hh = hh.flatten()
            n = flat_hh.shape[0]
            k = min(n, bits_needed - bit_idx)
            for i in range(k):
                bit = int(payload_bits[bit_idx])
                bit_idx += 1
                c_val = flat_hh[i]
                idx = round(c_val / Q)
                if (idx % 2) != bit:
                    up, down = idx + 1, idx - 1
                    idx = up if abs(up * Q - c_val) <= abs(down * Q - c_val) else down
                flat_hh[i] = idx * Q
            hh_mod = flat_hh.reshape(hh.shape)
            recon = pywt.idwt2((ll, (lh, hl, hh_mod)), WAVELET)
            stego[:uh, :uw, ch] = recon[:uh, :uw]
        stego_int = np.clip(np.round(stego), 0, 255).astype(np.uint8)
        params_out = {"quant_step": Q, "usable_h": uh, "usable_w": uw}
        # Self-verifying embed -- see dct.py's embed() for why this
        # check exists (pixel clipping near saturated/flat regions can
        # rarely flip a coefficient's quantization parity).
        check = self.extract(stego_int, len(payload), params_out)
        if check != payload:
            raise StegoCapacityError(
                "dwt: embedding is not reliably recoverable for this image/payload "
                "(likely a saturated or perfectly flat region leaving no headroom for the DWT perturbation)"
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
            channel = stego_pixels[:uh, :uw, ch].astype(np.float64)
            _, (_, _, hh) = pywt.dwt2(channel, WAVELET)
            flat_hh = hh.flatten()
            n = flat_hh.shape[0]
            k = min(n, bits_needed - bit_idx)
            for i in range(k):
                idx = round(flat_hh[i] / Q)
                bits_out[bit_idx] = idx % 2
                bit_idx += 1
        if bit_idx != bits_needed:
            raise StegoExtractError("dwt: stego image too small to contain the claimed payload length")
        packed = np.packbits(bits_out)
        return bytes(packed[:payload_len])
