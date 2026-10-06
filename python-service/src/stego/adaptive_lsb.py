"""Adaptive LSB steganography.

Classic (non-adaptive) LSB substitution embeds a fixed number of bits in
every pixel, which wastes capacity in smooth regions (where even a
1-bit change is sometimes visible as banding) and under-uses high-detail
regions (where the human eye cannot tell a 3-bit LSB change from sensor
noise). This implementation adapts the number of embedded bits PER PIXEL
LOCATION to the image's real local texture:

  1. Compute each pixel's "masked luma" = mean(R,G,B) with the low 3
     bits cleared (`& 0xF8`). Clearing those bits up front means this
     value is IDENTICAL whether read from the cover image or from the
     stego image after embedding -- embedding only ever touches the low
     <=3 bits of a channel, never bit 3 or above. This is what makes
     the bit-allocation map independently (and identically)
     reconstructible at extraction time, from the stego image alone,
     with no side channel needed.
  2. Compute the local variance of the masked luma over a 3x3
     neighborhood (`scipy.ndimage.uniform_filter`, a real sliding-window
     computation, not an approximation).
  3. Bucket that real variance into {1, 2, 3} bits-per-channel using two
     configurable thresholds (low-detail -> 1 bit, medium -> 2 bits,
     high-detail/edge -> 3 bits).
  4. Embed `k` LSBs of the payload's bitstream into each of the pixel's
     3 channels at that location, in fixed raster-scan order, stopping
     exactly at the payload's real bit length (the final slot may use
     fewer than `k` bits of the ones its bucket would allow).

Honest limitations (see docs/claims-and-limitations.md): the 1/2/3
variance thresholds below are fixed, reasonable-but-NOT-corpus-calibrated
defaults for an 8-bit image -- they were chosen to produce a usable
capacity/distortion trade-off on ordinary photographic test images, not
tuned against a steganalysis benchmark. This is a classical, visible-
domain LSB variant with no resistance to statistical LSB steganalysis
(chi-square attacks, RS analysis) -- it should be read as a research
prototype, not a security control against a motivated image analyst.
"""

from __future__ import annotations

import numpy as np
from scipy.ndimage import uniform_filter

from .base import EmbedResult, StegoCapacityError, StegoExtractError


class AdaptiveLsbStego:
    algorithm_id = "adaptive_lsb"
    algorithm_version = "1.0.0"

    def __init__(self, window: int = 3, low_threshold: float = 15.0, high_threshold: float = 100.0):
        self.window = window
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    # -- shared bucket-map computation, used identically by embed+extract --
    def _bucket_map(self, pixels: np.ndarray) -> np.ndarray:
        masked = (pixels.astype(np.int32) & 0xF8)
        luma = masked.mean(axis=2)
        mean = uniform_filter(luma, size=self.window, mode="reflect")
        mean_sq = uniform_filter(luma * luma, size=self.window, mode="reflect")
        variance = np.clip(mean_sq - mean * mean, 0.0, None)
        buckets = np.ones_like(variance, dtype=np.uint8)
        buckets[variance >= self.low_threshold] = 2
        buckets[variance >= self.high_threshold] = 3
        return buckets

    def capacity_bytes(self, cover_pixels: np.ndarray) -> int:
        buckets = self._bucket_map(cover_pixels)
        channels = cover_pixels.shape[2] if cover_pixels.ndim == 3 else 1
        total_bits = int(buckets.sum()) * channels
        return total_bits // 8

    def embed(self, cover_pixels: np.ndarray, payload: bytes, params: dict | None = None) -> EmbedResult:
        cap = self.capacity_bytes(cover_pixels)
        if len(payload) > cap:
            raise StegoCapacityError(f"adaptive_lsb: payload {len(payload)}B exceeds real capacity {cap}B for this image")
        h, w, c = cover_pixels.shape
        buckets = self._bucket_map(cover_pixels)
        stego = cover_pixels.copy()
        bits_needed = len(payload) * 8
        payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
        bit_idx = 0
        for y in range(h):
            if bit_idx >= bits_needed:
                break
            for x in range(w):
                if bit_idx >= bits_needed:
                    break
                k_full = int(buckets[y, x])
                for ch in range(c):
                    if bit_idx >= bits_needed:
                        break
                    k = min(k_full, bits_needed - bit_idx)
                    chunk = payload_bits[bit_idx:bit_idx + k]
                    bit_idx += k
                    chunk_val = 0
                    for b in chunk:
                        chunk_val = (chunk_val << 1) | int(b)
                    val = int(stego[y, x, ch])
                    cleared = val & (~((1 << k) - 1) & 0xFF)
                    stego[y, x, ch] = cleared | chunk_val
        return EmbedResult(stego_pixels=stego, algorithm_params={"window": self.window, "low_threshold": self.low_threshold, "high_threshold": self.high_threshold})

    def extract(self, stego_pixels: np.ndarray, payload_len: int, params: dict | None = None) -> bytes:
        p = params or {}
        window = p.get("window", self.window)
        low_t = p.get("low_threshold", self.low_threshold)
        high_t = p.get("high_threshold", self.high_threshold)
        algo = AdaptiveLsbStego(window=window, low_threshold=low_t, high_threshold=high_t)
        buckets = algo._bucket_map(stego_pixels)
        h, w, c = stego_pixels.shape
        bits_needed = payload_len * 8
        bits_out = np.zeros(bits_needed, dtype=np.uint8)
        bit_idx = 0
        for y in range(h):
            if bit_idx >= bits_needed:
                break
            for x in range(w):
                if bit_idx >= bits_needed:
                    break
                k_full = int(buckets[y, x])
                for ch in range(c):
                    if bit_idx >= bits_needed:
                        break
                    k = min(k_full, bits_needed - bit_idx)
                    val = int(stego_pixels[y, x, ch])
                    chunk_val = val & ((1 << k) - 1)
                    for i in range(k - 1, -1, -1):
                        bits_out[bit_idx] = (chunk_val >> i) & 1
                        bit_idx += 1
        if bit_idx != bits_needed:
            raise StegoExtractError("adaptive_lsb: stego image too small to contain the claimed payload length")
        packed = np.packbits(bits_out)
        return bytes(packed[:payload_len])
