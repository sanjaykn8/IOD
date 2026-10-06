"""Common types for the 2D image-steganography subsystem.

Every algorithm in this package implements the `StegoAlgorithm` protocol:
real `embed`/`extract` on real `numpy` pixel arrays, a real capacity
estimate for a given cover image, and nothing else -- no algorithm here
invents a performance number. Actual timing and distortion metrics
(PSNR/SSIM/MSE) are measured by `stego.benchmark.BenchmarkEngine` against
the REAL output of a REAL embed/extract call on the image+payload at
hand; see that module's docstring for why this separation matters (spec
requirement: "RAG must never invent performance numbers").

Classification (see ../../../docs/claims-and-limitations.md): REAL. These
are genuine, runnable implementations of well-known classical 2D
steganography techniques operating on 8-bit RGB raster images. They are
simulation/prototype-grade (no adversarial steganalysis hardening, no
JPEG re-compression robustness beyond what each technique inherently
has) -- see each algorithm's module docstring for its specific, honestly
stated limitations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import numpy as np


class StegoCapacityError(ValueError):
    """Raised when a payload will not fit in a cover image under a given
    algorithm's real capacity for that image (feasibility gate failure)."""


class StegoExtractError(ValueError):
    """Raised when extraction fails integrity checks (bad hint, corrupted
    stego image, length field inconsistent with actual embedded data)."""


@dataclass
class EmbedResult:
    """Output of a real embed call: the modified pixel array plus the
    algorithm-specific parameters needed to extract again (these become
    part of the non-secret `StegoHint`, never the secret payload)."""

    stego_pixels: np.ndarray
    algorithm_params: dict = field(default_factory=dict)


@runtime_checkable
class StegoAlgorithm(Protocol):
    """Protocol every one of the 5 algorithms implements identically, so
    the benchmark engine and selector can treat them uniformly."""

    algorithm_id: str
    algorithm_version: str

    def capacity_bytes(self, cover_pixels: np.ndarray) -> int:
        """Real maximum payload size (bytes) this algorithm can embed in
        this specific cover image, computed from the image's actual
        dimensions/channels -- never a fixed constant guess."""
        ...

    def embed(self, cover_pixels: np.ndarray, payload: bytes, params: dict | None = None) -> EmbedResult:
        """Embed `payload` into a copy of `cover_pixels`. Raises
        `StegoCapacityError` if `len(payload) > capacity_bytes(...)`."""
        ...

    def extract(self, stego_pixels: np.ndarray, payload_len: int, params: dict | None = None) -> bytes:
        """Recover exactly `payload_len` bytes previously embedded by
        `embed` using the same `params`."""
        ...


def mse(cover: np.ndarray, stego: np.ndarray) -> float:
    """Real mean squared error between cover and stego pixel arrays."""
    a = cover.astype(np.float64)
    b = stego.astype(np.float64)
    return float(np.mean((a - b) ** 2))


def psnr(cover: np.ndarray, stego: np.ndarray, max_pixel: float = 255.0) -> float:
    """Real peak signal-to-noise ratio (dB), computed from the real MSE
    above. Returns `float('inf')` for a bit-identical pair (MSE == 0) --
    the mathematically correct limit, not a fabricated large number."""
    m = mse(cover, stego)
    if m == 0.0:
        return float("inf")
    return float(10.0 * np.log10((max_pixel ** 2) / m))


def ssim_metric(cover: np.ndarray, stego: np.ndarray) -> float:
    """Real structural similarity index, via scikit-image's reference
    implementation (not reimplemented by hand, to avoid a subtly wrong
    formula silently producing plausible-looking fake-real numbers)."""
    from skimage.metrics import structural_similarity

    if cover.ndim == 3:
        return float(structural_similarity(cover, stego, channel_axis=2, data_range=255))
    return float(structural_similarity(cover, stego, data_range=255))


def timed(fn, *args, **kwargs):
    """Run `fn` and return `(result, elapsed_ms)` using a real wall-clock
    measurement (`time.perf_counter`) around the real call -- this is
    what every "_ms" timing field in a `StegoMetrics` ultimately comes
    from; nothing here is estimated or looked up from a table."""
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return result, elapsed_ms
