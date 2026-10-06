# 2D Image Steganography Algorithms

**Classification: REAL.** `python-service/src/stego/` implements five
genuine, runnable classical 2D image-steganography techniques against
real 8-bit RGB raster images (`numpy` arrays, read/written as PNG).
Every algorithm shares the `StegoAlgorithm` protocol
(`stego/base.py`): a real `capacity_bytes(cover_pixels)` computed from
the image's actual dimensions (never a fixed constant guess), a real
`embed`, and a real `extract`. None of them estimates, looks up, or
otherwise fabricates a capacity or quality number -- see
`docs/claims-and-limitations.md` §5 for the project-wide classification
table these feed into.

They are simulation/prototype-grade: no adversarial steganalysis
hardening, and no robustness beyond what each technique inherently has
against recompression or resizing (this project never recompresses or
resizes a stego image in transit -- see `docs/image-pipeline.md`).

## The five algorithms

### Adaptive LSB (`adaptive_lsb.py`)

Classic LSB substitution wastes capacity in smooth regions (even a
1-bit change can show as banding) and under-uses high-detail regions
(the eye cannot tell a 3-bit change from sensor noise there). This
implementation adapts the number of embedded bits **per pixel
location** to real local texture:

1. Each pixel's "masked luma" = `mean(R,G,B)` with the low 3 bits
   cleared (`& 0xF8`) -- identical whether read from the cover or the
   stego image, since embedding never touches bit 3 or above. This is
   what makes the bit-allocation map independently reconstructible at
   extraction time from the stego image alone.
2. Real local variance of that masked luma over a 3x3 neighborhood
   (`scipy.ndimage.uniform_filter`).
3. Variance is bucketed into {1, 2, 3} bits/channel (low-detail -> 1
   bit, medium -> 2, high-detail/edge -> 3), via two configurable
   thresholds.
4. `k` LSBs of the payload bitstream are embedded into each of a
   pixel's 3 channels at that location, raster-scan order.

Capacity = `sum(bucket bits per pixel) * channels / 8` bytes -- computed
from the real bucket map, not a fixed bits-per-pixel assumption.

### Pixel-Value Differencing / PVD (`pvd.py`)

Wu & Tsai, *"A steganographic method for images by pixel-value
differencing,"* Pattern Recognition Letters, 2003. Adjacent pixels are
processed in non-overlapping pairs; the magnitude of their difference
indicates how "edgy" that spot is, and a bigger difference tolerates a
bigger embedding change without becoming visible. Real quantization
ranges (the original paper's six ranges):

| difference range | width | bits |
|---|---|---|
| [0, 7] | 8 | 3 |
| [8, 15] | 8 | 3 |
| [16, 31] | 16 | 4 |
| [32, 63] | 32 | 5 |
| [64, 127] | 64 | 6 |
| [128, 255] | 128 | 7 |

For a pair `(p1, p2)` with `d = p2 - p1`, `|d|` falls in range
`[lo, hi]` with capacity `n` bits; to embed an `n`-bit value `b`, the
pair is adjusted so the new difference has magnitude `lo + b` (same
sign as `d`), the change split as evenly as possible between the two
pixels.

### DCT-domain QIM (`dct.py`)

Each channel is split into non-overlapping 8x8 blocks; each block gets
a real 2D type-II DCT (`scipy.fft.dctn`, orthonormal norm -- the same
transform family JPEG itself uses). A fixed set of mid-frequency
coefficients per block (avoiding the highly-visible DC term and the
lowest-energy highest frequencies) each carry one payload bit via
quantization-index modulation: the coefficient is nudged to the
nearest multiple of a step size `Q` whose index parity encodes the bit,
then the block is inverse-DCT'd and rounded/clipped to `[0, 255]`.
Extraction re-runs the real forward DCT on the actual stego pixels and
reads parity directly -- self-contained from the stego image alone.
Honest robustness note: `Q` must be large enough that pixel-domain
rounding noise (bounded by the inverse DCT's orthonormality) cannot
flip a coefficient's parity bucket; too small a `Q` is a real, visible
failure mode, not hidden behind a fudge factor.

### DWT-domain QIM (`dwt.py`)

Each channel gets one real level of a 2D discrete wavelet transform
(`pywt.dwt2`, Haar wavelet -- an exact orthogonal transform with no
edge-effect ambiguity for even-sized images). This produces four
subbands (`LL`, `LH`, `HL`, `HH`); embedding targets `HH` (diagonal
detail / highest frequency), the standard choice in DWT-steganography
surveys because it carries the least perceptually-significant energy
in most natural images. Same QIM idea as DCT: each `HH` coefficient's
parity-under-`Q` encodes one bit; reconstruction uses the real inverse
DWT (`pywt.idwt2`). Honest limitations: requires even height/width
(cropped by one pixel on an odd edge, disclosed via
`algorithm_params`); single-level decomposition only (not a
multi-resolution scheme).

### SVD-domain quantization (`svd.py`)

Each channel is split into 8x8 blocks (same blocking as DCT); each
block gets a real singular value decomposition
(`numpy.linalg.svd`: `block = U @ diag(S) @ Vt`). The largest singular
value `S[0]` dominates a block's brightness/contrast and visibly
distorts the image if touched, so this embeds one bit per block into
the **second** singular value `S[1]` instead, via the same QIM
approach, with a full-`Q`-step margin enforced against both neighbors
(`S[0]` above, `S[2]` below). That margin is not a theoretical nicety:
`numpy.linalg.svd` always returns singular values sorted descending, so
quantizing `S[1]` without regard to its neighbors can -- on real,
near-flat blocks seen during this project's own testing -- round it to
a value at or below `S[2]`, which silently relabels which physical
value is "`S[1]`" after a fresh SVD at extraction and corrupts the bit.
The margin logic exists because this failure was actually observed and
debugged, not as a precaution against a hypothetical.

## Shared measurement primitives (`stego/base.py`)

`mse`, `psnr` (returns real `+inf` for a bit-identical pair, the
mathematically correct limit -- never a fabricated large number), and
`ssim_metric` (via scikit-image's reference implementation, not a
hand-rolled formula, specifically to avoid a subtly-wrong
reimplementation silently producing plausible-looking fake numbers).
`timed()` wraps a real `time.perf_counter()` measurement around a real
call -- every `_ms` figure anywhere in this subsystem traces back to
this function, never an estimate.

## Where measurement and selection happen instead

This module never measures *itself* against competitors and never
picks a winner -- see `docs/algorithm-selection.md` for
`stego.benchmark` (the only place embed/extract time, PSNR, SSIM are
actually measured) and the deterministic selector, and
`docs/rag-stego-selection.md` for how the RAG narrative is built
strictly from those measurements.

## Tests

`python-service/tests/test_stego_algorithms.py` -- per-algorithm
round-trip correctness (embed then extract recovers the exact payload)
across multiple payload sizes including boundary cases (empty payload,
payload exactly at capacity, payload one byte over capacity raising
`StegoCapacityError`), and that each algorithm's own
`capacity_bytes` is never exceeded by its own `embed`.
`test_stego_benchmark.py` covers the benchmark engine's feasibility
gating and metric computation; `test_stego_api.py` covers the Flask
endpoints end-to-end. Run with `cd python-service && pytest`.
