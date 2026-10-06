---
algorithm_id: adaptive_lsb
title: Adaptive LSB Substitution
---

# Adaptive LSB Substitution

Least-significant-bit (LSB) substitution is the oldest and simplest
family of spatial-domain image steganography techniques: payload bits
directly replace the lowest-order bit(s) of selected pixel channels.
Plain (non-adaptive) LSB embeds the same fixed number of bits per pixel
everywhere, which wastes usable capacity in smooth image regions (where
even small changes can show as banding) and under-uses high-texture
regions (where the human eye cannot distinguish a few bits of LSB noise
from ordinary sensor noise).

**Adaptive** variants, including the one implemented in this project
(`stego/adaptive_lsb.py`), instead vary the number of embedded bits per
pixel location according to the image's own local texture/edge content:
more bits where detail already masks the change, fewer (or none) in
flat regions. This project's implementation buckets a 3x3 local-variance
measurement of the "masked luma" (top 5 bits of the pixel's RGB average)
into three tiers (1, 2, or 3 bits/channel).

## Representative literature

- C.K. Chan and L.M. Cheng, "Hiding data in images by simple LSB
  substitution," *Pattern Recognition*, 37(3), 2004.
- Classic LSB steganalysis context: J. Fridrich, M. Goljan, R. Du,
  "Detecting LSB steganography in color and gray-scale images," *IEEE
  MultiMedia*, 2001 (relevant to this technique's known weakness
  against statistical steganalysis -- chi-square and RS analysis).

## Relevant trade-offs for the selector

- **Capacity**: potentially the highest of the five algorithms in this
  project (up to 3 bits/channel/pixel in high-detail areas), but the
  REAL achievable capacity for any given image is always measured by
  the benchmark engine, never read off this document.
- **Distortion**: low in high-detail regions, can be more visible in
  smooth regions if too many bits are forced there -- mitigated by the
  variance-based bucketing, but still generally the most distortion-
  prone of the five for a fixed payload size, especially on very flat
  covers.
- **Robustness**: weakest of the five against statistical steganalysis
  (no transform-domain spreading of the embedding).
- **Speed**: fastest to embed/extract (no transform computed).
