---
algorithm_id: svd
title: SVD-Domain Steganography
---

# SVD-Domain Steganography

Singular Value Decomposition (SVD) based steganography embeds payload
bits into the singular values of small image blocks (`block = U @
diag(S) @ Vt`) rather than into pixel values or frequency-domain
coefficients directly. The largest singular value of a block dominates
its overall energy (roughly, average brightness/contrast) and is highly
visible if altered; smaller singular values carry progressively less
perceptually significant structure. This project's implementation
(`stego/svd.py`) embeds one bit per 8x8 block into the SECOND singular
value only, using quantization-index modulation with an explicit
margin against its neighboring singular values -- a deliberate,
documented robustness-over-capacity trade-off reached after this
project's own testing showed embedding into two adjacent singular
values could have their relative order swapped by ordinary pixel-
rounding noise on some blocks (see the module's docstring for the
concrete failure mode this design avoids).

## Representative literature

- C. Bergman and J. Davidson, "Unitary embedding for data hiding with
  the SVD," *Proc. SPIE 5681, Security, Steganography, and Watermarking
  of Multimedia Contents VII*, 2005 (representative of the SVD-domain
  singular-value embedding family this project's implementation
  belongs to).
- R. Liu and T. Tan, "An SVD-based watermarking scheme for protecting
  rightful ownership," *IEEE Transactions on Multimedia*, 4(1), 2002
  (SVD-domain embedding in the closely related watermarking context,
  relevant background on singular-value perturbation stability).

## Relevant trade-offs for the selector

- **Capacity**: the lowest nominal capacity of the five algorithms in
  this project (1 bit per 8x8 block, versus DCT's 8 bits/block at the
  same block size) -- a direct, disclosed consequence of this
  project's robustness-margin design, not an inherent property of SVD
  steganography in general.
- **Distortion**: can offer good perceptual quality, since it avoids
  the block's dominant (highly visible) singular value entirely.
- **Robustness**: singular values are comparatively stable under small
  perturbations (Weyl's inequality bounds how much they can move for a
  bounded perturbation), which is part of why this implementation's
  margin-based design works, but also means the usable "room" for
  embedding within a single block is limited.
- **Speed**: an SVD (and its reconstruction) per 8x8 block is
  numerically heavier than a DCT or Haar DWT of the same block size,
  typically making this the slowest of the five algorithms -- always
  confirmed by the benchmark engine's real timing.
