---
algorithm_id: dwt
title: DWT-Domain Steganography
---

# DWT-Domain Steganography

Discrete Wavelet Transform (DWT) based steganography embeds payload
bits into wavelet-domain subband coefficients rather than spatial pixel
values or DCT-block coefficients. A single-level 2D DWT decomposes an
image into four subbands: `LL` (coarse approximation, carries most of
the perceptually significant energy), and `LH`/`HL`/`HH` (horizontal,
vertical, and diagonal detail). This project's implementation
(`stego/dwt.py`) embeds into the `HH` (diagonal detail) subband using
the Haar wavelet, which is exactly invertible for even-sized images and
has no edge-effect ambiguity -- a deliberate choice favoring exact
round-trip reconstruction over the smoother frequency response of
longer wavelets (e.g. Daubechies-4/8).

## Representative literature

- P.Y. Chen and H.J. Lin, "A DWT Based Approach for Image
  Steganography," *International Journal of Applied Science and
  Engineering*, 4(3), 2006 (representative of the DWT-domain,
  detail-subband embedding family this project's implementation
  belongs to).
- N.F. Johnson and S. Jajodia, "Exploring steganography: Seeing the
  unseen," *IEEE Computer*, 31(2), 1998 (general transform-domain
  motivation, as cited for DCT above).

## Relevant trade-offs for the selector

- **Capacity**: one bit per `HH`-subband coefficient; for a Haar DWT,
  the `HH` subband has roughly a quarter of the image's total pixel
  count (per channel), giving a predictable nominal capacity -- always
  confirmed by real measurement, not assumed from subband size alone.
- **Distortion**: embedding in the diagonal detail subband generally
  preserves perceptual quality well, since `HH` carries the least
  visually significant energy of the four subbands in most natural
  images.
- **Robustness**: transform-domain embedding gives it similar
  steganalysis resistance advantages to DCT; single-level decomposition
  only in this implementation (no multi-resolution embedding).
- **Speed**: a 2D DWT/inverse-DWT pass per channel -- typically
  comparable to or faster than the block-by-block DCT pass over the
  same image, confirmed by the benchmark engine rather than assumed
  here.
