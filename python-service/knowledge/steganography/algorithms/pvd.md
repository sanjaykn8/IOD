---
algorithm_id: pvd
title: Pixel-Value Differencing (PVD)
---

# Pixel-Value Differencing (PVD)

PVD embeds payload bits into the *difference* between pairs of adjacent
pixels rather than into a pixel's absolute value. A larger difference
between neighbors indicates an edge or high-contrast boundary, which can
absorb a proportionally larger change without becoming visually
noticeable; a smaller difference (a smooth region) can only absorb a
small change. This project's implementation (`stego/pvd.py`) follows the
original six-range quantization table from the technique's founding
paper, applied independently per RGB channel.

## Representative literature

- D.C. Wu and W.H. Tsai, "A steganographic method for images by pixel-
  value differencing," *Pattern Recognition Letters*, 24(9-10), 2003.
  (The original PVD paper; its six quantization ranges are the ones
  reused directly in this project's implementation.)
- H.C. Wu, N.I. Wu, C.S. Tsai, M.S. Hwang, "Image steganographic scheme
  based on pixel-value differencing and LSB replacement methods," *IEE
  Proceedings - Vision, Image and Signal Processing*, 2005 (a notable
  PVD+LSB hybrid extension, relevant context on capacity/quality
  trade-offs within the PVD family).

## Relevant trade-offs for the selector

- **Capacity**: adaptive per-pair, similar spirit to adaptive LSB but
  measured over pixel *pairs* rather than individual pixels -- real
  capacity depends heavily on the image's own edge content, always
  measured directly rather than assumed here.
- **Distortion**: generally lower than plain LSB for the same nominal
  bit count, since changes concentrate where the image already has
  high local contrast.
- **Robustness**: better resistance to simple LSB-plane steganalysis
  than plain LSB, since the embedding operates on a derived quantity
  (the difference) rather than directly on raw pixel LSBs, though it
  remains a spatial-domain technique.
- **Boundary behavior**: pairs near the 0 or 255 extremes have limited
  room to shift without leaving the valid pixel range; this project's
  implementation handles that case explicitly (see `stego/pvd.py`'s
  module docstring) rather than ignoring it.
