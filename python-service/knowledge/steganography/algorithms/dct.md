---
algorithm_id: dct
title: DCT-Domain Steganography
---

# DCT-Domain Steganography

Discrete Cosine Transform (DCT) based steganography embeds payload bits
into frequency-domain coefficients of an image, computed block-by-block
(classically 8x8, matching JPEG's own block size) rather than directly
into pixel values. Mid-frequency coefficients are generally preferred
over the DC term (which carries the block's average brightness and is
highly visible if altered) and over the very highest frequencies (which
natural images carry little energy in, making changes there both low-
capacity and sometimes fragile). This project's implementation
(`stego/dct.py`) uses quantization-index modulation (QIM) on 8 fixed
mid-frequency coefficient positions per 8x8 block, per channel.

## Representative literature

- A. Westfeld, "F5 -- A Steganographic Algorithm," *Information Hiding
  2001*, Lecture Notes in Computer Science vol. 2137 (a well-known
  JPEG/DCT-domain steganography system; not reproduced here, but
  representative of the DCT-domain embedding family this project's
  simpler QIM approach belongs to).
- N.F. Johnson and S. Jajodia, "Exploring steganography: Seeing the
  unseen," *IEEE Computer*, 31(2), 1998 (general survey covering
  DCT/transform-domain techniques' capacity/robustness motivations).

## Relevant trade-offs for the selector

- **Capacity**: fixed at a configurable number of bits per 8x8 block
  (8 by default in this project), giving a predictable nominal capacity
  independent of local image content -- unlike adaptive LSB/PVD, whose
  capacity varies with texture.
- **Distortion**: generally good perceptual quality for a given payload
  size, since mid-frequency coefficients carry less perceptually salient
  energy than low frequencies, but can be more visible than spatial-
  domain methods on very flat/smooth blocks (little coefficient energy
  to "hide" a quantization step within).
- **Robustness**: more resistant to simple spatial-domain steganalysis
  than LSB/PVD, since the embedding lives in a transform domain, though
  this implementation works directly on PNG pixel DCT, not inside an
  actual JPEG compression pipeline, so it carries none of JPEG's own
  re-compression robustness claims.
- **Speed**: slower than spatial-domain methods (forward+inverse DCT per
  block), though still fast in absolute terms for prototype-scale
  images -- always confirmed by the benchmark engine's real timing, not
  assumed from this description.
