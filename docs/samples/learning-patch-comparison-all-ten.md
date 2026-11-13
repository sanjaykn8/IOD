# Patch-level steganography algorithm comparison (educational)

> **Educational experiment - not a live UAV transmission.** No UAV session, key or protocol state was involved.

* Experiment: `a85c5b25c82e40579c10da5f077b8367`
* Cover: 256x256 RGB synthetic natural-looking scene (generated, seed 2026) (256x256 RGB, sha256 `d275b445a0ddde3c`)
* Segmentation: `arg-cells-1`, 10 irregular patches; experiment patch **#2** (chosen by `largest`, 25088 pixels)
* Algorithms are this repository's implemented variants (see the Variant column), not canonical paper implementations. The production knowledge base and selector are not modified by experiments.
* Payload mode: `aead_fixture`; 112 bytes (896 bits), sha256 `b58c296f61985bbd`; same cover, patch and payload for every algorithm
* Payload construction: 46 plaintext bytes -> AppWire v1 112 bytes (50-byte header, 16-byte AEAD tag), TEST-ONLY key

## Metrics

| Algorithm | Variant | Status | Patch capacity bits | bits / patch sample | MSE | PSNR dB | SSIM | Patch PSNR dB | Embed ms | Extract ms | Bit acc. | BER | Outside-patch changes | Verification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lsb_replacement | lsb-replacement-msb-first-v1 (patch samples, raster order) | ok | 75264 | 0.011905 | 0.002274 | 74.564 | 0.999996 | 70.394 | 0.17 | 1.88 | 1.0000 | 0.000000 | 0 | aead_verified |
| lsb_matching | lsb-matching-pm1-seeded-v2 (patch samples; sign stream seeded per patch from the cover hash) | ok | 75264 | 0.011905 | 0.002274 | 74.564 | 0.999996 | 70.394 | 0.49 | 1.79 | 1.0000 | 0.000000 | 0 | aead_verified |
| pvd | wu-tsai-pvd-6range-v1 (pairs = consecutive patch samples) | ok | 165368 | 0.011905 | 0.289968 | 53.507 | 0.999764 | 49.337 | 1.34 | 2.77 | 1.0000 | 0.000000 | 0 | aead_verified |
| edge_adaptive_lsb | edge-mask-7msb-grad-threshold-v2 (gradient restricted to the patch) | ok | 1485 | 0.011905 | 0.002350 | 74.420 | 0.999980 | 70.250 | 1.59 | 3.56 | 1.0000 | 0.000000 | 0 | aead_verified |
| dct | dct8-midband-6coef-qim-v1 (complete 8x8 blocks inside the patch) | ok | 2352 | 0.011905 | 0.215220 | 54.802 | 0.998377 | 50.632 | 0.41 | 1.91 | 1.0000 | 0.000000 | 0 | aead_verified |
| dwt | haar-l1-hh-qim-v1 (complete 2x2 blocks inside the patch) | ok | 6272 | 0.011905 | 0.027578 | 63.725 | 0.999813 | 59.555 | 0.46 | 2.23 | 1.0000 | 0.000000 | 0 | aead_verified |
| dct_svd | dct8-svd-s1-qim-v1 (complete 8x8 blocks inside the patch) | rejected_capacity | 392 | 0.011905 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | not_extracted |
| hugo | HUGO additive approximation: exact single-change costs (T=90, sigma=1, gamma=1) + binary STC h=7 (custom submatrices), no model correction | ok | 37632 | 0.011905 | 0.000834 | 78.918 | 0.999994 | 74.748 | 149.00 | 3.21 | 1.0000 | 0.000000 | 0 | aead_verified |
| wow | WOW (p=-1, db8 filter bank) + binary STC h=7 (custom submatrices) | ok | 37632 | 0.011905 | 0.000783 | 79.192 | 0.999994 | 75.022 | 60.55 | 3.08 | 1.0000 | 0.000000 | 0 | aead_verified |
| s_uniward | S-UNIWARD (spatial, sigma=1, db8 filter bank) + binary STC h=7 (custom submatrices) | ok | 37632 | 0.011905 | 0.000768 | 79.277 | 0.999994 | 75.107 | 60.05 | 3.17 | 1.0000 | 0.000000 | 0 | aead_verified |

## Per-patch survey (measured capacity in bits; read-only knowledge-base ranking)

| Patch | Pixels | Gradient | 8x8 blocks | KB top-1 | Unsupported geometry |
|---|---|---|---|---|---|
| 0 | 1408 | 5.40 | 22 | lsb_replacement | - |
| 1 | 4224 | 4.82 | 66 | s_uniward | - |
| 2 | 25088 | 4.17 | 392 | dct | - |
| 3 | 3264 | 4.12 | 51 | s_uniward | - |
| 4 | 13888 | 4.15 | 217 | dct | - |
| 5 | 11200 | 26.32 | 175 | wow | - |
| 6 | 1280 | 27.65 | 20 | wow | - |
| 7 | 1152 | 3.90 | 18 | s_uniward | - |
| 8 | 2240 | 26.62 | 35 | wow | - |
| 9 | 1792 | 25.39 | 28 | wow | - |

## Robustness (outcome / oracle BER)

| Algorithm | none | jpeg95 | jpeg75 | jpeg50 | resize50 | crop4 | gauss1 | gauss3 | saltpepper | blur3 | bright2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| lsb_replacement | recovered / 0.000 | failed / 0.512 | failed / 0.478 | failed / 0.510 | failed / 0.513 | failed / 1.000 | failed / 0.474 | failed / 0.523 | partial / 0.004 | failed / 0.488 | recovered / 0.000 |
| lsb_matching | recovered / 0.000 | failed / 0.493 | failed / 0.482 | failed / 0.519 | failed / 0.517 | failed / 1.000 | failed / 0.474 | failed / 0.523 | partial / 0.004 | failed / 0.488 | recovered / 0.000 |
| pvd | recovered / 0.000 | failed / 0.470 | failed / 0.516 | failed / 0.480 | failed / 0.458 | failed / 1.000 | failed / 0.487 | failed / 0.478 | failed / 0.243 | failed / 0.478 | partial / 0.008 |
| edge_adaptive_lsb | recovered / 0.000 | failed / 1.000 | failed / 1.000 | failed / 1.000 | failed / 1.000 | failed / 1.000 | failed / 0.469 | failed / 0.503 | failed / 0.481 | failed / 1.000 | recovered / 0.000 |
| dct | recovered / 0.000 | failed / 0.413 | failed / 0.414 | failed / 0.430 | failed / 0.384 | failed / 1.000 | recovered / 0.000 | partial / 0.040 | failed / 0.151 | partial / 0.074 | recovered / 0.000 |
| dwt | recovered / 0.000 | failed / 0.427 | failed / 0.423 | failed / 0.422 | failed / 0.423 | failed / 1.000 | partial / 0.088 | failed / 0.481 | partial / 0.020 | failed / 0.423 | recovered / 0.000 |
| hugo | recovered / 0.000 | failed / 0.502 | failed / 0.491 | failed / 0.509 | failed / 0.483 | failed / 1.000 | failed / 0.528 | failed / 0.467 | failed / 0.122 | failed / 0.496 | recovered / 0.000 |
| wow | recovered / 0.000 | failed / 0.517 | failed / 0.531 | failed / 0.502 | failed / 0.490 | failed / 1.000 | failed / 0.513 | failed / 0.500 | failed / 0.116 | failed / 0.508 | recovered / 0.000 |
| s_uniward | recovered / 0.000 | failed / 0.490 | failed / 0.481 | failed / 0.474 | failed / 0.491 | failed / 1.000 | failed / 0.506 | failed / 0.501 | partial / 0.074 | failed / 0.517 | recovered / 0.000 |

Attack parameters:

* `none`: No attack (lossless PNG) {}
* `jpeg95`: JPEG recompression {"quality":95}
* `jpeg75`: JPEG recompression {"quality":75}
* `jpeg50`: JPEG recompression {"quality":50}
* `resize50`: Resize down 50% and back (bilinear) {"factor":0.5}
* `crop4`: Crop 4 px from left and top (image becomes smaller) {"pixels":4}
* `gauss1`: Gaussian noise {"seed":11,"sigma":1.0}
* `gauss3`: Gaussian noise {"seed":12,"sigma":3.0}
* `saltpepper`: Salt-and-pepper noise {"fraction":0.005,"seed":13}
* `blur3`: Gaussian blur 3x3 {"sigma":0.8}
* `bright2`: Brightness +2 {"offset":2}

## Metric definitions

* **ber**: (wrong bits + missing bits) / expected payload bits; 1.0 if extraction failed entirely
* **bit_accuracy**: matching bits / expected payload bits
* **bits_per_patch_sample**: payload_bits / (patch pixels x channels)
* **capacity_bits**: capacity measured by the algorithm implementation on this patch mask (not a knowledge-base estimate)
* **embed_ms**: patch embedding duration (perf_counter); setup_ms = cost evaluation inside it (STC methods)
* **extract_ms**: PNG decode + patch extraction
* **mse**: mean over all samples of the IMAGE of (cover - stego)^2
* **outside_patch_changes**: samples changed outside the patch mask (must be 0)
* **patch_mse**: mean over the samples of the chosen PATCH only of (cover - stego)^2
* **patch_psnr_db**: 10 log10(255^2 / patch_mse); null when the patch is unchanged
* **payload_bits**: payload bytes x 8
* **psnr_db**: 10 log10(255^2 / MSE) over the image; null when MSE = 0 (identical images)
* **robustness**: per attack: extraction from the attacked image with the known patch mask and parameters (oracle); outcome recovered (BER 0) / partial (BER <= 0.1) / failed (BER ~0.5 is chance level)
* **ssim**: mean SSIM over the image, uniform 7x7 window, K1=0.01, K2=0.03, L=255

## Interpretation

* High PSNR/SSIM means the stego image looks like the cover; it does not prove resistance to steganalysis.
* Capacity depends on the patch: block methods need complete 8x8 / 2x2 blocks inside the mask, edge-adaptive LSB needs edges.
* Exact extraction from an unmodified PNG does not establish robustness to lossy transforms.
* HUGO/WOW/S-UNIWARD minimise a distortion model; that is not a proof that no steganalyst can detect the message.
