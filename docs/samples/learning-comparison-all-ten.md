# Steganography algorithm comparison (educational)

> **Educational experiment - not a live UAV transmission.** No UAV session, key or protocol state was involved.

* Experiment: `599a55473eb6447fa45bf4f8fc851ab9`
* Cover: 256x256 RGB synthetic natural-looking scene (generated, seed 2026) (256x256 RGB, sha256 `d275b445a0ddde3c`)
* Payload mode: `aead_fixture`; 112 bytes (896 bits), sha256 `0d359641bb52f82d`; same cover and payload for every algorithm
* Payload construction: 46 plaintext bytes -> AppWire v1 112 bytes (50-byte header, 16-byte AEAD tag), TEST-ONLY key

## Metrics

| Algorithm | Variant | Status | Capacity bits (raw / verified) | bpp | MSE | PSNR dB | SSIM | Embed ms | Extract ms | Bit acc. | BER | Verification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lsb_replacement | lsb-replacement-msb-first-v1 | ok | 196480 / 196480 | 0.013672 | 0.002655 | 73.890 | 0.999996 | 0.15 | 2.52 | 1.0000 | 0.000000 | aead_verified |
| lsb_matching | lsb-matching-pm1-seeded-v1 | ok | 196480 / 196480 | 0.013672 | 0.002655 | 73.890 | 0.999996 | 0.64 | 2.38 | 1.0000 | 0.000000 | aead_verified |
| pvd | wu-tsai-pvd-6range-v1 | ok | 441465 / 441464 | 0.013672 | 0.194758 | 55.236 | 0.999848 | 5.14 | 8.42 | 1.0000 | 0.000000 | aead_verified |
| edge_adaptive_lsb | edge-mask-7msb-grad-threshold-v1 | ok | 44497 / 44496 | 0.013672 | 0.002584 | 74.008 | 0.999983 | 1.58 | 4.51 | 1.0000 | 0.000000 | aead_verified |
| dct | dct8-midband-6coef-qim-v1 | ok | 5952 / 5952 | 0.013672 | 0.210007 | 54.908 | 0.998328 | 0.43 | 2.37 | 1.0000 | 0.000000 | aead_verified |
| dwt | haar-l1-hh-qim-v1 | ok | 16256 / 16256 | 0.013672 | 0.027033 | 63.812 | 0.999814 | 0.82 | 2.40 | 1.0000 | 0.000000 | aead_verified |
| dct_svd | dct8-svd-s1-qim-v1 | ok | 992 / 992 | 0.013672 | 0.365392 | 52.503 | 0.997686 | 8.40 | 4.98 | 1.0000 | 0.000000 | aead_verified |
| hugo | HUGO, exact single-change costs (T=90, sigma=1, gamma=1), additive approximation + binary STC h=7, no model correction | ok | 65536 / 65536 | 0.013672 | 0.001531 | 76.281 | 0.999998 | 187.85 | 2.58 | 1.0000 | 0.000000 | aead_verified |
| wow | WOW (p=-1, db8 filter bank) + binary STC h=7 | ok | 65536 / 65536 | 0.013672 | 0.001434 | 76.564 | 0.999998 | 94.55 | 2.45 | 1.0000 | 0.000000 | aead_verified |
| s_uniward | S-UNIWARD (spatial, sigma=1, db8 filter bank) + binary STC h=7 | ok | 65536 / 65536 | 0.013672 | 0.001485 | 76.413 | 0.999998 | 85.22 | 2.56 | 1.0000 | 0.000000 | aead_verified |

## Robustness (outcome / oracle BER)

| Algorithm | none | jpeg95 | jpeg75 | jpeg50 | resize50 | crop4 | gauss1 | gauss3 | saltpepper | blur3 | bright2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| lsb_replacement | recovered / 0.000 | failed / 0.499 | failed / 0.510 | failed / 0.519 | failed / 0.511 | failed / 1.000 | failed / 0.490 | failed / 0.506 | partial / 0.007 | failed / 0.519 | recovered / 0.000 |
| lsb_matching | recovered / 0.000 | failed / 0.485 | failed / 0.500 | failed / 0.510 | failed / 0.499 | failed / 1.000 | failed / 0.490 | failed / 0.506 | partial / 0.007 | failed / 0.501 | recovered / 0.000 |
| pvd | recovered / 0.000 | failed / 0.517 | failed / 0.493 | failed / 0.506 | failed / 0.492 | failed / 1.000 | failed / 0.441 | failed / 0.502 | failed / 0.369 | failed / 0.480 | partial / 0.006 |
| edge_adaptive_lsb | recovered / 0.000 | failed / 0.480 | failed / 0.496 | failed / 0.515 | failed / 1.000 | failed / 1.000 | failed / 0.479 | failed / 0.507 | failed / 0.489 | failed / 0.515 | recovered / 0.000 |
| dct | recovered / 0.000 | failed / 0.408 | failed / 0.403 | failed / 0.416 | failed / 0.366 | failed / 1.000 | recovered_oracle_only / 0.000 | partial / 0.044 | failed / 0.144 | partial / 0.060 | recovered / 0.000 |
| dwt | recovered / 0.000 | failed / 0.423 | failed / 0.417 | failed / 0.417 | failed / 0.417 | failed / 1.000 | partial / 0.078 | failed / 0.483 | partial / 0.017 | failed / 0.417 | recovered / 0.000 |
| dct_svd | recovered / 0.000 | failed / 0.410 | failed / 0.405 | failed / 0.424 | failed / 0.338 | failed / 1.000 | partial / 0.038 | failed / 0.443 | failed / 0.128 | failed / 0.230 | recovered / 0.000 |
| hugo | recovered / 0.000 | failed / 0.488 | failed / 0.520 | failed / 0.501 | failed / 0.475 | failed / 1.000 | failed / 0.512 | failed / 0.500 | failed / 0.104 | failed / 0.513 | recovered / 0.000 |
| wow | recovered / 0.000 | failed / 0.485 | failed / 0.533 | failed / 0.477 | failed / 0.503 | failed / 1.000 | failed / 0.485 | failed / 0.509 | partial / 0.089 | failed / 0.510 | recovered / 0.000 |
| s_uniward | recovered / 0.000 | failed / 0.511 | failed / 0.547 | failed / 0.513 | failed / 0.509 | failed / 1.000 | failed / 0.496 | failed / 0.504 | partial / 0.036 | failed / 0.477 | recovered / 0.000 |

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
* **bits_per_pixel**: payload_bits / (width x height)
* **capacity_bits_raw**: algorithm capacity for this cover excluding the 128 bootstrap samples (estimated from the cover)
* **capacity_bits_verified**: largest payload actually embedded AND extracted exactly in a verification run (bytes x 8)
* **embed_ms**: sender-side codec.embed_frame duration (monotonic perf_counter); setup_ms = cost-map time inside it (STC methods)
* **extract_ms**: receiver-side PNG decode + bootstrap validation + extraction (perf_counter)
* **mse**: mean over all samples (pixels x channels) of (cover - stego)^2
* **payload_bits**: payload bytes x 8 (the complete payload: AEAD test envelope or synthetic fixture)
* **psnr_db**: 10 log10(255^2 / MSE); null when MSE = 0 (identical images, infinite PSNR)
* **robustness**: per attack: 'recovered' = full pipeline (bootstrap + payload) returned the exact payload; 'recovered_oracle_only' = only a direct extraction with the known algorithm/length/parameter was exact; 'partial' = oracle BER in (0, 0.1]; 'failed' = otherwise (BER ~0.5 is chance level). oracle_ber = BER of that direct extraction
* **ssim**: mean SSIM, uniform 7x7 window, K1=0.01, K2=0.03, L=255, data range 0..255, averaged over all windows and channels

## Interpretation

* High PSNR/SSIM means the stego image looks like the cover; it does not prove resistance to steganalysis.
* Low MSE is not a proof of security.
* Exact extraction from an unmodified PNG does not establish robustness to lossy transforms.
* Robustness, imperceptibility, capacity, speed and statistical undetectability are different objectives and trade off.
* HUGO/WOW/S-UNIWARD minimise a distortion model; that is not a proof that no steganalyst can detect the message.
