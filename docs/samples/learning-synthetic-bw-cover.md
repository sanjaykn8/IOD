# Steganography algorithm comparison (educational)

> **Educational experiment - not a live UAV transmission.** No UAV session, key or protocol state was involved.

* Experiment: `ef39b4bb5d484d7eb8944388c07ed35f`
* Cover: 256x256 black-and-white procedural cover (the operational fallback generator, seed 'learn-sample') (256x256 L, sha256 `5c985bf63ce419e2`)
* Payload mode: `synthetic`; 4 bytes (32 bits), sha256 `e2c5afb58a304027`; same cover and payload for every algorithm
* Payload: synthetic fixture A6 3C 91 5E (not a real ciphertext; AEAD verification not applicable)

## Metrics

| Algorithm | Variant | Status | Capacity bits (raw / verified) | bpp | MSE | PSNR dB | SSIM | Embed ms | Extract ms | Bit acc. | BER | Verification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lsb_replacement | lsb-replacement-msb-first-v1 | ok | 65408 / n/a | 0.000488 | 0.001129 | 77.603 | 0.999998 | 0.06 | 0.42 | 1.0000 | 0.000000 | not_applicable_synthetic |
| lsb_matching | lsb-matching-pm1-seeded-v1 | ok | 65408 / n/a | 0.000488 | 0.001160 | 77.487 | 0.999998 | 0.26 | 0.36 | 1.0000 | 0.000000 | not_applicable_synthetic |
| pvd | wu-tsai-pvd-6range-v1 | ok | 99664 / n/a | 0.000488 | 0.003494 | 72.697 | 0.999992 | 0.73 | 1.29 | 1.0000 | 0.000000 | not_applicable_synthetic |
| edge_adaptive_lsb | edge-mask-7msb-grad-threshold-v1 | ok | 1298 / n/a | 0.000488 | 0.001129 | 77.603 | 0.999998 | 0.53 | 1.23 | 1.0000 | 0.000000 | not_applicable_synthetic |
| dct | dct8-midband-6coef-qim-v1 | embed_failed | 5952 / n/a | 0.000488 | n/a | n/a | n/a | 0.26 | n/a | n/a | n/a | not_extracted |
| dwt | haar-l1-hh-qim-v1 | ok | 16256 / n/a | 0.000488 | 0.008698 | 68.737 | 0.999924 | 0.48 | 0.40 | 1.0000 | 0.000000 | not_applicable_synthetic |
| dct_svd | dct8-svd-s1-qim-v1 | ok | 992 / n/a | 0.000488 | 0.293732 | 53.451 | 0.996824 | 0.86 | 0.56 | 1.0000 | 0.000000 | not_applicable_synthetic |
| hugo | HUGO, exact single-change costs (T=90, sigma=1, gamma=1), additive approximation + binary STC h=7, no model correction | ok | 32704 / n/a | 0.000488 | 0.000992 | 78.166 | 0.999998 | 12.10 | 0.47 | 1.0000 | 0.000000 | not_applicable_synthetic |
| wow | WOW (p=-1, db8 filter bank) + binary STC h=7 | ok | 32704 / n/a | 0.000488 | 0.001175 | 77.431 | 0.999997 | 17.48 | 0.85 | 1.0000 | 0.000000 | not_applicable_synthetic |
| s_uniward | S-UNIWARD (spatial, sigma=1, db8 filter bank) + binary STC h=7 | ok | 32704 / n/a | 0.000488 | 0.001129 | 77.603 | 0.999998 | 16.31 | 0.43 | 1.0000 | 0.000000 | not_applicable_synthetic |

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
