# Steganography algorithm registry (transport v2: ten algorithms)

Owner of every algorithm: the Python image service (`python-service/src/stego/algorithms/`). There is
one implementation per algorithm; the Rust core only knows names/ids, and the learning workbench calls
the same functions. All ten embed the **complete binary payload** (operationally: Frame v1 = header ‖
AppWire ‖ HMAC tag; the AppWire is already AEAD-encrypted) MSB-first, never touch the 128 bootstrap
samples, verify capacity before embedding, and are exact through lossless PNG. **None is claimed robust**
to JPEG, resizing, cropping or filtering, and none is claimed undetectable.

Worked numerical examples for all ten: [`worked-examples.md`](worked-examples.md) (generated from code).
The educational workbench that runs them in isolation: [`learning-workbench.md`](learning-workbench.md).

## 1. Registry

| id | name | variant (exact) | domain | coding | input | capacity (bits) | extraction |
|---|---|---|---|---|---|---|---|
| 1 | `lsb_replacement` | `lsb-replacement-msb-first-v1` | spatial, LSB plane | direct | L/RGB uint8 | `N − 128` (N = samples) | LSBs of samples 128… |
| 2 | `lsb_matching` | `lsb-matching-pm1-seeded-v1` | spatial, ±1 | direct | L/RGB | `N − 128` | LSBs of samples 128… |
| 3 | `pvd` | `wu-tsai-pvd-6range-v1` | spatial, pixel pairs | direct | L/RGB | Σ range bits of pairs (exact, cover dependent) | `|a'−b'| − l_k` in `n_k` bits |
| 4 | `edge_adaptive_lsb` | `edge-mask-7msb-grad-threshold-v1` | spatial, edge mask + LSB | direct | L/RGB | eligible samples (gradient of 7 MSBs ≥ T=6) | rebuild mask from stego, read LSBs |
| 5 | `dct` | `dct8-midband-6coef-qim-v1` | 8×8 block DCT | direct (QIM) | L/RGB (blue plane) | 6 × usable blocks | `round(X[u,v]/Δ) mod 2`, Δ = 12 |
| 6 | `dwt` | `haar-l1-hh-qim-v1` | 1-level Haar DWT | direct (QIM) | L/RGB (blue plane) | usable 2×2 blocks | `round(HH/Δ) mod 2`, Δ = 4 |
| 7 | `dct_svd` | `dct8-svd-s1-qim-v1` | block DCT + SVD | direct (QIM) | L/RGB (blue plane) | usable 8×8 blocks (1 bit each) | `round(σ₁(S)/Δ) mod 2`, Δ = 16 |
| 8 | `hugo` | HUGO, exact single-change costs (T=90, σ=1, γ=1), additive approximation + binary STC h=7, no model correction | spatial, SPAM co-occurrence model | STC | L/RGB | `min(N−128, 131072) / w`, w ≥ 2 | `H·y` on the same elements |
| 9 | `wow` | WOW (p = −1, db8 filter bank) + binary STC h=7 | spatial, wavelet directional filters | STC | L/RGB | same as HUGO | `H·y` |
| 10 | `s_uniward` | S-UNIWARD (spatial, σ = 1, db8 filter bank) + binary STC h=7 | spatial, wavelet relative change | STC | L/RGB | same as HUGO | `H·y` |

Ids 1–5 are unchanged from transport v1 (backward compatible: the bootstrap/frame formats did not
change; ids 6–10 are new values of the existing `alg_id` byte). Parameters live in the existing
`param` byte (0 = default): Δ for `dct`/`dwt`/`dct_svd`, T for `edge_adaptive_lsb`, and the STC
width `w` for HUGO/WOW/S-UNIWARD (0 = automatic rate, see §4). Block methods skip block rows that
contain any bootstrap sample.

## 2. Original five (unchanged)

* **LSB replacement**: `p' = (p AND 0xFE) OR b`.
* **LSB matching**: if `p mod 2 ≠ b`, `p' = p ± 1`, sign from PCG64 seeded with SHA-256(cover‖"LSBM-v1"); 0→+1, 255→−1.
* **PVD** (Wu & Tsai 2003): pairs (a,b), `d=|a−b|`, ranges [0,7],[8,15],[16,31],[32,63],[64,127],[128,255] carry 3,3,4,5,6,7 bits; `d' = l_k + v`; sign of a−b kept; `a' = a + ⌈(t−(a−b))/2⌉` clipped, `b' = a' − t`.
* **Edge-adaptive LSB**: `g = ⌊p/2⌋` (RGB: integer luma of 7-MSB planes), `grad = |Δx g| + |Δy g|`, eligible if `grad ≥ T`; LSB replacement on eligible samples in raster order. A simplified member of the edge-adaptive family (not identical to Luo et al. 2010).
* **DCT**: orthonormal 8×8 DCT-II, coefficients (1,2),(2,1),(2,2),(1,3),(3,1),(3,0), QIM with Δ=12, per-block verification with one retry in the other direction; saturated covers can fail (`ENCODE_VERIFY_FAILED`).

## 3. New transform methods

### 3.1 DWT — `haar-l1-hh-qim-v1`
* One-level orthonormal 2-D Haar on non-overlapping 2×2 blocks `[[a,b],[c,d]]` (identical to a full level-1 Haar DWT because Haar has support 2):
  `LL=(a+b+c+d)/2, HL=(a−b+c−d)/2, LH=(a+b−c−d)/2, HH=(a−b−c+d)/2`.
* Sub-band: **HH** (diagonal detail). One bit per block.
* Modulation: target `HH' = qΔ`, `q ≡ b (mod 2)`, `|qΔ − HH|` minimal (Δ = 4 default, range 4–64).
* Inverse with only HH changed: `e = (HH' − HH)/2; a'=a+e, b'=b−e, c'=c−e, d'=d+e`, round half to even, clip [0,255].
* Exactness: rounding moves HH by at most `(4 × 0.5)/2 = 1 < Δ/2`. Near 0/255 each block is re-analysed; the same HH change is retried with alternative pixel patterns (pairs, single pixels; 11 patterns) and then the next-nearest index (up to 8). Extraction reads HH only and needs no side information. With these patterns `dwt` works even on the black-and-white fallback cover.

### 3.2 DCT-SVD — `dct8-svd-s1-qim-v1`
DCT-SVD is a family; this is one concrete variant (the cited family paper is a watermarking scheme and differs).
1. Plane: gray, or blue plane of RGB. 2. 8×8 blocks, raster order, bootstrap rows skipped, partial edge blocks unused.
3. `X = C B Cᵀ` (orthonormal DCT-II). 4. Region `S = X[1:5, 1:5]` (4×4, no DC row/column).
5. `S = U diag(σ₁..σ₄) Vᵀ` (numpy SVD). 6. `σ₁' = qΔ`, `q ≥ 0`, `q ≡ b (mod 2)`, nearest (Δ = 16, range 8–64).
7. `S' = U diag(σ₁',σ₂,σ₃,σ₄) Vᵀ`, inverse DCT, round, clip. 8. Verify by recomputing σ₁ from the rounded pixels; on failure try the next-nearest valid index (up to 8; e.g. when σ₁' would drop below σ₂ or near saturation).
Extraction: `round(σ₁/Δ) mod 2`. Rounding changes σ₁ by at most `‖E‖₂ ≤ ‖E‖_F ≤ 4`, so Δ = 16 leaves margin 4.
Capacity is the lowest of the ten (1 bit per 8×8 block): a 320×240 cover holds 145 bytes; a 640×480 webcam frame 590 bytes.

## 4. Content-adaptive methods and STC

### 4.1 Common embedding scheme (`stc-pm1-v1`)
* Cover elements: all samples except `[0,128)`; order = public permutation (PCG64 seeded with SHA-256("IOD-STC-PERM-v1"|name|H|W|C)). **No stego key** — confidentiality/integrity come from the AEAD and frame MAC; a secret permutation would need a key in the Python process, which the architecture forbids.
* `m` = payload bits, `w` = 1/rate. Automatic: `w = min(10, N_eff // m)`, `N_eff = min(N − 128, 131072)`; explicit `w` ∈ [2, 64] via `param`. The receiver recomputes `w` from image size and bootstrap length.
* `x` = LSBs of the first `n = m·w` elements, ρ = algorithm cost; STC returns `y` with `H y = payload` and minimal Σρ over changed elements; each changed element moves by ±1 (binary embedding with ±1 changes). HUGO uses the cheaper of its exact ρ⁺/ρ⁻; WOW/S-UNIWARD costs are symmetric, so the sign comes from a PCG64 stream seeded from the cover hash (0→+1, 255→−1).
* Extraction: `payload = H y` from the stego LSBs — no costs, no cover.

### 4.2 Syndrome-trellis codes (Filler, Judas & Fridrich 2011)
* Binary STC, constraint height **h = 7** (128 trellis states). Ĥ is h×w; columns from PCG64 seeded with SHA-256("IOD-STC-HHAT-v1"|h|w) with bit 0 and bit h−1 forced to 1. **These are not the optimised submatrices published with the reference code**, so coding efficiency is somewhat lower (coding loss not quantified against the reference tables).
* H (m × mw): Ĥ stacked along the diagonal, one row down per block; the last h−1 blocks use columns masked to the remaining rows (rows beyond m cropped).
* Embedding: Viterbi over the trellis (`O(n·2^h)`, ~4 µs per element in numpy); extraction: syndrome `H y`.
* Verified: optimality against brute force on small instances, encoder/decoder agreement over rates 1/2…1/64, wet elements never changed.
* STC is used **only** for the additive cost formulations (HUGO single-change approximation, WOW, S-UNIWARD); the other seven algorithms do not use coding.

### 4.3 Filter bank (WOW and S-UNIWARD)
16-tap Daubechies-8 decomposition filters; high-pass `h` =
`[-0.0544158422, 0.3128715909, -0.6756307363, 0.5853546837, 0.0158291053, -0.2840155430, -0.0004724846, 0.1287474266, 0.0173693010, -0.0440882539, -0.0139810279, 0.0087460940, 0.0048703530, -0.0003917404, -0.0006754494, -0.0001174768]`,
low-pass `l[n] = (−1)ⁿ h[15−n]` (identical to PyWavelets `Wavelet('db8').dec_hi/dec_lo`, checked in tests).
`K₁ = lᵀh` (LH), `K₂ = hᵀl` (HL), `K₃ = hᵀh` (HH); cover padded symmetrically by 16; residuals `R_k = K_k ∗ X` (zero-padded "same" convolution, centre offset ⌊L/2⌋).
The aggregation `· ∗ |K_k rotated 180°|` uses the **exact adjoint** of that convolution, so ρ_ij is aligned with pixel (i,j). (MATLAB's `conv2(·, rot90(|F|,2), 'same')` with an even 16-tap kernel equals this map shifted by one pixel.) A test proves `ρ_ij = D(X, X+e_ij)` for S-UNIWARD to 1e−9.

### 4.4 WOW (Holub & Fridrich, WIFS 2012)
`ξ_k = |R_k| ∗ |K_k|` (suitability per direction), `ρ = (Σ_k ξ_k^p)^(−1/p)` with **p = −1**, i.e. `ρ = 1/ξ₁ + 1/ξ₂ + 1/ξ₃`: a pixel is cheap only if it is textured in **all** directions (smooth regions and clean edges stay expensive). Costs > 1e10 or NaN → wet (1e10).

### 4.5 S-UNIWARD (Holub, Fridrich & Denemark 2014)
`D(X,Y) = Σ_k Σ_uv |W_k(X) − W_k(Y)|_uv / (σ + |W_k(X)|_uv)`, `W_k = K_k ∗ X`, **σ = 1** (spatial).
Additive cost (exact for a single change): `ρ = Σ_k (1/(σ + |R_k|)) ∗ |K_k|`. This is S-UNIWARD, not J-UNIWARD.

### 4.6 HUGO (Pevný, Filler & Bas 2010)
`D(X,Y) = Σ_{d∈[−T,T]³} w(d)·( |Σ_{k∈{→,←,↓,↑}} (C^X_k − C^Y_k)(d)| + |Σ_{k∈diagonals} (C^X_k − C^Y_k)(d)| )`,
`w(d) = 1/(√(d₁²+d₂²+d₃²) + σ)^γ`, C_k = co-occurrences of triples of consecutive pixel differences
truncated to [−T,T] along direction k (opposite directions give `(−d₃,−d₂,−d₁)`).
Parameters: **T = 90** (the BOSS default, confirmed); **σ = 1, γ = 1** (our reading of the original
paper; the full text could not be re-checked from this environment — both are configurable constants).
Implementation (**named variant**): ρ_i^± = D(X, X ± e_i) computed **exactly** for every used sample
(all triples touching the pixel in 8 directions, with cancellation inside each direction group; tested
against a brute-force evaluation of the full D to 1e−15); `ρ_i = min(ρ⁺, ρ⁻)`, sign = argmin; additive
approximation embedded with binary STC h=7. **No model correction / Gibbs re-sweeps** (canonical HUGO
recomputes costs during embedding), so the actual distortion of the combined changes can exceed the
additive sum. It is not the full HUGO-BD bounding formulation either; costs are computed once on the cover.

## 5. Selector `sel-policy-2`

Same rules as `sel-policy-1` (capacity filter → trial encode on the real cover → hard limits MSE ≤ 4,
PSNR ≥ 40 dB, cost ≤ 1000 → score `w_d·d + w_u·u + w_t·t` → tie-break), now over all ten. Static cost
model (estimated units, never measured times): WORK/SCAN = dwt 1.0/0.4, dct_svd 2.5/1.2, hugo 8.0/3.0,
wow 6.0/1.5, s_uniward 6.0/1.5 (original five unchanged). Tie order:
`s_uniward, wow, hugo, lsb_matching, pvd, edge_adaptive_lsb, dwt, dct_svd, lsb_replacement, dct`.
Features recorded additionally: cover source (webcam/fallback/upload), bits per pixel, texture statistic,
bit depth, format, and each candidate's exact variant. A 640×480 selection takes 2.2–4.4 s (150 B–1 KiB frames) on the build host
(ten trial encodes). Measured decisions for a 150-byte frame: natural 320×240 RGB cover -> `urgent`: lsb_replacement (BEST_SCORE),
`normal`: lsb_matching (TIE_BREAK_ORDER), `background`: s_uniward (TIE_BREAK_ORDER); B/W fallback 256×256 ->
lsb_replacement / lsb_matching / lsb_matching. RAG only explains (unchanged).

## 6. Failure modes and limitations
* All ten: fragile to JPEG/resize/crop/filter (measured in the workbench robustness suite); no anti-steganalysis claim; high PSNR/SSIM ≠ undetectable.
* `dct`: refuses saturated blocks; `edge_adaptive_lsb`: no capacity on flat covers; `dct_svd`: low capacity (1 bit/64 pixels).
* STC methods: public permutation (no stego key); non-optimised Ĥ; N_eff capped at 131072 elements (≤ 8 KiB frames at rate 1/2) to bound run time; HUGO variant without model correction; σ/γ for HUGO not re-verified against the full paper text here.
* Bootstrap is plain LSB replacement in samples 0–127 for every algorithm (unchanged v1 design).

## 7. References
* Pevný, Filler, Bas — *Using High-Dimensional Image Models to Perform Highly Undetectable Steganography*, IH 2010. https://doi.org/10.1007/978-3-642-16435-4_13
* Filler, Judas, Fridrich — *Minimizing Embedding Impact in Steganography Using Syndrome-Trellis Codes*, IEEE TIFS 6(3), 2011. https://doi.org/10.1109/TIFS.2011.2134094
* Holub, Fridrich — *Designing Steganographic Distortion Using Directional Filters* (WOW), IEEE WIFS 2012. https://doi.org/10.1109/WIFS.2012.6412655
* Holub, Fridrich, Denemark — *Universal Distortion Function for Steganography in an Arbitrary Domain*, EURASIP J. Inf. Secur. 2014:1. https://doi.org/10.1186/1687-417X-2014-1
* Wu, Tsai — *A steganographic method for images by pixel-value differencing*, Pattern Recognit. Lett. 24, 2003. https://doi.org/10.1016/S0167-8655(02)00402-6
* Chen, Wornell — *Quantization index modulation*, IEEE Trans. Inf. Theory 47(4), 2001. https://doi.org/10.1109/18.923725
* DCT-SVD family example (watermarking; differs from our variant): https://doi.org/10.1145/2345396.2345490
* DWT/SVD family example (differs from our variant): https://doi.org/10.1080/09720529.2019.1698801
* Luo, Huang, Huang — *Edge Adaptive Image Steganography Based on LSB Matching Revisited*, IEEE TIFS 5(2), 2010. https://doi.org/10.1109/TIFS.2009.2035372
* Bas, Filler, Pevný — *"Break Our Steganographic System": the ins and outs of organizing BOSS*, IH 2011 (HUGO T = 90 default).
