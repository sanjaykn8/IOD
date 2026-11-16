# Patch-wise, knowledge-base-guided steganography transport

Format identifier: `frame-v2/appwire-v1/bootstrap-v2/manifest-v1`
Segmentation `arg-cells-1` · selector `kb-bm25-1` · knowledge base `patch-kb-1`

This document describes the system **as implemented**. It replaces the earlier whole-image transport
(one algorithm per image, Frame v1). M1–M8 and K1–K3 are unchanged; only the transport of K4
application messages is described here. The cover of every transmission is a **fresh, locally generated
procedural image** selected with knowledge of the payload length only; there is no camera, upload or
client-selected cover. The generator, its quality pre-screen, the resource profiles and the configuration
are specified in `cover-generation.md`.

## 1. Roles

| Component | Responsibility | Never does |
|---|---|---|
| Rust core (`rust-core/src/transport/`) | AEAD seal/open, AppWire, manifest validation, Frame v2, HMAC, channel/direction/replay, acceptance, event log | pixel work |
| Python image service (`python-service/src/stego/`) | payload-aware cover generation, segmentation, patch features, knowledge-base retrieval, allocation, embedding, PNG save/re-read, extraction | holds keys, creates or checks the MAC, sees plaintext |
| Node gateway (`node-server/`) | relays `/api/stego/*` and `/api/learn/*` to the Rust core | talks to Python, selects, validates crypto |
| React UI (`web-ui/`) | renders values returned by the backend | computes or invents results |

The image service is **not trusted** by the core: every response is validated (manifest parsed
strictly, lengths and geometry cross-checked, saved file hashed by the core itself).

## 2. Sequence

Sender (direction D1→D2 or D2→D1; both use the same code path with direction-specific keys):

1. Core checks the session (key-issued, both members active), reserves the next sequence number.
2. Core seals the plaintext: `AppWire = header(28) | ciphertext | AEAD tag(16)`. Let `W = len(AppWire)`.
0. Core resolves the request's optional `cover_generation` object against the process profile
   (tighten-only; unknown fields such as a seed, a file or a source are rejected) **before** a sequence
   number is reserved.
3. Core → Python `POST /stego/plan {payload_bytes: W + 32, cover_generation, limits, segmentation, min_level, target_chunk_bytes}`.
   Only the **length** and the validated generation settings are sent. Python generates a bounded number of
   candidate covers from OS randomness, pre-screens them with the quality heuristics, and runs the planner on
   them best-first: it segments the candidate, computes patch features and measured capacities, allocates
   chunks, selects one algorithm per used patch and dry-runs every patch on a copy with pseudo-random bytes.
   The first candidate that plans is stored (PNG + generation sidecar) and its **manifest** is returned with
   the plan and generation diagnostics. If no candidate is acceptable the request fails; no other cover
   source exists.
4. Core parses the manifest strictly and checks it against the sealed length, the reported cover geometry,
   the generator ceilings and `cover.source == "generated"`.
5. Core builds **Frame v2** and computes the HMAC over header, manifest and AppWire.
6. Core → Python `POST /stego/encode {frame_b64, cover_id}`. Python loads that exact stored cover (it never
   generates here; a cover without a matching generation sidecar is refused), embeds exactly as the
   manifest says, writes the bootstrap carrier, saves the PNG, **re-reads the saved file**, extracts the frame
   again and compares it byte for byte. Any mismatch → nothing is kept.
7. Core reads the saved PNG itself and compares its SHA-256 with the reported one.

Receiver (input: session, recipient, artifact id — nothing else):

8. Core reads the PNG from the shared artifact directory and hashes it.
9. Core → Python `POST /stego/extract {artifact_id}`. Python reads the bootstrap preamble, the manifest and its
   CRC from the reserved rows, parses the manifest strictly, rebuilds the patch masks **from the manifest**
   (no segmentation is run), extracts each chunk and returns the reconstructed frame. All of it is untrusted.
10. Core verifies the frame MAC, then parses the (now authenticated) manifest strictly again, checks it against
    the payload length and the image geometry, decodes AppWire, checks channel/direction/replay and opens the AEAD.
11. Any failure is recorded as a failed event with a stable error code. No plaintext is returned on failure and
    there is no fallback transport.

If step 6 fails with `PATCH_EMBED_FAILED` (a real payload did not survive a patch although the dry run did),
the core re-plans **the same stored cover** — `POST /stego/plan {payload_bytes, replan_cover_id, min_level = level + 1, …}`,
no `cover_generation`, nothing is generated — at most `IOD_STEGO_MAX_REPLANS` (default 2) times, then fails.
The core rejects a re-plan response whose cover id or SHA-256 differs from the cover generated for this
transmission, and an encode response that names another cover. No other algorithm and no other cover is
substituted. The receiver never generates or plans anything.

## 3. Frame v2 (built and authenticated by the Rust core)

All integers big-endian.

```text
offset  size  field
0       4     magic "IOD2"
4       1     version = 2
5       1     flags = 0
6       2     reserved = 0
8       4     manifest_len  (M)
12      4     wire_len      (W)
16      M     manifest (section 4)
16+M    W     AppWire v1 (unchanged: 28-byte header | ciphertext | 16-byte AEAD tag)
16+M+W  32    tag = HMAC-SHA256(k_meta, "IOD-STEGO-FRAME-v2" | bytes[0 .. 16+M+W))
```

`k_meta = HKDF(directional AEAD key, info = "IOD-STEGO-META-v1" | channel_tag(16) | direction(1))` — the same
derivation as before; only the MAC domain string changed, so a v1 tag can never verify as v2.

**MAC coverage.** The tag covers the header and the *complete* manifest: image width/height/channels,
cell size, segmentation and selector version ids, the patch map (hence every patch id and its region),
every patch's algorithm id, parameter, payload offset and payload length, and the AppWire payload. Changing any
of these makes `FRAME_AUTH_FAILED`. The image service never receives `k_meta`.

**Where the bytes live in the image.** The header is not embedded (it is regenerated from the bootstrap
preamble). The manifest travels in the bootstrap carrier. The patches carry the *payload section*
`AppWire | tag` (`payload_len = W + 32`), cut into chunks. The receiver concatenates
`header | manifest | payload section` and hands that to the core.

## 4. Patch manifest v1

```text
offset  size  field
0       4     magic "IOPM"
4       1     manifest version = 1
5       1     segmentation version id = 1   (arg-cells-1)
6       1     selector version id = 1       (kb-bm25-1)
7       1     channels (1 = L, 3 = RGB)
8       2     width
10      2     height
12      1     cell size (4, 8 or 16)
13      1     n = patch count (1..255)
14      2     reserved_rows
16      4     payload_len (= sum of chunk lengths = W + 32)
20      4     map_len
24      12n   patch table, entry i = patch id i:
                alg_id u8 (0 = patch carries nothing; 1..10 otherwise)
                param  u8 (explicit algorithm parameter)
                flags  u16 = 0
                offset u32 (into the payload section)
                length u32
24+12n  map_len  cell map
```

*Cell map.* The image is covered by a grid of `ceil(H/cell) × ceil(W/cell)` cells; each cell belongs to one
patch. The map is the row-major label sequence, run-length coded as `(label u8, run LEB128)` pairs. Runs may
span rows. The encoding is canonical: adjacent runs have different labels, run lengths are > 0 and minimally
encoded, the runs cover the grid exactly, every label is `< n`, and every patch id occurs. A pixel `(y, x)`
belongs to patch `map[y // cell][x // cell]`.

*Chunks.* Used patches, taken in ascending patch id, must have `offset` equal to the running sum of the
previous lengths, `length ≥ 1`, and the sum must equal `payload_len`: contiguous, non-overlapping, covering the
payload exactly once. Unused patches have all-zero entries.

*Parameters* (explicit, no implied defaults): ids 1–3 `0`; edge-adaptive threshold `1..255`; DCT step `4..64`;
DWT step `4..64`; DCT-SVD step `8..64`; HUGO/WOW/S-UNIWARD STC inverse rate `w = 2..64`.

Limits: manifest ≤ 65 536 bytes, ≤ 255 patches, dimensions ≤ configured maximum. Both parsers
(`rust-core/src/transport/manifest.rs`, `python-service/src/stego/patch/manifest.py`) reject everything else
with `MANIFEST_INVALID`, `MANIFEST_TOO_LARGE`, `UNSUPPORTED_VERSION` or `UNKNOWN_ALGORITHM`; length arithmetic
is overflow-checked.

## 5. Bootstrap v2 (in the image, unauthenticated)

```text
preamble (16 bytes) = "SB" | version=2 | flags=0 | manifest_len u32 | frame_len u32 | crc32(first 12 bytes)
carrier             = preamble | manifest | crc32(manifest)
```

The carrier is written one bit per sample into the **least significant bits of the flat sample array from
index 0** (row-major, channel-interleaved, MSB of each byte first). It occupies
`reserved_rows = ceil(8·(16 + M + 4) / (width·channels))` whole image rows. These rows are excluded from
every patch (masks are cleared there) so no algorithm ever modifies or reads a carrier sample; the manifest
states `reserved_rows` and the parsers recompute and compare it.

The manifest size is fixed once the segmentation is known (fixed-size patch table + map), so the reserved rows
are known before capacities are measured — there is no circular dependency.

CRC-32 detects accidental damage only. **It is not authentication**: an attacker can rewrite the manifest with a
valid CRC; the frame MAC then fails (tests do exactly this).

## 6. Test vectors

Pinned byte-for-byte in `python-service/tests/test_patch_manifest.py` and
`rust-core/src/transport/manifest.rs` (both encoders must produce it, both parsers must accept it).

Manifest: 64×64 gray image, cell 16 (4×4 cells), 2 patches, patch 0 unused, patch 1 = LSB replacement
carrying 40 bytes; cell labels `0011 / 0111 / 0111 / 0001`:

```text
494f504d 01 01 01 01 0040 0040 10 02 000b 00000028 00000010     fixed part (24)
00 00 0000 00000000 00000000                                     patch 0 (unused)
01 00 0000 00000000 00000028                                     patch 1: alg 1, offset 0, length 40
00 02 01 02 00 01 01 03 00 01 01 03 00 03 01 01                  map: 0×2 1×2 0×1 1×3 0×1 1×3 0×3 1×1
```

64 bytes; carrier = 16 + 64 + 4 = 84 bytes = 672 bits → `reserved_rows = ceil(672 / 64) = 11 = 0x000b`.

Preamble for that manifest with an 8-byte AppWire (frame = 16 + 64 + 8 + 32 = 120 bytes):
`5342 02 00 00000040 00000078 bccc9fc7`.

Frame header for the same frame: `494f4432 02 00 0000 00000040 00000008`; the tag is
`HMAC-SHA256(k_meta, "IOD-STEGO-FRAME-v2" | header | manifest | wire)` (checked against an independent
computation in `frame.rs::test_vector_tag_is_hmac_over_domain_header_manifest_wire`).

A complete real transaction (plan, manifest, per-patch results) is in `docs/samples/patchwise-run-report.json`
with its cover, segmentation overlay, stego PNG and difference map next to it. In that run (first transaction): a
generated `strata` cover of 320×240 RGB with quality score 0.996; AppWire 313 B, manifest 686 B, frame 1047 B,
13 patches of which 8 carry 43–44 B each (`lsb_matching` ×6, `dct` ×1, `s_uniward` ×1); PSNR 58.7 dB.

## 7. Segmentation `arg-cells-1` (adaptive region growing)

Implemented in `python-service/src/stego/patch/segment.py`. Deterministic; no randomness; not SLIC, not a grid,
not a fixed count.

1. **Cells.** Cell size 4 px if `min(H, W) < 64`, 8 px if `H·W ≤ 2²¹`, else 16 px. Regions are 4-connected
   unions of cells, so they are irregular but their map is small and 8×8 / 2×2 blocks align with them.
2. **Cell features.** Mean luma, luma standard deviation (texture), mean gradient magnitude and, for RGB, mean
   Cb/Cr; scaled and multiplied by the weights `w_intensity, w_texture, w_gradient, w_color`.
3. **Complexity and target count.** `c = clip((mean gradient/16 + mean cell deviation/16)/2, 0, 1)`,
   `n_target = clip(round(sqrt(H·W)/64 · (1 + 3c) · 0.5^level), 2, max_regions)`. The count depends on the image
   size *and* its content.
4. **Seeded growing.** Seeds in order of increasing cell gradient (ties: cell index). A region absorbs the
   4-neighbour cell closest to its running mean feature while the distance ≤ τ and the region is below the
   maximum size.
5. **Threshold adaptation.** τ is found by bisection (at most `tau_iterations`, default 7, within
   0.004–1.5) so the count after merging is as close as possible to `n_target`.
6. **Deterministic merge.** Regions below `min_region_px` are merged, smallest first (ties: lowest id), into the
   adjacent region with the nearest mean feature whose merged size respects the maximum (otherwise the nearest
   neighbour). The same step enforces `max_regions`.
7. **Stable ids.** Regions are renumbered by first appearance in raster order.

Guarantees tested in `tests/test_patch_segmentation.py`: every pixel in exactly one region, dense ids, every
region connected, identical output for identical input, count within bounds and varying with content.

**Refinement (bounded).** Level `ℓ` halves the target count and doubles the minimum region size per level.
The planner tries levels `min_level .. max_refine_levels` (default 3) when the manifest does not fit, the
capacity is insufficient, no algorithm is eligible for a patch, or a dry run fails. After the last level the
request is rejected (`PATCH_CAPACITY_INSUFFICIENT` or `NO_ELIGIBLE_ALGORITHM`) with the list of attempts.

Settings (defaults; environment variable on the Rust core; bounds enforced in both services):

| Setting | Default | Variable |
|---|---|---|
| `cell_size` (0 = automatic) | 0 | `IOD_STEGO_SEG_CELL_SIZE` |
| `min_region_px` | 256 | `IOD_STEGO_SEG_MIN_REGION_PX` |
| `max_region_frac` | 0.35 | `IOD_STEGO_SEG_MAX_REGION_FRAC` |
| `max_regions` (≤ 255) | 96 | `IOD_STEGO_SEG_MAX_REGIONS` |
| `w_intensity / w_texture / w_gradient / w_color` | 1.0 / 1.0 / 0.6 / 0.5 | `IOD_STEGO_SEG_W_INTENSITY` … `_W_COLOR` |
| `tau_iterations` | 7 | `IOD_STEGO_SEG_TAU_ITERATIONS` |
| `max_refine_levels` | 3 | `IOD_STEGO_SEG_MAX_REFINE_LEVELS` |
| target chunk bytes | 48 | `IOD_STEGO_TARGET_CHUNK_BYTES` |
| sender re-plans after an embed failure | 2 | `IOD_STEGO_MAX_REPLANS` |

## 8. Patch features

Per patch (`patch/features.py`): id, pixel count, usable pixel count (outside the reserved rows), bounding box,
width, height, aspect ratio, perimeter, compactness (`4π·area/perimeter²`), centroid, mean intensity, mean
colour, variance, entropy, gradient mean/std, edge density (fraction of pixels with gradient ≥ 24), texture (mean absolute 4-neighbour Laplacian),
smoothness (`1/(1+variance)`), high-frequency energy ratio and mean AC energy (8×8 DCT of complete blocks), saturation (fraction of
pixels with luma ≤ 2 or ≥ 253), number of complete 8×8 and 2×2 blocks, block fill, and — per algorithm — geometry
support and the **capacity measured by the implementation on the mask**.

## 9. Knowledge base and per-patch selection

`python-service/src/stego/kb/algorithm_kb.json` is a static, curated file: one entry per algorithm id with name,
exact repository variant, domain, suitable/avoid characteristics, mask and geometry requirements, capacity
behaviour, distortion, cost, colour/format assumptions, extraction and synchronisation requirements,
limitations, references and evidence notes. Each evidence note is labelled `published` (stated in the cited
source), `implementation` (property of this code) or `local_heuristic` (maintainer judgement). All numeric
thresholds are local heuristics. The file is validated at service start (`KB_INVALID` otherwise) and shown in the
UI. Reference DOIs were typed from a reference list and are flagged as not machine-verified.

Selection for a patch that was allocated `B` bytes (`patch/kb.py`), no LLM, no embeddings, no network:

1. **Structured hard filters** per entry: `geometry_support` (the implementation's own check, e.g. at least one
   complete block), `min_usable_pixels`, `min_blocks`, the entry's `hard_avoid` rules (currently: DCT is excluded
   when saturation ≥ 0.02 because rounding at 0/255 breaks its round trip), and `measured_capacity ≥ 8·B`.
2. **BM25** over the entries that passed. Documents are the tokens of `suitable_terms` (weight 3), `summary`
   (1) and `suitable_when` (1); `k1 = 1.5`, `b = 0.75`, IDF over all ten entries
   (`ln(1 + (N − df + 0.5)/(df + 0.5))`). The query is the set of descriptive terms whose threshold rule holds
   for the patch (`flat`, `smooth`, `moderate-texture`, `textured`, `noisy`, `edge-rich`, `few-edges`,
   `high-entropy`, `low-entropy`, `saturated`, `binary`, `dark`, `bright`, `large/medium/small-region`,
   `compact`, `elongated`, `ragged`, `block-aligned`, `high/low-frequency`, `low/medium/high-rate`, `color`,
   `grayscale`).
3. **Top-1.** Highest score wins; ties go to the lower algorithm id.

Recorded per patch: every entry id, each filter result with its detail, matched terms, BM25 score, measured
capacity, rank, and the final choice. If nothing is eligible, or the chosen algorithm fails its dry run, there is
**no fallback**: the planner moves to the next refinement level or rejects.

There are no message priority classes; the request has no such field and old clients that send `priority`,
`algorithm`, `param` or `policy` get `400 INVALID_REQUEST`.

## 10. Sequential chunk allocation

For payload length `L` (`patch/planner.py`):

1. Usable patches: at least one algorithm passes the structural filters with ≥ 1 byte; `cap_i` = largest such
   capacity.
2. `k = clamp(ceil(L / target_chunk_bytes), 1, #usable)`. Patches are ranked by gradient mean (descending; ties:
   lower id); the shortest prefix with ≥ k patches whose capacities sum to ≥ L is used.
3. Water-filling in order of increasing `cap_i`: `chunk_i = min(cap_i, ceil(remaining / patches_left))`.
4. Offsets are assigned in ascending patch id.

No replication, parity or erasure coding. One lost patch loses the frame (the MAC then fails).

## 11. Algorithms on patch masks

Ids are stable. Every implementation exposes `support`, `capacity_bits`, `embed`, `extract` on a mask and never
changes a pixel outside it (asserted after every embedding).

| Id | Name | Variant implemented here | Mask handling |
|---|---|---|---|
| 1 | `lsb_replacement` | LSB replacement, MSB-first | patch samples in raster order |
| 2 | `lsb_matching` | ±1 matching, sign stream seeded from cover hash and patch id | patch samples |
| 3 | `pvd` | Wu–Tsai PVD, 6 ranges | pairs of consecutive patch samples |
| 4 | `edge_adaptive_lsb` | 7-MSB gradient threshold | gradient uses in-patch neighbours only |
| 5 | `dct` | 8×8 DCT, 6 mid-band coefficients, QIM | only complete 8×8 blocks inside the mask |
| 6 | `dwt` | Haar level-1 HH, QIM | only complete 2×2 blocks inside the mask |
| 7 | `dct_svd` | 8×8 DCT + SVD, largest singular value, QIM | only complete 8×8 blocks inside the mask |
| 8 | `hugo` | **additive approximation** of HUGO (exact single-change costs, no model correction) + binary STC h=7 with **custom sub-matrices** | costs restricted to patch samples |
| 9 | `wow` | WOW costs (db8) + the same custom STC | costs restricted to patch samples |
| 10 | `s_uniward` | S-UNIWARD costs (db8) + the same custom STC | costs restricted to patch samples |

A method that cannot work on a mask reports `unsupported` with a reason (e.g. `NO_COMPLETE_8X8_BLOCK`); nothing
silently becomes LSB. These are this repository's variants, not reference implementations, and none is claimed
undetectable.

## 12. Error codes (stable)

Cover generation: `GENERATOR_CONFIG_INVALID`, `GENERATOR_MEMORY_LIMIT`, `COVER_QUALITY_REJECTED`,
`GENERATION_BUDGET_EXCEEDED`, `COVER_GENERATION_FAILED` (and `PATCH_CAPACITY_INSUFFICIENT` when no cover within
the allowed size can carry the payload). Planning: `PATCH_CAPACITY_INSUFFICIENT`, `NO_ELIGIBLE_ALGORITHM`, `SEGMENTATION_FAILED`, `MANIFEST_INVALID`,
`KB_INVALID`. Embedding: `PATCH_EMBED_FAILED`, `PATCH_UNSUPPORTED`, `ENCODE_VERIFY_FAILED`, `IMAGE_WRITE_FAILED`.
Reading: `ARTIFACT_NOT_FOUND`, `IMAGE_DECODE_ERROR`, `BOOTSTRAP_MISSING`, `BOOTSTRAP_CORRUPT`,
`UNSUPPORTED_VERSION`, `FRAME_LENGTH_INVALID`, `MANIFEST_INVALID`, `MANIFEST_TOO_LARGE`, `UNKNOWN_ALGORITHM`,
`EXTRACT_FAILED`. Verification (core): `FRAME_MALFORMED`, `FRAME_VERSION_UNSUPPORTED`, `FRAME_TOO_LARGE`,
`FRAME_LENGTH_MISMATCH`, `FRAME_AUTH_FAILED`, `WRONG_CHANNEL`, `REPLAY`, `AEAD_FAILED`. Infrastructure:
`STEGO_BACKEND_UNAVAILABLE`, `BACKEND_MALFORMED_RESPONSE`, `ARTIFACT_HASH_MISMATCH`.

## 13. Limitations

* Lossless PNG handoff through a shared directory only. JPEG, resizing, cropping or filtering destroy the
  message; robustness is not claimed (the learning workbench measures it and reports the failures).
* Steganography here is an obscurity layer on top of AEAD. No steganalysis resistance is claimed for any
  algorithm; LSB-class methods and the QIM transform methods are detectable.
* The bootstrap carrier is plain LSB data in the top rows; its presence is detectable and it is not secret.
  The offline evaluation (`detectability-evaluation.md`) measures this: a small classical detector separates
  transport images from covers almost perfectly because of the carrier rows, and far less well when those
  rows are hidden from it.
* Covers are synthetic procedural images (`cover-generation.md`): coherent and varied, but not photographs,
  and produced by a public generator.
* The patch map is carried in clear inside the image (authenticated, not encrypted).
* Capacities are measured on the cover; a real payload can still fail a patch that passed the dry run. This is
  handled by the bounded re-plan, not by substituting an algorithm.
* The knowledge base is hand-curated; its thresholds are heuristics validated only by this repository's tests.
* Single-process simulator: both drones live in one Rust process and exchange a file, not a radio link.
* No error correction: one damaged used patch loses the frame.

## 14. Migration from Frame v1

Frame v1 (`"IODF"`, one algorithm id in the header, 128-sample bootstrap `"SB"` v1) is **not accepted**. A v1
image fails with `UNSUPPORTED_VERSION` (bootstrap) or `FRAME_MALFORMED` (frame magic); v2 images cannot be read
by v1 code. There is no interoperability and no conversion tool. Stored v1 artifacts and v1 events remain
readable as files/rows but cannot be received. Removed with v1: `/stego/analyze`, `/stego/explain`, the
`/rag/*` endpoints, the whole-image selector (`sel-policy-2`), message priority classes, the manual algorithm
override and the explanation stage.

## 15. Migration from camera / upload covers

The image formats did not change (`frame-v2/appwire-v1/bootstrap-v2/manifest-v1`): images written before
this change are still received. What changed is where a cover comes from. Removed: `POST /api/stego/camera/probe`,
`POST /api/stego/cover/upload`, the Python routes `/stego/camera/probe`, `/stego/cover/upload`, `/stego/capture`,
the request object `cover {source: webcam | browser_webcam | uploaded | test_cover | procedural, …}`, the
`seed` field, the OpenCV adapter and `requirements-camera.txt`, the `IOD_STEGO_CAMERA*` /
`IOD_STEGO_CAPTURE_TIMEOUT_MS` variables, the webcam and upload components of the dashboard and the
`procedural_fallback` cover label. Old requests are answered with 400 / 404, never silently reinterpreted.
Event fields `cover_fallback_reason` and timing `capture` are gone; events carry the generation fields listed
in `cover-generation.md` §8. Report schema is now `stego-report-3`.
