# Patch-wise, knowledge-base-guided steganography transport

Format identifier: `frame-v3/appwire-v1/bootstrap-v3/manifest-v2`
Segmentation `arg-cells-1` · selector `kb-risk-1` · risk table `risk-table-1` · knowledge base `patch-kb-1` · default policy `low_detectability`

This document describes the system **as implemented**. M1–M8 and K1–K3 are unchanged; only the transport of K4
application messages is described here. The cover of every transmission is a **fresh, locally generated
procedural image** selected with knowledge of the payload length only; there is no camera, upload or
client-selected cover (`cover-generation.md`). The keyed bootstrap-v3 carrier and the reasons for choosing it
over deterministic receiver-side reconstruction are in `bootstrap-v3-design.md`.

## 1. Roles

| Component | Responsibility | Never does |
|---|---|---|
| Rust core (`rust-core/src/transport/`) | AEAD seal/open, AppWire, manifest validation, operational algorithm policy check, Frame v3 + HMAC, bootstrap-v3 placement key / value stream / sync word / carrier encryption, discovery, channel/direction/replay, acceptance, event log | pixel work |
| Python image service (`python-service/src/stego/`) | payload-aware cover generation, segmentation, patch features, knowledge-base retrieval within the policy, allocation, embedding, mapping value streams to pixels, carrier bit I/O, PNG save/re-read, extraction with a given manifest | holds keys, derives positions from a key, creates or checks the MAC, decrypts the carrier, sees plaintext |
| Node gateway (`node-server/`) | relays `/api/stego/*`, `/api/learn/*`, `/api/system/*` to the Rust core | talks to Python, selects, validates crypto |
| React UI (`web-ui/`) | renders values returned by the backend | computes or invents results |

The image service is **not trusted** by the core: every response is validated (manifest parsed strictly, lengths,
geometry and policy cross-checked, the compressed manifest must inflate to the planned one, the saved file is hashed
by the core itself, every receive-side read is tied to that hash).

## 2. Sequence

Sender (direction D1→D2 or D2→D1; same code path with direction-specific keys):

1. Core resolves the optional `cover_generation` object against the process profile (tighten-only; unknown fields
   such as a seed, a file or a source are rejected) **before** a sequence number is reserved.
2. Core checks the session (key-issued, both members active), reserves the next sequence number `s` and seals the
   plaintext: `AppWire = header(28) | ciphertext | AEAD tag(16)`, `W = len(AppWire)`.
3. Core derives the placement key `PK(s)` from the directional key (section 5) and its value stream `V(s)`.
4. Core → Python `POST /stego/plan {payload_bytes: W + 32, cover_generation, limits, segmentation, min_level,
   target_chunk_bytes, carrier: {version: 3, values_b64: V(s)}, policy: {name, allowed}}`. Python generates a bounded
   number of candidate covers, pre-screens them and plans best-first: it maps `V(s)` to carrier pixels, reserves the
   first `R` of them (R from the manifest size), segments, computes features and capacities without those pixels,
   allocates chunks, selects one **permitted** algorithm per used patch, dry-runs every patch and returns the
   **manifest-v2** plus its raw DEFLATE form (`manifest_deflate_b64`). No other cover source exists.
5. Core parses the manifest strictly; checks it against the sealed length, cover geometry, generator ceilings,
   `cover.source == "generated"`, the plan diagnostics and the **operational policy** (`POLICY_VIOLATION`); checks that
   the DEFLATE form inflates (bounded) to exactly that manifest.
6. Core builds **Frame v3** (HMAC over header, manifest and AppWire) and the **carrier**
   `sync(PK) | E(header) | E(DEFLATE(manifest) | CRC32)`.
7. Core → Python `POST /stego/encode {frame_b64, cover_id, carrier: {values_b64, bits_b64, n_bits}}`. Python loads that
   exact stored cover, embeds the payload section patch by patch, writes the carrier bits by ±1 LSB matching into the
   first `ceil(n_bits / C)` reserved carrier pixels, checks that nothing outside the patches and those pixels changed,
   saves the PNG, **re-reads the saved file**, reads the carrier back and extracts the frame again. Any mismatch →
   nothing is kept.
8. Core reads the saved PNG itself and compares its SHA-256 with the reported one.

Receiver (input: session, recipient, artifact id; plus its own replay state `L` for that direction):

9. Core reads the PNG from the artifact directory and hashes it.
10. **Discovery** (section 5.3): for every candidate `s' ∈ [max(1, L − 63), L + W_sync]` the core sends the first
    128 values of `V(s')` (`POST /stego/carrier/probe`); Python returns 96 locator bits per candidate; the core
    compares them with `sync(PK(s'))`. Exactly one match is required; a match with `s' ≤ L` is a `REPLAY`.
11. Core decrypts the 32-bit header, reads the body (`POST /stego/carrier/read`), decrypts it, checks the CRC,
    inflates with a 64 KiB limit and parses manifest-v2 strictly (geometry checked against the image).
12. Core → Python `POST /stego/extract {artifact_id, manifest_b64, values_b64}`. Python rebuilds the masks **from that
    manifest** without the reserved carrier pixels (no segmentation is run), extracts each chunk and returns the frame.
13. Core verifies the frame MAC, requires the frame's manifest to equal the decoded one, parses it strictly again,
    decodes AppWire, requires `AppWire.seq == s'` (`SEQUENCE_MISMATCH`), checks channel/direction/replay and opens
    the AEAD. Only then is `L` advanced.
14. Any failure is recorded as a failed event with a stable error code. No plaintext is returned on failure, the replay
    state is unchanged, and there is no fallback transport.

If step 7 fails with `PATCH_EMBED_FAILED`, the core re-plans **the same stored cover** with the **same sequence number
and value stream** — `POST /stego/plan {payload_bytes, replan_cover_id, min_level = level + 1, carrier, policy, …}`,
nothing is generated — at most `IOD_STEGO_MAX_REPLANS` (default 2) times, then fails. No other algorithm and no other
cover is substituted. The receiver never generates or plans anything.

## 3. Frame v3 (built and authenticated by the Rust core)

All integers big-endian.

```text
offset  size  field
0       4     magic "IOD3"
4       1     version = 3
5       1     flags = 0
6       2     reserved = 0
8       4     manifest_len  (M)
12      4     wire_len      (W)
16      M     manifest-v2 (section 4, uncompressed)
16+M    W     AppWire v1 (unchanged: 28-byte header | ciphertext | 16-byte AEAD tag)
16+M+W  32    tag = HMAC-SHA256(k_meta, "IOD-STEGO-FRAME-v3" | bytes[0 .. 16+M+W))
```

`k_meta = HKDF(directional AEAD key, info = "IOD-STEGO-META-v1" | channel_tag(16) | direction(1))`. The MAC domain
string is versioned, so no v2 tag verifies as v3; a v2 header (`"IOD2"`) is rejected before any MAC work.

**MAC coverage.** The tag covers the header and the *complete* manifest: image width/height/channels, cell size,
segmentation and selector version ids, `carrier_pixels`, the patch map (hence every patch id and its region), every
patch's algorithm id, parameter, payload offset and payload length, and the AppWire payload. Changing any of these
makes `FRAME_AUTH_FAILED`. The image service never receives `k_meta`.

**Where the bytes live in the image.** The header is not embedded (the receiver's service rebuilds it from the
manifest Rust hands back). The manifest travels compressed and encrypted in the bootstrap-v3 carrier. The patches
carry the *payload section* `AppWire | tag` (`payload_len = W + 32`), cut into chunks.

## 4. Patch manifest v2

```text
offset  size  field
0       4     magic "IOPM"
4       1     manifest version = 2
5       1     segmentation version id = 1   (arg-cells-1)
6       1     selector version id = 2       (kb-risk-1)
7       1     channels (1 = L, 3 = RGB)
8       2     width
10      2     height
12      1     cell size (4, 8 or 16)
13      1     n = patch count (1..255)
14      2     carrier_pixels R
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

*carrier_pixels* is canonical: `R = ceil((96 + 8·(manifest_len + 64 + 4)) / channels)` and `R ≤ width·height / 8`.
It is an upper bound for the carrier (raw DEFLATE never grows a manifest of this size by more than 64 bytes). The
first `R` distinct pixels of the frame's value stream are removed from every patch mask; only the first
`ceil(carrier_bits / channels)` of them are written, the rest stay untouched. No rows are reserved.

*Cell map.* The image is covered by a grid of `ceil(H/cell) × ceil(W/cell)` cells; each cell belongs to one patch. The
map is the row-major label sequence, run-length coded as `(label u8, run LEB128)` pairs. Runs may span rows. The
encoding is canonical: adjacent runs have different labels, run lengths are > 0 and minimally encoded, the runs cover
the grid exactly, every label is `< n`, and every patch id occurs. A pixel `(y, x)` belongs to patch
`map[y // cell][x // cell]` unless it is a reserved carrier pixel.

*Chunks.* Used patches, taken in ascending patch id, must have `offset` equal to the running sum of the previous
lengths, `length ≥ 1`, and the sum must equal `payload_len`: contiguous, non-overlapping, covering the payload exactly
once. Unused patches have all-zero entries.

*Parameters* (explicit, no implied defaults): ids 1–3 `0`; edge-adaptive threshold `1..255`; DCT step `4..64`; DWT step
`4..64`; DCT-SVD step `8..64`; HUGO/WOW/S-UNIWARD STC inverse rate `w = 2..64`.

Limits: manifest ≤ 65 536 bytes, ≤ 255 patches, dimensions ≤ configured maximum. Both parsers
(`rust-core/src/transport/manifest.rs`, `python-service/src/stego/patch/manifest.py`) reject everything else with
`MANIFEST_INVALID`, `MANIFEST_TOO_LARGE`, `UNSUPPORTED_VERSION` or `UNKNOWN_ALGORITHM`; length arithmetic is
overflow-checked. Manifest v1 (with `reserved_rows`) is rejected as `UNSUPPORTED_VERSION`.

## 5. Bootstrap v3 (keyed, distributed; in the image, unauthenticated until the frame MAC verifies)

Full design, alternatives and discovery rationale: `bootstrap-v3-design.md`. Summary:

```text
PK   = HKDF-SHA256(directional AEAD key, info = "IOD-STEGO-PLACE-v3" | channel_tag(16) | direction(1) | seq u32)
V    = SHAKE-256("IOD-BOOT3-VALUES" | PK) as big-endian u32 values (8192 sent for embedding and reads)
S    = HMAC-SHA256(PK, "IOD-BOOT3-SYNC")[0..8]
KS   = SHAKE-256("IOD-BOOT3-STREAM" | PK)
P    = first distinct values of (V_i mod (W·H)), in stream order                (Python maps; flat pixel index)
slot k = pixel P[k div C], channel k mod C
carrier = S (64 bits) | header XOR KS[0..4] (32 bits) | body XOR KS[4..]
header  = version 3 | flags 0 | body_len u16
body    = raw DEFLATE(manifest-v2) | CRC32(DEFLATE output)
write   = ±1 LSB matching where the LSB differs (random sign; 0 → +1, 255 → −1)
```

`PK`, `S` and `KS` never leave Rust. Python receives value streams (pseudo-random u32 values) and already encrypted
carrier bits; neither reveals a key, and neither is logged.

### 5.1 Size

Measured on 72 plans (24 generated 320×240 RGB covers × payload 288 / 1056 / 3032 B): manifest 550 B mean, DEFLATE
280 B mean → carrier ≈ 2,350 bits instead of ≈ 4,560 bits for bootstrap-v2, about 2–3 % of the pixels reserved.

### 5.2 Why there is no circular dependency

The receiver needs the carrier positions before it knows anything in the image. They depend only on the session key,
the direction and the sequence number, which the receiver knows up to the bounded window of section 5.3. The manifest
size (hence `R`) is fixed by the segmentation before capacities are measured, and `R` is an upper bound for the
compressed carrier, so planning never depends on the compression result.

### 5.3 Discovery window

Candidates `s ∈ [max(1, L − 63), L + W_sync]`, `W_sync = IOD_STEGO_SYNC_WINDOW` (default 64, 1…1024). The lookback
exists only to report replays explicitly; the forward window covers sequence numbers consumed by failed sends. Outcomes:
none → `BOOTSTRAP_NOT_FOUND` (wrong recipient or key, out of window, not a v3 image; `BOOTSTRAP_VERSION_UNSUPPORTED` if a
valid retired bootstrap-v2 preamble is present), one with `s ≤ L` → `REPLAY`, more than one → `BOOTSTRAP_AMBIGUOUS`.
A random 64-bit sync match has probability 2⁻⁶⁴ per candidate.

CRC-32 only separates accidental damage from a wrong key in diagnostics. **It is not authentication**: an adversary with
the placement key could rewrite the manifest with a valid CRC; the frame MAC then fails (tests do exactly this).

## 6. Test vectors

Manifest (pinned byte-for-byte in `python-service/tests/test_patch_manifest.py` and
`rust-core/src/transport/manifest.rs`; both encoders must produce it, both parsers must accept it): 64×64 RGB image,
cell 16 (4×4 cells), 2 patches, patch 0 unused, patch 1 = LSB replacement carrying 40 bytes; cell labels
`0011 / 0111 / 0111 / 0001`:

```text
494f504d 02 01 02 03 0040 0040 10 02 0180 00000028 00000010     fixed part (24)
00 00 0000 00000000 00000000                                     patch 0 (unused)
01 00 0000 00000000 00000028                                     patch 1: alg 1, offset 0, length 40
00 02 01 02 00 01 01 03 00 01 01 03 00 03 01 01                  map: 0×2 1×2 0×1 1×3 0×1 1×3 0×3 1×1
```

64 bytes; `R = ceil((96 + 8·(64 + 64 + 4)) / 3) = 384 = 0x0180` (≤ 64·64/8 = 512).

Frame header for that manifest with an 8-byte AppWire: `494f4433 03 00 0000 00000040 00000008`; the tag is
`HMAC-SHA256(k_meta, "IOD-STEGO-FRAME-v3" | header | manifest | wire)` (checked against an independent computation in
`frame.rs`). Bootstrap-v3 derivations (placement key, value-stream prefix property, sync word, keystream, CRC, bounded
inflate, decompression-bomb rejection, reserve bound) are unit-tested in `rust-core/src/transport/bootstrap.rs`; the
pixel mapping is cross-checked by an independent reader (`rust-core/tests/helpers/tamper_png.py`) in
`stego_e2e_python.rs`.

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

Per patch (`patch/features.py`): id, pixel count, usable pixel count (without the reserved carrier pixels), bounding box,
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

Selection for a patch that was allocated `B` bytes (`patch/kb.py`, selector `kb-risk-1`), no LLM, no embeddings,
no network:

0. **Operational policy** (`operational_policy` filter): an algorithm the policy excludes is never eligible
   (section 9a). The educational workbench does not apply a policy.
1. **Structured hard filters** per entry: `geometry_support` (the implementation's own check, e.g. at least one
   complete block), `min_usable_pixels`, `min_blocks`, the entry's `hard_avoid` rules (currently: DCT is excluded
   when saturation ≥ 0.02 because rounding at 0/255 breaks its round trip), and `measured_capacity ≥ 8·B`
   (capacity is the hard constraint).
2. **Risk-aware ranking** of the eligible entries with the versioned risk table
   `python-service/src/stego/kb/risk_table.json` (`risk-table-1`, measured on the **validation** split only by
   `scripts/eval_detectability.py --stage risk-table`): (a) risk tier (`low` AUC < 0.65, `medium` 0.65–0.80,
   `high` ≥ 0.80; thresholds fixed before measuring), (b) expected distortion = measured changes per embedded bit,
   (c) processing cost = measured ms per KiB, (d) **BM25** suitability of the entry text for the patch's
   descriptive terms (higher first), (e) lower algorithm id.
   BM25: documents are the tokens of `suitable_terms` (weight 3), `summary` (1) and `suitable_when` (1);
   `k1 = 1.5`, `b = 0.75`, IDF over all ten entries (`ln(1 + (N − df + 0.5)/(df + 0.5))`). The query is the set of
   descriptive terms whose threshold rule holds for the patch (`flat`, `smooth`, `moderate-texture`, `textured`,
   `noisy`, `edge-rich`, `few-edges`, `high-entropy`, `low-entropy`, `saturated`, `binary`, `dark`, `bright`,
   `large/medium/small-region`, `compact`, `elongated`, `ragged`, `block-aligned`, `high/low-frequency`,
   `low/medium/high-rate`, `color`, `grayscale`).
3. **Top-1.** The first entry of that ranking wins.

Consequence (stated, not hidden): with `risk-table-1` the low tier is HUGO/WOW/S-UNIWARD and S-UNIWARD has the
fewest changes per bit, so S-UNIWARD is chosen for every patch where it is eligible; another algorithm is chosen
only where S-UNIWARD is filtered out (capacity, geometry). Diversity across patches is therefore a result of
eligibility, not a goal. The risk table is a whole-image, single-algorithm proxy measured with the detectors of
`detectability-evaluation.md`; it is versioned and must be rebuilt (new version) when algorithms or detectors change.

Recorded per patch: every entry id, each filter result with its detail, matched terms, BM25 score, measured
capacity, rank, and the final choice. If nothing is eligible, or the chosen algorithm fails its dry run, there is
**no fallback**: the planner moves to the next refinement level or rejects.

There are no message priority classes; a client request to the core has no such field, and old clients that send
`priority`, `algorithm`, `param` or `policy` get `400 INVALID_REQUEST`. The operational policy is configured on the core
(section 9a) and sent by the core to the image service, never chosen by a client.

## 9a. Operational algorithm policy

| Policy | Allowed | Excluded |
|---|---|---|
| `low_detectability` (default) | `lsb_matching`, `pvd`, `edge_adaptive_lsb`, `hugo`, `wow`, `s_uniward` | `dct`, `dwt`, `dct_svd` (by rule, pending an independent evaluation); `lsb_replacement` (high tier in risk table `risk-table-1`, validation split) |
| `all_algorithms` | all ten | none (comparison and research runs only) |

`IOD_STEGO_ALGORITHM_POLICY` selects the policy; `IOD_STEGO_ALGORITHM_ALLOW` (comma list) can only narrow it. The
allowed algorithms are *candidates*, not "safe" algorithms. If no permitted plan fits the payload, planning fails
(`NO_ELIGIBLE_ALGORITHM` / `PATCH_CAPACITY_INSUFFICIENT`); nothing falls back to an excluded algorithm. Rust re-checks
every planned manifest (`POLICY_VIOLATION`). `GET /api/stego/status` (`config.algorithm_policy`) shows the active policy
and its exclusions; `config.bootstrap` shows the bootstrap version and the sync window.

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
Policy (core): `POLICY_VIOLATION`.
Reading: `ARTIFACT_NOT_FOUND`, `IMAGE_DECODE_ERROR`, `BOOTSTRAP_NOT_FOUND`, `BOOTSTRAP_AMBIGUOUS`,
`BOOTSTRAP_VERSION_UNSUPPORTED`, `BOOTSTRAP_CORRUPT`, `UNSUPPORTED_VERSION`, `MANIFEST_INVALID`, `MANIFEST_TOO_LARGE`,
`UNKNOWN_ALGORITHM`, `EXTRACT_FAILED`. Verification (core): `FRAME_MALFORMED`, `FRAME_VERSION_UNSUPPORTED`,
`FRAME_TOO_LARGE`, `FRAME_LENGTH_MISMATCH`, `FRAME_AUTH_FAILED`, `SEQUENCE_MISMATCH`, `WRONG_CHANNEL`, `REPLAY`,
`AEAD_FAILED`. Infrastructure:
`STEGO_BACKEND_UNAVAILABLE`, `BACKEND_MALFORMED_RESPONSE`, `ARTIFACT_HASH_MISMATCH`.

## 13. Limitations

* Lossless PNG handoff through a shared directory only. JPEG, resizing, cropping or filtering destroy the
  message; robustness is not claimed (the learning workbench measures it and reports the failures).
* Steganography here is an obscurity layer on top of AEAD. No steganalysis resistance is claimed for any
  algorithm; LSB-class methods and the QIM transform methods are detectable.
* Keyed placement hides *where* the bootstrap-v3 carrier is from anyone without the session key; it does not make
  the ±1 changes statistically invisible. Detectability of the whole transport (carrier included) is measured, not
  assumed (`detectability-evaluation.md`); no undetectability is claimed.
* A receiver whose replay state lags the sender by more than `IOD_STEGO_SYNC_WINDOW` sequence numbers cannot locate
  the carrier (`BOOTSTRAP_NOT_FOUND`); after a core restart a new K1–K3 run is needed (channel keys are in memory).
* Covers are synthetic procedural images (`cover-generation.md`): coherent and varied, but not photographs,
  and produced by a public generator.
* The patch map is carried compressed and XOR-encrypted with a per-frame keystream inside the image; its integrity
  comes from the frame MAC, not from the encryption or the CRC.
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

What changed is where a cover comes from. Removed: `POST /api/stego/camera/probe`, `POST /api/stego/cover/upload`, the
Python routes `/stego/camera/probe`, `/stego/cover/upload`, `/stego/capture`, the request object
`cover {source: webcam | browser_webcam | uploaded | test_cover | procedural, …}`, the `seed` field, the OpenCV adapter
and `requirements-camera.txt`, the `IOD_STEGO_CAMERA*` / `IOD_STEGO_CAPTURE_TIMEOUT_MS` variables, the webcam and
upload components of the dashboard and the `procedural_fallback` cover label. Old requests are answered with 400 / 404,
never silently reinterpreted. Events carry the generation fields listed in `cover-generation.md` §8.

## 16. Migration from bootstrap-v2 / Frame v2 / manifest-v1

`frame-v2/appwire-v1/bootstrap-v2/manifest-v1` images (top-row `"SB"` preamble, `"IOD2"` frame, `reserved_rows`) are
**not accepted**: the receiver reports `BOOTSTRAP_VERSION_UNSUPPORTED` when it recognises a valid v2 preamble, otherwise
`BOOTSTRAP_NOT_FOUND`. There is no conversion. The Python `/stego/extract` endpoint now requires `manifest_b64` and
`values_b64`; `/stego/plan` requires `carrier` and accepts `policy`; `/stego/encode` requires `carrier`; the new
endpoints are `/stego/carrier/probe` and `/stego/carrier/read`. Plan diagnostics report `carrier_pixels`,
`bootstrap_carrier_bits`, `manifest_deflate_bytes`, `bootstrap_version` and `operational_policy` instead of
`reserved_rows`. Stored v2 artifacts and events remain readable as files/rows but cannot be received.
