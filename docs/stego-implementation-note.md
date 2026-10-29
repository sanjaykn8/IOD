# Steganographic application-message transport — implementation note

Status: **design note for the integration work** (written before implementation; the
final, verified behaviour is described in `docs/stego-transport.md` once built).
Scope decisions are fixed by the master integration prompt; this note records *how*.

## 0. Scope and invariants (requirements, not options)

* Steganography carries **application messages only** (K4), after M1–M8 and K1–K3 have
  completed. M1–M8 / K1–K3 code paths are not modified.
* D1→D2 **and** D2→D1 both use image transport. No silent passthrough fallback: any failure
  is a structured error plus a persisted failure event.
* Rust is authoritative for keys, sealing, frame MAC, parsing, replay/direction/channel
  checks, AEAD open, persistence. Python only manipulates bytes and pixels (+ webcam, metrics,
  RAG text). Node only relays. React only renders. **No key, MAC key, or plaintext ever
  crosses to Python/Node/browser/logs.** (The receiver's decrypted message is returned to the
  UI exactly once, as the result of the send/receive transaction — it is never logged.)
* Selection is deterministic and lives **outside** RAG; RAG explains an already-made choice.
* All five algorithms work on arbitrary bytes, are deterministic, and round-trip exactly
  through lossless PNG. They are **fragile** to JPEG/resize/filtering; none is claimed robust.

## 1. Layers (what is embedded where)

```
plaintext --AEAD(seal, AAD=APPMSG header)--> SecureAppMessage
   --AppWire v1 (binary)-->  payload
   --Frame v1 = header(12) || payload || HMAC tag(32)-->  frame bytes   (Rust)
   --Bootstrap(16B, LSB, fixed) + algorithm payload embedding-->  PNG    (Python)
```

### 1.1 AppWire v1 (Rust, strict, big-endian) — the complete message wire form

| off | len | field |
|---|---|---|
| 0 | 1 | `wire_version` = 1 |
| 1 | 16 | `channel_tag` |
| 17 | 1 | `direction` (1 = D1→D2, 2 = D2→D1) |
| 18 | 4 | `header_seq` u32 |
| 22 | 8 | `header_ts` u64 (ms) |
| 30 | 4 | `sealed.seq` u32 (must equal `header_seq`) |
| 34 | 12 | AEAD nonce |
| 46 | 4 | `ct_len` u32 (≤ max frame bytes) |
| 50 | ct_len | ciphertext‖Poly1305 tag |

The parse is strict: exact length, version, `ct_len` bound, `sealed.seq == header_seq`.
It contains **no DroneID/PID**. `SecureAppMessage::associated_data()` (the AEAD AAD) is
reconstructed from these fields, so header tampering also fails AEAD.

### 1.2 Transport Frame v1 (Rust)

| off | len | field |
|---|---|---|
| 0 | 4 | magic `"IODF"` |
| 4 | 1 | `frame_version` = 1 |
| 5 | 1 | `alg_id` (1..5) — must equal the bootstrap `alg_id` |
| 6 | 1 | `param` — must equal the bootstrap `param` |
| 7 | 1 | `flags` = 0 (non-zero rejected) |
| 8 | 4 | `wire_len` u32 |
| 12 | wire_len | AppWire v1 |
| 12+wire_len | 32 | `tag = HMAC-SHA256(meta_key, "IOD-STEGO-FRAME-v1" ‖ header(12) ‖ payload)` |

`meta_key = HKDF-SHA256(ikm = directional AEAD key, salt = none, info = "IOD-STEGO-META-v1" ‖ channel_tag ‖ direction, 32 B)`,
derived in Rust with the existing `crypto::kdf::hkdf_expand`. It is distinct from the AEAD
key (domain separation), never leaves Rust, and is never logged. The MAC covers the header
(including algorithm id/param) and the entire encrypted wire payload. MAC comparison is
constant-time (`hmac_verify`). A checksum is *not* used for authentication.

### 1.3 Bootstrap v1 (Python, algorithm-independent, fixed)

16 bytes, embedded by **LSB replacement into the LSB of samples `[0,128)`** of the flattened
(row-major, channel-interleaved) uint8 sample array — MSB-first bit order. Fixed position, fixed
method: no circular dependency between "which algorithm" and "how to read it".

| off | len | field |
|---|---|---|
| 0 | 2 | magic `"SB"` |
| 2 | 1 | `bootstrap_version` = 1 |
| 3 | 1 | `alg_id` (1 lsb_replacement, 2 lsb_matching, 3 pvd, 4 edge_adaptive_lsb, 5 dct) |
| 4 | 1 | `param` (algorithm-specific; 0 → default) |
| 5 | 1 | `flags` = 0 |
| 6 | 4 | `frame_len` u32 (bytes embedded by the payload algorithm) |
| 10 | 2 | reserved = 0 |
| 12 | 4 | CRC-32 of bytes 0..12 (accidental-corruption detection only) |

Before any expensive work the extractor validates: image mode (`L`/`RGB`), dimensions
(≥ 32×32, ≤ configured max), magic, version, CRC, `alg_id`, `flags`, reserved, and that
`frame_len` ≤ configured max **and** ≤ the algorithm's computed capacity for *this* image.
All payload algorithms leave samples `[0,128)` untouched (tested). The bootstrap is **not**
authenticated by itself; the Rust side requires the authenticated frame header's
`alg_id`/`param`/length to equal the bootstrap values (mismatch ⇒ `FRAME_ALGORITHM_MISMATCH`).

### 1.4 Algorithms (Python `stego/algorithms/`, ids above)

Common contract (all take/return `uint8` ndarray `(H,W)` or `(H,W,3)`; always copy):
`capacity_bits(img, param)`, `embed(img, payload, param) -> EmbedOutcome`, `extract(img, nbytes, param) -> bytes`.
Payload bits are MSB-first. "Sample" = one channel value; sample index = flat index of
`img.reshape(-1)`; payload positions never include `[0,128)`.

1. **lsb_replacement** — sample `128+i` carries bit *i* in its LSB. Capacity = `N-128` bits.
2. **lsb_matching** — LSB replaced only when it differs; the sample then moves ±1. At 0 → +1,
   at 255 → −1, otherwise direction from a deterministic PRNG
   (`numpy.random.PCG64` seeded with the first 8 bytes of `SHA-256(cover bytes ‖ "LSBM-v1")`).
   Extraction reads LSBs. Capacity `N-128`.
3. **pvd** (Wu–Tsai range table) — adjacent sample pairs `(128+2k, 129+2k)`; `d=|a-b|`; ranges
   `[0,7],[8,15],[16,31],[32,63],[64,127],[128,255]` carry `3,3,4,5,6,7` bits; the value `v` sets
   `d' = lower + v`. New pixel pair keeps the sign of `a-b`, minimises squared change, and is
   clamped into `[0,255]` while keeping `|a'-b'| = d'` exactly (a feasible pair always exists
   because `d' ≤ 255`). Because `d'` stays in the same range, the extractor derives the
   same bit count from the stego pair. Capacity = sum of range bits over all pairs (exact).
4. **edge_adaptive_lsb** — eligibility mask from the **7 most significant bits only**
   (`g = img >> 1`; luma `(299R+587G+114B)//1000` of those for RGB), gradient
   `|g[x+1]-g[x]| + |g[y+1]-g[y]|` (edge-padded) `>= T` (`param`, default 6). LSB replacement only
   changes the LSB, so the mask is identical for cover and stego. Eligible *pixels'* samples in raster order
   (excluding `[0,128)`) carry bits. If eligible capacity < frame bits ⇒ the algorithm is
   unavailable (`EDGE_CAPACITY_INSUFFICIENT`); there is **no** fallback to non-edge pixels.
5. **dct** — 8×8 orthonormal block DCT-II (numpy matrix form, no SciPy needed) on one plane
   (channel 2 for RGB, the only channel for L). Blocks with block-row ≥ 1 only (block-row 0
   overlaps the bootstrap). Per block, 6 mid-frequency coefficients
   `(1,2),(2,1),(2,2),(1,3),(3,1),(3,0)` — quantisation-index modulation with step Δ
   (`param`, default 12, allowed 4..64): `q = round(c/Δ)`; if `q mod 2 ≠ bit` move `q` by ±1
   toward `c`; `c' = qΔ`; inverse DCT; round to integer; clip to `[0,255]`. The encoder
   **re-extracts every used block** from the rounded/clipped result; blocks that fail are retried
   with the opposite ±1 choice; if still failing the whole encode fails with
   `ENCODE_VERIFY_FAILED` (typical for saturated 0/255 blocks, e.g. the B/W fallback cover).
   Capacity = `6 × blocks`. Not claimed robust to any transform.

Trailing bits of the last PVD pair/DCT block are zero-filled; extractors discard them.
The orchestration layer additionally does a full in-process extract-and-compare after embedding
(`EMBED_VERIFY_FAILED` on mismatch) and again after the PNG is saved and re-read.

### 1.5 Image mode handling and transforms

Accepted cover/stego modes: `RGB`, `L`. A webcam frame is RGB. The procedural B/W generator
(`latent_image.decode_latent`, mode `1`) is converted to `L` (0/255) — a recorded transform
(`"mode:1->L"`). Uploaded test covers in other modes are converted to `RGB`/`L` and the
transform is recorded; **no resizing or lossy step is ever applied** (images larger than the
configured limits are rejected with `IMAGE_TOO_LARGE`). Output is always PNG (lossless),
re-opened and verified before the artifact id is returned.

## 2. Deterministic selector (Python `stego/selector.py`, policy version `sel-policy-1`)

Pure function of `(features, policy)`; no RNG, no wall-clock, no RAG. Steps:

1. **Validate** cover and frame (`frame_bytes ≥ 1`, ≤ `max_frame_bytes`).
2. **Capacity filter**: `capacity_bits(alg) ≥ 8·frame_bytes` else exclude (`CAPACITY_INSUFFICIENT`
   / `EDGE_CAPACITY_INSUFFICIENT`).
3. **Trial encode** each remaining candidate on the real cover with a deterministic
   pseudo-random stand-in of the same length (an encrypted frame is indistinguishable from random;
   seeded `SHA-256("sel-trial"‖len)`): gives *measured* `mse`, `psnr`, `ssim`, `changed_samples`.
   Trial failure ⇒ exclude (`ENCODE_VERIFY_FAILED`).
4. **Hard constraints**: `mse ≤ max_mse` (default 4.0), `psnr ≥ min_psnr_db` (default 40.0; `inf` passes),
   `est_cost_units ≤ max_cost_units` (default 1000). Exclusions carry reasons `MSE_LIMIT`,
   `PSNR_LIMIT`, `COST_LIMIT`.
5. **Score** (lower = better; rounded to 6 d.p.):
   `score = w_d·d + w_u·u + w_t·t` with `d = clamp(1 − psnr/80, 0, 1)` (inf → 0),
   `u = frame_bits / capacity_bits`, `t = est_cost_units / 20` (clamped to 1).
   `est_cost_units` is a **static model, not a measurement**:
   `work[alg]·(frame_bytes+16)/64 + scan[alg]·(H·W)/1e5` with
   `work = {lsb_replacement 0.5, lsb_matching 0.7, pvd 1.2, edge_adaptive_lsb 0.9, dct 2.0}`,
   `scan = {lsb_replacement 0, lsb_matching 0.1, pvd 0.2, edge_adaptive_lsb 0.6, dct 1.0}`.
   Measured wall-clock timings are *reported* (per candidate and per stage) but never ranked, so
   the decision is reproducible.
   Weights by priority class `(w_d, w_u, w_t)`: `urgent (0.2, 0.1, 0.7)`, **`normal (0.5, 0.2, 0.3)`**
   (default — the application model has no priority field, so every message is `normal`),
   `background (0.8, 0.15, 0.05)`.
6. **Tie-break**: candidates whose score is within `tie_epsilon` (0.01) of the best are tied; the
   winner is the first in `tie_break_order`
   (default `[lsb_matching, pvd, edge_adaptive_lsb, lsb_replacement, dct]`; a documented policy
   preference, not a measurement).
7. Output: `selected`, `reason_code` (`BEST_SCORE` | `TIE_BREAK_ORDER` | `ONLY_ELIGIBLE` | `MANUAL_OVERRIDE`),
   `policy_version`, `features`, per-candidate `{algorithm, eligible, exclusion_reason, capacity_bits,
   capacity_bytes, utilization, headroom_bits, est_cost_units, mse, psnr, ssim, score, trial_ms}`.
   If none eligible ⇒ error `NO_ELIGIBLE_ALGORITHM` carrying the candidate table.

**Manual override** (Lab experiments) bypasses ranking but not safety: the forced algorithm must
still pass steps 1–4, else `ALGORITHM_NOT_ELIGIBLE` with the reason. Unknown name ⇒ `INVALID_REQUEST`.

Policy is a JSON object supplied by Rust on every call (single source of truth: Rust config);
Python validates ranges and applies defaults. The policy is pluggable (`Selector` registry keyed
by policy name) but only `sel-policy-1` ships.

## 3. RAG = explanation only

`POST /stego/explain` (Python `rag/explain.py`) receives the **finished** selection report and
returns narrative + evidence. It reuses the existing word-overlap retrieval over a curated,
versioned knowledge base `rag/knowledge/stego_algorithms.json` (`kb_version`). The narrative is
template-generated (mock LLM) and then **claim-checked**: every number quoted must appear in the
evidence; otherwise `status = "unsupported_claims"` and the caller uses the deterministic fallback.
Output carries `status: "simulated_rag"`, `selected_unchanged: true` (echoed from the input). The
endpoint cannot alter the decision (it has no write path). Rust treats any error/timeout as
`explanation.status = "fallback_deterministic"` with a Rust-generated rule-based text, never
failing delivery.

## 4. Rust ↔ Python boundary

Rust calls Python over **plain HTTP/1.1 on localhost** with a tiny hand-written client
(`std::net::TcpStream`, `Connection: close`, `Content-Length`): *no new dependency, and no TLS
stack* (rustls/ring would pull ECC code into the tree, forbidden by the no-ECC rule).
Explicit connect/read/write timeouts (default 20 s), maximum response size (default 32 MiB), strict
status/JSON parsing. The global `Mutex<SimulationState>` is **not held across calls**: each
transaction takes short lock sections (prepare → release → Python calls → relock → commit).
`IOD_PYTHON_URL` (default `http://127.0.0.1:5001`) must be a loopback `http://` URL (validated).

Artifacts live in `IOD_STEGO_ARTIFACT_DIR` (default `./data/stego-artifacts`), shared by both
processes (Docker: named volume). File names are `<32-hex>.png` (stego) and `<32-hex>.cover.png`;
ids are `uuid4().hex`; every endpoint accepts only the id and validates `^[0-9a-f]{32}$` — no
client path is ever opened. Files are written atomically (`tmp` + `os.replace`), never overwritten
(exclusive create). Retention: `IOD_STEGO_RETENTION_MAX_ARTIFACTS` (default `0` = keep everything).

### 4.1 Python endpoints (service `python-service`, blueprint `stego`)

All JSON. Errors: HTTP 4xx/5xx with `{"ok":false,"error":{"code","message","details"?}}`.
Binary values are standard base64.

* `GET /stego/health` → `{ok, service, version, algorithms:[{id,name}], limits, artifact_dir_writable, camera:{backend, opencv_available, mode}, numpy, pillow}`
* `POST /stego/camera/probe` `{camera_index?, timeout_s?}` → `{available, reason|null, width?, height?}`
* `POST /stego/capture` `{cover:{source,...}, limits}` → cover descriptor (cover artifact saved) — used by the Lab "capture" button.
* `POST /stego/analyze` `{frame_bytes:int, cover:{...}, priority, policy, limits}` → `{selection, cover}`; no stego image is saved (trial encodes only).
* `POST /stego/encode` `{frame_b64, cover:{...}, algorithm|null, priority, policy, limits}` →
  `{ok, artifact_id, stego:{path_name, sha256, size, width, height, mode, channels, format:"PNG"}, cover:{artifact_id, source, fallback_reason, width, height, mode, channels, transforms, sha256, seed?}, selection:{...§2 output...}, embed:{algorithm, alg_id, param, params, capacity_bytes, frame_len, used_fraction, metrics:{mse,psnr,ssim,changed_samples,changed_fraction,max_abs_diff}}, timings_ms:{capture,select,embed,verify,save}}`
* `POST /stego/extract` `{artifact_id, limits}` → `{ok, frame_b64, bootstrap:{version, alg_id, algorithm, param, frame_len}, image:{width,height,mode,channels,format,size,sha256}, timings_ms:{read,extract}}`
* `POST /stego/explain` — §3.

`cover` object: `{"source": "webcam"|"procedural"|"test_cover", "camera_index"?:int, "test_cover_id"?:hex32, "seed"?:str}`.
`"webcam"` means *webcam with procedural fallback* (the default for sending); `"procedural"` forces
the generator; `"test_cover"` loads a previously uploaded/saved cover artifact.

Stable error codes (Python): `INVALID_REQUEST, FRAME_TOO_LARGE, IMAGE_TOO_LARGE, IMAGE_TOO_SMALL, UNSUPPORTED_IMAGE_MODE,
IMAGE_DECODE_ERROR, ARTIFACT_NOT_FOUND, BOOTSTRAP_MISSING, BOOTSTRAP_CORRUPT, UNSUPPORTED_VERSION, UNKNOWN_ALGORITHM,
FRAME_LENGTH_INVALID, EXTRACT_FAILED, NO_ELIGIBLE_ALGORITHM, ALGORITHM_NOT_ELIGIBLE, ENCODE_VERIFY_FAILED, EMBED_VERIFY_FAILED,
IMAGE_WRITE_FAILED, COVER_FAILED, INTERNAL_ERROR`.
Camera fallback reasons (not errors): `CAMERA_ABSENT, CAMERA_PERMISSION_DENIED, CAMERA_TIMEOUT, CAMERA_BACKEND_UNAVAILABLE, CAMERA_CAPTURE_FAILED, CAMERA_DISABLED`.

### 4.2 Rust HTTP API (browser-facing through Node `/api/stego/*`, same paths under `/api`)

* `GET  /api/stego/status` → `{backend:{reachable, error?, health?}, config:{limits, policy, artifact_dir_name, retention}, counts:{events, ok, failed}}`
* `POST /api/stego/camera/probe` `{camera_index?}` → Python probe result (proxied by Rust).
* `POST /api/stego/analyze` `{frame_bytes?:int (default 256), cover?, priority?, policy?}` → selection table.
* `POST /api/stego/message` `{session_id?|d1_id+d2_id, from_id, plaintext, algorithm?, cover?, priority?}` — full send→save→receive→verify transaction.
  Success `200`: `{ok:true, event_id, session_id, direction, seq, from_role, to_role, delivered_message, artifact:{id,stego_sha256,size,preview_url,cover_preview_url}, cover:{...}, selection:{...}, embed:{...}, verification:{frame_match,header_mac_ok,algorithm_consistent,aead_ok}, timings_ms:{aead_seal,capture,select,embed,save,read,extract,verify,aead_open,explain,total}, stages:[{name,status,ms,detail}], explanation:{status,narrative,evidence,retrieved,kb_version,fallback,selected_unchanged}}`.
  Failure: `{ok:false, event_id, error:{code,message,stage,details?}, stages:[...]}` with status 400/403/404/409/413/422/502/503.
* `POST /api/stego/send` (same request; returns after the PNG is saved: `{ok, event_id, artifact, selection, ...}` and stages up to *save*) and
  `POST /api/stego/receive` `{session_id, recipient_id, artifact_id}` (reads the saved file only).
* `GET  /api/stego/events?session_id=&direction=&algorithm=&outcome=&since_ms=&until_ms=&limit=` → `{events:[StegoEvent]}`
* `GET  /api/stego/report?format=json|csv` → report (§5).
* `POST /api/stego/benchmark` `{session_id, iterations?(≤50), frame_sizes?:[int], algorithms?:[names], cover?}` → runs real sealed messages through the full pipeline and returns `{runs, summary}`.
* `GET  /api/stego/artifacts/{id}/stego|cover` → `image/png` bytes (id validated).
* Existing `POST /api/secure-message` now routes through the same pipeline (fails closed with `503 STEGO_BACKEND_UNAVAILABLE` if Python is down) and keeps its legacy response fields, adding `stego` details.

Error HTTP mapping: validation/401-class → 400/403/404; `NO_AUTH_SESSION`/replay → 409; capacity → 413 (`FRAME_TOO_LARGE`, `NO_ELIGIBLE_ALGORITHM` → 422); backend → 503/502.

### 4.3 StegoEvent (SQLite table `stego_events`, additive migration `CREATE TABLE IF NOT EXISTS`)

Columns: `id` autoinc, `ts_ms`, `session_id`, `direction`, `algorithm`, `outcome` (`ok`/`failed`), `data` (JSON of the full
event). JSON fields: `event_id, ts_ms, kind(send|receive|transaction|benchmark), session_id, direction, seq, from_role, to_role,
transport_format_version, algorithm, param, selection_policy_version, selection_mode, selection_reason_code, candidates[…scores/exclusions],
explanation_status, cover_source, cover_fallback_reason, width, height, mode, channels, output_format, frame_bytes, wire_bytes,
image_bytes, capacity_bytes, capacity_margin_bytes, timings_ms{…}, mse, psnr, ssim, (nullable with `*_defined` flags), success,
error_code, error_message, error_stage, artifact_id, stego_sha256, cover_sha256, frame_sha256_prefix (first 8 B hex of SHA-256(frame) — correlation only),
frame_match, header_mac_ok, aead_ok`. **Never**: plaintext, ciphertext, keys, MAC key, tokens.

## 5. Report (JSON/CSV, stable schema `stego-report-1`)

`{schema, generated_ms, environment{os, rustc?, python_service{version,numpy,pillow}, camera_mode}, totals{events, ok, failed, fallback_cover_count, error_counts{code:n}}, per_algorithm[{algorithm, n_ok, n_failed, capacity_bytes{mean}, frame_bytes{mean}, mse{mean,n}, psnr{mean,n}, ssim{mean,n}, timings_ms{stage:{n,mean,p50,p95|null}}}], limitations[...]}`; p50/p95 are `null` unless `n ≥ 20`. CSV is one row per event with the flat fields above (header row fixed).

## 6. Tests required (see prompt §Test requirements) — mapping

* Python: `python-service/tests/test_stego_*.py` (algorithms, bootstrap/extract failures, PNG round trip, boundary pixels, edge mask, DCT blocks, metrics, selector determinism/tie-break/forced/no-capacity, camera adapter mocks, procedural fallback, artifacts/path safety, Flask routes, RAG explain + claim check). Original standalone tests preserved under `tools/stego-standalone/`.
* Rust: `src/transport/**` unit tests (frame/wire/MAC/tamper/fuzz-style malformed), `tests/stego_pipeline.rs` (fake backend: file-only receive, both directions, replay, tamper, wrong recipient, no plaintext/keys in events, persistence across restart, RAG outage fallback) and `tests/stego_e2e_python.rs` (spawns the real Python service; skipped *visibly* if python/numpy missing).
* Integration/UI: Node `tsc`, React `tsc`+`vite build`, `scripts/` smoke test of the whole saved-image flow.

## 7. Honest limitations (to be repeated in final docs)

Research prototype. Lossless PNG handoff only. No anti-steganalysis claim (LSB-class methods are
statistically detectable). Frame/ciphertext is high-entropy, so stego adds *obscurity*, not
cryptographic strength — confidentiality/authenticity come from ML-KEM-derived AEAD keys + HMAC.
Mock RAG (word-overlap retrieval + template text). Camera path verified only via mocks in CI;
a physical webcam was not available in the build environment.
