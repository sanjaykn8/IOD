# Bootstrap-v3 design note

Status: implemented 2026-11-19. Transport identifier changes from
`frame-v2/appwire-v1/bootstrap-v2/manifest-v1` to **`frame-v3/appwire-v1/bootstrap-v3/manifest-v2`**.

## 1. The path being changed

1. Rust seals the message (ChaCha20-Poly1305 under the directional session key, sequence number
   reserved per session and direction) and wraps it as AppWire v1.
2. Rust asks the image service to plan for the payload **length** (`POST /stego/plan`); the service
   generates the cover, segments it, selects one algorithm per patch and returns the manifest.
3. Rust builds the frame `header | manifest | wire | HMAC tag` (tag key derived from the session key,
   never leaves Rust) and asks the service to embed it into the stored cover (`POST /stego/encode`).
4. The receiver's Rust core reads the saved PNG, the service extracts the frame from that same file,
   and Rust verifies frame MAC → manifest → AppWire → channel / direction / replay → AEAD before any
   plaintext exists.

Bootstrap-v2 (what the receiver needs before it can find the patches) was
`"SB" preamble (16 B) | manifest | CRC32` written as plain LSB replacement into consecutive samples
from pixel 0, i.e. the first 3–7 image rows were a reserved band of structured LSB data. The offline
evaluation attributed most of the operational detectability (AUC ≈ 0.98) to this band; with those rows
hidden from the detector the AUC fell to ≈ 0.61 (256 B) / 0.75 (1536 B).

Files involved: `python-service/src/stego/{bootstrap,codec,service}.py`, `stego/patch/{manifest,planner,
features,render}.py`; `rust-core/src/transport/{frame,manifest,pipeline,fake,backend}.rs`; tests
`test_patch_manifest.py`, `test_patch_planner_codec.py`, `test_patch_service_api.py`, `stego_pipeline.rs`,
`stego_e2e_python.rs`, `tests/helpers/tamper_png.py`.

## 2. Options considered

Measured on 72 plans (24 fresh 320×240 RGB covers × payload 288 / 1056 / 3032 B):
manifest-v1 = 550 B mean (320–798), of which 385 B is the run-length patch map; DEFLATE of the manifest =
280 B mean (200–398).

**Option A — deterministic receiver reconstruction.** Carry only an encrypted cover seed, generator and
planner versions, refinement level and payload length (≈ 40 B); the receiver regenerates the pristine
cover and re-runs segmentation, retrieval and allocation.
* + smallest carrier (≈ 400 bits instead of ≈ 4,500).
* − every receive must reproduce float32 NumPy generation, segmentation and BM25 scoring bit-exactly;
  this holds on one machine but not across CPU architectures or NumPy builds (the intended sender/receiver
  pair is two different devices); a mismatch is an undetectable-until-failure extraction error.
* − the raw cover seed would have to leave the service, be stored (encrypted) in the image and be handed
  back to the service at receive time, contradicting the generator rule that raw production seeds never
  leave the generator.
* − receive cost becomes generation + full planning (≈ 0.3–1.5 s on the development host per message).
* − abandons the established invariant that the receiver never segments.

**Option B — compact, keyed, distributed carrier.** Keep a manifest in the image, but compress it, encrypt
it, and spread it over keyed pseudo-random pixel positions with ±1 embedding instead of a fixed band.
* + extraction depends only on bits read from the saved PNG; no float reproducibility needed.
* + receiver still never segments; raw cover seeds stay inside the generator.
* + carrier ≈ 2.2× smaller than v2 (DEFLATE), no contiguous region, uniformly random-looking bits.
* − larger than Option A; positions must be discoverable without knowing the sequence number (§4).

**Decision: Option B.** Reliability (no cross-platform float determinism), the seed-handling rule and the
receive cost outweigh the extra ≈ 2,000 carrier bits. Its detectability is measured, not assumed
(`detectability-evaluation.md`).

## 3. Format

```text
placement key  PK  = HKDF-SHA256(directional AEAD key,
                       info = "IOD-STEGO-PLACE-v3" ‖ channel_tag(16) ‖ direction(1) ‖ seq(u32 BE))   — Rust only
value stream   v_i = SHAKE-256("IOD-BOOT3-VALUES" ‖ PK)  read as big-endian u32, i = 0..V-1   (V = 8192)
sync word      S   = HMAC-SHA256(PK, "IOD-BOOT3-SYNC")[0..8]                                     — 64 bits
keystream      KS  = SHAKE-256("IOD-BOOT3-STREAM" ‖ PK)
carrier pixels P   = first distinct values of (v_i mod (W·H)), in stream order     (service-side mapping)
sample slots       bit k → pixel P[k div C], channel k mod C            (C = 3 for RGB, 1 for grey)

carrier bits   = S (64) ‖ E(header)(32) ‖ E(body)
header         = version u8 = 3 ‖ flags u8 = 0 ‖ body_len u16 BE
body           = DEFLATE(manifest-v2) ‖ CRC32(DEFLATE(manifest-v2))
E(x)           = x XOR KS                                  (header uses KS[0..4], body KS[4..])
write          = ±1 LSB matching at each slot whose LSB differs (direction random; 0 → +1, 255 → −1)
```

**Manifest-v2** is manifest-v1 with `version = 2` and the 16-bit `reserved_rows` field replaced by
`carrier_pixels` (the number R of reserved carrier pixels, ≥ locator pixels, ≤ W·H / 8). The patch
masks used for planning, embedding and extraction are the segmentation labels with the first R carrier
pixels removed (label 255). No row band is reserved. The sender reserves
`R = ceil((96 + 8·(manifest_len + 64 + 4)) / C)` pixels: an upper bound for the carrier, because the
DEFLATE output is never more than the stored-block bound used here; only the first `ceil(bits / C)` of them
are written, the rest stay untouched cover pixels excluded from patches.

**Frame v3** has the frame-v2 layout with magic `IOD3`, version 3 and MAC domain `IOD-STEGO-FRAME-v3`;
the tag still covers header, manifest-v2 (uncompressed) and AppWire. A v2 image cannot be mistaken for a
v3 one, nor the reverse.

CRC32 only separates accidental corruption from forgery in diagnostics. **It is not authentication**: the
manifest is authenticated by the frame MAC, and nothing from the carrier is trusted until that MAC verifies.

## 4. Discovery and synchronisation (no circular dependency)

The receiver knows: session, its own role (hence direction), the directional key, and `L` = the highest
sequence number it has accepted for that direction. It does **not** know the frame's sequence number, the
manifest or the carrier length. Discovery uses only what it knows:

1. Candidates `s ∈ [max(1, L − 63), L + W]`, `W = IOD_STEGO_SYNC_WINDOW` (default 64, 1…1024). The window
   covers sequence numbers consumed by failed or lost sends (every send attempt reserves one).
2. For every candidate Rust derives `PK(s)` and the first 128 values of its stream (96 locator bits need 32 RGB or 96 grey pixels) and sends **only those
   values** to the service (`POST /stego/carrier/probe`). The service maps them to pixels of the saved PNG
   and returns the 96 locator bits per candidate. One request, no secrets.
3. Rust compares each candidate's first 64 bits with `S(s)`. A random match has probability 2⁻⁶⁴ per
   candidate. Exactly one match is required:
   * none → `BOOTSTRAP_NOT_FOUND` (not addressed to this channel/direction, wrong key, outside the window,
     or not a v3 image; if the image carries a valid v2 top-row preamble the error is
     `BOOTSTRAP_VERSION_UNSUPPORTED`);
   * a match with `s ≤ L` → `REPLAY` (fail closed, before any decryption);
   * more than one → `BOOTSTRAP_AMBIGUOUS` (fail closed).
4. Rust decrypts the header with `KS(s)`, checks version and bounds, sends the full value stream and the
   body bit count (`POST /stego/carrier/read`), decrypts the body, checks the CRC, inflates with an output
   limit of 64 KiB, and strictly parses manifest-v2 (geometry, versions, algorithm whitelist, parameters,
   contiguous chunks, map coverage, `carrier_pixels` bounds).
5. Rust sends the validated manifest and the value stream (`POST /stego/extract`); the service rebuilds
   the masks without the R carrier pixels, extracts the payload section and returns the frame.
6. Rust verifies the frame MAC (manifest included), AppWire, channel, direction, `seq == s`, replay and
   AEAD. Only then is `L` advanced. Any failure returns no plaintext and leaves `L` unchanged.

Nothing in steps 1–4 depends on information inside the carrier being decoded. Restart: channel keys are
held in memory, so after a core restart a new K1–K3 run is needed and sequence numbers start again under
new keys (new placement keys). Retries of one transmission (bounded re-plan) reuse the reserved
sequence number and therefore the same placement.

## 5. Security boundaries

* Raw session keys, the meta (MAC) key, `PK`, `S` and `KS` never leave Rust.
* The service receives: payload length; the value stream (pseudo-random u32 values, i.e. coordinates
  independent of the image size); the carrier bits (already encrypted); at receive time the validated
  manifest. It never receives plaintext, keys, or anything from which `PK` can be computed.
* The value stream and the carrier bits are as sensitive as the image itself: they reveal where the
  carrier is in one image. They are not logged.

## 6. Trade-offs and limits

* Carrier bits fall from ≈ 4,560 (v2, mean) to ≈ 2,350 (v3, mean incl. 96 locator bits); with ±1 matching
  about half of the carrier slots change.
* Keyed placement hides *where* the carrier is from someone without the session key; it does not make the
  ±1 changes statistically invisible. A detector looking at the whole image sees a sparse ±1 signal at
  ≈ 1 % of samples in addition to the patch embeddings. The effect is measured in
  `detectability-evaluation.md`; no undetectability is claimed.
* Reserved carrier pixels cost patch capacity (≈ 2–3 % of pixels at 320×240).
* Receiving costs three service calls (probe, carrier read, extract) instead of one.
* An image whose sender's sequence counter ran more than `W` ahead of the receiver cannot be located.
