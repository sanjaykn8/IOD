# Data and Evaluation Scope for the Steganography Subsystem

What this project's steganography numbers are actually measured
against, stated plainly so nobody reading `docs/steganography.md` or a
Registration (Stego) page result mistakes "real measurement" for
"evaluated at scale."

## What's measured, and against what

Every embed-time/extract-time/capacity/MSE/PSNR/SSIM number anywhere in
this project (the selector's candidate table, the RAG narrative, the
dashboard preview) is a **real measurement against the specific cover
image and specific payload actually in hand at that moment**
(`docs/steganography.md`'s `stego.benchmark`). There is no offline
training set, no precomputed lookup table, and no literature-derived
estimate feeding any of these numbers.

The **bundled default cover images** (`rust-core/tests/fixtures/
cover_d1_to_gcs.png`, `cover_gcs_to_d1.png`) are both 512x512 RGB PNGs.
Real registration payloads (a KEM-then-AEAD-sealed `EnrollmentRequest`,
~50 KB observed, dominated by the PID pool; the response is similar in
size) exceed the capacity of `dct`, `dwt` and `svd` on these images, so
in practice the selector chooses between `adaptive_lsb` and `pvd`. The
exported benchmark (`benchmarks/stego_benchmark.{csv,json}`, produced
by `benchmarks/stego_bench.py`) covers both fixtures at 1 KB, 8 KB and
50,007 B payloads, 10 trials each, with avg/p50/p95 timings and the
real capacity/MSE/PSNR/SSIM, on a shared sandbox VM (relative
comparison only).

## What this evaluation does NOT cover

- **No large image corpus.** Numbers are not averaged over a standard
  steganalysis benchmark set (e.g. BOSSbase, BOWS2) -- this project
  measures the actual image+payload at hand, which is the correct
  behavior for a registration-time selector, but means nobody should
  read "SSIM=0.998 on the bundled fixture" as a claim about typical
  behavior across arbitrary images. A very different cover image
  (near-solid color, extreme aspect ratio, very small resolution) will
  produce different real numbers -- that is the point of measuring per
  request rather than once.
- **No adversarial steganalysis.** Nothing here was evaluated against
  a steganalysis detector (classical or learned). "Real SSIM/PSNR"
  measures fidelity to the human eye and to a standard image-quality
  metric, not statistical detectability by a targeted attacker. See
  `docs/steganography.md`'s per-algorithm "honest limitations" notes.
- **No channel-noise or recompression robustness testing.** This
  project never recompresses a stego image after embedding
  (`docs/image-pipeline.md`), and there is no simulated lossy channel
  between "embed" and "extract" -- the round trip is immediate and
  exact. Real-world transport that recompresses, resizes, or
  otherwise lossily alters the image would need its own evaluation
  before any claim about robustness there.
- **No cross-run statistical aggregation** (mean/variance/confidence
  interval across repeated trials) for the stego metrics specifically
  -- each registration reports the one real measurement for that one
  request. (Contrast with `docs/benchmarking.md`'s crypto/protocol
  benchmarks, which do report avg/p50/p95 over repeated trials -- a
  different subsystem with a different, already-honest methodology.)

## Running your own comparison

Nothing above is hidden behind the registration flow -- the same
`stego.benchmark.measure_all(cover_pixels, payload)` call the live
endpoint uses can be run directly against any cover image and payload
you choose:

```python
import numpy as np
from PIL import Image
from stego.benchmark import measure_all

cover = np.array(Image.open("your_cover.png").convert("RGB"))
payload = b"your test payload bytes"
for m in measure_all(cover, payload):
    print(m.algorithm_id, m.feasible, m.capacity_bytes, m.embed_time_ms, m.ssim, m.psnr_db)
```

Or via HTTP: `POST /stego/select-and-embed` with your own
`cover_image_b64`/`payload_b64` (see `docs/image-pipeline.md` for the
wire format) returns the full `selection.candidates` array with every
algorithm's real measurement for that specific input, not just the
winner.

## Relationship to `docs/benchmarking.md`

`docs/benchmarking.md` covers the Rust crypto/protocol benchmarks
(`iod-bench`): Kyber768/Dilithium2 key/ciphertext/signature sizes, and
avg/p50/p95 latencies over repeated trials for each primitive. That
methodology (many repeated trials, percentile reporting) is
appropriate there because those primitives' performance does not
depend on image content. It is intentionally a different methodology
from this document's per-request stego measurement, because the two
questions ("how fast is ML-KEM-768 in general" vs. "what does THIS
embed actually cost on THIS image") are different questions.
