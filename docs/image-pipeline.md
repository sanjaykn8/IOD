# Image Pipeline: Wire Format, Cover Images, Feasibility

How an actual image gets from "a PNG/JPEG on disk or picked in the
browser" to "pixels a steganography algorithm embeds into" and back,
end to end.

## Wire format

Every HTTP boundary in this subsystem (`python-service`'s
`/stego/*` Flask endpoints, the Rust `HttpStegoClient`, and the
dashboard's Registration (Stego) page) exchanges images as
**base64-encoded PNG bytes** inside JSON, never multipart form data and
never a raw binary body:

- `cover_image_b64` / `stego_image_b64`: base64 of a PNG file's raw
  bytes.
- Decoding (`stego_api.py`'s `_decode_image`): `PIL.Image.open(...)
  .convert("RGB")` then `numpy.array(...)` -- any input image is
  normalized to 8-bit RGB (no alpha channel, no palette/grayscale
  modes) before any algorithm sees it, so a JPEG, a grayscale PNG, or
  an RGBA PNG are all accepted on input and handled identically.
- Encoding (`_encode_image`): `PIL.Image.fromarray(pixels.astype(
  np.uint8), mode="RGB")`, always saved as **PNG** regardless of the
  cover's original format -- PNG is lossless, which matters because
  every algorithm here embeds by making small, exact pixel/coefficient
  changes that a lossy re-encode (JPEG) could silently destroy. This
  project never re-compresses a stego image after embedding.

## Cover images

**Any RGB-convertible image works** -- there is no required
resolution, aspect ratio, or content. What varies by algorithm is real
*capacity* (`docs/algorithm-selection.md`'s feasibility gate), which
scales with pixel count and (for DCT/SVD) is reduced slightly by
cropping to a multiple of 8 in each dimension (disclosed via
`algorithm_params`), and (for DWT) a multiple of 2.

**Default fixtures**: `rust-core/tests/fixtures/cover_d1_to_gcs.png`
(used for R1, D1 -> GCS) and `cover_gcs_to_d1.png` (used for R3, GCS ->
D1) -- real PNG images checked into the repo, embedded into the
`iod-server` binary at compile time via `include_bytes!` (see
`rust-core/src/api/state.rs`) so the live HTTP registration endpoint
and `iod-register-stego-demo` have no runtime dependency on the
working directory to find them. The dashboard's Registration (Stego)
page uses these automatically when the operator does not supply their
own cover image for R1/R3.

**Custom cover images**: the dashboard page accepts a user-supplied
image file for either step (read client-side via `FileReader`, sent as
base64, no server-side size limit beyond the Node gateway's 20MB JSON
body cap -- see `node-server/src/index.ts`). The live HTTP API
(`POST /api/drones/:id/register-stego`) accepts the same
`cover_image_r1_b64` / `cover_image_r3_b64` fields directly.

## Feasibility and what happens when a payload doesn't fit

`stego.benchmark.measure_one` computes each algorithm's real
`capacity_bytes` for the actual cover image first, and marks a
candidate `feasible=False` with `reason="capacity_exceeded"` before
ever attempting an embed if the payload is too large for it -- this is
a cheap check, not a caught exception from a failed embed. If **every**
registered algorithm is infeasible for a given (cover, payload) pair,
`POST /stego/select-and-embed` returns HTTP 422 with the full
per-candidate measurement set (so the caller can see exactly how close
each one came) rather than picking a doomed "least-bad" option. The
live registration endpoint surfaces this as a clear 400 error naming
the cause; it never silently truncates a payload or falls back to a
non-steganographic path.

In practice (measured, see `benchmarks/stego_benchmark.csv`): a real
sealed R1 `EnrollmentRequest` is ~50 KB (the PID pool dominates), and
on the bundled 512x512 fixtures only `adaptive_lsb` (~184-194 KB
capacity) and `pvd` (~162-168 KB) can carry it. `dct` (12,288 B), `dwt`
(24,576 B) and `svd` (1,536 B) are reported infeasible at that size --
correctly, by the feasibility gate, not by failure. Smaller payloads
(1-8 KB) make more of them feasible. So feasibility is a live
constraint for real registrations, not a theoretical one; a much
smaller cover image could make every algorithm infeasible (HTTP 422).

## Round trip integrity

Both the live registration endpoint and `iod-register-stego-demo`
extract immediately after embedding and assert byte-for-byte equality
against what was sealed before ever treating a stego image as
"transmitted" -- see the `anyhow::ensure!(extracted == plaintext, ...)`
checks in `rust-core/src/api/state.rs`'s `register_drone_via_stego` and
in `bin/register_stego_demo.rs`. This is the same correctness gate
`stego.benchmark.measure_one` already applies per-algorithm
(`reason="roundtrip_mismatch"`), checked again at the
cryptographic-envelope level on the Rust side.
