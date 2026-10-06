# Registration via Steganography (R1-R3)

**Classification: REAL**, end to end -- real ML-KEM-768/ML-DSA-44
keys, real KEM-then-AEAD sealing (`protocol::envelope`, the same
construction M2/M3/K1 already use), a real HTTP round trip to
`python-service` for RAG-assisted algorithm selection
(`docs/algorithm-selection.md`), and real pixel embedding/extraction
(`docs/steganography.md`) against real cover images
(`docs/image-pipeline.md`). This document covers the message flow,
the code that implements it, and how to run it -- as a standalone
demo, as live tests, or from the dashboard.

## Message flow

Matches `docs/diagrams/iod_full_sequence.mmd`'s Registration section:

- **R1** (D1 -> GCS): D1 builds an `EnrollmentRequest` (real PUF read,
  real fuzzy-extractor generation, real ML-KEM-768/ML-DSA-44 keypair
  derivation -- identical to the first half of
  `registration::register_drone`, just packaged as an explicit message
  instead of writing straight into shared state), encrypts it with
  `encrypt_enrollment_request` (KEM-then-AEAD), and the ciphertext is
  embedded into a cover image by the RAG-assisted selector. The
  resulting stego image is what actually "crosses the network" in this
  simulation.
- **R2** (GCS-internal): `gcs_process_enrollment` -- no message is
  sent anywhere for this step; GCS computes the Merkle leaf, registers
  it, and prepares its response. Diagrammed as internal processing,
  never a network arrow (binding notation rule for both sequence
  diagrams).
- **R3** (GCS -> D1): GCS builds an `EnrollmentResponse`, encrypts it
  for D1's (just-learned) KEM public key, and it too is
  steganographically embedded and sent back.

## Two documented, necessary additions beyond the spec's literal field list

(See `registration_stego.rs`'s module docs for the full reasoning;
summarized here.)

1. **`rho` added to `EnrollmentRequest`.** The spec's R1 field list
   never actually transmits the leaf-randomness `rho` that
   `identity::leaf::compute_leaf` requires both parties to agree on.
   In the original fused `registration::register_drone` this was
   invisible because D1 and GCS are the same in-process call; once
   split across a real channel, `rho` must travel from D1 (who
   generates it) to GCS. It is not secret (`DronePublicRecord.rho` is
   already GCS-visible), so including it introduces no new trust
   assumption.
2. **`pid_pool` added to `EnrollmentRequest`.** `protocol::entities`'
   own module docs already specify the intended design (each drone
   locally derives a batch of upcoming PIDs and submits
   `(pid -> drone_id)` bindings to GCS over the trusted enrollment
   channel); this module implements that for real -- D1 derives its
   own PID batch locally (`identity::pid::derive_pid`, using its own
   seed, which never leaves the drone) and sends only the resulting
   opaque PID bytes.

## A genuine, new integrity check this split enables

Because R3 now travels as an explicit, independently-decryptable
message instead of being silently assigned into `DroneState` by a
function that already trusts itself, `d1_apply_enrollment_response`
actually calls `merkle::tree::verify_witness` on the witness GCS sent,
before accepting it -- D1 no longer blindly trusts that GCS's R3 is
internally consistent, the same "recompute, don't just store" posture
`auth_flow` already uses elsewhere.

## Code map

| Piece | Where |
|---|---|
| Wire messages, R1-R3 functions, `StegoRegistrationError` | `rust-core/src/protocol/registration_stego.rs` |
| `StegoClient` trait, `HttpStegoClient` (real), `MockStegoClient` (crypto/framing test double, NOT a steganography implementation) | `rust-core/src/protocol/stego_client.rs` |
| Live HTTP endpoint (`SimulationState::register_drone_via_stego`) | `rust-core/src/api/state.rs` |
| `POST /api/drones/:id/register-stego` route | `rust-core/src/api/server.rs` |
| Standalone cross-language demo | `rust-core/src/bin/register_stego_demo.rs` |
| Pure crypto/framing tests (no stego, no network) | `registration_stego.rs`'s own `#[cfg(test)]` module |
| Full chained E2E test (Stego Registration -> Authentication -> Authorization -> Group Key -> Secure Message -> Revocation -> denied Re-authentication) | `rust-core/tests/end_to_end.rs`'s `full_chain_stego_registration_through_revocation_and_denied_reauthentication` (uses `MockStegoClient` -- crypto/framing correctness, not a steganography claim) |
| Dashboard page | `web-ui/src/components/command/registration-page.tsx`, route `/registration` |
| Node gateway proxy | `node-server/src/api/routes.ts`: `POST /api/drones/:id/register-stego` |
| Flask endpoints this calls into | `python-service/src/stego_api.py` |

## Running it

**Standalone CLI demo** (prints every stage's real measurements as a
worked example):

```bash
cd python-service && source venv/bin/activate && flask --app src/app.py run --port 5001 &
cd rust-core && cargo run --release --bin iod-register-stego-demo
# or: cargo run --release --bin iod-register-stego-demo -- http://127.0.0.1:5001
```

**Live, from the dashboard**: start the full stack
(`./scripts/linux/run_demo.sh` + `cd web-ui && npm run dev`), open
`http://127.0.0.1:5173/registration`, create or pick an unregistered
drone, optionally supply R1/R3 cover images, pick a target group and
role, and click "Register via steganography". The page shows every
candidate algorithm's real measurements for both R1 and R3, the
selector's winner and the RAG narrative explaining it, the resulting
stego images, and the final leaf index once registered.

**Directly over HTTP** (what the dashboard calls, through the Node
gateway):

```bash
curl -X POST http://127.0.0.1:4000/api/drones/<drone_id>/register-stego \
  -H "Content-Type: application/json" \
  -d '{"group_id": "alpha", "role": "recon"}'
```

`cover_image_r1_b64` / `cover_image_r3_b64` are optional base64-PNG
fields; omitted, the server uses the same bundled fixture images the
CLI demo uses (`docs/image-pipeline.md`).

## Dependency on `python-service`

Unlike the plain (non-stego) registration path
(`protocol::registration::register_drone`, still used by every
test/benchmark that does not need steganographic transport, and still
reachable via `POST /api/drones/:id/register`), this path requires
`python-service` reachable at `IOD_STEGO_SERVICE_URL` (default
`http://127.0.0.1:5001`). If it is not running, both the live endpoint
and the CLI demo fail with a clear, specific error -- they never
silently fall back to a non-steganographic path, which would
misrepresent what actually happened.

## Tests

- `registration_stego.rs`'s own tests: full R1->R2->R3 round trip
  without steganographic embedding (crypto/framing correctness only --
  the steganographic transport is a separate concern, exercised below),
  tampered-witness rejection, and that GCS never sees the PUF seed.
- `end_to_end.rs`'s full chain test (see table above).
- Live cross-language correctness: `iod-register-stego-demo` and the
  dashboard flow both assert the extracted plaintext matches the
  sealed envelope byte-for-byte before proceeding (see
  `docs/image-pipeline.md`'s "Round trip integrity").
