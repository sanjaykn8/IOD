# Security Review (protocol v2 hardening)

Scope: this review covers the v2 changes; the v1 review is superseded (see git history `baseline-upload`). Nothing here is an external audit.

## Findings fixed in v2
| # | Finding (v1) | Severity | Fix |
|---|---|---|---|
| 1 | "ZK" backend transmitted the full witness (leaf, path, keys, rho) | Critical | Plonky3 hiding-FRI STARK; no witness on the wire; backend deleted |
| 2 | Goldilocks Poseidon, 64-bit digest (≈2^32 collision) | Critical | Poseidon2/BabyBear, 248-bit digest |
| 3 | D2's key accepted from an unsigned M4 field | High | GCS-signed credentials + pinned anchor |
| 4 | M3 and M6 results unauthenticated / failures unsigned | High | GCS signatures on M3 and every M6 outcome |
| 5 | K1 accepted without a completed session; literal nonces, `[0u8;32]` context | High | session state machine, D1 confirmation, canonical KDF context |
| 6 | PIDs reusable | Medium | PID lifecycle `Active/Consumed/Expired` |
| 7 | Replay set not durable | Medium | nonces and sessions persisted |
| 8 | Trace endpoint trusted a body role string | High | admin token, reason, flagged-session rule, audit |
| 9 | M8 carried a public key and was not session-bound | High | no key field; bound to `session_ctx`; replay flag |
| 10 | Secure-message headers carried identities | Low | pseudonymous channel tag |

## Findings found while testing v2
* A replayed M6 initially looked "accepted": it returns a GCS-signed `Invalid(SESSION_REPLAY_OR_WRONG_STATE)` and leaves the session untouched; the test now asserts exactly that.
* The CRP pool (16) is exhausted after 16 sessions per drone and there is no refill; documented, bench re-enrolls.
* Plonky3 estimator with a degree-4 challenge field gave only 111/102/74 bits; moved to degree 5 (128/120/74).

## Open items (not fixed)
GCS-known group key; linkable sessions; ZK adds little to authenticity in the moderate model (see `zk-security-analysis.md`); no statistical privacy experiment; RC-version Plonky3; FIPS 203/204 algorithms but no FIPS 140-3 validation; `iod_simulation.db` stores private keys; no constant-time claims; JSON wire format; trace flagging is unauthenticated (anyone can flag).

## Bootstrap-v3 / operational policy review (2026-11-19)
Checked for the keyed carrier (`bootstrap-v3-design.md`): the placement key, sync word, keystream and frame-MAC key are derived and used only in Rust (`transport/bootstrap.rs`, `frame.rs`); `PlacementKey` has no `Debug`/`Clone`/`Serialize`; the image service receives value streams (SHAKE output, no key material) and already encrypted carrier bits, and the probe request carries only 128 values per candidate; the Python package contains no HMAC or HKDF code and derives nothing from a key (its only SHAKE use generates the public educational sample images). Discovery depends only on receiver state (key, direction, last accepted sequence number), so there is no circular dependency; the window is bounded (default 64 forward, 63 back, max 1024 forward) and a replayed image is refused during discovery before anything is extracted or decrypted. The header length is bounded (u16), the body is CRC-checked and inflated with a 64 KiB output limit (decompression-bomb unit test), and the decoded manifest is parsed strictly and checked against the image geometry before the service is asked to extract; the frame's manifest must equal the decoded one and the AppWire sequence number must equal the discovered one. CRC-32 is documented and tested as non-authenticating (re-encrypted carriers with a valid CRC and a structurally valid altered manifest end in `FRAME_AUTH_FAILED`). Failures never advance the replay window (tested for every tamper case). The operational policy is enforced in the planner and re-checked in Rust (`POLICY_VIOLATION`); the environment allow list can only narrow it. The value stream and carrier bits are never written to events or logs; the segmentation overlay does not mark carrier pixels. Residual risks: a compromised image service learns where the carrier is in images it handles (it already holds the cover and stego image); a receiver more than the window behind the sender cannot locate frames; keyed placement does not make ±1 changes undetectable — detectability is measured in `detectability-evaluation.md`, not claimed.

## Steganography integration review (2026-10-29)
Checks done: MAC verified before AppWire parse and before AEAD open; constant-time compare; `recv_seen` committed only after successful open; bootstrap validated (CRC, length bounds vs capacity) before extraction; artifact ids whitelisted; atomic exclusive writes; state mutex not held across Python calls; secrets/witness never logged. Open: no TLS on the loopback hop (deliberate, ECC avoidance); no steganalysis resistance; camera path untested on hardware.

## Generated-cover review (2026-11-15; supersedes the webcam / cover-upload review)
The camera probe, the cover upload and every client-selected cover were removed (Python routes, Rust routes and trait methods, Node relays and the 14 MB body exception, UI components, types, configuration, optional OpenCV dependency). Checked by tests at each layer: the routes return 404; the old request shapes (`cover.source` = `webcam` / `browser_webcam` / `uploaded` / `test_cover` / `procedural`, `seed`, `cover_id`, `test_cover_id`, `image_b64`) are rejected and store nothing; a PNG placed in the artifact directory without a generation sidecar can be neither re-planned nor embedded into.

Reviewed for the generator:
* **Seed handling** — `os.urandom(16)` per production cover; not derived from any message or key material; expanded with SHA-256 under a domain label; never written to the sidecar, the logs, the events or any response (tests search responses, sidecars and events for a raw seed). The test-only fixed seed is process-level, visible in health (`seeding: "test-fixed"`) and flagged in the UI.
* **What Python learns** — unchanged: the payload length when planning, the finished authenticated frame when embedding. The plan and encode request bodies are asserted key-by-key in `stego_pipeline.rs`; requests carrying `payload`, `wire`, `ciphertext`, `message`, `plaintext`, `key` … are rejected by the service.
* **Bounds** — hard ceilings and tighten-only resolution implemented independently in Rust (`transport/generator.rs`) and Python (`generator/profile.py`) with mirrored tests; the core additionally rejects a planned cover that exceeds the generator ceilings or is not labelled `generated`; invalid environment values stop the process at start-up.
* **One cover per transmission** — a re-plan must return the same cover id and SHA-256, and encode must name it, otherwise the core fails closed (`BACKEND_MALFORMED_RESPONSE`). Verified against the real service with an induced embed failure.
* **No fallback** — quality rejection, budget exhaustion, memory limit and insufficient capacity are terminal, structured failures; nothing lowers the gates or switches the source.

Open / not done: the time budget is cooperative (checked between steps) and the memory limit is a pre-flight estimate, neither is OS-enforced; no measurement on a Raspberry Pi 5; the quality heuristics were calibrated only on this generator; detectability was evaluated only with a weak classical detector (`detectability-evaluation.md`) — the result there (the bootstrap carrier is easily detected) was a property of the `bootstrap-v2` format; it is addressed by bootstrap-v3 (keyed distributed carrier, see the 2026-11-19 review section) and re-measured in `detectability-evaluation.md`.

## Ten algorithms + workbench review (2026-10-30)
(Historical note, superseded by the patch-wise review below: at that time the single algorithm id was authenticated in the Frame v1 header.) Checked: new algorithm ids flow through the unchanged bootstrap/frame (alg id authenticated in Frame v1; a wrong but valid id fails closed - e2e test `set-alg 9`); receiver id range derived from the registry; STC extraction needs only public parameters; learn routes whitelisted, separate table, no secrets returned (extracted payload replaced by a hex preview; no keys in responses); CSV export neutralised. Open: no stego key; HUGO without model correction; non-optimised STC submatrices.


## Patch-wise transport review (2026-11-13)
Checked for the redesign (`patchwise-transport.md`): the Python service receives only the payload length when planning and only the finished frame when embedding (asserted on the recorded request in `stego_pipeline::the_image_service_receives_lengths_only_for_planning`); `k_meta` never leaves Rust and Python has no MAC code; the MAC domain string changed so v1 tags cannot verify; the manifest is parsed strictly **before** it is authenticated on the sender and **after** the MAC on the receiver, by an independent Rust parser, with overflow-checked lengths, version/algorithm/parameter whitelists and exact chunk coverage; the in-image CRC is treated as non-authenticating (tests rewrite the manifest with a valid CRC and expect `FRAME_AUTH_FAILED`); bootstrap rows are excluded from every patch on both sides; the receiver does not segment; failures never return plaintext and never advance the replay window; artifact access stays id-only with fixed suffixes (five kinds); removed request fields are rejected rather than ignored. Residual risks: plaintext loopback hop between Rust and Python (an on-host attacker can already read both processes); the patch map and bootstrap are visible in the image; a compromised image service can deny service or leak the cover and ciphertext it is given, but cannot forge an accepted message.
