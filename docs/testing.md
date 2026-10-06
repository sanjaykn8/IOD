# Testing

## Summary (all commands actually run in this session; see below for exact invocations)

| Suite | Count | Status |
|---|---|---|
| Rust unit tests (`cargo test --lib`) | 132 | all passing |
| Rust integration tests (`rust-core/tests/end_to_end.rs`) | 3 | all passing |
| Rust security-negative tests (`rust-core/tests/security_negative.rs`) | 3 | all passing |
| Python unit tests (`pytest`) | 75 | all passing |
| **Total automated tests** | **213** | **all passing** |
| React dashboard | build + type-check clean; functionally verified with a real headless-browser (Playwright/Chromium) session driving the live 4-service stack | pass |

The Rust integration count's third test is
`full_chain_stego_registration_through_revocation_and_denied_reauthentication`
-- the single longest chain this project tests end-to-end in one
function: Stego Registration (R1-R3 via `MockStegoClient`, crypto/
framing correctness) -> Authentication (M1-M8, ALLOW) -> Authorization
(Zero Trust) -> Group Key (K1-K4) -> Secure Message (send + decrypt) ->
Revocation -> Authentication Failure (the same pair, post-revocation,
correctly denied). The Python count's growth (13 -> 75) is almost
entirely the new steganography subsystem: `test_stego_algorithms.py`,
`test_stego_benchmark.py`, `test_selector.py`, `test_stego_knowledge.py`,
`test_stego_api.py` -- see `docs/steganography.md`,
`docs/algorithm-selection.md`, `docs/rag-stego-selection.md`. The
original 13 collaborative-RAG tests are unchanged and still pass.

Re-run stability: the full Rust suite was re-run 5 consecutive times
with zero flakiness (the PUF fuzzy-extractor's probabilistic reliability
is designed to fail less than once in ~10⁶ attempts at the default
noise level — see `docs/puf.md` — consistent with observing zero
failures across these runs).

## Running the tests

```bash
# Rust: unit + integration + security-negative (all three run with one command)
cd rust-core
cargo test

# Python
cd python-service
./venv/bin/python -m pytest tests/ -v     # venv\Scripts\python.exe -m pytest tests\ -v on Windows

# React (type-check + build; there is no separate unit-test suite for the
# UI layer in this version — verification is via build correctness plus
# the live headless-browser session documented below)
cd web-ui
npx tsc -b
npx vite build
```

## Project brief's testing checklist → where each item is covered

**Unit tests** (PUF, fuzzy extractor, KDF, ML-KEM wrapper, ML-DSA
wrapper, Poseidon, Merkle tree, membership witness, ZK interface,
transcript hashing, canonical serialization, nonce handling, AEAD, Zero
Trust policy, group membership changes): every one of these has a
dedicated `#[cfg(test)] mod tests` block in its own source file — see
`docs/IMPLEMENTATION_STATUS.md`'s per-phase tables for the exact file
list.

**Integration tests** (drone registration, group creation, group
assignment, authentication, failed authentication, revocation, stale
witness, stale version, invalid signature, invalid PUF proof, invalid
ZK proof, unauthorized operation, group-key establishment, secure
message transfer): covered across `protocol::registration::tests`,
`protocol::simulation::tests`, `zk::backend::tests`,
`zero_trust::tests`, `group_key::tests`, `secure_messaging::tests`, plus
`rust-core/tests/end_to_end.rs`.

**End-to-end test** (GCS + D1 + D2 + group + registration +
authentication + authorization + group-key + secure message + logging,
executing automatically): `rust-core/tests/end_to_end.rs`'s
`full_stack_end_to_end_gcs_d1_d2_group_auth_authz_groupkey_message_logging`
— asserts every M1-M8 stage appears in the event log, the Zero Trust
decision is ALLOW, the group key matches on both sides, and the secure
message round-trips correctly. Runs automatically with `cargo test`.

**Security/negative tests checklist**, mapped to the actual test:

| Requirement | Test |
|---|---|
| Stale timestamp | `tests/security_negative.rs::stale_timestamp_fails_freshness_check` |
| Reused nonce | `protocol::simulation::tests::reused_nonce_at_m6_is_rejected` |
| Invalid signature | `crypto::sign::tests::corrupted_signature_fails`, `protocol::simulation::tests::tampered_signature_in_proof_bundle_is_rejected` |
| Altered signature transcript | `crypto::sign::tests::altered_transcript_fails_verification` |
| Altered public key | `tests/security_negative.rs::claiming_a_different_public_key_than_registered_fails_zk_and_signature_checks` |
| Wrong Merkle path | `merkle::tree::tests::witness_fails_for_wrong_leaf` |
| Wrong root | `zk::backend::tests::wrong_root_is_rejected` |
| Wrong version | `zk::backend::tests::stale_version_is_rejected_even_if_root_unchanged_in_the_proof` |
| Revoked member | `protocol::simulation::tests::revoked_drone_fails_authentication`, `zk::backend::tests::revoked_member_fails_to_prove_against_the_current_root` |
| Wrong group | `protocol::simulation::tests::cross_group_authentication_is_rejected_at_m2`, `zk::backend::tests::wrong_group_is_rejected` |
| Altered PUF MAC | `protocol::simulation::tests::altered_puf_mac_is_rejected` |
| Unknown PID | `protocol::simulation::tests::unknown_pid_at_m2_is_rejected` |
| Unauthorized operation | `zero_trust::tests::operation_outside_allowlist_denies` |
| Malformed message | `tests/security_negative.rs::malformed_m2_envelope_is_rejected_not_panicked_on` |
| Malformed proof | `zk::backend::tests::tampered_opening_after_the_fact_is_rejected`, `::cannot_prove_with_an_inconsistent_witness` |
| Invalid KEM ciphertext | `crypto::kem::tests::invalid_ciphertext_is_rejected_or_disagrees`, `protocol::envelope::tests::tampered_ciphertext_fails` |
| Invalid AEAD authentication tag | `crypto::aead::tests::tampered_ciphertext_fails` |

## Real bugs this test suite actually caught during development

Documented in full in `docs/IMPLEMENTATION_STATUS.md`; summarized here:

1. **Fuzzy-extractor reliability** (Phase 1): the initial REPEAT=15
   parameter failed a 25-trial reliability test; root-caused as
   insufficient error-correction margin (not a logic bug), fixed by
   increasing to REPEAT=31 with a computed reliability table (see
   `docs/puf.md`).
2. **Duplicate/misordered persisted events** (Phase 7): manual
   end-to-end curl testing caught `SimulationState::authenticate()`
   re-persisting the entire recent event log instead of just the new
   M1-M8 events on every call. Fixed and reverified via direct SQLite
   inspection.
3. **Benchmark harness group-ID mismatch** (Phase 10): a copy-paste bug
   in `iod-bench`'s ZK benchmark setup used two different group-ID
   strings for leaf construction vs. the ZK statement, causing a
   `LeafMismatch` panic on first run. Fixed and reverified.
4. **React "Reactivate" button enabled for never-registered drones**
   (Phase 9): caught via Playwright-driven UI testing, not by code
   review. Fixed and reverified with a fresh screenshot.

## Live cross-service verification: Registration (Stego) end-to-end

Beyond the automated suites above, the live HTTP path was actually run
against all three backend services together (not mocked, not just
unit-tested): `iod-server`, `python-service` (Flask), and
`node-server`, started as real OS processes. Through the Node gateway
(exactly the path the browser uses), a group and a drone were created,
`POST /drones/:id/register-stego` was called with no cover images
supplied (exercising the bundled-fixture default path), and the
response was inspected directly:

- `adaptive_lsb` was the real selector winner for both R1 and R3 on the
  bundled 512x512 fixtures, chosen from real measured candidates
  (`adaptive_lsb`, `pvd`, `dct`, `dwt`, `svd`).
- The returned stego images were real, non-trivial base64 PNG payloads
  (hundreds of KB).
- `GET /drones/:id` afterward showed `registered: true` with the
  correct leaf index and a real Merkle root.
- The event log (`GET /events/history`) showed the real R1 -> R2 -> R3
  sequence with the selector's actual per-step choice recorded.
- A second, normally-registered drone in the same group then
  successfully completed real M1-M8 authentication (`ALLOW`) against
  the stego-registered drone, confirming the two registration paths
  produce interoperable Merkle state.
- Re-registering an already-registered drone via this endpoint was
  confirmed to fail cleanly (400, clear error message), not silently
  succeed or panic.

This is the same "don't just trust the type signature, actually run
the real stack" standard the React dashboard verification below
applies, extended to this stage's new endpoint.

## React dashboard verification methodology

A headless Chromium browser (Playwright, already available in this
environment) was used to load the live app against the real 4-service
stack and drive it through: group/drone creation, registration (with
witness-refresh confirmation), a full authenticate-and-inspect run,
group-key establishment + secure message send/decrypt, revoke →
subsequent-authentication-denied, the live SSE log, the RAG pipeline,
and the Trace Manager. Console/page errors were captured on every load
(zero found after fixing the one real bug above). This is a stronger
verification standard than build-success-only or curl-only checks, and
is why the dashboard is marked COMPLETE (not merely "should work based
on typed API contracts") in `docs/IMPLEMENTATION_STATUS.md`.
