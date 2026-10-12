# Test Results (executed 2026-10-12, rustc 1.97.0, Linux x86_64)

| Suite | Release | Debug |
|---|---|---|
| unit tests (`cargo test --lib`) | 115 passed, 0 failed, 2 ignored | 115 passed, 0 failed, 2 ignored |
| `tests/protocol_integration.rs` (tests 1–16) | 16 passed | 16 passed |
| `tests/end_to_end.rs` | 1 passed | 1 passed |
| ignored: `zk::tests::standard_params_smoke` | run manually (release): proof 249,798 B, prove 85.6 ms, verify 3.5 ms, conjectured 128 b / proven(list) 120 b / proven(unique) 74 b | not run |
| ignored: `zk::tests::param_sweep` | **not run** | not run |
Not executed: Python service tests (RAG untouched, unchanged), Windows builds (no Windows host available), Raspberry Pi/hardware runs.
API smoke (manual, curl against the release server): create group/drones, register, K1 before auth → `NO_AUTH_SESSION`, authenticate → ALLOW, K1 → ok, K1 again → `SESSION_REPLAY`, secure message → delivered, revoke then authenticate → `PID_NOT_ACTIVE`, trace without token → `NOT_ADMIN`; `/api/drones` response contains no `rho`/secret/seed strings.

## ZK tests (`rust-core/src/zk/tests.rs`, `zk/air.rs`)
honest proof verifies; every leaf position verifies and proof size does not depend on position; proofs are randomized; the proof bytes do not contain the witness (`rho`, non-zero siblings); `Debug` of the witness is redacted; invalid `rho`/sibling/path/root/version/group/commitment are refused by the prover; a **malicious prover that bypasses the native check** is rejected by the verifier; 7 tampered public inputs fail; tampered/truncated proofs fail; wrong depth/params rejected; revoked (zero) leaf cannot prove; non-canonical inputs rejected; AIR permutation == native Poseidon2.
Limitation: the privacy tests are structural; there is no statistical distinguisher experiment.

## Area → tests (Phase 4 list)
| Area | Tests |
|---|---|
| ZK, serialization, witness non-disclosure, invalid witness/path/root/version/group, commitment/key mismatch, tampered proof, session mismatch | `zk::tests::*`, `zkhash::tests`, integration `t10` |
| Transcript canonicalization | `protocol::canon` (2), `protocol::transcript` (2) |
| ML-KEM / ML-DSA / envelope / AEAD | `crypto::kem` (3), `crypto::sign` (4), `protocol::envelope` (4), `crypto::aead` (5), `t15` |
| GCS credential verification | `protocol::credentials` (2), `t01`, `t02` |
| PUF / fuzzy extractor | `puf::sram_puf` (4), `puf::fuzzy_extractor` (3) |
| PID lifecycle, replay | `registration` (7), `t03`, `t04`, `t09` |
| Zero Trust | `zero_trust::tests` (7) |
| Merkle/group tree | `merkle::tree` (6), `merkle::group_tree` (7) |
| Persistence | `storage::db` (4) |
| Trace manager | `trace::tests` (4) |
| Protocol flow incl. negative cases | `protocol::simulation` (15) |

## Integration tests 1–16 (`tests/protocol_integration.rs`)
t01 forged M4 key rejected · t02 invalid GCS signature rejected (and rogue GCS cannot open M2) · t03 expired PID · t04 consumed PID · t05 K1 before authentication · t06 K1 after DENY (failed session, D2-DENY, lying D2) · t07 K1 only for the exact session · t08 revocation blocks authentication and key issue · t09 replay of M2/M6/K1 · t10 M3↔M5 commitment consistency and no witness/keys on the wire · t11 stale membership root · t12 stale timestamp · t13 signed M6 failure and forged result · t14 M8 replay/cross-session/tampered result · t15 AEAD tamper/replay/direction/header identity-free · t16 K1 forgeries.
## E2E
Register → M1–M8 (ALLOW) → K1–K3 → AEAD messages both directions → event-log has no D1 DroneID → revoke → authentication rejected and K1 rejected.
