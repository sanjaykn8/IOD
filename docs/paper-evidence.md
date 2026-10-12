# Paper Evidence Ledger

Facts a paper may cite, each tied to its source and status. No paper text is drafted here.

| Claim | Evidence (file / command) | Status |
|---|---|---|
| Membership proof is a zk-STARK with hiding FRI over BabyBear/Poseidon2; verifier receives no witness | `zk-design.md`, `rust-core/src/zk/*`; tests `zk::tests::*`, `t10` | verified by tests (structural) |
| Estimated security 128 b conjectured / 120 b proven list / 74 b unique | `zk::security_report`, `zk-test-results.md` (smoke run) | computed by Plonky3's estimator; classical |
| Poseidon2 digest 248 b: ≈2^124 classical / ≈2^83 quantum (BHT) collision | `zk-design.md` (generic bound arithmetic) | analytical, not experimental |
| Proof ≈250 KB, prove ≈85–105 ms, verify ≈3.5–5.5 ms (depth 4–12) | `benchmark-results-host-simulation.txt` | measured, **host simulation** (2-core Xeon VM), not drone hardware |
| M1–M8 sequential compute ≈112 ms avg (p95 ≈153 ms), K1–K3 ≈2.2 ms, no network | same | measured, host simulation |
| Kyber768 pk 1184 B / ct 1088 B; Dilithium2 pk 1312 B / sig 2420 B | same | measured sizes |
| No ECC in dependency graph or binaries | `ecc-audit.md` | verified 2026-10-12 |
| Attacks rejected: forged M4 key, bad GCS signature, replay (M2/M6/M8/K1), stale/consumed PID, K1 before auth/after DENY/wrong session, revoked member, tampered proof/commitment/MAC/AEAD | `tests/protocol_integration.rs` (t01–t16), `protocol::simulation` tests | passing |
| Revocation → authentication and key issue fail | `t08`, e2e | passing |
| Moderate anonymity: D2 never learns DroneID; sessions linkable; metadata public | `zk-specification.md` §1, e2e log check | stated model; linkability **not** mitigated |
| Limitations to disclose | `IMPLEMENTATION_STATUS.md` (known limitations), `zk-security-analysis.md` caveats | — |

Do not claim: unlinkability, hardware PUF behaviour, drone-hardware performance, FIPS 203/204 conformance, an independent audit, quantum-ROM soundness.
