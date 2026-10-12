# ZK Implementation Notes

Files:
* `rust-core/src/zkhash.rs` — Poseidon2/BabyBear hash, `Digest`, packing, leaf/node hashes.
* `rust-core/src/zk/air.rs` — membership AIR and trace builder (Poseidon2 round evaluation adapted from `p3-poseidon2-air`, whose `eval` is crate-private; a test asserts AIR permutation == native permutation).
* `rust-core/src/zk/config.rs` — STARK configuration, `ZkParams`, prover/verifier wrappers, security estimator (`security_report`).
* `rust-core/src/zk/mod.rs` — public API, native relation check.
* `rust-core/src/identity/{commitment,group_id,metadata,leaf}.rs` — statement components.
* `rust-core/src/merkle/{tree,group_tree}.rs` — `Digest` Merkle tree (revoked leaf = zero digest).

Key decisions
* Verifier checks `degree_bits == log2(height)+1` (hiding PCS doubles the domain) and the proof header's `param_id` against its own config; panics inside the prover/verifier are caught and mapped to errors.
* PCS/MMCS randomness comes from the OS RNG for every proof; the verifier's dummy seed is irrelevant.
* `ZkParams::testing` is for unit tests only and never used by the protocol (`zk_params_for` = `standard`).
* Trace height is dominated by the hiding-FRI budget (256 rows), so prove time is almost independent of tree depth (4–12) — see benchmarks.
* Private witness: no `Serialize`, redacted `Debug`, zeroized `Drop`; never in logs, API, DB or UI (API views are hand-built; no view contains `rho`, siblings or path).
* Old v1 snapshots/hashes are rejected (non-canonical limbs, new JSON shapes).

Commands: `cargo test --release zk::`, `cargo test --release --lib zk::tests::standard_params_smoke -- --ignored --nocapture`, `cargo run --release --bin iod-bench`.
