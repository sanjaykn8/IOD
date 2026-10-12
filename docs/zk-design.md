# ZK Membership Design

## Why the old backend was removed
The v1 "ZK" backend was a hash commitment plus a Fiat–Shamir challenge whose
`ZkProof` carried a `WitnessOpening` (leaf, Merkle siblings, path indices, both
public keys, metadata, `rho`, blinding). The verifier received the entire private
witness: it was a proof of *consistency*, not zero knowledge. It is deleted
(`rust-core/src/zk/{backend,statement,witness}.rs`); no code path transmits a
witness, Merkle path or `rho` any more. The 64-bit Goldilocks Poseidon it used
(one 64-bit element of output, ≈ 2^32 classical collision resistance) is also removed.

## Requirements → choice

| Requirement | Choice |
|---|---|
| genuine witness-hiding ZK | zk-STARK with a **hiding** FRI PCS (random codewords + salted Merkle commitments), Haböck, ePrint 2024/1037 as implemented in Plonky3 `p3-fri::HidingFriPcs` |
| transparent (no trusted setup) | FRI/STARK: public randomness only |
| non-ECC | only hashes (Keccak-256, Poseidon2) and the BabyBear field; no curve, no pairing |
| post-quantum | security rests on collision/preimage resistance of Keccak-256 and Poseidon2 and on FRI soundness; no discrete-log/factoring assumption |
| Poseidon-based tree kept | Poseidon2 over BabyBear (arithmetization-friendly), 8-limb digests |

Alternatives considered: Groth16/PLONK-KZG (ECC pairings — excluded by policy);
Halo2-IPA (ECC — excluded); Ligero/Brakedown-style (no maintained, hiding,
Poseidon-friendly Rust library of production quality was available); MPC-in-the-head
(proof sizes and no existing AIR for Poseidon). Bulletproofs: ECC.

## Hash audit (post-quantum collision strength)
* Goldilocks, 1×64-bit output: classical collision ≈ 2^32. **Inadequate**, replaced.
* BabyBear Poseidon2, 8×31-bit = 248-bit digest, capacity 248 bits:
  generic classical collision ≈ 2^124; generic quantum collision (BHT) ≈ 2^(248/3) ≈ 2^83.
  Poseidon2 round counts (8 full + 13 partial, x^7, width 16) are those proposed by
  the designers for 128-bit security against known algebraic attacks; Poseidon-family
  cryptanalysis is ongoing and the Poseidon2 paper is younger than SHA-3.
* **Residual risk and the stronger alternative**: a Keccak-based Merkle tree would give
  256-bit digests (≈ 2^85 BHT) but is ≈ 20–50× more expensive to arithmetize. The
  mitigation chosen is *crypto-agility*: `PARAM_SET_ID` and `LEAF_FORMAT_VERSION`
  are bound into every leaf and `protocol_version` into every statement, so a stronger
  tree can be introduced as parameter set 2.
* **Migration / re-enrollment**: a new parameter set changes every leaf and root, so
  drones must be re-enrolled (R2/R3 repeated, `reactivate_drone`/`register_drone`) into
  a new group tree; the GCS issues new credentials, old credentials/PIDs are expired
  (`expire_pids_of`). Version 1 data (Goldilocks leaves, JSON snapshots) is not
  readable by v2 and is intentionally rejected.
* The proof-system's own commitments (Keccak-256 Merkle, 256-bit) have ≈ 2^128 classical /
  ≈ 2^85 quantum collision resistance.

## Circuit (AIR)
One Poseidon2 permutation per trace row (≈ 340 columns incl. all round states)
plus control columns; a one-hot selector state machine pins row types:
6 leaf-absorb rows, `D` Merkle rows, padding. See `zk-specification.md` §4 and
`rust-core/src/zk/air.rs`. Constraints (max degree 3): selector booleanity, sum-to-one,
first-row and transition rules, last-row anti-truncation, public-value binding,
leaf-absorb chain, Merkle swap by `bit`, root equality guarded by the last-Merkle
selector.

## Interface (`rust-core/src/zk/mod.rs`)
`prove_membership(&ZkParams, &MembershipPublicInputs, &MembershipPrivateWitness) -> MembershipProof`,
`verify_membership(&ZkParams, &MembershipPublicInputs, &MembershipProof) -> Result<(), ZkError>`,
canonical proof bytes `IMP2 || param_id || postcard`, and parameter configuration
`ZkParams::{standard, testing}`.

## References
* Grassi, Khovratovich, Schofnegger, *Poseidon2*, ePrint 2023/323.
* Ben-Sasson, Bentov, Horesh, Riabzev, *FRI*, ICALP 2018; *STARKs*, ePrint 2018/046.
* Haböck, *A note on adding zero-knowledge to STARKs* / *Hiding FRI*, ePrint 2024/1037.
* Plonky3 (Polygon Zero), https://github.com/Plonky3/Plonky3 (`=0.9.0-rc.1`).
* Brassard, Høyer, Tapp, *Quantum cryptanalysis of hash and claw-free functions*, LATIN 1998.
